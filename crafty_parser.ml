(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(* Copyright 2026, Cedric Cellier
 *
 * This file is part of RobiNet.
 *
 * RobiNet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RobiNet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with RobiNet.  If not, see <http://www.gnu.org/licenses/>.
 *)
(** Crafty programs, from text to {!Crafty_ast}.

   Statements end at the end of the line, or at a semicolon. Within
   parentheses, brackets and braces, and after a binary operator, a new line
   is mere white space; a block opens on the line of the statement it
   belongs to. Comments run from a [#] that is not followed by a hexadecimal
   digit (which would be a byte literal) to the end of the line.

   Literals are read as whole words: [5s] is an interval, [1.2.3.4] an IP
   address, [0x1f] an integer, [12:34:56:78:9a:bc] a MAC address.

   A layer name in an expression is a layer of a packet, which must be
   followed by a field ([IP.src]) or be a selector ([MATCH[IP]]).

   Blocks, [if] and [case] are expressions, and any expression is a
   statement. Braces with no field in them are a block, not a record.

   Every reading of the program is considered, and one that can be read in
   several ways is an error. *)
open Batteries
open Crafty_ast

(* Whether the layer of that name sends a packet: *)
let terminal name =
    List.exists (fun (l : Crafty_layers.layer) ->
        l.terminal && l.name = name) Crafty_layers.all

(* What is wrong with a stack of [layers] that is followed by a block although
 * it sends, and the fixes: *)
let no_block_after anchor layers =
    let top = List.last layers in
    let name = Layer_name.to_string top.layer_name in
    let below = List.take (List.length layers - 1) layers in
    Printf.sprintf "%s is a terminal layer, therefore %s %s message. \
                    No further layer can be stacked on top of it, therefore it \
                    cannot open a block.\n  Do you mean \"%s\"%s, or \"expect %s { ... }\"?"
        name
        (string_of_stack anchor (List.map (fun l -> { l with options = [] }) layers))
        (if anchor = Absolute then "is a complete" else "completes a")
        (string_of_stack ~sends:true anchor layers)
        (if below = [] then "" else
         Printf.sprintf ", \"%s { %s ... }\""
            (string_of_stack anchor below)
            (string_of_stack ~sends:true (Relative 0) [ top ]))
        (string_of_stack anchor layers)

(* What is wrong with a stack of [layers] that does not send, but is used as a
 * message (or, if [block], is not followed by a block): *)
let not_a_message ?(block=false) anchor layers =
    let top = Layer_name.to_string (List.last layers).layer_name in
    let terminals =
        List.filter_map (fun (l : Crafty_layers.layer) ->
            if l.terminal &&
               List.exists (fun (b : Crafty_layers.layer) ->
                   Layer_name.to_string b.name = top) l.above
            then Some (Layer_name.to_string l.name) else None) Crafty_layers.all |>
        List.unique in
    Printf.sprintf "%s is not a terminal layer, therefore %s is not a complete \
                    message that could be sent: it needs %s%s."
        top
        (string_of_stack anchor (List.map (fun l -> { l with options = [] }) layers))
        (if terminals = [] then "more layers on top, up to a terminal one"
         else "a terminal layer on top ("^ String.join " or " terminals ^")")
        (if not block then ""
         else if terminals = [] then ", or a block in which to stack them"
         else ", or a block in which to stack one")

module P = Parsers.Make (ParsersPositions.LineCol (Parsers.SimpleConfig (Char)))
open P

type error = { where : location ; message : string }

let print_error oc e =
    Printf.fprintf oc "%a: %s" print_location e.where e.message

(* Rejections are told from what was expected by this mark: *)
let rejection_mark = "\001"

let reject fmt =
    Printf.ksprintf (fun s -> raise (Reject (rejection_mark ^ s))) fmt

let loc_of (pos : ParsersPositions.file_position) =
    { line = pos.line ; column = pos.column }

(* The location of what comes next: *)
let here : location t = fun _m e c s ->
    ct_bind (take s) (fun (pos, _, _) -> ct_return (e, [ loc_of pos, c, s ]))

(* What [p] is looking for, for error messages: *)
let (|?) p what = fun m e c s -> p (what :: m) e c s

(* [p] without the errors it finds, for those parsers that look ahead without
 * expecting anything in particular: *)
let quiet p = dismiss_error_if (fun _ _ -> true) p

(* Grammar rules that refer to each other are tied with these: *)
let forward () =
    let r = ref fail in
    (fun m e c s -> !r m e c s), (fun p -> r := p)

(** {2 Characters and words} *)

let char_if what f = cond what f ' '

let quoted s = "'"^ s ^"'"

let is_digit c = c >= '0' && c <= '9'
let is_hex c =
    is_digit c || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
let is_alpha c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c = '_'
let is_word c = is_alpha c || is_digit c

(* With no error but at its start, the only place where it can fail: *)
let chars_of ?(min=1) ?max what f =
    dismiss_error_if (fun start pos -> not (parsed_fewer_than 1 start pos))
        (repeat_greedy ~sep:none ~min ?max (char_if what f)) >>: String.of_list

(* That word, or else no error but at its start: *)
let word s =
    dismiss_error_if (fun start pos -> not (parsed_fewer_than 1 start pos))
        (String.fold_right (fun c p -> item c -- p) s (return ())) |? quoted s

let comment =
    item '#' -- nay (char_if "hexadecimal digit" is_hex) --
    chars_of ~min:0 "anything" ((<>) '\n')

let blank =
    (char_if "space" (fun c -> c = ' ' || c = '\t' || c = '\r') >>: ignore) |||
    comment

(* Spaces and comments, then also new lines: *)
let sp = quiet (repeat_greedy ~sep:none blank >>: ignore)
let nl_sp =
    quiet (repeat_greedy ~sep:none (blank ||| (item '\n' >>: ignore)) >>: ignore)

(* [p] after spaces, for what may or may not come next: not finding it is no
 * error, unless it is found in part. *)
let maybe_next p = sp -+ dismiss_error_if (parsed_fewer_than 1) p

let slash = (item '/' ||| item '\\') >>: ignore |? "'/'"

(* What a word or a literal cannot be followed by; a colon can, for the key
 * of a map: *)
let end_of_word =
    quiet (nay (char_if "end of word" (fun c ->
        is_word c || c = '.' || Char.code c >= 128)))

(* Failing only at its first letter: *)
let identifier =
    char_if "letter" is_alpha ++ quiet (chars_of ~min:0 "letter or digit" is_word) >>:
    (fun (c, s) -> String.make 1 c ^ s) |? "name"

let is_in names s = List.mem (String.lowercase_ascii s) names

let is_keyword s = is_in keywords s

let is_reserved s =
    is_keyword s || is_in functions s || Layer_name.of_string s <> None ||
    List.mem s predefined ||
    Crafty_layers.find_constant s <> None

(* Names of the user's variables: *)
let name =
    identifier >>= fun s -> if is_reserved s then fail else return s

let predefined_var =
    identifier >>= fun s ->
        if List.mem s predefined then return s else fail

let constant =
    identifier >>= fun s ->
        match Crafty_layers.find_constant s with
        | Some l -> return (s, l)
        | None -> fail

let function_name =
    identifier >>= fun s -> if is_in functions s then return s else fail

(* A name right before a parenthesis, which only a function, a layer or a
 * constructor can be, but is neither, refused once [args] are read (so that
 * the rejection is found further than what other readings expect): *)
let unknown_function args =
    (quiet (identifier +- check (item '(')) >>= fun s ->
        if is_keyword s || is_in functions s || Layer_name.of_string s <> None ||
           is_constructor s && not (is_reserved s)
        then fail else return s) ++ args >>:
    fun (s, _) ->
        reject "Unknown function %s%s" s
            (did_you_mean (functions @ List.map Layer_name.to_string Layer_name.all) s)

let known_layer =
    identifier >>= fun s ->
        match Layer_name.of_string s with Some n -> return n | None -> fail

(* Where only a layer can be: *)
let layer_name =
    (identifier >>= fun s ->
        if is_keyword s || is_in functions s then fail else return s) >>:
    fun s ->
        match Layer_name.of_string s with
        | Some n -> n
        | None ->
            reject "Unknown layer %s%s" s
                (did_you_mean (List.map Layer_name.to_string Layer_name.all) s)

(* That keyword, or else no error: a name that starts like it is no
 * misspelling of it. *)
let keyword k =
    let rec loop i =
        if i >= String.length k then quiet (nay (char_if "" is_word))
        else char_if (quoted k) (fun c -> Char.lowercase_ascii c = k.[i]) --
             loop (i + 1) in
    quiet (loop 0)

(** {2 Literals} *)

let digits = chars_of "digit" is_digit

(* A number with a minus sign is a literal of its own: *)
let signed p = (item '-' -+ p >>: fun s -> "-"^ s) ||| p

let int_lit =
    let prefixed p what f =
        item '0' -- char_if what (fun c -> Char.lowercase_ascii c = p) -+
        chars_of what f >>: fun s -> "0"^ String.make 1 p ^ s in
    (prefixed 'x' "hexadecimal digit" is_hex |||
     prefixed 'o' "octal digit" (fun c -> c >= '0' && c <= '7') |||
     prefixed 'b' "binary digit" (fun c -> c = '0' || c = '1') |||
     digits |> signed) +- end_of_word >>:
    fun s ->
        match int_of_string_opt s with
        | Some i -> Int i
        | None -> reject "Integer %s is too large" s

let float_lit =
    let exponent =
        char_if "exponent" (fun c -> c = 'e' || c = 'E') -+
        optional ~def:"" (char_if "sign" (fun c -> c = '-' || c = '+') >>:
                          String.make 1) ++
        digits >>: fun (sign, d) -> "e"^ sign ^ d in
    ((digits +- item '.' ++ digits ++ optional ~def:"" exponent >>:
        fun ((i, f), e) -> i ^"."^ f ^ e) |||
     (digits ++ exponent >>: fun (i, e) -> i ^ e) |> signed) +- end_of_word >>:
    fun s -> Float (float_of_string s)

let ip_lit =
    let octet = chars_of ~max:3 "digit" is_digit in
    octet ++ times 3 ~sep:none (item '.' -+ octet) +- end_of_word >>:
    fun (o, os) ->
        let s = String.concat "." (o :: os) in
        if List.exists (fun o -> int_of_string o > 255) (o :: os) then
            reject "Invalid IP address %s" s ;
        Ip (Ip.Addr.of_dotted_string s)

(* No error before its first colon, as a word can start like a byte: *)
let mac_lit =
    let byte = chars_of ~max:2 "hexadecimal digit" is_hex in
    quiet (check (byte -- item ':')) -+
    byte ++ times 5 ~sep:none (item ':' -+ byte) +- end_of_word >>:
    fun (b, bs) -> Mac (Eth.Addr.of_string (String.concat ":" (b :: bs)))

let interval_lit =
    let unit_ = chars_of "unit" (fun c -> is_alpha c || Char.code c >= 128) in
    (repeat_greedy ~sep:none ~min:1 (
        digits ++ optional ~def:"" (item '.' -+ digits >>: (^) ".") ++
        unit_ >>: fun ((i, f), u) -> i ^ f ^ u) >>: String.concat "" |>
    signed) +- end_of_word >>:
    fun s ->
        match Clock.Interval.of_string s with
        | i -> Interval i
        | exception Invalid_argument msg ->
            let reason =
                try snd (String.rsplit msg ~by:": ") with Not_found -> msg in
            reject "Invalid interval %s: %s" s reason

(* ISO 8601, in the local time of the host unless given a zone: *)
let time_lit =
    let num n = chars_of ~min:n ~max:n "digit" is_digit >>: int_of_string in
    let two = num 2 in
    let zone =
        (char_if "time zone" (fun c -> c = 'Z' || c = 'z') >>:
            fun _ -> Clock.Interval.zero) |||
        (char_if "sign" (fun c -> c = '+' || c = '-') ++ two +- item ':' ++ two >>:
            fun ((sign, h), m) ->
                let off = Clock.Interval.(add (hour (float_of_int h)) (min (float_of_int m))) in
                if sign = '-' then Clock.Interval.(sub zero off) else off) in
    let seconds =
        item ':' -+ chars_of ~min:2 ~max:2 "digit" is_digit ++
        optional ~def:"" (item '.' -+ digits) >>:
        fun (s, f) -> float_of_string (s ^"."^ f) in
    num 4 +- item '-' ++ two +- item '-' ++ two +-
    char_if "T" (fun c -> c = 'T' || c = 't') ++ two +- item ':' ++ two ++
    optional ~def:0. seconds ++ optional ~def:None (zone >>: Option.some) +-
    end_of_word >>:
    fun ((((((y, mo), d), h), mi), s), utc_offset) ->
        match Clock.Wall.of_date ?utc_offset y mo d h mi s with
        | t -> Time t
        | exception Invalid_argument msg -> reject "Invalid time: %s" msg

let bool_lit =
    (keyword "true" >>: fun () -> Bool true) |||
    (keyword "false" >>: fun () -> Bool false)

(* Of those that fail at the same place, the last one tried tells why: *)
let literal =
    time_lit ||| interval_lit ||| bool_lit ||| ip_lit ||| mac_lit ||| float_lit |||
    int_lit

(** The literal that is all of that text, if any. *)
let parse_literal s =
    match to_result ((literal +- eof) [] None Parsers.no_error_correction
                                      (stream_of_string s)) with
    | Ok (l, _) -> Some l
    | Error _ -> None

(*$= parse_literal & ~printer:(function None -> "None" | Some l -> IO.to_string Crafty_ast.print_literal l)
  (Some (Crafty_ast.Int 16)) (parse_literal "0x10")
  (Some (Crafty_ast.Float (-1.5))) (parse_literal "-1.5")
  None (parse_literal "1.2.3.4 x")
  None (parse_literal "")
*)

(* One byte, or an array of them when more than two digits: *)
let bytes_lit =
    here ++ (item '#' -+ chars_of "hexadecimal digit" is_hex +- end_of_word) >>:
    fun (loc, s) ->
        let byte i = Lit (Byte (int_of_string ("0x"^ String.sub s i 2))) in
        let n = String.length s in
        if n <= 2 then
            { loc ; desc = Lit (Byte (int_of_string ("0x"^ s))) }
        else if n mod 2 = 1 then
            reject "Odd number of hexadecimal digits in #%s" s
        else
            { loc ; desc = Array (List.init (n / 2) (fun i ->
                { loc = { loc with column = loc.column + 1 + 2 * i } ;
                  desc = byte (2 * i) })) }

(* Adjacent texts merged, and no empty one: *)
let rec merge_texts = function
    | Text "" :: rest -> merge_texts rest
    | Text a :: Text b :: rest -> merge_texts (Text (a ^ b) :: rest)
    | x :: rest -> x :: merge_texts rest
    | [] -> []

let string_lit expr =
    let plain =
        chars_of "character" (fun c -> c <> '"' && c <> '\\' && c <> '$') >>:
        fun s -> Text s
    and dollar = item '$' -- nay (item '{') >>: fun () -> Text "$"
    and hex_escape =
        word "\\x" -+ times 2 ~sep:none (char_if "hexadecimal digit" is_hex) >>:
        fun ds ->
            Text (String.make 1 (Char.chr (int_of_string ("0x"^ String.of_list ds))))
    and escape =
        item '\\' -+ char_if "escaped character" ((<>) 'x') >>: function
            | 'n' -> Text "\n" | 'r' -> Text "\r" | 't' -> Text "\t"
            | '0' -> Text "\000"
            | '\\' | '"' | '$' as c -> Text (String.make 1 c)
            | c -> reject "Unknown escape sequence \\%c" c
    and interp =
        word "${" -- nl_sp -+ expr +- nl_sp +- item '}' >>: fun e -> Interp e in
    here ++ (item '"' -+
             repeat ~sep:none (plain ||| dollar ||| hex_escape ||| escape ||| interp) +-
             item '"') >>:
    (fun (loc, parts) -> { loc ; desc = String (merge_texts parts) }) |? "string"

(** {2 Expressions} *)

(* Comma separated, over several lines if need be, with an optional final
 * comma: *)
let list_of p =
    repeat ~sep:(nl_sp -- item ',' -- nl_sp) p +-
    optional ~def:() (nl_sp -- item ',')

let in_ opening p closing =
    item opening -- nl_sp -+ p +- nl_sp +- item closing

let args expr =
    let arg =
        here ++
        optional ~def:None (
            identifier +- sp +- item '=' +- nay (item '=') +- nl_sp >>:
            Option.some) ++
        expr >>:
        fun ((arg_loc, arg_name), value) -> { arg_loc ; arg_name ; value } in
    in_ '(' (list_of arg) ')' |? "arguments"

let check_var n =
    if List.mem n self_declared then reject "%s cannot be changed" n ;
    if is_reserved n then reject "%s is a reserved name" n ;
    n

(* The name of a variable, given as a parameter: *)
let var_name what e =
    match e.desc with
    | Var n -> check_var n
    | String [ Text n ] -> check_var n
    | String [] -> reject "The %s cannot be empty" what
    | _ -> reject "The %s must be a name" what

(* Parameters of a special form, by name, or the single one it has (which
 * starts neither as a record nor as a layer, not to be mistaken for the
 * block or the pattern that follows); only by name if not [unnamed], for a
 * form followed by an expression ([expr]). Before a [pattern], what is
 * followed by the block is that pattern, misspelled, rather than a
 * parameter: *)
let params_of expr ?(unnamed=true) ?(pattern=false) form names =
    let param_name =
        identifier >>= fun s -> if Layer_name.of_string s <> None then fail else return s in
    (* Without [unnamed], or before a pattern, a name not followed by [=] is
     * no error, but the expression or the pattern that follows: *)
    let equal = if unnamed && not pattern then item '=' else quiet (item '=') in
    let named =
        (param_name +- sp +- equal +- nay (item '=') +- sp >>: Option.some) ++
        expr in
    let param =
        here ++
        (if not unnamed then named else
         named |||
         (nay (item '{' >>: ignore ||| (known_layer >>: ignore)) --
          (if pattern then quiet (nay (expr -- sp -- item '{')) else return ()) -+
          expr >>: fun e -> None, e)) in
    repeat ~sep:none (maybe_next param) >>: fun ps ->
        let ps =
            List.map (fun (_loc, (n, e)) ->
                match n with
                | Some n ->
                    let n' = String.lowercase_ascii n in
                    if not (List.mem n' names) then
                        reject "Unknown parameter %s for %s (expected %s)"
                            n form (String.concat ", " names) ;
                    n', e
                | None ->
                    (match names with
                    | [ n ] -> n, e
                    | _ -> reject "Parameters of %s must be named" form)
            ) ps in
        List.iter (fun n ->
            if List.length (List.filter (fun (n', _) -> n' = n) ps) > 1 then
                reject "Parameter %s of %s given twice" n form) names ;
        fun n -> try Some (List.assoc n ps) with Not_found -> None

let carets = repeat_greedy ~sep:none ~min:1 (item '^') >>: List.length

let left_assoc op term =
    term ++ repeat ~sep:none (maybe_next (op +- nl_sp ++ term)) >>:
    fun (first, rest) ->
        List.fold_left (fun l (op, r) ->
            { loc = l.loc ; desc = Binop (op, l, r) }) first rest

let op s v = word s >>: fun () -> v

(* An operator that must not be followed by [c]: *)
let op_not_before s c v = word s -- nay (item c) >>: fun () -> v

(* [self] is the grammar being built: that of normal expressions, or that of
 * conditions, where [=] compares. [expr] is that of normal expressions, used
 * within brackets. *)
let make_expr ~cond ~self ~expr ~pattern ~block =
    let body = sp -+ block in
    (* What follows [if] or [elsif], the else on the same line as the brace
     * that ends the block before it or on the next ones: *)
    let if_ = fix (fun if_ ->
        sp -+ expr ++ body ++
        optional ~def:None (nl_sp -+ (
            (keyword "else" -+ body) |||
            (keyword "elsif" -+ here ++ if_ >>:
                fun (loc, desc) -> [ { stmt_loc = loc ; stmt = Expr { loc ; desc } } ])) >>:
            Option.some) >>:
        fun ((cond, then_), else_) -> If { cond ; then_ ; else_ }) in
    (* Its cases, separated by bars that may start or end lines, then maybe
     * an [else], with or without a bar before it: *)
    let case =
        let sep = nl_sp -- item '|' -- nl_sp in
        let arm =
            here ++ (identifier >>= fun s -> if is_keyword s then fail else return s) ++
            body >>: fun ((arm_loc, ctor), body) -> { arm_loc ; ctor ; body } in
        let else_ = keyword "else" -+ body in
        let arms =
            (repeat ~min:1 ~sep arm ++
             optional ~def:None ((sep ||| nl_sp) -+ else_ >>: Option.some)) |||
            (else_ >>: fun b -> [], Some b) in
        (params_of expr ~unnamed:false "case" [ "var" ] >>:
            fun p -> Option.map (var_name "variable name") (p "var")) +- sp ++
        expr ++ (nl_sp -+ arms |? "constructor") >>:
        fun ((var, subject), (arms, else_)) -> Case { var ; subject ; arms ; else_ } in
    let field = identifier +- sp +- item ':' +- nl_sp ++ expr in
    let atom =
        (here ++ literal >>: fun (loc, l) -> { loc ; desc = Lit l }) |||
        bytes_lit |||
        string_lit expr |||
        in_ '(' self ')' |||
        (* The items of an array, or the keys and values of a map: *)
        (here ++ in_ '[' (list_of (
            expr ++ optional ~def:None (
                sp -- item ':' -- nl_sp -+ expr >>: Option.some))) ']' >>:
            fun (loc, es) ->
                let desc =
                    if List.for_all (Option.is_none % snd) es then
                        Array (List.map fst es)
                    else if List.for_all (Option.is_some % snd) es then
                        Map (List.map (fun (k, v) -> k, Option.get v) es)
                    else reject "Items without keys in a map" in
                { loc ; desc }) |||
        (here ++ in_ '{' (
            repeat ~min:1 ~sep:(nl_sp -- item ',' -- nl_sp) field +-
            optional ~def:() (nl_sp -- item ',')) '}' >>:
            fun (loc, fs) -> { loc ; desc = Record fs }) |||
        (here ++ block >>: fun (loc, b) -> { loc ; desc = Block b }) |||
        (here ++ (keyword "if" -+ if_) >>: fun (loc, desc) -> { loc ; desc }) |||
        (here ++ (keyword "case" -+ case) >>: fun (loc, desc) -> { loc ; desc }) |||
        (here ++ function_name ++ args expr >>:
            fun ((loc, f), args) -> { loc ; desc = Call (f, args) }) |||
        unknown_function (args expr) |||
        (here ++ (name >>= fun s -> if is_constructor s then return s else fail) ++
         in_ '(' (optional ~def:None (expr >>: Option.some)) ')' >>:
            fun ((loc, c), e) -> { loc ; desc = Construct (c, e) }) |||
        (here ++ (name ||| predefined_var) >>:
            fun (loc, n) -> { loc ; desc = Var n }) |||
        (here ++ constant >>: fun (loc, (n, l)) -> { loc ; desc = Constant (n, l) }) |||
        (* A layer that is not followed by what makes it a value is not an
         * error of its own; whatever is expected there is: *)
        (quiet (here ++ optional ~def:0 carets ++ known_layer ++
                optional ~def:0 carets +- check (item '.' ||| item ']')) >>:
            fun (((loc, before), name), after) ->
                let desc =
                    match before, after with
                    | 0, n -> Layer { name ; from_start = false ; nth = n }
                    | n, 0 -> Layer { name ; from_start = true ; nth = n - 1 }
                    | _ -> reject "Carets on both sides of %s"
                                    (Layer_name.to_string name) in
                { loc ; desc }) in
    let bound = optional ~def:None (expr >>: Option.some) in
    let postfix =
        atom ++ repeat_greedy ~sep:none (
            (item '.' -+ identifier >>: fun f -> `Field f) |||
            (in_ '[' (bound ++ optional ~def:None (
                sp -- item ':' -- nl_sp -+ bound >>: Option.some)) ']' >>= function
                | Some i, None -> return (`Index i)
                | from, Some to_ -> return (`Slice (from, to_))
                | None, None -> fail)) >>:
        fun (a, ops) ->
            List.fold_left (fun e -> function
                | `Field f -> { loc = a.loc ; desc = Field (e, f) }
                | `Index i -> { loc = a.loc ; desc = Index (e, i) }
                | `Slice (from, to_) ->
                    { loc = a.loc ; desc = Slice (e, from, to_) }) a ops in
    let unary = fix (fun unary ->
        (here ++ (item '!' -- sp -+ unary) >>:
            fun (loc, e) -> { loc ; desc = Unop (Not, e) }) |||
        (* Not before a digit, which would be a literal: *)
        (here ++ (item '-' -- nay (char_if "" is_digit) -- sp -+ unary) >>:
            fun (loc, e) -> { loc ; desc = Unop (Neg, e) }) |||
        postfix) in
    let product =
        left_assoc (op "*" Mul ||| op "/" Div ||| op "%" Mod) unary in
    let sum = left_assoc (op "+" Add ||| op "-" Sub) product in
    let bit_and = left_assoc (op_not_before "&" '&' BitAnd) sum in
    let bit_xor = left_assoc (op "^" BitXor) bit_and in
    let bit_or = left_assoc (op_not_before "|" '|' BitOr) bit_xor in
    let comparison =
        let cmp =
            op "==" Eq ||| op "!=" Ne |||
            op_not_before "<" '=' Lt ||| op "<=" Le |||
            op_not_before ">" '=' Gt ||| op ">=" Ge in
        let cmp =
            if cond then
                cmp ||| (item '=' -- nay (item '=' ||| item '~') >>: fun () -> Eq)
            else cmp in
        bit_or ++ optional ~def:None (maybe_next (
            (cmp +- nl_sp ++ bit_or >>: fun (op, r) -> `Cmp (op, r)) |||
            (word "=~" -- nl_sp -+ pattern >>: fun p -> `Match p)) >>:
            Option.some) >>:
        fun (l, rhs) ->
            match rhs with
            | None -> l
            | Some (`Cmp (op, r)) -> { loc = l.loc ; desc = Binop (op, l, r) }
            | Some (`Match p) -> { loc = l.loc ; desc = Matches (l, p) } in
    let conjunction = left_assoc (op "&&" And) comparison in
    left_assoc (op "||" Or) conjunction |? "expression"

(* From the root ([/]), or else down the current stack ([../] each): *)
let anchor =
    (slash >>: fun () -> Absolute) |||
    (repeat_greedy ~sep:none (word ".." -- slash) >>:
        fun l -> Relative (List.length l))

let make_pattern cond_expr =
    let conditions =
        in_ '(' (list_of cond_expr) ')' >>: function
            | [] -> None
            | c :: cs ->
                Some (List.fold_left (fun a b ->
                    { loc = a.loc ; desc = Binop (And, a, b) }) c cs) in
    let layer =
        here ++ layer_name ++ optional ~def:false (item '!' >>: fun _ -> true) ++
        optional ~def:None conditions >>:
        fun (((pl_loc, pl_name), pl_manual), cond) ->
            { pl_loc ; pl_name ; pl_manual ; cond } in
    here ++ anchor ++ repeat ~min:1 ~sep:(maybe_next (slash -- nl_sp)) layer >>:
    (fun ((pat_loc, anchor), pat_layers) -> { pat_loc ; anchor ; pat_layers })
    |? "pattern"

let expr, set_expr = forward ()
let cond_expr, set_cond_expr = forward ()
let block, set_block = forward ()
let pattern = make_pattern cond_expr
(* Separated by bars that may start or end lines, in parentheses or not: *)
let patterns =
    fix (fun patterns ->
        repeat ~min:1 ~sep:(nl_sp -- item '|' -- nl_sp)
            ((pattern >>: fun p -> [ p ]) |||
             (quiet (item '(') -- nl_sp -+ patterns +- nl_sp +- item ')') |? "pattern") >>:
        List.concat)
let () =
    set_expr (make_expr ~cond:false ~self:expr ~expr ~pattern ~block) ;
    set_cond_expr (make_expr ~cond:true ~self:cond_expr ~expr ~pattern ~block)

(** {2 Statements} *)

let params ?unnamed ?pattern form names = params_of expr ?unnamed ?pattern form names

let stmt_sep = sp -- (item '\n' ||| item ';') -- nl_sp |? "end of statement"

let layer =
    here ++ layer_name ++ optional ~def:false (item '!' >>: fun _ -> true) ++
    optional ~def:[] (args expr) >>:
    fun (((layer_loc, layer_name), manual), options) ->
        { layer_loc ; layer_name ; manual ; options }

let assign_op =
    op ":=" None |||
    op "+=" (Some Add) ||| op "-=" (Some Sub) ||| op "*=" (Some Mul) |||
    op "/=" (Some Div) ||| op "%=" (Some Mod) ||| op "|=" (Some BitOr) |||
    op "&=" (Some BitAnd) ||| op "^=" (Some BitXor)

let stmt =
    let body = sp -+ block in
    (* Of first and on, separated by bars that may start or end lines: *)
    let cases = repeat ~min:1 ~sep:(nl_sp -- item '|' -- nl_sp) (patterns ++ body) in
    let with_loc p = here ++ p >>: fun (stmt_loc, stmt) -> { stmt_loc ; stmt } in
    (* Any name, that is then refused if reserved, for a better message: *)
    let variable =
        identifier >>= fun s -> if is_keyword s then fail else return s in
    (* A name and a parenthesis, which only a stack (or an unknown function)
     * starts with, unless a function's or a constructor's: *)
    let call_of_no_function =
        quiet (identifier >>= fun s ->
            if is_keyword s || is_in functions s ||
               is_constructor s && not (is_reserved s) then fail else return ()) --
        item '(' in
    (* The variable of a foreach, unnamed: a name then, after a space, what
     * starts its items rather than continues an expression: *)
    let foreach_var =
        quiet (variable +- char_if "space" (fun c -> c = ' ' || c = '\t') +-
               sp +- check (char_if "" (fun c ->
                   is_word c || c = '[' || c = '(' || c = '"'))) in
    with_loc (
        (* Alone, a call rather than a stack, of an unknown layer: *)
        unknown_function (quiet (args expr +-
            check (sp -- ((item '\n' ||| item ';' ||| item '}' >>: ignore) ||| eof)))) |||
        (* A stack sends a packet if its top layer is terminal, and is
         * otherwise that of the block that follows: *)
        (anchor ++
         repeat ~min:1 ~sep:(maybe_next (slash -- nl_sp)) layer >>=
            fun (anchor, layers) ->
                let top = (List.last layers).layer_name in
                if terminal top then
                    (* Refused at the brace, rather than at the block's end: *)
                    optional ~def:() (sp -- item '{' >>: fun _ ->
                        reject "%s" (no_block_after anchor layers)) >>:
                    fun () -> Stack { anchor ; layers ; body = None }
                else
                    optional ~def:None (body >>: Option.some) >>: function
                    | None -> reject "%s" (not_a_message ~block:true anchor layers)
                    | body -> Stack { anchor ; layers ; body }) |||
        (nay call_of_no_function -+ expr >>: fun e -> Expr e) |||
        (variable ++ maybe_next (
            item '=' -- nay (item '=' ||| item '~') -- nl_sp -+ expr) >>:
            fun (v, e) ->
                Declare ((if List.mem v self_declared then v else check_var v), e)) |||
        (* The packet of a stack, as it leaves: what starts like a stack
         * rather than an expression, up to the end of the statement: *)
        (let assign =
            (item '=' -- nay (item '=' ||| item '~') >>: fun _ -> true) |||
            (item ':' -- item '=' >>: fun _ -> false) in
         let stack_start =
            slash ||| (item '.' -- item '.') |||
            (identifier >>= fun s ->
                if not (is_keyword s) && Layer_name.of_string s <> None
                then return () else fail) in
         check (quiet (variable -- sp -- assign -- nl_sp -- stack_start)) -+
         variable ++ maybe_next assign +- nl_sp ++
         anchor ++ repeat ~min:1 ~sep:(maybe_next (slash -- nl_sp)) layer +-
         check (sp -- ((item '\n' ||| item ';' ||| item '}' >>: ignore) ||| eof)) >>:
            fun (((v, declare), anchor), layers) ->
                let top = (List.last layers).layer_name in
                if terminal top then
                    Capture { var = check_var v ; declare ; anchor ; layers }
                else
                    reject "%s" (not_a_message anchor layers)) |||
        (* Quiet, not to expect indices after any name: *)
        (variable ++ repeat_greedy ~sep:none (
            quiet (item '[') -- nl_sp -+ expr +- nl_sp +- item ']') >>=
         fun (v, is) ->
            maybe_next (
                (assign_op +- nl_sp ++ expr >>:
                    fun (op, e) -> Assign (check_var v, is, op, e)) |||
                (if is = [] then fail else
                 item '=' -- nay (item '=' ||| item '~') >>:
                    fun _ -> reject "An item is not declared (:= changes it)"))) |||
        (keyword "repeat" -+ params "repeat" [ "var" ; "count" ; "every" ; "for" ] ++
         body >>: fun (p, body) ->
            Repeat { var = Option.map (var_name "variable name") (p "var") ;
                     count = p "count" ; every = p "every" ; for_ = p "for" ;
                     body }) |||
        (keyword "foreach" -+
         (optional ~def:None (sp -+ foreach_var >>: Option.some) ++ here ++
          params ~unnamed:false "foreach" [ "var" ; "every" ; "for" ] ++ here >>=
          (* After the parameters too, if any, not to read it twice: *)
          fun (((v1, l1), p), l2) ->
            optional ~def:None (
                if v1 = None && l1 <> l2 then sp -+ foreach_var >>: Option.some
                else fail) >>: fun v2 -> (v1, p), v2) +- sp ++
         expr ++ body >>: fun ((((v1, p), v2), items), body) ->
            let var =
                match v1, v2, Option.map (var_name "variable name") (p "var") with
                | None, None, v -> v
                | (Some _ as v), None, None | None, (Some _ as v), None ->
                    Option.map check_var v
                | _ -> reject "Variable name of foreach given twice" in
            Foreach { var ; items ; every = p "every" ; for_ = p "for" ;
                      body }) |||
        (keyword "retry" -+ params "retry" [ "max" ] ++ body >>:
            fun (p, body) -> Retry { max = p "max" ; body }) |||
        (keyword "catch" -+ body >>: fun body -> Catch body) |||
        (keyword "break" -+ params "break" [ "depth" ] >>:
            fun p -> Break { depth = p "depth" }) |||
        (keyword "wait" -+ params "wait" [ "dur" ] >>:
            fun p ->
                match p "dur" with
                | Some d -> Wait d
                | None -> reject "wait needs a duration") |||
        (keyword "expect" -+ params ~pattern:true "expect" [ "timeout" ] +- sp ++ patterns ++
         body >>: fun ((p, patterns), body) ->
            Expect { timeout = p "timeout" ; patterns ; body }) |||
        (keyword "first" -+ params ~pattern:true "first" [ "timeout" ] +- sp ++
         cases >>: fun (p, cases) -> First { timeout = p "timeout" ; cases }) |||
        (keyword "on" -+
         params ~pattern:true "on" [ "for" ; "linger" ; "timeout" ; "max" ] +- sp ++
         cases >>: fun (p, cases) ->
            On { for_ = p "for" ; linger = p "linger" ; timeout = p "timeout" ;
                 max = p "max" ; cases })) |? "statement"

let () =
    set_block (
        in_ '{' (repeat ~sep:stmt_sep stmt +- optional ~def:() (sp -- item ';'))
            '}' |? "block")

let program =
    nl_sp -+ repeat ~sep:stmt_sep stmt +- optional ~def:() (sp -- item ';') +-
    nl_sp +- (eof |? "end of statement")

(* Labels of what is too small to be worth telling: *)
let low_level =
    [ "" ; "nay" ; "check" ; "eof" ; "letter" ; "letter or digit" ;
      "end of word" ; "space" ; "anything" ]

(* What is in the way, from the contexts (innermost first) it was looked for
 * in: *)
let message_of what =
    let meaningful = List.filter (fun c -> not (List.mem c low_level)) in
    let in_ = function [] -> "" | c :: _ -> " in "^ c in
    match what with
    | [] -> "Syntax error"
    | w :: _ when String.starts_with w rejection_mark -> String.lchop w
    | "nay" :: ctx -> "Unexpected input"^ in_ (meaningful ctx)
    | what ->
        (match meaningful what with
        | [] -> "Syntax error"
        | w :: ctx ->
            let ctx = List.filter ((<>) w) ctx in
            let w = if String.length w = 1 then quoted (String.escaped w)
                    else w in
            "Expected "^ w ^ in_ ctx)

(* That text read with [p], or where and why it is not: *)
let parse_with p text =
    match to_result (p [] None Parsers.no_error_correction
                       (stream_of_string text)) with
    | Ok (p, _) -> Ok p
    | Error (NoSolution None) ->
        Error { where = { line = 1 ; column = 1 } ; message = "Syntax error" }
    | Error (NoSolution (Some e)) ->
        Error { where = loc_of e.where ; message = message_of e.what }
    | Error (Ambiguous rs) ->
        Error { where = { line = 1 ; column = 1 } ;
                message = Printf.sprintf "The program can be read in %d ways"
                                         (List.length rs) }
    | Error (Approximation _) ->
        (* Only with error correction, which is not asked for *)
        assert false

(** Parse that text, or tell where and why it does not parse. *)
let parse text = parse_with program text

(** Parse that text as patterns, alternatives. *)
let parse_patterns text =
    parse_with (sp -+ patterns +- sp +- (eof |? "end of pattern")) text

(* [reads text] is how the program in that text reads back, or the error;
 * [formats text] is that program with only the parentheses it needs. *)
(*$inject
  let reads text =
      match parse text with
      | Ok p -> Crafty_ast.string_of_program p
      | Error e -> IO.to_string print_error e
  let formats text =
      match parse text with
      | Ok p -> Crafty_ast.string_of_program ~all:false p
      | Error e -> IO.to_string print_error e
*)

(*$= reads & ~printer:identity
  "x = ((1 + (2 * 3)) - ((4 / 2) % 3))\n" (reads "x = 1 + 2 * 3 - 4 / 2 % 3")
  "x = (a || (b && (c == (d | (e ^ (f & (g + h)))))))\n" \
    (reads "x = a || b && c == d | e ^ f & g + h")
  "x = ((!a) && ((- b) < 3))\n" (reads "x = !a && -b < 3")
  "x = (((-1 + -2.5) - -3s) - (- 1))\n" (reads "x = -1 + -2.5 - -3s - - 1")
  "x = (3 - 1)\n" (reads "x = 3 -1")
  "x = ((3 & 4) == 4)\n" (reads "x = 3 & 4 == 4")
  "x = (MATCH[IP^].src + MATCH[^^IP].dst)\n" \
    (reads "x = MATCH[IP^].src + MATCH[^^IP].dst")
  "x = a.b.c[0].d\n" (reads "x = a.b.c[0].d")
  "x = (SYN | ack)\n" (reads "x = SYN | ack")
  "x = (MATCH[IP].src + LAST[TCP].seq)\n" \
    (reads "x = MATCH[ip].src + LAST[TCP].seq")
  "x = (length(MATCH) * rand(max=3))\n" (reads "x = length(MATCH) * rand(max=3)")
  "x = ((((31 + 15) + 5) + 1500.0) + 0.002)\n" \
    (reads "x = 0x1F + 0o17 + 0b101 + 1.5e3 + 2e-3")
  "x = ((1m30s + 10ms) + 1µs500ns)\n" (reads "x = 1m30s + 10ms + 1.5µs")
  "x = [(1.2.3.4 == y), AA:BB:CC:DD:EE:FF]\n" \
    (reads "x = [1.2.3.4 == y, aa:bb:cc:dd:ee:ff]")
  "x = [#1e, #e7]\nx = #0f\n" (reads "x = #1ee7 # a comment\nx = #f")
  "x = \"a ${(x + 1)} b \\${not} A\\$\"\n" \
    (reads "x = \"a ${x + 1} b \\${not} \\x41$\"")
  "x = (1 + 2)\ny = [1, 2]\nz = {a: 1, b: \"x\"}\n" \
    (reads "x = 1 +\n  2\ny = [1,\n 2,\n]\nz = {a: 1, b: \"x\",}")
  "x = a\n/IP {\n}\n" (reads "x = a\n/IP {}")
  "/IP/UDP/Bytes(\"x\")\n{\n  y = 1\n}\n" (reads "/IP/UDP/Bytes(\"x\")\n{ y = 1 }")
  "IP!(ttl=1)/TCP!(flags=2)/Bytes(\"x\")\n" \
    (reads "IP!(ttl=1)\\TCP!(flags=2)/Bytes(\"x\")")
  "../../IP!/TCP!(flags=4)/Bytes\n" (reads "../../IP!/TCP!(flags=4)/Bytes()")
  "x = (y =~ /IP/UDP(dport == 53))\n" (reads "x = y =~ /IP/UDP(dport = 53)")
  "retry max=3 {\n  break\n}\n" (reads "retry 3 {\n  break\n}")
  "catch {\n  x = 1\n}\n" (reads "catch { x = 1 }")
  "if x == 1 {\n  y := 1\n}\n" (reads "if x == 1 { y := 1 }")
  "if x {\n} else {\n  y := 2\n}\n" (reads "if x {}\nelse { y := 2 }")
  "if a {\n} elsif b {\n} elsif c && d {\n} else {\n}\n" \
    (reads "if a {} elsif b {}\n  elsif c && d {} else {}")
  "if a {\n} elsif b {\n}\n" (reads "if a {} else { if b {} }")
  "if a {\n} else {\n  if b {\n  }\n  x := 1\n}\n" \
    (reads "if a {} else { if b {}; x := 1 }")
  "repeat {\n  if I > 3 {\n    break\n  }\n}\n" \
    (reads "repeat { if I > 3 { break } }")
  "wait dur=10ms\nwait dur=(1s * n)\n" (reads "wait 10ms\nwait dur=1s * n")
  "repeat var=j {\n  break depth=2\n}\n" (reads "repeat var=\"j\" { break 2 }")
  "repeat var=i count=3 every=1ms for=1s {\n  print(\"${i}\")\n}\n" \
    (reads "repeat var=i count=3 every=1ms for=1s { print(\"${i}\") }")
  "repeat count=(n * 2) every=(1s / n) {\n}\n" \
    (reads "repeat every=1s / n count=n*2 {}")
  "foreach t [3, 5, 6] {\n  print(\"${t}\")\n}\n" \
    (reads "foreach t [3, 5, 6] { print(\"${t}\") }")
  "foreach t every=1s ts {\n}\nforeach t for=1m ts {\n}\nforeach t ts {\n}\n" \
    (reads "foreach t every=1s ts {}\nforeach for=1m t (ts) {}\nforeach var=t ts {}")
  "foreach t ts {\n}\nforeach a - b {\n}\n" (reads "foreach t\tts {}\nforeach a - b {}")
  "foreach every=(1s / n) for=1m ttls {\n}\n" (reads "foreach for=1m every=1s / n ttls {}")
  "foreach x a.b[(i + 1)] {\n}\n" (reads "foreach var=\"x\" a.b[i + 1] {}")
  "x[1][(i + 1)] += 2\nx[0] := [1]\n" (reads "x[1][i+1] += 2\nx[0]:=[1]")
  "x = [1: \"a\", (2 + 3): \"b\"]\n" (reads "x = [1:\"a\", 2+3 : \"b\",]")
  "x = [true: 1, 1.2.3.4: 2, AA:BB:CC:DD:EE:FF: 3, y: [4]]\n" \
    (reads "x = [true: 1, 1.2.3.4: 2, aa:bb:cc:dd:ee:ff: 3, y: [4]]")
  "on timeout=1s max=3 ../UDP {\n  n += 1\n  m := 2\n}\n" \
    (reads "on max=3 timeout=1s ../UDP { n += 1; m := 2 }")
  "on for=1s timeout=100ms ../UDP {\n}\non linger=1s ../UDP {\n}\n" \
    (reads "on timeout=100ms for=1s ../UDP {}\non linger=1s ../UDP {}")
  "expect UDP((IP^.ttl == 3) && (^IP.src == 1.2.3.4)) {\n}\n" \
    (reads "expect UDP(IP^.ttl = 3, ^IP.src == 1.2.3.4) {}")
  "expect ../../TCP!(flags & RST) {\n}\n" \
    (reads "expect ../../TCP!(flags & RST) {}")
  "expect timeout=5s /IP(src == x)/UDP {\n}\n" \
    (reads "expect 5s /IP(src=x)/UDP {}")
  "expect timeout=5s /IP/UDP {\n}\n" (reads "expect timeout=5s /IP/UDP {}")
  "p = Bytes(\"a\")\n" (reads "p = Bytes(\"a\")")
  "p := ../../IP!/UDP(dst=7)/Bytes(\"a\")\n" (reads "p:=../../IP!/UDP(dst=7)/Bytes(\"a\")")
  "line 1, column 13: UDP is not a terminal layer, therefore /IP!/UDP is not a complete message that could be sent: it needs a terminal layer on top (Bytes)." (reads "p = /IP!/UDP")
  "first timeout=1s Bytes(\"a\") {\n} | Bytes(\"b\") {\n  x := 1\n}\n" \
    (reads "first 1s Bytes(\"a\") {} | Bytes(\"b\") { x := 1 }")
  "first Bytes(data == \"a\") {\n} | ../ICMP {\n} | /IP(src == x)/UDP {\n}\nx := 1\n" \
    (reads "first Bytes(data = \"a\") {}\n| ../ICMP {} |\n/IP(src=x)/UDP {}\nx := 1")
  "on for=1s Bytes {\n} | ../ICMP | /IP/UDP {\n  x := 1\n}\n" \
    (reads "on for=1s Bytes {} | (../ICMP | /IP/UDP) { x := 1 }")
  "expect Bytes | ../ICMP | /IP/UDP {\n}\n" \
    (reads "expect ((Bytes)\n  | (../ICMP | /IP/UDP)) {}")
*)

(* Blocks, if and case are expressions, and an expression is a statement;
 * braces with no field are a block: *)
(*$= reads & ~printer:identity
  "x = {\n  y = 2\n  y * 3\n}\n" (reads "x = { y = 2; y * 3 }")
  "x = {\n}\ny = {a: 1}\n" (reads "x = {}\ny = {a: 1,}")
  "x == 1\n{\n  rand(3)\n}\n" (reads "x == 1\n{ rand(3) }")
  "x = if a > 1 {\n  1\n} else {\n  2.5\n}\n" (reads "x = if a > 1 { 1 } else { 2.5 }")
  "x = (1 + if a {\n  1\n} elsif b {\n  2\n} else {\n  3\n})\n" \
    (reads "x = 1 + if a { 1 } elsif b { 2 }\n  else { 3 }")
  "x = {\n  y = if a {\n    1\n  } else {\n    2\n  }\n}.f\n" \
    (reads "x = { y = if a { 1 } else { 2 } }.f")
  "case I IP {\n  print(\"ip\")\n} | UDP {\n} else {\n  x := 1\n}\n" \
    (reads "case I\n  IP { print(\"ip\") }\n  | UDP {} |\n  else { x := 1 }")
  "x = case var=l MATCH[0] Eth {\n  l.src\n} else {\n  0\n}\n" \
    (reads "x = case var=\"l\" MATCH[0] Eth { l.src } else { 0 }")
  "x = case y IP {\n  1\n} | TCP {\n  2\n} else {\n  3\n}\n" \
    (reads "x = case y IP { 1 } | TCP { 2 }\n  else { 3 }")
  "case x else {\n}\n" (reads "case x else {}")
  "x = Ok(1 + 2)\ny = [Pending, Err(\"a\")]\n" (reads "x = Ok(1 + 2)\ny = [Pending, Err(\"a\")]")
  "x = [Pending(), Pending]\n" (reads "x = [Pending( ), Pending]")
  "print(case x Bytes {\n  \"b\"\n} else {\n  \"?\"\n})\n" \
    (reads "print(case x Bytes { \"b\" } | else { \"?\" })")
*)

(*$= formats & ~printer:identity
  "x = 1 + 2 * 3 - 4 / 2 % 3\n" (formats "x = 1 + 2 * 3 - 4 / 2 % 3")
  "x = (1 + 2) * 3\ny = 1 - (2 - 3)\nz = 1 - 2 - 3\n" \
    (formats "x = (1 + 2) * 3\ny = 1 - (2 - 3)\nz = (1 - 2) - 3")
  "x = a || b && c == d | e ^ f & g + h\n" \
    (formats "x = a || b && c == d | e ^ f & g + h")
  "x = (a || b) && c\ny = (a == b) == c\n" (formats "x = (a || b) && c\ny = (a == b) == c")
  "x = !a && -b < 3\ny = !(a && b)\nz = -(1 + x)\nw = - 1\n" \
    (formats "x = !a && -b < 3\ny = !(a && b)\nz = -(1 + x)\nw = - 1")
  "x = (a + 1).b + [1 + 2][0]\n" (formats "x = (a + 1).b + [1 + 2][0]")
  "x = \"a ${x + 1} b\"\nassert(a + 1 == 2)\n" \
    (formats "x = \"a ${x + 1} b\"\nassert(a + 1 == 2)")
  "x = y =~ /IP && z\ny = (a == b) =~ /IP\n" (formats "x = (y =~ /IP) && z\ny = (a == b) =~ /IP")
  "wait 1s * n\nrepeat count=n * 2 {\n}\n" (formats "wait dur=1s * n\nrepeat count=n*2 {}")
  "if x & FLAG {\n} elsif x == 1 || y {\n}\n" \
    (formats "if (x & FLAG) {} elsif (x == 1) || y {}")
  "expect UDP(IP^.ttl == 3 && (a || b)) {\n}\n" \
    (formats "expect UDP(IP^.ttl = 3, a || b) {}")
*)

(* Times, printed in UTC; without a zone, in the local time of the host: *)
(*$= reads & ~printer:identity
  "x = 2026-10-20T22:02:45Z\n" (reads "x = 2026-10-20T22:02:45Z")
  "x = 2026-10-20T20:02:45.25Z\n" (reads "x = 2026-10-20T22:02:45.25+02:00")
  "x = (2026-10-20T23:00:00Z - 2026-10-20T22:00:00Z)\n" \
    (reads "x = 2026-10-20t22:30-00:30 - 2026-10-20T22:00:00z")
  "x = (2026-10-20T22:02:45Z - 1)\n" (reads "x = 2026-10-20T22:02:45Z-1")
  "line 1, column 22: Invalid time: No day 30 in month 2 of 2026" \
    (reads "x = 2026-02-30T00:00Z")
*)
(*$T reads
  reads "x = 2026-10-20T22:02:45" = \
    "x = "^ Clock.Wall.(to_iso8601 (of_date 2026 10 20 22 2 45.)) ^"\n"
*)

(* Formatted, a program reads back as itself: *)
(*$T formats
  List.for_all (fun t -> reads (formats t) = reads t) [ \
    "x = 1 + 2 * 3 - 4 / 2 % 3" ; "x = a || b && c == d | e ^ f & g + h" ; \
    "x = !a && -b < 3" ; "x = -1 + -2.5 - -3s - - 1" ; "x = 3 -1" ; \
    "x = 3 & 4 == 4" ; "x = MATCH[IP^].src + MATCH[^^IP].dst" ; \
    "x = length(MATCH) * rand(max=3)" ; "x = - -1 - - (2 - 3)" ; \
    "x = 1m30s + 10ms + 1.5\xc2\xb5s" ; "x = [1.2.3.4 == y, aa:bb:cc:dd:ee:ff]" ; \
    "x = #1ee7 # a comment\nx = #f" ; "x = \"a ${x + 1} b \\${not} \\x41$\"" ; \
    "x = y =~ /IP/UDP(dport = 53)" ; "wait dur=1s * n" ; \
    "repeat every=1s / n count=n*2 {}" ; "foreach t every=1s * 2 [1, 2] {}" ; \
    "on max=3 timeout=1s ../UDP { n += 1; m := 2 }" ; \
    "on for=1s ../UDP {}\non linger=2s * n ../UDP {}" ; \
    "expect UDP(IP^.ttl = 3, ^IP.src == 1.2.3.4) {}" ; \
    "expect ../../TCP!(flags & RST) {}" ; "IP!(ttl=1)/TCP!(flags=2)/Bytes(\"x\")" ; \
    "/IP/UDP/Bytes(\"x\")\n{ y = !(a == b) }" ; \
    "if a & 1 {} elsif (b || c) && d { x := 1 }\nelse { if e {} }" ; \
    "first timeout=2s * n Bytes(\"a\") {} | ../TCP!(flags & (SYN | RST)) {}" ; \
    "x = 1 + if a { { y = 1; y * 2 } } elsif b { 2 } else { 3 }" ; \
    "x = case var=l MATCH[0] Eth { l.src } | IP { if a { 1 } else { 2 } } | else { 0 }" ; \
    "x = case y IP { 1 }\nelse { 2 }" ; \
    "x = [Ok(1 + 2), Pending, Pending()]\ny = Got({a: Ok(-1)})" ; \
    "y = [{a: 1}, {}]" ]
*)

(* The errors, where they are found: *)
(*$= reads & ~printer:identity
  "line 1, column 17: Expected expression in arguments" \
    (reads "/IP(dst=1.2.3.4/UDP")
  "line 1, column 11: Expected end of statement" (reads "print(\"a\"))")
  "line 1, column 16: UDP is not a terminal layer, therefore /IP/UDP is not a complete message that could be sent: it needs a terminal layer on top (Bytes), or a block in which to stack one." \
    (reads "/IP/UDP(dst=53)")
  "line 1, column 18: Bytes is a terminal layer, therefore /IP/UDP/Bytes is a complete message. No further layer can be stacked on top of it, therefore it cannot open a block.\n  Do you mean \"/IP/UDP/Bytes()\", \"/IP/UDP { Bytes() ... }\", or \"expect /IP/UDP/Bytes { ... }\"?" \
    (reads "/IP/UDP/Bytes() {}")
  "line 4, column 21: Bytes is a terminal layer, therefore /IP/UDP/Bytes is a complete message. No further layer can be stacked on top of it, therefore it cannot open a block.\n  Do you mean \"/IP/UDP/Bytes(\"b\")\", \"/IP/UDP { Bytes(\"b\") ... }\", or \"expect /IP/UDP/Bytes(\"b\") { ... }\"?" \
    (reads "/IP/UDP/Bytes(\"a\")\n{\n}\n/IP/UDP/Bytes(\"b\") {\n  x = 1\n}")
  "line 1, column 12: Expected end of statement" (reads "print(\"a\") print(\"b\")")
  "line 1, column 7: Expected end of statement" (reads "x = 1 2")
  "line 1, column 5: Expected expression in statement" (reads "x = ")
  "line 1, column 8: Expected expression in statement" (reads "x = 1 +")
  "line 1, column 11: Expected ')' in expression" (reads "x = (1 + 2")
  "line 1, column 10: Expected ']' in expression" (reads "x = [1, 2")
  "line 1, column 14: Expected ':' in expression" (reads "x = {a: 1, b 2}")
  "line 2, column 1: Expected '}' in block" \
    (reads "expect Bytes(\"x\") { print(\"ok\")\n")
  "line 1, column 19: Expected pattern in statement" (reads "expect timeout=5s {\n}")
  "line 1, column 13: Unknown parameter cnt for repeat (expected var, count, every, for)" \
    (reads "repeat cnt=3 {\n}")
  "line 1, column 11: Expected '{' in block" (reads "foreach {}")
  "line 1, column 19: Expected '{' in block" (reads "foreach var=t ttls")
  "line 1, column 16: Unknown parameter count for foreach (expected var, every, for)" \
    (reads "foreach count=3 ttls {}")
  "line 1, column 22: Variable name of foreach given twice" \
    (reads "foreach t var=u ts {}")
  "line 1, column 21: MATCH is a reserved name" (reads "foreach MATCH [1] {}")
  "line 1, column 18: Parameter max of retry given twice" \
    (reads "retry max=1 max=2 {\n}")
  "line 1, column 10: Parameter depth of break given twice" (reads "break 2 3")
  "line 1, column 6: Parameters of on must be named" \
    (reads "on 1s Bytes(\"x\") {\n}")
  "line 1, column 18: Expected '=' in statement" (reads "repeat count=3 x {\n}")
  "line 1, column 7: IP is not a terminal layer, therefore IP is not a complete message that could be sent: it needs a terminal layer on top (Bytes)." (reads "x = IP")
  "line 1, column 7: ip is a reserved name" (reads "ip = 3")
  "line 1, column 11: print is a reserved name" (reads "print += 3")
  "line 1, column 7: An item is not declared (:= changes it)" (reads "x[0] = 1")
  "line 1, column 14: Items without keys in a map" (reads "x = [1: 2, 3]")
  "line 1, column 10: MATCH is a reserved name" (reads "MATCH = 1")
  "line 1, column 19: LAST is a reserved name" (reads "repeat var=LAST {}")
  "line 1, column 20: tcp is a reserved name" (reads "repeat var=\"tcp\" {}")
  "line 1, column 9: Unknown layer HTTP" (reads "/IP/HTTP {}")
  "line 1, column 8: Unknown layer UPD, do you mean UDP?" (reads "/IP/UPD {}")
  "line 1, column 13: Unknown layer Bytse, do you mean Bytes?" (reads "expect Bytse {}")
  "line 1, column 13: Unknown layer Bytse, do you mean Bytes?" (reads "expect Bytse(\"x\") {}")
  "line 1, column 24: Unknown layer Bytse, do you mean Bytes?" (reads "expect timeout=1s Bytse {}")
  "line 1, column 9: Unknown layer Bytse, do you mean Bytes?" (reads "on Bytse {}")
  "line 1, column 12: Unknown layer Bytse, do you mean Bytes?" (reads "first Bytse {} | Bytes {}")
  "line 1, column 8: Expected pattern in statement" (reads "expect 2s {}")
  "line 1, column 11: Unknown function pirnt, do you mean print?" (reads "pirnt(\"x\")")
  "line 1, column 7: Unknown function foo" (reads "foo(1)")
  "line 1, column 15: Unknown function foo" (reads "x := 1; foo(1); y := 2")
  "line 1, column 4: Unknown layer foo" (reads "foo(1)/Bytes(\"x\")")
  "line 1, column 4: Unknown layer foo" (reads "foo(1) {}")
  "line 1, column 24: Unknown function get" (reads "x = get(a=[1], index=0)")
  "line 1, column 14: Unknown function foo" (reads "x = 1 + foo()")
  "line 1, column 18: Unknown function foo" (reads "expect UDP(foo(1)) {}")
  "line 1, column 15: Unknown function foo" (reads "/IP(dst=foo(1))/UDP(dst=1)/Bytes(\"x\")")
  "line 1, column 16: Unknown function foo" (reads "print(\"${foo(2)}\")")
  "line 1, column 11: Carets on both sides of IP" (reads "x = a[^IP^]")
  "line 1, column 8: Expected constructor in expression" (reads "case x {}")
  "line 1, column 10: Expected '{' in block" (reads "case x IP")
  "line 2, column 15: MATCH is a reserved name" (reads "x = 1\ncase var=MATCH x IP {}")
  "line 2, column 18: Expected expression in statement" (reads "x = 1\ncase x else {} | IP {}")
  "line 1, column 7: Expected pattern in statement" (reads "first {}")
  "line 1, column 23: Expected pattern in statement" (reads "first Bytes(\"a\") {} | {}")
  "line 1, column 16: Expected pattern in statement" (reads "expect Bytes | {}")
  "line 1, column 17: Expected pattern in statement" (reads "expect (Bytes | ) {}")
  "line 1, column 15: Expected ')' in pattern" (reads "expect (Bytes {}")
  "line 1, column 5: wait needs a duration" (reads "wait")
  "line 1, column 5: Expected '{' in block" (reads "if x\n{}")
  "line 1, column 1: Expected end of statement" (reads "else {}")
  "line 1, column 9: Expected '\\\"' in string" (reads "x = \"abc")
  "line 1, column 9: Unknown escape sequence \\q" (reads "x = \"a\\qb\"")
  "line 1, column 9: Odd number of hexadecimal digits in #123" (reads "x = #123")
  "line 1, column 14: Invalid IP address 300.1.2.3" (reads "x = 300.1.2.3")
  "line 1, column 7: Invalid interval 5x: unknown unit x" (reads "x = 5x")
  "line 1, column 25: Integer 99999999999999999999 is too large" \
    (reads "x = 99999999999999999999")
*)

(* The examples of the spec, each read as in its golden file, which reads the
 * same again: *)
(*$R reads
  let dir = "tests/crafty" in
  Sys.readdir dir |> Array.iter (fun f ->
      if String.ends_with f ".crafty" then (
          let path = dir ^"/"^ f in
          let golden = Filename.chop_suffix path ".crafty" ^".expected" in
          let read = reads (Tools.file_content path) in
          assert_equal ~printer:identity ~msg:f
              (Tools.file_content golden) read ;
          assert_equal ~printer:identity ~msg:(f ^" read again") read (reads read)))
*)
