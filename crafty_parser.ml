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

   Every reading of the program is considered, and one that can be read in
   several ways is an error. *)
open Batteries
open Crafty_ast

let layers = Crafty_layers.names

(* Whether the layer of that name sends a packet: *)
let terminal name =
    List.exists (fun (l : Crafty_layers.layer) ->
        l.terminal && Crafty_layers.same_name l.name name) Crafty_layers.all

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

(* What a word or a literal cannot be followed by: *)
let end_of_word =
    quiet (nay (char_if "end of word" (fun c ->
        is_word c || c = '.' || c = ':' || Char.code c >= 128)))

let identifier =
    char_if "letter" is_alpha ++ chars_of ~min:0 "letter or digit" is_word >>:
    (fun (c, s) -> String.make 1 c ^ s) |? "name"

let is_in names s = List.mem (String.lowercase_ascii s) names

let is_keyword s = is_in keywords s || is_in unsupported s

let is_reserved s =
    is_keyword s || is_in functions s || is_in layers s || is_in predefined s ||
    Crafty_layers.find_constant s <> None

(* Names of the user's variables: *)
let name =
    identifier >>= fun s -> if is_reserved s then fail else return s

let predefined_var =
    identifier >>= fun s ->
        if is_in predefined s then return (String.uppercase_ascii s) else fail

let constant =
    identifier >>= fun s ->
        match Crafty_layers.find_constant s with
        | Some l -> return (s, l)
        | None -> fail

let function_name =
    identifier >>= fun s -> if is_in functions s then return s else fail

let known_layer =
    identifier >>= fun s -> if is_in layers s then return s else fail

(* Where only a layer can be: *)
let layer_name =
    (identifier >>= fun s ->
        if is_keyword s || is_in functions s then fail else return s) >>:
    fun s -> if is_in layers s then s else reject "Unknown layer %s" s

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

let mac_lit =
    let byte = chars_of ~max:2 "hexadecimal digit" is_hex in
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

let bool_lit =
    (keyword "true" >>: fun () -> Bool true) |||
    (keyword "false" >>: fun () -> Bool false)

(* Of those that fail at the same place, the last one tried tells why: *)
let literal =
    interval_lit ||| bool_lit ||| ip_lit ||| mac_lit ||| float_lit ||| int_lit

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
let make_expr ~cond ~self ~expr ~pattern =
    let atom =
        (here ++ literal >>: fun (loc, l) -> { loc ; desc = Lit l }) |||
        bytes_lit |||
        string_lit expr |||
        in_ '(' self ')' |||
        (here ++ in_ '[' (list_of expr) ']' >>:
            fun (loc, es) -> { loc ; desc = Array es }) |||
        (here ++ in_ '{' (list_of (
            identifier +- sp +- item ':' +- nl_sp ++ expr)) '}' >>:
            fun (loc, fs) -> { loc ; desc = Record fs }) |||
        (here ++ function_name ++ args expr >>:
            fun ((loc, f), args) -> { loc ; desc = Call (f, args) }) |||
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
                    | _ -> reject "Carets on both sides of %s" name in
                { loc ; desc }) in
    let postfix =
        atom ++ repeat_greedy ~sep:none (
            (item '.' -+ identifier >>: fun f -> `Field f) |||
            (in_ '[' expr ']' >>: fun i -> `Index i)) >>:
        fun (a, ops) ->
            List.fold_left (fun e -> function
                | `Field f -> { loc = a.loc ; desc = Field (e, f) }
                | `Index i -> { loc = a.loc ; desc = Index (e, i) }) a ops in
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
let pattern = make_pattern cond_expr
let () =
    set_expr (make_expr ~cond:false ~self:expr ~expr ~pattern) ;
    set_cond_expr (make_expr ~cond:true ~self:cond_expr ~expr ~pattern)

(** {2 Statements} *)

(* Parameters of a special form, by name, or the single one it has (which
 * starts neither as a record nor as a layer, not to be mistaken for the
 * block or the pattern that follows): *)
let params form names =
    let param_name =
        identifier >>= fun s -> if is_in layers s then fail else return s in
    let param =
        here ++
        ((param_name +- sp +- item '=' +- nay (item '=') +- sp >>: Option.some) ++
         expr |||
         (nay (item '{' >>: ignore ||| (known_layer >>: ignore)) -+ expr >>:
            fun e -> None, e)) in
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

let stmt = fix (fun stmt ->
    let block =
        in_ '{' (repeat ~sep:stmt_sep stmt +- optional ~def:() (sp -- item ';'))
            '}' |? "block" in
    let body = sp -+ block in
    let with_loc p = here ++ p >>: fun (stmt_loc, stmt) -> { stmt_loc ; stmt } in
    (* Any name, that is then refused if reserved, for a better message: *)
    let variable =
        identifier >>= fun s -> if is_keyword s then fail else return s in
    let check_var n =
        if is_reserved n then reject "%s is a reserved name" n ;
        n in
    let var_name what e =
        match e.desc with
        | Var n -> check_var n
        | String [ Text n ] -> check_var n
        | String [] -> reject "The %s cannot be empty" what
        | _ -> reject "The %s must be a name" what in
    with_loc (
        (* A stack sends a packet if its top layer is terminal, and is
         * otherwise that of the block that follows: *)
        (anchor ++
         repeat ~min:1 ~sep:(maybe_next (slash -- nl_sp)) layer ++
         optional ~def:None (body >>: Option.some) >>:
            fun ((anchor, layers), body) ->
                let top = (List.last layers).layer_name in
                (match body, terminal top with
                | None, false ->
                    reject "%s needs a block, or a layer on top that sends" top
                | Some _, true ->
                    reject "No block can follow %s, which sends" top
                | _ -> ()) ;
                Stack { anchor ; layers ; body }) |||
        (block >>: fun b -> Block b) |||
        (variable ++ maybe_next (
            item '=' -- nay (item '=' ||| item '~') -- nl_sp -+ expr) >>:
            fun (v, e) -> Declare (check_var v, e)) |||
        (variable ++ maybe_next (assign_op +- nl_sp ++ expr) >>:
            fun (v, (op, e)) -> Assign (check_var v, op, e)) |||
        (function_name ++ args expr >>: fun (f, args) -> Do (f, args)) |||
        (keyword "repeat" -+ params "repeat" [ "var" ; "count" ; "every" ; "for" ] ++
         body >>: fun (p, body) ->
            Repeat { var = Option.map (var_name "variable name") (p "var") ;
                     count = p "count" ; every = p "every" ; for_ = p "for" ;
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
        (keyword "expect" -+ params "expect" [ "timeout" ] +- sp ++ pattern ++
         body >>: fun ((p, pattern), body) ->
            Expect { timeout = p "timeout" ; pattern ; body }) |||
        (keyword "on" -+ params "on" [ "timeout" ; "max" ] +- sp ++ pattern ++
         body >>: fun ((p, pattern), body) ->
            On { timeout = p "timeout" ; max = p "max" ; pattern ; body }) |||
        (identifier >>= (fun s ->
            if List.mem (String.lowercase_ascii s) unsupported then return s
            else fail) >>:
            fun s -> reject "%s is not supported yet" s)) |? "statement")

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

(** Parse that text, or tell where and why it does not parse. *)
let parse text =
    match to_result (program [] None Parsers.no_error_correction
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

(* [reads text] is how the program in that text reads back, or the error. *)
(*$inject
  let reads text =
      match parse text with
      | Ok p -> Crafty_ast.string_of_program p
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
  "x = (MATCH[ip].src + LAST[TCP].seq)\n" \
    (reads "x = match[ip].src + Last[TCP].seq")
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
  "IP!(ttl=1)/TCP!(flags=2)/Bytes(\"x\")\n" \
    (reads "IP!(ttl=1)\\TCP!(flags=2)/Bytes(\"x\")")
  "../../IP!/TCP!(flags=4)/Bytes\n" (reads "../../IP!/TCP!(flags=4)/Bytes()")
  "x = (y =~ /IP/UDP(dport == 53))\n" (reads "x = y =~ /IP/UDP(dport = 53)")
  "retry max=3 {\n  break\n}\n" (reads "retry 3 {\n  break\n}")
  "catch {\n  x = 1\n}\n" (reads "catch { x = 1 }")
  "wait dur=10ms\nwait dur=(1s * n)\n" (reads "wait 10ms\nwait dur=1s * n")
  "repeat var=j {\n  break depth=2\n}\n" (reads "repeat var=\"j\" { break 2 }")
  "repeat var=i count=3 every=1ms for=1s {\n  print(\"${i}\")\n}\n" \
    (reads "repeat var=i count=3 every=1ms for=1s { print(\"${i}\") }")
  "repeat count=(n * 2) every=(1s / n) {\n}\n" \
    (reads "repeat every=1s / n count=n*2 {}")
  "on timeout=1s max=3 ../UDP {\n  n += 1\n  m := 2\n}\n" \
    (reads "on max=3 timeout=1s ../UDP { n += 1; m := 2 }")
  "expect UDP((IP^.ttl == 3) && (^IP.src == 1.2.3.4)) {\n}\n" \
    (reads "expect UDP(IP^.ttl = 3, ^IP.src == 1.2.3.4) {}")
  "expect ../../TCP!(flags & RST) {\n}\n" \
    (reads "expect ../../TCP!(flags & RST) {}")
  "expect timeout=5s /IP(src == x)/UDP {\n}\n" \
    (reads "expect 5s /IP(src=x)/UDP {}")
  "expect timeout=5s /IP/UDP {\n}\n" (reads "expect timeout=5s /IP/UDP {}")
*)

(* The errors, where they are found: *)
(*$= reads & ~printer:identity
  "line 1, column 17: Expected expression in arguments" \
    (reads "/IP(dst=1.2.3.4/UDP")
  "line 1, column 11: Expected end of statement" (reads "print(\"a\"))")
  "line 1, column 16: UDP needs a block, or a layer on top that sends" \
    (reads "/IP/UDP(dst=53)")
  "line 1, column 19: No block can follow Bytes, which sends" \
    (reads "/IP/UDP/Bytes() {}")
  "line 1, column 12: Expected end of statement" (reads "print(\"a\") print(\"b\")")
  "line 1, column 7: Expected end of statement" (reads "x = 1 2")
  "line 1, column 5: Expected expression in statement" (reads "x = ")
  "line 1, column 8: Expected expression in statement" (reads "x = 1 +")
  "line 1, column 11: Expected ')' in expression" (reads "x = (1 + 2")
  "line 1, column 10: Expected ']' in expression" (reads "x = [1, 2")
  "line 1, column 14: Expected ':' in expression" (reads "x = {a: 1, b 2}")
  "line 1, column 4: Unexpected input in statement" (reads "x == 1")
  "line 2, column 1: Expected '}' in block" \
    (reads "expect Bytes(\"x\") { print(\"ok\")\n")
  "line 1, column 19: Expected name in pattern" (reads "expect timeout=5s {\n}")
  "line 1, column 13: Unknown parameter cnt for repeat (expected var, count, every, for)" \
    (reads "repeat cnt=3 {\n}")
  "line 1, column 18: Parameter max of retry given twice" \
    (reads "retry max=1 max=2 {\n}")
  "line 1, column 10: Parameter depth of break given twice" (reads "break 2 3")
  "line 1, column 6: Parameters of on must be named" \
    (reads "on 1s Bytes(\"x\") {\n}")
  "line 1, column 18: Expected '=' in statement" (reads "repeat count=3 x {\n}")
  "line 1, column 5: Expected expression in statement" (reads "x = IP")
  "line 1, column 7: ip is a reserved name" (reads "ip = 3")
  "line 1, column 11: print is a reserved name" (reads "print += 3")
  "line 1, column 10: match is a reserved name" (reads "match = 1")
  "line 1, column 19: LAST is a reserved name" (reads "repeat var=last {}")
  "line 1, column 20: tcp is a reserved name" (reads "repeat var=\"tcp\" {}")
  "line 1, column 8: Unknown layer DNS" (reads "/IP/DNS {}")
  "line 1, column 11: Carets on both sides of IP" (reads "x = a[^IP^]")
  "line 1, column 3: if is not supported yet" (reads "if x {}")
  "line 1, column 5: wait needs a duration" (reads "wait")
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
