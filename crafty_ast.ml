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
(** Abstract syntax of crafty programs, as parsed and before any typing.

   Names of layers, fields, functions and special forms are case insensitive;
   layers are known by their names, and the others kept as written. Variables
   are case sensitive, and cannot be named after a layer, a constant, a
   function, a keyword or a predefined variable. *)
open Batteries

(** Where something starts in the source, counting from 1. *)
type location = { line : int ; column : int }

let print_location oc loc =
    Printf.fprintf oc "line %d, column %d" loc.line loc.column

(** The names of the layers. Layers on top of different ones can share a
 * name ([DNS/Query], [HTTP/Query]). *)
module Layer_name =
struct
    type t =
        | Eth | IP | TCP | UDP | ICMP | Echo | Request | Reply
        | DestUnreachable | TimeExceeded | DNS | Query | Answer | Bytes

    let all =
        [ Eth ; IP ; TCP ; UDP ; ICMP ; Echo ; Request ; Reply ;
          DestUnreachable ; TimeExceeded ; DNS ; Query ; Answer ; Bytes ]

    let to_string = function
        | Eth -> "Eth" | IP -> "IP" | TCP -> "TCP" | UDP -> "UDP"
        | ICMP -> "ICMP" | Echo -> "Echo" | Request -> "Request"
        | Reply -> "Reply" | DestUnreachable -> "DestUnreachable"
        | TimeExceeded -> "TimeExceeded" | DNS -> "DNS" | Query -> "Query"
        | Answer -> "Answer" | Bytes -> "Bytes"

    (* However written: *)
    let of_string s =
        let s = String.lowercase_ascii s in
        List.find_opt (fun n -> String.lowercase_ascii (to_string n) = s) all

    let print oc n = String.print oc (to_string n)
end

(* Names are found however written: *)
(*$T
  Layer_name.of_string "dns" = Some Layer_name.DNS
  Layer_name.of_string "destUNREACHABLE" = Some Layer_name.DestUnreachable
  Layer_name.of_string "HTTP" = None
  List.for_all (fun n -> Layer_name.of_string (Layer_name.to_string n) = Some n) Layer_name.all
*)

(** Types of values. *)
module Type =
struct
    type t =
        | Void | Bool | Byte | Int | Float | String | Interval | Time | Ip | Mac
        | Record of (string * t) list
        | Array of t
        (* Of the keys, then of the values: *)
        | Map of t * t
        | Variant of (string * t) list
        | Pattern

    let bytes = Array Byte

    let rec print oc = function
        | Void -> String.print oc "void"
        | Bool -> String.print oc "bool"
        | Byte -> String.print oc "byte"
        | Int -> String.print oc "int"
        | Float -> String.print oc "float"
        | String -> String.print oc "string"
        | Interval -> String.print oc "interval"
        | Time -> String.print oc "time"
        | Ip -> String.print oc "ip"
        | Mac -> String.print oc "mac"
        | Record fs ->
            List.print ~first:"{" ~last:"}" ~sep:", " (fun oc (n, t) ->
                Printf.fprintf oc "%s: %a" n print t) oc fs
        | Array t -> Printf.fprintf oc "%a[]" print t
        | Map (k, v) -> Printf.fprintf oc "%a[%a]" print v print k
        | Variant cs ->
            List.print ~first:"(" ~last:")" ~sep:" | " (fun oc (n, t) ->
                if t = Void then String.print oc n
                else Printf.fprintf oc "%s %a" n print t) oc cs
        | Pattern -> String.print oc "pattern"

    let to_string t = IO.to_string print t
end

type unop = Not | Neg

type binop =
    | Add | Sub | Mul | Div | Mod
    | And | Or
    | BitAnd | BitOr | BitXor
    | Eq | Ne | Lt | Le | Gt | Ge

type literal =
    | Bool of bool
    | Int of int
    | Float of float
    | Byte of int
    | Interval of Clock.Interval.t
    | Time of Clock.Wall.t
    | Ip of Ip.Addr.t
    | Mac of Eth.Addr.t

type expr = { loc : location ; desc : expr_desc }

and expr_desc =
    | Lit of literal
    (* One of the layers' constants ([RST]), named as written: *)
    | Constant of string * literal
    | String of string_part list
    (* The predefined variables ([MATCH], [LAST]) are named in upper case,
     * however written: *)
    | Var of string
    (* A layer of a packet ([A[IP]]) or of the one being matched ([IP.src]),
     * counted from the end ([nth] carets after its name: [IP] is the last,
     * [IP^] the last but one), or from the start ([nth] + 1 carets before
     * it: [^IP] is the first one). *)
    | Layer of { name : Layer_name.t ; from_start : bool ; nth : int }
    | Field of expr * string
    | Index of expr * expr
    | Call of string * arg list
    | Unop of unop * expr
    | Binop of binop * expr * expr
    | Record of (string * expr) list
    | Array of expr list
    (* Never empty, as [[]] is an array: *)
    | Map of (expr * expr) list
    | Matches of expr * pattern
    (* A constructor of a variant, with what it holds ([Ok(42)]) or nothing
     * ([Pending()]); without the parentheses, a constructor is read as a
     * [Var]: *)
    | Construct of string * expr option
    (* The value of a block is that of its last statement, if an expression,
     * and else void: *)
    | Block of block
    (* [elsif] being an [else] block of a single [If]: *)
    | If of { cond : expr ; then_ : block ; else_ : block option }
    (* The block of the constructor of [subject]'s value, in which [var]
     * (or else [subject], if a variable) is what that constructor holds: *)
    | Case of { var : string option ; subject : expr ; arms : arm list ;
                else_ : block option }

and arm = { arm_loc : location ; ctor : string ; body : block }

and string_part = Text of string | Interp of expr

(* Arguments of functions and layers, and parameters of special forms, are
 * named but for a lone one. *)
and arg = { arg_loc : location ; arg_name : string option ; value : expr }

and pattern =
    { pat_loc : location ;
      anchor : anchor ;
      (* Bottom to top, never empty: *)
      pat_layers : pattern_layer list }

and anchor =
    | Absolute
    (* How many layers to go down from the current stack ([../]) first: *)
    | Relative of int

and pattern_layer =
    { pl_loc : location ;
      pl_name : Layer_name.t ;
      pl_manual : bool ;
      (* With the conditions separated by commas joined into one with [And],
       * and [=] already read as [Eq]: *)
      cond : expr option }

(* A layer of a protocol stack, with its options: *)
and layer =
    { layer_loc : location ;
      layer_name : Layer_name.t ;
      manual : bool ;
      options : arg list }

and stmt = { stmt_loc : location ; stmt : stmt_desc }

and stmt_desc =
    (* Those layers on top of the [anchor]: the stack of [body] if any, or
     * else a packet to send, its top layer being terminal: *)
    | Stack of { anchor : anchor ; layers : layer list ; body : block option }
    (* Its value unused: *)
    | Expr of expr
    (* [x = e]: *)
    | Declare of string * expr
    (* [x := e], or [x op= e] with that [binop]; [x[i][j] := e] with the
     * indices [i; j]: *)
    | Assign of string * expr list * binop option * expr
    | Repeat of { var : string option ; count : expr option ;
                  every : expr option ; for_ : expr option ; body : block }
    (* A [Repeat] whose [var] is each of [items] in turn: *)
    | Foreach of { var : string option ; items : expr ; every : expr option ;
                   for_ : expr option ; body : block }
    (* Run [body], and again up to [max] times while it fails: *)
    | Retry of { max : expr option ; body : block }
    (* Run [body], leaving it on its first error: *)
    | Catch of block
    | Break of { depth : expr option }
    | Wait of expr
    | Expect of { timeout : expr option ; pattern : pattern ; body : block }
    (* The block of the first of those patterns to match, never empty: *)
    | Any of { timeout : expr option ; cases : (pattern * block) list }
    | On of { timeout : expr option ; max : expr option ;
              pattern : pattern ; body : block }

and block = stmt list

type program = block

(** Whether that name is a constructor's: it starts with a capital letter. *)
let is_constructor s = s <> "" && Char.is_uppercase s.[0]

(** The functions a statement can call (any other name being a layer).
 * Lower case. *)
let functions =
    [ "rand" ; "randbytes" ; "exp" ; "ln" ; "log" ; "log2" ; "int" ; "float" ;
      "bool" ; "byte" ; "interval" ; "time" ; "now" ; "ip_addr" ; "mac_addr" ; "getenv" ;
      "array" ; "length" ; "concat" ; "append" ; "prepend" ;
      "map" ; "has" ; "remove" ; "keys" ; "values" ;
      "print" ; "print_err" ; "assert" ]

(** Variables that the language defines, which are case insensitive as are
 * all the names that the user does not choose. Lower case. *)
let predefined = [ "match" ; "last" ]

(** Names that are neither variables, layers nor functions. Lower case. *)
let keywords =
    [ "true" ; "false" ; "repeat" ; "foreach" ; "retry" ; "catch" ; "if" ;
      "elsif" ; "else" ; "case" ; "break" ; "expect" ; "any" ; "on" ; "wait" ]

(** Keywords of what the language will have but not yet. Lower case. *)
let unsupported =
    [ "report" ]

(** {2 Printing}
 *
 * As source code that parses back into the same program, with every operation
 * in parentheses, or only those that need some. *)

let string_of_binop = function
    | Add -> "+" | Sub -> "-" | Mul -> "*" | Div -> "/" | Mod -> "%"
    | And -> "&&" | Or -> "||"
    | BitAnd -> "&" | BitOr -> "|" | BitXor -> "^"
    | Eq -> "==" | Ne -> "!=" | Lt -> "<" | Le -> "<=" | Gt -> ">" | Ge -> ">="

(* The shortest that reads back as [f], and as a float: *)
let string_of_float f =
    let s = Printf.sprintf "%.15g" f in
    let s = if float_of_string s = f then s else Printf.sprintf "%.17g" f in
    if String.exists s "." || String.exists s "e" then s else s ^".0"

let print_literal oc = function
    | Bool b -> String.print oc (if b then "true" else "false")
    | Int i -> Int.print oc i
    | Float f -> String.print oc (string_of_float f)
    | Byte b -> Printf.fprintf oc "#%02x" b
    | Interval i -> String.print oc (Clock.Interval.to_string i)
    | Time t -> String.print oc (Clock.Wall.to_iso8601 t)
    | Ip ip -> String.print oc (Ip.Addr.to_dotted_string ip)
    | Mac mac ->
        (* Not [Eth.Addr.to_string], which may name the vendor: *)
        String.print oc (Tools.hexstring ~sep:":"
            (Bitstring.string_of_bitstring (mac :> Bitstring.bitstring)))

let print_text oc s =
    String.iter (function
        | '"' -> String.print oc "\\\""
        | '\\' -> String.print oc "\\\\"
        | '$' -> String.print oc "\\$"
        | '\n' -> String.print oc "\\n"
        | '\r' -> String.print oc "\\r"
        | '\t' -> String.print oc "\\t"
        | c when Char.code c < 32 || Char.code c = 127 ->
            Printf.fprintf oc "\\x%02x" (Char.code c)
        | c -> Char.print oc c) s

let print_list print oc l =
    List.print ~first:"" ~last:"" ~sep:", " print oc l

(* How tightly an operation binds, as the parser reads them: *)
let precedence = function
    | Or -> 1 | And -> 2
    | Eq | Ne | Lt | Le | Gt | Ge -> 3
    | BitOr -> 4 | BitXor -> 5 | BitAnd -> 6
    | Add | Sub -> 7 | Mul | Div | Mod -> 8

let unary_precedence = 9

(* [e] where an operation binding less than [p] needs parentheses, as do all
 * of them with [all] (but the outermost one if [bare]), its blocks at that
 * [indent]: *)
let rec print_expr_at ?(bare=false) ~all ~indent p oc e =
    let paren q f =
        if all && not bare || q < p then Printf.fprintf oc "(%t)" f else f oc in
    let at = print_expr_at ~all ~indent in
    let sub = at 0 in
    let bare_sub = print_expr_at ~bare:true ~all ~indent 0 in
    let block = print_block ~all indent in
    match e.desc with
    | Lit l -> print_literal oc l
    | Constant (n, _) -> String.print oc n
    | String parts ->
        Char.print oc '"' ;
        List.iter (function
            | Text s -> print_text oc s
            | Interp e -> Printf.fprintf oc "${%a}" sub e) parts ;
        Char.print oc '"'
    | Var n -> String.print oc n
    | Layer { name ; from_start ; nth } ->
        let carets = String.make (if from_start then nth + 1 else nth) '^' in
        if from_start then Printf.fprintf oc "%s%a" carets Layer_name.print name
        else Printf.fprintf oc "%a%s" Layer_name.print name carets
    | Field (e, f) ->
        Printf.fprintf oc "%a.%s" (at max_int) e f
    | Index (e, i) ->
        Printf.fprintf oc "%a[%a]" (at max_int) e sub i
    | Call (f, args) -> Printf.fprintf oc "%s(%a)" f (print_args ~all ~indent) args
    | Unop (Not, e) ->
        paren unary_precedence (fun oc ->
            Printf.fprintf oc "!%a" (at unary_precedence) e)
    | Unop (Neg, e) ->
        (* With a space before a digit, not to make a negative literal of a
         * positive one: *)
        let s = IO.to_string (at unary_precedence) e in
        let sep = if all || s <> "" && Char.is_digit s.[0] then " " else "" in
        paren unary_precedence (fun oc -> Printf.fprintf oc "-%s%s" sep s)
    | Binop (op, a, b) ->
        let q = precedence op in
        (* Comparisons do not chain: *)
        let pa, pb = if q = precedence Eq then q + 1, q + 1 else q, q + 1 in
        paren q (fun oc ->
            Printf.fprintf oc "%a %s %a"
                (at pa) a (string_of_binop op) (at pb) b)
    | Record fields ->
        Printf.fprintf oc "{%a}"
            (print_list (fun oc (n, e) -> Printf.fprintf oc "%s: %a" n sub e))
            fields
    | Array es -> Printf.fprintf oc "[%a]" (print_list sub) es
    | Map kvs ->
        Printf.fprintf oc "[%a]" (print_list (fun oc (k, v) ->
            Printf.fprintf oc "%a: %a" sub k sub v)) kvs
    | Matches (e, pat) ->
        let q = precedence Eq in
        paren q (fun oc ->
            Printf.fprintf oc "%a =~ %a"
                (at (q + 1)) e (print_pattern ~all ~indent) pat)
    | Construct (c, e) ->
        Printf.fprintf oc "%s(%a)" c (fun oc -> Option.may (bare_sub oc)) e
    | Block b -> block oc b
    | If { cond ; then_ ; else_ } ->
        let rec print_if kw cond then_ else_ =
            Printf.fprintf oc "%s %a " kw bare_sub cond ;
            block oc then_ ;
            match else_ with
            | None -> ()
            | Some [ { stmt = Expr { desc = If { cond ; then_ ; else_ } ; _ } ; _ } ] ->
                print_if " elsif" cond then_ else_
            | Some b -> String.print oc " else " ; block oc b in
        print_if "if" cond then_ else_
    | Case { var ; subject ; arms ; else_ } ->
        String.print oc "case" ;
        Option.may (Printf.fprintf oc " var=%s") var ;
        Printf.fprintf oc " %a" bare_sub subject ;
        List.iteri (fun i a ->
            Printf.fprintf oc "%s%s " (if i = 0 then " " else " | ") a.ctor ;
            block oc a.body) arms ;
        Option.may (fun b -> String.print oc " else " ; block oc b) else_

and print_args ~all ~indent oc args =
    print_list (fun oc a ->
        Option.may (Printf.fprintf oc "%s=") a.arg_name ;
        print_expr_at ~all ~indent 0 oc a.value) oc args

and print_anchor oc = function
    | Absolute -> Char.print oc '/'
    | Relative n -> for _ = 1 to n do String.print oc "../" done

and print_pattern ~all ~indent oc p =
    print_anchor oc p.anchor ;
    List.print ~first:"" ~last:"" ~sep:"/" (fun oc l ->
        Printf.fprintf oc "%a%s" Layer_name.print l.pl_name (if l.pl_manual then "!" else "") ;
        Option.may (Printf.fprintf oc "(%a)" (print_expr_at ~bare:true ~all ~indent 0)) l.cond
    ) oc p.pat_layers

and print_layer ~all ~indent oc l =
    Printf.fprintf oc "%a%s" Layer_name.print l.layer_name (if l.manual then "!" else "") ;
    if l.options <> [] then Printf.fprintf oc "(%a)" (print_args ~all ~indent) l.options

and print_stmt ~all indent oc s =
    let expr = print_expr_at ~all ~indent 0 in
    let param name = Option.may (Printf.fprintf oc " %s=%a" name expr) in
    let pattern = print_pattern ~all ~indent in
    String.print oc (String.make indent ' ') ;
    match s.stmt with
    | Stack { anchor ; layers ; body } ->
        print_anchor oc anchor ;
        List.print ~first:"" ~last:"" ~sep:"/" (print_layer ~all ~indent) oc layers ;
        Option.may (fun b -> Char.print oc ' ' ; print_block ~all indent oc b) body
    | Expr e -> print_expr_at ~bare:true ~all ~indent 0 oc e
    | Declare (v, e) -> Printf.fprintf oc "%s = %a" v expr e
    | Assign (v, is, op, e) ->
        Printf.fprintf oc "%s%a %s= %a" v
            (List.print ~first:"" ~last:"" ~sep:"" (fun oc i ->
                Printf.fprintf oc "[%a]" expr i)) is
            (match op with None -> ":" | Some op -> string_of_binop op)
            expr e
    | Repeat { var ; count ; every ; for_ ; body } ->
        String.print oc "repeat" ;
        Option.may (Printf.fprintf oc " var=%s") var ;
        param "count" count ; param "every" every ; param "for" for_ ;
        Char.print oc ' ' ; print_block ~all indent oc body
    | Foreach { var ; items ; every ; for_ ; body } ->
        String.print oc "foreach" ;
        Option.may (Printf.fprintf oc " %s") var ;
        param "every" every ; param "for" for_ ;
        Printf.fprintf oc " %a " (print_expr_at ~bare:true ~all ~indent 0) items ;
        print_block ~all indent oc body
    | Retry { max ; body } ->
        String.print oc "retry" ; param "max" max ;
        Char.print oc ' ' ; print_block ~all indent oc body
    | Catch body ->
        String.print oc "catch " ; print_block ~all indent oc body
    | Break { depth } ->
        String.print oc "break" ; param "depth" depth
    | Wait dur ->
        if all then (String.print oc "wait" ; param "dur" (Some dur))
        else Printf.fprintf oc "wait %a" expr dur
    | Expect { timeout ; pattern = p ; body } ->
        String.print oc "expect" ; param "timeout" timeout ;
        Printf.fprintf oc " %a " pattern p ;
        print_block ~all indent oc body
    | Any { timeout ; cases } ->
        String.print oc "any" ; param "timeout" timeout ;
        List.iteri (fun i (p, body) ->
            Printf.fprintf oc "%s%a " (if i = 0 then " " else " | ") pattern p ;
            print_block ~all indent oc body) cases
    | On { timeout ; max ; pattern = p ; body } ->
        String.print oc "on" ; param "timeout" timeout ; param "max" max ;
        Printf.fprintf oc " %a " pattern p ;
        print_block ~all indent oc body

and print_block ~all indent oc b =
    String.print oc "{\n" ;
    List.iter (fun s -> print_stmt ~all (indent + 2) oc s ; Char.print oc '\n') b ;
    Printf.fprintf oc "%s}" (String.make indent ' ')

(* With every operation in parentheses: *)
let print_expr = print_expr_at ~all:true ~indent:0 0

(* The same, but for the outermost operation: *)
let print_bare_expr = print_expr_at ~bare:true ~all:true ~indent:0 0

(** The program, with [all] operations in parentheses (default), or only those
 * that need some: *)
let print_program ?(all=true) oc p =
    List.iter (fun s -> print_stmt ~all 0 oc s ; Char.print oc '\n') p

let string_of_program ?all p =
    IO.to_string (print_program ?all) p
