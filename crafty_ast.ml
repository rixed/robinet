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

   Names of layers, fields, functions and special forms are case insensitive
   and kept as written. Variables are case sensitive, and cannot be named
   after a layer, a function, a keyword or a predefined variable. *)
open Batteries

(** Where something starts in the source, counting from 1. *)
type location = { line : int ; column : int }

let print_location oc loc =
    Printf.fprintf oc "line %d, column %d" loc.line loc.column

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
    | Ip of Ip.Addr.t
    | Mac of Eth.Addr.t

type expr = { loc : location ; desc : expr_desc }

and expr_desc =
    | Lit of literal
    | String of string_part list
    (* The predefined variables ([MATCH], [LAST]) are named in upper case,
     * however written: *)
    | Var of string
    (* A layer of a packet ([A[IP]]) or of the one being matched ([IP.src]),
     * counted from the end ([nth] carets after its name: [IP] is the last,
     * [IP^] the last but one), or from the start ([nth] + 1 carets before
     * it: [^IP] is the first one). *)
    | Layer of { name : string ; from_start : bool ; nth : int }
    | Field of expr * string
    | Index of expr * expr
    | Call of string * arg list
    | Unop of unop * expr
    | Binop of binop * expr * expr
    | Record of (string * expr) list
    | Array of expr list
    | Matches of expr * pattern

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
      pl_name : string ;
      pl_manual : bool ;
      (* With the conditions separated by commas joined into one with [And],
       * and [=] already read as [Eq]: *)
      cond : expr option }

(** A layer of a protocol stack, with its options. *)
type layer =
    { layer_loc : location ;
      layer_name : string ;
      manual : bool ;
      options : arg list }

type stmt = { stmt_loc : location ; stmt : stmt_desc }

and stmt_desc =
    (* Add those layers on top of the current stack, or on top of the root
     * if [absolute]; with a block, only for the duration of that block: *)
    | Stack of { absolute : bool ; layers : layer list ; body : block option }
    | Block of block
    (* [x = e]: *)
    | Declare of string * expr
    (* [x := e], or [x op= e] with that [binop]: *)
    | Assign of string * binop option * expr
    (* A function called for its effect, such as [print]: *)
    | Do of string * arg list
    | Repeat of { var : string option ; count : expr option ;
                  every : expr option ; for_ : expr option ; body : block }
    | Retry of { max : expr option ; body : block }
    | Break of { depth : expr option }
    | Expect of { timeout : expr option ; pattern : pattern ; body : block }
    | On of { timeout : expr option ; max : expr option ;
              pattern : pattern ; body : block }

and block = stmt list

type program = block

(** The functions a statement can call (any other name being a layer).
 * Lower case. *)
let functions =
    [ "rand" ; "randbytes" ; "exp" ; "ln" ; "log" ; "log2" ; "int" ; "float" ;
      "bool" ; "byte" ; "interval" ; "array" ; "length" ; "get" ; "print" ;
      "print_err" ]

(** The layers, until a registry of them tells. Lower case. *)
let layers =
    [ "eth" ; "ip" ; "tcp" ; "udp" ; "icmp" ; "echorequest" ; "echoreply" ;
      "destunreachable" ; "timeexceeded" ; "bytes" ]

(** Variables that the language defines, which are case insensitive as are
 * all the names that the user does not choose. Lower case. *)
let predefined = [ "match" ; "last" ]

(** Names that are neither variables, layers nor functions. Lower case. *)
let keywords =
    [ "true" ; "false" ; "repeat" ; "retry" ; "break" ; "expect" ; "on" ]

(** Keywords of what the language will have but not yet. Lower case. *)
let unsupported =
    [ "any" ; "catch" ; "if" ; "elsif" ; "else" ; "case" ; "wait" ; "report" ]

(** {2 Printing}
 *
 * As source code that parses back into the same program, with every operation
 * in parentheses. *)

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

let rec print_expr oc e =
    match e.desc with
    | Lit l -> print_literal oc l
    | String parts ->
        Char.print oc '"' ;
        List.iter (function
            | Text s -> print_text oc s
            | Interp e -> Printf.fprintf oc "${%a}" print_expr e) parts ;
        Char.print oc '"'
    | Var n -> String.print oc n
    | Layer { name ; from_start ; nth } ->
        let carets = String.make (if from_start then nth + 1 else nth) '^' in
        if from_start then Printf.fprintf oc "%s%s" carets name
        else Printf.fprintf oc "%s%s" name carets
    | Field (e, f) -> Printf.fprintf oc "%a.%s" print_expr e f
    | Index (e, i) -> Printf.fprintf oc "%a[%a]" print_expr e print_expr i
    | Call (f, args) -> Printf.fprintf oc "%s(%a)" f print_args args
    | Unop (Not, e) -> Printf.fprintf oc "(!%a)" print_expr e
    (* With a space, not to make a negative literal of a positive one: *)
    | Unop (Neg, e) -> Printf.fprintf oc "(- %a)" print_expr e
    | Binop (op, a, b) ->
        Printf.fprintf oc "(%a %s %a)"
            print_expr a (string_of_binop op) print_expr b
    | Record fields ->
        Printf.fprintf oc "{%a}"
            (print_list (fun oc (n, e) -> Printf.fprintf oc "%s: %a" n print_expr e))
            fields
    | Array es -> Printf.fprintf oc "[%a]" (print_list print_expr) es
    | Matches (e, p) -> Printf.fprintf oc "(%a =~ %a)" print_expr e print_pattern p

and print_args oc args =
    print_list (fun oc a ->
        Option.may (Printf.fprintf oc "%s=") a.arg_name ;
        print_expr oc a.value) oc args

(* Without the parentheses around the outermost operation: *)
and print_bare_expr oc e =
    match e.desc with
    | Unop (Not, e) -> Printf.fprintf oc "!%a" print_expr e
    | Unop (Neg, e) -> Printf.fprintf oc "- %a" print_expr e
    | Binop (op, a, b) ->
        Printf.fprintf oc "%a %s %a"
            print_expr a (string_of_binop op) print_expr b
    | Matches (e, p) -> Printf.fprintf oc "%a =~ %a" print_expr e print_pattern p
    | _ -> print_expr oc e

and print_pattern oc p =
    (match p.anchor with
    | Absolute -> Char.print oc '/'
    | Relative n -> for _ = 1 to n do String.print oc "../" done) ;
    List.print ~first:"" ~last:"" ~sep:"/" (fun oc l ->
        Printf.fprintf oc "%s%s" l.pl_name (if l.pl_manual then "!" else "") ;
        Option.may (Printf.fprintf oc "(%a)" print_bare_expr) l.cond
    ) oc p.pat_layers

let print_layer oc l =
    Printf.fprintf oc "%s%s" l.layer_name (if l.manual then "!" else "") ;
    if l.options <> [] then Printf.fprintf oc "(%a)" print_args l.options

let rec print_stmt indent oc s =
    let param name = Option.may (Printf.fprintf oc " %s=%a" name print_expr) in
    String.print oc (String.make indent ' ') ;
    match s.stmt with
    | Stack { absolute ; layers ; body } ->
        if absolute then Char.print oc '/' ;
        List.print ~first:"" ~last:"" ~sep:"/" print_layer oc layers ;
        Option.may (fun b -> Char.print oc ' ' ; print_block indent oc b) body
    | Block b -> print_block indent oc b
    | Declare (v, e) -> Printf.fprintf oc "%s = %a" v print_expr e
    | Assign (v, op, e) ->
        Printf.fprintf oc "%s %s= %a" v
            (match op with None -> ":" | Some op -> string_of_binop op)
            print_expr e
    | Do (f, args) -> Printf.fprintf oc "%s(%a)" f print_args args
    | Repeat { var ; count ; every ; for_ ; body } ->
        String.print oc "repeat" ;
        Option.may (Printf.fprintf oc " var=%s") var ;
        param "count" count ; param "every" every ; param "for" for_ ;
        Char.print oc ' ' ; print_block indent oc body
    | Retry { max ; body } ->
        String.print oc "retry" ; param "max" max ;
        Char.print oc ' ' ; print_block indent oc body
    | Break { depth } ->
        String.print oc "break" ; param "depth" depth
    | Expect { timeout ; pattern ; body } ->
        String.print oc "expect" ; param "timeout" timeout ;
        Printf.fprintf oc " %a " print_pattern pattern ;
        print_block indent oc body
    | On { timeout ; max ; pattern ; body } ->
        String.print oc "on" ; param "timeout" timeout ; param "max" max ;
        Printf.fprintf oc " %a " print_pattern pattern ;
        print_block indent oc body

and print_block indent oc b =
    String.print oc "{\n" ;
    List.iter (fun s -> print_stmt (indent + 2) oc s ; Char.print oc '\n') b ;
    Printf.fprintf oc "%s}" (String.make indent ' ')

let print_program oc p =
    List.iter (fun s -> print_stmt 0 oc s ; Char.print oc '\n') p

let string_of_program p =
    IO.to_string print_program p
