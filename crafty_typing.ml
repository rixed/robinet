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
(** Checks a parsed program and resolves what it refers to, into a typed
   program, or tells every statement that makes no sense and why.

   Stacks and patterns are resolved against the layer registry, starting
   from its root ([/IP] being [/Eth/IP]). A stack is either that of the
   block that follows it, or a packet to send, its top layer being
   terminal; a packet leaves the current stack as it was.

   Within a pattern's condition, a name is a field of that layer if it has
   one, else a variable; [IP.src] is a field of the nearest IP below ([IP^]
   the next one, [^IP] the first one of the packet).

   A block, an [if] or a [case] has the value of the branch it runs, and can
   wait (or send, receive, loop, break) only as the value of a declaration,
   an assignment or a statement, or as a branch of such a one: elsewhere in
   an expression, it is computed at once. *)
open Batteries
module A = Crafty_ast
module L = Crafty_layers
module Type = A.Type

(** {2 Typed programs} *)

(* Each declaration is a variable of its own: *)
type var = { name : string ; id : int ; typ : Type.t }

type builtin =
    | Rand | Randbytes | Exp | Ln | Log | Log2
    | To_int | To_float | To_bool | To_byte | To_interval | To_time | Now
    | To_ip | To_mac | Getenv
    | Make_array | Length | Concat | Append | Prepend
    | Make_map | Has | Keys | Values | Remove
    | Min | Max | Mean | Stddev | Percentile | Sorted | Sum
    | Print | Print_err | Assert

type expr = { loc : A.location ; typ : Type.t ; desc : desc }

and desc =
    | Lit of A.literal
    | String of part list
    | Var of var
    (* In a condition, a field (its index in the registry) of a layer of the
     * packet being matched (counted from the bottom of the packet): *)
    | Packet_field of { layer : int ; field : int }
    (* The field of a record, by its index in the record type: *)
    | Field of expr * int
    | Index of expr * expr
    (* The layer of a packet ([MATCH[IP^]]), counted from the end, or from
     * the start: *)
    | Select of { packet : expr ; layer : L.layer ; from_start : bool ;
                  nth : int }
    (* With all the arguments, in the order of the function's parameters: *)
    | Call of builtin * expr list
    | Unop of A.unop * expr
    | Binop of A.binop * expr * expr
    (* In the order of the record type's fields: *)
    | Record of expr list
    | Array of expr list
    | Map of (expr * expr) list
    (* The value of that expression, as this one's type: *)
    | Convert of expr
    (* A constructor of a variant, with what it holds unless void: *)
    | Construct of string * expr option
    (* The value of its last statement, if an expression, or else void: *)
    | Block of block
    (* With no [else], an empty [else_]: *)
    | If of { cond : expr ; then_ : block ; else_ : block }
    (* The branch of the arm of the constructor of [subject]'s value, else
     * [else_], which is [None] when the arms are for every constructor: *)
    | Case of { subject : expr ; arms : arm list ; else_ : block option }

and part = Text of string | Interp of expr

(* [held] is what the constructor holds, unless void or not named: *)
and arm = { ctor : string ; held : var option ; branch : block }

and layer =
    { layer_loc : A.location ;
      layer : L.layer ;
      mode : L.mode ;
      (* By index of the field in the registry: *)
      options : (int * expr) list }

and pattern_layer =
    { pl_loc : A.location ;
      pl_layer : L.layer ;
      pl_mode : L.mode ;
      cond : expr option }

and pattern =
    { pat_loc : A.location ;
      (* How many layers of the current stack, from its bottom, are below the
       * pattern; with none, the pattern starts from the root: *)
      depth : int ;
      (* How many of its layers, from the first, are over the same layers of
       * the current stack, and see only the streams of their nodes: *)
      overlay : int ;
      pat_layers : pattern_layer list }

and stmt = { stmt_loc : A.location ; stmt : stmt_desc }

and stmt_desc =
    (* On top of the [depth] first layers of the current stack, from its
     * bottom (with none, from the root); a root that was left implicit is
     * the first layer. The first [overlay] layers are over the same layers
     * of the current stack, whose keys and options they take unless they
     * give them. The stack of [body]: *)
    | Stack of { depth : int ; overlay : int ; layers : layer list ;
                 body : block }
    (* The same, for a packet to send, which [last] is then: *)
    | Send of { depth : int ; overlay : int ; layers : layer list ; last : var }
    (* Its value unused, or that of the block it ends: *)
    | Expr of expr
    | Declare of var * expr
    (* [var], or its item at [path]: each index is bound to its variable
     * before [value], which reads them, is evaluated: *)
    | Assign of { var : var ; path : (var * expr) list ; value : expr }
    (* With [items], [var] is each of them in turn, rather than a counter: *)
    | Repeat of { var : var ; count : expr option ; items : expr option ;
                  every : expr option ; for_ : expr option ; body : block }
    | Retry of { max : expr option ; body : block }
    | Catch of block
    (* How many enclosing [repeat] and [on] to leave: *)
    | Break of int
    | Wait of expr
    (* An [expect] being an [any] of a single case; [form] is which: *)
    | Any of { form : string ; timeout : expr option ; cases : case list }
    | On of { timeout : expr option ; max : expr option ; pattern : pattern ;
              match_ : var ; body : block }

(* [match_] is the variable [MATCH] of the block: *)
and case = { pattern : pattern ; match_ : var ; body : block }

and block = stmt list

(** {2 Types} *)

let same_name a b = String.lowercase_ascii a = String.lowercase_ascii b

let lname = A.Layer_name.to_string

(* Records are compared field by field, whatever the order they were written
 * in: *)
let record_type fields =
    Type.Record (List.sort (fun (a, _) (b, _) ->
        String.compare (String.lowercase_ascii a) (String.lowercase_ascii b))
        fields)

(* The record of a layer of a received packet, with every field that can be
 * read, in whatever mode: *)
let packet_record (l : L.layer) =
    record_type (Array.to_list l.fields |> List.filter_map (fun (f : L.field) ->
        if f.read_in = [] then None else Some (f.name, f.typ)))

(* Variants are compared constructor by constructor, whatever the order they
 * were met in: *)
let variant_type ctors =
    Type.Variant (List.sort (fun (a, _) (b, _) -> String.compare a b) ctors)

(** The type of packets, such as [MATCH]: their layers from the bottom. A
 * name is one variant, which the layers that share it all read the same
 * record as: *)
let packet_type =
    Type.Array (variant_type (List.map (fun (l : L.layer) ->
        lname l.name, packet_record l) L.all |> List.unique))

(*$T packet_type
  List.for_all (fun (a : Crafty_layers.layer) -> List.for_all (fun (b : Crafty_layers.layer) -> \
      a.name <> b.name || packet_record a = packet_record b) Crafty_layers.all) Crafty_layers.all
*)

let type_of_literal = function
    | A.Bool _ -> Type.Bool
    | A.Int _ -> Type.Int
    | A.Float _ -> Type.Float
    | A.Byte _ -> Type.Byte
    | A.Interval _ -> Type.Interval
    | A.Time _ -> Type.Time
    | A.Ip _ -> Type.Ip
    | A.Mac _ -> Type.Mac

(** {2 Errors} *)

exception Error of A.location * string

(* For what refers to a variable whose declaration was in error, already
 * told: *)
exception Already_told

let error loc fmt = Printf.ksprintf (fun s -> raise (Error (loc, s))) fmt

let tname = Type.to_string

(* The name of a type with its article: *)
let a_type t =
    let n = tname t in
    (if String.length n > 0 && String.contains "aeiou" n.[0] then "an " else "a ")
    ^ n

(** {2 Conversions} *)

let convert e typ = { e with typ ; desc = Convert e }

let all_some l =
    if List.for_all Option.is_some l then Some (List.map Option.get l) else None

(* Whether a value of type [a] converts to a [b] (the conversions to IP and
 * MAC addresses checking the length at run time). A variant converts to one
 * with the same constructors and more; what they hold, the fields of a
 * record and the items of an array converting as well: *)
let rec converts a b =
    let converts_to a b = a = b || converts a b in
    match a, b with
    | Type.Int, Type.Float
    | Type.Byte, Type.Int
    | Type.String, Type.Array Type.Byte
    | Type.Array Type.Byte, (Type.String | Type.Ip | Type.Mac) -> true
    | Type.Variant cs, Type.Variant ds ->
        a <> b &&
        List.for_all (fun (n, t) ->
            match List.assoc_opt n ds with
            | Some t' -> converts_to t t'
            | None -> false) cs
    | Type.Record fs, Type.Record gs ->
        List.length fs = List.length gs &&
        List.for_all2 (fun (n, t) (n', t') -> n = n' && converts_to t t') fs gs &&
        a <> b
    | Type.Array a, Type.Array b -> converts a b
    | Type.Map (k, a), Type.Map (k', b) -> k = k' && converts a b
    | _ -> false

(* Whether a value of that type holds a variant: *)
let rec has_variant = function
    | Type.Variant _ -> true
    | Type.Record fs -> List.exists (has_variant % snd) fs
    | Type.Array t | Type.Map (_, t) -> has_variant t
    | _ -> false

(* The type that values of types [a] and [b] both convert to, if any; [a]
 * if they convert to each other. Variants make one with the constructors of
 * both: *)
let rec join_types a b =
    match a, b with
    | _ when a = b || converts b a -> Some a
    | _ when converts a b -> Some b
    | Type.Variant cs, Type.Variant ds ->
        List.fold_left (fun acc (n, t) ->
            Option.bind acc (fun acc ->
                match List.assoc_opt n acc with
                | None -> Some ((n, t) :: acc)
                | Some t' ->
                    Option.map (fun t -> (n, t) :: List.remove_assoc n acc)
                        (join_types t' t))) (Some cs) ds |>
        Option.map variant_type
    | Type.Record fs, Type.Record gs when List.map fst fs = List.map fst gs ->
        List.map2 (fun (n, t) (_, t') ->
            Option.map (fun t -> n, t) (join_types t t')) fs gs |>
        all_some |> Option.map (fun fs -> Type.Record fs)
    | Type.Array a, Type.Array b -> Option.map (fun t -> Type.Array t) (join_types a b)
    | Type.Map (k, a), Type.Map (k', b) when k = k' ->
        Option.map (fun t -> Type.Map (k, t)) (join_types a b)
    | _ -> None

(* Whether that block ends only with a break: *)
let rec diverges (b : block) =
    match List.rev b with
    | { stmt = Break _ ; _ } :: _ -> true
    | { stmt = Expr e ; _ } :: _ ->
        (match e.desc with
        | Block b -> diverges b
        | If { then_ ; else_ ; _ } -> diverges then_ && diverges else_
        | Case { arms ; else_ ; _ } ->
            List.for_all (fun a -> diverges a.branch) arms &&
            Option.map_default diverges true else_
        | _ -> false)
    | _ -> false

let block_type (b : block) =
    match List.rev b with
    | { stmt = Expr e ; _ } :: _ -> e.typ
    | _ -> Type.Void

(* [e] as a [typ], if it converts to one; that of a block, an [if] or a
 * [case] is the value of each of its branches converted: *)
let rec coerce e typ =
    if e.typ = typ then Some e else
    let with_desc = Option.map (fun desc -> { e with typ ; desc }) in
    match e.desc with
    | Block b -> with_desc (Option.map (fun b -> Block b) (coerce_tail b typ))
    | If { cond ; then_ ; else_ } ->
        with_desc (
            match coerce_tail then_ typ, coerce_tail else_ typ with
            | Some then_, Some else_ -> Some (If { cond ; then_ ; else_ })
            | _ -> None)
    | Case { subject ; arms ; else_ } ->
        let arms =
            all_some (List.map (fun a ->
                Option.map (fun branch -> { a with branch })
                    (coerce_tail a.branch typ)) arms) in
        let else_ =
            match else_ with
            | None -> Some None
            | Some b -> Option.map Option.some (coerce_tail b typ) in
        with_desc (
            match arms, else_ with
            | Some arms, Some else_ -> Some (Case { subject ; arms ; else_ })
            | _ -> None)
    | _ -> if converts e.typ typ then Some (convert e typ) else None

(* The block with its value converted to [typ]: *)
and coerce_tail b typ =
    if diverges b || block_type b = typ then Some b else
    match List.rev b with
    | ({ stmt = Expr e ; _ } as s) :: rest ->
        Option.map (fun e -> List.rev ({ s with stmt = Expr e } :: rest))
            (coerce e typ)
    | _ -> None

(* The type of the values of those blocks (of those types), to which they
 * are converted; those that end only with a break have none: *)
let join loc what branches =
    let typ =
        List.fold_left (fun acc (b, t) ->
            if diverges b then acc else
            match acc with
            | None -> Some t
            | Some a ->
                (match join_types a t with
                | Some _ as acc -> acc
                | None ->
                    error loc "The branches of this %s are of different types: %s and %s"
                        what (a_type a) (a_type t))) None branches |>
        Option.default Type.Void in
    typ, List.map (fun (b, _) -> Option.get (coerce_tail b typ)) branches

let expect what e typ =
    match coerce e typ with
    | Some e -> e
    | None -> error e.loc "%s must be %s, not %s" what (a_type typ) (a_type e.typ)

(* The type that all of [es] convert to: the [expected] one if they all do,
 * else the first one's, which the others are then told not to be: *)
let common_type expected es =
    match expected with
    | Some t when List.for_all (fun e -> coerce e t <> None) es -> t
    | _ ->
        let first = (List.hd es).typ in
        List.fold_left (fun acc e -> Option.bind acc (join_types e.typ))
            (Some first) es |>
        Option.default first

(* Conditions take integers as well, non zero being true: *)
let as_bool what e =
    match e.typ with
    | Type.Bool -> e
    | Type.Int -> convert e Type.Bool
    | t -> error e.loc "%s must be a bool, not %s" what (a_type t)

(** {2 Environment} *)

(* The errors found so far, last first: *)
type errors = (A.location * string) list ref

let tell errors = function
    | Error (loc, msg) -> errors := (loc, msg) :: !errors
    | _ -> ()

(* Where a layer's options or conditions are typed: *)
type layer_ctx =
    { cur : L.layer ;
      cur_mode : L.mode ;
      in_cond : bool ;
      (* The layers of the packet below it, from the bottom: *)
      below : (L.layer * L.mode) array }

type env =
    { (* Innermost first: *)
      vars : var list ;
      (* Declared in the current block: *)
      declared_here : string list ;
      (* Whose declaration was in error: *)
      poisoned : string list ;
      (* The current protocol stack, top first: *)
      stack : (L.layer * L.mode) list ;
      (* How many [repeat] and [on] enclose: *)
      loops : int ;
      layer_ctx : layer_ctx option ;
      (* Whether the statements of the block can wait (or send, receive,
       * loop, break), which they cannot in a block within an expression but
       * for the value of a declaration, an assignment or a statement: *)
      may_wait : bool ;
      errors : errors ;
      (* Where the variables of the declarations are declared, by id: *)
      declared_at : (int, A.location) Hashtbl.t ;
      (* The type of the variables declared there, when wider than that of
       * their value, as their assignments tell: *)
      widened : (A.location, Type.t) Hashtbl.t ;
      (* Whether a variable was widened while typing: *)
      widening : bool ref }

let bound env name =
    List.exists (fun (v : var) -> v.name = name) env.vars ||
    List.mem name env.poisoned

(* Whether a variable declared [at] that type [a] would be of a wider type
 * than it was, to be assigned a [b]: *)
let widens env at a b =
    has_variant a &&
    match join_types a b with
    | Some t -> Hashtbl.find_opt env.widened at <> Some t
    | None -> false

let new_var =
    let next = ref 0 in
    fun name typ -> incr next ; { name ; id = !next ; typ }

let lookup_var env loc name =
    match List.find_opt (fun (v : var) -> v.name = name) env.vars with
    | Some v -> v
    | None ->
        if List.mem name env.poisoned then raise Already_told ;
        if name = "MATCH" then
            error loc "MATCH is only defined in the blocks of expect, any and on" ;
        if name = "LAST" then
            error loc "LAST is only defined once a packet was sent, in that block or an enclosing one" ;
        error loc "Unknown variable %s" name

(** {2 Stacks and patterns} *)

(* [base] (top first) with layer [name] on top, and the layer: the root is
 * put below it if need be: *)
let push loc base name =
    let below = match base with [] -> None | (b, _) :: _ -> Some b in
    match L.find ?below name, below with
    | Some l, _ -> base, l
    | None, None ->
        (match L.find ~below:L.root name with
        | Some l -> [ L.root, L.Driven ], l
        | None -> error loc "%s cannot be at the bottom of a stack" (lname name))
    | None, Some (b : L.layer) ->
        if b.terminal then error loc "Nothing can be on top of %s" (L.to_string b)
        else error loc "%s cannot be on top of %s" (lname name) (L.to_string b)

let mode_on loc base (l : L.layer) ~bang =
    let mode = L.mode_of l ~bang in
    if mode = L.Driven then
        Option.may (fun ((b : L.layer), _) ->
            error loc "%s cannot be self-driven on top of a manual %s"
                (L.to_string l) (L.to_string b)
        ) (List.find_opt (fun ((b : L.layer), m) -> b.driven && m = L.Manual) base) ;
    mode

let implicit_root loc = { layer_loc = loc ; layer = L.root ; mode = L.Driven ; options = [] }

(* How many of [layers] (bottom first), from the first, are the same as
 * those of [over]: *)
let overlay over (layers : L.layer list) =
    let rec loop n = function
        | (o : L.layer) :: over, (l : L.layer) :: layers when o == l ->
            loop (n + 1) (over, layers)
        | _ -> n in
    loop 0 (over, layers)

(* Where the layers of a stack or pattern go: on top of the root, or on top
 * of the current stack once [n] layers are taken off. Returns that base and
 * the layers taken off, bottom first: *)
let anchor_base env loc = function
    | A.Absolute -> [], []
    | A.Relative n ->
        if n > List.length env.stack then
            error loc "../ goes below the bottom of the stack" ;
        List.drop n env.stack, List.rev_map fst (List.take n env.stack)

(** {2 Expressions} *)

type default =
    | Literal of A.literal
    (* The source of the argument for that parameter, after this text: *)
    | Quote of string * string
    (* No argument at all: *)
    | Omitted

type param =
    { pname : string ;
      default : default option ;
      (* What an argument of that type converts to, if acceptable: *)
      accept : Type.t -> Type.t option ;
      descr : string }

let param ?default pname descr accept = { pname ; default ; accept ; descr }

let only typs t =
    List.find_opt (fun typ -> t = typ || converts t typ) typs

let only_exactly typs t = if List.mem t typs then Some t else None

let any_value t =
    match t with Type.Void | Type.Pattern -> None | t -> Some t

let any_array t = match t with Type.Array _ -> Some t | _ -> None

let any_map t = match t with Type.Map _ -> Some t | _ -> None

let ordered = Type.[ Int ; Float ; Byte ; Interval ; Time ; String ]

(* The type of the items of an array, or of the values of a map: *)
let values_type = function
    | Type.Array t | Type.Map (_, t) -> Some t
    | _ -> None

(* An array, or a map, of values of one of [typs]: *)
let values_of typs t =
    Option.bind (values_type t) (fun v -> if List.mem v typs then Some t else None)

let scalars = Type.[ Bool ; Int ; Float ; Byte ]

(* Each function's name, parameters, and type of result given the types of
 * its arguments: *)
let builtins =
    let num = param "x" "a number" (only Type.[ Float ]) in
    let scalar =
        param "x" "a bool, int, float, byte or string"
              (only_exactly (Type.String :: scalars)) in
    (* Times and intervals as numbers of seconds: *)
    let number =
        param "x" "a bool, int, float, byte, interval, time or string"
              (only_exactly Type.(String :: Interval :: Time :: scalars)) in
    let secs what = param "x" what (only_exactly Type.[ Int ; Float ; String ]) in
    let res t _ = t in
    let sized =
        param "a" "an array, a map or a string" (function
            | Type.String | Type.Array _ | Type.Map _ as t -> Some t
            | _ -> None) in
    let some_ordered =
        param "a" "an array or a map of ordered values" (values_of ordered) in
    let item_type ts = Option.get (values_type (List.hd ts)) in
    let some_numbers =
        param "a" "an array or a map of numbers or intervals"
              (values_of Type.[ Int ; Float ; Byte ; Interval ]) in
    let float_or_interval = function
        | [ t ] when values_type t = Some Type.Interval -> Type.Interval
        | _ -> Type.Float in
    [ "rand", Rand,
        [ param "max" "an int, bool or float" ~default:(Literal (A.Float 1.))
                (only_exactly Type.[ Int ; Bool ; Float ]) ],
        (fun ts -> List.hd ts) ;
      "randbytes", Randbytes, [ param "len" "an int" (only Type.[ Int ]) ],
        res Type.bytes ;
      "exp", Exp, [ num ], res Type.Float ;
      "ln", Ln, [ num ], res Type.Float ;
      "log", Log, [ num ], res Type.Float ;
      "log2", Log2, [ param "x" "an int" (only Type.[ Int ]) ], res Type.Int ;
      "int", To_int, [ number ], res Type.Int ;
      "float", To_float, [ number ], res Type.Float ;
      "bool", To_bool, [ scalar ], res Type.Bool ;
      "byte", To_byte, [ scalar ], res Type.Byte ;
      "interval", To_interval, [ secs "a number of seconds or a string" ],
        res Type.Interval ;
      "time", To_time, [ secs "a number of seconds since 1970 or a string" ],
        res Type.Time ;
      "now", Now, [], res Type.Time ;
      "ip_addr", To_ip,
        [ param "b" "4 bytes or a string" (only_exactly Type.[ bytes ; String ]) ],
        res Type.Ip ;
      "mac_addr", To_mac,
        [ param "b" "6 bytes or a string" (only_exactly Type.[ bytes ; String ]) ],
        res Type.Mac ;
      "getenv", Getenv,
        [ param "name" "a string" (only Type.[ String ]) ;
          param "default" "a string" (only Type.[ String ]) ~default:Omitted ],
        res Type.String ;
      "array", Make_array,
        [ param "init" "a value" any_value ; param "len" "an int" (only Type.[ Int ]) ],
        (fun ts -> Type.Array (List.hd ts)) ;
      "length", Length, [ sized ], res Type.Int ;
      "count", Length, [ sized ], res Type.Int ;
      "min", Min, [ some_ordered ], item_type ;
      "max", Max, [ some_ordered ], item_type ;
      "mean", Mean, [ some_numbers ], float_or_interval ;
      (* Given then the zero of its type, by [expr]: *)
      "sum", Sum, [ some_numbers ],
        (fun ts ->
            match values_type (List.hd ts) with
            | Some (Type.Int | Type.Byte) -> Type.Int
            | Some t -> t
            | None -> assert false) ;
      "stddev", Stddev, [ some_numbers ], float_or_interval ;
      "sorted", Sorted,
        [ param "a" "an array of ordered values" (function
            | Type.Array t as a when List.mem t ordered -> Some a
            | _ -> None) ],
        List.hd ;
      "percentile", Percentile,
        [ some_ordered ; param "p" "a number" (only Type.[ Float ]) ], item_type ;
      (* Of types that [array_join] checks: *)
      "concat", Concat,
        [ param "a" "an array" any_array ; param "b" "an array" any_array ], List.hd ;
      "append", Append,
        [ param "a" "an array" any_array ; param "x" "a value" any_value ], List.hd ;
      "prepend", Prepend,
        [ param "x" "a value" any_value ; param "a" "an array" any_array ],
        (fun ts -> List.nth ts 1) ;
      "map", Make_map,
        [ param "key" "a value" any_value ; param "default" "a value" any_value ],
        (fun ts -> Type.Map (List.hd ts, List.nth ts 1)) ;
      (* Of a key that [map_call] checks: *)
      "has", Has, [ param "m" "a map" any_map ; param "k" "a value" any_value ],
        res Type.Bool ;
      "remove", Remove, [ param "m" "a map" any_map ; param "k" "a value" any_value ],
        List.hd ;
      "keys", Keys, [ param "m" "a map" any_map ],
        (function [ Type.Map (k, _) ] -> Type.Array k | _ -> assert false) ;
      "values", Values, [ param "m" "a map" any_map ],
        (function [ Type.Map (_, v) ] -> Type.Array v | _ -> assert false) ;
      "print", Print, [ param "s" "a string" (only Type.[ String ]) ], res Type.Void ;
      "print_err", Print_err, [ param "s" "a string" (only Type.[ String ]) ],
        res Type.Void ;
      (* Failing, as any error, where it is called: *)
      "assert", Assert,
        [ param "cond" "a bool or an int" (only_exactly Type.[ Bool ; Int ]) ;
          param "msg" "a string" (only Type.[ String ])
                ~default:(Quote ("Assertion failed: ", "cond")) ],
        res Type.Void ]

let find_builtin loc name =
    match List.find_opt (fun (n, _, _, _) -> same_name n name) builtins with
    | Some b -> b
    | None -> error loc "Unknown function %s" name

let numeric t = t = Type.Int || t = Type.Float

(* That call of [Concat], [Append] or [Prepend], if [x] and [y] convert to
 * arrays and items of the same type: *)
let array_join f loc x y =
    let mk x y = Some { loc ; typ = (if f = Prepend then y else x).typ ;
                        desc = Call (f, [ x ; y ]) } in
    match f, x.typ, y.typ with
    | Concat, Type.Array _, Type.Array _ ->
        (match coerce y x.typ, coerce x y.typ with
        | Some y, _ -> mk x y
        | _, Some x -> mk x y
        | None, None -> None)
    | Append, Type.Array t, _ -> Option.bind (coerce y t) (mk x)
    | Prepend, _, Type.Array t -> Option.bind (coerce x t) (fun x -> mk x y)
    | _ -> None

(* That call of [Has] or [Remove] on map [m], if [k] converts to its keys: *)
let map_call f loc typ m k =
    match m.typ with
    | Type.Map (kt, _) ->
        (match coerce k kt with
        | Some k -> { loc ; typ ; desc = Call (f, [ m ; k ]) }
        | None -> error k.loc "The keys of %s are not %s" (a_type m.typ) (a_type k.typ))
    | _ -> assert false

(* Both of the same type, converting one to the other's if need be: *)
let unify what a b =
    if a.typ = b.typ then a, b else
    let cannot () =
        error a.loc "Cannot %s %s and %s" what (a_type a.typ) (a_type b.typ) in
    match coerce a b.typ, coerce b a.typ with
    | Some a, _ -> a, b
    | _, Some b -> a, b
    | None, None ->
        (* Two variants, as one with the constructors of both: *)
        match join_types a.typ b.typ with
        | Some t ->
            (match coerce a t, coerce b t with
            | Some a, Some b -> a, b
            | _ -> cannot ())
        | None -> cannot ()

(* With [tail], [e] is the value of a declaration, an assignment or a
 * statement, which can wait if its block can. Without [used], the value of
 * a block, [if] or [case] is that of a statement: void. *)
let rec expr ?expected ?(tail=false) ?(used=true) env (e : A.expr) =
    let loc = e.loc in
    let mk typ desc = { loc ; typ ; desc } in
    (* Where the branches of a block, an [if] or a [case] are typed: *)
    let inner = if tail then env else { env with may_wait = false } in
    let branch ?(env=inner) b = block_value ?expected ~used env.errors env b in
    match e.desc with
    | A.Lit l | A.Constant (_, l) -> mk (type_of_literal l) (Lit l)
    | A.String parts ->
        mk Type.String (String (List.map (function
            | A.Text s -> Text s
            | A.Interp e ->
                let e = expr env e in
                if any_value e.typ = None then
                    error e.loc "Cannot print %s" (a_type e.typ) ;
                Interp e) parts))
    | A.Var name when A.is_constructor name && not (Crafty_parser.is_reserved name) &&
                      not (bound env name) ->
        mk (variant_type [ name, Type.Void ]) (Construct (name, None))
    | A.Var name -> var env loc name
    | A.Construct (c, None) -> mk (variant_type [ c, Type.Void ]) (Construct (c, None))
    | A.Construct (c, Some e) ->
        let e = expr env e in
        if any_value e.typ = None then
            error e.loc "A constructor cannot hold %s" (a_type e.typ) ;
        mk (variant_type [ c, e.typ ]) (Construct (c, Some e))
    | A.Layer { name ; _ } ->
        error loc "A layer is no value: %s needs a field, as in %s.src, or to \
                   select a layer of a packet, as in MATCH[%s]"
              (lname name) (lname name) (lname name)
    | A.Field ({ desc = A.Layer { name ; from_start ; nth } ; _ }, f) ->
        layer_field env loc name from_start nth f
    | A.Field (r, f) ->
        let r = expr env r in
        (match r.typ with
        | Type.Record fs ->
            (match List.findi (fun _ (n, _) -> same_name n f) fs with
            | i, (_, t) -> mk t (Field (r, i))
            | exception Not_found ->
                error loc "No field %s in %s" f (tname r.typ))
        | t -> error loc "No field %s in %s" f (a_type t))
    | A.Index (a, { desc = A.Layer { name ; from_start ; nth } ; _ }) ->
        let a = expr env a in
        (match a.typ with
        | Type.Array (Type.Variant cs) ->
            (match List.assoc_opt (lname name) cs with
            | Some t ->
                let layer = List.find (fun (l : L.layer) -> l.name = name) L.all in
                mk t (Select { packet = a ; layer ; from_start ; nth })
            | None -> error loc "No %s in %s" (lname name) (a_type a.typ))
        | t -> error loc "Cannot select a layer of %s" (a_type t))
    | A.Index (a, i) ->
        let a = expr env a in
        (match a.typ with
        | Type.Array t -> mk t (Index (a, expect "An index" (expr env i) Type.Int))
        | Type.Map (k, v) -> mk v (Index (a, expect "A key" (expr ~expected:k env i) k))
        | t -> error loc "Cannot index %s" (a_type t))
    | A.Call (f, _) when same_name f "sort" ->
        error loc "sort changes its array and has no value; sorted(a) is a sorted copy"
    | A.Call (f, args) ->
        (match call env loc f args with
        | (Concat | Append | Prepend as b), [ x ; y ], _ ->
            (match array_join b loc x y with
            | Some e -> e
            | None ->
                let x, y = a_type x.typ, a_type y.typ in
                (match b with
                | Append -> error loc "Cannot append %s to %s" y x
                | Prepend -> error loc "Cannot prepend %s to %s" x y
                | _ -> error loc "Cannot concatenate %s and %s" x y))
        | (Has | Remove as b), [ m ; k ], t -> map_call b loc t m k
        | Sum, [ a ], t ->
            let zero =
                match t with
                | Type.Float -> A.Float 0.
                | Type.Interval -> A.Interval Clock.Interval.zero
                | _ -> A.Int 0 in
            mk t (Call (Sum, [ a ; { loc ; typ = t ; desc = Lit zero } ]))
        | b, args, t -> mk t (Call (b, args)))
    | A.Unop (A.Not, e) ->
        let e = as_bool "The operand of !" (expr env e) in
        mk Type.Bool (Unop (A.Not, e))
    | A.Unop (A.Neg, e) ->
        let e = expr env e in
        if not (numeric e.typ || e.typ = Type.Interval) then
            error loc "Cannot negate %s" (a_type e.typ) ;
        mk e.typ (Unop (A.Neg, e))
    | A.Binop (op, a, b) -> binop env loc op a b
    | A.Record fields ->
        let rec dup = function
            | [] -> ()
            | (n, _) :: rest ->
                if List.exists (fun (n', _) -> same_name n n') rest then
                    error loc "Field %s given twice" n ;
                dup rest in
        dup fields ;
        let fields = List.map (fun (n, e) -> n, expr env e) fields in
        let typ = record_type (List.map (fun (n, e) -> n, e.typ) fields) in
        (match typ with
        | Type.Record fs ->
            mk typ (Record (List.map (fun (n, _) ->
                List.find (fun (n', _) -> n' = n) fields |> snd) fs))
        | _ -> assert false)
    | A.Array [] ->
        (match expected with
        | Some (Type.Array _ as t) -> mk t (Array [])
        | _ -> error loc "Cannot tell the type of the items of an empty array")
    | A.Array items ->
        let expected_item =
            match expected with Some (Type.Array t) -> Some t | _ -> None in
        let items = List.map (expr ?expected:expected_item env) items in
        let item_typ = common_type expected_item items in
        let items = List.map (fun i -> expect "An item of this array" i item_typ) items in
        mk (Type.Array item_typ) (Array items)
    | A.Map kvs ->
        let ek, ev =
            match expected with
            | Some (Type.Map (k, v)) -> Some k, Some v
            | _ -> None, None in
        let ks = List.map (fun (k, _) -> expr ?expected:ek env k) kvs
        and vs = List.map (fun (_, v) -> expr ?expected:ev env v) kvs in
        let kt = common_type ek ks and vt = common_type ev vs in
        let ks = List.map (fun k -> expect "A key of this map" k kt) ks
        and vs = List.map (fun v -> expect "A value of this map" v vt) vs in
        mk (Type.Map (kt, vt)) (Map (List.combine ks vs))
    | A.Matches _ -> error loc "=~ is not supported yet"
    | A.Block b ->
        let b, typ = branch b in
        mk typ (Block b)
    | A.If { cond ; then_ ; else_ = None } ->
        let cond = as_bool "The condition of if" (expr env cond) in
        let then_, typ = branch then_ in
        if typ <> Type.Void && not (diverges then_) then
            error loc "This if needs an else, to have a value when its condition is false" ;
        mk Type.Void (If { cond ; then_ ; else_ = [] })
    | A.If { cond ; then_ ; else_ = Some else_ } ->
        let cond = as_bool "The condition of if" (expr env cond) in
        let then_ = branch then_ in
        let else_ = branch else_ in
        (match join loc "if" [ then_ ; else_ ] with
        | typ, [ then_ ; else_ ] -> mk typ (If { cond ; then_ ; else_ })
        | _ -> assert false)
    | A.Case { var ; subject ; arms ; else_ } ->
        let subject = expr env subject in
        let ctors =
            match subject.typ with
            | Type.Variant cs -> cs
            | t -> error subject.loc "The subject of case must be a variant, \
                                      such as a layer of a packet, not %s" (a_type t) in
        (* The name of what each constructor holds: *)
        let name =
            match var, subject.desc with
            | Some n, _ -> Some n
            | None, Var v -> Some v.name
            | _ -> None in
        let arms =
            List.fold_left (fun arms (a : A.arm) ->
                let ctor =
                    match List.find_opt (fun (n, _) -> n = a.ctor) ctors with
                    | None -> List.find_opt (fun (n, _) -> same_name n a.ctor) ctors
                    | c -> c in
                match ctor with
                | None ->
                    error a.arm_loc "%s is none of %s" a.ctor
                        (String.concat ", " (List.map fst ctors))
                | Some (ctor, t) ->
                    if List.exists (fun (n, _, _) -> n = ctor) arms then
                        error a.arm_loc "%s already has a block in this case" ctor ;
                    let held =
                        match name with
                        | Some n when t <> Type.Void -> Some (new_var n t)
                        | _ -> None in
                    let env =
                        Option.map_default (fun v -> { inner with vars = v :: inner.vars })
                            inner held in
                    (ctor, held, branch ~env a.body) :: arms) [] arms |>
            List.rev in
        let missing =
            List.filter (fun (n, _) ->
                not (List.exists (fun (n', _, _) -> n' = n) arms)) ctors |>
            List.map fst in
        let else_ =
            Option.map (fun b ->
                if missing = [] then
                    error loc "This case has a block for each of %s: its else is never run"
                        (String.concat ", " (List.map fst ctors)) ;
                branch b) else_ in
        let with_branches bs =
            List.map2 (fun (ctor, held, _) branch -> { ctor ; held ; branch }) arms bs in
        let branches = List.map (fun (_, _, b) -> b) arms in
        if missing <> [] && else_ = None then (
            (* With no value when no block is run: *)
            List.iter (fun (b, typ) ->
                if typ <> Type.Void && not (diverges b) then
                    error loc "This case needs an else, or a block for each of %s, \
                               to have a value" (String.concat ", " missing)) branches ;
            mk Type.Void (Case { subject ; arms = with_branches (List.map fst branches) ;
                                 else_ = Some [] }))
        else
            let typ, bs =
                join loc "case" (branches @ Option.map_default (fun b -> [ b ]) [] else_) in
            let arm_bs, else_bs = List.split_at (List.length arms) bs in
            mk typ (Case { subject ; arms = with_branches arm_bs ;
                           else_ = List.Exceptionless.hd else_bs })

and var env loc name =
    let mk typ desc = { loc ; typ ; desc } in
    let as_var () = let v = lookup_var env loc name in mk v.typ (Var v) in
    match env.layer_ctx with
    | None -> as_var ()
    | Some ctx ->
        let field =
            if ctx.in_cond then L.find_field ctx.cur name else None in
        match field with
        | Some i ->
            let f = ctx.cur.fields.(i) in
            if not (List.mem ctx.cur_mode f.read_in) then
                error loc "%s cannot be read in a %s %s" f.name
                    (L.string_of_mode ctx.cur_mode) (L.to_string ctx.cur) ;
            mk f.typ (Packet_field { layer = Array.length ctx.below ; field = i })
        | None -> as_var ()

and layer_field env loc name from_start nth f =
    let ctx =
        match env.layer_ctx with
        | Some ctx when ctx.in_cond -> ctx
        | _ -> error loc "Fields of %s can only be read in a condition" (lname name) in
    let positions =
        Array.to_list ctx.below |>
        List.mapi (fun i (l, m) -> i, l, m) |>
        List.filter (fun (_, (l : L.layer), _) -> l.name = name) in
    let positions = if from_start then positions else List.rev positions in
    match List.nth_opt positions nth with
    | None ->
        (match List.length positions with
        | 0 -> error loc "There is no %s below %s" (lname name) (L.to_string ctx.cur)
        | 1 -> error loc "There is only one %s below %s" (lname name) (L.to_string ctx.cur)
        | n -> error loc "There are only %d %s below %s" n (lname name) (L.to_string ctx.cur))
    | Some (layer, (l : L.layer), mode) ->
        match L.find_field l f with
        | None -> error loc "%s has no field %s" (L.to_string l) f
        | Some i ->
            let fd = l.fields.(i) in
            if not (List.mem mode fd.read_in) then
                error loc "%s cannot be read in a %s %s" fd.name
                    (L.string_of_mode mode) (L.to_string l) ;
            { loc ; typ = fd.typ ; desc = Packet_field { layer ; field = i } }

(* The function, its arguments in the order of its parameters, and the type
 * of its result: *)
and call env loc f args =
    let fname, b, params, result = find_builtin loc f in
    let named =
        (* Unnamed, all the parameters in order if none has a default: *)
        if List.length params > 1 && List.length args = List.length params &&
           List.for_all (fun (a : A.arg) -> a.arg_name = None) args &&
           List.for_all (fun p -> p.default = None) params then
            List.map2 (fun p a -> p.pname, a) params args else
        List.map (fun (a : A.arg) ->
            match a.arg_name, params with
            | Some n, _ ->
                (match List.find_opt (fun p -> same_name p.pname n) params with
                | Some p -> p.pname, a
                | None -> error a.arg_loc "%s has no parameter %s" fname n)
            | None, [ p ] -> p.pname, a
            (* Else for the only one that must be given, if any: *)
            | None, _ when List.length (List.filter (fun p -> p.default = None) params) = 1 ->
                (List.find (fun p -> p.default = None) params).pname, a
            | None, _ -> error a.arg_loc "The arguments of %s must be named" fname
        ) args in
    List.iter (fun p ->
        if List.length (List.filter (fun (n, _) -> n = p.pname) named) > 1 then
            error loc "Argument %s of %s given twice" p.pname fname) params ;
    let args =
        List.filter_map (fun p ->
            match List.assoc p.pname named with
            | (a : A.arg) ->
                let e = expr env a.value in
                (match p.accept e.typ with
                | Some t -> Some (expect "" e t)
                | None ->
                    error e.loc "Argument %s of %s must be %s, not %s"
                        p.pname fname p.descr (a_type e.typ))
            | exception Not_found ->
                (match p.default with
                | Some (Literal l) -> Some { loc ; typ = type_of_literal l ; desc = Lit l }
                | Some (Quote (text, quoted)) ->
                    let (a : A.arg) = List.assoc quoted named in
                    Some { loc ; typ = Type.String ;
                           desc = String [ Text (text ^ IO.to_string A.print_bare_expr a.value) ] }
                | Some Omitted -> None
                | None -> error loc "%s needs an argument %s" fname p.pname)
        ) params in
    b, args, result (List.map (fun e -> e.typ) args)

and binop env loc op a b =
    let a = expr env a and b = expr env b in
    let mk typ desc = { loc ; typ ; desc } in
    let sym = A.string_of_binop op in
    let cannot () =
        error loc "Cannot apply %s to %s and %s" sym (a_type a.typ) (a_type b.typ) in
    match op with
    | A.Add | A.Sub | A.Mul | A.Div | A.Mod ->
        (match a.typ, b.typ with
        | (Type.Int | Type.Float), (Type.Int | Type.Float) ->
            let a, b = unify sym a b in
            mk a.typ (Binop (op, a, b))
        | Type.Interval, Type.Interval when op = A.Add || op = A.Sub ->
            mk Type.Interval (Binop (op, a, b))
        | Type.Interval, (Type.Int | Type.Float) when op = A.Mul || op = A.Div ->
            mk Type.Interval (Binop (op, a, expect "" b Type.Float))
        | (Type.Int | Type.Float), Type.Interval when op = A.Mul ->
            mk Type.Interval (Binop (op, expect "" a Type.Float, b))
        (* Numbers offset times by that many seconds: *)
        | Type.Time, Type.Time when op = A.Sub ->
            mk Type.Interval (Binop (op, a, b))
        | Type.Time, Type.Interval when op = A.Add || op = A.Sub ->
            mk Type.Time (Binop (op, a, b))
        | Type.Interval, Type.Time when op = A.Add ->
            mk Type.Time (Binop (op, a, b))
        | Type.Time, (Type.Int | Type.Float) when op = A.Add || op = A.Sub ->
            mk Type.Time (Binop (op, a, expect "" b Type.Float))
        | (Type.Int | Type.Float), Type.Time when op = A.Add ->
            mk Type.Time (Binop (op, expect "" a Type.Float, b))
        (* A concatenation, else an append, else a prepend: *)
        | (Type.Array _, _ | _, Type.Array _) when op = A.Add ->
            (match List.filter_map (fun f -> array_join f loc a b)
                                   [ Concat ; Append ; Prepend ] with
            | e :: _ -> e
            | [] -> cannot ())
        | _ -> cannot ())
    | A.BitAnd | A.BitOr | A.BitXor ->
        (match a.typ, b.typ with
        | Type.Int, Type.Int | Type.Byte, Type.Byte ->
            mk a.typ (Binop (op, a, b))
        | (Type.Int | Type.Byte), (Type.Int | Type.Byte) ->
            mk Type.Int (Binop (op, expect "" a Type.Int, expect "" b Type.Int))
        | _ -> cannot ())
    | A.And | A.Or ->
        let what = "An operand of "^ sym in
        mk Type.Bool (Binop (op, as_bool what a, as_bool what b))
    | A.Eq | A.Ne ->
        if any_value a.typ = None || any_value b.typ = None then cannot () ;
        let a, b = unify "compare" a b in
        mk Type.Bool (Binop (op, a, b))
    | A.Lt | A.Le | A.Gt | A.Ge ->
        let a, b = unify "compare" a b in
        if not (List.mem a.typ ordered) then
            error loc "Cannot order values of type %s" (tname a.typ) ;
        mk Type.Bool (Binop (op, a, b))

(* The layers of a stack statement on top of [base], over the layers [over]
 * (bottom first) that were taken off the current stack, and the new stack.
 * The layers that are over the same ones take their key, which they need
 * not give: *)
and stack_layers env base over (layers : A.layer list) =
    List.fold_left (fun (base, tls) (al : A.layer) ->
        let base', l = push al.layer_loc base al.layer_name in
        let tls =
            if base' == base then tls else implicit_root al.layer_loc :: tls in
        let mode = mode_on al.layer_loc base' l ~bang:al.manual in
        let ctx = { cur = l ; cur_mode = mode ; in_cond = false ;
                    below = Array.of_list (List.rev base') } in
        let env = { env with layer_ctx = Some ctx } in
        let options =
            List.map (fun (a : A.arg) ->
                let i =
                    match a.arg_name with
                    | Some n ->
                        (match L.find_field l n with
                        | Some i -> i
                        | None -> error a.arg_loc "%s has no field %s" (L.to_string l) n)
                    | None ->
                        (match l.default_field with
                        | Some i -> i
                        | None -> error a.arg_loc "The options of %s must be named" (L.to_string l)) in
                let f = l.fields.(i) in
                if not (List.mem mode f.set_in) then (
                    if f.set_in = [] then
                        error a.arg_loc "%s of %s cannot be set" f.name (L.to_string l)
                    else
                        error a.arg_loc "%s cannot be set in a %s %s" f.name
                            (L.string_of_mode mode) (L.to_string l)) ;
                let e = expr ~expected:f.typ env a.value in
                i, expect ("The value of "^ f.name) e f.typ
            ) al.options in
        List.iter (fun (i, (e : expr)) ->
            if List.length (List.filter (fun (i', _) -> i = i') options) > 1 then
                error e.loc "%s given twice" l.fields.(i).name) options ;
        (l, mode) :: base',
        { layer_loc = al.layer_loc ; layer = l ; mode ; options } :: tls
    ) (base, []) layers |>
    fun (base, tls) ->
        let tls = List.rev tls in
        let n = overlay over (List.map (fun tl -> tl.layer) tls) in
        List.iteri (fun j tl ->
            if j >= n then
                Array.iteri (fun i (f : L.field) ->
                    if f.pick = Some L.Required && not (List.mem_assoc i tl.options) then
                        error tl.layer_loc "%s needs a %s" (L.to_string tl.layer) f.name
                ) tl.layer.fields) tls ;
        base, tls, n

and pattern env (p : A.pattern) =
    let base, over = anchor_base env p.pat_loc p.anchor in
    let depth = List.length base in
    let _, pls =
        List.fold_left (fun (base, pls) (pl : A.pattern_layer) ->
            let base', l = push pl.pl_loc base pl.pl_name in
            let pls =
                if base' == base then pls
                else { pl_loc = pl.pl_loc ; pl_layer = L.root ; pl_mode = L.Driven ;
                       cond = None } :: pls in
            let mode = mode_on pl.pl_loc base' l ~bang:pl.pl_manual in
            let ctx = { cur = l ; cur_mode = mode ; in_cond = true ;
                        below = Array.of_list (List.rev base') } in
            let env = { env with layer_ctx = Some ctx } in
            let cond =
                Option.map (fun c ->
                    let c = expr env c in
                    match c.typ, l.default_field with
                    | (Type.Bool | Type.Int), _ -> as_bool "" c
                    | _, Some i when List.mem mode l.fields.(i).read_in ->
                        (* A value for the default field: *)
                        let f = l.fields.(i) in
                        let c = expect ("The value of "^ f.name) c f.typ in
                        let field =
                            { loc = c.loc ; typ = f.typ ;
                              desc = Packet_field { layer = Array.length ctx.below ;
                                                    field = i } } in
                        { loc = c.loc ; typ = Type.Bool ; desc = Binop (A.Eq, field, c) }
                    | t, _ ->
                        error c.loc "The condition on %s must be a bool, not %s"
                            (L.to_string l) (a_type t)
                ) pl.cond in
            (l, mode) :: base',
            { pl_loc = pl.pl_loc ; pl_layer = l ; pl_mode = mode ; cond } :: pls
        ) (base, []) p.pat_layers in
    let pat_layers = List.rev pls in
    { pat_loc = p.pat_loc ; depth ; pat_layers ;
      overlay = overlay over (List.map (fun pl -> pl.pl_layer) pat_layers) }

(** {2 Statements} *)

and opt_expr env what typ = Option.map (fun e -> expect what (expr env e) typ)

(* The statements of a block, and its type: that of its last statement if an
 * expression whose value is [used], else void: *)
and block_value ?expected ~used errors env stmts =
    let env = { env with declared_here = [] } in
    let rec loop env ss = function
        | [] -> List.rev ss, Type.Void
        | [ { A.stmt = A.Expr e ; stmt_loc } ] when used ->
            let e = expr ?expected ~tail:true env e in
            List.rev ({ stmt_loc ; stmt = Expr e } :: ss), e.typ
        | s :: rest ->
            match stmt errors env s with
            | env, Some s -> loop env (s :: ss) rest
            | env, None -> loop env ss rest in
    loop env [] stmts

and block errors env stmts = fst (block_value ~used:false errors env stmts)

(* The environment for the next statements, and the statement unless it is
 * in error: *)
and stmt errors env (s : A.stmt) =
    let loc = s.stmt_loc in
    let mk stmt = { stmt_loc = loc ; stmt } in
    let any form timeout cases =
        let timeout =
            opt_expr env ("The timeout of "^ form) Type.Interval timeout in
        let cases =
            List.map (fun (p, body) ->
                let pattern = pattern env p in
                let match_ = new_var "MATCH" packet_type in
                let body = block errors { env with vars = match_ :: env.vars } body in
                { pattern ; match_ ; body }) cases in
        env, Some (mk (Any { form ; timeout ; cases })) in
    let declare env name e =
        if List.mem name env.declared_here then
            error loc "%s is already declared in this block (:= changes it)" name ;
        let v = new_var name e.typ in
        { env with vars = v :: env.vars ;
                   declared_here = name :: env.declared_here }, v in
    try
        if not env.may_wait then (
            let what =
                match s.stmt with
                | A.Stack { body = None ; _ } -> Some "A packet"
                | A.Stack _ -> Some "A stack"
                | A.Repeat _ -> Some "repeat" | A.Foreach _ -> Some "foreach"
                | A.Retry _ -> Some "retry" | A.Catch _ -> Some "catch"
                | A.Break _ -> Some "break" | A.Wait _ -> Some "wait"
                | A.Expect _ -> Some "expect" | A.Any _ -> Some "any"
                | A.On _ -> Some "on"
                | A.Expr _ | A.Declare _ | A.Assign _ -> None in
            Option.may (fun what ->
                error loc "%s cannot be in a block within an expression, but for \
                           the value of a declaration, an assignment or a statement"
                      what) what) ;
        match s.stmt with
        | A.Stack { anchor ; layers ; body } ->
            let base, over = anchor_base env s.stmt_loc anchor in
            let stack, tls, overlay = stack_layers env base over layers in
            (* Which the parser checked: *)
            let top = fst (List.hd stack) in
            assert (top.terminal = (body = None)) ;
            let depth = List.length base in
            (match body with
            | Some body ->
                let body = block errors { env with stack } body in
                env, Some (mk (Stack { depth ; overlay ; layers = tls ; body }))
            | None ->
                (* One [LAST] per block, that the packets it sends update: *)
                let env, last =
                    if List.mem "LAST" env.declared_here then
                        env, lookup_var env loc "LAST"
                    else
                        let v = new_var "LAST" packet_type in
                        { env with vars = v :: env.vars ;
                                   declared_here = "LAST" :: env.declared_here }, v in
                env, Some (mk (Send { depth ; overlay ; layers = tls ; last })))
        (* [sort(x[i])] is [x[i] := sorted(x[i])]: *)
        | A.Expr { desc = A.Call (f, [ arg ]) ; _ }
          when same_name f "sort" && (arg.arg_name = None || arg.arg_name = Some "a") ->
            let rec target (e : A.expr) =
                match e.desc with
                | A.Var n -> n, []
                | A.Index (a, i) -> let n, is = target a in n, is @ [ i ]
                | _ -> error e.loc "sort needs a variable, or an item of one" in
            let name, is = target arg.value in
            (match (expr env arg.value).typ with
            | Type.Array t when List.mem t ordered -> ()
            | t -> error arg.value.loc "sort needs an array of ordered values, not %s" (a_type t)) ;
            let sorted = { arg.value with desc = A.Call ("sorted", [ arg ]) } in
            stmt errors env { s with stmt = A.Assign (name, is, None, sorted) }
        | A.Expr e ->
            let te = expr ~tail:true ~used:false env e in
            if te.typ <> Type.Void then (
                match e.desc with
                | A.Call (f, _) -> error loc "The result of %s is not used" f
                | _ -> error loc "This %s is not used" (tname te.typ)) ;
            env, Some (mk (Expr te))
        | A.Declare (name, e) ->
            (* A declaration in error still declares its variable, so that
             * its uses are not reported as well: *)
            let poisoned () =
                { env with poisoned = name :: env.poisoned ;
                           declared_here = name :: env.declared_here }, None in
            (* Of the type that its assignments widened it to: *)
            let widen e =
                match Hashtbl.find_opt env.widened loc with
                | Some t -> Option.default e (coerce e t)
                | None -> e in
            (match widen (expr ~tail:true env e) with
            | e when e.typ = Type.Void ->
                tell errors (Error (loc, name ^" would have no value")) ;
                poisoned ()
            | e ->
                let env, v = declare env name e in
                Hashtbl.replace env.declared_at v.id loc ;
                env, Some (mk (Declare (v, e)))
            | exception (Error _ | Already_told as ex) ->
                tell errors ex ;
                poisoned ())
        | A.Assign (name, (_ :: _ as is), op, e) ->
            let v = lookup_var env loc name in
            (* Each index is evaluated once, into a variable no program can
             * name, [x[i] op= e] being [x[#0] op e]: *)
            let typ, path, lhs, env' =
                List.fold_lefti (fun (t, path, lhs, env') n i ->
                    let t, i =
                        match t with
                        | Type.Array t -> t, expect "An index" (expr env i) Type.Int
                        | Type.Map (k, t) -> t, expect "A key" (expr ~expected:k env i) k
                        | t -> error loc "Cannot index %s" (a_type t) in
                    let iv = new_var ("#"^ string_of_int n) i.typ in
                    t, (iv, i) :: path,
                    { A.loc ; A.desc = A.Index (lhs, { A.loc ; A.desc = A.Var iv.name }) },
                    { env' with vars = iv :: env'.vars }
                ) (v.typ, [], { A.loc ; A.desc = A.Var name }, env) is in
            let e =
                match op with
                | None -> expr ~tail:true env e
                | Some op -> binop env' loc op lhs e in
            (match coerce e typ with
            | Some value -> env, Some (mk (Assign { var = v ; path = List.rev path ; value }))
            | None ->
                error loc "Cannot assign %s to an item of %s, which is %s"
                    (a_type e.typ) name (a_type typ))
        | A.Assign (name, [], op, e) ->
            let v = lookup_var env loc name in
            let e =
                match op with
                | None -> expr ~tail:true env e
                | Some op ->
                    binop env loc op { A.loc ; A.desc = A.Var name } e in
            (match coerce e v.typ, Hashtbl.find_opt env.declared_at v.id with
            | Some e, _ -> env, Some (mk (Assign { var = v ; path = [] ; value = e }))
            | None, Some at when widens env at v.typ e.typ ->
                (* The program is typed again, with that variable of a
                 * variant of the constructors of both: *)
                Hashtbl.replace env.widened at (Option.get (join_types v.typ e.typ)) ;
                env.widening := true ;
                env, None
            | None, _ ->
                error loc "Cannot assign %s to %s, which is %s"
                    (a_type e.typ) name (a_type v.typ))
        | A.Repeat { var ; count ; every ; for_ ; body } ->
            let count = opt_expr env "The count of repeat" Type.Int count
            and every = opt_expr env "The period of repeat" Type.Interval every
            and for_ = opt_expr env "The duration of repeat" Type.Interval for_ in
            let v = new_var (var |? "I") Type.Int in
            let body =
                block errors { env with vars = v :: env.vars ;
                                        loops = env.loops + 1 } body in
            env, Some (mk (Repeat { var = v ; count ; items = None ; every ;
                                    for_ ; body }))
        | A.Foreach { var ; items ; every ; for_ ; body } ->
            let items = expr env items in
            let t =
                match items.typ with
                | Type.Array t -> t
                | Type.Map (k, v) -> record_type [ "key", k ; "value", v ]
                | t -> error items.loc "The items of foreach must be an array or a map, not %s"
                           (a_type t) in
            let every = opt_expr env "The period of foreach" Type.Interval every
            and for_ = opt_expr env "The duration of foreach" Type.Interval for_ in
            let v = new_var (var |? "I") t in
            let body =
                block errors { env with vars = v :: env.vars ;
                                        loops = env.loops + 1 } body in
            env, Some (mk (Repeat { var = v ; count = None ; items = Some items ;
                                    every ; for_ ; body }))
        | A.Retry { max ; body } ->
            let max = opt_expr env "The maximum of retry" Type.Int max in
            env, Some (mk (Retry { max ; body = block errors env body }))
        | A.Catch body ->
            env, Some (mk (Catch (block errors env body)))
        | A.Break { depth } ->
            let depth =
                match depth with
                | None -> 1
                | Some { desc = A.Lit (A.Int n) ; _ } when n > 0 -> n
                | Some e -> error e.loc "The depth of break must be a positive integer" in
            if depth > env.loops then
                error loc "Break out of %d repeat, foreach or on, but %s" depth
                    (match env.loops with
                    | 0 -> "there is none"
                    | 1 -> "there is only one"
                    | n -> Printf.sprintf "there are only %d" n) ;
            env, Some (mk (Break depth))
        | A.Wait dur ->
            env, Some (mk (Wait (expect "The duration of wait" (expr env dur) Type.Interval)))
        | A.Expect { timeout ; pattern ; body } ->
            any "expect" timeout [ pattern, body ]
        | A.Any { timeout ; cases } ->
            any "any" timeout cases
        | A.On { timeout ; max ; pattern = p ; body } ->
            let timeout = opt_expr env "The timeout of on" Type.Interval timeout
            and max = opt_expr env "The maximum of on" Type.Int max in
            let pattern = pattern env p in
            let match_ = new_var "MATCH" packet_type in
            let body =
                block errors { env with vars = match_ :: env.vars ;
                                        loops = env.loops + 1 } body in
            env, Some (mk (On { timeout ; max ; pattern ; match_ ; body }))
    with Error _ | Already_told as ex ->
        tell errors ex ;
        env, None

(** The variables a program declares, with their types, in order. *)
let rec declarations (b : block) =
    List.concat_map (fun s ->
        match s.stmt with
        | Declare (v, e) -> v :: expr_declarations e
        | Assign { path ; value ; _ } ->
            List.concat_map (expr_declarations % snd) path @ expr_declarations value
        | Expr e -> expr_declarations e
        | Stack { body = b ; _ } | Retry { body = b ; _ } | Catch b
        | On { body = b ; _ } -> declarations b
        | Any { cases ; _ } -> List.concat_map (fun (c : case) -> declarations c.body) cases
        | Repeat { var ; body ; _ } -> var :: declarations body
        | _ -> []) b

and expr_declarations e =
    match e.desc with
    | Block b -> declarations b
    | If { cond ; then_ ; else_ } ->
        expr_declarations cond @ declarations then_ @ declarations else_
    | Case { subject ; arms ; else_ } ->
        expr_declarations subject @
        List.concat_map (fun a -> (match a.held with Some v -> [ v ] | None -> []) @ declarations a.branch) arms @
        Option.map_default declarations [] else_
    | Field (e, _) | Unop (_, e) | Convert e | Select { packet = e ; _ } ->
        expr_declarations e
    | Index (a, b) | Binop (_, a, b) -> expr_declarations a @ expr_declarations b
    | Call (_, es) | Record es | Array es -> List.concat_map expr_declarations es
    | Map kvs ->
        List.concat_map (fun (k, v) -> expr_declarations k @ expr_declarations v) kvs
    | String parts ->
        List.concat_map (function Interp e -> expr_declarations e | Text _ -> []) parts
    | Construct (_, e) -> Option.map_default expr_declarations [] e
    | Lit _ | Var _ | Packet_field _ -> []

(** The typed program, or the errors, in the order of the source. *)
let check (program : A.program) =
    let widened = Hashtbl.create 7 in
    (* Until no variable is widened, which types grow until they have all
     * the constructors of the program: *)
    let rec typed () =
        let errors = ref [] in
        let env = { vars = [] ; declared_here = [] ; poisoned = [] ; stack = [] ;
                    loops = 0 ; layer_ctx = None ; may_wait = true ; errors ;
                    declared_at = Hashtbl.create 7 ; widened ; widening = ref false } in
        let p = block errors env program in
        if !(env.widening) then typed () else p, errors in
    let p, errors = typed () in
    if !errors = [] then Ok p
    else
        Error (List.rev_map (fun (where, message) ->
            Crafty_parser.{ where ; message }) !errors |>
            List.sort (fun (a : Crafty_parser.error) b -> compare a.where b.where))

(* [types text] is what the program in that text declares, with the types,
 * or what is wrong with it. *)
(*$inject
  let types text =
      match Crafty_parser.parse text with
      | Error e -> IO.to_string Crafty_parser.print_error e
      | Ok p ->
          match check p with
          | Ok b ->
              String.concat ", " (List.map (fun (v : var) ->
                  v.name ^": "^ Type.to_string v.typ) (declarations b))
          | Error es ->
              String.concat "\n" (List.map (IO.to_string Crafty_parser.print_error) es)
*)

(*$= types & ~printer:identity
  "x: float, y: float, z: interval, w: float[], v: {a: byte, b: string}, u: byte" \
    (types "x = 1 + 2.5\ny = x * 2\nz = 1s * 3\nw = [1, 2.5]\nv = {b: \"x\", a: #01}\nu = v.A")
  "x: float, y: int, z: bool" \
    (types "x = rand()\ny = rand(10)\nz = rand(max=true)")
  "x: int[], y: int, z: int" \
    (types "x = array(init=0, len=3)\ny = x[1]\nz = length(x)")
  "x: int, y: bool, z: interval, b: bool" \
    (types "x = int(1.5) + log2(8)\ny = 1.2.3.4 == #01020304\nz = -1s\nb = !3 && 1")
  "x: float" \
    (types "x = 1.0\nx += 1")
  "a: int[], b: int[], c: float[], d: int[][]" \
    (types "a = [1] + [2]\nb = [1] + 2\nc = 1 + [2.5]\nd = [[1]] + [2]")
  "a: int[], b: float[], c: int[], d: float[]" \
    (types "a = [1]\na += 2\nb = append([1.5], 1)\nc = prepend(a=[2], x=1)\nd = concat([1], [2.5])")
  "m: string[int], n: int[ip], c: int, k: ip[], v: int[], b: bool, l: int" \
    (types "m = [1: \"a\"]\nn = map(key=0.0.0.0, default=0)\nc = n[1.2.3.4]\nk = keys(n)\nv = values(n)\nb = has(n, 1.2.3.4)\nl = length(m)")
  "m: float[string], n: int[{a: int}], I: {key: string, value: float}, k: string" \
    (types "m = [\"a\": 1, \"b\": 2.5]\nm[\"c\"] += 1\nm := remove(m, \"a\")\nn = [{a: 1}: 2]\nforeach m { k = I.key }")
  "I: int, x: int" (types "repeat count=2 { x = rand(max=3) }")
  "a: float, b: interval" (types "a = stddev([1, 2])\nb = stddev([1s])")
  "a: int, b: int, c: float, d: interval" \
    (types "a = sum([1])\nb = sum([#01])\nc = sum([1: 1.5])\nd = sum([1s])")
  "a: int, b: float, c: interval, d: float, e: string, f: int" \
    (types "a = min([3, 1])\nb = mean([1, 2])\nc = mean([1s, 2s])\nd = percentile([1.5, 2], 95)\ne = max([1: \"x\"])\nf = count([1: 2])")
  "x: float[][], i: int" \
    (types "x = [[1.0]]\ni = 0\nx[i][0] += 1\nx[0] := [2]")
  "x: int, y: int" \
    (types "x = SYN | ACK\ny = port_unreachable")
  "" \
    (types "/IP(dst=1.2.3.4)/ICMP { expect DestUnreachable(code == PORT_UNREACHABLE) {} }")
  "I: int" \
    (types "repeat { on Bytes(\"x\") { break 2 } }")
  "x: int, y: ip" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { any Bytes(\"a\") { x = length(MATCH) } | ../ICMP { y = MATCH[IP].src } }")
  "x: int, y: ip" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { Bytes(\"a\")\n  { x = LAST[UDP].src }\n  Bytes(\"b\")\n  expect ../UDP(IP.src == LAST[IP].dst) { y = LAST[IP].src } }")
  "t: float, x: float, p: {a: int}, y: int" \
    (types "foreach t [1, 2.5] { x = t * 2 }\nforeach p [{a: 1}] { y = p.a }")
  "n: int, x: int, y: bool, z: float" \
    (types "n = 3\nif n & 1 { x = 1 } elsif n > 2 { y = true } else { z = 1.0 }")
  "" \
    (types "/IP!(dst=1.2.3.4, id=3)/TCP!(dst=80, flags=SYN|ACK)/Bytes(\"x\")")
  "" \
    (types "/IP(dst=1.2.3.4)/ICMP/Echo/Request(\"hello\")")
  "x: ip" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { Bytes(\"hi\")\n  expect Bytes(\"ho\") { x = MATCH[IP].src } }")
  "x: int" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect ../UDP(dst == 53, IP.ttl < 3, ^IP.src = 1.2.3.4, Eth.proto == 0x800) { x = MATCH[UDP].src } }")
  "" \
    (types "/IP(dst=1.2.3.4)/TCP(dst=80) { expect ../TCP!(flags & RST, seq_num > 3) {}\n  expect ../TCP!/Bytes(data == \"x\") {} }")
  "t: time, d: interval, u: time, v: time, w: bool" \
    (types "t = now()\nd = t - time(0)\nu = t + 1\nv = 2.5 + t - 1s\nw = t < u")
*)

(* Blocks, if and case have the value of their branches, converted to the
 * same type; one ending with a break has none: *)
(*$= types & ~printer:identity
  "x: float, y: int, z: int, w: int" \
    (types "x = if 1 > 0 { 1 } else { 2.5 }\ny = { z = 2; z * 3 }\nw = 1 + if x > 1 { 1 } else { 2 }")
  "x: string, y: byte[]" \
    (types "x = if true { \"a\" } elsif false { #4142 } else { \"b\" }\ny = if true { #4142 } else { \"b\" }")
  "I: int, x: int" \
    (types "repeat { x = if I > 3 { break } else { I } }")
  "x: int" (types "if 1 { wait 1s }\nx = 1\nif x > 0 { print(\"a\") } else { x := 2 }")
  "x: ip, b: {data: byte[]}, y: byte[]" \
    (types "expect /IP { x = case MATCH[1] IP { MATCH[IP].src } | else { 0.0.0.0 }\n  case var=b MATCH[2] Bytes { y = b.data } }")
  "x: int" (types "expect /IP { x = case MATCH[0] Eth { 0 } | ICMP { 1 } | Echo { 2 } | Request { 3 } | Reply { 4 } | DestUnreachable { 5 } | TimeExceeded { 6 } | IP { 7 } | UDP { 8 } | TCP { 9 } | DNS { 10 } | Query { 11 } | Answer { 12 } | Bytes { 13 } }")
  "x: int, y: int" \
    (types "expect /IP { x = case MATCH[1] IP { wait 1s\n  1 } | else { 2 }\n  y = { expect Bytes {}\n  3 } }")
*)

(* A constructor makes a variant of its own; where variants meet, as values
 * of a variable, branches, items or operands, they make one of the
 * constructors of all: *)
(*$= types & ~printer:identity
  "r: (Failed string | Got int | Pending), r: int, n: int" \
    (types "r = Pending\nr := Got(3)\nif true { r := Failed(\"x\") }\ncase r Got { n = r } else {}")
  "x: (Err string | Ok float)[], y: (Nope | Ok int), z: bool" \
    (types "x = [Ok(1), Err(\"a\"), Ok(2.5)]\ny = if true { Ok(1) } else { Nope }\nz = Ok(1) == Err(\"a\")")
  "Pending: int, y: int" (types "Pending = 3\ny = Pending + 1")
  "Pending: int, y: (Got int | Pending)" \
    (types "Pending = 3\ny = Pending()\ny := Got(Pending)")
  "x: (A {b: (C | D)}), y: (Got int | Pending)[]" \
    (types "x = A({b: C})\nx := A({b: D})\ny = [Pending]\ny := [Got(1)]")
  "x: float[], y: {a: float}" (types "x = [1.5]\nx := [1]\ny = {a: 2.5}\ny := {a: 1}")
*)

(* What makes no sense, and where; after an error in a declaration, the uses
 * of that variable are not reported: *)
(*$= types & ~printer:identity
  "line 2, column 1: Cannot assign a float[] to x, which is an int[]" \
    (types "x = [1]\nx := [2.5]")
  "line 2, column 1: Cannot assign an int to x, which is a (Ok int)" \
    (types "x = Ok(1)\nx := 3")
  "line 2, column 1: Cannot assign a (Ok string) to r, which is a (Ok int)" \
    (types "r = Ok(1)\nr := Ok(\"s\")")
  "line 1, column 8: A constructor cannot hold a void" \
    (types "x = Ok(print(\"a\"))")
  "line 1, column 5: Cannot compare a (Ok int) and a (Ok string)" \
    (types "x = Ok(1) == Ok(\"a\")")
  "line 2, column 8: Nope is none of Ok" \
    (types "x = Ok(1)\ncase x Nope {}")
*)
(*$= types & ~printer:identity
  "line 1, column 5: Cannot apply + to a string and an int" \
    (types "x = \"a\" + 1")
  "line 1, column 8: ack is a reserved name" \
    (types "ack = 1")
  "line 2, column 1: x is already declared in this block (:= changes it)" \
    (types "x = 1\nx = 2")
  "line 2, column 1: Cannot assign a string to x, which is an int" \
    (types "x = 1\nx := \"s\"")
  "line 1, column 1: Unknown variable x" \
    (types "x := 1")
  "line 2, column 1: Cannot assign a float to x, which is an int" \
    (types "x = 1\nx += 1.5")
  "line 2, column 1: Cannot assign a float to an item of x, which is an int" \
    (types "x = [[1]]\nx[0][0] += 1.5")
  "line 1, column 5: Cannot apply + to an int[] and a string" \
    (types "x = [1] + \"a\"")
  "line 1, column 5: Cannot append a string to an int[]" \
    (types "x = append([1], \"a\")")
  "line 1, column 5: Cannot prepend an int[] to an int[]" \
    (types "x = prepend([1], [2])")
  "line 1, column 5: Cannot concatenate an int[] and a float[][]" \
    (types "x = concat([1], [[2.5]])")
  "line 1, column 11: The arguments of array must be named" \
    (types "x = array(1)")
  "line 2, column 7: A key must be an int, not a string" \
    (types "m = [1: 2]\nx = m[\"a\"]")
  "line 2, column 12: The keys of an int[int] are not a string" \
    (types "m = [1: 2]\nx = has(m, \"a\")")
  "line 1, column 9: Argument a of min must be an array or a map of ordered values, not a bool[]" \
    (types "x = min([true])")
  "line 1, column 10: Argument a of mean must be an array or a map of numbers or intervals, not an ip[]" \
    (types "x = mean([1.2.3.4])")
  "line 1, column 21: Argument p of percentile must be a number, not a string" \
    (types "x = percentile([1], \"a\")")
  "line 1, column 10: count is a reserved name" (types "count = 1")
  "line 1, column 5: sort changes its array and has no value; sorted(a) is a sorted copy" \
    (types "x = sort([1])")
  "line 1, column 6: sort needs a variable, or an item of one" (types "sort([1])")
  "line 2, column 6: sort needs an array of ordered values, not an int[int]" \
    (types "m = [1: 2]\nsort(m)")
  "line 1, column 12: Argument a of sorted must be an array of ordered values, not a bool[]" \
    (types "x = sorted([true])")
  "line 1, column 5: map needs an argument default" \
    (types "m = map(key=1)")
  "line 1, column 5: Cannot tell the type of the items of an empty array" \
    (types "m = []")
  "line 2, column 1: Cannot index an int" \
    (types "x = [1]\nx[0][0] := 1")
  "line 1, column 5: Cannot tell the type of the items of an empty array" \
    (types "x = []")
  "line 1, column 1: x would have no value" \
    (types "x = print(\"a\")")
  "line 1, column 1: The result of rand is not used" \
    (types "rand(3)")
  "line 1, column 12: Argument a of length must be an array, a map or a string, not an int" \
    (types "x = length(3)")
  "line 1, column 8: Argument cond of assert must be a bool or an int, not a string" \
    (types "assert(\"x\")")
  "line 1, column 13: Argument b of ip_addr must be 4 bytes or a string, not an int" \
    (types "x = ip_addr(1)")
  "line 1, column 1: x would have no value" \
    (types "x = assert(true)")
  "line 1, column 7: Argument s of print must be a string, not an int" \
    (types "print(1)")
  "line 1, column 1: Break out of 1 repeat, foreach or on, but there is none" \
    (types "break")
  "line 1, column 10: Break out of 2 repeat, foreach or on, but there is only one" \
    (types "repeat { break 2 }")
  "line 1, column 4: The condition of if must be a bool, not a string" \
    (types "if \"x\" {}")
  "line 1, column 13: The timeout of any must be an interval, not an int" \
    (types "any timeout=1 Bytes {}")
  "line 2, column 5: MATCH is only defined in the blocks of expect, any and on" \
    (types "any Bytes {} | Bytes { x = MATCH }\ny = MATCH")
  "line 1, column 11: The maximum of retry must be an int, not an interval" \
    (types "retry max=1s {}")
  "line 1, column 11: The items of foreach must be an array or a map, not an int" \
    (types "foreach t 3 {}")
  "line 1, column 15: The period of foreach must be an interval, not an int" \
    (types "foreach every=1 [1] {}")
  "line 2, column 2: Break out of 2 repeat, foreach or on, but there is only one" \
    (types "foreach t [1] { x = t * 2.0\n break 2 }")
  "line 1, column 22: The period of repeat must be an interval, not an int" \
    (types "repeat count=3 every=1 {}")
  "line 1, column 6: The duration of wait must be an interval, not an int" \
    (types "wait 3")
  "line 1, column 8: The timeout of expect must be an interval, not an int" \
    (types "expect 5 Bytes(\"x\") {}")
  "line 1, column 22: The value of ttl must be an int, not a string" \
    (types "/IP(dst=1.2.3.4, ttl=\"x\")/UDP(dst=53)/Bytes(\"hi\")")
  "line 1, column 30: UDP has no field flags" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53, flags=2) {}")
  "line 1, column 5: id cannot be set in a self-driven IP" \
    (types "/IP(id=3)/TCP(dst=80) {}")
  "line 1, column 19: TCP cannot be self-driven on top of a manual IP" \
    (types "/IP!(dst=1.2.3.4)/TCP(dst=80) {}")
  "line 1, column 23: type of ICMP cannot be set" \
    (types "/IP(dst=1.2.3.4)/ICMP(type=8) {}")
  "line 1, column 43: Nothing can be on top of Request" \
    (types "/IP(dst=1.2.3.4)/ICMP/Echo/Request(seq=1)/Bytes(\"x\")")
  "line 1, column 2: IP needs a dst" \
    (types "/IP/UDP(dst=53) {}")
  "line 1, column 18: TCP needs a dst" \
    (types "/IP(dst=1.2.3.4)/TCP(src=1) {}")
  "" (types "/IP(dst=1.2.3.4)/UDP(src=1) { DNS/Query(\"x\") }")
  "" (types "/IP(dst=1.2.3.4)/TCP(dst=80) { ../TCP!(flags=RST)/Bytes() }")
  "line 1, column 35: TCP needs a dst" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { ../TCP/Bytes() }")
  "line 1, column 2: UDP cannot be at the bottom of a stack" \
    (types "/UDP {}")
  "line 1, column 18: IP cannot be on top of IP" \
    (types "/IP(dst=1.2.3.4)/IP {}")
  "line 1, column 5: MATCH is only defined in the blocks of expect, any and on" \
    (types "x = MATCH")
  "line 1, column 5: LAST is only defined once a packet was sent, in that block or an enclosing one" \
    (types "x = LAST")
  "line 2, column 5: LAST is only defined once a packet was sent, in that block or an enclosing one" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { Bytes(\"a\") }\nx = LAST")
  "line 1, column 36: LAST is only defined once a packet was sent, in that block or an enclosing one" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { x = LAST\n  Bytes(\"a\") }")
  "line 1, column 5: Fields of IP can only be read in a condition" \
    (types "x = IP.src")
  "line 1, column 5: =~ is not supported yet" \
    (types "x = y =~ /IP")
  "line 1, column 39: ../ goes below the bottom of the stack" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect ../../../../UDP {} }")
  "line 1, column 46: There is no TCP below UDP" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect ../UDP(TCP.src == 1) {} }")
  "line 1, column 46: There is only one IP below UDP" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect ../UDP(IP^.ttl == 1) {} }")
  "line 1, column 46: The condition on TCP must be a bool, not a string" \
    (types "/IP(dst=1.2.3.4)/TCP(dst=80) { expect ../TCP(\"x\") {} }")
  "line 1, column 46: flags cannot be read in a self-driven TCP" \
    (types "/IP(dst=1.2.3.4)/TCP(dst=80) { expect ../TCP(flags & ACK) {} }")
  "line 1, column 5: Field a given twice" \
    (types "x = {a: 1, A: 2}")
  "line 1, column 5: Cannot order values of type ip" \
    (types "x = 1.2.3.4 < 1.2.3.5")
  "line 1, column 9: An item of this array must be an int, not a string" \
    (types "x = [1, \"a\"]")
  "line 1, column 5: Cannot apply / to an int and an interval" \
    (types "x = 3 / 2s")
  "line 1, column 5: Cannot apply + to a time and a time" \
    (types "x = now() + now()")
  "line 1, column 5: Cannot apply - to an int and a time" \
    (types "x = 1 - now()")
  "line 1, column 5: Unknown variable z\nline 3, column 1: Unknown variable w\nline 4, column 7: Argument s of print must be a string, not an int" \
    (types "x = z\ny = x + 1\nw := 1\nprint(2)")
  "line 2, column 1: This bool is not used" \
    (types "x = 1\nx == 1")
  "line 1, column 11: This int is not used\nline 1, column 22: This int is not used" \
    (types "if true { 1 } else { 2 }")
  "line 1, column 1: x would have no value" \
    (types "x = { y = 1 }")
  "line 1, column 9: This if needs an else, to have a value when its condition is false" \
    (types "y = 1 + if true { 1 }")
  "line 1, column 5: The branches of this if are of different types: an int and a string" \
    (types "x = if true { 1 } else { \"a\" }")
  "line 1, column 19: A packet cannot be in a block within an expression, but for the value of a declaration, an assignment or a statement" \
    (types "x = 1 + if true { /IP(dst=1.2.3.4)/UDP(dst=53)/Bytes(\"x\") ; 1 } else { 2 }")
  "line 1, column 13: wait cannot be in a block within an expression, but for the value of a declaration, an assignment or a statement" \
    (types "print(\"${ { wait 1s ; 1 } }\")")
  "line 1, column 6: The subject of case must be a variant, such as a layer of a packet, not an int" \
    (types "case 3 IP {}")
  "line 1, column 36: Foo is none of Answer, Bytes, DNS, DestUnreachable, Echo, Eth, ICMP, IP, Query, Reply, Request, TCP, TimeExceeded, UDP" \
    (types "expect /IP { case MATCH[0] IP {} | Foo {} }")
  "line 1, column 36: IP already has a block in this case" \
    (types "expect /IP { case MATCH[0] IP {} | ip {} }")
  "line 1, column 18: This case needs an else, or a block for each of Answer, Bytes, DNS, DestUnreachable, Echo, Eth, ICMP, Query, Reply, Request, TimeExceeded, UDP, to have a value" \
    (types "expect /IP { x = case MATCH[1] IP { 1 } | TCP { 2 } }")
  "line 1, column 18: The branches of this case are of different types: a string and an int" \
    (types "expect /IP { x = case MATCH[1] Bytes { \"a\" } | IP { 1 } | else { 2 } }")
  "line 1, column 18: This case has a block for each of Answer, Bytes, DNS, DestUnreachable, Echo, Eth, ICMP, IP, Query, Reply, Request, TCP, TimeExceeded, UDP: its else is never run" \
    (types "expect /IP { x = case MATCH[0] Eth { 0 } | ICMP { 1 } | Echo { 2 } | Request { 3 } | Reply { 4 } | DestUnreachable { 5 } | TimeExceeded { 6 } | IP { 7 } | UDP { 8 } | TCP { 9 } | DNS { 10 } | Query { 11 } | Answer { 12 } | Bytes { 13 } | else { 0 } }")
  "line 1, column 40: Unknown variable l" \
    (types "expect /IP { case MATCH[1] Bytes { x = l.data } }")
*)

(* The examples of the spec that use only v1 features: *)
(*$= types & ~printer:identity
  "num_resp: int, I: int" (types (Tools.file_content "tests/crafty/ping_counter.crafty"))
  "" (types (Tools.file_content "tests/crafty/reset.crafty"))
  "line 3, column 35: Unknown variable n" \
    (types (Tools.file_content "tests/crafty/pong_counter.crafty"))
  "line 4, column 19: flags cannot be read in a self-driven TCP" \
    (types (Tools.file_content "tests/crafty/not_acked.crafty"))
  "line 4, column 54: =~ is not supported yet" \
    (types (Tools.file_content "tests/crafty/icmp_error.crafty"))
*)
