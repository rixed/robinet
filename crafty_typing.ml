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
   from its root ([/IP] being [/Eth/IP]). A terminal layer sends a packet
   and does not stay on the current stack; other layers do, for the rest of
   the block or for the block that follows them.

   Within a pattern's condition, a name is a field of that layer if it has
   one, else a variable; [IP.src] is a field of the nearest IP below ([IP^]
   the next one, [^IP] the first one of the packet). *)
open Batteries
module A = Crafty_ast
module L = Crafty_layers
module Type = A.Type

(** {2 Typed programs} *)

(* Each declaration is a variable of its own: *)
type var = { name : string ; id : int ; typ : Type.t }

type builtin =
    | Rand | Randbytes | Exp | Ln | Log | Log2
    | To_int | To_float | To_bool | To_byte | To_interval
    | Make_array | Length | Get | Print | Print_err

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
    (* The value of that expression, as this one's type: *)
    | Convert of expr

and part = Text of string | Interp of expr

type layer =
    { layer_loc : A.location ;
      layer : L.layer ;
      mode : L.mode ;
      (* By index of the field in the registry: *)
      options : (int * expr) list }

type pattern_layer =
    { pl_loc : A.location ;
      pl_layer : L.layer ;
      pl_mode : L.mode ;
      cond : expr option }

type pattern =
    { pat_loc : A.location ;
      (* How many layers of the current stack, from its bottom, are below the
       * pattern; with none, the pattern starts from the root: *)
      depth : int ;
      pat_layers : pattern_layer list }

type stmt = { stmt_loc : A.location ; stmt : stmt_desc }

and stmt_desc =
    (* From the root if [absolute], otherwise on top of the current stack;
     * a root that was left implicit is the first layer: *)
    | Stack of { absolute : bool ; layers : layer list ; body : block option }
    | Block of block
    | Declare of var * expr
    | Assign of var * expr
    | Do of builtin * expr list
    | Repeat of { var : var ; count : expr option ; every : expr option ;
                  for_ : expr option ; body : block }
    | Retry of { max : expr option ; body : block }
    (* How many enclosing [repeat] and [on] to leave: *)
    | Break of int
    (* [match_] is the variable [MATCH] of the block: *)
    | Expect of { timeout : expr option ; pattern : pattern ; match_ : var ;
                  body : block }
    | On of { timeout : expr option ; max : expr option ; pattern : pattern ;
              match_ : var ; body : block }

and block = stmt list

(** {2 Types} *)

let same_name a b = String.lowercase_ascii a = String.lowercase_ascii b

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

(** The type of packets, such as [MATCH]: their layers from the bottom. *)
let packet_type =
    Type.Array (Type.Variant (List.map (fun (l : L.layer) ->
        l.name, packet_record l) L.all))

let type_of_literal = function
    | A.Bool _ -> Type.Bool
    | A.Int _ -> Type.Int
    | A.Float _ -> Type.Float
    | A.Byte _ -> Type.Byte
    | A.Interval _ -> Type.Interval
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

(* Whether a value of type [a] converts to a [b] (the conversions to IP and
 * MAC addresses checking the length at run time): *)
let converts a b =
    match a, b with
    | Type.Int, Type.Float
    | Type.Byte, Type.Int
    | Type.String, Type.Array Type.Byte
    | Type.Array Type.Byte, (Type.String | Type.Ip | Type.Mac) -> true
    | _ -> false

(* [e] as a [typ], if it converts to one: *)
let coerce e typ =
    if e.typ = typ then Some e
    else if converts e.typ typ then Some (convert e typ)
    else None

let expect what e typ =
    match coerce e typ with
    | Some e -> e
    | None -> error e.loc "%s must be %s, not %s" what (a_type typ) (a_type e.typ)

(* Conditions take integers as well, non zero being true: *)
let as_bool what e =
    match e.typ with
    | Type.Bool -> e
    | Type.Int -> convert e Type.Bool
    | t -> error e.loc "%s must be a bool, not %s" what (a_type t)

(** {2 Environment} *)

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
      layer_ctx : layer_ctx option }

let new_var =
    let next = ref 0 in
    fun name typ -> incr next ; { name ; id = !next ; typ }

let lookup_var env loc name =
    match List.find_opt (fun (v : var) -> v.name = name) env.vars with
    | Some v -> v
    | None ->
        if List.mem name env.poisoned then raise Already_told ;
        if name = "MATCH" then
            error loc "MATCH is only defined in the blocks of expect and on" ;
        if name = "LAST" then error loc "LAST is not supported yet" ;
        error loc "Unknown variable %s" name

(** {2 Expressions} *)

type param =
    { pname : string ;
      default : A.literal option ;
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

let scalars = Type.[ Bool ; Int ; Float ; Byte ]

(* Each function's name, parameters, and type of result given the types of
 * its arguments: *)
let builtins =
    let num = param "x" "a number" (only Type.[ Float ]) in
    let scalar = param "x" "a bool, int, float or byte" (only_exactly scalars) in
    let res t _ = t in
    [ "rand", Rand,
        [ param "max" "an int, bool or float" ~default:(A.Float 1.)
                (only_exactly Type.[ Int ; Bool ; Float ]) ],
        (fun ts -> List.hd ts) ;
      "randbytes", Randbytes, [ param "len" "an int" (only Type.[ Int ]) ],
        res Type.bytes ;
      "exp", Exp, [ num ], res Type.Float ;
      "ln", Ln, [ num ], res Type.Float ;
      "log", Log, [ num ], res Type.Float ;
      "log2", Log2, [ param "x" "an int" (only Type.[ Int ]) ], res Type.Int ;
      "int", To_int, [ scalar ], res Type.Int ;
      "float", To_float, [ scalar ], res Type.Float ;
      "bool", To_bool, [ scalar ], res Type.Bool ;
      "byte", To_byte, [ scalar ], res Type.Byte ;
      "interval", To_interval,
        [ param "x" "a number of seconds" (only_exactly Type.[ Int ; Float ]) ],
        res Type.Interval ;
      "array", Make_array,
        [ param "init" "a value" any_value ; param "len" "an int" (only Type.[ Int ]) ],
        (fun ts -> Type.Array (List.hd ts)) ;
      "length", Length,
        [ param "a" "an array" (fun t ->
            if t = Type.String then Some t else any_array t) ],
        res Type.Int ;
      "get", Get,
        [ param "a" "an array" any_array ; param "index" "an int" (only Type.[ Int ]) ],
        (function Type.Array t :: _ -> t | _ -> assert false) ;
      "print", Print, [ param "s" "a string" (only Type.[ String ]) ], res Type.Void ;
      "print_err", Print_err, [ param "s" "a string" (only Type.[ String ]) ],
        res Type.Void ]

let find_builtin loc name =
    match List.find_opt (fun (n, _, _, _) -> same_name n name) builtins with
    | Some b -> b
    | None -> error loc "Unknown function %s" name

let numeric t = t = Type.Int || t = Type.Float

(* Both of the same type, converting one to the other's if need be: *)
let unify what a b =
    if a.typ = b.typ then a, b else
    match coerce a b.typ, coerce b a.typ with
    | Some a, _ -> a, b
    | _, Some b -> a, b
    | None, None ->
        error a.loc "Cannot %s %s and %s" what (a_type a.typ) (a_type b.typ)

let rec expr ?expected env (e : A.expr) =
    let loc = e.loc in
    let mk typ desc = { loc ; typ ; desc } in
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
    | A.Var name -> var env loc name
    | A.Layer { name ; _ } ->
        error loc "A layer is no value: %s needs a field, as in %s.src, or to \
                   select a layer of a packet, as in MATCH[%s]" name name name
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
            (match List.find_opt (fun (n, _) -> same_name n name) cs with
            | Some (_, t) ->
                let layer =
                    List.find (fun (l : L.layer) -> same_name l.name name) L.all in
                mk t (Select { packet = a ; layer ; from_start ; nth })
            | None -> error loc "No %s in %s" name (a_type a.typ))
        | t -> error loc "Cannot select a layer of %s" (a_type t))
    | A.Index (a, i) ->
        let a = expr env a and i = expr env i in
        (match a.typ with
        | Type.Array t -> mk t (Index (a, expect "An index" i Type.Int))
        | t -> error loc "Cannot index %s" (a_type t))
    | A.Call (f, args) ->
        let b, args, t = call env loc f args in
        mk t (Call (b, args))
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
        let item_typ =
            match expected_item with
            | Some t when List.for_all (fun i -> coerce i t <> None) items -> t
            | _ ->
                let first = List.hd items in
                if List.exists (fun i -> i.typ = Type.Float) items &&
                   List.for_all (fun i -> numeric i.typ) items then Type.Float
                else first.typ in
        let items = List.map (fun i -> expect "An item of this array" i item_typ) items in
        mk (Type.Array item_typ) (Array items)
    | A.Matches _ -> error loc "=~ is not supported yet"

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
                    (L.string_of_mode ctx.cur_mode) ctx.cur.name ;
            mk f.typ (Packet_field { layer = Array.length ctx.below ; field = i })
        | None -> as_var ()

and layer_field env loc name from_start nth f =
    let ctx =
        match env.layer_ctx with
        | Some ctx when ctx.in_cond -> ctx
        | _ -> error loc "Fields of %s can only be read in a condition" name in
    let positions =
        Array.to_list ctx.below |>
        List.mapi (fun i (l, m) -> i, l, m) |>
        List.filter (fun (_, (l : L.layer), _) -> same_name l.name name) in
    let positions = if from_start then positions else List.rev positions in
    match List.nth_opt positions nth with
    | None ->
        (match List.length positions with
        | 0 -> error loc "There is no %s below %s" name ctx.cur.name
        | 1 -> error loc "There is only one %s below %s" name ctx.cur.name
        | n -> error loc "There are only %d %s below %s" n name ctx.cur.name)
    | Some (layer, (l : L.layer), mode) ->
        match L.find_field l f with
        | None -> error loc "%s has no field %s" l.name f
        | Some i ->
            let fd = l.fields.(i) in
            if not (List.mem mode fd.read_in) then
                error loc "%s cannot be read in a %s %s" fd.name
                    (L.string_of_mode mode) l.name ;
            { loc ; typ = fd.typ ; desc = Packet_field { layer ; field = i } }

(* The function, its arguments in the order of its parameters, and the type
 * of its result: *)
and call env loc f args =
    let fname, b, params, result = find_builtin loc f in
    let named =
        List.map (fun (a : A.arg) ->
            match a.arg_name, params with
            | Some n, _ ->
                (match List.find_opt (fun p -> same_name p.pname n) params with
                | Some p -> p.pname, a
                | None -> error a.arg_loc "%s has no parameter %s" fname n)
            | None, [ p ] -> p.pname, a
            | None, _ -> error a.arg_loc "The arguments of %s must be named" fname
        ) args in
    List.iter (fun p ->
        if List.length (List.filter (fun (n, _) -> n = p.pname) named) > 1 then
            error loc "Argument %s of %s given twice" p.pname fname) params ;
    let args =
        List.map (fun p ->
            match List.assoc p.pname named with
            | (a : A.arg) ->
                let e = expr env a.value in
                (match p.accept e.typ with
                | Some t -> expect "" e t
                | None ->
                    error e.loc "Argument %s of %s must be %s, not %s"
                        p.pname fname p.descr (a_type e.typ))
            | exception Not_found ->
                (match p.default with
                | Some l -> { loc ; typ = type_of_literal l ; desc = Lit l }
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
        if not (List.mem a.typ Type.[ Int ; Float ; Byte ; Interval ; String ]) then
            error loc "Cannot order values of type %s" (tname a.typ) ;
        mk Type.Bool (Binop (op, a, b))

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
        | None -> error loc "%s cannot be at the bottom of a stack" name)
    | None, Some (b : L.layer) ->
        if b.terminal then error loc "Nothing can be on top of %s" b.name
        else error loc "%s cannot be on top of %s" name b.name

let mode_on loc base (l : L.layer) ~bang =
    let mode = L.mode_of l ~bang in
    if mode = L.Driven then
        Option.may (fun ((b : L.layer), _) ->
            error loc "%s cannot be self-driven on top of a manual %s" l.name b.name
        ) (List.find_opt (fun ((b : L.layer), m) -> b.driven && m = L.Manual) base) ;
    mode

let implicit_root loc = { layer_loc = loc ; layer = L.root ; mode = L.Driven ; options = [] }

(* The layers of a stack statement on top of [base], and the new stack: *)
let stack_layers env base (layers : A.layer list) =
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
                        | None -> error a.arg_loc "%s has no field %s" l.name n)
                    | None ->
                        (match l.default_field with
                        | Some i -> i
                        | None -> error a.arg_loc "The options of %s must be named" l.name) in
                let f = l.fields.(i) in
                if not (List.mem mode f.set_in) then (
                    if f.set_in = [] then
                        error a.arg_loc "%s of %s cannot be set" f.name l.name
                    else
                        error a.arg_loc "%s cannot be set in a %s %s" f.name
                            (L.string_of_mode mode) l.name) ;
                let e = expr ~expected:f.typ env a.value in
                i, expect ("The value of "^ f.name) e f.typ
            ) al.options in
        List.iter (fun (i, (e : expr)) ->
            if List.length (List.filter (fun (i', _) -> i = i') options) > 1 then
                error e.loc "%s given twice" l.fields.(i).name) options ;
        (l, mode) :: base',
        { layer_loc = al.layer_loc ; layer = l ; mode ; options } :: tls
    ) (base, []) layers |>
    fun (base, tls) -> base, List.rev tls

let pattern env (p : A.pattern) =
    let base =
        match p.anchor with
        | A.Absolute -> []
        | A.Relative n ->
            if n > List.length env.stack then
                error p.pat_loc "../ goes below the bottom of the stack" ;
            List.drop n env.stack in
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
                            l.name (a_type t)
                ) pl.cond in
            (l, mode) :: base',
            { pl_loc = pl.pl_loc ; pl_layer = l ; pl_mode = mode ; cond } :: pls
        ) (base, []) p.pat_layers in
    { pat_loc = p.pat_loc ; depth ; pat_layers = List.rev pls }

(** {2 Statements} *)

(* The errors found so far, last first: *)
type errors = (A.location * string) list ref

let tell errors = function
    | Error (loc, msg) -> errors := (loc, msg) :: !errors
    | _ -> ()

let opt_expr env what typ = Option.map (fun e -> expect what (expr env e) typ)

let rec block errors env stmts =
    let env = { env with declared_here = [] } in
    List.fold_left (fun (env, ss) s ->
        match stmt errors env s with
        | env, Some s -> env, s :: ss
        | env, None -> env, ss
    ) (env, []) stmts |> snd |> List.rev

(* The environment for the next statements, and the statement unless it is
 * in error: *)
and stmt errors env (s : A.stmt) =
    let loc = s.stmt_loc in
    let mk stmt = { stmt_loc = loc ; stmt } in
    let declare env name e =
        if List.mem name env.declared_here then
            error loc "%s is already declared in this block (:= changes it)" name ;
        let v = new_var name e.typ in
        { env with vars = v :: env.vars ;
                   declared_here = name :: env.declared_here }, v in
    try
        match s.stmt with
        | A.Stack { absolute ; layers ; body } ->
            let base = if absolute then [] else env.stack in
            let stack, tls = stack_layers env base layers in
            let top, stack_after =
                match stack with
                | (top, _) :: rest when top.terminal -> top, rest
                | (top, _) :: _ -> top, stack
                | [] -> assert false in
            (match body with
            | Some body ->
                if top.terminal then
                    error loc "No block can follow %s, which sends" top.name ;
                let body = block errors { env with stack } body in
                env, Some (mk (Stack { absolute ; layers = tls ; body = Some body }))
            | None ->
                { env with stack = stack_after },
                Some (mk (Stack { absolute ; layers = tls ; body = None })))
        | A.Block b ->
            env, Some (mk (Block (block errors env b)))
        | A.Declare (name, e) ->
            (* A declaration in error still declares its variable, so that
             * its uses are not reported as well: *)
            let poisoned () =
                { env with poisoned = name :: env.poisoned ;
                           declared_here = name :: env.declared_here }, None in
            (match expr env e with
            | e when e.typ = Type.Void ->
                tell errors (Error (loc, name ^" would have no value")) ;
                poisoned ()
            | e ->
                let env, v = declare env name e in
                env, Some (mk (Declare (v, e)))
            | exception (Error _ | Already_told as ex) ->
                tell errors ex ;
                poisoned ())
        | A.Assign (name, op, e) ->
            let v = lookup_var env loc name in
            let e =
                match op with
                | None -> expr env e
                | Some op ->
                    binop env loc op { A.loc ; A.desc = A.Var name } e in
            (match coerce e v.typ with
            | Some e -> env, Some (mk (Assign (v, e)))
            | None ->
                error loc "Cannot assign %s to %s, which is %s"
                    (a_type e.typ) name (a_type v.typ))
        | A.Do (f, args) ->
            let b, args, t = call env loc f args in
            if t <> Type.Void then
                error loc "The result of %s is not used" f ;
            env, Some (mk (Do (b, args)))
        | A.Repeat { var ; count ; every ; for_ ; body } ->
            let count = opt_expr env "The count of repeat" Type.Int count
            and every = opt_expr env "The period of repeat" Type.Interval every
            and for_ = opt_expr env "The duration of repeat" Type.Interval for_ in
            let v = new_var (var |? "I") Type.Int in
            let body =
                block errors { env with vars = v :: env.vars ;
                                        loops = env.loops + 1 } body in
            env, Some (mk (Repeat { var = v ; count ; every ; for_ ; body }))
        | A.Retry { max ; body } ->
            let max = opt_expr env "The maximum of retry" Type.Int max in
            env, Some (mk (Retry { max ; body = block errors env body }))
        | A.Break { depth } ->
            let depth =
                match depth with
                | None -> 1
                | Some { desc = A.Lit (A.Int n) ; _ } when n > 0 -> n
                | Some e -> error e.loc "The depth of break must be a positive integer" in
            if depth > env.loops then
                error loc "Break out of %d repeat or on, but %s" depth
                    (match env.loops with
                    | 0 -> "there is none"
                    | 1 -> "there is only one"
                    | n -> Printf.sprintf "there are only %d" n) ;
            env, Some (mk (Break depth))
        | A.Expect { timeout ; pattern = p ; body } ->
            let timeout = opt_expr env "The timeout of expect" Type.Interval timeout in
            let pattern = pattern env p in
            let match_ = new_var "MATCH" packet_type in
            let body = block errors { env with vars = match_ :: env.vars } body in
            env, Some (mk (Expect { timeout ; pattern ; match_ ; body }))
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
        | Declare (v, _) -> [ v ]
        | Stack { body = Some b ; _ } | Block b | Retry { body = b ; _ }
        | Expect { body = b ; _ } | On { body = b ; _ } -> declarations b
        | Repeat { var ; body ; _ } -> var :: declarations body
        | _ -> []) b

(** The typed program, or the errors, in the order of the source. *)
let check (program : A.program) =
    let errors = ref [] in
    let env = { vars = [] ; declared_here = [] ; poisoned = [] ; stack = [] ;
                loops = 0 ; layer_ctx = None } in
    let p = block errors env program in
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
    (types "x = array(init=0, len=3)\ny = get(a=x, index=1)\nz = length(x)")
  "x: int, y: bool, z: interval, b: bool" \
    (types "x = int(1.5) + log2(8)\ny = 1.2.3.4 == #01020304\nz = -1s\nb = !3 && 1")
  "x: float" \
    (types "x = 1.0\nx += 1")
  "x: int, y: int" \
    (types "x = SYN | ACK\ny = port_unreachable")
  "" \
    (types "/IP/ICMP { expect DestUnreachable(code == PORT_UNREACHABLE) {} }")
  "I: int" \
    (types "repeat { on Bytes(\"x\") { break 2 } }")
  "" \
    (types "/IP!(id=3)/TCP!(dst=80, flags=SYN|ACK)/Bytes(\"x\")")
  "" \
    (types "/IP/ICMP/EchoRequest(\"hello\")")
  "x: ip" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { Bytes(\"hi\")\n  expect Bytes(\"ho\") { x = MATCH[IP].src } }")
  "x: int" \
    (types "/IP/UDP { expect ../UDP(dst == 53, IP.ttl < 3, ^IP.src = 1.2.3.4, Eth.proto == 0x800) { x = MATCH[UDP].src } }")
  "" \
    (types "/IP/TCP { expect ../TCP!(flags & RST, seq_num > 3) {}\n  expect ../TCP!/Bytes(data == \"x\") {} }")
*)

(* What makes no sense, and where; after an error in a declaration, the uses
 * of that variable are not reported: *)
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
  "line 1, column 5: Cannot tell the type of the items of an empty array" \
    (types "x = []")
  "line 1, column 1: x would have no value" \
    (types "x = print(\"a\")")
  "line 1, column 1: The result of rand is not used" \
    (types "rand(3)")
  "line 1, column 12: Argument a of length must be an array, not an int" \
    (types "x = length(3)")
  "line 1, column 7: Argument s of print must be a string, not an int" \
    (types "print(1)")
  "line 1, column 1: Break out of 1 repeat or on, but there is none" \
    (types "break")
  "line 1, column 10: Break out of 2 repeat or on, but there is only one" \
    (types "repeat { break 2 }")
  "line 1, column 11: The maximum of retry must be an int, not an interval" \
    (types "retry max=1s {}")
  "line 1, column 22: The period of repeat must be an interval, not an int" \
    (types "repeat count=3 every=1 {}")
  "line 1, column 8: The timeout of expect must be an interval, not an int" \
    (types "expect 5 Bytes(\"x\") {}")
  "line 1, column 22: The value of ttl must be an int, not a string" \
    (types "/IP(dst=1.2.3.4, ttl=\"x\")/UDP(dst=53)/Bytes(\"hi\")")
  "line 1, column 17: UDP has no field flags" \
    (types "/IP/UDP(dst=53, flags=2)")
  "line 1, column 5: id cannot be set in a self-driven IP" \
    (types "/IP(id=3)/TCP(dst=80)")
  "line 1, column 6: TCP cannot be self-driven on top of a manual IP" \
    (types "/IP!/TCP(dst=80)")
  "line 1, column 10: type of ICMP cannot be set" \
    (types "/IP/ICMP(type=8)")
  "line 1, column 28: Nothing can be on top of EchoRequest" \
    (types "/IP/ICMP/EchoRequest(id=1)/Bytes(\"x\")")
  "line 1, column 1: No block can follow Bytes, which sends" \
    (types "/IP/TCP/Bytes(\"x\") { print(\"a\") }")
  "line 1, column 2: UDP cannot be at the bottom of a stack" \
    (types "/UDP")
  "line 1, column 5: IP cannot be on top of IP" \
    (types "/IP/IP")
  "line 1, column 5: MATCH is only defined in the blocks of expect and on" \
    (types "x = MATCH")
  "line 1, column 5: LAST is not supported yet" \
    (types "x = LAST")
  "line 1, column 5: Fields of IP can only be read in a condition" \
    (types "x = IP.src")
  "line 1, column 5: =~ is not supported yet" \
    (types "x = y =~ /IP")
  "line 1, column 18: ../ goes below the bottom of the stack" \
    (types "/IP/UDP { expect ../../../../UDP {} }")
  "line 1, column 25: There is no TCP below UDP" \
    (types "/IP/UDP { expect ../UDP(TCP.src == 1) {} }")
  "line 1, column 25: There is only one IP below UDP" \
    (types "/IP/UDP { expect ../UDP(IP^.ttl == 1) {} }")
  "line 1, column 25: The condition on TCP must be a bool, not a string" \
    (types "/IP/TCP { expect ../TCP(\"x\") {} }")
  "line 1, column 25: flags cannot be read in a self-driven TCP" \
    (types "/IP/TCP { expect ../TCP(flags & ACK) {} }")
  "line 1, column 5: Field a given twice" \
    (types "x = {a: 1, A: 2}")
  "line 1, column 5: Cannot order values of type ip" \
    (types "x = 1.2.3.4 < 1.2.3.5")
  "line 1, column 9: An item of this array must be an int, not a string" \
    (types "x = [1, \"a\"]")
  "line 1, column 5: Cannot apply / to an int and an interval" \
    (types "x = 3 / 2s")
  "line 1, column 5: Unknown variable z\nline 3, column 1: Unknown variable w\nline 4, column 7: Argument s of print must be a string, not an int" \
    (types "x = z\ny = x + 1\nw := 1\nprint(2)")
*)

(* The examples of the spec that use only v1 features: *)
(*$= types & ~printer:identity
  "num_resp: int, I: int" (types (Tools.file_content "tests/crafty/ping_counter.crafty"))
  "" (types (Tools.file_content "tests/crafty/reset.crafty"))
  "line 3, column 35: Unknown variable n" \
    (types (Tools.file_content "tests/crafty/pong_counter.crafty"))
  "line 4, column 19: flags cannot be read in a self-driven TCP" \
    (types (Tools.file_content "tests/crafty/not_acked.crafty"))
  "line 4, column 19: LAST is not supported yet" \
    (types (Tools.file_content "tests/crafty/icmp_error.crafty"))
*)
