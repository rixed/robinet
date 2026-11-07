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
   one, else a variable; [IP.src] is a field of the only IP below, this one
   included ([/IP] the first one, [TimeExceeded/IP] the one on top of a
   TimeExceeded, when there are several).

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
    | To_string | To_bytes | Checksum | To_ip | To_mac | To_cidr | Getenv | Arg | Nargs | Resolve | Hostname
    | Is_ip4 | Is_ip6 | Split
    | Make_array | Length | Concat | Append | Prepend
    | Make_map | Has | Keys | Values | Remove
    | Min | Max | Mean | Stddev | Percentile | Sorted | Sum | Histogram
    | Print | Print_err | Format | Assert | Stats | Summary | Report

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
    | Slice of expr * expr option * expr option
    (* The innermost layer of a packet that a path selects ([MATCH[/IP]]),
     * of kind [layer] if its top is named: *)
    | Select of { packet : expr ; layer : L.layer option ;
                  path : string option list ; absolute : bool }
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

(* [held] is what the constructor holds, unless void: *)
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
    (* The same, for a packet to send, which [LAST] is then: *)
    | Send of { depth : int ; overlay : int ; layers : layer list ;
                (* Set to the packet as captured on its way out, once it is: *)
                capture : var option }
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
    (* How many enclosing [repeat], [on] and [spawn] to leave: *)
    | Break of int
    | Wait of expr
    | Expect of { timeout : expr option ; cases : case list }
    (* Without [for_], it ends [linger] after the statements of its block: *)
    | On of { for_ : expr option ; linger : expr option ; timeout : expr option ;
              max : expr option ; cases : case list }
    (* Without [for_], it ends with the statements of its block, as an [on]
     * without [for_] nor [linger] does: *)
    | Spawn of { for_ : expr option ; body : block }

(* Of alternative [patterns]; [match_] is the variable [MATCH] of the
 * block: *)
and case = { patterns : pattern list ; match_ : var ; body : block }

and block = stmt list

(** {2 Types} *)

let same_name a b = String.lowercase_ascii a = String.lowercase_ascii b

let lname = A.Layer_name.to_string

(** {2 Layer paths} *)

let string_of_path ~absolute path =
    (if absolute then "/" else "") ^
    String.concat "/" (List.map (Option.default "_") path)

(* The positions in [names] (bottom first), innermost first, of the layers
 * that [path] selects: the tops of the runs of layers named as it ([None]
 * being any layer), which start at the bottom (or right above a root it
 * leaves out) when [absolute]: *)
let path_positions names ~absolute path =
    let names = Array.of_list names and path = Array.of_list path in
    let n = Array.length names and k = Array.length path in
    let root = lname L.root.name in
    let rec fits s j =
        j >= k ||
        ((match path.(j) with None -> true | Some p -> names.(s + j) = p) &&
         fits s (j + 1)) in
    let starts_well s =
        not absolute ||
        s = (if names.(0) = root && path.(0) <> Some root then 1 else 0) in
    List.init (max 0 (n - k + 1)) identity |>
    List.filter_map (fun s ->
        if starts_well s && fits s 0 then Some (s + k - 1) else None) |>
    List.rev

(* The shortest path that selects only the layer at [i] in [names]: *)
let unique_path names i =
    let below = List.take (i + 1) names in
    let from_root =
        match below with
        | r :: (_ :: _ as rest) when r = lname L.root.name -> rest
        | _ -> below in
    let rec loop k =
        let path = List.drop (i + 1 - k) below |> List.map Option.some in
        if k > List.length from_root then
            string_of_path ~absolute:true (List.map Option.some from_root)
        else if path_positions names ~absolute:false path = [ i ] then
            string_of_path ~absolute:false path
        else loop (k + 1) in
    loop 1

(* Records are compared field by field, whatever the order they were written
 * in: *)
let record_type fields =
    Type.Record (List.sort (fun (a, _) (b, _) ->
        String.compare (String.lowercase_ascii a) (String.lowercase_ascii b))
        fields)

(* What [summary] gives of an array of numbers, or intervals, of type [t]: *)
let summary_of_items t =
    let avg = if t = Type.Interval then Type.Interval else Type.Float in
    record_type [ "count", Type.Int ; "min", t ; "mean", avg ; "stddev", avg ;
                  "p50", t ; "p95", t ; "p99", t ; "max", t ]

(* The record of a summary of no values, the fields but [count] of which are
 * void: *)
let is_summary typ =
    List.exists (fun t -> typ = summary_of_items t) Type.[ Int ; Float ; Interval ]

(* What [summary] gives of a value of type [typ]: arrays of numbers or
 * intervals summarized, within any other value, the rest as is: *)
let rec summary_type (typ : Type.t) =
    match typ with
    | Array (Int | Float | Interval as t) -> summary_of_items t
    | Array t when t <> Type.Byte -> Array (summary_type t)
    | Map (k, v) -> Map (k, summary_type v)
    | Record fs -> Record (List.map (fun (n, t) -> n, summary_type t) fs)
    | Variant cs -> Variant (List.map (fun (n, t) -> n, summary_type t) cs)
    | t -> t

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

(*$T packet_record
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
    | A.Cidr _ -> Type.Cidr

(** {2 Errors} *)

exception Error of A.location * string

(* For what refers to a variable whose declaration was in error, already
 * told: *)
exception Already_told

let error loc fmt = Printf.ksprintf (fun s -> raise (Error (loc, s))) fmt

(* Packets and their layers are named, rather than spelled out: *)
let tname =
    let layer = match packet_type with Type.Array t -> t | _ -> assert false in
    Type.to_string ~name:(fun t ->
        if t = packet_type then Some "packet" else
        if t = layer then Some "layer" else None)

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
    | (Type.String | Type.Ip | Type.Mac), Type.Array Type.Byte
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
      below : (L.layer * L.mode) array ;
      (* The bare names of the condition read as variables though fields of
       * [cur] (where, name, field): *)
      shadowing : (A.location * string * int) list ref ;
      (* The fields of [cur] that the condition reads with a prefix: *)
      prefixed : int list ref }

type env =
    { (* Innermost first: *)
      vars : var list ;
      (* Declared in the current block: *)
      declared_here : string list ;
      (* Whose declaration was in error: *)
      poisoned : string list ;
      (* The current protocol stack, top first: *)
      stack : (L.layer * L.mode) list ;
      (* Its layers as written, for messages: *)
      stack_text : string list ;
      (* How many [repeat] and [on] enclose: *)
      loops : int ;
      layer_ctx : layer_ctx option ;
      (* Whether the statements of the block can wait (or send, receive,
       * loop, break), which they cannot in a block within an expression but
       * for the value of a declaration, an assignment or a statement: *)
      may_wait : bool ;
      errors : errors ;
      warnings : errors ;
      (* Where the variables of the declarations are declared, by id: *)
      declared_at : (int, A.location) Hashtbl.t ;
      (* And the value they are declared with: *)
      declared_as : (int, A.expr) Hashtbl.t ;
      (* Where variables are first read, by id: *)
      reads : (int, A.location) Hashtbl.t ;
      (* The type of the variables declared there, when wider than that of
       * their value, as their assignments tell: *)
      widened : (A.location, Type.t) Hashtbl.t ;
      (* Whether a variable was widened while typing: *)
      widening : bool ref ;
      (* The constructor of what the variables of a case hold, by id: *)
      held_by : (int, string) Hashtbl.t ;
      (* The type of what each report reports, and where first: *)
      reports : (string, Type.t * A.location) Hashtbl.t ;
      (* Whether an empty array literal is of {!unknown_items} when nothing
       * tells its type, as in the value of a declaration typed first: *)
      provisional : bool ;
      (* The variables declared of such a type, by location: *)
      unknown : (A.location, string * Type.t) Hashtbl.t }

let bound env name =
    List.exists (fun (v : var) -> v.name = name) env.vars ||
    List.mem name env.poisoned

(* Whether [var], the variable of a repeat, foreach or case, is an [I] that
 * hides another: *)
let hides_i env var =
    var = None && List.exists (fun (v : var) -> v.name = "I") env.vars

(* Warns of the first read of [v], an [I] that hides another, which is
 * [what]: *)
let warn_hidden_i env what (v : var) =
    Hashtbl.find_opt env.reads v.id |>
    Option.may (fun loc ->
        env.warnings :=
            (loc, Printf.sprintf "This I is %s, which hides an outer I: \
                                  name one of them with var=" what) ::
            !(env.warnings))

(* Whether a variable declared [at] that type [a] would be of a wider type
 * than it was, to be assigned a [b]: *)
let widens env at a b =
    has_variant a &&
    match join_types a b with
    | Some t -> Hashtbl.find_opt env.widened at <> Some t
    | None -> false

(* The type of an empty array literal of a declaration, until what is added
 * to it tells the type of its items: *)
let unknown_items = Type.Array Type.Void

let rec has_unknown (typ : Type.t) =
    match typ with
    | Array Void -> true
    | Array t | Map (_, t) -> has_unknown t
    | Record fs | Variant fs -> List.exists (has_unknown % snd) fs
    | _ -> false

(* Whether [b] is [a] with what is unknown in it known: *)
let rec fills (a : Type.t) (b : Type.t) =
    match a, b with
    | Array Void, Array t -> not (has_unknown b) && t <> Type.Void
    | Array a, Array b | Map (_, a), Map (_, b) -> fills a b
    | _ -> false

(* [typ], with what [n] indexes into it reach being [t]: *)
let rec set_at (typ : Type.t) n t =
    if n = 0 then t else
    match typ with
    | Array u -> Type.Array (set_at u (n - 1) t)
    | Map (k, u) -> Type.Map (k, set_at u (n - 1) t)
    | _ -> invalid_arg "Crafty_typing.set_at"

(* What an empty array literal next to [other] is of: *)
let empty_next_to (other : Type.t) =
    match other with
    | _ when has_unknown other -> None
    | Type.Void -> None
    | Type.Array _ -> Some other
    | t -> Some (Type.Array t)

let is_empty_array (e : A.expr) = match e.desc with A.Array [] -> true | _ -> false

let new_var =
    let next = ref 0 in
    fun name typ -> incr next ; { name ; id = !next ; typ }

(** {2 What a program says of itself}
 *
 * [BUDGET], [PORTS] and [PERMISSIONS], which crafty combines with its
 * command line. What
 * a program declares is found without running it: declared at the top level
 * only, with literals only, and never assigned. *)

(** The fields of [BUDGET], named after crafty's options: *)
let budget_fields =
    Type.[ "max_duration", Interval ; "max_packets", Int ; "max_bytes", Int ;
           "max_packets_per_secs", Float ; "max_bytes_per_secs", Float ;
           "max_syns", Int ; "max_syns_per_secs", Float ]

let budget_type = record_type budget_fields

(* Ranges of ports, [first, last], whether declared as ranges or ports: *)
let ports_type = record_type Type.[ "tcp", Array (Array Int) ; "udp", Array (Array Int) ]

(* An address rule, an address standing for its /32: *)
let rule_type = Type.Variant [ "Accept", Type.Cidr ; "Deny", Type.Cidr ]

let permissions_type =
    record_type Type.[ "local_ips", Array rule_type ; "remote_ips", Array rule_type ;
                       "mac_spoofing", Bool ; "exfiltration", Bool ]

(* Bound to their values in the program as it runs: *)
let budget_var = new_var "BUDGET" budget_type
let ports_var = new_var "PORTS" ports_type
let permissions_var = new_var "PERMISSIONS" permissions_type

(* The last packet sent by any block, void until one is: *)
let last_var = new_var "LAST" packet_type

type limits =
    { (* The fields of [BUDGET] that are set, floats as floats: *)
      budget : (string * A.literal) list ;
      (* The ranges of local ports, sorted and disjoint, if restricted; then
       * the ports of a protocol without ranges are none: *)
      ports : ports option ;
      permissions : permissions }

and ports = { tcp : (int * int) list ; udp : (int * int) list }

(* The fields of [PERMISSIONS], if set: *)
and permissions =
    { local_ips : Firewall.address_rule list option ;
      remote_ips : Firewall.address_rule list option ;
      mac_spoofing : bool option ;
      exfiltration : bool option }

let no_permissions =
    { local_ips = None ; remote_ips = None ; mac_spoofing = None ;
      exfiltration = None }

let no_limits = { budget = [] ; ports = None ; permissions = no_permissions }

(* Sorted, and merged where they overlap or meet: *)
let merge_ranges rs =
    List.sort compare rs |>
    List.fold_left (fun acc (lo, hi) ->
        match acc with
        | (lo', hi') :: rest when lo <= hi' + 1 -> (lo', max hi hi') :: rest
        | _ -> (lo, hi) :: acc) [] |>
    List.rev

(*$= merge_ranges & ~printer:(IO.to_string (List.print (Tuple2.print Int.print Int.print)))
  [ 1, 5 ; 7, 9 ] (merge_ranges [ 7, 8 ; 3, 5 ; 1, 3 ; 9, 9 ])
  [] (merge_ranges [])
*)

(* The fields of the literal record [e], declaring [var], each of one of the
 * [known] types, by [f name typ value]: *)
let literal_fields var known f (e : A.expr) =
    match e.desc with
    | A.Record fs ->
        List.fold_left (fun acc (n, v) ->
            match List.find_opt (fun (k, _) -> same_name k n) known with
            | Some (k, _) when List.mem_assoc k acc ->
                error e.loc "Field %s given twice" n
            | Some (k, t) -> (k, f k t (v : A.expr)) :: acc
            | None ->
                error e.loc "No field %s in %s%s" n var
                    (A.did_you_mean (List.map fst known) n)) [] fs
    | _ -> error e.loc "%s is declared with a literal record" var

let budget_literal name typ (e : A.expr) =
    let bad () =
        error e.loc "BUDGET.%s must be a literal %s, 0 or more" name (tname typ) in
    match typ, e.desc with
    | Type.Interval, A.Lit (A.Interval i) ->
        if Clock.Interval.(compare i zero) < 0 then bad () ;
        A.Interval i
    | Type.Int, A.Lit (A.Int n) -> if n < 0 then bad () ; A.Int n
    | Type.Float, A.Lit (A.Int n) -> if n < 0 then bad () ; A.Float (float_of_int n)
    | Type.Float, A.Lit (A.Float x) -> if x < 0. then bad () ; A.Float x
    | _ -> bad ()

let port_ranges name _typ (e : A.expr) =
    let port (e : A.expr) =
        match e.desc with
        | A.Lit (A.Int p) when p > 0 && p < 0x10000 -> p
        | _ -> error e.loc "A port is a literal int, from 1 to 65535" in
    match e.desc with
    | A.Array rs ->
        List.map (fun (r : A.expr) ->
            match r.desc with
            | A.Array [ lo ; hi ] ->
                let lo = port lo and hi = port hi in
                if lo > hi then error r.loc "Empty range of ports: [%d, %d]" lo hi ;
                lo, hi
            | A.Lit _ -> let p = port r in p, p
            | _ -> error r.loc "A range of ports is [first, last], or a port") rs |>
        merge_ranges
    | _ -> error e.loc "PORTS.%s is an array of ports and ranges [first, last]" name

type permission = Rules of Firewall.address_rule list | Flag of bool

let permission_literal name typ (e : A.expr) =
    match typ, e.desc with
    | Type.Bool, A.Lit (A.Bool b) -> Flag b
    | Type.Bool, _ -> error e.loc "PERMISSIONS.%s must be true or false" name
    | _, A.Array rs ->
        Rules (List.map (fun (r : A.expr) ->
            let cidr (e : A.expr) =
                match e.desc with
                | A.Lit (A.Cidr c) -> c
                | A.Lit (A.Ip ip) -> Ip.Cidr.single ip
                | _ -> error e.loc "A rule is about a literal CIDR or IP address" in
            match r.desc with
            | A.Construct ("Accept", Some c) -> Firewall.Accept, cidr c
            | A.Construct ("Deny", Some c) -> Firewall.Deny, cidr c
            | _ -> error r.loc "A rule is Accept(CIDR) or Deny(CIDR)") rs)
    | _ -> error e.loc "PERMISSIONS.%s is an array of rules" name

(* The declarations of [BUDGET], [PORTS] and [PERMISSIONS] at the top level
 * of [program], and the rest of it: *)
let self_declarations (program : A.program) =
    List.partition (fun (s : A.stmt) ->
        match s.stmt with
        | A.Declare (n, _) -> List.mem n A.self_declared
        | _ -> false) program

(* What those declarations say, telling [errors] what is wrong with them: *)
let limits_of errors decls =
    List.fold_left (fun (declared, limits) (s : A.stmt) ->
        match s.stmt with
        | A.Declare (n, e) ->
            (try
                if List.mem n declared then
                    error s.stmt_loc "%s is already declared" n ;
                let limits =
                    if n = "BUDGET" then
                        { limits with budget = literal_fields n budget_fields budget_literal e }
                    else if n = "PERMISSIONS" then
                        let fields = match permissions_type with
                            | Type.Record fs -> fs | _ -> assert false in
                        let ps = literal_fields n fields permission_literal e in
                        let rules k =
                            match List.assoc_opt k ps with
                            | Some (Rules r) -> Some r | _ -> None
                        and flag k =
                            match List.assoc_opt k ps with
                            | Some (Flag b) -> Some b | _ -> None in
                        { limits with permissions = {
                            local_ips = rules "local_ips" ;
                            remote_ips = rules "remote_ips" ;
                            mac_spoofing = flag "mac_spoofing" ;
                            exfiltration = flag "exfiltration" } }
                    else (
                        let ranges = literal_fields n [ "tcp", Type.Void ; "udp", Type.Void ]
                                                    port_ranges e in
                        let get k = List.assoc_opt k ranges |? [] in
                        let ports = { tcp = get "tcp" ; udp = get "udp" } in
                        if ports.tcp = [] && ports.udp = [] then
                            error e.loc "PORTS gives no port" ;
                        { limits with ports = Some ports }) in
                n :: declared, limits
            with Error _ as ex -> tell errors ex ; n :: declared, limits)
        | _ -> declared, limits) ([], no_limits) decls |> snd

let least a b =
    match a, b with
    | A.Int a, A.Int b -> A.Int (min a b)
    | A.Float a, A.Float b -> A.Float (Float.min a b)
    | A.Interval a, A.Interval b ->
        A.Interval (if Clock.Interval.compare a b <= 0 then a else b)
    | _ -> invalid_arg "Crafty_typing.least"

(** What both the [program] and the [cli] allow, or why nothing is. The
 * permissions are the [program]'s, which {!resolve_permissions} combines
 * with the [cli]'s. *)
let combine ~program:a ~cli:b =
    let permissions = a.permissions in
    let budget =
        List.filter_map (fun (n, _) ->
            match List.assoc_opt n a.budget, List.assoc_opt n b.budget with
            | Some x, Some y -> Some (n, least x y)
            | Some x, None | None, Some x -> Some (n, x)
            | None, None -> None) budget_fields in
    let inter ra rb =
        List.concat_map (fun (lo, hi) ->
            List.filter_map (fun (lo', hi') ->
                let lo = max lo lo' and hi = min hi hi' in
                if lo <= hi then Some (lo, hi) else None) rb) ra |>
        merge_ranges in
    match a.ports, b.ports with
    | Some pa, Some pb ->
        let ports = { tcp = inter pa.tcp pb.tcp ; udp = inter pa.udp pb.udp } in
        if ports.tcp = [] && ports.udp = [] then Stdlib.Error "No port is allowed by both"
        else Ok { budget ; ports = Some ports ; permissions }
    | Some p, None | None, Some p -> Ok { budget ; ports = Some p ; permissions }
    | None, None -> Ok { budget ; ports = None ; permissions }

(*$T combine
  combine ~program:{ no_limits with budget = [ "max_syns", A.Int 3 ; "max_bytes", A.Int 10 ] } \
          ~cli:{ no_limits with \
                 budget = [ "max_syns", A.Int 2 ; "max_duration", A.Interval (Clock.Interval.sec 1.) ] ; \
                 ports = Some { tcp = [ 1, 10 ; 20, 30 ] ; udp = [] } } = \
    Ok { no_limits with \
         budget = [ "max_duration", A.Interval (Clock.Interval.sec 1.) ; \
                    "max_bytes", A.Int 10 ; "max_syns", A.Int 2 ] ; \
         ports = Some { tcp = [ 1, 10 ; 20, 30 ] ; udp = [] } }
  combine ~program:{ no_limits with ports = Some { tcp = [ 5, 25 ] ; udp = [ 1, 2 ] } } \
          ~cli:{ no_limits with ports = Some { tcp = [ 1, 10 ; 20, 30 ] ; udp = [] } } = \
    Ok { no_limits with ports = Some { tcp = [ 5, 10 ; 20, 25 ] ; udp = [] } }
  Result.is_error (combine ~program:{ no_limits with ports = Some { tcp = [ 1, 2 ] ; udp = [] } } \
                           ~cli:{ no_limits with ports = Some { tcp = [] ; udp = [ 1, 2 ] } })
*)

(** The permissions a program runs with, all set: the [cli]'s rules before the
 * [program]'s, or before the defaults where it sets none: accepting the
 * [local] addresses, and any remote one; the [cli]'s flags over the
 * [program]'s, false by default. *)
let resolve_permissions ~program ~cli ~local =
    let rules cli prog default = Some ((cli |? []) @ (prog |? default))
    and flag cli prog = Some (cli |? (prog |? false)) in
    { local_ips =
        rules cli.local_ips program.local_ips
              (List.map (fun ip -> Firewall.Accept, Ip.Cidr.single ip) local) ;
      remote_ips = rules cli.remote_ips program.remote_ips
                         Firewall.accept_all_addresses ;
      mac_spoofing = flag cli.mac_spoofing program.mac_spoofing ;
      exfiltration = flag cli.exfiltration program.exfiltration }

(*$T resolve_permissions
  let cidr = Firewall.cidr_of_string in \
  resolve_permissions ~local:[ Ip.Addr.of_string "10.0.0.1" ] \
    ~program:{ no_permissions with remote_ips = Some [ Firewall.Accept, cidr "10.0.0.0/8" ] ; \
                                   mac_spoofing = Some true ; exfiltration = Some true } \
    ~cli:{ no_permissions with remote_ips = Some [ Firewall.Deny, cidr "10.0.0.1" ] ; \
                               local_ips = Some [ Firewall.Deny, cidr "10.0.0.2" ] ; \
                               exfiltration = Some false } = \
    { local_ips = Some [ Firewall.Deny, cidr "10.0.0.2" ; Firewall.Accept, cidr "10.0.0.1" ] ; \
      remote_ips = Some [ Firewall.Deny, cidr "10.0.0.1" ; Firewall.Accept, cidr "10.0.0.0/8" ] ; \
      mac_spoofing = Some true ; exfiltration = Some false }
  resolve_permissions ~local:[] ~program:no_permissions ~cli:no_permissions = \
    { local_ips = Some [] ; remote_ips = Some Firewall.accept_all_addresses ; \
      mac_spoofing = Some false ; exfiltration = Some false }
*)

let lookup_var env loc name =
    match List.find_opt (fun (v : var) -> v.name = name) env.vars with
    | Some v -> v
    | None ->
        if List.mem name env.poisoned then raise Already_told ;
        if name = "MATCH" then
            error loc "MATCH is only defined in the blocks of expect and on" ;
        (* In a condition, a name can also be a field of the layer, and
         * those of the layers around it read otherwise: *)
        let fields, elsewhere =
            match env.layer_ctx with
            | Some { cur ; in_cond = true ; below ; _ } ->
                let having ls =
                    List.filter (fun l -> L.find_field l name <> None) ls |>
                    List.unique ~eq:(fun a b -> L.to_string a = L.to_string b) in
                let names ls = List.map L.to_string ls in
                Array.to_list cur.fields |> List.map (fun (fd : L.field) -> fd.name),
                (match List.rev (having (List.map fst (Array.to_list below))),
                       names (having (L.uppers cur)) with
                | l :: _, _ ->
                    let f = l.fields.(Option.get (L.find_field l name)) in
                    let l = L.to_string l in
                    Printf.sprintf ": the field of %s below is %s.%s" l l f.name
                | [], [] -> ""
                | [], ls ->
                    Printf.sprintf ": %s, on top of %s, %s one"
                        (String.concat " and " ls) (L.to_string cur)
                        (if List.length ls = 1 then "has" else "have"))
            | _ -> [], "" in
        let what =
            match env.layer_ctx with
            | Some { in_cond = true ; _ } -> "field or variable"
            | _ -> "variable" in
        let predefined =
            if elsewhere = "" && A.is_constructor name then
                "\n  The packets predefined are MATCH, the one that matched, and \
                 LAST, the last one sent."
            else "" in
        match A.did_you_mean (fields @ List.map (fun (v : var) -> v.name) env.vars) name with
        | "" -> error loc "Unknown %s %s%s%s" what name elsewhere predefined
        | hint -> error loc "Unknown %s %s%s" what name hint

(** {2 Stacks and patterns} *)

(* A stack (top first) as in messages, without the root unless alone:
 * [/IP/UDP], [/Eth]. *)
let string_of_layers stack =
    match List.rev stack with
    | [ (l, _) ] -> "/"^ L.to_string l
    | stack ->
        List.filter_map (fun ((l : L.layer), _) ->
            if l == L.root then None else Some ("/"^ L.to_string l)) stack |>
        String.concat ""

(* A stack as written (top first), without the implicit root: *)
let string_of_stack_text texts =
    match List.rev texts with
    | "Eth" :: (_ :: _ as texts) | texts -> "/"^ String.concat "/" texts

(* [base] (top first) with layer [name] on top, and the layer: the root is
 * put below it if need be: *)
let push ?(hint=lazy "") loc base name =
    let below = match base with [] -> None | (b, _) :: _ -> Some b in
    match L.find ?below name, below with
    | Some l, _ -> base, l
    | None, None ->
        (match L.find ~below:L.root name with
        | Some l -> [ L.root, L.Driven ], l
        | None ->
            error loc "%s cannot be at the bottom of a stack%s" (lname name)
                (Lazy.force hint))
    | None, Some (b : L.layer) ->
        if b.terminal then
            error loc "%s is a terminal layer, therefore %s is a complete message. \
                       No further layer can be stacked on top of it%s"
                (L.to_string b) (string_of_layers base) (Lazy.force hint)
        else
            let hint =
                match Lazy.force hint with
                | "" ->
                    "\n  On top of "^ L.to_string b ^" can be: "^
                    (L.uppers b |> List.map L.to_string |> List.unique |> String.concat ", ") ^"."
                | hint -> hint in
            error loc "%s cannot be on top of %s%s" (lname name) (L.to_string b) hint

(* What to append to the message about an unknown field [f] of [l], on top
 * of the layers [below]: a field of [l] of a similar name, or else the
 * layers that have one of that name, on top of [l] or below it: *)
(* A misspelling of a field of [l], else the layers that can be on top of
 * it or below it and have field [f]: *)
let field_hint (l : L.layer) f =
    match A.did_you_mean (Array.to_list l.fields |> List.map (fun (fd : L.field) -> fd.name)) f with
    | "" ->
        let having ls =
            List.filter (fun u -> L.find_field u f <> None) ls |>
            List.map L.to_string |> List.unique in
        let names = function
            | [ n ] -> n ^" has one"
            | ns -> String.concat ", " (List.take (List.length ns - 1) ns) ^
                    " and "^ List.last ns ^" have one" in
        (match having (L.uppers l), having l.above with
        | [], [] -> ""
        | [], ns -> ": "^ names ns ^", below it"
        | ns, [] -> ": "^ names ns ^", on top of it"
        | ns, ns' -> ": "^ names ns ^", on top of it, and "^ names ns' ^", below it")
    | hint -> hint

(* A layer as written in a stack or a pattern, for the fixes of where it
 * goes: *)
type written =
    { w_name : A.Layer_name.t ;
      bang : bool ;
      (* With no options, or no condition: *)
      plain : bool ;
      text : string }

let string_of_written anchor ws =
    IO.to_string A.print_anchor anchor ^ String.concat "/" (List.map (fun w -> w.text) ws)

(* The layers [ws] (bottom first) are on top of [base], if they can be: *)
let fits base ws =
    let no_loc = A.{ line = 0 ; column = 0 } in
    try
        List.fold_left (fun (base, ls) w ->
            let base, l = push no_loc base w.w_name in
            (l, L.mode_of l ~bang:w.bang) :: base, l :: ls) (base, []) ws |>
        fun (_, ls) -> Some (List.rev ls)
    with Error _ -> None

(* Whether a layer in mode [m] can be on top of [base], as [mode_on]
 * requires: *)
let carried base m =
    m = L.Manual ||
    not (List.exists (fun ((b : L.layer), bm) -> b.driven && bm = L.Manual) base)

let written_of (l : L.layer) m =
    let bang = m = L.Manual && l.driven in
    { w_name = l.name ; bang ; plain = true ;
      text = L.to_string l ^ (if bang then "!" else "") }

(* [ws] (bottom first) with the layers of [over] (bottom first, with their
 * modes) that they skip put back, so that they fit on top of [base] and
 * overlay [over], if they can; [None] if none is skipped: *)
let filled base over ws =
    let no_loc = A.{ line = 0 ; column = 0 } in
    let rec go base over ws acc skipped =
        match ws, over with
        | [], _ -> if skipped then Some (List.rev acc) else None
        | w :: _, ((o : L.layer), om) :: over' when o.name <> w.w_name ->
            (match go ((o, om) :: base) over' ws (written_of o om :: acc) true with
            | Some _ as r -> r
            | None -> place base over ws acc skipped)
        | _ -> place base over ws acc skipped
    and place base over ws acc skipped =
        match ws with
        | [] -> assert false
        | w :: ws ->
            match push no_loc base w.w_name with
            | exception Error _ -> None
            | base, l ->
                let m = L.mode_of l ~bang:w.bang in
                if not (carried base m) then None else
                let over = match over with (o, _) :: over when o == l -> over | _ -> [] in
                go ((l, m) :: base) over ws (w :: acc) skipped in
    go base over ws [] false

(* [ws] (bottom first) with the layers missing put in, so that they fit on
 * top of [base]: one between two of them (Echo between ICMP and Reply), or
 * any number below the first of an absolute stack (IP/UDP below DNS), each
 * time the only way with the fewest. [None] if none is missing, or if that
 * is not known: *)
let bridged base ws =
    let no_loc = A.{ line = 0 ; column = 0 } in
    let on base w =
        match push no_loc base w.w_name with
        | exception Error _ -> None
        | base, l ->
            let m = L.mode_of l ~bang:w.bang in
            if carried base m then Some ((l, m) :: base) else None in
    let rec go base acc added = function
        | [] -> if added then Some (List.rev acc) else None
        | w :: ws ->
            match bridge base w with
            | None -> None
            | Some (path, stack) ->
                go stack (w :: List.rev_append (List.map (fun (l, m) -> written_of l m) path) acc)
                   (added || path <> []) ws
    (* The fewest layers (bottom first) on top of [base] for [w] to fit, and
     * the stack with them and [w], searched one more layer at a time: *)
    and bridge base w =
        let max = if base = [] then 5 else 1 in
        let rec search depth paths =
            let found =
                List.filter_map (fun (path, base) ->
                    Option.map (fun stack -> List.rev path, stack) (on base w)) paths in
            (* Of a way through IP and one through IP6, the first: *)
            let found =
                match List.filter (fun (path, _) ->
                          not (List.exists (fun (l, _) -> l == L.ip6) path)) found with
                | [ _ ] as v4 when List.length found = 2 -> v4
                | _ -> found in
            match found with
            | [ found ] -> Some found
            | _ :: _ -> None
            | [] when depth >= max -> None
            | [] ->
                List.concat_map (fun (path, base) ->
                    let base = if base = [] then [ L.root, L.Driven ] else base in
                    L.uppers (fst (List.hd base)) |> List.filter_map (fun (u : L.layer) ->
                        if u.terminal || u.quoted || List.exists (fun (l, _) -> l == u) base
                        then None else
                        let m = if carried base L.Driven then L.mode_of u ~bang:false
                                else L.Manual in
                        Some ((u, m) :: path, (u, m) :: base))) paths |>
                search (depth + 1) in
        search 0 [ [], base ] in
    go base [] false ws

(* What tells where the layers [ws] (bottom first) can go, for the errors
 * about where they are put: the current stack, if [anchor] is relative to
 * it, and the nearest other anchor they fit on (with its shortest form, if
 * they overlay some of its layers with neither options nor another mode),
 * or else the nearest one they overlay once the layers they skip are put
 * back, or else the nearest one they fit on once the missing layers are put
 * in; if absolute or out of any stack, with the missing layers put in: *)
let where_to_hint env anchor ws =
    lazy (
        match anchor with
        | A.Relative k when env.stack <> [] ->
            let n = List.length env.stack in
            let context =
                Printf.sprintf "\n  In this block, the stack is %s (%s)."
                    (string_of_layers env.stack)
                    (List.init (n - 1) (fun j ->
                        String.repeat "../" (j + 1) ^
                        (if j = 0 then " goes back to " else " to ") ^
                        string_of_layers (List.drop (j + 1) env.stack)) |>
                     String.concat ", ") in
            let nearest =
                List.sort (fun (a, _, _) (b, _, _) ->
                    compare (abs (a - k), a) (abs (b - k), b)) in
            let fixes =
                List.init n identity |> List.filter_map (fun j ->
                    if j = k then None
                    else Option.map (fun ls -> j, ls, ws) (fits (List.drop j env.stack) ws)) |>
                nearest in
            let fixes =
                if fixes <> [] then fixes else
                List.init n identity |> List.filter_map (fun j ->
                    let base = List.drop j env.stack in
                    Option.bind (filled base (List.rev (List.take j env.stack)) ws)
                        (fun ws -> Option.map (fun ls -> j, ls, ws) (fits base ws))) |>
                nearest in
            let fixes =
                if fixes <> [] then fixes else
                List.init n identity |> List.filter_map (fun j ->
                    let base = List.drop j env.stack in
                    Option.bind (bridged base ws)
                        (fun ws -> Option.map (fun ls -> j, ls, ws) (fits base ws))) |>
                nearest in
            (match fixes with
            | [] -> context
            | (j, ls, ws) :: _ ->
                let rec same m = function
                    | ((o : L.layer), om) :: over, ((l : L.layer), w) :: rest
                      when o == l && w.plain && L.mode_of l ~bang:w.bang = om ->
                        same (m + 1) (over, rest)
                    | _ -> m in
                let m = same 0 (List.rev (List.take j env.stack), List.combine ls ws) in
                Printf.sprintf "%s\n  Do you mean \"%s\"%s?" context
                    (string_of_written (A.Relative j) ws)
                    (if m = 0 || m = List.length ws then ""
                     else Printf.sprintf " (the same as \"%s\")"
                            (string_of_written (A.Relative (j - m)) (List.drop m ws))))
        | A.Relative _ | A.Absolute when anchor <> A.Absolute || fits [] ws = None ->
            (* With the fewest layers put below, from the root, and in
             * between: *)
            (match bridged [] ws with
            | Some ws -> Printf.sprintf "\n  Do you mean \"%s\"?" (string_of_written A.Absolute ws)
            | None -> "")
        | _ -> "")

let mode_on loc base (l : L.layer) ~bang =
    let mode = L.mode_of l ~bang in
    if mode = L.Driven then
        Option.may (fun ((b : L.layer), _) ->
            error loc "%s cannot be self-driven on top of a manual %s"
                (L.to_string l) (L.to_string b)
        ) (List.find_opt (fun ((b : L.layer), m) -> b.driven && m = L.Manual) base) ;
    mode

(* The other mode of [l], when [modes] has it and not [mode]: *)
let other_mode_hint (l : L.layer) mode modes =
    let other = if mode = L.Driven then L.Manual else L.Driven in
    if l.driven && List.mem other modes then
        Printf.sprintf "\n  Do you mean \"%s%s\"?" (L.to_string l)
            (if other = L.Manual then "!" else "")
    else ""

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
let anchor_base ?(hint=lazy "") env loc = function
    | A.Absolute -> [], []
    | A.Relative n ->
        if env.stack = [] && n > 0 then
            error loc "../ goes back in the current stack, and there is none \
                       out of a block%s" (Lazy.force hint) ;
        if n > List.length env.stack then
            error loc "../ goes below the bottom of the stack%s" (Lazy.force hint) ;
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

(* Bytes print as text, other values as interpolated: *)
let printable t =
    match only Type.[ String ] t with None -> any_value t | s -> s

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
    let bytes_like name =
        param name "bytes, a byte, a string, an IP or a MAC address" (function
            | Type.Byte -> Some Type.Byte
            | t when t = Type.bytes || converts t Type.bytes -> Some Type.bytes
            | _ -> None) in
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
      "int", To_int,
        [ param "x" "a bool, int, float, byte, interval, time, string or IP address"
                (only_exactly Type.(Ip :: String :: Interval :: Time :: scalars)) ],
        res Type.Int ;
      "float", To_float, [ number ], res Type.Float ;
      "bool", To_bool, [ scalar ], res Type.Bool ;
      "byte", To_byte, [ scalar ], res Type.Byte ;
      "interval", To_interval, [ secs "a number of seconds or a string" ],
        res Type.Interval ;
      "time", To_time, [ secs "a number of seconds since 1970 or a string" ],
        res Type.Time ;
      "now", Now, [], res Type.Time ;
      (* Of a type that [expr] tells: *)
      "stats", Stats, [], res Type.Void ;
      (* Made an interpolation by [expr]: *)
      "string", To_string, [ param "x" "a value" printable ], res Type.String ;
      "bytes", To_bytes, [ bytes_like "x" ], res Type.bytes ;
      "checksum", Checksum, [ bytes_like "b" ], res Type.bytes ;
      "ip_addr", To_ip,
        [ param "b" "4 bytes, an int or a string"
                (only_exactly Type.[ bytes ; Int ; String ]) ],
        res Type.Ip ;
      "mac_addr", To_mac,
        [ param "b" "6 bytes or a string" (only_exactly Type.[ bytes ; String ]) ],
        res Type.Mac ;
      "cidr", To_cidr, [ param "s" "a string" (only Type.[ String ]) ],
        res Type.Cidr ;
      "getenv", Getenv,
        [ param "name" "a string" (only Type.[ String ]) ;
          param "default" "a string" (only Type.[ String ]) ~default:Omitted ],
        res Type.String ;
      "arg", Arg,
        [ param "n" "an int" (only Type.[ Int ]) ;
          param "default" "a string" (only Type.[ String ]) ~default:Omitted ],
        res Type.String ;
      "nargs", Nargs, [], res Type.Int ;
      "resolve", Resolve, [ param "name" "a string" (only Type.[ String ]) ],
        res (Type.Array Type.Ip) ;
      "hostname", Hostname,
        [ param "ip" "an IP address" (only Type.[ Ip ]) ;
          param "default" "a string" (only Type.[ String ]) ~default:Omitted ],
        res Type.String ;
      "is_ip4", Is_ip4, [ param "ip" "an IP address" (only Type.[ Ip ]) ],
        res Type.Bool ;
      "is_ip6", Is_ip6, [ param "ip" "an IP address" (only Type.[ Ip ]) ],
        res Type.Bool ;
      "split", Split,
        [ param "s" "a string" (only Type.[ String ]) ;
          param "by" "a string" (only Type.[ String ]) ],
        res (Type.Array Type.String) ;
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
      (* Of a type that [expr] tells: *)
      "histogram", Histogram,
        [ some_numbers ;
          param "bucket" "a number or an interval"
                (only_exactly Type.[ Int ; Float ; Interval ]) ],
        res Type.Void ;
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
      "print", Print, [ param "x" "a value" printable ], res Type.Void ;
      "print_err", Print_err, [ param "x" "a value" printable ],
        res Type.Void ;
      "format", Format, [ param "x" "a value" any_value ], res Type.String ;
      (* Of a type that [expr] tells: *)
      "summary", Summary, [ param "x" "a value" any_value ], res Type.Void ;
      (* Of a name that [expr] checks: *)
      "report", Report,
        [ param "x" "a value" any_value ; param "name" "a string" (only Type.[ String ]) ],
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
    | None ->
        error loc "Unknown function %s%s" name
            (A.did_you_mean (List.map (fun (n, _, _, _) -> n) builtins) name)

let numeric t = t = Type.Int || t = Type.Float

(* That call of [Concat], [Append] or [Prepend], if [x] and [y] convert to
 * arrays and items of the same type; an array of items not known yet (see
 * {!unknown_items}) taking the type of the other: *)
let array_join f loc x y =
    let mk x y = Some { loc ; typ = (if f = Prepend then y else x).typ ;
                        desc = Call (f, [ x ; y ]) } in
    let mk_typ typ = Some { loc ; typ ; desc = Call (f, [ x ; y ]) } in
    match f, x.typ, y.typ with
    | Concat, Type.Array Type.Void, Type.Array _ -> mk_typ y.typ
    | Concat, Type.Array _, Type.Array Type.Void -> mk_typ x.typ
    | Append, Type.Array Type.Void, t when t <> Type.Void -> mk_typ (Type.Array t)
    | Prepend, t, Type.Array Type.Void when t <> Type.Void -> mk_typ (Type.Array t)
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

(* Both of the same type, converting one to the other's if need be; to
 * bytes rather than from them, as that never fails: *)
let unify ?(describe=fun e -> a_type e.typ) what a b =
    if a.typ = b.typ then a, b else
    let cannot () =
        error a.loc "Cannot %s %s and %s" what (describe a) (describe b) in
    match (if a.typ = Type.bytes then None else coerce a b.typ), coerce b a.typ with
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

(* Where the fields of a packet sent that only its capture tells are: *)
let only_captured =
    "only a packet captured as it leaves has it (p = MESSAGE, through manual layers)"

(* [LAST[Eth]], whose [ts] is never known: *)
let is_last_eth r =
    match r.desc with
    | Select { packet = { desc = Var { name = "LAST" ; _ } ; _ } ;
               layer = Some layer ; _ } ->
        layer.name = L.(eth.name)
    | _ -> false

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
    | A.Layer { path ; absolute } ->
        let name = string_of_path ~absolute (List.map (Option.map lname) path) in
        error loc "A layer is no value: %s needs a field, as in %s.src, or to \
                   select a layer of a packet, as in MATCH[%s]"
              name name name
    | A.Field ({ desc = A.Layer { path ; absolute } ; _ }, f) ->
        layer_field env loc path absolute f
    | A.Field (r, f) ->
        let r = expr env r in
        (match r.typ with
        | Type.Record fs ->
            let has f = List.exists (fun (n, _) -> same_name n f) fs in
            let f =
                if has f then f else
                List.filter (fun l -> packet_record l = r.typ) L.all |>
                List.map (fun l -> L.unalias l f) |> List.find_opt has |? f in
            (match List.findi (fun _ (n, _) -> same_name n f) fs with
            | _, ("ts", _) when is_last_eth r ->
                error loc "LAST[Eth].ts is not known: %s" only_captured
            | i, (_, t) -> mk t (Field (r, i))
            | exception Not_found ->
                (match r.desc with
                | Select { packet ; layer = Some layer ; _ } ->
                    (* What ICMP errors quote is on top of them: *)
                    let quoted =
                        match packet.desc with
                        | Var { name ; _ } when List.memq layer L.quoted_ip.above ->
                            let l = L.to_string layer in
                            Printf.sprintf "\n  The packet it quotes is on top of it: \
                                            %s[%s/IP].id is the id of the quoted IP, \
                                            %s[/IP] the IP of the error." name l name
                        | _ -> "" in
                    let hint = field_hint layer f in
                    error loc "No field %s in %s (only %s)%s" f (L.to_string layer)
                        (tname r.typ) (if hint = "" then quoted else hint)
                | _ ->
                    (* A layer of a packet, of a kind that [case] told: *)
                    let ctor =
                        match r.desc with
                        | Var v -> Hashtbl.find_opt env.held_by v.id
                        | _ -> None in
                    let ls =
                        List.filter (fun (l : L.layer) ->
                            packet_record l = r.typ &&
                            Option.map_default ((=) (lname l.name)) true ctor) L.all in
                    let hint =
                        match List.unique (List.map (fun l -> field_hint l f) ls) with
                        | [ h ] -> h
                        | _ -> A.did_you_mean (List.map fst fs) f in
                    (match List.unique (List.map L.to_string ls) with
                    | [ n ] -> error loc "No field %s in %s (only %s)%s" f n (tname r.typ) hint
                    | _ -> error loc "No field %s in %s%s" f (tname r.typ) hint)))
        | Type.Variant cs as t ->
            no_constructor env r ;
            let have =
                List.filter_map (function
                    | c, Type.Record fs when List.exists (fun (n, _) -> same_name n f) fs ->
                        Some c
                    | _ -> None) cs in
            if have = [] then error loc "No field %s in %s" f (a_type t) else
            error loc "No field %s in %s: case tells its constructors apart, \
                       and %s have one" f (a_type t) (String.concat ", " have)
        | t -> no_constructor env r ; error loc "No field %s in %s" f (a_type t))
    | A.Index (a, { desc = A.Layer { path ; absolute } ; _ }) ->
        let a = expr env a in
        (match a.typ with
        | Type.Array (Type.Variant cs as t) ->
            List.iter (Option.may (fun n ->
                if not (List.mem_assoc (lname n) cs) then
                    error loc "No %s in %s" (lname n) (a_type a.typ))) path ;
            let layer =
                Option.map (fun n -> List.find (fun (l : L.layer) -> l.name = n) L.all)
                           (List.last path) in
            let t = Option.map_default (fun n -> List.assoc (lname n) cs) t (List.last path) in
            mk t (Select { packet = a ; layer ; path = List.map (Option.map lname) path ;
                           absolute })
        | t -> no_constructor env a ; error loc "Cannot select a layer of %s" (a_type t))
    | A.Index (a, i) ->
        let a = expr env a in
        (match a.typ with
        | Type.Array t -> mk t (Index (a, expect "An index" (expr env i) Type.Int))
        | Type.Map (k, v) -> mk v (Index (a, expect "A key" (expr ~expected:k env i) k))
        | t -> no_constructor env a ; error loc "Cannot index %s" (a_type t))
    | A.Slice (a, from, to_) ->
        let a = expr env a in
        let bound = Option.map (fun i -> expect "A bound" (expr env i) Type.Int) in
        (match a.typ with
        | Type.Array _ | Type.String -> mk a.typ (Slice (a, bound from, bound to_))
        | t -> no_constructor env a ; error loc "Cannot slice %s" (a_type t))
    | A.Call (f, _) when same_name f "sort" ->
        error loc "sort changes its array and has no value; sorted(a) is a sorted copy"
    | A.Call (f, args) ->
        (match call ?expected env loc f args with
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
        | To_string, [ x ], _ ->
            if x.typ = Type.String then { x with loc }
            else mk Type.String (String [ Interp x ])
        | Stats, [], _ ->
            (match env.stack with
            | [] -> error loc "stats() is only defined on a protocol stack"
            | (l, _) :: _ ->
                mk (record_type (L.stream_stats @ l.stats)) (Call (Stats, [])))
        | Histogram, [ a ; bucket ], _ ->
            let t =
                if values_type a.typ = Some Type.Interval then Type.Interval
                else Type.Float in
            let bucket =
                match coerce bucket t with
                | Some b -> b
                | None ->
                    error bucket.loc "The bucket of a histogram of %s must be %s, not %s"
                        (a_type a.typ) (if t = Type.Float then "a number" else "an interval")
                        (a_type bucket.typ) in
            mk (Type.Array (record_type [ "min", t ; "count", Type.Int ; "max", t ]))
               (Call (Histogram, [ a ; bucket ]))
        | Summary, [ x ], _ ->
            mk (summary_type x.typ) (Call (Summary, [ x ]))
        | Report, [ x ; name ], t ->
            (match name.desc with
            | String [ Text n ] ->
                (match Hashtbl.find_opt env.reports n with
                | Some (typ, where) when typ <> x.typ ->
                    error x.loc "Report %s is of %s since line %d, not of %s" n
                        (a_type typ) where.A.line (a_type x.typ)
                | Some _ -> ()
                | None -> Hashtbl.add env.reports n (x.typ, x.loc))
            | _ -> error name.loc "The name of a report must be a literal string") ;
            mk t (Call (Report, [ x ; name ]))
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
        | _ when env.provisional -> mk unknown_items (Array [])
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
        let name = Some (var |? "I") in
        (* Unless the hidden [I] is the subject, which the case narrows: *)
        let hides =
            hides_i env var &&
            match subject.desc with Var { name = "I" ; _ } -> false | _ -> true in
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
                        | Some n when t <> Type.Void ->
                            let v = new_var n t in
                            Hashtbl.replace env.held_by v.id ctor ;
                            Some v
                        | _ -> None in
                    let env =
                        Option.map_default (fun v -> { inner with vars = v :: inner.vars })
                            inner held in
                    let body = branch ~env a.body in
                    if hides then
                        Option.may (warn_hidden_i env ("what "^ ctor ^" holds")) held ;
                    (ctor, held, body) :: arms) [] arms |>
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

(* An operand, named if a variable, with where its type comes from: *)
and describe env e =
    match e.desc with
    | Var v when not (String.starts_with v.name "#") ->
        (match origin env v with
        | "" -> Printf.sprintf "%s (%s)" v.name (a_type e.typ)
        | o -> Printf.sprintf "%s (%s, %s)" v.name (a_type e.typ) o)
    | _ -> a_type e.typ

(* Where [v] was declared, and as what if short: *)
and origin env (v : var) =
    match Hashtbl.find_opt env.declared_at v.id with
    | None -> ""
    | Some loc ->
        let as_ =
            match Hashtbl.find_opt env.declared_as v.id with
            | Some e ->
                let s = IO.to_string A.print_bare_expr e in
                if String.length s <= 40 && not (String.contains s '\n') then " as "^ s else ""
            | None -> "" in
        Printf.sprintf "declared at line %d%s" loc.line as_

(* A capitalized name that is not a variable is a constructor ([Pending]),
 * which no operation applies to but [case]: used otherwise, it is more likely
 * a misnamed variable. *)
and no_constructor env e =
    match e.desc with
    | Construct (c, None) -> ignore (var env e.loc c)
    | _ -> ()

and var env loc name =
    let mk typ desc = { loc ; typ ; desc } in
    let as_var () =
        let v = lookup_var env loc name in
        if not (Hashtbl.mem env.reads v.id) then Hashtbl.add env.reads v.id loc ;
        mk v.typ (Var v) in
    match env.layer_ctx with
    | Some ctx when ctx.in_cond ->
        (match L.find_field ctx.cur name with
        | Some i when bound env name ->
            ctx.shadowing := (loc, name, i) :: !(ctx.shadowing) ;
            as_var ()
        | Some i ->
            let f = ctx.cur.fields.(i) in
            if not (List.mem ctx.cur_mode f.read_in) then
                error loc "%s cannot be read in a %s %s%s" f.name
                    (L.string_of_mode ctx.cur_mode) (L.to_string ctx.cur)
                    (other_mode_hint ctx.cur ctx.cur_mode f.read_in) ;
            mk f.typ (Packet_field { layer = Array.length ctx.below ; field = i })
        | None -> as_var ())
    | _ -> as_var ()

and layer_field env loc path absolute f =
    let ctx =
        match env.layer_ctx with
        | Some ctx when ctx.in_cond -> ctx
        | ctx ->
            let n = string_of_path ~absolute (List.map (Option.map lname) path) in
            error loc "%s.%s is a field of a packet being matched, which only the \
                       condition of a pattern can read (as in \"expect Raw(%s.%s == x)\")%s.\n  \
                       Of a packet in a variable, it is \"p[%s].%s\": \"LAST[%s].%s\" for the \
                       last one sent, \"MATCH[%s].%s\" for the one that matched."
                n f n f
                (if Option.is_none ctx then ""
                 else "; the options of a stack cannot read the layers below")
                n f n f n f in
    (* The current layer included: *)
    let layers = Array.to_list ctx.below @ [ ctx.cur, ctx.cur_mode ] in
    let names = List.map (fun ((l : L.layer), _) -> lname l.name) layers in
    let path = List.map (Option.map lname) path in
    let where =
        match List.last path with
        | Some n when n <> lname ctx.cur.name -> " below "^ L.to_string ctx.cur
        | _ -> ", this one included" in
    match path_positions names ~absolute path with
    | [] -> error loc "There is no %s%s" (string_of_path ~absolute path) where
    | layer :: others ->
        if others <> [] then (
            let written i = unique_path names i ^"."^ f in
            env.warnings :=
                (loc, Printf.sprintf "%s.%s is any of %d layers%s: it reads %s, \
                                      not %s"
                          (string_of_path ~absolute path) f (List.length others + 1)
                          where (written layer)
                          (String.concat " or " (List.map written others))) ::
                !(env.warnings)) ;
        let l, mode = List.nth layers layer in
        match L.find_field l f with
        | None ->
            error loc "%s has no field %s%s" (L.to_string l) f (field_hint l f)
        | Some i ->
            if layer = Array.length ctx.below then
                ctx.prefixed := i :: !(ctx.prefixed) ;
            let fd = l.fields.(i) in
            if not (List.mem mode fd.read_in) then
                error loc "%s cannot be read in a %s %s%s" fd.name
                    (L.string_of_mode mode) (L.to_string l)
                    (other_mode_hint l mode fd.read_in) ;
            { loc ; typ = fd.typ ; desc = Packet_field { layer ; field = i } }

(* The function, its arguments in the order of its parameters, and the type
 * of its result: *)
and call ?expected env loc f args =
    let fname, b, params, result = find_builtin loc f in
    let unnamed = List.filter (fun (a : A.arg) -> a.arg_name = None) args in
    (* The parameters of the unnamed arguments, in order: the only one, else
     * those that must be given and are not named, if no fewer: *)
    let slots =
        match params with
        | [ p ] -> List.map (fun _ -> p) unnamed
        | _ ->
            List.filter (fun p ->
                p.default = None &&
                not (List.exists (fun (a : A.arg) ->
                    Option.map_default (same_name p.pname) false a.arg_name) args)
            ) params in
    if List.length unnamed > List.length slots then
        error (List.hd unnamed).arg_loc "The arguments of %s must be named" fname ;
    let slots = ref slots in
    let named =
        List.map (fun (a : A.arg) ->
            match a.arg_name with
            | Some n ->
                (match List.find_opt (fun p -> same_name p.pname n) params with
                | Some p -> p.pname, a
                | None ->
                    error a.arg_loc "%s has no parameter %s%s" fname n
                        (A.did_you_mean (List.map (fun p -> p.pname) params) n))
            | None ->
                let p = List.hd !slots in
                slots := List.tl !slots ;
                p.pname, a
        ) args in
    List.iter (fun p ->
        if List.length (List.filter (fun (n, _) -> n = p.pname) named) > 1 then
            error loc "Argument %s of %s given twice" p.pname fname) params ;
    (* An empty array literal is of the type the others tell, typed after
     * them: *)
    let typed = Hashtbl.create 3 in
    let typ_of n = Option.map (fun (e : expr) -> e.typ) (Hashtbl.find_opt typed n) in
    let item = function Some (Type.Array t) -> Some t | _ -> None in
    let expected_arg pname =
        match b, pname with
        | Concat, "a" -> typ_of "b"
        | Concat, "b" -> typ_of "a"
        | Append, "a" -> Option.map (fun t -> Type.Array t) (typ_of "x")
        | Append, "x" -> item (typ_of "a")
        | Prepend, "a" -> Option.map (fun t -> Type.Array t) (typ_of "x")
        | Prepend, "x" -> item (typ_of "a")
        | Make_array, "init" -> item expected
        | Make_map, "default" ->
            (match expected with Some (Type.Map (_, v)) -> Some v | _ -> None)
        | _ -> None in
    let typed_arg (a : A.arg) pname =
        match Hashtbl.find_opt typed pname with
        | Some e -> e
        | None ->
            let e = expr ?expected:(expected_arg pname) env a.value in
            Hashtbl.replace typed pname e ;
            e in
    List.iter (fun (pname, (a : A.arg)) ->
        if not (is_empty_array a.value) then ignore (typed_arg a pname)) named ;
    let args =
        List.filter_map (fun p ->
            match List.assoc p.pname named with
            | (a : A.arg) ->
                let e = typed_arg a p.pname in
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
    (* An empty array literal is of the type of the other operand: *)
    let a, b =
        if is_empty_array a && not (is_empty_array b) then
            let b = expr env b in expr ?expected:(empty_next_to b.typ) env a, b
        else
            let a = expr env a in
            a, expr ?expected:(if is_empty_array b then empty_next_to a.typ else None)
                    env b in
    let mk typ desc = { loc ; typ ; desc } in
    let sym = A.string_of_binop op in
    let cannot () =
        no_constructor env a ; no_constructor env b ;
        error loc "Cannot apply %s to %s and %s" sym (describe env a) (describe env b) in
    let unify = unify ~describe:(describe env) in
    match op with
    | A.Add | A.Sub | A.Mul | A.Div | A.Mod ->
        (match a.typ, b.typ with
        | (Type.Int | Type.Float), (Type.Int | Type.Float) ->
            let a, b = unify sym a b in
            mk a.typ (Binop (op, a, b))
        | Type.Interval, Type.Interval when op = A.Add || op = A.Sub ->
            mk Type.Interval (Binop (op, a, b))
        | Type.Interval, Type.Interval when op = A.Div ->
            mk Type.Float (Binop (op, a, b))
        | Type.Interval, (Type.Int | Type.Float) when op = A.Mul || op = A.Div ->
            mk Type.Interval (Binop (op, a, expect "" b Type.Float))
        | (Type.Int | Type.Float), Type.Interval when op = A.Mul ->
            mk Type.Interval (Binop (op, expect "" a Type.Float, b))
        (* A repetition, of a byte as of bytes: *)
        | (Type.Array _ | Type.Byte), Type.Int | Type.Int, (Type.Array _ | Type.Byte)
          when op = A.Mul ->
            let as_array x =
                if x.typ = Type.Byte then
                    { x with typ = Type.Array Type.Byte ; desc = Array [ x ] }
                else x in
            let a = as_array a and b = as_array b in
            mk (if b.typ = Type.Int then a.typ else b.typ) (Binop (op, a, b))
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
        (* A string and anything but an array other than bytes, as their
         * interpolations: *)
        | _ when op = A.Add &&
                 (let other x y =
                      x.typ = Type.String && any_value y.typ <> None &&
                      (match y.typ with Type.Array _ -> y.typ = Type.bytes | _ -> true) in
                  other a b || other b a) ->
            let parts x =
                match x.desc with
                | String ps -> ps
                | _ -> [ Interp x ] in
            mk Type.String (String (parts a @ parts b))
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
    | A.Shl | A.Shr ->
        (match a.typ, b.typ with
        | (Type.Int | Type.Byte), (Type.Int | Type.Byte) ->
            mk a.typ (Binop (op, a, expect "" b Type.Int))
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
    | A.In ->
        (match a.typ, b.typ with
        | Type.Ip, Type.Cidr -> mk Type.Bool (Binop (op, a, b))
        | _ -> cannot ())

(* What tells where the [layers] of a stack statement can go: *)
and stack_hint env anchor (layers : A.layer list) ~sends =
    where_to_hint env anchor (List.mapi (fun i (al : A.layer) ->
        let sends = sends && i = List.length layers - 1 in
        { w_name = al.layer_name ; bang = al.manual ; plain = al.options = [] ;
          text = A.string_of_stack ~sends (A.Relative 0) [ al ] }) layers)

(* The stack as written (top first) that [tls], typed from [layers], make on
 * top of the [depth] first layers of the current stack; a layer that overlays
 * one of the same mode without options is written as that one: *)
and stack_text env depth overlay (layers : A.layer list) tls =
    let n = List.length env.stack - depth in
    let over = List.rev (List.take n (List.combine env.stack env.stack_text)) in
    let written =
        List.map (fun (al : A.layer) ->
            al.options = [], A.string_of_stack (A.Relative 0) [ al ]) layers in
    let written =
        if List.length tls > List.length layers then (true, "Eth") :: written
        else written in
    List.rev (List.mapi (fun i ((plain, w), tl) ->
        match List.nth_opt over i with
        | Some ((_, m), ow) when i < overlay && plain && tl.mode = m -> ow
        | _ -> w) (List.combine written tls)) @
    List.drop n env.stack_text

(* The layers of a stack statement on top of [base], over the layers [over]
 * (bottom first) that were taken off the current stack, and the new stack.
 * The layers that are over the same ones take their key, which they need
 * not give: *)
and stack_layers ~hint env base over (layers : A.layer list) =
    List.fold_left (fun (base, tls) (al : A.layer) ->
        let base', l = push ~hint al.layer_loc base al.layer_name in
        let tls =
            if base' == base then tls else implicit_root al.layer_loc :: tls in
        let mode = mode_on al.layer_loc base' l ~bang:al.manual in
        let ctx = { cur = l ; cur_mode = mode ; in_cond = false ;
                    below = Array.of_list (List.rev base') ;
                    shadowing = ref [] ; prefixed = ref [] } in
        let env = { env with layer_ctx = Some ctx } in
        let options =
            List.map (fun (a : A.arg) ->
                let i =
                    match a.arg_name with
                    | Some n ->
                        (match L.find_field l n with
                        | Some i -> i
                        | None ->
                            error a.arg_loc "%s has no field %s%s" (L.to_string l) n
                                (field_hint l n))
                    | None ->
                        (match l.default_field with
                        | Some i -> i
                        | None -> error a.arg_loc "The options of %s must be named" (L.to_string l)) in
                let f = l.fields.(i) in
                if not (List.mem mode f.set_in) then (
                    if f.set_in = [] then
                        let ln = L.to_string l in
                        error a.arg_loc "%s.%s is a virtual field%s: it cannot be set"
                            ln f.name
                            (if f.about = "" then "" else
                             " ("^ String.nreplace ~str:f.about ~sub:"%s" ~by:ln ^")")
                    else
                        error a.arg_loc "%s cannot be set in a %s %s%s" f.name
                            (L.string_of_mode mode) (L.to_string l)
                            (other_mode_hint l mode f.set_in)) ;
                let e = expr ~expected:f.typ env a.value in
                i, expect ("The value of "^ f.name) e f.typ
            ) al.options in
        List.iter (fun (i, (e : expr)) ->
            if List.length (List.filter (fun (i', _) -> i = i') options) > 1 then
                error e.loc "%s given twice" l.fields.(i).name ;
            Option.may (fun p ->
                if List.exists (fun (j, _) -> l.fields.(j).name = p) options then
                    error e.loc "%s and %s cannot both be given" l.fields.(i).name p
            ) l.fields.(i).part_of) options ;
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
                ) tl.layer.fields ;
            (* The type and code of ICMP are those of the message on top, but
             * for Raw: *)
            if tl.layer == L.icmp || tl.layer == L.icmp6 then
                let name = L.to_string tl.layer in
                match List.nth_opt tls (j + 1) with
                | Some up when up.layer == L.raw ->
                    if j >= n && not (List.exists (fun (i, _) ->
                                         tl.layer.fields.(i).name = "type") tl.options) then
                        error tl.layer_loc "%s needs a type, with Raw on top" name
                | Some up ->
                    List.iter (fun (i, (e : expr)) ->
                        error e.loc "The %s of %s is that of the %s on top: \
                                     it can be set only with Raw on top"
                            tl.layer.fields.(i).name name (L.to_string up.layer)) tl.options
                | None -> ()) tls ;
        base, tls, n

and pattern env (p : A.pattern) =
    let hint =
        where_to_hint env p.anchor (List.map (fun (pl : A.pattern_layer) ->
            { w_name = pl.pl_name ; bang = pl.pl_manual ; plain = pl.cond = None ;
              text = IO.to_string (A.print_pattern ~all:false ~indent:0)
                       { p with anchor = A.Relative 0 ; pat_layers = [ pl ] } })
            p.pat_layers) in
    let base, over = anchor_base ~hint env p.pat_loc p.anchor in
    let depth = List.length base in
    let _, pls =
        List.fold_left (fun (base, pls) (pl : A.pattern_layer) ->
            let base', l = push ~hint pl.pl_loc base pl.pl_name in
            let pls =
                if base' == base then pls
                else { pl_loc = pl.pl_loc ; pl_layer = L.root ; pl_mode = L.Driven ;
                       cond = None } :: pls in
            let mode = mode_on pl.pl_loc base' l ~bang:pl.pl_manual in
            let ctx = { cur = l ; cur_mode = mode ; in_cond = true ;
                        below = Array.of_list (List.rev base') ;
                        shadowing = ref [] ; prefixed = ref [] } in
            let env = { env with layer_ctx = Some ctx } in
            let cond =
                Option.map (fun c ->
                    let c = expr env c in
                    (* A condition that prefixes a field tells it from the
                     * variable of the same name: *)
                    List.iter (fun (loc, name, i) ->
                        if not (List.mem i !(ctx.prefixed)) then
                            let n = lname l.name in
                            env.warnings :=
                                (loc, Printf.sprintf "This %s is the variable %s, \
                                                      not the field of %s: write %s.%s \
                                                      for the field"
                                    name name n n l.fields.(i).name) ::
                                !(env.warnings)
                    ) !(ctx.shadowing) ;
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
    if p.anchor = A.Absolute then overreach env p pat_layers ;
    { pat_loc = p.pat_loc ; depth ; pat_layers ;
      overlay = overlay over (List.map (fun pl -> pl.pl_layer) pat_layers) }

(* Warns of an absolute pattern [p] that shares with the current stack more
 * than its IP layer, or all of it, but without a condition on those, which
 * then matches the packets of any stream rather than of the stack's; the
 * relative pattern suggested instead overlays from the lowest shared layer
 * that has a condition: *)
and overreach env (p : A.pattern) pat_layers =
    let n = List.length env.stack in
    let shared =
        overlay (List.rev_map fst env.stack) (List.map (fun pl -> pl.pl_layer) pat_layers) in
    let cond i = (List.nth pat_layers i).cond <> None in
    if shared >= 2 && (shared >= 3 || shared = n) && not (cond 0 || cond 1) then
        let i0 =
            List.find_opt (fun i -> i >= 2 && cond i) (List.init shared identity) |? (
                if shared = List.length pat_layers then shared - 1 else shared) in
        let written = List.length pat_layers - List.length p.pat_layers in
        let fix =
            { p with anchor = A.Relative (n - i0) ;
                     pat_layers = List.drop (i0 - written) p.pat_layers } in
        env.warnings :=
            (p.pat_loc,
             Printf.sprintf "This pattern matches any %s, not only those of the \
                             current stack %s.\n  Do you mean \"%s\"?"
                (string_of_layers (List.rev_map (fun pl -> pl.pl_layer, pl.pl_mode) pat_layers))
                (string_of_stack_text env.stack_text)
                (IO.to_string (A.print_pattern ~all:false ~indent:0) fix)) ::
            !(env.warnings)

(** {2 Statements} *)

and opt_expr env what typ = Option.map (fun e -> expect what (expr env e) typ)

(* The timeout of a [form] that a pattern follows, which a misspelled layer
 * before an absolute pattern reads as ([UPD/Raw]): *)
and timeout_of env form timeout =
    try opt_expr env ("The timeout of "^ form) Type.Interval timeout
    with Error (loc, msg) as ex ->
        match timeout with
        | Some { desc = A.Var c | A.Construct (c, _) ; _ } when A.is_constructor c ->
            (match A.did_you_mean (List.map A.Layer_name.to_string A.Layer_name.all) c with
            | "" -> raise ex
            | hint -> error loc "%s\n  If %s is a misspelled layer%s" msg c hint)
        | _ -> raise ex

(* The statements of a block, and its type: that of its last statement if an
 * expression whose value is [used], else void: *)
and block_value ?expected ~used errors env stmts =
    let env = { env with declared_here = [] } in
    (* An [on] or a [spawn] ending with its block, which nothing after it
     * keeps waiting, ends as it starts: *)
    let rec ends_at_once = function
        | { A.stmt = A.On { for_ = None ; linger = None ; _ } ; stmt_loc } :: rest ->
            ends_at_once rest &&
            (env.warnings :=
                (stmt_loc, "This on ends at once, with its block: give it a \
                            duration (for), or a linger after its block") ::
                !(env.warnings) ;
             true)
        | { A.stmt = A.Spawn { for_ = None ; _ } ; stmt_loc } :: rest ->
            ends_at_once rest &&
            (env.warnings :=
                (stmt_loc, "This spawn ends at once, with its block: give it a \
                            duration (for)") ::
                !(env.warnings) ;
             true)
        | [] -> true
        | _ :: rest -> ignore (ends_at_once rest) ; false in
    ignore (ends_at_once stmts) ;
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
    let cases ?(loops=0) cs =
        List.map (fun (ps, body) ->
            let patterns = List.map (pattern env) ps in
            let match_ = new_var "MATCH" packet_type in
            let body =
                block errors { env with vars = match_ :: env.vars ;
                                        loops = env.loops + loops } body in
            { patterns ; match_ ; body }) cs in
    let declare_typ env name typ =
        if List.mem name env.declared_here then
            error loc "%s is already declared in this block (:= changes it)" name ;
        let v = new_var name typ in
        { env with vars = v :: env.vars ;
                   declared_here = name :: env.declared_here }, v in
    let declare env name e = declare_typ env name e.typ in
    try
        if not env.may_wait then (
            let what =
                match s.stmt with
                | A.Stack { body = None ; _ } | A.Capture _ -> Some "A packet"
                | A.Stack _ -> Some "A stack"
                | A.Repeat _ -> Some "repeat" | A.Foreach _ -> Some "foreach"
                | A.Retry _ -> Some "retry" | A.Catch _ -> Some "catch"
                | A.Break _ -> Some "break" | A.Wait _ -> Some "wait"
                | A.Expect _ -> Some "expect"
                | A.On _ -> Some "on" | A.Spawn _ -> Some "spawn"
                | A.Expr _ | A.Declare _ | A.Assign _ -> None in
            Option.may (fun what ->
                error loc "%s cannot be in a block within an expression, but for \
                           the value of a declaration, an assignment or a statement"
                      what) what) ;
        match s.stmt with
        | A.Stack { anchor ; layers ; body } ->
            let hint = stack_hint env anchor layers ~sends:(body = None) in
            let base, over = anchor_base ~hint env s.stmt_loc anchor in
            let stack, tls, overlay = stack_layers ~hint env base over layers in
            (* Which the parser checked: *)
            let top = fst (List.hd stack) in
            assert (if body = None then top.ends else not top.terminal) ;
            let depth = List.length base in
            (match body with
            | Some body ->
                let stack_text = stack_text env depth overlay layers tls in
                let body = block errors { env with stack ; stack_text } body in
                env, Some (mk (Stack { depth ; overlay ; layers = tls ; body }))
            | None ->
                env, Some (mk (Send { depth ; overlay ; layers = tls ; capture = None })))
        | A.Capture { var ; declare = decl ; anchor ; layers } ->
            let hint = stack_hint env anchor layers ~sends:true in
            let base, over = anchor_base ~hint env s.stmt_loc anchor in
            let stack, tls, overlay = stack_layers ~hint env base over layers in
            (* What a self-driven layer sends is no one frame that could be
             * waited for, but for the interface's: *)
            List.iter (fun ((l : L.layer), m) ->
                if m = L.Driven && l != L.root then
                    error s.stmt_loc "Only a packet sent through manual layers can \
                                      be seen leaving, and %s is self-driven"
                        (L.to_string l)) stack ;
            let env, capture =
                if decl then
                    declare_typ env var packet_type
                else
                    let v = lookup_var env loc var in
                    if v.typ <> packet_type then
                        error loc "%s is %s, not a packet" var (a_type v.typ) ;
                    env, v in
            env, Some (mk (Send { depth = List.length base ; overlay ; layers = tls ;
                                  capture = Some capture }))
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
                | A.Construct (c, _) ->
                    (* Rather a misspelled layer than a value: *)
                    error loc "This %s is not used%s" (tname te.typ)
                        (A.did_you_mean (List.map A.Layer_name.to_string A.Layer_name.all) c)
                | _ -> error loc "This %s is not used" (tname te.typ)) ;
            env, Some (mk (Expr te))
        | A.Declare (name, _) when List.mem name A.self_declared ->
            error loc "%s can only be declared at the top level of the program" name
        | A.Declare (name, value) ->
            let e = value in
            (* A declaration in error still declares its variable, so that
             * its uses are not reported as well: *)
            let poisoned () =
                { env with poisoned = name :: env.poisoned ;
                           declared_here = name :: env.declared_here }, None in
            (* Of the type that its assignments widened it to: *)
            let widened = Hashtbl.find_opt env.widened loc in
            let widen e =
                match widened with
                | Some t -> Option.default e (coerce e t)
                | None -> e in
            let typed () =
                let provisional = Option.map_default has_unknown true widened in
                let e = expr ?expected:widened ~tail:true { env with provisional } e in
                if has_unknown e.typ then Hashtbl.replace env.unknown loc (name, e.typ) ;
                e in
            (match widen (typed ()) with
            | e when e.typ = Type.Void ->
                tell errors (Error (loc, name ^" would have no value")) ;
                poisoned ()
            | e ->
                let env, v = declare env name e in
                Hashtbl.replace env.declared_at v.id loc ;
                Hashtbl.replace env.declared_as v.id value ;
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
                | None -> expr ~expected:typ ~tail:true env e
                | Some op -> binop env' loc op lhs e in
            (match coerce e typ, Hashtbl.find_opt env.declared_at v.id with
            | Some value, _ -> env, Some (mk (Assign { var = v ; path = List.rev path ; value }))
            | None, Some at when fills typ e.typ ->
                (* Typed again, with the items of the type assigned: *)
                Hashtbl.replace env.widened at (set_at v.typ (List.length is) e.typ) ;
                env.widening := true ;
                env, None
            | None, _ ->
                error loc "Cannot assign %s to an item of %s, which is %s"
                    (a_type e.typ) name (a_type typ))
        | A.Assign (name, [], op, e) ->
            let v = lookup_var env loc name in
            let e =
                match op with
                | None ->
                    expr ?expected:(if has_unknown v.typ then None else Some v.typ)
                         ~tail:true env e
                | Some op ->
                    binop env loc op { A.loc ; A.desc = A.Var name } e in
            (match coerce e v.typ, Hashtbl.find_opt env.declared_at v.id with
            | Some e, _ -> env, Some (mk (Assign { var = v ; path = [] ; value = e }))
            | None, Some at when fills v.typ e.typ ->
                (* Typed again, with the items of the type assigned: *)
                Hashtbl.replace env.widened at e.typ ;
                env.widening := true ;
                env, None
            | None, Some at when widens env at v.typ e.typ ->
                (* The program is typed again, with that variable of a
                 * variant of the constructors of both: *)
                Hashtbl.replace env.widened at (Option.get (join_types v.typ e.typ)) ;
                env.widening := true ;
                env, None
            | None, _ ->
                error loc "Cannot assign %s to %s, which is %s%s%s"
                    (a_type e.typ) name (a_type v.typ)
                    (match origin env v with "" -> "" | o -> " ("^ o ^")")
                    (if v.typ = Type.Interval && e.typ = Type.Time then
                        "\n  A time variable starts as now(), or time(0)." else ""))
        | A.Repeat { var ; count ; every ; for_ ; body } ->
            let count = opt_expr env "The count of repeat" Type.Int count
            and every = opt_expr env "The period of repeat" Type.Interval every
            and for_ = opt_expr env "The duration of repeat" Type.Interval for_ in
            let v = new_var (var |? "I") Type.Int in
            let body =
                block errors { env with vars = v :: env.vars ;
                                        loops = env.loops + 1 } body in
            if hides_i env var then
                warn_hidden_i env "the number of the iteration of this repeat" v ;
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
            if hides_i env var then warn_hidden_i env "the item of this foreach" v ;
            env, Some (mk (Repeat { var = v ; count = None ; items = Some items ;
                                    every ; for_ ; body }))
        | A.Retry { max ; body } ->
            if body = [] then
                env.warnings :=
                    (loc, "This retry has an empty block: it has nothing to retry") ::
                    !(env.warnings) ;
            let max = opt_expr env "The maximum of retry" Type.Int max in
            env, Some (mk (Retry { max ; body = block errors env body }))
        | A.Catch body ->
            if body = [] then
                env.warnings :=
                    (loc, "This catch has an empty block: it catches nothing") ::
                    !(env.warnings) ;
            env, Some (mk (Catch (block errors env body)))
        | A.Break { depth } ->
            let depth =
                match depth with
                | None -> 1
                | Some { desc = A.Lit (A.Int n) ; _ } when n > 0 -> n
                | Some e -> error e.loc "The depth of break must be a positive integer" in
            if depth > env.loops then
                error loc "Break out of %d repeat, foreach, on or spawn, but %s" depth
                    (match env.loops with
                    | 0 -> "there is none"
                    | 1 -> "there is only one"
                    | n -> Printf.sprintf "there are only %d" n) ;
            env, Some (mk (Break depth))
        | A.Wait dur ->
            env, Some (mk (Wait (expect "The duration of wait" (expr env dur) Type.Interval)))
        | A.Expect { timeout ; cases = cs } ->
            let timeout = timeout_of env "expect" timeout in
            env, Some (mk (Expect { timeout ; cases = cases cs }))
        | A.On { for_ ; linger ; timeout ; max ; cases = cs } ->
            if for_ <> None && linger <> None then
                error loc "An on lasts either for its own duration (for), \
                           keeping its block waiting, or until its block ends, \
                           which linger delays: not both" ;
            let for_ = opt_expr env "The duration of on" Type.Interval for_
            and linger = opt_expr env "The linger of on" Type.Interval linger
            and timeout = timeout_of env "on" timeout
            and max = opt_expr env "The maximum of on" Type.Int max in
            env, Some (mk (On { for_ ; linger ; timeout ; max ;
                                cases = cases ~loops:1 cs }))
        | A.Spawn { for_ ; body } ->
            let for_ = opt_expr env "The duration of spawn" Type.Interval for_ in
            let body = block errors { env with loops = env.loops + 1 } body in
            env, Some (mk (Spawn { for_ ; body }))
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
        | Spawn { body = b ; _ } -> declarations b
        | Expect { cases ; _ } | On { cases ; _ } ->
            List.concat_map (fun (c : case) -> declarations c.body) cases
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
    | Slice (a, from, to_) ->
        List.concat_map expr_declarations (a :: List.filter_map identity [ from ; to_ ])
    | Call (_, es) | Record es | Array es -> List.concat_map expr_declarations es
    | Map kvs ->
        List.concat_map (fun (k, v) -> expr_declarations k @ expr_declarations v) kvs
    | String parts ->
        List.concat_map (function Interp e -> expr_declarations e | Text _ -> []) parts
    | Construct (_, e) -> Option.map_default expr_declarations [] e
    | Lit _ | Var _ | Packet_field _ -> []

(* Errors in the order of the source: *)
let in_order es =
    List.rev_map (fun (where, message) -> Crafty_parser.{ where ; message }) es |>
    List.sort (fun (a : Crafty_parser.error) b -> compare a.where b.where)

(* The expressions directly within [s], not within its blocks: *)
let stmt_exprs s =
    let opts = List.filter_map identity in
    let layers = List.concat_map (fun l -> List.map snd l.options) in
    match s.stmt with
    | Stack { layers = ls ; _ } | Send { layers = ls ; _ } -> layers ls
    | Expr e | Declare (_, e) | Wait e -> [ e ]
    | Assign { path ; value ; _ } -> List.map snd path @ [ value ]
    | Repeat { count ; items ; every ; for_ ; _ } -> opts [ count ; items ; every ; for_ ]
    | Retry { max ; _ } -> opts [ max ]
    | Expect { timeout ; _ } -> opts [ timeout ]
    | On { for_ ; linger ; timeout ; max ; _ } -> opts [ for_ ; linger ; timeout ; max ]
    | Spawn { for_ ; _ } -> opts [ for_ ]
    | Catch _ | Break _ -> []

(* The expressions directly within [e], not within its blocks: *)
let sub_exprs e =
    match e.desc with
    | Field (e, _) | Unop (_, e) | Convert e | Select { packet = e ; _ } -> [ e ]
    | Index (a, b) | Binop (_, a, b) -> [ a ; b ]
    | Slice (a, from, to_) -> a :: List.filter_map identity [ from ; to_ ]
    | Call (_, es) | Record es | Array es -> es
    | Map kvs -> List.concat_map (fun (k, v) -> [ k ; v ]) kvs
    | String parts -> List.filter_map (function Interp e -> Some e | Text _ -> None) parts
    | Construct (_, e) -> Option.map_default (fun e -> [ e ]) [] e
    | If { cond ; _ } -> [ cond ]
    | Case { subject ; _ } -> [ subject ]
    | Block _ | Lit _ | Var _ | Packet_field _ -> []

(* The blocks directly within [s] and [e]: *)
let stmt_blocks s =
    match s.stmt with
    | Stack { body ; _ } | Repeat { body ; _ } | Retry { body ; _ } | Catch body
    | Spawn { body ; _ } ->
        [ body ]
    | Expect { cases ; _ } | On { cases ; _ } -> List.map (fun (c : case) -> c.body) cases
    | Send _ | Expr _ | Declare _ | Wait _ | Assign _ | Break _ -> []

let expr_blocks e =
    match e.desc with
    | Block b -> [ b ]
    | If { then_ ; else_ ; _ } -> [ then_ ; else_ ]
    | Case { arms ; else_ ; _ } ->
        List.map (fun a -> a.branch) arms @ Option.map_default (fun b -> [ b ]) [] else_
    | _ -> []

(** Calls [f] on every statement of [b], outer ones first, including those
 * in the blocks of expressions. *)
let rec iter_stmts f (b : block) =
    List.iter (fun s ->
        f s ;
        List.iter (iter_expr_stmts f) (stmt_exprs s) ;
        List.iter (iter_stmts f) (stmt_blocks s)) b

and iter_expr_stmts f e =
    List.iter (iter_stmts f) (expr_blocks e) ;
    List.iter (iter_expr_stmts f) (sub_exprs e)

(** The literal addresses that the stacks of [b] send from or to and that are
 * not permitted, as errors where they are written: an IP source by the
 * [local] rules and a destination by the [remote] ones (the other way round
 * in a quoted IP), an Ethernet source other than [mac]. Without rules or
 * [mac], those are not checked. *)
let denied_literals ~local ~remote ~mac (b : block) =
    let errors = ref [] in
    let deny (e : expr) what addr =
        errors := (e.loc, Printf.sprintf "%s %s is not permitted" what addr) :: !errors in
    let ip e what rules ip =
        Option.may (fun rules ->
            if Firewall.(verdict (of_address_rules rules) ip) = Firewall.Deny then
                deny e what (Ip.Addr.to_dotted_string ip)) rules in
    let layer l =
        let quoted = l.layer.L.quoted in
        let q = if quoted then "Quoted source" else "Source"
        and r = if quoted then "Quoted destination" else "Destination" in
        List.iter (fun (i, e) ->
            match l.layer.L.name, l.layer.L.fields.(i).L.name, e.desc with
            | (A.Layer_name.IP | IP6), "src", Lit (A.Ip a) ->
                ip e (q ^" address") (if quoted then remote else local) a
            | (A.Layer_name.IP | IP6), "dst", Lit (A.Ip a) ->
                ip e (r ^" address") (if quoted then local else remote) a
            | A.Layer_name.Eth, "src", Lit (A.Mac m) ->
                Option.may (fun mac ->
                    if not (Eth.Addr.eq m mac) then
                        deny e "Source MAC" (Eth.Addr.to_hexstring m)) mac
            | _ -> ()) l.options in
    iter_stmts (fun s ->
        match s.stmt with
        | Stack { layers ; _ } | Send { layers ; _ } -> List.iter layer layers
        | _ -> ()) b ;
    in_order !errors

(* What a message carries, which is the payload of the packet: its bytes and
 * strings, and what holds them, rather than its numbers: *)
let is_payload (l : L.layer) (f : L.field) =
    l.ends &&
    match f.typ with
    | Type.Bool | Type.Byte | Type.Int | Type.Float -> false
    | _ -> true

(** Where [b] sets a payload with what it received, as errors: the payload
 * fields of what [MATCH] matched taint what they are copied, assigned or
 * computed into, whichever the order of the statements. *)
let exfiltrations (b : block) =
    (* The variables that hold received packets or their layers, and those
     * that hold what their payloads made: *)
    let packets = Hashtbl.create 7 and tainted = Hashtbl.create 7 in
    let changed = ref true in
    let mark tbl (v : var) =
        if not (Hashtbl.mem tbl v.id) then (
            Hashtbl.add tbl v.id () ;
            changed := true) in
    (* Whether [e] holds received packets or their layers: *)
    let rec is_packet e =
        match e.desc with
        | Var v -> Hashtbl.mem packets v.id
        | Select { packet ; _ } | Index (packet, _) | Slice (packet, _, _) ->
            is_packet packet
        | _ -> false in
    (* Whether [e] is made of what a received packet carried, which a packet
     * read whole is: *)
    let rec taints e =
        match e.desc with
        | Var v -> Hashtbl.mem tainted v.id
        | Field (r, i) when is_packet r ->
            (match r.typ with
            | Type.Record fs ->
                let name = fst (List.nth fs i) in
                List.exists (fun (l : L.layer) ->
                    packet_record l = r.typ &&
                    Array.exists (fun (f : L.field) -> f.name = name && is_payload l f)
                                 l.fields) L.all
            | _ -> false)
        | _ when is_packet e -> false
        | Block b -> block_taints b
        | If { then_ ; else_ ; _ } -> block_taints then_ || block_taints else_
        | Case { arms ; else_ ; _ } ->
            List.exists (fun a -> block_taints a.branch) arms ||
            Option.map_default block_taints false else_
        | _ -> List.exists (fun e -> is_packet e || taints e) (sub_exprs e)
    and block_taints b =
        match List.last b with
        | { stmt = Expr e ; _ } -> taints e
        | _ | exception _ -> false in
    let flows (v : var) e =
        if is_packet e then mark packets v ;
        if taints e then mark tainted v in
    (* What a case binds, in any expression: *)
    let rec bind_cases e =
        (match e.desc with
        | Case { subject ; arms ; _ } ->
            List.iter (fun a -> Option.may (fun v -> flows v subject) a.held) arms
        | _ -> ()) ;
        List.iter bind_cases (sub_exprs e) in
    while !changed do
        changed := false ;
        iter_stmts (fun s ->
            List.iter bind_cases (stmt_exprs s) ;
            match s.stmt with
            | Declare (v, e) -> flows v e
            | Assign { var ; value ; _ } -> flows var value
            | Repeat { var ; items = Some e ; _ } -> flows var e
            | Expect { cases ; _ } | On { cases ; _ } ->
                List.iter (fun (c : case) -> mark packets c.match_) cases
            | _ -> ()) b
    done ;
    let errors = ref [] in
    iter_stmts (fun s ->
        match s.stmt with
        | Stack { layers ; _ } | Send { layers ; _ } ->
            List.iter (fun l ->
                List.iter (fun (i, e) ->
                    if is_payload l.layer l.layer.L.fields.(i) && taints e then
                        errors := (e.loc, "This payload is made of what was received, \
                                           which PERMISSIONS.exfiltration does not allow") ::
                                  !errors) l.options) layers
        | _ -> ()) b ;
    in_order !errors

(* [exfiltrated text] is what [exfiltrations] says of that program: *)
(*$inject
  let exfiltrated text =
      match Result.bind (Result.map_error (fun e -> [ e ]) (Crafty_parser.parse text)) check with
      | Error es -> String.concat "\n" (List.map (IO.to_string Crafty_parser.print_error) es)
      | Ok b ->
          exfiltrations b |>
          List.map (fun (e : Crafty_parser.error) -> Printf.sprintf "%d:%d" e.where.line e.where.column) |>
          String.concat " "
*)
(*$= exfiltrated & ~printer:identity
  "" (exfiltrated "/IP(dst=1.2.3.4)/UDP(dst=7) { Raw(\"x\")\nexpect Raw { Raw(\"${MATCH[UDP].src}\") } }")
  "2:18" (exfiltrated "/IP(dst=1.2.3.4)/UDP(dst=7) {\nexpect Raw { Raw(MATCH[Raw].data) } }")
  "4:5" (exfiltrated "/IP(dst=1.2.3.4)/UDP(dst=7) {\nx = randbytes(1)\nexpect Raw { x := x + MATCH[Raw].data[1:] }\nRaw(x) }")
  "2:18" (exfiltrated "/IP(dst=1.2.3.4)/UDP(dst=7) {\nexpect Raw { Raw(\"${MATCH}\") } }")
  "4:5" (exfiltrated "/IP(dst=1.2.3.4)/UDP(dst=7) {\nexpect Raw { p = MATCH\nq = p[Raw]\nRaw(q.data) } }")
  "2:45" (exfiltrated "/IP(dst=1.2.3.4)/UDP(dst=7) {\nexpect Raw { case var=r MATCH[-1] Raw { Raw(r.data) } else {} } }")
  "" (exfiltrated "/IP(dst=1.2.3.4)/UDP(dst=7) {\nexpect Raw { case var=r MATCH[-1] UDP { Raw(\"${r.src}\") } else {} } }")
  "4:5" (exfiltrated "/IP(dst=1.2.3.4)/UDP(dst=7) {\nn = 0\non Raw { n += length(MATCH[Raw].data) }\nRaw(\"${n}\") }")
  "2:23" (exfiltrated "/IP(dst=1.2.3.4)/UDP(dst=53)/DNS { Query(\"a\")\nexpect Answer { Query(MATCH[Answer].answers[0].name) } }")
  "2:33" (exfiltrated "/IP(dst=1.2.3.4)/TCP(dst=80)/HTTP { HttpRequest(\"/\")\nexpect HttpAnswer { HttpRequest(MATCH[HttpAnswer].headers[0].value) } }")
  "" (exfiltrated "/IP(dst=1.2.3.4)/TCP(dst=80)/HTTP { HttpRequest(\"/\")\nexpect HttpAnswer { HttpRequest(\"/${MATCH[HttpAnswer].code}\") } }")
*)

(* [denied text] is what [denied_literals] says of that program, with local
 * rules accepting 10.0.0.0/8, remote ones anything but 192.0.2.66, and the
 * MAC 02:00:00:00:00:01: *)
(*$inject
  let denied text =
      let cidr = Firewall.cidr_of_string in
      match Result.bind (Result.map_error (fun e -> [ e ]) (Crafty_parser.parse text)) check with
      | Error es -> String.concat "\n" (List.map (IO.to_string Crafty_parser.print_error) es)
      | Ok b ->
          denied_literals b ~local:(Some [ Firewall.Accept, cidr "10.0.0.0/8" ])
              ~remote:(Some [ Firewall.Deny, cidr "192.0.2.66" ; Firewall.Accept, cidr "0.0.0.0/0" ])
              ~mac:(Some (Eth.Addr.of_string "02:00:00:00:00:01")) |>
          List.map (IO.to_string Crafty_parser.print_error) |> String.concat "\n"
*)
(*$= denied & ~printer:identity
  "" (denied "/IP(dst=192.0.2.1)/UDP(dst=7)/Raw()")
  "line 1, column 9: Destination address 192.0.2.66 is not permitted" \
    (denied "/IP(dst=192.0.2.66)/UDP(dst=7)/Raw()")
  "line 1, column 41: Source address 172.16.0.1 is not permitted" \
    (denied "/IP(dst=192.0.2.1) { if true { /IP!(src=172.16.0.1, dst=192.0.2.1)/UDP(dst=7)/Raw() } }")
  "line 1, column 78: Quoted destination address 172.16.0.2 is not permitted" \
    (denied "/IP!(src=10.0.0.1, dst=192.0.2.1)/ICMP/DestUnreachable/IP(src=192.0.2.1, dst=172.16.0.2)/UDP(src=1, dst=2)/Raw()")
  "line 1, column 11: Source MAC 02:00:00:00:00:99 is not permitted" \
    (denied "/Eth!(src=02:00:00:00:00:99, dst=ff:ff:ff:ff:ff:ff)/Raw()")
*)

(** The typed program, or the errors, in the order of the source; and in
 * [warnings], what makes sense but is likely not what was meant. [BUDGET]
 * and [PORTS] are what {!limits} reads. *)
let check ?(warnings=ref []) (program : A.program) =
    let self, program = self_declarations program in
    let self_errors = ref [] in
    ignore (limits_of self_errors self) ;
    let widened = Hashtbl.create 7 in
    (* Until no variable is widened, which types grow until they have all
     * the constructors of the program: *)
    let rec typed () =
        let env = { vars = [ budget_var ; ports_var ; permissions_var ; last_var ] ;
                    declared_here = [] ;
                    poisoned = [] ; stack = [] ;
                    stack_text = [] ; loops = 0 ; layer_ctx = None ;
                    may_wait = true ; errors = ref [] ; warnings = ref [] ;
                    declared_at = Hashtbl.create 7 ; declared_as = Hashtbl.create 7 ;
                    reads = Hashtbl.create 7 ;
                    widened ; widening = ref false ; held_by = Hashtbl.create 7 ;
                    reports = Hashtbl.create 3 ; provisional = false ;
                    unknown = Hashtbl.create 3 } in
        let p = block env.errors env program in
        if !(env.widening) then typed () else p, env in
    let p, env = typed () in
    (* What the items not known make go wrong is not told, but that they are
     * not: *)
    if Hashtbl.length env.unknown > 0 then (
        let unknown = tname unknown_items in
        env.errors := List.filter (fun (_, m) -> not (String.exists m unknown)) !(env.errors)) ;
    Hashtbl.iter (fun loc (name, typ) ->
        env.errors :=
            (loc, if typ = unknown_items then
                      Printf.sprintf "Cannot tell the type of the items of %s: \
                                      nothing is added to it" name
                  else
                      Printf.sprintf "Cannot tell the type of the items of the \
                                      empty arrays in %s: nothing is added to them" name)
            :: !(env.errors)
    ) env.unknown ;
    warnings := in_order !(env.warnings) ;
    let errors = !self_errors @ !(env.errors) in
    if errors = [] then Ok p else Error (in_order errors)

(** What [program] declares of itself, or what is wrong with it. *)
let limits (program : A.program) =
    let errors = ref [] in
    let l = limits_of errors (fst (self_declarations program)) in
    if !errors = [] then Ok l else Error (in_order !errors)

(** The typed patterns, absolute and with no variable but the fields of their
 * layers, or what is wrong with them. *)
let check_patterns (ps : A.patterns) =
    let env = { vars = [] ; declared_here = [] ; poisoned = [] ; stack = [] ;
                stack_text = [] ; loops = 0 ; layer_ctx = None ; may_wait = false ;
                errors = ref [] ; warnings = ref [] ; declared_at = Hashtbl.create 1 ;
                declared_as = Hashtbl.create 1 ;
                reads = Hashtbl.create 1 ; widened = Hashtbl.create 1 ;
                widening = ref false ; held_by = Hashtbl.create 1 ;
                reports = Hashtbl.create 1 ; provisional = false ;
                unknown = Hashtbl.create 1 } in
    try
        Ok (List.map (fun (p : A.pattern) ->
            if p.anchor <> A.Absolute then
                error p.pat_loc "The pattern must be absolute (start with /)" ;
            pattern env p) ps)
    with Error (where, message) -> Error Crafty_parser.{ where ; message }

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

(* [warns text] is what the program in that text is warned of. *)
(*$inject
  let warns text =
      let warnings = ref [] in
      ignore (check ~warnings (Result.get_ok (Crafty_parser.parse text))) ;
      String.concat "\n" (List.map (IO.to_string Crafty_parser.print_error) !warnings)
*)

(*$= warns & ~printer:identity
  "line 1, column 33: IP.ttl is any of 2 layers, this one included: it reads TimeExceeded/IP.ttl, not /IP.ttl" \
    (warns "expect /IP/ICMP/TimeExceeded/IP(IP.ttl == 1) {}")
  "" \
    (warns "expect /IP/ICMP/TimeExceeded/IP(/IP.ttl == 1, TimeExceeded/IP.ttl == 2, ICMP/_.code == 0) {}")
  "line 2, column 9: This pattern matches any /IP/UDP/DNS/Answer, not only those of the current stack /IP(dst=1.2.3.4)/UDP(dst=53)/DNS.\n  Do you mean \"Answer\"?" \
    (warns "/IP(dst=1.2.3.4)/UDP(dst=53)/DNS { Query(\"x\")\n expect /IP/UDP/DNS/Answer {} }")
  "line 1, column 43: This pattern matches any /IP/UDP/DNS/Answer, not only those of the current stack /IP(dst=1.2.3.4)/UDP(dst=53)/DNS.\n  Do you mean \"../../UDP(src == 53)/DNS/Answer\"?" \
    (warns "/IP(dst=1.2.3.4)/UDP(dst=53)/DNS { expect /IP/UDP(src == 53)/DNS/Answer {} }")
  "line 1, column 39: This pattern matches any /IP/UDP, not only those of the current stack /IP(dst=1.2.3.4)/UDP(dst=53).\n  Do you mean \"../UDP\"?" \
    (warns "/IP(dst=1.2.3.4)/UDP(dst=53) { expect /IP/UDP {} }")
  "line 1, column 27: This pattern matches any /IP/ICMP, not only those of the current stack /IP(dst=1.2.3.4).\n  Do you mean \"ICMP\"?" \
    (warns "/IP(dst=1.2.3.4) { expect /IP/ICMP {} }")
  "line 2, column 1: This on ends at once, with its block: give it a duration (for), or a linger after its block\nline 3, column 1: This on ends at once, with its block: give it a duration (for), or a linger after its block" \
    (warns "on for=1s /IP/UDP {}\non /IP/UDP {}\non max=2 /IP/TCP {}")
  "" (warns "on /IP/UDP {}\non linger=1s /IP/TCP {}")
  "" (warns "on /IP/UDP {}\nwait 1s")
  "line 2, column 1: This catch has an empty block: it catches nothing" \
    (warns "wait 1s\ncatch { }")
  "line 1, column 1: This retry has an empty block: it has nothing to retry" \
    (warns "retry max=2 { }")
  "line 2, column 12: This id is the variable id, not the field of IP: write IP.id for the field\nline 2, column 18: This id is the variable id, not the field of IP: write IP.id for the field" \
    (warns "id = 5\nexpect /IP(id == id) {}")
  "" (warns "id = 5\nexpect /IP(IP.id == id) {}")
  "" (warns "n = 5\nexpect /IP(id == n) {}")
  "line 1, column 52: This pattern matches any /IP/UDP/DNS/Answer, not only those of the current stack /IP(dst=1.2.3.4)/UDP(dst=53)/DNS.\n  Do you mean \"Answer\"?" \
    (warns "/IP(dst=1.2.3.4)/UDP(dst=53) { ../UDP/DNS { expect /IP/UDP/DNS/Answer {} } }")
  "" (warns "/IP(dst=1.2.3.4)/UDP(dst=53)/DNS { expect /IP(src == 1.2.3.4)/UDP/DNS/Answer {} }")
  "" (warns "/IP(dst=1.2.3.4)/UDP(dst=53) { expect /IP/ICMP {} }")
  "" (warns "/IP(dst=1.2.3.4)/TCP(dst=53) { expect /IP/UDP/DNS/Answer {} }")
  "" (warns "expect /IP/UDP/DNS/Answer {}")
  "" (warns "expect Raw {} | ../ICMP {}")
  "line 1, column 41: This I is the number of the iteration of this repeat, which hides an outer I: name one of them with var=" \
    (warns "repeat count=2 { repeat count=2 { print(I) } }")
  "line 1, column 41: This I is the item of this foreach, which hides an outer I: name one of them with var=" \
    (warns "repeat count=2 { foreach [1, 2] { print(I) } }")
  "line 2, column 35: This I is what Got holds, which hides an outer I: name one of them with var=" \
    (warns "r = [Got(1), Pending]\nforeach r { case r[0] Got { print(I) } else {} }")
  "" (warns "repeat count=2 { repeat count=2 { print(\"x\") }\n  print(I) }")
  "" (warns "repeat count=2 { repeat var=j count=2 { print(\"${I} ${j}\") } }")
  "" (warns "r = [Got(1), Pending]\nforeach r { case I Got { print(I) } else {} }")
  "" (warns "r = [Got(1), Pending]\nforeach r { case var=g r[0] Got { print(\"${I} ${g}\") } else {} }")
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
  "a: byte[], b: byte[], c: int[], d: byte[]" \
    (types "a = #01 * 2\nb = 3 * #0102\nc = [1] * 2\nd = #0001\nd *= 4")
  "line 1, column 5: Cannot apply * to a byte and a byte" \
    (types "a = #01 * #02")
  "a: int[], b: float[], c: int[], d: float[]" \
    (types "a = [1]\na += 2\nb = append([1.5], 1)\nc = prepend(a=[2], x=1)\nd = concat([1], [2.5])")
  "m: string[int], n: int[ip], c: int, k: ip[], v: int[], b: bool, l: int" \
    (types "m = [1: \"a\"]\nn = map(key=0.0.0.0, default=0)\nc = n[1.2.3.4]\nk = keys(n)\nv = values(n)\nb = has(n, 1.2.3.4)\nl = length(m)")
  "m: float[string], n: int[{a: int}], I: {key: string, value: float}, k: string" \
    (types "m = [\"a\": 1, \"b\": 2.5]\nm[\"c\"] += 1\nm := remove(m, \"a\")\nn = [{a: 1}: 2]\nforeach m { k = I.key }")
  "I: int, x: int" (types "repeat count=2 { x = rand(max=3) }")
  "a: float, b: interval" (types "a = stddev([1, 2])\nb = stddev([1s])")
  "h: {count: int, max: float, min: float}[], i: {count: int, max: interval, min: interval}[]" \
    (types "h = histogram([1, 2], bucket=0.5)\ni = histogram(bucket=1s, a=[2: 3s])")
  "line 1, column 28: The bucket of a histogram of an interval[] must be an interval, not an int" \
    (types "h = histogram([1s], bucket=1)")
  "line 1, column 27: The bucket of a histogram of an int[] must be a number, not an interval" \
    (types "h = histogram([1], bucket=1s)")
  "h: {count: int, max: float, min: float}[]" (types "h = histogram([1], 1)")
  "line 1, column 5: histogram needs an argument bucket" (types "h = histogram([1])")
  "line 2, column 8: Report x is of an int since line 1, not of a float" \
    (types "report(1, name=\"x\")\nreport(1.5, name=\"x\")")
  "line 2, column 16: The name of a report must be a literal string" \
    (types "n = \"x\"\nreport(1, name=n)")
  "s: {count: int, max: interval, mean: interval, min: interval, p50: interval, p95: interval, p99: interval, stddev: interval}[ip]" \
    (types "s = summary([1.2.3.4: [1ms]])")
  "a: int, b: int, c: float, d: interval" \
    (types "a = sum([1])\nb = sum([#01])\nc = sum([1: 1.5])\nd = sum([1s])")
  "a: int, b: float, c: interval, d: float, e: string, f: int" \
    (types "a = min([3, 1])\nb = mean([1, 2])\nc = mean([1s, 2s])\nd = percentile([1.5, 2], 95)\ne = max([1: \"x\"])\nf = count([1: 2])")
  "x: float[][], i: int" \
    (types "x = [[1.0]]\ni = 0\nx[i][0] += 1\nx[0] := [2]")
  "x: int, y: int, ack: string" \
    (types "x = SYN | ACK\ny = PORT_UNREACHABLE\nack = \"a\"")
  "" \
    (types "/IP(dst=1.2.3.4)/ICMP { expect DestUnreachable(code == PORT_UNREACHABLE) {} }")
  "I: int" \
    (types "repeat { on Raw(\"x\") { break 2 } }")
  "x: int, y: ip" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect Raw(\"a\") { x = length(MATCH) } | ../ICMP { y = MATCH[IP].src } }")
  "x: int, y: ip" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { Raw(\"a\")\n  { x = LAST[UDP].src }\n  Raw(\"b\")\n  expect ../UDP(IP.src == LAST[IP].dst) { y = LAST[IP].src } }")
  "t: float, x: float, p: {a: int}, y: int" \
    (types "foreach t [1, 2.5] { x = t * 2 }\nforeach p [{a: 1}] { y = p.a }")
  "n: int, x: int, y: bool, z: float" \
    (types "n = 3\nif n & 1 { x = 1 } elsif n > 2 { y = true } else { z = 1.0 }")
  "" \
    (types "/IP!(dst=1.2.3.4, id=3)/TCP!(dst=80, flags=SYN|ACK)/Raw(\"x\")")
  "" \
    (types "/IP(dst=1.2.3.4)/ICMP/Echo/Request(\"hello\")")
  "x: ip" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { Raw(\"hi\")\n  expect Raw(\"ho\") { x = MATCH[IP].src } }")
  "x: int, c: int, l: {code: int, length: int}" \
    (types "expect /IP/ICMP/TimeExceeded/IP/UDP { x = MATCH[ICMP/_/IP].id\n  c = case var=l MATCH[ICMP/_] TimeExceeded { l.code } else { 0 } }")
  "x: int" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect ../UDP(dst == 53, IP.ttl < 3, /IP.src = 1.2.3.4, Eth.proto == 0x800) { x = MATCH[UDP].src } }")
  "id: int" \
    (types "id = 5\nexpect /IP(IP.id == id, IP.src == /IP.src) {}")
  "" \
    (types "/IP(dst=1.2.3.4)/TCP(dst=80) { expect ../TCP!(flags & RST, seq_num > 3) {}\n  expect ../TCP!/Raw(data == \"x\") {} }")
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
  "x: ip, I: {dont_frag: bool, dst: ip, frag_offset: int, id: int, is_fragment: bool, length: int, more_frags: bool, options: byte[], proto: int, src: ip, tos: int, tot_len: int, ttl: int}, b: {data: byte[], length: int}, y: byte[]" \
    (types "expect /IP { x = case MATCH[1] IP { MATCH[IP].src } | else { 0.0.0.0 }\n  case var=b MATCH[2] Raw { y = b.data } }")
  "x: int, I: {dst: mac, length: int, proto: int, src: mac, ts: time}, I: {code: int, length: int, type: int}, I: {id: int, length: int}, I: {payload: byte[], seq: int}, I: {payload: byte[], seq: int}, I: {code: int, length: int, mtu: int}, I: {code: int, length: int}, I: {dont_frag: bool, dst: ip, frag_offset: int, id: int, is_fragment: bool, length: int, more_frags: bool, options: byte[], proto: int, src: ip, tos: int, tot_len: int, ttl: int}, I: {checksum: int, dst: int, length: int, src: int}, I: {ack_num: int, checksum: int, dst: int, flags: int, length: int, mss: int, options: byte[], sack_ok: bool, seq_num: int, src: int, ts_ecr: int, ts_val: int, urg_ptr: int, win_size: int, wscale: int}, I: {id: int, length: int}, I: {additional: {class: int, data: byte[], name: string, ttl: int, type: int}[], answers: {class: int, data: byte[], name: string, ttl: int, type: int}[], authentic_data: bool, authoritative: bool, authority: {class: int, data: byte[], name: string, ttl: int, type: int}[], checking_disabled: bool, class: int, name: string, opcode: int, rec_avail: bool, rec_desired: bool, status: int, truncated: bool, type: int}, I: {additional: {class: int, data: byte[], name: string, ttl: int, type: int}[], answers: {class: int, data: byte[], name: string, ttl: int, type: int}[], authentic_data: bool, authoritative: bool, authority: {class: int, data: byte[], name: string, ttl: int, type: int}[], checking_disabled: bool, class: int, name: string, opcode: int, rec_avail: bool, rec_desired: bool, status: int, truncated: bool, type: int}, I: {data: byte[], length: int}, I: {dst: ip, flow_label: int, hop_limit: int, is_fragment: bool, length: int, proto: int, src: ip, traffic_class: int}, I: {code: int, length: int, type: int}, I: {code: int, length: int, mtu: int}, I: {length: int}, I: {headers: {name: string, value: string}[], length: int, method: string, url: string, version: string}, I: {code: int, headers: {name: string, value: string}[], length: int, version: string}, I: {final: bool, length: int, mask: int, masked: bool, opcode: int}" \
    (types "expect /IP { x = case MATCH[0] Eth { 0 } | ICMP { 1 } | Echo { 2 } | Request { 3 } | Reply { 4 } | DestUnreachable { 5 } | TimeExceeded { 6 } | IP { 7 } | UDP { 8 } | TCP { 9 } | DNS { 10 } | Query { 11 } | Answer { 12 } | Raw { 13 } | IP6 { 14 } | ICMP6 { 15 } | PacketTooBig { 16 } | HTTP { 17 } | HttpRequest { 18 } | HttpAnswer { 19 } | WebSocket { 20 } }")
  "x: int, I: {dont_frag: bool, dst: ip, frag_offset: int, id: int, is_fragment: bool, length: int, more_frags: bool, options: byte[], proto: int, src: ip, tos: int, tot_len: int, ttl: int}, y: int" \
    (types "expect /IP { x = case MATCH[1] IP { wait 1s\n  1 } | else { 2 }\n  y = { expect Raw {}\n  3 } }")
*)

(* A constructor makes a variant of its own; where variants meet, as values
 * of a variable, branches, items or operands, they make one of the
 * constructors of all: *)
(*$= types & ~printer:identity
  "r: (Failed string | Got int | Pending), I: int, n: int" \
    (types "r = Pending\nr := Got(3)\nif true { r := Failed(\"x\") }\ncase r Got { n = I } else {}")
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
  "line 2, column 1: Cannot assign a float[] to x, which is an int[] (declared at line 1 as [1])" \
    (types "x = [1]\nx := [2.5]")
  "line 2, column 1: Cannot assign an int to x, which is a (Ok int) (declared at line 1 as Ok(1))" \
    (types "x = Ok(1)\nx := 3")
  "line 2, column 1: Cannot assign a (Ok string) to r, which is a (Ok int) (declared at line 1 as Ok(1))" \
    (types "r = Ok(1)\nr := Ok(\"s\")")
  "line 1, column 8: A constructor cannot hold a void" \
    (types "x = Ok(print(\"a\"))")
  "line 1, column 5: Cannot compare a (Ok int) and a (Ok string)" \
    (types "x = Ok(1) == Ok(\"a\")")
  "line 2, column 8: Nope is none of Ok" \
    (types "x = Ok(1)\ncase x Nope {}")
*)
(*$= types & ~printer:identity
  "x: string, y: string, z: string, w: string[], v: string" \
    (types "x = \"a\" + 1\ny = #4243 + x + 10.0.0.1\nz = string(y)\nw = [\"a\"] + \"b\"\nv = string(#41) + string(1)")
  "line 1, column 5: Cannot apply + to a string and an int[]" \
    (types "x = \"a\" + [1]")
  "line 1, column 8: ACK is a reserved name" \
    (types "ACK = 1")
  "line 2, column 1: x is already declared in this block (:= changes it)" \
    (types "x = 1\nx = 2")
  "line 2, column 1: Cannot assign a string to x, which is an int (declared at line 1 as 1)" \
    (types "x = 1\nx := \"s\"")
  "line 1, column 1: Unknown variable x" \
    (types "x := 1")
  "line 2, column 1: Cannot assign a float to x, which is an int (declared at line 1 as 1)" \
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
  "line 1, column 5: array needs an argument len" \
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
  "line 1, column 1: Cannot tell the type of the items of m: nothing is added to it" \
    (types "m = []")
  "line 1, column 1: Cannot tell the type of the items of a: nothing is added to it" \
    (types "a = []\nprint(min(a))")
  "a: interval[], b: float[], c: int[]" \
    (types "a = []\na += 1ms\nb = []\nb := append(b, 1.5)\nc = []\nc += [1]\nc := []")
  "a: int[], w: int[], x: int[], y: int[], z: bool" \
    (types "a = [1]\nw = [] + 1\nx = concat([], a)\ny = append([], 1)\nz = [] == a")
  "m: int[][int], r: int[][]" \
    (types "m = [1: [1]]\nm[2] := []\nr = [[1]]\nr := array(init=[], len=2)")
  "m: interval[][ip], n: string[], o: float[][], p: int[][string][int]" \
    (types "m = map(key=0.0.0.0, default=[])\nm[1.2.3.4] += 1ms\nn = []\nn += \"x\"\no = array(init=[], len=2)\no[0] := [1.5]\np = map(key=1, default=map(key=\"\", default=[]))\np[1][\"a\"] += 2")
  "line 1, column 1: Cannot tell the type of the items of the empty arrays in m: nothing is added to them" \
    (types "m = map(key=1, default=[])\nprint(length(m))")
  "line 2, column 1: Cannot index an int" \
    (types "x = [1]\nx[0][0] := 1")
  "line 1, column 1: x would have no value" \
    (types "x = print(\"a\")")
  "line 1, column 1: The result of rand is not used" \
    (types "rand(3)")
  "line 1, column 12: Argument a of length must be an array, a map or a string, not an int" \
    (types "x = length(3)")
  "line 1, column 8: Argument cond of assert must be a bool or an int, not a string" \
    (types "assert(\"x\")")
  "line 1, column 13: Argument b of ip_addr must be 4 bytes, an int or a string, not a float" \
    (types "x = ip_addr(1.5)")
  "line 1, column 1: x would have no value" \
    (types "x = assert(true)")
  "line 1, column 7: Argument x of print must be a value, not a void" \
    (types "print(print(1))")
  "line 1, column 1: Break out of 1 repeat, foreach, on or spawn, but there is none" \
    (types "break")
  "line 1, column 10: Break out of 2 repeat, foreach, on or spawn, but there is only one" \
    (types "repeat { break 2 }")
  "line 1, column 9: Break out of 2 repeat, foreach, on or spawn, but there is only one" \
    (types "spawn { break 2 }")
  "line 1, column 11: The duration of spawn must be an interval, not an int" \
    (types "spawn for=1 {}")
  "line 1, column 11: spawn cannot be in a block within an expression, but for the value of a declaration, an assignment or a statement" \
    (types "x = 1 + { spawn {} ; 1 }")
  "line 1, column 4: The condition of if must be a bool, not a string" \
    (types "if \"x\" {}")
  "line 1, column 16: The timeout of expect must be an interval, not an int" \
    (types "expect timeout=1 Raw {}")
  "line 2, column 5: MATCH is only defined in the blocks of expect and on" \
    (types "expect Raw {} | Raw { x = MATCH }\ny = MATCH")
  "line 1, column 11: The maximum of retry must be an int, not an interval" \
    (types "retry max=1s {}")
  "line 1, column 11: The items of foreach must be an array or a map, not an int" \
    (types "foreach t 3 {}")
  "line 1, column 15: The period of foreach must be an interval, not an int" \
    (types "foreach every=1 [1] {}")
  "line 2, column 2: Break out of 2 repeat, foreach, on or spawn, but there is only one" \
    (types "foreach t [1] { x = t * 2.0\n break 2 }")
  "line 1, column 22: The period of repeat must be an interval, not an int" \
    (types "repeat count=3 every=1 {}")
  "line 1, column 6: The duration of wait must be an interval, not an int" \
    (types "wait 3")
  "line 1, column 8: The timeout of expect must be an interval, not an int" \
    (types "expect 5 Raw(\"x\") {}")
  "line 1, column 22: The value of ttl must be an int, not a string" \
    (types "/IP(dst=1.2.3.4, ttl=\"x\")/UDP(dst=53)/Raw(\"hi\")")
  "line 1, column 5: IP has no field dts, do you mean dst?" \
    (types "/IP(dts=1.2.3.4)/UDP(dst=53) {}")
  "line 1, column 46: Unknown field or variable scr, do you mean src?" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect ../UDP(scr == 1) {} }")
  "line 1, column 46: IP has no field scr, do you mean src?" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect ../UDP(IP.scr == 1.2.3.4) {} }")
  "line 2, column 5: Unknown variable anwsers, do you mean answers?" \
    (types "answers = 1\nx = anwsers")
  "line 1, column 21: No field src in a layer: case tells its constructors apart, and Eth, IP, IP6, TCP, UDP have one" \
    (types "on for=1s /IP { x = MATCH[0].src }")
  "line 1, column 21: Cannot apply + to MATCH (a packet) and an int" \
    (types "on for=1s /IP { x = MATCH + 1 }")
  "line 1, column 39: No field unused in TimeExceeded (only {code: int, length: int})\n  The packet it quotes is on top of it: MATCH[TimeExceeded/IP].id is the id of the quoted IP, MATCH[/IP] the IP of the error." \
    (types "on for=1s /IP/ICMP/TimeExceeded { x = MATCH[TimeExceeded].unused }")
  "line 1, column 36: No field cod in TimeExceeded (only {code: int, length: int}), do you mean code?" \
    (types "expect /IP/ICMP/TimeExceeded { x = MATCH[TimeExceeded].cod }")
  "line 1, column 22: No field port in UDP (only {checksum: int, dst: int, length: int, src: int})" \
    (types "expect /IP/UDP { x = MATCH[UDP].port }")
  "line 2, column 5: No field abd in {abc: int}, do you mean abc?" \
    (types "x = {abc: 1}\ny = x.abd")
  "line 1, column 10: rand has no parameter mxa, do you mean max?" \
    (types "x = rand(mxa=3)")
  "line 1, column 8: The timeout of expect must be an interval, not a (UPD)\n  If UPD is a misspelled layer, do you mean UDP?" \
    (types "expect UPD/Raw {}")
  "t: interval" (types "t = 1s\nexpect t Raw {}")
  "line 1, column 1: This (Rae string) is not used, do you mean Raw?" \
    (types "Rae(\"x\")")
  "line 1, column 30: UDP has no field flags" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53, flags=2) {}")
  "line 1, column 30: UDP has no field ttl: IP has one, below it" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53, ttl=3)/Raw()")
  "line 1, column 28: Echo has no field seq: Request and Reply have one, on top of it" \
    (types "/IP(dst=1.2.3.4)/ICMP/Echo(seq=3)/Request()")
  "line 1, column 28: Raw cannot be on top of Echo\n  On top of Echo can be: Request, Reply." \
    (types "/IP(dst=1.2.3.4)/ICMP/Echo/Raw()")
  "line 1, column 16: Unknown field or variable ttl: the field of IP below is IP.ttl" \
    (types "expect /IP/UDP(ttl == 3) {}")
  "line 1, column 22: Unknown field or variable seq: Request and Reply, on top of Echo, have one" \
    (types "expect /IP/ICMP/Echo(seq == 3) {}")
  "line 1, column 36: mss and options cannot both be given" \
    (types "/IP!(dst=1.2.3.4)/TCP!(dst=80, mss=1400, options=#01010101)/Raw()")
  "line 2, column 45: Unknown variable SENT\n  The packets predefined are MATCH, the one that matched, and LAST, the last one sent." \
    (types "tsum = 0s\non for=1s /IP/UDP { tsum += MATCH[Eth].ts - SENT[Eth].ts }")
  "line 1, column 9: Unknown variable SENT\n  The packets predefined are MATCH, the one that matched, and LAST, the last one sent." \
    (types "x = 1 + SENT")
  "line 1, column 5: Unknown variable LASTT, do you mean LAST?" \
    (types "x = LASTT.ts")
  "line 1, column 37: No field seq in Echo (only {id: int, length: int}): Request and Reply have one, on top of it" \
    (types "on for=1s /IP/ICMP/Echo/Reply { x = MATCH[Echo].seq }")
  "line 1, column 37: No field id in ICMP (only {code: int, length: int, type: int}): Echo has one, on top of it, and IP has one, below it" \
    (types "on for=1s /IP/ICMP/Echo/Reply { x = MATCH[ICMP].id }")
  "line 1, column 66: No field seq in Echo (only {id: int, length: int}): Request and Reply have one, on top of it" \
    (types "on for=1s /IP/ICMP/Echo/Reply { case var=l MATCH[0] Echo { print(l.seq) } else {} }")
  "line 1, column 64: No field ttl in DNS (only {id: int, length: int})" \
    (types "on for=1s /IP/UDP/DNS/Answer { case var=l MATCH[0] DNS { print(l.ttl) } else {} }")
  "x: byte[]" \
    (types "expect /IP/UDP/Raw(payload == \"echo\") { x = MATCH[Raw].payload }")
  "line 1, column 31: Unknown field or variable len: the field of Echo below is Echo.length" \
    (types "on for=1s /IP/ICMP/Echo/Reply(len > 0) {}")
  "line 3, column 4: Cannot compare d (a time, declared at line 2 as last + 1s) and an interval" \
    (types "last = now()\nd = last + 1s\nif d > 100ms { }")
  "line 2, column 1: Cannot assign a time to last, which is an interval (declared at line 1 as 0s)\n  A time variable starts as now(), or time(0)." \
    (types "last = 0s\nlast := now()")
  "line 1, column 31: TCP.length is a virtual field (the bytes TCP carries): it cannot be set" \
    (types "/IP(dst=1.2.3.4)/TCP!(dst=80, len=3)/Raw(\"x\")")
  "line 1, column 7: Eth.ts is a virtual field (when the frame was captured): it cannot be set" \
    (types "/Eth!(ts=now(), dst=ff:ff:ff:ff:ff:ff, proto=1)/Raw(\"x\")")
  "line 1, column 30: sack_ok cannot be set in a self-driven TCP\n  Do you mean \"TCP!\"?" \
    (types "/IP(dst=1.2.3.4)/TCP(dst=80, sack_ok=true) {}")
  "line 1, column 5: id cannot be set in a self-driven IP\n  Do you mean \"IP!\"?" \
    (types "/IP(id=3)/TCP(dst=80) {}")
  "line 1, column 19: TCP cannot be self-driven on top of a manual IP" \
    (types "/IP!(dst=1.2.3.4)/TCP(dst=80) {}")
  "line 1, column 28: The type of ICMP is that of the Echo on top: it can be set only with Raw on top" \
    (types "/IP(dst=1.2.3.4)/ICMP(type=8)/Echo {}")
  "line 1, column 18: ICMP needs a type, with Raw on top" \
    (types "/IP(dst=1.2.3.4)/ICMP/Raw(\"x\")")
  "" (types "/IP(dst=1.2.3.4)/ICMP(type=8) {}")
  "line 1, column 43: Request is a terminal layer, therefore /IP/ICMP/Echo/Request is a complete message. No further layer can be stacked on top of it" \
    (types "/IP(dst=1.2.3.4)/ICMP/Echo/Request(seq=1)/Raw(\"x\")")
  "line 1, column 2: IP needs a dst" \
    (types "/IP/UDP(dst=53) {}")
  "line 1, column 18: TCP needs a dst" \
    (types "/IP(dst=1.2.3.4)/TCP(src=1) {}")
  "" (types "/IP(dst=1.2.3.4)/UDP(src=1) { DNS/Query(\"x\") }")
  "" (types "/IP(dst=1.2.3.4)/TCP(dst=80) { ../TCP!(flags=RST)/Raw() }")
  "line 1, column 35: TCP needs a dst" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { ../TCP/Raw() }")
  "line 1, column 2: UDP cannot be at the bottom of a stack\n  Do you mean \"/IP/UDP\"?" \
    (types "/UDP {}")
  "line 1, column 18: IP cannot be on top of IP\n  On top of IP can be: TCP, UDP, ICMP, Raw." \
    (types "/IP(dst=1.2.3.4)/IP {}")
  "line 1, column 5: MATCH is only defined in the blocks of expect and on" \
    (types "x = MATCH")
  "line 1, column 5: IP.src is a field of a packet being matched, which only the condition of a pattern can read (as in \"expect Raw(IP.src == x)\").\n  Of a packet in a variable, it is \"p[IP].src\": \"LAST[IP].src\" for the last one sent, \"MATCH[IP].src\" for the one that matched." \
    (types "x = IP.src")
  "line 1, column 42: IP.ttl is a field of a packet being matched, which only the condition of a pattern can read (as in \"expect Raw(IP.ttl == x)\"); the options of a stack cannot read the layers below.\n  Of a packet in a variable, it is \"p[IP].ttl\": \"LAST[IP].ttl\" for the last one sent, \"MATCH[IP].ttl\" for the one that matched." \
    (types "/IP(dst=1.2.3.4)/UDP(dst=7) { Raw(\"ttl ${IP.ttl}\") }")
  "line 1, column 5: =~ is not supported yet" \
    (types "x = y =~ /IP")
  "line 1, column 39: ../ goes below the bottom of the stack\n  In this block, the stack is /IP/UDP (../ goes back to /IP, ../../ to /Eth).\n  Do you mean \"../UDP\"?" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect ../../../../UDP {} }")
  "line 1, column 32: TCP cannot be on top of TCP\n  In this block, the stack is /IP/TCP (../ goes back to /IP, ../../ to /Eth).\n  Do you mean \"../TCP/Raw()\" (the same as \"Raw()\")?" \
    (types "/IP(dst=1.2.3.4)/TCP(dst=80) { TCP/Raw() }")
  "line 1, column 42: DNS cannot be on top of IP\n  In this block, the stack is /IP/UDP/DNS (../ goes back to /IP/UDP, ../../ to /IP, ../../../ to /Eth).\n  Do you mean \"../DNS(id=3)/Query(\"x\")\"?" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53)/DNS { ../../DNS(id=3)/Query(\"x\") }")
  "line 1, column 49: DNS cannot be on top of IP\n  In this block, the stack is /IP/UDP/DNS (../ goes back to /IP/UDP, ../../ to /IP, ../../../ to /Eth).\n  Do you mean \"../DNS/Answer\" (the same as \"Answer\")?" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53)/DNS { expect ../../DNS/Answer {} }")
  "line 1, column 32: TCP cannot be on top of TCP\n  In this block, the stack is /IP/TCP (../ goes back to /IP, ../../ to /Eth).\n  Do you mean \"../TCP!(flags=RST)/Raw()\"?" \
    (types "/IP(dst=1.2.3.4)/TCP(dst=80) { TCP!(flags=RST)/Raw() }")
  "line 1, column 36: IP cannot be on top of IP\n  In this block, the stack is /IP/ICMP/Echo (../ goes back to /IP/ICMP, ../../ to /IP, ../../../ to /Eth).\n  Do you mean \"../../../IP!(ttl=1)/ICMP/Echo/Request(seq=1)\"?" \
    (types "/IP(dst=1.2.3.4)/ICMP/Echo { ../../IP!(ttl=1)/Request(seq=1) }")
  "line 1, column 33: Request cannot be on top of ICMP\n  In this block, the stack is /IP/ICMP/Echo (../ goes back to /IP/ICMP, ../../ to /IP, ../../../ to /Eth).\n  Do you mean \"Request(seq=1)\"?" \
    (types "/IP(dst=1.2.3.4)/ICMP/Echo { ../Request(seq=1) }")
  "line 1, column 2: DNS cannot be at the bottom of a stack\n  Do you mean \"/IP/UDP/DNS/Query(\"x\")\"?" \
    (types "/DNS/Query(\"x\")")
  "line 1, column 36: Reply cannot be on top of ICMP\n  Do you mean \"/IP(src == 1.2.3.4)/ICMP/Echo/Reply\"?" \
    (types "on for=1s /IP(src == 1.2.3.4)/ICMP/Reply {}")
  "line 1, column 12: Reply cannot be on top of IP\n  On top of IP can be: TCP, UDP, ICMP, Raw." \
    (types "expect /IP/Reply {}")
  "line 1, column 17: IP cannot be on top of ICMP\n  On top of ICMP can be: Echo, DestUnreachable, TimeExceeded, Raw." \
    (types "expect /IP/ICMP/IP {}")
  "line 1, column 30: Query cannot be on top of UDP\n  Do you mean \"/IP(dst=1.2.3.4)/UDP(dst=53)/DNS/Query(\"x\")\"?" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53)/Query(\"x\")")
  "line 1, column 25: Request cannot be on top of ICMP\n  In this block, the stack is /IP (../ goes back to /Eth).\n  Do you mean \"ICMP/Echo/Request(\"x\")\"?" \
    (types "/IP(dst=1.2.3.4) { ICMP/Request(\"x\") }")
  "line 1, column 1: DNS cannot be at the bottom of a stack\n  Do you mean \"/IP/UDP/DNS/Query(\"x\")\"?" \
    (types "DNS/Query(\"x\")")
  "line 1, column 8: UDP cannot be at the bottom of a stack\n  Do you mean \"/IP/UDP\"?" \
    (types "expect udp {}")
  "line 1, column 8: ../ goes back in the current stack, and there is none out of a block\n  Do you mean \"/IP/UDP\"?" \
    (types "expect ../UDP {}")
  "line 1, column 46: There is no TCP below UDP" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect ../UDP(TCP.src == 1) {} }")
  "line 1, column 46: There is no ICMP/IP below UDP" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { expect ../UDP(ICMP/IP.ttl == 1) {} }")
  "line 1, column 16: There is no /IP/_/_/IP below UDP" \
    (types "expect /IP/UDP(/IP/_/_/IP.ttl == 1) {}")
  "line 1, column 46: The condition on TCP must be a bool, not a string" \
    (types "/IP(dst=1.2.3.4)/TCP(dst=80) { expect ../TCP(\"x\") {} }")
  "line 1, column 46: flags cannot be read in a self-driven TCP\n  Do you mean \"TCP!\"?" \
    (types "/IP(dst=1.2.3.4)/TCP(dst=80) { expect ../TCP(flags & ACK) {} }")
  "line 1, column 5: Field a given twice" \
    (types "x = {a: 1, A: 2}")
  "line 1, column 5: Cannot order values of type ip" \
    (types "x = 1.2.3.4 < 1.2.3.5")
  "line 1, column 9: An item of this array must be an int, not a string" \
    (types "x = [1, \"a\"]")
  "line 1, column 5: Cannot apply / to an int and an interval" \
    (types "x = 3 / 2s")
  "line 1, column 5: Cannot apply in to a cidr and an ip" \
    (types "x = 10.0.0.0/8 in 10.0.0.1")
  "line 1, column 5: Cannot apply + to a time and a time" \
    (types "x = now() + now()")
  "line 1, column 5: Cannot apply - to an int and a time" \
    (types "x = 1 - now()")
  "line 1, column 5: Unknown variable z\nline 3, column 1: Unknown variable w\nline 4, column 7: Argument x of print must be a value, not a void" \
    (types "x = z\ny = x + 1\nw := 1\nprint(print(2))")
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
    (types "x = 1 + if true { /IP(dst=1.2.3.4)/UDP(dst=53)/Raw(\"x\") ; 1 } else { 2 }")
  "line 1, column 13: wait cannot be in a block within an expression, but for the value of a declaration, an assignment or a statement" \
    (types "print(\"${ { wait 1s ; 1 } }\")")
  "line 1, column 1: An on lasts either for its own duration (for), keeping its block waiting, or until its block ends, which linger delays: not both" \
    (types "on for=1s linger=1s /IP {}")
  "line 1, column 6: The subject of case must be a variant, such as a layer of a packet, not an int" \
    (types "case 3 IP {}")
  "line 1, column 36: Foo is none of Answer, DNS, DestUnreachable, Echo, Eth, HTTP, HttpAnswer, HttpRequest, ICMP, ICMP6, IP, IP6, PacketTooBig, Query, Raw, Reply, Request, TCP, TimeExceeded, UDP, WebSocket" \
    (types "expect /IP { case MATCH[0] IP {} | Foo {} }")
  "line 1, column 36: IP already has a block in this case" \
    (types "expect /IP { case MATCH[0] IP {} | ip {} }")
  "line 1, column 18: This case needs an else, or a block for each of Answer, DNS, DestUnreachable, Echo, Eth, HTTP, HttpAnswer, HttpRequest, ICMP, ICMP6, IP6, PacketTooBig, Query, Raw, Reply, Request, TimeExceeded, UDP, WebSocket, to have a value" \
    (types "expect /IP { x = case MATCH[1] IP { 1 } | TCP { 2 } }")
  "line 1, column 18: The branches of this case are of different types: a string and an int" \
    (types "expect /IP { x = case MATCH[1] Raw { \"a\" } | IP { 1 } | else { 2 } }")
  "line 1, column 18: This case has a block for each of Answer, DNS, DestUnreachable, Echo, Eth, HTTP, HttpAnswer, HttpRequest, ICMP, ICMP6, IP, IP6, PacketTooBig, Query, Raw, Reply, Request, TCP, TimeExceeded, UDP, WebSocket: its else is never run" \
    (types "expect /IP { x = case MATCH[0] Eth { 0 } | ICMP { 1 } | Echo { 2 } | Request { 3 } | Reply { 4 } | DestUnreachable { 5 } | TimeExceeded { 6 } | IP { 7 } | UDP { 8 } | TCP { 9 } | DNS { 10 } | Query { 11 } | Answer { 12 } | Raw { 13 } | IP6 { 14 } | ICMP6 { 15 } | PacketTooBig { 16 } | HTTP { 17 } | HttpRequest { 18 } | HttpAnswer { 19 } | WebSocket { 20 } | else { 0 } }")
  "line 1, column 38: Unknown variable l" \
    (types "expect /IP { case MATCH[1] Raw { x = l.data } }")
*)

(* The examples of the spec that use only v1 features: *)
(*$= types & ~printer:identity
  "num_resp: int, I: int" (types (Tools.file_content "tests/crafty/ping_counter.crafty"))
  "" (types (Tools.file_content "tests/crafty/reset.crafty"))
  "line 3, column 33: Unknown variable n" \
    (types (Tools.file_content "tests/crafty/pong_counter.crafty"))
  "line 4, column 19: flags cannot be read in a self-driven TCP\n  Do you mean \"TCP!\"?" \
    (types (Tools.file_content "tests/crafty/not_acked.crafty"))
  "line 4, column 54: =~ is not supported yet" \
    (types (Tools.file_content "tests/crafty/icmp_error.crafty"))
*)

(* A packet sent into a variable must go through manual layers only, but the
 * interface: *)
(*$= types & ~printer:identity
  "" (types "/IP!(dst=1.2.3.4)/UDP(dst=53) { p = Raw(\"x\") }")
  "" (types "/IP(dst=1.2.3.4)/TCP(dst=80) { p = ../../IP!/TCP!/Raw(\"GET /\") }")
  "line 1, column 32: Only a packet sent through manual layers can be seen leaving, and TCP is self-driven" \
    (types "/IP(dst=1.2.3.4)/TCP(dst=80) { p = Raw(\"GET /\") }")
  "line 1, column 32: Only a packet sent through manual layers can be seen leaving, and IP is self-driven" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=53) { p = Raw(\"x\") }")
  "line 2, column 7: LAST[Eth].ts is not known: only a packet captured as it leaves has it (p = MESSAGE, through manual layers)" \
    (types "/IP!(dst=1.2.3.4)/UDP(dst=53) { Raw(\"x\")\n  t = LAST[Eth].ts }")
  "line 2, column 33: p is an int, not a packet" \
    (types "p = 1\n/IP!(dst=1.2.3.4)/UDP(dst=53) { p := Raw(\"x\") }")
  "line 1, column 7: A packet cannot be in a block within an expression, but for the value of a declaration, an assignment or a statement" \
    (types "x = { p = /IP!(dst=1.2.3.4)/UDP(dst=53)/Raw(\"x\") ; 1 } + 1")
*)

(* The stats of the stream at the top of the stack: *)
(*$= types & ~printer:identity
  "line 1, column 5: stats() is only defined on a protocol stack" (types "x = stats()")
  "s: {bytes_in: int, bytes_out: int, packets_in: int, packets_out: int}" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=7) { s = stats() }")
  "line 1, column 35: No field cwnd in {bytes_in: int, bytes_out: int, packets_in: int, packets_out: int}" \
    (types "/IP(dst=1.2.3.4)/UDP(dst=7) { x = stats().cwnd }")
  "x: int, y: interval" \
    (types "/IP(dst=1.2.3.4)/TCP!(dst=7) { x = stats().cwnd\ny = stats().srtt }")
*)
