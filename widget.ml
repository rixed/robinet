(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(* Copyright 2012, Cedric Cellier
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
(**
  Any object that can be visualized and manipulated via the API
 *)
open Batteries

type t =
    { (* The stable identity of a widget.
       * Names are neither unique nor stable: several siblings may share a name,
       * and a widget can be moved elsewhere in the tree. The administration UI,
       * the browser URL and (eventually) the saved topology all need a handle
       * that survives those changes, so that handle is this id. *)
      id : int ;
      (* Which simulation this widget belongs to. An id rather than the
       * simulation itself, because a simulation holds the root of its widget
       * tree and this module is therefore compiled before it. A widget only
       * ever relates to widgets of its own simulation: a cable cannot span two
       * clocks. *)
      sim : int ;
      (* A mere label. Must not contain '/' so that [full_name] stays
       * unambiguous. *)
      name : string ;
      (* We want to be able to navigate the logs/stats/characteristics of
       * every simulated things (aka "widgets").
       * Widgets are connected with TRX in various ways, sometime "vertically",
       * as a stack of layers to assemble composed objects (ex: a service with
       * a host with an HTTP layer with a TCP layer with an IP layer with an
       * ETH layer), and sometimes "horizontally" as connections between various
       * objects, mostly via cables.
       * From the point of view of the simulator, all these are just trxs
       * connected together.
       * Those relationships are indicated at construction time.
       *
       * Parent / children: widgets form a hierarchical tree. The full_name of a
       * widget indicates that hierarchy. *)
      mutable parent : t option ;
      mutable children : t list ;
      (* Siblings: When widgets are connected "horizontally" to others.
       * Widget names are then unrelated. *)
      mutable peers : peer list ;
      logger : Log.t ;
      (* Setter and getter of configurable properties: *)
      mutable properties : property list }

and peer = { widget : t ;
             via : t option }

and property = { name : string ;
                descr : string ;
               getter : (unit -> value) ;
               (* If that property can be set *)
               setter : (value -> unit) option ;
               (* What the value looks like, so that the UI can offer the right
                * input and reject nonsense before submitting it. Values still
                * travel as strings: this only says how to render one. *)
                 kind : kind }

(* A property value, in the shape the administration interface speaks.
 *
 * Not a string: properties exist only for that interface, so its own type is
 * their natural one, and keeping values typed all the way to the setter spares
 * every property author from inventing a string encoding -- and from getting it
 * wrong, which is easier than it sounds (string_of_float renders 5. as "5.",
 * which is not a number any browser will accept).
 *
 * [Basic] rather than [Safe]: the three extra constructors Safe carries --
 * Intlit, Tuple, Variant -- cannot mean anything here, and would only show up
 * as dead branches, or worse, be swallowed by a catch-all. *)
and value = Yojson.Basic.t

and kind =
    | String
    | Int
    | Float
    (* "true" or "false", as the setter reads them *)
    | Bool
    (* One of those values, and nothing else *)
    | Enum of string list
    (* A number known to lie within those bounds *)
    | Range of float * float
    (* A family of counts or measures, keyed by the parameters of the events
     * they come from: it reads as a small table, and the only thing a write
     * does is reset it. Which sort of metric it is comes with the value, which
     * a metric, unlike a range, describes itself. *)
    | Metric

let property ?(descr="") ?setter ?(kind=String) ~getter name =
    { name ; descr ; getter ; setter ; kind }

(** A metric, as a property: it reads as the metric's current figures, and the
 * only thing that can be written to it is a reset -- whatever the value. *)
let metric_property ?(descr="") ?(resettable=true) name metric =
    property name ~descr ~kind:Metric
        ~getter:(fun () -> Metric.to_json metric)
        ?setter:(if resettable then Some (fun _ -> Metric.reset metric) else None)

(** What a setter raises when handed something it cannot use. The API turns it
 * into a 400 with this message, like any other exception a setter throws. *)
exception Bad_value of string

let bad_value fmt =
    Printf.ksprintf (fun s -> raise (Bad_value s)) fmt

(* Coercions for setters to read their argument with.
 *
 * JSON has a single number type while Yojson has two, so a UI sending a round
 * number for a float property delivers `Int, not `Float: a setter that matched
 * only `Float would refuse 42 and accept 42.5, which is the kind of bug that
 * only shows up when a user happens to type a whole number. These accept both,
 * and a string besides, so that a value typed by hand also works. *)

let to_float = function
    | `Float f -> f
    | `Int i -> float_of_int i
    | `String s ->
        (try float_of_string s
        with _ -> bad_value "not a number: %S" s)
    | v -> bad_value "expected a number, not %s" (Yojson.Basic.to_string v)

let to_int = function
    | `Int i -> i
    | `Float f when f = float_of_int (int_of_float f) -> int_of_float f
    | `Float f -> bad_value "expected a whole number, not %g" f
    | `String s ->
        (try int_of_string s
        with _ -> bad_value "not a whole number: %S" s)
    | v -> bad_value "expected a whole number, not %s" (Yojson.Basic.to_string v)

let to_bool = function
    | `Bool b -> b
    | `String ("true" | "1") -> true
    | `String ("false" | "0") -> false
    | v -> bad_value "expected true or false, not %s" (Yojson.Basic.to_string v)

let to_string = function
    | `String s -> s
    (* Anything else is rendered as it would be on the wire, so that a property
     * declared as a string still gets something usable when handed a number. *)
    | v -> Yojson.Basic.to_string v

(* Beware that the widget graph is cyclic (parent/children and peers point back
 * at each other), so widgets must never be compared with the polymorphic
 * equality; use physical equality throughout. *)

let full_name t =
    let rec loop full_name = function
        | None -> full_name
        | Some p -> loop ("/"^ p.name ^ full_name) p.parent in
    loop ("/"^ t.name) t.parent

(* Ids are unique across the whole process rather than merely within a
 * simulation, which costs nothing: allocating one needs no simulation in hand,
 * and widget creation is vanishingly rare on the time scale of a simulation.
 * They remain unique within a simulation, which is all the API asks of them. *)
let next_id =
    let seq = ref 0 in
    fun () ->
        let id = !seq in
        incr seq ;
        id

(* The one place a widget is built. *)
let make_ ?parent ~sim ?now ?size ?(properties=[]) name =
    if String.contains name '/' then
        invalid_arg ("Widget.make: name must not contain '/': "^ name) ;
    let logger = Log.make ?size ?now () in
    let t = {
        id = next_id () ;
        sim ;
        name ;
        parent ;
        children = [] ;
        peers = [] ;
        logger ;
        properties } in
    (* Linking it to its parent is all the registration there is: a simulation's
     * inventory of widgets is that tree, reachable from its root.
     * Appended rather than prepended so that children stay in creation order,
     * which is the order they are then enumerated, listed by the API and shown
     * in the UI. Quadratic in the number of siblings, which is irrelevant:
     * widgets are created once, at set-up. *)
    Option.may (fun p -> p.children <- p.children @ [ t ]) parent ;
    t

(** Create a widget below [parent], in [parent]'s simulation and reading the
 * time from [parent]'s clock.
 *
 * A parent is always required, and always available: a caller either has the
 * widget it is building this one under, or has the simulation, whose root is
 * one [Simulation.root] away. That is what keeps the root the only parentless
 * widget of a simulation, and hence keeps it a complete inventory. *)
let make ~parent ?size ?properties name =
    make_ ~parent ~sim:parent.sim ~now:parent.logger.Log.now
          ?size ?properties name

(** Create the root of a simulation's widget tree: the only widget with no
 * parent, and the only one that has to be told which simulation it is in and
 * where to read the time. Called by [Simulation.make], and nowhere else. *)
let make_root ~sim ~now ?size ?properties name =
    make_ ~sim ~now ?size ?properties name

(** Enumerate [t] and all of its descendants, depth first. *)
let rec enum t =
    Enum.append
        (Enum.singleton t)
        (Enum.flatten (List.enum t.children /@ enum))

(** [t] and all of its descendants. *)
let descendants t =
    enum t |> List.of_enum

(** Lookup a widget by id within a tree. *)
let find root id =
    try
        enum root |>
        Enum.find (fun w -> w.id = id) |>
        Option.some
    with Not_found ->
        None

(** Lookup widgets by their [full_name] within a tree. Since names are not
 * unique this may return any number of widgets (usually zero or one). The first
 * component of the path is the root's own name. *)
let find_by_path root path =
    let names =
        String.split_on_char '/' path |>
        List.filter (fun n -> n <> "") in
    let matching name widgets =
        List.filter (fun w -> w.name = name) widgets in
    let rec loop candidates = function
        | [] -> candidates
        | name :: rest ->
            let children =
                List.concat (List.map (fun w -> w.children) candidates) in
            loop (matching name children) rest in
    match names with
    | [] -> []
    | first :: rest -> loop (matching first [ root ]) rest

(* Is [a] [t] itself or one of its ancestors? *)
let rec is_ancestor a t =
    a == t ||
    (match t.parent with
    | None -> false
    | Some p -> is_ancestor a p)

let unlink_from_parent t =
    Option.may (fun p ->
        p.children <- List.filter (fun c -> c != t) p.children
    ) t.parent

(** Delete a widget and, recursively, all of its children: a widget is made of
 * its children, so they cannot outlive it.
 *
 * Any peering relationship involving the deleted widgets is dropped, including
 * those where they merely served as the intermediary: a cable *is* the link, so
 * removing it disconnects its two ends.
 *
 * Unlinking it from its parent is all there is to it: nothing else holds a
 * reference, since a simulation's widgets are just its root's subtree. *)
let rec delete t =
    (* [List.iter] walks the list value we have now, which is unaffected by the
     * children unlinking themselves from [t.children] as they go: *)
    List.iter delete t.children ;
    t.children <- [] ;
    let mentions p =
        p.widget == t ||
        (match p.via with Some v -> v == t | None -> false) in
    let unlink w =
        w.peers <- List.filter (fun p -> not (mentions p)) w.peers in
    List.iter (fun p ->
        unlink p.widget ;
        Option.may unlink p.via
    ) t.peers ;
    t.peers <- [] ;
    unlink_from_parent t ;
    t.parent <- None

(** Move a widget (and therefore its whole subtree) elsewhere in the hierarchy.
 *
 * Nothing else has to be updated: the id is unchanged and [full_name] is
 * computed on demand. A widget cannot leave its simulation. *)
let reparent t new_parent =
    if new_parent.sim <> t.sim then
        invalid_arg ("Widget.reparent: "^ full_name new_parent ^
                     " belongs to another simulation") ;
    if is_ancestor t new_parent then
        invalid_arg ("Widget.reparent: "^ full_name new_parent ^" is within "^
                     full_name t ^", that would create a cycle") ;
    unlink_from_parent t ;
    t.parent <- Some new_parent ;
    new_parent.children <- t :: new_parent.children

let same_via v1 v2 =
    match v1, v2 with
    | None, None -> true
    | Some a, Some b -> a == b
    | _ -> false

let has_peer t peer via =
    List.exists (fun p -> p.widget == peer && same_via p.via via) t.peers

let make_peers ?via t1 t2 =
    if t1.sim <> t2.sim then
        invalid_arg ("Widget.make_peers: "^ full_name t1 ^" and "^ full_name t2 ^
                     " belong to different simulations") ;
    (match via with
    | Some v when v.sim <> t1.sim ->
        invalid_arg ("Widget.make_peers: "^ full_name v ^
                     " belongs to another simulation")
    | _ -> ()) ;
    if t1 == t2 then
        invalid_arg ("Widget.make_peers: "^ full_name t1 ^
                     " cannot be its own peer") ;
    (match via with
    | Some v when v == t1 || v == t2 ->
        invalid_arg ("Widget.make_peers: "^ full_name v ^
                     " cannot be both an end and the intermediary")
    | _ -> ()) ;
    if has_peer t1 t2 via then
        invalid_arg ("Widget.make_peers: "^ full_name t1 ^" and "^
                     full_name t2 ^" are already peers via the same \
                     intermediary") ;
    t1.peers <- { widget = t2 ; via } :: t1.peers ;
    t2.peers <- { widget = t1 ; via } :: t2.peers ;
    Option.may (fun via ->
        via.peers <- { widget = t1 ; via = None } ::
                     { widget = t2 ; via = None } :: via.peers
    ) via
