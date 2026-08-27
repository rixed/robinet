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
               getter : (unit -> string) ;
               (* If that property can be set *)
               setter : (string -> unit) option }

let property ?(descr="") ?setter ~getter name =
    { name ; descr ; getter ; setter }

(* Beware that the widget graph is cyclic (parent/children and peers point back
 * at each other), so widgets must never be compared with the polymorphic
 * equality; use physical equality throughout. *)

let full_name t =
    let rec loop full_name = function
        | None -> full_name
        | Some p ->
            loop ("/"^ p.name ^ full_name) p.parent in
    loop ("/"^ t.name) t.parent

(* All existing widgets are inventoried here, indexed by their id: *)
let all : (int, t) Hashtbl.t = Hashtbl.create 131

let next_id =
    let seq = ref 0 in
    fun () ->
        let id = !seq in
        incr seq ;
        id

let make ?parent ?use_wall_clock ?size ?(properties=[]) name =
    if String.contains name '/' then
        invalid_arg ("Widget.make: name must not contain '/': "^ name) ;
    let size =
        match size, parent with
        | Some _, _ -> size
        | None, Some p -> Some (Array.length p.logger.queues.(0).msgs)
        | None, None -> None in
    let use_wall_clock =
        match use_wall_clock, parent with
        | Some _, _ -> use_wall_clock
        | None, Some p -> Some p.logger.use_wall_clock
        | None, None -> None in
    let logger = Log.make ?use_wall_clock ?size () in
    let t = {
        id = next_id () ;
        name ;
        parent ;
        children = [] ;
        peers = [] ;
        logger ;
        properties } in
    Option.may (fun p -> p.children <- t :: p.children) parent ;
    Hashtbl.add all t.id t ;
    t

(** Lookup a widget by its id. *)
let find id =
    Hashtbl.find_option all id

(** All the widgets with no parent. *)
let roots () =
    Hashtbl.fold (fun _id t roots ->
        if t.parent = None then t :: roots else roots
    ) all []

(** Lookup widgets by their [full_name]. Since names are not unique this may
 * return any number of widgets (usually zero or one). *)
let find_by_path path =
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
    | first :: rest -> loop (matching first (roots ())) rest

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
 * removing it disconnects its two ends. *)
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
    t.parent <- None ;
    Hashtbl.remove all t.id

(** Move a widget (and therefore its whole subtree) elsewhere in the hierarchy.
 * [new_parent] is [None] to turn it into a root.
 *
 * Nothing else has to be updated: the id is unchanged and [full_name] is
 * computed on demand. *)
let reparent t new_parent =
    (match new_parent with
    | Some p when is_ancestor t p ->
        invalid_arg ("Widget.reparent: "^ full_name p ^" is within "^
                     full_name t ^", that would create a cycle")
    | _ -> ()) ;
    unlink_from_parent t ;
    t.parent <- new_parent ;
    Option.may (fun p -> p.children <- t :: p.children) new_parent

let same_via v1 v2 =
    match v1, v2 with
    | None, None -> true
    | Some a, Some b -> a == b
    | _ -> false

let has_peer t peer via =
    List.exists (fun p -> p.widget == peer && same_via p.via via) t.peers

let make_peers ?via t1 t2 =
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
