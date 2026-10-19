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
(** The tree of parsers: one node per layer of every stream a program sends
   or receives, under the node of the layer it is on top of.

   Siblings are told apart by their layer and their key, the values of the
   discriminants a stack can set (the IP addresses, the ports...); those
   that cannot be set (the protocol of IP) are told by the layer on top. A
   node is shared by the stacks and patterns that use it, whatever their
   mode, and goes away when the last of them is gone and it has no children
   left. The nodes of terminal layers, which send a message each, are not
   held by the stack that sends it: they go away with their parent. The root
   is the Ethernet interface. *)
open Batteries
open Crafty_value
module A = Crafty_ast
module L = Crafty_layers

(* The discriminants of [L.key_fields], with their values in the packets a
 * node sends: *)
module Key =
struct
    type t = (int * value) list

    let equal a b =
        List.length a = List.length b &&
        List.for_all2 (fun (i, a) (j, b) -> i = j && equal a b) a b

    (* Keys hold ints and addresses only: *)
    let hash k =
        Hashtbl.hash (List.map (fun (i, v) -> i, to_string A.Type.Void v) k)
end

module Siblings = Hashtbl.Make (Key)

type node =
    { layer : L.layer ;
      key : Key.t ;
      parent : node option ;
      (* By layer name, then by key, as a received packet is looked up at
       * every layer, among possibly many streams. A layer with no node
       * left has no entry: *)
      children : (string, node Siblings.t) Hashtbl.t ;
      (* How many stacks and patterns hold it: *)
      mutable users : int ;
      eth : Eth.State.t ;
      ops : L.ops }

(** A layer of a stack: a node used in a mode, with the options given. *)
type entry = { node : node ; mode : L.mode ; options : (int * value) list }

let make_root eth =
    { layer = L.root ; key = [] ; parent = None ;
      children = Hashtbl.create 10 ; users = 0 ; eth ;
      ops = L.root.node { eth ; below = None } }

(* The children of [n] for layer [l]: *)
let siblings n (l : L.layer) = Hashtbl.find_option n.children l.name

(* A value of field [i] of [l] within [lo, hi] that no sibling has: *)
let pick_random loc parent (l : L.layer) i lo hi =
    let taken =
        Option.map_default (fun s ->
            Siblings.fold (fun k _ taken ->
                match List.assoc_opt i k with
                | Some (Int v) -> Set.Int.add v taken
                | _ -> taken) s Set.Int.empty) Set.Int.empty (siblings parent l) in
    let n = hi - lo + 1 in
    if Set.Int.cardinal taken >= n then
        error loc "No %s left for another %s" l.fields.(i).name l.name ;
    (* The first free one from a random start: *)
    let rec loop v =
        if Set.Int.mem v taken then loop (if v = hi then lo else v + 1) else v in
    Int (loop (lo + Random.int n))

(** The child of [parent] for [l] given these [options]: an existing one if
 * they give all of its key, or else a new one, with what is missing picked
 * as {!L.pick} says. *)
let child loc parent (l : L.layer) (options : (int * value) list) =
    let random = ref false in
    let key =
        List.map (fun i ->
            match List.assoc_opt i options with
            | Some v -> i, v
            | None ->
                (match l.fields.(i).pick with
                | Some L.Local_address ->
                    (match Eth.State.find_ip4 parent.eth with
                    | ip -> i, Ip ip
                    | exception Not_found ->
                        error loc "No IPv4 address to send %s from" l.name)
                | Some (L.Random_in (lo, hi)) ->
                    random := true ;
                    i, pick_random loc parent l i lo hi
                | Some (L.Random_shared (lo, hi)) ->
                    (match Option.bind (siblings parent l) (fun s ->
                               Siblings.fold (fun k _ v ->
                                   if v = None then List.assoc_opt i k else v) s None) with
                    | Some v -> i, v
                    | None -> i, pick_random loc parent l i lo hi)
                | Some L.Required | None ->
                    error loc "%s needs a %s" l.name l.fields.(i).name)
        ) (L.key_fields l) in
    let existing =
        if !random then None
        else Option.bind (siblings parent l) (fun s -> Siblings.find_option s key) in
    match existing with
    | Some c -> c
    | None ->
        let c = { layer = l ; key ; parent = Some parent ;
                  children = Hashtbl.create 3 ; users = 0 ; eth = parent.eth ;
                  ops = l.node { eth = parent.eth ; below = Some parent.ops } } in
        let s =
            match siblings parent l with
            | Some s -> s
            | None ->
                let s = Siblings.create 3 in
                Hashtbl.add parent.children l.name s ;
                s in
        Siblings.add s key c ;
        c

let acquire n = n.users <- n.users + 1

let children n =
    Hashtbl.fold (fun _ s cs -> Siblings.fold (fun _ c cs -> c :: cs) s cs)
                 n.children []

(* Removes [n] if nothing uses it any more, its terminal children with it,
 * and so on down to the root: *)
let rec prune n =
    if n.users = 0 &&
       List.for_all (fun c -> c.layer.terminal && c.users = 0) (children n) then
        Option.may (fun p ->
            Option.may (fun s ->
                Siblings.remove s n.key ;
                if Siblings.length s = 0 then Hashtbl.remove p.children n.layer.name
            ) (siblings p n.layer) ;
            prune p) n.parent

let release n =
    assert (n.users > 0) ;
    n.users <- n.users - 1 ;
    prune n

(** {2 Sending} *)

(* The fields of the node of [e] by name: its key, then the options: *)
let fields_of e name =
    match L.find_field e.node.layer name with
    | None -> invalid_arg ("Crafty_tree: no field "^ name ^" in "^ e.node.layer.name)
    | Some i ->
        (match List.assoc_opt i e.node.key with
        | Some _ as v -> v
        | None -> List.assoc_opt i e.options)

(** Sends a packet down that stack, from its top (a terminal layer): each
 * manual layer packs what is above it, until a self-driven one takes it, or
 * the root, which emits it as it is. Raises [Failed]. *)
let send stack =
    let rec loop hints bits = function
        | [] ->
            invalid_arg "Crafty_tree.send: empty stack"
        | e :: rest ->
            (match e.mode with
            | L.Driven ->
                e.node.ops.send (fields_of e) hints bits
            | L.Manual ->
                let bits, hints = e.node.ops.pack (fields_of e) hints bits in
                (match rest with
                | [] ->
                    let st = e.node.eth in
                    Simulation.asap st.iface.widget.power st.iface.emit bits
                | rest ->
                    loop hints bits rest)) in
    loop [] Bitstring.empty_bitstring stack

(** {2 Printing} *)

let rec size n = List.fold_left (fun s c -> s + size c) 1 (children n)

let key_string n =
    List.map (fun (i, v) ->
        let f = n.layer.fields.(i) in
        f.name ^"="^ to_string f.typ v) n.key |>
    String.concat ", "

(** As [Layer(key)*users{children}], children by layer then key. *)
let rec print oc n =
    String.print oc n.layer.name ;
    if n.key <> [] then Printf.fprintf oc "(%s)" (key_string n) ;
    if n.users > 0 then Printf.fprintf oc "*%d" n.users ;
    match children n with
    | [] -> ()
    | cs ->
        List.map (fun c -> (c.layer.name, key_string c), c) cs |>
        List.sort (fun (a, _) (b, _) -> compare a b) |>
        List.map snd |>
        List.print ~first:"{" ~last:"}" ~sep:", " print oc

let to_string n = IO.to_string print n

(*$inject
  let sim = Simulation.make ~realtime:false "crafty-tree"
  let eth =
      Eth.State.make ~parent:sim.root ~name:"crafty"
          ~mac:(Eth.Addr.of_string "02:00:00:00:00:01")
          ~my_addresses:[ Eth.State.make_my_ip_address
                              (Ip.Addr.of_string "10.0.0.1") ] ()
  let loc = Crafty_ast.{ line = 1 ; column = 1 }
  let ip_to s = [ 1, Crafty_value.Ip (Ip.Addr.of_string s) ]
  let port n = Crafty_value.Int n
*)
(*$R child
  let root = make_root eth in
  let ip = child loc root Crafty_layers.ip (ip_to "1.2.3.4") in
  acquire ip ;
  assert_bool "found again" (child loc root Crafty_layers.ip (ip_to "1.2.3.4") == ip) ;
  let udp = child loc ip Crafty_layers.udp [ 1, port 53 ] in
  acquire udp ;
  let udp' = child loc ip Crafty_layers.udp [ 1, port 53 ] in
  acquire udp' ;
  assert_bool "a new source port for each" (udp != udp') ;
  assert_bool "in the range" (match List.assoc 0 udp.key with
      | Crafty_value.Int p -> p >= 49152 && p <= 65535 | _ -> false) ;
  let fixed = child loc ip Crafty_layers.udp [ 0, port 1 ; 1, port 53 ] in
  acquire fixed ;
  assert_equal ~printer:identity
      "Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1{UDP(src=1, dst=53)*1}}"
      (release udp ; release udp' ; to_string root) ;
  release ip ;
  assert_equal ~printer:identity
      "Eth{IP(src=10.0.0.1, dst=1.2.3.4){UDP(src=1, dst=53)*1}}" (to_string root) ;
  release fixed ;
  assert_equal ~printer:identity "Eth" (to_string root)
*)
(*$R child
  let root = make_root eth in
  let ip = child loc root Crafty_layers.ip (ip_to "1.2.3.4") in
  let icmp = child loc ip Crafty_layers.icmp [] in
  let echo = Option.get (Crafty_layers.find ~below:icmp.layer "EchoRequest") in
  let first = child loc icmp echo [] in
  assert_bool "a shared id" (child loc icmp echo [] == first) ;
  assert_bool "a given id" (child loc icmp echo [ 0, port 7 ] != first) ;
  let icmp' = child loc (child loc root Crafty_layers.ip (ip_to "1.2.3.5")) Crafty_layers.icmp [] in
  let given = child loc icmp' echo [ 0, port 7 ] in
  assert_bool "shares a given id" (child loc icmp' echo [] == given) ;
  let l = Crafty_layers.layer "Tiny" ~above:[ "ip" ]
      [ Crafty_layers.field "id" Crafty_ast.Type.Int ~discriminant:true
          ~pick:(Crafty_layers.Random_in (1, 2)) ] in
  ignore (child loc ip l []) ; ignore (child loc ip l []) ;
  assert_raises (Crafty_value.Runtime_error (loc, "No id left for another Tiny"))
      (fun () -> child loc ip l [])
*)
