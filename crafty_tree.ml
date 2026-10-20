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
   held by the stack that sends it: they go away with their parent, or once
   sent for those of the root, which stays. The root is the Ethernet
   interface.

   Patterns are registered on nodes: a relative one on the node of the
   current stack it is on top of, an absolute one on the root. A received
   packet goes up the nodes of its stream, each updating its state then
   telling what goes on (a reassembled packet...); along the way, it carries
   the patterns whose layers matched so far, each layer seen in its mode. A
   layer of a pattern that matched where there is no node yet makes one (so
   that, say, the fragments of a packet are reassembled), which the pattern
   holds as long as it is registered. Once the packet is through, the
   patterns it completed are told, by order of registration: none of them
   runs while the tree is being walked. *)
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

(** A received packet as decoded: its layers, the top first. *)
type packet = (L.layer * L.unpacked) list

type node =
    { layer : L.layer ;
      (* Without the keys that are told (see {!tell}) until they are: *)
      mutable key : Key.t ;
      parent : node option ;
      (* By layer name, then by key, as a received packet is looked up at
       * every layer, among possibly many streams. A layer with no node
       * left has no entry: *)
      children : (L.N.t, node Siblings.t) Hashtbl.t ;
      (* How many stacks and patterns hold it: *)
      mutable users : int ;
      (* How many received packets went through it: *)
      mutable received : int ;
      (* Unused, it is finishing what it has to before going away: *)
      mutable closing : bool ;
      eth : Eth.State.t ;
      (* The ranges of local ports to pick from, by layer name: *)
      ports : string -> (int * int) list ;
      ops : L.ops ;
      (* Registered on it, by order of registration: *)
      mutable patterns : pattern list }

(* Of patterns, whose layers are matched from that of the node they are
 * registered on: *)
and pattern =
    { seq : int ;
      layers : pattern_layer list ;
      (* Holds a node made for it, for as long as it is registered: *)
      hold : node -> unit ;
      (* Told a packet that completed it: *)
      matched : packet -> unit ;
      (* Told an error of one of its conditions: *)
      failed : A.location -> string -> unit }

(* Matches a layer of a packet seen in that mode, if its condition, given
 * the packet up to that layer, holds (raising [Runtime_error] if it
 * fails): *)
and pattern_layer =
    { player : L.layer ;
      pmode : L.mode ;
      test : (packet -> bool) option }

(** A layer of a stack: a node used in a mode, with the options given. *)
type entry = { node : node ; mode : L.mode ; options : (int * value) list }


(* The children of [n] for layer [l]: *)
let siblings n (l : L.layer) = Hashtbl.find_option n.children l.name

(* A value of field [i] of [l] within one of the [ranges] (inclusive and
 * disjoint) that no sibling has: *)
let pick_random loc parent (l : L.layer) i ranges =
    let within v = List.exists (fun (lo, hi) -> v >= lo && v <= hi) ranges in
    let taken =
        Option.map_default (fun s ->
            Siblings.fold (fun k _ taken ->
                match List.assoc_opt i k with
                | Some (Int v) when within v -> Set.Int.add v taken
                | _ -> taken) s Set.Int.empty) Set.Int.empty (siblings parent l) in
    let n = List.fold_left (fun n (lo, hi) -> n + hi - lo + 1) 0 ranges in
    if Set.Int.cardinal taken >= n then
        error loc "No %s left for another %s" l.fields.(i).name (L.N.to_string l.name) ;
    (* The [j]th value of all the ranges: *)
    let rec nth j = function
        | [] -> assert false
        | (lo, hi) :: rest ->
            if j <= hi - lo then lo + j else nth (j - (hi - lo + 1)) rest in
    (* The first free one from a random start: *)
    let rec loop j =
        let v = nth j ranges in
        if Set.Int.mem v taken then loop ((j + 1) mod n) else v in
    Int (loop (Random.int n))

(* The fields of key [key] of layer [l], by name: *)
let key_fields (l : L.layer) key name =
    Option.bind (L.find_field l name) (fun i -> List.assoc_opt i key)

(* A new child of [parent], with no user. Its operations read the keys as
 * they are, which a told one completes: *)
let make_child parent (l : L.layer) key =
    let self = ref None in
    let current () = match !self with Some c -> c.key | None -> key in
    let c = { layer = l ; key ; parent = Some parent ;
              children = Hashtbl.create 3 ; users = 0 ; received = 0 ;
              closing = false ; eth = parent.eth ; ports = parent.ports ;
              ops = l.node { eth = parent.eth ;
                             key = (fun name -> key_fields l (current ()) name) ;
                             below_key = (fun name -> key_fields parent.layer parent.key name) ;
                             below = Some parent.ops } ;
              patterns = [] } in
    self := Some c ;
    let s =
        match siblings parent l with
        | Some s -> s
        | None ->
            let s = Siblings.create 3 in
            Hashtbl.add parent.children l.name s ;
            s in
    Siblings.add s key c ;
    c

(** The child of [parent] for [l] given these [options]: an existing one if
 * they give all of its key, or else a new one, with what is missing picked
 * as {!L.pick} says; but for what is told, which it is left without. *)
let child loc parent (l : L.layer) (options : (int * value) list) =
    let random = ref false in
    let key =
        List.filter_map (fun i ->
            match List.assoc_opt i options with
            | Some v -> Some (i, v)
            | None ->
                Option.map (fun v -> i, v) @@
                (match l.fields.(i).pick with
                | Some L.Told -> None
                | Some L.Local_address ->
                    (match Eth.State.find_ip4 parent.eth with
                    | ip -> Some (Ip ip)
                    | exception Not_found ->
                        error loc "No IPv4 address to send %s from" (L.N.to_string l.name))
                | Some (L.Random_in (lo, hi)) ->
                    random := true ;
                    Some (pick_random loc parent l i [ lo, hi ])
                | Some L.Local_port ->
                    random := true ;
                    Some (pick_random loc parent l i (parent.ports (L.N.to_string l.name)))
                | Some L.Required | None ->
                    error loc "%s needs a %s" (L.N.to_string l.name) l.fields.(i).name)
        ) (L.key_fields l) in
    let existing =
        if !random then None
        else Option.bind (siblings parent l) (fun s -> Siblings.find_option s key) in
    match existing with
    | Some c -> c
    | None -> make_child parent l key

let acquire n = n.users <- n.users + 1

let children n =
    Hashtbl.fold (fun _ s cs -> Siblings.fold (fun _ c cs -> c :: cs) s cs)
                 n.children []

(* Removes [n] if nothing uses it any more, once it has closed, its terminal
 * children with it, and so on down to the root; unless it is used again
 * meanwhile: *)
let rec prune n =
    let unused () =
        n.users = 0 &&
        List.for_all (fun c -> c.layer.terminal && c.users = 0) (children n) in
    if unused () && not n.closing then
        Option.may (fun p ->
            n.closing <- true ;
            n.ops.close (fun () ->
                n.closing <- false ;
                if unused () then (
                    Option.may (fun s ->
                        Siblings.remove s n.key ;
                        if Siblings.length s = 0 then Hashtbl.remove p.children n.layer.name
                    ) (siblings p n.layer) ;
                    prune p))) n.parent

let release n =
    assert (n.users > 0) ;
    n.users <- n.users - 1 ;
    prune n

(** {2 Sending} *)

let key_string n =
    List.map (fun (i, v) ->
        let f = n.layer.fields.(i) in
        f.name ^"="^ to_string f.typ v) n.key |>
    String.concat ", "

(* Completes the key of [n] with what the layer on top tells of the keys its
 * stack left out, so that a stream is that of its first message. Raises
 * [Failed]. *)
let tell n hints =
    let keys = L.key_fields n.layer in
    if List.length n.key < List.length keys then
        let key =
            List.map (fun i ->
                match List.assoc_opt i n.key with
                | Some v -> i, v
                | None ->
                    let name = n.layer.fields.(i).name in
                    (match List.assoc_opt name hints with
                    | Some v -> i, v
                    | None -> fail "%s needs a %s" (L.to_string n.layer) name)
            ) keys in
        Option.may (fun p ->
            Option.may (fun s ->
                if Siblings.mem s key then
                    fail "There is already a %s with %s" (L.to_string n.layer)
                        (key_string { n with key }) ;
                Siblings.remove s n.key ;
                Siblings.add s key n) (siblings p n.layer)) n.parent ;
        n.key <- key

(* The fields of the node of [e] by name: its key, then the options: *)
let fields_of e name =
    match L.find_field e.node.layer name with
    | None -> invalid_arg ("Crafty_tree: no field "^ name ^" in "^ L.N.to_string e.node.layer.name)
    | Some i ->
        (match List.assoc_opt i e.node.key with
        | Some _ as v -> v
        | None -> List.assoc_opt i e.options)

(* A layer of [e] that no packet tells: what its stack gives, else [hints],
 * else zeros: *)
let assumed e hints =
    let values =
        Array.to_list e.node.layer.fields |>
        List.filter_map (fun (f : L.field) ->
            if f.read_in = [] then None else
            Some (f.name,
                  match fields_of e f.name with
                  | Some v -> v
                  | None -> List.assoc_opt f.name hints |? zero f.typ)) in
    e.node.layer,
    L.{ values ; upper = Nothing ; payload = Bitstring.empty_bitstring ;
        up_hints = [] ; bits = Bitstring.empty_bitstring }

(** Sends a packet down that stack, from its top (a terminal layer): each
 * manual layer packs what is above it, until a self-driven one takes it, or
 * the root, which emits it as it is. Returns the packet: what was packed,
 * decoded, on top of the self-driven layers as their stack gives them (those
 * may send it later, or never, or in several packets). Raises [Failed]. *)
let send stack =
    (* What the first self-driven layer is given, with the hints of the layer
     * above it, and the layers from it down: *)
    let rec loop hints bits = function
        | [] ->
            invalid_arg "Crafty_tree.send: empty stack"
        | e :: rest as driven ->
            tell e.node hints ;
            (match e.mode with
            | L.Driven ->
                e.node.ops.send (fields_of e) hints bits ;
                bits, hints, driven
            | L.Manual ->
                let bits, hints = e.node.ops.pack (fields_of e) hints bits in
                (match rest with
                | [] ->
                    let st = e.node.eth in
                    Simulation.asap st.iface.widget.power st.iface.emit bits ;
                    bits, [], []
                | rest ->
                    loop hints bits rest)) in
    let bits, hints, driven = loop [] Bitstring.empty_bitstring stack in
    (match stack with
    | { node = { parent = Some { parent = None ; _ } ; _ } as n ; _ } :: _ ->
        prune n
    | _ -> ()) ;
    (* The packed layers, the bottom first: *)
    let packed = List.rev (List.take (List.length stack - List.length driven) stack) in
    let rec decode_up acc up_hints bits = function
        | [] -> acc
        | e :: above ->
            (match e.node.layer.unpack up_hints bits with
            | Some u -> decode_up ((e.node.layer, u) :: acc) u.up_hints u.payload above
            | None -> List.rev_map (fun e -> assumed e []) above @ assumed e [] :: acc) in
    decode_up [] [] bits packed @
    List.mapi (fun i e -> assumed e (if i = 0 then hints else [])) driven

(* The entries of that stack that what is sent goes through: down to the
 * first self-driven one that keeps it, or all of them: *)
let rec senders = function
    | [] -> []
    | e :: _ when e.mode = L.Driven && e.node.ops.buffered -> [ e ]
    | e :: rest -> e :: senders rest

(** How long what is sent down that stack now would wait before it is
 * accepted, in the node that makes it wait the longest: *)
let busy_for stack =
    List.fold_left (fun d e -> max d (e.node.ops.busy_for ()))
        Clock.Interval.zero (senders stack)

(** Calls [k] when a node of that stack tells it is no longer busy, which
 * the others may still be; possibly never, and possibly several times: *)
let on_ready stack k =
    List.iter (fun e -> e.node.ops.on_ready k) (senders stack)

(** {2 Patterns} *)

let next_seq = ref 0

(** Registers a pattern on [node], which it holds until the function
 * returned unregisters it; [layers] start with that of [node]. *)
let register node layers ~hold ~matched ~failed =
    incr next_seq ;
    let p = { seq = !next_seq ; layers ; hold ; matched ; failed } in
    acquire node ;
    node.patterns <- node.patterns @ [ p ] ;
    let registered = ref true in
    fun () ->
        if !registered then (
            registered := false ;
            node.patterns <- List.filter ((!=) p) node.patterns ;
            release node)

(** {2 Receiving} *)

(* The key of the node of [l] that a packet with this layer belongs to: *)
let incoming_key (l : L.layer) (u : L.unpacked) =
    List.map (fun i -> i, List.assoc l.fields.(i).peer u.values) (L.key_fields l)

(** Whether a received layer, of that of [n], is of the stream of [n]: of
 * the root, any is. *)
let of_stream n (u : L.unpacked) =
    List.for_all (fun (i, v) ->
        equal v (List.assoc n.layer.fields.(i).peer u.values)) n.key

type event = Match of packet | Condition_error of A.location * string

(* What a packet did to the patterns it met, the last first; at most one
 * thing to each: *)
type walk = { mutable met : (pattern * event) list }

let met w p = List.exists (fun (p', _) -> p' == p) w.met

(* Whether [pl] matches the top of [packet], seen in [modes]: *)
let passes packet modes pl =
    pl.player == fst (List.hd packet) && List.mem pl.pmode modes &&
    match pl.test with None -> true | Some test -> test packet

(* A pattern on its way up, with its layers left to match: *)
type pending = pattern * pattern_layer list

(* What of [pending] goes on past the top of [packet], seen in [modes]; what
 * it completes, or makes fail, is met: *)
let check w packet modes (pending : pending list) =
    List.filter_map (fun (p, pls) ->
        match pls with
        | pl :: rest when not (met w p) ->
            (match passes packet modes pl, rest with
            | true, [] -> w.met <- (p, Match packet) :: w.met ; None
            | true, rest -> Some (p, rest)
            | false, _ -> None
            | exception Runtime_error (where, message) ->
                w.met <- (p, Condition_error (where, message)) :: w.met ; None)
        | _ -> None) pending

(* Of the layers that can be on top of [packet] (the one its header names,
 * if it names one), those with nodes on [node], the node of its top if any,
 * or that a pending pattern goes on with: *)
let wanted node packet pending =
    let l, (u : L.unpacked) = List.hd packet in
    let wants (ul : L.layer) =
        Option.is_some (Option.bind node (fun n -> siblings n ul)) ||
        List.exists (fun (_, pls) ->
            match pls with pl :: _ -> pl.player == ul | [] -> false) pending in
    (match u.upper with
    | L.Nothing -> []
    | L.Only name -> Option.map_default List.singleton [] (L.find ~below:l name)
    | L.Any _ -> L.uppers l) |>
    List.filter wants

(* Decodes each layer wanted on top of [packet], and goes on along the nodes
 * of that stream, or as long as some patterns are pending: *)
let rec up w node packet pending =
    List.iter (up_to w node packet pending) (wanted node packet pending)

and up_to w node packet pending (ul : L.layer) =
    let u = snd (List.hd packet) in
    let streams = Option.bind node (fun n -> siblings n ul) in
    match ul.unpack u.L.up_hints u.payload with
    | None -> ()
    | Some uu ->
        let key = incoming_key ul uu in
        match Option.bind streams (fun s -> Siblings.find_option s key) with
        | Some c -> enter w c packet uu pending
        | None ->
            let above = (ul, uu) :: packet in
            (* The patterns that would make a node for that layer (but
             * for errors, told in [enter]): *)
            let makers =
                if ul.terminal then [] else
                List.filter (fun (p, pls) ->
                    not (met w p) &&
                    match pls with
                    | pl :: _ -> (try passes above L.both pl with Runtime_error _ -> false)
                    | [] -> false) pending in
            match node, makers with
            | Some n, _ :: _ ->
                let c = make_child n ul key in
                List.iter (fun ((p : pattern), _) -> p.hold c) makers ;
                if List.exists (fun (_, pls) ->
                       match pls with pl :: _ -> pl.pmode = L.Driven | [] -> false) makers
                then c.ops.listen () ;
                enter w c packet uu pending
            | _ ->
                let pending = check w above L.both pending in
                if not (List.is_empty pending) then up w None above pending

(* What goes on from that layer of a packet, received by its node, with
 * the patterns registered there: *)
and enter w node packet u pending =
    node.received <- node.received + 1 ;
    let pending = pending @ List.map (fun p -> p, p.layers) node.patterns in
    List.iter (fun (u, modes) ->
        let packet = (node.layer, u) :: packet in
        up w (Some node) packet (check w packet modes pending)
    ) (node.ops.receive u)

(** Takes a frame from the interface, then tells the patterns it met. *)
let receive root frame =
    let w = { met = [] } in
    Option.may (fun u -> enter w root [] u []) (L.root.unpack [] frame) ;
    List.sort (fun (a, _) (b, _) -> Int.compare a.seq b.seq) w.met |>
    List.iter (fun (p, e) ->
        match e with
        | Match packet -> p.matched packet
        | Condition_error (where, message) -> p.failed where message)

(** [packet] with the layers on top of it, as decoded without any node: of
 * those that could be, the one named, else [Bytes]. *)
let rec complete (packet : packet) =
    let l, (u : L.unpacked) = List.hd packet in
    let names =
        match u.upper with
        | L.Nothing -> []
        | L.Only name -> [ name ]
        | L.Any name -> [ name ; L.N.Bytes ] in
    let rec first = function
        | [] -> packet
        | name :: names ->
            (match Option.bind (L.find ~below:l name) (fun ul ->
                       Option.map (fun uu -> ul, uu) (ul.unpack u.up_hints u.payload)) with
            | Some top -> complete (top :: packet)
            | None -> first names) in
    first names

(** The layers of a frame, as decoded without any node. *)
let decode frame : packet =
    match L.root.unpack [] frame with
    | None -> []
    | Some u -> complete [ L.root, u ]

(** The local ports picked by default, those that IANA leaves to dynamic
 * use: *)
let dynamic_ports = [ 49152, 65535 ]

(** The tree of an interface, which then receives through it. Local ports
 * that a stack leaves out are picked from [ports] for each layer that has
 * some (inclusive and disjoint ranges, by layer name), and else from
 * {!dynamic_ports}. *)
let make_root ?(ports=[]) (eth : Eth.State.t) =
    let ports name =
        match List.assoc_opt (String.uppercase_ascii name) ports with
        | Some (_ :: _ as ranges) -> ranges
        | _ -> dynamic_ports in
    let root =
        { layer = L.root ; key = [] ; parent = None ;
          children = Hashtbl.create 10 ; users = 0 ; received = 0 ;
          closing = false ; eth ; ports ;
          ops = L.root.node { eth ; key = (fun _ -> None) ;
                              below_key = (fun _ -> None) ; below = None } ;
          patterns = [] } in
    eth.iface.recv <- receive root ;
    root

(** {2 Printing} *)

(** As [Layer(field=value, ...)/...], the bottom first. *)
let print_packet oc (p : packet) =
    List.print ~first:"" ~last:"" ~sep:"/" (fun oc ((l : L.layer), (u : L.unpacked)) ->
        String.print oc (L.to_string l) ;
        List.print ~first:"(" ~last:")" ~sep:", " (fun oc (n, v) ->
            let typ =
                match L.find_field l n with
                | Some i -> l.fields.(i).typ
                | None -> A.Type.Void in
            Printf.fprintf oc "%s=%s" n (to_string typ v)) oc u.values
    ) oc (List.rev p)

let rec size n = List.fold_left (fun s c -> s + size c) 1 (children n)

(** As [Layer(key)*users#received{children}], children by layer then key. *)
let rec print oc n =
    String.print oc (L.to_string n.layer) ;
    if n.key <> [] then Printf.fprintf oc "(%s)" (key_string n) ;
    if n.users > 0 then Printf.fprintf oc "*%d" n.users ;
    if n.received > 0 then Printf.fprintf oc "#%d" n.received ;
    match children n with
    | [] -> ()
    | cs ->
        List.map (fun c -> (L.to_string c.layer, key_string c), c) cs |>
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
  let echo = child loc icmp Crafty_layers.echo [] in
  assert_bool "a new id for each" (child loc icmp Crafty_layers.echo [] != echo) ;
  let given = child loc icmp Crafty_layers.echo [ 0, port 7 ] in
  assert_bool "a given id" (child loc icmp Crafty_layers.echo [ 0, port 7 ] == given) ;
  let request = Option.get (Crafty_layers.find ~below:Crafty_layers.echo Crafty_ast.Layer_name.Request) in
  assert_bool "one message node" (child loc echo request [] == child loc echo request []) ;
  let l = Crafty_layers.layer Crafty_ast.Layer_name.Echo ~above:[ Crafty_layers.ip ]
      [ Crafty_layers.field "id" Crafty_ast.Type.Int ~discriminant:true
          ~pick:(Crafty_layers.Random_in (1, 2)) ] in
  ignore (child loc ip l []) ; ignore (child loc ip l []) ;
  assert_raises (Crafty_value.Runtime_error (loc, "No id left for another Echo"))
      (fun () -> child loc ip l [])
*)
(* Local ports are picked from the ranges of the tree, across them all: *)
(*$R child
  let root = make_root ~ports:[ "UDP", [ 10, 11 ; 20, 20 ] ] eth in
  let ip = child loc root Crafty_layers.ip (ip_to "1.2.3.4") in
  let src n = match List.assoc_opt 0 n.key with Some (Crafty_value.Int p) -> p | _ -> -1 in
  let udp () = src (child loc ip Crafty_layers.udp [ 1, port 53 ]) in
  let picked = List.sort Int.compare [ udp () ; udp () ; udp () ] in
  assert_equal ~printer:dump [ 10 ; 11 ; 20 ] picked ;
  assert_raises (Crafty_value.Runtime_error (loc, "No src left for another UDP"))
      (fun () -> udp ()) ;
  let tcp = child loc ip Crafty_layers.tcp [ 1, port 80 ] in
  assert_bool "other layers keep the dynamic ports" (src tcp >= 49152)
*)
(* A terminal node of the root goes once sent, the root staying; what was
 * sent is told back: *)
(*$R send
  let root = make_root eth in
  let bytes = child loc root Crafty_layers.bytes [] in
  assert_equal ~printer:identity "Eth{Bytes}" (to_string root) ;
  let sent =
      send [ { node = bytes ; mode = Crafty_layers.Manual ;
               options = [ 0, Crafty_value.bytes_of_string "hi" ] } ;
             { node = root ; mode = Crafty_layers.Manual ;
               options = [ 1, Crafty_value.Mac Eth.Addr.broadcast ;
                           2, Crafty_value.Int 0x88b5 ] } ] in
  assert_equal ~printer:identity "Eth" (to_string root) ;
  assert_equal ~printer:identity
      "Eth(src=02:00:00:00:00:01, dst=FF:FF:FF:FF:FF:FF, proto=34997)/Bytes(data=#6869)"
      (IO.to_string print_packet sent)
*)
(*$= decode & ~printer:identity
  "Eth(src=02:00:00:00:00:02, dst=02:00:00:00:00:01, proto=2048)/IP(src=10.0.0.2, dst=10.0.0.1, proto=17, tos=0, ttl=64, dont_frag=false, id=1, more_frags=false, frag_offset=0, tot_len=30, options=[], is_fragment=false)/UDP(src=53, dst=1000, length=10, checksum=32593)/Bytes(data=#6869)" \
    (IO.to_string print_packet (decode (Eth.Pdu.(pack (make Eth.Proto.ip4 \
        (Eth.Addr.of_string "02:00:00:00:00:02") (Eth.Addr.of_string "02:00:00:00:00:01") \
        (Ip.Pdu.pack (Ip.Pdu.make ~id:1 Ip.Proto.udp (Ip.Addr.of_string "10.0.0.2") (Ip.Addr.of_string "10.0.0.1") \
            (Udp.Pdu.(pack (make ~src_port:(Udp.Port.o 53) ~dst_port:(Udp.Port.o 1000) \
                (Bitstring.bitstring_of_string "hi")))))))))))
  "Eth(src=02:00:00:00:00:02, dst=02:00:00:00:00:01, proto=2048)/IP(src=10.0.0.2, dst=10.0.0.1, proto=1, tos=0, ttl=64, dont_frag=false, id=1, more_frags=false, frag_offset=0, tot_len=29, options=[], is_fragment=false)/ICMP(type=3, code=3)/DestUnreachable(mtu=0, code=3)/Bytes(data=#41)" \
    (IO.to_string print_packet (decode (Eth.Pdu.(pack (make Eth.Proto.ip4 \
        (Eth.Addr.of_string "02:00:00:00:00:02") (Eth.Addr.of_string "02:00:00:00:00:01") \
        (Ip.Pdu.pack (Ip.Pdu.make ~id:1 Ip.Proto.icmp (Ip.Addr.of_string "10.0.0.2") (Ip.Addr.of_string "10.0.0.1") \
            (Icmp.Pdu.(pack { msg_type = Icmp.MsgType.o (3, 3) ; \
                              payload = DestUnreachable (0, Payload.o (Bitstring.bitstring_of_string "A")) })))))))))
*)
