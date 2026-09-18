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
(** Packet synthesizer

Packet synthesizer are special devices that can generate streams of packets
with a given shape.

The protocol stack and the various field values can be chosen precisely, or
generated at random, or set to "automatic".
*)
open Batteries
open SimTypes
open Bitstring
open Tools

type 'a synth =
    | Const of 'a
    | Generator of int (* in the array of generators *)
    | Automatic

(* In JSON, as a field of a packet synth is: *)
let synth_to_json to_json = function
    | Const v -> Generator.const (to_json v)
    | Generator g -> `Assoc [ "gen", `Int g ]
    | Automatic -> `Null

let synth_of_json of_json = function
    | `Assoc [ "const", v ] -> Const (of_json v)
    | `Assoc [ "gen", `Int g ] when g >= 0 -> Generator g
    | `Null -> Automatic
    | js ->
        Widget.bad_value "expected a constant, a generator or null, not %s"
            (Yojson.Basic.to_string js)

(*$Q synth_of_json
  Q.(option (option nat_small)) (fun s -> \
    let s = match s with \
      | None -> Automatic \
      | Some None -> Generator 3 \
      | Some (Some v) -> Const v in \
    synth_of_json Widget.to_int (synth_to_json (fun v -> `Int v) s) = s)
 *)

(*$T synth_of_json
  try ignore (synth_of_json Widget.to_int (`Assoc [ "gen", `Int ~-1 ])) ; false \
  with Widget.Bad_value _ -> true
 *)

(* The value of a synth given the values the generators are at, [of_int]
 * turning one of those into a value. *)
let synth_value ~of_int ~auto gen_values = function
    | Const v -> v
    | Generator g ->
        if g >= Array.length gen_values then
            Widget.bad_value "generator #%d does not exist" g ;
        of_int gen_values.(g)
    | Automatic -> auto ()

type stream = {
    stop_after : int option ;
    (* Distance between two packets: *)
    distance : int synth ;
    distance_from_end : bool ;
}

module Stream =
struct
    (*$< Stream *)

    type t = stream

    (* A distance is a synth of its own: a number of bits, a generator by name,
     * or nothing at all for back to back (see [bits_to_next]). *)
    let distance_kind =
        Widget.optional (Widget.variant [| "const", IRange (0, max_int) ;
                                           "gen", String |])

    let kind =
        Widget.record [|
            "stop after", Widget.optional (IRange (0, max_int)) ;
            "distance", distance_kind ;
            "distance from end", Bool |]

    let to_json t : Yojson.Basic.t =
        `Assoc [
            "stop after",
                (match t.stop_after with Some n -> `Int n | None -> `Null) ;
            "distance", synth_to_json (fun d -> `Int d) t.distance ;
            "distance from end", `Bool t.distance_from_end ]

    let of_json js =
        let count = Widget.to_int_range ~min:0 in
        { stop_after =
            Widget.to_field "stop after" (Widget.to_option count) js ;
          distance = Widget.to_field "distance" (synth_of_json count) js ;
          distance_from_end =
            Widget.to_field "distance from end" Widget.to_bool js }

    (*$Q of_json
      Q.(triple (option nat_small) (option nat_small) bool) \
        (fun (stop_after, d, distance_from_end) -> \
          let distance = match d with None -> Automatic | Some d -> Const d in \
          let t = { stop_after ; distance ; distance_from_end } in \
          of_json (to_json t) = t)
     *)

    (* Whether the stream is over once [count] packets are emitted: *)
    let is_over t count =
        match t.stop_after with
        | Some n -> count >= n
        | None -> false

    (*$T is_over
      not (is_over { stop_after = None ; distance = Automatic ; distance_from_end = true } max_int)
      not (is_over { stop_after = Some 2 ; distance = Automatic ; distance_from_end = true } 1)
      is_over { stop_after = Some 2 ; distance = Automatic ; distance_from_end = true } 2
     *)

    (** How many bits from the first bit of a packet of [bits] bits to the
     * first bit of the next one, on a link leaving [ifg] bits between frames.
     * The distance is never negative, and is 0 when automatic: packets are
     * back to back. *)
    let bits_to_next t gen_values ~ifg bits =
        let from_end d = bits + ifg + d in
        match t.distance with
        | Automatic -> from_end 0
        | d ->
            let d = synth_value ~of_int:identity ~auto:(fun () -> 0) gen_values d
                    |> max 0 in
            if t.distance_from_end then from_end d else d

    (*$= bits_to_next & ~printer:string_of_int
      (1000 + 96 + 10) \
        (bits_to_next { stop_after = None ; distance = Const 10 ; distance_from_end = true } [||] ~ifg:96 1000)
      10 \
        (bits_to_next { stop_after = None ; distance = Const 10 ; distance_from_end = false } [||] ~ifg:96 1000)
      (1000 + 96) \
        (bits_to_next { stop_after = None ; distance = Automatic ; distance_from_end = false } [||] ~ifg:96 1000)
      (1000 + 96 + 42) \
        (bits_to_next { stop_after = None ; distance = Generator 1 ; distance_from_end = true } [| 0 ; 42 |] ~ifg:96 1000)
      0 \
        (bits_to_next { stop_after = None ; distance = Generator 0 ; distance_from_end = false } [| -5 |] ~ifg:96 1000)
     *)

    (*$>*)
end

(** {2 Packet synthesis} *)

module Packet =
struct
    (*$< Packet *)

    module Pdu = Packet.Pdu

    (* The protocol of a layer, by its name as [Packet.Pdu.field_names] writes
     * it: "Vlan 2" is a Vlan. *)
    let layer_name_of_field_name name =
        try String.sub name 0 (String.index name ' ')
        with Not_found -> name

    (*$= layer_name_of_field_name & ~printer:identity
      "Vlan" (layer_name_of_field_name "Vlan 2")
      "Eth" (layer_name_of_field_name "Eth")
     *)

    let pack_layer = function
        | Pdu.Raw bits -> bits
        | Pdu.Dhcp t -> Dhcp.Pdu.pack t
        | Pdu.Eth t -> Eth.Pdu.pack t
        | Pdu.Arp t -> Arp.Pdu.pack t
        | Pdu.Ip t -> Ip.Pdu.pack t
        | Pdu.Ip6 t -> Ip6.Pdu.pack t
        | Pdu.Udp t -> Udp.Pdu.pack t
        | Pdu.Tcp t -> Tcp.Pdu.pack t
        | Pdu.Dns t -> Dns.Pdu.pack t
        | Pdu.Sll t -> Sll.Pdu.pack t
        | Pdu.Vlan t -> Vlan.Pdu.pack t
        | Pdu.Icmp t -> Icmp.Pdu.pack t
        | Pdu.Pcap t -> Pcap.Pdu.pack t

    (* The layer named [layer_name], synthesized from [js] above [upper] (the name
     * and the packed bits of the layer above) and after [prev], this layer
     * in the previous packet. *)
    let layer_of_synth js ?upper prev gen_values layer_name : Pdu.layer =
        match layer_name with
        | "Data" ->
            let kind = Bytes in
            Pdu.Raw (Widget.to_bitstring (
                match Generator.value_of_synth gen_values kind js with
                | Some v -> v
                | None -> Generator.coerce kind (Generator.random_int ())))
        | "Dhcp" ->
            Pdu.Dhcp (Dhcp.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Dhcp p) -> Some p | _ -> None))
        | "Eth" ->
            Pdu.Eth (Eth.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Eth p) -> Some p | _ -> None))
        | "Arp" ->
            Pdu.Arp (Arp.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Arp p) -> Some p | _ -> None))
        | "Ip" ->
            Pdu.Ip (Ip.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Ip p) -> Some p | _ -> None))
        | "Ip6" ->
            Pdu.Ip6 (Ip6.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Ip6 p) -> Some p | _ -> None))
        | "Udp" ->
            Pdu.Udp (Udp.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Udp p) -> Some p | _ -> None))
        | "Tcp" ->
            Pdu.Tcp (Tcp.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Tcp p) -> Some p | _ -> None))
        | "Dns" ->
            Pdu.Dns (Dns.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Dns p) -> Some p | _ -> None))
        | "Sll" ->
            Pdu.Sll (Sll.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Sll p) -> Some p | _ -> None))
        | "Vlan" ->
            Pdu.Vlan (Vlan.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Vlan p) -> Some p | _ -> None))
        | "Icmp" ->
            Pdu.Icmp (Icmp.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Icmp p) -> Some p | _ -> None))
        | "Pcap" ->
            Pdu.Pcap (Pcap.Pdu.of_synth js ?upper gen_values
                ?prev:(match prev with Some (Pdu.Pcap p) -> Some p | _ -> None))
        | p ->
            Widget.bad_value "no protocol is named %S" p

    (** From an array of proto names and synthesized layers as JSON, top to
     * bottom, describing the packet to generate, create an array of actual
     * layers as Pdu.layer, from which a [Packet.Pdu.t] is easily formed
     * (array to list, in reverse order, see [pdu_of_array_top_to_bottom]).
     * Note that the proto names are proper names as given by
     * [Packet.Pdu.name_of_layer] (or [layer_name_of_field_name]), not
     * field names.
     * [prev] is the previous such packet, if any. It is needed, along with
     * the upper layer, to generate some default values. *)
    let of_synth layers ?prev gen_values =
        let upper = ref None in
        Array.init (Array.length layers) (fun i ->
            let layer_name, js = layers.(i) in
            let prev_layer =
                (* Just in case the packet generator was edited while running,
                 * which should never happen. *)
                Option.bind prev (fun prev -> try Some prev.(i) with _ -> None) in
            let layer =
                try layer_of_synth js ?upper:!upper prev_layer gen_values layer_name
                with Widget.Bad_value msg ->
                    Widget.bad_value "%s: %s" layer_name msg in
            upper := Some (layer_name, pack_layer layer) ;
            layer)

    (* Helper to transform a list of layers as JSON into the array format expected
     * by [of_synth]: *)
    let to_array_top_to_bottom = function
        | `Assoc lst ->
            List.rev_map (fun (field_name, layer) ->
                layer_name_of_field_name field_name, layer
            ) lst |>
            Array.of_list
        | js ->
            Widget.bad_value "expected a stack of layers, not %s"
                (Yojson.Basic.to_string js)

    (* Similarly, transform the output of [of_synth] into a [Packet.Pdu.t]: *)
    let pdu_of_array_top_to_bottom a =
        Array.fold_left (fun lst layer -> layer :: lst) [] a

    (* Real traffic, every value a constant: what is read back is the packet,
       but for the payloads, which below the top layer are the layers above
       packed afresh, and the capture time, which can only be automatic. *)
    (*$R of_synth
      let map_layers f = function
        | `Assoc layers -> `Assoc (List.map (fun (name, js) -> name, f name js) layers)
        | js -> js in
      let map_fields f = function
        | `Assoc fields -> `Assoc (List.filter_map f fields)
        | js -> js in
      let auto_ts =
        map_layers (fun name js ->
          if name <> "Pcap" then js else
          map_fields (fun (n, v) ->
            Some (n, if n = "captured at" then `Null else v)) js) in
      let comparable =
        map_layers (fun _ ->
          map_fields (fun (n, v) ->
            if n = "payload" || n = "captured at" then None else Some (n, v))) in
      List.iter (fun file ->
        Pcap.enum_of_file file /@ Pdu.unpack |>
        Enum.iter (fun p ->
          let js = Pdu.to_json p in
          let synth =
            Generator.wrap (Pdu.kind_of p) Generator.const js |> auto_ts |>
            to_array_top_to_bottom in
          let js' =
            Pdu.to_json (pdu_of_array_top_to_bottom (of_synth synth [||])) in
          assert_equal ~printer:Yojson.Basic.to_string
            (comparable js) (comparable js'))
      ) [ "tests/someweb.pcap" ; "tests/someweb_sll.pcap" ;
          "tests/various_vlans.pcap" ]
     *)

    (* What the layers above say, and what the previous packet does. *)
    (*$R of_synth
      let layer_synth f l = Generator.wrap (Pdu.kind_of_layer l) f (Pdu.json_of_layer l) in
      let autos = layer_synth (fun _ -> `Null) in
      let auto_id = function
        | `Assoc fields ->
            `Assoc (List.map (fun (n, v) -> n, if n = "id" then `Null else v) fields)
        | js -> js in
      let synth =
        [| "Dns", layer_synth Generator.const (Pdu.Dns (Dns.Pdu.random ())) |>
                     auto_id ;
           "Udp", autos (Pdu.Udp (Udp.Pdu.random ())) ;
           "Ip", autos (Pdu.Ip (Ip.Pdu.random ())) ;
           "Eth", autos (Pdu.Eth (Eth.Pdu.random ())) |] in
      let p1 = of_synth synth [||] in
      let p2 = of_synth synth ~prev:p1 [||] in
      let printer = string_of_int in
      match p1, p2 with
      | [| Pdu.Dns dns ; Pdu.Udp udp ; Pdu.Ip ip ; Pdu.Eth eth |],
        [| Pdu.Dns dns2 ;          _ ; Pdu.Ip ip2 ; _ |] ->
          assert_equal ~printer (Arp.HwProto.ip4 :> int) (eth.Eth.Pdu.proto :> int) ;
          assert_equal ~printer (Ip.Proto.udp :> int) (ip.Ip.Pdu.proto :> int) ;
          assert_equal ~printer 53 (udp.Udp.Pdu.dst_port :> int) ;
          assert_equal ~printer (bytelength (Dns.Pdu.pack dns))
            (Payload.length udp.Udp.Pdu.payload) ;
          assert_equal ~printer (8 + Payload.length udp.Udp.Pdu.payload)
            udp.Udp.Pdu.length ;
          assert_equal ~printer
            (20 + bytelength ip.Ip.Pdu.options + Payload.length ip.Ip.Pdu.payload)
            ip.Ip.Pdu.tot_len ;
          assert_equal ~printer ((ip.Ip.Pdu.id + 1) land 0xffff) ip2.Ip.Pdu.id ;
          assert_equal ~printer ((dns.Dns.Pdu.id + 1) land 0xffff) dns2.Dns.Pdu.id
      | _ ->
          assert_failure "not the layers the synth says"
     *)

    (*$>*)
end

(** {2 A synthesizer, as the interface edits it} *)

(* Generators are named in what the API and the interface exchange, and
 * numbered in what [Packet.of_synth] reads: a generator is named, renamed and
 * reordered from the outside, while reading a field must not look a name up
 * for every packet. So names become indexes on the way in and names again on
 * the way out, in the packet and in the stream alike. *)
let index_of_name generators name =
    match Array.findi (fun (g : Generator.t) -> g.name = name) generators with
    | exception Not_found ->
        Widget.bad_value "no generator is named %S" name
    | i -> i

let name_of_index generators i =
    if i < 0 || i >= Array.length generators then
        Widget.bad_value "generator #%d does not exist" i ;
    generators.(i).Generator.name

(* Every generator a synth references, its name or number passed through [f].
 * A synth leaf is an object of the single field "gen" whichever kind it has
 * (see [Generator.value_of_synth]), and no protocol has a field of that name,
 * so this walks a packet without knowing anything of the layers in it. *)
let rec map_gens f (js : Yojson.Basic.t) : Yojson.Basic.t =
    match js with
    | `Assoc [ "gen", v ] -> `Assoc [ "gen", f v ]
    | `Assoc fields -> `Assoc (List.map (fun (n, v) -> n, map_gens f v) fields)
    | `List vs -> `List (List.map (map_gens f) vs)
    | js -> js

let named generators =
    map_gens (fun v -> `String (name_of_index generators (Widget.to_int v)))

let numbered generators =
    map_gens (fun v -> `Int (index_of_name generators (Widget.to_string v)))

(* The whole of a synthesizer, as it is saved and as the interface reads it
 * (the machine's own kinds are the properties of [make]). *)
let kind =
    Widget.record [|
        "generators", Widget.list Generator.named_kind ;
        "stream", Stream.kind ;
        "packet", Synth ;
        "independent", Bool |]

(* No two generators may share a name, a name being what references one. *)
let generators_of_json js =
    let generators = Widget.to_list Generator.of_json js |> Array.of_list in
    Array.iteri (fun i (g : Generator.t) ->
        if Array.exists (fun (g' : Generator.t) -> g'.name = g.name)
                        (Array.sub generators 0 i) then
            Widget.bad_value "two generators are named %S" g.name
    ) generators ;
    generators

(* A packet of TCP over IP over Ethernet with every field automatic: what a
 * synthesizer is born with, and the shape a reader edits rather than types
 * from nothing. *)
let default_packet () : Yojson.Basic.t =
    let layer l =
        Generator.wrap (Packet.Pdu.kind_of_layer l) (fun _ -> `Null)
            (Packet.Pdu.json_of_layer l) in
    `Assoc [ "Eth", layer (Packet.Pdu.Eth (Eth.Pdu.random ())) ;
             "Ip", layer (Packet.Pdu.Ip (Ip.Pdu.random ())) ;
             "Tcp", layer (Packet.Pdu.Tcp (Tcp.Pdu.random ())) ]

(* Check that the stream and packet definitions match the available generators.
 * Called whenever one is updated. *)
let check ~generators ~stream ~packet =
    let gen_values = Array.map (fun g -> Generator.get g 0) generators in
    ignore (Packet.of_synth (Packet.to_array_top_to_bottom packet)
                            gen_values) ;
    ignore (Stream.bits_to_next stream gen_values ~ifg:Eth.Iface.ifg_min 0)

(** {2 The synthesizer device} *)

(* How far a stream has got: which step the generators are read at, and the
 * packet the next one follows. There is one per adapter when the generators
 * are independent, and a single one for the whole machine otherwise -- which
 * is what makes every adapter emit the very same packets, the values of a
 * step being drawn once and not recomputable afterwards. *)
type state =
    { (* Which adapters this stream feeds: one of them, or all of them. *)
      ifaces : int array ; (* indexes in t.ifaces *)
      mutable count : int ;
      mutable prev : Packet.Pdu.layer array option }

(* A real packet synthesizer is a machine with real Ethernet adapters, and this
 * simulates one: what it sends goes out through an adapter, which is what
 * knows the speed of the link and the silence to leave between two frames --
 * both of which a stream needs, its distances being counted in bits.
 *
 * It has as many adapters as it was asked for, all driven by the same
 * generators, so that saturating several ports of a router asks for one
 * machine and not several. *)
type t =
    { widget : Widget.t ;
      (* In port order: port [n] is adapter [n]. *)
      ifaces : Eth.Iface.t array ;
      (* Generators are referenced by index in this array (they carry the name
       * they are known by from the outside): *)
      mutable generators : Generator.t array ;
      mutable stream : stream ;
      (* We need to specify a Packet.Pdu.t with synth types everywhere where
       * we can have a field value. We are not going to write two versions of
       * each Pdu, so instead we take the description of the stack in a more
       * dynamical representation, using yojson. At each step we can turn
       * this json description of a packet into a real one. Maybe the
       * Widget.kind of the Pdu that we have already can be used to make this
       * generation partially automatic. *)
      mutable packet : Yojson.Basic.t ;
      (* If true, the adapters of this synthesizer have their own distinct
       * values from the generators. If false, every adapter will emit exactly
       * the same packets at the same time. *)
      mutable independent : bool ;
      (* Whether it is emitting. A synthesizer is born stopped: what it is born
       * with is a packet nobody has looked at yet. *)
      mutable emitting : bool ;
      mutable states : state array ;
      (* Generation number, used by [emit_next] to stop calling itself back when
       * the synthesizer config has been changed: *)
      mutable gen : int ;
      (* FIXME: If we wanted to count packets we should do this in the Iface. *)
      packets_sent : Metric.Counter.t }

type Widget.device += Synthesizer of t

(* The synthesizer a widget stands for, when it stands for one. *)
let of_widget (w : Widget.t) =
    match w.device with
    | Some (Synthesizer t) -> Some t
    | _ -> None

(* One packet of [state], out of every adapter it feeds, and the next one
 * scheduled -- until the stream is over or the emission is stopped.
 *
 * The values of the step are drawn once and used for the packet and for the
 * distance to the next one, so that a stream whose distance is a generator
 * reads the same value the packet did. *)
let rec emit_next t gen state =
    if gen = t.gen && t.emitting &&
       not (Stream.is_over t.stream state.count) then (
        let gen_values =
            Array.map (fun g -> Generator.get g state.count) t.generators in
        let layers =
            Packet.of_synth (Packet.to_array_top_to_bottom t.packet)
                            ?prev:state.prev gen_values in
        state.prev <- Some layers ;
        state.count <- state.count + 1 ;
        (* The frame itself: the bottom layer, whose payload is everything
         * above it (see [Packet.of_synth]). *)
        let bits = Packet.pack_layer layers.(Array.length layers - 1) in
        let now = Simulation.Widget.now t.widget in
        Metric.Counter.add t.packets_sent ~now (Array.length state.ifaces) ;
        Array.iter (fun i -> t.ifaces.(i).emit bits) state.ifaces ;
        (* Timed on the first adapter it feeds: the others have ports of their
         * own, and what they make of a frame handed to them is their own
         * business (see [Eth.Iface.set_read]). A link that has not negotiated
         * yet is paced at the best speed it offers, that being what it will
         * settle on with something at least as fast at the other end. *)
        let iface = t.ifaces.(state.ifaces.(0)) in
        let speed =
            match iface.negotiated with
            | Some (speed, _) -> speed
            | None -> Eth.Speed.best iface.speeds in
        let bitlen = bitstring_length bits in
        let d =
            Stream.bits_to_next t.stream gen_values
                                ~ifg:iface.inter_frame_gap bitlen in
        (* No faster than back to back, whatever the stream says: a port cannot
         * emit a frame before it has finished the one before it, and a
         * distance of nothing at all would be an unending run of packets at
         * one instant of the clock. *)
        let d = max d (bitlen + iface.inter_frame_gap) in
        Simulation.delay t.widget.power (Eth.Speed.duration speed d)
                         (emit_next t gen) state)

(* Stop/start act on the stream as opposed to merely pausing packet generation.
 * When it's restarted, a stream reset its generators from step 1 (which
 * matters for incrementing values). *)
let start t =
    t.emitting <- true ;
    t.gen <- t.gen + 1 ;
    (* Recreate the states from scratch rather than reseting them because we
     * might have changed the [independent] flag: *)
    t.states <-
        (if t.independent then
            (* One state per iface: *)
            Array.(init (length t.ifaces) (fun i ->
                { ifaces = [| i |] ; count = 0 ; prev = None }))
        else
            (* One state with all ifaces: *)
            [| { ifaces = Array.(init (length t.ifaces) identity) ;
                 count = 0 ; prev = None } |]) ;
    Array.iter (fun state ->
        Simulation.asap t.widget.power (emit_next t t.gen) state
    ) t.states

let stop t =
    t.emitting <- false ;
    t.states <- [||]

(* Called by the UI when updating any of those interdependent properties: *)
let set_generators t generators =
    check ~generators ~stream:t.stream ~packet:t.packet ;
    t.generators <- generators

let set_stream t stream =
    check ~generators:t.generators ~stream ~packet:t.packet ;
    t.stream <- stream

let set_packet t packet =
    check ~generators:t.generators ~stream:t.stream ~packet ;
    t.packet <- packet

let to_json t : Yojson.Basic.t =
    let named = named t.generators in
    `Assoc [
        "generators",
            `List (Array.to_list t.generators |> List.map Generator.to_json) ;
        "stream", named (Stream.to_json t.stream) ;
        "packet", named t.packet ;
        "independent", `Bool t.independent ]

(* A whole synth read into [t], which is what a saved one comes back as: every
 * part at once, and nothing installed unless all of it reads. *)
let set_json t js =
    let generators = Widget.to_field "generators" generators_of_json js in
    let stream =
        Widget.to_field "stream" (Stream.of_json % numbered generators) js in
    let packet = Widget.to_field "packet" (numbered generators) js in
    let independent = Widget.to_field "independent" Widget.to_bool js in
    check ~generators ~stream ~packet ;
    t.generators <- generators ;
    t.stream <- stream ;
    t.packet <- packet ;
    t.independent <- independent

let make ~parent ?location ?speeds ?(adapters=1) ?(independent=false) name =
    if adapters < 1 then invalid_arg "Synth.make" ;
    let widget =
        Widget.make ~parent ?location ~device_type:"synthesizer"
                    ~own_power:true name in
    let ifaces =
        Array.init adapters (fun i ->
            Eth.Iface.make ~parent:widget ~power:widget.power ?speeds
                           ("eth"^ string_of_int i)) in
    let t =
        { widget ; ifaces ; generators = [||] ;
          stream = { stop_after = None ; distance = Automatic ;
                     distance_from_end = true } ;
          packet = default_packet () ; independent ;
          emitting = false ; states = [||] ; gen = 0 ;
          packets_sent = Metric.Counter.make () } in
    widget.device <- Some (Synthesizer t) ;
    (* Its adapters are its ports, as a switch's are. *)
    widget.ports <- Widget.{
        count = (fun () -> Array.length t.ifaces) ;
        is_connected = (fun i -> t.ifaces.(i).widget.ports.is_connected 0) ;
        dev = (fun i -> t.ifaces.(i).widget.ports.dev 0) ;
        owner = (fun i -> t.ifaces.(i).widget.ports.owner 0) ;
        disconnect = (fun i -> t.ifaces.(i).widget.ports.disconnect 0) ;
        get_capabilities = (fun i ->
            t.ifaces.(i).widget.ports.get_capabilities 0) ;
        set_capabilities = (fun i c ->
            t.ifaces.(i).widget.ports.set_capabilities 0 c) } ;
    Widget.add_properties widget Widget.[
        property "emitting" ~kind:Bool
            ~descr:"Whether packets are being emitted."
            ~getter:(fun () -> `Bool t.emitting)
            ~setter:(fun v ->
                let v = to_bool v in
                if v <> t.emitting then (
                    if v then start t else stop t ;
                    Log.(log widget.logger Info (lazy (
                        (if v then "Started" else "Stopped") ^" emitting"))))) ;
        (* Generators come first because they are what the other two are read
           against, and a topology restores properties in this order. *)
        property "generators" ~kind:(list Generator.named_kind)
            ~descr:"The named value generators the packet is filled from."
            ~getter:(fun () ->
                `List (Array.to_list t.generators |>
                       List.map Generator.to_json))
            ~setter:(fun v -> set_generators t (generators_of_json v)) ;
        property "stream" ~kind:Stream.kind
            ~descr:"How many packets to emit, and how far apart."
            ~getter:(fun () ->
                named t.generators (Stream.to_json t.stream))
            ~setter:(fun v ->
                set_stream t (Stream.of_json (numbered t.generators v))) ;
        property "packet" ~kind:Synth
            ~descr:"The packet to emit: a stack of layers, each field a \
                    constant, a generator or automatic."
            ~getter:(fun () -> named t.generators t.packet)
            ~setter:(fun v -> set_packet t (numbered t.generators v)) ;
        property "independent" ~kind:Bool
            ~descr:"Whether every adapter draws its own values, rather than \
                    emitting the very same packets (requires restart)."
            ~getter:(fun () -> `Bool t.independent)
            ~setter:(fun v -> t.independent <- to_bool v) ;
        metric_property "packets" ~descr:"Packets emitted."
            (Metric.Counter.T t.packets_sent) ] ;
    (* A machine switched off emits nothing, and one switched back on goes on
     * emitting if that is what it was doing: its events were dropped with the
     * supply (see [Simulation.at]), so the chain has to be started again. *)
    widget.power_up <- (fun () -> if t.emitting then start t) ;
    Simulation.power_up widget.power ;
    t

(* Born with a packet it can make, one adapter for every port, and stopped. *)
(*$R make
  let sim = Simulation.make ~realtime:false "synth" in
  let t = make ~parent:sim.root ~adapters:3 "gen" in
  assert_equal ~printer:string_of_int 3 (t.widget.ports.count ()) ;
  "a synthesizer is born stopped" @? not t.emitting ;
  "and with a packet of its own" @?
    (check ~generators:t.generators ~stream:t.stream ~packet:t.packet ; true) ;
  "which is what its widget stands for" @?
    (match of_widget t.widget with Some t' -> t' == t | None -> false) ;
  let prop name =
    List.find (fun (p : Widget.property) -> p.name = name)
              t.widget.properties in
  let set name v = (Option.get (prop name).setter) v in
  let get name = (prop name).getter () in
  set "emitting" (`Bool true) ;
  "it starts when told to" @? t.emitting ;
  (* A generator is named from the outside, and referenced by that name. *)
  set "generators"
    (`List [ Generator.to_json (Generator.make "len" (Generator.Constant 3)) ]) ;
  set "stream"
    (`Assoc [ "stop after", `Int 10 ;
              "distance", `Assoc [ "gen", `String "len" ] ;
              "distance from end", `Bool false ]) ;
  assert_equal ~printer:Yojson.Basic.to_string
    (`Assoc [ "gen", `String "len" ])
    (Widget.json_of_field "distance" (get "stream")) ;
  "a generator the stream needs cannot be dropped" @?
    (try set "generators" (`List []) ; false
     with Widget.Bad_value _ -> true) ;
  "and a packet that cannot be read is refused" @?
    (try set "packet" (`Assoc [ "Eth", `Assoc [ "src", `Assoc [ "const", `String "nope" ] ] ]) ;
         false
     with Widget.Bad_value _ -> true)
 *)

(* What a synthesizer says of itself is what it reads back, generators named
   and not numbered, and a name that is none of theirs is refused rather than
   read as a number. *)
(*$R to_json
  let sim = Simulation.make ~realtime:false "synth-json" in
  let t = make ~parent:sim.root "gen" in
  let gen name = Generator.make name (Generator.Constant 42) in
  set_generators t [| gen "a" ; gen "b" |] ;
  set_stream t { t.stream with distance = Generator 1 } ;
  let js = to_json t in
  Widget.check_value kind js ;
  assert_equal ~printer:Yojson.Basic.to_string
    (`Assoc [ "gen", `String "b" ])
    (Widget.json_of_field "distance" (Widget.json_of_field "stream" js)) ;
  set_json t js ;
  assert_equal ~printer:Yojson.Basic.to_string js (to_json t) ;
  assert_raises (Widget.Bad_value "stream: no generator is named \"c\"")
    (fun () -> set_json t (map_gens (fun _ -> `String "c") js))
 *)

(* A stream of three packets, out of every adapter, through real cables: what
 * the other end receives is what the synthesizer sent, and a stream that is
 * over leaves nothing scheduled -- which is what lets this simulation run to
 * its end. *)
(*$R start
  let sim = Simulation.make ~realtime:false "synth-run" in
  let t = make ~parent:sim.root ~adapters:2 "gen" in
  (* Something at the other end of every adapter, to negotiate with and to
     count what arrives. *)
  let got = Array.make 2 [] in
  Array.iteri (fun i (iface : Eth.Iface.t) ->
    let sink =
      Eth.Iface.make ~parent:sim.root ~power:sim.root.power
                     ~recv:(fun bits -> got.(i) <- bits :: got.(i))
                     (Printf.sprintf "sink%d" i) in
    let cable =
      Eth.Cable.State.make ~parent:sim.root ~name:(Printf.sprintf "c%d" i) () in
    Eth.Cable.plug cable (iface.widget, 0) (sink.widget, 0)
  ) t.ifaces ;
  let emit n =
    set_stream t { stop_after = Some n ; distance = Const 1000 ;
                   distance_from_end = true } ;
    Array.fill got 0 2 [] ;
    start t ;
    Simulation.run sim false in
  emit 3 ;
  let printer = string_of_int in
  assert_equal ~printer 3 (List.length got.(0)) ;
  assert_equal ~printer 3 (List.length got.(1)) ;
  "the same packets out of every adapter" @?
    (List.map hexstring_of_bitstring got.(0) =
     List.map hexstring_of_bitstring got.(1)) ;
  "and the stream stops after those" @? not (Stream.is_over t.stream 2) ;
  (* Every adapter drawing its own values emits packets of its own. *)
  t.independent <- true ;
  emit 3 ;
  assert_equal ~printer 3 (List.length got.(0)) ;
  assert_equal ~printer 3 (List.length got.(1)) ;
  "distinct packets, one adapter to the next" @?
    (List.map hexstring_of_bitstring got.(0) <>
     List.map hexstring_of_bitstring got.(1))
 *)

(* A generator is read at the step the stream is at, which is what tells one
 * packet from the next: the source addresses of these walk up. *)
(*$R start
  let sim = Simulation.make ~realtime:false "synth-gen" in
  let t = make ~parent:sim.root "gen" in
  let got = ref [] in
  let sink =
    Eth.Iface.make ~parent:sim.root ~power:sim.root.power
                   ~recv:(fun bits -> got := bits :: !got) "sink" in
  let cable = Eth.Cable.State.make ~parent:sim.root ~name:"c" () in
  Eth.Cable.plug cable (t.ifaces.(0).widget, 0) (sink.widget, 0) ;
  (* The IP source address of every packet, from the generator. *)
  let from_gen = function
    | `Assoc layers ->
        `Assoc (List.map (fun (lname, layer) ->
          lname,
          match lname, layer with
          | "Ip", `Assoc fields ->
              `Assoc (List.map (fun (fname, v) ->
                fname,
                if fname = "source" then `Assoc [ "gen", `Int 0 ] else v) fields)
          | _ -> layer) layers)
    | js -> js in
  set_generators t
    [| Generator.make "src" (Generator.Increment { start = 1 ; step = 1 }) |] ;
  set_packet t (from_gen t.packet) ;
  set_stream t { stop_after = Some 3 ; distance = Automatic ;
                 distance_from_end = true } ;
  start t ;
  Simulation.run sim false ;
  let sources =
    List.rev !got |>
    List.map (fun bits ->
      let pcap = Pcap.Pdu.make "" (Clock.Wall.now ()) bits in
      match Packet.Pdu.unpack pcap with
      | _pcap :: _eth :: Packet.Pdu.Ip ip :: _ ->
          Ip.Addr.to_dotted_string ip.Ip.Pdu.src
      | _ -> "?") in
  assert_equal ~printer:(String.concat ",")
    [ "0.0.0.1" ; "0.0.0.2" ; "0.0.0.3" ] sources
 *)
