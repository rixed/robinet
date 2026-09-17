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
  Q.(option (option small_nat)) (fun s -> \
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
      Q.(triple (option small_nat) (option small_nat) bool) \
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

type t = {
    seed : int ;
    (* Generators will be referenced by index in this array: *)
    generators : Generator.t array ;
    stream : stream ;
    (* We need to specify a Packet.Pdu.t with synth types everywhere where
     * we can have a field value. We are not going to write two versions of
     * each Pdu, so instead we take the description of the stack in a more
     * dynamical representation, using yojson. At each step we can turn
     * this json description of a packet into a real one. Maybe the
     * Widget.kind of the Pdu that we have already can be used to make this
     * generation partially automatic. *)
    packet : Yojson.Basic.t ;
}

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
