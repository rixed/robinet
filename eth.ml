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
 * Ethernet protocol implementation.
 *
 * TODO: (r)STP, optional padding
 *)
open Batteries
open SimTypes
open Bitstring
open Tools
open Clock

(** {2 Private Types} *)

(** {3 Ethernet addresses} *)

(** Ethernet addresses are implemented as [bitstring] internally but
 * the abstract type Eth.Addr.t has a batter printer (which support
 * such thing as vendor decoding).
 *
 * Anyway, one is able to cast from/to a [bitstring] with
 * [(addr :> bitstring)] for instance. *)
module Addr = struct
    (*$< Addr *)
    (** If true, use the vendor database to decode address names:
     * {[# Eth.Addr.of_string "a4:ba:db:e6:15:fa";;]}
     * {[- : Eth.Addr.t = Dell:e6:15:fa]}
     * {[# Eth.Addr.print_with_vendor := false;;]}
     * {[- : unit = ()]}
     * {[# Eth.Addr.of_string "a4:ba:db:e6:15:fa";;]}
     * {[- : Eth.Addr.t = a4:ba:db:e6:15:fa]}
     *
     * This only affect the printing of Ethernet addresses in the toplevel and
     * [Eth.Addr.to_string]. *)
    let print_with_vendor = ref true

    let string_of_sfx l sfx =
        let rec aux prev l rem =
            if l <= 0 then prev else
            aux ((Printf.sprintf ":%02Lx" (Int64.logand rem 0xffL))^prev)
                (l-8)
                (Int64.shift_right_logical rem 8) in
        aux "" l sfx
    (*$= string_of_sfx & ~printer:identity
      (string_of_sfx  8 0xabL) ":ab"
      (string_of_sfx 12 0x123L) ":01:23"
      (string_of_sfx  0 0x123L) ""
      (string_of_sfx 48 0x123456789abcL) ":12:34:56:78:9a:bc"
    *)

    (** Low level wrapper around the C vendor database. *)
    external vendor_lookup : int64 -> (string * int) option = "wrap_eth_vendor_lookup"

    include Private.Make (struct
        type t = bitstring

        (** Converts an address to it's string representation. *)
        let to_string mac =
            let simple_name mac64 =
                String.lchop (string_of_sfx 48 mac64) in
            match%bitstring mac with
                | {| mac64 : 48 |} ->
                    if !print_with_vendor then (
                        match vendor_lookup mac64 with
                            | None -> simple_name mac64
                            | Some (name, bits) ->
                                let sfx_bits = 48 - bits in
                                let sfx = Int64.logand mac64 (Int64.pred (Int64.shift_left 1L sfx_bits)) in
                                name ^ (string_of_sfx sfx_bits sfx)
                    ) else (
                        simple_name mac64
                    )
                | {| _ |} -> should_not_happen ()
        (*$= to_string & ~printer:identity
          (to_string (of_string "00:23:8b:5f:09:ce")) "QuantaCo:5f:09:ce"
          (to_string (of_string "80:ee:73:07:76:f1")) "Shuttle:07:76:f1"
          (to_string broadcast) "Broadcast"
          (to_string (of_string "00:50:c2:00:0a:bc")) "TLS:0a:bc"
          (to_string (of_string "ff:ff:07:c0:00:04")) "ff:ff:07:c0:00:04"
        *)
        let is_valid t = bitstring_length t = 48
        let repl_tag = "addr"
    end)

    (** Converts a string to an address. Note that the string must be in
     * hexadecimal notation (["a4:ba:db:e6:15:fa"], not ["Dell:e6:15:fa"]).
     * So [Eth.Addr.of_string (Eth.Addr.to_string "a4:ba:db:e6:15:fa")]
     * will {e not} work if {!Eth.Addr.print_with_vendor} is true! *)
    let of_string str =
        (* Six numbers of one or two hex digits, colon separated, and nothing
         * else: whoever tells a MAC from an IP address does it by asking. *)
        let len = String.length str in
        let bad () = invalid_arg ("Eth.Addr.of_string: "^ str) in
        let digit i =
            if i >= len then -1 else
            match str.[i] with
            | '0'..'9' as c -> Char.code c - Char.code '0'
            | 'a'..'f' as c -> Char.code c - Char.code 'a' + 10
            | 'A'..'F' as c -> Char.code c - Char.code 'A' + 10
            | _ -> -1 in
        let addr = Bytes.create 6 in
        let rec octet n i =
            let hi = digit i in
            if hi < 0 then bad () ;
            let lo = digit (i + 1) in
            let v, i = if lo < 0 then hi, i + 1 else hi * 16 + lo, i + 2 in
            Bytes.set addr n (Char.chr v) ;
            if n = 5 then (if i <> len then bad ())
            else if i < len && str.[i] = ':' then octet (n + 1) (i + 1)
            else bad () in
        octet 0 0 ;
        o (bitstring_of_bytes addr)
    (*$T of_string
      eq (of_string "0:1:a:B:cd:EF") (of_string "00:01:0a:0b:cd:ef")
      List.for_all (fun s -> try ignore (of_string s) ; false \
                             with Invalid_argument _ -> true) \
        [ "" ; "10.1.0.254" ; "2001:db8::1" ; "00:11:22:33:44" ; \
          "00:11:22:33:44:55:66" ; "00:11:22:33:44:55x" ; \
          "000:11:22:33:44:55" ; ":00:11:22:33:44:55" ]
    *)

    (** The plain hexadecimal notation, which is what [of_string] reads back:
     * [to_string] may name the vendor instead ("Dell:e6:15:fa"), which is for
     * reading and not for typing in again. Whatever is offered to be edited
     * must be written this way. *)
    let to_hexstring (t : t) =
        hexstring ~sep:":" (string_of_bitstring (t :> bitstring))
    (*$= to_hexstring & ~printer:identity
      (to_hexstring (of_string "a4:ba:db:e6:15:fa")) "A4:BA:DB:E6:15:FA"
     *)

    (** Constant for Ethernet broadcast address. *)
    let broadcast = of_string "FF:FF:FF:FF:FF:FF"

    (** Constant for Ethernet all zeroes address. *)
    let zero = of_string "00:00:00:00:00:00"

    (** Since Ethernet addresses are bitstrings, which cannot be compared
     * using the built-in [=] operator, here is a dedicated comparison
     * operator for addresses. *)
    let eq (a : t) (b : t) =
        Bitstring.equals (a :> bitstring) (b :> bitstring)

    let is_broadcast = eq broadcast

    (** Returns a random Ethernet address.
     * i_g:
     * « The I/G address bit is used to identify the destination MAC address as
     *   an individual MAC address or a group MAC address. If the I/G address
     *   bit is 0, it indicates that the MAC address field is an individual MAC
     *   address. If this bit is 1, the MAC address is a group MAC address that
     *   identifies one or more (or all) stations connected to the IEEE 802
     *   network. The all-stations broadcast MAC address is a special group MAC
     *   address of all 1’s »
     *
     * « The U/L bit indicates whether the MAC address has been assigned by a
     *   local or universal administrator. Universal addresses have the U/L bit
     *   set to 0. If the U/L bit is set to 1, the remaining bits (i.e., all
     *   bits except the I/G and U/L bits) are locally administered and should
     *   not be expected to meet the uniqueness requirement of the IEEE
     *   RA-assigned values. »  -- IEEE 802 *)
    let true_random ?i_g ?u_l () =
        let maybe_set b pos bits =
            match b with
            | None -> ()
            | Some true -> Bitstring.set bits pos
            | Some false -> Bitstring.clear bits pos in
        let a = randbs 6 in
        maybe_set i_g 7 a ;
        maybe_set u_l 6 a ;
        o a
    (*$= bitstring_of_int16 & ~printer:hexstring_of_bitstring
      (bitstring_of_int16 0x01_00) \
          (let b = bitstring_of_int16 0 in Bitstring.set b 7 ; b)
    *)

    (** Returns a random Ethernet address (but neither broadcast nor zero). *)
    (* In general we just want a locally unique individual address: *)
    let random = true_random ~i_g:false ~u_l:true

    (* Get the Eth address of a device (on Linux). *)
    let of_iface ifname =
        info_of_iface ifname "address" |> of_string

    (*$>*)
end

(** {2 Ethernet frames} *)

module Proto = Arp.HwProto

(** Pack/Unpack an Ethernet frame.  *)
module Pdu = struct
    (*$< Pdu *)
    (** An Ethernet frame is made up from these constituents *)
    type t = { src : Addr.t ; dst : Addr.t ;
               proto : Proto.t ;
               payload : Payload.t }

    (** Build an {!Eth.Pdu.t} for the given [payload]. *)
    let make proto src dst bits =
        { src ; dst ; proto ; payload = Payload.o bits }

    (** Returns a random {!Eth.Pdu.t}. *)
    let random () =
        make (Proto.random ()) (Addr.random ()) (Addr.random ()) (randbs 30)

    (** Pack an {!Eth.Pdu.t} into its [bitstring] raw representation, ready for
     * injection onto the wire (via {!Pcap.inject} for instance). *)
    let pack t =
        (* TODO: pad into minimal (64bytes) size? *)
        let%bitstring hdr = {|
             (t.dst :> bitstring) : 6*8 : bitstring ;
             (t.src :> bitstring) : 6*8 : bitstring ;
             (t.proto :> int) : 16 |} in
        concat [ hdr ; (t.payload :> bitstring) ]

    (** Unpack a [bitstring] into an {!Eth.Pdu.t} *)
    let unpack bits = match%bitstring bits with
        | {| dst : 6*8 : bitstring ;
             src : 6*8 : bitstring ;
             proto : 16 ;
             payload : -1 : bitstring |} (* FIXME: might not be a proto if < 1500 *) ->
            Ok { src = Addr.o src ; dst = Addr.o dst ;
                 proto = Proto.o proto ;
                 payload = Payload.o payload }
        | {| _ |} ->
           Error (lazy "Not Eth")

    let extract_proto do_extract proto pld =
        if proto = Proto.ip4 then
            do_extract pld
        else if proto = Proto.ieee8021q then
            Result.Monad.bind (Vlan.Pdu.unpack pld) (fun vlan ->
                if vlan.Vlan.Pdu.proto = Proto.ip4 then
                    do_extract (vlan.Vlan.Pdu.payload :> bitstring)
                else Error (lazy ("Vlan proto not IPv4")))
        else Error (lazy ("Eth proto neither IPv4 not ieee8021q"))

    (* Actually only extract IP addresses *)
    let extract_src_proto =
        extract_proto (fun pdu ->
            Result.Monad.bind (Ip.Pdu.unpack pdu) (fun ip ->
                Ok ip.Ip.Pdu.src))

    let extract_dst_proto =
        extract_proto (fun pdu ->
            Result.Monad.bind (Ip.Pdu.unpack pdu) (fun ip ->
                Ok ip.Ip.Pdu.dst))

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)

    (** What a frame's header says, which is little enough: where from, where
     * to, and what is inside. No preamble and no trailing checksum -- neither
     * is in [t], both being the wire's business and not the frame's. *)
    module Kinds =
    struct
        let src = Widget.hint "a4:ba:db:e6:15:fa" Mac
        let dst = src
        let proto = Widget.one_of ~range:(0, 0xffff) Proto.choices
        let payload = BRange (0, 0xffff_ffff)
    end

    let kind =
        Widget.record
            [| "source", Kinds.src ;
               "destination", Kinds.dst ;
               "protocol", Kinds.proto ;
               "payload", Kinds.payload |]

    let to_json (t : t) =
        (* The plain hexadecimal and not [Addr.to_string], which may name the
           vendor instead ("Dell:e6:15:fa"): what is shown is what can be typed
           back. *)
        `Assoc [ "source", `String (Addr.to_hexstring t.src) ;
                 "destination", `String (Addr.to_hexstring t.dst) ;
                 "protocol", `Int (t.proto :> int) ;
                 "payload", Widget.json_of_bytes (t.payload :> bitstring) ]

    (* Where each field is in [kind], which [of_synth] reads them by: *)
    module Field =
    struct
        let i = Widget.field_index kind
        let src = i "source"
        let dst = i "destination"
        let proto = i "protocol"
        let payload = i "payload"
    end

    (* [r] are the fields of a synth of [kind] (see [Generator.fields]): *)
    let of_synth r ?upper ?prev gen_values =
        ignore prev ;
        let open Generator in
        let addr i kind =
            of_nth r i gen_values kind (Addr.of_string % Widget.to_string) in
        { src = addr Field.src Kinds.src ;
          dst = addr Field.dst Kinds.dst ;
          proto = int_of_nth r Field.proto gen_values
                      ?auto:(from_upper upper Proto.of_layer)
                      Kinds.proto Proto.o ;
          payload = Payload.o (payload_of_nth ?upper r Field.payload
                                              gen_values Kinds.payload) }

    (*$Q of_synth
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_consts (fun js g -> \
            of_synth (Generator.fields_of_synth kind js) g) kind to_json)
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_autos (fun js g -> \
            of_synth (Generator.fields_of_synth kind js) g) kind to_json)
     *)

    (*$Q kind
      (Q.make (fun _ -> random ())) (fun t -> \
        try Widget.check_value kind (to_json t) ; true \
        with _ -> false)
     *)

    (*$>*)
end

(** {3 Gateway specifications} *)

module Gateway =
struct
    (** The address of a gateway, which can be given either as an Ethernet address
     * of as an IP address. *)
    type t = Mac of Addr.t | IPv4 of Ip.Addr.t

    (** Converts a {!Eth.Addr} to a string. *)
    let to_string = function
        | Mac mac -> Addr.to_string mac
        | IPv4 ip -> Ip.Addr.to_string ip

    (** Converts the other way around. *)
    let of_string str =
        try Mac (Addr.of_string str)
        with _ -> IPv4 (Ip.Addr.of_string str)

    (** And print. *)
    let print oc a =
        String.print oc (to_string a)
end

(** {2 Standard transceiver speeds} *)

module Speed =
struct
    (* Possible adapter speeds: *)
    include Capabilities.EthSpeed

    let to_bps = function
        | Capabilities.EthSpeed.Eth10Mbps -> 10e6
        | Eth100Mbps -> 100e6
        | Eth1Gbps -> 1000e6
        | Eth2_5Gbps -> 2.5e9
        | Eth5Gbps -> 5e9
        | Eth10Gbps -> 10e9
        | Eth25Gbps -> 25e9
        | Eth40Gbps -> 40e9
        | Eth100Gbps -> 100e9

    let to_string = function
        | Capabilities.EthSpeed.Eth10Mbps -> "10Mbps"
        | Eth100Mbps -> "100Mbps"
        | Eth1Gbps -> "1Gbps"
        | Eth2_5Gbps -> "2.5Gbps"
        | Eth5Gbps -> "5Gbps"
        | Eth10Gbps -> "10Gbps"
        | Eth25Gbps -> "25Gbps"
        | Eth40Gbps -> "40Gbps"
        | Eth100Gbps -> "100Gbps"

    (* Every speed and its name, in the order the enum numbers them.
     *
     * That order is what a property of a speed is made of: an [Enum] kind
     * offers [names], and the value of such a property is a place in it. The
     * two arrays are built from the same enumeration, so a speed added to the
     * type above is offered and read back without anything else to change. *)
    let all = Array.init (t_max + 1) (fun i -> Option.get (of_enum i))
    let names = Array.map to_string all

    let duration speed num_bits =
        Interval.of_secs (float num_bits /. to_bps speed)

    let best speeds =
        List.reduce max speeds
end

(** {2 Transceiver: basic state, connection, speed, etc}
 * An Iface is used by both address-less Ethernet switches as well as independent
 * adapters with a MAC address etc.
 * Its read and write functions count the frames and the bytes going either
 * way, while the
 * write function (reception of a frame from the outside) account for
 * deserialization delay. Which implies that the timestamp at which a frame
 * is transmitted is the timestamp of the first bit on the wire (ie.
 * serialization is instant). *)
module Iface =
struct
    (* Each interface is its own widget for easier configuration: *)
    type t =
        { widget : Widget.t ;
          (* The function called with payload to emit, depends on what's
           * plugged in: *)
          mutable emit : bitstring -> unit ;
          (* The function called with received frames, depends on what's
           * hardwired behind the adapter. Unlike [emit], must not be called
           * directly. Instead, call [write] to write to the adapter from the
           * outside. *)
          mutable recv : bitstring -> unit ;
          (* If the interface is able to forward the received frame as soon
           * as that many bits have been deserialized (see cut-through switches
           * and routers): *)
          mutable can_forward_after : int option ;
          mutable is_connected : bool ;
          (* It's very common for a single switch to have ports with different
           * characteristics: *)
          mutable speeds : Speed.t list ;
          mutable full_duplex : bool ;
          mutable negotiated : (Speed.t * bool (* duplex *)) option ;
          (* IFP: gap (in bits) to leave in between two frames. *)
          mutable inter_frame_gap : int ;
          mutable tx_busy_until : Time.t ;
          mutable rx_busy_until : Time.t ;
          (* Frames and bytes, either way: what became of one is the "dir"
           * parameter (see [dir_params]). *)
          packets : Metric.Counter.t ;
          volume : Metric.Counter.t }

    let string_of_negotiated = function
        | None ->
            "down"
        | Some (speed, full_duplex) ->
            Speed.to_string speed ^" "^
            (if full_duplex then "full" else "half")^ "-duplex"

    (* Reception *)
    let write t pld =
        match t.widget.power.on, t.negotiated with
        | true, Some (speed, full_duplex) ->
            (* On reception, accept no inter-frame-gap. IFG is a discipline for
             * the sender. *)
            let bitlen = bitstring_length pld in
            Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Rx %d bits" bitlen))) ;
            let now = Simulation.Widget.now t.widget in
            (* Every byte that arrived, whether or not the frame survives the
             * collision below, as SNMP's ifInOctets counts them -- "packets"
             * counts what was delivered instead. *)
            Metric.(Counter.add t.volume ~now ~params:ingress
                                (bytelength pld)) ;
            (* Another frame arriving before rx_busy_until would be a collision.
             * We can't take back the previous frame with which this one collided,
             * but this one is dropped. *)
            let busy_until =
                if full_duplex then t.rx_busy_until
                else max t.rx_busy_until t.tx_busy_until in
            let dbl_recept = now < busy_until in
            let ser_delay = Speed.duration speed bitlen in
            let rx_stop = Time.add now ser_delay in
            t.rx_busy_until <- max t.rx_busy_until rx_stop ;
            if dbl_recept then
                Metric.(Counter.inc t.packets ~now ~params:rx_crc_error)
            else (
                Metric.(Counter.inc t.packets ~now ~params:ingress) ;
                let recv_ts =
                    match t.can_forward_after with
                    | Some b when b < bitlen ->
                        Time.add now (Speed.duration speed b)
                    | _ ->
                        rx_stop in
                Simulation.at t.widget.power recv_ts t.recv pld
            )
        | _ ->
            Log.(log t.widget.logger Warning (lazy
                "Ignoring an RX frame (I'm off)"))

    (* Emission *)
    let set_read t f =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Setting emitter"))) ;
        t.emit <- (fun pld ->
            match t.negotiated with
            | Some (speed, full_duplex) ->
                let bitlen = bitstring_length pld in
                Log.(log t.widget.logger Debug (lazy (Printf.sprintf
                    "Tx %d bits" bitlen))) ;
                let now = Simulation.Widget.now t.widget in
                Metric.(Counter.add t.volume ~now ~params:egress
                                    (bytelength pld)) ;
                Metric.(Counter.inc t.packets ~now ~params:egress) ;
                (* Frames must wait for each others when sending: *)
                let ser_delay = Speed.duration speed bitlen in
                let busy_until =
                    if full_duplex then t.tx_busy_until
                    else max t.rx_busy_until t.tx_busy_until in
                (* The IFG is a silence after the carrier stops (not a longer
                 * carrier, or the link would appear busy when receiving in
                 * half duplex). *)
                let quiet_until =
                    Time.add busy_until
                                   (Speed.duration speed t.inter_frame_gap) in
                let tx_start = max now quiet_until in
                t.tx_busy_until <- Time.add tx_start ser_delay ;
                Simulation.at t.widget.power tx_start f pld
            | None ->
                Log.(log t.widget.logger Warning (lazy
                    "Ignoring a TX frame (I'm off)"))) ;
        if not t.is_connected then (
            t.is_connected <- true ;
            Log.(log t.widget.logger Info (lazy (Printf.sprintf "Connected!")))
        )

    (** Turns an iface into a device *)
    let dev (t : t) =
        { write = write t ; set_read = set_read t }

    let ignore_disconnected ~logger bits =
        Log.(log logger Debug (lazy
            (Printf.sprintf "Dropping %d bits sent to disconnected interface"
                (bitstring_length bits))))

    let reset t =
        t.tx_busy_until <- beginning_of_time ;
        t.rx_busy_until <- beginning_of_time

    let disconnect t =
        if t.is_connected then (
            t.is_connected <- false ;
            t.emit <- ignore_disconnected ~logger:t.widget.logger ;
            (* Code calling disconnect is call using cables and negotiation: *)
            t.negotiated <- None ;
            reset t
        ) else
            Log.(log t.widget.logger Debug (lazy (Printf.sprintf
                "Ignoring request to disconnect interface %s that is not connected"
                t.widget.name)))

    let default_speeds =
        Speed.[ Eth10Mbps ; Eth100Mbps ; Eth1Gbps ; Eth2_5Gbps ; Eth5Gbps ]

    let ifg_min = 32

    let make ~parent ?power ?speeds ?(full_duplex=true) ?(inter_frame_gap=96)
             ?can_forward_after ?recv name =
        (* Before negotiation, the interface is actually functional,
         * using conservative settings that go through most equipments.
         * This is not physical; This is to accommodate the many programs,
         * examples and tests that wire eth adapters manually and expect
         * them to work; at least, as long as no [speeds] were asked for.
         * Passing [speeds] means planning for negotiation.
         * Also half-duplex so a non negotiating iface can go through most
         * repeaters. *)
        let negotiated =
            if speeds = None then Some (Speed.Eth100Mbps, false)
            else None in
        let speeds = speeds |? default_speeds in
        if speeds = [] then
            invalid_arg "Cannot build an iface supporting no speed" ;
        if inter_frame_gap < ifg_min then
            Printf.sprintf "inter_frame_gap can't be below %d" ifg_min |>
            invalid_arg ;
        let widget = Widget.make ~parent ?power name in
        let t =
            { widget ;
              emit = ignore_disconnected ~logger:widget.logger ;
              recv = recv |? ignore_bits ~logger:widget.logger ;
              is_connected = false ; can_forward_after ;
              tx_busy_until = beginning_of_time ;
              rx_busy_until = beginning_of_time ;
              speeds ; full_duplex ; negotiated ; inter_frame_gap ;
              packets = Metric.Counter.make () ;
              volume = Metric.Counter.make () } in
        Widget.add_properties widget Widget.[
            property "connected" ~kind:Bool
                ~descr:"Is there a cable plugged in?"
                ~getter:(fun () -> `Bool t.is_connected) ;
            property "link" ~kind:String
                ~descr:"Is the link up?"
                ~getter:(fun () ->
                    `String (string_of_negotiated t.negotiated)) ;
            property "speeds" ~kind:(Set (choices Speed.names))
                ~descr:"Supported speeds"
                ~getter:(fun () ->
                    `List (List.map (fun s -> `Int (Speed.to_enum s))
                                    t.speeds))
                ~setter:(fun v ->
                    (* TODO: Also renegotiate [negotiated] *)
                    let speeds =
                        List.map (fun i -> Speed.all.(i))
                                 (to_choices (choices Speed.names) v) in
                    (* As [make] refuses to build one: an adapter that supports
                     * no speed at all has nothing to negotiate with, and
                     * nothing to fall back on either. *)
                    if speeds = [] then
                        bad_value "An interface must support some speed" ;
                    t.speeds <- speeds) ;
            property "full-duplex" ~kind:Bool
                ~descr:"Can the interface receive and transmit at the same time."
                ~getter:(fun () -> `Bool t.full_duplex)
                ~setter:(fun v ->
                    (* TODO: Also renegotiate [negotiated] *)
                    t.full_duplex <- to_bool v) ;
            property "inter-frame-gap" ~kind:(IRange (ifg_min, max_int))
                ~descr:"How many bits of silence to include after every frame."
                ~getter:(fun () -> `Int t.inter_frame_gap)
                ~setter:(fun v ->
                    t.inter_frame_gap <- to_int_range ~min:ifg_min v) ;
            metric_property "packets"
                ~descr:"Frames received and emitted, and those dropped on \
                        reception."
                (Metric.Counter.T t.packets) ;
            metric_property "volume" ~descr:"Volume received and emitted."
                ~units:"bytes"
                (Metric.Counter.T t.volume) ] ;
        (* An adapter is the one port of whatever owns it. *)
        widget.ports <- Widget.{
            count = (fun () -> 1) ;
            is_connected = (fun _ -> t.is_connected) ;
            dev = (fun _ -> dev t) ;
            owner = (fun _ -> t.widget) ;
            disconnect = (fun _ -> disconnect t) ;
            get_capabilities = (fun ?peer:_ _ ->
                Capabilities.Eth { speeds = t.speeds ;
                                   full_duplex = t.full_duplex }) ;
            set_capabilities = (fun _ -> function
                | Capabilities.Eth { speeds ; full_duplex } when speeds <> [] ->
                    t.negotiated <- Some (Speed.best speeds, full_duplex) ;
                    Log.(log widget.logger Info (lazy (Printf.sprintf
                        "Negotiated %s" (string_of_negotiated t.negotiated))))
                | Any ->
                    (* [t.speeds] and not the list this was built with: the
                     * supported speeds are editable. *)
                    t.negotiated <- Some (Speed.best t.speeds, t.full_duplex) ;
                    Log.(log widget.logger Info (lazy "Using best performances"))
                | _ ->
                    t.negotiated <- None ;
                    Log.(log widget.logger Warning (lazy "Failed negotiation")))
        } ;
        t
end

(** {2 Stateful Eth adapters} *)

module State =
struct
    type my_address =
        { addr : bitstring ; netmask : bitstring }

    let my_address_equal a1 a2 =
        Bitstring.equals a1.addr a2.addr &&
        Bitstring.equals a2.netmask a2.netmask

    let make_my_address ?(netmask=Ip.Addr.(to_bitstring zero)) addr =
        { addr ; netmask }

    let make_my_ip_address ?netmask ip =
        let netmask = Option.map Ip.Addr.to_bitstring netmask
        and addr = Ip.Addr.to_bitstring ip in
        make_my_address ?netmask addr

    let print_my_address oc my_addr =
        Printf.fprintf oc "%s (netmask %s)"
            (hexstring_of_bitstring my_addr.addr)
            (hexstring_of_bitstring my_addr.netmask)

    type gw_selector = { dest_ip : Ip.Addr.t ; mask : Ip.Addr.t }

    let gw_selector ?(dest_ip=Ip.Addr.zero) ?(mask=Ip.Addr.zero) () =
        { dest_ip ; mask }

    let print_selector oc sel =
        Printf.fprintf oc "%s/%s"
            (Ip.Addr.to_string sel.dest_ip)
            (Ip.Addr.to_string sel.mask)

    let print_gw oc (selector, gw_opt) =
        Printf.fprintf oc "%a: " print_selector selector ;
        match gw_opt with
        | None -> String.print oc "direct"
        | Some gw -> Gateway.print oc gw

    type t =
        { iface : Iface.t ;
          (* The function called with received payloads (some IP stack
           * probably). *)
          mutable recv : bitstring -> unit ;
          mac : Addr.t ;
          (* Eth knows how to pick a gateways according to the destination IP.
           * Editable, and read afresh on every send. *)
          mutable gateways : (gw_selector * Gateway.t option) list ;
          (* Which can be overridden for one packet in routers with: *)
          mutable via : Gateway.t option ;
          proto : Proto.t ;
          mtu : int ;
          mutable my_addresses : my_address list ;
          mutable promisc : (bitstring -> unit) option ;
          rx_otherhost_dropped : Metric.Counter.t ;
          mutable do_proxy_arp : Arp.Pdu.t -> bool ;
          (* Whether an ARP announcing its own sender adds that sender to the
           * cache. Otherwise, as RFC 826 has it, only an ARP about this
           * adapter's own address adds its sender, and any other merely
           * updates an entry already there. *)
          mutable accept_gratuitous_arp : bool ;
          (* TODO: these two should be timeouted, requiring a clock *)
          arp_cache : Addr.t option BitHash.t ;     (* proto_addr -> hw_addr option (None when resolving) *)
          (* Hash of messages waiting for an ARP resolution.
           * dest_proto_addr -> msg *)
          postponed : bitstring BitHash.t ;
          (* TODO: a gauge for how many packets are postponed *)
          (* Optional average delay to add to transmissions: *)
          mutable delay : Interval.t ;
          (* Optional packet loss ratio: *)
          mutable loss : float }

    let find_ip4 t =
        List.find_map (fun my_addr ->
            if bitstring_length my_addr.addr = 32 then
                Some (Ip.Addr.of_bitstring my_addr.addr)
            else None
        ) t.my_addresses

    (* Add this IPv4 in the list of my addresses: *)
    let add_ip4 t ?netmask ip =
        t.my_addresses <- make_my_ip_address ?netmask ip :: t.my_addresses

    let set_arp (t : t) iaddr = function
        | None      ->
            Log.(log t.iface.widget.logger Debug (lazy (Printf.sprintf "Removing entry for iaddr %s from ARP table" (hexstring_of_bitstring iaddr)))) ;
            BitHash.remove_all t.arp_cache iaddr
        | haddr_opt ->
            Log.(log t.iface.widget.logger Debug (lazy (Printf.sprintf "Adding entry for iaddr %s to MAC %s from ARP table" (hexstring_of_bitstring iaddr) (match haddr_opt with None -> "None" | Some haddr -> Addr.to_string haddr)))) ;
            BitHash.replace t.arp_cache iaddr haddr_opt

    (* What an adapter learnt about its neighbours, and what it was holding
     * back until it learnt more. Both are true only for as long as the device
     * is running: an ARP request that went out and was answered while the
     * device was off would have to be asked again, and a frame waiting on one
     * is a frame nobody is waiting for any more. Left behind, the postponed
     * entry is worse than useless -- the adapter takes it as an ARP request
     * already in flight and sends no other. *)
    let reset t =
        BitHash.clear t.arp_cache ;
        BitHash.clear t.postponed ;
        t.via <- None ;
        Iface.reset t.iface

    (** Broadcast one ARP request per address of this adapter, each asking
     * for that very address: what neighbours that accept gratuitous ARP
     * learn this adapter from, without having to ask. *)
    let emit_gratuitous_arp t =
        List.iter (fun my_addr ->
            Arp.Pdu.make_request Arp.HwType.eth t.proto (t.mac :> bitstring)
                                 my_addr.addr my_addr.addr |>
            Arp.Pdu.pack |>
            Pdu.make Proto.arp t.mac Addr.broadcast |>
            Pdu.pack |>
            Simulation.asap t.iface.widget.power t.iface.emit
        ) t.my_addresses

    (** Create the state machine for an Ethernet communication.
     * @param mtu the maximum transmit unit (ie. you won't be able to send longer payloads)
     * @param mac the source {!Eth.Addr}
     * @param gateways list of [Gateeway.t]
     * @param promisc an optional function that will receive frames received but not destined to this TRX.
     * @param do_proxy_arp an optional function instructing the driver to perform proxy-arp on a give ARP request
     * @param proto the {!Proto} we want to transmit/receive.
     * @param my_addresses a list of [bitstring]s that we consider to be our address (used for instance to reply to ARP queries)
     *)
    let make ?speeds ?full_duplex ?inter_frame_gap ?can_forward_after
             ?(mtu=1500) ?(delay=Interval.zero) ?(loss=0.)
             ?(mac=Addr.random ()) ?(gateways=[])
             ?promisc ?(do_proxy_arp=(fun _ -> false))
             ?(my_addresses=[]) ?(proto=Proto.ip4) ?(name="eth")
             ~parent ?power () =
        (* An adapter is called "eth" unless its owner names it, which a
         * device with several of them has to do: which one this is is the
         * owner's to know, and a router names them after its ports. Two left
         * with the default name under one parent end up "eth" and "eth-2",
         * courtesy of [Widget.unique_among]. *)
        let iface =
            Iface.make ~parent ?power ?speeds ?full_duplex ?inter_frame_gap
                       ?can_forward_after name in
        let t = {
            iface ; mac ; gateways ; proto ; mtu ; promisc ; do_proxy_arp ;
            accept_gratuitous_arp = false ;
            rx_otherhost_dropped = Metric.Counter.make () ;
            recv = ignore_bits ~logger:iface.widget.logger ;
            my_addresses ; delay ; loss ; via = None ;
            arp_cache = BitHash.create 3 ;
            postponed = BitHash.create 3 } in
        (* Enrich the underlying dumb adapter with more properties: *)
        Widget.add_properties iface.widget Widget.[
            property "MAC" ~kind:String ~descr:"MAC address."
                ~getter:(fun () -> `String (Addr.to_string t.mac)) ;
            property "MTU" ~kind:Int ~descr:"MTU of the interface."
                ~getter:(fun () -> `Int t.mtu) ;
            property "ARP cache size" ~kind:Int
                ~descr:"Current size of the ARP cache"
                ~getter:(fun () -> `Int (BitHash.length t.arp_cache)) ;
            property "gateways"
                ~descr:"Where to send what is not on this LAN."
                ~kind:(list (row [| "destination", String ;
                                    "mask", String ;
                                    "via", optional String |]))
                ~getter:(fun () ->
                    (* Dotted rather than [Ip.Addr.to_string], and plain hex
                       rather than [Addr.to_string]: both of those may hand
                       back a name, and a name is not something the setter can
                       read again. *)
                    `List (
                        List.map (fun ({ dest_ip ; mask }, gw) ->
                            `Assoc [
                                "destination",
                                    `String (Ip.Addr.to_dotted_string dest_ip) ;
                                "mask",
                                    `String (Ip.Addr.to_dotted_string mask) ;
                                "via",
                                    (match gw with
                                    | None -> `Null
                                    | Some (Gateway.Mac mac) ->
                                        `String (Addr.to_hexstring mac)
                                    | Some (Gateway.IPv4 ip) ->
                                        `String (Ip.Addr.to_dotted_string ip)) ]
                        ) t.gateways))
                ~setter:(fun v ->
                    (* Every row is read before any of them is installed, so
                       that a table with one bad row leaves the old one alone
                       rather than a half-replaced one behind. *)
                    (* Which field it was about is added by [to_field]. *)
                    let ip s =
                        match Ip.Addr.of_dotted_string_opt s with
                        | Some ip -> ip
                        | None -> bad_value "%S is not an IP address" s in
                    let gateways =
                        to_list (fun row ->
                            let addr what =
                                to_field what (fun v -> ip (to_string v)) row in
                            let via =
                                to_field "via" (to_option (fun v ->
                                    let s = to_string v in
                                    (* A MAC when it reads as one, an IP
                                       otherwise: that is the choice
                                       [Gateway.t] offers. *)
                                    match Addr.of_string s with
                                    | exception _ ->
                                        (match Ip.Addr.of_dotted_string_opt s with
                                        | Some ip -> Gateway.IPv4 ip
                                        | None ->
                                            bad_value "%S is neither a MAC nor \
                                                       an IP address" s)
                                    | mac -> Gateway.Mac mac)) row in
                            { dest_ip = addr "destination" ;
                              mask = addr "mask" }, via
                        ) v in
                    t.gateways <- gateways) ;
            property "delay" ~kind:Float ~units:"secs"
                ~descr:"Average delay to add to transmissions."
                ~getter:(fun () -> `Float (Interval.to_secs t.delay))
                ~setter:(fun v -> t.delay <- Interval.sec (to_float v)) ;
            property "loss" ~kind:(FRange (0., 1.))
                ~descr:"Packet loss ratio."
                ~getter:(fun () -> `Float t.loss)
                ~setter:(fun v -> t.loss <- to_float_range ~min:0. ~max:1. v) ;
            property "accept gratuitous ARP" ~kind:Bool
                ~descr:"Learn the neighbours that announce themselves, and not \
                        only the ones that were asked for."
                ~getter:(fun () -> `Bool t.accept_gratuitous_arp)
                ~setter:(fun v -> t.accept_gratuitous_arp <- to_bool v) ;
            metric_property "rx-otherhost-dropped" ~units:"frames"
                ~descr:"Number of frames dropped by the MAC recipient filter."
                (Metric.Counter.T t.rx_otherhost_dropped) ] ;
        Widget.add_actions iface.widget Widget.[
            action "emit gratuitous ARP"
                ~descr:"Announce this adapter's addresses to its neighbours."
                ~can_run:(fun () ->
                    iface.widget.power.on && t.my_addresses <> [])
                ~handler:(fun s -> emit_gratuitous_arp t ; Action.stop s) ] ;
        t
end

(** {2 Transceiver} *)

(** An Ethernet TRX will convert from payload to Ethernet frames (resolving
 * destinations using ARP), for a single {!Proto}. *)
module TRX =
struct
    let gw_for_ip (st : State.t) ip =
        if st.via <> None then (
            let gw = st.via in
            st.via <- None ;
            gw
        ) else (
            (* If not provided (typically by a routing process) then look into
             * the interface configuration: *)
            let rec loop = function
                | [] -> None
                | (State.{ dest_ip ; mask }, addr) :: rest ->
                    if Ip.Addr.in_mask ip dest_ip mask then addr
                    else loop rest in
            loop st.gateways
        )

    (** Low level send function. Takes a {!Proto} since it's used both
     * for the user payload protocol and ARP protocol. *)
    let really_send (st : State.t) proto dst bits =
        let pdu = Pdu.make proto st.mac dst bits in
        Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "Emitting an Eth packet, proto %s, from %s to %s (content '%s')" (Proto.to_string proto) (Addr.to_string st.mac) (Addr.to_string dst) (hexstring_of_bitstring bits)))) ;
        let delay =
            if proto <> Proto.arp &&
               Interval.compare st.delay Interval.zero > 0 then
                Interval.sec
                    (max 0. (jitter 0.1 (Interval.to_secs st.delay)))
            else Interval.zero in
        Simulation.delay st.iface.widget.power delay
                         st.iface.emit (Pdu.pack pdu)

    let send (st : State.t) proto dst bits =
        if st.proto = Proto.arp || st.loss = 0. || Random.float 1. >= st.loss then
            really_send st proto dst bits
        else
            Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "Dropping packet of proto %s from %s" (Proto.to_string proto) (Addr.to_string st.mac))))

    let resolve_proto_addr (st : State.t) bits sender_proto_addr target_proto_addr =
        (* Add the msg to postponed messages _before_ sending the query *)
        Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "Postponing a msg for '%s'" (hexstring_of_bitstring target_proto_addr)))) ;
        BitHash.add st.postponed target_proto_addr bits ;
        let request = Arp.Pdu.make_request Arp.HwType.eth st.proto (st.mac :> bitstring) sender_proto_addr target_proto_addr in
        send st Proto.arp Addr.broadcast (Arp.Pdu.pack request)

    type dst = Postponed | Dst of Addr.t

    let arp_resolve_ipv4 (st : State.t) bits sender_ip target_ip =
        match Option.get (BitHash.find st.arp_cache target_ip) with
        | dst ->
            Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "found HW addr for '%s' in the ARP cache" (hexstring_of_bitstring target_ip)))) ;
            Dst dst
        | exception Not_found ->
            Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "Cannot find HW addr for '%s' in ARP cache" (hexstring_of_bitstring target_ip)))) ;
            BitHash.add st.arp_cache target_ip None ;
            resolve_proto_addr st bits sender_ip target_ip ;
            Postponed
        | exception Invalid_argument _ ->
            Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "HW addr for '%s' is still resolving" (hexstring_of_bitstring target_ip)))) ;
            (* Every frame waiting on that address, and not merely the one that
             * asked for it: they all leave together when the reply comes (see
             * the loop that drains [postponed]). *)
            BitHash.add st.postponed target_ip bits ;
            Postponed

    let dst_for (st : State.t) bits =
        let arp_resolve_ipv4_pld sender_ip pld =
            Result.Monad.bind (Ip.Pdu.unpack pld) (fun ip ->
                (* Note: we might be a router forwarding a packet. In that case,
                 * ip.mac is that of the original packet, yet the ARP sender addr
                 * is that of the emitting device, aka the router: *)
                let target_ip = Ip.Addr.to_bitstring ip.Ip.Pdu.dst in
                Ok (arp_resolve_ipv4 st bits sender_ip target_ip)) in
        let arp_resolve_ieee8021q_pld sender_ip pld =
            Result.Monad.bind (Vlan.Pdu.unpack pld) (fun vlan ->
                if vlan.Vlan.Pdu.proto = Proto.ip4 then
                    arp_resolve_ipv4_pld sender_ip (vlan.Vlan.Pdu.payload :> bitstring)
                else Error (lazy "Vlan proto not IPv4")) in
        let arp_resolve_pld pld =
            let my_addr =
                match st.my_addresses with
                | [] -> failwith "No address to use as sender proto addr for ARP"
                | a :: _ -> a.addr in
            if st.proto = Proto.ip4 then (
                arp_resolve_ipv4_pld my_addr pld
            ) else if st.proto = Proto.ieee8021q then (
                arp_resolve_ieee8021q_pld my_addr pld
            ) else (
                Error (lazy "Don't know how to resolve address for this protocol")
            ) in
        let same_net my_addresses bits =
            List.exists (fun (my_addr : State.my_address) ->
                match_mask my_addr.netmask my_addr.addr bits
            ) my_addresses in
        match Pdu.extract_dst_proto st.proto bits with
        | Ok dst_ip when dst_ip = Ip.Addr.broadcast ->
            Ok (Dst Addr.broadcast)
        | Ok dst_ip when same_net st.my_addresses (Ip.Addr.to_bitstring dst_ip) ->
            Log.(log st.iface.widget.logger Debug (lazy "Same network as me, sending directly")) ;
            arp_resolve_pld bits (* FIXME: should also tell us which source address to use *)
        | Ok dst_ip ->
            Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf2 "Not on my LAN (my addresses = %a)" (List.print State.print_my_address) st.my_addresses))) ;
            (match gw_for_ip st dst_ip with
            | None ->
                Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "No GW, resolving with ARP"))) ;
                arp_resolve_pld bits
            | Some (Mac addr) ->
                Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "Using GW MAC %s" (Addr.to_string addr)))) ;
                Ok (Dst addr)
            | Some (IPv4 ip)  ->
                Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "Using GW IP %s" (Ip.Addr.to_string ip)))) ;
                let sender_ip = match st.my_addresses with
                    | my_ip::_ -> my_ip.addr
                    | []       -> Ip.Addr.zero |> Ip.Addr.to_bitstring (* maybe take the source IP from the payload? *) in
                Ok (arp_resolve_ipv4 st bits sender_ip (Ip.Addr.to_bitstring ip)))
        | Error s ->
            Error (lazy ("Cannot extract dest IP: "^ Lazy.force s))

    (** Transmit function. [tx t payload] Will send the payload. *)
    let tx (st : State.t) bits =
        Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "TX a payload of %d bytes (while MTU=%d)" (bytelength bits) st.mtu))) ;
        if bytelength bits > st.mtu then
            Log.(log st.iface.widget.logger Warning (lazy (Printf.sprintf "Dropping a frame larger than MTU (%d > %d)" (bytelength bits) st.mtu)))
        else
            match dst_for st bits with
            | Ok (Dst dst) -> send st st.proto dst bits
            | Ok Postponed -> Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "...postponed")))
            | Error s -> Log.(log st.iface.widget.logger Debug s)

    (** Receive function, called to input an Ethernet frame into the TRX. *)
    let rx (st : State.t) bits =
        match Pdu.unpack bits with
        | Error s ->
            Log.(log st.iface.widget.logger Warning s)
        | Ok frame ->
            Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "Got an eth frame of proto %s for %s" (Proto.to_string frame.Pdu.proto) (Addr.to_string frame.Pdu.dst)))) ;
            if frame.Pdu.proto = st.proto &&
               (Addr.eq frame.Pdu.dst st.mac || Addr.eq frame.Pdu.dst Addr.broadcast) then (
                Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "...that's me!"))) ;
                if Payload.bitlength frame.Pdu.payload > 0 then (
                    (* Take note of the MAC/IP pair of the sender (TODO: with a short timeout) : *)
                    Pdu.extract_src_proto frame.proto (frame.payload :> bitstring) |>
                    Result.iter (fun ip_src ->
                        let src_proto_addr = Ip.Addr.to_bitstring ip_src in
                        BitHash.replace st.arp_cache src_proto_addr (Some frame.src)) ;
                    Simulation.asap st.iface.widget.power
                                    st.recv (frame.Pdu.payload :> bitstring)
                )
            ) else if frame.Pdu.proto = Proto.arp then (
                match Arp.Pdu.unpack (frame.Pdu.payload :> bitstring) with
                | Error s ->
                    Log.(log st.iface.widget.logger Warning s)
                | Ok (arp : Arp.Pdu.t) ->
                    Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "...an ARP of opcode %s" (Arp.Op.to_string arp.operation)))) ;
                    if arp.hw_type = Arp.HwType.eth then (
                        Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "...regarding an ethernet device!"))) ;
                        let sender_hw = Addr.o arp.sender_hw (* will raise if not of the advertised type *)
                        and merge_flag = ref false in
                        if arp.proto_type = st.proto then (
                            Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "...transporting same proto than me!"))) ;
                            if BitHash.mem st.arp_cache arp.sender_proto then (
                                Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "...updating entry %s->%s in ARP cache" (hexstring_of_bitstring arp.sender_proto) (Addr.to_string sender_hw)))) ;
                                merge_flag := true ;
                                BitHash.replace st.arp_cache arp.sender_proto (Some sender_hw)
                            ) else if st.accept_gratuitous_arp &&
                                      Bitstring.equals arp.sender_proto
                                                       arp.target_proto then (
                                Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "...learning %s->%s from a gratuitous ARP" (hexstring_of_bitstring arp.sender_proto) (Addr.to_string sender_hw)))) ;
                                merge_flag := true ;
                                BitHash.replace st.arp_cache arp.sender_proto (Some sender_hw)
                            ) ;
                            Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf2 "...concerning '%s' (I'm %a)" (hexstring_of_bitstring arp.target_proto) (List.print (fun oc a -> String.print oc (hexstring_of_bitstring a.State.addr))) st.my_addresses))) ;
                            let do_reply () =
                                Arp.Pdu.make_reply arp.hw_type arp.proto_type
                                    (st.mac :> bitstring) arp.target_proto
                                    arp.sender_hw arp.sender_proto |>
                                Arp.Pdu.pack |>
                                send st Proto.arp sender_hw in
                            if List.exists (fun my_addr -> Bitstring.equals arp.target_proto my_addr.State.addr) st.my_addresses then (
                                Log.(log st.iface.widget.logger Debug (lazy "...It's about me!!")) ;
                                if not !merge_flag then (
                                    BitHash.add st.arp_cache arp.sender_proto (Some sender_hw) ;
                                    Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "...adding %s->%s in ARP cache" (hexstring_of_bitstring arp.sender_proto) (Addr.to_string sender_hw)))) ;
                                ) ;
                                if arp.operation = Arp.Op.request then (
                                    Log.(log st.iface.widget.logger Debug (lazy "...It's a request, let's reply!")) ;
                                    do_reply ()
                                )
                            ) else if arp.operation = Arp.Op.request &&
                                      st.do_proxy_arp arp then (
                                (* Pretend that's me! *)
                                Log.(log st.iface.widget.logger Debug (lazy "...Let's impersonate the requested IP")) ;
                                do_reply ()
                            ) ;
                            (* Now that we may have gained knowledge, try to send the msg in waiting queue *)
                            (* TODO: timeout some? *)
                            Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "...Do I have a msg waiting for '%s'?" (hexstring_of_bitstring arp.sender_proto)))) ;
                            (* In the order they were postponed, which
                             * [find_all] gives the reverse of. *)
                            let waiting =
                                List.rev
                                    (BitHash.find_all st.postponed
                                                      arp.sender_proto) in
                            BitHash.remove_all st.postponed arp.sender_proto ;
                            List.iter (fun msg ->
                                Log.(log st.iface.widget.logger Debug (lazy "...Yes!! Let's send it!")) ;
                                send st st.proto sender_hw msg
                            ) waiting
                        )
                    )
            ) else ( (* not for me, send to promisc function *)
                Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf "...not for me (for %s but I'm %s)!"
                    (Addr.to_string frame.Pdu.dst) (Addr.to_string st.mac)))) ;
                if Payload.bitlength frame.payload > 0 then
                    match st.promisc with
                    | Some f ->
                        (* In promiscuous mode we don't count that frame as dropped *)
                        f (frame.payload :> bitstring)
                    | None ->
                        let now = Simulation.Widget.now st.iface.widget in
                        Metric.Counter.inc ~now st.rx_otherhost_dropped
            )

    (** Creates an {!Tools.trx}. *)
    let make (st : State.t) =
        (* Pass the received frames to the TRX engine: *)
        st.iface.recv <- rx st ;
        Log.(log st.iface.widget.logger Debug (lazy (Printf.sprintf2 "Creating an eth TRX with addresses mac: %s, IPs: %a and gateways: %a"
            (Addr.to_string st.mac)
            (List.print State.print_my_address) st.my_addresses
            (List.print State.print_gw) st.gateways))) ;
        { ins = { write = tx st ;
                  set_read = fun f -> st.recv <- f } ;
          out = Iface.dev st.iface }
end

(** {2 Ethernet Cables}
 *
 * Can be used in between simulated equipment to introduce latency, errors,
 * and also _record_ everything globally in a global pcap. *)


(** {2 Global record of every Ethernet traffic} *)

let recording = ref false
let recorder_file = ref "/tmp/robinet_eth.pcap"

let maybe_record =
    let recorder = ref ignore in
    let close_recording = ref None in
    let next_recorder_file =
        let file_seq = ref 0 in
        fun () ->
            let fname =
                if !file_seq = 0 then
                    !recorder_file
                else
                    !recorder_file ^"."^ string_of_int !file_seq in
            incr file_seq ;
            fname in
    fun sim bits ->
        if !recording then (
            if !close_recording = None then (
                let fname = next_recorder_file () in
                (* We have to limit ourselves to Eth traffic because a pcap file,
                 * supposedly captured from a single spot, is limited to one DLT: *)
                let write, close = Pcap.(save sim ~dlt:Dlt.en10mb) fname in
                recorder := write ;
                close_recording := Some close
            ) ;
            Log.(log default Debug (lazy (Printf.sprintf "Record %d bits" (bitstring_length bits)))) ;
            !recorder bits
        ) else (
            Option.may (fun close ->
                recorder := ignore ;
                close () ;
                close_recording := None
            ) !close_recording
        )

(* For throughput, remember the timestamp where the link will be available again *)
(* It may seams bogus to have throughput as a cable characteristic instead of
 * device characteristic, but it acknowledges the fact that both ends of a same
 * cable must agree on throughput. In other words, throughput negotiation
 * already happened and you pass the resulting throughput here.
 * Also, notice that you can use the same [limited x y] in both directions,
 * thus having something similar to a half-duplex cable ;-) *)
let limited power latency throughput =
    let next_avlb = ref Time.zero in
    (fun emit bits ->
        let min_start = Time.add (Simulation.now power.sim) latency in
        let start = max min_start !next_avlb
        and num_bits = float_of_int (min (bitstring_length bits) 368) in
        let duration =
            max (Interval.usec 1.)
                (Interval.of_secs (num_bits /. throughput)) in
        next_avlb := Time.add start duration ;
        Simulation.at power start emit bits)


(** {2 Ethernet cables}
 *
 * Point to point, faulty, and recordable in PCAP of type en10mb. *)

module Cable =
struct
    (** {3 State for a given cable} *)

    (* FIXME: state should be the real object and "trx" a function
     * returning the trx? *)

    module State =
    struct
        type t = {
            mutable length : float ;  (** In meters. *)
             mutable speed : float ;   (** In meters per second. *)
             mutable delay : Interval.t ; (** From the length and the speed *)
        mutable error_rate : float ;  (** In faulty bits per transmitted bits *)
      mutable success_rate : int ;    (** The inverse of the above *)
          mutable tot_bits : Metric.Counter.t ; (** Per direction. *)
        mutable bit_shifts : Metric.Counter.t ; (** Casualties in individual bits *)
           (** Boolean: true if from [a] to [b] (see [Cable.make] *)
              last_packets : (Time.t * bool * bitstring) option OrdArray.t ;
            (* How to tell each of the two ends that it is no longer
             * connected, recorded by whoever plugged this cable in -- which is
             * the only place that knows which port of which device each end
             * went to. [None] until then, since a cable is built before it is
             * plugged in, and either it reaches two ports or it reaches none.
             * The only thing in a simulation that has to be undone by hand:
             * everything else within a device is torn down with it. *)
              mutable ends : ((unit -> unit) * (unit -> unit)) option ;
                    widget : Widget.t }

        type Widget.device += T of t

        (* The cable a widget stands for, when it stands for one. *)
        let of_widget (w : Widget.t) =
            match w.device with
            | Some (T t) -> Some t
            | _ -> None

        let light_speed = 3e8

        let delay length speed = Interval.sec (length /. speed)
        let success_rate error_rate = int_of_float (1. /. error_rate)

        (* A cable has no natural parent; hang it off the root of the
         * simulation it connects things within. It takes no location: it is
         * drawn as the line between the two ends it joins, so where it is on
         * the map is a consequence of where they are.
         *
         * A source of its own, like any other device: what is travelling down
         * a cable is scheduled on it, and it is the only thing that is, so
         * switching one off is a cut link and deleting one takes what was
         * still on its way. Sharing the mains -- which is what it did, having
         * the root for a parent -- meant neither could be done without
         * stopping the whole network. *)
        let make ~parent ?(length=10.) ?(speed=0.7 *. light_speed)
                 ?(error_rate=0.) ?(history=10) ?(name="cable") () =
            (* A cable is its own power source so we can clear its scheduled
             * events when deleting it. *)
            let widget = Widget.make ~parent ~own_power:true name in
            widget.device_type <- Some "cable" ;
            let t = {
                length ; speed ; delay = delay length speed ;
                error_rate ; success_rate = success_rate error_rate ;
                tot_bits = Metric.Counter.make () ;
                bit_shifts = Metric.Counter.make () ;
                widget ;
                ends = None ;
                last_packets = OrdArray.make history None } in
            widget.device <- Some (T t) ;
            Widget.add_properties widget Widget.[
                property "length" ~kind:Float ~units:"meters"
                    ~descr:"Length of the cable."
                    ~setter:(fun v ->
                        let l = to_float v in
                        t.length <- l ;
                        t.delay <- delay l t.speed)
                    ~getter:(fun () -> `Float t.length) ;
                property "propagation speed" ~kind:(FRange (0.1, 1.))
                    ~units:"× speed of light"
                    ~descr:"How fast a signal travels along it."
                    ~setter:(fun v ->
                        let s =
                            to_float_range ~min:0.1 ~max:1. v *. light_speed in
                        t.speed <- s ;
                        t.delay <- delay t.length s)
                    ~getter:(fun () -> `Float (t.speed /. light_speed)) ;
                property "error rate" ~kind:(FRange (0., 1.))
                    ~descr:"Faulty bits per transmitted bits."
                    ~setter:(fun v ->
                        let r = to_float_range ~min:0. ~max:1. v in
                        t.error_rate <- r ;
                        t.success_rate <- success_rate r)
                    ~getter:(fun () -> `Float t.error_rate) ;
                property "last packets"
                    ~kind:(List (Row [| "time", Time ;
                                        "dir", one_of (choices [| "→" ; "←" |]) ;
                                        "frame", Packet |]))
                    ~descr:"Last packets transmitted."
                    (* Most recent first, and the slots nothing has reached
                     * yet left out: a cable that has carried three frames has
                     * three rows and not ten. *)
                    ~getter:(fun () ->
                        `List (
                            OrdArray.fold_left (fun lst -> function
                                | None -> lst
                                | Some (ts, dir, bits) ->
                                    `Assoc [ "time", json_of_time ts ;
                                             "dir", `Int (if dir then 0 else 1) ;
                                             "frame", json_of_packet bits ] ::
                                    lst
                            ) [] t.last_packets |>
                            List.rev)) ;
                metric_property "total bits"
                    ~descr:"Total number of transmitted bits."
                    (Metric.Counter.T t.tot_bits) ;
                metric_property "bit shifts" ~descr:"Number of flipped bits"
                    (Metric.Counter.T t.bit_shifts) ] ;

            t
    end

    (* Transfer some bits along the cable *)
    let pass (st : State.t) dir bits =
        let len = bitstring_length bits in
        let params = Metric.(Params.singleton "dir" Param.(Bool dir)) in
        let prev_tot_bits = Metric.Counter.get ~params st.tot_bits in
        let now = Simulation.Widget.now st.widget in
        Metric.Counter.add st.tot_bits ~now ~params len ;
        if prev_tot_bits > Metric.Counter.get ~params st.tot_bits then (
            Log.(log st.widget.logger Warning (lazy "Bit count wrapped around 0")) ;
            (* For better stats: *)
            Metric.Counter.reset st.bit_shifts
        ) ;
        let bits =
            (* Beware that [int_of_float infinity] is 0: *)
            if st.success_rate > 0 then
                let shift_pos = Random.int st.success_rate in
                if shift_pos < len then (
                    Metric.Counter.inc st.bit_shifts ~now ~params ;
                    let bits' = bitstring_copy bits in
                    bitstring_shift shift_pos bits' ;
                    bits'
                ) else bits
            else bits in
        maybe_record (Simulation.of_widget st.widget) bits ;
        OrdArray.prepend st.last_packets (Some (now, dir, bits)) ;
        bits

    (** Return a TRX representing an imperfect network link. *)
    let make (st : State.t) =
        let a_reader = ref (ignore_bits ~logger:st.widget.logger)
        and b_reader = ref (ignore_bits ~logger:st.widget.logger) in
        let ins_write bits =
            let bits = pass st true bits in
            Simulation.delay st.widget.power st.delay !b_reader bits
        and ins_set_read f = a_reader := f
        and out_write bits =
            let bits = pass st false bits in
            Simulation.delay st.widget.power st.delay !a_reader bits
        and out_set_read f = b_reader := f
        in
        { ins = { write = ins_write ; set_read = ins_set_read } ;
          out = { write = out_write ; set_read = out_set_read } }

    (* What the reader is shown of a cable: the frames that have gone by, most
     * recent first, one row per frame and not one per slot it remembers. A
     * cable that has carried three frames therefore answers with three rows,
     * and one that has carried more than it remembers answers with what it
     * still has -- which is what walking a ring has to be careful about, since
     * a full ring has no empty slot left to stop at. *)
    (*$< Cable *)
    (*$R make
        let sim = Simulation.make ~realtime:false "last-packets" in
        let st = State.make ~parent:sim.root ~history:3 () in
        let trx = make st in
        let rows () =
            let p =
                List.find (fun (p : property) -> p.name = "last packets")
                          st.State.widget.properties in
            match p.getter () with
            | `List l -> List.length l
            | _ -> -1 in
        assert_equal ~printer:string_of_int ~msg:"a fresh cable has carried none"
            0 (rows ()) ;
        List.iter (fun n ->
            trx.ins.write (Bitstring.create_bitstring 64) ;
            assert_equal ~printer:string_of_int
                ~msg:("after "^ string_of_int n ^" frame(s)")
                (min n 3) (rows ())
        ) [ 1 ; 2 ; 3 ; 4 ; 5 ]
     *)
    (* Frames held back while an address is being resolved leave in the order
     * they were held: what a fast link lets pile up behind one ARP must come
     * out the way it went in, or a pair sent back to back arrives reversed. *)
    (*$R plug
        let sim = Simulation.make ~realtime:false "arp-order" in
        let ip n = Ip.Addr.of_string ("192.168.0." ^ string_of_int n) in
        let host n =
            Host.make ~parent:sim.root ~static_ip:(ip n)
                      ~netmask:(Ip.Addr.of_string "255.255.255.0")
                      ("h" ^ string_of_int n) in
        let a = host 1 and b = host 2 in
        let st = State.make ~parent:sim.root ~name:"c" () in
        plug st (a.Host.trx.Host.widget, 0) (b.Host.trx.Host.widget, 0) ;
        Simulation.run_startup sim ;
        let got = ref [] in
        b.Host.trx.Host.udp_server (Udp.Port.o 5000) (fun udp ->
            udp.Udp.TRX.trx.ins.set_read (fun bits ->
                got := Bitstring.string_of_bitstring bits :: !got)) ;
        (* Both go out before the first can be answered, so both wait on the
           same resolution. *)
        List.iter (fun n ->
            a.Host.trx.Host.udp_send (Host.IPv4 (ip 2)) (Udp.Port.o 5000)
                                     (Bitstring.bitstring_of_string n)
        ) [ "one" ; "two" ] ;
        Simulation.run sim false ;
        assert_equal ~printer:(String.concat ",") [ "one" ; "two" ]
                     (List.rev !got)
     *)
    (*$>*)

    let connect (st : State.t) a widget_a b widget_b =
        let trx = make st in
        Widget.make_peers widget_a ~via:st.widget widget_b ;
        a ==> trx <==> b

    (** Unplug both ends, so that the ports they were on emit nothing and are
     * free for another cable.
     *
     * The peering is not undone here: a cable that is unplugged is a cable that
     * is going away, and deleting its widget scrubs every relation that went
     * through it. *)
    let disconnect (st : State.t) =
        match st.ends with
        | None ->
            Log.(log st.widget.logger Debug (lazy (Printf.sprintf
                "Ignoring request to unplug %s, which is not plugged in"
                st.widget.name)))
        | Some (unplug_a, unplug_b) ->
            unplug_a () ;
            unplug_b () ;
            st.ends <- None

    (* How many ports a question may be passed along before the chain is
     * called broken. Taps in series are the only thing that passes it along,
     * and a ring of them would otherwise spin forever. *)
    let max_hops = 8

    (* The port the link from port [p] of [w] really ends at, and what it
     * advertises: [w, p] itself for anything that answers for itself, and
     * whatever a tap points at for one that does not. [peer] is given to the
     * first port only -- it is who *that* one faces, and is none of the
     * business of the ports the question is passed along to. *)
    let link_end ~peer (w : Widget.t) p =
        let rec loop left (w : Widget.t) p c =
            match c with
            | Capabilities.ForwardTo (w', p') when left > 0 ->
                loop (left - 1) w' p' (w'.ports.get_capabilities p')
            | ForwardTo _ ->
                Log.(log w.logger Error (lazy (Printf.sprintf
                    "Giving up looking for what %s port#%d leads to after %d \
                     ports: a tap pointing at itself?"
                    (Widget.full_name w) p max_hops))) ;
                (w, p), Capabilities.NoCapabilities
            | c ->
                (w, p), c in
        loop max_hops w p (w.ports.get_capabilities ~peer p)

    (** Plug a cable between port [pa] of [wa] and port [pb] of [wb]: wire the
     * two together, remember how to let go of them, and record in the graph
     * that this cable joins the widgets those two ports belong to.
     *
     * The ports-level counterpart of [connect], and the one to use when the
     * ends are devices rather than bare trxs: it is the only place that knows
     * which port of which device each end went to, which is what [disconnect]
     * then needs. *)
    let plug (st : State.t) ((wa : Widget.t), pa) ((wb : Widget.t), pb) =
        if st.ends <> None then
            (* Plugging it again would leave the first two ports emitting into
             * a cable nothing can unplug them from. *)
            invalid_arg ("Eth.Cable.plug: "^ Widget.full_name st.widget ^
                         " is already plugged in") ;
        let trx = make st in
        let end_a = link_end ~peer:(wb, pb) wa pa
        and end_b = link_end ~peer:(wa, pa) wb pb in
        let c = Capabilities.negotiate (snd end_a) (snd end_b) in
        let settle ((w : Widget.t), p) = w.ports.set_capabilities p c in
        settle (fst end_a) ;
        settle (fst end_b) ;
        wa.ports.dev pa -=> trx <=-> wb.ports.dev pb ;
        st.ends <- Some ((fun () -> wa.ports.disconnect pa),
                         (fun () -> wb.ports.disconnect pb)) ;
        (* Deleting the cable is how one gets rid of it, from the interface as
           much as from a program, and a deleted cable that had not let go of
           its two ports would leave them emitting into nothing. *)
        st.widget.on_delete <- (fun () -> disconnect st) ;
        Widget.make_peers ~via:st.widget
            (wa.ports.owner pa) (wb.ports.owner pb)

end
