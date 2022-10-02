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
open Bitstring
open Tools

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
     * {!Eth.Addr.to_string}. *)
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
        let pack_addr a b c d e f =
            let%bitstring addr = {| a : 8 ; b : 8 ; c : 8 ; d : 8 ; e : 8 ; f : 8 |} in
            o addr in
        Scanf.sscanf str "%x:%x:%x:%x:%x:%x" pack_addr

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

    (** Returns a random Ethernet address (but neither broadcast nor zero). *)
    let rec random () =
        let a = o (randbs 6) in
        if eq a broadcast || eq a zero then random ()
        else a

    (* Get the Eth address of a device (on Linux). *)
    let of_iface ifname =
        info_of_iface ifname "address" |> of_string

    (*$>*)
end

(** {3 Gateway specifications} *)

(** The address of a gateway, which can be given either as an Ethernet address
 * of as an IP address. *)
type gw_addr = Mac of Addr.t | IPv4 of Ip.Addr.t

(** Converts a {!Eth.gw_addr} to a string. *)
let string_of_gw_addr = function
    | Mac mac -> Addr.to_string mac
    | IPv4 ip -> Ip.Addr.to_string ip

(** Converts the other way around. *)
let gw_addr_of_string str =
    try Mac (Addr.of_string str)
    with _ -> IPv4 (Ip.Addr.of_string str)

(** {2 Ethernet frames} *)

(** Pack/Unpack an Ethernet frame.  *)
module Pdu = struct
    (*$< Pdu *)
    (** An Ethernet frame is made up from these constituents *)
    type t = { src : Addr.t ; dst : Addr.t ;
               proto : Arp.HwProto.t ;
               payload : Payload.t }

    (** Build an {!Eth.Pdu.t} for the given [payload]. *)
    let make proto src dst bits =
        { src ; dst ; proto ; payload = Payload.o bits }

    (** Returns a random {!Eth.Pdu.t}. *)
    let random () =
        make (Arp.HwProto.random ()) (Addr.random ()) (Addr.random ()) (randbs 30)

    (** Pack an {!Eth.Pdu.t} into its [bitstring] raw representation, ready for
     * injection onto the wire (via {!Pcap.inject_pdu} for instance). *)
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
            Some { src = Addr.o src ; dst = Addr.o dst ;
                   proto = Arp.HwProto.o proto ;
                   payload = Payload.o payload }
        | {| _ |} ->
            err "Not Eth"

    let extract_proto do_extract proto pld =
        if proto = Arp.HwProto.ip4 then
            do_extract pld
        else if proto = Arp.HwProto.ieee8021q then
            Option.Monad.bind (Vlan.Pdu.unpack pld) (fun vlan ->
                if vlan.Vlan.Pdu.proto = Arp.HwProto.ip4 then
                    do_extract (vlan.Vlan.Pdu.payload :> bitstring)
                else None)
        else None

    (* Actually only extract IP addresses *)
    let extract_src_proto =
        extract_proto (fun pdu ->
            Option.Monad.bind (Ip.Pdu.unpack pdu) (fun ip ->
                Some ip.Ip.Pdu.src))

    let extract_dst_proto =
        extract_proto (fun pdu ->
            Option.Monad.bind (Ip.Pdu.unpack pdu) (fun ip ->
                Some ip.Ip.Pdu.dst))

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Option.get (unpack t)))
     *)
    (*$>*)
end

(** {2 Transceiver} *)

(** An Ethernet TRX will convert from payload to Ethernet frames (resolving
 * destinations using ARP), for a single {!Arp.HwProto.t}. *)
module TRX =
struct
    type t =
        { logger : Log.logger ;
          src : Addr.t ;
          gw : gw_addr option ;
          proto : Arp.HwProto.t ;
          mtu : int ;
          mutable my_addresses : my_address list ;
          mutable emit : bitstring -> unit ;
          mutable recv : bitstring -> unit ;
          mutable promisc : bitstring -> unit ;
          (* TODO: these two should be timeouted, requiring a clock *)
          arp_cache : Addr.t option BitHash.t ;     (* proto_addr -> hw_addr option (None when resolving) *)
          delayed : bitstring BitHash.t }  (* dest_proto_addr -> msg *)
    and my_address =
        { addr : bitstring ; netmask : bitstring }

    let make_my_address ?(netmask = Ip.Addr.(to_bitstring all_ones)) addr =
        { addr ; netmask }

    let print_my_address oc my_addr =
        Printf.fprintf oc "%s (netmask %s)"
            (hexstring_of_bitstring my_addr.addr)
            (hexstring_of_bitstring my_addr.netmask)

    type eth_trx =
        { trx : trx ;
          set_promiscuous : (bitstring -> unit) -> unit ;
          set_addresses : my_address list -> unit ;
          get_source : unit -> Addr.t ;
          arp_set : bitstring -> Addr.t option -> unit }

    (** Low level send function. Takes a {!Arp.HwProto.t} since it's used both
     * for the user payload protocol and ARP protocol. *)
    let send t proto dst bits =
        let pdu = Pdu.make proto t.src dst bits in
        Log.(log t.logger Debug (lazy (Printf.sprintf "Eth: Emitting an Eth packet, proto %s, from %s to %s (content '%s')" (Arp.HwProto.to_string proto) (Addr.to_string t.src) (Addr.to_string dst) (hexstring_of_bitstring bits)))) ;
        Clock.asap t.emit (Pdu.pack pdu)

    let resolve_proto_addr t bits sender_proto_addr target_proto_addr =
        (* Add the msg to delayed messages _before_ sending the query *)
        Log.(log t.logger Debug (lazy (Printf.sprintf "Eth: Postponing a msg for '%s'" (hexstring_of_bitstring target_proto_addr)))) ;
        BitHash.add t.delayed target_proto_addr bits ;
        let request = Arp.Pdu.make_request Arp.HwType.eth t.proto (t.src :> bitstring) sender_proto_addr target_proto_addr in
        send t Arp.HwProto.arp Addr.broadcast (Arp.Pdu.pack request)

    type dst = Postponed | Dst of Addr.t

    let arp_resolve_ipv4 t bits sender_ip target_ip =
        match Option.get (BitHash.find t.arp_cache target_ip) with
        | dst ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Eth: found HW addr for '%s' in the ARP cache" (hexstring_of_bitstring target_ip)))) ;
            Dst dst
        | exception Not_found ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Eth: Cannot find HW addr for '%s' in ARP cache" (hexstring_of_bitstring target_ip)))) ;
            BitHash.add t.arp_cache target_ip None ;
            resolve_proto_addr t bits sender_ip target_ip ;
            Postponed
        | exception Invalid_argument _ ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Eth: HW addr for '%s' is still resolving" (hexstring_of_bitstring target_ip)))) ;
            Postponed

    let dst_for t bits =
        let arp_resolve_ipv4_pld sender_ip pld =
            Option.Monad.bind (Ip.Pdu.unpack pld) (fun ip ->
                (* Note: we might be a router forwarding a packet. In that case,
                 * ip.src is that of the original packet, yet the ARP sender addr
                 * is that of the emitting device, aka the router: *)
                let target_ip = Ip.Addr.to_bitstring ip.Ip.Pdu.dst in
                Some (arp_resolve_ipv4 t bits sender_ip target_ip)) in
        let arp_resolve_ieee8021q_pld sender_ip pld =
            Option.Monad.bind (Vlan.Pdu.unpack pld) (fun vlan ->
                if vlan.Vlan.Pdu.proto = Arp.HwProto.ip4 then
                    arp_resolve_ipv4_pld sender_ip (vlan.Vlan.Pdu.payload :> bitstring)
                else None) in
        let arp_resolve_pld pld =
            let my_addr =
                match t.my_addresses with
                | [] -> failwith "No adress to use as sender proto addr for ARP"
                | a :: _ -> a.addr in
            if t.proto = Arp.HwProto.ip4 then (
                arp_resolve_ipv4_pld my_addr pld
            ) else if t.proto = Arp.HwProto.ieee8021q then (
                arp_resolve_ieee8021q_pld my_addr pld
            ) else (
                err "Don't know how to resolve address for this protocol"
            ) in
        let same_net my_addresses bits =
            List.exists (fun my_addr ->
                match_mask my_addr.netmask my_addr.addr bits
            ) my_addresses in
        match Pdu.extract_dst_proto t.proto bits with
        | Some dst_ip when dst_ip = Ip.Addr.broadcast ->
            Some (Dst Addr.broadcast)
        | Some dst_ip when same_net t.my_addresses (Ip.Addr.to_bitstring dst_ip) ->
            Log.(log t.logger Debug (lazy "Same network as me, sending directly")) ;
            arp_resolve_pld bits (* FIXME: should also tell us which source address to use *)
        | _ ->
            Log.(log t.logger Debug (lazy (Printf.sprintf2 "Not on my LAN (my addresses = %a)" (List.print print_my_address) t.my_addresses))) ;
            (match t.gw with
            | None ->
                Log.(log t.logger Debug (lazy (Printf.sprintf "No GW, resolving with ARP"))) ;
                arp_resolve_pld bits
            | Some (Mac addr) ->
                Log.(log t.logger Debug (lazy (Printf.sprintf "Using MAC of GW"))) ;
                Some (Dst addr)
            | Some (IPv4 ip)  ->
                Log.(log t.logger Debug (lazy (Printf.sprintf "Using GW which IP is %s" (Ip.Addr.to_string ip)))) ;
                let sender_ip = match t.my_addresses with
                    | my_ip::_ -> my_ip.addr
                    | []       -> Ip.Addr.zero |> Ip.Addr.to_bitstring (* maybe take the source IP from the payload? *) in
                Some (arp_resolve_ipv4 t bits sender_ip (Ip.Addr.to_bitstring ip)))

    (** Transmit function. [tx t payload] Will send the payload. *)
    let tx t bits =
        Log.(log t.logger Debug (lazy (Printf.sprintf "Eth: TX a payload of %d bytes (while MTU=%d)" (bytelength bits) t.mtu))) ;
        if bytelength bits <= t.mtu then (
            match dst_for t bits with
            | Some (Dst dst) -> send t t.proto dst bits
            | Some Postponed -> Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...postponed")))
            | None -> Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...no destination?!")))
        )

    (** Receive function, called to input an Ethernet frame into the TRX. *)
    let rx t bits = (match Pdu.unpack bits with
        | None -> ()
        | Some frame ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Eth: Got an eth frame of proto %s for %s" (Arp.HwProto.to_string frame.Pdu.proto) (Addr.to_string frame.Pdu.dst)))) ;
            if frame.Pdu.proto = t.proto &&
               (Addr.eq frame.Pdu.dst t.src || Addr.eq frame.Pdu.dst Addr.broadcast) then (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...that's me!"))) ;
                if Payload.bitlength frame.Pdu.payload > 0 then (
                    (* Take note of the MAC/IP pair of the sender (TODO: with a short timeout) : *)
                    Pdu.extract_src_proto frame.proto (frame.payload :> bitstring) |>
                    Option.may (fun ip_src ->
                        let src_proto_addr = Ip.Addr.to_bitstring ip_src in
                        BitHash.replace t.arp_cache src_proto_addr (Some frame.src)) ;
                    Clock.asap t.recv (frame.Pdu.payload :> bitstring)
                )
            ) else if frame.Pdu.proto = Arp.HwProto.arp then (
                match Arp.Pdu.unpack (frame.Pdu.payload :> bitstring) with
                | None -> ()
                | Some arp ->
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...an ARP of opcode %s" (Arp.Op.to_string arp.Arp.Pdu.operation)))) ;
                    if arp.Arp.Pdu.hw_type = Arp.HwType.eth then (
                        Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...regarding an ethernet device!"))) ;
                        let sender_hw = Addr.o arp.Arp.Pdu.sender_hw (* will raise if not of the advertised type *)
                        and merge_flag = ref false in
                        if arp.Arp.Pdu.proto_type = t.proto then (
                            Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...transporting same proto than me!"))) ;
                            if BitHash.mem t.arp_cache arp.Arp.Pdu.sender_proto then (
                                Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...updating entry %s->%s in ARP cache" (hexstring_of_bitstring arp.Arp.Pdu.sender_proto) (Addr.to_string sender_hw)))) ;
                                merge_flag := true ;
                                BitHash.replace t.arp_cache arp.Arp.Pdu.sender_proto (Some sender_hw)
                            ) ;
                            Log.(log t.logger Debug (lazy (Printf.sprintf2 "Eth:...concerning '%s' (I'm %a)" (hexstring_of_bitstring arp.Arp.Pdu.target_proto) (List.print (fun oc a -> String.print oc (hexstring_of_bitstring a.addr))) t.my_addresses))) ;
                            if List.exists (fun my_addr -> Bitstring.equals arp.Arp.Pdu.target_proto my_addr.addr) t.my_addresses then (
                                Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...It's about me!!"))) ;
                                if not !merge_flag then (
                                    BitHash.add t.arp_cache arp.Arp.Pdu.sender_proto (Some sender_hw) ;
                                    Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...adding %s->%s in ARP cache" (hexstring_of_bitstring arp.Arp.Pdu.sender_proto) (Addr.to_string sender_hw)))) ;
                                ) ;
                                if arp.Arp.Pdu.operation = Arp.Op.request then (
                                    Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...It's a request, let's reply!"))) ;
                                    let reply = Arp.Pdu.make_reply arp.Arp.Pdu.hw_type arp.Arp.Pdu.proto_type
                                                                   (t.src :> bitstring) arp.Arp.Pdu.target_proto
                                                                   arp.Arp.Pdu.sender_hw arp.Arp.Pdu.sender_proto in
                                    send t Arp.HwProto.arp sender_hw (Arp.Pdu.pack reply)
                                )
                            ) ;
                            (* Now that we may have gained knowledge, try to send the msg in waiting queue *)
                            (* TODO: timeout some? *)
                            Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...Do I have a msg waiting for '%s'?" (hexstring_of_bitstring arp.Arp.Pdu.sender_proto)))) ;
                            while BitHash.mem t.delayed arp.Arp.Pdu.sender_proto do
                                Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...Yes!! Let's send it!"))) ;
                                let msg = BitHash.find t.delayed arp.Arp.Pdu.sender_proto in
                                send t t.proto sender_hw msg ;
                                BitHash.remove t.delayed arp.Arp.Pdu.sender_proto
                            done
                        )
                    )
            ) else ( (* not for me, send to promisc function *)
                Log.(log t.logger Debug (lazy (Printf.sprintf "Eth:...not for me (for %s but I'm %s)!"
                    (Addr.to_string frame.Pdu.dst) (Addr.to_string t.src)))) ;
                if Payload.bitlength frame.Pdu.payload > 0 then t.promisc (frame.Pdu.payload :> bitstring)
            ))

    (** Creates an {!Eth.TRX.t}.
     * @param mtu the maximum transmit unit (ie. you won't be able to send longer payloads)
     * @param src the source {!Eth.Addr.t}
     * @param gw an optional gateway
     * @param promisc an optional function that will receive frames received but not destined to this TRX.
     * @param proto the {!Arp.HwProto.t} we want to transmit/receive.
     * @param my_addresses a list of [bitstring]s that we consider to be our address (used for instance to reply to ARP queries)
     *)
    let make ?(mtu=1500) src ?gw ?(promisc=ignore) proto my_addresses logger =
        Log.(log logger Debug (lazy (Printf.sprintf2 "Eth: Creating an eth TRX with addresses %a" (List.print print_my_address) my_addresses))) ;
        let t = { logger ; src ; gw ; proto ;
                  emit = ignore_bits logger ;
                  recv = ignore_bits logger ;
                  mtu ; promisc ; my_addresses ;
                  arp_cache = BitHash.create 3 ;
                  delayed = BitHash.create 3 } in
        { trx = { ins = { write = tx t ;
                          set_read = fun f -> t.recv <- f } ;
                  out = { write = rx t ;
                          set_read = fun f -> t.emit <- f ; } } ;
          set_promiscuous = (fun f -> t.promisc <- f) ;
          set_addresses = (fun l -> t.my_addresses <- l) ;
          get_source = (fun () -> t.src) ;
          arp_set = (fun iaddr -> function
            | None      ->
                Log.(log t.logger Debug (lazy (Printf.sprintf "Eth: Removing entry for iaddr %s from ARP table" (hexstring_of_bitstring iaddr)))) ;
                BitHash.remove_all t.arp_cache iaddr
            | haddr_opt ->
                Log.(log t.logger Debug (lazy (Printf.sprintf "Eth: Adding entry for iaddr %s to MAC %s from ARP table" (hexstring_of_bitstring iaddr) (match haddr_opt with None -> "None" | Some haddr -> Addr.to_string haddr)))) ;
                BitHash.replace t.arp_cache iaddr haddr_opt) }

end

(* for throughput, remember the timestamp where the link will be available again *)
(* It may seams bogus to have throughput as a cable characteristic instead of
 * device characteristic, but it acknowledges the fact that both ends of a same
 * cable must agree on throughput. In other words, throughput negotiation
 * already happened and you pass the resulting throughput here.
 * Also, notice that you can use the same [limited x y] in both directions,
 * thus having something similar to a half-duplex cable ;-) *)
let limited latency throughput =
    let next_avlb = ref (Clock.Time.o 0.) in
    (fun emit bits ->
        let min_start = Clock.Time.add (Clock.now ()) latency in
        let start = max min_start !next_avlb
        and nb_bits = float_of_int (min (bitstring_length bits) 368) in
        let duration = max (Clock.Interval.usec 1.) (Clock.Interval.o (nb_bits /. throughput)) in
        next_avlb := Clock.Time.add start duration ;
        Clock.at start emit bits)
