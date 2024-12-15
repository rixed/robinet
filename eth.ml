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
    (*$>*)
end

(** {3 Gateway specifications} *)

module Gateway =
struct
    (** The address of a gateway, which can be given either as an Ethernet address
     * of as an IP address. *)
    type t = Mac of Addr.t | IPv4 of Ip.Addr.t

    (** Converts a {!Eth.addr} to a string. *)
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

(** {2 Transceiver State} *)

module State =
struct
    type my_address =
        { addr : bitstring ; netmask : bitstring }

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
        { logger : Log.logger ;
          mac : Addr.t ;
          (* Eth knows how to pick a gateways according to the destination IP: *)
          gateways : (gw_selector * Gateway.t option) list ;
          (* Which can be overridden for one packet in routers with: *)
          mutable via : Gateway.t option ;
          proto : Proto.t ;
          mtu : int ;
          mutable connected : bool ;
          mutable my_addresses : my_address list ;
          mutable emit : bitstring -> unit ;
          mutable recv : bitstring -> unit ;
          mutable promisc : bitstring -> unit ;
          (* TODO: these two should be timeouted, requiring a clock *)
          arp_cache : Addr.t option BitHash.t ;     (* proto_addr -> hw_addr option (None when resolving) *)
          (* Hash of messages waiting for an ARP resolution.
           * dest_proto_addr -> msg *)
          postponed : bitstring BitHash.t ;
          (* Optional average delay to add to transmissions: *)
          delay : float option ;
          (* Optional packet loss ratio: *)
          loss : float option }

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
            Log.(log t.logger Debug (lazy (Printf.sprintf "Removing entry for iaddr %s from ARP table" (hexstring_of_bitstring iaddr)))) ;
            BitHash.remove_all t.arp_cache iaddr
        | haddr_opt ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Adding entry for iaddr %s to MAC %s from ARP table" (hexstring_of_bitstring iaddr) (match haddr_opt with None -> "None" | Some haddr -> Addr.to_string haddr)))) ;
            BitHash.replace t.arp_cache iaddr haddr_opt

    (** Create the state machine for an Ethernet communication.
     * @param mtu the maximum transmit unit (ie. you won't be able to send longer payloads)
     * @param mac the source {!Eth.Addr.t}
     * @param gateways list of [Gateeway.t]
     * @param promisc an optional function that will receive frames received but not destined to this TRX.
     * @param proto the {!Proto.t} we want to transmit/receive.
     * @param my_addresses a list of [bitstring]s that we consider to be our address (used for instance to reply to ARP queries)
     *)

    let make ?(mtu=1500) ?delay ?loss ?(mac=Addr.random ()) ?(gateways=[])
             ?(promisc=ignore) ?(my_addresses=[])
             ?(proto=Proto.ip4) ?(parent_logger=Log.default) () =
        let logger = Log.sub parent_logger "eth" in
        { logger ; mac ; gateways ; proto ;
          emit = ignore_bits ~logger ;
          recv = ignore_bits ~logger ;
          mtu ; promisc ; my_addresses ;
          via = None ;
          connected = false ;
          arp_cache = BitHash.create 3 ;
          postponed = BitHash.create 3 ;
          delay ; loss }
end

(** {2 Transceiver} *)

(** An Ethernet TRX will convert from payload to Ethernet frames (resolving
 * destinations using ARP), for a single {!Proto.t}. *)
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

    (** Low level send function. Takes a {!Proto.t} since it's used both
     * for the user payload protocol and ARP protocol. *)
    let really_send (st : State.t) proto dst bits =
        let pdu = Pdu.make proto st.mac dst bits in
        Log.(log st.logger Debug (lazy (Printf.sprintf "Emitting an Eth packet, proto %s, from %s to %s (content '%s')" (Proto.to_string proto) (Addr.to_string st.mac) (Addr.to_string dst) (hexstring_of_bitstring bits)))) ;
        let delay =
            match proto, st.delay with
            | p, Some d when p <> Proto.arp ->
                jitter 0.1 d
            | _ ->
                0. in
        Clock.delay (Clock.Interval.o delay) st.emit (Pdu.pack pdu)

    let send (st : State.t) proto dst bits =
        let loss = st.loss |? 0. in
        if st.proto = Proto.arp || loss = 0. || Random.float 1. >= loss then
            really_send st proto dst bits
        else
            Log.(log st.logger Debug (lazy (Printf.sprintf "Dropping packet of proto %s from %s" (Proto.to_string proto) (Addr.to_string st.mac))))

    let resolve_proto_addr (st : State.t) bits sender_proto_addr target_proto_addr =
        (* Add the msg to postponed messages _before_ sending the query *)
        Log.(log st.logger Debug (lazy (Printf.sprintf "Postponing a msg for '%s'" (hexstring_of_bitstring target_proto_addr)))) ;
        BitHash.add st.postponed target_proto_addr bits ;
        let request = Arp.Pdu.make_request Arp.HwType.eth st.proto (st.mac :> bitstring) sender_proto_addr target_proto_addr in
        send st Proto.arp Addr.broadcast (Arp.Pdu.pack request)

    type dst = Postponed | Dst of Addr.t

    let arp_resolve_ipv4 (st : State.t) bits sender_ip target_ip =
        match Option.get (BitHash.find st.arp_cache target_ip) with
        | dst ->
            Log.(log st.logger Debug (lazy (Printf.sprintf "found HW addr for '%s' in the ARP cache" (hexstring_of_bitstring target_ip)))) ;
            Dst dst
        | exception Not_found ->
            Log.(log st.logger Debug (lazy (Printf.sprintf "Cannot find HW addr for '%s' in ARP cache" (hexstring_of_bitstring target_ip)))) ;
            BitHash.add st.arp_cache target_ip None ;
            resolve_proto_addr st bits sender_ip target_ip ;
            Postponed
        | exception Invalid_argument _ ->
            Log.(log st.logger Debug (lazy (Printf.sprintf "HW addr for '%s' is still resolving" (hexstring_of_bitstring target_ip)))) ;
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
            Log.(log st.logger Debug (lazy "Same network as me, sending directly")) ;
            arp_resolve_pld bits (* FIXME: should also tell us which source address to use *)
        | Ok dst_ip ->
            Log.(log st.logger Debug (lazy (Printf.sprintf2 "Not on my LAN (my addresses = %a)" (List.print State.print_my_address) st.my_addresses))) ;
            (match gw_for_ip st dst_ip with
            | None ->
                Log.(log st.logger Debug (lazy (Printf.sprintf "No GW, resolving with ARP"))) ;
                arp_resolve_pld bits
            | Some (Mac addr) ->
                Log.(log st.logger Debug (lazy (Printf.sprintf "Using GW MAC %s" (Addr.to_string addr)))) ;
                Ok (Dst addr)
            | Some (IPv4 ip)  ->
                Log.(log st.logger Debug (lazy (Printf.sprintf "Using GW IP %s" (Ip.Addr.to_string ip)))) ;
                let sender_ip = match st.my_addresses with
                    | my_ip::_ -> my_ip.addr
                    | []       -> Ip.Addr.zero |> Ip.Addr.to_bitstring (* maybe take the source IP from the payload? *) in
                Ok (arp_resolve_ipv4 st bits sender_ip (Ip.Addr.to_bitstring ip)))
        | Error s ->
            Error (lazy ("Cannot extract dest IP: "^ Lazy.force s))

    (** Transmit function. [tx t payload] Will send the payload. *)
    let tx (st : State.t) bits =
        Log.(log st.logger Debug (lazy (Printf.sprintf "TX a payload of %d bytes (while MTU=%d)" (bytelength bits) st.mtu))) ;
        if bytelength bits <= st.mtu then (
            match dst_for st bits with
            | Ok (Dst dst) -> send st st.proto dst bits
            | Ok Postponed -> Log.(log st.logger Debug (lazy (Printf.sprintf "...postponed")))
            | Error s -> Log.(log st.logger Debug s)
        ) (* TODO: else (re)fragment *)

    (** Receive function, called to input an Ethernet frame into the TRX. *)
    let rx (st : State.t) bits =
        match Pdu.unpack bits with
        | Error s ->
            Log.(log st.logger Warning s)
        | Ok frame ->
            Log.(log st.logger Debug (lazy (Printf.sprintf "Got an eth frame of proto %s for %s" (Proto.to_string frame.Pdu.proto) (Addr.to_string frame.Pdu.dst)))) ;
            if frame.Pdu.proto = st.proto &&
               (Addr.eq frame.Pdu.dst st.mac || Addr.eq frame.Pdu.dst Addr.broadcast) then (
                Log.(log st.logger Debug (lazy (Printf.sprintf "...that's me!"))) ;
                if Payload.bitlength frame.Pdu.payload > 0 then (
                    (* Take note of the MAC/IP pair of the sender (TODO: with a short timeout) : *)
                    Pdu.extract_src_proto frame.proto (frame.payload :> bitstring) |>
                    Result.iter (fun ip_src ->
                        let src_proto_addr = Ip.Addr.to_bitstring ip_src in
                        BitHash.replace st.arp_cache src_proto_addr (Some frame.src)) ;
                    Clock.asap st.recv (frame.Pdu.payload :> bitstring)
                )
            ) else if frame.Pdu.proto = Proto.arp then (
                match Arp.Pdu.unpack (frame.Pdu.payload :> bitstring) with
                | Error s ->
                    Log.(log st.logger Warning s)
                | Ok arp ->
                    Log.(log st.logger Debug (lazy (Printf.sprintf "...an ARP of opcode %s" (Arp.Op.to_string arp.Arp.Pdu.operation)))) ;
                    if arp.Arp.Pdu.hw_type = Arp.HwType.eth then (
                        Log.(log st.logger Debug (lazy (Printf.sprintf "...regarding an ethernet device!"))) ;
                        let sender_hw = Addr.o arp.Arp.Pdu.sender_hw (* will raise if not of the advertised type *)
                        and merge_flag = ref false in
                        if arp.Arp.Pdu.proto_type = st.proto then (
                            Log.(log st.logger Debug (lazy (Printf.sprintf "...transporting same proto than me!"))) ;
                            if BitHash.mem st.arp_cache arp.Arp.Pdu.sender_proto then (
                                Log.(log st.logger Debug (lazy (Printf.sprintf "...updating entry %s->%s in ARP cache" (hexstring_of_bitstring arp.Arp.Pdu.sender_proto) (Addr.to_string sender_hw)))) ;
                                merge_flag := true ;
                                BitHash.replace st.arp_cache arp.Arp.Pdu.sender_proto (Some sender_hw)
                            ) ;
                            Log.(log st.logger Debug (lazy (Printf.sprintf2 "...concerning '%s' (I'm %a)" (hexstring_of_bitstring arp.Arp.Pdu.target_proto) (List.print (fun oc a -> String.print oc (hexstring_of_bitstring a.State.addr))) st.my_addresses))) ;
                            if List.exists (fun my_addr -> Bitstring.equals arp.Arp.Pdu.target_proto my_addr.State.addr) st.my_addresses then (
                                Log.(log st.logger Debug (lazy (Printf.sprintf "...It's about me!!"))) ;
                                if not !merge_flag then (
                                    BitHash.add st.arp_cache arp.Arp.Pdu.sender_proto (Some sender_hw) ;
                                    Log.(log st.logger Debug (lazy (Printf.sprintf "...adding %s->%s in ARP cache" (hexstring_of_bitstring arp.Arp.Pdu.sender_proto) (Addr.to_string sender_hw)))) ;
                                ) ;
                                if arp.Arp.Pdu.operation = Arp.Op.request then (
                                    Log.(log st.logger Debug (lazy (Printf.sprintf "...It's a request, let's reply!"))) ;
                                    let reply = Arp.Pdu.make_reply arp.Arp.Pdu.hw_type arp.Arp.Pdu.proto_type
                                                                   (st.mac :> bitstring) arp.Arp.Pdu.target_proto
                                                                   arp.Arp.Pdu.sender_hw arp.Arp.Pdu.sender_proto in
                                    send st Proto.arp sender_hw (Arp.Pdu.pack reply)
                                )
                            ) ;
                            (* Now that we may have gained knowledge, try to send the msg in waiting queue *)
                            (* TODO: timeout some? *)
                            Log.(log st.logger Debug (lazy (Printf.sprintf "...Do I have a msg waiting for '%s'?" (hexstring_of_bitstring arp.Arp.Pdu.sender_proto)))) ;
                            while BitHash.mem st.postponed arp.Arp.Pdu.sender_proto do
                                Log.(log st.logger Debug (lazy (Printf.sprintf "...Yes!! Let's send it!"))) ;
                                let msg = BitHash.find st.postponed arp.Arp.Pdu.sender_proto in
                                send st st.proto sender_hw msg ;
                                BitHash.remove st.postponed arp.Arp.Pdu.sender_proto
                            done
                        )
                    )
            ) else ( (* not for me, send to promisc function *)
                Log.(log st.logger Debug (lazy (Printf.sprintf "...not for me (for %s but I'm %s)!"
                    (Addr.to_string frame.Pdu.dst) (Addr.to_string st.mac)))) ;
                if Payload.bitlength frame.Pdu.payload > 0 then st.promisc (frame.Pdu.payload :> bitstring)
            )

    (** Creates an {!Eth.TRX.t}. *)
    let make (st : State.t) =
        Log.(log st.logger Debug (lazy (Printf.sprintf2 "Creating an eth TRX with addresses mac: %s, IPs: %a and gateways: %a"
            (Addr.to_string st.mac)
            (List.print State.print_my_address) st.my_addresses
            (List.print State.print_gw) st.gateways))) ;
        { ins = { write = tx st ;
                  set_read = fun f -> st.recv <- f } ;
          out = { write = rx st ;
                  set_read = fun f ->
                    Log.(log st.logger Debug (lazy "Connected!")) ;
                    st.connected <- true ;
                    st.emit <- f } }
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
    fun bits ->
        if !recording then (
            if !close_recording = None then (
                let fname = next_recorder_file () in
                (* We have to limit ourselves to Eth traffic because a pcap file,
                 * supposedly captured from a single spot, is limited to one DLT: *)
                let write, close = Pcap.(save ~dlt:Dlt.en10mb) fname in
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
let limited latency throughput =
    let next_avlb = ref (Clock.Time.o 0.) in
    (fun emit bits ->
        let min_start = Clock.Time.add (Clock.now ()) latency in
        let start = max min_start !next_avlb
        and num_bits = float_of_int (min (bitstring_length bits) 368) in
        let duration = max (Clock.Interval.usec 1.) (Clock.Interval.o (num_bits /. throughput)) in
        next_avlb := Clock.Time.add start duration ;
        Clock.at start emit bits)


(** {2 Ethernet cables}
 *
 * Point to point, faulty, and recordable in PCAP of type en10mb. *)

module Cable =
struct
    (** {3 State for a given cable} *)

    module State =
    struct
        type t = {  length : float ;  (** In meters. *)
                     delay : Clock.Interval.t ; (** Computed from the length *)
                error_rate : float ;  (** In faulty bits per transmitted bits *)
              success_rate : int ;    (** The inverse of the above *)
          mutable tot_bits : int ;    (** Both ways. *)
        mutable bit_shifts : int ;    (** Casualties in individual bits *)
           (** Boolean: true if from [a] to [b] (see [Cable.make] *)
              last_packets : (bool * bitstring) OrdArray.t ;
                    logger : Log.logger }

        let make ?(length=10.) ?(error_rate=0.) ?(history=10)
                 ?(logger=Log.default) () =
            let delay = Clock.Interval.sec (length /. 3e9)
            and success_rate = int_of_float (1. /. error_rate) in
            { length ; delay ; error_rate ; success_rate ; tot_bits = 0 ;
              bit_shifts = 0 ; logger ;
              last_packets = OrdArray.make history (false, empty_bitstring) }
    end

    let pass (st : State.t) dir bits =
        let len = bitstring_length bits in
        let prev_tot_bits = st.tot_bits in
        st.tot_bits <- st.tot_bits + len ;
        if prev_tot_bits > st.tot_bits then (
            Log.(log st.logger Warning (lazy "Bit count wrapped around 0")) ;
            (* For better stats: *)
            st.bit_shifts <- 0
        ) ;
        let bits =
            (* Beware that [int_of_float infinity] is 0: *)
            if st.success_rate > 0 then
                let shift_pos = Random.int st.success_rate in
                if shift_pos < len then (
                    st.bit_shifts <- st.bit_shifts + 1 ;
                    let bits' = bitstring_copy bits in
                    bitstring_shift shift_pos bits' ;
                    bits'
                ) else bits
            else bits in
        maybe_record bits ;
        OrdArray.prepend st.last_packets (dir, bits) ;
        bits

    (** Return a TRX representing an imperfect network link. *)
    let make (st : State.t) =
        let a_reader = ref (ignore_bits ~logger:st.logger)
        and b_reader = ref (ignore_bits ~logger:st.logger) in
        let ins_write bits =
            let bits = pass st true bits in
            Clock.delay st.delay !b_reader bits
        and ins_set_read f = a_reader := f
        and out_write bits =
            let bits = pass st false bits in
            Clock.delay st.delay !a_reader bits
        and out_set_read f = b_reader := f
        in
        { ins = { write = ins_write ; set_read = ins_set_read } ;
          out = { write = out_write ; set_read = out_set_read } }

    let connect t a b =
        a ==> t <==> b
end
