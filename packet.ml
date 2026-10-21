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
(** Packet scrutiny

The purpose of this module is to help individual packet inquiry and
manipulation by offering an {e unpacked} view of a single packet.
It is not used when simulating a network.

This is the module to look for if you want to fiddle with packets a single at
a time, for instance to fuzz some packet source, collect some statistics on
individual packets, search for some packets in a pcap file, etc...

Due to the fact that every packet is considered in isolation, it can only
decode the simplest protocols for which all required data fits within a
single packet. In other words, it will not venture much deeper than TCP/UDP.


{1 Examples}

{2 Capturing local traffic}

Although you can manipulate the pcap interface directly and receive or inject
packets individually, it is often easier to just capture the whole stream of
packets for some time and then study them or save them in a pcap file.

An easy way to capture traffic is to use {[let packets = capture "em1";;]} and press
CTRL+C to terminate the capture and return to the toplevel with a list of
packets. During the capture a dot will be printed to the screen each time a packet
is captured.


{2 Exploring a pcap file}

This module is more useful from the toplevel [robinet.top].
Suppose you have this huge {{:http://www.tcpdump.org}pcap} file
of several tens of gigabyte, and we want to get some idea of what's
in there. We start with the obvious:

{[
# Pcap.infos_of "big_one.pcap";;]}
{[- : Pcap.infos =
{Pcap.filename = "big_one.pcap"; Pcap.data_link_type = 1l;
 Pcap.num_packets = 53993956; Pcap.data_size = 40756596469L;
 Pcap.start_time = 1323766040.99259496; Pcap.stop_time = 1323767137.688411}
]}

This will take a significant amount of time since the whole pcap file
must be scanned.

Now we are interested in all the packets attempting to connect port 80:

{[
# open Packet;;
# let s80 = enum_of_file "big_one.pcap" //
            function [_;_;_;_; Pdu.Tcp { Tcp.Pdu.dst_port = p ;
                                         Tcp.Pdu.flags = { Tcp.Pdu.syn = true ; _ } ;
                                         _ }] -> p = Tcp.Port.o 80
                   | _ -> false;;
val s80 : Packet.Pdu.layer list BatEnum.t = <abstr>
]}

This will return surprisingly fast, due to the lazy nature of Enum.filter.
Note that in this example, for brevity, I pattern match for Tcp in 5th
position only (since my big_file.pcap have a 802.1q tunnel between Ethernet
and IP).

Let us have a look at the first of them:

{[
# Enum.peek s80;;]}
{[- : Packet.Pdu.layer list option =
Some
 [Packet.Pdu.Pcap
   {Pcap.Pdu.source_name = "big_one.pcap"; Pcap.Pdu.caplen = 78;
    Pcap.Pdu.dlt = Ethernet (10Mb);
    Pcap.Pdu.ts = 22:32:18.38;
    Pcap.Pdu.payload = 78 bytes};
  Packet.Pdu.Eth
   {Eth.Pdu.src = Cisco:1d:6d:01;
    Eth.Pdu.dst = Cisco:4d:5c:01;
    Eth.Pdu.proto = Eth8021q;
    Eth.Pdu.payload = 64 bytes};
  Packet.Pdu.Vlan
   {Vlan.Pdu.prio = 0; Vlan.Pdu.cfi = false; Vlan.Pdu.id = 250;
    Vlan.Pdu.proto = IP; Vlan.Pdu.payload = 60 bytes};
  Packet.Pdu.Ip
   {Ip.Pdu.tos = 0; Ip.Pdu.tot_len = 60; Ip.Pdu.id = 25178;
    Ip.Pdu.dont_frag = true; Ip.Pdu.more_frags = false;
    Ip.Pdu.frag_offset = 0; Ip.Pdu.ttl = 62; Ip.Pdu.proto = tcp;
    Ip.Pdu.src = 193.51.52.41;
    Ip.Pdu.dst = 91.202.200.31; Ip.Pdu.options = [];
    Ip.Pdu.payload = 40 bytes};
  Packet.Pdu.Tcp
   {Tcp.Pdu.src_port = 44994; Tcp.Pdu.dst_port = www;
    Tcp.Pdu.seq_num = 0xC7A42126;
    Tcp.Pdu.ack_num = 0x00000000; Tcp.Pdu.win_size = 5840;
    Tcp.Pdu.flags = Syn; Tcp.Pdu.checksum = Some 38264;
    Tcp.Pdu.urg_ptr = 0;
    Tcp.Pdu.options =
     [Tcp.Pdu.Opt.Mss 1380; Tcp.Pdu.Opt.Nop; Tcp.Pdu.Opt.Nop;
      Tcp.Pdu.Opt.Timestamps (-1939775357l, 0l); Tcp.Pdu.Opt.Nop;
      Tcp.Pdu.Opt.Wscale 7];
    Tcp.Pdu.payload = empty}]
]}

Now imagine you want to edit a pcap to change the TCP source/dest port from 21 to 2121.

{[
# open Packet;;
# let old = Tcp.Port.o 21 and newp = Tcp.Port.o 2121 in
    enum_of_file "some.pcap" /@
    (function cap::eth::ip::Pdu.Tcp ({ Tcp.Pdu.dst_port = port ; _ } as tcp)::rest when port = old ->
               cap::eth::ip::Pdu.Tcp { tcp with Tcp.Pdu.dst_port = newp }::rest
           | cap::eth::ip::Pdu.Tcp ({ Tcp.Pdu.src_port = port ; _ } as tcp)::rest when port = old ->
               cap::eth::ip::Pdu.Tcp { tcp with Tcp.Pdu.src_port = newp }::rest
           | x -> x) |>
    to_file "changed.pcap" ;;
]}

*)
open Batteries
open SimTypes
open Bitstring
open Tools

(** {2 Captured packet} *)

(** Pack/Unpack the whole protocol stack that fits entirely within a packet.
 *
 * Each raw packet can be seen either as a [bitstring] or as a pile of layers (for
 * instance, DNS over UDP over IP over Ethernet). This Module will convert between these
 * two representations, without loss of information.
 * Typically you want to unpack then update, then pack back to [bitstring]. *)
module Pdu = struct
    (*$< Pdu *)
    (** Each layer can be of any one of these known protocol. *)
    type layer = Raw  of bitstring (** the fallback when the actual protocol is not known *)
               | Dhcp of Dhcp.Pdu.t | Eth  of Eth.Pdu.t | Arp  of Arp.Pdu.t
               | Ip   of Ip.Pdu.t   | Ip6  of Ip6.Pdu.t
               | Udp  of Udp.Pdu.t  | Tcp  of Tcp.Pdu.t
               | Dns  of Dns.Pdu.t  | Sll  of Sll.Pdu.t | Vlan of Vlan.Pdu.t
               | Icmp of Icmp.Pdu.t | Pcap of Pcap.Pdu.t

    (** Name of the protocol for that layer: *)
    let name_of_layer = function
        | Raw _ -> ""
        | Dhcp _ -> "Dhcp"
        | Eth _ -> "Eth"
        | Arp _ -> "Arp"
        | Ip _ -> "Ip"
        | Ip6 _ -> "Ip6"
        | Udp _ -> "Udp"
        | Tcp _ -> "Tcp"
        | Dns _ -> "Dns"
        | Sll _ -> "Sll"
        | Vlan _ -> "Vlan"
        | Icmp _ -> "Icmp"
        | Pcap _ -> "Pcap"

    let payload = function
        | Raw bits  -> bits
        | Pcap p -> (p.Pcap.Pdu.payload :> bitstring)
        | Eth  p -> (p.Eth.Pdu.payload :> bitstring)
        | Sll  p -> (p.Sll.Pdu.payload :> bitstring)
        | Vlan p -> (p.Vlan.Pdu.payload :> bitstring)
        | Ip   p -> (p.Ip.Pdu.payload :> bitstring)
        | Ip6  p -> (p.Ip6.Pdu.payload :> bitstring)
        | Udp  p -> (p.Udp.Pdu.payload :> bitstring)
        | Tcp  p -> (p.Tcp.Pdu.payload :> bitstring)
        | _ -> invalid_arg "Packet.Pdu.payload"

    (** A Pdu.t is a list of {!Packet.Pdu.layer}s, with the outer layer first for
     * a more natural presentation when printed. *)
    type t = layer list

    (* Packets are given from bottom to top but we want to represent the
     * protocol stack with higher level protocols first (as in "TCP/IP"). *)
    let rec names = function
        | [] ->
            ""
        | layer :: rest ->
            let rest = names rest in
            (if rest = "" then "" else rest ^"/") ^ name_of_layer layer

    (* TODO: Add a compact description of each layer *)
    let to_short_string t =
        names t

    (** [pack pdu] converts the layer list back to a {!Pcap.Pdu.t}.
     * It is of course much faster to just take the Pcap.Pdu.t from the
     * first [Pcap] layer (see [fast_pack]). *)
    let pack t =
        let new_payload bits = function
            | Raw _  -> Raw bits
            (* can you spot a pattern here? *)
            | Pcap p -> Pcap { p with Pcap.Pdu.payload = Payload.o bits }
            | Eth  p -> Eth  { p with Eth.Pdu.payload  = Payload.o bits }
            | Sll  p -> Sll  { p with Sll.Pdu.payload  = Payload.o bits }
            | Vlan p -> Vlan { p with Vlan.Pdu.payload = Payload.o bits }
            | Ip   p -> Ip   { p with Ip.Pdu.payload   = Payload.o bits }
            | Ip6  p -> Ip6  { p with Ip6.Pdu.payload  = Payload.o bits }
            | Udp  p -> Udp  { p with Udp.Pdu.payload  = Payload.o bits }
            | Tcp  p -> Tcp  { p with Tcp.Pdu.payload  = Payload.o bits }
            | x -> x in
        let pack_1 = function (* there ought to be a better way *)
            | Dhcp t -> Dhcp.Pdu.pack t | Eth t  -> Eth.Pdu.pack t
            | Arp t  -> Arp.Pdu.pack t  | Ip t   -> Ip.Pdu.pack t
            | Ip6 t  -> Ip6.Pdu.pack t
            | Udp t  -> Udp.Pdu.pack t  | Tcp t  -> Tcp.Pdu.pack t
            | Dns t  -> Dns.Pdu.pack t  | Sll t  -> Sll.Pdu.pack t
            | Vlan t -> Vlan.Pdu.pack t | Pcap t -> Pcap.Pdu.pack t
            | Icmp t -> Icmp.Pdu.pack t | Raw t  -> t in
        let rec aux bits = function
            | [] -> Option.get bits
            | p :: ps ->
                (* bits, if set, is the new payload for p *)
                let p' = match bits with None -> p | Some b -> new_payload b p in
                aux (Some (pack_1 p')) ps in
        match t with
        | Pcap pcap :: rest ->
            let pld = aux None (List.rev rest) in
            { pcap with Pcap.Pdu.payload = Payload.o pld }
        | _ ->
            should_not_happen ()

    let fast_pack = function
        | Pcap pcap :: _ ->
            pcap
        | _ ->
            should_not_happen ()

    (** Converts a {!Pcap.Pdu.t} into a {!Packet.Pdu.t}. *)
    let unpack pcap =
        let unpack_raw bits =
            if bitstring_is_empty bits then [] else [ Raw bits ] in
        let try_unpack unp do_t bits =
            match unp bits with Error _ -> unpack_raw bits
                              | Ok x    -> do_t x in
        let unpack_dhcp = try_unpack Dhcp.Pdu.unpack (fun x -> [ Dhcp x]) in
        let unpack_dns  = try_unpack Dns.Pdu.unpack  (fun x -> [ Dns x]) in
        let unpack_icmp = try_unpack Icmp.Pdu.unpack (fun x -> [ Icmp x]) in
        let unpack_arp  = try_unpack Arp.Pdu.unpack  (fun x -> [ Arp x]) in
        let unpack_ports src dst = (match src, dst with
                | 53, _ | _, 53 -> unpack_dns
                | 67, _ | _, 67 -> unpack_dhcp
                | _ -> unpack_raw) in
        let unpack_tcp = try_unpack Tcp.Pdu.unpack (fun tcp -> Tcp tcp ::
                        (if Payload.length tcp.Tcp.Pdu.payload > 0 then
                             unpack_raw (tcp.Tcp.Pdu.payload :> bitstring)
                        else [])) in
        let unpack_udp = try_unpack Udp.Pdu.unpack (fun udp -> Udp udp ::
                        (unpack_ports (udp.Udp.Pdu.src_port :> int)
                                      (udp.Udp.Pdu.dst_port :> int)
                                      (udp.Udp.Pdu.payload :> bitstring))) in
        let unpack_ip6 = try_unpack Ip6.Pdu.unpack (fun ip -> Ip6 ip ::
                    ((if ip.Ip6.Pdu.proto = Ip.Proto.tcp then unpack_tcp
                      else if ip.Ip6.Pdu.proto = Ip.Proto.udp then unpack_udp
                      else if ip.Ip6.Pdu.proto = Ip.Proto.icmp then unpack_icmp
                      else unpack_raw) (ip.Ip6.Pdu.payload :> bitstring))) in
        let unpack_ip = try_unpack Ip.Pdu.unpack (fun ip -> Ip ip ::
                    ((if ip.Ip.Pdu.proto = Ip.Proto.tcp then unpack_tcp
                      else if ip.Ip.Pdu.proto = Ip.Proto.udp then unpack_udp
                      else if ip.Ip.Pdu.proto = Ip.Proto.icmp then unpack_icmp
                      else if ip.Ip.Pdu.proto = Ip.Proto.ipv6 then unpack_ip6
                      else unpack_raw) (ip.Ip.Pdu.payload :> bitstring))) in
        let unpack_vlan = try_unpack Vlan.Pdu.unpack (fun vlan -> Vlan vlan ::
                    ((if vlan.Vlan.Pdu.proto = Arp.HwProto.ip4 then unpack_ip
                      else if vlan.Vlan.Pdu.proto = Arp.HwProto.arp then unpack_arp
                      else unpack_raw) (vlan.Vlan.Pdu.payload :> bitstring))) in
        let unpack_eth = try_unpack Eth.Pdu.unpack (fun eth -> Eth eth ::
                    ((if eth.Eth.Pdu.proto = Arp.HwProto.ip4 then unpack_ip
                      else if eth.Eth.Pdu.proto = Arp.HwProto.ip6 then unpack_ip6
                      else if eth.Eth.Pdu.proto = Arp.HwProto.arp then unpack_arp
                      else if eth.Eth.Pdu.proto = Arp.HwProto.ieee8021q then unpack_vlan
                      else unpack_raw) (eth.Eth.Pdu.payload :> bitstring))) in
        let unpack_sll = try_unpack Sll.Pdu.unpack (fun sll -> Sll sll ::
                    ((if sll.Sll.Pdu.proto = Arp.HwProto.ip4 then unpack_ip
                      else if sll.Sll.Pdu.proto = Arp.HwProto.ip6 then unpack_ip6
                      else if sll.Sll.Pdu.proto = Arp.HwProto.arp then unpack_arp
                      else unpack_raw) (sll.Sll.Pdu.payload :> bitstring)))
        in
        Pcap pcap :: ((if pcap.Pcap.Pdu.dlt = Pcap.Dlt.linux_cooked then unpack_sll
                      else unpack_eth) (pcap.Pcap.Pdu.payload :> bitstring))

    let fold_ips t f u =
        List.fold_left (fun u -> function
            | Raw _ | Eth _ | Udp _ | Tcp _ | Sll _ | Vlan _ | Pcap _ ->
                u
            | Dhcp (pdu : Dhcp.Pdu.t) ->
                f pdu.ciaddr u |>
                f pdu.yiaddr |>
                f pdu.siaddr |>
                f pdu.giaddr
            | Arp (pdu : Arp.Pdu.t) ->
                if pdu.proto_type = Arp.HwProto.ip4 ||
                   pdu.proto_type = Arp.HwProto.ip6
                then
                    let try_bitstring bs u =
                        try f (Ip.Addr.of_bitstring bs) u
                        with _ -> u in
                    try_bitstring pdu.sender_proto u |>
                    try_bitstring pdu.target_proto
                else
                    u
            | Ip (pdu : Ip.Pdu.t) ->
                f pdu.src u |>
                f pdu.dst
            | Ip6 (pdu : Ip6.Pdu.t) ->
                f pdu.src u |>
                f pdu.dst
            | Dns (pdu : Dns.Pdu.t) ->
                let open Dns.QType in
                let fold_rrs lst u =
                    List.fold_left (fun u (_, typ, _, _, bytes) ->
                        if typ = a || typ = aaaa then
                            match Ip.Addr.of_bytes bytes with
                            | exception _ -> u
                            | ip -> f ip u
                        else u
                    ) u lst in
                (* Collect IPs from PTR questions: *)
                List.fold_left (fun u (s, typ, _) ->
                    if typ = ptr then
                        match Ip.Addr.of_string s with
                        | exception _ -> u
                        | ip -> f ip u
                    else u
                ) u pdu.questions |>
                (* Then collect IPs from answers: *)
                fold_rrs pdu.answer_rrs |>
                fold_rrs pdu.authority_rrs |>
                fold_rrs pdu.additional_rrs
            | Icmp (pdu : Icmp.Pdu.t) ->
                (match pdu with
                | { payload = Header { pld ; _ } ; _ } ->
                    (match Ip.Pdu.unpack (pld :> bitstring) with
                    | Ok (ip : Ip.Pdu.t) ->
                        f ip.src u |> f ip.dst
                    | _ ->
                        (match Ip6.Pdu.unpack (pld :> bitstring) with
                        | Ok (ip : Ip6.Pdu.t) ->
                            f ip.src u |> f ip.dst
                        | _ ->
                            u))
                | _ ->
                    u)
        ) u t

    (** {2 A packet, in the kind language}
     *
     * What a packet is is not a fixed shape -- which layers it has follows
     * from what is in it -- so its kind is computed for the packet at hand,
     * layer by layer, and travels beside its value exactly as a property's
     * kind travels beside its own. Nothing has to describe every packet there
     * could be.
     *
     * Each layer is one field of a record, drawn one under the next: the
     * layers of a packet are what a reader unwraps, and each of them opens
     * into its own fields. *)

    (* What a PDU of each protocol is made of, by the name that protocol's
     * layer goes by (see [name_of_layer]). A protocol's kind says nothing
     * about any one packet, so this is all anybody needs to draw the fields of
     * a layer -- or of one that is not there yet, which is what a packet
     * generator is editing (see {!Synth}). "Data" is the fallback layer: bytes
     * nothing claimed. *)
    let kinds_of_protocols =
        [ "Data", Bytes ;
          "Dhcp", Dhcp.Pdu.kind ;
          "Eth", Eth.Pdu.kind ;
          "Arp", Arp.Pdu.kind ;
          "Ip", Ip.Pdu.kind ;
          "Ip6", Ip6.Pdu.kind ;
          "Udp", Udp.Pdu.kind ;
          "Tcp", Tcp.Pdu.kind ;
          "Dns", Dns.Pdu.kind ;
          "Sll", Sll.Pdu.kind ;
          "Vlan", Vlan.Pdu.kind ;
          "Icmp", Icmp.Pdu.kind ;
          "Pcap", Pcap.Pdu.kind ]

    let kind_of_protocol name = List.assoc_opt name kinds_of_protocols

    let kind_of_layer = function
        | Raw _ -> Bytes
        | Dhcp _ -> Dhcp.Pdu.kind
        | Eth  _ -> Eth.Pdu.kind
        | Arp  _ -> Arp.Pdu.kind
        | Ip   _ -> Ip.Pdu.kind
        | Ip6  _ -> Ip6.Pdu.kind
        | Udp  _ -> Udp.Pdu.kind
        | Tcp  _ -> Tcp.Pdu.kind
        | Dns  _ -> Dns.Pdu.kind
        | Sll  _ -> Sll.Pdu.kind
        | Vlan _ -> Vlan.Pdu.kind
        | Icmp _ -> Icmp.Pdu.kind
        | Pcap _ -> Pcap.Pdu.kind

    (* Every layer a packet can be made of is a protocol that can be named, and
       every name is one [kind_of_protocol] answers for. *)
    (*$T kind_of_protocol
      Pcap.enum_of_file "tests/various_vlans.pcap" /@ unpack |> \
      Enum.for_all (List.for_all (fun l -> \
          kind_of_protocol (match name_of_layer l with "" -> "Data" | n -> n) = \
          Some (kind_of_layer l)))
     *)

    let json_of_layer = function
        | Raw bits -> Widget.json_of_bytes bits
        | Dhcp p -> Dhcp.Pdu.to_json p
        | Eth  p -> Eth.Pdu.to_json p
        | Arp  p -> Arp.Pdu.to_json p
        | Ip   p -> Ip.Pdu.to_json p
        | Ip6  p -> Ip6.Pdu.to_json p
        | Udp  p -> Udp.Pdu.to_json p
        | Tcp  p -> Tcp.Pdu.to_json p
        | Dns  p -> Dns.Pdu.to_json p
        | Sll  p -> Sll.Pdu.to_json p
        | Vlan p -> Vlan.Pdu.to_json p
        | Icmp p -> Icmp.Pdu.to_json p
        | Pcap p -> Pcap.Pdu.to_json p

    (* What each layer is called, which is a field name and so must be its own:
     * a packet carrying the same protocol twice -- a VLAN within a VLAN --
     * numbers the second. The fallback layer has no protocol to be named by
     * and is named for what it is.
     *
     * A packet of no layers at all is one of a single empty one: [unpack]
     * never returns one, always giving the pcap pseudo-header at least, but a
     * list is a list and a record must have a field. *)
    let field_names t =
        let seen = Hashtbl.create 8 in
        List.map (fun layer ->
            let name =
                match name_of_layer layer with "" -> "Data" | n -> n in
            let n = (Hashtbl.find_opt seen name |? 0) + 1 in
            Hashtbl.replace seen name n ;
            if n = 1 then name else Printf.sprintf "%s %d" name n
        ) t

    let layers = function
        | [] -> [ Raw empty_bitstring ]
        | t -> t

    let kind_of t =
        let t = layers t in
        List.map2 (fun name layer -> name, kind_of_layer layer)
                  (field_names t) t |>
        Array.of_list |> Widget.record

    let to_json t =
        let t = layers t in
        `Assoc (List.map2 (fun name layer -> name, json_of_layer layer)
                          (field_names t) t)

    (* Every packet of a capture of real traffic, which is a good many shapes
       of packet and every layer these two halves know how to describe. *)
    (*$T kind_of
      Pcap.enum_of_file "tests/someweb.pcap" /@ unpack |> \
      Enum.for_all (fun p -> Widget.check_value (kind_of p) (to_json p) = ())
      Pcap.enum_of_file "tests/someweb_sll.pcap" /@ unpack |> \
      Enum.for_all (fun p -> Widget.check_value (kind_of p) (to_json p) = ())
      Pcap.enum_of_file "tests/various_vlans.pcap" /@ unpack |> \
      Enum.for_all (fun p -> Widget.check_value (kind_of p) (to_json p) = ())
      kind_of [] = Record [| "Data", Bytes |]
     *)

    (** Packets as text, each printer for its own reader. A printer takes
     * the layers outermost first, as [unpack] or {!of_frame} give them, and
     * skips any [Pcap] layer. *)
    module Printer =
    struct
        (*$< Printer *)
        let without_pcap = List.filter (function Pcap _ -> false | _ -> true)

        let str bits = string_of_bitstring bits
        let pld (p : Payload.t) = str (p :> bitstring)

        let ip_of_bits bits =
            try Ip.Addr.to_dotted_string (Ip.Addr.of_bitstring bits)
            with _ -> "?"

        (* As tcpdump has them, ACK last: *)
        let tcp_flags (f : Tcp.Pdu.flags) =
            (if f.syn then "S" else "") ^ (if f.fin then "F" else "") ^
            (if f.rst then "R" else "") ^ (if f.psh then "P" else "") ^
            (if f.urg then "U" else "") ^ (if f.ack then "." else "")

        (** A summary in the manner of tcpdump, addresses and ports first. *)
        let oneline t =
            let b = Stdlib.Buffer.create 80 in
            let add fmt = Printf.bprintf b fmt in
            let rec layer_3 = function
                | Vlan v :: rest ->
                    add "vlan %d " v.Vlan.Pdu.id ;
                    layer_3 rest
                | Arp a :: _ ->
                    let tha = ip_of_bits a.Arp.Pdu.target_proto
                    and sha = ip_of_bits a.sender_proto in
                    if a.operation = Arp.Op.request then
                        add "ARP who-has %s tell %s" tha sha
                    else if a.operation = Arp.Op.reply then
                        add "ARP %s is-at %s" sha
                            (Eth.Addr.to_hexstring (Eth.Addr.o a.sender_hw))
                    else
                        add "ARP %s" (Arp.Op.to_string a.operation)
                | Ip ip :: rest ->
                    let fragment = ip.Ip.Pdu.more_frags || ip.frag_offset > 0 in
                    if ip.frag_offset > 0 then
                        add "%s > %s IP proto %d len %d"
                            (Ip.Addr.to_dotted_string ip.src)
                            (Ip.Addr.to_dotted_string ip.dst)
                            (ip.proto :> int) (Payload.length ip.payload)
                    else
                        layer_4 ip.src ip.dst ip.proto ip.payload rest ;
                    if fragment then
                        add " (frag id %d off %d%s)" ip.id (ip.frag_offset * 8)
                            (if ip.more_frags then "+" else "") ;
                    if ip.options <> [] then
                        add " (options %s)" (Ip.Pdu.Opt.list_to_string ip.options)
                | Ip6 ip :: rest ->
                    layer_4 ip.Ip6.Pdu.src ip.dst ip.proto ip.payload rest
                | Eth e :: _ ->
                    (* Only when what it carries could not be decoded: *)
                    add "%s > %s proto 0x%04x len %d"
                        (Eth.Addr.to_hexstring e.Eth.Pdu.src)
                        (Eth.Addr.to_hexstring e.dst)
                        (e.proto :> int) (Payload.length e.payload)
                | _ ->
                    add "?"
            and layer_4 src dst proto payload rest =
                let src = Ip.Addr.to_dotted_string src
                and dst = Ip.Addr.to_dotted_string dst in
                (match rest with
                | Udp u :: _ ->
                    add "%s:%d > %s:%d UDP len %d" src (u.Udp.Pdu.src_port :> int)
                        dst (u.dst_port :> int) (Payload.length u.payload)
                | Tcp t :: _ ->
                    add "%s:%d > %s:%d TCP [%s] seq %lu ack %lu win %d"
                        src (t.Tcp.Pdu.src_port :> int) dst (t.dst_port :> int)
                        (tcp_flags t.flags) (t.seq_num :> int32)
                        (t.ack_num :> int32) t.win_size ;
                    if t.options <> [] then
                        add " options [%s]" (Tcp.Pdu.Opt.list_to_string t.options) ;
                    add " len %d" (Payload.length t.payload)
                | Icmp i :: _ ->
                    add "%s > %s ICMP %s" src dst
                        (Icmp.MsgType.to_string i.Icmp.Pdu.msg_type) ;
                    (match i.payload with
                    | Icmp.Pdu.Ids (id, seq, p) ->
                        add " id %d seq %d len %d" id seq (Payload.length p)
                    | _ -> ())
                | _ ->
                    add "%s > %s IP proto %d len %d" src dst (proto :> int)
                        (Payload.length payload)) ;
                (* What the transport carries, when it is known: *)
                match rest with
                | _ :: (Dns _ | Dhcp _ as l) :: _ -> add " %s" (name_of_layer l)
                | _ -> () in
            (match without_pcap t with
            | (Eth _ :: (Vlan _ | Arp _ | Ip _ | Ip6 _) :: _ as l)
            | (Sll _ :: (Arp _ | Ip _ | Ip6 _) :: _ as l) ->
                layer_3 (List.tl l)
            | l -> layer_3 l) ;
            Stdlib.Buffer.contents b

        (*$= oneline & ~printer:identity
          "10.0.0.1:1000 > 1.2.3.4:53 UDP len 2" \
            (oneline (of_frame (Eth.Pdu.(pack (make Eth.Proto.ip4 \
                (Eth.Addr.of_string "02:00:00:00:00:01") \
                (Eth.Addr.of_string "02:00:00:00:00:02") \
                (Ip.Pdu.(pack (make Ip.Proto.udp (Ip.Addr.of_string "10.0.0.1") \
                    (Ip.Addr.of_string "1.2.3.4") \
                    (Udp.Pdu.(pack (make ~src_port:(Udp.Port.o 1000) \
                        ~dst_port:(Udp.Port.o 53) \
                        (Bitstring.bitstring_of_string "hi"))))))))))))
          "10.0.0.1 > 1.2.3.4 IP proto 99 len 1 (options RR ptr=4 0.0.0.0, NOP)" \
            (oneline (of_frame (Eth.Pdu.(pack (make Eth.Proto.ip4 \
                (Eth.Addr.of_string "02:00:00:00:00:01") \
                (Eth.Addr.of_string "02:00:00:00:00:02") \
                (Ip.Pdu.(pack (make ~options:Opt.[ Rr (4, [ Ip.Addr.zero ]) ; Nop ] \
                    (Ip.Proto.o 99) (Ip.Addr.of_string "10.0.0.1") \
                    (Ip.Addr.of_string "1.2.3.4") \
                    (Bitstring.bitstring_of_string "x")))))))))
          "10.0.0.1:1000 > 1.2.3.4:80 TCP [S] seq 1 ack 0 win 1024 options [mss 1460,nop,wscale 7] len 0" \
            (oneline (of_frame (Eth.Pdu.(pack (make Eth.Proto.ip4 \
                (Eth.Addr.of_string "02:00:00:00:00:01") \
                (Eth.Addr.of_string "02:00:00:00:00:02") \
                (Ip.Pdu.(pack (make Ip.Proto.tcp (Ip.Addr.of_string "10.0.0.1") \
                    (Ip.Addr.of_string "1.2.3.4") \
                    (Tcp.Pdu.(pack (make ~src_port:(Tcp.Port.o 1000) ~syn:true \
                        ~seq_num:(Tcp.SeqNum.o 1l) \
                        ~options:Opt.[ Mss 1460 ; Nop ; Wscale 7 ] \
                        Bitstring.empty_bitstring)))))))))))
          "02:00:00:00:00:01 > FF:FF:FF:FF:FF:FF proto 0x88b5 len 3" \
            (oneline (of_frame (Eth.Pdu.(pack (make (Eth.Proto.o 0x88b5) \
                (Eth.Addr.of_string "02:00:00:00:00:01") Eth.Addr.broadcast \
                (Bitstring.bitstring_of_string "abc"))))))
          "?" (oneline [])
         *)

        (** What the tests show of a frame: Ethernet and IP addresses, IP
         * TTL and DF flag, ports, ICMP type, code and ids, TCP flags, and the
         * payloads; and "bad-checksum" after any layer whose checksum is
         * wrong. *)
        let for_tests t =
            let b = Stdlib.Buffer.create 80 in
            let add fmt = Printf.bprintf b fmt in
            (match without_pcap t with
            | Eth e :: rest ->
                add "%s>%s" (Eth.Addr.to_hexstring e.Eth.Pdu.src)
                    (Eth.Addr.to_hexstring e.dst) ;
                (* A layer's bits are the payload of the one below it: *)
                let bits = (e.payload :> bitstring) in
                if e.proto = Eth.Proto.arp then add " ARP"
                else if e.proto <> Eth.Proto.ip4 then
                    add " proto=0x%x %S" (e.proto :> int) (str bits)
                else (match rest with
                | Ip ip :: rest ->
                    add " IP %s>%s ttl=%d" (Ip.Addr.to_dotted_string ip.Ip.Pdu.src)
                        (Ip.Addr.to_dotted_string ip.dst) ip.ttl ;
                    if ip.dont_frag then add " df" ;
                    if ip.options <> [] then
                        add " opts=[%s]" (Ip.Pdu.Opt.list_to_string ip.options) ;
                    if sum (takebits (8 * Ip.Pdu.hdr_len ip) bits) <> 0 then
                        add " bad-checksum" ;
                    let l4 = (ip.payload :> bitstring) in
                    let check_l4 () =
                        if sum_list [ Ip.Pdu.pseudo_header ip () ; l4 ] <> 0 then
                            add " bad-checksum" in
                    if ip.proto = Ip.Proto.udp then (
                        match rest with
                        | Udp u :: _ ->
                            add " UDP %d>%d %S" (u.Udp.Pdu.src_port :> int)
                                (u.dst_port :> int) (pld u.payload) ;
                            check_l4 ()
                        | _ -> add " ?"
                    ) else if ip.proto = Ip.Proto.icmp then (
                        match rest with
                        | Icmp i :: _ ->
                            let typ, code = (i.Icmp.Pdu.msg_type :> int * int) in
                            add " ICMP %d/%d" typ code ;
                            (match i.payload with
                            | Icmp.Pdu.Ids (id, seq, p) ->
                                add " id=%d seq=%d %S" id seq (pld p)
                            | Icmp.Pdu.Header { mtu ; pld = p ; _ } ->
                                add " mtu=%d %S" mtu (pld p)
                            | _ -> add " ?") ;
                            if sum l4 <> 0 then add " bad-checksum"
                        | _ -> add " ?"
                    ) else if ip.proto = Ip.Proto.tcp then (
                        match rest with
                        | Tcp t :: _ ->
                            add " TCP %d>%d %s" (t.Tcp.Pdu.src_port :> int)
                                (t.dst_port :> int) (Tcp.Pdu.string_of_flags t.flags) ;
                            if t.options <> [] then
                                add " opts=[%s]" (Tcp.Pdu.Opt.list_to_string t.options) ;
                            add " %S" (pld t.payload) ;
                            check_l4 ()
                        | _ -> add " ?"
                    ) else add " proto=%d %S" (ip.proto :> int) (str l4)
                | _ -> add " ?")
            | _ -> add "?") ;
            Stdlib.Buffer.contents b
        (*$>*)
    end
    (*$>*)
end

(** {2 Shorthands} *)

(** [of_frame bits] is what a frame off a wire is made of, outermost layer
 * first.
 *
 * [Pdu.unpack] reads what came out of a capture file and therefore begins with
 * a [Pcap] layer; a frame that came off a cable has no such thing around it,
 * so one is put there to unpack with and taken off again. The timestamp given
 * to it is never read: what is wanted here is the layers below it. *)
let of_frame bits =
    match Pdu.unpack (Pcap.Pdu.make "" (Clock.Wall.now ()) bits) with
    | _pcap :: layers -> layers
    | [] -> []

(** A frame in a few words: the protocols it is made of, innermost first --
 * "Icmp/Ip/Eth". What the administration interface shows for a packet before
 * the reader asks to see more of it, and what it sets
 * {!Widget.describe_packet} to. *)
let describe bits =
    Pdu.to_short_string (of_frame bits)

(** [Packet.enum_of_file filename] reads a pcap file and returns an [Enum.t] of {!Packet.Pdu.t}. *)
let enum_of_file fname = Pcap.enum_of_file fname /@ Pdu.unpack

(* Check that we manage to decode the actual content of the packets by counting the cnx establishments *)
(*$= enum_of_file & ~printer:string_of_int
    (enum_of_file "tests/someweb.pcap" // \
        (function _ :: _ :: _ :: Pdu.Tcp { Tcp.Pdu.flags = { Tcp.Pdu.syn = true ; \
                                                             Tcp.Pdu.ack = true ; _ } ; _ } :: _ -> true \
                | _ -> false) |> Enum.hard_count) 1
    (enum_of_file "tests/someweb_sll.pcap" // \
        (function _ :: _ :: _ :: Pdu.Tcp { Tcp.Pdu.flags = { Tcp.Pdu.syn = true ; \
                                                             Tcp.Pdu.ack = true ; _ } ; _ } :: _ -> true \
                | _ -> false) |> Enum.hard_count) 1
 *)

(* Check we manage to decode vlan tags *)
(*$= enum_of_file & ~printer:(IO.to_string (List.print Int.print))
    ((enum_of_file "tests/various_vlans.pcap" //@ \
        function _ :: _ :: Pdu.Vlan { Vlan.Pdu.id = id ; _ } :: _ -> Some id \
               | _ -> None) |> List.of_enum) [ 1 ; 2 ]
 *)

(** [Packet.to_file filename e] write the enumeration of {!Packet.Pdu.t} into the given file. *)
let to_file fname e = Enum.map Pdu.pack e |> Pcap.file_of_enum fname

let capture sim ?promisc ?filter ifname =
    let widget = Widget.make ~parent:sim.root ifname in
    let iface = Pcap.open_iface ~widget ?promisc ?filter ifname in
    let pkts = ref [] in
    let rec aux () =
        if not (Simulation.is_running sim) then List.rev !pkts else
        let pkt = Pcap.sniff iface.handler in
        pkts := pkt :: !pkts ;
        Printf.printf ".%!" ;
        aux () in
    Simulation.with_trapped [Sys.sigint] aux
