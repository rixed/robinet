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
Note that in this exemple, for brevety, I pattern match for Tcp in 5th
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
    Ip.Pdu.dst = 91.202.200.31; Ip.Pdu.options = ;
    Ip.Pdu.payload = 40 bytes};
  Packet.Pdu.Tcp
   {Tcp.Pdu.src_port = 44994; Tcp.Pdu.dst_port = www;
    Tcp.Pdu.seq_num = 0xC7A42126;
    Tcp.Pdu.ack_num = 0x00000000; Tcp.Pdu.win_size = 5840;
    Tcp.Pdu.flags = Syn; Tcp.Pdu.checksum = Some 38264;
    Tcp.Pdu.urg_ptr = 0;
    Tcp.Pdu.options =
     02 04 05 64 01 01 08 0a - 8c 61 60 83 00 00 00 00  ...d.....a......
     01 03 03 07                                        ....
     ;
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

    (* TODO: to_short_string, for all Pdu types, with a compact description
     * of each layer, so we can print the packet in one line *)

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

    (** Converts a {!Pcap.pdu.t} into a {!Packet.Pdu.t}. *)
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
                      else if sll.Sll.Pdu.proto = Arp.HwProto.arp then unpack_arp
                      else unpack_raw) (sll.Sll.Pdu.payload :> bitstring)))
        in
        Pcap pcap :: ((if pcap.Pcap.Pdu.dlt = Pcap.Dlt.linux_cooked then unpack_sll
                      else unpack_eth) (pcap.Pcap.Pdu.payload :> bitstring))

end

(** {2 Shorthands} *)

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

let capture ?promisc ?filter ifname =
    let iface = Pcap.openif ?promisc ?filter ifname in
    let pkts = ref [] in
    let rec aux () =
        if not !Clock.continue then List.rev !pkts else
        let pkt = Pcap.sniff iface in
        pkts := pkt :: !pkts ;
        Printf.printf ".%!" ;
        aux () in
    Clock.with_trapped [Sys.sigint] aux
