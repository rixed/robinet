(* vim:sw=4 ts=4 sts=4 expandtab
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

This is the module to look for if you want to fiddle with packets on a
one to one basis, for instance to fuzz some packet source, collect some
statistics on individual packets, search for some packets in a pcap file,
etc...

Due to the fact that every packet is considered in isolation, it can only
decode the simpler protocols for which all required data fits within a
single packet. In other words, it will not venture much deeper than TCP/UDP.


{1 Examples}

{2 Exploring a pcap file}

This module is more usefull from the toplevel [robinet.top].
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

Now we are interrested in all the packets attempting to connect port 80:

{[
# open Packet;;
# let s80 = enum_of "big_one.pcap" //
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

Let have a look at the first of them:

{[
# Enum.peek s80;;]}
{[- : Packet.Pdu.layer list option =
Some
 [Packet.Pdu.Pcap
   {Pcap.Pdu.source_name = "big_one.pcap"; Pcap.Pdu.caplen = 78;
    Pcap.Pdu.dlt = 1; Pcap.Pdu.ts = 1332451938.3774271;
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

*)
open Batteries
open Bitstring
open Tools

(** {1 (Un)Packing any packet} *)

(** Pack/Unpack the whole protocol stack that fits entirely within a packet.
 *
 * Each raw packet can be seen either as a [bitstring] or as a pile of layers (for
 * instance, DNS over UDP over IP over Ethernet). This Module will convert between these
 * two representations, without loss of information.
 * Typically you want to unpack then update, then pack back to [bitstring]. *)
module Pdu = struct
    (** Each layer can be of any one of these known protocol. *)
    type layer = Raw of bitstring (** the fallback when the actual protocol is not known *)
               | Dhcp of Dhcp.Pdu.t | Eth of Eth.Pdu.t | Arp  of Arp.Pdu.t
               | Ip   of Ip.Pdu.t   | Udp of Udp.Pdu.t | Tcp  of Tcp.Pdu.t
               | Dns  of Dns.Pdu.t  | Sll of Sll.Pdu.t | Vlan of Vlan.Pdu.t
               | Pcap of Pcap.Pdu.t
    (** A Pdu.t is a list of {!Packet.Pdu.layer}s, with the outer layer first for
     * a more natural presentation when printed. *)
    type t = layer list

    (** [pack pdu] converts the layer list back to a [bitstring]. *)
    let pack (t:t) =
        let new_payload bits = function
            | Raw _  -> Raw bits
            (* can you spot a pattern here? *)
            | Pcap p -> Pcap { p with Pcap.Pdu.payload = Payload.o bits }
            | Eth  p -> Eth  { p with Eth.Pdu.payload = Payload.o bits }
            | Sll  p -> Sll  { p with Sll.Pdu.payload = Payload.o bits }
            | Vlan p -> Vlan { p with Vlan.Pdu.payload = Payload.o bits }
            | Ip   p -> Ip   { p with Ip.Pdu.payload = Payload.o bits }
            | Udp  p -> Udp  { p with Udp.Pdu.payload = Payload.o bits }
            | Tcp  p -> Tcp  { p with Tcp.Pdu.payload = Payload.o bits }
            | x -> x in
        let pack_1 = function (* there ought to be a better way *)
            | Dhcp t -> Dhcp.Pdu.pack t | Eth t  -> Eth.Pdu.pack t
            | Arp t  -> Arp.Pdu.pack t  | Ip t   -> Ip.Pdu.pack t
            | Udp t  -> Udp.Pdu.pack t  | Tcp t  -> Tcp.Pdu.pack t
            | Dns t  -> Dns.Pdu.pack t  | Sll t  -> Sll.Pdu.pack t
            | Vlan t -> Vlan.Pdu.pack t | Pcap t -> Pcap.Pdu.pack t
            | Raw t -> t in
        let rec aux bits = function
            | [] -> Option.get bits
            | p :: ps ->
                (* bits, if set, is the new payload for p *)
                let p' = match bits with None -> p | Some b -> new_payload b p in
                aux (Some (pack_1 p')) ps
        in
        aux None (List.rev t)

    (** Convert a [bitstring] (from a Pcap.pdu) into a {!Packet.Pdu.t}.
     * @param dlt if the {e data link layer} is not Ethernet then you can change it here.
     *            The only other known {e DLT} is {!Pcap.dlt_linux_cooked}, though. *)
    let unpack pcap =
        let unpack_raw bits =
            if bitstring_is_empty bits then [] else [ Raw bits ] in
        let try_unpack unp do_t bits =
            match unp bits with None -> unpack_raw bits
                              | Some x -> do_t x in
        let unpack_dhcp = try_unpack Dhcp.Pdu.unpack (fun x -> [ Dhcp x]) in
        let unpack_dns  = try_unpack Dns.Pdu.unpack  (fun x -> [ Dns x]) in
        let unpack_arp  = try_unpack Arp.Pdu.unpack  (fun x -> [ Arp x]) in
        let unpack_ports src dst = (match src, dst with
                | 53, _ | _, 53 -> unpack_dns
                | 67, _ | _, 67 -> unpack_dhcp
                | _ -> unpack_raw) in
        let unpack_tcp = try_unpack Tcp.Pdu.unpack (fun tcp -> Tcp tcp ::
                        (if Payload.length tcp.Tcp.Pdu.payload > 0 then
                            (unpack_ports (tcp.Tcp.Pdu.src_port :> int)
                                          (tcp.Tcp.Pdu.dst_port :> int)
                                          (tcp.Tcp.Pdu.payload :> bitstring))
                        else [])) in
        let unpack_udp = try_unpack Udp.Pdu.unpack (fun udp -> Udp udp ::
                        (unpack_ports (udp.Udp.Pdu.src_port :> int)
                                      (udp.Udp.Pdu.dst_port :> int)
                                      (udp.Udp.Pdu.payload :> bitstring))) in
        let unpack_ip  = try_unpack Ip.Pdu.unpack (fun ip -> Ip ip ::
                    ((if ip.Ip.Pdu.proto = Ip.Proto.tcp then unpack_tcp
                      else if ip.Ip.Pdu.proto = Ip.Proto.udp then unpack_udp
                      else unpack_raw) (ip.Ip.Pdu.payload :> bitstring))) in
        let unpack_vlan = try_unpack Vlan.Pdu.unpack (fun vlan -> Vlan vlan ::
                    ((if vlan.Vlan.Pdu.proto = Arp.HwProto.ip4 then unpack_ip
                      else if vlan.Vlan.Pdu.proto = Arp.HwProto.arp then unpack_arp
                      else unpack_raw) (vlan.Vlan.Pdu.payload :> bitstring))) in
        let unpack_eth = try_unpack Eth.Pdu.unpack (fun eth -> Eth eth ::
                    ((if eth.Eth.Pdu.proto = Arp.HwProto.ip4 then unpack_ip
                      else if eth.Eth.Pdu.proto = Arp.HwProto.arp then unpack_arp
                      else if eth.Eth.Pdu.proto = Arp.HwProto.ieee8021q then unpack_vlan
                      else unpack_raw) (eth.Eth.Pdu.payload :> bitstring))) in
        let unpack_sll = try_unpack Sll.Pdu.unpack (fun sll -> Sll sll ::
                    ((if sll.Sll.Pdu.proto = Arp.HwProto.ip4 then unpack_ip
                      else if sll.Sll.Pdu.proto = Arp.HwProto.arp then unpack_arp
                      else unpack_raw) (sll.Sll.Pdu.payload :> bitstring)))
        in
        Pcap pcap :: ((if pcap.Pcap.Pdu.dlt = Pcap.dlt_linux_cooked then unpack_sll
                      else unpack_eth) (pcap.Pcap.Pdu.payload :> bitstring))

end

(** {1 Shorthands} *)

(** [Packet.enum_of filename] reads a pcap file and returns an [Enum.t] of {!Packet.Pdu.t}. *)
let enum_of fname = Pcap.enum_of fname /@ Pdu.unpack

(* Check that we manage to decode the actual content of the packets by counting the cnx establishments *)
(*$= enum_of & ~printer:string_of_int
    (enum_of "tests/someweb.pcap" // \
        (function _ :: _ :: _ :: Pdu.Tcp { Tcp.Pdu.flags = { Tcp.Pdu.syn = true ; \
                                                             Tcp.Pdu.ack = true ; _ } ; _ } :: _ -> true \
                | _ -> false) |> Enum.hard_count) 1
    (enum_of "tests/someweb_sll.pcap" // \
        (function _ :: _ :: _ :: Pdu.Tcp { Tcp.Pdu.flags = { Tcp.Pdu.syn = true ; \
                                                             Tcp.Pdu.ack = true ; _ } ; _ } :: _ -> true \
                | _ -> false) |> Enum.hard_count) 1
 *)

(* Check we manage to decode vlan tags *)
(*$= enum_of & ~printer:(Printf.sprintf2 "%a" (List.print Int.print))
    ((enum_of "tests/various_vlans.pcap" //@ \
        function _ :: _ :: Pdu.Vlan { Vlan.Pdu.id = id ; _ } :: _ -> Some id \
               | _ -> None) |> List.of_enum) [ 1 ; 2 ]
 *)
