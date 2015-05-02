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
open Bitstring

(* TODO: make this a parameter.
         make eth0 a command line arg *)
let iface = Pcap.openif "eth0"

let arp_query (src_eth : Eth.Addr.t) src_ip target_ip =
    let arp = Arp.Pdu.make_request Arp.HwType.eth Arp.HwProto.ip4
                                   (src_eth :> bitstring)
                                   ( Ip.Addr.to_bitstring src_ip)
                                   ( Ip.Addr.to_bitstring target_ip) in
    let eth = Eth.Pdu.make Arp.HwProto.arp src_eth Eth.Addr.broadcast (Arp.Pdu.pack arp) in
    Pcap.inject iface (Eth.Pdu.pack eth)

let wait_answer target_ip_bits =
    (* TODO: times out *)
    let rec aux () =
        let pdu = Pcap.sniff iface in
        (match Eth.Pdu.unpack (pdu.Pcap.Pdu.payload :> bitstring) with
        | None -> failwith "Cannot unpack Eth"
        | Some eth ->
            if eth.Eth.Pdu.proto <> Arp.HwProto.arp then aux () else
            (match Arp.Pdu.unpack (eth.Eth.Pdu.payload :> bitstring) with
            | None -> failwith "Cannot unpack ARP"
            | Some arp ->
                if arp.Arp.Pdu.operation <> Arp.Op.reply ||
                   not (Bitstring.equals arp.Arp.Pdu.sender_proto target_ip_bits) then aux ()
                else
                    arp.Arp.Pdu.sender_hw
            )
        )
    in aux ()

let main =
    let src_ip_str = ref "192.168.66.147" and src_eth_str = ref "01:23:45:67:89:ab" in
    let resolve_one target_ip_str =
        let target_ip      = Ip.Addr.of_string target_ip_str in
        let target_ip_bits = Ip.Addr.to_bitstring target_ip
        and src_eth        = Eth.Addr.of_string !src_eth_str
        and src_ip         = Ip.Addr.of_string !src_ip_str in
        arp_query src_eth src_ip target_ip ;
        let answer = Eth.Addr.o (wait_answer target_ip_bits) in
        Printf.printf "%s: %s\n" (Ip.Addr.to_string target_ip) (Eth.Addr.to_string answer)
    in
    Arg.parse [ "-src-ip",  Arg.Set_string src_ip_str,  "IP to use as the query sender" ;
                "-src-mac", Arg.Set_string src_eth_str, "MAC to use as the query sender" ]
              resolve_one
              "Send and receive ARP queries for some target IP"

