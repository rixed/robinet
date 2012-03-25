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
open Batteries
open Bitstring
open Tools

let debug = false

(* Pack/Unpack the whole protocol stack *)

module Pdu = struct
    type pkt = Raw of bitstring
             | Dhcp of Dhcp.Pdu.t | Eth of Eth.Pdu.t  | Arp of Arp.Pdu.t
             | Ip   of Ip.Pdu.t   | Udp of Udp.Pdu.t  | Tcp of Tcp.Pdu.t
             | Http of Http.Pdu.t | Dns of Dns.Pdu.t
    type t = pkt list (* with outer layer first for more natural presentation *)
    
    let new_payload bits = function
        | Raw _  -> Raw bits
        (* can you spot a pattern here? *)
        | Eth  p -> Eth { p with Eth.Pdu.payload = Payload.o bits }
        | Ip   p -> Ip  { p with Ip.Pdu.payload = Payload.o bits }
        | Udp  p -> Udp { p with Udp.Pdu.payload = Payload.o bits }
        | Tcp  p -> Tcp { p with Tcp.Pdu.payload = Payload.o bits }
        | x -> x

    let pack_1 = function (* there ought to be a better way *)
        | Dhcp t -> Dhcp.Pdu.pack t | Eth t -> Eth.Pdu.pack t
        | Arp t  -> Arp.Pdu.pack t  | Ip t  -> Ip.Pdu.pack t
        | Udp t  -> Udp.Pdu.pack t  | Tcp t -> Tcp.Pdu.pack t
        | Http t -> Http.Pdu.pack t | Dns t -> Dns.Pdu.pack t
        | Raw t  -> t
    let pack t =
        let rec aux bits = function
            | [] -> Option.get bits
            | p :: ps ->
                (* bits, if set, is the new payload for p *)
                let p' = match bits with None -> p | Some b -> new_payload b p in
                aux (Some (pack_1 p')) ps in
        aux None (List.rev t)

    let unpack_raw bits = if bitstring_is_empty bits then [] else [ Raw bits ]
    let try_unpack unp do_t bits =
        match unp bits with None -> unpack_raw bits
                          | Some x -> do_t x
    let unpack_http = try_unpack Http.Pdu.unpack (fun x -> [ Http x ])
    let unpack_dhcp = try_unpack Dhcp.Pdu.unpack (fun x -> [ Dhcp x])
    let unpack_dns  = try_unpack Dns.Pdu.unpack  (fun x -> [ Dns x])
    let unpack_arp  = try_unpack Arp.Pdu.unpack  (fun x -> [ Arp x])
    let unpack_ports src dst = (match src, dst with
            | 53, _ | _, 53 -> unpack_dns
            | 67, _ | _, 67 -> unpack_dhcp
            | 80, _ | _, 80 -> unpack_http
            | 8080, _ | _, 8080 -> unpack_http
            | _ -> unpack_raw)
    let unpack_tcp = try_unpack Tcp.Pdu.unpack (fun tcp -> Tcp tcp ::
                    (unpack_ports (tcp.Tcp.Pdu.src_port :> int)
                                  (tcp.Tcp.Pdu.dst_port :> int)
                                  (tcp.Tcp.Pdu.payload :> bitstring)))
    let unpack_udp = try_unpack Udp.Pdu.unpack (fun udp -> Udp udp ::
                    (unpack_ports (udp.Udp.Pdu.src_port :> int)
                                  (udp.Udp.Pdu.dst_port :> int)
                                  (udp.Udp.Pdu.payload :> bitstring)))
    let unpack_ip  = try_unpack Ip.Pdu.unpack (fun ip -> Ip ip ::
                ((if ip.Ip.Pdu.proto = Ip.Proto.tcp then unpack_tcp
                  else if ip.Ip.Pdu.proto = Ip.Proto.udp then unpack_udp
                  else unpack_raw) (ip.Ip.Pdu.payload :> bitstring)))
    let unpack_eth = try_unpack Eth.Pdu.unpack (fun eth -> Eth eth ::
                ((if eth.Eth.Pdu.proto = Arp.proto_ip4 then unpack_ip
                  else if eth.Eth.Pdu.proto = Arp.proto_arp then unpack_arp
                  else unpack_raw) (eth.Eth.Pdu.payload :> bitstring)))

    let unpack = unpack_eth
end

(* Shorthands *)

let of_pcap (_ts, bits) = Pdu.unpack bits

let enum_of fname = Pcap.enum_of fname /@ of_pcap

