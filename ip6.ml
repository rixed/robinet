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
 * Everything related to IPv4 packets: (un)packing, addresses, transceiver...
 *
 * TODO: Some usual IP options should be understood.
 *)
open Batteries
open Bitstring
open Tools

let debug = false

(** {2 IPv6 Packet} *)

(** (Un)Packing an IPv6 packet. *)

module Pdu = struct
    (*$< Pdu *)

    type t = { ttl : int ; proto : Ip.Proto.t ;
               diff_serv : int ; ecn : int ; flow_label : int ;
               src : Ip.Addr.t ; dst : Ip.Addr.t ;
               payload : Payload.t }

    let make ?(ttl=64) ?(diff_serv=0) ?(ecn=0) ?(flow_label=0)
             proto src dst payload =
        { ttl ; proto ; diff_serv ; ecn ; flow_label ; src ; dst ;
          payload = Payload.o payload }

    let random () =
        make (Ip.Proto.random ())
             (Ip.Addr.random ~v4:false ())
             (Ip.Addr.random ~v4:false ())
             (randbs (Random.int 10 + 20))

    let pseudo_header t () =
        (BITSTRING {
            Ip.Addr.to_bitstring t.src : 128 : bitstring ;
            Ip.Addr.to_bitstring t.dst : 128 : bitstring ;
            bytelength (t.payload :> bitstring) : 16 ;
            0 : 24 ;
            (t.proto :> int) : 8 })

    let pack t =
        let header = (BITSTRING {
            6 : 4 ; t.diff_serv : 6 ; t.ecn : 2 ; t.flow_label : 20 ;
            bytelength (t.payload :> bitstring) : 16 ;
            (t.proto :> int) : 8 ; t.ttl : 8 ;
            Ip.Addr.to_bitstring t.src : 128 : bitstring ;
            Ip.Addr.to_bitstring t.dst : 128 : bitstring })
        (* must we patch some checksum? *)
        and payload =
            let fix_udp_checksum = function 0 -> 0xffff | x -> x in (* As per rfc2460, 8.1 *)
            if t.proto = Ip.Proto.tcp then Ip.Pdu.patch_checksum 128 (pseudo_header t) t.payload
            else if t.proto = Ip.Proto.udp then Ip.Pdu.patch_checksum 48 (pseudo_header t) ~fixit:fix_udp_checksum t.payload
            else if t.proto = Ip.Proto.icmpv6 then Ip.Pdu.patch_checksum 16 (pseudo_header t) t.payload
            else t.payload in
        concat [ header ; (payload :> bitstring) ]

    let unpack bits = bitmatch bits with
        | { 6 : 4 ; diff_serv : 6 ; ecn : 2 ; flow_label : 20 ;
            payload_len : 16 ; proto : 8 ; ttl : 8 ;
            src : 128 : bitstring ; dst : 128 : bitstring ;
            payload : payload_len*8 : bitstring } ->
            Some { diff_serv ; ecn ; flow_label ;
                   proto = Ip.Proto.o proto ; ttl ;
                   src = Ip.Addr.of_bitstring src ;
                   dst = Ip.Addr.of_bitstring dst ;
                   payload = Payload.o payload }
        | { version : 4 } when version <> 6 ->
            if version <> 4 then
                err (Printf.sprintf "Ip6: Bad version (%d)" version)
            else None
        | { _ } ->
            err "Ip6: Not IPv6"

    (*$Q pack
      ((random %> pack), dump) (fun t -> t = pack (Option.get (unpack t)))
     *)

    (* TODO: unpack with ports a la ip.ml? *)

    (*$>*)
end

(** {2 Transceiver} *)

module TRX = struct

    type t = { src : Ip.Addr.t ; dst : Ip.Addr.t ;
               proto : Ip.Proto.t ;
               mutable emit : bitstring -> unit ;
               mutable recv : bitstring -> unit }

    let tx t bits =
        let pdu = Pdu.make t.proto t.src t.dst bits in
        if debug then Printf.printf "Ip6: Emitting an IPv6 packet from %s to %s of length %d (content '%s')\n%!" (Ip.Addr.to_dotted_string t.src) (Ip.Addr.to_dotted_string t.dst) (bytelength bits) (hexstring_of_bitstring bits) ;
        Clock.asap t.emit (Pdu.pack pdu)

    let rx t bits = (match Pdu.unpack bits with
        | None -> ()
        | Some ip ->
            if Payload.bitlength ip.Pdu.payload > 0 then Clock.asap t.recv (ip.Pdu.payload :> bitstring))

    (* Note: In Eth we do not require dst addr since the trx know (using ARP) how to get dest addr itself.
     *       IP cannot do this since the application layer won't tell him the destination hostname. Or
     *       we must add the destination to any tx call, making host layer simpler only at the expense of
     *       this layer. *)
    let make src dst proto =
        let t = { src ; dst ; proto ;
                  emit = ignore ; recv = ignore } in
        { ins = { write = tx t ;
                  set_read = fun f -> t.recv <- f } ;
          out = { write = rx t ;
                  set_read = fun f -> t.emit <- f } }

end
