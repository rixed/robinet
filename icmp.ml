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
 * Internet Control Message Protocol (ICMP), (un)packing and tools.
 *)
open Batteries
open Bitstring
open Tools

(** {2 Private types} *)

module MsgType =
struct
    module Outer = struct
        type t = int * int
        let to_string = function
            |  0,  0 -> "Echo Reply"
            |  3,  0 -> "Network Unreachable"
            |  3,  1 -> "Host Unreachable"
            |  3,  2 -> "Protocol Unreachable"
            |  3,  3 -> "Port Unreachable"
            |  3,  4 -> "Fragmentation Required"
            |  3,  5 -> "Source Route Failed"
            |  3,  6 -> "Network Unknown"
            |  3,  7 -> "Host Unknown"
            |  3,  8 -> "Source Host Isolated"
            |  3,  9 -> "Network Prohibited"
            |  3, 10 -> "Host Prohibited"
            |  3, 11 -> "Network Unreachable for TOS"
            |  3, 12 -> "Host Unreachable for TOS"
            |  3, 13 -> "Communication Prohibited"
            |  3, 14 -> "Host Precedence Violation"
            |  3, 15 -> "Precedence Cutoff in Effect"
            |  4,  0 -> "Source Quench"
            |  5,  0 -> "Redirect Datagram for the Network"
            |  5,  1 -> "Redirect Datagram for the Host"
            |  5,  2 -> "Redirect Datagram for the TOS & Network"
            |  5,  3 -> "Redirect Datagram for the TOS & Host"
            |  6,  _ -> "Alternate Host Address"
            |  8,  0 -> "Echo Request"
            |  9,  0 -> "Router Advertisement"
            | 10,  0 -> "Router Solicitation"
            | 11,  0 -> "TTL Expired in Transit"
            | 11,  1 -> "Fragment Reassembly Time Exceeded"
            | 12,  0 -> "Bad IP header, Ptr indicate the problem"
            | 12,  1 -> "Bad IP header, Missing required option"
            | 12,  2 -> "Bad IP header, Bad length"
            | 13,  0 -> "Timestamp"
            | 14,  0 -> "Timestamp Reply"
            | 15,  0 -> "Information Request"
            | 16,  0 -> "Information Reply"
            | 17,  0 -> "Address Mask Request"
            | 18,  0 -> "Address Mask Reply"
            | 30,  0 -> "Traceroute"
            | 31,  _ -> "Datagram Conversion Error"
            | 32,  _ -> "Mobile Host Redirect"
            | 33,  _ -> "Where-Are-You"
            | 34,  _ -> "Here-I-Am"
            | 35,  _ -> "Mobile Registration Request"
            | 36,  _ -> "Mobile Registration Reply"
            | 37,  _ -> "Domain Name Request"
            | 38,  _ -> "Domain Name Reply"
            | 39,  _ -> "SKIP Discovery Protocol"
            | 40,  _ -> "Photuris, Security failures"
            | 41,  _ -> "Experimental Mobility"
            |  x,  y -> Printf.sprintf "Reserved(%d,%d)" x y
        let is_valid (x, y) = x < 256 && y < 256
        let repl_tag = "code"
    end
    include Private.Make (Outer)

    let rec random () =
        let m = Random.int 49, Random.int 15 in
        if Outer.is_valid m then o m else random ()

    let type_of (t : t) = fst (t :> int*int)
    let code_of (t : t) = snd (t :> int*int)
end

(** {2 ICMP Messages} *)

(** This module handle ICMP messages (un)packing. *)
module Pdu = struct
    (*$< Pdu *)

    type payload = Ids of int * int * Payload.t
                 | Redirect of Ip.Addr.t * Payload.t
                 | Header of int * Payload.t (* with optional pointer *)

    let random_payload msg_type =
        let random_redirect () = Redirect (Ip.Addr.random(), Payload.random (20*8 + 64))
        and random_id () = Ids (randi 8, randi 8, Payload.empty)
        and random_header () = Header (randi 8, Payload.random (20*8 + 64)) in
        match MsgType.type_of msg_type with
            | 5 -> random_redirect ()
            | 0 | 8 | 13 | 14 | 15 | 16 -> random_id ()
            | _ -> random_header ()

    (** Unpacked ICMP message. *)
    type t = { msg_type : MsgType.t ;
               payload  : payload }

    let random () =
        let msg_type = MsgType.random () in
        { msg_type ;
          payload  = random_payload msg_type }

    let make_echo_request id seq =
        { msg_type = MsgType.o (8, 0) ;
          payload  = Ids (id, seq, Payload.empty) }

    let make_echo_reply id seq =
        { msg_type = MsgType.o (0, 0) ;
          payload  = Ids (id, seq, Payload.empty) }

    let make_ttl_expired code ip =
        let ip_hdr = Ip.Pdu.pack_header ip
        and ip_pld = Ip.Pdu.pack_payload ip in
        let ip_start = concat [ ip_hdr ; takebits 64 (ip_pld :> bitstring) ] in
        { msg_type = MsgType.o (11, code) ;
          payload = Header (0, Payload.o ip_start) }

    let make_ttl_expired_in_transit = make_ttl_expired 0
    let make_ttl_expired_during_reassembly = make_ttl_expired 1

    let is_echo_request t =
        MsgType.type_of t.msg_type = 8 && MsgType.code_of t.msg_type = 0

    let pack t =
        let pack_payload = function
            | Ids (id, seq, pld) ->
                let%bitstring b = {| id : 16 ; seq : 16 ;
                                     (pld :> bitstring) : -1 : bitstring |} in b
            | Redirect (ip, pld) ->
                let%bitstring b = {| (Ip.Addr.to_int32 ip) : 32 ;
                                     (pld :> bitstring) : -1 : bitstring |} in b
            | Header (ptr, pld)  ->
                let%bitstring b = {| ptr : 8 ; 0 : 24 ;
                                     (pld :> bitstring) : -1 : bitstring |} in b
        in
        let typ, cod = (t.msg_type :> int*int) in
        let pld = pack_payload t.payload in
        let%bitstring hdr = {| typ : 8 ; cod : 8 ; 0 : 16 |} in
        let pck = concat [ hdr ; pld ] in
        let chk = sum pck in
        let%bitstring hdr = {| typ : 8 ; cod : 8 ; chk : 16 |} in
        concat [ hdr ; pld ]

    let unpack bits = match%bitstring bits with
        | {| 5 : 8 ; cod : 8 ; _checksum : 16 ;
             ip : 32 ; pld : -1 : bitstring |} ->
            Some { msg_type = MsgType.o (5, cod) ;
                   payload = Redirect (Ip.Addr.o32 ip, Payload.o pld) }
        | {| typ : 8 ; cod : 8 ; _checksum : 16 ;
             id : 16 ; seq : 16 ; pld : -1 : bitstring |}
            when typ = 0 || typ = 8 || (typ >= 13 && typ <= 16) ->
            Some { msg_type = MsgType.o (typ, cod) ;
                   payload = Ids (id, seq, Payload.o pld) }
        | {| typ : 8 ; cod : 8 ; _checksum : 16 ;
            ptr : 8 ; _ : 24 ; pld : -1 : bitstring |} ->
            Some { msg_type = MsgType.o (typ, cod) ;
                   payload = Header (ptr, Payload.o pld) }
        | {| _ |} ->
            err "Not ICMP"
    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Option.get (unpack t)))
     *)
    (*$>*)
end
