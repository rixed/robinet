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
        type t = int * int (* type, code *)
        let to_string = function
            |   1, 0 -> "No route to destination"
            |   1, 1 -> "Communication with destination administratively prohibited  "
            |   1, 2 -> "Beyond scope of source address"
            |   1, 3 -> "Address unreachable"
            |   1, 4 -> "Port unreachable"
            |   1, 5 -> "Source address failed ingress/egress policy"
            |   1, 6 -> "Reject route to destination"
            |   1, 7 -> "Error in Source Routing Header"
            |   1, y -> Printf.sprintf "Destination Unreachable (%d)" y
            |   2, 0 -> "Packet Too Big"
            |   2, y -> Printf.sprintf "Packet Too Big (%d)" y
            |   3, 0 -> "Hop limit exceeded in transit"
            |   3, 1 -> "Fragment reassembly time exceeded"
            |   3, y -> Printf.sprintf "Time Exceeded (%d)" y
            |   4, 0 -> "Erroneous header field encountered"
            |   4, 1 -> "Unrecognized Next Header type encountered"
            |   4, 2 -> "Unrecognized IPv6 option encountered"
            |   4, y -> Printf.sprintf "Parameter Problem (%d)" y
            | 128, 0 -> "Echo Request"
            | 129, 0 -> "Echo Reply"
            | 130, 0 -> "Multicast Listener Query"
            | 131, 0 -> "Multicast Listener Report"
            | 132, 0 -> "Multicast Listener Done"
            | 133, 0 -> "Router Solicitation"
            | 134, 0 -> "Router Advertisement"
            | 135, 0 -> "Neighbor Solicitation"
            | 136, 0 -> "Neighbor Advertisement"
            | 137, 0 -> "Redirect Message"
            | 138, 0 -> "Router Renumbering Command"
            | 138, 1 -> "Router Renumbering Result"
            | 138, 2 -> "Sequence Number Reset"
            | 138, y -> Printf.sprintf "Router Renumbering (%d)" y
            | 139, 0 -> "The Data field contains an IPv6 address which is the Subject of this Query"
            | 139, 1 -> "The Data field contains a name which is the Subject of this Query, or is empty, as in the case of a NOOP"
            | 139, 2 -> "The Data field contains an IPv4 address which is the Subject of this Query"
            | 140, 0 -> "A successful reply. The Reply Data field may or may not be empty"
            | 140, 1 -> "The Responder refuses to supply the answer. The Reply Data field will be empty"
            | 140, 2 -> "The Qtype of the Query is unknown to the Responder. The Reply Data field will be empty"
            | 141, 0 -> "Inverse Neighbor Discovery (Solicitation Message)"
            | 142, 0 -> "Inverse Neighbor Discovery (Advertisement Message)"
            | 144, 0 -> "Home Agent Address Discovery (Request Message)"
            | 145, 0 -> "Home Agent Address Discovery (Reply Message)"
            | 146, 0 -> "Mobile Prefix Solicitation"
            | 147, 0 -> "Mobile Prefix Advertisement"
            | 148, 0 -> "Certification Path Solicitation"
            | 149, 0 -> "Certification Path Advertisement"
            | 151, 0 -> "Multicast Router Advertisement"
            | 152, 0 -> "Multicast Router Solicitation"
            | 153, 0 -> "Multicast Router Termination"
            | 154, 0 -> "Reserved [RFC5568]"
            | 154, 1 -> "Reserved [RFC5568]"
            | 154, 2 -> "RtSolPr [RFC5568]"
            | 154, 3 -> "PrRtAdv [RFC5568]"
            | 154, 4 -> "HI - Deprecated (Unavailable for Assignment) [RFC5568]"
            | 154, 5 -> "HAck - Deprecated (Unavailable for Assignment)"
            | 155, 0 -> "RPL Control Message"
            |   x, y -> Printf.sprintf "Reserved(%d,%d)" x y
        let is_valid (x, y) = x < 256 && y < 256
        let repl_tag = "code"
    end
    include MakePrivate(Outer)

    let rec random () =
        let m = Random.int 155, Random.int 7 in
        if Outer.is_valid m then o m else random ()

    let type_of (t : t) = fst (t :> int*int)
    let code_of (t : t) = snd (t :> int*int)
end

(** {2 ICMPv6 Messages} *)

(** This module handle ICMPv6 messages (un)packing. *)
module Pdu = struct
    (*$< Pdu *)

    (* TODO: parse common ICMPv6 msgs *)
    type payload = Ids of int * int * Payload.t
                 | Unknown of Payload.t

    let random_payload msg_type =
        let random_id () = Ids (randi 8, randi 8, Payload.empty) in
        match MsgType.type_of msg_type with
            | 128 | 129 -> random_id ()
            | _ -> Unknown (Payload.o (randbs (Random.int 20)))

    (** Unpacked ICMP message. *)
    type t = { msg_type : MsgType.t ;
               payload  : payload }

    let random () =
        let msg_type = MsgType.random () in
        { msg_type ;
          payload  = random_payload msg_type }

    let make_echo_request id seq =
        { msg_type = MsgType.o (128, 0) ;
          payload  = Ids (id, seq, Payload.empty) }

    let make_echo_reply id seq =
        { msg_type = MsgType.o (129, 0) ;
          payload  = Ids (id, seq, Payload.empty) }

    let is_echo_request t =
        MsgType.type_of t.msg_type = 128 && MsgType.code_of t.msg_type = 0

    let pack t =
        let pack_payload = function
            | Ids (id, seq, pld) -> (BITSTRING { id : 16 ; seq : 16 ;
                                                 (pld :> bitstring) : -1 : bitstring })
            | Unknown pld -> (pld :> bitstring) in
        let typ, cod = (t.msg_type :> int*int) in
        let pld = pack_payload t.payload in
        (* Checksum will be patched later when IP addresses are known *)
        concat [(BITSTRING { typ : 8 ; cod : 8 ; 0 : 16 }) ; pld ]

    let unpack bits = bitmatch bits with
        | { (128|129) as typ : 8 ; 0 : 8 ; _checksum : 16 ;
            id : 16 ; seq : 16 ; pld : -1 : bitstring } ->
            Some { msg_type = MsgType.o (typ, 0) ;
                   payload = Ids (id, seq, Payload.o pld) }
        | { typ : 8 ; cod : 8 ; _checksum : 16 ;
            pld : -1 : bitstring } ->
            Some { msg_type = MsgType.o (typ, cod) ;
                   payload = Unknown (Payload.o pld) }
        | { _ } ->
            err "Not ICMP"
    (*$Q pack
      ((random %> pack), dump) (fun t -> t = pack (Option.get (unpack t)))
     *)
    (*$>*)
end

