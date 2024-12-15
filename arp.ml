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
 * Address Resolution Protocol.
 *)
open Batteries
open Bitstring
open Tools

let debug = true

(** {2 ARP messages} *)

(** ARP Operations Codes *)
module Op = struct
    include Private.Make (struct
        type t = int
        let to_string = function
            |  1 -> "request"
            |  2 -> "reply"
            |  3 -> "request rev"
            |  4 -> "reply rev"
            |  5 -> "DRARP request"
            |  6 -> "DRARP reply"
            |  7 -> "DRARP error"
            |  8 -> "InARP request"
            |  9 -> "InARP reply"
            | 10 -> "NACK"
            |  x -> string_of_int x
        let is_valid t = t >= 1 && t < 0x10000
        let repl_tag = "code"
    end)

    let request       = o 1
    let reply         = o 2
    let request_rev   = o 3
    let reply_rev     = o 4
    let drarp_request = o 5
    let drarp_reply   = o 6
    let drarp_error   = o 7
    let inarp_request = o 8
    let inarp_reply   = o 9
    let arp_nack      = o 10
end

(** Arp identifiers for MAC types.
 * These are used by DHCP as well. *)
module HwType = struct
    module Inner = struct
        type t = int
        let to_string = function
            | 1 -> "Eth"
            | 2 -> "Expe Eth"
            | 3 -> "AX25"
            | 4 -> "Tok.Ring"
            | 5 -> "Chaos"
            | 6 -> "IEEE 802"
            | 7 -> "ArcNet"
            | x -> Printf.sprintf "HwType(%d)" x
        let is_valid x = x >= 1
        let repl_tag = "code"
    end
    include Private.Make (Inner)
    let eth      = o 1
    let expe_eth = o 2
    let ax25     = o 3
    let tokring  = o 4
    let chaos    = o 5
    let ieee_802 = o 6
    let arcnet   = o 7

    let rec random () =
        let p = randi 3 in
        if Inner.is_valid p then o p else random ()
end

(** Arp Protocol Types.
 * These are used in other places as well. *)
module HwProto = struct
    include Private.Make (struct
        type t = int
        let to_string = function
            | 0x0800 -> "IP"
            | 0x86DD -> "IPv6"
            | 0x0806 -> "ARP"
            | 0x8100 -> "Eth8021q"
            |      x -> Printf.sprintf "Protocol(0x%X)" x
        let is_valid x = x < 0x10000
        let repl_tag = "proto"
    end)
    let ip4       = o 0x0800
    let ip6       = o 0x86DD
    let arp       = o 0x0806
    let ieee8021q = o 0x8100

    let random () = o (randi 16)
end

(** Pack/Unpack an ARP message *)
module Pdu = struct
    (*$< Pdu *)

    type t = { hw_type : HwType.t ; proto_type : HwProto.t ;
               operation : Op.t ;
               sender_hw : bitstring ; sender_proto : bitstring ;
               target_hw : bitstring ; target_proto : bitstring }

    let make_request hw_type proto_type sender_hw sender_proto target_proto =
        { hw_type ; proto_type ; operation = Op.request ;
          sender_hw ; sender_proto ;
          target_hw = create_bitstring (bitstring_length sender_hw) ; target_proto }

    let make_reply hw_type proto_type sender_hw sender_proto target_hw target_proto =
        { hw_type ; proto_type ; operation = Op.reply ;
          sender_hw ; sender_proto ; target_hw ; target_proto }

    let random () =
        let hw_type = HwType.random ()
        and proto_type = HwProto.random ()
        and sender_hw = randbs 6
        and sender_proto = randbs 4
        and target_proto = randbs 4 in
        if randb () then
            make_request hw_type proto_type sender_hw sender_proto target_proto
        else
            make_reply hw_type proto_type sender_hw sender_proto (randbs 6) target_proto

    let pack t =
        let%bitstring b = {|
            (t.hw_type :> int) : 16 ;
            (t.proto_type :> int) : 16 ;
            (bitstring_length t.sender_hw)/8 : 8 ;
            (bitstring_length t.sender_proto)/8 : 8 ;
            (t.operation :> int) : 16 ;
            t.sender_hw : -1 : bitstring ;
            t.sender_proto : -1 : bitstring ;
            t.target_hw : -1 : bitstring ;
            t.target_proto : -1 : bitstring |}
        in b

    let unpack bits = match%bitstring bits with
        | {| hw_type : 16 ;
             proto_type : 16 ;
             hw_len : 8 ;
             proto_len : 8 ;
             operation : 16 ;
             sender_hw : hw_len*8 : bitstring ;
             sender_proto : proto_len*8 : bitstring ;
             target_hw : hw_len*8 : bitstring ;
             target_proto : proto_len*8 : bitstring |} ->
            Ok { hw_type = HwType.o hw_type ;
                 proto_type = HwProto.o proto_type ;
                 operation = Op.o operation ;
                 sender_hw ; sender_proto ;
                 target_hw ; target_proto }
        | {| _ |} ->
            Error (lazy "Not ARP")
    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)
    (*$>*)
end

