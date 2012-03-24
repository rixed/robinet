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

(* ARP messages *)

module Op = MakePrivate(struct
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
    let is_valid t = t >= 1 && t <= 0x10000
    let repl_tag = "code"
end)

let op_request       = Op.o 1
let op_reply         = Op.o 2
let op_request_rev   = Op.o 3
let op_reply_rev     = Op.o 4
let op_DRARP_request = Op.o 5
let op_DRARP_reply   = Op.o 6
let op_DRARP_error   = Op.o 7
let op_InARP_request = Op.o 8
let op_InARP_reply   = Op.o 9
let op_ARP_NACK      = Op.o 10

module HwType = struct
    include MakePrivate(struct
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
    end)
    let random () = o (randi 3)
end

let hw_type_eth      = HwType.o 1
let hw_type_expe_eth = HwType.o 2
let hw_type_AX25     = HwType.o 3
let hw_type_tokring  = HwType.o 4
let hw_type_chaos    = HwType.o 5
let hw_type_IEEE_802 = HwType.o 6
let hw_type_arcnet   = HwType.o 7

module HwProto = struct
    include MakePrivate(struct
        type t = int
        let to_string = function
            | 0x0800 -> "IP"
            | 0x86DD -> "IPv6"
            | 0x0806 -> "ARP"
            | 0x8100 -> "Eth8021q"
            |      x -> Printf.sprintf "Protocol(%X)" x
        let is_valid x = x < 0x10000
        let repl_tag = "proto"
    end)
    let random () = o (randi 16)
end

let proto_ip4   = HwProto.o 0x0800
let proto_ip6   = HwProto.o 0x86DD
let proto_arp   = HwProto.o 0x0806
let proto_8021q = HwProto.o 0x8100

module Pdu = struct
    type t = { hw_type : HwType.t ; proto_type : HwProto.t ;
               operation : Op.t ;
               sender_hw : bitstring ; sender_proto : bitstring ;
               target_hw : bitstring ; target_proto : bitstring }

    let make_request hw_type proto_type sender_hw sender_proto target_proto =
        { hw_type ; proto_type ; operation = op_request ;
          sender_hw ; sender_proto ;
          target_hw = create_bitstring (bitstring_length sender_hw) ; target_proto }

    let make_reply hw_type proto_type sender_hw sender_proto target_hw target_proto =
        { hw_type ; proto_type ; operation = op_reply ;
          sender_hw ; sender_proto ; target_hw ; target_proto }

    let pack t =
        (BITSTRING {
            (t.hw_type :> int) : 16 ;
            (t.proto_type :> int) : 16 ;
            (bitstring_length t.sender_hw)/8 : 8 ;
            (bitstring_length t.sender_proto)/8 : 8 ;
            (t.operation :> int) : 16 ;
            t.sender_hw : -1 : bitstring ;
            t.sender_proto : -1 : bitstring ;
            t.target_hw : -1 : bitstring ;
            t.target_proto : -1 : bitstring })

    let unpack bits = bitmatch bits with
        | { hw_type : 16 ;
            proto_type : 16 ;
            hw_len : 8 ;
            proto_len : 8 ;
            operation : 16 ;
            sender_hw : hw_len*8 : bitstring ;
            sender_proto : proto_len*8 : bitstring ;
            target_hw : hw_len*8 : bitstring ;
            target_proto : proto_len*8 : bitstring } ->
            Some { hw_type = HwType.o hw_type ;
                   proto_type = HwProto.o proto_type ;
                   operation = Op.o operation ;
                   sender_hw ; sender_proto ;
                   target_hw ; target_proto }
        | { _ } ->
            err "Not ARP"
end

