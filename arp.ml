(* vim:sw=4 ts=4 sts=4 expandtab
*)
open Batteries
open Bitstring
open Tools

let debug = false

(* ARP messages *)

(* TODO: dedicated type and printer for ARP operations and hw_types? *)

let op_request       = 1
let op_reply         = 2
let op_request_rev   = 3
let op_reply_rev     = 4
let op_DRARP_request = 5
let op_DRARP_reply   = 6
let op_DRARP_error   = 7
let op_InARP_request = 8
let op_InARP_reply   = 9
let op_ARP_NACK      = 10

let hw_type_eth      = 1
let hw_type_expe_eth = 2
let hw_type_AX25     = 3
let hw_type_tokring  = 4
let hw_type_chaos    = 5
let hw_type_IEEE_802 = 6
let hw_type_arcnet   = 7

module Pdu = struct
    type t = { hw_type : int ; proto_type : int ;
               operation : int ;
               sender_hw : bitstring ; sender_proto : bitstring ;
               target_hw : bitstring ; target_proto : bitstring }

    let make_request hw_type proto_type sender_hw sender_proto target_proto =
        { hw_type = hw_type ; proto_type = proto_type ; operation = op_request ;
          sender_hw = sender_hw ; sender_proto = sender_proto ;
          target_hw = create_bitstring (bitstring_length sender_hw) ; target_proto = target_proto }

    let make_reply hw_type proto_type sender_hw sender_proto target_hw target_proto =
        { hw_type ; proto_type ; operation = op_reply ;
          sender_hw ; sender_proto ; target_hw ; target_proto }

    let pack t =
        (BITSTRING {
            t.hw_type : 16 ;
            t.proto_type : 16 ;
            (bitstring_length t.sender_hw)/8 : 8 ;
            (bitstring_length t.sender_proto)/8 : 8 ;
            t.operation : 16 ;
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
            Some { hw_type = hw_type ; proto_type = proto_type ; operation = operation ;
                   sender_hw = sender_hw ; sender_proto = sender_proto ;
                   target_hw = target_hw ; target_proto = target_proto }
        | { _ } ->
            err "Not ARP"
end

