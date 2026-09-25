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

let debug = false

(** {2 ARP messages} *)

(** ARP Operations Codes *)
module Op = struct
    module Inner = struct
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
    end
    include Private.Make (Inner)

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
    let num_ops       = 10

    let rec random () =
        let p = Random.int num_ops + 1 in
        if Inner.is_valid p then o p else random ()

    (** The operations this module has a name for, as the choices of a kind
     * (see [Widget.one_of]), labelled by [to_string]. *)
    let choices =
        Array.init num_ops (fun i ->
            let i = i + 1 in
            i, to_string (o i))
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
    let num_typs = 7

    let rec random () =
        let p = randi 3 in
        if Inner.is_valid p then o p else random ()

    (** The hardware types this module has a name for (see [Arp.Op.choices]). *)
    let choices =
        Array.init num_typs (fun i ->
            let i = i + 1 in
            i, to_string (o i))
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

    (** The protocol of the layer named [name] (see
     * [Packet.Pdu.name_of_layer]), when it is one of these. *)
    let of_layer = function
        | "Ip" -> Some ip4
        | "Ip6" -> Some ip6
        | "Arp" -> Some arp
        | "Vlan" -> Some ieee8021q
        | _ -> None

    (** The protocols this module has a name for (see [Arp.Op.choices]). These
     * are the numbers an Ethernet frame carries to say what is in it, so
     * everything above uses them too. *)
    let choices =
        [| ip4 ; ip6 ; arp ; ieee8021q |] |>
        Array.map (fun (p : t) -> (p :> int), to_string p)
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
        (* TODO: other ARP types, esp Nack *)
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

    (** What a message says.
     *
     * The four addresses are bytes and not strings, because this module cannot
     * know what they are: what a hardware address looks like is what [hw_type]
     * says, and the module that can read one is above this one. Their lengths
     * are not here either -- [pack] writes them from the addresses
     * themselves. *)
    module Kinds =
    struct
        open SimTypes
        open Widget
        let hw_type = one_of ~range:(0, 0xffff) HwType.choices
        let proto_type = one_of ~range:(0, 0xffff) HwProto.choices
        let operation = one_of ~range:(0, 0xffff) Op.choices
        let sender_hw = BRange (0, 255)
        let sender_proto = BRange (0, 255)
        let target_hw = BRange (0, 255)
        let target_proto = BRange (0, 255)
    end

    let kind =
        Widget.record
            [| "hardware type", Kinds.hw_type ;
               "protocol type", Kinds.proto_type ;
               "operation", Kinds.operation ;
               "sender hardware address", Kinds.sender_hw ;
               "sender protocol address", Kinds.sender_proto ;
               "target hardware address", Kinds.target_hw ;
               "target protocol address", Kinds.target_proto |]

    let to_json (t : t) =
        `Assoc [ "hardware type", `Int (t.hw_type :> int) ;
                 "protocol type", `Int (t.proto_type :> int) ;
                 "operation", `Int (t.operation :> int) ;
                 "sender hardware address",
                 Widget.json_of_bytes t.sender_hw ;
                 "sender protocol address",
                 Widget.json_of_bytes t.sender_proto ;
                 "target hardware address",
                 Widget.json_of_bytes t.target_hw ;
                 "target protocol address",
                 Widget.json_of_bytes t.target_proto ]

    (*$Q kind
      (Q.make (fun _ -> random ())) (fun t -> \
        try Widget.check_value kind (to_json t) ; true \
        with _ -> false)
     *)

    (* Where each field is in [kind], which [of_synth] reads them by: *)
    module Field =
    struct
        let i = Widget.field_index kind
        let hw_type = i "hardware type"
        let proto_type = i "protocol type"
        let operation = i "operation"
        let sender_hw = i "sender hardware address"
        let sender_proto = i "sender protocol address"
        let target_hw = i "target hardware address"
        let target_proto = i "target protocol address"
    end

    (* [r] are the fields of a synth of [kind] (see [Generator.fields]): *)
    let of_synth r ?upper ?prev gen_values =
        (* Nothing above or before an ARP says anything about it: *)
        ignore upper ; ignore prev ;
        let open Generator in
        (* Automatic is Ethernet and IPv4, with addresses of the length those
         * two call for: the header says how long its addresses are, so a
         * random type with a random length is a message nothing can read --
         * and every ARP anybody has seen is this pair anyway. *)
        let hw i = bs_of_nth r i gen_values ~auto:(fun () -> randbs 6)
                             Kinds.sender_hw
        and proto i = bs_of_nth r i gen_values ~auto:(fun () -> randbs 4)
                                Kinds.sender_proto in
        {
            hw_type = int_of_nth r Field.hw_type ~auto:(fun () -> HwType.eth)
                                 gen_values Kinds.hw_type HwType.o ;
            proto_type = int_of_nth r Field.proto_type
                                    ~auto:(fun () -> HwProto.ip4)
                                    gen_values Kinds.proto_type HwProto.o ;
            operation = int_of_nth r Field.operation ~auto:Op.random gen_values
                                   Kinds.operation Op.o ;
            sender_hw = hw Field.sender_hw ;
            sender_proto = proto Field.sender_proto ;
            target_hw = hw Field.target_hw ;
            target_proto = proto Field.target_proto ;
        }

    (*$Q of_synth
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_consts (fun js g -> \
            of_synth (Generator.fields_of_synth kind js) g) kind to_json)
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_autos (fun js g -> \
            of_synth (Generator.fields_of_synth kind js) g) kind to_json)
     *)

    (*$>*)
end
