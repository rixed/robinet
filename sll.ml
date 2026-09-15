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
 * Linux Cooked Capture (aka SLL)
 *
 * When you capture traffic on the {e any} interface on Linux, you end up with
 * a special frame header similar to ethernet but 2 bytes longer, with the
 * local hardware address missing but other informations instead.
 *
 * This fake protocol can only be seen when reading pcap file or sniffing
 * the {e any} network interface. It is not used when simulating a network.
 *)
open Batteries
open Bitstring
open Tools

let debug = false

(** {2 Linux Cooked Capture frames} *)

(** Pack/Unpack a SLL frame. *)
module Pdu = struct
    (*$< Pdu *)
    (** The 5 possible directions of the frame *)
    type pkt_type = UnicastIn | BroadcastIn | MulticastIn | OutToOut | SentByUs
    let pkt_type_of_int = function
        | 0 -> UnicastIn | 1 -> BroadcastIn | 2 -> MulticastIn | 3 -> OutToOut | 4 -> SentByUs
        | _ -> error "Invalid SLL packet type"
    let int_of_pkt_type = function
        | UnicastIn -> 0 | BroadcastIn -> 1 | MulticastIn -> 2 | OutToOut -> 3 | SentByUs -> 4

    (** A SLL frame has an address (usually Ethernet), a direction, and a
     * protocol. Notice the absence of the local address. *)
    type t = { pkt_type     : pkt_type ;
               ll_addr_type : int ;
               ll_addr      : bitstring ;
               proto        : Arp.HwProto.t ;
               payload      : Payload.t }

    (** Build a {!Sll.Pdu.t} for a given [payload]. *)
    let make ?(ll_addr_type=1) pkt_type proto ll_addr bits =
        { pkt_type ; ll_addr_type ; ll_addr ; proto ; payload = Payload.o bits }

    (** Returns a random {!Sll.Pdu.t}. *)
    let random () =
        let pkt_type = pkt_type_of_int (Random.int 5) in
        make pkt_type (Arp.HwProto.random ()) (Eth.Addr.random () :> bitstring) (randbs 30)

    (** Pack a {!Sll.Pdu.t} into its [bitstring] raw representation. *)
    let pack t =
        let%bitstring hdr = {|
            int_of_pkt_type t.pkt_type : 16 ;
            t.ll_addr_type : 16 ;
            bytelength t.ll_addr : 16 ;
            fixedbits 64 t.ll_addr : 64 : bitstring ;
            (t.proto :> int) : 16 |} in
        concat [ hdr ; (t.payload :> bitstring) ]

    (** Unpack a [bitstring] into a {!Sll.Pdu.t} *)
    let unpack bits = match%bitstring bits with
        | {| pkt_type : 16 ;
             ll_addr_type : 16 ;
             ll_addr_len : 16 ;
             ll_addr : min 64 (ll_addr_len*8) : bitstring ;
             _zeroes : if ll_addr_len*8 >= 64 then 0 else 64-ll_addr_len*8 : bitstring ;
             proto : 16 ;
             payload : -1 : bitstring |} when pkt_type >= 0 && pkt_type <= 4 ->
            Ok { pkt_type = pkt_type_of_int pkt_type ;
                 ll_addr_type ; ll_addr ;
                 proto = Arp.HwProto.o proto ;
                 payload = Payload.o payload }
        | {| _ |} ->
            Error (lazy "Not SLL")

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)

    (** The five directions, as the choices of a kind: numbered as they are on
     * the wire, which is what [int_of_pkt_type] says. *)
    let pkt_type_choices =
        [| UnicastIn, "unicast to us" ; BroadcastIn, "broadcast" ;
           MulticastIn, "multicast" ; OutToOut, "between two others" ;
           SentByUs, "sent by us" |] |>
        Array.map (fun (t, name) -> int_of_pkt_type t, name)

    (** What the pseudo-header libpcap writes in front of a cooked capture
     * says. No local address: a cooked capture does not carry one, which is
     * the whole reason it exists. *)
    module Kinds =
    struct
        open SimTypes
        let direction = Widget.one_of pkt_type_choices
        let addr_type = Widget.one_of ~range:(0, 0xffff) Arp.HwType.choices
        let addr = BRange (0, 8)
        let proto = Widget.one_of ~range:(0, 0xffff) Arp.HwProto.choices
        let payload = BRange (0, 0xffff_ffff)
    end

    let kind_of (_ : t) =
        Widget.record
            [| "direction", Kinds.direction ;
               "address type", Kinds.addr_type ;
               "address", Kinds.addr ;
               "protocol", Kinds.proto ;
               "payload", Kinds.payload |]

    let to_json (t : t) =
        `Assoc [ "direction", `Int (int_of_pkt_type t.pkt_type) ;
                 "address type", `Int t.ll_addr_type ;
                 "address", Widget.json_of_bytes t.ll_addr ;
                 "protocol", `Int (t.proto :> int) ;
                 "payload", Widget.json_of_bytes (t.payload :> bitstring) ]

    let of_synth js ?upper ?prev gen_values =
        ignore prev ;
        let open Generator in
        { pkt_type = int_of_field "direction" gen_values Kinds.direction
                                  pkt_type_of_int js ;
          ll_addr_type = int_of_field "address type" gen_values Kinds.addr_type
                                      identity js ;
          ll_addr = bs_of_field "address" gen_values Kinds.addr js ;
          proto = int_of_field "protocol" gen_values
                      ?auto:(from_upper upper Arp.HwProto.of_layer)
                      Kinds.proto Arp.HwProto.o js ;
          payload =
              Payload.o (payload_of_field ?upper gen_values Kinds.payload js) }

    (*$Q of_synth
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_consts (fun js g -> of_synth js g) kind_of to_json)
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_autos (fun js g -> of_synth js g) kind_of to_json)
     *)

    (*$Q kind_of
      (Q.make (fun _ -> random ())) (fun t -> \
        try Widget.check_value (kind_of t) (to_json t) ; true \
        with _ -> false)
     *)
    (*$>*)
end
