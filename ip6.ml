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
 * Everything related to IPv6 packets.
 * For addresses and CIDR, see ip.ml.
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
        let%bitstring hdr = {|
            Ip.Addr.to_bitstring t.src : 128 : bitstring ;
            Ip.Addr.to_bitstring t.dst : 128 : bitstring ;
            Payload.length t.payload : 16 ;
            0 : 24 ;
            (t.proto :> int) : 8 |} in
        hdr

    let pack t =
        let%bitstring header = {|
            6 : 4 ; t.diff_serv : 6 ; t.ecn : 2 ; t.flow_label : 20 ;
            Payload.length t.payload : 16 ;
            (t.proto :> int) : 8 ; t.ttl : 8 ;
            Ip.Addr.to_bitstring t.src : 128 : bitstring ;
            Ip.Addr.to_bitstring t.dst : 128 : bitstring |} in
        (* must we patch some checksum? *)
        let payload =
            let fix_udp_checksum = function 0 -> 0xffff | x -> x in (* As per rfc2460, 8.1 *)
            if t.proto = Ip.Proto.tcp then Ip.Pdu.patch_checksum 128 (pseudo_header t) t.payload
            else if t.proto = Ip.Proto.udp then Ip.Pdu.patch_checksum 48 (pseudo_header t) ~fixit:fix_udp_checksum t.payload
            else if t.proto = Ip.Proto.icmpv6 then Ip.Pdu.patch_checksum 16 (pseudo_header t) t.payload
            else t.payload in
        concat [ header ; (payload :> bitstring) ]

    let unpack bits = match%bitstring bits with
        | {| 6 : 4 ; diff_serv : 6 ; ecn : 2 ; flow_label : 20 ;
             payload_len : 16 ; proto : 8 ; ttl : 8 ;
             src : 128 : bitstring ; dst : 128 : bitstring ;
             payload : payload_len*8 : bitstring |} ->
            Ok { diff_serv ; ecn ; flow_label ;
                 proto = Ip.Proto.o proto ; ttl ;
                 src = Ip.Addr.of_bitstring src ;
                 dst = Ip.Addr.of_bitstring dst ;
                 payload = Payload.o payload }
        | {| 4 : 4 ; _ |} ->
            Error (lazy "IPv6 looks like v4")
        | {| _ |} ->
            Error (lazy ("Not IPv6: "^ hexstring_of_bitstring_abbrev bits))

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)

    (* TODO: unpack with ports a la ip.ml? *)

    (** What a datagram's header says. No payload length: [t] has none, it
     * being however long the payload is; and no version, that being what this
     * module is.
     *
     * The traffic class is split in two here, unlike IPv4's type of service,
     * because [t] holds it split. *)
    module Kinds =
    struct
        open SimTypes
        let diff_serv = IRange (0, 0x3f)
        let ecn = IRange (0, 3)
        let flow_label = IRange (0, 0xfffff)
        let proto = Widget.one_of ~range:(0, 0xff) Ip.Proto.choices
        let ttl = IRange (0, 0xff)
        let addr = Widget.hint "2001:db8::1" Ipv6
        let payload = BRange (0, 0xffff)
    end

    let kind =
        Widget.record
            [| "differentiated services", Kinds.diff_serv ;
               "explicit congestion notification", Kinds.ecn ;
               "flow label", Kinds.flow_label ;
               "next header", Kinds.proto ;
               "hop limit", Kinds.ttl ;
               "source", Kinds.addr ;
               "destination", Kinds.addr ;
               "payload", Kinds.payload |]

    let to_json (t : t) =
        `Assoc [ "differentiated services", `Int t.diff_serv ;
                 "explicit congestion notification", `Int t.ecn ;
                 "flow label", `Int t.flow_label ;
                 "next header", `Int (t.proto :> int) ;
                 "hop limit", `Int t.ttl ;
                 "source", Ip.Addr.to_json t.src ;
                 "destination", Ip.Addr.to_json t.dst ;
                 "payload", Widget.json_of_bytes (t.payload :> bitstring) ]

    let of_synth js ?upper ?prev gen_values =
        ignore prev ;
        let open Generator in
        let int fname ?auto kind f =
            int_of_field fname gen_values ?auto kind f js
        and addr fname =
            of_field fname gen_values Kinds.addr
                     (Ip.Addr.of_dotted_string % Widget.to_string) js in
        { diff_serv = int "differentiated services" Kinds.diff_serv identity ;
          ecn = int "explicit congestion notification" Kinds.ecn identity ;
          flow_label = int "flow label" Kinds.flow_label identity ;
          proto = int "next header" ?auto:(from_upper upper Ip.Proto.of_layer)
                      Kinds.proto Ip.Proto.o ;
          ttl = int "hop limit" Kinds.ttl identity ;
          src = addr "source" ;
          dst = addr "destination" ;
          payload =
              Payload.o (payload_of_field ?upper gen_values Kinds.payload js) }

    (*$Q of_synth
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_consts (fun js g -> of_synth js g) kind to_json)
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_autos (fun js g -> of_synth js g) kind to_json)
     *)

    (*$Q kind
      (Q.make (fun _ -> random ())) (fun t -> \
        try Widget.check_value kind (to_json t) ; true \
        with _ -> false)
     *)

    (*$>*)
end

(** {2 Transceiver} *)

module TRX = struct

    type t = { logger : Log.t ;
               (* What pays for the events this TRX schedules, and names the
                * clock they run on: the host it belongs to, so that they go
                * down with it. *)
               power : Simulation.power ;
               src : Ip.Addr.t ; dst : Ip.Addr.t ;
               proto : Ip.Proto.t ;
               mutable emit : bitstring -> unit ;
               mutable recv : bitstring -> unit }

    let tx t bits =
        let pdu = Pdu.make t.proto t.src t.dst bits in
        if debug then Printf.printf "Ip6: Emitting an IPv6 packet from %s to %s of length %d (content '%s')\n%!" (Ip.Addr.to_dotted_string t.src) (Ip.Addr.to_dotted_string t.dst) (bytelength bits) (hexstring_of_bitstring bits) ;
        Simulation.asap t.power t.emit (Pdu.pack pdu)

    let rx (t : t) bits = (match Pdu.unpack bits with
        | Error s ->
            Log.(log t.logger Warning s)
        | Ok ip ->
            if Payload.bitlength ip.Pdu.payload > 0 then Simulation.asap t.power t.recv (ip.Pdu.payload :> bitstring))

    (* Note: In Eth we do not require dst addr since the trx knows (using ARP) how to get dest addr itself.
     *       IP cannot do this since the application layer won't tell him the destination hostname. Or
     *       we must add the destination to any tx call, making host layer simpler only at the expense of
     *       this layer. *)
    let make power src dst proto logger =
        let t = { logger ; power ; src ; dst ; proto ;
                  emit = ignore ; recv = ignore } in
        { ins = { write = tx t ;
                  set_read = fun f -> t.recv <- f } ;
          out = { write = rx t ;
                  set_read = fun f -> t.emit <- f } }
end
