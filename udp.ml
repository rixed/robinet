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
(** User Data Protocol. *)
open Batteries
open Bitstring
open Tools

(** {2 Private Types} *)

module Port = Tcp.MakePort (struct let srv = "udp" end)

(** {2 UDP datagrams} *)

module Pdu =
struct
    (*$< Pdu *)
    (** An unpacked UDP datagram. Notice the absence of the checksum, which
     * will be set to 0 by {!Udp.Pdu.pack}, and filled in by {!Ip.Pdu.pack},
     * since it's computed over some IP fields. *)
    type t = {
        src_port : Port.t ; dst_port : Port.t ; length : int ; checksum : int ;
        payload  : Payload.t }

    let make ?(src_port = Port.o 1024) ?(dst_port = Port.o 80) ?length ?checksum bits =
        let payload = Payload.o bits in
        let length = length |? Payload.length payload + 8 in
        (* Will be overwritten by Ip.pack_header for outgoing packets, anyway *)
        let checksum = checksum |? 0 in
        { src_port ; dst_port ; length ; checksum ; payload }

    let random () =
        make ~src_port:(Port.o (randi 16)) ~dst_port:(Port.o (randi 16))
             (randbs 64)

    let pack t =
        let%bitstring hdr = {|
            (t.src_port :> int) : 16 ; (t.dst_port :> int) : 16 ;
            t.length : 16 ; t.checksum : 16 |} in
        concat [ hdr ; (t.payload :> bitstring) ]

    let unpack bits = match%bitstring bits with
        | {| src_port : 16 ; dst_port : 16 ;
             length   : 16 ; checksum : 16 ;
             payload  : (length-8) * 8 : bitstring |} when length >= 8 ->
            Ok { src_port = Port.o src_port ; dst_port = Port.o dst_port ;
                 length ; checksum ; payload  = Payload.o payload }
        | {| _ |} -> Error (lazy "Not UDP")

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)

    (** What a datagram holds. The length counts the header as well as the
     * payload, and the checksum is over fields of the IP header below: both
     * are computed on the way out (see [make] and [Ip.Pdu.pack]) and are shown
     * here as the plain numbers they are. Offering to compute them is
     * something an editor does, and there is no editor yet. *)
    module Kinds =
    struct
        open SimTypes
        let port = IRange (0, 0xffff)
        let length = IRange (0, 0xffff)
        let checksum = IRange (0, 0xffff)
        let payload = BRange (0, 0xffff - 8)
    end

    let kind =
        Widget.record
            [| "source port", Kinds.port ;
               "destination port", Kinds.port ;
               "length", Kinds.length ;
               "checksum", Kinds.checksum ;
               "payload", Kinds.payload |]

    let to_json (t : t) =
        `Assoc [ "source port", `Int (t.src_port :> int) ;
                 "destination port", `Int (t.dst_port :> int) ;
                 "length", `Int t.length ;
                 "checksum", `Int t.checksum ;
                 "payload", Widget.json_of_bytes (t.payload :> bitstring) ]

    (* Where each field is in [kind], which [of_synth] reads them by: *)
    module Field =
    struct
        let i = Widget.field_index kind
        let src_port = i "source port"
        let dst_port = i "destination port"
        let length = i "length"
        let checksum = i "checksum"
        let payload = i "payload"
    end

    (* [r] are the fields of a synth of [kind] (see [Generator.fields]): *)
    let of_synth r ?upper ?prev gen_values =
        let open Generator in
        let payload = payload_of_nth ?upper r Field.payload gen_values
                                     Kinds.payload in
        (* The ports DNS and DHCP are known by, under those; otherwise those of
         * the previous datagram, mostly. *)
        let known_src, known_dst =
            match upper with
            | Some ("Dns", _) -> None, Some 53
            | Some ("Dhcp", _) -> Some 68, Some 67
            | _ -> None, None in
        let port i known prev_port =
            let auto =
                match known with
                | Some p -> Some (fun () -> Port.o p)
                | None -> mostly_same prev_port Port.random in
            int_of_nth r i gen_values ?auto Kinds.port Port.o in
        { src_port = port Field.src_port known_src
                          (Option.map (fun p -> p.src_port) prev) ;
          dst_port = port Field.dst_port known_dst
                          (Option.map (fun p -> p.dst_port) prev) ;
          length = int_of_nth r Field.length gen_values
                       ~auto:(fun () -> 8 + bytelength payload)
                       Kinds.length identity ;
          (* 0, which is the only checksum [Ip.Pdu.pack] computes: *)
          checksum = int_of_nth r Field.checksum gen_values
                         ~auto:(fun () -> 0) Kinds.checksum identity ;
          payload = Payload.o payload }

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

    (*$Q kind
      (Q.make (fun _ -> random ())) (fun t -> \
        try Widget.check_value kind (to_json t) ; true \
        with _ -> false)
     *)
    (*$>*)
end

(** {2 Transceiver} *)

module TRX =
struct
    type udp_trx = {       trx : trx ;
                     get_ports : unit -> Port.t * Port.t }
    type t = {
        logger : Log.t ;
        (* What pays for the events this TRX schedules, and names the clock
         * they run on: the host it belongs to, so that they go down with
         * it. *)
        power : Simulation.power ;
        mutable src : Port.t ; mutable dst : Port.t ;
        mutable emit : bitstring -> unit ;
        mutable recv : bitstring -> unit }

    let tx t bits =
        let udp = Pdu.make ~src_port:t.src ~dst_port:t.dst bits in
        Log.(log t.logger Debug (lazy (Printf.sprintf "Udp: Emitting a packet from %s to %s" (Port.to_string t.src) (Port.to_string t.dst)))) ;
        Simulation.asap t.power t.emit (Pdu.pack udp)

    (* TODO: check checksum *)
    let rx (t : t) bits = (match Pdu.unpack bits with
        | Error s ->
            Log.(log t.logger Warning s)
        | Ok udp ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Udp: Received a datagram"))) ;
            Log.(log t.logger Debug (lazy (Printf.sprintf "Udp: Got a datagram with %d bytes" (Payload.length udp.Pdu.payload)))) ;
            if Payload.bitlength udp.Pdu.payload > 0 then Simulation.asap t.power t.recv (udp.Pdu.payload :> bitstring))

    let trx_of t =
        { trx = { ins = { write = tx t ;
                          set_read = fun f -> t.recv <- f } ;
                  out = { write = rx t;
                          set_read = fun f -> t.emit <- f } } ;
          get_ports = (fun () -> t.src, t.dst) }

    let make power src dst logger =
        let t = { power ; src = src ; dst = dst ;
                  emit = ignore_bits ~logger ;
                  recv = ignore_bits ~logger ;
                  logger } in
        trx_of t
end
