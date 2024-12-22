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
        src_port : Port.t ; dst_port : Port.t ;
        payload  : Payload.t }

    let make ?(src_port = Port.o 1024) ?(dst_port = Port.o 80) bits =
        { src_port ; dst_port ; payload = Payload.o bits }

    let random () =
        make ~src_port:(Port.o (randi 16)) ~dst_port:(Port.o (randi 16))
             (randbs 64)

    let pack t =
        let length = Payload.length t.payload + 8 in
        let%bitstring hdr = {|
            (t.src_port :> int) : 16 ; (t.dst_port :> int) : 16 ;
            length : 16 ; 0 : 16 |} in
        concat [ hdr ; (t.payload :> bitstring) ]

    let unpack bits = match%bitstring bits with
        | {| src_port : 16 ; dst_port : 16 ;
             length   : 16 ; _checksum : 16 ;
             payload  : (length-8) * 8 : bitstring |} when length >= 8 ->
            Ok { src_port = Port.o src_port ; dst_port = Port.o dst_port ;
                 payload  = Payload.o payload }
        | {| _ |} -> Error (lazy "Not UDP")

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)
    (*$>*)
end

(** {2 Transceiver} *)

module TRX =
struct
    type udp_trx = {       trx : trx ;
                     get_ports : unit -> Port.t * Port.t }
    type t = {
        logger : Log.logger ;
        mutable src : Port.t ; mutable dst : Port.t ;
        mutable emit : bitstring -> unit ;
        mutable recv : bitstring -> unit }

    let tx t bits =
        let udp = Pdu.make ~src_port:t.src ~dst_port:t.dst bits in
        Log.(log t.logger Debug (lazy (Printf.sprintf "Udp: Emitting a packet from %s to %s" (Port.to_string t.src) (Port.to_string t.dst)))) ;
        Clock.asap t.emit (Pdu.pack udp)

    (* TODO: check checksum *)
    let rx (t : t) bits = (match Pdu.unpack bits with
        | Error s ->
            Log.(log t.logger Warning s)
        | Ok udp ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Udp: Received a datagram"))) ;
            Log.(log t.logger Debug (lazy (Printf.sprintf "Udp: Got a datagram with %d bytes" (Payload.length udp.Pdu.payload)))) ;
            if Payload.bitlength udp.Pdu.payload > 0 then Clock.asap t.recv (udp.Pdu.payload :> bitstring))

    let trx_of t =
        { trx = { ins = { write = tx t ;
                          set_read = fun f -> t.recv <- f } ;
                  out = { write = rx t;
                          set_read = fun f -> t.emit <- f } } ;
          get_ports = (fun () -> t.src, t.dst) }

    let make src dst logger =
        let t = { src = src ; dst = dst ;
                  emit = ignore_bits ~logger ;
                  recv = ignore_bits ~logger ;
                  logger } in
        trx_of t
end
