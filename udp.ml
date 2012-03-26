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

(* Private Types *)

module Port = Tcp.MakePort (struct let srv = "udp" end)

(* UDP datagrams *)

module Pdu =
struct
    (*$< Pdu *)
    type t = {
        src_port : Port.t ; dst_port : Port.t ;
        checksum : int option ; payload  : Payload.t }

    let make ?(src_port = Port.o 1024) ?(dst_port = Port.o 80)
             ?checksum payload =
        { src_port ; dst_port ; checksum ; payload }

    let random () =
        make ~src_port:(Port.o (randi 16)) ~dst_port:(Port.o (randi 16))
             (Payload.o (randbs 64))

    let pack t =
        let length = Payload.length t.payload + 8 in
        concat [ (BITSTRING {
            (t.src_port :> int) : 16 ; (t.dst_port :> int) : 16 ;
            length : 16 ; (Option.default 0 t.checksum) : 16 }) ;
            (t.payload :> bitstring) ]

    let unpack bits = bitmatch bits with
        | { src_port : 16 ; dst_port : 16 ;
            length   : 16 ; checksum : 16 ;
            payload  : (length-8) * 8 : bitstring } when length >= 8 ->
            Some { src_port = Port.o src_port ; dst_port = Port.o dst_port ;
                   checksum = Some checksum ;
                   payload  = Payload.o payload }
        | { _ } -> err "Not UDP"

    (*$Q pack
      ((random |- pack), dump) (fun t -> t = pack (Option.get (unpack t)))
     *)
    (*$>*)
end

(* Transceiver *)

module TRX =
struct
    type t = {
        mutable src : Port.t ; mutable dst : Port.t option ;
        mutable emit : bitstring -> unit ;
        mutable recv : bitstring -> unit }

    let tx t bits =
        let src_port = t.src and dst_port = Option.get t.dst in
        let udp = Pdu.make ~src_port ~dst_port (Payload.o bits) in
        if debug then Printf.printf "Udp: Emitting a packet from %s to %s\n%!" (Port.to_string src_port) (Port.to_string dst_port) ;
        t.emit (Pdu.pack udp)

    (* TODO: check checksum *)
    let rx t bits = (match Pdu.unpack bits with
        | None -> ()
        | Some udp ->
            if debug then Printf.printf "Udp: Received a datagram\n%!" ;
            if debug then Printf.printf "Udp: Got a datagram with %d bytes\n%!" (Payload.length udp.Pdu.payload) ;
            if Payload.bitlength udp.Pdu.payload > 0 then t.recv (udp.Pdu.payload :> bitstring))

    let make ?dst src =
        let t = { src = src ; dst = dst ;
                  emit = ignore ; recv = ignore } in
        { tx = tx t ;
          rx = rx t ;
          set_emit = (fun f -> t.emit <- f) ;
          set_recv = (fun f -> t.recv <- f) }

    let make_client ~src ~dst = make ~dst src

    let make_server src = make src
end
