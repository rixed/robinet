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
 * Ethernet 802.1q Virtual Lan.
 * We decode/encode it for the purpose of manipulating pcap files,
 * but it's currently unused in the network simulator.
 *
 * For more informations see for instance
 * {{:http://en.wikipedia.org/wiki/IEEE_802.1Q} Wikipedia}.
 *)
open Batteries
open Bitstring
open Tools

(** {2 802.1q frames} *)

(** Pack/Unpack a 802.1q tunnel *)
module Pdu = struct
    (*$< Pdu *)
    (** An 802.1q tunnel is very simple indeed *)
    type t = { prio : int ; (** Priority from 0 - best effot - to 7 - highest *)
               cfi : bool ; (** Should be zero if you live after 1990 *)
               id : int ; (** The vlan trag itself *)
               proto : Arp.HwProto.t ; (** What's the payload *)
               payload : Payload.t }

    (** Build a [Vlan.Pdu.t] for the given [payload]. *)
    let make ?(prio=0) ?(cfi=false) id proto bits =
        { prio ; cfi ; id ; proto ; payload = Payload.o bits }

    (** Returns a random [Vlan.Pdu.t]. *)
    let random () =
        make ~prio:(randi 3) (randi 12) (Arp.HwProto.random ()) (randbs 30)

    (** Pack a [Vlan.Pdu.t] into its [bitstring] raw representation, ready for
     * encapsulation into a {!Eth.Pdu.t} (or anywhere you like). *)
    let pack t =
        let%bitstring hdr = {| t.prio : 3 ; t.cfi : 1 ; t.id : 12 ;
                               (t.proto :> int) : 16 |} in
        concat [ hdr ; (t.payload :> bitstring) ]

    (** Unpack a [bitstring] into a [Vlan.Pdu.t] *)
    let unpack bits = match%bitstring bits with
        | {| prio : 3 ; cfi : 1 ; id : 12 ;
             proto : 16 ;
             payload : -1 : bitstring |} ->
            Ok { prio ; cfi ; id ;
                 proto = Arp.HwProto.o proto ;
                 payload = Payload.o payload }
        | {| _ |} ->
            Error (lazy "Not 802.1q")

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)
    (*$>*)
end

(** {2 Transceiver} *)

(** A Vlan TRX accepts raw packets (presumably from some {!Eth.TRX}), unpack them
 * and forward the payload to a callback; and it can be given some payload to
 * tunnel and it will tag it and pass it presumably to an {!Eth.TRX}.
 *
 * Create it with an {!Arp.HwProto.t}, a prio and vlan id. *)
module TRX =
struct
    type t =
        { logger : Log.logger ;
          prio : int ; id : int ;
          proto : Arp.HwProto.t ;
          mutable emit : bitstring -> unit ;
          mutable recv : bitstring -> unit }

    (** Transmit function. [tx t payload] will tunnel the payload through this TRX. *)
    let tx t bits =
        let pdu = Pdu.make ~prio:t.prio t.id t.proto bits in
        Clock.asap t.emit (Pdu.pack pdu)

    (** Receive function, called to output untaggd frames from the 802.1q tunnel. *)
    let rx (t : t) bits = match Pdu.unpack bits with
        | Error s ->
            Log.(log t.logger Warning s)
        | Ok frame ->
            if frame.Pdu.proto = t.proto && Payload.bitlength frame.Pdu.payload > 0 then (
                Clock.asap t.recv (frame.Pdu.payload :> bitstring)
            )

    (** Creates a {!Vlan.TRX.t}.
     * @param prio the tunnel priority (0 = default = lowest, 7 = highest).
     * @param id then vlan tag.
     * @param proto the {!Arp.HwProto.t} we want to transmit/receive.
     *)
    let make prio id proto logger =
        let t = { logger ; prio ; id ; proto ;
                  emit = ignore_bits ~logger ;
                  recv = ignore_bits ~logger } in
        { ins = { write = tx t ;
                  set_read = fun f -> t.recv <- f } ;
          out = { write = rx t ;
                  set_read = fun f -> t.emit <- f } }
end
