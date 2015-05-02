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
open Batteries
open Bitstring
open Tools

let debug = false

(** A Repeater (or HUB) is a device that receives Eth frames and blindly mirrors them
   to several locations (but the one from which the frame came from) *)
module Repeater =
struct
    type port = { mutable emit : bitstring -> unit }
    type t = { ports : port array }

    let make n = { ports = Array.init n (fun _ -> { emit = ignore }) }

    let forward_from n t pld =
        Array.iteri (fun i port ->
            if i <> n then (
                if debug then Printf.printf "Repeater:...fwd to port %d\n%!" i ;
                Clock.asap port.emit pld
            )) t.ports

    let write n t pld =
        if debug then Printf.printf "Repeater: rx from port %d\n%!" n ;
        forward_from n t pld

    let set_read n t f =
        if debug then Printf.printf "Repeater: setting emitter for port %d\n%!" n ;
        t.ports.(n).emit <- f

    (** Turns a port into a device *)
    let to_dev n t =
        { write = write n t ; set_read = set_read n t }

    let t_printer _paren oc t =
        Printf.fprintf oc "%d" (Array.length t.ports)

end

(** A Switch is a device that will forward Ethernet frames based on the observed
  location of the destination. *)
module Switch =
struct
    module R = Repeater

    type mac_entry =
        { mutable addr : Eth.Addr.t option ;
          mutable port : int }

    type t =
        { hub  : R.t ;
          macs : mac_entry OrdArray.t ;
          macs_h : int BitHash.t }

    let make nb_ports nb_macs =
        { hub = R.make nb_ports ;
          macs = OrdArray.init nb_macs (fun _ -> { addr = None ; port = 0 }) ;
          macs_h = BitHash.create (nb_macs/10) }

    let forward_from ins t bits = bitmatch bits with
        | { dst : 6*8 : bitstring ;
            src : 6*8 : bitstring } ->
            (* update mac table for source (before forwarding!) *)
            (match BitHash.find_option t.macs_h src with
            | None ->
                if debug then Printf.printf "Switch: new mac %s\n%!" (Eth.Addr.to_string (Eth.Addr.o src)) ;
                let last_idx = OrdArray.last t.macs in
                let last = OrdArray.get t.macs last_idx in
                (match last.addr with None -> () | Some addr ->
                    BitHash.remove t.macs_h (addr :> bitstring)) ;
                last.addr <- Some (Eth.Addr.o src) ;
                last.port <- ins ;
                BitHash.add t.macs_h src last_idx ;
                OrdArray.promote t.macs last_idx
            | Some n ->
                let mac = OrdArray.get t.macs n in
                if mac.port <> ins then (
                    if debug then Printf.printf "Switch: host %s changed from port %d to %d\n"
                        (Eth.Addr.to_string (Eth.Addr.o src)) n ins ;
                    mac.port <- ins
                ) ;
                OrdArray.promote t.macs n) ;
            (* TODO: addresses reserved by 802.1d should not be forwarded. *)
            (* now forward *)
            (match BitHash.find_option t.macs_h dst with
            | None ->
                if debug then Printf.printf "Switch: unknown dest %s, broadcasting\n%!"
                    (Eth.Addr.to_string (Eth.Addr.o dst)) ;
                R.forward_from ins t.hub bits
            | Some n ->
                Clock.asap t.hub.Repeater.ports.((OrdArray.get t.macs n).port).Repeater.emit bits ;
                OrdArray.promote t.macs n)
        | { _ } ->
            if debug then Printf.printf "Switch: drop incoming frame without destination\n%!"

    let write n t pld =
        if debug then Printf.printf "Switch: rx from port %d\n%!" n ;
        forward_from n t pld

    let set_read n t f =
        if debug then Printf.printf "Switch: setting emitter for port %d\n%!" n ;
        Repeater.set_read n t.hub f

    (** Turns a port into a device *)
    let to_dev n t =
        { write = write n t ; set_read = set_read n t }

end

(** A Tap is a 2 port repeater wich mirror each packet to a user function.
  It can be used as a transparent TRX. *)
module Tap =
struct
    type t = trx

    let make mirror =
        let emit_ins = ref ignore and emit_out = ref ignore in
        { ins = { write = (fun bits -> mirror bits ; !emit_out bits) ;
                  set_read = fun f -> emit_ins := f } ;
          out = { write = (fun bits -> mirror bits ; !emit_ins bits) ;
                  set_read = fun f -> emit_out := f } }

end
