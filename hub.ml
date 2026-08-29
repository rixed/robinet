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

(** A Repeater (or HUB) is a device that receives Eth frames and blindly mirrors them
   to several locations (but the one from which the frame came from) *)
module Repeater =
struct
    type t = { ifaces : (bitstring -> unit) array ;
         is_connected : bool array ;
               widget : Widget.t ;
              ingress : Metric.Counter.t ;
               egress : Metric.Counter.t }

    let print oc t =
        Printf.fprintf oc "repeater %s with %d ifaces" t.widget.name (Array.length t.ifaces)

    let make ~parent n name =
        let widget = Widget.make ~parent name in
        let t = {
            ifaces = Array.make n (ignore_bits ~logger:widget.logger) ;
            is_connected = Array.make n false ;
            widget ;
            ingress = Metric.Counter.make () ;
            egress = Metric.Counter.make () } in
        widget.properties <- Widget.[
            metric_property "ingress" ~descr:"Received volume." ~units:"bytes"
                (Metric.Counter.T t.ingress) ;
            metric_property "egress" ~descr:"Emitted volume." ~units:"bytes"
                (Metric.Counter.T t.egress) ] ;
        t

    let forward_from (t : t) n pld =
        Array.iteri (fun i emit ->
            if i <> n then (
                Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Forward to iface %d/%d" i (Array.length t.ifaces)))) ;
                let now = Simulation.Widget.now t.widget in
                Metric.(Counter.add t.egress ~now ~params:(Params.singleton "port" (Param.Int i)) (bytelength pld)) ;
                Simulation.asap (Simulation.of_widget t.widget) emit pld
            )) t.ifaces

    let write (t : t) n pld =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Rx from iface %d/%d" n (Array.length t.ifaces)))) ;
        let now = Simulation.Widget.now t.widget in
        Metric.(Counter.add t.ingress ~now ~params:(Params.singleton "port" (Param.Int n)) (bytelength pld)) ;
        forward_from t n pld

    let set_read (t : t) n f =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Setting reader for iface %d" n))) ;
        t.is_connected.(n) <- true ;
        t.ifaces.(n) <- f

    (** Turns a iface into a device *)
    let iface t n =
        { write = write t n ; set_read = set_read t n }

    let t_printer _paren oc t =
        Printf.fprintf oc "%d" (Array.length t.ifaces)

    let first_free_iface t =
        try Some (Array.findi not t.is_connected)
        with Not_found -> None
end

(** A Switch is a device that will forward Ethernet frames based on the observed
  location of the destination. *)
module Switch =
struct
    module R = Repeater

    type mac_entry =
        { mutable addr : Eth.Addr.t option ;
          mutable iface : int }

    type t =
        { hub  : R.t ;
          macs : mac_entry OrdArray.t ;
          (* Mapping from mac to position in the OrdArray [macs] *)
          macs_h : int BitHash.t ;
          widget : Widget.t ;
          mac_size : Metric.Gauge.t ;
          mac_hits : Metric.Atomic.t ;
          mac_misses : Metric.Atomic.t }

    let print oc t =
        Printf.fprintf oc "switch %s with %d ifaces" t.widget.name (Array.length t.hub.ifaces)

    (* [num_macs] is the maximum number of remembered MACs. *)
    let make ~parent num_ifaces num_macs name =
        let widget = Widget.make ~parent name in
        let t = {
            hub = R.make ~parent:widget num_ifaces "hub" ;
            macs = OrdArray.init num_macs (fun _ -> { addr = None ; iface = 0 }) ;
            macs_h = BitHash.create (num_macs/10) ;
            widget ;
            mac_size = Metric.Gauge.make () ;
            mac_hits = Metric.Atomic.make () ;
            mac_misses = Metric.Atomic.make () } in
        widget.properties <- Widget.[
            metric_property "macs"
                ~descr:"Number of MAC addresses remembered."
                (Metric.Gauge.T t.mac_size) ;
            metric_property "cache hits"
                ~descr:"Number of MAC cache hits."
                (Metric.Atomic.T t.mac_hits) ;
            metric_property "cache misses"
                ~descr:"Number of MAC cache misses."
                (Metric.Atomic.T t.mac_misses) ] ;
        t

    let update_macs t src ins =
        match BitHash.find_option t.macs_h src with
        | None ->
            Log.(log t.widget.logger Debug (lazy (Printf.sprintf "New mac %s" (Eth.Addr.to_string (Eth.Addr.o src))))) ;
            let last_idx = OrdArray.last t.macs in
            let last = OrdArray.get t.macs last_idx in
            (match last.addr with
            | None ->
                let now = Simulation.Widget.now t.widget in
                Metric.Gauge.succ ~now t.mac_size
            | Some addr ->
                (* This MAC which has not been used for long leaves the switch
                 * memory: *)
                BitHash.remove t.macs_h (addr :> bitstring)) ;
            last.addr <- Some (Eth.Addr.o src) ;
            last.iface <- ins ;
            BitHash.add t.macs_h src last_idx ;
            OrdArray.promote t.macs last_idx
        | Some n ->
            let mac = OrdArray.get t.macs n in
            if mac.iface <> ins then (
                Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Host %s changed from iface %d to %d" (Eth.Addr.to_string (Eth.Addr.o src)) mac.iface ins))) ;
                mac.iface <- ins
            ) ;
            OrdArray.promote t.macs n

    let forward_from t ins bits = match%bitstring bits with
        | {| dst : 6*8 : bitstring ;
             src : 6*8 : bitstring |} ->
            (* update mac table for source (before forwarding!) *)
            update_macs t src ins ;
            (* TODO: addresses reserved by 802.1d should not be forwarded. *)
            (* now forward *)
            let do_broadcast () =
                Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Forwarding to all ifaces (but %d)" ins))) ;
                R.forward_from t.hub ins bits in
            if Eth.Addr.is_broadcast (Eth.Addr.o dst) then
                do_broadcast ()
            else (
                let now = Simulation.Widget.now t.widget in
                match BitHash.find_option t.macs_h dst with
                | None ->
                    Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Unknown dest %s, broadcasting" (Eth.Addr.to_string (Eth.Addr.o dst))))) ;
                    Metric.Atomic.fire ~now t.mac_misses ;
                    do_broadcast ()
                | Some n ->
                    Metric.Atomic.fire ~now t.mac_hits ;
                    let mac = OrdArray.get t.macs n in
                    if mac.iface <> ins then (
                        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Known dest %s, will forward to iface %d" (Eth.Addr.to_string (Eth.Addr.o dst)) mac.iface))) ;
                        Simulation.asap (Simulation.of_widget t.widget)
                            t.hub.Repeater.ifaces.(mac.iface) bits ;
                        OrdArray.promote t.macs n
                    ) else
                        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Known dest %s is located on iface %d, dropping" (Eth.Addr.to_string (Eth.Addr.o dst)) mac.iface)))
            )
        | {| _ |} ->
            Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Drop incoming frame without destination")))

    let write (t : t) n pld =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Rx from iface %d/%d" n (Array.length t.hub.ifaces)))) ;
        forward_from t n pld

    let set_read (t : t) n f =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Setting emitter for iface %d/%d" n (Array.length t.hub.ifaces)))) ;
        Repeater.set_read t.hub n f

    (** Turns a iface into a device *)
    let iface (t : t) n =
        { write = write t n ; set_read = set_read t n }

    let first_free_iface t =
        R.first_free_iface t.hub
end

(** A Tap is a 2 ifaces repeater which mirror each packet to a user function.
  It can be used as a transparent TRX. *)
module Tap =
struct
    type t = { trx : trx ;
            widget : Widget.t }

    let make ~parent mirror =
        let widget = Widget.make ~parent "tap" in
        let emit_ins = ref (ignore_bits ~logger:widget.logger)
        and emit_out = ref (ignore_bits ~logger:widget.logger) in
        let trx =
            { ins = { write = (fun bits -> mirror bits ; !emit_out bits) ;
                      set_read = fun f -> emit_ins := f } ;
              out = { write = (fun bits -> mirror bits ; !emit_ins bits) ;
                      set_read = fun f -> emit_out := f } } in
        { trx ; widget }
end
