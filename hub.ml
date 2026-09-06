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
    type t = { ports : ((bitstring -> unit) * bool) array ;
               speed : float ;  (* Fixed speed, in bps *)
               power : Simulation.power ;
              widget : Widget.t ;
             ingress : Metric.Counter.t ;
              egress : Metric.Counter.t }

    let print oc t =
        Printf.fprintf oc "repeater %s with %d ports" t.widget.name (Array.length t.ports)

    (* Whether port [n] has something on the other end. Set by [set_read]. *)
    let is_connected (t : t) n =
        snd t.ports.(n)

    let forward_from (t : t) n pld =
        let now = Simulation.Widget.now t.widget in
        Array.iteri (fun i (emit, _is_conn) ->
            if i <> n then (
                Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Forward to port %d/%d" i (Array.length t.ports)))) ;
                Metric.(Counter.add t.egress ~now ~params:(Params.singleton "port" (Param.Int i)) (bytelength pld)) ;
                Simulation.asap t.power emit pld
            )) t.ports

    let write (t : t) n pld =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Rx from port %d/%d" n (Array.length t.ports)))) ;
        let now = Simulation.Widget.now t.widget in
        Metric.(Counter.add t.ingress ~now ~params:(Params.singleton "port" (Param.Int n)) (bytelength pld)) ;
        forward_from t n pld

    let set_read (t : t) n f =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Setting reader for port %d" n))) ;
        t.ports.(n) <- (f, true)

    (** Turns a port into a device *)
    let dev t n =
        { write = write t n ; set_read = set_read t n }

    let t_printer _paren oc t =
        Printf.fprintf oc "%d" (Array.length t.ports)

    let first_free_iface t =
        try Some (Array.findi (fun (_emit, is_conn) -> not is_conn) t.ports)
        with Not_found -> None

    (* And undoes it: nothing is emitted to port [n] any more, and it is free
       for another cable. *)
    let disconnect (t : t) n =
        if is_connected t n then
            t.ports.(n) <-
                (Eth.State.ignore_disconnected ~logger:t.widget.logger, false)
        else
            Log.(log t.widget.logger Debug (lazy (Printf.sprintf
                "Ignoring request to disconnect port %d, which is not \
                 connected" n)))

    let make ~parent ?location ?(speed=100e6) n name =
        let widget = Widget.make ~parent ?location ~device:"hub" name in
        let t = {
            ports = Array.make n (ignore_bits ~logger:widget.logger, false) ;
            speed ;
            power = Simulation.make_power (Simulation.of_widget widget) name ;
            widget ;
            ingress = Metric.Counter.make () ;
            egress = Metric.Counter.make () } in
        (* This repeater minted the supply above; a switch's inner one is a
           child of the switch, so deleting the switch reaches it. *)
        widget.on_delete <- (fun () -> Simulation.power_down t.power) ;
        widget.ports <- Widget.{
            count = (fun () -> n) ;
            is_connected = (fun i -> is_connected t i) ;
            dev = dev t ;
            (* Its ports are not widgets, and want no name: one is as good as
               another, so a cable is recorded as reaching the repeater. *)
            owner = (fun _ -> widget) ;
            disconnect = disconnect t } ;
        Widget.add_properties widget Widget.[
            property "speed" ~kind:Float ~descr:"Fixed speed for this Hub."
                ~units:"bps" ~getter:(fun () -> `Float t.speed) ;
            metric_property "ingress" ~descr:"Received volume." ~units:"bytes"
                (Metric.Counter.T t.ingress) ;
            metric_property "egress" ~descr:"Emitted volume." ~units:"bytes"
                (Metric.Counter.T t.egress) ;
            property "tot ports" ~kind:Int ~descr:"Total number of ports."
                ~getter:(fun () -> `Int (Array.length t.ports)) ] ;
        t
end

(** A Switch is a device that will forward Ethernet frames based on the observed
  location of the destination.
  Contrary to a simple Hub, it does have proper eth adapters that negociate a
  speed, read eth headers etc; But don't have a full eth stack (no support for
  ARP, no addresses of their own, etc). *)
module Switch =
struct
    type mac_entry =
        { mutable addr : Eth.Addr.t option ;
          mutable iface : int }

    (* Each interface is its own widget for easier configuration: *)
    type iface =
        { widget : Widget.t ;
          mutable emit : bitstring -> unit ;
          mutable is_connected : bool ;
          (* It's very common for a single switch to have ports with different
           * characteristics: *)
          mutable speeds : float list ;
          mutable full_duplex : bool ;
          ingress : Metric.Counter.t ;
          egress : Metric.Counter.t }

    let default_speeds = [ 10e6 ; 100e6 ; 1000e6 ; 2.5e9 ; 5e9 ]

    let make_iface ~parent ~speeds ~full_duplex name =
        let widget = Widget.make ~parent name in
        let iface =
            { widget ;
              emit = ignore_bits ~logger:widget.logger ;
              is_connected = false ;
              speeds ; full_duplex ;
              ingress = Metric.Counter.make () ;
              egress = Metric.Counter.make () } in
        Widget.add_properties widget Widget.[
            property "connected" ~kind:Bool
                ~descr:"Is this interface connected?"
                ~getter:(fun () -> `Bool iface.is_connected) ;
            property "speeds" ~kind:(List Float) ~units:"bps"
                ~descr:"Accepted speeds for this interface"
                ~getter:(fun () -> `List (List.map (fun s -> `Float s) iface.speeds))
                (* TODO: ~setter *) ;
            property "full-duplex" ~kind:Bool
                ~descr:"If a port can receive and transmit at the same time."
                ~getter:(fun () -> `Bool iface.full_duplex) ;
            metric_property "ingress" ~descr:"Received volume." ~units:"bytes"
                (Metric.Counter.T iface.ingress) ;
            metric_property "egress" ~descr:"Emitted volume." ~units:"bytes"
                (Metric.Counter.T iface.egress) ] ;
        iface

    type t =
        { ifaces : iface array ;
          (* If the switch is capable of cut-through: *)
          mutable cut_through : bool ;
          macs : mac_entry OrdArray.t ;
          (* Mapping from mac to position in the OrdArray [macs] *)
          macs_h : int BitHash.t ;
          widget : Widget.t ;
          power : Simulation.power ;
          mac_size : Metric.Gauge.t ;
          mac_hits : Metric.Atomic.t ;
          mac_misses : Metric.Atomic.t }

    let print oc t =
        Printf.fprintf oc "switch %s with %d ifaces" t.widget.name (Array.length t.ifaces)

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
                let now = Simulation.Widget.now t.widget in
                Array.iteri (fun i (iface : iface) ->
                    if i <> ins && iface.is_connected then (
                        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Forward to iface %d/%d" i (Array.length t.ifaces)))) ;
                        Metric.(Counter.add iface.egress ~now (bytelength bits)) ;
                        Simulation.asap t.power iface.emit bits
                    )
                ) t.ifaces in
            let do_unicast out =
                let iface = t.ifaces.(out) in
                Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Known dest %s, will forward to iface %d" (Eth.Addr.to_string (Eth.Addr.o dst)) out))) ;
                if iface.is_connected then (
                    let now = Simulation.Widget.now t.widget in
                    Metric.(Counter.add iface.egress ~now (bytelength bits)) ;
                    Simulation.asap t.power iface.emit bits
                ) in
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
                        do_unicast mac.iface ;
                        OrdArray.promote t.macs n
                    ) else
                        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Known dest %s is located on iface %d, dropping" (Eth.Addr.to_string (Eth.Addr.o dst)) mac.iface)))
            )
        | {| _ |} ->
            Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Drop incoming frame without destination")))

    let write (t : t) n pld =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Rx from iface %d/%d" n (Array.length t.ifaces)))) ;
        let now = Simulation.Widget.now t.widget in
        Metric.(Counter.add t.ifaces.(n).ingress ~now (bytelength pld)) ;
        forward_from t n pld

    let set_read (t : t) n f =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Setting emitter for iface %d/%d" n (Array.length t.ifaces)))) ;
        t.ifaces.(n).emit <- f ;
        t.ifaces.(n).is_connected <- true

    (** Turns a iface into a device *)
    let dev (t : t) n =
        { write = write t n ; set_read = set_read t n }

    let first_free_iface t =
        try Some (Array.findi (fun iface -> not iface.is_connected) t.ifaces)
        with Not_found -> None

    let disconnect (t : t) n =
        if t.ifaces.(n).is_connected then (
            let iface = t.ifaces.(n) in
            iface.emit <- Eth.State.ignore_disconnected ~logger:t.widget.logger ;
            iface.is_connected <- false
        ) else
            Log.(log t.widget.logger Debug (lazy (Printf.sprintf
                "Ignoring request to disconnect port %d, which is not \
                 connected" n)))

    (* [num_macs] is the maximum number of remembered MACs. *)
    let make ~parent ?location
             ?(speeds=default_speeds) ?(full_duplex=true) ?(cut_through=true)
             num_ifaces num_macs name =
        let widget = Widget.make ~device:"switch" ~parent ?location name in
        let t = {
            ifaces =
                Array.init num_ifaces (fun i ->
                    let name = "#"^ string_of_int i in
                    make_iface ~parent:widget ~speeds ~full_duplex name) ;
            cut_through ;
            macs = OrdArray.init num_macs (fun _ -> { addr = None ; iface = 0 }) ;
            macs_h = BitHash.create (num_macs/10) ;
            widget ;
            power = Simulation.make_power (Simulation.of_widget widget) name ;
            mac_size = Metric.Gauge.make () ;
            mac_hits = Metric.Atomic.make () ;
            mac_misses = Metric.Atomic.make () } in
        widget.on_delete <- (fun () -> Simulation.power_down t.power) ;
        (* A port one can tell from the one beside it -- its own speeds, its own
           counters -- is a port a cable must be able to name, so each interface
           offers the one port it is. The switch then numbers those, as a router
           numbers its interfaces: naming the switch and naming the interface
           reach the same port. *)
        Array.iteri (fun i (iface : iface) ->
            iface.widget.Widget.ports <- Widget.{
                count = (fun () -> 1) ;
                is_connected = (fun _ -> iface.is_connected) ;
                dev = (fun _ -> dev t i) ;
                owner = (fun _ -> iface.widget) ;
                disconnect = (fun _ -> disconnect t i) }
        ) t.ifaces ;
        widget.Widget.ports <- Widget.{
            count = (fun () -> num_ifaces) ;
            is_connected = (fun i -> t.ifaces.(i).widget.ports.is_connected 0) ;
            dev = (fun i -> t.ifaces.(i).widget.ports.dev 0) ;
            owner = (fun i -> t.ifaces.(i).widget.ports.owner 0) ;
            disconnect = (fun i -> t.ifaces.(i).widget.ports.disconnect 0) } ;
        Widget.add_properties widget Widget.[
            property "cut-through" ~kind:Bool
                ~descr:"If the switch starts transmitting without buffering."
                ~getter:(fun () -> `Bool t.cut_through)
                ~setter:(fun v -> t.cut_through <- to_bool v) ;
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
end

(** A Tap is a 2 ifaces repeater which mirror each packet to a user function.
  It can be used as a transparent TRX. *)
module Tap =
struct
    type t = { trx : trx ;
            widget : Widget.t }

    let make ~parent ?location mirror =
        let widget = Widget.make ~parent ?location "tap" in
        let emit_ins = ref (ignore_bits ~logger:widget.logger)
        and emit_out = ref (ignore_bits ~logger:widget.logger) in
        let trx =
            { ins = { write = (fun bits -> mirror bits ; !emit_out bits) ;
                      set_read = fun f -> emit_ins := f } ;
              out = { write = (fun bits -> mirror bits ; !emit_ins bits) ;
                      set_read = fun f -> emit_out := f } } in
        { trx ; widget }
end
