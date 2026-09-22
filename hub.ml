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
open SimTypes
open Bitstring
open Tools

(** A Repeater (or HUB) is a device that receives Eth frames and blindly mirrors them
   to several locations (but the one from which the frame came from) *)
module Repeater =
struct
    type t = { ports : ((bitstring -> unit) * bool) array ;
       mutable speed : Eth.Speed.t ;  (* One of [speeds] *)
  (* A Repeater can only transmit one frame at a time. If another is received
   * while one is copied then both are garbage. The hub will emit a jamming
   * signal for 32bits on all ports, and the hub is effectively unusable during
   * that time.
   * For us, since the bits of a payload are forwarded all at once we just
   * mark the hub as "busy" until the end of the forward, and if any frame is
   * received before that time it will be dropped and an additional jamming
   * of 32bits added on top. *)
  mutable busy_until : Clock.Time.t ;
mutable jamming_time : Clock.Interval.t ; (** Cached from hub's speed *)
              widget : Widget.t ;
              volume : Metric.Counter.t ;
          collisions : Metric.Counter.t }

    type Widget.device += T of t

    (* The repeater a widget stands for, when it stands for one. *)
    let of_widget (w : Widget.t) =
        match w.device with
        | Some (T t) -> Some t
        | _ -> None

    let print oc t =
        Printf.fprintf oc "repeater %s with %d ports" t.widget.name (Array.length t.ports)

    (* Whether port [n] has something on the other end. Set by [set_read]. *)
    let is_connected (t : t) n =
        snd t.ports.(n)

    let write (t : t) n pld =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Rx from port %d/%d" n (Array.length t.ports)))) ;
        let params = Metric.(Params.singleton "port" (Param.Int n)) in
        let now = Simulation.Widget.now t.widget in
        if t.busy_until > now then (
            Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Jammed frame on port %d" n))) ;
            (* Add 32bits of jam: *)
            t.busy_until <- max t.busy_until (Clock.Time.add now t.jamming_time) ;
            (* We can't take back the previous one, but this one is dropped. *)
            Metric.Counter.inc t.collisions ~now ~params
        ) else (
            (* Mark the hub as busy and do transfers that frame *)
            let ttime = Eth.Speed.duration t.speed (bitstring_length pld) in
            t.busy_until <- Clock.Time.add now ttime ;
            Metric.Counter.add t.volume ~now (bytelength pld)
                               ~params:(Eth.dir_params ~port:n "ingress") ;
            (* Forward to all ports but the incoming one: *)
            Array.iteri (fun i (emit, _is_conn) ->
                if i <> n then (
                    Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Forward to port %d/%d" i (Array.length t.ports)))) ;
                    Metric.Counter.add t.volume ~now (bytelength pld)
                        ~params:(Eth.dir_params ~port:i "egress") ;
                    (* Beware: the scheduler will separate simultaneous TX of ε *)
                    Simulation.asap t.widget.power emit pld
                )) t.ports
        )

    let set_read (t : t) n f =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Setting reader for port %d" n))) ;
        t.ports.(n) <- (f, true)

    (** Turns a port into a device *)
    let dev t n =
        { write = write t n ; set_read = set_read t n }

    let t_printer _paren oc t =
        Printf.fprintf oc "%d" (Array.length t.ports)

    (* And undoes it: nothing is emitted to port [n] any more, and it is free
     * for another cable. *)
    let disconnect (t : t) n =
        if is_connected t n then
            t.ports.(n) <-
                (Eth.Iface.ignore_disconnected ~logger:t.widget.logger, false)
        else
            Log.(log t.widget.logger Debug (lazy (Printf.sprintf
                "Ignoring request to disconnect port %d, which is not \
                 connected" n)))

    (* What a repeater can be clocked at, and nothing else: a hub is a 10 or a
     * 100Mbps device, the faster ones having never been built as repeaters. *)
    let speeds = Eth.Speed.[| Eth10Mbps ; Eth100Mbps |]
    let speed_names = Array.map Eth.Speed.to_string speeds

    let make ~parent ?(own_power=true) ?location ?(speed=Eth.Speed.Eth100Mbps)
             n name =
        if not (Array.mem speed speeds) then
            invalid_arg ("Hub.Repeater.make: no hub runs at "^
                         Eth.Speed.to_string speed) ;
        let widget =
            Widget.make ~parent ?location ~device_type:"hub" ~own_power
                        name in
        let t = {
            ports = Array.make n (ignore_bits ~logger:widget.logger, false) ;
            speed ;
            busy_until = Clock.beginning_of_time ;
            jamming_time = Eth.Speed.duration speed 32 ;
            widget ;
            volume = Metric.Counter.make () ;
            collisions = Metric.Counter.make () } in
        widget.device <- Some (T t) ;
        widget.ports <- Widget.{
            count = (fun () -> n) ;
            is_connected = (fun i -> is_connected t i) ;
            dev = dev t ;
            (* Its ports are not widgets, and want no name: one is as good as
             * another, so a cable is recorded as reaching the repeater. *)
            owner = (fun _ -> widget) ;
            disconnect = disconnect t ;
            get_capabilities = (fun ?peer:_ _ ->
                Capabilities.Eth { speeds = [ t.speed ] ; full_duplex = false }) ;
            set_capabilities = (fun _ _ -> ()) } ;
        Widget.add_properties widget Widget.[
            property "speed"
                ~kind:(one_of (choices speed_names))
                ~descr:"Fixed speed for this Hub."
                ~getter:(fun () -> `Int (Array.findi ((=) t.speed) speeds))
                ~setter:(fun v ->
                    t.speed <- speeds.(to_choice (choices speed_names) v) ;
                    t.jamming_time <- Eth.Speed.duration t.speed 32) ;
            metric_property "volume" ~descr:"Volume received and emitted."
                ~units:"bytes"
                (Metric.Counter.T t.volume) ;
            metric_property "collisions" ~descr:"Dropped frames due to collisions."
                (Metric.Counter.T t.collisions) ;
            property "tot ports" ~kind:Int ~descr:"Total number of ports."
                ~getter:(fun () -> `Int (Array.length t.ports)) ] ;
        t
end

(** A Backplane is what joins the parts a device is made of, as against a
  length of shared wire joining devices: everything reaches every other part
  at once, with no speed of its own, no collisions and no jamming.

  Parts are wired to one another rather than taking turns on a segment, so a
  box's insides neither slow down what passes through it nor drop a reply that
  comes back while it is still busy. Nothing is plugged into one from outside
  and it has no ports of its own: whoever builds one wires it by hand, as it
  does the rest of its parts. *)
module Backplane =
struct
    type t = { ports : ((bitstring -> unit) * bool) array ;
              widget : Widget.t ;
              volume : Metric.Counter.t }

    type Widget.device += T of t

    (* The backplane a widget stands for, when it stands for one. *)
    let of_widget (w : Widget.t) =
        match w.device with
        | Some (T t) -> Some t
        | _ -> None

    let print oc t =
        Printf.fprintf oc "backplane %s with %d ports" t.widget.name
                       (Array.length t.ports)

    (* Whether anything is wired to port [n]. Set by [set_read], as a
     * repeater's is: the parts are wired at build time, and the one port a
     * device exposes as a socket of its own is marked when a cable lands. *)
    let is_connected (t : t) n =
        snd t.ports.(n)

    let write (t : t) n pld =
        let now = Simulation.Widget.now t.widget in
        Metric.Counter.add t.volume ~now (bytelength pld)
                           ~params:(Eth.dir_params ~port:n "ingress") ;
        Array.iteri (fun i (emit, _is_conn) ->
            if i <> n then (
                Metric.Counter.add t.volume ~now (bytelength pld)
                    ~params:(Eth.dir_params ~port:i "egress") ;
                (* Through the scheduler rather than straight down the stack:
                   a part that answers at once would otherwise do so from
                   within the call that is still delivering to the others. *)
                Simulation.asap t.widget.power emit pld
            )) t.ports

    let set_read (t : t) n f =
        t.ports.(n) <- (f, true)

    (** Turns a port into a device *)
    let dev t n =
        { write = write t n ; set_read = set_read t n }

    (* And undoes it, for the port a device offers as a socket. *)
    let disconnect (t : t) n =
        if is_connected t n then
            t.ports.(n) <-
                (Eth.Iface.ignore_disconnected ~logger:t.widget.logger, false)
        else
            Log.(log t.widget.logger Debug (lazy (Printf.sprintf
                "Ignoring request to disconnect port %d, which is not \
                 connected" n)))

    let make ~parent ?(own_power=false) n name =
        let widget = Widget.make ~parent ~own_power name in
        let t = {
            ports = Array.make n (ignore_bits ~logger:widget.logger, false) ;
            widget ;
            volume = Metric.Counter.make () } in
        widget.device <- Some (T t) ;
        Widget.add_properties widget Widget.[
            metric_property "volume" ~descr:"Volume received and emitted."
                ~units:"bytes"
                (Metric.Counter.T t.volume) ;
            property "tot ports" ~kind:Int ~descr:"Total number of ports."
                ~getter:(fun () -> `Int (Array.length t.ports)) ] ;
        t
end

(** A Switch is a device that will forward Ethernet frames based on the observed
  location of the destination.
  Contrary to a simple Hub, it does have proper eth adapters that negotiate a
  speed, read eth headers etc; But don't have a full eth stack (no support for
  ARP, no addresses of their own, etc). *)
module Switch =
struct
    type mac_entry =
        { mutable addr : Eth.Addr.t option ;
          mutable iface : int }

    type t =
        { mutable ifaces : Eth.Iface.t array ; (* mutable for two stage construction *)
          (* If the switch is capable of cut-through: *)
          mutable cut_through : bool ;
          macs : mac_entry OrdArray.t ;
          (* Mapping from mac to position in the OrdArray [macs] *)
          macs_h : int BitHash.t ;
          widget : Widget.t ;
          mac_size : Metric.Gauge.t ;
          mac_hits : Metric.Atomic.t ;
          mac_misses : Metric.Atomic.t }

    type Widget.device += T of t

    (* The switch a widget stands for, when it stands for one. *)
    let of_widget (w : Widget.t) =
        match w.device with
        | Some (T t) -> Some t
        | _ -> None

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
                Array.iteri (fun i (iface : Eth.Iface.t) ->
                    if i <> ins && iface.is_connected then (
                        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Forward to iface %d/%d" i (Array.length t.ifaces)))) ;
                        Simulation.asap t.widget.power iface.emit bits
                    )
                ) t.ifaces in
            let do_unicast out =
                let iface = t.ifaces.(out) in
                Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Known dest %s, will forward to iface %d" (Eth.Addr.to_string (Eth.Addr.o dst)) out))) ;
                if iface.is_connected then
                    Simulation.asap t.widget.power iface.emit bits in
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

    let write t n =
        Eth.Iface.write t.ifaces.(n)

    let set_read t n =
        Eth.Iface.set_read t.ifaces.(n)

    let dev t n =
        Eth.Iface.dev t.ifaces.(n)

    (* [num_macs] is the maximum number of remembered MACs. *)
    let make ~parent ?(own_power=true) ?location ?speeds ?full_duplex
             ?(cut_through=true) num_ifaces num_macs name =
        let widget =
            Widget.make ~device_type:"switch" ~parent ?location
                        ~own_power name in
        let t = {
            ifaces = [||] (* See below *) ;
            cut_through ;
            macs = OrdArray.init num_macs (fun _ -> { addr = None ; iface = 0 }) ;
            macs_h = BitHash.create (num_macs/10) ;
            widget ;
            mac_size = Metric.Gauge.make () ;
            mac_hits = Metric.Atomic.make () ;
            mac_misses = Metric.Atomic.make () } in
        (* Cut-through: make the interfaces pay only for deserializing the dest
         * address: *)
        t.ifaces <-
            Array.init num_ifaces (fun i ->
                let name = "#"^ string_of_int i in
                let recv = forward_from t i in
                Eth.Iface.make ~parent:widget ?speeds ?full_duplex ~recv name) ;
        let reset_cut_through () =
            let can_forward_after =
                if t.cut_through then Some (6 * 8) else None in
            Array.iter (fun (i : Eth.Iface.t) ->
                i.can_forward_after <- can_forward_after
            ) t.ifaces in
        reset_cut_through () ;
        widget.device <- Some (T t) ;
        widget.ports <- Widget.{
            count = (fun () -> num_ifaces) ;
            is_connected = (fun i -> t.ifaces.(i).widget.ports.is_connected 0) ;
            dev = (fun i -> t.ifaces.(i).widget.ports.dev 0) ;
            owner = (fun i -> t.ifaces.(i).widget.ports.owner 0) ;
            disconnect = (fun i -> t.ifaces.(i).widget.ports.disconnect 0) ;
            get_capabilities = (fun ?peer i ->
                t.ifaces.(i).widget.ports.get_capabilities ?peer 0) ;
            set_capabilities = (fun i c ->
                t.ifaces.(i).widget.ports.set_capabilities 0 c) } ;
        Widget.add_properties widget Widget.[
            property "cut-through" ~kind:Bool
                ~descr:"If the switch starts transmitting without buffering."
                ~getter:(fun () -> `Bool t.cut_through)
                ~setter:(fun v ->
                    t.cut_through <- to_bool v ;
                    reset_cut_through ()) ;
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

(** A VirtTap is a 2 ifaces repeater which mirror each packet to a user function.
  It can be used as a transparent TRX. *)
module VirtTap =
struct
    type t = trx

    (* If specified, [rev_mirror] will be called with traffic from out to in
     * and [mirror] only with traffic from in to out.
     * If [rev_mirror] is unspecified, [mirror] receives it all. *)
    let make ?rev_mirror mirror =
        let emit_ins = ref ignore
        and emit_out = ref ignore in
        let rev_mirror = rev_mirror |? mirror in
        { ins = { write = (fun bits -> mirror bits ; !emit_out bits) ;
                  set_read = fun f -> emit_ins := f } ;
          out = { write = (fun bits -> rev_mirror bits ; !emit_ins bits) ;
                  set_read = fun f -> emit_out := f } }
end

(* A Tap is a passive 4 ports device: what crosses the link between ports 0 and
 * 1 is copied to port 2 on its way from 0 to 1, and to port 3 on its way back.
 * It is glass and copper only -- no eth iface, no power, no delay of its own,
 * and its ports advertise no capability, so each end of the monitored link
 * settles its speed with the tap rather than with the other end. Which is the
 * point: unlike a hub, a tap does not drag a whole segment down to its own
 * speed.
 *
 * Ports 2 and 3 are outputs. Nothing plugged into one of them ever reaches the
 * link, which is what makes the device safe to insert into traffic one only
 * wants to look at. *)
module Tap =
struct
    type t = {
        widget : Widget.t ;
        (* Per port, whether a cable is on it and what to emit into it. *)
        forward : (bool * (bitstring -> unit)) array ; (* 4 ports *)
        (* Per link port, the port the cable on it reaches, so that either end
         * of the link can be told to negotiate with the other. Learnt when a
         * cable is plugged, which is the only time it is asked for. *)
        peers : (Widget.t * int) option array ; (* 2 link ports *)
    }

    type Widget.device += T of t

    let of_widget (w : Widget.t) =
        match w.device with
        | Some (T t) -> Some t
        | _ -> None

    let num_ports = 4

    (* Ports 0 and 1 are the link, and the mirror of port [n] is [n + 2]. *)
    let is_link_port n = n < 2

    let make ~parent ?location name =
        let widget = Widget.make ~parent ?location ~device_type:"tap" name in
        let t = { widget ;
                  forward = Array.make num_ports (false, ignore) ;
                  peers = Array.make 2 None } in
        widget.ports <- Widget.{
            count = (fun () -> num_ports) ;
            is_connected = (fun n -> fst t.forward.(n)) ;
            dev = (fun n ->
                if is_link_port n then
                    { write = (fun bits ->
                         (snd t.forward.(n + 2)) bits ; (* mirror *)
                         (snd t.forward.(n lxor 1)) bits) ; (* forward *)
                      set_read = fun f -> t.forward.(n) <- true, f }
                else
                    { write = (fun _ ->
                         Log.(log t.widget.logger Debug (lazy (Printf.sprintf
                             "Dropping what was emitted into mirror port#%d, \
                              which is an output" n)))) ;
                      set_read = fun f -> t.forward.(n) <- true, f }) ;
            owner = (fun _ -> t.widget) ;
            disconnect = (fun n ->
                if fst t.forward.(n) then (
                    t.forward.(n) <- false, ignore ;
                    (* Or the far end would go on negotiating against a port
                     * nothing reaches any more. *)
                    if is_link_port n then t.peers.(n) <- None
                ) else
                    Log.(log t.widget.logger Debug (lazy (Printf.sprintf
                        "Ignoring request to disconnect Tap %s free port#%d"
                        t.widget.name n)))) ;
            (* A tap is not an end of the link it is cut into: it sends the
             * question across to whatever is on the other side, so that the
             * two ends settle with each other and keep the speed they would
             * have had on a bare cable. With nothing there yet there is no
             * link to settle; the second cable settles both ends, the question
             * it passes across reaching the first one. Which is also the only
             * time a port is asked who it faces, so this is where that is
             * learnt. *)
            get_capabilities = (fun ?peer n ->
                if not (is_link_port n) then Any else (
                    Option.may (fun p -> t.peers.(n) <- Some p) peer ;
                    match t.peers.(n lxor 1) with
                    | None -> NoCapabilities
                    | Some p -> ForwardTo p)) ;
            (* Never called for a link port, [get_capabilities] having sent
               whoever asked somewhere else; a mirror has nothing to settle. *)
            set_capabilities = (fun _ _ -> ())
        } ;
        Widget.add_properties widget Widget.[
            property "tot ports" ~kind:Int ~descr:"Total number of ports."
                ~getter:(fun () -> `Int num_ports) ] ;
        t

    (* A tap is transparent to negotiation: the two ends settle with each
     * other and not with the glass between them, whichever of the two cables
     * is plugged first. Two ends with nothing in common therefore make no
     * link, exactly as they would on a bare cable. *)
    (*$< Tap *)
    (*$R make
        let link speeds_a speeds_b order =
            let sim = Simulation.make ~realtime:false "tapped" in
            let iface name speeds =
                Eth.Iface.make ~parent:sim.root ~speeds name in
            let a = iface "a" speeds_a
            and b = iface "b" speeds_b
            and tap = make ~parent:sim.root "tap" in
            let plug n (i : Eth.Iface.t) =
                let c = Eth.Cable.State.make ~parent:sim.root
                                             ~name:("c" ^ string_of_int n) () in
                Eth.Cable.plug c (tap.widget, n) (i.widget, 0) in
            List.iter (fun (n, i) -> plug n i) (if order then [ 0, a ; 1, b ]
                                                          else [ 1, b ; 0, a ]) ;
            Eth.Iface.(string_of_negotiated a.negotiated,
                       string_of_negotiated b.negotiated) in
        let printer (x, y) = x ^" / "^ y in
        List.iter (fun order ->
            let msg = if order then "(near end first)" else "(far end first)" in
            assert_equal ~printer ~msg:("the fastest both have "^ msg)
                ("1Gbps full-duplex", "1Gbps full-duplex")
                (link Eth.Speed.[ Eth10Mbps ; Eth1Gbps ; Eth5Gbps ]
                      Eth.Speed.[ Eth100Mbps ; Eth1Gbps ] order) ;
            assert_equal ~printer ~msg:("nothing in common is no link "^ msg)
                ("down", "down")
                (link Eth.Speed.[ Eth10Mbps ] Eth.Speed.[ Eth1Gbps ] order)
        ) [ true ; false ]
     *)
    (*$>*)
end
