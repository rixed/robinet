(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(* Copyright 2026, Cedric Cellier
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
(** A box that drops what goes from its port 0 to its port 1 beyond the
   limits it is given; what goes the other way passes as it is.

   Limits on totals (packets, volume, duration) once reached drop everything,
   until their flag is reset, which restarts their count. Limits on rates
   (packets per second, bytes per second) drop what goes beyond them, with a
   token bucket that holds a second's worth. The limits on SYNs (TCP SYN
   without ACK, that open connections), a total and a rate, work the same but
   drop only SYNs. The duration counts from the power-on, or from the first
   packet. Switched off, it passes nothing. *)
open Batteries
open Bitstring
open SimTypes
open Tools
module Interval = Clock.Interval
module Time = Clock.Time

(** What made a frame be dropped: *)
type limit = Expired | Max_packets | Max_volume | Max_packet_rate | Max_throughput
           | Max_syns | Max_syn_rate

let string_of_limit = function
    | Expired -> "expired"
    | Max_packets -> "max-packets"
    | Max_volume -> "max-volume"
    | Max_packet_rate -> "max-packet-rate"
    | Max_throughput -> "max-throughput"
    | Max_syns -> "max-syns"
    | Max_syn_rate -> "max-syn-rate"

(** When the duration starts counting: *)
type start = At_power_on | At_first_packet

let start_names = [| "at power on" ; "at first packet" |]

let start_of_int = function 0 -> At_power_on | _ -> At_first_packet

let int_of_start = function At_power_on -> 0 | At_first_packet -> 1

(* A token bucket of [rate] per second, holding a second's worth, with its
 * remaining tokens: *)
type bucket =
    { mutable rate : float option ;
      mutable last : Time.t ;
      mutable tokens : float }

type t =
    { widget : Widget.t ;
      start : start ;
      (* Called when a limit starts dropping: *)
      mutable on_limit : limit -> unit ;
      (* Per port, whether a cable is on it and what to emit into it: *)
      forward : (bool * (bitstring -> unit)) array ;
      (* Per port, the port the cable on it reaches (see {!Hub.Tap}): *)
      peers : (Widget.t * int) option array ;
      mutable max_packets : int option ;
      mutable packets : int ;
      (* In bytes of frames: *)
      mutable max_volume : int option ;
      mutable volume : int ;
      mutable max_duration : Interval.t option ;
      (* When the duration started counting, if it has: *)
      mutable started : Time.t option ;
      (* Only the last timer armed for the duration is live: *)
      mutable timer_gen : int ;
      mutable max_syns : int option ;
      mutable syns : int ;
      packet_rate : bucket ;
      throughput : bucket ;
      syn_rate : bucket ;
      (* The limits that are dropping: for the totals until reset, for the
       * rates until their bucket is full again: *)
      mutable dropping : limit list ;
      dropped : Metric.Counter.t }

type Widget.device += T of t

let of_widget (w : Widget.t) =
    match w.device with
    | Some (T t) -> Some t
    | _ -> None

let now t = Simulation.Widget.now t.widget

let is_total = function
    | Expired | Max_packets | Max_volume -> true
    | Max_packet_rate | Max_throughput | Max_syns | Max_syn_rate -> false

(* Whether that limit is dropping, now that a frame met it: *)
let hit t limit =
    if not (List.mem limit t.dropping) then (
        t.dropping <- limit :: t.dropping ;
        t.on_limit limit)

let elapsed t =
    match t.started with
    | None -> Interval.zero
    | Some s -> Time.diff (now t) s

(* Expiring at the end of the duration, rather than at the next frame, for
 * [on_limit] to be told then: *)
let rec arm t =
    t.timer_gen <- t.timer_gen + 1 ;
    match t.max_duration, t.started with
    | Some d, Some _ ->
        let gen = t.timer_gen in
        let left = Interval.sub d (elapsed t) in
        if Interval.compare left Interval.zero <= 0 then hit t Expired
        else Simulation.delay t.widget.power left (fun () ->
            if gen = t.timer_gen then arm t) ()
    | _ -> ()

let start_counting t =
    t.started <- Some (now t) ;
    arm t

(* Restarts the count of that total: *)
let reset t limit =
    t.dropping <- List.filter ((<>) limit) t.dropping ;
    match limit with
    | Max_packets -> t.packets <- 0
    | Max_volume -> t.volume <- 0
    | Max_syns -> t.syns <- 0
    | Expired ->
        (match t.start with
        | At_power_on -> start_counting t
        | At_first_packet -> t.started <- None ; arm t)
    | Max_packet_rate | Max_throughput | Max_syn_rate -> ()

(* Refills [b], the bucket of [limit], which stops dropping once full: *)
let refill t b limit =
    Option.may (fun rate ->
        let now = now t in
        let elapsed = Interval.to_secs (Time.diff now b.last) in
        b.tokens <- Float.min rate (b.tokens +. elapsed *. rate) ;
        b.last <- now ;
        if b.tokens >= rate then t.dropping <- List.filter ((<>) limit) t.dropping
    ) b.rate

(* Whether [b] has [n] tokens; without a rate, it has: *)
let has b n = b.rate = None || b.tokens >= n

let spend b n =
    if b.rate <> None then b.tokens <- b.tokens -. n

(* Whether that frame opens a TCP connection (SYN without ACK), over IPv4 or
 * IPv6, with VLAN tags or not: *)
let is_syn bits =
    let tcp bits =
        match Tcp.Pdu.unpack bits with
        | Ok tcp -> tcp.flags.syn && not tcp.flags.ack
        | Error _ -> false in
    let ip6 bits =
        match Ip6.Pdu.unpack bits with
        | Ok ip -> ip.proto = Ip.Proto.tcp && tcp (ip.payload :> bitstring)
        | Error _ -> false in
    let ip bits =
        match Ip.Pdu.unpack bits with
        | Ok ip when ip.frag_offset = 0 ->
            if ip.proto = Ip.Proto.tcp then tcp (ip.payload :> bitstring)
            else ip.proto = Ip.Proto.ipv6 && ip6 (ip.payload :> bitstring)
        | _ -> false in
    let rec l3 proto bits =
        if proto = Arp.HwProto.ip4 then ip bits
        else if proto = Arp.HwProto.ip6 then ip6 bits
        else if proto = Arp.HwProto.ieee8021q then
            match Vlan.Pdu.unpack bits with
            | Ok vlan -> l3 vlan.proto (vlan.payload :> bitstring)
            | Error _ -> false
        else false in
    match Eth.Pdu.unpack bits with
    | Ok eth -> l3 eth.proto (eth.payload :> bitstring)
    | Error _ -> false

let set_rate t b rate =
    b.rate <- rate ;
    b.last <- now t ;
    b.tokens <- rate |? 0.

(* The limit that drops this frame of [len] bytes, if any; otherwise its
 * tokens are taken: *)
let limit_for t len syn =
    let beyond max v = Option.map_default (fun m -> v > m) false max in
    let len = float_of_int len and syns = if syn then 1. else 0. in
    match List.find_opt is_total t.dropping with
    | Some l -> Some l
    | None ->
        refill t t.packet_rate Max_packet_rate ;
        refill t t.throughput Max_throughput ;
        refill t t.syn_rate Max_syn_rate ;
        if Option.is_some t.max_duration && Option.is_some t.started &&
           Interval.compare (elapsed t) (Option.get t.max_duration) >= 0 then
            Some Expired
        else if beyond t.max_packets (t.packets + 1) then Some Max_packets
        else if beyond t.max_volume (t.volume + int_of_float len) then Some Max_volume
        else if syn && (List.mem Max_syns t.dropping ||
                        beyond t.max_syns (t.syns + 1)) then Some Max_syns
        else if not (has t.packet_rate 1.) then Some Max_packet_rate
        else if not (has t.throughput len) then Some Max_throughput
        else if not (has t.syn_rate syns) then Some Max_syn_rate
        else (
            spend t.packet_rate 1. ;
            spend t.throughput len ;
            spend t.syn_rate syns ;
            None)

let police t bits =
    if t.widget.power.on then (
        if t.started = None && t.start = At_first_packet then start_counting t ;
        let len = bitstring_length bits / 8 and syn = is_syn bits in
        match limit_for t len syn with
        | Some limit ->
            Metric.Counter.inc t.dropped ~now:(now t)
                ~params:(Metric.Params.singleton "cause"
                             (Metric.Param.String (string_of_limit limit))) ;
            hit t limit
        | None ->
            t.packets <- t.packets + 1 ;
            t.volume <- t.volume + len ;
            if syn then t.syns <- t.syns + 1 ;
            (snd t.forward.(1)) bits)

let num_ports = 2

let make ~parent ?location ?(start=At_power_on) ?max_packets ?max_volume
         ?max_packet_rate ?max_throughput ?max_duration ?max_syns ?max_syn_rate
         ?(on_limit=ignore) name =
    let widget =
        Widget.make ~parent ?location ~device_type:"policer" ~own_power:true
                    name in
    let bucket rate = { rate ; last = Time.beginning_of_time ; tokens = rate |? 0. } in
    let t = { widget ; start ; on_limit ;
              forward = Array.make num_ports (false, ignore) ;
              peers = Array.make num_ports None ;
              max_packets ; packets = 0 ; max_volume ; volume = 0 ;
              max_duration ; started = None ; timer_gen = 0 ;
              max_syns ; syns = 0 ;
              packet_rate = bucket max_packet_rate ;
              throughput = bucket max_throughput ;
              syn_rate = bucket max_syn_rate ;
              dropping = [] ;
              dropped = Metric.Counter.make () } in
    widget.device <- Some (T t) ;
    widget.ports <- Widget.{
        count = (fun () -> num_ports) ;
        is_connected = (fun n -> fst t.forward.(n)) ;
        dev = (fun n ->
            { write = (if n = 0 then police t
                       else fun bits -> if t.widget.power.on then (snd t.forward.(0)) bits) ;
              busy_for = never_busy ;
              set_read = fun f _ -> t.forward.(n) <- true, f }) ;
        owner = (fun _ -> t.widget) ;
        disconnect = (fun n ->
            t.forward.(n) <- false, ignore ;
            t.peers.(n) <- None) ;
        (* Transparent to negotiation, as a tap is: *)
        get_capabilities = (fun ?peer n ->
            Option.may (fun p -> t.peers.(n) <- Some p) peer ;
            match t.peers.(n lxor 1) with
            | None -> NoCapabilities
            | Some p -> ForwardTo p) ;
        set_capabilities = (fun _ _ -> ())
    } ;
    widget.power_up <- (fun () ->
        set_rate t t.packet_rate t.packet_rate.rate ;
        set_rate t t.throughput t.throughput.rate ;
        set_rate t t.syn_rate t.syn_rate.rate ;
        match start with
        | At_power_on -> start_counting t
        | At_first_packet -> ()) ;
    let opt_int = function `Null -> None | v -> Some (Widget.to_int_range ~min:0 v)
    and opt_float = function `Null -> None | v -> Some (Widget.to_float_range ~min:0. v)
    and int_opt = function None -> `Null | Some i -> `Int i
    and float_opt = function None -> `Null | Some f -> `Float f in
    (* A flag that is only reset, which restarts the count: *)
    let flag name limit descr =
        Widget.property name ~kind:Bool ~descr
            ~getter:(fun () -> `Bool (List.mem limit t.dropping))
            ~setter:(fun v ->
                if Widget.to_bool v then
                    Widget.bad_value "%s can only be reset, to false" name ;
                reset t limit) in
    Widget.add_properties widget Widget.[
        property "start" ~kind:(one_of (choices start_names))
            ~descr:"When the duration starts counting."
            ~getter:(fun () -> `Int (int_of_start start)) ;
        property "max packets" ~kind:(optional Int)
            ~descr:"How many packets may pass."
            ~getter:(fun () -> int_opt t.max_packets)
            ~setter:(fun v -> t.max_packets <- opt_int v) ;
        property "packets" ~kind:Int
            ~descr:"How many packets passed, toward the maximum."
            ~getter:(fun () -> `Int t.packets) ;
        flag "max packets reached" Max_packets
            "Whether everything is dropped for having passed the maximum \
             number of packets (reset it to start counting again)." ;
        property "max volume" ~kind:(optional Int) ~units:"bytes"
            ~descr:"How many bytes of frames may pass."
            ~getter:(fun () -> int_opt t.max_volume)
            ~setter:(fun v -> t.max_volume <- opt_int v) ;
        property "volume" ~kind:Int ~units:"bytes"
            ~descr:"How many bytes of frames passed, toward the maximum."
            ~getter:(fun () -> `Int t.volume) ;
        flag "max volume reached" Max_volume
            "Whether everything is dropped for having passed the maximum \
             volume (reset it to start counting again)." ;
        property "max duration" ~kind:(optional Duration)
            ~descr:"For how long frames may pass."
            ~getter:(fun () ->
                float_opt (Option.map Interval.to_secs t.max_duration))
            ~setter:(fun v ->
                t.max_duration <- Option.map Interval.of_secs (opt_float v) ;
                arm t) ;
        property "elapsed" ~kind:Duration
            ~descr:"For how long frames have been passing, toward the maximum \
                    duration."
            ~getter:(fun () -> `Float (Interval.to_secs (elapsed t))) ;
        flag "expired" Expired
            "Whether everything is dropped for the maximum duration being \
             over (reset it to start counting again)." ;
        property "max packet rate" ~kind:(optional Float) ~units:"packets/s"
            ~descr:"How many packets may pass per second, beyond which they \
                    are dropped (a second's worth may pass at once)."
            ~getter:(fun () -> float_opt t.packet_rate.rate)
            ~setter:(fun v -> set_rate t t.packet_rate (opt_float v)) ;
        property "max throughput" ~kind:(optional Float) ~units:"bytes/s"
            ~descr:"How many bytes of frames may pass per second, beyond \
                    which they are dropped (a second's worth may pass at once)."
            ~getter:(fun () -> float_opt t.throughput.rate)
            ~setter:(fun v -> set_rate t t.throughput (opt_float v)) ;
        property "max syns" ~kind:(optional Int)
            ~descr:"How many TCP SYNs (without ACK) may pass."
            ~getter:(fun () -> int_opt t.max_syns)
            ~setter:(fun v -> t.max_syns <- opt_int v) ;
        property "syns" ~kind:Int
            ~descr:"How many TCP SYNs passed, toward the maximum."
            ~getter:(fun () -> `Int t.syns) ;
        flag "max syns reached" Max_syns
            "Whether SYNs are dropped for having passed the maximum number \
             of SYNs (reset it to start counting again)." ;
        property "max syn rate" ~kind:(optional Float) ~units:"SYNs/s"
            ~descr:"How many TCP SYNs (without ACK) may pass per second, beyond \
                    which they are dropped (a second's worth may pass at once)."
            ~getter:(fun () -> float_opt t.syn_rate.rate)
            ~setter:(fun v -> set_rate t t.syn_rate (opt_float v)) ;
        metric_property "dropped"
            ~descr:"Packets dropped, by the limit that dropped them."
            (Metric.Counter.T t.dropped) ] ;
    t

(* [frames ?first ?limits ()] is what passes when a frame of 46 bytes is
 * sent every millisecond from [first] ms to 300ms, through a policer with
 * these limits switched on at the start: how many frames passed by 5.5ms,
 * 100.5ms and 300ms, then the limits that started dropping, and when. *)
(*$inject
  let frames ?(first=0) ?start ?max_packets ?max_volume ?max_packet_rate ?max_throughput ?max_duration () =
      let sim = Simulation.make ~realtime:false "policer" in
      let hits = ref [] in
      let on_limit l =
          hits := Printf.sprintf "%s at %s" (string_of_limit l)
                      (Clock.Time.to_string (Simulation.now sim)) :: !hits in
      let t = make ~parent:sim.root ?start ?max_packets ?max_volume ?max_packet_rate
                   ?max_throughput ?max_duration ~on_limit "p" in
      let passed = ref 0 in
      Tools.((t.widget.ports.dev 1) --> sink (fun _ -> incr passed)) ;
      Simulation.power_up t.widget.power ;
      for i = first to 299 do
          Simulation.at sim.root.power (Clock.Time.of_secs (float_of_int i /. 1000.))
              (t.widget.ports.dev 0).write (Bitstring.create_bitstring (46 * 8))
      done ;
      let seen = ref [] in
      List.iter (fun ms ->
          Simulation.at sim.root.power (Clock.Time.of_secs (ms /. 1000.)) (fun () ->
              seen := Printf.sprintf "%gms:%d" ms !passed :: !seen) ()
      ) [ 5.5 ; 100.5 ; 300. ] ;
      Simulation.run sim false ;
      String.concat " " (List.rev !seen) ^ " | " ^ String.concat ", " (List.rev !hits)
*)
(*$= frames & ~printer:identity
  "5.5ms:6 100.5ms:101 300ms:300 | " (frames ())
  "5.5ms:3 100.5ms:3 300ms:3 | max-packets at 3ms" (frames ~max_packets:3 ())
  "5.5ms:4 100.5ms:4 300ms:4 | max-volume at 4ms" (frames ~max_volume:200 ())
  "5.5ms:0 100.5ms:50 300ms:50 | expired at 100ms" \
    (frames ~first:50 ~max_duration:(Clock.Interval.msec 100.) ())
  "5.5ms:0 100.5ms:51 300ms:100 | expired at 150ms" \
    (frames ~first:50 ~start:At_first_packet ~max_duration:(Clock.Interval.msec 100.) ())
  "5.5ms:6 100.5ms:101 300ms:129 | max-packet-rate at 110ms" \
    (frames ~max_packet_rate:100. ())
  "5.5ms:6 100.5ms:101 300ms:129 | max-throughput at 110ms" \
    (frames ~max_throughput:4600. ())
*)
(* [tcp_frame ?vlan ?v6 ~syn ~ack ()] is a frame of a TCP segment with these
 * flags: *)
(*$inject
  let tcp_frame ?(vlan=false) ?(v6=false) ~syn ~ack () =
      let tcp = Tcp.Pdu.(pack (make ~syn ~ack Bitstring.empty_bitstring)) in
      let ip, proto =
          if v6 then
              Ip6.Pdu.(pack (make Ip.Proto.tcp (Ip.Addr.of_string "::1")
                                  (Ip.Addr.of_string "::2") tcp)), Arp.HwProto.ip6
          else
              Ip.Pdu.(pack (make Ip.Proto.tcp (Ip.Addr.of_string "10.0.0.1")
                                 (Ip.Addr.of_string "10.0.0.2") tcp)), Arp.HwProto.ip4 in
      let payload, proto =
          if vlan then Vlan.Pdu.(pack (make 42 proto ip)), Arp.HwProto.ieee8021q
          else ip, proto in
      Eth.Pdu.(pack (make proto (Eth.Addr.random ()) (Eth.Addr.random ()) payload))
*)
(*$T is_syn
  is_syn (tcp_frame ~syn:true ~ack:false ())
  is_syn (tcp_frame ~vlan:true ~syn:true ~ack:false ())
  is_syn (tcp_frame ~v6:true ~syn:true ~ack:false ())
  is_syn (tcp_frame ~vlan:true ~v6:true ~syn:true ~ack:false ())
  not (is_syn (tcp_frame ~syn:true ~ack:true ()))
  not (is_syn (tcp_frame ~syn:false ~ack:true ()))
  not (is_syn (Bitstring.create_bitstring (46 * 8)))
*)
(* [syns ?limits ()] is how many SYNs and other segments passed when both are
 * sent every millisecond for 300ms, then the limits that started dropping: *)
(*$inject
  let syns ?max_syns ?max_syn_rate () =
      let sim = Simulation.make ~realtime:false "policer" in
      let hits = ref [] in
      let t = make ~parent:sim.root ?max_syns ?max_syn_rate
                   ~on_limit:(fun l -> hits := string_of_limit l :: !hits) "p" in
      let syns = ref 0 and others = ref 0 in
      Tools.((t.widget.ports.dev 1) --> sink (fun bits ->
          incr (if is_syn bits then syns else others))) ;
      Simulation.power_up t.widget.power ;
      for i = 0 to 299 do
          List.iter (fun syn ->
              Simulation.at sim.root.power (Clock.Time.of_secs (float_of_int i /. 1000.))
                  (t.widget.ports.dev 0).write (tcp_frame ~syn ~ack:(not syn) ())
          ) [ true ; false ]
      done ;
      Simulation.run sim false ;
      Printf.sprintf "%d syns, %d others | %s" !syns !others
          (String.concat ", " (List.rev !hits))
*)
(*$= syns & ~printer:identity
  "300 syns, 300 others | " (syns ())
  "3 syns, 300 others | max-syns" (syns ~max_syns:3 ())
  "129 syns, 300 others | max-syn-rate" (syns ~max_syn_rate:100. ())
*)
(* A total reached is told by its flag, which only resets, and then counts
 * again from 0; what was dropped is counted by cause: *)
(*$R make
  let sim = Simulation.make ~realtime:false "policer" in
  let t = make ~parent:sim.root ~max_packets:2 "p" in
  let prop name = List.find (fun (p : property) -> p.name = name) t.widget.properties in
  let get name = (prop name).getter () in
  let set name v = Option.get (prop name).setter v in
  let passed = ref 0 in
  Tools.((t.widget.ports.dev 1) --> sink (fun _ -> incr passed)) ;
  Simulation.power_up t.widget.power ;
  let send () = (t.widget.ports.dev 0).write (Bitstring.create_bitstring 400) in
  send () ; send () ;
  assert_equal (`Bool false) (get "max packets reached") ;
  send () ;
  assert_equal (`Bool true) (get "max packets reached") ;
  assert_equal (`Int 2) (get "packets") ;
  assert_raises (Widget.Bad_value "max packets reached can only be reset, to false")
      (fun () -> set "max packets reached" (`Bool true)) ;
  set "max packets reached" (`Bool false) ;
  assert_equal (`Int 0) (get "packets") ;
  send () ;
  assert_equal ~printer:string_of_int 3 !passed ;
  assert_equal ~printer:string_of_int 1
      (Metric.Counter.get t.dropped
          ~params:(Metric.Params.singleton "cause" (Metric.Param.String "max-packets"))) ;
  (t.widget.ports.dev 1).write (Bitstring.create_bitstring 400) ;
  Simulation.power_down t.widget.power ;
  send () ;
  assert_equal ~printer:string_of_int 3 !passed
*)
