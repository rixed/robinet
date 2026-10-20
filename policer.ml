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
   token bucket that holds a second's worth. The duration counts from the
   power-on, or from the first packet. Switched off, it passes nothing. *)
open Batteries
open Bitstring
open SimTypes
open Tools
module Interval = Clock.Interval
module Time = Clock.Time

(** What made a frame be dropped: *)
type limit = Expired | Max_packets | Max_volume | Max_packet_rate | Max_throughput

let string_of_limit = function
    | Expired -> "expired"
    | Max_packets -> "max-packets"
    | Max_volume -> "max-volume"
    | Max_packet_rate -> "max-packet-rate"
    | Max_throughput -> "max-throughput"

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
      packet_rate : bucket ;
      throughput : bucket ;
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
    | Max_packet_rate | Max_throughput -> false

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
    | Expired ->
        (match t.start with
        | At_power_on -> start_counting t
        | At_first_packet -> t.started <- None ; arm t)
    | Max_packet_rate | Max_throughput -> ()

(* Takes [n] tokens from [b], the bucket of [limit], if there are; without a
 * rate, there are: *)
let take t b limit n =
    match b.rate with
    | None -> true
    | Some rate ->
        let now = now t in
        let elapsed = Interval.to_secs (Time.diff now b.last) in
        b.tokens <- Float.min rate (b.tokens +. elapsed *. rate) ;
        b.last <- now ;
        if b.tokens >= rate then t.dropping <- List.filter ((<>) limit) t.dropping ;
        if b.tokens < n then false else (b.tokens <- b.tokens -. n ; true)

let set_rate t b rate =
    b.rate <- rate ;
    b.last <- now t ;
    b.tokens <- rate |? 0.

(* The limit that drops this frame of [len] bytes, if any: *)
let limit_for t len =
    let beyond max v = Option.map_default (fun m -> v > m) false max in
    match List.find_opt is_total t.dropping with
    | Some l -> Some l
    | None ->
        if Option.is_some t.max_duration && Option.is_some t.started &&
           Interval.compare (elapsed t) (Option.get t.max_duration) >= 0 then
            Some Expired
        else if beyond t.max_packets (t.packets + 1) then Some Max_packets
        else if beyond t.max_volume (t.volume + len) then Some Max_volume
        else if not (take t t.packet_rate Max_packet_rate 1.) then Some Max_packet_rate
        else if not (take t t.throughput Max_throughput (float_of_int len)) then (
            (* The frame does not go, nor does its packet token: *)
            t.packet_rate.tokens <- t.packet_rate.tokens +. 1. ;
            Some Max_throughput)
        else None

let police t bits =
    if t.widget.power.on then (
        if t.started = None && t.start = At_first_packet then start_counting t ;
        let len = bitstring_length bits / 8 in
        match limit_for t len with
        | Some limit ->
            Metric.Counter.inc t.dropped ~now:(now t)
                ~params:(Metric.Params.singleton "cause"
                             (Metric.Param.String (string_of_limit limit))) ;
            hit t limit
        | None ->
            t.packets <- t.packets + 1 ;
            t.volume <- t.volume + len ;
            (snd t.forward.(1)) bits)

let num_ports = 2

let make ~parent ?location ?(start=At_power_on) ?max_packets ?max_volume
         ?max_packet_rate ?max_throughput ?max_duration ?(on_limit=ignore)
         name =
    let widget =
        Widget.make ~parent ?location ~device_type:"policer" ~own_power:true
                    name in
    let bucket rate = { rate ; last = Time.beginning_of_time ; tokens = rate |? 0. } in
    let t = { widget ; start ; on_limit ;
              forward = Array.make num_ports (false, ignore) ;
              peers = Array.make num_ports None ;
              max_packets ; packets = 0 ; max_volume ; volume = 0 ;
              max_duration ; started = None ; timer_gen = 0 ;
              packet_rate = bucket max_packet_rate ;
              throughput = bucket max_throughput ;
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
