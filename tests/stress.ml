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
  Tests for the parts that qtest cannot reach: what happens when several
  simulations run at once and another thread reaches into them.

  These are the places that actually broke while the machinery was written --
  a lock taken twice by the same thread, a lock_owner left stale across a
  condition wait, a clock that leapt forward on resume -- and none of them show
  up in a single-threaded test.

  Three parts:
  - the clock semantics of pause, step and resume, checked deterministically;
  - many threads borrowing a running simulation, reading and writing its
    widgets' properties and pausing it, to shake out deadlocks and races;
  - the same through the administration interface, over real HTTP.

  Run with no argument for the short version [make check] uses; pass a duration
  in seconds (and optionally a thread count) to lean on it harder:

    tests/stress.opt 60 32
*)
open Batteries

(*
 * Reporting
 *)

let failures = ref 0
let checks = ref 0

let check name b =
    incr checks ;
    if b then
        Printf.printf "  ok   %s\n%!" name
    else (
        incr failures ;
        Printf.printf "  FAIL %s\n%!" name
    )

(* Most of what we check is a duration or a simulated time, which no test can
 * pin down exactly: assert a range instead. *)
let check_between name lo hi v =
    check (Printf.sprintf "%s (%g in [%g, %g])" name v lo hi) (v >= lo && v <= hi)

let section name =
    Printf.printf "\n%s\n%!" name

(* Wait for [cond] to hold, up to [timeout] seconds. Returns whether it did, so
 * that a test can report a timeout rather than hanging the suite. *)
let wait_for ?(timeout=5.) cond =
    let deadline = Unix.gettimeofday () +. timeout in
    let rec loop () =
        if cond () then true
        else if Unix.gettimeofday () >= deadline then false
        else (
            Thread.delay 0.005 ;
            loop ()
        ) in
    loop ()

(*
 * The network under test
 *)

(* Slow enough that a handful of steps is measurable, fast enough that a
 * non-realtime simulation churns through plenty of them. *)
let tick = Clock.Interval.msec 100.

let make_net () =
    let net = Simulation.make ~realtime:false "net" in
    let parent = net.root in
    let netmask = Ip.Addr.of_string "255.255.255.0" in
    let h1 =
        Host.make_static ~parent ~netmask (Ip.Addr.of_string "192.168.1.1") "h1"
    and h2 =
        Host.make_static ~parent ~netmask (Ip.Addr.of_string "192.168.1.2") "h2" in
    let cable =
        Eth.Cable.State.make ~parent ~length:10. ~error_rate:0.001
                             ~name:"link" () in
    Widget.make_peers ~via:cable.widget h1.Host.trx.widget h2.Host.trx.widget ;
    (* One of our own, so that what the API does with a property that cannot be
     * written does not depend on which of a cable's happen to be read-only. *)
    (* And one bounded on a single side, since no cable has such a property and
       what the API says about an end that is not there is worth pinning. *)
    let count = ref 0 and nickname = ref None in
    Widget.add_properties cable.widget
        [ Widget.property "sealed" ~descr:"Cannot be written."
              ~kind:Widget.Int ~getter:(fun () -> `Int 1) ;
          Widget.property "count" ~descr:"Any number of things."
              ~kind:(Widget.IRange (0, max_int))
              ~getter:(fun () -> `Int !count)
              ~setter:(fun v -> count := Widget.to_int_range ~min:0 v) ;
          (* And one that may have no value at all. *)
          Widget.property "nickname" ~descr:"A name, or none."
              ~kind:(Widget.optional Widget.String)
              ~getter:(fun () ->
                  match !nickname with None -> `Null | Some s -> `String s)
              ~setter:(fun v ->
                  nickname := Widget.to_option Widget.to_string v) ] ;
    (* Something to keep its clock busy for ever: *)
    let rec ticking () = Simulation.delay net.Simulation.power tick ticking () in
    ticking () ;
    net, cable

let property (w : Widget.t) name =
    List.find (fun (p : Widget.property) -> p.name = name) w.properties

(*
 * 1. Clock semantics
 *)

let test_clock net =
    section "Clock: pause, step and resume" ;
    check "a running simulation advances"
        (let t0 = Simulation.now net in
         Thread.delay 0.05 ;
         Simulation.now net > t0) ;

    Simulation.pause net () ;
    (* Pausing takes effect at the next dispatch, so let it settle: *)
    Thread.delay 0.05 ;
    let paused_at = Simulation.now net in
    Thread.delay 0.2 ;
    check "a paused simulation's clock stands still"
        (Simulation.now net = paused_at) ;

    (* [step] must run exactly that many events, no more. *)
    Simulation.step ~n:5 net () ;
    let stepped =
        wait_for (fun () -> net.Simulation.steps = 0) in
    check "step consumed its budget" stepped ;
    Thread.delay 0.05 ;
    let after_step = Simulation.now net in
    check_between "step advanced by exactly 5 ticks" 0.49 0.51
        (Clock.Time.diff after_step paused_at :> float) ;
    check "still paused after stepping" net.Simulation.paused ;

    (* Resuming must account for the wall clock time spent paused, or every
     * event scheduled during the pause fires at once. *)
    let before = (net.Simulation.paused_total :> float) in
    Thread.delay 0.3 ;
    Simulation.resume net () ;
    let spent = (net.Simulation.paused_total :> float) -. before in
    check_between "resume accounted for the time spent paused" 0.29 1.0 spent ;
    check "not paused any more" (not net.Simulation.paused) ;
    check "the clock advances again"
        (let t0 = Simulation.now net in
         Thread.delay 0.05 ;
         Simulation.now net > t0)

(* How fast a simulation runs against the wall clock, in simulated seconds per
   wall second, measured over [wall]. *)
let measure_speed net wall =
    let t0 = Simulation.now net in
    Thread.delay wall ;
    (Clock.Time.diff (Simulation.now net) t0 :> float) /. wall

let test_speed net =
    section "Clock: speed against the wall clock" ;
    (* This network's events are on a 100ms grid and time only moves when one
       of them is dispatched, so a measurement over a second lands within one
       tick of the speed asked for. That tick, not drift, is what the tolerances
       below leave room for. *)
    Simulation.set_speed_ratio net (Some 1.) ;
    check_between "at one, a simulated second takes a second" 0.85 1.15
        (measure_speed net 1.) ;
    Simulation.set_speed_ratio net (Some 4.) ;
    check_between "at four, four of them do" 3.8 4.2
        (measure_speed net 1.) ;
    Simulation.set_speed_ratio net (Some 0.25) ;
    check_between "at a quarter, a quarter of one does" 0.15 0.35
        (measure_speed net 1.) ;
    check "keeping up is not being late"
        ((net.Simulation.late :> float) < 0.1) ;

    (* Asked for more than any machine can do: it must say how far behind it
       is rather than pretend. *)
    Simulation.set_speed_ratio net (Some 1e9) ;
    Thread.delay 0.5 ;
    let late = (net.Simulation.late :> float) in
    check_between "an impossible speed is reported as lateness" 0.4 2.0 late ;

    (* Changing the speed is not the new speed being late. *)
    Simulation.set_speed_ratio net (Some 1.) ;
    check "changing the speed clears the lateness"
        ((net.Simulation.late :> float) < 0.1) ;

    (* A step is asked for now, whatever the pace says. *)
    Simulation.set_speed_ratio net (Some 0.01) ;
    Simulation.pause net () ;
    Thread.delay 0.05 ;
    let before = Simulation.now net in
    Simulation.step ~n:5 net () ;
    check "stepping does not wait for the pace"
        (wait_for (fun () -> net.Simulation.steps = 0)) ;
    Thread.delay 0.05 ;
    check_between "and stepped by exactly five ticks" 0.49 0.51
        (Clock.Time.diff (Simulation.now net) before :> float) ;
    Simulation.resume net () ;

    (* Back to what the other tests expect. *)
    Simulation.set_speed_ratio net None ;
    check "full speed outruns the wall clock" (measure_speed net 0.2 > 10.) ;
    check "a realtime simulation has no speed of ours to set"
        (let admin = Simulation.make ~realtime:true "speed-guard" in
         match Simulation.set_speed_ratio admin (Some 2.) with
         | exception Invalid_argument _ -> true
         | () -> false)

(*
 * 2. Concurrent access to a running simulation
 *)

(* Each worker hammers one facet of the API. What we are looking for is not a
 * result but the absence of a deadlock, an exception, or a corrupted value. *)
(*
 * 3. Metric history
 *)

(* A simulation of its own, dispatching a known number of events at a known
   pace, so that what lands in the ring can be predicted exactly. Not the
   shared [net]: this one has to run to exhaustion and be sampled while nothing
   else feeds it. *)
let test_metric_samples () =
    section "Metrics: the history the plots are drawn from" ;
    let sim = Simulation.make ~realtime:false "samples" in
    let w = Widget.make ~parent:sim.Simulation.root "thing" in
    let c = Metric.Counter.make ()
    (* A gauge as well, whose value moves within every sampling window: the
       point of the windows is that they say what happened between two points,
       which the figures since the last reset cannot. *)
    and g = Metric.Gauge.make () in
    Widget.add_properties w
        [ Widget.metric_property "bytes" ~units:"bytes" (Metric.Counter.T c) ;
          Widget.metric_property "level" (Metric.Gauge.T g) ] ;
    Simulation.set_metrics_sample_rate sim (Clock.Interval.sec 1.) ;
    (* One event every quarter of a simulated second, for five seconds. *)
    let rec feed n () =
        Metric.Counter.add c ~now:(Simulation.now sim) 100 ;
        Metric.Gauge.set ~now:(Simulation.now sim) g (10 * (20 - n)) ;
        (* Something to read back through the logs endpoint, at one instant per
           event and at two levels, so that both what [since] and what [level]
           leave out can be told apart from what they keep. *)
        Log.(log w.Widget.logger Info (lazy (Printf.sprintf "tick %d" n))) ;
        if n mod 5 = 0 then
            Log.(log w.Widget.logger Warning (lazy "every fifth tick")) ;
        if n > 0 then
            Simulation.delay sim.Simulation.power (Clock.Interval.sec 0.25) (feed (n - 1)) () in
    Simulation.delay sim.Simulation.power (Clock.Interval.sec 0.25) (feed 19) () ;
    Simulation.run sim false ;
    let key = w.Widget.id, "bytes", Metric.Params.empty in
    (* A metric that has not fired yet has no row at all, which is not the
       same as a row worth zero -- but it plots the same. *)
    let count (s : Simulation.sample) =
        match Hashtbl.find_opt s.Simulation.values key with
        | Some (Metric.Count c) -> c
        | _ -> 0 in
    let samples = Simulation.metric_samples sim in
    (* Five simulated seconds sampled once a simulated second: five crossings
       of the grid, or six depending on where within a second the clock
       started. *)
    check_between "one sample per simulated second" 5. 7.
        (float_of_int (List.length samples)) ;
    (* The first snapshot is due at once and is therefore taken before the
       first event runs: at that point the counter has never been added to and
       has nothing to say. *)
    check "the first sample holds what there was to hold: nothing"
        (Hashtbl.length (List.hd samples).Simulation.values = 0) ;
    check "and every one after it holds the metric"
        (List.for_all (fun (s : Simulation.sample) ->
            Hashtbl.mem s.Simulation.values key) (List.tl samples)) ;
    (* Each is taken at the first event at or after its due time, and those
       are multiples of the rate, so the gaps are a second give or take one
       event -- all but the first, since the baseline is taken as soon as the
       simulation dispatches anything and the grid only starts after it. *)
    let gaps_of l =
        List.map2 (fun (a : Simulation.sample) (b : Simulation.sample) ->
            (Clock.Time.diff b.Simulation.taken a.Simulation.taken :> float)
        ) (List.take (List.length l - 1) l) (List.tl l) in
    let gaps = gaps_of samples in
    check "the samples after the baseline are a simulated second apart"
        (List.for_all (fun g -> g > 0.7 && g < 1.3) (List.tl gaps)) ;
    check "and the baseline comes no later than one sample in"
        (List.hd gaps <= 1.3) ;
    check "and each holds more than the one before"
        (List.for_all2 (fun a b -> count b > count a)
            (List.take (List.length samples - 1) samples) (List.tl samples)) ;
    (* Nothing is sampled while nothing happens: the clock of a closed
       simulation does not move on its own. *)
    let quiet = List.length (Simulation.metric_samples sim) in
    Thread.delay 0.2 ;
    check "a simulation with nothing to do records nothing"
        (List.length (Simulation.metric_samples sim) = quiet) ;
    (* Keeping fewer keeps the most recent. *)
    let last = count (List.last samples) in
    Simulation.set_metrics_max_samples sim 2 ;
    let kept = Simulation.metric_samples sim in
    check "keeping fewer keeps that many" (List.length kept = 2) ;
    check "and keeps the newest" (count (List.last kept) = last) ;
    (* And the ring wraps rather than growing. *)
    Simulation.delay sim.Simulation.power (Clock.Interval.sec 0.25) (feed 19) () ;
    Simulation.run sim false ;
    let after = Simulation.metric_samples sim in
    check "the ring never grows past what it may keep" (List.length after = 2) ;
    check "and what it keeps is the newest"
        (count (List.last after) > last) ;
    (* The windows: each sample says what the gauge did since the one before,
       while the figures beside them say what it has done since it started. *)
    let level (s : Simulation.sample) =
        Hashtbl.find_option s.Simulation.values
            (w.Widget.id, "level", Metric.Params.empty) in
    let levels =
        List.filter_map (fun s ->
            match level s with
            | Some (Metric.Value v) -> Some v
            | _ -> None) samples in
    check "a window holds the value it was sampled at"
        (List.for_all (fun (v : Metric.Gauge.value) ->
            v.sample_min <= v.current && v.current <= v.sample_max &&
            v.min <= v.sample_min && v.sample_max <= v.max) levels) ;
    check "and only what happened within it, not since the beginning"
        (List.exists (fun (v : Metric.Gauge.value) ->
            v.sample_max - v.sample_min < v.max - v.min) levels) ;
    (* Both knobs are properties of the root widget, so that the interface can
       turn them while the simulation runs without knowing anything about
       rings. *)
    let root_prop name =
        List.find (fun (p : Widget.property) -> p.Widget.name = name)
                  sim.Simulation.root.Widget.properties in
    let set name v = (Option.get (root_prop name).Widget.setter) v in
    set "metrics samples kept" (`Int 5) ;
    check "the root widget says how many samples are kept"
        (Simulation.metrics_max_samples sim = 5 &&
         (root_prop "metrics samples kept").Widget.getter () = `Int 5) ;
    set "metrics sample rate" (`Float 0.5) ;
    check "and how often they are taken"
        ((Simulation.metrics_sample_rate sim :> float) = 0.5 &&
         (root_prop "metrics sample rate").Widget.getter () = `Float 0.5) ;
    (* Five more simulated seconds, now sampled twice a second: more than
       enough to fill the shortened ring at the new pace. *)
    Simulation.delay sim.Simulation.power (Clock.Interval.sec 0.25) (feed 19) () ;
    Simulation.run sim false ;
    let dense = Simulation.metric_samples sim in
    check "the sampler follows what the properties say"
        (List.length dense = 5 &&
         List.for_all (fun g -> g > 0.3 && g < 0.7) (gaps_of dense)) ;
    check "a rate that is not a delay is refused through the property too"
        (List.for_all (fun v ->
            try set "metrics sample rate" v ; false
            with Widget.Bad_value _ -> true)
            [ `Float 0. ; `Float (-1.) ; `Float infinity ; `String "nonsense" ]) ;
    check "and so is a history of a length that is not one"
        (List.for_all (fun v ->
            try set "metrics samples kept" v ; false
            with Widget.Bad_value _ -> true)
            [ `Int (-1) ; `Int 2_000_000 ; `String "plenty" ]) ;
    (* A rate is a delay, and some floats are not. (Not nan, which cannot be
       made into an [Interval.t] in the first place.) *)
    check "a rate that is not a delay is refused"
        (List.for_all (fun r ->
            try Simulation.set_metrics_sample_rate sim (Clock.Interval.o r) ;
                false
            with Invalid_argument _ -> true)
            [ 0. ; -1. ; infinity ]) ;
    (* Handed to the HTTP tests: a ring that has stopped being written to, of a
       length and a content they can check exactly. *)
    sim, w

let test_concurrency net cable duration nthreads =
    section
        (Printf.sprintf "Concurrency: %d threads for %gs against a running \
                         simulation" nthreads duration) ;
    let deadline = Unix.gettimeofday () +. duration in
    let running () = Unix.gettimeofday () < deadline in
    let errors = ref [] in
    let error_lock = Mutex.create () in
    let record e =
        BatMutex.synchronize ~lock:error_lock (fun () ->
            errors := Printexc.to_string e :: !errors) () in
    let loops = ref 0 in
    let loop_lock = Mutex.create () in
    let count n =
        BatMutex.synchronize ~lock:loop_lock (fun () -> loops := !loops + n) () in
    let worker f () =
        let n = ref 0 in
        (try
            while running () do f () ; incr n done
        with e -> record e) ;
        count !n in
    let length = property cable.Eth.Cable.State.widget "length"
    and tot_bits = property cable.Eth.Cable.State.widget "total bits" in
    let workers = [
        (* Read a property while the simulation mutates it. *)
        worker (fun () ->
            Simulation.borrow net (fun () -> ignore (tot_bits.getter ()))) ;
        (* Write one. *)
        worker (fun () ->
            let v = `Float (float_of_int (Random.int 100) +. 0.5) in
            Simulation.borrow net (fun () ->
                (Option.get length.setter) v)) ;
        (* Walk the whole widget tree. *)
        worker (fun () ->
            let n = Simulation.borrow net (fun () ->
                List.length (Simulation.widgets net)) in
            if n <> 6 then failwith (Printf.sprintf "tree has %d widgets" n)) ;
        (* Pause and resume under everyone's feet. *)
        worker (fun () ->
            Simulation.pause net () ;
            Thread.yield () ;
            Simulation.resume net ()) ;
        (* Read the clock. *)
        worker (fun () -> ignore (Simulation.now net)) ;
    ] in
    let threads =
        List.init nthreads (fun i ->
            Thread.create (List.nth workers (i mod List.length workers)) ()) in
    List.iter Thread.join threads ;
    check (Printf.sprintf "no worker raised (%d iterations)" !loops)
        (!errors = []) ;
    List.iter (fun e -> Printf.printf "       %s\n%!" e) !errors ;
    check "workers made progress" (!loops > 0) ;
    (* Whatever they did to it, it must still be a working simulation: *)
    Simulation.resume net () ;
    check "the simulation survived"
        (let t0 = Simulation.now net in
         wait_for (fun () -> Simulation.now net > t0)) ;
    check "its length property is still readable"
        (Widget.to_float (length.getter ()) >= 0.)

(*
 * 3. The administration interface, over HTTP
 *)

(* A throwaway HTTP client: enough to drive the API, and no dependency on
 * anything outside the standard library. *)
(* Returns the status, the headers as they came, and the body. Most tests want
   only the first and the last; the headers matter when what is being checked
   is how the answer is framed rather than what it says. *)
let http_full ?(meth="GET") ?body port path =
    let sock = Unix.(socket PF_INET SOCK_STREAM 0) in
    finally (fun () -> Unix.close sock) (fun () ->
        (* A test must never be able to hang the suite: give up rather than
         * block for ever should the server stop answering. *)
        Unix.(setsockopt_float sock SO_RCVTIMEO 5.) ;
        Unix.(setsockopt_float sock SO_SNDTIMEO 5.) ;
        Unix.(connect sock (ADDR_INET (inet_addr_loopback, port))) ;
        let body = body |? "" in
        let req =
            Printf.sprintf
                "%s %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
                 Content-Length: %d\r\n\r\n%s"
                meth path (String.length body) body in
        let rec write o =
            if o < String.length req then
                write (o + Unix.write_substring sock req o
                                                (String.length req - o)) in
        write 0 ;
        (* Read the headers, then exactly as many bytes as they announce.
         * Deliberately not "read until end of file": opache answers and then
         * closes, but the close never reaches us, because Localhost.close
         * closes the fd while its own reader thread is still blocked reading
         * it -- which on Linux keeps the socket alive and sends no FIN. A test
         * client that waited for the peer to hang up would hang instead. *)
        let buf = Buffer.create 1024 and chunk = Bytes.create 4096 in
        let received () = Buffer.contents buf in
        let rec read_until found =
            if found (received ()) then received () else
            let r = Unix.read sock chunk 0 (Bytes.length chunk) in
            if r <= 0 then received ()
            else (
                Buffer.add_subbytes buf chunk 0 r ;
                read_until found
            ) in
        let headers =
            read_until (fun s -> String.exists s "\r\n\r\n") in
        let head, _ = String.split ~by:"\r\n\r\n" headers in
        let content_length =
            String.split_on_char '\n' head |>
            List.fold_left (fun found l ->
                match String.split ~by:":" l with
                | exception Not_found -> found
                | name, v when String.icompare (String.trim name)
                                               "content-length" = 0 ->
                    (try int_of_string (String.trim v) with _ -> found)
                | _ -> found) 0 in
        let wanted = String.length head + 4 + content_length in
        let resp = read_until (fun s -> String.length s >= wanted) in
        let status =
            match String.split_on_char ' ' resp with
            | _ :: code :: _ -> (try int_of_string code with _ -> 0)
            | _ -> 0 in
        let payload =
            try snd (String.split ~by:"\r\n\r\n" resp)
            with Not_found -> "" in
        status, head, payload) ()

let http ?meth ?body port path =
    let status, _head, payload = http_full ?meth ?body port path in
    status, payload

(* Ask the OS for a free port, then hand it to myadmin. Racy in principle,
 * retried in practice. *)
let free_port () =
    let sock = Unix.(socket PF_INET SOCK_STREAM 0) in
    finally (fun () -> Unix.close sock) (fun () ->
        Unix.(bind sock (ADDR_INET (inet_addr_loopback, 0))) ;
        match Unix.getsockname sock with
        | Unix.ADDR_INET (_, port) -> port
        | _ -> assert false) ()

let start_admin () =
    let rec attempt n =
        if n <= 0 then None else (
            let port = free_port () in
            let admin = Simulation.make ~realtime:true "admin" in
            match Myadmin.make admin (Localhost.host admin) (Tcp.Port.o port) with
            | exception Unix.Unix_error (Unix.EADDRINUSE, _, _) ->
                attempt (n - 1)
            | () ->
                ignore (Simulation.start admin) ;
                if wait_for (fun () ->
                       match http port "/api/simulations" with
                       | exception _ -> false
                       | status, _ -> status = 200)
                then Some (admin, port)
                else None) in
    attempt 5

(*
 * 4. Unplugging a cable
 *)

(* The one thing in a simulation that has to be undone by hand: everything
   inside a device goes away with it, but a cable reaches out of one device into
   another, so both ends have to be told. What each end has to be told differs
   -- an adapter clears a flag, a repeater puts an iface back to a sink -- and
   the cable knows neither: it was handed the two undo functions when it was
   plugged in. *)
let test_disconnect () =
    section "Unplugging a cable" ;
    let sim = Simulation.make ~realtime:false "unplug" in
    let parent = sim.Simulation.root in
    let netmask = Ip.Addr.of_dotted_string_exc "255.255.255.0" in
    let sw = Hub.Switch.make ~parent 2 8 "sw" in
    let h =
        Host.make_static ~parent ~netmask
                         (Ip.Addr.of_dotted_string_exc "10.1.0.1") "h" in
    let sw_w = sw.Hub.Switch.widget
    and h_w = h.Host.trx.Host.widget in
    (* Through the same call the creation API uses, which is the only place
       that knows which port of which device either end went to. *)
    let st = Eth.Cable.State.make ~parent ~name:"link" () in
    Eth.Cable.plug st (sw_w, 1) (h_w, 0) ;

    check "both ends report a cable"
        (sw_w.Widget.ports.is_connected 1 &&
         h_w.Widget.ports.is_connected 0) ;
    (* Only the port it was plugged into: the one beside it was never taken. *)
    check "and the ports beside them are untouched"
        (not (sw_w.Widget.ports.is_connected 0)) ;

    (* What the cable has carried, which is how "still plugged in" is told from
       "no longer": a frame into the switch's other port is flooded to this one,
       and crosses -- or does not. *)
    let carried () =
        match List.find (fun (p : Widget.property) -> p.name = "total bits")
                        st.Eth.Cable.State.widget.Widget.properties with
        | exception Not_found -> -1
        | p ->
            Yojson.Basic.Util.(
                p.getter () |> member "values" |> to_list |>
                List.fold_left (fun n v -> n + (member "value" v |> to_int)) 0) in
    let flood () =
        (* Addressed to everyone, so that the switch floods it rather than
           deciding it has nowhere to send it. *)
        let frame =
            Bitstring.concat [ Bitstring.ones_bitstring 48 ;
                               Bitstring.zeroes_bitstring (8 * 54) ] in
        Hub.Switch.write sw 0 frame ;
        Simulation.run sim false in
    flood () ;
    check "a frame flooded to it crosses" (carried () > 0) ;
    let before = carried () in

    (* And it cannot be plugged in twice: the first two ports would be left
       emitting into a cable that nothing could unplug them from. *)
    check "a cable already plugged in refuses to be plugged in again"
        (try Eth.Cable.plug st (sw_w, 0) (h_w, 0) ; false
         with Invalid_argument _ -> true) ;

    Eth.Cable.disconnect st ;
    flood () ;
    check "and none does once it is unplugged" (carried () = before) ;
    check "unplugging frees the adapter" (not (h_w.Widget.ports.is_connected 0)) ;
    check "and the switch port, which is not an adapter at all"
        (not (sw_w.Widget.ports.is_connected 1)) ;
    check "so the port can be asked for again"
        (Widget.first_free_port sw_w = Some 0 &&
         Widget.first_free_port h_w = Some 0) ;
    (* Deleting the cable widget is what takes it out of the graph -- which is
       why [disconnect] does not have to. *)
    Widget.delete st.Eth.Cable.State.widget ;
    check "and deleting its widget unpairs the two ends"
        (sw_w.Widget.peers = [] && (h_w.Widget.ports.owner 0).Widget.peers = []) ;

    (* Those two ports are free, so another cable may take them -- and then the
       first one must not be able to unplug it. Which is what forgetting the
       ends is for: a cable that has let go has nothing left to let go of. *)
    let st2 = Eth.Cable.State.make ~parent ~name:"link2" () in
    Eth.Cable.plug st2 (sw_w, 1) (h_w, 0) ;
    Eth.Cable.disconnect st ;
    check "unplugging a cable a second time leaves the next one alone"
        (sw_w.Widget.ports.is_connected 1 && h_w.Widget.ports.is_connected 0)

(* Deleting a device is deleting the thing, not the picture of it: what it is
   made of goes with it, it stops running, and the cables that reached it are
   unplugged and go too -- a cable is the link, and a link with one end missing
   is nothing. What must survive is everything else. *)
let test_delete () =
    section "Deleting a device" ;
    let sim = Simulation.make ~realtime:false "delete" in
    let parent = sim.Simulation.root in
    let netmask = Ip.Addr.of_dotted_string_exc "255.255.255.0" in
    let sw = Hub.Switch.make ~parent 2 8 "sw" in
    let sw_w = sw.Hub.Switch.widget in
    let host port name ip =
        let h = Host.make_static ~parent ~netmask
                                 (Ip.Addr.of_dotted_string_exc ip) name in
        let st = Eth.Cable.State.make ~parent ~name:("cable-"^ name) () in
        Eth.Cable.plug st (sw_w, port) (h.Host.trx.Host.widget, 0) ;
        h, st in
    let h1, _ = host 0 "h1" "10.3.0.1"
    and h2, cable2 = host 1 "h2" "10.3.0.2" in
    let h1_w = h1.Host.trx.Host.widget
    and h2_w = h2.Host.trx.Host.widget in
    let h1_id = h1_w.Widget.id
    and h2_id = h2_w.Widget.id
    and cable2_id = cable2.Eth.Cable.State.widget.Widget.id in
    Simulation.run sim false ;

    (* Something it was going to do, to tell a device that has stopped from one
       that has merely been taken out of the drawing. *)
    let fired = ref 0 in
    Simulation.delay h2.Host.trx.Host.power (Clock.Interval.sec 1.)
                     (fun () -> incr fired) () ;
    Widget.destroy h2_w ;
    Simulation.run sim false ;
    check "a deleted device stops running" (!fired = 0) ;
    check "and is out of the tree, with everything it was made of"
        (Widget.find sim.Simulation.root h2_id = None) ;
    check "so is the cable that reached it"
        (Widget.find sim.Simulation.root cable2_id = None) ;
    check "the port it was plugged into is free again"
        (not (sw_w.Widget.ports.is_connected 1)) ;
    check "and nothing is peered with what is gone"
        (List.for_all (fun (p : Widget.peer) ->
             p.widget != h2_w && p.via <> Some cable2.Eth.Cable.State.widget)
             sw_w.Widget.peers) ;
    (* The other end of the switch never noticed. *)
    check "the rest of the network is untouched"
        (sw_w.Widget.ports.is_connected 0 &&
         h1_w.Widget.ports.is_connected 0 &&
         Widget.find sim.Simulation.root h1_id <> None) ;

    (* And from the other side: deleting what a host was cabled to leaves the
       host, minus the cable. *)
    Widget.destroy sw_w ;
    check "deleting a device unplugs what was still on it"
        (not (h1_w.Widget.ports.is_connected 0)) ;
    check "leaving the device at the far end behind"
        (Widget.find sim.Simulation.root h1_id <> None) ;
    check "and taking its own parts with it"
        (Widget.find sim.Simulation.root sw_w.Widget.id = None &&
         sw_w.Widget.children = []) ;
    (* Including their supply: the repeater inside a switch has one of its own,
       and it is reached by the walk rather than by the switch knowing it is
       there. *)
    check "which are stopped as well"
        (not sw.Hub.Switch.hub.Hub.Repeater.power.Simulation.on)

(* Powering a host off is not a request that it stop: whatever it had planned
   to do ceases to exist. Everything it schedules -- its adapter, its sockets,
   its timers -- draws from one power source, so cutting that source and
   withdrawing what it had already paid for is the whole of a power-off.

   What must not happen is either half of that failing: an event outliving the
   host that scheduled it, or a power-off taking with it something it does not
   own. *)
let test_power () =
    section "Powering a host off" ;
    let sim = Simulation.make ~realtime:false "power" in
    let parent = sim.Simulation.root in
    let netmask = Ip.Addr.of_dotted_string_exc "255.255.255.0" in
    let sw = Hub.Switch.make ~parent 2 8 "sw" in
    let host port name ip =
        let h = Host.make_static ~parent ~netmask
                                 (Ip.Addr.of_dotted_string_exc ip) name in
        let st = Eth.Cable.State.make ~parent ~name:("cable-"^ name) () in
        Eth.Cable.plug st (sw.Hub.Switch.widget, port)
                          (h.Host.trx.Host.widget, 0) ;
        h, st in
    let h1, _ = host 0 "h1" "10.2.0.1"
    and h2, cable2 = host 1 "h2" "10.2.0.2" in
    Simulation.run sim false ;

    (* Events due later, some the host's own and some not. Counting them rather
       than watching for traffic, so that "did it fire" has one answer. *)
    let mine = ref 0 and theirs = ref 0 in
    let plan () =
        for i = 1 to 5 do
            let d = Clock.Interval.sec (float_of_int i) in
            Simulation.delay h2.Host.trx.Host.power d (fun () -> incr mine) () ;
            Simulation.delay sim.Simulation.power d (fun () -> incr theirs) ()
        done in
    plan () ;
    h2.Host.trx.Host.power_off () ;
    Simulation.run sim false ;
    check "powering a host off drops what it had scheduled" (!mine = 0) ;
    check "and leaves everybody else's events alone" (!theirs = 5) ;

    (* And nothing new is taken on while it is off: a power-off that only
       emptied the queue would let the next timer put the host back to work. *)
    plan () ;
    Simulation.run sim false ;
    check "an off host schedules nothing more" (!mine = 0) ;
    check "while the rest of the simulation carries on" (!theirs = 10) ;

    h2.Host.trx.Host.power_on () ;
    plan () ;
    Simulation.run sim false ;
    check "and it schedules again once powered back on" (!mine = 5) ;

    (* End to end, since the counters above would be just as happy if the host
       were merely a bag of timers: a server on h2, reached from h1. *)
    let served = ref 0 in
    let listen () =
        h2.Host.trx.Host.udp_server (Udp.Port.o 1234) (fun _ -> incr served) in
    let send () =
        h1.Host.trx.Host.udp_send (Host.IPv4 (Ip.Addr.of_dotted_string_exc "10.2.0.2"))
                                  (Udp.Port.o 1234) (Bitstring.zeroes_bitstring 64) ;
        Simulation.run sim false in
    listen () ;
    send () ;
    check "a live host answers for the ports it listens on" (!served = 1) ;
    h2.Host.trx.Host.power_off () ;
    send () ;
    check "an off host does not" (!served = 1) ;
    (* Its servers are gone with the rest of its state, so coming back up is
       coming back up empty rather than resuming. *)
    h2.Host.trx.Host.power_on () ;
    send () ;
    check "and does not remember them when it comes back" (!served = 1) ;
    listen () ;
    send () ;
    check "but serves again once it listens again" (!served = 2) ;

    (* An adapter is state too, and the sort that goes wrong quietly. A frame
       held back waiting on an ARP that nobody answered leaves the adapter
       believing a request is in flight; left there across a power cut, the
       next frame for that address joins the queue and no request ever goes
       out again. *)
    let waiting () =
        Tools.BitHash.length h2.Host.eth_state.Eth.State.postponed in
    let to_nowhere () =
        h2.Host.trx.Host.udp_send
            (Host.IPv4 (Ip.Addr.of_dotted_string_exc "10.2.0.99"))
            (Udp.Port.o 1234) (Bitstring.zeroes_bitstring 64) ;
        Simulation.run sim false in
    to_nowhere () ;
    check "a frame for nobody leaves the adapter waiting on an ARP"
        (waiting () > 0) ;
    h2.Host.trx.Host.power_off () ;
    check "which a power cut clears" (waiting () = 0) ;
    (* And having forgotten, it asks again rather than queueing in silence. *)
    let carried () =
        match List.find (fun (p : Widget.property) -> p.name = "total bits")
                        cable2.Eth.Cable.State.widget.Widget.properties with
        | exception Not_found -> -1
        | p ->
            Yojson.Basic.Util.(
                p.getter () |> member "values" |> to_list |>
                List.fold_left (fun n v -> n + (member "value" v |> to_int)) 0) in
    h2.Host.trx.Host.power_on () ;
    let before = carried () in
    to_nowhere () ;
    check "so the adapter asks again once it is back" (carried () > before)

let test_http net cable duration nthreads
              (hist_sim : Simulation.t) (hist_widget : Widget.t) =
    section "Administration interface over HTTP" ;
    match start_admin () with
    | None ->
        incr failures ;
        Printf.printf "  FAIL could not start the admin interface\n%!"
    | Some (admin, port) ->
        let net_id = Simulation.id net
        and cable_id = cable.Eth.Cable.State.widget.Widget.id in
        let api fmt = Printf.ksprintf (fun p -> http port p) fmt in
        (* First, that each route answers what it should: *)
        check "GET /api/simulations" (fst (api "/api/simulations") = 200) ;
        check "GET a simulation's widgets"
            (fst (api "/api/simulations/%d/widgets" net_id) = 200) ;
        check "GET a widget"
            (fst (api "/api/simulations/%d/widgets/%d" net_id cable_id) = 200) ;
        check "GET its properties"
            (fst (api "/api/simulations/%d/widgets/%d/properties"
                      net_id cable_id) = 200) ;
        check "PUT a property"
            (fst (http ~meth:"PUT" ~body:"33.5" port
                      (Printf.sprintf
                          "/api/simulations/%d/widgets/%d/properties/length"
                          net_id cable_id)) = 200) ;
        check "PUT a read-only property is refused"
            (fst (http ~meth:"PUT" ~body:"1" port
                      (Printf.sprintf
                          "/api/simulations/%d/widgets/%d/properties/sealed"
                          net_id cable_id)) = 405) ;
        (* Writing to a metric resets it, whatever is written. *)
        check "PUT a metric resets it"
            (fst (http ~meth:"PUT" ~body:"null" port
                      (Printf.sprintf
                          "/api/simulations/%d/widgets/%d/properties/total%%20bits"
                          net_id cable_id)) = 200) ;
        check "PUT a bad value is refused"
            (fst (http ~meth:"PUT" ~body:"nonsense" port
                      (Printf.sprintf
                          "/api/simulations/%d/widgets/%d/properties/length"
                          net_id cable_id)) = 400) ;
        (* What a range tells the interface: both of its ends, and which values
           it will take. An end that is not there is null, not an infinity that
           JSON cannot carry nor a [max_int] no slider could span. *)
        let field name what =
            match api "/api/simulations/%d/widgets/%d/properties"
                      net_id cable_id with
            | 200, body ->
                Yojson.Basic.(
                    from_string body |> Util.to_list |>
                    List.find (fun p -> Util.(member "name" p |> to_string) = name) |>
                    Util.member what)
            | _ ->
                `Null in
        let kind name = field name "kind" in
        check "a bounded range comes with both of its ends"
            (kind "error rate" =
                `Assoc [ "type", `String "range" ; "int", `Bool false ;
                         "min", `Float 0. ; "max", `Float 1. ]) ;
        check "a range bounded on one side only says so"
            (kind "count" =
                `Assoc [ "type", `String "range" ; "int", `Bool true ;
                         "min", `Int 0 ; "max", `Null ]) ;
        (* What a value is counted in travels with it, so that the interface
           can show it without knowing what a cable is. *)
        check "a property says what it is counted in"
            (field "length" "units" = `String "meters") ;
        check "and says so plainly when it is counted in nothing"
            (field "count" "units" = `String "") ;
        (* A value that may be absent: the interface is told what the value
           would be, and null is how its absence travels both ways. *)
        check "an optional value says what it would hold"
            (kind "nickname" =
                `Assoc [ "type", `String "optional" ;
                         "of", `Assoc [ "type", `String "string" ] ]) ;
        check "PUT a value to an optional property"
            (fst (http ~meth:"PUT" ~body:"\"link0\"" port
                      (Printf.sprintf
                          "/api/simulations/%d/widgets/%d/properties/nickname"
                          net_id cable_id)) = 200 &&
             field "nickname" "value" = `String "link0") ;
        check "PUT null unsets it"
            (fst (http ~meth:"PUT" ~body:"null" port
                      (Printf.sprintf
                          "/api/simulations/%d/widgets/%d/properties/nickname"
                          net_id cable_id)) = 200 &&
             field "nickname" "value" = `Null) ;
        check "a value within a range is taken"
            (fst (http ~meth:"PUT" ~body:"5" port
                      (Printf.sprintf
                          "/api/simulations/%d/widgets/%d/properties/count"
                          net_id cable_id)) = 200) ;
        check "a value outside a range is refused"
            (fst (http ~meth:"PUT" ~body:"-1" port
                      (Printf.sprintf
                          "/api/simulations/%d/widgets/%d/properties/count"
                          net_id cable_id)) = 400) ;
        (* What a metric has been worth, which is what the plots are drawn
           from. Asked of the simulation the sampling test left behind: it has
           stopped, so its ring holds exactly what that test put there. *)
        let history ?since () =
            let path =
                Printf.sprintf
                    "/api/simulations/%d/widgets/%d/properties/bytes/history%s"
                    (Simulation.id hist_sim) hist_widget.Widget.id
                    (match since with
                     | None -> ""
                     | Some t -> Printf.sprintf "?since=%.9f" t) in
            match http port path with
            | 200, body -> Some (Yojson.Basic.from_string body)
            | _ -> None in
        let points j =
            Yojson.Basic.Util.(
                member "series" j |> to_list |> List.map (fun s ->
                    member "points" s |> to_list |> List.map (fun p ->
                        member "t" p |> to_float,
                        member "value" p |> to_int))) in
        check "GET the history of a metric"
            (match history () with
            | None -> false
            | Some j ->
                Yojson.Basic.Util.(
                    member "kind" j = `String "counter" &&
                    member "units" j = `String "bytes" &&
                    member "rate" j = `Float 0.5 &&
                    (match member "now" j with `Float _ -> true | _ -> false)) &&
                (match points j with
                 (* One row, since nothing was counted with parameters, and as
                    many points as the ring was told to keep. *)
                 | [ ps ] -> List.length ps = 5
                 | _ -> false)) ;
        check "the points come oldest first, and only grow"
            (match Option.map points (history ()) with
            | Some [ ps ] ->
                List.for_all2 (fun (t1, v1) (t2, v2) -> t2 > t1 && v2 > v1)
                    (List.take (List.length ps - 1) ps) (List.tl ps)
            | _ -> false) ;
        check "since brings back what was taken after it, and nothing else"
            (match Option.map points (history ()) with
            | Some [ ps ] ->
                let t, _ = List.nth ps 2 in
                (match Option.map points (history ~since:t ()) with
                | Some [ after ] ->
                    List.length after = 2 &&
                    List.for_all (fun (t', _) -> t' > t) after
                | _ -> false)
            | _ -> false) ;
        check "since the last point brings back nothing at all"
            (match Option.map points (history ()) with
            | Some [ ps ] ->
                let t, _ = List.last ps in
                (match Option.map points (history ~since:t ()) with
                 (* A row with nothing new to say does not appear: an empty
                    answer is "nothing has been written down since". *)
                 | Some [] -> true
                 | _ -> false)
            | _ -> false) ;
        check "a since that is not a time is refused"
            (List.for_all (fun since ->
                fst (http port
                        (Printf.sprintf
                            "/api/simulations/%d/widgets/%d/properties/bytes/history?since=%s"
                            (Simulation.id hist_sim) hist_widget.Widget.id
                            since)) = 400)
                [ "nonsense" ; "inf" ; "" ]) ;
        check "a property that is not a metric has no history"
            (fst (api "/api/simulations/%d/widgets/%d/properties/length/history"
                      net_id cable_id) = 400) ;
        (* What a widget logged. Asked of the same stopped simulation: nothing
           writes to its logger any more, so what comes back is exactly what
           the sampling test put there. *)
        let logs ?since ?level () =
            let path =
                Printf.sprintf "/api/simulations/%d/widgets/%d/logs"
                    (Simulation.id hist_sim) hist_widget.Widget.id ^
                (match since with
                 | None -> "" | Some t -> Printf.sprintf "?since=%.9f" t) ^
                (match level with
                 | None -> "" | Some l -> (if since = None then "?" else "&") ^
                                          "level=" ^ l) in
            match http port path with
            | 200, body ->
                let j = Yojson.Basic.from_string body in
                Yojson.Basic.Util.(
                    Some (member "lost" j |> to_bool,
                          member "messages" j |> to_list |> List.map (fun m ->
                              member "t" m |> to_float,
                              member "level" m |> to_string,
                              member "text" m |> to_string)))
            | _ ->
                None in
        check "GET what a widget logged"
            (match logs () with
            | Some (false, msgs) ->
                List.length msgs >= 20 &&
                List.for_all (fun (_, l, _) -> l = "info" || l = "warning") msgs
            | _ -> false) ;
        check "oldest first"
            (match logs () with
            | Some (_, msgs) ->
                List.for_all2 (fun (t1, _, _) (t2, _, _) -> t2 >= t1)
                    (List.take (List.length msgs - 1) msgs) (List.tl msgs)
            | None -> false) ;
        check "since brings back what was logged after it, and nothing else"
            (match logs () with
            | Some (_, msgs) ->
                let t, _, _ = List.nth msgs 4 in
                (match logs ~since:t () with
                | Some (_, after) ->
                    List.length after = List.length msgs - 5 &&
                    List.for_all (fun (t', _, _) -> t' > t) after
                | None -> false)
            | None -> false) ;
        check "since the last of them brings back nothing"
            (match logs () with
            | Some (_, msgs) ->
                let t, _, _ = List.last msgs in
                (match logs ~since:t () with
                 | Some (false, []) -> true
                 | _ -> false)
            | None -> false) ;
        check "a level is how deep to go, not which one to show"
            (match logs ~level:"warning" () with
            | Some (_, msgs) ->
                msgs <> [] &&
                List.for_all (fun (_, l, _) -> l = "warning") msgs
            | None -> false) ;
        check "a level that is not one is refused"
            (fst (http port
                     (Printf.sprintf
                         "/api/simulations/%d/widgets/%d/logs?level=chatty"
                         (Simulation.id hist_sim) hist_widget.Widget.id)) = 400) ;
        check "and a since that is not a time"
            (fst (http port
                     (Printf.sprintf
                         "/api/simulations/%d/widgets/%d/logs?since=nonsense"
                         (Simulation.id hist_sim) hist_widget.Widget.id)) = 400) ;
        (* The composition tree is what the interface draws: a server has to
           appear within the host running it, not beside it. *)
        check "a server is shown within the host that runs it"
            (match api "/api/simulations/%d/widgets" (Simulation.id admin) with
            | 200, body ->
                let widgets =
                    Yojson.Basic.from_string body |> Yojson.Basic.Util.to_list in
                let name w = Yojson.Basic.Util.(member "name" w |> to_string)
                and id w = Yojson.Basic.Util.(member "id" w |> to_int)
                and parent w = Yojson.Basic.Util.(member "parent" w |> to_int_option) in
                let httpd =
                    List.find_opt (fun w ->
                        String.starts_with (name w) "httpd:") widgets in
                (match httpd with
                | None -> false
                | Some httpd ->
                    (match parent httpd with
                    | None -> false
                    | Some p ->
                        List.exists (fun w -> id w = p && name w = "localhost")
                                    widgets))
            | _ ->
                false) ;
        check "PUT a speed"
            (fst (http ~meth:"POST" port
                      (Printf.sprintf "/api/simulations/%d/speed?ratio=2" net_id))
             = 200) ;
        check "a speed that is not one is refused"
            (List.for_all (fun ratio ->
                fst (http ~meth:"POST" port
                         (Printf.sprintf "/api/simulations/%d/speed?ratio=%s"
                             net_id ratio)) = 400)
                (* Zero is a pause, not a speed; the rest are not numbers you
                   can run at, and [float_of_string] accepts them all. *)
                [ "0" ; "-1" ; "inf" ; "-inf" ; "nan" ; "nonsense" ]) ;
        check "a simulation on the wall clock has no speed to set"
            (fst (http ~meth:"POST" port
                      (Printf.sprintf "/api/simulations/%d/speed?ratio=2"
                          (Simulation.id admin))) = 400) ;
        check "back to full speed"
            (fst (http ~meth:"POST" port
                      (Printf.sprintf "/api/simulations/%d/speed?ratio=full" net_id))
             = 200) ;
        (* An answer with no [Content-Length] is one a client cannot tell the
           end of: it waits for the connection to close, and this server keeps
           it open. So what matters about a refusal is not only its status. *)
        check "a URL nobody serves is refused, and says how long the refusal is"
            (match http_full port "/no/such/thing" with
            | 404, head, body ->
                String.exists (String.lowercase head) "content-length:" &&
                String.trim body <> ""
            | _ -> false) ;
        check "an unknown widget is not found"
            (fst (api "/api/simulations/%d/widgets/99999" net_id) = 404) ;
        check "an unknown simulation is not found"
            (fst (api "/api/simulations/99999") = 404) ;
        check "the serving simulation refuses to pause itself"
            (fst (http ~meth:"POST" port
                      (Printf.sprintf "/api/simulations/%d/pause"
                          (Simulation.id admin))) = 400) ;
        check "a simulation's root cannot be deleted"
            (fst (http ~meth:"DELETE" port
                      (Printf.sprintf "/api/simulations/%d/widgets/%d"
                          net_id net.root.Widget.id)) = 400) ;

        (* Building a network from the outside. The catalogue says what can be
           asked for, and what each of them has to be told; a POST asks for one.
           Everything here goes through HTTP rather than through [Device]
           directly, since what is being pinned is the API. *)
        let post fmt =
            Printf.ksprintf (fun body ->
                http ~meth:"POST" ~body port
                     (Printf.sprintf "/api/simulations/%d/widgets" net_id)) fmt in
        let created fmt =
            Printf.ksprintf (fun body ->
                match http ~meth:"POST" ~body port
                           (Printf.sprintf "/api/simulations/%d/widgets" net_id) with
                | 200, payload ->
                    Yojson.Basic.(from_string payload |> Util.member "id" |>
                                  Util.to_int)
                | status, payload ->
                    incr failures ;
                    Printf.printf "  FAIL creating %s: %d %s\n%!"
                        body status payload ;
                    -1) fmt in
        let widget id =
            match Widget.find net.root id with
            | Some w -> w
            | None -> failwith (Printf.sprintf "no widget %d" id) in
        check "GET the catalogue of what can be built"
            (match http port "/api/device-types" with
            | 200, payload ->
                let types =
                    Yojson.Basic.(from_string payload |> Util.to_list |>
                                  List.map (fun t ->
                                      Util.(member "type" t |> to_string))) in
                List.mem "host" types && List.mem "cable" types
            | _ -> false) ;
        (* Every parameter says what kind of value it is in the same words a
           property does, which is what lets one dialog be built out of both. *)
        check "a catalogue entry describes its parameters"
            (match http port "/api/device-types" with
            | 200, payload ->
                Yojson.Basic.(
                    from_string payload |> Util.to_list |>
                    List.find (fun t -> Util.(member "type" t |> to_string) = "switch") |>
                    Util.member "params" |> Util.to_list |>
                    List.exists (fun p ->
                        Util.(member "name" p |> to_string) = "ports" &&
                        Util.member "default" p = `Int 8 &&
                        Util.(member "kind" p |> member "type" |> to_string)
                            = "range"))
            | _ -> false) ;
        let switch_id = created {|{"type":"switch","name":"built",
                                   "params":{"ports":3,"MACs":8}}|} in
        check "a device built from the API is in the tree"
            (match Widget.find net.root switch_id with
            | Some w -> w.Widget.name = "built"
            | None -> false) ;
        (* Made of the same parts as one an OCaml program would have built: a
           switch is a hub that remembers, and the hub is a widget of its own. *)
        check "and is made of what such a device is made of"
            (match Widget.find net.root switch_id with
            | Some w ->
                (match w.Widget.children with
                | [ c ] -> c.Widget.name = "hub"
                | _ -> false)
            | None -> false) ;
        let host_a = created {|{"type":"host","name":"a",
                                "params":{"address":"10.9.0.1"}}|}
        and host_b = created {|{"type":"host","name":"b",
                                "params":{"address":"10.9.0.2"}}|} in
        let cable_of a b =
            created {|{"type":"cable","params":{"from":%d,"to":%d}}|} a b in
        let joined = cable_of switch_id host_a in
        (* Peered with what the cable reaches, which is not always what was
           named to ask for it: a host is reached through its adapter, so that
           is the end the graph records. A switch is reached at the switch --
           its ports are not widgets, one being as good as another. *)
        let adapter id =
            List.find (fun (c : Widget.t) -> c.name = "eth")
                      (widget id).Widget.children in
        (* Named after what it joins, since "built-a" says what "cable-1"
           cannot. *)
        check "a cable with no name is named after its two ends"
            ((widget joined).Widget.name = "built-a") ;
        check "a cable makes peers of the two ends it joins"
            (let c = widget joined in
             let end_of w =
                 List.find_opt (fun (p : Widget.peer) ->
                     match p.via with Some v -> v == c | None -> false)
                     w.Widget.peers in
             match end_of (widget switch_id) with
             | Some p -> p.widget == adapter host_a
             | None -> false) ;
        check "and the far end says the same the other way round"
            (let c = widget joined in
             List.exists (fun (p : Widget.peer) ->
                 p.widget.Widget.id = switch_id &&
                 (match p.via with Some v -> v == c | None -> false))
                 (adapter host_a).Widget.peers) ;
        (* And frames really cross it: a device added from the outside is on the
           network, not merely in the picture of it. A host with no address of
           its own starts asking a DHCP server for one the moment it is built,
           so it is traffic nobody has to arrange. *)
        let asker = created {|{"type":"host","name":"asker","params":{}}|} in
        let asking = cable_of switch_id asker in
        let bits_across id =
            match Widget.find net.root id with
            | None -> 0
            | Some c ->
                (match List.find (fun (p : Widget.property) ->
                           p.name = "total bits") c.Widget.properties with
                | exception Not_found -> 0
                | p ->
                    Yojson.Basic.Util.(
                        p.getter () |> member "values" |> to_list |>
                        List.fold_left (fun n v ->
                            n + (member "value" v |> to_int)) 0)) in
        check "the new network is wired, not merely drawn"
            (wait_for (fun () -> bits_across asking > 0)) ;
        (* And what crosses one cable reaches the far side of the next: the
           switch forwards it, which is the whole of being connected. *)
        check "and the device at the other end of the switch hears it"
            (wait_for (fun () -> bits_across joined > 0)) ;
        (* And it is a switch that is forwarding them, not the repeater it is
           made of: the ports are the switch's own, so what arrives on one goes
           through the address learning rather than straight out of every other
           port. A switch that has learnt nothing has never seen a frame. *)
        let learnt id =
            match List.find (fun (p : Widget.property) -> p.name = "macs")
                            (widget id).Widget.properties with
            | exception Not_found -> false
            | p -> Yojson.Basic.Util.member "first_last" (p.getter ()) <> `Null in
        check "and it is the switch forwarding them, not the repeater inside it"
            (wait_for (fun () -> learnt switch_id)) ;
        check "which is therefore no port of its own"
            (List.for_all (fun (c : Widget.t) -> c.ports.count () = 0)
                          (widget switch_id).Widget.children) ;
        (* Three ports, and the third one takes the last of them. *)
        ignore (cable_of switch_id host_b) ;
        let host_c = created {|{"type":"host","name":"c",
                                "params":{"address":"10.9.0.5"}}|} in
        check "one cable too many for the ports it has is refused"
            (fst (post {|{"type":"cable","params":{"from":%d,"to":%d}}|}
                       switch_id host_c) = 400) ;
        check "and so is a second cable on a host's single adapter"
            (fst (post {|{"type":"cable","params":{"from":%d,"to":%d}}|}
                       host_a host_c) = 400) ;
        check "an unknown kind of device is refused"
            (fst (post {|{"type":"firewall","name":"fw"}|}) = 400) ;
        check "a parameter that is not one is refused"
            (fst (post {|{"type":"switch","name":"x","params":{"port":2}}|}) = 400) ;
        check "a value out of range is refused"
            (fst (post {|{"type":"switch","name":"x","params":{"ports":0}}|}) = 400) ;
        check "an address that is not one is refused"
            (fst (post {|{"type":"host","name":"x","params":{"address":"nope"}}|})
             = 400) ;
        (* [Ip.Addr.of_string] would have asked the resolver, which is a wait
           this holds the simulation's lock across. *)
        check "and a name is not resolved into one"
            (fst (post {|{"type":"host","name":"x","params":{"address":"localhost"}}|})
             = 400) ;
        (* The other way round: no name asks for one, which is the only way to
           be sure of a free one -- a name checked beforehand and sent
           afterwards is one something else may have taken in between. *)
        check "a device with no name is given one"
            ((widget (created {|{"type":"hub"}|})).Widget.name = "hub-1") ;
        check "and the next of that kind is given the next number"
            ((widget (created {|{"type":"hub","name":""}|})).Widget.name
             = "hub-2") ;
        check "while a name that was actually typed and is taken is refused"
            (fst (post {|{"type":"hub","name":"hub-1"}|}) = 400) ;
        (* From a device with a port to spare, so that what is being refused is
           the far end and not the near one. *)
        let spare = created {|{"type":"host","name":"spare",
                               "params":{"address":"10.9.0.7"}}|} in
        check "a cable to something that takes none is refused"
            (fst (post {|{"type":"cable","params":{"from":%d,"to":%d}}|}
                       spare net.root.Widget.id) = 400) ;
        (* A host says nothing about ports itself: it is reached through its
           adapter, and answers with whatever adapters it has. Which is why the
           root of a simulation, which is reached through nothing, has none --
           it is not that every ancestor inherits what is below it. *)
        check "a host's ports are its adapter's"
            ((widget host_a).ports.count () = 1 &&
             List.exists (fun (c : Widget.t) ->
                 c.name = "eth" && c.ports.count () = 1)
                 (widget host_a).Widget.children) ;
        check "and a simulation's root has none of its children's"
            (net.root.ports.count () = 0) ;
        (* Nothing writes down which ports are taken. The device is asked, and
           answers from the flag it raises when a reader is installed on it --
           which is what plugging a cable in does, whoever does it. So a cable
           an OCaml program wired up itself is seen for what it is, without
           anyone having had to say so. *)
        let lone =
            widget (created {|{"type":"host","name":"lone",
                               "params":{"address":"10.9.0.6"}}|}) in
        check "a port with nothing on it is free"
            (not (lone.ports.is_connected 0)) ;
        (lone.ports.dev 0).Tools.set_read ignore ;
        check "and a cable plugged in by a program counts as one"
            (lone.ports.is_connected 0) ;
        (* The length of a cable is how long a frame takes to cross it, so where
           the two ends are is the answer when nobody gives another. *)
        let place id lat lon =
            fst (http ~meth:"PUT"
                      ~body:(Printf.sprintf {|{"lat":%g,"lon":%g}|} lat lon) port
                      (Printf.sprintf "/api/simulations/%d/widgets/%d/location"
                          net_id id)) in
        let paris = created {|{"type":"host","name":"paris",
                               "params":{"address":"10.9.0.3"}}|}
        and lyon = created {|{"type":"host","name":"lyon",
                              "params":{"address":"10.9.0.4"}}|} in
        check "placing the two ends" (place paris 48.8566 2.3522 = 200 &&
                                      place lyon 45.764 4.8357 = 200) ;
        let long = cable_of paris lyon in
        (* Which is all a saved topology needs: each end is a widget that takes
           cables, so writing down the two ids is writing down the cable. No
           port number travels, and none is needed -- where a port makes a
           difference there is a widget for it, and where there is none the
           ports are interchangeable. *)
        check "and both ends are things a cable can be asked for again"
            (match (widget joined).Widget.peers with
            | [ x ; y ] ->
                x.widget.Widget.ports.count () > 0 &&
                y.widget.Widget.ports.count () > 0
            | _ -> false) ;

        check "a cable between two places is as long as the way between them"
            (match http port
                     (Printf.sprintf
                         "/api/simulations/%d/widgets/%d/properties/length"
                         net_id long) with
            | 200, payload ->
                Yojson.Basic.(from_string payload |> Util.member "value") =
                    `Float 391499.
            | _ -> false) ;

        (* Deleting is the other half of building, and it is the cables that
           make it more than taking a widget out of the picture: they are the
           one thing that reaches from one device into another, so they cannot
           outlive either end. *)
        let del id =
            fst (http ~meth:"DELETE" port
                      (Printf.sprintf "/api/simulations/%d/widgets/%d"
                                      net_id id))
        and gone id =
            fst (api "/api/simulations/%d/widgets/%d" net_id id) = 404 in
        check "deleting a cable frees the two ports it was on"
            (del long = 200 && gone long &&
             not ((widget paris).ports.is_connected 0) &&
             not ((widget lyon).ports.is_connected 0)) ;
        check "and leaves the two devices it joined where they were"
            (not (gone paris) && not (gone lyon)) ;
        let near = created {|{"type":"host","name":"near",
                              "params":{"address":"10.9.0.8"}}|}
        and far = created {|{"type":"host","name":"far",
                             "params":{"address":"10.9.0.9"}}|} in
        let between = cable_of near far in
        check "deleting a device takes the cable that reached it with it"
            (del near = 200 && gone near && gone between) ;
        check "and gives the far end its port back"
            (not (gone far) && not ((widget far).ports.is_connected 0)) ;
        (* What this interface cannot build it will not remove either: a part of
           a device is not a device, and deleting a host's adapter would leave a
           host whose port answers for a widget nobody can see. *)
        check "a device says what kind of device it is"
            ((widget far).Widget.device = Some "host" &&
             (widget switch_id).Widget.device = Some "switch") ;
        check "and a part of one says it is not a device at all"
            ((adapter far).Widget.device = None) ;
        (* The repeater inside a switch *is* a repeater, and says so. What it
           is not is a device of its own: one does not order or return the
           parts of a machine separately. *)
        check "while a part that is a device in its own right says so"
            (List.exists (fun (c : Widget.t) -> c.device = Some "hub")
                         (widget switch_id).Widget.children) ;
        check "so deleting a device's adapter is refused"
            (del (adapter far).Widget.id = 400 && not (gone far)) ;
        check "and so is deleting the repeater inside a switch"
            (List.for_all (fun (c : Widget.t) -> del c.id = 400)
                          (widget switch_id).Widget.children) ;
        check "and the interface says as much before being asked"
            (match api "/api/simulations/%d/widgets/%d" net_id switch_id with
            | 200, payload ->
                Yojson.Basic.(from_string payload |> Util.member "deletable")
                    = `Bool true &&
                List.for_all (fun (c : Widget.t) ->
                    match api "/api/simulations/%d/widgets/%d" net_id c.Widget.id with
                    | 200, payload ->
                        Yojson.Basic.(from_string payload |>
                                      Util.member "deletable") = `Bool false
                    | _ -> false) (widget switch_id).Widget.children
            | _ -> false) ;
        check "while the whole device goes"
            (del far = 200 && gone far) ;

        (* A machine arrives from the shop unconfigured: a router with as many
           interfaces as were ordered, an empty routing table, and no address
           on any of them. What it is to do with a packet comes later, as
           properties do. *)
        let r = created {|{"type":"router","name":"r1",
                           "params":{"ports":3,"MAC range":"00:11:22"}}|} in
        check "a router is built with the ports it was ordered with"
            ((widget r).ports.count () = 3) ;
        (* Unconfigured means unconfigured: an interface with no address of its
           own has no admin host on it, so each of them is an adapter and
           nothing else. *)
        check "and arrives with nothing on its interfaces but their adapters"
            (List.length (widget r).Widget.children = 3 &&
             List.for_all (fun (c : Widget.t) ->
                 List.map (fun (a : Widget.t) -> a.name) c.children = [ "eth" ])
                 (widget r).Widget.children) ;
        let macs_of id =
            List.filter_map (fun (c : Widget.t) ->
                match c.children with
                | [ eth ] ->
                    (match http port
                             (Printf.sprintf
                                 "/api/simulations/%d/widgets/%d/properties/MAC"
                                 net_id eth.Widget.id) with
                    | 200, payload ->
                        Some Yojson.Basic.(from_string payload |>
                                           Util.member "value")
                    | _ -> None)
                | _ -> None
            ) (widget id).Widget.children in
        check "with one address per interface, and no two the same"
            (let macs = macs_of r in
             List.length macs = 3 &&
             List.length (List.sort_unique compare macs) = 3) ;
        let plugged = created {|{"type":"host","name":"plugged",
                                 "params":{"address":"10.9.0.11"}}|} in
        check "a router can be cabled like anything else"
            (fst (post {|{"type":"cable","params":{"from":%d,"to":%d}}|}
                       r plugged) = 200 &&
             (widget r).ports.is_connected 0) ;
        let g = created {|{"type":"gateway","name":"gw",
                           "params":{"LAN":"10.42.0.0/24"}}|} in
        check "a gateway offers its two sides and nothing from inside"
            ((widget g).ports.count () = 2) ;
        check "and the router within it is not a device of its own"
            (List.for_all (fun (c : Widget.t) -> del c.id = 400)
                          (widget g).Widget.children) ;
        check "but the gateway itself is"
            (del g = 200 && gone g) ;
        check "and so is the router"
            (del r = 200 && gone r) ;
        check "a MAC that is not one is refused"
            (fst (post {|{"type":"router","name":"x","params":{"MACs":"nope"}}|})
                 = 400) ;
        check "and so is a list that does not match the ports"
            (fst (post {|{"type":"router","name":"x",
                          "params":{"ports":2,"MACs":"00:11:22:33:44:55"}}|})
                 = 400) ;
        check "and a LAN that is not a network"
            (fst (post {|{"type":"gateway","name":"x","params":{"LAN":"nope"}}|})
                 = 400) ;

        (* Then, that it keeps answering while hammered from all sides -- which
         * is the whole point of myadmin living in its own simulation. *)
        Printf.printf "  (hammering for %gs with %d threads)\n%!"
            duration nthreads ;
        let deadline = Unix.gettimeofday () +. duration in
        let running () = Unix.gettimeofday () < deadline in
        let bad = ref 0 and reqs = ref 0 in
        let lock = Mutex.create () in
        let tally b r =
            BatMutex.synchronize ~lock (fun () ->
                bad := !bad + b ; reqs := !reqs + r) () in
        let worker f () =
            let b = ref 0 and r = ref 0 in
            while running () do
                (match f () with
                | exception _ -> incr b
                | status -> if status <> 200 then incr b) ;
                incr r
            done ;
            tally !b !r in
        let workers = [
            (fun () -> fst (api "/api/simulations")) ;
            (fun () -> fst (api "/api/simulations/%d/widgets" net_id)) ;
            (fun () -> fst (api "/api/simulations/%d/widgets/%d/properties"
                                net_id cable_id)) ;
            (fun () ->
                fst (http ~meth:"PUT" ~body:(Printf.sprintf "%d.5" (Random.int 100)) port
                         (Printf.sprintf
                             "/api/simulations/%d/widgets/%d/properties/length"
                             net_id cable_id))) ;
            (fun () ->
                fst (http ~meth:"POST" port
                         (Printf.sprintf "/api/simulations/%d/pause" net_id))) ;
            (fun () ->
                fst (http ~meth:"POST" port
                         (Printf.sprintf "/api/simulations/%d/resume" net_id))) ;
        ] in
        let threads =
            List.init nthreads (fun i ->
                Thread.create (worker (List.nth workers
                                          (i mod List.length workers))) ()) in
        List.iter Thread.join threads ;
        check (Printf.sprintf "every request answered 200 (%d requests, %d bad)"
                  !reqs !bad)
            (!bad = 0) ;
        check "requests actually went through" (!reqs > 0) ;
        (* And that the admin is still there afterwards: *)
        check "the admin interface survived"
            (fst (api "/api/simulations") = 200) ;
        (* The hammering may have left it paused: *)
        ignore (http ~meth:"POST" port
                    (Printf.sprintf "/api/simulations/%d/resume" net_id)) ;
        check "the simulation under test survived"
            (let t0 = Simulation.now net in
             wait_for (fun () -> Simulation.now net > t0))

(*
 * Main
 *)

let main =
    let duration =
        if Array.length Sys.argv > 1 then float_of_string Sys.argv.(1) else 2.
    and nthreads =
        if Array.length Sys.argv > 2 then int_of_string Sys.argv.(2) else 10 in
    Random.self_init () ;
    let net, cable = make_net () in
    ignore (Simulation.start net) ;
    test_clock net ;
    test_speed net ;
    let samples_sim, samples_widget = test_metric_samples () in
    test_concurrency net cable duration nthreads ;
    test_disconnect () ;
    test_power () ;
    test_delete () ;
    test_http net cable duration nthreads samples_sim samples_widget ;
    Printf.printf "\n%d checks, %d failure(s)\n%!" !checks !failures ;
    (* Simulations run in threads of their own, which would otherwise keep the
     * process alive: *)
    exit (if !failures = 0 then 0 else 1)
