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
    cable.widget.properties <-
        cable.widget.properties @
        [ Widget.property "sealed" ~descr:"Cannot be written."
              ~kind:Widget.Int ~getter:(fun () -> `Int 1) ] ;
    (* Something to keep its clock busy for ever: *)
    let rec ticking () = Simulation.delay net tick ticking () in
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
        (Clock.Time.sub after_step paused_at :> float) ;
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

(*
 * 2. Concurrent access to a running simulation
 *)

(* Each worker hammers one facet of the API. What we are looking for is not a
 * result but the absence of a deadlock, an exception, or a corrupted value. *)
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
let http ?(meth="GET") ?body port path =
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
        status, payload) ()

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

let test_http net cable duration nthreads =
    section "Administration interface over HTTP" ;
    match start_admin () with
    | None ->
        incr failures ;
        Printf.printf "  FAIL could not start the admin interface\n%!"
    | Some (_admin, port) ->
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
        check "an unknown widget is not found"
            (fst (api "/api/simulations/%d/widgets/99999" net_id) = 404) ;
        check "an unknown simulation is not found"
            (fst (api "/api/simulations/99999") = 404) ;
        check "the serving simulation refuses to pause itself"
            (fst (http ~meth:"POST" port
                      (Printf.sprintf "/api/simulations/%d/pause"
                          (Simulation.id _admin))) = 400) ;
        check "a simulation's root cannot be deleted"
            (fst (http ~meth:"DELETE" port
                      (Printf.sprintf "/api/simulations/%d/widgets/%d"
                          net_id net.root.Widget.id)) = 400) ;

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
    test_concurrency net cable duration nthreads ;
    test_http net cable duration nthreads ;
    Printf.printf "\n%d checks, %d failure(s)\n%!" !checks !failures ;
    (* Simulations run in threads of their own, which would otherwise keep the
     * process alive: *)
    exit (if !failures = 0 then 0 else 1)
