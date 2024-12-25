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
   This module creates an alarm-clock that schedule registered events.
   There are two modes of operation: realtime and not realtime.

   When in realtime mode (the default), the clock will merely follow
   wall-clock. Then, scheduling an event in the future is equivalent to
   [Unix.sleep] for some time. This is not very interesting but is required
   whenever you plan to work with real network devices and outside world.  On
   the other hand, if your simulated network does not communicates with the
   outside world, for instance because your objective is to build a pcap file,
   then you can use not realtime mode and then play your simulation at full
   speed (and full CPU), and produce a pcap file representing, say, the
   workload of a day in minutes, or conversely a very busy hour in several
   hours but with all packets and accurate timestamps.

*)
open Batteries

let debug = false

let realtime = ref true

(** {2 Private Types} *)

(** Time.t represents a given timestamp (ie. number of seconds since 1970-01-01 00:00:00 UTC. *)
module rec Time : sig
    val print_date : bool ref
    include Private.S with type t = private float and type outer_t = float
    val add : t -> Interval.t -> t
    val sub : t -> t -> Interval.t
    val wall_clock : unit -> t
    val to_ints : t -> int * int
    val compare : t -> t -> int
    val is_after : t -> t -> bool
end = struct
    (** When displaying a time, print also the corresponding date.
     * Only useful if your simulation spans several days, which is uncommon. *)
    let print_date = ref false

    include Private.Make (struct
        type t = float
        let to_string t =
            let open Unix in
            let tm = localtime t in
            let msec = Float.round_to_int (100. *. (fst (modf t))) in
            let sec, msec =
                if msec < 100 then tm.tm_sec, msec
                else tm.tm_sec + 1, 0 in
            if !print_date then
                Printf.sprintf "%d-%02d-%02d %02d:%02d:%02d.%02d"
                    (1900+tm.tm_year) (1+tm.tm_mon) tm.tm_mday tm.tm_hour tm.tm_min sec msec
            else
                Printf.sprintf "%02d:%02d:%02d.%02d"
                    tm.tm_hour tm.tm_min sec msec
        let is_valid v = v = v
        let repl_tag = "time"
    end)

    (** Adds a time and an interval. *)
    let add (t : t) (i : Interval.t) = o ((t :> float) +. (i :> float))

    (** Substract two time and returns an interval. *)
    let sub (a : t) (b : t) = Interval.o ((a :> float) -. (b :> float))

    (** Get the current wall clock (through {Unix.gettimeofday}). *)
    let wall_clock () = o (Unix.gettimeofday ())

    (** Convert a timestamp to a pair of ints with seconds, microseconds *)
    let to_ints (t : t) =
        let t = (t :> float) in
        let sec  = Int.of_float t in
        let usec = Int.of_float ((t -. (floor t)) *. 1_000_000.) in
        sec, usec

    let compare a b =
        Float.compare (a : t :> float) (b : t :> float)

    let is_after a b =
        compare a b >= 0
end

(** While Interval.t represents a time interval.
 * Both are floats internally to match OCaml stdlib. *)
and Interval : sig
    include Private.S with type t = private float and type outer_t = float
    val usec : float -> t
    val msec : float -> t
    val sec  : float -> t
    val min  : float -> t
    val hour : float -> t
    val zero : t
    val compare : t -> t -> int
    val add : t -> t -> t
    val sub : t -> t -> t
    val mul : t -> float -> t
end = struct
    include Private.Make (struct
        type t = float
        let to_string t =
            Printf.sprintf "+%fs" t
        let is_valid v = v = v
        let repl_tag = "time"
    end)

    (** microseconds to {Interval.t}. *)
    let usec i = o (i *. 0.000001)

    (** milliseconds to {Interval.t}. *)
    let msec i = o (i *. 0.001)

    (** seconds to {Interval.t}. *)
    let sec i  = o i

    (** minutes to {Interval.t}. *)
    let min i  = o (i *. 60.)

    (** hours to {Interval.t}. *)
    let hour i = o (i *. 3600.)

    (** Empty interval *)
    let zero = o 0.

    (** Custom comparison function so that we can change time representation
     * more easily in the future. *)
    let compare (a : t) (b : t) = Float.compare (a :> float) (b :> float)

    (** Adds two intervals. *)
    let add (a : t) (b : t) = o ((a :> float) +. (b :> float))

    (** Subtract two intervals. *)
    let sub (a : t) (b : t) = o ((a :> float) -. (b :> float))

    (** Multiply the duration by a scalar. *)
    let mul (t : t) s = o ((t :> float) *. s)
end

(** {2 Current running time} *)

module Map = Map.Make (struct
    type t = Time.t
    let compare (a : t) (b : t) = Float.compare (a :> float) (b :> float)
end)

(** A clock is a current timestamp and the set of future events. *)
type clock = { mutable now : Time.t ; mutable events : (unit -> unit) Map.t }

(** We have only one clock so can run only one simulation at the same time. *)
let current = { now = Time.o (Unix.gettimeofday ()) ; events = Map.empty }

(* A lock to protect both the condition and the current events map *)
let lock = Mutex.create ()
let cond = Condition.create ()

let with_lock f x =
    BatMutex.synchronize ~lock f x

let signal_me () = Condition.signal cond

(** Return the current simulation time. *)
let now () =
    with_lock (fun () -> current.now) ()

(** [at t f x] will execute [f x] when simulation clock reaches time [t]. *)
let at (ts : Time.t) f x =
    let epsilon = Interval.usec 1. in
    let rec loop ts =
        (* If ts was already bound in current.events, its previous binding disappears.
           Also, we do not like the idea of several sequential events having the same TS. *)
        if Map.mem ts current.events then (
            loop (Time.add ts epsilon)
        ) else (
            if debug then Printf.printf "Clock: add an event for time %s (%s)\n%!" (Time.to_string ts) (Interval.to_string (Time.sub ts current.now)) ;
            current.events <- Map.add ts (fun () -> f x) current.events
        ) in
    with_lock loop ts ;
    signal_me ()

(** [delay d f x] will delay the execution of [f x] by the interval [d]. *)
let delay d f x =
    at (Time.add current.now d) f x

let asap f x =
    (* FIXME: would be more precise and fast to have a dedicated list for asap events *)
    delay (Interval.o 0.) f x

let synch_locked () =
    assert !realtime (* Synch with real clock in non-realtime mode!? *) ;
    current.now <- Time.wall_clock () ;
    if debug then Printf.printf "Clock: synch: set current time to %s\n%!" (Time.to_string current.now)

(** Synchronize internal clock with realtime clock.
 * You must call this after real time passes (for instance after a blocking call).
 * Otherwise, time jumps from one registered event to the next. *)
let synch = with_lock synch_locked

let continue = ref true

(** Will process the next event *)
let next_event () =
    let min_ts_for_sleep = Interval.msec 10. in
    (* Time to sleep while waiting for an event to be added in the queue.
     * Must be > min_ts_for_sleep *)
    let max_sleep_time = Interval.sec 3. in
    let run_first_event =
        if !realtime then (
            (* Note: In realtime, other threads may add new events while we are
             * sleeping, so a condition variable is used (instead of a mere
             * Unix.sleep). *)
            Mutex.lock lock ;
            (* Wait until there is an event to process now: *)
            let rec wait_loop () =
                let until =
                    match Map.min_binding current.events with
                    | exception Not_found -> Time.add current.now max_sleep_time
                    | ts, _ -> ts in
                let wait_time = Time.sub until current.now in
                if Interval.compare wait_time min_ts_for_sleep > 0 then (
                    if debug then Printf.printf "Clock: next_event: waiting until %s since we're too early\n%!" (Time.to_string until) ;
                    (try Condvar.timed_wait cond lock (until :> float)
                    with Condvar.Timeout -> ()) ;
                    (* If we timed out we need to wait longer.
                     * If we have been signaled we still need to wait for the
                     * next event, which may be a different one. *)
                    (* Because of the loop condition above: *)
                    synch_locked () ;
                    if !continue then wait_loop ()
                ) in
                (* Else there is no need to wait we can go straight to processing
                   that event: *)
            wait_loop () ;
            Mutex.unlock lock ;
            !continue
        ) else ( (* not realtime *)
            if with_lock Map.is_empty current.events then (
                if debug then Printf.printf "Clock: no more events" ;
                false
            ) else true
        ) in
    if run_first_event then (
        (* We have some work to do *)
        let f =
            with_lock (fun () ->
                let ts, f = Map.min_binding current.events in
                if debug then Printf.printf "Clock: next_event: executing since it's %s\n%!" (Time.to_string ts) ;
                current.events <- Map.remove ts current.events ;
                current.now <- ts ;
                f) () in
        try f ()
        with exn ->
            Printf.printf "Clock: event handler triggered an exception : %a\n%s%!"
                Printexc.print exn
                (Printexc.get_backtrace ())
    )

(** [run true] will run forever while [run false] will return once no more
 * events are waiting.  If you choose to not run forever, beware that waiting
 * for an answer from the outside world is _not_ a clock event. You should
 * probably run forever whenever you communicate with the outside. *)
let run wait =
    if debug then Printf.printf "clock: running the clock!\n%!" ;
    while !continue && (wait || not (Map.is_empty current.events)) do
        next_event () ;
        Thread.yield ()
    done

let with_trapped signals f =
    let prev_sigs =
        List.map (fun s ->
            let open Sys in
            signal s (Signal_handle (fun _n -> continue := false))
        ) signals in
    let res = f () in
    List.iter2 Sys.set_signal signals prev_sigs ;
    res
