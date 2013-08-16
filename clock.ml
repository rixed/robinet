(* vim:sw=4 ts=4 sts=4 expandtab
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
open Tools

let debug = false

let realtime = ref true

(** {2 Private Types} *)

(** Time.t represents a given timestamp (ie. number of seconds since 1970-01-01 00:00:00 UTC. *)
module rec Time : sig
    val print_date : bool ref
    include PRIVATE_TYPE with type t = private float and type outer_t = float
    val add : t -> Interval.t -> t
    val sub : t -> t -> Interval.t
    val wall_clock : unit -> t
    val to_ints : t -> int * int
end = struct
    (** When displaying a time, print also the corresponding date.
     * Only useful if your simulation spans several days, which is uncommon. *)
    let print_date = ref false

    include MakePrivate(struct
        type t = float
        let to_string t =
            let open Unix in
            let tm = localtime t in
            let msec = Float.round_to_int (100. *. (fst (modf t))) in
            if !print_date then
                Printf.sprintf "%d-%02d-%02d %02d:%02d:%02d.%02d"
                    (1900+tm.tm_year) (1+tm.tm_mon) tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec msec
            else
                Printf.sprintf "%02d:%02d:%02d.%02d"
                    tm.tm_hour tm.tm_min tm.tm_sec msec
        let is_valid _ = true
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
end
(** While Interval.t reprensents a time interval.
 * Both are floats internaly to match OCaml stdlib. *)
and Interval : sig
    include PRIVATE_TYPE with type t = private float and type outer_t = float
    val usec : float -> t
    val msec : float -> t
    val sec  : float -> t
    val min  : float -> t
    val hour : float -> t
    val compare : t -> t -> int
    val add : t -> t -> t
end = struct
    include MakePrivate(struct
        type t = float
        let to_string t =
            Printf.sprintf "+%fs" t
        let is_valid _ = true
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

    (** Custom comparison function so that we can change time representation
     * more easily in the future. *)
    let compare (a : t) (b : t) = Float.compare (a :> float) (b :> float)
    (** Adds two intervals. *)
    let add (a : t) (b : t) = o ((a :> float) +. (b :> float))
end

(* poor man's asctime *)
let printer oc t = BatIO.nwrite oc (Time.to_string t)

(** {2 Current running time} *)

module Map = Map.Make (struct
    type t = Time.t
    let compare (a : t) (b : t) = Float.compare (a :> float) (b :> float)
end)

(** A clock is a current timestamp and the set of future events. *)
type clock = { mutable now : Time.t ; mutable events : (unit -> unit) Map.t }

(** We have only one clock so can run only one simulation at the same time. *)
let current = { now = Time.o (Unix.gettimeofday ()) ; events = Map.empty }

(** Return the current simulation time. *)
let now () = current.now

let cond_lock = Mutex.create ()
let cond = Condition.create ()

let signal_me () = Condition.signal cond

let epsilon = Interval.usec 1.

(** [at t f x] will execute [f x] when simulation clock reachs time [t]. *)
let rec at (ts : Time.t) f x =
    (* FIXME: since localhost.reader add events from other threads, use a mutex to protect current.events *)
    (* If ts was already bound in current.events, its previous binding disappears.
       Also, we do not like the idea of several sequencial events having the same TS. *)
    try Map.find ts current.events |> ignore ;
        at (Time.add ts epsilon) f x
    with Not_found ->
        if debug then Printf.printf "Clock: add an event for time %s (%s)\n%!" (Time.to_string ts) (Interval.to_string (Time.sub ts current.now)) ;
        current.events <- Map.add ts (fun () -> f x) current.events ;
        signal_me ()

(** [delay d f x] will delay the execution of [f x] by the interval [d]. *)
let delay d f x =
    at (Time.add current.now d) f x

let asap f x =
    (* FIXME: would be more precise and fast to have a dedicated list for asap events *)
    delay (Interval.o 0.) f x

(** Synchronize internal clock with realtime clock.
 * You must call this after real time passes (for instance after a blocking call).
 * Otherwise, time jumps from one registered event to the next. *)
let synch () =
    ensure !realtime "Synch with real clock in non-realtime mode!?" ;
    current.now <- Time.wall_clock () ;
    if debug then Printf.printf "Clock: synch: set current time to %s\n%!" (Time.to_string current.now)

(** Will process the next event *)
let next_event () =
    let run_first =
        if !realtime then (
            (* Note: In realtime, other threads may add new events while we are sleeping.
               So we use a condition variable (instead of a mere Unix.sleep) so that addition of event can awake us. *)
            let wait_ts = ref (Interval.o 0.) in
            Mutex.lock cond_lock ;
            while
                let ts, _ = try Map.min_binding current.events
                            with Not_found -> Time.o max_float, (fun () -> ()) in
                wait_ts := Time.sub ts current.now ;
                Interval.compare !wait_ts (Interval.msec 10.) > 0
            do
                if debug then Printf.printf "Clock: next_event: waiting for %s since we're too early\n%!" (Interval.to_string !wait_ts) ;
                (* fork a thread that will sleep then signal_me () *)
                (* FIXME: since we cant Thread.kill this thread many can accumulate. *)
                ignore (Thread.create (fun ts ->
                    Thread.delay (min 1. ts) ;
                    if debug then Printf.printf "Clock: waiker: time to waike up!\n" ;
                    signal_me ()) (!wait_ts :> float)) ;
                Condition.wait cond cond_lock ; (* zzz *)
                synch ()
            done ;
            Mutex.unlock cond_lock ;
            true
        ) else ( (* not realtime *)
            if Map.is_empty current.events then (
                if debug then Printf.printf "Clock: no more events" ;
                false
            ) else true
        ) in
    if run_first then (
        (* We have some work to do *)
        let ts, f = Map.min_binding current.events in
        if debug then Printf.printf "Clock: next_event: executing since it's %s\n%!" (Time.to_string ts) ;
        current.events <- Map.remove ts current.events ;
        current.now <- ts ;
        try f ()
        with exn ->
            Printf.printf "Clock: event handler triggered an exception : %a\n%!" Printexc.print exn
    )

(** [run true] will run forever while [run false] will return once no more events are waiting. *)
let run wait =
    while wait || not (Map.is_empty current.events) do
        next_event () ;
        Thread.yield ()
    done

