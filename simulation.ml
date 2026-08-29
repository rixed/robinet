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
  A simulation: a clock, and the widgets living on it.

  Several simulations can run at the same time in the same process, each in its
  own thread. They are independent: a widget only ever relates to widgets of its
  own simulation, since a cable cannot span two clocks.

  What this buys us is an administration interface that stays responsive while
  the simulation it inspects is paused: myadmin runs in its own realtime
  simulation, which is never paused, and reaches into the others only to read
  and write their state.

  A simulation need to be passed explicitly to everything that schedules an
  event or reads the time.

  Reaching into a simulation from a thread that does not run it is done
  exclusively through [with_lock], which takes that simulation's lock -- the
  same lock its own thread holds while dispatching an event, so the borrower
  sees a consistent state, never one halfway through a handler.

  {2 Realtime and not}

  A simulation's clock has two modes of operation.

  In realtime mode (the default), the clock merely follows the wall clock, and
  scheduling an event in the future amounts to [Unix.sleep]ing until then. That
  is not very interesting in itself, but it is required whenever the simulation
  works with real network devices and the outside world.

  If on the other hand the simulated network does not communicate with the
  outside -- when the objective is to produce a pcap file, say -- then not
  realtime mode plays the simulation at full speed and full CPU, and can produce
  a pcap representing the workload of a day in minutes, or conversely a very
  busy hour in several hours, with all packets present and their timestamps
  accurate.

  Only a simulation in realtime mode calls [synch]; a simulation that is not in
  realtime mode has no wall clock to synchronise against, and its time advances
  from one scheduled event to the next.
*)
open Batteries
open Clock

let debug = false

(** {2 Current running time} *)

module Events = Map.Make (struct
    type t = Time.t
    let compare (a : t) (b : t) = Float.compare (a :> float) (b :> float)
end)

type t =
    { (* What identifies a simulation, and what a widget records to say which
       * one it belongs to. *)
      id : int ;
      (* Only a label. The root widget of this simulation takes this name. *)
      name : string ;
      (* The root of this simulation's widget tree, and its inventory: every
       * widget of this simulation is somewhere below it. *)
      root : Widget.t ;
      (* The clock: the current simulated time, and everything waiting to
       * happen, soonest first.
       *
       * [now] is a ref rather than a field so that the root widget's logger can
       * share it: the logger has to be given a way to read the time when the
       * widget is built, which is before this record exists. *)
      now : Time.t ref ;
      mutable events : (unit -> unit) Events.t ;
      mutable thread : Thread.t option ;
      (* Protects everything this simulation owns. It is held for the whole of
       * an event dispatch, which is what gives a thread borrowing this
       * simulation (see [Simulation.with_lock]) a consistent view: it never
       * observes a state halfway through a handler.
       *
       * It is *re-entrant* (see [lock_owner] and [with_lock]). It has to be:
       * a handler runs holding it and goes on to call [now] and [at], which
       * want it too, and a handler that walks every simulation necessarily
       * reaches its own, which it is already dispatching. Re-entrance also
       * makes those inner calls free -- they take no mutex at all -- while
       * still letting a thread from outside acquire it in the ordinary way,
       * with no invariant for callers to remember. *)
      lock : Mutex.t ;
      cond : Condition.t ;
      (* Which thread holds [lock], if any. Must be cleared before releasing the
       * mutex to wait on [cond], and restored on waking. *)
      mutable lock_owner : int option ;
      (* Whether this simulation follows the wall clock. A simulation talking to
       * the outside world must; a closed one need not, and then runs as fast as
       * it can. *)
      mutable realtime : bool ;
      (* [continue] and [paused] both mean "not running", but differ in kind.
       * Clearing [continue] *ends* the simulation: [run] returns, its thread
       * finishes, and nothing sets it back -- that is what SIGINT and [stop]
       * do. Setting [paused] merely *suspends* it: the thread stays inside
       * [run] dispatching nothing, simulated time stands still, the wall clock
       * time spent that way accumulates in [paused_total] so that resuming does
       * not make time leap forward, and [resume] undoes it. *)
      mutable continue : bool ;
      mutable paused : bool ;
      (* When paused, when (wall clock) we were paused: *)
      mutable paused_since : float option ;
      (* How much wall clock time this simulation has spent paused, in total.
       * Subtracted from the wall clock when synchronising, so that resuming
       * a realtime simulation does not make the simulation time leap forward
       * and fire every pending event at once. *)
      mutable paused_total : Interval.t ;
      (* When > 0, run that many events then pause again: *)
      mutable steps : int ;
      (* Non-realtime only: how fast simulated time is to advance compared to
       * the wall clock -- 1. for real time, .5 for half of it, 2. for twice as
       * fast. [None] is as fast as it can, which is what a closed simulation
       * does when nobody asks for anything else.
       *
       * Pausing leaves it alone, so that unpausing goes back to the speed that
       * was in use: it is the simulation that remembers it, not whoever paused
       * it. *)
      mutable speed_ratio : float option ;
      (* Where the pace is measured from: the wall clock time (the float, as
       * [Unix.gettimeofday] gives it) and the simulated time (the [Time.t]),
       * both read at the same instant when the anchor was set. An event due at
       * simulated time [ts] is then due, by the wall clock, at
       * [wall +. (ts -. sim) /. ratio].
       *
       * Measured from an anchor rather than event by event: per event, every
       * dispatch that ran late would push the next one later still, and a
       * simulation that fell behind would stay behind instead of catching up.
       * Set afresh whenever the speed changes or the simulation resumes --
       * neither of which is the simulation being late. *)
      mutable pace_anchor : (float * Time.t) option ;
      (* How far behind that pace the simulation is: zero while it keeps up,
       * growing while it cannot go as fast as it was asked to. *)
      mutable late : Interval.t ;
      (* How often, in *simulated* time, every metric of this simulation is
       * written down. A plot of a simulation is drawn against that
       * simulation's own clock, so the samples must be spaced along it too: a
       * simulation running as fast as it can would otherwise be sampled at
       * whatever irregular intervals the wall clock happened to catch it at.
       *
       * The cost follows from that: a simulation running N times faster than
       * real time writes N/rate snapshots per wall second, each proportional
       * to the number of metric rows it has. Lower the rate for a big network
       * watched at speed. *)
      mutable metrics_sample_rate : Interval.t ;
      (* The snapshots kept, oldest overwritten first, [None] where none has
       * been written yet. How many are kept is the length of this array --
       * there is no second field to disagree with it; see
       * [set_metrics_max_samples].
       *
       * Memory is that count times the number of metric rows, so one or the
       * other has to give on a large network. *)
      mutable metric_samples : sample option array ;
      (* Where the next snapshot goes, which is also the oldest one. *)
      mutable metric_samples_next : int ;
      (* The simulated time the next snapshot is due at. *)
      mutable metric_samples_due : Time.t }

(* What every metric of a simulation was worth at one instant, keyed by the
 * widget that owns it, the property it is read through, and the parameters of
 * the events it counts -- a hub counts its bytes per port, so that triple is
 * what identifies one series among the rest.
 *
 * [taken] is the simulated time the snapshot was taken at, which is the time
 * of the event about to be dispatched: everything strictly before it has
 * happened, and nothing at it has. It is on or after the instant the snapshot
 * was due, never before, and the two differ by however long the simulation had
 * nothing to do. *)
and sample =
    { taken : Time.t ;
      values : (int * string * Metric.Params.t, Metric.value) Hashtbl.t }

(* Indexed by id, which is handed out in sequence, so this is a plain array
 * rather than a hash: resolving the simulation a widget belongs to happens
 * once per scheduled event and must cost nothing. *)
let sims : t option array ref = ref (Array.make 4 None)

let register t =
    let a = !sims in
    let a =
        if t.id < Array.length a then a else (
            let a' = Array.make (max (t.id + 1) (2 * Array.length a)) None in
            Array.blit a 0 a' 0 (Array.length a) ;
            sims := a' ;
            a') in
    a.(t.id) <- Some t

(** Every simulation, oldest first. *)
let all () =
    Array.fold_right (fun t l ->
        match t with Some t -> t :: l | None -> l
    ) !sims []

(* One second of simulated time between snapshots, and half an hour of them
 * kept. Both are meant to become properties of the root widget, so that a
 * simulation can be told to remember more, or less often, while it runs. *)
let default_metrics_sample_rate = Interval.sec 1.
let default_metrics_max_samples = 1800

(** Create a simulation. [realtime] tells whether its clock follows the wall
 * clock: a simulation talking to the outside world needs it, a closed one does
 * not and will then run as fast as it can. *)
let make =
    let seq = ref 0 in
    fun ?(realtime=true) name ->
        let id = !seq in
        let now = ref (Time.o (Unix.gettimeofday ())) in
        let root = Widget.make_root ~sim:id ~now:(fun () -> !now) name in
        incr seq ;
        let t =
            { id ;
              name ;
              root ;
              thread = None ;
              now ;
              events = Events.empty ;
              lock = Mutex.create () ;
              cond = Condition.create () ;
              lock_owner = None ;
              realtime ;
              continue = true ;
              paused = false ;
              paused_since = None ;
              paused_total = Interval.zero ;
              steps = 0 ;
              speed_ratio = None ;
              pace_anchor = None ;
              late = Interval.zero ;
              metrics_sample_rate = default_metrics_sample_rate ;
              metric_samples = Array.make default_metrics_max_samples None ;
              metric_samples_next = 0 ;
              (* Due at once, so that a simulation has a first point to be
               * plotted from rather than a rate's worth of nothing. *)
              metric_samples_due = !now } in
        register t ;
        t

let find id =
    let a = !sims in
    if id >= 0 && id < Array.length a then a.(id) else None

let id t = t.id

let name t = t.name

(** The simulation a widget belongs to.
 *
 * A widget records only the id, since a simulation holds the root of its widget
 * tree and this module is therefore compiled after Widget. Resolving it is an
 * array access, which is why no state record bothers to cache it. *)
let of_widget (w : Widget.t) =
    match find w.Widget.sim with
    | Some t -> t
    | None ->
        invalid_arg ("Simulation.of_widget: "^ Widget.full_name w ^
                     " belongs to no simulation")

(** Every widget of this simulation. *)
let widgets t = Widget.descendants t.root

(** Lookup one of its widgets by id. *)
let find_widget t id = Widget.find t.root id

(** Lookup its widgets by path. *)
let find_widgets_by_path t path = Widget.find_by_path t.root path

let me () = Thread.(id (self ()))

let with_lock t f x =
    let me = me () in
    if t.lock_owner = Some me then
        (* Already ours, and by construction consistent: we are the one who made
         * it so. Taking the mutex again would deadlock. *)
        f x
    else
        BatMutex.synchronize ~lock:t.lock (fun x ->
            t.lock_owner <- Some me ;
            finally (fun () -> t.lock_owner <- None) f x
        ) x

let signal_me t () =
    Condition.signal t.cond

(** Return the current simulation time. *)
(** The current simulated time.
 *
 * Deliberately not under the lock: reading the ref is a single word load,
 * which the runtime lock makes atomic, so a reader sees either the previous
 * value or the new one, never a torn one. (A [float ref] is an ordinary block
 * holding a pointer to a boxed float, not the flat float record a
 * float-only record would get -- either way it is one word.) And there is no
 * invariant tying [now] to anything else that a lone read could break:
 * whatever needs a consistent view of it *and* [events], as [next_event] does,
 * takes the lock itself.
 *
 * (This is the same unsynchronised read the root logger's clock closure does on
 * every log line.) *)
let now t = !(t.now)

let is_running t = t.continue

let stop t () =
    t.continue <- false ;
    Condition.signal t.cond

(** Stop every simulation. *)
let stop_all () = List.iter (fun t -> stop t ()) (all ())

(** [at t f x] will execute [f x] when simulation clock reaches time [t]. *)
let at t (ts : Time.t) f x =
    let epsilon = Interval.usec 1. in
    let rec loop ts =
        (* If ts was already bound in t.events, its previous binding disappears.
           Also, we do not like the idea of several sequential events having the same TS. *)
        if Events.mem ts t.events then (
            loop (Time.add ts epsilon)
        ) else (
            if debug then Printf.printf "Clock: add an event for time %s (%s)\n%!" (Time.to_string ts) (Interval.to_string (Time.sub ts (now t))) ;
            t.events <- Events.add ts (fun () -> f x) t.events
        ) in
    with_lock t loop ts ;
    signal_me t ()

(** [delay d f x] will delay the execution of [f x] by the interval [d]. *)
let delay t d f x =
    at t (Time.add (now t) d) f x

let asap t f x =
    (* FIXME: would be more precise and fast to have a dedicated list for asap events *)
    delay t (Interval.o 0.) f x

(* The wall clock, less however long this simulation has been paused. *)
let unpaused_wall_clock t =
    Time.o (Unix.gettimeofday () -. (t.paused_total :> float))

let synch_locked t =
    assert t.realtime (* Synch with real clock in non-realtime mode!? *) ;
    (* While paused, time must stand still: the pause duration has not been
     * accounted into paused_total yet. *)
    if not t.paused then (
        t.now := unpaused_wall_clock t ;
        if debug then Printf.printf "Clock: synch: set current time to %s\n%!" (Time.to_string (now t))
    )

(** Synchronize internal clock with realtime clock.
 * You must call this after real time passes (for instance after a blocking call).
 * Otherwise, time jumps from one registered event to the next. *)
let synch t =
    with_lock t synch_locked t

(*
 * Pausing
 *)

(** Stop dispatching events. The simulation time stands still until [resume]. *)
let pause t () =
    with_lock t (fun () ->
        if not t.paused then (
            t.paused <- true ;
            t.paused_since <- Some (Unix.gettimeofday ()) ;
            t.steps <- 0 ;
            (* Standing still is not falling behind. *)
            t.late <- Interval.zero
        )) () ;
    Condition.signal t.cond

(* Measure the pace from here: this wall clock time, this simulated time. Also
 * clears the lateness, which was measured against the anchor being replaced. *)
let reanchor t =
    t.pace_anchor <- Some (Unix.gettimeofday (), !(t.now)) ;
    t.late <- Interval.zero

(** Resume a paused simulation, accounting for the time it stood still so that
 * its clock does not leap forward. It goes back to the speed it was running at:
 * pausing does not disturb that. *)
let resume t () =
    with_lock t (fun () ->
        if t.paused then (
            Option.may (fun since ->
                t.paused_total <-
                    Interval.add t.paused_total
                                 (Interval.o (Unix.gettimeofday () -. since))
            ) t.paused_since ;
            t.paused_since <- None ;
            t.paused <- false ;
            (* Standing still is not being late. *)
            reanchor t
        )) () ;
    Condition.signal t.cond

(** How fast simulated time is to advance compared to the wall clock: [None] as
 * fast as it can, [Some r] at [r] times real time -- 1. for real time, .5 for
 * half of it. Meaningless for a simulation that follows the wall clock, and
 * refused for one. *)
let set_speed_ratio t ratio =
    if t.realtime then
        invalid_arg ("Simulation.set_speed_ratio: "^ t.name ^
                     " follows the wall clock") ;
    Option.may (fun r ->
        (* [is_finite] is false for the infinities and for nan alike; the
         * comparison then leaves only the positives. *)
        if not (Float.is_finite r) || r <= 0. then
            invalid_arg (Printf.sprintf
                "Simulation.set_speed_ratio: %g is not a speed (use None to \
                 run as fast as possible)" r)
    ) ratio ;
    with_lock t (fun () ->
        t.speed_ratio <- ratio ;
        (* The speed that was not being kept up with is not this one's fault. *)
        reanchor t) () ;
    Condition.signal t.cond

(* When, by the wall clock, the event at [ts] is due at that speed. *)
let due_at t ratio ts =
    match t.pace_anchor with
    | None ->
        reanchor t ;
        Unix.gettimeofday ()
    | Some (wall0, sim0) ->
        wall0 +. (Time.sub ts sim0 :> float) /. ratio

(** Run [n] events then pause again. *)
let step ?(n=1) t () =
    with_lock t (fun () ->
        t.paused <- true ;
        if t.paused_since = None then
            t.paused_since <- Some (Unix.gettimeofday ()) ;
        t.steps <- t.steps + n) () ;
    Condition.signal t.cond

(* Whether an event may be dispatched now. Must be called with the lock held. *)
let may_dispatch t =
    not t.paused || t.steps > 0

(* Account for one dispatched event. Must be called with the lock held. *)
let dispatched t =
    if t.paused && t.steps > 0 then (
        t.steps <- t.steps - 1 ;
        (* Stepping does not make time pass for the pause accounting: we are
         * still paused, so paused_since keeps running. *)
        ()
    )

(* Wait on [cond], which hands the mutex back for the duration. Must be called
 * with the lock held. The mutex is not ours while we wait, so [lock_owner] is
 * cleared and restored around it -- otherwise a thread that acquired it
 * meanwhile would find it claimed by us. *)
let wait_on_cond ?until t =
    let me = me () in
    t.lock_owner <- None ;
    (match until with
    | None ->
        Condition.wait t.cond t.lock
    | Some (until : Time.t) ->
        (try Condvar.timed_wait t.cond t.lock (until :> float)
        with Condvar.Timeout -> ())) ;
    t.lock_owner <- Some me

(*
 * Metric history
 *
 * Every metric of the simulation, written down at regular intervals of
 * simulated time, so that the interface can plot what happened rather than
 * only what is. The snapshots are taken by the dispatcher, on the simulation's
 * own clock: only it knows when simulated time has moved, and only it can
 * catch the figures between two events rather than halfway through one.
 *)

(** How many snapshots are kept at most. *)
let metrics_max_samples t = Array.length t.metric_samples

(** How often, in simulated time, they are taken. *)
let metrics_sample_rate t = t.metrics_sample_rate

(** The snapshots kept, oldest first. *)
let metric_samples t =
    with_lock t (fun () ->
        let n = Array.length t.metric_samples in
        let rec loop acc i =
            if i >= n then List.rev acc else
            let s = t.metric_samples.((t.metric_samples_next + i) mod n) in
            loop (match s with None -> acc | Some s -> s :: acc) (i + 1) in
        loop [] 0) ()

(* Write down what every metric of this simulation is worth. Must be called
 * with the lock held: it reads the tables that event handlers write to.
 *
 * Every metric is reached through the widget tree, which is the whole
 * inventory of a simulation; a metric that belongs to no widget is not part of
 * the simulation as far as anything here is concerned. *)
let take_metric_sample t =
    let n = Array.length t.metric_samples in
    if n > 0 then (
        let values = Hashtbl.create 64 in
        Widget.enum t.root |>
        Enum.iter (fun (w : Widget.t) ->
            List.iter (fun (p : Widget.property) ->
                Option.may (fun m ->
                    List.iter (fun (params, v) ->
                        Hashtbl.replace values
                            (w.Widget.id, p.Widget.name, params) v
                    ) (Metric.samples m)
                ) p.Widget.metric
            ) w.Widget.properties) ;
        t.metric_samples.(t.metric_samples_next) <-
            Some { taken = now t ; values } ;
        t.metric_samples_next <- (t.metric_samples_next + 1) mod n
    )

(* Take one if the clock has reached the time it was due at, and say when the
 * next one is. Due times are multiples of the rate, so that the snapshots of a
 * simulation that has something to do land on a regular grid whatever the
 * delays between its events. Periods that went by without a snapshot are
 * skipped rather than filled with copies of the same figures: a simulation
 * with nothing to do produced nothing to record.
 *
 * Must be called with the lock held, and with [now] already advanced to the
 * event about to be dispatched. *)
let sample_metrics_if_due t =
    if Time.is_after (now t) t.metric_samples_due then (
        take_metric_sample t ;
        t.metric_samples_due <-
            Time.add (Time.trunc (now t) t.metrics_sample_rate)
                     t.metrics_sample_rate
    )

(** How often to take a snapshot, in simulated time. Changing it makes one due
 * at once, so that the new cadence starts from a point rather than from a gap.
 *)
let set_metrics_sample_rate t (rate : Interval.t) =
    (* [Interval.o] has already refused a nan; an infinity it lets through, and
     * a sample due at the end of time is never due at all. *)
    if not (Float.is_finite (rate :> float)) || (rate :> float) <= 0. then
        invalid_arg "Simulation.set_metrics_sample_rate: not a delay: it must \
                     be finite and above zero" ;
    with_lock t (fun () ->
        t.metrics_sample_rate <- rate ;
        t.metric_samples_due <- Time.trunc (now t) rate) ()

(** How many snapshots to keep. The most recent ones are kept when there is
 * suddenly room for fewer, since those are the ones anybody is looking at. *)
let set_metrics_max_samples t n =
    if n < 0 then
        invalid_arg "Simulation.set_metrics_max_samples: cannot keep fewer \
                     than no samples at all" ;
    with_lock t (fun () ->
        let kept = metric_samples t in
        let kept = List.drop (max 0 (List.length kept - n)) kept in
        let a = Array.make n None in
        List.iteri (fun i s -> a.(i) <- Some s) kept ;
        t.metric_samples <- a ;
        t.metric_samples_next <- if n = 0 then 0 else List.length kept mod n) ()

(** Will process the next event *)
let next_event t =
    let min_ts_for_sleep = Interval.msec 10. in
    (* Time to sleep while waiting for an event to be added in the queue.
     * Must be > min_ts_for_sleep *)
    let max_sleep_time = Interval.sec 3. in
    let run_first_event =
        if t.realtime then (
            (* Note: In realtime, other threads may add new events while we are
             * sleeping, so a condition variable is used (instead of a mere
             * Unix.sleep). *)
            with_lock t (fun () ->
            (* Wait until there is an event to process now: *)
            let rec wait_loop () =
                let until =
                    if not (may_dispatch t) then
                        (* Paused: nothing to run, wake up only when signalled *)
                        Time.add (now t) max_sleep_time
                    else
                        match Events.min_binding t.events with
                        | exception Not_found -> Time.add (now t) max_sleep_time
                        | ts, _ -> ts in
                let wait_time = Time.sub until (now t) in
                if not (may_dispatch t) ||
                   Interval.compare wait_time min_ts_for_sleep > 0 then (
                    if debug then Printf.printf "Clock: next_event: waiting until %s since we're too early\n%!" (Time.to_string until) ;
                    wait_on_cond ~until t ;
                    (* If we timed out we need to wait longer.
                     * If we have been signaled we still need to wait for the
                     * next event, which may be a different one. *)
                    (* Because of the loop condition above: *)
                    synch_locked t ;
                    if t.continue then wait_loop ()
                ) in
                (* Else there is no need to wait we can go straight to processing
                   that event: *)
            wait_loop () ;
            t.continue && may_dispatch t) ()
        ) else ( (* not realtime *)
            with_lock t (fun () ->
                if not (may_dispatch t) then (
                    (* Paused: block until someone resumes or steps us, rather
                     * than spinning. *)
                    wait_on_cond t ;
                    false
                ) else if Events.is_empty t.events then (
                    if debug then Printf.printf "Clock: no more events\n%!" ;
                    (* Nothing more will come from a clock of our own, but
                     * another thread may still feed us, so wait to be signalled
                     * instead of spinning: *)
                    wait_on_cond t ;
                    false
                ) else match t.speed_ratio with
                | None ->
                    (* As fast as it can. *)
                    true
                | Some _ when t.steps > 0 ->
                    (* A step is asked for now: pacing it would defeat it. *)
                    true
                | Some ratio ->
                    let ts, _ = Events.min_binding t.events in
                    let due = due_at t ratio ts
                    and wall = Unix.gettimeofday () in
                    if wall >= due then (
                        (* Due already: run it, and say how far behind we are. *)
                        t.late <- Interval.o (wall -. due) ;
                        true
                    ) else (
                        t.late <- Interval.zero ;
                        (* Sleeping on the condition rather than on the clock:
                         * whoever changes the speed, resumes or adds an event
                         * meanwhile wakes us to reconsider. *)
                        wait_on_cond ~until:(Time.o due) t ;
                        false
                    )) ()
        ) in
    if run_first_event then (
        (* We have some work to do *)
        let f =
            with_lock t (fun () ->
                match Events.min_binding t.events with
                | exception Not_found -> None
                | ts, f ->
                    if debug then Printf.printf "Clock: next_event: executing since it's %s\n%!" (Time.to_string ts) ;
                    t.events <- Events.remove ts t.events ;
                    t.now := ts ;
                    (* Before the handler runs, so that a snapshot holds
                     * everything that happened strictly before [ts] and
                     * nothing that happens at it. *)
                    sample_metrics_if_due t ;
                    dispatched t ;
                    Some f) () in
        Option.may (fun f ->
            (* Held for the whole dispatch. The handler will call back into
             * [now] and [at], which want the lock too and get it for free,
             * since it is re-entrant and already ours. *)
            with_lock t (fun () ->
                try f ()
                with exn ->
                    Printf.printf "Clock: event handler triggered an exception : %a\n%s%!"
                        Printexc.print exn
                        (Printexc.get_backtrace ())) ()
        ) f
    )

(** [run true] will run forever while [run false] will return once no more
 * events are waiting.  If you choose to not run forever, beware that waiting
 * for an answer from the outside world is _not_ a clock event. You should
 * probably run forever whenever you communicate with the outside. *)
let run t wait =
    if debug then Printf.printf "clock: running the clock!\n%!" ;
    while t.continue && (wait || not (Events.is_empty t.events)) do
        next_event t ;
        Thread.yield ()
    done

(** Run [f] with those signals stopping every simulation, then put the previous
 * handlers back.
 *
 * Signals are delivered to the process, not to a simulation: there is no such
 * thing as interrupting one of them and leaving the others running, so the
 * handler stops the lot -- including any simulation started while [f] runs. *)
let with_trapped signals f =
    let prev_sigs =
        List.map (fun s ->
            let open Sys in
            signal s (Signal_handle (fun _n ->
                Printf.printf "Quitting...\n%!" ;
                stop_all ()))
        ) signals in
    finally (fun () -> List.iter2 Sys.set_signal signals prev_sigs) f ()

(** Start this simulation in its own thread. [wait] has the meaning it has for
 * [run]: keep going even with an empty event queue. *)
let start ?(wait=true) t =
    match t.thread with
    | Some _ ->
        invalid_arg ("Simulation.start: "^ t.name ^" is already running")
    | None ->
        let thread = Thread.create (fun () -> run t wait) () in
        t.thread <- Some thread ;
        thread

(** Run this simulation in the calling thread, which then becomes its thread.
 * For the common case of a program running a single simulation. *)
let run_here ?(wait=true) t =
    t.thread <- Some (Thread.self ()) ;
    run t wait

(** Borrow a simulation from a thread that does not run it: take its lock for
 * the duration of [f]. This is how the administration interface reads and
 * writes the simulations it displays.
 *
 * [f] must not wait for that simulation to advance: it holds the very lock the
 * simulation needs in order to dispatch. Read state, change a parameter,
 * schedule an event for later, and return. *)
let borrow t f = with_lock t f ()

(** Helpers for reaching the simulation of a widget: *)
module Widget =
struct
    let now = now % of_widget

    (* TODO: etc... *)
end
