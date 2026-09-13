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

  Reading the time takes a simulation. Scheduling an event takes a {!power}
  instead: a clock to schedule on, plus something to draw the energy from. A
  host that is switched off is a power source that has been cut, and the events
  it had paid for cease to exist -- which is all there is to powering a
  simulated machine down.

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
  outside (when the objective is to produce a pcap file, say) then not realtime
  mode plays the simulation at full speed and full CPU, and can produce a pcap
  representing the workload of a day in minutes, or conversely a very busy hour
  in several hours, with all packets present and their timestamps accurate.

  Only a simulation in realtime mode calls [synch]; a simulation that is not in
  realtime mode has no wall clock to synchronise against, and its time advances
  from one scheduled event to the next.
*)
open Batteries
open Clock
open SimTypes

let debug = false

type t = simulation

(* What is needed in order to act in a simulation: a clock to schedule on, and
 * something to draw the energy from.
 *
 * Every scheduled event names the source that pays for it, and switching a
 * source off (see [power_down]) both stops it paying for new ones and
 * withdraws the ones it has already paid for, so that a host powered off has
 * no future left rather than a future that is merely ignored. That is what a
 * simulated power-off is: not a machine that goes down gracefully, but one
 * whose pending work ceases to exist.
 *
 * The source itself is [SimTypes.power], declared there with the simulation
 * and the widget because the three name one another: a source says which
 * simulation pays, a simulation says which widget is the root of its tree, and
 * a widget says which source it draws on. Everything that acts on a source is
 * here all the same, this being where the events are.
 *
 * Sources are unrelated to one another: switching one off leaves every other
 * one alone. A box within a box -- a gateway's router, were it to mint a
 * source of its own -- would need [power_down] to know about that nesting,
 * and nothing needs it to yet: matching a source against a chain of parents
 * would put a walk on [at], which every packet goes through. *)

(* Every simulation of this process, indexed by id, which is handed out in
 * sequence -- a plain array rather than a hash, since ids are dense and few.
 *
 * This is a register, not a way of reaching one: a widget names its power
 * source and a source names its simulation, so nothing has to look one up in
 * order to act. What it is for is answering "which simulations are there",
 * which the interface asks and nothing else can. *)
let sims : t option array ref = ref (Array.make 4 None)

let register (t : t) =
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
 * kept. Both are properties of the root widget, so that a simulation can be
 * told to remember more, or less often, while it runs. *)
let default_metrics_sample_rate = Interval.sec 1.
let default_metrics_max_samples = 1800

let find id =
    let a = !sims in
    if id >= 0 && id < Array.length a then a.(id) else None

let id (t : t) = t.id

(** The name a new simulation will answer to: the one asked for, or that name
 * with a number appended when another simulation has it already.
 *
 * The same numbering widgets get among their siblings, and for the same
 * reason: two simulations called the same thing are two the reader has no way
 * of telling apart, in a column that shows nothing else of them when they are
 * folded away. Applied where a name comes from the reader rather than in
 * [make], so that a program naming its own simulations gets the names it
 * asked for or none at all. *)
let unique_name name =
    let taken n = List.exists (fun (t : t) -> t.name = n) (all ()) in
    if not (taken name) then name else
    let rec loop i =
        let n = Printf.sprintf "%s-%d" name i in
        if taken n then loop (i + 1) else n in
    loop 2

let name (t : t) = t.name

(** The simulation a widget belongs to: the one its power source schedules on,
 * which is [Widget.sim] and is named here as well, this being where a caller
 * with a widget in hand looks for it. *)
let of_widget = Widget.sim

(** Every widget of this simulation. *)
let widgets (t : t) = Widget.descendants t.root

(** Lookup one of its widgets by id. *)
let find_widget (t : t) id = Widget.find t.root id

(** Lookup its widgets by path. *)
let find_widgets_by_path (t : t) path = Widget.find_by_path t.root path

let me () = Thread.(id (self ()))

let with_lock (t : t) f x =
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

let signal_me (t : t) () =
    Condition.signal t.cond

(** The power source of {!Widget}, named here as well: this is where it is
 * switched, and where the events it pays for are kept. *)
type power = SimTypes.power

(** What every metric of this simulation was worth at one instant. *)
type sample = SimTypes.sample

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
let now (t : t) = !(t.now)

let is_running (t : t) = t.continue

let stop (t : t) () =
    with_lock t (fun () ->
        t.continue <- false ;
        (* The mains, which is the root widget's: a simulation that has been
           stopped pays for nothing more. *)
        t.root.power.on <- false ;
        t.events <- Events.empty) () ;
    Condition.signal t.cond

(** Stop every simulation. *)
let stop_all () = List.iter (fun t -> stop t ()) (all ())

(** Call this simulation, and the root widget standing for it, something else.
 *
 * The name is a label and nothing hangs off it, so there is nothing else to
 * put right: a widget's place in the tree is its path, and the root's name is
 * only the head of it. *)
let rename (t : t) name =
    if String.contains name '/' then
        invalid_arg ("Simulation.rename: a name must not contain '/': "^ name) ;
    with_lock t (fun () ->
        t.name <- name ;
        t.root.name <- name) ()

(** Take a simulation out of this process for good: stop its clock, take apart
 * everything it was running, and forget it.
 *
 * The taking apart is not housekeeping that could be left to the collector: a
 * recorder holds a file open and a portal a real interface, and dropping the
 * tree on the floor would leave both held. It is [Widget.destroy] that tells
 * them, exactly as deleting one device does.
 *
 * The thread is not waited for. It is asleep on the condition [stop] has just
 * signalled, and what it wakes to do is notice that it is to stop -- which
 * touches nothing this has taken away. Waiting for it would be the interface
 * blocking on a simulation, which is the one thing it must never do. *)
let delete (t : t) =
    stop t () ;
    with_lock t (fun () -> Widget.destroy t.root) () ;
    let a = !sims in
    if t.id < Array.length a then a.(t.id) <- None

(* Empty the root widget. One widget at a time because of cascading deletions. *)
let rec clear (t : t) =
    match t.root.children with
    | [] -> ()
    | w :: _ -> Widget.destroy w ; clear t

(** Something about this simulation's network has been changed from outside. *)
let changed (t : t) = t.unsaved <- true

(** Its network has just been written out, or read in: what it holds is safe
 * somewhere else. *)
let saved (t : t) = t.unsaved <- false

(** Whether anything has been done to it since. *)
let unsaved (t : t) = t.unsaved

(** [at p ts f x] will execute [f x] when the clock of [p]'s simulation reaches
 * time [ts] -- or never, if [p] is switched off by then.
 *
 * Nothing is scheduled at all while [p] is off, and [power_down] withdraws
 * what it had already scheduled, which is why the dispatcher never has to look
 * at a power source: everything left in the queue is powered. *)
let at (p : power) (ts : Time.t) f x =
    let t = p.sim in
    if not p.on then (
        if debug then Printf.printf "Clock: dropping an event for time %s: %s is off\n%!" (Time.to_string ts) p.name ;
        Log.(log t.root.logger Debug (lazy (Printf.sprintf
            "Not scheduling anything at %s: %s is off"
            (Time.to_string ts) p.name)))
    ) else (
        let epsilon = Interval.o 1 in
        let rec loop ts =
            (* If ts was already bound in t.events, its previous binding disappears.
               Also, we do not like the idea of several sequential events having the same TS. *)
            if Events.mem ts t.events then (
                loop (Time.add ts epsilon)
            ) else (
                if debug then Printf.printf "Clock: add an event for time %s (%s)\n%!" (Time.to_string ts) (Interval.to_string (Time.diff ts (now t))) ;
                t.events <- Events.add ts (p, (fun () -> f x)) t.events
            ) in
        with_lock t loop ts ;
        signal_me t ()
    )

(** [delay d f x] will delay the execution of [f x] by the interval [d]. *)
let delay (p : power) d f x =
    at p (Time.add (now p.sim) d) f x

let asap (p : power) f x =
    (* FIXME: would be more precise and fast to have a dedicated list for asap events *)
    delay p Interval.zero f x

(* The widgets drawing on [p], in tree order: found by walking rather than by
 * registration, so that a widget destroyed or moved needs no unregistering and
 * cannot be called after it is gone. Walked on switching only, which is a
 * human-scale event -- [power_down] already walks the whole event queue. *)
let users (p : power) =
    Widget.enum p.sim.root //
    (fun (w : widget) -> w.power == p)

(* Tell one widget that its source has been switched, and put what it has to
 * say about it where it can be read: a switch cannot be refused, so a widget
 * that cannot do what switching means for it says so and the rest of the
 * network carries on. *)
let tell (w : widget) what f =
    match f () with
    | () -> w.error <- None
    | exception e ->
        let m = Printexc.to_string e in
        w.error <- Some m ;
        Log.(log w.logger Error (lazy (Printf.sprintf
            "Cannot power %s: %s" what m)))

let power_up (p : power) =
    if not p.on then (
        p.on <- true ;
        (* In tree order, a box before what is inside it. *)
        users p |>
        Enum.iter (fun (w : widget) -> tell w "up" w.power_up)
    )

(** Switch a power source off, and forget every event it had paid for.
 *
 * Forgetting them is the point: an event that merely went unnoticed would
 * still be there to fire on the next power-up, and a host that comes back
 * would resume the conversations it was having when it went down. *)
let power_down (p : power) =
    if p.on then (
        let t = p.sim in
        with_lock t (fun () ->
            (* The flag first, so that nothing woken below can schedule
               anything; then the events, so that nothing already scheduled
               survives; then the widgets, which therefore have nothing to add
               to the queue and are told in the reverse of the order they came
               up in, what is inside a box before the box. *)
            p.on <- false ;
            let before = Events.cardinal t.events in
            t.events <- Events.filter (fun _ (p', _) -> p' != p) t.events ;
            let dropped = before - Events.cardinal t.events in
            if dropped > 0 then
                Log.(log t.root.logger Debug (lazy (Printf.sprintf
                    "Dropped %d event(s) powered by %s" dropped p.name))) ;
            users p |> List.of_enum |> List.rev |>
            List.iter (fun (w : widget) -> tell w "down" w.power_down)) () ;
        signal_me t ()
    )

(** Place an instant read off the real world -- the timestamp libpcap put on a
 * captured packet -- on [t]'s own timeline.
 *
 * The two are the same instant for a simulation that has always followed the
 * wall clock and never been paused. Every other one is somewhere else, and an
 * instant taken from the world outside has to be brought across before it can
 * be scheduled: used as it stands it would land in the simulation's past, and
 * be dispatched at once, or in its future, and wait there. *)
let of_wall_clock (t : t) (ts : Wall.t) =
    Time.sub (Time.of_interval (Wall.diff ts t.epoch)) t.paused_total

(** The other way: what the wall clock will read when [t] calls it [ts].
 *
 * For whoever has to wait, by a clock of the real world, for an instant named
 * on the simulation's -- which the run loop does every time it sleeps until
 * its next event. *)
let to_wall_clock (t : t) (ts : Time.t) =
    Wall.add t.epoch (Interval.add (Time.to_interval ts) t.paused_total)

(* The wall clock, on this simulation's timeline: shifted by whatever it is
 * from the world outside, and less however long it has stood paused. *)
let unpaused_wall_clock (t : t) =
    of_wall_clock t (Wall.now ())

let synch_locked (t : t) =
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
let synch (t : t) =
    with_lock t synch_locked t

(*
 * Pausing
 *)

(** Stop dispatching events. The simulation time stands still until [resume]. *)
let pause (t : t) () =
    with_lock t (fun () ->
        if not t.paused then (
            t.paused <- true ;
            t.paused_since <- Some (Wall.now ()) ;
            t.steps <- 0 ;
            (* Standing still is not falling behind. *)
            t.late <- Interval.zero
        )) () ;
    Condition.signal t.cond

(* Measure the pace from here: this wall clock time, this simulated time. Also
 * clears the lateness, which was measured against the anchor being replaced. *)
let reanchor (t : t) =
    t.pace_anchor <- Some (Wall.now (), !(t.now)) ;
    t.late <- Interval.zero

(** Resume a paused simulation, accounting for the time it stood still so that
 * its clock does not leap forward. It goes back to the speed it was running at:
 * pausing does not disturb that. *)
let resume (t : t) () =
    with_lock t (fun () ->
        if t.paused then (
            Option.may (fun since ->
                t.paused_total <-
                    Interval.add t.paused_total (Wall.diff (Wall.now ()) since)
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
let set_speed_ratio (t : t) ratio =
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

(** Tie [t] to the wall clock from here on. Nothing to do if it already is.
 *
 * A simulation that talks to the outside world has to run at the speed of the
 * outside world, so this is what opening a real interface on one asks of it.
 *
 * Its clock must not jump as it happens. A simulation that has been running as
 * fast as it could is hours from the world outside, and everything already
 * scheduled on it is dated in its own time; moving the present would fire all
 * of that at once, or strand it. So its beginning is moved instead ([epoch]),
 * to where the world outside says it must have been for the present to fall
 * exactly where it already is; from here on the simulation's time is read off
 * the wall clock, advancing at its rate, as asked.
 *
 * Anything the outside world dates then has to cross the same gap; that is
 * what [of_wall_clock] is for.
 *
 * Whatever speed it had been asked to run at goes with it: a simulation
 * following the wall clock runs at the speed of the wall clock, which is why
 * [set_speed_ratio] refuses one. *)
let make_realtime (t : t) =
    with_lock t (fun () ->
        if not t.realtime then (
            (* Read from the simulated time as it stands, before anything is
               flipped: this is the number that will hold it there once [now]
               starts being read off the wall clock. Undoing [paused_total],
               which [of_wall_clock] takes off again. *)
            t.epoch <-
                Wall.sub (Wall.now ())
                    (Interval.add (Time.to_interval !(t.now)) t.paused_total) ;
            t.realtime <- true ;
            t.speed_ratio <- None ;
            (* Both belong to pacing a simulation that sets its own pace, which
               this one no longer does. *)
            t.pace_anchor <- None ;
            t.late <- Interval.zero ;
            Log.(log t.root.logger Debug (lazy (Printf.sprintf
                "Following the wall clock, having begun at %s"
                (Wall.to_string t.epoch))))
        )) () ;
    (* The run loop may be asleep in the branch for a simulation that paces
       itself; it has to wake up and take the other one. *)
    signal_me t ()

(* A simulation that has run ahead of the world keeps the time it has reached,
   and goes on from there at the pace of the wall clock. *)
(*$T make_realtime
  let t = make ~realtime:false "ahead" in \
  t.now := Clock.Time.of_secs 3600. ; \
  let before = now t in \
  make_realtime t ; \
  t.realtime && t.speed_ratio = None && \
  Clock.Interval.(compare (abs (Clock.Time.diff (now t) before)) (sec 1.)) < 0
 *)

(* And a reading of the wall clock now lands where that simulation is, which is
   what a sniffed packet needs. *)
(*$T make_realtime
  let t = make ~realtime:false "across" in \
  t.now := Clock.Time.of_secs 3600. ; \
  make_realtime t ; \
  Clock.Interval.(compare \
    (abs (Clock.Time.diff (of_wall_clock t (Clock.Wall.now ())) (now t))) \
    (sec 1.)) < 0
 *)

(* One that already follows the wall clock is left exactly as it was. *)
(*$T make_realtime
  let t = make "already" in \
  let epoch = t.epoch in \
  make_realtime t ; \
  t.epoch = epoch && t.realtime
 *)

(* When, by the wall clock, the event at [ts] is due at that speed. *)
let due_at (t : t) ratio ts =
    match t.pace_anchor with
    | None ->
        reanchor t ;
        Wall.now ()
    | Some (wall0, sim0) ->
        Wall.add wall0 (Interval.div (Time.diff ts sim0) ratio)

(** Run [n] events then pause again. *)
let step ?(n=1) t () =
    with_lock t (fun () ->
        t.paused <- true ;
        if t.paused_since = None then
            t.paused_since <- Some (Wall.now ()) ;
        t.steps <- t.steps + n) () ;
    Condition.signal t.cond

(* Whether an event may be dispatched now. Must be called with the lock held. *)
let may_dispatch (t : t) =
    not t.paused || t.steps > 0

(* Account for one dispatched event. Must be called with the lock held. *)
let dispatched (t : t) =
    if t.paused && t.steps > 0 then (
        t.steps <- t.steps - 1 ;
        (* Stepping does not make time pass for the pause accounting: we are
         * still paused, so paused_since keeps running. *)
        ()
    )

(* Wait on [cond], which hands the mutex back for the duration. Must be called
 * with the lock held. The mutex is not ours while we wait, so [lock_owner] is
 * cleared and restored around it -- otherwise a thread that acquired it
 * meanwhile would find it claimed by us.
 *
 * [until] is by the wall clock, since that is the clock the sleeper is woken
 * by; a caller holding an instant of the simulation's own has to put it
 * through [to_wall_clock] first. *)
let wait_on_cond ?until t =
    (* A simulation that has been stopped has nothing left to wait for, and the
     * signal that stopped it may already have gone by: [stop] writes the flag
     * and signals the condition under the lock, so a thread that has the lock
     * but has not yet reached its wait misses that signal and then sleeps to
     * its deadline -- as far off as the next event, with whoever asked it to
     * quit waiting on it all that time. Reading the flag here rather than at
     * each of the waits below, which is where it would be forgotten. *)
    if t.continue then (
        let me = me () in
        t.lock_owner <- None ;
        (match until with
        | None ->
            Condition.wait t.cond t.lock
        | Some (until : Wall.t) ->
            (try Condvar.timed_wait t.cond t.lock (Wall.to_secs until)
            with Condvar.Timeout -> ())) ;
        t.lock_owner <- Some me
    )

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
let metrics_max_samples (t : t) = Array.length t.metric_samples

(** How often, in simulated time, they are taken. *)
let metrics_sample_rate (t : t) = t.metrics_sample_rate

(** The snapshots kept, oldest first. *)
let metric_samples (t : t) =
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
let take_metric_sample (t : t) =
    let n = Array.length t.metric_samples in
    if n > 0 then (
        let values = Hashtbl.create 64 in
        Widget.enum t.root |>
        Enum.iter (fun (w : widget) ->
            List.iter (fun (p : property) ->
                Option.may (fun m ->
                    List.iter (fun (params, v) ->
                        Hashtbl.replace values
                            (w.id, p.name, params) v
                    ) (Metric.sample m)
                ) p.metric
            ) w.properties) ;
        t.metric_samples.(t.metric_samples_next) <-
            Some { taken = now t ; values } ;
        t.metric_samples_next <- (t.metric_samples_next + 1) mod n
    )

(** The history kept for one metric property: its points, one list per
 * parameter row, oldest first. [since] leaves out everything at or before that
 * simulated time, which is how the interface asks for what it has not got yet:
 * it passes the time of its last point back.
 *
 * A row with nothing new to say does not appear at all -- an empty answer is
 * "nothing has been written down since", which is what a caller polling for
 * fresh points wants to hear. *)
let metric_history ?since t widget_id property_name =
    (* Deliberately not under the lock, beyond the moment [metric_samples]
     * holds it to copy the ring: a snapshot is built whole and only then put
     * into the ring, and never touched again -- the dispatcher replaces the
     * slot it sits in, it does not write into the snapshot. So a reference to
     * one is enough to read it at leisure, and this walk, which is by far the
     * longest thing anybody does with the history, does not stop the
     * simulation for as long as it takes.
     *
     * A snapshot that gets evicted while being read is still a true point of
     * the history, so nothing has to be done about it. *)
    let samples = metric_samples t in
    let wanted (id, name, _params) = id = widget_id && name = property_name
    and after (s : sample) =
        match since with
        | None -> true
        | Some (since : Time.t) -> Time.compare s.taken since > 0 in
    (* Points are gathered per row, then handed back in the order they were
     * taken. *)
    let rows = Hashtbl.create 8 in
    List.iter (fun (s : sample) ->
        if after s then
            Hashtbl.iter (fun ((_, _, params) as key) v ->
                if wanted key then
                    Hashtbl.modify_def [] params
                        (fun points -> (s.taken, v) :: points) rows
            ) s.values
    ) samples ;
    Hashtbl.fold (fun params points l ->
        (params, List.rev points) :: l
    ) rows [] |>
    (* By parameters, so that a caller polling every second is handed the rows
     * in the same order every time: a hash table has none. *)
    List.sort (fun (a, _) (b, _) -> Metric.Params.compare Stdlib.compare a b)

(* Take one if the clock has reached the time it was due at, and say when the
 * next one is. Due times are multiples of the rate, so that the snapshots of a
 * simulation that has something to do land on a regular grid whatever the
 * delays between its events. Periods that went by without a snapshot are
 * skipped rather than filled with copies of the same figures: a simulation
 * with nothing to do produced nothing to record.
 *
 * Must be called with the lock held, and with [now] already advanced to the
 * event about to be dispatched. *)
let sample_metrics_if_due (t : t) =
    if Time.is_after (now t) t.metric_samples_due then (
        take_metric_sample t ;
        t.metric_samples_due <-
            Time.add (Time.trunc (now t) t.metrics_sample_rate)
                     t.metrics_sample_rate
    )

(** How often to take a snapshot, in simulated time. Changing it makes one due
 * at once, so that the new cadence starts from a point rather than from a gap.
 *)
let set_metrics_sample_rate (t : t) (rate : Interval.t) =
    (* Whatever was not a length of time at all was refused when the interval
     * was built (see [Interval.of_secs]); what is left to refuse here is a
     * rate that would sample everything at once, or never. *)
    if (rate :> int) <= 0 then
        invalid_arg "Simulation.set_metrics_sample_rate: not a delay: it must \
                     be above zero" ;
    with_lock t (fun () ->
        t.metrics_sample_rate <- rate ;
        t.metric_samples_due <- Time.trunc (now t) rate) ()

(** How many snapshots to keep. The most recent ones are kept when there is
 * suddenly room for fewer, since those are the ones anybody is looking at. *)
let set_metrics_max_samples (t : t) n =
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

(** Create a simulation. [realtime] tells whether its clock follows the wall
 * clock: a simulation talking to the outside world needs it, a closed one does
 * not and will then run as fast as it can. *)
let make =
    let seq = ref 0 in
    fun ?(realtime=true) name ->
        let id = !seq in
        (* Every instant is counted from here, so the clock starts at zero
           and [epoch] says what the world outside called that moment. *)
        let now = ref Time.zero in
        (* What numbers the messages of every logger in this simulation, so
           that a reader can keep its place in one: see [Log.messages]. Shared
           with the closure the loggers hold, as [now] is, since the root is
           built before the record that holds them both.

           Incremented without taking the lock, which is how [now] is read:
           logging happens under it in the ordinary case -- within a dispatch,
           or within a borrow -- and where it does not, OCaml's own lock is
           what makes the read and the write of one word indivisible. *)
        let log_seq = ref 0 in
        let logger =
            Log.make ~now:(fun () -> !now)
                     ~seq:(fun () -> incr log_seq ; !log_seq) () in
        incr seq ;
        (* The one knot in the program, and the reason the three types are
           declared together: a source says which simulation pays for what it
           buys, a simulation says which widget is the root of its tree, and
           that root draws on the mains, which is a source. None of the three
           can be built before the other two.

           Which is why the root widget is a record here rather than something
           [Widget.make] returns: OCaml ties a knot of records in one [let
           rec], and only of records -- a function call in there is refused.
           Everything a widget needs beyond its fields is done to it just
           below, by the same [Widget.add_common_properties] every other widget
           goes through. *)
        let rec t =
            { id ;
              name ;
              root ;
              thread = None ;
              now ;
              log_seq ;
              events = Events.empty ;
              lock = Mutex.create () ;
              cond = Condition.create () ;
              lock_owner = None ;
              realtime ;
              (* A simulation is made either following the wall clock, and then
                 it is on the wall clock's own timeline, or not following it at
                 all -- and then nothing has yet asked the two to agree. Either
                 way there is no gap between them until [make_realtime] opens
                 one. *)
              epoch = Wall.now () ;
              continue = true ;
              paused = false ;
              paused_since = None ;
              paused_total = Interval.zero ;
              steps = 0 ;
              unsaved = false ;
              speed_ratio = None ;
              pace_anchor = None ;
              late = Interval.zero ;
              metrics_sample_rate = default_metrics_sample_rate ;
              metric_samples = Array.make default_metrics_max_samples None ;
              metric_samples_next = 0 ;
              (* Due at once, so that a simulation has a first point to be
               * plotted from rather than a rate's worth of nothing. *)
              metric_samples_due = !now }
        and root =
            { id = Widget.next_id () ;
              name ;
              parent = None ;
              children = [] ;
              peers = [] ;
              location = None ;
              logger ;
              ports = Widget.no_ports ;
              device_type = None ;
              device = None ;
              made_with = None ;
              on_delete = ignore ;
              power = mains ;
              owns_power = true ;
              power_up = ignore ;
              power_down = ignore ;
              error = None ;
              properties = [] }
        (* What powers everything in this simulation that nothing more
           particular powers, and the one source that is never switched off:
           switching it off is stopping the simulation (see [stop]). *)
        and mains = { on = true ; name = "the mains of "^ name ; sim = t } in
        Widget.add_common_properties root ;
        Widget.add_properties root Widget.[
            property "metrics sample rate" ~kind:Float ~units:"secs"
              ~descr:"How often every metric of this simulation is written \
                      down, in its own simulated time."
              ~getter:(fun () -> `Float (Interval.to_secs (metrics_sample_rate t)))
              ~setter:(fun v ->
                  let r = to_float v in
                  (* Said here rather than left to [set_metrics_sample_rate],
                   * whose [Invalid_argument] means a mistake in the program
                   * while this one means a mistake by whoever typed it. *)
                  if not (Float.is_finite r) || r <= 0. then
                      bad_value
                          "a sample rate is a delay above zero, not %g" r ;
                  set_metrics_sample_rate t (Interval.sec r)) ;
            property "metrics samples kept" ~kind:(IRange (0, 1_000_000))
              ~descr:"How many of those snapshots to keep; none at all means \
                      no history."
              (* The bound is not the array, which is one word per sample, but
               * what fills it: a million snapshots of anything is already
               * more than any plot can use. *)
              ~getter:(fun () -> `Int (metrics_max_samples t))
              ~setter:(fun v ->
                  set_metrics_max_samples t
                      (Widget.to_int_range ~min:0 ~max:1_000_000 v)) ] ;
        register t ;
        t

(** Will process the next event *)
let next_event (t : t) =
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
                let wait_time = Time.diff until (now t) in
                if not (may_dispatch t) ||
                   Interval.compare wait_time min_ts_for_sleep > 0 then (
                    if debug then Printf.printf "Clock: next_event: waiting until %s since we're too early\n%!" (Time.to_string until) ;
                    (* [until] names an instant of this simulation, which is
                       not where the wall clock is unless the two were never
                       parted (see [make_realtime]). *)
                    wait_on_cond ~until:(to_wall_clock t until) t ;
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
                    and wall = Wall.now () in
                    if Wall.compare wall due >= 0 then (
                        (* Due already: run it, and say how far behind we are. *)
                        t.late <- Wall.diff wall due ;
                        true
                    ) else (
                        t.late <- Interval.zero ;
                        (* Sleeping on the condition rather than on the clock:
                         * whoever changes the speed, resumes or adds an event
                         * meanwhile wakes us to reconsider. *)
                        wait_on_cond ~until:due t ;
                        false
                    )) ()
        ) in
    if run_first_event then (
        (* We have some work to do *)
        let f =
            with_lock t (fun () ->
                match Events.min_binding t.events with
                | exception Not_found -> None
                | ts, (_power, f) ->
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
let run (t : t) wait =
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
                (* From a thread of its own, and nothing else here. A handler
                 * runs wherever the process happened to be, which is as likely
                 * as not to be in the middle of a dispatch -- holding a
                 * simulation's lock, or halfway through the bookkeeping
                 * [with_lock] does around it, having taken the mutex and not
                 * yet written down whose it is. Stopping a simulation wants
                 * that same lock, and asking for it from there either takes a
                 * mutex the thread already holds or, worse, is handed one it
                 * only appears to own and gives it back twice. So the handler
                 * does the one thing that needs no lock at all: it starts a
                 * thread, which then queues for them like anybody else. *)
                ignore (Thread.create (fun () ->
                    Printf.printf "Quitting...\n%!" ;
                    stop_all ()) ())))
        ) signals in
    (* Somewhere for that handler to run. A signal handler is OCaml code, and
     * OCaml code runs where the program next polls; a program whose every
     * thread sits in a system call -- a simulation waiting on its next event,
     * the thread waiting on that simulation -- polls nowhere at all, and the
     * signal stays pending until something happens to wake one of them, which
     * can be as far off as the quietest moment of the network. This thread
     * wakes every second and does nothing else, so that there is always one
     * place to run it after at most 1s. *)
    let ticking = ref true in
    let ticker = Thread.create (fun () -> while !ticking do Thread.delay 1. done) () in
    finally (fun () ->
        ticking := false ;
        Thread.join ticker ;
        List.iter2 Sys.set_signal signals prev_sigs) f ()

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
let borrow (t : t) f = with_lock t f ()

(** Helpers for reaching the simulation of a widget: *)
module Widget =
struct
    let now = now % of_widget

    (* TODO: etc... *)
end
