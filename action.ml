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
   Running what a widget can be asked to do.

   An action is declared with {!Widget.action}, beside the widget's properties,
   and run from here: {!start} reads its parameters, records the run and calls
   the handler; {!stop} closes that run with whatever it came to. In between,
   what the action does is whatever its handler scheduled.

   This is the vocabulary a widget's author uses; several of these words are
   {!Simulation}'s, named here where they are looked for. They are there
   because the simulator itself has to be able to run one and to end one: a
   startup list is run when a simulation starts running, and switching a source
   off ends the runs of the widgets drawing on it.

   Which is why a run ends when its handler says so, and not when the scheduler
   has nothing left of it: every frame is delivered by an event, so the work one
   ping causes reaches the switch, the host at the other end, and whatever timer
   each of them arms on the way. "No event left" is a question about the
   network, not about the action.

   Three ways a run could then never end, of which the simulator sees two: a
   handler that raises rather than returning, which {!start} ends as a
   [Failed]; the source paying for what it scheduled going off, or its widget
   being taken away, which {!Simulation.power_down} and
   {!Simulation.remove_widget} end as a [Withdrawn]. The third is a handler
   that simply forgets, and nothing can see that one.
 *)
open Batteries
open SimTypes

type t = action
type state = action_state
type origin = action_origin = Startup | Api
type result = action_result =
    | Value of value option
    | Failed of string
    | Withdrawn of withdrawal_reason

(** The action of [w] by that name, if it has one. *)
let find = Simulation.find_action

(** A run in a few words: what was asked for, with what. *)
let describe = Simulation.describe_run

(** Whether that run is still going on. *)
let is_running (s : state) = s.ended = None

(** Run [a] on [w] with [given] as its parameters: those the action declares,
 * the ones left out taking their default (see {!Simulation.start_action},
 * where this lives, since the simulator has to be able to run one itself). *)
let start = Simulation.start_action

(** Record that this run is over, and what it came to. Called from whatever the
 * handler scheduled, since nothing else knows when the work is done. *)
let stop ?result (s : state) =
    Simulation.stop_action s (Value result)

(** The same, for a run that got nowhere: what went wrong, in the action's own
 * words. A timeout that is a failure is one of these -- see {!SimTypes}. *)
let fail (s : state) fmt =
    Printf.ksprintf (fun m -> Simulation.stop_action s (Failed m)) fmt

(*
 * Schedules
 *)

(** A schedule from what a document or the API gives for it, [field] answering
 * [`Null] for what was left out: "delay" before the first run, "repeat_after"
 * between the end of a run and the start of the next, both in seconds, and
 * "times" for how many runs in all.
 *
 * "repeat_after" alone repeats until stopped, and "times" alone repeats with
 * no gap. Refuses with {!Widget.Bad_value} a loop with neither a gap nor an
 * end: a run that is over as soon as it starts would hold the clock for
 * ever. *)
let schedule_of_fields field =
    let secs name =
        match field name with
        | `Null -> None
        | v ->
            (try Some (Widget.to_float_range ~min:0. v |> Clock.Interval.of_secs)
            with Widget.Bad_value m -> Widget.bad_value "%S: %s" name m) in
    let times =
        match field "times" with
        | `Null -> None
        | v ->
            (try Some (Widget.to_int_range ~min:1 v)
            with Widget.Bad_value m -> Widget.bad_value "%S: %s" "times" m) in
    let repeat_after =
        match secs "repeat_after", times with
        | None, Some _ -> Some Clock.Interval.zero
        | r, _ -> r in
    (match repeat_after, times with
    | Some gap, None when Clock.Interval.compare gap Clock.Interval.zero <= 0 ->
        Widget.bad_value "repeating until stopped needs a \"repeat_after\" \
                          above zero"
    | _ -> ()) ;
    { delay = secs "delay" |? Clock.Interval.zero ; repeat_after ; times }

(** The fields of a schedule, as [schedule_of_fields] reads them; none for a
 * run once, now. *)
let schedule_fields (s : schedule) =
    (if Clock.Interval.compare s.delay Clock.Interval.zero > 0 then
        [ "delay", Widget.json_of_duration s.delay ] else []) @
    (match s.repeat_after with
    | None -> []
    | Some gap ->
        [ "repeat_after", Widget.json_of_duration gap ] @
        (match s.times with None -> [] | Some n -> [ "times", `Int n ]))

(*
 * The startup list
 *
 * What is to be run once a network has been built, in order: it is saved with
 * the network (see {!Topology}) and is how a document says what is to be
 * *done* to what it describes, as against what it is made of.
 *)

type entry = startup_entry

(** What [w] being asked to do [a] with [params] is, as an entry: the widget by
 * its path, since the list outlives this process. Refuses a widget that is not
 * in its own simulation's tree, which cannot happen for one that is still in
 * it. *)
let entry_of ?(schedule=once) (w : widget) name params =
    match Widget.path_within (Widget.sim w).root w with
    | None ->
        Widget.bad_value "%s is no longer in the simulation"
            (Widget.full_name w)
    | Some path -> { path ; action = name ; params ; schedule }

let startup (sim : simulation) = sim.startup

(** Add one at the end, which is where a device registering its own belongs:
 * the order is the order things are to be done in, and what is built later is
 * started later. *)
let add_startup (sim : simulation) (e : entry) =
    Simulation.with_lock sim (fun () ->
        sim.startup <- sim.startup @ [ e ] ;
        Simulation.changed sim) ()

(** The whole list at once, which is how the interface edits it: reordering and
 * removing are both this. *)
let set_startup (sim : simulation) entries =
    Simulation.with_lock sim (fun () ->
        sim.startup <- entries ;
        Simulation.changed sim) ()

(** Run those entries, and the whole list: {!Simulation}'s, for the same
 * reason -- a list is run when a simulation starts running. *)
let run_entries = Simulation.run_entries
let run_startup = Simulation.run_startup

(** The run of [s]'s loop that is still going on or waiting, if any: at most
 * one is, since a round only starts once the one before it is over. *)
let live_round (s : state) =
    if s.ended = None then Some s else
    List.find_opt (fun (s' : state) -> s'.loop = s.loop && s'.ended = None)
        (Widget.sim s.widget).started_actions

(** Stop a run because somebody asked for it to stop, and with it the loop it
 * is a round of: the live round of that loop is the one ended.
 *
 * This ends the *record* of the run, and nothing else: what the handler
 * scheduled is the handler's, and nothing here can tell which of a box's
 * pending events belong to which run. An action worth cancelling therefore
 * checks [is_running] in the callbacks it schedules, and gives up whatever it
 * was holding when the answer is no -- which is what {!Host}'s ping does. *)
let cancel (s : state) =
    Option.may (fun s -> Simulation.stop_action s (Withdrawn Cancelled))
               (live_round s)

(** The run of [sim] with that id, if there is one. *)
let find_run (sim : simulation) id =
    List.find_opt (fun (s : state) -> s.id = id) sim.started_actions

(** What has been run in [sim], most recent first; [widget] narrows it to the
 * runs of one widget. *)
let runs ?widget (sim : simulation) =
    match widget with
    | None -> sim.started_actions
    | Some (w : widget) ->
        List.filter (fun (s : state) -> s.widget == w) sim.started_actions
