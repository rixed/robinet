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

(* Runs are numbered across the process, as widgets are, although the interface
 * only ever names one within a simulation. *)
let next_id =
    let seq = ref 0 in
    fun () ->
        let id = !seq in
        incr seq ;
        id

(** The action of [w] by that name, if it has one. *)
let find (w : widget) name =
    List.find_opt (fun (a : t) -> a.name = name) w.actions

(* A run in a few words, for the logs: what was asked for, with what. *)
let describe (s : state) =
    if s.params = [] then s.action_name else
    Printf.sprintf "%s (%s)" s.action_name
        (List.map (fun (n, v) ->
            n ^"="^ Yojson.Basic.to_string v
        ) s.params |> String.concat ", ")

(** Whether that run is still going on. *)
let is_running (s : state) = s.ended = None

(** Run [a] on [w] with [given] as its parameters: those the action declares,
 * the ones left out taking their default.
 *
 * Refuses with {!Widget.Bad_value} -- which the API answers with a 400, as it
 * does for a setter -- what cannot be read as the parameters the action
 * declares, and what the action itself says it cannot do just now.
 *
 * What the handler raises comes back out as it is, and the run stays recorded:
 * it did start, and a run that failed on its first step is worth seeing. *)
let start ?(origin=Api) (w : widget) (a : t) given =
    let sim = Widget.sim w in
    Simulation.with_lock sim (fun () ->
        if not (a.can_run ()) then
            Widget.bad_value "%s cannot %s just now" (Widget.full_name w) a.name ;
        let params = Widget.args_of a.name a.params given in
        let s =
            { id = next_id () ;
              widget = w ;
              action_name = a.name ;
              params ;
              origin ;
              started = Simulation.now sim ;
              ended = None } in
        sim.started_actions <- s :: sim.started_actions ;
        Log.(log w.logger Info (lazy (Printf.sprintf "Running %s" (describe s)))) ;
        (* A handler that raises has ended this run, whatever it meant to do,
           and the run must say so rather than wait for ever on work that was
           never scheduled. The exception goes on out to whoever asked -- the
           API answers it with a 400 -- and what is recorded here is what the
           reader will find afterwards. *)
        (match a.handler s with
        | () -> ()
        | exception e ->
            Simulation.stop_action s (Failed (match e with
                | Widget.Bad_value m -> m
                | e -> Printexc.to_string e)) ;
            raise e) ;
        s) ()

(** Record that this run is over, and what it came to. Called from whatever the
 * handler scheduled, since nothing else knows when the work is done. *)
let stop ?result (s : state) =
    Simulation.stop_action s (Value result)

(** The same, for a run that got nowhere: what went wrong, in the action's own
 * words. A timeout that is a failure is one of these -- see {!SimTypes}. *)
let fail (s : state) fmt =
    Printf.ksprintf (fun m -> Simulation.stop_action s (Failed m)) fmt

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
let entry_of (w : widget) name params =
    match Widget.path_within (Widget.sim w).root w with
    | None ->
        Widget.bad_value "%s is no longer in the simulation"
            (Widget.full_name w)
    | Some path -> { path ; action = name ; params }

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

(** Run the list, in order, each entry on the widget its path names.
 *
 * An entry that cannot be run does not stop the ones after it: a network is
 * read back from a document that may have been edited by hand, and one line of
 * it naming a widget that is not there is no reason to leave the rest of the
 * network idle. What went wrong is logged against the simulation's root, which
 * is where something that belongs to no widget goes. *)
let run_startup (sim : simulation) =
    let fail fmt =
        Printf.ksprintf (fun m ->
            Log.(log sim.root.logger Error (lazy m))) fmt in
    List.iter (fun (e : entry) ->
        match Widget.find_within sim.root e.path with
        | None ->
            fail "Cannot run %S at startup: no widget at %S" e.action e.path
        | Some w ->
            (match find w e.action with
            | None ->
                fail "Cannot run %S at startup: %s cannot do that" e.action
                    (Widget.full_name w)
            | Some a ->
                (match start ~origin:Startup w a e.params with
                | exception ex ->
                    fail "Cannot run %S at startup on %s: %s" e.action
                        (Widget.full_name w)
                        (match ex with
                        | Widget.Bad_value m -> m
                        | ex -> Printexc.to_string ex)
                | _ -> ()))
    ) (startup sim)

(** What has been run in [sim], most recent first; [widget] narrows it to the
 * runs of one widget. *)
let runs ?widget (sim : simulation) =
    match widget with
    | None -> sim.started_actions
    | Some (w : widget) ->
        List.filter (fun (s : state) -> s.widget == w) sim.started_actions
