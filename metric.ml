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
(*
   Metrics for counting events, and generating realtime or final reports.
   Events may have a start and stop time or be atomic (no duration).
   In case of event with duration, two events are added: one for start and one for stop,
   so that it's possible to have the rate(t) of starts and rate(t) of stops.

   These reports must provide:
   - total number of occurrences of a given event
   - current/total rate of an event
   - current/total min/max of this rate
   - current/total mean rate of an event
   For events with duration, in addition to the above for the start and end event:
   - total duration of an event
   - current/total mean duration of an event

   (note: "current" values can be obtained from a polling agent from the bare counters
   offered here)

   Also, each event is given a name and is known to the module so that we can
   build reports including all events without requiring much from the user.

   Also, events of the same kind may be grouped together to form a compound
   event of this same type. Events are thus ordered in a tree. This need not to
   be performed until creation of the report, though.
*)

open Batteries
open Bitstring
open Tools

let debug = false

(* Atomic events are for errors, per results stats, etc *)
module Atomic =
struct

    type t = { name               : string ;
               mutable count      : int64 ;
               mutable first_last : (Clock.Time.t * Clock.Time.t) option }

    let all = Hashtbl.create 37

    let make name =
        let ret = { name        = name ;
                    count       = 0L ;
                    first_last  = None } in
        Hashtbl.add all name ret ;
        ret

    let fire ev =
        let now = Clock.now () in
        ev.count <- Int64.succ ev.count ;
        match ev.first_last with
        | None ->
            ev.first_last <- Some (now, now)
        | Some (first, _) ->
            ev.first_last <- Some (first, now)

    let print oc ev =
        Printf.fprintf oc "Metric: %s:\n\tcount: %Ld\n" ev.name ev.count ;
        match ev.first_last with None -> () | Some (first, last) ->
            Printf.fprintf oc "\tfirst: %a\n\tlast: %a\n" Clock.printer first Clock.printer last ;
            if first <> last then
                Printf.fprintf oc "\trate: %f Hz\n" (Int64.to_float ev.count /. ((Clock.Time.sub last first) :> float))
end

(* Counters are for counting bytes, etc *)
module Counter =
struct
    type t = { name          : string ;
               unit_str      : string ;
               mutable value : int64 ;
               events        : Atomic.t }

    let all = Hashtbl.create 37

    let make name u =
        let ret = { name = name ; unit_str = u ;
                    value = 0L ; events = Atomic.make (name^"_events") } in
        Hashtbl.add all name ret ;
        ret

    let increase ev c =
        Atomic.fire ev.events ;
        ev.value <- Int64.add ev.value c

    let print oc ev =
        Printf.fprintf oc "Metric: %s:\n\tcount: %Ld %s\n"
            ev.name ev.value ev.unit_str
end

(* Timeds are for download times, connection times, etc *)
module Timed =
struct

    type minmax = { mutable min : (Clock.Interval.t * string) ;
                    mutable max : (Clock.Interval.t * string) }

    let make_minmax v id = { min = v, id ; max = v, id }

    let update_minmax mm v id =
        if fst mm.max <= v then mm.max <- v, id ;
        if fst mm.min >= v then mm.min <- v, id

    type t = { name                  : string ;
               start                 : Atomic.t ;
               stop                  : Atomic.t ;
               mutable tot_duration  : Clock.Interval.t ;
               mutable minmax        : minmax option ;
               mutable simult        : int ;
               mutable max_simult    : int }

    let all = Hashtbl.create 37

    let make name =
        let ret = { name              = name ;
                    start             = Atomic.make (name^"/start") ;
                    stop              = Atomic.make (name^"/stop") ;
                    tot_duration      = Clock.Interval.o 0. ;
                    minmax            = None ;
                    simult            = 0 ;
                    max_simult        = 0 } in
        Hashtbl.add all name ret ;
        ret

    let start ev =
        Atomic.fire ev.start ;
        ev.simult <- ev.simult + 1 ;
        if ev.simult > ev.max_simult then ev.max_simult <- ev.simult ;
        Clock.now ()

    let stop ev start_time id =
        let now = Clock.now () in
        Atomic.fire ev.stop ;
        ev.simult <- ev.simult - 1 ;
        let duration = Clock.Time.sub now start_time in
        ev.tot_duration <- Clock.Interval.add ev.tot_duration duration ;
        match ev.minmax with
            | None -> ev.minmax <- Some (make_minmax duration id)
            | Some mm -> update_minmax mm duration id

    let print oc ev =
        Printf.fprintf oc "Metric: %s:\n\ttotal-duration: %s\n\tsimultaneous: %d\n\tmax-simult: %d\n"
            ev.name (Clock.Interval.to_string ev.tot_duration) ev.simult ev.max_simult ;
        if ev.stop.Atomic.count <> 0L then
            Printf.fprintf oc "\tavg-duration: %s\n"
                (((ev.tot_duration :> float) /. Int64.to_float ev.stop.Atomic.count) |> Clock.Interval.o |> Clock.Interval.to_string) ;
        (match ev.minmax with None -> () | Some mm ->
            Printf.fprintf oc "\tmin-duration: %s (%s)\n\tmax-duration: %s (%s)\n"
                (Clock.Interval.to_string (fst mm.min)) (snd mm.min)
                (Clock.Interval.to_string (fst mm.max)) (snd mm.max))
end

(* Report generation *)

let print_report oc =
    Hashtbl.iter (fun _ ev -> Atomic.print oc ev) Atomic.all ;
    Hashtbl.iter (fun _ ev -> Counter.print oc ev) Counter.all ;
    Hashtbl.iter (fun _ ev -> Timed.print oc ev) Timed.all ;
    flush oc

let rec report_thread oc period =
    lwt () = Lwt_unix.sleep period in
    print_report oc ;
    report_thread oc period

(* Tools for building UI *)

type item = Atomic of Atomic.t
          | Counter of Counter.t
          | Timed of Timed.t
          | Tree of (string * tree)
and tree = item list
 
let tree () =
    let empty = [] in
    let rec tree_add tree path item =
        match path with
        | [] -> should_not_happen ()
        | [_] -> item :: tree
        | p::p' -> (* look for a subtree of this name *)
            (match tree with
            | [] -> [ Tree (p, tree_add empty p' item) ]
            | Tree (n, t) :: t' when n = p ->
                Tree (n, tree_add t p' item) :: t'
            | i :: t' ->
                i :: tree_add t' path item) in
    let tree = Hashtbl.fold (fun n ev tree ->
        if debug then Printf.printf "Merging %s into the tree\n" n ;
        tree_add tree (String.nsplit n "/") (Atomic ev)) Atomic.all empty in
    let tree = Hashtbl.fold (fun n ev tree ->
        if debug then Printf.printf "Merging %s into the tree\n" n ;
        tree_add tree (String.nsplit n "/") (Counter ev)) Counter.all tree in
    let tree = Hashtbl.fold (fun n ev tree ->
        if debug then Printf.printf "Merging %s into the tree\n" n ;
        tree_add tree (String.nsplit n "/") (Timed ev)) Timed.all tree in
    tree

