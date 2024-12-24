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
   Facility to count events/measure performances.

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
open Tools

let debug = false

module Param =
struct
    type t =
        | Bool of bool
        | Int of int
        | String of string

    let to_string = function
        | Bool b -> string_of_bool b
        | Int d -> string_of_int d
        | String s -> s
end

module Params =
struct
    (* There are smarter representations but let's see if we need them *)
    type t = (string * Param.t) list

    let empty = []

    let singleton n v = [ n, v ]

    let compare = List.compare

    let cmp_param (n1, _) (n2, _) = String.compare n1 n2

    let make assoc_lst =
        List.fast_sort cmp_param assoc_lst

    let ref find n = function
        | [] ->
            raise Not_found
        | (n', v) :: rest ->
            let c = String.compare n n' in
            if c < 0 then raise Not_found else
            if c = 0 then v else
            find n rest

    let rec (+::) (n, _ as p) = function
        | [] ->
            [ p ]
        | (n', _ as p') :: rest ->
            let c = String.compare n n' in
            if c < 0 then p :: rest else
            if c = 0 then invalid_arg ("Params.cons: "^ n ^" added twice")
            else p' :: (p +:: rest)

    let add t1 t2 =
        List.merge cmp_param t1 t2

    let has_param n t =
        try ignore (find n t) ; true with Not_found -> false

    let print oc t =
        List.print ~first:"" ~sep:"|" ~last:""
            (fun oc (n, v) -> Printf.fprintf oc "%S:%s" n (Param.to_string v))
            oc t

    let print_hash p oc h =
        Hashtbl.print ~first:"" ~last:"" ~sep:"" ~kvsep:""
            (fun oc params -> Printf.fprintf oc "\t\t%a: " print params)
            (fun oc v -> Printf.fprintf oc "%a\n" p v)
            oc h
end

module FirstLast =
struct
    type t_ = { first : Clock.Time.t ; mutable last : Clock.Time.t }

    type t = t_ ref

    let empty =
        let z = Clock.Time.o 0. in
        { first = z ; last = z }

    let make () =
        ref empty

    let reset t =
        t := empty

    let update ?now t =
        let now = Option.default_delayed Clock.now now in
        if !t == empty then
            t := { first = now ; last = now }
        else
            !t.last <- now

    let printf oc t =
        if !t != empty then
            Printf.fprintf oc "\
                \tfirst: %a\n\
                \tlast: %a\n"
                Clock.Time.printf !t.first
                Clock.Time.printf !t.last
end

(* All defined metrics *)

type metric = ..

let all : (string, metric) Hashtbl.t = Hashtbl.create 99

(* Atomic events are for errors, per results stats, etc *)
module Atomic =
struct

    type t = { name : string ;
               counts : (Params.t, int) Hashtbl.t ;
               first_last : FirstLast.t }

    type metric += T of t

    let make name =
        match hash_find_or_insert all name (fun () ->
                T {
                    name = name ;
                    counts = Hashtbl.create 5 ;
                    first_last = FirstLast.make () }) with
        | T t -> t
        | _ -> invalid_arg ("Atomic.make reuse name "^ name)

    let reset t =
        Hashtbl.clear t.counts ;
        FirstLast.reset t.first_last

    let fire ?now ?(params=Params.empty) t =
        Hashtbl.modify_def 0 params succ t.counts ;
        FirstLast.update ?now t.first_last

    let print oc t =
        Printf.fprintf oc "\
            Metric: %s:\n\
            \tcounts:\n\
            %a"
            t.name
            (Params.print_hash Int.print)
                t.counts ;
        FirstLast.printf oc t.first_last
end

(* Measure some current capacity. Can increase or decrease. *)
module Gauge =
struct
    type t = { name : string ;
               values : (Params.t, value) Hashtbl.t ;
               first_last : FirstLast.t }
    and value = { min : int ; current : int ; max : int }

    type metric += T of t

    let make name =
        match hash_find_or_insert all name (fun () ->
                T {
                    name = name ;
                    values = Hashtbl.create 5 ;
                    first_last = FirstLast.make () }) with
        | T t -> t
        | _ -> invalid_arg ("Gauge.make reuse name "^ name)

    let reset t =
        Hashtbl.clear t.values ;
        FirstLast.reset t.first_last

    let set ?now ?(params=Params.empty) t v =
        Hashtbl.modify_opt params (function
        | None ->
            Some { min = v ; current = v ; max = v }
        | Some value ->
            Some { min = min value.min v ; current = v ; max = max value.max v }
        ) t.values ;
        FirstLast.update ?now t.first_last

    let add ?now ?(params=Params.empty) t d =
        let v =
            try (Hashtbl.find t.values params).current
            with Not_found -> 0 in
        set ?now ~params t (v + d)

    let print oc t =
        Printf.fprintf oc "\
            Metric: %s:\n\
            \tvalues:\n\
            %a"
            t.name
            (Params.print_hash
                (fun oc value ->
                    Printf.fprintf oc "min:%d, current:%d, max:%d"
                        value.min value.current value.max)
            ) t.values ;
        FirstLast.printf oc t.first_last
end

(* Counters are for counting bytes, etc *)
module Counter =
struct
    type t = { name : string ;
               units : string ; (* TODO: an enum with known pretty printers *)
               values : (Params.t, int) Hashtbl.t ;
               fired : Atomic.t }

    type metric += T of t

    let make name units =
        match hash_find_or_insert all name (fun () ->
            T {
                name ; units ;
                values = Hashtbl.create 10 ;
                fired = Atomic.make (name^"/fired") }) with
        | T t -> t
        | _ -> invalid_arg ("Counter.make reuse name "^ name)

    let reset t =
        Hashtbl.clear t.values ;
        Atomic.reset t.fired

    let add t ?now ?(params=Params.empty) c =
        Hashtbl.modify_opt params (function
            | None ->
                Some c
            | Some sum ->
                Some (sum + c)
        ) t.values ;
        Atomic.fire ?now t.fired

    let print oc t =
        Printf.fprintf oc "\
            Metric: %s:\n\
            \tcounts:\n\
            %a"
            t.name
            (Params.print_hash
                (fun oc v -> Printf.fprintf oc "%d\n" v))
                t.values
end

(* Timeds are for download times, connection times, etc *)
module Timed =
struct
    type t = { name : string ;
               durations : (Params.t, duration) Hashtbl.t ;
               starts : Atomic.t ;
               stops : Atomic.t ;
               mutable simult : int ;
               mutable max_simult : int }

    and duration =
        { min : Clock.Interval.t ;
          max : Clock.Interval.t ;
          sum : Clock.Interval.t ;
          count : int }

    type metric += T of t

    let make name =
        match hash_find_or_insert all name (fun () ->
            T {
                name ;
                starts = Atomic.make (name^"/start") ;
                stops = Atomic.make (name^"/stop") ;
                durations = Hashtbl.create 10 ;
                simult = 0 ;
                max_simult = 0 }) with
        | T t -> t
        | _ -> invalid_arg ("Timed.make reuse name "^ name)

    let reset t =
        Atomic.reset t.starts ;
        Atomic.reset t.stops ;
        Hashtbl.clear t.durations ;
        t.simult <- 0 ;
        t.max_simult <- 0

    type stop_func = Params.t -> unit

    let start ?(params=Params.empty) t : stop_func =
        let start_time = Clock.now () in
        t.simult <- t.simult + 1 ;
        if t.simult > t.max_simult then t.max_simult <- t.simult ;
        (* Return the stop function: *)
        fun extra_params ->
            let now = Clock.now () in
            let params = Params.add params extra_params in
            Atomic.fire ~now:start_time ~params t.starts ;
            Atomic.fire ~now ~params t.stops ;
            t.simult <- t.simult - 1 ;
            let duration = Clock.Time.sub now start_time in
            Hashtbl.modify_opt params (function
                | None ->
                    Some {
                        min = duration ;
                        max = duration ;
                        sum = duration ;
                        count = 1 }
                | Some d ->
                    Some {
                        min = min d.min duration ;
                        max = max d.max duration ;
                        sum = Clock.Interval.add d.sum duration ;
                        count = d.count + 1 }
            ) t.durations

    let timed ?(params=Params.empty) t f =
        let start_time = Clock.now () in
        t.simult <- t.simult + 1 ;
        if t.simult > t.max_simult then t.max_simult <- t.simult ;
        match f () with
        | exception e ->
            let bt = Printexc.get_raw_backtrace () in
            Atomic.fire ~now:start_time ~params t.starts ;
            t.simult <- t.simult - 1 ;
            Printexc.raise_with_backtrace e bt
        | extra_params, res->
            let now = Clock.now () in
            let params = Params.add params extra_params in
            Atomic.fire ~now:start_time ~params t.starts ;
            Atomic.fire ~now ~params t.stops ;
            t.simult <- t.simult - 1 ;
            let duration = Clock.Time.sub now start_time in
            Hashtbl.modify_opt params (function
                | None ->
                    Some {
                        min = duration ;
                        max = duration ;
                        sum = duration ;
                        count = 1 }
                | Some d ->
                    Some {
                        min = min d.min duration ;
                        max = max d.max duration ;
                        sum = Clock.Interval.add d.sum duration ;
                        count = d.count + 1 }
            ) t.durations ;
            res

    let print oc t =
        Printf.fprintf oc "\
            Metric: %s:\n\
            \tdurations:\n\
            %a\
            \tsimultaneous: %d\n\
            \tmax-simultaneous: %d\n"
            t.name
            (Params.print_hash
                (fun oc d ->
                    let open Clock.Interval in
                    Printf.fprintf oc "min:%s, avg:%s, max:%s, count:%d"
                        (to_string d.min)
                        (to_string (mul d.sum (1. /. float_of_int d.count)))
                        (to_string d.max)
                        d.count)
            ) t.durations
            t.simult t.max_simult
end

(* Report generation *)

let print_report oc =
    Hashtbl.iter (fun _ -> function
        | Atomic.T t -> Atomic.print oc t
        | Gauge.T t -> Gauge.print oc t
        | Counter.T t -> Counter.print oc t
        | Timed.T t -> Timed.print oc t
        | _ -> invalid_arg "Metric.print_report"
    ) all ;
    flush oc

let report_thread oc period =
    let rec loop () =
        Thread.delay period ;
        print_report oc ;
        if !Clock.continue then loop () in
    Thread.create loop ()

(* Misc *)

let reset () =
    Hashtbl.iter (fun _ -> function
        | Atomic.T t -> Atomic.reset t
        | Gauge.T t -> Gauge.reset t
        | Counter.T t -> Counter.reset t
        | Timed.T t -> Timed.reset t
        | _ -> invalid_arg "Metric.reset"
    ) all

let params = function
    | Atomic.T t -> Hashtbl.keys t.counts
    | Gauge.T t -> Hashtbl.keys t.values
    | Counter.T t -> Hashtbl.keys t.values
    | Timed.T t -> Hashtbl.keys t.durations
    | _ -> invalid_arg "Metric.params"
