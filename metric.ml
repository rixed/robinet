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

   Also, events of the same kind may be grouped together to form a compound
   event of this same type. Events are thus ordered in a tree. This need not to
   be performed until creation of the report, though.

   A metric belongs to the widget that owns it, and is read through that
   widget's properties; there is no registry of every metric in the process.

   Whatever records a time takes it as an argument: a metric measuring a
   simulation must be told that simulation's time, and there is no default that
   could quietly substitute the wall clock for it. This module therefore knows
   nothing of simulations, and can be used by a parser as readily as by a
   simulated host.
*)

open Batteries

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

    let print oc v =
        String.print oc (to_string v)

    (* Written out rather than derived: a parameter is a value, and the UI has
     * no use for the constructor that carried it. *)
    let to_yojson = function
        | Bool b -> `Bool b
        | Int d -> `Int d
        | String s -> `String s
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

    let to_yojson t =
        `Assoc (List.map (fun (n, v) -> n, Param.to_yojson v) t)
end

(* Every metric is a family, keyed by the parameters of the event: a JSON
 * object cannot hold that, its keys being strings, so the tables become a list
 * of the pairs they hold. *)
let table_to_yojson value_to_yojson h =
    `List (
        Hashtbl.fold (fun params v lst ->
            `Assoc [ "params", Params.to_yojson params ;
                     "value", value_to_yojson v ] :: lst
        ) h [])

module FirstLast =
struct
    type t_ = { first : Clock.Time.t ; mutable last : Clock.Time.t }
        [@@deriving to_yojson]

    type t = t_ ref

    let empty =
        let z = Clock.Time.o 0. in
        { first = z ; last = z }

    let make () =
        ref empty

    let reset t =
        t := empty

    let update now t =
        if !t == empty then
            t := { first = now ; last = now }
        else
            !t.last <- now

    (* Null while the event has never happened: "never" and "at the epoch" are
     * not the same statement. *)
    let to_yojson t =
        if !t == empty then `Null else t__to_yojson !t

    let printf oc t =
        if !t != empty then
            Printf.fprintf oc "\
                first: %a\n\
                last: %a\n"
                Clock.Time.printf !t.first
                Clock.Time.printf !t.last
end

(* A metric is one of those; each kind adds its own constructor below, and
 * [to_yojson] at the end of this file knows how to name them. *)

type metric = ..

(* Atomic events are for errors, per results stats, etc *)
module Atomic =
struct

    type t = { counts : (Params.t, int) Hashtbl.t
                   [@to_yojson table_to_yojson (fun c -> `Int c)] ;
               first_last : FirstLast.t } [@@deriving to_yojson]

    type metric += T of t

    let make () =
        { counts = Hashtbl.create 5 ;
          first_last = FirstLast.make () }

    let reset t =
        Hashtbl.clear t.counts ;
        FirstLast.reset t.first_last

    let fire ~now ?(params=Params.empty) t =
        Hashtbl.modify_def 0 params succ t.counts ;
        FirstLast.update now t.first_last

    let print oc t =
        Printf.fprintf oc "counts: %a"
            (Params.print_hash Int.print)
                t.counts ;
        FirstLast.printf oc t.first_last
end

(* Measure some current capacity. Can increase or decrease. *)
module Gauge =
struct
    type t = { values : (Params.t, value) Hashtbl.t
                   [@to_yojson table_to_yojson value_to_yojson] ;
               first_last : FirstLast.t }
    (* [min] and [max] are the extremes since the metric was last reset, which
     * is what a reader looking at the figures wants to know. [sample_min] and
     * [sample_max] are those of the window that started when the metric was
     * last sampled, which is what a plot of the interval between two points
     * wants instead -- the others only ever widen, and a band drawn from them
     * would swallow the plot within a minute. Sampling closes the window and
     * opens a new one at the value standing then; see [sample]. *)
    and value = { min : int ; current : int ; max : int ;
                  sample_min : int ; sample_max : int }
    [@@deriving to_yojson]

    type metric += T of t

    let make () =
        { values = Hashtbl.create 5 ;
          first_last = FirstLast.make () }

    let reset t =
        Hashtbl.clear t.values ;
        FirstLast.reset t.first_last

    let set ~now ?(params=Params.empty) t v =
        Hashtbl.modify_opt params (function
        | None ->
            Some { min = v ; current = v ; max = v ;
                   sample_min = v ; sample_max = v }
        | Some value ->
            Some { min = min value.min v ; current = v ; max = max value.max v ;
                   sample_min = min value.sample_min v ;
                   sample_max = max value.sample_max v }
        ) t.values ;
        FirstLast.update now t.first_last

    (* Read every row and start a new window at the value each of them stands
     * at: the extremes of what comes next are those of what happens next. *)
    let take_windows t =
        let rows = Hashtbl.fold (fun params v l -> (params, v) :: l) t.values [] in
        List.iter (fun (params, v) ->
            Hashtbl.replace t.values params
                { v with sample_min = v.current ; sample_max = v.current }
        ) rows ;
        rows

    let add ~now ?(params=Params.empty) t d =
        let v =
            try (Hashtbl.find t.values params).current
            with Not_found -> 0 in
        set ~now ~params t (v + d)

    let succ ~now ?params t =
        add ~now ?params t 1

    let pred ~now ?params t =
        add ~now ?params t (-1)

    let print oc t =
        Printf.fprintf oc "\
            \tvalues:\n\
            %a"
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
    type t = { values : (Params.t, int) Hashtbl.t
                   [@to_yojson table_to_yojson (fun c -> `Int c)] ;
               fired : Atomic.t } [@@deriving to_yojson]

    type metric += T of t

    let make () =
        { values = Hashtbl.create 10 ;
          fired = Atomic.make () }

    let reset t =
        Hashtbl.clear t.values ;
        Atomic.reset t.fired

    let add t ~now ?(params=Params.empty) c =
        Hashtbl.modify_opt params (function
            | None ->
                Some c
            | Some sum ->
                Some (sum + c)
        ) t.values ;
        Atomic.fire ~now ~params t.fired

    let inc ?params t =
        add t ?params 1

    let get ?(params=Params.empty) t =
        try Hashtbl.find t.values params
        with Not_found -> 0

    let print oc t =
        Printf.fprintf oc "counts: %a"
            (Params.print_hash
                (fun oc v -> Printf.fprintf oc "%d\n" v))
                t.values
end

(* Timeds are for download times, connection times, etc *)
module Timed =
struct
    type t = { durations : (Params.t, duration) Hashtbl.t
                   [@to_yojson table_to_yojson duration_to_yojson] ;
               starts : Atomic.t ;
               stops : Atomic.t ;
               (* How many are running right now. *)
               simult : Gauge.t }

    and duration =
        { min : Clock.Interval.t ;
          max : Clock.Interval.t ;
          sum : Clock.Interval.t ;
          count : int ;
          (* The shortest and longest of those measured since the metric was
           * last sampled, as opposed to the [min] and [max] above, which are
           * those since it was last reset. [None] when nothing at all was
           * measured in that window, which is not the same as a duration of
           * zero. See [sample]. *)
          sample_min : Clock.Interval.t option ;
          sample_max : Clock.Interval.t option }
    [@@deriving to_yojson]

    type metric += T of t

    let make () =
        { starts = Atomic.make () ;
          stops = Atomic.make () ;
          durations = Hashtbl.create 10 ;
          simult = Gauge.make () }

    let reset t =
        Atomic.reset t.starts ;
        Atomic.reset t.stops ;
        Hashtbl.clear t.durations ;
        Gauge.reset t.simult

    (* The event is over at the time the caller says it is: only the caller
     * knows which clock was running while it lasted. *)
    type stop_func = now:Clock.Time.t -> Params.t -> unit

    let record t params duration =
        Hashtbl.modify_opt params (function
            | None ->
                Some {
                    min = duration ;
                    max = duration ;
                    sum = duration ;
                    count = 1 ;
                    sample_min = Some duration ;
                    sample_max = Some duration }
            | Some d ->
                let keep f = function
                    | None -> Some duration
                    | Some d -> Some (f d duration) in
                Some {
                    min = min d.min duration ;
                    max = max d.max duration ;
                    sum = Clock.Interval.add d.sum duration ;
                    count = d.count + 1 ;
                    sample_min = keep min d.sample_min ;
                    sample_max = keep max d.sample_max }
        ) t.durations

    (* Read every row and start a new window, which holds nothing until
     * something else is measured. *)
    let take_windows t =
        let rows =
            Hashtbl.fold (fun params d l -> (params, d) :: l) t.durations [] in
        List.iter (fun (params, d) ->
            Hashtbl.replace t.durations params
                { d with sample_min = None ; sample_max = None }
        ) rows ;
        rows

    let start ~now:start_time ?(params=Params.empty) t : stop_func =
        Gauge.succ ~now:start_time ~params t.simult ;
        (* Return the stop function: *)
        fun ~now extra_params ->
            let params = Params.add params extra_params in
            Atomic.fire ~now:start_time ~params t.starts ;
            Atomic.fire ~now ~params t.stops ;
            Gauge.pred ~now ~params t.simult ;
            let duration = Clock.Time.diff now start_time in
            record t params duration

    (* [clock] rather than a timestamp: this one spans the call to [f], so it
     * has to read the time twice. *)
    let timed ~clock ?(params=Params.empty) t f =
        let start_time = clock () in
        Gauge.succ ~now:start_time ~params t.simult ;
        match f () with
        | exception e ->
            let bt = Printexc.get_raw_backtrace () in
            Atomic.fire ~now:start_time ~params t.starts ;
            Gauge.pred ~now:(clock ()) ~params t.simult ;
            Printexc.raise_with_backtrace e bt
        | extra_params, res->
            let now = clock () in
            let params = Params.add params extra_params in
            Atomic.fire ~now:start_time ~params t.starts ;
            Atomic.fire ~now ~params t.stops ;
            Gauge.pred ~now ~params t.simult ;
            let duration = Clock.Time.diff now start_time in
            record t params duration ;
            res

    let print oc t =
        Printf.fprintf oc "durations: %a"
            (Params.print_hash
                (fun oc d ->
                    let open Clock.Interval in
                    Printf.fprintf oc "min:%s, avg:%s, max:%s, count:%d"
                        (to_string d.min)
                        (to_string (mul d.sum (1. /. float_of_int d.count)))
                        (to_string d.max)
                        d.count)
            ) t.durations
end

(* Whatever the kind, one of these. The dispatch is written out rather than
 * derived: every kind names its constructor [T], so the tag the ppx would emit
 * says nothing, while the reader needs to know a counter from a gauge. *)

(* What a metric is worth at one instant: the figures a plot can be drawn from,
 * one entry per parameter combination. A metric's kind is what says which of
 * these it yields, so a series always knows how to read its own points.
 *
 * The bare figures, and not what surrounds them: when a metric was first and
 * last touched, or how many times a counter was added to, tell the reader
 * about the metric as it stands, not about the instant a sample was taken. *)
type value =
    (* How many times, for an [Atomic]; how much, for a [Counter]. *)
    | Count of int
    | Value of Gauge.value
    | Durations of Timed.duration

(* Everything a metric holds right now, as a list because that is what a
 * snapshot does with it: read it once and move on.
 *
 * A verb, because reading is not without effect: it closes the window that the
 * [sample_min] and [sample_max] of a gauge or a duration describe, and opens
 * the next one. Sample a metric from one place only -- the simulation that
 * owns it does, once per period -- or those two figures end up describing
 * whatever happened since some other caller last looked. *)
let sample m =
    let of_table wrap l = List.map (fun (params, v) -> params, wrap v) l in
    let all h = Hashtbl.fold (fun params v l -> (params, v) :: l) h [] in
    match m with
    | Atomic.T t -> of_table (fun c -> Count c) (all t.Atomic.counts)
    | Counter.T t -> of_table (fun c -> Count c) (all t.Counter.values)
    | Gauge.T t -> of_table (fun v -> Value v) (Gauge.take_windows t)
    | Timed.T t -> of_table (fun d -> Durations d) (Timed.take_windows t)
    | _ -> invalid_arg "Metric.sample: unknown kind of metric"

(* As the interface reads them: a count is a number, and the other two are the
 * objects their own serializers give -- the same shapes a metric's current
 * figures already arrive in, so a point and a live value read alike. *)
let value_to_yojson = function
    | Count c -> `Int c
    | Value v -> Gauge.value_to_yojson v
    | Durations d -> Timed.duration_to_yojson d

let value_to_json v = Yojson.Safe.to_basic (value_to_yojson v)

(*$T sample
  sample (Atomic.T (Atomic.make ())) = []
  (let a = Atomic.make () in let params = Params.singleton "port" (Param.Int 2) in Atomic.fire ~now:(Clock.Time.o 1.) ~params a ; Atomic.fire ~now:(Clock.Time.o 3.) ~params a ; sample (Atomic.T a) = [ params, Count 2 ])
  (let g = Gauge.make () in Gauge.set ~now:(Clock.Time.o 1.) g 5 ; sample (Gauge.T g) = [ Params.empty, Value { min = 5 ; current = 5 ; max = 5 ; sample_min = 5 ; sample_max = 5 } ])
  (* The window is what happened since the last sample; the extremes beside it are those since the metric began. *) \
  (let now = Clock.Time.o 1. in let g = Gauge.make () in Gauge.set ~now g 5 ; Gauge.set ~now g 1 ; ignore (sample (Gauge.T g)) ; Gauge.set ~now g 3 ; sample (Gauge.T g) = [ Params.empty, Value { min = 1 ; current = 3 ; max = 5 ; sample_min = 1 ; sample_max = 3 } ])
  (* Nothing having moved, the window is the value standing still. *) \
  (let now = Clock.Time.o 1. in let g = Gauge.make () in Gauge.set ~now g 5 ; Gauge.set ~now g 2 ; ignore (sample (Gauge.T g)) ; sample (Gauge.T g) = [ Params.empty, Value { min = 2 ; current = 2 ; max = 5 ; sample_min = 2 ; sample_max = 2 } ])
  (* A duration's window holds nothing until one is measured in it, which is not the same as a duration of zero. *) \
  (let t = Timed.make () in let stop = Timed.start ~now:(Clock.Time.o 1.) t in stop ~now:(Clock.Time.o 3.) Params.empty ; (match sample (Timed.T t) with [ _, Durations d ] -> d.count = 1 && d.sample_min = Some (Clock.Interval.o 2.) && d.sample_max = Some (Clock.Interval.o 2.) | _ -> false) && (match sample (Timed.T t) with [ _, Durations d ] -> d.count = 1 && d.sample_min = None && d.sample_max = None | _ -> false))
 *)

(* Which of them it is. A metric never changes kind, so this is what tells the
 * interface how to display one, before and independently of its figures. *)
let kind_name = function
    | Atomic.T _ -> "atomic"
    | Gauge.T _ -> "gauge"
    | Counter.T _ -> "counter"
    | Timed.T _ -> "timed"
    | _ -> invalid_arg "Metric.kind_name: unknown kind of metric"

let to_yojson m =
    let tagged = function
        | `Assoc fields -> `Assoc (("kind", `String (kind_name m)) :: fields)
        | json -> json in
    match m with
    | Atomic.T t -> tagged (Atomic.to_yojson t)
    | Gauge.T t -> tagged (Gauge.to_yojson t)
    | Counter.T t -> tagged (Counter.to_yojson t)
    | Timed.T t -> tagged (Timed.to_yojson t)
    | _ -> invalid_arg "Metric.to_yojson: unknown kind of metric"

(* What the administration interface speaks. *)
let to_json m = Yojson.Safe.to_basic (to_yojson m)

(*$T to_json
  (match to_json (Counter.T (Counter.make ())) with \
   | `Assoc l -> List.assoc "kind" l = `String "counter" \
   | _ -> false)
  (* Never fired: not "fired at the epoch". *) \
  (match to_json (Atomic.T (Atomic.make ())) with \
   | `Assoc l -> List.assoc "first_last" l = `Null \
   | _ -> false)
  (* A family, keyed by the parameters of the events. *) \
  (let a = Atomic.make () in \
   let params = Params.singleton "port" (Param.Int 2) in \
   Atomic.fire ~now:(Clock.Time.o 1.) ~params a ; \
   Atomic.fire ~now:(Clock.Time.o 3.) ~params a ; \
   match to_json (Atomic.T a) with \
   | `Assoc l -> \
       List.assoc "counts" l = \
           `List [ `Assoc [ "params", `Assoc [ "port", `Int 2 ] ; \
                            "value", `Int 2 ] ] && \
       List.assoc "first_last" l = \
           `Assoc [ "first", `Float 1. ; "last", `Float 3. ] \
   | _ -> false)
 *)

let print oc = function
    | Atomic.T t -> Atomic.print oc t
    | Gauge.T t -> Gauge.print oc t
    | Counter.T t -> Counter.print oc t
    | Timed.T t -> Timed.print oc t
    | _ -> invalid_arg "Metric.print: unknown kind of metric"

let reset = function
    | Atomic.T t -> Atomic.reset t
    | Gauge.T t -> Gauge.reset t
    | Counter.T t -> Counter.reset t
    | Timed.T t -> Timed.reset t
    | _ -> invalid_arg "Metric.reset: unknown kind of metric"

let params = function
    | Atomic.T t -> Hashtbl.keys t.counts
    | Gauge.T t -> Hashtbl.keys t.values
    | Counter.T t -> Hashtbl.keys t.values
    | Timed.T t -> Hashtbl.keys t.durations
    | _ -> invalid_arg "Metric.params: unknown kind of metric"

let has_data metric =
    not (Enum.is_empty (params metric))
