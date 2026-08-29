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
  Logging facility

  We keep lazily the last N messages of every log levels.
  Additionally, messages of higher level than some threshold are copied onto stderr.
*)
open Batteries

(* Basically, Info is the lowest thing you want to see by default. *)
(* TODO: several Debug level? *)
type level  = Fatal | Critical | Error | Warning | Info | Debug

type msg = Clock.Time.t * (string Lazy.t)

type queue  =
    { mutable oldest : int ; (* points to the next to be overwritten *)
      (* How many of [msgs] hold a message: the array fills up once, and from
       * then on every write overwrites an older message. *)
      mutable len : int ;
      (* When the message that was overwritten last had been logged, if any.
       * A reader asking for everything logged after some time can then be told
       * that part of what it asked for is already gone -- which a log window
       * must say, or it quietly claims a continuity it does not have. *)
      mutable purged : Clock.Time.t option ;
      msgs : msg array }

type t =
    { (* Where this logger reads the time. Defaults to the wall clock, which is
       * the only time there is for a logger belonging to no simulation (a
       * parser, a tool). Widget points its widgets' loggers at their own
       * simulation's clock -- their own, note, not whichever simulation the
       * thread doing the logging happens to be running. *)
      now : unit -> Clock.Time.t ;
      queues : queue array }

(* log level <-> queue index *)

let int_of_level = function
    | Fatal -> 0
    | Critical -> 1
    | Error -> 2
    | Warning -> 3
    | Info -> 4
    | Debug -> 5

let level_of_int = function
    | 0 -> Fatal
    | 1 -> Critical
    | 2 -> Error
    | 3 -> Warning
    | 4 -> Info
    | 5 -> Debug
    | _ -> invalid_arg "Log.level_of_int"

let num_levels = 6
let max_level = num_levels - 1

let string_of_level = function
    | Fatal -> "fatal"
    | Critical -> "critical"
    | Error -> "error"
    | Warning -> "warning"
    | Info -> "info"
    | Debug -> "debug"

let string_of_int_level = string_of_level % level_of_int

(* output to console happen based on a constant current loglevel *)

let console_lvl = ref Error
let console_log (t, lstr) =
    Printf.printf "%a: %s\n%!" Clock.Time.printf t (Lazy.force lstr)

(* queue management *)

let make_queue size =
    { oldest = 0 ; len = 0 ; purged = None ;
      msgs = Array.create size (Clock.Time.o 0., lazy "") }

let enqueue q m =
    if q.len >= Array.length q.msgs then
        (* What is about to be overwritten is lost from here on: remember when
         * it was logged. Only the time, and only the last one: what a reader
         * needs to know is whether anything is missing from what it asked
         * for, not how much. *)
        q.purged <- Some (fst q.msgs.(q.oldest))
    else
        q.len <- q.len + 1 ;
    q.msgs.(q.oldest) <- m ;
    q.oldest <- if q.oldest + 1 >= Array.length q.msgs then 0 else q.oldest + 1

type queue_cursor = { mutable next : int ; mutable wrapped : bool }

let queue_enum q =
    let rec next cursor () =
        (* cursor points to the next entry to output: *)
        let i = cursor.next in
        let i =
            if i >= Array.length q.msgs then
                if cursor.wrapped then raise Enum.No_more_elements
                else (cursor.wrapped <- true ; 0)
            else i in
        let i =
            if i >= q.oldest && cursor.wrapped then
                raise Enum.No_more_elements
            else i in
        cursor.next <- i + 1 ; (* for next iteration *)
        q.msgs.(i)
    and count cursor () =
        let l = q.oldest - cursor.next in
        if l <= 0 then
            if not cursor.wrapped then l + Array.length q.msgs
            else 0
        else l
    and clone cursor () =
        let cursor = { cursor with next = cursor.next } in (* Copy the cursor *)
        make cursor
    and make cursor =
        Enum.make ~next:(next cursor) ~count:(count cursor) ~clone:(clone cursor)
    in
    let cursor = { next = q.oldest ; wrapped = false } in
    let e = make cursor in
    (* Advance cursor as strings are empty or we moved back to oldest: *)
    Enum.drop_while (fun (_, s) -> Lazy.force s = "") e

(*$inject
  let queue_of_list ?(size=3) msgs =
    let q = make_queue size in
    List.iteri (fun i s ->
        let t = Clock.Time.o (float_of_int i) in
        enqueue q (t, lazy s)
    ) msgs ;
    q
 *)
(*$= queue_enum & ~printer:(fun lst -> String.concat "," (List.map (Lazy.force % snd) lst))
  [] \
        (List.of_enum (queue_enum (queue_of_list [])))
  [ Clock.Time.o 0., lazy "glop" ] \
        (List.of_enum (queue_enum (queue_of_list [ "glop" ])))
  [ Clock.Time.o 0., lazy "glop" ; \
    Clock.Time.o 1., lazy "pas glop" ] \
        (List.of_enum (queue_enum (queue_of_list [ "glop" ; "pas glop" ])))
  [ Clock.Time.o 0., lazy "glop" ; \
    Clock.Time.o 1., lazy "glop glop" ; \
    Clock.Time.o 2., lazy "pas glop" ] \
        (List.of_enum (queue_enum (queue_of_list [ "glop" ; "glop glop" ; \
                                                   "pas glop" ])))
  [ Clock.Time.o 1., lazy "glop glop" ; \
    Clock.Time.o 2., lazy "pas glop" ; \
    Clock.Time.o 3., lazy "glop pas glop" ] \
        (List.of_enum (queue_enum (queue_of_list [ "glop" ; "glop glop" ; \
                                                   "pas glop" ; "glop pas glop" ])))
*)

(*$= queue_enum & ~printer:string_of_int
  0  (Enum.count (queue_enum (queue_of_list [])))
  1  (Enum.count (queue_enum (queue_of_list [ "glop" ])))
  2  (Enum.count (queue_enum (queue_of_list [ "glop" ; "pas glop" ])))
  3  (Enum.count (queue_enum (queue_of_list [ "glop" ; "glop glop" ; \
                                              "pas glop" ])))
  3  (Enum.count (queue_enum (queue_of_list [ "glop" ; "glop glop" ; \
                                              "pas glop" ; "glop pas glop" ])))
*)

(** Everything a logger holds, oldest first: the messages of every level up to
 * [max_level] that were logged strictly after [since], and whether anything
 * that would have answered has already been overwritten.
 *
 * [since] is exclusive and needs no more than a time to be exact. A logger
 * belonging to a simulation is stamped with that simulation's clock, which
 * stands still for the whole of an event dispatch, and no two events are ever
 * scheduled at the same instant (see [Simulation.at]); so one timestamp is one
 * dispatch, a reader holding the simulation's lock sees all of a dispatch's
 * messages or none of them, and "everything after t" cannot cut a dispatch in
 * half. What can slip through is a message logged by another thread at the
 * current time, out of any dispatch, after a reader has already been given
 * that instant -- a ping asked for from the outside, say.
 *
 * Messages logged at the same instant keep the order they were logged in
 * within one level, and are ordered by level between them: the queues are per
 * level, so the true interleaving of a debug and an info message logged one
 * after the other is not recorded anywhere. *)
let messages ?since ?(max_level=max_level) t =
    let after (ts, _) =
        match since with
        | None -> true
        | Some (since : Clock.Time.t) -> Clock.Time.compare ts since > 0 in
    let lost =
        match since with
        | None ->
            (* Nothing was asked for, so nothing can be missing from it: a
             * reader with no history yet has lost nothing. *)
            false
        | Some since ->
            Enum.range 0 ~until:max_level |>
            Enum.exists (fun lvl ->
                match t.queues.(lvl).purged with
                | Some p -> Clock.Time.compare p since > 0
                | None -> false) in
    let msgs =
        Enum.range 0 ~until:max_level |>
        Enum.map (fun lvl ->
            queue_enum t.queues.(lvl) //
            after /@
            (fun (ts, lstr) -> ts, level_of_int lvl, Lazy.force lstr)) |>
        Enum.flatten |>
        List.of_enum in
    (* Stable, so that the messages of one level stay in the order they were
     * logged in when they share a timestamp. *)
    lost, List.stable_sort (fun (t1, _, _) (t2, _, _) ->
              Clock.Time.compare t1 t2) msgs

(*$inject
  let logged ?since ?max_level msgs =
    let t = make ~size:2 ~now:(fun () -> Clock.Time.o 0.) () in
    List.iter (fun (ts, lvl, s) ->
      enqueue t.queues.(int_of_level lvl) (Clock.Time.o ts, lazy s)) msgs ;
    let lost, msgs = messages ?since ?max_level t in
    lost, List.map (fun (ts, lvl, s) ->
      (ts : Clock.Time.t :> float), string_of_level lvl, s) msgs
 *)
(*$= logged & ~printer:dump
  (false, []) (logged [])
  (false, [ 1., "info", "a" ; 2., "error", "b" ])     (logged [ 1., Info, "a" ; 2., Error, "b" ])
  (* [since] is exclusive, and what it leaves out is not lost: it was read. *)   (false, [ 2., "error", "b" ])     (logged ~since:(Clock.Time.o 1.) [ 1., Info, "a" ; 2., Error, "b" ])
  (* A level nobody asked for is not read at all. *)   (false, [ 2., "error", "b" ])     (logged ~max_level:(int_of_level Error) [ 1., Info, "a" ; 2., Error, "b" ])
  (* Two of that level fit; the third pushes the first out, and a reader that      had asked for everything after it is told so. *)   (true, [ 2., "info", "b" ; 3., "info", "c" ])     (logged ~since:(Clock.Time.o 0.5)       [ 1., Info, "a" ; 2., Info, "b" ; 3., Info, "c" ])
  (* But not one that had already read it. *)   (false, [ 3., "info", "c" ])     (logged ~since:(Clock.Time.o 2.)       [ 1., Info, "a" ; 2., Info, "b" ; 3., Info, "c" ])
  (* Of one instant, every level, most serious first. *)   (false, [ 1., "error", "b" ; 1., "info", "a" ; 1., "info", "c" ])     (logged [ 1., Info, "a" ; 1., Error, "b" ; 1., Info, "c" ])
 *)

(* log *)

let log t level lstr =
    let lvl = int_of_level level in
    let now = t.now () in
    let msg = now, lstr in
    enqueue t.queues.(lvl) msg ;
    if lvl <= int_of_level !console_lvl then console_log msg ;
    assert (level <> Fatal)

let log_exceptions t ?(level=Warning) what f x =
    try
        f x
    with e ->
        log t level (lazy (
            Printf.sprintf "Ignoring exception %s while performing %s"
                (Printexc.to_string e)
                what))

let make ?(size=50) ?(now=Clock.Time.wall_clock) () =
    { now ; queues = Array.init num_levels (fun _ -> make_queue size) }

(* The logger that will adopt any others: *)

let default = make ()
