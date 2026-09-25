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

(* A message is a number, an instant and what it says.
 *
 * The number is what a reader keeps its place by, and the reason it is not the
 * instant: a simulation's clock stands still between two events, so several
 * messages share one, and "everything after that instant" then loses the ones
 * logged at it -- which is exactly what a thread outside the dispatcher does,
 * the administration interface every time it switches something. The instant
 * is a label on a message; this is its identity. *)
type msg = int * Clock.Time.t * (string Lazy.t)

type queue  =
    { mutable oldest : int ; (* points to the next to be overwritten *)
      (* How many of [msgs] hold a message: the array fills up once, and from
       * then on every write overwrites an older message. *)
      mutable len : int ;
      (* Which message was overwritten last, if any. A reader asking for
       * everything logged after some message can then be told that part of
       * what it asked for is already gone -- which a log window must say, or
       * it quietly claims a continuity it does not have. *)
      mutable purged : int option ;
      msgs : msg array }

type t =
    { (* Where this logger reads the time. Defaults to the wall clock, which is
       * the only time there is for a logger belonging to no simulation (a
       * parser, a tool). Widget points its widgets' loggers at their own
       * simulation's clock -- their own, note, not whichever simulation the
       * thread doing the logging happens to be running. *)
      now : unit -> Clock.Time.t ;
      (* Where it takes the number to stamp the next message with. One counter
       * per simulation, handed down from its root widget to every logger
       * below, so that the numbers of two widgets of one simulation can be
       * compared -- and so that nothing has to be unique across a process
       * that runs several. A logger belonging to no simulation counts on its
       * own. *)
      seq : unit -> int ;
      queues : queue array ;
      (* The deepest level stored: what is deeper is dropped as it is logged. *)
      mutable keep : int ;
      (* After that time, [keep] goes back to [default_keep]. *)
      mutable lease_until : float }

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

(* What a logger stores with no reader asking for more. *)
let default_keep = int_of_level Info

let console_log (_seq, t, lstr) =
    Printf.printf "%a: %s\n%!" Clock.Time.printf t (Lazy.force lstr)

(* queue management *)

let make_queue size =
    { oldest = 0 ; len = 0 ; purged = None ;
      msgs = Array.create size (0, Clock.Time.zero, lazy "") }

let enqueue q m =
    if q.len >= Array.length q.msgs then
        (* What is about to be overwritten is lost from here on: remember
         * which one it was. Only the number, and only of the last one: what a
         * reader needs to know is whether anything is missing from what it
         * asked for, not how much. *)
        q.purged <- Some (let seq, _, _ = q.msgs.(q.oldest) in seq)
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
    Enum.drop_while (fun (_, _, s) -> Lazy.force s = "") e

(*$inject
  let queue_of_list ?(size=3) msgs =
    let q = make_queue size in
    List.iteri (fun i s ->
        let t = Clock.Time.of_secs (float_of_int i) in
        enqueue q (i + 1, t, lazy s)
    ) msgs ;
    q
 *)
(*$= queue_enum & ~printer:(fun lst -> String.concat "," (List.map (fun (_, _, s) -> Lazy.force s) lst))
  [] \
        (List.of_enum (queue_enum (queue_of_list [])))
  [ 1, Clock.Time.of_secs 0., lazy "glop" ] \
        (List.of_enum (queue_enum (queue_of_list [ "glop" ])))
  [ 1, Clock.Time.of_secs 0., lazy "glop" ; \
    2, Clock.Time.of_secs 1., lazy "pas glop" ] \
        (List.of_enum (queue_enum (queue_of_list [ "glop" ; "pas glop" ])))
  [ 1, Clock.Time.of_secs 0., lazy "glop" ; \
    2, Clock.Time.of_secs 1., lazy "glop glop" ; \
    3, Clock.Time.of_secs 2., lazy "pas glop" ] \
        (List.of_enum (queue_enum (queue_of_list [ "glop" ; "glop glop" ; \
                                                   "pas glop" ])))
  [ 2, Clock.Time.of_secs 1., lazy "glop glop" ; \
    3, Clock.Time.of_secs 2., lazy "pas glop" ; \
    4, Clock.Time.of_secs 3., lazy "glop pas glop" ] \
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
 * [max_level] that were logged after the message numbered [since], and whether
 * anything that would have answered has already been overwritten.
 *
 * [since] is exclusive, and is a message and not an instant. It used to be an
 * instant, and that lost messages: a simulation's clock stands still between
 * two events, so everything logged within one dispatch shares a timestamp, and
 * so does everything a thread outside the dispatcher logs while the clock
 * waits. A reader given the last message of an instant, asking for what came
 * after it, was then never shown the rest of that instant -- which the
 * administration interface hit every time it switched a device: the line
 * saying so was logged from its own thread, at a time the reader already had.
 * It showed up at one log level and not at the next, since a level that
 * delivers more messages is a level whose reader is more likely to be holding
 * the current instant already.
 *
 * A reader holding the simulation's lock still sees all of a dispatch or none
 * of it, which is what matters for reading one: the numbers within a dispatch
 * are consecutive, and nothing else can log in the middle of one.
 *
 * Messages come back in the order they were logged, whatever their level: the
 * queues are per level, and these numbers are the only record of how the two
 * interleaved. *)
let messages ?since ?(max_level=max_level) t =
    let after (seq, _, _) =
        match since with
        | None -> true
        | Some since -> seq > since in
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
                | Some p -> p > since
                | None -> false) in
    let msgs =
        Enum.range 0 ~until:max_level |>
        Enum.map (fun lvl ->
            queue_enum t.queues.(lvl) //
            after /@
            (fun (seq, ts, lstr) ->
                seq, ts, level_of_int lvl, Lazy.force lstr)) |>
        Enum.flatten |>
        List.of_enum in
    (* By the order they were logged in, which is what the numbers are: the
     * queues are per level, so this is the only place the interleaving of a
     * debug and an info message logged one after the other is recovered. *)
    lost, List.sort (fun (s1, _, _, _) (s2, _, _, _) -> compare s1 s2) msgs

(*$inject
  let logged ?since ?max_level msgs =
    let t = make ~size:2 ~now:(fun () -> Clock.Time.zero) () in
    List.iteri (fun i (ts, lvl, s) ->
      enqueue t.queues.(int_of_level lvl)
              (i + 1, Clock.Time.of_secs ts, lazy s)) msgs ;
    let lost, msgs = messages ?since ?max_level t in
    lost, List.map (fun (_seq, ts, lvl, s) ->
      Clock.Time.to_secs ts, string_of_level lvl, s) msgs
 *)
(*$= logged & ~printer:dump
  (false, []) (logged [])
  (false, [ 1., "info", "a" ; 2., "error", "b" ]) \
    (logged [ 1., Info, "a" ; 2., Error, "b" ])
  (* [since] is exclusive, and names a message: what it leaves out is not \
     lost, it was read. *) \
  (false, [ 2., "error", "b" ]) \
    (logged ~since:1 [ 1., Info, "a" ; 2., Error, "b" ])
  (* A level nobody asked for is not read at all. *) \
  (false, [ 2., "error", "b" ]) \
    (logged ~max_level:(int_of_level Error) [ 1., Info, "a" ; 2., Error, "b" ])
  (* Two of that level fit; the third pushes the first out, and a reader that \
     had asked for everything is told so. *) \
  (true, [ 2., "info", "b" ; 3., "info", "c" ]) \
    (logged ~since:0 [ 1., Info, "a" ; 2., Info, "b" ; 3., Info, "c" ])
  (* But not one that had already read it. *) \
  (false, [ 3., "info", "c" ]) \
    (logged ~since:2 [ 1., Info, "a" ; 2., Info, "b" ; 3., Info, "c" ])
  (* Of one instant, in the order they were logged, whatever their level: \
     that is what the numbers are for, and what an instant cannot say. *) \
  (false, [ 1., "info", "a" ; 1., "error", "b" ; 1., "info", "c" ]) \
    (logged [ 1., Info, "a" ; 1., Error, "b" ; 1., Info, "c" ])
 *)

(* And the failure this cursor exists for: a clock that stands still stamps
   several messages with one instant, so a reader given the first of them and
   asking for what came after used to be shown none of the rest. Which is what
   the administration interface does every time it switches something: the
   line saying so is logged from its own thread, at an instant the reader
   already has. *)
(*$= logged & ~printer:dump
  (false, [ 1., "info", "b" ]) \
    (logged ~since:1 [ 1., Info, "a" ; 1., Info, "b" ])
 *)

(* log *)

(** Whether a message of that level would be kept.
 * Ask first before a very frequent log, to save the closure. *)
let wants t level =
    let lvl = int_of_level level in
    lvl <= default_keep || lvl <= int_of_level !console_lvl ||
    lvl <= t.keep ||
    Unix.gettimeofday () < t.lease_until ||
    (t.keep <- default_keep ; false)

(** Keep what is logged down to [max_level] for [secs] more seconds of wall
 * clock, on behalf of a reader who will be back for it by then. Of several
 * readers, the deepest level and the latest end are kept. *)
let lease t max_level secs =
    let now = Unix.gettimeofday () in
    if now >= t.lease_until then t.keep <- default_keep ;
    t.keep <- max t.keep max_level ;
    t.lease_until <- max t.lease_until (now +. secs)

let log t level lstr =
    if wants t level then (
        let lvl = int_of_level level in
        let now = t.now () in
        let msg = t.seq (), now, lstr in
        enqueue t.queues.(lvl) msg ;
        if lvl <= int_of_level !console_lvl then console_log msg) ;
    assert (level <> Fatal)

let log_exceptions t ?(level=Warning) what f x =
    try
        f x
    with e ->
        log t level (lazy (
            Printf.sprintf "Ignoring exception %s while performing %s"
                (Printexc.to_string e)
                what))

let make ?(size=50) ?(now=Clock.Time.since_start) ?seq () =
    let seq =
        match seq with
        | Some seq -> seq
        | None ->
            (* A logger belonging to no simulation, counting for itself. *)
            let n = ref 0 in
            fun () -> incr n ; !n in
    { now ; seq ; queues = Array.init num_levels (fun _ -> make_queue size) ;
      keep = default_keep ; lease_until = 0. }

(*$T lease
  let t = make () in \
  log t Debug (lazy "dropped") ; \
  lease t (int_of_level Debug) 60. ; \
  log t Debug (lazy "kept") ; \
  List.map (fun (_, _, _, s) -> s) (snd (messages t)) = [ "kept" ]
  let t = make () in \
  lease t (int_of_level Debug) 0. ; \
  log t Debug (lazy "too late") ; log t Info (lazy "kept") ; \
  List.map (fun (_, _, _, s) -> s) (snd (messages t)) = [ "kept" ]
*)

(* The logger that will adopt any others: *)

let default = make ()
