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
      msgs : msg array }

type logger =
    { name : string ;
      full_name : string ;
      use_wall_clock : bool ;
      queues : queue array ;
      (* We want to be able to navigate the logs/stats/characteristics of
       * every simulated things.
       * Things are connected with TRX in various ways, sometime "vertically",
       * as a stack of layers to assemble composed objects (ex: a service with
       * a host with an HTTP layer with a TCP layer with an IP layer with an
       * ETH layer), and sometimes "horizontally" as connections between various
       * objects, mostly via cables.
       * From the point of view of the simulator, all these are just trxs
       * connected together.
       * That's only when the loggers are constructed that those relationships
       * are indicated.
       *
       * TODO: logger is becoming a base "connected thing" object. Make it so?
       * Not the same things as a trx though, as trxs are linear.
       *
       * Parent / children: loggers form a hierarchy. The full_name of a logger
       * indicate that hierarchy. *)
      parent : logger option ;
      mutable children : logger list ;
      (* Siblings: When loggers are connected "horizontally" to others.
       * Loggers names are then unrelated. *)
      mutable peers : peer list }

and peer = { logger : logger ; via : logger option }

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
let console_log name =
    let name = if name = "" then name else name ^": " in
    fun (t, lstr) ->
        Printf.printf "%a: %s%s\n%!" Clock.printer t name (Lazy.force lstr)

(* queue management *)

let make_queue size =
    { oldest = 0 ; msgs = Array.create size (Clock.Time.o 0., lazy "") }

let enqueue q m =
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
        Enum.make (next cursor) (count cursor) (clone cursor)
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

(* log *)

let log logger level lstr =
    let lvl = int_of_level level in
    let now =
        if logger.use_wall_clock then
            Clock.Time.wall_clock ()
        else
            Clock.now () in
    let msg = now, lstr in
    enqueue logger.queues.(lvl) msg ;
    if lvl <= int_of_level !console_lvl then console_log logger.full_name msg ;
    assert (level <> Fatal)

let log_exceptions logger ?(level=Warning) what f x =
    try
        f x
    with e ->
        log logger level (lazy (
            Printf.sprintf "Ignoring exception %s while performing %s"
                (Printexc.to_string e)
                what))

(* creation *)

(* All existing loggers are known so we can display them in the GUI.
 * Indexed by a list of names, from indexed logger to ancestor: *)
let loggers = Hashtbl.create 131

let make ?parent ?(use_wall_clock=false) ?(size=50) name =
    let full_name =
        let rec loop full_name = function
            | None -> full_name
            | Some p ->
                let full_name = "/"^ p.name ^ full_name in
                loop full_name p.parent in
        loop ("/"^ name) parent in
    let logger = {
        name ;
        full_name ;
        use_wall_clock ;
        queues = Array.init num_levels (fun _ -> make_queue size) ;
        parent ;
        children = [] ;
        peers = [] } in
    Option.may (fun p -> p.children <- logger :: p.children) parent ;
    Hashtbl.add loggers full_name logger ;
    logger

let sub logger ?size name =
    let size = size |? Array.length logger.queues.(0).msgs in
    make ~parent:logger ~use_wall_clock:logger.use_wall_clock ~size name

let make_peers ?via l1 l2 =
    l1.peers <- { logger = l2 ; via } :: l1.peers ;
    l2.peers <- { logger = l1 ; via } :: l2.peers ;
    Option.may (fun via ->
        via.peers <- { logger = l1 ; via = None } ::
                     { logger = l2 ; via = None } :: via.peers
    ) via

(* The logger that will adopt any others: *)

let default = make ""
