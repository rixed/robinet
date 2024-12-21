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
type level  = Fatal | Critical | Error | Warning | Info | Debug

type msg    = Clock.Time.t * (string Lazy.t)

type queue  =
    { mutable head : int ; (* points to the last message enqueued *)
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
      mutable siblings : sibling list }

and sibling = { peer : logger ; via : logger option }

(* log level <-> queue index *)

let int_of_level = function
    | Fatal -> 0
    | Critical -> 1
    | Error -> 2
    | Warning -> 3
    | Info -> 4
    | Debug -> 5

let num_levels = 6

(* output to console happen based on a constant current loglevel *)

let console_lvl = ref Error
let console_log name =
    let name = if name = "" then name else name ^": " in
    fun (t, lstr) ->
        Printf.printf "%a: %s%s\n%!" Clock.printer t name (Lazy.force lstr)

(* queue management *)

let enqueue q m =
    q.msgs.(q.head) <- m ;
    q.head <- if q.head >= Array.length q.msgs - 1 then 0 else q.head + 1

let queue_iter f q = (* TODO: ?(order=DESC) *)
    let aux i =
        let t, lstr = q.msgs.(i) in
        let str = Lazy.force lstr in
        if str <> "" then f t str in
    for i = q.head - 1 downto 0 do aux i done ;
    for i = Array.length q.msgs - 1 downto q.head do aux i done

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

let make_queue size =
    { head = 0 ; msgs = Array.create size (Clock.Time.o 0., lazy "") }

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
        siblings = [] } in
    Option.may (fun p -> p.children <- logger :: p.children) parent ;
    Hashtbl.add loggers full_name logger ;
    logger

let sub logger ?size name =
    let size = size |? Array.length logger.queues.(0).msgs in
    make ~parent:logger ~use_wall_clock:logger.use_wall_clock ~size name

let make_siblings ?via l1 l2 =
    l1.siblings <- { peer = l2 ; via } :: l1.siblings ;
    l2.siblings <- { peer = l1 ; via } :: l2.siblings ;
    Option.may (fun via ->
        via.siblings <- { peer = l1 ; via = None } ::
                        { peer = l2 ; via = None } :: via.siblings
    ) via

(* The logger that will adopt any others: *)

let default = make ""
