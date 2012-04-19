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
  We keep lazyly the last N messages of every log levels.
*)
open Batteries
open Tools

(* Basically, Info is the lowest thing you want to see by default. *)
type level  = Critical | Error | Warning | Info | Debug
type msg    = Clock.Time.t * (string Lazy.t)
type queue  = int * msg array
type logger = { name : string ; queues : queue array }

(* log level <-> queue index *)

let int_of_level = function Critical -> 0 | Error -> 1 | Warning -> 2 | Info -> 3 | Debug -> 4
let nb_levels = 5

(* output to console happen based on a constant current loglevel *)

let console_lvl = ref Warning
let console_log name (t, lstr) =
    Printf.printf "%a: %s: %s\n%!" Clock.printer t name (Lazy.force lstr)

(* queue management *)

let enqueue (qs, ar) m =
    let next_wrap max v = if v >= max-1 then 0 else v+1 in
    ar.(qs) <- m ;
    next_wrap (Array.length ar) qs, ar

let queue_iter f (qs, ar) = (* TODO: ?(order=DESC) *)
    let aux i =
        let t, lstr = ar.(i) in
        let str = Lazy.force lstr in
        if String.length str > 0 then f t str in
    for i = qs-1 downto 0 do aux i done ;
    for i = (Array.length ar) - 1 downto qs do aux i done

(* log *)

let log logger level lstr =
    let lvl = int_of_level level
    and msg = Clock.now (), lstr in
    logger.queues.(lvl) <- enqueue logger.queues.(lvl) msg ;
    if lvl <= int_of_level !console_lvl then console_log logger.name msg

(* creation *)

let make_queue size =
    0, Array.create size (Clock.Time.o 0., lazy "")

let loggers = Hashtbl.create 131

let make name size =
    let logger = {
        name ;
        queues = Array.init nb_levels (fun _ -> make_queue size)
    } in
    Hashtbl.add loggers name logger ;
    logger

