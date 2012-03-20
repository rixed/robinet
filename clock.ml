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
   This module creates an alarm-clock that orders registered events.
*)
open Batteries
open Bitstring
open Tools

let debug = false

let realtime = ref true

type time = float

let date_and_time = false

let string_of_time t =
    let open Unix in
    let tm = localtime t in
    let msec = Float.round_to_int (100. *. (fst (modf t))) in
    if date_and_time then
        Printf.sprintf "%d-%02d-%02d %02d:%02d:%02d.%02d"
            (1900+tm.tm_year) (1+tm.tm_mon) tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec msec
    else
        Printf.sprintf "%02d:%02d:%02d.%02d"
            tm.tm_hour tm.tm_min tm.tm_sec msec

let time_printer fmt (t : time) = (* for the toplevel *)
    Format.fprintf fmt "@{<time>%s@}" (string_of_time t)

(* poor man's asctime *)
let print oc t = BatIO.nwrite oc (string_of_time t)

let usec i = i *. 0.000001
let msec i = i *. 0.001
let sec i  = i
let min i  = i *. 60.
let hour i = i *. 3600.

module Map = Map.Make (struct type t = time let compare = Float.compare end)

type clock = { mutable now : time ; mutable events : (unit -> unit) Map.t }
let current = { now = Unix.gettimeofday () ; events = Map.empty }

let now () = current.now

let nextev_wakener = ref None

let nextev_awake () = match !nextev_wakener with
    | None -> ()
    | Some w ->
        nextev_wakener := None ;
        if debug then Printf.printf "Clock: waking waiter up\n%!" ;
        Lwt.wakeup w ()

let at ts f x =
    if debug then Printf.printf "Clock: add an event for time %f (%+fs)\n%!" ts (ts -. current.now) ;
    current.events <- Map.add ts (fun () -> f x) current.events ;
    nextev_awake ()

let next_event () =
    let ts, f = try Map.min_binding current.events
                with Not_found -> max_float, (fun () -> ()) in
    let wait_ts = if not !realtime then 0. else ts -. current.now in
    if wait_ts > msec 10. then (
        if debug then Printf.printf "Clock: next_event: waiting for %fs since we're too early\n%!" wait_ts ;
        let waiter, wakener = Lwt.task () in
        nextev_wakener := Some wakener ;
        lwt _ = Lwt.pick [ Lwt_unix.sleep wait_ts ; waiter ] in
        nextev_wakener := None ;
        Lwt.return ()
    ) else (
        if debug then Printf.printf "Clock: next_event: executing since it's time (%+fs)\n%!" wait_ts ;
        current.events <- Map.remove ts current.events ;
        current.now <- ts ;
        Lwt.catch (fun () -> Lwt.return (f ())) (fun exn ->
            Printf.printf "Clock: event handler triggered an exception : %a\n%!" Printexc.print exn ;
            Lwt.return ())
    )

let delay d f x =
    at (d +. current.now) f x

(* We cannot allow our thread to sleep since we want to control the speed of time *)
let sleep d =
    let waiter, wakener = Lwt.wait () in
    delay d (Lwt.wakeup wakener) () ;
    waiter

let run () =
    let rec aux () =
        lwt _ = next_event () in
        aux () in
    aux ()

(* Synchronize internal clock with realtime clock.
   You must call this after real time passes (for instance after a blocking call).
   Otherwise, time jumps from one registered event to the next. *)
let synch () =
    ensure !realtime "Synch with real clock in non-realtime mode!?" ;
    current.now <- Unix.gettimeofday ()

