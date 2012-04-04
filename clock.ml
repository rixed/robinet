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
(**
   This module creates an alarm-clock that schedule registered events.
   There are two modes of operation: realtime and not realtime.

   When in realtime mode (the default), the clock will merely follow
   wall-clock. This is not very interesting but is required whenever you plan
   to work with real network devices and outside world.  If your simulated
   network does not communicates with the outside world, though, then you can
   use not realtime mode and then play your simulation at full speed (and full
   CPU).
*)
open Batteries
open Bitstring
open Tools

let debug = false

let realtime = ref true

(** {2 Private Types} *)

(** Time.t represents a given timestamp (ie. number of seconds since 1970-01-01 00:00:00 UTC. *)
module rec Time : sig
    val print_date : bool ref
    include PRIVATE_TYPE with type t = private float and type outer_t = float
    val add : t -> Interval.t -> t
    val sub : t -> t -> Interval.t
    val wall_clock : unit -> t
    val to_ints : t -> int * int
end = struct
    (** When displaying a time, print also the corresponding date.
     * Only useful if your simulation spans several days, which is uncommon. *)
    let print_date = ref false

    include MakePrivate(struct
        type t = float
        let to_string t =
            let open Unix in
            let tm = localtime t in
            let msec = Float.round_to_int (100. *. (fst (modf t))) in
            if !print_date then
                Printf.sprintf "%d-%02d-%02d %02d:%02d:%02d.%02d"
                    (1900+tm.tm_year) (1+tm.tm_mon) tm.tm_mday tm.tm_hour tm.tm_min tm.tm_sec msec
            else
                Printf.sprintf "%02d:%02d:%02d.%02d"
                    tm.tm_hour tm.tm_min tm.tm_sec msec
        let is_valid _ = true
        let repl_tag = "time"
    end)

    (** Adds a time and an interval. *)
    let add (t : t) (i : Interval.t) = o ((t :> float) +. (i :> float))
    (** Substract two time and returns an interval. *)
    let sub (a : t) (b : t) = Interval.o ((a :> float) -. (b :> float))
    (** Get the current wall clock (through {Unix.gettimeofday}). *)
    let wall_clock () = o (Unix.gettimeofday ())
    (** Convert a timestamp to a pair of ints with seconds, microseconds *)
    let to_ints (t : t) =
        let t = (t :> float) in
        let sec  = Int.of_float t in
        let usec = Int.of_float ((t -. (floor t)) *. 1_000_000.) in
        sec, usec
end
(** While Interval.t reprensents a time interval.
 * Both are floats internaly to match OCaml stdlib. *)
and Interval : sig
    include PRIVATE_TYPE with type t = private float and type outer_t = float
    val usec : float -> t
    val msec : float -> t
    val sec  : float -> t
    val min  : float -> t
    val hour : float -> t
    val compare : t -> t -> int
    val add : t -> t -> t
end = struct
    include MakePrivate(struct
        type t = float
        let to_string t =
            Printf.sprintf "+%fs" t
        let is_valid _ = true
        let repl_tag = "time"
    end)

    (** Takes some microseconds, milliseconds, seconds, minutes or hour and return an [Interval.t]. *)
    let usec i = o (i *. 0.000001)
    let msec i = o (i *. 0.001)
    let sec i  = o i
    let min i  = o (i *. 60.)
    let hour i = o (i *. 3600.)

    (** Custom comparison function so that we can change time representation
     * more easily in the future. *)
    let compare (a : t) (b : t) = Float.compare (a :> float) (b :> float)
    (** Adds two intervals. *)
    let add (a : t) (b : t) = o ((a :> float) +. (b :> float))
end

(* poor man's asctime *)
let printer oc t = BatIO.nwrite oc (Time.to_string t)

(** {2 Current running time} *)

module Map = Map.Make (struct
    type t = Time.t
    let compare (a : t) (b : t) = Float.compare (a :> float) (b :> float)
end)

type clock = { mutable now : Time.t ; mutable events : (unit -> unit) Map.t }
let current = { now = Time.o (Unix.gettimeofday ()) ; events = Map.empty }

let now () = current.now

let nextev_wakener = ref None

let nextev_awake () = match !nextev_wakener with
    | None -> ()
    | Some w ->
        nextev_wakener := None ;
        if debug then Printf.printf "Clock: waking waiter up\n%!" ;
        Lwt.wakeup w ()

let at (ts : Time.t) f x =
    if debug then Printf.printf "Clock: add an event for time %s (%s)\n%!" (Time.to_string ts) (Interval.to_string (Time.sub ts current.now)) ;
    current.events <- Map.add ts (fun () -> f x) current.events ;
    nextev_awake ()

(* returns true if more events are scheduled *)
let next_event wait =
    if not wait && Map.is_empty current.events then (
        if debug then Printf.printf "Clock: no more events" ;
        Lwt.return false
    ) else
    let ts, f = try Map.min_binding current.events
                with Not_found -> Time.o max_float, (fun () -> ()) in
    let wait_ts = if not !realtime then Interval.o 0. else (Time.sub ts current.now) in
    if Interval.compare wait_ts (Interval.msec 10.) > 0 then (
        if debug then Printf.printf "Clock: next_event: waiting for %s since we're too early\n%!" (Interval.to_string wait_ts) ;
        let waiter, wakener = Lwt.task () in
        nextev_wakener := Some wakener ;
        lwt _ = Lwt.pick [ Lwt_unix.sleep (wait_ts :> float) ; waiter ] in
        nextev_wakener := None ;
        Lwt.return true
    ) else (
        if debug then Printf.printf "Clock: next_event: executing since it's time (%s)\n%!" (Interval.to_string wait_ts) ;
        current.events <- Map.remove ts current.events ;
        current.now <- ts ;
        Lwt.catch (fun () -> f () ; Lwt.return true) (fun exn ->
            Printf.printf "Clock: event handler triggered an exception : %a\n%!" Printexc.print exn ;
            Lwt.return true)
    )

let delay d f x =
    at (Time.add current.now d) f x

(* We cannot allow our thread to sleep since we want to control the speed of time *)
let sleep d =
    let waiter, wakener = Lwt.wait () in
    delay d (Lwt.wakeup wakener) () ;
    waiter

(** [run true] will run forever while [run false] will return once no more events are waiting. *)
let run wait =
    let rec aux () =
        lwt more = next_event wait in
        if more then aux ()
        else Lwt.return () in
    aux ()

(* Synchronize internal clock with realtime clock.
   You must call this after real time passes (for instance after a blocking call).
   Otherwise, time jumps from one registered event to the next. *)
let synch () =
    ensure !realtime "Synch with real clock in non-realtime mode!?" ;
    current.now <- Time.wall_clock ()

