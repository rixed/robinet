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
   Timestamps and durations.

   [Time.t] is an instant and [Interval.t] a length of time, both counted in
   whole picoseconds from the beginning of the simulation.
   A picosecond is a tenth of a bit at 100Gbps, and 62 bits of them are 53 days.
   The instants of the world outside (what [Unix.gettimeofday] reads, what
   libpcap writes beside a captured packet) are [Wall.t], and those two meet
   only where a simulation says they do.
*)
open Batteries

(** How long, in picoseconds. *)
module rec Interval : sig
    include Private.S with type t = private int and type outer_t = int
    val psec : int -> t
    val nsec : float -> t
    val usec : float -> t
    val msec : float -> t
    val sec  : float -> t
    val min  : float -> t
    val hour : float -> t
    val day : float -> t
    val zero : t
    val compare : t -> t -> int
    val add : t -> t -> t
    val sub : t -> t -> t
    val mul : t -> float -> t
    val div : t -> float -> t
    val abs  : t -> t
    val of_secs : float -> t
    val to_secs : t -> float
    (* In seconds, for whoever reads the API: picoseconds are for computing
     * with, not for a graph's axis. *)
    val to_yojson : t -> Yojson.Safe.t
end = struct
    (*$< Interval *)
    include Private.Make (struct
        type t = int

        (* Every unit that has something in it and none of the ones that have
         * not, largest first, down to the last unit that leaves nothing over:
         * "1d10m" for a day and ten minutes, "10ms390µs" for what a frame
         * takes, "0s" for nothing at all. *)
        let rec to_string t =
            if t < 0 then "-"^ to_string (~- t) else
            let rec loop s t = function
                | [] ->
                    if s = "" then "0s" else s
                | (unit_, name) :: rest ->
                    if t = 0 then (if s = "" then "0s" else s)
                    else if t >= unit_ then
                        loop (s ^ string_of_int (t / unit_) ^ name)
                             (t mod unit_) rest
                    else loop s t rest in
            loop "" t
                [ 86_400_000_000_000_000, "d" ;
                   3_600_000_000_000_000, "h" ;
                      60_000_000_000_000, "m" ;
                       1_000_000_000_000, "s" ;
                           1_000_000_000, "ms" ;
                               1_000_000, "µs" ;
                                   1_000, "ns" ;
                                       1, "ps" ]
        (*$= to_string & ~printer:identity
          "1d10m" (to_string (sec 87000.))
          "10s" (to_string (sec 10.))
          "0s" (to_string zero)
          "1d42ms" (to_string (add (day 1.) (msec 42.)))
          "3s42ms" (to_string (sec 3.042))
          "-3s42ms" (to_string (sec (-3.042)))
          "3s42µs" (to_string (sec 3.000_042))
          "-3s42µs" (to_string (sec (-3.000_042)))
          "-10ms390µs" (to_string (sec (-0.010_390)))
          "10ms390µs" (to_string (sec 0.010_390))
          "96ns" (to_string (nsec 96.))
          "1ps" (to_string (psec 1))
        *)

        let is_valid _ = true
        let repl_tag = "time"
    end)

    (** picoseconds to {Interval.t}: what one is made of, and the shortest
     * length of time this can tell from none at all. *)
    let psec = o

    (* Seconds are how a length of time is written everywhere but here, so
     * these round to the nearest picosecond rather than truncating: a tenth of
     * a microsecond asked for is a tenth of a microsecond, not one picosecond
     * less. *)
    let of_secs s =
        (* Not every float is a length of time: *)
        if not (Float.is_finite s) then
            invalid_arg (Printf.sprintf "Interval.of_secs: %g is not a length \
                                         of time" s) ;
        o (int_of_float (Float.round (s *. 1e12)))

    (** nanoseconds to {Interval.t}. *)
    let nsec i = of_secs (i *. 1e-9)

    (** microseconds to {Interval.t}. *)
    let usec i = of_secs (i *. 1e-6)

    (** milliseconds to {Interval.t}. *)
    let msec i = of_secs (i *. 1e-3)

    (** seconds to {Interval.t}. *)
    let sec i  = of_secs i

    (** minutes to {Interval.t}. *)
    let min i  = of_secs (i *. 60.)

    (** hours to {Interval.t}. *)
    let hour i = of_secs (i *. 3600.)

    (** days to {Interval.t} *)
    let day d = hour (24. *. d)

    (** Empty interval *)
    let zero = o 0

    (** Custom comparison function so that we can change time representation
     * more easily in the future. *)
    let compare (a : t) (b : t) = Int.compare (a :> int) (b :> int)

    (** Adds two intervals. *)
    let add (a : t) (b : t) = o ((a :> int) + (b :> int))

    (** Subtract two intervals. *)
    let sub (a : t) (b : t) = o ((a :> int) - (b :> int))

    (** Multiply/divide the duration by a scalar. *)
    let mul (t : t) s = o (int_of_float (Float.round (float_of_int (t :> int) *. s)))

    let div (t : t) s = o (int_of_float (Float.round (float_of_int (t :> int) /. s)))

    let abs (t : t) = o (Int.abs (t :> int))

    let to_secs (t : t) = float_of_int (t :> int) *. 1e-12

    let to_yojson (t : t) = `Float (to_secs t)

    (*$= to_secs & ~printer:string_of_float
      0.5 (to_secs (sec 0.5))
      1e-9 (to_secs (nsec 1.))
    *)

    (*$T psec
      to_string (add (psec 1) (psec 1)) = "2ps"
      (psec 1 :> int) = 1
    *)

    (*$T usec
      (usec 1. :> int) = 1_000_000
      (usec 0.001 :> int) = 1_000
    *)

    (*$>*)
end

(** When, on the timeline of the simulation this instant belongs to: picoseconds
 * since that simulation began (see [Simulation.epoch]). *)
and Time : sig
    include Private.S with type t = private int and type outer_t = int
    val zero : t
    val of_secs : float -> t
    val to_secs : t -> float
    (* An instant, as how long it is after the beginning, and back. *)
    val of_interval : Interval.t -> t
    val to_interval : t -> Interval.t
    val add : t -> Interval.t -> t
    val sub : t -> Interval.t -> t
    val diff : t -> t -> Interval.t
    val compare : t -> t -> int
    val is_after : t -> t -> bool
    val trunc : t -> Interval.t -> t
    (* How long this program has been running, used as default clock by the
     * logger. *)
    val since_start : unit -> t
    (* Seconds since the simulation began. Named for ppx_deriving_yojson, which
     * looks for [to_yojson] beside any type it is asked to serialize. *)
    val to_yojson : t -> Yojson.Safe.t
end = struct
    include Private.Make (struct
        type t = int
        (* An instant is how long since the simulation started, so it reads as
         * that length of time. What a reader of the world outside expects --
         * a date, a time of day -- is a [Wall.t], and only a simulation can
         * turn one into the other. *)
        let to_string t = Interval.to_string (Interval.o t)
        let is_valid _ = true
        let repl_tag = "time"
    end)

    let zero = o 0

    let of_secs s = o (Interval.of_secs s :> int)

    let of_interval (i : Interval.t) = o (i :> int)

    let to_interval (t : t) = Interval.o (t :> int)

    let to_secs (t : t) = float_of_int (t :> int) *. 1e-12

    (** Adds a time and an interval. *)
    let add (t : t) (i : Interval.t) = o ((t :> int) + (i :> int))

    (** subtract an interval from a time. *)
    let sub (t : t) (i : Interval.t) = o ((t :> int) - (i :> int))

    (** Substract two time and returns an interval. *)
    let diff (a : t) (b : t) = Interval.o ((a :> int) - (b :> int))

    let compare a b = Int.compare (a : t :> int) (b : t :> int)

    let is_after a b = compare a b >= 0

    (** The last multiple of [i] before [t]: what dates a sample that stands
     * for everything that happened in that slice of time. *)
    let trunc (t : t) (i : Interval.t) =
        let t = (t :> int) and i = (i :> int) in
        (* Rounding toward zero would step *up* on the negative side, which is
         * the wrong slice: [trunc] must never answer with an instant that has
         * not happened yet. *)
        let q = if t >= 0 || t mod i = 0 then t / i else t / i - 1 in
        o (q * i)

    (*$T &
      (Clock.Time.(trunc (of_secs 3.7) (Clock.Interval.sec 1.)) :> int) = \
        3_000_000_000_000
      (Clock.Time.(trunc (of_secs 3.) (Clock.Interval.sec 1.)) :> int) = \
        3_000_000_000_000
      (Clock.Time.(trunc (of_secs (-3.7)) (Clock.Interval.sec 1.)) :> int) = \
        -4_000_000_000_000
    *)

    (* Since the first time anything asked, which is as good an origin as any
     * for what does not belong to a simulation: what matters of those instants
     * is how far apart they are. *)
    let program_start = Unix.gettimeofday ()

    let since_start () = of_secs (Unix.gettimeofday () -. program_start)

    let to_yojson (t : t) = `Float (to_secs t)
end

(** An instant of the world outside, in seconds since 1970-01-01 00:00:00 UTC:
 * what [Unix.gettimeofday] reads and what libpcap writes beside a captured
 * packet.
 *
 * Not a [Time.t], and deliberately not made of the same stuff: those two
 * timelines are the same only for a simulation that has followed the wall
 * clock since it was made, and a simulation is entitled to run faster than the
 * world, to pause, or to have started before it. Crossing from one to the
 * other is [Simulation.of_wall_clock] and [Simulation.to_wall_clock], and
 * nothing else may do it. *)
module Wall : sig
    include Private.S with type t = private float and type outer_t = float
    val print_date : bool ref
    val now : unit -> t
    val of_secs : float -> t
    val to_secs : t -> float
    val add : t -> Interval.t -> t
    val sub : t -> Interval.t -> t
    val diff : t -> t -> Interval.t
    val compare : t -> t -> int
    val to_ints : t -> int * int
end = struct
    (** When displaying a time, print also the corresponding date.
     * Only useful if your simulation spans several days, which is uncommon. *)
    let print_date = ref false

    include Private.Make (struct
        type t = float
        let to_string t =
            let open Unix in
            let tm = localtime t in
            let msec = Float.round_to_int (100. *. (fst (modf t))) in
            let sec, msec =
                if msec < 100 then tm.tm_sec, msec
                else tm.tm_sec + 1, 0 in
            if !print_date then
                Printf.sprintf "%d-%02d-%02d %02d:%02d:%02d.%02d"
                    (1900+tm.tm_year) (1+tm.tm_mon) tm.tm_mday tm.tm_hour tm.tm_min sec msec
            else
                Printf.sprintf "%02d:%02d:%02d.%02d"
                    tm.tm_hour tm.tm_min sec msec
        let is_valid v = v = v
        let repl_tag = "time"
    end)

    (** Get the current wall clock (through {Unix.gettimeofday}). *)
    let now () = o (Unix.gettimeofday ())

    let of_secs s = o s

    let to_secs (t : t) = (t :> float)

    let add (t : t) (i : Interval.t) = o ((t :> float) +. Interval.to_secs i)

    let sub (t : t) (i : Interval.t) = o ((t :> float) -. Interval.to_secs i)

    let diff (a : t) (b : t) = Interval.of_secs ((a :> float) -. (b :> float))

    let compare a b = Float.compare (a : t :> float) (b : t :> float)

    (** Convert a timestamp to a pair of ints with seconds, microseconds *)
    let to_ints (t : t) =
        let t = (t :> float) in
        let sec  = Int.of_float t in
        let usec = Int.of_float ((t -. (floor t)) *. 1_000_000.) in
        sec, usec
end

(* Sentinels, for a value that has to be an instant while meaning "not yet" or
 * "never": compare them, [max] them, but do not compute with them -- there is
 * nothing on the other side of either. *)

let end_of_time =
    Time.o max_int

let beginning_of_time =
    Time.o min_int
