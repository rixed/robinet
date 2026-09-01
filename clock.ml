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

   [Time.t] is an absolute instant and [Interval.t] a length of time, both in
   seconds and kept distinct so that one is never mistaken for the other. The
   clock that hands out those instants, and the events scheduled against it,
   belong to a simulation; see the Simulation module.
*)
open Batteries

(** Time.t represents a given timestamp (ie. number of seconds since 1970-01-01 00:00:00 UTC. *)
module rec Time : sig
    val print_date : bool ref
    include Private.S with type t = private float and type outer_t = float
    val add : t -> Interval.t -> t
    val sub : t -> Interval.t -> t
    val diff : t -> t -> Interval.t
    val wall_clock : unit -> t
    val to_ints : t -> int * int
    val compare : t -> t -> int
    val is_after : t -> t -> bool
    val trunc : t -> Interval.t -> t
    val to_timestamp : t -> float
    (* Seconds since the epoch. Named for ppx_deriving_yojson, which looks for
     * [to_yojson] beside any type it is asked to serialize. *)
    val to_yojson : t -> Yojson.Safe.t
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

    (** Adds a time and an interval. *)
    let add (t : t) (i : Interval.t) = o ((t :> float) +. (i :> float))

    (** subtract an interval from a time. *)
    let sub (t : t) (i : Interval.t) = o ((t :> float) -. (i :> float))

    (** Substract two time and returns an interval. *)
    let diff (a : t) (b : t) = Interval.o ((a :> float) -. (b :> float))

    (** Get the current wall clock (through {Unix.gettimeofday}). *)
    let wall_clock () = o (Unix.gettimeofday ())

    (** Convert a timestamp to a pair of ints with seconds, microseconds *)
    let to_ints (t : t) =
        let t = (t :> float) in
        let sec  = Int.of_float t in
        let usec = Int.of_float ((t -. (floor t)) *. 1_000_000.) in
        sec, usec

    let compare a b =
        Float.compare (a : t :> float) (b : t :> float)

    let is_after a b =
        compare a b >= 0

    let trunc (t : t) (i : Interval.t) =
        o (floor ((t :> float) /. (i :> float)) *. (i :> float))

    let to_timestamp (t : t) = (t :> float)

    let to_yojson (t : t) = `Float (t :> float)
end

(** While Interval.t represents a time interval.
 * Both are floats internally to match OCaml stdlib. *)
and Interval : sig
    include Private.S with type t = private float and type outer_t = float
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
    val to_secs : t -> float
    (* In seconds. See Time.to_yojson. *)
    val to_yojson : t -> Yojson.Safe.t
end = struct
    (*$< Interval *)
    include Private.Make (struct
        type t = float

        let rec to_string t =
            if t < 0. then "-"^ to_string (~-. t) else
            let epsilon = 1e-9 in
            let finished t = abs_float t <= epsilon in
            let to_str = Printf.sprintf "%g" in
            let aux s t k u =
                if t >= k then
                    let x = Float.floor (epsilon +. t /. k) in
                    s ^ to_str x ^ u, t -. x *. k
                else
                    s, t in
            let s, t = aux "" t 86400. "d" in
            if finished t && s <> "" then s else
            let s, t = aux s t 3600. "h" in
            if finished t && s <> "" then s else
            let s, t = aux s t 60. "m" in
            if finished t && s <> "" then s else
            let s, t = aux s t 1. "s" in
            if finished t then
                if s <> "" then s else "0s"
            else
            let s, t = aux s t 1e-3 "ms" in
            if finished t && s <> "" then s else
            s ^ to_str (1e6 *. t) ^ "µs"
        (*$= to_string & ~printer:identity
          "1d10m" (to_string (sec 87000.))
          "10s" (to_string (sec 10.))
          "0s" (to_string zero)
          "1d42ms" (to_string (add (day 1.) (msec 42.)))
          "3s42ms" (to_string (o 3.042))
          "-3s42ms" (to_string (o (-3.042)))
          "3s42µs" (to_string (o 3.000_042))
          "-3s42µs" (to_string (o (-3.000_042)))
          "-10ms390µs" (to_string (o (-0.010_390)))
          "10ms390µs" (to_string (o 0.010_390))
        *)

        let is_valid v = v = v
        let repl_tag = "time"
    end)

    (** microseconds to {Interval.t}. *)
    let usec i = o (i *. 0.000001)

    (** milliseconds to {Interval.t}. *)
    let msec i = o (i *. 0.001)

    (** seconds to {Interval.t}. *)
    let sec i  = o i

    (** minutes to {Interval.t}. *)
    let min i  = o (i *. 60.)

    (** hours to {Interval.t}. *)
    let hour i = o (i *. 3600.)

    (** days to {Interval.t} *)
    let day d = hour (24. *. d)

    (** Empty interval *)
    let zero = o 0.

    (** Custom comparison function so that we can change time representation
     * more easily in the future. *)
    let compare (a : t) (b : t) = Float.compare (a :> float) (b :> float)

    (** Adds two intervals. *)
    let add (a : t) (b : t) = o ((a :> float) +. (b :> float))

    (** Subtract two intervals. *)
    let sub (a : t) (b : t) = o ((a :> float) -. (b :> float))

    (** Multiply/divide the duration by a scalar. *)
    let mul (t : t) s = o ((t :> float) *. s)

    let div (t : t) s = o ((t :> float) /. s)

    let abs (t : t) = o (Float.abs (t :> float))

    let to_secs (t : t) = (t :> float)

    let to_yojson (t : t) = `Float (t :> float)

    (*$>*)
end

let end_of_time =
    Time.o infinity

let beginning_of_time =
    Time.o neg_infinity
