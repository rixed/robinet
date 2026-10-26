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
    val of_string : string -> t
    val to_short_string : t -> string
    (* In seconds, for whoever reads the API: picoseconds are for computing
     * with, not for a graph's axis. *)
    val to_yojson : t -> Yojson.Safe.t
end = struct
    (*$< Interval *)
    (* Picoseconds in each unit, largest first: *)
    let units =
        [ 86_400_000_000_000_000, "d" ;
           3_600_000_000_000_000, "h" ;
              60_000_000_000_000, "m" ;
               1_000_000_000_000, "s" ;
                   1_000_000_000, "ms" ;
                       1_000_000, "µs" ;
                           1_000, "ns" ;
                               1, "ps" ]

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
            loop "" t units
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

    (** Reads what [to_string] writes: an optional minus sign then one or more
     * numbers each followed by its unit (d, h, m, s, ms, µs or us, ns, ps),
     * added together, such as "5s", "1m30s" or "1.5ms". A number alone, with
     * no unit, is refused.
     * Fractions are rounded to the nearest picosecond. *)
    let of_string str =
        let fail reason =
            invalid_arg (Printf.sprintf "Interval.of_string: %S: %s" str reason) in
        let len = String.length str in
        let neg = len > 0 && str.[0] = '-' in
        let is_num c = Char.is_digit c || c = '.' in
        let add a b =
            if a > max_int - b then fail "too long" else a + b in
        (* Returns the picoseconds of the terms from position [i]: *)
        let rec terms i =
            if i >= len then 0 else
            let j = ref i in
            while !j < len && is_num str.[!j] do incr j done ;
            let k = ref !j in
            while !k < len && not (is_num str.[!k]) do incr k done ;
            if !j = i then fail "a number is expected" ;
            let unit_ =
                match String.sub str !j (!k - !j) with
                | "" -> fail "a unit is expected"
                | "us" -> 1_000_000
                | u ->
                    (try fst (List.find (fun (_, n) -> n = u) units)
                    with Not_found -> fail ("unknown unit "^ u)) in
            let num = String.sub str i (!j - i) in
            let int_part, frac_part =
                try String.split num ~by:"."
                with Not_found -> num, "" in
            if int_part = "" && frac_part = "" ||
               String.contains frac_part '.' then
                fail ("invalid number "^ num) ;
            let int_part = if int_part = "" then 0 else int_of_string int_part in
            if int_part > max_int / unit_ then fail "too long" ;
            let frac =
                if frac_part = "" then 0 else
                int_of_float (Float.round (
                    float_of_string ("0."^ frac_part) *. float_of_int unit_)) in
            add (add (int_part * unit_) frac) (terms !k) in
        if len = (if neg then 1 else 0) then fail "empty" ;
        let t = terms (if neg then 1 else 0) in
        o (if neg then ~- t else t)

    (*$= of_string & ~printer:to_string
      (sec 5.) (of_string "5s")
      (msec 10.) (of_string "10ms")
      (min 1.) (of_string "1m")
      (usec 7.) (of_string "7us")
      (usec 7.) (of_string "7µs")
      (msec 1.5) (of_string "1.5ms")
      (msec 500.) (of_string ".5s")
      (sec 90.) (of_string "1m30s")
      (sec (-3.042)) (of_string "-3s42ms")
      zero (of_string "0s")
      (add (day 1.) (msec 42.)) (of_string "1d42ms")
    *)
    (*$Q of_string
      Q.int (fun i -> i = min_int || let t = o i in of_string (to_string t) = t)
    *)
    (*$T of_string
      List.for_all (fun s -> \
          try ignore (of_string s) ; false with Invalid_argument _ -> true) \
        [ "" ; "-" ; "5" ; "s" ; "5x" ; "1.2.3s" ; ".s" ; "5s3" ; "- 5s" ; \
          "1000000d" ; "53d53d" ]
    *)

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

    let to_secs (t : t) = float_of_int (t :> int) /. 1e12

    let to_yojson (t : t) = `Float (to_secs t)

    (** For people to read and compare: at most six significant digits, in
     * the largest of s, ms, µs and ns that leaves an integer part (ns below
     * that), trailing zeros removed: "157.949ms", "3725.5s", "0.523ns".
     * [of_string] reads it back, to within that rounding. *)
    let rec to_short_string (t : t) =
        let t = (t :> int) in
        if t < 0 then "-"^ to_short_string (o (~- t)) else
        if t = 0 then "0s" else
        let rec digits n = if n < 10 then 1 else 1 + digits (n / 10) in
        let rec pow10 k = if k = 0 then 1 else 10 * pow10 (k - 1) in
        (* The unit, its name, and how many of its decimals to print: *)
        let pick t =
            let u, n =
                List.find_opt (fun (u, _) -> t >= u)
                    [ 1_000_000_000_000, "s" ; 1_000_000_000, "ms" ;
                      1_000_000, "µs" ; 1_000, "ns" ] |>
                Option.default (1_000, "ns") in
            u, n, Int.min (digits u - 1) (Int.max 0 (6 - digits (t / u))) in
        let u, _, k = pick t in
        let q = u / pow10 k in
        let r = (if t > max_int - q / 2 then t else t + q / 2) / q * q in
        (* Rounding up may reach the next unit or another integer digit: *)
        let u, n, k = pick r in
        let q = u / pow10 k in
        let frac =
            if k = 0 then "" else
            let f = Printf.sprintf "%0*d" k (r mod u / q) in
            let len = ref k in
            while !len > 0 && f.[!len - 1] = '0' do decr len done ;
            if !len = 0 then "" else "."^ String.sub f 0 !len in
        string_of_int (r / u) ^ frac ^ n

    (*$= to_short_string & ~printer:identity
      "0s" (to_short_string zero)
      "1.5s" (to_short_string (msec 1500.))
      "-2s" (to_short_string (sec (-2.)))
      "157.949ms" (to_short_string (of_secs 0.157_949_2))
      "8.85159µs" (to_short_string (of_secs 8.851_594e-6))
      "10.0865s" (to_short_string (of_secs 10.086_480_617_523))
      "3725.5s" (to_short_string (sec 3725.5))
      "1000000s" (to_short_string (sec 999_999.6))
      "1ms" (to_short_string (of_secs 999.999_6e-6))
      "100s" (to_short_string (of_secs 99.999_996))
      "0.523ns" (to_short_string (psec 523))
      "0.001ns" (to_short_string (psec 1))
      "96ns" (to_short_string (nsec 96.))
    *)
    (*$Q to_short_string
      Q.int (fun i -> i = min_int || \
        let t = o i in let r = of_string (to_short_string t) in \
        Int.abs ((r :> int) - i) <= Int.max 1 (Int.abs i / 100_000))
    *)

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
    val max : t -> t -> t
    val is_after : t -> t -> bool
    val trunc : t -> Interval.t -> t
    (* How long this program has been running, used as default clock by the
     * logger. *)
    val since_start : unit -> t
    val beginning_of_time : t
    val end_of_time : t
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

    let to_secs (t : t) = float_of_int (t :> int) /. 1e12

    (** Adds a time and an interval. *)
    let add (t : t) (i : Interval.t) = o ((t :> int) + (i :> int))

    (** subtract an interval from a time. *)
    let sub (t : t) (i : Interval.t) = o ((t :> int) - (i :> int))

    (** Substract two time and returns an interval. *)
    let diff (a : t) (b : t) = Interval.o ((a :> int) - (b :> int))

    let compare a b = Int.compare (a : t :> int) (b : t :> int)

    let max a b = if compare a b >= 0 then a else b

    let is_after a b = compare a b >= 0

    (* Sentinels, for a value that has to be an instant while meaning "not yet" or
     * "never": compare them, [max] them, but do not compute with them -- there is
     * nothing on the other side of either. *)
    let beginning_of_time = o min_int
    let end_of_time = o max_int

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
    val trunc : t -> Interval.t -> t
    val to_ints : t -> int * int
    val of_date : ?utc_offset:Interval.t -> int -> int -> int -> int -> int -> float -> t
    val to_iso8601 : t -> string
    val beginning_of_time : t
    val end_of_time : t
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

    (** The last multiple of [i] before [t]. [i] must be a whole number of
     * seconds: those are exact floats, so the division cannot round [t] into
     * a neighbouring slice, which other lengths can. *)
    let trunc (t : t) (i : Interval.t) =
        if (i :> int) <= 0 || (i :> int) mod 1_000_000_000_000 <> 0 then
            invalid_arg "Wall.trunc: slices must be a whole number of seconds" ;
        let i = Interval.to_secs i in
        o (floor ((t :> float) /. i) *. i)

    (*$= & ~printer:(Printf.sprintf "%.17g")
      3. Clock.Wall.(trunc (of_secs 3.7) (Clock.Interval.sec 1.) |> to_secs)
      3. Clock.Wall.(trunc (of_secs 3.) (Clock.Interval.sec 1.) |> to_secs)
      (-4.) Clock.Wall.(trunc (of_secs (-3.7)) (Clock.Interval.sec 1.) |> to_secs)
      (-128.) Clock.Wall.(trunc (of_secs (-128.)) (Clock.Interval.sec 1.) |> to_secs)
      1785221520. \
        Clock.Wall.(trunc (of_secs 1785221556.318881) (Clock.Interval.min 1.) |> to_secs)
      1785196800. \
        Clock.Wall.(trunc (of_secs 1785196800.) (Clock.Interval.day 1.) |> to_secs)
    *)
    (*$T
      try ignore (Clock.Wall.(trunc (of_secs 3.) (Clock.Interval.msec 100.))) ; \
        false with Invalid_argument _ -> true
      try ignore (Clock.Wall.(trunc (of_secs 3.) (Clock.Interval.msec 1500.))) ; \
        false with Invalid_argument _ -> true
      try ignore (Clock.Wall.(trunc (of_secs 3.) (Clock.Interval.sec 0.))) ; \
        false with Invalid_argument _ -> true
    *)

    (** Convert a timestamp to a pair of ints with seconds, microseconds *)
    let to_ints (t : t) =
        let t = (t :> float) in
        let sec  = Int.of_float t in
        let usec = Int.of_float ((t -. (floor t)) *. 1_000_000.) in
        sec, usec

    let is_leap y = y mod 4 = 0 && (y mod 100 <> 0 || y mod 400 = 0)

    let days_in_month y m =
        match m with
        | 2 -> if is_leap y then 29 else 28
        | 4 | 6 | 9 | 11 -> 30
        | _ -> 31

    (* Days from 1970-01-01 to that day of the proleptic Gregorian calendar: *)
    let days_from_civil y m d =
        let y = if m <= 2 then y - 1 else y in
        let era = (if y >= 0 then y else y - 399) / 400 in
        let yoe = y - era * 400 in
        let doy = (153 * (if m > 2 then m - 3 else m + 9) + 2) / 5 + d - 1 in
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy in
        era * 146097 + doe - 719468

    (** The instant of that [year], [month] (from 1), [day], [hour], [minute]
     * and [second] (with its fraction), which are [utc_offset] ahead of UTC,
     * or else in the local time of the host. Raises [Invalid_argument] for a
     * date that does not exist. *)
    let of_date ?utc_offset year month day hour minute second =
        if month < 1 || month > 12 then
            invalid_arg (Printf.sprintf "No month %d" month) ;
        if day < 1 || day > days_in_month year month then
            invalid_arg (Printf.sprintf "No day %d in month %d of %d" day month year) ;
        if hour > 23 || minute > 59 || second < 0. || second >= 61. then
            invalid_arg (Printf.sprintf "No time %02d:%02d:%g" hour minute second) ;
        match utc_offset with
        | Some off ->
            let secs = (days_from_civil year month day * 24 + hour) * 3600 + minute * 60 in
            o (float_of_int secs +. second -. Interval.to_secs off)
        | None ->
            let tm = Unix.{ tm_year = year - 1900 ; tm_mon = month - 1 ;
                            tm_mday = day ; tm_hour = hour ; tm_min = minute ;
                            tm_sec = 0 ; tm_wday = 0 ; tm_yday = 0 ;
                            tm_isdst = false } in
            o (fst (Unix.mktime tm) +. second)

    (** As ISO 8601 writes it in UTC, to the microsecond: *)
    let to_iso8601 (t : t) =
        let us = int_of_float (Float.round ((t :> float) *. 1e6)) in
        let sec = if us >= 0 then us / 1_000_000 else (us - 999_999) / 1_000_000 in
        let us = us - sec * 1_000_000 in
        let tm = Unix.gmtime (float_of_int sec) in
        let frac =
            if us = 0 then "" else
            let s = Printf.sprintf "%06d" us in
            let n = ref 6 in
            while s.[!n - 1] = '0' do decr n done ;
            "."^ String.sub s 0 !n in
        Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02d%sZ"
            (1900 + tm.tm_year) (1 + tm.tm_mon) tm.tm_mday tm.tm_hour tm.tm_min
            tm.tm_sec frac

    (*$= & ~printer:identity
      "2026-10-20T22:02:45Z" \
        Clock.Wall.(to_iso8601 (of_date ~utc_offset:Clock.Interval.zero 2026 10 20 22 2 45.))
      "2026-10-20T20:02:45.25Z" \
        Clock.Wall.(to_iso8601 (of_date ~utc_offset:(Clock.Interval.hour 2.) 2026 10 20 22 2 45.25))
      "2024-02-29T00:00:00Z" \
        Clock.Wall.(to_iso8601 (of_date ~utc_offset:Clock.Interval.zero 2024 2 29 0 0 0.))
      "1969-12-31T23:59:59.5Z" Clock.Wall.(to_iso8601 (of_secs (-0.5)))
      "1970-01-01T00:00:00.000001Z" Clock.Wall.(to_iso8601 (of_secs 1e-6))
    *)
    (*$= & ~printer:(Printf.sprintf "%.17g")
      1792533765. Clock.Wall.(to_secs (of_date ~utc_offset:Clock.Interval.zero 2026 10 20 22 2 45.))
    *)
    (*$T
      try ignore (Clock.Wall.of_date 2026 2 29 0 0 0.) ; false with Invalid_argument _ -> true
      try ignore (Clock.Wall.of_date 2026 13 1 0 0 0.) ; false with Invalid_argument _ -> true
    *)

    (* Sentinels, for a value that has to be an instant while meaning "not yet" or
     * "never": compare them, [max] them, but do not compute with them -- there is
     * nothing on the other side of either. *)
    let beginning_of_time = o neg_infinity
    let end_of_time = o infinity
end
