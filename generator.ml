(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(* Copyright 2026, Cedric Cellier
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
 * Value generators that can be created and named, so that the same random value
 * can be used at various places in the simulation.
 * For simplicity, all generators always generate a random integer, but generated
 * values can be used in places expecting some other kind of value. Generated
 * values will be silently coerced into the expected type.
 *)
open Batteries

type kind =
    (* Useful to share a simple parameter: *)
    | Constant of int
    | Increment of { start : int ; step : int }
    | Uniform of { start_incl : int ; stop_excl : int }
    | Normal of { mean : float ; scale : float } (* scale = σ *)

type t =
    { name : string ; kind : kind }

(* A [Uniform] range must be neither empty nor wider than [max_int]; either
 * makes [stop_excl - start_incl] non positive. *)
let make name kind =
    (match kind with
    | Uniform { start_incl ; stop_excl } when stop_excl - start_incl <= 0 ->
        Widget.bad_value "generator %S: cannot draw from [%d, %d["
            name start_incl stop_excl
    | _ -> ()) ;
    { name ; kind }

(*$T make
  try ignore (make "g" (Uniform { start_incl = 3 ; stop_excl = 3 })) ; false \
  with Widget.Bad_value _ -> true
  try ignore (make "g" (Uniform { start_incl = min_int ; stop_excl = max_int })) ; false \
  with Widget.Bad_value _ -> true
*)

(* Return the generated value for generator [t] at step [n]: *)
let get t n =
    match t.kind with
    | Constant x ->
        x
    | Increment { start ; step } ->
        start + step * n
    | Uniform { start_incl ; stop_excl } ->
        start_incl + Random.full_int (stop_excl - start_incl)
    | Normal { mean ; scale } ->
        let u = 1. -. Random.float 1.
        and v = 1. -. Random.float 1. in
        let x = sqrt ((-2.) *. log u) *. cos (2. *. Float.pi *. v) in
        mean +. scale *. x |> Float.round |> int_of_float

(*$T get
  get (make "g" (Increment { start = 10 ; step = 3 })) 2 = 16
  List.exists (fun _ -> \
    get (make "g" (Uniform { start_incl = 0 ; stop_excl = 1 lsl 40 })) 0 >= 1 lsl 30 \
  ) (List.init 100 identity)
*)
(*$Q get
  Q.int (fun n -> \
    let x = get (make "g" (Uniform { start_incl = 1 ; stop_excl = 1 lsl 40 })) n in \
    x >= 1 && x < 1 lsl 40)
*)

(*
 * Helpers building a JSON value that match a given kind.
 *)
open SimTypes
open Tools

let rec coerce kind x =
    let max_string_len = 50_000 in
    (* Not [abs], which leaves [min_int] negative: *)
    let x = x land max_int in
    match kind with
    | String | Text | FileName ->
        (* What's a random string associated with a random integer [x]?
         * A random string of that length. *)
        let x = x mod max_string_len in
        `String (randstr x)
    | Int ->
        `Int x
    | Float ->
        `Float (float_of_int x)
    | Bool ->
        `Bool (x land 1 <> 0)
    | Enum (values, _) ->
        (* Pick an entry at random, assuming empty enums are not a thing: *)
        `Int (fst values.(x mod Array.length values))
    | Set (values) ->
        let rec loop lst i =
            if i < Array.length values then (
                let lst =
                    if x land (1 lsl i) = 0 then
                        lst
                    else
                        (`Int (fst values.(i))) :: lst in
                loop lst (i + 1)
            ) else `List lst in
        loop [] 0
    | FRange (mi, ma) ->
        let w = ma -. mi in
        `Float (if w > 0. then mi +. mod_float (float_of_int x) w else mi)
    | IRange (mi, ma) ->
        let rng = ma - mi + 1 in
        (* [rng] overflows when the range is wider than [max_int], in which
         * case [mi + x] is within it for any [x] >= 0. *)
        `Int (if rng <= 0 then mi + x else mi + x mod rng)
    | Duration ->
        `Float (float_of_int x)
    | Bytes ->
        let x = x mod max_string_len in
        `String (hexstring_of_bitstring (randbs x))
    | Optional kind ->
        if x land 1 = 0 then `Null else coerce kind (x lsr 1)
    | Variant variants ->
        let n = Array.length variants in
        let var = x mod n in
        let x = x / n in
        coerce (snd variants.(var)) x
    | Hint (_, kind) ->
        coerce kind x
    | _ ->
        failwith "Cannot assign a random value to this kind"

(*$T coerce
  coerce Int min_int = `Int 0
  coerce (FRange (1., 1.)) 42 = `Float 1.
*)
(*$Q coerce
  Q.int (fun x -> match coerce (IRange (3, 7)) x with \
    | `Int i -> 3 <= i && i <= 7 | _ -> false)
  Q.int (fun x -> match coerce (IRange (min_int, 0)) x with \
    | `Int i -> i <= 0 | _ -> false)
  Q.int (fun x -> match coerce (FRange (-1., 1.)) x with \
    | `Float f -> -1. <= f && f <= 1. | _ -> false)
*)

(* The integer an automatic value is coerced from, as wide as [coerce] can
 * use: *)
let random_int () = Random.full_int max_int

(* Take the json of a synth value and return a value appropriate for the given
 * kind, or None for auto. [gen_values] is an array of integers holding all
 * generated values for that generation step. *)
let value_of_synth gen_values kind : Yojson.Basic.t -> Yojson.Basic.t option =
    function
    | `Assoc [ "const", v ] ->
        Widget.check_value kind v ;
        Some v
    | `Assoc [ "gen", `Int g ] ->
        if g < 0 || g >= Array.length gen_values then
            Widget.bad_value "generator #%d does not exist" g ;
        Some (coerce kind gen_values.(g))
    | `Null ->
        None
    | v ->
        Widget.bad_value "expected a constant, a generator or null, not %s"
            (Yojson.Basic.to_string v)

(* Read the field [fname] of the synthesized record [js] with [f], which is
 * given a value of [kind]. A null field is automatic: [auto ()] if given, a
 * random value of [kind] otherwise. Whatever goes wrong is a [Bad_value] that
 * names the field. *)
let of_field fname gen_values ?auto kind f js =
    let decode v =
        try f v with
        | Widget.Bad_value _ as e -> raise e
        | e -> Widget.bad_value "invalid value %s: %s"
                   (Yojson.Basic.to_string v) (Printexc.to_string e) in
    Widget.to_field fname (fun js ->
        match value_of_synth gen_values kind js with
        | Some v ->
            decode v
        | None ->
            (match auto with
            | Some auto -> auto ()
            | None -> decode (coerce kind (random_int ())))
    ) js

let int_of_field fname gen_values ?auto kind f js =
    of_field fname gen_values ?auto kind (f % Widget.to_int) js

(* Same as for int, but without a validation function since when we expect a
 * bitstring, any bitstring will do. *)
let bs_of_field fname gen_values ?auto kind js =
    of_field fname gen_values ?auto kind Widget.to_bitstring js

(*$T int_of_field
  int_of_field "f" [| 5 |] (IRange (0, 9)) identity \
    (`Assoc [ "f", `Assoc [ "gen", `Int 0 ] ]) = 5
  int_of_field "f" [||] Int identity \
    (`Assoc [ "f", `Assoc [ "const", `Int 42 ] ]) = 42
  try ignore (int_of_field "f" [||] Int identity (`Assoc [ "f", `Int 42 ])) ; false \
  with Widget.Bad_value msg -> String.starts_with msg "f: "
  try ignore (int_of_field "f" [||] (IRange (0, 9)) identity \
                (`Assoc [ "f", `Assoc [ "const", `Int 10 ] ])) ; false \
  with Widget.Bad_value msg -> String.starts_with msg "f: "
  try ignore (int_of_field "f" [||] Int (fun _ -> assert false) \
                (`Assoc [ "f", `Assoc [ "const", `Int 1 ] ])) ; false \
  with Widget.Bad_value msg -> String.starts_with msg "f: "
  try ignore (int_of_field "f" [||] Int identity \
                (`Assoc [ "f", `Assoc [ "gen", `Int 1 ] ])) ; false \
  with Widget.Bad_value msg -> String.starts_with msg "f: "
  List.exists (fun _ -> \
    int_of_field "f" [||] (IRange (0, 0xffff_ffff)) identity \
                 (`Assoc [ "f", `Null ]) > 0x3fff_ffff \
  ) (List.init 100 identity)
*)

(* Helper for tests: turn a JSON representation of a Packet.Pdu.t into one where
 * every immediate value is a synthesized "const". *)
let rec wrap f : Yojson.Basic.t -> Yojson.Basic.t = function
    | `Assoc lst -> `Assoc (List.map (fun (n, js) -> n, wrap f js) lst)
    | `List lst -> `List (List.map (wrap f) lst)
    | js -> f js
