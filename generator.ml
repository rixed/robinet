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
    | Increment of int
    | Uniform of { start_incl : int ; stop_excl : int }
    | Normal of { mean : float ; scale : float } (* scale = σ *)

type t =
    { name : string ; kind : kind }

(* Return the generated value for generator [t] at step [n]: *)
let get t n =
    match t.kind with
    | Constant x ->
        x
    | Increment i ->
        i * n
    | Uniform { start_incl ; stop_excl } ->
        start_incl + Random.int (stop_excl - start_incl)
    | Normal { mean ; scale } ->
        let u = 1. -. Random.float 1.
        and v = 1. -. Random.float 1. in
        let x = sqrt ((-2.) *. log u) *. cos (2. *. Float.pi *. v) in
        mean +. scale *. x |> Float.round |> int_of_float

(*
 * Helpers building a JSON value that match a given kind.
 *)
open SimTypes
open Tools

let rec coerce kind x =
    let max_string_len = 50_000 in
    let x = abs x in
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
        let x = float_of_int x in
        let x = mod_float x (ma -. mi) in
        `Float (mi +. x)
    | IRange (mi, ma) ->
        let rng = ma - mi + 1 in
        let x =
            if rng <= 0 then x
            else mi + x mod rng in
        `Int x
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

(* Take the json of a synth value and return a value appropriate for the given
 * kind, or None for auto. [gen_values] is an array of integers holding all
 * generated values for that generation step. *)
let value_of_synth gen_values kind : Yojson.Basic.t -> Yojson.Basic.t option =
    function
    | `Assoc [ "const", v ] ->
        Some v
    | `Assoc [ "gen", `Int g ] ->
        if g < 0 || g >= Array.length gen_values then
            Widget.bad_value "Generator #%d does not exist" g ;
        let x = gen_values.(g) in
        Some (coerce kind x)
    | `Null ->
        None
    | _ ->
        invalid_arg "Synth.of_synth"

let int_of_field fname gen_values ?auto kind f js =
    let js = Widget.json_of_field fname js in
    match value_of_synth gen_values kind js with
    | Some v ->
        f (Widget.to_int v)
    | None ->
        (match auto with
        | Some auto -> auto ()
        | None -> f (Widget.to_int (coerce kind (Random.bits ()))))

(* Same as for int, but without a validation function since when we expect a
 * bitstring, any bitstring will do. *)
let bs_of_field fname gen_value ?auto kind js =
    let js = Widget.json_of_field fname js in
    match value_of_synth gen_value kind js with
    | Some v ->
        Widget.to_bitstring v
    | None ->
        (match auto with
        | Some auto -> auto ()
        | None -> Widget.to_bitstring (coerce kind (Random.bits ())))

(* Helper for tests: turn a JSON representation of a Packet.Pdu.t into one where
 * every immediate value is a synthesized "const". *)
let rec wrap f : Yojson.Basic.t -> Yojson.Basic.t = function
    | `Assoc lst -> `Assoc (List.map (fun (n, js) -> n, wrap f js) lst)
    | `List lst -> `List (List.map (wrap f) lst)
    | js -> f js
