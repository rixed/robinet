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
 * makes [stop_excl - start_incl] non positive. A [Normal] must be a
 * distribution: a spread is a distance, and neither it nor the mean it is
 * around can be infinite or not a number. *)
let make name kind =
    (match kind with
    | Uniform { start_incl ; stop_excl } when stop_excl - start_incl <= 0 ->
        Widget.bad_value "generator %S: cannot draw from [%d, %d["
            name start_incl stop_excl
    | Normal { mean ; scale }
      when Float.is_nan mean || Float.is_special mean ||
           Float.is_nan scale || Float.is_special scale || scale < 0. ->
        Widget.bad_value "generator %S: cannot draw around %g within %g"
            name mean scale
    | _ -> ()) ;
    { name ; kind }

(*$T make
  try ignore (make "g" (Uniform { start_incl = 3 ; stop_excl = 3 })) ; false \
  with Widget.Bad_value _ -> true
  try ignore (make "g" (Uniform { start_incl = min_int ; stop_excl = max_int })) ; false \
  with Widget.Bad_value _ -> true
  try ignore (make "g" (Normal { mean = 0. ; scale = -1. })) ; false \
  with Widget.Bad_value _ -> true
  try ignore (make "g" (Normal { mean = nan ; scale = 1. })) ; false \
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

(* Another integer as random as [x], and as good as independent from it for
 * each [salt]: what the parts of a value are coerced from, so that the same
 * [x] always gives the same whole. *)
let derive x salt =
    let h = x lxor (salt * 0x2545F4914F6CDD1D) in
    let h = (h lxor (h lsr 31)) * 0x3F58476D1CE4E5B9 in
    let h = (h lxor (h lsr 27)) * 0x14D049BB133111EB in
    (h lxor (h lsr 31)) land max_int

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
        let case, kind = variants.(x mod n) in
        `Assoc [ case, coerce kind (x / n) ]
    | Hint (_, kind) ->
        coerce kind x
    | BRange (mi, ma) ->
        let ma = min ma (mi + max_string_len) in
        let len = if ma < mi then mi else mi + x mod (ma - mi + 1) in
        `String (hexstring_of_bitstring (randbs len))
    | Ipv4 ->
        `String (Printf.sprintf "%d.%d.%d.%d"
                    ((x lsr 24) land 0xff) ((x lsr 16) land 0xff)
                    ((x lsr 8) land 0xff) (x land 0xff))
    | Ipv6 ->
        (* The low 64 bits, under the documentation prefix: *)
        `String (Printf.sprintf "2001:db8::%x:%x:%x:%x"
                    ((x lsr 48) land 0xffff) ((x lsr 32) land 0xffff)
                    ((x lsr 16) land 0xffff) (x land 0xffff))
    | Mac ->
        `String (Printf.sprintf "%02x:%02x:%02x:%02x:%02x:%02x"
                    ((x lsr 40) land 0xff) ((x lsr 32) land 0xff)
                    ((x lsr 24) land 0xff) ((x lsr 16) land 0xff)
                    ((x lsr 8) land 0xff) (x land 0xff))
    | Time ->
        `Float (float_of_int x)
    | Row fields | Record fields ->
        `Assoc (Array.to_list fields |>
                List.map (fun (name, k) ->
                    name, coerce k (derive x (Hashtbl.hash name))))
    | List kind ->
        let max_list_len = 4 in
        let len = x mod (max_list_len + 1) in
        `List (List.init len (fun i -> coerce kind (derive x (i + 1))))
    | Widget_id | Packet | Synth | Metric ->
        Widget.bad_value "cannot generate %s" (Widget.kind_name kind)

(*$T coerce
  coerce Int min_int = `Int 0
  coerce (FRange (1., 1.)) 42 = `Float 1.
  let k = Widget.record [| "a", Int ; "b", Widget.list Int |] in \
  coerce k 42 = coerce k 42
  (try ignore (coerce Widget_id 1) ; false with Widget.Bad_value _ -> true)
  (try ignore (coerce (Optional Packet) 3) ; false with Widget.Bad_value _ -> true)
  (try ignore (coerce Metric 1) ; false with Widget.Bad_value _ -> true)
*)
(*$Q coerce
  Q.int (fun x -> List.for_all (fun k -> \
    try Widget.check_value k (coerce k x) ; true with _ -> false) \
    [ String ; Text ; FileName ; Int ; Float ; Bool ; Time ; Duration ; \
      Bytes ; Ipv4 ; Ipv6 ; Mac ; BRange (0, 0) ; BRange (4, 16) ; \
      IRange (-5, 5) ; IRange (min_int, max_int) ; FRange (0., 1.) ; \
      Widget.one_of [| 1, "a" ; 7, "b" |] ; \
      Widget.one_of ~range:(0, 9) [| 1, "a" |] ; \
      Set (Widget.choices [| "a" ; "b" ; "c" |]) ; \
      Widget.optional Int ; Widget.hint "x" Ipv4 ; \
      Widget.list (Widget.row [| "a", Mac ; "b", Widget.optional Bytes |]) ; \
      Widget.record [| "a", Widget.list Int ; \
                       "b", Widget.record [| "c", Bool |] |] ; \
      Widget.variant [| "a", Int ; "b", Widget.record [| "c", Ipv6 |] |] ])
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

(* Turn the value [js] of [kind] into a synth, by applying [f] to each value a
 * single synth stands for: down through the fields of records and rows, the
 * elements of lists and what a variant's case carries, to what is none of
 * those. *)
let rec wrap kind f (js : Yojson.Basic.t) : Yojson.Basic.t =
    let kind_of_part parts name =
        Array.find_opt (fun (n, _) -> n = name) parts |> Option.map snd in
    match kind, js with
    | Hint (_, k), _ ->
        wrap k f js
    | (Row fields | Record fields), `Assoc given ->
        `Assoc (List.map (fun (name, v) ->
            name, (match kind_of_part fields name with
                  | Some k -> wrap k f v
                  | None -> f v)
        ) given)
    | List k, `List l ->
        `List (List.map (wrap k f) l)
    | Variant cases, `Assoc [ case, v ] ->
        (match kind_of_part cases case with
        | Some k -> `Assoc [ case, wrap k f v ]
        | None -> f js)
    | _ ->
        f js

let const v : Yojson.Basic.t = `Assoc [ "const", v ]

(*$T wrap
  wrap (Set (Widget.choices [| "a" |])) const (`List [ `Int 0 ]) = \
    `Assoc [ "const", `List [ `Int 0 ] ]
  wrap (Widget.record [| "a", Int ; "b", Widget.list Int |]) const \
    (`Assoc [ "a", `Int 1 ; "b", `List [ `Int 2 ] ]) = \
    `Assoc [ "a", `Assoc [ "const", `Int 1 ] ; \
             "b", `List [ `Assoc [ "const", `Int 2 ] ] ]
*)

(* A synth of [kind] structured as the kind is: a constant, a generated value
 * or an automatic one given for the whole of a record, a list or a variant
 * becomes a constant for each of its parts. *)
let expand gen_values kind js =
    match js with
    | `Null | `Assoc [ ("const" | "gen"), _ ] ->
        let v =
            match value_of_synth gen_values kind js with
            | Some v -> v
            | None -> coerce kind (random_int ()) in
        wrap kind const v
    | js ->
        js

(*$T expand
  expand [||] (Widget.list Int) (`Assoc [ "const", `List [ `Int 2 ] ]) = \
    `List [ `Assoc [ "const", `Int 2 ] ]
  expand [| 3 |] (Widget.variant [| "a", Int |]) (`Assoc [ "gen", `Int 0 ]) = \
    `Assoc [ "a", `Assoc [ "const", `Int 3 ] ]
  expand [||] (Widget.list Int) (`List []) = `List []
*)

(* Read the field [fname] of [kind] -- a record, a list or a variant -- with
 * [f], which is given a synth of that kind structured as the kind is. *)
let sub_of_field fname gen_values kind f js =
    Widget.to_field fname (fun js -> f (expand gen_values kind js)) js

(* A layer's payload: the layer above, packed, when there is one, and what the
 * synth says otherwise. *)
let payload_of_field ?upper gen_values kind js =
    match upper with
    | Some (_, bits) -> bits
    | None -> bs_of_field "payload" gen_values kind js

(* The automatic value the name of the layer above says, when [f] knows what
 * to make of that name. *)
let from_upper upper f =
    Option.bind upper (fun (name, _) -> f name) |> Option.map (fun v () -> v)

(* The automatic value of what lasts from one packet to the next, such as a
 * port: what it was in the previous packet 99 times out of 100, and [fresh ()]
 * otherwise. None without a previous packet. *)
let mostly_same prev fresh =
    Option.map (fun v () -> if Random.int 100 = 0 then fresh () else v) prev

(* For tests, given a Pdu [t]: whether [of_synth] reads [t] back from a synth
 * where every value is a constant, *)
let reads_consts of_synth kind_of to_json t =
    let synth = wrap (kind_of t) const (to_json t) in
    to_json (of_synth synth [||]) = to_json t

(* and whether a synth where every value is automatic reads as a value of its
 * kind. *)
let reads_autos of_synth kind_of to_json t =
    let t = of_synth (wrap (kind_of t) (fun _ -> `Null) (to_json t)) [||] in
    Widget.check_value (kind_of t) (to_json t) ;
    true

(** {2 Generators, as the interface edits them} *)

(* Which shape a generator has, and then that shape's own parameters. The
 * names are those of the fields above, spelled as they are read. *)
let kind =
    Widget.variant [|
        "constant", Int ;
        "increment", Widget.row [| "start", Int ; "step", Int |] ;
        "uniform", Widget.row [| "from", Int ; "up to (excluded)", Int |] ;
        "normal", Widget.row [| "mean", Float ;
                                "standard deviation", Float |] |]

(* A generator and the name it is known by, which is how it is referenced
 * (see {!Synth}). *)
let named_kind = Widget.record [| "name", String ; "generator", kind |]

let json_of_kind k : Yojson.Basic.t =
    match k with
    | Constant x ->
        `Assoc [ "constant", `Int x ]
    | Increment { start ; step } ->
        `Assoc [ "increment", `Assoc [ "start", `Int start ;
                                       "step", `Int step ] ]
    | Uniform { start_incl ; stop_excl } ->
        `Assoc [ "uniform", `Assoc [ "from", `Int start_incl ;
                                     "up to (excluded)", `Int stop_excl ] ]
    | Normal { mean ; scale } ->
        `Assoc [ "normal", `Assoc [ "mean", `Float mean ;
                                    "standard deviation", `Float scale ] ]

let kind_of_json =
    Widget.to_case (fun case v ->
        let int f = Widget.to_field f Widget.to_int v
        and float f = Widget.to_field f Widget.to_float v in
        match case with
        | "constant" ->
            Constant (Widget.to_int v)
        | "increment" ->
            Increment { start = int "start" ; step = int "step" }
        | "uniform" ->
            Uniform { start_incl = int "from" ;
                      stop_excl = int "up to (excluded)" }
        | "normal" ->
            Normal { mean = float "mean" ;
                     scale = float "standard deviation" }
        | case ->
            Widget.bad_value "no generator is a %S" case)

let to_json (g : t) : Yojson.Basic.t =
    `Assoc [ "name", `String g.name ; "generator", json_of_kind g.kind ]

(* Whatever [make] refuses is refused here too: what the interface sends is
 * read with this. *)
let of_json js =
    make (Widget.to_field "name" Widget.to_string js)
         (Widget.to_field "generator" kind_of_json js)

(*$Q of_json
  Q.(oneof [ map (fun x -> Constant x) int ; \
             map (fun (a, b) -> Increment { start = a ; step = b }) \
                 (pair int int) ; \
             map (fun (a, b) -> Uniform { start_incl = a ; \
                                          stop_excl = a + 1 + abs b }) \
                 (pair nat_small nat_small) ; \
             map (fun (a, b) -> Normal { mean = float_of_int a ; \
                                         scale = float_of_int (abs b) }) \
                 (pair nat_small nat_small) ]) \
    (fun k -> \
      let t = make "g" k in \
      Widget.check_value named_kind (to_json t) ; \
      of_json (to_json t) = t)
 *)

(*$T of_json
  try ignore (of_json (`Assoc [ "name", `String "g" ; \
                                "generator", `Assoc [ "flat", `Int 1 ] ])) ; \
      false \
  with Widget.Bad_value _ -> true
 *)
