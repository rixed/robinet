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
(** The values of crafty programs, and the errors met computing them. *)
open Batteries
module A = Crafty_ast
module Interval = Clock.Interval

type value =
    | Void
    | Bool of bool
    | Byte of int
    | Int of int
    | Float of float
    | String of string
    | Interval of Interval.t
    | Time of Clock.Wall.t
    | Ip of Ip.Addr.t
    | Mac of Eth.Addr.t
    (* In the order of the fields of the record type: *)
    | Record of value array
    | Array of value array
    (* Ordered by [compare_keys], with the value of the missing keys if any: *)
    | Map of (value, value) Map.PMap.t * value option
    | Variant of string * value

let of_literal = function
    | A.Bool b -> Bool b
    | A.Int i -> Int i
    | A.Float f -> Float f
    | A.Byte b -> Byte b
    | A.Interval i -> Interval i
    | A.Time t -> Time t
    | A.Ip ip -> Ip ip
    | A.Mac mac -> Mac mac

let bytes_of_string s =
    Array (Array.init (String.length s) (fun i -> Byte (Char.code s.[i])))

let string_of_bytes a =
    String.init (Array.length a) (fun i ->
        match a.(i) with Byte b -> Char.chr b | _ -> assert false)

let mac_bits mac = (mac : Eth.Addr.t :> Bitstring.bitstring)

(* A total order that agrees with [equal], which ignores the defaults of
 * maps: *)
let rec compare_keys a b =
    let compare_arrays a b =
        match Int.compare (Array.length a) (Array.length b) with
        | 0 ->
            let rec loop i =
                if i >= Array.length a then 0 else
                match compare_keys a.(i) b.(i) with 0 -> loop (i + 1) | c -> c in
            loop 0
        | c -> c in
    match a, b with
    | Ip a, Ip b -> Ip.Addr.compare a b
    | Mac a, Mac b -> Bitstring.compare (mac_bits a) (mac_bits b)
    | Interval a, Interval b -> Interval.compare a b
    | Time a, Time b -> Clock.Wall.compare a b
    | Record a, Record b | Array a, Array b -> compare_arrays a b
    | Map (a, _), Map (b, _) -> Map.PMap.compare compare_keys a b
    | Variant (n, a), Variant (m, b) ->
        (match String.compare n m with 0 -> compare_keys a b | c -> c)
    | a, b -> compare a b

let empty_map default = Map (Map.PMap.create compare_keys, default)

(* How a value of type [typ] is written into a string: *)
let rec to_string (typ : A.Type.t) v =
    match typ, v with
    | _, Void -> "?"
    | _, Bool b -> if b then "true" else "false"
    | _, Byte b -> Printf.sprintf "#%02x" b
    | _, Int i -> string_of_int i
    | _, Float f -> A.string_of_float f
    | _, String s -> s
    | _, Interval i -> Interval.to_string i
    | _, Time t -> Clock.Wall.to_iso8601 t
    | _, Ip ip -> Ip.Addr.to_dotted_string ip
    | _, Mac mac ->
        Tools.hexstring ~sep:":" (Bitstring.string_of_bitstring (mac_bits mac))
    | Record fs, Record vs ->
        "{"^ String.concat ", " (List.mapi (fun i (n, t) ->
            n ^": "^ to_string t vs.(i)) fs) ^"}"
    | Array Byte, Array a when Array.length a > 0 ->
        "#"^ String.concat "" (Array.to_list (Array.map (function
            | Byte b -> Printf.sprintf "%02x" b | _ -> assert false) a))
    | Array t, Array a ->
        "["^ String.concat ", " (Array.to_list (Array.map (to_string t) a)) ^"]"
    | Map (_, _), Map (m, _) when Map.PMap.is_empty m -> "[:]"
    | Map (k, t), Map (m, _) ->
        "["^ String.concat ", " (List.map (fun (key, v) ->
            to_string k key ^": "^ to_string t v) (Map.PMap.bindings m)) ^"]"
    | Variant cs, Variant (n, v) ->
        let t = try List.assoc n cs with Not_found -> A.Type.Void in
        if t = A.Type.Void then n else n ^" "^ to_string t v
    | _ -> invalid_arg "Crafty_value.to_string"

(* As JSON, with durations in seconds, and what JSON has no type for as
 * {!to_string} writes it: *)
let rec to_json (typ : A.Type.t) v : Yojson.Basic.t =
    match typ, v with
    | _, Void -> `Null
    | _, Bool b -> `Bool b
    | _, Int i -> `Int i
    | _, Float f -> `Float f
    | _, String s -> `String s
    | _, Interval i -> `Float (Interval.to_secs i)
    | Record fs, Record vs ->
        `Assoc (List.mapi (fun i (n, t) -> n, to_json t vs.(i)) fs)
    | Array t, Array a when t <> Byte ->
        `List (Array.to_list (Array.map (to_json t) a))
    | _ -> `String (to_string typ v)

(** JSON as text, with each float in the fewest digits that read back as
 * that float (Yojson may write 17: [0.07144200000000001]). *)
let rec json_to_string : Yojson.Basic.t -> string = function
    | `Float f when Stdlib.Float.is_integer f && Float.abs f < 1e15 ->
        Printf.sprintf "%.1f" f
    | `Float f when Float.is_finite f ->
        let s = Printf.sprintf "%.15g" f in
        if float_of_string s = f then s else
        let s = Printf.sprintf "%.16g" f in
        if float_of_string s = f then s else Printf.sprintf "%.17g" f
    | `List l -> "["^ String.concat "," (List.map json_to_string l) ^"]"
    | `Assoc l ->
        "{"^ String.concat "," (List.map (fun (k, v) ->
            Yojson.Basic.to_string (`String k) ^":"^ json_to_string v) l) ^"}"
    | j -> Yojson.Basic.to_string j

(*$= json_to_string & ~printer:identity
  "{\"a\":[0.071442,1e-12,2.0,0.1],\"b\\\"\":null}" \
    (json_to_string (`Assoc [ "a", `List [ `Float (71442. /. 1e6) ; `Float 1e-12 ; \
                                          `Float 2. ; `Float 0.1 ] ; \
                              "b\"", `Null ]))
*)

(** How values are written: as {!to_string} does, as CSV, or as JSON. *)
type format = Human | Csv | Json

(** A field of CSV, quoted if it must be (RFC 4180). *)
let csv_field s =
    if String.exists s "," || String.exists s "\"" ||
       String.contains s '\n' || String.contains s '\r' then
        "\""^ String.nreplace ~str:s ~sub:"\"" ~by:"\"\"" ^"\""
    else s

(* A value with no others in it (bytes are one), as a CSV field: *)
let csv_scalar (typ : A.Type.t) v =
    match typ with
    | Record _ | Map _ | Variant _ | Void | Pattern -> None
    | Array t when t <> Byte -> None
    | _ ->
        Some (csv_field (match to_json typ v with
            | `String s -> s
            | j -> json_to_string j))

(* As CSV: a scalar, or a record or array of scalars, as a line; a map of
 * scalars as a line per key and value; and nothing else. *)
let to_csv (typ : A.Type.t) v =
    let row l =
        String.concat "," (List.map (fun (t, v) ->
            Option.get_exn (csv_scalar t v) Exit) l) in
    try
        Some (match typ, v with
            | Record fs, Record vs -> row (List.mapi (fun i (_, t) -> t, vs.(i)) fs)
            | Array t, Array a when t <> Byte ->
                row (List.map (fun v -> t, v) (Array.to_list a))
            | Map (k, t), Map (m, _) ->
                String.concat "\n" (List.map (fun (key, v) ->
                    row [ k, key ; t, v ]) (Map.PMap.bindings m))
            | _ -> Option.get_exn (csv_scalar typ v) Exit)
    with Exit -> None

(*$= to_csv & ~printer:(function None -> "None" | Some s -> s)
  (Some "1.5") (to_csv A.Type.Interval (Interval (Interval.of_secs 1.5)))
  (Some "#0102") (to_csv A.Type.bytes (Array [| Byte 1 ; Byte 2 |]))
  (Some "1,\"a,\"\"b\"\"\",true") \
    (to_csv A.Type.(Record [ "x", Int ; "s", String ; "b", Bool ]) \
            (Record [| Int 1 ; String "a,\"b\"" ; Bool true |]))
  (Some "1,2") (to_csv A.Type.(Array Int) (Array [| Int 1 ; Int 2 |]))
  (Some "") (to_csv A.Type.(Array Int) (Array [||]))
  (Some "a,1\nb,2") \
    (to_csv A.Type.(Map (String, Int)) \
            (Map (Map.PMap.add (String "b") (Int 2) \
                    (Map.PMap.add (String "a") (Int 1) (Map.PMap.create compare_keys)), None)))
  None (to_csv A.Type.(Array (Array Int)) (Array [| Array [||] |]))
  None (to_csv A.Type.(Record [ "a", Array Int ]) (Record [| Array [||] |]))
*)

(** [v] of type [typ] in that format, unless CSV cannot tell it. *)
let format fmt typ v =
    match fmt with
    | Human -> Some (to_string typ v)
    | Csv -> to_csv typ v
    | Json -> Some (json_to_string (to_json typ v))

(* The value of type [typ] that a field takes when nothing tells it: *)
let rec zero (typ : A.Type.t) =
    match typ with
    | Void -> Void
    | Bool -> Bool false
    | Byte -> Byte 0
    | Int -> Int 0
    | Float -> Float 0.
    | String -> String ""
    | Interval -> Interval Interval.zero
    | Time -> Time (Clock.Wall.of_secs 0.)
    | Ip -> Ip Ip.Addr.zero
    | Mac -> Mac Eth.Addr.zero
    | Record fs -> Record (Array.of_list (List.map (zero % snd) fs))
    | Array _ -> Array [||]
    | Map (_, t) -> empty_map (Some (zero t))
    | Variant ((n, t) :: _) -> Variant (n, zero t)
    | Variant [] | Pattern -> invalid_arg "Crafty_value.zero"

let rec equal a b =
    match a, b with
    | Ip a, Ip b -> Ip.Addr.compare a b = 0
    | Mac a, Mac b -> Bitstring.equals (mac_bits a) (mac_bits b)
    | Record a, Record b | Array a, Array b ->
        Array.length a = Array.length b && Array.for_all2 equal a b
    | Variant (n, a), Variant (m, b) -> n = m && equal a b
    | Map _, Map _ -> compare_keys a b = 0
    | a, b -> a = b

(* Only what the typer lets be ordered: *)
let compare_values a b =
    match a, b with
    | Interval a, Interval b -> Interval.compare a b
    | Time a, Time b -> Clock.Wall.compare a b
    | a, b -> compare a b

(* The bits of a byte array: *)
let bits_of_bytes = function
    | Array a -> Bitstring.bitstring_of_string (string_of_bytes a)
    | _ -> invalid_arg "Crafty_value.bits_of_bytes"

(** {2 Errors} *)

exception Runtime_error of A.location * string

let error loc fmt = Printf.ksprintf (fun s -> raise (Runtime_error (loc, s))) fmt

(* An error of what has no location to tell, such as a layer building a
 * packet, which whoever runs it places: *)
exception Failed of string

let fail fmt = Printf.ksprintf (fun s -> raise (Failed s)) fmt
