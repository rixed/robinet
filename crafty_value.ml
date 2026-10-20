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

(* How a value of type [typ] is written into a string: *)
let rec to_string (typ : A.Type.t) v =
    match typ, v with
    | _, Void -> ""
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
    | Variant cs, Variant (n, v) ->
        let t = try List.assoc n cs with Not_found -> A.Type.Void in
        if t = A.Type.Void then n else n ^" "^ to_string t v
    | _ -> invalid_arg "Crafty_value.to_string"

let rec equal a b =
    match a, b with
    | Ip a, Ip b -> Ip.Addr.compare a b = 0
    | Mac a, Mac b -> Bitstring.equals (mac_bits a) (mac_bits b)
    | Record a, Record b | Array a, Array b ->
        Array.length a = Array.length b && Array.for_all2 equal a b
    | Variant (n, a), Variant (m, b) -> n = m && equal a b
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
