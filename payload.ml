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
  Represents the payload of any protocol as a bitstring, with associated functions
  *)
open Bitstring
open Tools

include Private.Make (struct
    type t = bitstring
    let to_string t =
        let bytes = bytelength t in
        if bytes > 0 then (
            Printf.sprintf "%d bytes (%s)" bytes (hexstring_of_bitstring_abbrev t)
        ) else "empty"
    let is_valid _ = true
    let repl_tag = "bits"
end)

let empty = o empty_bitstring
let bitlength (t : t) = bitstring_length (t :> bitstring)
let length (t : t) = bytelength (t :> bitstring)
let random len = o (randbs len)
(* Since a bitstring is a slice, if we want a hash of the content we have
 * to extract the content first: *)
let hash (t : t) =
    string_of_bitstring (t :> bitstring) |> Hashtbl.hash
let is_empty (t : t) = bitstring_is_empty (t :> bitstring)
