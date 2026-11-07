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
  Marks: tags on bits that follow them through the network.

  A mark covers a range of the buffer of a bitstring. Slices share their
  buffer, so they keep the marks of the bits they cover; a copy must be given
  them with [carry], which every function copying payloads around must call
  ({!Tools.concat} does). While no mark is live, [carry] and [find] cost one
  comparison.

  Simulations run in threads of their own and share these tables, which a
  lock protects. The count of live marks is read without it: a thread may see
  it stale only about the marks of other simulations, which are on buffers of
  theirs it never handles.
  *)

type t = int

let live_count = Atomic.make 0

let active () = Atomic.get live_count > 0

(* What follows is only used with [lock] held: *)
let lock = Mutex.create ()

let locked f =
    Mutex.lock lock ;
    match f () with
    | x -> Mutex.unlock lock ; x
    | exception e -> Mutex.unlock lock ; raise e

(* Live marks: *)
let live : (t, unit) Hashtbl.t = Hashtbl.create 3

(* Buffers are keyed by identity, but hashed by length as their content may
 * change after they are marked (checksums are patched in place): *)
module Buffers = Ephemeron.K1.Make (struct
    type t = Bytes.t
    let equal = (==)
    let hash = Bytes.length
end)

(* The ranges of each marked buffer, in bits: start, length and mark: *)
let buffers : (int * int * t) list Buffers.t = Buffers.create 16

let next = ref 0

let make () =
    locked (fun () ->
        incr next ;
        Hashtbl.replace live !next () ;
        Atomic.incr live_count ;
        !next)

(** Once released, a mark is carried no more and found nowhere. Releasing
 * it again does nothing. *)
let release m =
    locked (fun () ->
        if Hashtbl.mem live m then (
            Hashtbl.remove live m ;
            Atomic.decr live_count ;
            if Hashtbl.length live = 0 then Buffers.reset buffers))

let add_range b start len m =
    let ranges = Option.value ~default:[] (Buffers.find_opt buffers b) in
    Buffers.replace buffers b
        ((start, len, m) :: List.filter (fun (_, _, m) -> Hashtbl.mem live m) ranges)

(** Marks the bits of [bits] with [m]. *)
let add m ((b, off, len) : Bitstring.bitstring) =
    locked (fun () -> if Hashtbl.mem live m && len > 0 then add_range b off len m)

(* The live ranges of [b] that overlap [off, off+len), cut to it: *)
let overlapping b off len =
    match Buffers.find_opt buffers b with
    | None -> []
    | Some ranges ->
        List.filter_map (fun (s, l, m) ->
            let s' = max s off and e' = min (s + l) (off + len) in
            if s' < e' && Hashtbl.mem live m then Some (s', e' - s', m)
            else None) ranges

(** The marks of any bit of [bits]. *)
let find ((b, off, len) : Bitstring.bitstring) =
    if not (active ()) then [] else
    locked (fun () -> List.map (fun (_, _, m) -> m) (overlapping b off len)) |>
    List.sort_uniq compare

let mem m bits = List.mem m (find bits)

(** Gives the bits of [dst] from bit [at] the marks of [src], of which they
 * are a copy. *)
let carry ~src:((b, off, len) : Bitstring.bitstring)
          ~dst:((db, doff, _) : Bitstring.bitstring) ~at =
    if active () && b != db then
        locked (fun () ->
            List.iter (fun (s, l, m) ->
                add_range db (doff + at + s - off) l m) (overlapping b off len))

(*$R
  let before = Atomic.get live_count in
  let m = make () in
  let bits = Bitstring.bitstring_of_string "abcdef" in
  add m (Bitstring.subbitstring bits 16 16) ;
  assert_bool "the marked bits" (mem m (Bitstring.subbitstring bits 8 16)) ;
  assert_bool "not the others" (not (mem m (Bitstring.subbitstring bits 32 16))) ;
  let copy = Tools.concat [ Bitstring.bitstring_of_string "xy" ; bits ] in
  assert_bool "a copy" (mem m (Bitstring.subbitstring copy 32 8)) ;
  assert_bool "where they were copied" (not (mem m (Bitstring.subbitstring copy 16 16))) ;
  release m ;
  assert_bool "released" (not (mem m copy)) ;
  release m ;
  assert_equal ~printer:string_of_int before (Atomic.get live_count)
*)
