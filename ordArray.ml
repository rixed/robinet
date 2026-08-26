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
  An OrdArray is a container for an ordered set of bounded size.
*)
open Batteries

type entry = { mutable prev : int ;
               mutable next : int }
type 'a t =
    {     last_used : entry array ; (** The ordered list of indices. *)
      mutable first : int ;         (** The index of the first element. *)
       mutable last : int ;         (** and the last one. *)
               data : 'a array }    (** User data *)

let make_from_data data =
    let s = Array.length data in
    { last_used = Array.init s (fun i ->
        (* -1 is for invalid: *)
        { prev = if i = 0 then -1 else i-1 ;
          next = if i = s-1 then -1 else i+1 }) ;
      first = 0 ;
      last = s-1 ;
      data  }

let make s x = make_from_data (Array.create s x)
let init s f = make_from_data (Array.init s f)

(** Returns the first and last indices: *)
let first t = t.first
let last t = t.last

(** So that [get t (first t)] will return the first data item in the queue *)
let get t n = t.data.(n)
let set t n x = t.data.(n) <- x

let unlink t n =
    if t.last_used.(n).prev <> -1 then
        t.last_used.(t.last_used.(n).prev).next <- t.last_used.(n).next ;
    if t.last_used.(n).next <> -1 then
        t.last_used.(t.last_used.(n).next).prev <- t.last_used.(n).prev ;
    if t.first = n then t.first <- t.last_used.(n).next ;
    if t.last = n then t.last <- t.last_used.(n).prev

(* n must have already been unlinked! *)
let link_at_head t n =
    t.last_used.(n).prev <- -1 ;
    t.last_used.(n).next <- t.first ;
    t.last_used.(t.first).prev <- n ;
    t.first <- n

let promote t n =
    unlink t n ;
    link_at_head t n

(*$R promote
    let oa = make_from_data [| 5;6;7 |] in
    assert_equal ~printer:string_of_int ~msg:"order should be preserved at creation"
        5 (get oa (first oa)) ;
    promote oa 1 ;
    assert_equal ~printer:string_of_int ~msg:"promoted item should come first"
        6 (get oa (first oa)) ;
    assert_equal ~printer:string_of_int ~msg:"but last one should not change"
        7 (get oa (last oa))
 *)

(* Overwrite the last entry with [x] and make it the new first entry: *)
let prepend t x =
    set t t.last x ;
    promote t t.last
