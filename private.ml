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
(* A Module with a private type and custom printer, used
   to customize printing of various protocolar fields such as
   TCP ports and so on. A little convoluted but we gain:
   - the toplevel don't mix TCP ports with ETH protocol fields
     and can display them differently;
   - the programmer can't confuse the two either or will be told
     by the compiler. *)
open Batteries

module type S =
sig
    type t
    type outer_t
    val to_string : t -> string
    val print : Format.formatter -> t -> unit
    val printf : 'a BatInnerIO.output -> t -> unit
    val o : outer_t -> t
end

module Make (Outer : sig
    type t
    val to_string : t -> string
    val is_valid : t -> bool
    val repl_tag : string
end) : S with type t = private Outer.t and type outer_t = Outer.t =
struct
    type t = Outer.t
    type outer_t = Outer.t
    let to_string = Outer.to_string
    let print fmt t = Format.fprintf fmt "@{<%s>%s@}" Outer.repl_tag (to_string t)
    let printf oc t = String.print oc (to_string t)

    let o t =
      if not (Outer.is_valid t) then (
        Printf.eprintf "Invalid value for type %S\n%!" Outer.repl_tag ;
        assert false
      ) ;
      t
end
