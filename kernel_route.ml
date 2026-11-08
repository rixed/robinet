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
  Asking the host's kernel where it would route a packet, over netlink: at a
  few microseconds, cheap enough to ask for every packet. Linux only.
*)
open Batteries

type kind = Unicast | Local | Broadcast | Multicast | Unroutable

type answer =
    { kind : kind ;
      ifname : string ;
      gateway : Ip.Addr.t option }

external available : unit -> bool = "wrap_route_available"
external lookup_ : string -> string -> int * string * string = "wrap_route_lookup"

(* The RTN_* of <linux/rtnetlink.h>: *)
let kind_of_rtn = function
    | 1 -> Unicast
    | 2 | 4 -> Local (* or anycast, which is the host's too *)
    | 3 -> Broadcast
    | 5 -> Multicast
    | _ -> Unroutable

(** The route to [dst], through the interface named [oif] only if given. *)
let lookup ?(oif="") dst =
    let bytes = Bitstring.string_of_bitstring (Ip.Addr.to_bitstring dst) in
    match lookup_ bytes oif with
    | rtn, ifname, gw ->
        Ok { kind = kind_of_rtn rtn ; ifname ;
             gateway = if gw = "" then None
                       else Some (Ip.Addr.of_bitstring (Bitstring.bitstring_of_string gw)) }
    | exception Failure e -> Error e

(*$T lookup
  not (available ()) || \
    match lookup (Ip.Addr.of_string "127.0.0.1") with \
    | Ok { kind = Local ; ifname = "lo" ; gateway = None } -> true \
    | _ -> false
  not (available ()) || \
    match lookup ~oif:"robinet-no-such-iface" (Ip.Addr.of_string "127.0.0.1") with \
    | Error _ -> true \
    | Ok _ -> false
*)
