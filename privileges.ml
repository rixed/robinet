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
  What the process is allowed beyond its user, as root or through the
  capabilities [setcap cap_net_raw,cap_net_admin=ep] gives a binary.
*)

(** Whether the process gained privileges when it started (setuid, or
 * capabilities of its file): the libc then ignores the environment, which
 * its user chose. *)
external is_secure : unit -> bool = "wrap_is_secure"

(** Empty the environment, for {!Unix.putenv} to fill again. *)
external clearenv : unit -> unit = "wrap_clearenv"

(** Whether the process may change the network configuration, as root may. *)
external has_net_admin : unit -> bool = "wrap_has_net_admin"

external pass_on_net_caps : unit -> int = "wrap_pass_on_net_caps"
external restore_net_caps : int -> unit = "wrap_restore_net_caps"

(** Call [f], during which the programs this thread runs get the
 * cap_net_admin and cap_net_raw it has, although they have none of their
 * own, which ip, nft, ethtool... need. Root's programs need nothing of this,
 * and nothing happens to a process without these capabilities. *)
let with_net_caps_passed_on f =
    let done_ = pass_on_net_caps () in
    Fun.protect ~finally:(fun () -> restore_net_caps done_) f
