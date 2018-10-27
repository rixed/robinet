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
  This module can set-up a tap interface and use it to send/receive traffic.
  It does this without libpcap.
 *)
open Batteries
open Bitstring
open Tools

let debug = true

let make n =
    let fname = "/dev/tap" ^ string_of_int n in
    let open Legacy.Unix in
    if debug then Printf.printf "Tap: Opening %s" fname ;
    let fd = openfile fname [O_RDWR; O_CLOEXEC] 0o640 in
    Printf.sprintf "ifconfig tap%d up" n |>
    Sys.command |> ignore ; (* TODO: check err code *)
    last_tap := fd

