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
  Somewhere for a portal to open onto.

  A portal is a real interface of the machine, by name, and robinet is happy to
  be handed one that is already there. This is for when it is not: for a portal
  called [foo] it makes a network namespace [foo] and a veth pair, [foo] left
  where robinet can sniff it and [foo-ns] moved into the namespace, which is
  where whatever is to talk to the simulated network runs -- a shell under [ip
  netns exec foo], a container, a program of one's own.

  This wants root, and is the only thing in robinet that does: opening an
  interface that is already there asks no more than the cap_net_raw and
  cap_net_admin the Makefile advises, which is why it is a separate ask made by
  a separate option. Nothing clever is attempted about it -- a capability given
  to robinet is not given to the [ip] it runs, and handing one over would want
  cap_dac_override on top, which is root by another name. So [ip] is left to
  fail, and to say what it lacked.

  The end in the namespace sends with checksum offload off, and so without
  segmentation offload either: robinet passes on frames as it captures them, so
  a checksum left for a veth to never fill in would reach the next kernel wrong
  and be dropped there, and a TCP segment the size of 64KB would cross a
  simulated link whole.

  Neither end is given an address. What holds one is the business of the
  network on this side: a DHCP server in the document can hand the namespace
  its address, its gateway and its DNS, which is most of the reason for joining
  the two.
*)
open Batteries

let ip = "ip"

let run args = Host_config.run ip args
let try_run args = Host_config.try_run ip args

(** The far end of the pair for a portal called [ifname]: what it is called,
 * and the namespace it lives in. Both are named after the portal, so that
 * nothing has to be looked up to use them. *)
let peer_of ifname = ifname ^"-ns"
let namespace_of ifname = ifname

(** Make the namespace and the pair a portal called [ifname] needs, and bring
 * both ends up. Raises if any of it will not go, having undone what it made:
 * half a pair is not a smaller pair, and the portal that was to open on it is
 * about to say the interface is not there. *)
let setup ifname =
    let peer = peer_of ifname and ns = namespace_of ifname in
    try
        run [ "netns" ; "add" ; ns ] ;
        run [ "link" ; "add" ; ifname ; "type" ; "veth" ; "peer" ; "name" ; peer ] ;
        run [ "link" ; "set" ; peer ; "netns" ; ns ] ;
        run [ "link" ; "set" ; ifname ; "up" ] ;
        run [ "netns" ; "exec" ; ns ; ip ; "link" ; "set" ; "lo" ; "up" ] ;
        run [ "netns" ; "exec" ; ns ; ip ; "link" ; "set" ; peer ; "up" ] ;
        run [ "netns" ; "exec" ; ns ; "ethtool" ; "-K" ; peer ; "tx" ; "off" ]
    with e ->
        try_run [ "netns" ; "del" ; ns ] ;
        try_run [ "link" ; "del" ; ifname ] ;
        raise e

(** Take back what {!setup} made for [ifname], and nothing else: a namespace
 * takes the veth inside it with it, and a pair goes when either of its ends
 * does. Best effort, since this runs while the program is leaving and the
 * reader has nothing to do with what it might say. *)
let teardown ifname =
    try_run [ "netns" ; "del" ; namespace_of ifname ] ;
    try_run [ "link" ; "del" ; ifname ]
