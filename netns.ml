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

  Neither end is given an address. What holds one is the business of the
  network on this side: a DHCP server in the document can hand the namespace
  its address, its gateway and its DNS, which is most of the reason for joining
  the two.
*)
open Batteries

(* Through [ip] rather than through netlink: there is no netlink binding here,
 * this is a handful of commands, and [ip] is what anybody would check the
 * result with by hand in any case. *)
let ip = "ip"

exception Command_failed of string * string

let () =
    Printexc.register_printer (function
        | Command_failed (cmd, how) ->
            Some (Printf.sprintf "%S %s.\n\
                                  Making a namespace or an interface is for \
                                  root, and this is the one thing robinet \
                                  asks to be root for: if that is what it \
                                  lacked, try again under sudo." cmd how)
        | _ -> None)

(* Shells do not need to be told about a name or a keyword, and a line of them
 * quoted one by one is a line nobody can read back. *)
let quote arg =
    let plain c =
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || String.contains "_-./:=@," c in
    if arg <> "" && String.for_all plain arg then arg
    else Filename.quote arg

(* Run one [ip] command, or say which one would not run.
 *
 * [quiet] silences what the command itself has to say, never the line naming
 * it: a command that is undoing something reports on a state of affairs that
 * is already being given up on -- half of it may be gone before it runs -- and
 * the error that matters was reported before it. What was run is worth seeing
 * either way, so that a reader whose robinet was killed before it could tidy
 * up knows what is left and what to type. *)
let run ?(quiet=false) args =
    let cmd = String.concat " " (ip :: List.map quote args) in
    (* Printed rather than logged, and this is the only thing in the library
     * that prints: what is being changed here is the machine the simulation
     * runs on, not anything in the simulation, and it outlives the run. A
     * reader has to be able to see what was done to their interfaces, and to
     * undo it by hand if robinet is killed before it can. *)
    Printf.printf "%s\n%!" cmd ;
    (* What is printed is what a reader would type; what is run is that, with
     * its own noise thrown away when it is undoing something. *)
    match Unix.system (if quiet then cmd ^" >/dev/null 2>&1" else cmd) with
    | Unix.WEXITED 0 -> ()
    | Unix.WEXITED n ->
        raise (Command_failed (cmd, Printf.sprintf "exited with status %d" n))
    | Unix.WSIGNALED n | Unix.WSTOPPED n ->
        raise (Command_failed (cmd, Printf.sprintf "was signalled (%d)" n))

(* What was asked for and what is there may already agree, and a command that
 * fails on the way out is not a reason to stop taking things down. *)
let try_run args = try run ~quiet:true args with _ -> ()

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
        run [ "netns" ; "exec" ; ns ; ip ; "link" ; "set" ; peer ; "up" ]
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
