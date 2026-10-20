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
  Changing the machine robinet runs on: its interfaces, namespaces, firewall
  and kernel settings, for what a simulation needs of them.

  Through the usual commands ([ip], [ethtool]...) rather than through
  netlink: there is no netlink binding here, this is a handful of commands,
  and they are what anybody would check the result with by hand in any case.
  Changing them wants root (or cap_net_admin), which is left to the commands
  to ask for: a capability given to robinet is not given to what it runs.
*)
open Batteries

exception Command_failed of string * string

let () =
    Printexc.register_printer (function
        | Command_failed (cmd, how) ->
            Some (Printf.sprintf "%S %s.\n\
                                  Changing the configuration of the host is \
                                  for root; Have you tried under sudo?" cmd how)
        | _ -> None)

(* Shells do not need to be told about a name or a keyword, and a line of them
 * quoted one by one is a line nobody can read back. *)
let quote arg =
    let plain c =
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || String.contains "_-./:=@," c in
    if arg <> "" && String.for_all plain arg then arg
    else Filename.quote arg

(*$= quote & ~printer:identity
  "eth0" (quote "eth0")
  "'a b'" (quote "a b")
  "''" (quote "")
 *)

(** The command line of [prog] with [args], as a reader would type it. *)
let command_line prog args = String.concat " " (List.map quote (prog :: args))

(** Run [prog] with [args], or say which command would not run.
 *
 * [quiet] silences what the command itself has to say, never the line naming
 * it: a command that is undoing something reports on a state of affairs that
 * is already being given up on -- half of it may be gone before it runs -- and
 * the error that matters was reported before it. What was run is worth seeing
 * either way, so that a reader whose program was killed before it could tidy
 * up knows what is left and what to type. *)
let run ?(quiet=false) prog args =
    let cmd = command_line prog args in
    (* Printed rather than logged: what is being changed here is the machine
     * the simulation runs on, not anything in the simulation, and it
     * outlives the run. A reader has to be able to see what was done to
     * their machine, and to undo it by hand. *)
    Printf.printf "%s\n%!" cmd ;
    (* What is printed is what a reader would type; what is run is that, with
     * its own noise thrown away when it is undoing something. *)
    match Unix.system (if quiet then cmd ^" >/dev/null 2>&1" else cmd) with
    | Unix.WEXITED 0 -> ()
    | Unix.WEXITED n ->
        raise (Command_failed (cmd, Printf.sprintf "exited with status %d" n))
    | Unix.WSIGNALED n | Unix.WSTOPPED n ->
        raise (Command_failed (cmd, Printf.sprintf "was signalled (%d)" n))

(** As [run], for a command that may fail without it mattering: what was asked
 * for and what is there may already agree, and a command that fails on the
 * way out is not a reason to stop taking things down. *)
let try_run prog args = try run ~quiet:true prog args with _ -> ()
