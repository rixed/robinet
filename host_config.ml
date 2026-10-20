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

(** What [prog] with [args] prints, which reading the configuration of the
 * host changes nothing of, so the command is not printed. *)
let output prog args =
    (* UnixLabels, whose channels are those of the stdlib, unlike Batteries'
     * Unix: *)
    let ic = UnixLabels.open_process_args_in prog (Array.of_list (prog :: args)) in
    let out = Stdlib.In_channel.input_all ic in
    (* Failing to read is no matter of privileges, as {!Command_failed}
     * suggests: *)
    let fail how =
        failwith (Printf.sprintf "%S %s" (command_line prog args) how) in
    match UnixLabels.close_process_in ic with
    | Unix.WEXITED 0 -> out
    | Unix.WEXITED n -> fail (Printf.sprintf "exited with status %d" n)
    | Unix.WSIGNALED n | Unix.WSTOPPED n ->
        fail (Printf.sprintf "was signalled (%d)" n)

(** {2 Interfaces} *)

(** What a simulated adapter needs to stand in for an interface: *)
type iface =
    { ifname : string ;
      mac : Eth.Addr.t ;
      mtu : int ;
      (* Its first IPv4 address and netmask, if any: *)
      ip : (Ip.Addr.t * Ip.Addr.t) option ;
      (* The IPv4 gateway of its default route, if any: *)
      gateway : Ip.Addr.t option }

let netmask_of_prefix n =
    Ip.Addr.of_bitstring (Bitstring.concat [ Bitstring.ones_bitstring n ;
                                             Bitstring.zeroes_bitstring (32 - n) ])

(*$= netmask_of_prefix & ~printer:identity
  "255.255.255.0" (Ip.Addr.to_dotted_string (netmask_of_prefix 24))
  "255.255.240.0" (Ip.Addr.to_dotted_string (netmask_of_prefix 20))
  "0.0.0.0" (Ip.Addr.to_dotted_string (netmask_of_prefix 0))
 *)

(* [ip_addr] is the output of [ip -j addr show dev IF], [ip_route] that of
 * [ip -j -4 route show default dev IF]: *)
let iface_of_json ifname ~ip_addr ~ip_route =
    let open Yojson.Basic.Util in
    let link =
        match Yojson.Basic.from_string ip_addr with
        | `List [ link ] -> link
        | _ -> failwith (Printf.sprintf "No interface %s" ifname) in
    let ip =
        link |> member "addr_info" |> to_list |>
        List.find_map_opt (fun a ->
            if member "family" a = `String "inet" then
                Some (Ip.Addr.of_dotted_string (member "local" a |> to_string),
                      netmask_of_prefix (member "prefixlen" a |> to_int))
            else None)
    and gateway =
        Yojson.Basic.from_string ip_route |> to_list |>
        List.find_map_opt (fun r ->
            member "gateway" r |> to_string_option |>
            Option.map Ip.Addr.of_dotted_string) in
    { ifname ;
      mac = Eth.Addr.of_string (link |> member "address" |> to_string) ;
      mtu = link |> member "mtu" |> to_int ;
      ip ; gateway }

(*$inject
  let sample_addr = {|[{"ifindex":3,"ifname":"wlp59s0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"qdisc":"noqueue","operstate":"UP","group":"default","txqlen":1000,"link_type":"ether","address":"04:ea:56:ad:bf:ab","broadcast":"ff:ff:ff:ff:ff:ff","altnames":["wlx04ea56adbfab"],"addr_info":[{"family":"inet6","local":"fe80::2f5d:b660:1af9:29","prefixlen":64,"scope":"link","noprefixroute":true,"valid_life_time":4294967295,"preferred_life_time":4294967295},{"family":"inet","local":"192.168.1.31","prefixlen":24,"broadcast":"192.168.1.255","scope":"global","dynamic":true,"noprefixroute":true,"label":"wlp59s0","valid_life_time":35881,"preferred_life_time":35881}]}]|}
  let sample_route = {|[{"dst":"default","gateway":"192.168.1.254","dev":"wlp59s0","protocol":"dhcp","prefsrc":"192.168.1.31","metric":600,"flags":[]}]|}
  let describe i =
      Printf.sprintf "%s %s mtu=%d ip=%s gw=%s" i.ifname
          (Eth.Addr.to_hexstring i.mac) i.mtu
          (match i.ip with
           | None -> "none"
           | Some (a, m) -> Ip.Addr.to_dotted_string a ^"/"^ Ip.Addr.to_dotted_string m)
          (Option.map_default Ip.Addr.to_dotted_string "none" i.gateway)
*)
(*$= iface_of_json & ~printer:identity
  "wlp59s0 04:EA:56:AD:BF:AB mtu=1500 ip=192.168.1.31/255.255.255.0 gw=192.168.1.254" \
    (describe (iface_of_json "wlp59s0" ~ip_addr:sample_addr ~ip_route:sample_route))
  "wlp59s0 04:EA:56:AD:BF:AB mtu=1500 ip=192.168.1.31/255.255.255.0 gw=none" \
    (describe (iface_of_json "wlp59s0" ~ip_addr:sample_addr ~ip_route:"[]"))
 *)

(** The configuration of interface [ifname]. *)
let iface ifname =
    iface_of_json ifname
        ~ip_addr:(output "ip" [ "-j" ; "addr" ; "show" ; "dev" ; ifname ])
        ~ip_route:(output "ip" [ "-j" ; "-4" ; "route" ; "show" ; "default" ;
                                 "dev" ; ifname ])
