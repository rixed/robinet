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

(** Run the command line [cmd], or say which command would not run.
 *
 * [quiet] silences what the command itself has to say, never the line naming
 * it: a command that is undoing something reports on a state of affairs that
 * is already being given up on -- half of it may be gone before it runs -- and
 * the error that matters was reported before it. What was run is worth seeing
 * either way, so that a reader whose program was killed before it could tidy
 * up knows what is left and what to type. *)
let run_line ?(quiet=false) cmd =
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

(** As [run_line], for [prog] with [args]. *)
let run ?quiet prog args = run_line ?quiet (command_line prog args)

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

(** {2 Ports} *)

type proto = Tcp | Udp

let string_of_proto = function Tcp -> "tcp" | Udp -> "udp"

(** An inclusive range of ports of a protocol. *)
type port_range = { proto : proto ; lo : int ; hi : int }

(** [port_range_of_string proto "lo-hi"], or of a single port. *)
let port_range_of_string proto s =
    let port s =
        match int_of_string (String.trim s) with
        | p when p > 0 && p < 0x10000 -> p
        | _ | exception Failure _ ->
            invalid_arg (Printf.sprintf "Not a port: %S" s) in
    let lo, hi =
        match String.split s ~by:"-" with
        | lo, hi -> port lo, port hi
        | exception Not_found -> port s, port s in
    if lo > hi then invalid_arg (Printf.sprintf "Empty range of ports: %S" s) ;
    { proto ; lo ; hi }

(*$T port_range_of_string
  port_range_of_string Tcp "14000-14099" = { proto = Tcp ; lo = 14000 ; hi = 14099 }
  port_range_of_string Udp "53" = { proto = Udp ; lo = 53 ; hi = 53 }
  try ignore (port_range_of_string Udp "2-1") ; false with Invalid_argument _ -> true
  try ignore (port_range_of_string Udp "0") ; false with Invalid_argument _ -> true
  try ignore (port_range_of_string Udp "50000:50099") ; false with Invalid_argument _ -> true
 *)

let string_of_range r =
    if r.lo = r.hi then string_of_int r.lo else Printf.sprintf "%d-%d" r.lo r.hi

(** A pcap filter for what a program may receive: ARP, and IPv4 to [ip] if
 * given, of which ICMP and the TCP and UDP ports of [ports], if any. *)
let pcap_filter ?ip ports =
    let l4 =
        if ports = [] then None
        else Some (String.concat " or " (
            "icmp" :: List.map (fun r ->
                Printf.sprintf "(%s dst portrange %d-%d)"
                    (string_of_proto r.proto) r.lo r.hi) ports)) in
    match ip, l4 with
    | None, None -> ""
    | None, Some l4 -> "arp or "^ l4
    | Some ip, None -> "arp or dst host "^ Ip.Addr.to_dotted_string ip
    | Some ip, Some l4 ->
        Printf.sprintf "arp or (dst host %s and (%s))"
            (Ip.Addr.to_dotted_string ip) l4

(*$= pcap_filter & ~printer:identity
  "" (pcap_filter [])
  "arp or dst host 10.0.0.1" (pcap_filter ~ip:(Ip.Addr.of_string "10.0.0.1") [])
  "arp or icmp or (tcp dst portrange 14000-14099) or (udp dst portrange 53-53)" \
    (pcap_filter [ port_range_of_string Tcp "14000-14099" ; port_range_of_string Udp "53" ])
  "arp or (dst host 10.0.0.1 and (icmp or (udp dst portrange 1-2)))" \
    (pcap_filter ~ip:(Ip.Addr.of_string "10.0.0.1") [ port_range_of_string Udp "1-2" ])
 *)

(** {2 Firewall} *)

(** The nftables script of a table [table] of rules about interface
 * [ifname], that keeps the kernel off the [ports]: what comes in to them,
 * what leaves from them, and the ICMP errors about them either way, IPv4
 * and IPv6. ICMP errors are told by the ports of the packet they quote,
 * assuming an IPv4 header with no options, and an IPv6 header with no
 * extension. With [forward_drop], it also keeps the kernel from forwarding
 * what is for that address. *)
let ruleset ~table ~ifname ?(ports=[]) ?forward_drop () =
    let ip_proto = function Tcp -> 6 | Udp -> 17 in
    (* The ICMP errors quoting [r]'s ports, as source ([src]) or as
     * destination, with offsets in bits from the start of the ICMP header: *)
    let icmp_errors r ~src =
        let port = if src then 0 else 16 in
        [ Printf.sprintf "icmp type { destination-unreachable, time-exceeded, \
                          parameter-problem } @th,64,8 0x45 @th,136,8 %d \
                          @th,%d,16 %s drop"
              (ip_proto r.proto) (224 + port) (string_of_range r) ;
          Printf.sprintf "icmpv6 type { destination-unreachable, packet-too-big, \
                          time-exceeded, parameter-problem } @th,112,8 %d \
                          @th,%d,16 %s drop"
              (ip_proto r.proto) (384 + port) (string_of_range r) ] in
    let chain hook dir rules =
        if rules = [] then "" else
        Printf.sprintf "    chain %s {\n\
                        \        type filter hook %s priority filter; policy accept;\n\
                        %s\
                        \    }\n" hook hook
            (String.concat "" (List.map (fun r ->
                Printf.sprintf "        %s %S %s\n" dir ifname r) rules)) in
    let input =
        List.concat_map (fun r ->
            Printf.sprintf "%s dport %s drop"
                (string_of_proto r.proto) (string_of_range r) ::
            icmp_errors r ~src:true) ports
    and output =
        List.concat_map (fun r ->
            Printf.sprintf "%s sport %s drop"
                (string_of_proto r.proto) (string_of_range r) ::
            icmp_errors r ~src:false) ports
    and forward =
        Option.map_default (fun ip ->
            [ "ip daddr "^ Ip.Addr.to_dotted_string ip ^" drop" ]) [] forward_drop in
    Printf.sprintf "table inet %s {\n%s%s%s}\n" table
        (chain "input" "iifname" input)
        (chain "output" "oifname" output)
        (chain "forward" "iifname" forward)

(*$= ruleset & ~printer:identity
  (String.concat "\n" [ \
    "table inet t {" ; \
    "    chain input {" ; \
    "        type filter hook input priority filter; policy accept;" ; \
    "        iifname \"eth0\" udp dport 53 drop" ; \
    "        iifname \"eth0\" icmp type { destination-unreachable, time-exceeded, parameter-problem } @th,64,8 0x45 @th,136,8 17 @th,224,16 53 drop" ; \
    "        iifname \"eth0\" icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } @th,112,8 17 @th,384,16 53 drop" ; \
    "    }" ; \
    "    chain output {" ; \
    "        type filter hook output priority filter; policy accept;" ; \
    "        oifname \"eth0\" udp sport 53 drop" ; \
    "        oifname \"eth0\" icmp type { destination-unreachable, time-exceeded, parameter-problem } @th,64,8 0x45 @th,136,8 17 @th,240,16 53 drop" ; \
    "        oifname \"eth0\" icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } @th,112,8 17 @th,400,16 53 drop" ; \
    "    }" ; \
    "}" ; "" ]) \
    (ruleset ~table:"t" ~ifname:"eth0" ~ports:[ port_range_of_string Udp "53" ] ())
  (String.concat "\n" [ \
    "table inet t {" ; \
    "    chain forward {" ; \
    "        type filter hook forward priority filter; policy accept;" ; \
    "        iifname \"eth0\" ip daddr 10.0.0.1 drop" ; \
    "    }" ; \
    "}" ; "" ]) \
    (ruleset ~table:"t" ~ifname:"eth0" ~forward_drop:(Ip.Addr.of_string "10.0.0.1") ())
 *)

(** {2 Changes and their undoing}
 *
 * A set of changes is undone in the reverse order of its changes, at the end
 * of the program that made it, and also by any later one if that program was
 * killed: each change first writes the command that undoes it to a file of
 * the set, in {!state_dir}, named after the set, which also holds the pid of
 * its program. *)

let state_dir = "/run/robinet"

type changes =
    { name : string ;
      file : string ;
      (* The commands undoing what was done, the latest first: *)
      mutable undo : string list ;
      mutable undone : bool }

(** A new set of changes called [name] (made of letters, digits and
 * underscores, as it names an nftables table too), which the pid of this
 * process is appended to. *)
let changes name =
    let name = Printf.sprintf "%s_%d" name (Unix.getpid ()) in
    if not (String.for_all (fun c -> Char.is_letter c || Char.is_digit c ||
                                      c = '_') name) then
        invalid_arg (Printf.sprintf "Not a name for changes: %S" name) ;
    run "mkdir" [ "-p" ; state_dir ] ;
    let file = state_dir ^"/"^ name in
    File.with_file_out file (fun oc ->
        Printf.fprintf oc "pid %d\n" (Unix.getpid ())) ;
    { name ; file ; undo = [] ; undone = false }

(** Make a change by running [prog] with [args], after having recorded that
 * running [undo] (a program and its arguments) undoes it. *)
let change t ~undo prog args =
    let undo = command_line (List.hd undo) (List.tl undo) in
    File.with_file_out ~mode:[ `append ] t.file (fun oc ->
        Printf.fprintf oc "%s\n" undo) ;
    t.undo <- undo :: t.undo ;
    run prog args

(* Undo [cmds], the latest first, as best as possible: *)
let undo_lines cmds =
    List.iter (fun cmd -> try run_line ~quiet:true cmd with _ -> ()) cmds

(** Undo what [t] did, once. *)
let undo t =
    if not t.undone then (
        t.undone <- true ;
        undo_lines t.undo ;
        try_run "rm" [ "-f" ; t.file ; t.file ^".nft" ])

(* The pid and the undoing commands, the latest first, of a file of
 * changes: *)
let read_changes file =
    match File.lines_of file |> List.of_enum with
    | pid :: cmds when String.starts_with pid "pid " ->
        Some (int_of_string (String.lchop ~n:4 pid), List.rev cmds)
    | _ | exception _ -> None

(** Undo the changes left by processes that are no longer running, and
 * return their names. *)
let cleanup_stale () =
    match Sys.readdir state_dir with
    | exception Sys_error _ -> []
    | files ->
        Array.to_list files |>
        List.filter (fun name -> not (String.ends_with name ".nft")) |>
        List.filter_map (fun name ->
            let file = state_dir ^"/"^ name in
            match read_changes file with
            | Some (pid, cmds) when not (Sys.file_exists (Printf.sprintf "/proc/%d" pid)) ->
                undo_lines cmds ;
                try_run "rm" [ "-f" ; file ; file ^".nft" ] ;
                Some name
            | _ -> None)

(** {2 What can be changed} *)

(** Install the nftables table of {!ruleset}, named after [t]. *)
let firewall t ~ifname ?ports ?forward_drop () =
    let script = t.file ^".nft" in
    File.with_file_out script (fun oc ->
        String.print oc (ruleset ~table:t.name ~ifname ?ports ?forward_drop ())) ;
    change t ~undo:[ "nft" ; "delete" ; "table" ; "inet" ; t.name ]
        "nft" [ "-f" ; script ]

let reserved_ports_sysctl = "net.ipv4.ip_local_reserved_ports"

(** [ports] added to the reserved ports [current] (as the sysctl gives them,
 * which is ranges and ports separated by commas). *)
let add_reserved_ports current ports =
    let current = String.trim current in
    let added =
        List.map string_of_range ports |> List.unique |>
        List.filter (fun r -> not (List.mem r (String.split_on_char ',' current))) in
    String.concat "," ((if current = "" then [] else [ current ]) @ added)

(*$= add_reserved_ports & ~printer:identity
  "14000-14099,53" \
    (add_reserved_ports "\n" [ port_range_of_string Tcp "14000-14099" ; \
                                port_range_of_string Udp "53" ])
  "8080,53" (add_reserved_ports "8080\n" [ port_range_of_string Udp "53" ; \
                                           port_range_of_string Tcp "53" ])
 *)

(** Keep the kernel from picking [ports] as local ports of its own (TCP and
 * UDP alike, IPv4 and IPv6). Undoing restores the reserved ports as they
 * were, whatever reserved others since. *)
let reserve_ports t ports =
    let current =
        File.with_file_in ("/proc/sys/net/ipv4/ip_local_reserved_ports") IO.read_all in
    let set v = [ "sysctl" ; "-w" ; reserved_ports_sysctl ^"="^ v ] in
    change t ~undo:(set (String.trim current))
        "sysctl" (List.tl (set (add_reserved_ports current ports)))

(** The features of [ethtool -k] output that gather received packets, and
 * are on and can be turned off. *)
let rx_offloads_on ethtool_k =
    let features = [ "generic-receive-offload" ; "large-receive-offload" ;
                     "rx-gro-hw" ; "rx-gro-list" ; "rx-udp-gro-forwarding" ] in
    String.split_on_char '\n' ethtool_k |>
    List.filter_map (fun line ->
        match String.split (String.trim line) ~by:": " with
        | feature, state when List.mem feature features &&
                              String.starts_with state "on" &&
                              not (String.exists state "[fixed]") ->
            Some feature
        | _ | exception Not_found -> None)

(*$= rx_offloads_on & ~printer:(String.concat ",")
  [ "generic-receive-offload" ; "rx-gro-list" ] \
    (rx_offloads_on (String.concat "\n" [ \
        "Features for wlp59s0:" ; \
        "rx-checksumming: on" ; \
        "generic-receive-offload: on" ; \
        "large-receive-offload: off [fixed]" ; \
        "rx-gro-hw: on [fixed]" ; \
        "rx-gro-list: on" ; \
        "rx-udp-gro-forwarding: off" ]))
 *)

(** Have [ifname] pass on received packets as they came, rather than
 * gathered. *)
let disable_rx_offloads t ifname =
    output "ethtool" [ "-k" ; ifname ] |>
    rx_offloads_on |>
    List.iter (fun feature ->
        change t ~undo:[ "ethtool" ; "-K" ; ifname ; feature ; "on" ]
            "ethtool" [ "-K" ; ifname ; feature ; "off" ])

(** Whether the kernel forwards IPv4 packets. *)
let ip_forward () =
    try File.with_file_in "/proc/sys/net/ipv4/ip_forward" IO.read_all |>
        String.trim <> "0"
    with Sys_error _ -> false
