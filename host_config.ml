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

(* [prog] as found on the PATH, or else in the sbin directories: a user's PATH
 * may lack them, although what is there can read the configuration. Commands
 * are run by that path, as a shell may prefer its own version of them
 * otherwise (busybox's sysctl, which cannot clear a setting). *)
let find_prog prog =
    if String.contains prog '/' then prog else
    let path = try String.split_on_char ':' (Sys.getenv "PATH") with Not_found -> [] in
    let executable d =
        d <> "" &&
        try Unix.access (Filename.concat d prog) [ Unix.X_OK ] ; true
        with Unix.Unix_error _ -> false in
    try Filename.concat (List.find executable (path @ [ "/usr/sbin" ; "/sbin" ])) prog
    with Not_found -> prog

(** Whether {!run_line} prints the commands it runs. *)
let verbose = ref false

(** Run the command line [cmd], or say which command would not run; with
 * {!verbose}, print it first, so that a reader can see what was done to their
 * machine and undo it by hand.
 *
 * [quiet] silences what the command itself has to say: a command that is
 * undoing something reports on a state of affairs that is already being given
 * up on -- half of it may be gone before it runs -- and the error that matters
 * was reported before it. *)
let run_line ?(quiet=false) cmd =
    if !verbose then Printf.printf "%s\n%!" cmd ;
    match Unix.system (if quiet then cmd ^" >/dev/null 2>&1" else cmd) with
    | Unix.WEXITED 0 -> ()
    | Unix.WEXITED n ->
        raise (Command_failed (cmd, Printf.sprintf "exited with status %d" n))
    | Unix.WSIGNALED n | Unix.WSTOPPED n ->
        raise (Command_failed (cmd, Printf.sprintf "was signalled (%d)" n))

(** As [run_line], for [prog] with [args]. *)
let run ?quiet prog args = run_line ?quiet (command_line (find_prog prog) args)

(** As [run], for a command that may fail without it mattering: what was asked
 * for and what is there may already agree, and a command that fails on the
 * way out is not a reason to stop taking things down. *)
let try_run prog args = try run ~quiet:true prog args with _ -> ()

(** What [prog] with [args] prints, which reading the configuration of the
 * host changes nothing of, so the command is not printed. With [quiet], what
 * it prints on stderr is thrown away. *)
let output ?(quiet=false) prog args =
    let prog = find_prog prog in
    (* UnixLabels, whose channels are those of the stdlib, unlike Batteries'
     * Unix: *)
    let r, w = UnixLabels.pipe ~cloexec:true () in
    let err =
        if quiet then UnixLabels.openfile "/dev/null" ~mode:[ O_WRONLY ; O_CLOEXEC ] ~perm:0
        else UnixLabels.stderr in
    let pid =
        UnixLabels.create_process ~prog ~args:(Array.of_list (prog :: args))
            ~stdin:UnixLabels.stdin ~stdout:w ~stderr:err in
    UnixLabels.close w ;
    if quiet then UnixLabels.close err ;
    let ic = UnixLabels.in_channel_of_descr r in
    let out = Stdlib.In_channel.input_all ic in
    Stdlib.close_in ic ;
    (* Failing to read is no matter of privileges, as {!Command_failed}
     * suggests: *)
    let fail how =
        failwith (Printf.sprintf "%S %s" (command_line prog args) how) in
    match snd (UnixLabels.waitpid ~mode:[] pid) with
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

(* [ip_addr] is the output of [ip addr show dev IF], [ip_route] that of
 * [ip -4 route show default dev IF], in the text format common to iproute2
 * and busybox: *)
let iface_of_ip_output ifname ~ip_addr ~ip_route =
    let lines s =
        String.split_on_char '\n' s |>
        List.map (List.filter ((<>) "") % String.split_on_char ' ') in
    let rec after w = function
        | w' :: v :: _ when w' = w -> Some v
        | _ :: rest -> after w rest
        | [] -> None in
    let addr = lines ip_addr in
    let find what f =
        match List.find_map_opt f addr with
        | Some v -> v
        | None -> failwith (Printf.sprintf "No %s for interface %s" what ifname) in
    let mac =
        find "MAC address" (function
            | l :: m :: _ when String.starts_with l "link/" -> Some m
            | _ -> None)
    and mtu = find "MTU" (fun l -> Option.map int_of_string (after "mtu" l))
    and ip =
        List.find_map_opt (function
            | "inet" :: a :: _ ->
                let a, p =
                    try String.split a ~by:"/"
                    with Not_found -> a, "32" in
                Some (Ip.Addr.of_dotted_string a,
                      netmask_of_prefix (int_of_string p))
            | _ -> None) addr
    and gateway =
        lines ip_route |>
        List.find_map_opt (function
            | "default" :: r -> Option.map Ip.Addr.of_dotted_string (after "via" r)
            | _ -> None) in
    { ifname ; mac = Eth.Addr.of_string mac ; mtu ; ip ; gateway }

(*$inject
  let iproute2_addr = {|3: wlp59s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 04:ea:56:ad:bf:ab brd ff:ff:ff:ff:ff:ff
    altname wlx04ea56adbfab
    inet6 2a01:e0a:823:6270:fa1f:2a78:30a:3da2/64 scope global dynamic noprefixroute
       valid_lft 86021sec preferred_lft 86021sec
    inet 192.168.1.31/24 brd 192.168.1.255 scope global dynamic noprefixroute wlp59s0
       valid_lft 32605sec preferred_lft 32605sec
|}
  let iproute2_route = {|default via 192.168.1.254 dev wlp59s0 proto dhcp src 192.168.1.31 metric 600
|}
  let busybox_addr = {|5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1400 qlen 1000
    link/ether 02:00:00:00:00:01 brd ff:ff:ff:ff:ff:ff
    inet 10.1.1.2/26 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::ff:fe00:1/64 scope link
       valid_lft forever preferred_lft forever
|}
  let busybox_route = {|default via 10.1.1.1 dev eth0
|}
  let describe i =
      Printf.sprintf "%s %s mtu=%d ip=%s gw=%s" i.ifname
          (Eth.Addr.to_hexstring i.mac) i.mtu
          (match i.ip with
           | None -> "none"
           | Some (a, m) -> Ip.Addr.to_dotted_string a ^"/"^ Ip.Addr.to_dotted_string m)
          (Option.map_default Ip.Addr.to_dotted_string "none" i.gateway)
*)
(*$= iface_of_ip_output & ~printer:identity
  "wlp59s0 04:EA:56:AD:BF:AB mtu=1500 ip=192.168.1.31/255.255.255.0 gw=192.168.1.254" \
    (describe (iface_of_ip_output "wlp59s0" ~ip_addr:iproute2_addr ~ip_route:iproute2_route))
  "wlp59s0 04:EA:56:AD:BF:AB mtu=1500 ip=192.168.1.31/255.255.255.0 gw=none" \
    (describe (iface_of_ip_output "wlp59s0" ~ip_addr:iproute2_addr ~ip_route:""))
  "eth0 02:00:00:00:00:01 mtu=1400 ip=10.1.1.2/255.255.255.192 gw=10.1.1.1" \
    (describe (iface_of_ip_output "eth0" ~ip_addr:busybox_addr ~ip_route:busybox_route))
  "No MAC address for interface tun0" \
    (try describe (iface_of_ip_output "tun0" ~ip_addr:"7: tun0: <UP> mtu 1500\n    link/none\n" ~ip_route:"") \
     with Failure e -> e)
 *)

(** The configuration of interface [ifname]. *)
let iface ifname =
    iface_of_ip_output ifname
        ~ip_addr:(output "ip" [ "addr" ; "show" ; "dev" ; ifname ])
        ~ip_route:(output "ip" [ "-4" ; "route" ; "show" ; "default" ;
                                 "dev" ; ifname ])

(** The slowest Ethernet speed at least as fast as [mbps] Mb/s, the fastest
 * past it, or none for a speed that is not positive (unknown). *)
let eth_speed_of_mbps mbps =
    if mbps <= 0 then None else
    let speeds = Array.to_list Eth.Speed.all in
    match List.filter (fun s -> Eth.Speed.to_bps s >= float mbps *. 1e6) speeds with
    | [] -> Some (Eth.Speed.best speeds)
    | faster -> Some (List.reduce min faster)

(*$inject
  let string_of_speed = Option.map_default Eth.Speed.to_string "?"
  let string_of_link (s, d) =
      string_of_speed s ^" "^
      Option.map_default (fun d -> if d then "full" else "half") "?" d
*)
(*$= eth_speed_of_mbps & ~printer:string_of_speed
  (Some Eth.Speed.Eth1Gbps) (eth_speed_of_mbps 1000)
  (Some Eth.Speed.Eth10Gbps) (eth_speed_of_mbps 10000)
  (Some Eth.Speed.Eth25Gbps) (eth_speed_of_mbps 20000)
  (Some Eth.Speed.Eth100Gbps) (eth_speed_of_mbps 400000)
  None (eth_speed_of_mbps (-1))
 *)

(** The speed and whether full duplex, from [ethtool IF] output, of what it
 * knows of them: *)
let link_of_ethtool out =
    let value name =
        String.split_on_char '\n' out |>
        List.find_map_opt (fun line ->
            match String.split (String.trim line) ~by:": " with
            | n, v when n = name -> Some (String.trim v)
            | _ | exception Not_found -> None) in
    (match value "Speed" with
     | Some v when String.ends_with v "Mb/s" ->
         Option.bind (int_of_string_opt (String.rchop ~n:4 v)) eth_speed_of_mbps
     | _ -> None),
    (match value "Duplex" with
     | Some "Full" -> Some true
     | Some "Half" -> Some false
     | _ -> None)

(*$= link_of_ethtool & ~printer:string_of_link
  (Some Eth.Speed.Eth10Gbps, Some true) \
    (link_of_ethtool "Settings for veth0:\n\tSpeed: 10000Mb/s\n\tDuplex: Full\n\tLink detected: yes\n")
  (Some Eth.Speed.Eth100Mbps, Some false) \
    (link_of_ethtool "Settings for eth0:\n\tSpeed: 100Mb/s\n\tDuplex: Half\n")
  (None, None) \
    (link_of_ethtool "Settings for eth0:\n\tSpeed: Unknown!\n\tDuplex: Unknown! (255)\n")
  (None, None) (link_of_ethtool "Settings for wlan0:\n\tLink detected: yes\n")
 *)

(** The speed of interface [ifname]'s link and whether it is full duplex, when
 * ethtool can tell: not for most virtual or wireless interfaces, nor without
 * a link, nor without ethtool. *)
let link ifname =
    try link_of_ethtool (output ~quiet:true "ethtool" [ ifname ])
    with Failure _ -> None, None

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
 * given, of which ICMP and the TCP and UDP ports of [ports], if any. With
 * [outgoing], for what it may send: from [ip] and from those ports. *)
let pcap_filter ?(outgoing=false) ?ip ports =
    let local = if outgoing then "src" else "dst" in
    let l4 =
        if ports = [] then None
        else Some (String.concat " or " (
            "icmp" :: List.map (fun r ->
                Printf.sprintf "(%s %s portrange %d-%d)"
                    (string_of_proto r.proto) local r.lo r.hi) ports)) in
    match ip, l4 with
    | None, None -> ""
    | None, Some l4 -> "arp or "^ l4
    | Some ip, None -> Printf.sprintf "arp or %s host %s" local (Ip.Addr.to_dotted_string ip)
    | Some ip, Some l4 ->
        Printf.sprintf "arp or (%s host %s and (%s))"
            local (Ip.Addr.to_dotted_string ip) l4

(*$= pcap_filter & ~printer:identity
  "" (pcap_filter [])
  "arp or dst host 10.0.0.1" (pcap_filter ~ip:(Ip.Addr.of_string "10.0.0.1") [])
  "arp or icmp or (tcp dst portrange 14000-14099) or (udp dst portrange 53-53)" \
    (pcap_filter [ port_range_of_string Tcp "14000-14099" ; port_range_of_string Udp "53" ])
  "arp or (dst host 10.0.0.1 and (icmp or (udp dst portrange 1-2)))" \
    (pcap_filter ~ip:(Ip.Addr.of_string "10.0.0.1") [ port_range_of_string Udp "1-2" ])
  "arp or (src host 10.0.0.1 and (icmp or (udp src portrange 1-2)))" \
    (pcap_filter ~outgoing:true ~ip:(Ip.Addr.of_string "10.0.0.1") [ port_range_of_string Udp "1-2" ])
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
    let undo = command_line (find_prog (List.hd undo)) (List.tl undo) in
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

(* Whether process [pid] runs, which a zombie (as a killed process is, for
 * a while) does not: *)
let running pid =
    match File.with_file_in (Printf.sprintf "/proc/%d/stat" pid) IO.read_all with
    | exception Sys_error _ -> false
    | stat ->
        (* The state follows the command, which is within parentheses: *)
        (match String.rsplit stat ~by:") " with
        | _, state -> not (String.starts_with state "Z" || String.starts_with state "X")
        | exception Not_found -> true)

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
            | Some (pid, cmds) when not (running pid) ->
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
