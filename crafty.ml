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
  Run a crafty program on a real interface.

  The program sends and receives through the interface, behind a firewall
  that enforces its permissions, then a policer that enforces the budgets,
  which limit what the program sends. With ports, it
  uses only those, and only what the interface receives for them is
  captured. Budgets and ports are those that both the command line and the
  program (its [BUDGET] and [PORTS]) allow; permissions are the program's
  [PERMISSIONS], which the command line overrides. With [--ip], it uses an
  address of its own, not added to the interface, and only what is for that
  address is captured. With [--fw], the kernel is kept off those ports. What
  is changed on the host is undone at exit, or by [--cleanup] if crafty was
  killed.
*)
open Batteries
module EthSpeed = SimTypes.EthSpeed

let synopsis = "crafty [options] (PROG.cfty | -e PROG) [ARG...]"
let usage = synopsis ^"\n\nOptions:"

let die fmt =
    Printf.ksprintf (fun s -> prerr_endline s ; exit 2) fmt

(* How crafty prints what it tells of packets, streams and its run, and
 * what [format()] writes: *)
type format = Crafty_value.format = Human | Csv | Json

let formats = [ "human", Human ; "csv", Csv ; "json", Json ]

(* A record of that kind, a line of CSV or a JSON object, with the [json]
 * fields too in JSON: *)
let record format ?(json=[]) kind fields =
    match format with
    | Human -> invalid_arg "Crafty.record"
    | Csv ->
        let field = function
            | `String s -> Crafty_value.csv_field s
            | j -> Crafty_value.json_to_string j in
        String.concat "," (kind :: List.map (field % snd) fields)
    | Json ->
        Crafty_value.json_to_string (`Assoc (("type", `String kind) :: fields @ json))

(* The stats of streams that tell what -p and the streams may hide, summed
 * over all streams for a warning at exit, by what they tell: *)
let suspicious_stats =
    [ "IP fragmentation", [ "fragmented" ; "frags_in" ] ;
      "incomplete IP packets", [ "reasm_timeouts" ] ;
      "TCP retransmissions", [ "retrans" ; "timeouts" ] ;
      "TCP duplicate acks", [ "dupacks" ] ;
      "gaps in received TCP data", [ "holes_in" ] ;
      "TCP segments out of order", [ "ooo_in" ] ;
      "duplicate TCP segments", [ "dup_in" ] ]

(* Setuid root, crafty becomes root entirely, for the commands it runs to be
 * root as well (busybox's sh drops an effective uid that is not the real
 * one), and starts over in an environment of its own, since the user's
 * (PATH, LD_PRELOAD...) would decide what runs as root. The user's variables
 * come along renamed, for the program's [getenv] only: *)
let () =
    if Unix.geteuid () = 0 && Unix.getuid () <> 0 then (
        (* Without CAP_SETUID, only the effective uid would change: *)
        Unix.setuid 0 ;
        if Unix.getuid () <> 0 then die "Setuid root, but without CAP_SETUID." ;
        let user_env =
            Unix.unsafe_environment () |>
            Array.map ((^) Crafty_interp.user_env_prefix) in
        Unix.execve Sys.executable_name Sys.argv
            (Array.append [| "PATH=/usr/sbin:/usr/bin:/sbin:/bin" |] user_env))

(* Ids, ISNs and ports differ from one run to the next, lest a peer take a
 * packet of this run for one of a previous run's: *)
let () = Random.self_init ()

(* Each line is out as soon as written, for whoever reads crafty through a
 * pipe; OCaml channels have no line buffering: *)
let () = Out_channel.set_buffered Stdlib.stdout false

let () =
    let ifname = ref "" and own_ip = ref None and ports = ref []
    and fw = ref false and promisc = ref false and print_packets = ref false
    and print_only = ref None and stats = ref false and cleanup = ref false
    and check = ref false and normalize = ref false and format = ref Human
    and warn_error = ref false and no_warning = ref false
    and linger = ref (Clock.Interval.sec 2.)
    (* What the errors name it after, and its text: *)
    and prog = ref None and prog_args = ref []
    and max_duration = ref None and max_packets = ref None
    and max_volume = ref None and max_packet_rate = ref None
    and max_throughput = ref None and max_syns = ref None and max_syn_rate = ref None
    and speed = ref None and full_duplex = ref None and mtu = ref None
    and local_ips = ref None and remote_ips = ref None
    and mac_spoofing = ref None and exfiltration = ref None in
    let interval r = Arg.String (fun s ->
        try r := Clock.Interval.of_string s
        with Invalid_argument _ -> die "Not a duration: %S" s) in
    let some_interval r = Arg.String (fun s ->
        try r := Some (Clock.Interval.of_string s)
        with Invalid_argument _ -> die "Not a duration: %S" s) in
    let some_int r = Arg.Int (fun n -> r := Some n)
    and some_float r = Arg.Float (fun n -> r := Some n) in
    (* VERDICT:CIDR, after those already given: *)
    let rule r = Arg.String (fun s ->
        match String.split s ~by:":" with
        | exception Not_found -> die "Not a rule (accept:CIDR or deny:CIDR): %S" s
        | v, c ->
            let v =
                match String.lowercase_ascii v with
                | "accept" -> Firewall.Accept
                | "deny" -> Firewall.Deny
                | _ -> die "Not a verdict (accept or deny): %S" v in
            let c =
                try Firewall.cidr_of_string c
                with Widget.Bad_value e -> die "%s" e in
            r := Some ((!r |? []) @ [ v, c ]))
    and some_bool r = Arg.Bool (fun b -> r := Some b) in
    let port_range proto = Arg.String (fun s ->
        try ports := !ports @ [ Host_config.port_range_of_string proto s ]
        with Invalid_argument e -> die "%s" e) in
    (* The options, which [--help] lists: *)
    let specs = ref [] in
    (* With the next argument if it is an absolute pattern rather than a
     * program: *)
    let print_packets_spec = Arg.Unit (fun () ->
        print_packets := true ;
        let next = !Arg.current + 1 in
        if next < Array.length Sys.argv then
            let s = Sys.argv.(next) in
            if String.starts_with s "/" && not (Sys.file_exists s) then (
                print_only := Some s ;
                Arg.current := next)) in
    let manual text = Arg.Unit (fun () -> print_string text ; exit 0) in
    (* The introduction describes the options: *)
    let help () =
        print_string ("Usage: "^ synopsis ^"\n\n"^ Crafty_manual.introduction) ;
        exit 0 in
    let set_prog name text =
        if !prog <> None then die "Only one program, please" ;
        prog := Some (name, text) in
    (* The first file is the program, and options stop there; with -e, all
     * are arguments: *)
    let program_or_arg ~stop s =
        if !prog <> None then prog_args := !prog_args @ [ s ] else (
            set_prog s (lazy (File.with_file_in s IO.read_all)) ;
            if stop then (
                prog_args := Array.(to_list (sub Sys.argv (!Arg.current + 1)
                                       (length Sys.argv - !Arg.current - 1))) ;
                Arg.current := Array.length Sys.argv - 1)) in
    (* BEWARE: Update docs/crafty.md every time you update the CLI! *)
    specs := Arg.align [
        "-i", Arg.Set_string ifname, "IFACE the interface to use (default: that of the default route)" ;
        "-e", Arg.String (fun s -> set_prog "-e" (lazy s)),
            "PROG the program, rather than from a file" ;
        "--ip", Arg.String (fun s -> own_ip := Some (Ip.Addr.of_dotted_string s)),
            "ADDR use this address, rather than the interface's" ;
        "--tcp", port_range Host_config.Tcp,
            "LO[-HI] TCP ports the program uses (repeatable)" ;
        "--udp", port_range Host_config.Udp,
            "LO[-HI] UDP ports the program uses (repeatable)" ;
        "--fw", Arg.Set fw, " keep the kernel off the ports of --tcp and --udp" ;
        "--promisc", Arg.Set promisc,
            " receive the frames for other addresses too (promiscuous mode)" ;
        "--speed",
            Arg.Symbol (Array.to_list EthSpeed.names, fun s ->
                speed := Array.find_opt (fun x -> EthSpeed.to_string x = s) EthSpeed.all),
            " the speed of the link, rather than the interface's (or else 1Gbps)" ;
        "--duplex",
            Arg.Symbol ([ "full" ; "half" ], fun s -> full_duplex := Some (s = "full")),
            " the duplex of the link, rather than the interface's (or else full)" ;
        "--mtu", some_int mtu, "N the MTU, rather than the interface's" ;
        "--max-duration", some_interval max_duration, "DURATION run no longer" ;
        "--max-packets", some_int max_packets, "N send no more packets" ;
        "--max-bytes", some_int max_volume, "N send no more bytes" ;
        "--max-packets-per-secs", some_float max_packet_rate,
            "N send no more packets per second" ;
        "--max-bytes-per-secs", some_float max_throughput,
            "N send no more bytes per second" ;
        "--max-syns", some_int max_syns, "N send no more TCP SYNs (without ACK)" ;
        "--max-syns-per-secs", some_float max_syn_rate,
            "N send no more TCP SYNs (without ACK) per second" ;
        "--local-ip", rule local_ips,
            "VERDICT:CIDR accept or deny these local addresses, before the program's rules (repeatable)" ;
        "--remote-ip", rule remote_ips,
            "VERDICT:CIDR accept or deny these remote addresses, before the program's rules (repeatable)" ;
        "--mac-spoofing", some_bool mac_spoofing,
            "BOOL allow sending from another MAC than the interface's, whatever the program says" ;
        "--exfiltration", some_bool exfiltration,
            "BOOL allow sending what was received, whatever the program says" ;
        "--linger", interval linger,
            "DURATION once done, stop after that long without traffic (default 2s)" ;
        "-p", print_packets_spec,
            "[/PATTERN] print every packet sent and received, or those that match" ;
        "--print-packets", print_packets_spec, "[/PATTERN] same as -p" ;
        "--stats", Arg.Set stats,
            " print the stats of each stream, as it closes or when crafty exits" ;
        "--verbose", Arg.Set Host_config.verbose,
            " print the interface's settings and the commands configuring it" ;
        "--check", Arg.Set check, " compile the program, and exit" ;
        "--warn-error", Arg.Set warn_error, " take the warnings as errors" ;
        "--no-warning", Arg.Set no_warning, " print no warning, and take none as an error" ;
        "--format",
            Arg.Symbol (List.map fst formats, fun s -> format := List.assoc s formats),
            " print packets, stats and the outcome as text (default), CSV or JSON" ;
        "--normalize", Arg.Set normalize,
            " print the program back, normalised (without its comments), and exit" ;
        "--cleanup", Arg.Set cleanup,
            " undo what a killed crafty left on the host, and exit" ;
        "--reference", manual Crafty_manual.reference,
            " print the reference of the crafty language, and exit" ;
        "--examples", manual Crafty_manual.examples,
            " print examples of crafty programs, and exit" ;
        "--cliref", Arg.Unit (fun () ->
                print_string (Arg.usage_string !specs usage) ; exit 0),
            " print every option, and exit" ;
        "-help", Arg.Unit help, " print this help and an introduction to crafty" ;
        "--help", Arg.Unit help, " same as -help" ;
        "--", Arg.Rest (program_or_arg ~stop:false),
            " end the options, even before a program from -e" ] ;
    (* BEWARE: Update docs/crafty.md every time you update the CLI! *)
    Arg.parse !specs (program_or_arg ~stop:true) usage ;
    Crafty_interp.prog_args := Array.of_list !prog_args ;
    if !cleanup then (
        (match Host_config.cleanup_stale () with
        | [] -> print_endline "Nothing to clean up."
        | names -> List.iter (Printf.printf "Cleaned up after %s.\n") names) ;
        exit 0) ;
    let prog_name, text = match !prog with
        | Some (name, text) -> name, Lazy.force text
        | None -> die "No program given.\n%s" (Arg.usage_string !specs usage) in
    let fail es =
        List.iter (fun e ->
            Printf.eprintf "%s: %s\n" prog_name
                (IO.to_string Crafty_interp.print_error e)) es ;
        exit 2 in
    (* A typo in the program changes nothing on the host: *)
    let compile () =
        let warnings = ref [] in
        let res = Crafty_interp.compile ~warnings text in
        if !no_warning then warnings := [] ;
        List.iter (fun e ->
            Printf.eprintf "%s: %a: Warning: %s\n%!" prog_name
                Crafty_ast.print_location e.Crafty_parser.where e.message) !warnings ;
        match res with
        | Error es -> fail es
        | Ok _ when !warn_error && !warnings <> [] -> exit 2
        | Ok p -> p in
    if !normalize then (
        if !check then ignore (compile ()) ;
        (match Crafty_parser.parse text with
        | Ok p -> print_string (Crafty_ast.string_of_program ~all:false p)
        | Error e -> fail [ e ]) ;
        exit 0) ;
    let program = compile () in
    let cli_permissions =
        Crafty_typing.{ local_ips = !local_ips ; remote_ips = !remote_ips ;
                        mac_spoofing = !mac_spoofing ; exfiltration = !exfiltration } in
    (* What both the command line and the program allow: *)
    let limits =
        let budget =
            List.filter_map identity Crafty_ast.[
                Option.map (fun d -> "max_duration", Interval d) !max_duration ;
                Option.map (fun n -> "max_packets", Int n) !max_packets ;
                Option.map (fun n -> "max_bytes", Int n) !max_volume ;
                Option.map (fun x -> "max_packets_per_secs", Float x) !max_packet_rate ;
                Option.map (fun x -> "max_bytes_per_secs", Float x) !max_throughput ;
                Option.map (fun n -> "max_syns", Int n) !max_syns ;
                Option.map (fun x -> "max_syns_per_secs", Float x) !max_syn_rate ] in
        let ranges proto =
            List.filter_map (fun (r : Host_config.port_range) ->
                if r.proto = proto then Some (r.lo, r.hi) else None) !ports |>
            Crafty_typing.merge_ranges in
        let cli =
            Crafty_typing.{
                budget ;
                ports = if !ports = [] then None
                        else Some { tcp = ranges Host_config.Tcp ;
                                    udp = ranges Host_config.Udp } ;
                permissions = cli_permissions } in
        match Crafty_typing.combine ~program:program.limits ~cli with
        | Ok l -> l
        | Error e -> die "%s: %s its PORTS and --tcp/--udp." prog_name e in
    let ports =
        Option.map_default (fun (p : Crafty_typing.ports) ->
            let ranges proto = List.map (fun (lo, hi) -> Host_config.{ proto ; lo ; hi }) in
            ranges Host_config.Tcp p.tcp @ ranges Host_config.Udp p.udp) [] limits.ports in
    let budget_int n =
        match List.assoc_opt n limits.budget with Some (Crafty_ast.Int i) -> Some i | _ -> None
    and budget_float n =
        match List.assoc_opt n limits.budget with Some (Crafty_ast.Float x) -> Some x | _ -> None in
    let format = !format in
    (* What crafty tells of how it goes, on stderr unless as text, out of the
     * way of the records: *)
    let info fmt =
        Printf.ksprintf (fun s ->
            let oc = if format = Human then stdout else stderr in
            Printf.fprintf oc "%s\n%!" s) fmt in
    let print_only =
        Option.map (fun s ->
            match Crafty_interp.compile_filter s with
            | Ok f -> f
            | Error e ->
                Printf.eprintf "-p: %s\n" (IO.to_string Crafty_interp.print_error e) ;
                exit 2) !print_only in
    let denied_literals (p : Crafty_typing.permissions) ~mac =
        match Crafty_typing.denied_literals ~local:p.local_ips
                  ~remote:p.remote_ips ~mac program.body with
        | [] -> ()
        | es -> fail es in
    if !check then (
        (* Without the interface, the local rules are checked only when they
         * do not end with its addresses: *)
        let p = program.limits.permissions in
        let r = Crafty_typing.resolve_permissions ~program:p ~cli:cli_permissions
                                                  ~local:[] in
        denied_literals { r with local_ips = if p.local_ips = None then None
                                              else r.local_ips } ~mac:None ;
        Printf.printf "%s: OK\n" prog_name ;
        exit 0) ;
    if !ifname = "" then (
        match Host_config.default_ifname () with
        | Some i -> ifname := i
        | None -> die "No default route: give the interface (-i).") ;
    if !fw && ports = [] then die "--fw needs ports (--tcp, --udp, or PORTS)." ;
    if !fw && !own_ip <> None then
        die "--fw and --ip do not go together: an address of the program's \
             own shares no port with the kernel." ;
    let iface = Host_config.iface !ifname in
    if !fw then (
        match Host_config.fenced ~addresses:iface.addresses ports
                                 (Host_config.listening ()) with
        | [] -> ()
        | sockets ->
            (* By port, with the addresses listened on: *)
            let ports =
                List.map (fun (proto, _, p) -> proto, p) sockets |> List.unique |>
                List.sort (fun (a, p) (b, q) -> compare (p, a) (q, b)) in
            die "--fw would keep the host off ports it listens on: %s. \
                 Narrow --tcp, --udp or PORTS."
                (String.concat ", " (List.map (fun (proto, p) ->
                    Printf.sprintf "%s %d (%s)"
                        (String.uppercase_ascii (Host_config.string_of_proto proto)) p
                        (String.concat ", " (List.filter_map (fun (proto', a, p') ->
                            if proto' = proto && p' = p then
                                Some (Unix.string_of_inet_addr a)
                            else None) sockets))) ports))) ;
    let ip, netmask =
        match iface.ip, !own_ip with
        | Some (ip, netmask), None -> ip, netmask
        | Some (_, netmask), Some ip -> ip, netmask
        | None, _ -> die "Interface %s has no IPv4 address." !ifname in
    (* The local addresses accepted unless said otherwise: the program's own,
     * or else the interface's: *)
    let limits =
        let local =
            match !own_ip with
            | Some ip -> [ ip ]
            | None ->
                List.filter_map (fun a ->
                    if Unix.is_inet6_addr a then None else Some (Ip.Addr.o a))
                    iface.addresses in
        { limits with permissions =
            Crafty_typing.resolve_permissions ~program:program.limits.permissions
                                              ~cli:cli_permissions ~local } in
    let permissions = limits.permissions in
    let rules = Option.default [] and flag = Option.default false in
    denied_literals permissions
        ~mac:(if flag permissions.mac_spoofing then None else Some iface.mac) ;
    let speed, full_duplex =
        let speed', full_duplex' = Host_config.link !ifname in
        (match !speed, speed' with Some s, _ | None, Some s -> s | None, None -> EthSpeed.Eth1Gbps),
        (match !full_duplex, full_duplex' with Some d, _ | None, Some d -> d | None, None -> true)
    and mtu = !mtu |? iface.mtu in
    if !Host_config.verbose then (
        info "Interface %s: %s %s-duplex, MTU %d." !ifname
            (EthSpeed.to_string speed) (if full_duplex then "full" else "half") mtu ;
        info "Budget: %s." (if limits.budget = [] then "none" else
            String.concat ", " (List.map (fun (n, l) ->
                n ^" "^ Crafty_value.(to_string (Crafty_typing.type_of_literal l) (of_literal l)))
                limits.budget)) ;
        info "Ports: %s." (if ports = [] then "any" else
            String.concat ", " (List.map (fun (r : Host_config.port_range) ->
                String.uppercase_ascii (Host_config.string_of_proto r.proto) ^" "^
                Host_config.string_of_range r) ports)) ;
        let rules rs =
            String.concat ", " (List.map Firewall.string_of_rule (rules rs)) in
        info "Permissions: local IPs %s; remote IPs %s; MAC spoofing %b; \
              exfiltration %b."
            (rules permissions.local_ips) (rules permissions.remote_ips)
            (flag permissions.mac_spoofing) (flag permissions.exfiltration)) ;
    let configure = !fw || !own_ip <> None in
    if configure && Unix.geteuid () <> 0 then
        die "Configuring interface %s is for root; Have you tried under sudo?"
            !ifname ;
    (* Configuring the host: *)
    let changes =
        if not configure then None else (
            if !Host_config.verbose then
                info "Configuring interface %s..." !ifname ;
            let t = Host_config.changes "crafty" in
            at_exit (fun () -> Host_config.undo t) ;
            (try
                Host_config.disable_rx_offloads t !ifname ;
                if !fw then (
                    Host_config.firewall t ~ifname:!ifname ~ports () ;
                    Host_config.reserve_ports t ports) ;
                if !own_ip <> None && Host_config.ip_forward () then
                    Host_config.firewall t ~ifname:!ifname ~forward_drop:ip ()
            with e ->
                Printf.eprintf "Cannot configure %s: %s\n" !ifname
                    (Printexc.to_string e) ;
                exit 1) ;
            Some t) in
    (* The simulation: crafty, a policer and the interface. What is sent is
     * injected through a handle that captures nothing, so that the other
     * one, capturing either way, sees it leave, before whatever it causes
     * comes back: *)
    let sim = Simulation.make "crafty" in
    let open_iface ?blocking ~direction ~filter () =
        Pcap.open_iface ~widget:(Widget.make ~parent:sim.root !ifname)
            ~promisc:!promisc ~direction ~caplen:(Pcap.caplen_of_mtu mtu)
            ?blocking ~filter !ifname in
    (* Blocking, so that crafty sends no faster than the kernel takes: *)
    let injector =
        open_iface ~blocking:true ~direction:Pcap.Out ~filter:"less 0" ()
    and pcap =
        open_iface ~direction:Pcap.InOut
            ~filter:(Host_config.pcap_filter ?ip:!own_ip ports) () in
    let secs () = Clock.Time.to_secs (Simulation.now sim) in
    (* Dated to the microsecond, as the text and captures are: *)
    let emit ?json kind fields =
        let ts = Float.round (secs () *. 1e6) /. 1e6 in
        print_endline (record format ?json kind (("ts", `Float ts) :: fields)) in
    let print_stats what n =
        if !stats then
            if format = Human then
                Printf.printf "%s %s\n" (String.capitalize_ascii what)
                    (Crafty_tree.stats_line n)
            else
                emit what (
                    ("stream", `String (Crafty_tree.stream_name n)) ::
                    List.map (fun (name, typ, v) -> name, Crafty_value.to_json typ v)
                        (Crafty_tree.typed_stats n)) in
    let suspicious = Hashtbl.create 8 in
    let tally n =
        List.iter (fun (name, v) ->
            match v with
            | Crafty_value.Int c
              when List.exists (List.mem name % snd) suspicious_stats ->
                Hashtbl.modify_def 0 name ((+) c) suspicious
            | _ -> ()
        ) (Crafty_tree.stats n) in
    (* What the program sends, what goes out and comes in, and what is
     * captured going out, the host's included: *)
    let sent = ref 0 and pkts_out = ref 0 and pkts_in = ref 0
    and bytes_out = ref 0 and bytes_in = ref 0
    and wire_pkts = ref 0 and wire_bytes = ref 0 in
    let status = ref Crafty_interp.Running and limit = ref None in
    (* The handle, which the program is given no event before [run]
     * returns: *)
    let handle = ref None in
    let idle () = Option.map_default (fun h -> h.Crafty_interp.idle ()) true !handle in
    let dev, h =
        Crafty_interp.run ~parent:sim.root ~mac:iface.mac ~ip ~netmask
            ~speed ~full_duplex ~mtu
            ?gateway:(Option.map (fun gw -> Eth.Gateway.IPv4 gw) iface.gateway)
            (* The kernel answers for its own address: *)
            ~answer_arp:(!own_ip <> None) ~promisc:!promisc
            ~limits
            ~format
            ~print:(fun s ->
                if format = Human then print_endline s
                else emit "print" [ "text", `String s ])
            ~print_err:prerr_endline
            ~on_warning:(fun e ->
                if not !no_warning then
                    if format = Human then
                        Printf.eprintf "%s: %a: Warning: %s\n%!" prog_name
                            Crafty_ast.print_location e.where e.message
                    else
                        emit "warning" [ "text", `String e.message ;
                                         "line", `Int e.where.line ;
                                         "column", `Int e.where.column ])
            ~on_closed:(fun n -> tally n ; print_stats "closed" n)
            (* What comes in was received by the real interface already: *)
            ~rx_wire:false
            ~on_exit:(fun s ->
                status := s ;
                (* Streams that are closing, and frames on their way, go on
                 * for as long as packets keep going out or coming in, until
                 * none did for [linger]; checked from the next tick, once
                 * the kernel has sent all that was injected, and once the
                 * clock has caught up with the wall clock, which dates what
                 * is captured, and which blocking injections leave it
                 * behind: *)
                let linger = Clock.Interval.to_secs !linger
                and tick = Clock.Interval.msec 100. in
                (* From a thread of its own, as stopping takes the lock this
                 * event runs under: *)
                let stop () = ignore (Thread.create (Simulation.stop sim) ()) in
                let rec check pkts deadline =
                    Simulation.delay sim.root.power tick (fun () ->
                        let pkts' = !pkts_out + !pkts_in in
                        let deadline =
                            if pkts' <> pkts then secs () +. linger else deadline in
                        if Pcap.unsent injector.handler = 0 &&
                           Clock.Interval.compare sim.late tick < 0 &&
                           (idle () || secs () >= deadline) then stop ()
                        else check pkts' deadline) () in
                if s = Crafty_interp.Stopped then stop ()
                else check (!pkts_out + !pkts_in) (secs () +. linger))
            program in
    handle := Some h ;
    let policer =
        Policer.make ~parent:sim.root
            ?max_duration:(match List.assoc_opt "max_duration" limits.budget with
                           | Some (Crafty_ast.Interval d) -> Some d | _ -> None)
            ?max_packets:(budget_int "max_packets")
            ?max_volume:(budget_int "max_bytes")
            ?max_packet_rate:(budget_float "max_packets_per_secs")
            ?max_throughput:(budget_float "max_bytes_per_secs")
            ?max_syns:(budget_int "max_syns")
            ?max_syn_rate:(budget_float "max_syns_per_secs")
            ~on_limit:(fun l ->
                if !limit = None then (
                    limit := Some l ;
                    info "Limit reached: %s." (Policer.string_of_limit l) ;
                    h.stop ()))
            "policer" in
    (* The first packet sent that the permissions deny, which stops the
     * program, and how many of those were sent and received: *)
    let denied = ref None and denied_out = ref 0 and denied_in = ref 0 in
    let firewall =
        Firewall.make ~parent:sim.root
            ~inside:(rules permissions.local_ips)
            ~outside:(rules permissions.remote_ips)
            ?mac:(if flag permissions.mac_spoofing then None else Some iface.mac)
            ~on_drop:(fun dir cause bits ->
                match dir with
                | Firewall.In -> incr denied_in
                | Firewall.Out ->
                    incr denied_out ;
                    if !denied = None then (
                        denied := Some (cause, bits) ;
                        h.stop ()))
            "firewall" in
    let print dir bits =
        if !print_packets &&
           Option.map_default (fun f -> h.matches f bits) true print_only then
            let packet = Packet.of_frame bits in
            let summary = Packet.Pdu.Printer.oneline packet in
            if format = Human then
                Printf.printf "%s %.6f %s\n" dir (secs ()) summary
            else
                emit "packet" ~json:[ "layers", Packet.Pdu.to_json packet ]
                    [ "dir", `String (if dir = ">" then "out" else "in") ;
                      "bytes", `Int (Tools.bytelength bits) ;
                      "summary", `String summary ] in
    let before = Hub.VirtTap.make ~rev_mirror:ignore (fun _ -> incr sent)
    and after =
        Hub.VirtTap.make
            ~rev_mirror:(fun bits ->
                incr pkts_in ; bytes_in := !bytes_in + Tools.bytelength bits ; print "<" bits)
            (fun bits ->
                incr pkts_out ; bytes_out := !bytes_out + Tools.bytelength bits ; print ">" bits) in
    Tools.(dev <--> before.ins) ;
    Tools.(before.out <--> firewall.widget.ports.dev 0) ;
    Tools.(firewall.widget.ports.dev 1 <--> policer.widget.ports.dev 0) ;
    Tools.(policer.widget.ports.dev 1 <--> after.ins) ;
    (* What was injected and not seen leaving yet, oldest first, of which
     * those that are never seen are passed by the next that is: *)
    let injected = Queue.create () in
    let was_injected frame =
        let is_it bits = Crafty_tree.(is_emitted (Frame bits) frame) in
        if Queue.fold (fun found bits -> found || is_it bits) false injected then (
            while not (is_it (Queue.pop injected)) do () done ;
            true
        ) else false in
    let not_injected = ref 0 in
    Tools.(after.out --> sink (fun bits ->
        Queue.push bits injected ;
        try Pcap.inject injector.handler bits
        with Failure msg ->
            if !not_injected = 0 then info "Cannot inject: %s." msg ;
            incr not_injected)) ;
    Simulation.run_startup sim ;
    Simulation.power_up firewall.widget.power ;
    Simulation.power_up policer.widget.power ;
    (* The host refusing what is for a port crafty uses, once per port: *)
    let refused = Hashtbl.create 3 in
    let warn_refused bits =
        match Host_config.refused_port bits with
        | Some (proto, p)
          when not !no_warning && not (Hashtbl.mem refused (proto, p)) &&
               h.uses_port (Host_config.string_of_proto proto) p ->
            Hashtbl.add refused (proto, p) () ;
            let text =
                Printf.sprintf "The host %s %d, which crafty uses: %s"
                    (if proto = Host_config.Tcp then "reset TCP port"
                     else "refused UDP port")
                    p
                    (if !fw then
                        "it is outside the ports that --fw keeps the host off"
                     else "keep the host off it with --fw, or give crafty \
                           an address of its own with --ip") in
            if format = Human then
                Printf.eprintf "%s: Warning: %s\n%!" prog_name text
            else emit "warning" [ "text", `String text ]
        | _ -> () in
    (* What leaves is what crafty injected, or else what the host sends,
     * which has the interface's address: *)
    ignore (Pcap.sniffer pcap (fun bits ->
        let injected = was_injected bits in
        if injected ||
           (match Eth.Pdu.unpack bits with
           | Ok f -> Eth.Addr.eq f.src iface.mac
           | Error _ -> false)
        then (
            if not injected then warn_refused bits ;
            incr wire_pkts ; wire_bytes := !wire_bytes + Tools.bytelength bits ;
            h.emitted bits
        ) else after.out.write bits)) ;
    Simulation.with_trapped [ Sys.sigint ; Sys.sigterm ] (fun () ->
        Simulation.run sim true) ;
    let not_captured = Pcap.dropped pcap.handler in
    Option.may Host_config.undo changes ;
    List.iter (fun n -> tally n ; print_stats "open" n) (h.open_streams ()) ;
    let status_str, code =
        match !status, !limit with
        (* Whether or not the program was over by the time it was denied: *)
        | _ when !denied <> None ->
            let cause, bits = Option.get !denied in
            let what =
                match cause with
                | Firewall.Inside ip -> "local address "^ Ip.Addr.to_dotted_string ip
                | Outside ip -> "remote address "^ Ip.Addr.to_dotted_string ip
                | Mac m -> "source MAC "^ Eth.Addr.to_hexstring m
                | Uninspectable -> "uninspectable frame" in
            Printf.sprintf "stopped: %s not permitted, in %s" what
                (Packet.Pdu.Printer.oneline (Packet.of_frame bits)), 4
        | Crafty_interp.Done, _ -> "OK", 0
        | Failed e, _ -> "failed: "^ IO.to_string Crafty_interp.print_error e, 1
        | Stopped, Some l -> "stopped: "^ Policer.string_of_limit l, 3
        | Stopped, None -> "stopped", 3
        | Running, _ -> "interrupted", 130 in
    (* What was seen, with the counters that are not 0: *)
    let suspicious =
        List.filter_map (fun (what, names) ->
            match List.filter_map (fun name ->
                    match Hashtbl.find_default suspicious name 0 with
                    | 0 -> None
                    | c -> Some (name, c)) names with
            | [] -> None
            | counts -> Some (what, counts)) suspicious_stats in
    if not !no_warning && !denied_in > 0 then (
        let text =
            Printf.sprintf "Received %d packets the permissions deny, dropped" !denied_in in
        if format = Human then Printf.eprintf "Warning: %s\n%!" text
        else emit "warning" [ "text", `String text ] ~json:[ "denied_in", `Int !denied_in ]) ;
    if not !no_warning && suspicious <> [] then (
        let text =
            "Detected "^ String.concat ", " (List.map (fun (what, counts) ->
                what ^" ("^ String.concat ", " (List.map (fun (name, c) ->
                    Printf.sprintf "%s=%d" name c) counts) ^")") suspicious) in
        if format = Human then Printf.eprintf "Warning: %s\n%!" text
        else
            emit "warning" [ "text", `String text ]
                 ~json:(List.concat_map (fun (_, counts) ->
                     List.map (fun (name, c) -> name, `Int c) counts) suspicious)) ;
    if format = Human then (
        (* Display verose details regarding captured traffic if we had an error: *)
        let verbose = !Host_config.verbose || code <> 0 in
        if verbose then
            Printf.printf "Done after %.1fs, status: %s.\n" (secs ()) status_str ;
        if verbose then
            Printf.printf "Packets: %d out, %d in. Bytes: %d out, %d in.\n"
                !pkts_out !pkts_in !bytes_out !bytes_in ;
        if !sent - !denied_out > !pkts_out then
            Printf.printf "Dropped by the policer: %d packets.\n"
                (!sent - !denied_out - !pkts_out) ;
        if !denied_out > 0 then
            Printf.printf "Not permitted: %d packets.\n" !denied_out ;
        if !not_injected > 0 then
            Printf.printf "Not injected: %d packets.\n" !not_injected ;
        if not_captured > 0 then
            Printf.printf "Not captured: %d packets.\n" not_captured ;
        if verbose then
            Printf.printf "Captured going out: %d packets, %d bytes.\n" !wire_pkts !wire_bytes
    ) else
        emit "done"
            [ "status", `String status_str ;
              "packets_out", `Int !pkts_out ; "packets_in", `Int !pkts_in ;
              "bytes_out", `Int !bytes_out ; "bytes_in", `Int !bytes_in ;
              "dropped", `Int (!sent - !denied_out - !pkts_out) ;
              "not_permitted", `Int !denied_out ;
              "not_injected", `Int !not_injected ;
              "not_captured", `Int not_captured ;
              "captured_packets", `Int !wire_pkts ;
              "captured_bytes", `Int !wire_bytes ] ;
    exit code
