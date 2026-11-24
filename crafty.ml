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

let synopsis = "crafty [options] (PROG.cfty | - | -e PROG) [ARG...]"
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
            | `Null -> ""
            | j -> Crafty_value.json_to_string j in
        String.concat "," (kind :: List.map (field % snd) fields)
    | Json ->
        Crafty_value.json_to_string (`Assoc (("type", `String kind) :: fields @ json))

let () =
    match Crafty_run.secure_env () with
    | Ok () -> ()
    | Error e -> die "%s" e

(* Ids, ISNs and ports differ from one run to the next, lest a peer take a
 * packet of this run for one of a previous run's: *)
let () = Random.self_init ()

(* Each line is out as soon as written, for whoever reads crafty through a
 * pipe; OCaml channels have no line buffering: *)
let () = Out_channel.set_buffered Stdlib.stdout false

(* Unless the command line or the program's BUDGET sets one: *)
let default_max_duration = Clock.Interval.min 10.

let () =
    let ifname = ref "" and own_ip = ref None and ports = ref []
    and routing = ref None
    and fw = ref false and print_packets = ref false
    and print_only = ref None and stats = ref false and cleanup = ref false
    and check = ref false and normalize = ref false and format = ref Human
    and warn_error = ref false and no_warning = ref false
    and linger = ref (Clock.Interval.sec 2.) and time_wait = ref None
    (* What the errors name it after, and its text: *)
    and prog = ref None and prog_args = ref []
    and max_duration = ref None and max_packets = ref None
    and max_volume = ref None and max_packet_rate = ref None
    and max_throughput = ref None and max_syns = ref None and max_syn_rate = ref None
    and max_ram = ref None
    and speed = ref None and full_duplex = ref None and mtu = ref None
    and local_ips = ref None and remote_ips = ref None
    and mac_spoofing = ref None and exfiltration = ref None and promiscuous = ref None in
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
    (* The first file ([-] for stdin) is the program, and options stop there;
     * with -e, all are arguments: *)
    let program_or_arg ~stop s =
        if !prog <> None then prog_args := !prog_args @ [ s ] else (
            if s = "-" then set_prog "stdin" (lazy (IO.read_all IO.stdin))
            else set_prog s (lazy (File.with_file_in s IO.read_all)) ;
            if stop then (
                prog_args := Array.(to_list (sub Sys.argv (!Arg.current + 1)
                                       (length Sys.argv - !Arg.current - 1))) ;
                Arg.current := Array.length Sys.argv - 1)) in
    (* BEWARE: Update docs/crafty.md every time you update the CLI! *)
    specs := Arg.align [
        "-i", Arg.Set_string ifname,
            "IFACE the interface to use (default: the one the kernel routes the \
             program's destinations through, else that of the default route)" ;
        "--routing",
            Arg.Symbol ([ "kernel" ; "manual" ], fun s -> routing := Some (s = "kernel")),
            " ask the kernel for each packet's route (default, on Linux), or use the \
              interface's subnets and default gateways as they are at start" ;
        "-e", Arg.String (fun s -> set_prog "-e" (lazy s)),
            "PROG the program, rather than from a file" ;
        "-", Arg.Unit (fun () -> program_or_arg ~stop:true "-"),
            " read the program from stdin" ;
        "--ip", Arg.String (fun s -> own_ip := Some (Ip.Addr.of_dotted_string s)),
            "ADDR use this address, rather than the interface's" ;
        "--tcp", port_range Host_config.Tcp,
            "LO[-HI] TCP ports the program uses (repeatable)" ;
        "--udp", port_range Host_config.Udp,
            "LO[-HI] UDP ports the program uses (repeatable)" ;
        "--fw", Arg.Set fw, " keep the kernel off the ports of --tcp and --udp" ;
        "--speed",
            Arg.Symbol (Array.to_list EthSpeed.names, fun s ->
                speed := Array.find_opt (fun x -> EthSpeed.to_string x = s) EthSpeed.all),
            " the speed of the link, rather than the interface's (or else 1Gbps)" ;
        "--duplex",
            Arg.Symbol ([ "full" ; "half" ], fun s -> full_duplex := Some (s = "full")),
            " the duplex of the link, rather than the interface's (or else full)" ;
        "--mtu", some_int mtu, "N the MTU, rather than the interface's" ;
        "--max-duration", some_interval max_duration, "DURATION run no longer (default 10m)" ;
        "--max-packets", some_int max_packets, "N send no more packets" ;
        "--max-bytes", some_int max_volume, "N send no more bytes" ;
        "--max-packets-per-secs", some_float max_packet_rate,
            "N send no more packets per second" ;
        "--max-bytes-per-secs", some_float max_throughput,
            "N send no more bytes per second" ;
        "--max-syns", some_int max_syns, "N send no more TCP SYNs (without ACK)" ;
        "--max-syns-per-secs", some_float max_syn_rate,
            "N send no more TCP SYNs (without ACK) per second" ;
        "--max-ram", some_int max_ram,
            "N stop once the heap, or an array, bytes or string about to be made, outgrows that many bytes" ;
        "--local-ip", rule local_ips,
            "VERDICT:CIDR accept or deny these local addresses, before the program's rules (repeatable)" ;
        "--remote-ip", rule remote_ips,
            "VERDICT:CIDR accept or deny these remote addresses, before the program's rules (repeatable)" ;
        "--mac-spoofing", some_bool mac_spoofing,
            "BOOL allow sending from another MAC than the interface's, whatever the program says" ;
        "--exfiltration", some_bool exfiltration,
            "BOOL allow sending what was received, whatever the program says" ;
        "--promiscuous", some_bool promiscuous,
            "BOOL receive the frames for other addresses too, whatever the program says" ;
        "--linger", interval linger,
            "DURATION once done, stop after that long without traffic (default 2s)" ;
        "--time-wait", some_interval time_wait,
            "DURATION pick no source port again until that long after its stream closed \
             (default 0)" ;
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
    if !cleanup then (
        (match Crafty_run.cleanup () with
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
        let rules = Option.map (List.map (fun (v, c) -> v, Crafty_typing.Addresses c)) in
        Crafty_typing.{ local_ips = rules !local_ips ; remote_ips = rules !remote_ips ;
                        mac_spoofing = !mac_spoofing ; exfiltration = !exfiltration ;
                        promiscuous = !promiscuous } in
    (* What the command line allows, with a default duration if neither it
     * nor the program sets one: *)
    let extra_limits =
        let budget =
            List.filter_map identity Crafty_ast.[
                Option.map (fun d -> "max_duration", Interval d) !max_duration ;
                Option.map (fun n -> "max_packets", Int n) !max_packets ;
                Option.map (fun n -> "max_bytes", Int n) !max_volume ;
                Option.map (fun x -> "max_packets_per_secs", Float x) !max_packet_rate ;
                Option.map (fun x -> "max_bytes_per_secs", Float x) !max_throughput ;
                Option.map (fun n -> "max_syns", Int n) !max_syns ;
                Option.map (fun x -> "max_syns_per_secs", Float x) !max_syn_rate ;
                Option.map (fun n -> "max_ram", Int n) !max_ram ] in
        let budget =
            if List.mem_assoc "max_duration" budget ||
               List.mem_assoc "max_duration" program.limits.budget then budget
            else ("max_duration", Crafty_ast.Interval default_max_duration) :: budget in
        let ranges proto =
            List.filter_map (fun (r : Host_config.port_range) ->
                if r.proto = proto then Some (r.lo, r.hi) else None) !ports |>
            Crafty_typing.merge_ranges in
        Crafty_typing.{
            budget ;
            ports = if !ports = [] then None
                    else Some { tcp = ranges Host_config.Tcp ;
                                udp = ranges Host_config.Udp } ;
            permissions = cli_permissions } in
    (* What both allow, which the run computes as well: *)
    let limits =
        match Crafty_run.effective_limits ~extra_limits program with
        | Ok l -> l
        | Error e -> die "%s: %s its PORTS and --tcp/--udp." prog_name e in
    let format = !format in
    (* What crafty tells of how it goes, on stderr unless as text, out of the
     * way of the records: *)
    let info fmt =
        Printf.ksprintf (fun s ->
            let oc = if format = Human then stdout else stderr in
            Printf.fprintf oc "%s\n%!" s) fmt in
    Host_config.print_command := info "%s" ;
    let print_only =
        Option.map (fun s ->
            match Crafty_interp.compile_filter s with
            | Ok f -> f
            | Error e ->
                Printf.eprintf "-p: %s\n" (IO.to_string Crafty_interp.print_error e) ;
                exit 2) !print_only in
    let args = Array.of_list !prog_args
    and resolver = Crafty_interp.(cached system_resolver) in
    (* With what is known before the run computed, resolving no name when only
     * checking. Computed addresses are then literals, which the permissions
     * check: *)
    let program =
        let body =
            Crafty_interp.Partial.block ~getenv:Crafty_interp.getenv ~args
                ?resolver:(if !check then None else Some resolver) program.body in
        Crafty_interp.{ program with body } in
    if !check then (
        (* Unless allowed, nothing received is sent: *)
        if not (limits.permissions.exfiltration |? false) then (
            match Crafty_typing.exfiltrations program.body with
            | [] -> ()
            | es -> fail es) ;
        (* Without the interface, rules about its addresses are not checked: *)
        let known rs =
            let rs = Option.default [] rs in
            if List.exists (fun (_, a) -> a = Crafty_typing.Own_ip || a = Own_ips) rs then None
            else Some (Crafty_typing.address_rules ~own:[] rs) in
        (match Crafty_typing.denied_literals ~local:(known limits.permissions.local_ips)
                   ~remote:(known limits.permissions.remote_ips) ~mac:None program.body with
        | [] -> ()
        | es -> fail es) ;
        Printf.printf "%s: OK\n" prog_name ;
        exit 0) ;
    let kernel_routing =
        match !routing with
        | Some true when not (Kernel_route.available ()) ->
            die "--routing kernel works only on Linux."
        | Some r -> r
        | None -> Kernel_route.available () in
    (* Without -i, the interface the kernel routes the program's destinations
     * through, else that of the default route; the kernel may still route
     * what is known only at run time through another one: *)
    let any_iface = !ifname = "" in
    if any_iface then (
        let routed =
            if not kernel_routing then None else
            match Crafty_run.route_ifname program with
            | Ok i -> i
            | Error e -> die "%s: give the interface (-i)." e in
        match if routed = None then Host_config.default_ifname () else routed with
        | Some i -> ifname := i
        | None -> die "No default route: give the interface (-i).") ;
    if !fw && limits.ports = None then die "--fw needs ports (--tcp, --udp, or PORTS)." ;
    if !fw && !own_ip <> None then
        die "--fw and --ip do not go together: an address of the program's \
             own shares no port with the kernel." ;
    let failed = function
        | Crafty_run.Setup e -> die "%s" e
        | Denied es -> fail es
        | Configure e -> prerr_endline e ; exit 1 in
    let iface =
        match Crafty_run.Iface.setup ~rx_offloads_off:(!fw || !own_ip <> None)
                                     ~ifname:!ifname () with
        | Ok i -> i
        | Error e -> failed e in
    (* Dated to the microsecond, as the text and captures are: *)
    let emit ?json t kind fields =
        let ts = Float.round (Clock.Time.to_secs t *. 1e6) /. 1e6 in
        print_endline (record format ?json kind (("ts", `Float ts) :: fields)) in
    (* A report as the summary of its value, in CSV as a line per key of a
     * map, with the fields of a record of scalars after the key: *)
    let report name typ v t =
        let typ, v = Crafty_interp.summarize typ v in
        let json = Crafty_value.to_json in
        let scalar = function
            | Crafty_ast.Type.(Record _ | Map _ | Variant _ | Void | Pattern) -> false
            | Crafty_ast.Type.Array t -> t = Crafty_ast.Type.Byte
            | _ -> true in
        let fields typ v =
            match typ, v with
            | Crafty_ast.Type.Record fs, Crafty_value.Record vs
              when List.for_all (scalar % snd) fs ->
                List.mapi (fun i (n, t) -> n, json t vs.(i)) fs
            | t, v when scalar t -> [ "value", json t v ]
            | t, v -> [ "value", `String (Crafty_value.json_to_string (json t v)) ] in
        match format, typ, v with
        | Human, _, _ ->
            print_endline (name ^": "^ Crafty_value.to_string typ v)
        | Json, _, _ -> emit t "report" [ "name", `String name ; "value", json typ v ]
        | Csv, Map (k, ty), Map (m, _) when scalar k ->
            Map.PMap.iter (fun key v ->
                emit t "report" (("name", `String name) :: ("key", json k key) :: fields ty v)) m
        | Csv, _, _ -> emit t "report" (("name", `String name) :: fields typ v) in
    let print_stats t what n =
        if !stats then
            if format = Human then
                Printf.printf "%s %s\n" (String.capitalize_ascii what)
                    (Crafty_tree.stats_line n)
            else
                emit t what (
                    ("stream", `String (Crafty_tree.stream_name n)) ::
                    List.map (fun (name, typ, v) -> name, Crafty_value.to_json typ v)
                        (Crafty_tree.typed_stats n)) in
    (* The suspicious stats of all streams, summed, for a warning at exit: *)
    let suspicious = Hashtbl.create 8 in
    let warning t ?(json=[]) text =
        if format = Human then Printf.eprintf "%s: Warning: %s\n%!" prog_name text
        else emit t "warning" (("text", `String text) :: json) in
    let on_warning t = function
        | Crafty_run.Not_injected msg -> info "Cannot inject: %s." msg
        (* Told in the summary: *)
        | Not_captured _ -> ()
        | _ when !no_warning -> ()
        | Program e ->
            if format = Human then
                Printf.eprintf "%s: %a: Warning: %s\n%!" prog_name
                    Crafty_ast.print_location e.where e.message
            else
                warning t e.message ~json:[ "line", `Int e.where.line ;
                                            "column", `Int e.where.column ]
        | Unrouted (dst, reason) ->
            warning t (Printf.sprintf "Cannot send to %s: %s"
                           (Ip.Addr.to_dotted_string dst) reason)
        | Host_refused (proto, p) ->
            warning t (Printf.sprintf "The host %s %d, which crafty uses: %s"
                (if proto = Host_config.Tcp then "reset TCP port"
                 else "refused UDP port")
                p
                (if !fw then
                    "it is outside the ports that --fw keeps the host off"
                 else "keep the host off it with --fw, or give crafty \
                       an address of its own with --ip")) in
    (* A first signal stops the program, or its lingering, and a second one
     * crafty: *)
    let control = ref None and signalled = ref false in
    let on_packet dir t bits =
        let wanted f = (Option.get !control).Crafty_run.matches f bits in
        if Option.map_default wanted true print_only then (
            let packet = Packet.of_frame bits in
            let summary = Packet.Pdu.Printer.oneline packet in
            if format = Human then
                Printf.printf "%s %.6f %s\n" (if dir = Crafty_run.Out then ">" else "<")
                    (Clock.Time.to_secs t) summary
            else
                emit t "packet" ~json:[ "layers", Packet.Pdu.to_json packet ]
                    [ "dir", `String (if dir = Crafty_run.Out then "out" else "in") ;
                      "bytes", `Int (Tools.bytelength bits) ;
                      "summary", `String summary ]) in
    let on_start c =
        control := Some c ;
        if !signalled then c.Crafty_run.stop () in
    let res =
        Fun.protect ~finally:(fun () -> Crafty_run.Iface.release iface) (fun () ->
            Simulation.with_trapped [ Sys.sigint ; Sys.sigterm ]
                ~on_signal:(fun () ->
                    signalled := true ;
                    Option.may (fun c -> c.Crafty_run.stop ()) !control)
                (fun () ->
                    Crafty_run.run iface ?own_ip:!own_ip ~fw:!fw ~kernel_routing ~any_iface
                        ?speed:!speed ?full_duplex:!full_duplex ?mtu:!mtu ~linger:!linger ?time_wait:!time_wait
                        ~format ~args ~resolver
                        ~getenv:Crafty_interp.getenv
                        ~extra_limits
                        ~on_start ~info:(info "%s") ~on_report:report
                        ~on_print:(fun t s ->
                            if format = Human then print_endline s
                            else emit t "print" [ "text", `String s ])
                        ~on_print_err:(fun _ s -> prerr_endline s)
                        ~on_warning
                        ?on_packet:(if !print_packets then Some on_packet else None)
                        ~on_stream:(fun t what n ->
                            print_stats t (if what = `Closed then "closed" else "open") n ;
                            List.iter (fun (name, c) ->
                                Hashtbl.modify_def 0 name ((+) c) suspicious)
                                (Crafty_run.suspicious n))
                        program)) in
    let o = match res with Ok o -> o | Error e -> failed e in
    let c = o.counters in
    let end_ = Clock.Time.of_interval o.duration in
    let status_str, code =
        match o.status, o.limit with
        (* Whether or not the program was over by the time it was denied: *)
        | _ when o.denied <> None ->
            let cause, bits = Option.get o.denied in
            let what, hint =
                match cause with
                | Firewall.Inside ip ->
                    let a = Ip.Addr.to_dotted_string ip in
                    "local address "^ a,
                    Printf.sprintf "; add Accept(%s) to PERMISSIONS.local_ips to spoof it" a
                | Outside ip -> "remote address "^ Ip.Addr.to_dotted_string ip, ""
                | Mac m -> "source MAC "^ Eth.Addr.to_hexstring m, ""
                | Tcp_flags f -> "TCP flags "^ Tcp.Pdu.string_of_flags f, ""
                | Uninspectable -> "uninspectable frame", "" in
            Printf.sprintf "stopped: %s not permitted, in %s%s" what
                (Packet.Pdu.Printer.oneline (Packet.of_frame bits)) hint, 4
        | Crafty_interp.Done, _ -> "OK", 0
        | Failed e, _ -> "failed: "^ IO.to_string Crafty_interp.print_error e, 1
        | Stopped, Some l -> "stopped: "^ Policer.string_of_limit l, 3
        | Stopped, None when o.stopped -> "interrupted", 130
        | Stopped, None when o.over_ram -> "stopped: max-ram", 3
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
            | counts -> Some (what, counts)) Crafty_run.suspicious_stats in
    if not !no_warning && c.denied_in > 0 then (
        let text =
            Printf.sprintf "Received %d packets the permissions deny, dropped" c.denied_in in
        if format = Human then Printf.eprintf "Warning: %s\n%!" text
        else emit end_ "warning" [ "text", `String text ] ~json:[ "denied_in", `Int c.denied_in ]) ;
    if not !no_warning && suspicious <> [] then (
        let text =
            "Detected "^ String.concat ", " (List.map (fun (what, counts) ->
                what ^" ("^ String.concat ", " (List.map (fun (name, c) ->
                    Printf.sprintf "%s=%d" name c) counts) ^")") suspicious) in
        if format = Human then Printf.eprintf "Warning: %s\n%!" text
        else
            emit end_ "warning" [ "text", `String text ]
                 ~json:(List.concat_map (fun (_, counts) ->
                     List.map (fun (name, c) -> name, `Int c) counts) suspicious)) ;
    if format = Human then (
        (* Details of the traffic captured, also after an error: *)
        let verbose = !Host_config.verbose || code <> 0 in
        if verbose then
            Printf.printf "Done after %.1fs, status: %s.\n"
                (Clock.Interval.to_secs o.duration) status_str ;
        if verbose then
            Printf.printf "Packets: %d out, %d in. Bytes: %d out, %d in.\n"
                c.pkts_out c.pkts_in c.bytes_out c.bytes_in ;
        if c.sent - c.denied_out > c.pkts_out then
            Printf.printf "Dropped by the policer: %d packets.\n"
                (c.sent - c.denied_out - c.pkts_out) ;
        if c.denied_out > 0 then
            Printf.printf "Not permitted: %d packets.\n" c.denied_out ;
        if c.not_injected > 0 then
            Printf.printf "Not injected: %d packets.\n" c.not_injected ;
        if c.not_captured > 0 then
            Printf.printf "Not captured: %d packets.\n" c.not_captured ;
        if verbose then
            Printf.printf "Captured going out: %d packets, %d bytes.\n" c.wire_pkts c.wire_bytes
    ) else
        emit end_ "done"
            [ "status", `String status_str ;
              "packets_out", `Int c.pkts_out ; "packets_in", `Int c.pkts_in ;
              "bytes_out", `Int c.bytes_out ; "bytes_in", `Int c.bytes_in ;
              "dropped", `Int (c.sent - c.denied_out - c.pkts_out) ;
              "not_permitted", `Int c.denied_out ;
              "not_injected", `Int c.not_injected ;
              "not_captured", `Int c.not_captured ;
              "captured_packets", `Int c.wire_pkts ;
              "captured_bytes", `Int c.wire_bytes ] ;
    exit code
