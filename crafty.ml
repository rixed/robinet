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

  The program sends and receives through the interface, behind a policer that
  enforces the budgets given on the command line, which limit what the
  program sends. With [--tcp]/[--udp], it uses only those ports, and only
  what the interface receives for them is captured; with [--ip], it uses an
  address of its own, not added to the interface, and only what is for that
  address is captured. With [--fw], the kernel is kept off those ports. What
  is changed on the host is undone at exit, or by [--cleanup] if crafty was
  killed.
*)
open Batteries

let usage = "crafty [options] PROG.cfty\n\nOptions:"

let die fmt =
    Printf.ksprintf (fun s -> prerr_endline s ; exit 2) fmt

let () =
    let ifname = ref "" and own_ip = ref None and ports = ref []
    and fw = ref false and print_packets = ref false and cleanup = ref false
    and linger = ref (Clock.Interval.sec 2.) and prog_file = ref None
    and max_duration = ref None and max_packets = ref None
    and max_volume = ref None and max_packet_rate = ref None
    and max_throughput = ref None in
    let interval r = Arg.String (fun s ->
        try r := Clock.Interval.of_string s
        with Invalid_argument _ -> die "Not a duration: %S" s) in
    let some_interval r = Arg.String (fun s ->
        try r := Some (Clock.Interval.of_string s)
        with Invalid_argument _ -> die "Not a duration: %S" s) in
    let some_int r = Arg.Int (fun n -> r := Some n)
    and some_float r = Arg.Float (fun n -> r := Some n) in
    let port_range proto = Arg.String (fun s ->
        try ports := !ports @ [ Host_config.port_range_of_string proto s ]
        with Invalid_argument e -> die "%s" e) in
    (* The options, which [--help] lists: *)
    let specs = ref [] in
    let manual text = Arg.Unit (fun () -> print_string text ; exit 0) in
    let help () =
        print_string (Arg.usage_string !specs usage) ;
        print_string ("\n"^ Crafty_manual.introduction) ;
        exit 0 in
    specs := Arg.align [
        "-i", Arg.Set_string ifname, "IFACE the interface to use (required)" ;
        "--ip", Arg.String (fun s -> own_ip := Some (Ip.Addr.of_dotted_string s)),
            "ADDR use this address, rather than the interface's" ;
        "--tcp", port_range Host_config.Tcp,
            "LO[-HI] TCP ports the program uses (repeatable)" ;
        "--udp", port_range Host_config.Udp,
            "LO[-HI] UDP ports the program uses (repeatable)" ;
        "--fw", Arg.Set fw, " keep the kernel off the ports of --tcp and --udp" ;
        "--max-duration", some_interval max_duration, "DURATION run no longer" ;
        "--max-packets", some_int max_packets, "N send no more packets" ;
        "--max-bytes", some_int max_volume, "N send no more bytes" ;
        "--max-packets-per-secs", some_float max_packet_rate,
            "N send no more packets per second" ;
        "--max-bytes-per-secs", some_float max_throughput,
            "N send no more bytes per second" ;
        "--linger", interval linger,
            "DURATION wait that long at most for streams to close (default 2s)" ;
        "-p", Arg.Set print_packets, " print every packet sent and received" ;
        "--print-packets", Arg.Set print_packets, " same as -p" ;
        "--cleanup", Arg.Set cleanup,
            " undo what a killed crafty left on the host, and exit" ;
        "--reference", manual Crafty_manual.reference,
            " print the reference of the crafty language, and exit" ;
        "--examples", manual Crafty_manual.examples,
            " print examples of crafty programs, and exit" ;
        "-help", Arg.Unit help, " print this help and an introduction to crafty" ;
        "--help", Arg.Unit help, " same as -help" ] ;
    Arg.parse !specs
        (fun s ->
            if !prog_file <> None then die "Only one program, please" ;
            prog_file := Some s)
        usage ;
    if !cleanup then (
        (match Host_config.cleanup_stale () with
        | [] -> print_endline "Nothing to clean up."
        | names -> List.iter (Printf.printf "Cleaned up after %s.\n") names) ;
        exit 0) ;
    let prog_file = match !prog_file with
        | Some f -> f
        | None -> die "No program given.\n%s" (Arg.usage_string !specs usage) in
    if !ifname = "" then die "No interface given (-i)." ;
    if !fw && !ports = [] then die "--fw needs ports (--tcp, --udp)." ;
    if !fw && !own_ip <> None then
        die "--fw and --ip do not go together: an address of the program's \
             own shares no port with the kernel." ;
    (* A typo in the program changes nothing on the host: *)
    let program =
        match Crafty_interp.compile (File.with_file_in prog_file IO.read_all) with
        | Ok p -> p
        | Error es ->
            List.iter (fun e ->
                Printf.eprintf "%s: %s\n" prog_file
                    (IO.to_string Crafty_interp.print_error e)) es ;
            exit 2 in
    let iface = Host_config.iface !ifname in
    let ip, netmask =
        match iface.ip, !own_ip with
        | Some (ip, netmask), None -> ip, netmask
        | Some (_, netmask), Some ip -> ip, netmask
        | None, _ -> die "Interface %s has no IPv4 address." !ifname in
    let configure = !fw || !own_ip <> None in
    if configure && Unix.geteuid () <> 0 then
        die "Configuring interface %s is for root; Have you tried under sudo?"
            !ifname ;
    (* Configuring the host: *)
    let changes =
        if not configure then None else (
            Printf.printf "Configuring interface %s...\n%!" !ifname ;
            let t = Host_config.changes "crafty" in
            at_exit (fun () -> Host_config.undo t) ;
            (try
                Host_config.disable_rx_offloads t !ifname ;
                if !fw then (
                    Host_config.firewall t ~ifname:!ifname ~ports:!ports () ;
                    Host_config.reserve_ports t !ports) ;
                if !own_ip <> None && Host_config.ip_forward () then
                    Host_config.firewall t ~ifname:!ifname ~forward_drop:ip ()
            with e ->
                Printf.eprintf "Cannot configure %s: %s\n" !ifname
                    (Printexc.to_string e) ;
                exit 1) ;
            Some t) in
    (* The simulation: crafty, a policer and the interface. *)
    let sim = Simulation.make "crafty" in
    let pcap =
        Pcap.open_iface ~widget:(Widget.make ~parent:sim.root !ifname)
            ~promisc:false ~direction:Pcap.In
            ~caplen:(Pcap.caplen_of_mtu iface.mtu)
            ~filter:(Host_config.pcap_filter ?ip:!own_ip !ports) !ifname in
    let secs () = Clock.Time.to_secs (Simulation.now sim) in
    let ports_of proto =
        String.uppercase_ascii (Host_config.string_of_proto proto),
        List.filter_map (fun (r : Host_config.port_range) ->
            if r.proto = proto then Some (r.lo, r.hi) else None) !ports in
    let status = ref Crafty_interp.Running and limit = ref None in
    (* The handle, which the program is given no event before [run]
     * returns: *)
    let handle = ref None in
    let idle () = Option.map_default (fun h -> h.Crafty_interp.idle ()) true !handle in
    let dev, h =
        Crafty_interp.run ~parent:sim.root ~mac:iface.mac ~ip ~netmask
            ?gateway:(Option.map (fun gw -> Eth.Gateway.IPv4 gw) iface.gateway)
            (* The kernel answers for its own address: *)
            ~answer_arp:(!own_ip <> None)
            ~ports:[ ports_of Host_config.Tcp ; ports_of Host_config.Udp ]
            ~print:print_endline ~print_err:prerr_endline
            ~on_exit:(fun s ->
                status := s ;
                (* Streams that are closing, and frames on their way, go on
                 * for a while; checked from the next tick, once what was
                 * sent last is out: *)
                let deadline = secs () +. Clock.Interval.to_secs !linger in
                (* From a thread of its own, as stopping takes the lock this
                 * event runs under: *)
                let stop () = ignore (Thread.create (Simulation.stop sim) ()) in
                let rec check () =
                    Simulation.delay sim.root.power (Clock.Interval.msec 100.) (fun () ->
                        if idle () || secs () >= deadline then stop () else check ()) () in
                if s = Crafty_interp.Stopped then stop () else check ())
            program in
    handle := Some h ;
    let policer =
        Policer.make ~parent:sim.root ?max_packets:!max_packets
            ?max_volume:!max_volume ?max_packet_rate:!max_packet_rate
            ?max_throughput:!max_throughput ?max_duration:!max_duration
            ~on_limit:(fun l ->
                if !limit = None then (
                    limit := Some l ;
                    Printf.printf "Limit reached: %s.\n%!" (Policer.string_of_limit l) ;
                    h.stop ()))
            "policer" in
    (* What the program sends, and what goes out and comes in: *)
    let sent = ref 0 and pkts_out = ref 0 and pkts_in = ref 0
    and bytes_out = ref 0 and bytes_in = ref 0 in
    let print dir bits =
        if !print_packets then
            Printf.printf "%s %.6f %s\n%!" dir (secs ())
                (Packet.Pdu.Printer.oneline (Packet.of_frame bits)) in
    let before = Hub.VirtTap.make ~rev_mirror:ignore (fun _ -> incr sent)
    and after =
        Hub.VirtTap.make
            ~rev_mirror:(fun bits ->
                incr pkts_in ; bytes_in := !bytes_in + Tools.bytelength bits ; print "<" bits)
            (fun bits ->
                incr pkts_out ; bytes_out := !bytes_out + Tools.bytelength bits ; print ">" bits) in
    Tools.(dev <--> before.ins) ;
    Tools.(before.out <--> policer.widget.ports.dev 0) ;
    Tools.(policer.widget.ports.dev 1 <--> after.ins) ;
    Tools.(after.out --> sink (Pcap.inject pcap.handler)) ;
    Simulation.run_startup sim ;
    Simulation.power_up policer.widget.power ;
    ignore (Pcap.sniffer pcap after.out.write) ;
    print_endline "Running..." ;
    Simulation.with_trapped [ Sys.sigint ; Sys.sigterm ] (fun () ->
        Simulation.run sim true) ;
    Option.may Host_config.undo changes ;
    let status_str, code =
        match !status, !limit with
        | Crafty_interp.Done, _ -> "OK", 0
        | Failed e, _ -> "failed: "^ IO.to_string Crafty_interp.print_error e, 1
        | Stopped, Some l -> "stopped: "^ Policer.string_of_limit l, 3
        | Stopped, None -> "stopped", 3
        | Running, _ -> "interrupted", 130 in
    Printf.printf "Done after %.1fs, status: %s.\n" (secs ()) status_str ;
    Printf.printf "Packets: %d out, %d in. Bytes: %d out, %d in.\n"
        !pkts_out !pkts_in !bytes_out !bytes_in ;
    if !sent > !pkts_out then
        Printf.printf "Dropped by the policer: %d packets.\n" (!sent - !pkts_out) ;
    exit code
