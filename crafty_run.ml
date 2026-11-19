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
  Running compiled crafty programs on a real interface.

  A program sends and receives through the interface, behind a firewall that
  enforces its permissions, then a policer that enforces its budget. With
  ports, it uses only those, and only what the interface receives for them is
  captured. With an address of its own, not added to the interface, only what
  is for that address is captured. With [fw], the kernel is kept off its
  ports.

  {!Iface.setup} prepares an interface for any number of runs, and {!run}
  runs one program on it, telling as it goes what the program prints,
  reports and sends, what it receives, what its streams do and what looks
  amiss, until it is over.

  What is changed on the host is undone when a run is over, when the
  interface is released, or at exit; or else by {!cleanup} once the process
  is gone, if it was killed. A process calls {!secure_env} (if privileged) and
  {!cleanup} once, before anything else.
*)
open Batteries
module EthSpeed = SimTypes.EthSpeed

type error =
    (* Nothing was changed on the host: *)
    | Setup of string
    (* The program would send what its permissions deny: *)
    | Denied of Crafty_parser.error list
    (* Changing the host failed, and what was changed is undone: *)
    | Configure of string

(** Privileged (setuid root, or given capabilities with setcap), a process
 * runs the commands that configure the host with an environment of its own,
 * since the user's (LD_PRELOAD...) would decide what they do. The user's
 * variables stay, renamed, for the programs' [getenv] only. Setuid root, the
 * process becomes root entirely, for these commands to be root as well
 * (busybox's sh drops an effective uid that is not the real one). *)
let secure_env () =
    if not (Privileges.is_secure ()) then Ok () else
    try
        if Unix.geteuid () = 0 && Unix.getuid () <> 0 then (
            (* Without CAP_SETUID, only the effective uid would change: *)
            Unix.setuid 0 ;
            if Unix.getuid () <> 0 then failwith "Setuid root, but without CAP_SETUID.") ;
        let user_env = Unix.unsafe_environment () in
        Privileges.clearenv () ;
        Unix.putenv "PATH" "/usr/sbin:/usr/bin:/sbin:/bin" ;
        Array.iter (fun var ->
            match String.split var ~by:"=" with
            | name, v -> Unix.putenv (Crafty_interp.user_env_prefix ^ name) v
            | exception Not_found -> ()) user_env ;
        Ok ()
    with Failure e -> Error e
       | Unix.Unix_error (e, f, _) -> Error (f ^": "^ Unix.error_message e)

(** Undo what processes that are gone left on the host, and return the names
 * of their sets of changes. *)
let cleanup = Host_config.cleanup_stale

let needs_net_admin ifname =
    Printf.sprintf "Configuring interface %s takes root or cap_net_admin; Have \
                    you tried under sudo?" ifname

let cannot_configure ifname e =
    Printf.sprintf "Cannot configure %s: %s" ifname (Printexc.to_string e)

(** The stats of streams that tell what may go unnoticed, by what they tell: *)
let suspicious_stats =
    [ "IP fragmentation", [ "fragmented" ; "frags_in" ] ;
      "incomplete IP packets", [ "reasm_timeouts" ] ;
      "TCP retransmissions", [ "retrans" ; "timeouts" ] ;
      "TCP duplicate acks", [ "dupacks" ] ;
      "gaps in received TCP data", [ "holes_in" ] ;
      "TCP segments out of order", [ "ooo_in" ] ;
      "duplicate TCP segments", [ "dup_in" ] ]

type warning =
    | Program of Crafty_parser.error
    (* No route to that address, and why: *)
    | Unrouted of Ip.Addr.t * string
    (* The host reset that TCP port, or refused that UDP port, which the
     * program uses; once per port: *)
    | Host_refused of Host_config.proto * int
    (* Why the first frame not injected was not: *)
    | Not_injected of string

(* Of a frame, as seen after the firewall and the policer: *)
type dir = Out | In

type counters =
    { (* Sent by the program, before the firewall and the policer: *)
      sent : int ;
      (* Through the firewall and the policer: *)
      pkts_out : int ; bytes_out : int ;
      pkts_in : int ; bytes_in : int ;
      (* Dropped by the firewall: *)
      denied_out : int ; denied_in : int ;
      (* That the interface refused to send: *)
      not_injected : int ;
      (* That the capture dropped: *)
      not_captured : int ;
      (* Captured going out, the host's included: *)
      wire_pkts : int ; wire_bytes : int }

type outcome =
    { status : Crafty_interp.status ;
      (* The limit of the budget that stopped the program: *)
      limit : Policer.limit option ;
      (* The first frame sent that the permissions deny, which stopped the
       * program, and why: *)
      denied : (Firewall.cause * Bitstring.bitstring) option ;
      (* Whether [control.stop] was called: *)
      stopped : bool ;
      over_ram : bool ;
      duration : Clock.Interval.t ;
      counters : counters }

(** What a caller can do with a run in progress, from any thread: *)
type control =
    { (* Stop the program, and then once lingering is over the run; called
       * again, stop the run now: *)
      stop : unit -> unit ;
      now : unit -> Clock.Time.t }

(** {2 Interfaces} *)

module Iface =
struct
    type t =
        { ifname : string ;
          host : Host_config.iface ;
          (* Of the link, when the interface tells: *)
          speed : EthSpeed.t option ;
          full_duplex : bool option ;
          rx_offloads_off : bool ;
          changes : Host_config.changes option }

    (** Read interface [ifname], and with [rx_offloads_off] have it pass on
     * received packets as they came rather than gathered, which a run that
     * changes the host (with [fw] or [own_ip]) needs. *)
    let setup ?(rx_offloads_off=false) ~ifname () =
        match Host_config.iface ifname with
        | exception (Failure e) -> Error (Setup e)
        | exception e -> Error (Setup (Printexc.to_string e))
        | host ->
            let speed, full_duplex = Host_config.link ifname in
            let t changes =
                { ifname ; host ; speed ; full_duplex ; rx_offloads_off ; changes } in
            if not rx_offloads_off then Ok (t None)
            else if not (Privileges.has_net_admin ()) then Error (Setup (needs_net_admin ifname))
            else match Host_config.require [ "ethtool" ] with
            | exception e -> Error (Setup (Printexc.to_string e))
            | () ->
                let c = Host_config.changes "crafty" in
                match Host_config.disable_rx_offloads c ifname with
                | () -> Ok (t (Some c))
                | exception e ->
                    Host_config.undo c ;
                    Error (Configure (cannot_configure ifname e))

    (** Undo what {!setup} changed, once the runs on it are over. *)
    let release t = Option.may Host_config.undo t.changes
end

(** {2 Running} *)

(** Run [program] on [iface], with [limits] (the program's combined with the
 * caller's, its permissions resolved), and return how it went, once it is
 * over and what it changed on the host undone; or why it did not run.
 *
 * - [own_ip]: an address of its own, on the network of the interface's first
 *   one of its family (else on no network), rather than the interface's.
 * - [fw]: keep the kernel off the program's ports (not with [own_ip]).
 * - [kernel_routing]: ask the kernel for each packet's route (default, on
 *   Linux), rather than use the interface's subnets and gateways. With
 *   [any_iface], the kernel may tell of another interface (refused), as when
 *   the interface was not chosen but is that of the default route.
 * - [speed], [full_duplex], [mtu]: of the link, rather than the interface's
 *   (or else 1Gbps, full duplex).
 * - [linger]: once the program is over, stop after that long without
 *   traffic.
 * - [format]: what [format()] writes.
 * - [args], [resolver]: for [arg()], and [resolve()] and [hostname()].
 * - [packet_filter]: which frames to tell [on_packet] of (default: all).
 *
 * The callbacks are given the instant of the simulation. They run in its
 * thread, under its lock, and must neither take long nor stop it otherwise
 * than through [control.stop]:
 *
 * - [on_start]: once running, with what controls it.
 * - [info]: with {!Host_config.verbose}, the settings of the run; and when a
 *   limit of the budget is reached.
 * - [on_print], [on_print_err], [on_report]: what the program prints and
 *   reports ([on_report] defaults to printing).
 * - [on_warning]: what the program, or the run, warns of.
 * - [on_packet]: each frame the program sends, through the firewall and the
 *   policer, and each it receives, through them.
 * - [on_stream]: each stream as it closes, then those still open at the end.
 * - [on_suspicious]: with the same streams, each of their stats among
 *   {!suspicious_stats} that is not 0. *)
let run (iface : Iface.t) ?own_ip ?(fw=false) ?kernel_routing ?(any_iface=false)
        ?speed ?full_duplex ?mtu ?(linger=Clock.Interval.sec 2.) ?format ?args
        ~resolver ~(limits : Crafty_typing.limits) ?packet_filter
        ?(on_start=ignore) ?(info=ignore)
        ?(on_print=fun _ _ -> ()) ?(on_print_err=fun _ _ -> ()) ?on_report
        ?(on_warning=fun _ _ -> ()) ?(on_packet=fun _ _ _ -> ())
        ?(on_stream=fun _ _ _ -> ()) ?(on_suspicious=fun _ _ _ _ -> ())
        (program : Crafty_interp.program) =
    let ( let* ) = Stdlib.Result.bind in
    let refuse cond e = if cond then Error (Setup e) else Ok () in
    let ifname = iface.ifname and host = iface.host in
    let ports =
        Option.map_default (fun (p : Crafty_typing.ports) ->
            let ranges proto = List.map (fun (lo, hi) -> Host_config.{ proto ; lo ; hi }) in
            ranges Host_config.Tcp p.tcp @ ranges Host_config.Udp p.udp) [] limits.ports in
    let permissions = limits.permissions in
    let flag = Option.default false in
    let promisc = flag permissions.promiscuous in
    (* Unless allowed, nothing received is sent: *)
    let* () =
        if flag permissions.exfiltration then Ok () else
        match Crafty_typing.exfiltrations program.body with
        | [] -> Ok ()
        | es -> Error (Denied es) in
    let* kernel_routing =
        match kernel_routing with
        | Some true when not (Kernel_route.available ()) ->
            Error (Setup "Routing by the kernel works only on Linux.")
        | Some r -> Ok r
        | None -> Ok (Kernel_route.available ()) in
    let* () = refuse (fw && ports = []) "Keeping the kernel off ports needs ports." in
    let* () =
        refuse (fw && own_ip <> None)
            "Keeping the kernel off ports and an address of the program's own do \
             not go together: such an address shares no port with the kernel." in
    let* () =
        if not fw then Ok () else
        let addresses =
            List.map (fun c -> (fst (c : Ip.Cidr.t :> Ip.Addr.t * int) :> Unix.inet_addr))
                     host.addresses in
        match Host_config.fenced ~addresses ports (Host_config.listening ()) with
        | [] -> Ok ()
        | sockets ->
            (* By port, with the addresses listened on: *)
            let ports =
                List.map (fun (proto, _, p) -> proto, p) sockets |> List.unique |>
                List.sort (fun (a, p) (b, q) -> compare (p, a) (q, b)) in
            Error (Setup (Printf.sprintf
                "Keeping the kernel off the ports would keep the host off ports \
                 it listens on: %s. Narrow the ports."
                (String.concat ", " (List.map (fun (proto, p) ->
                    Printf.sprintf "%s %d (%s)"
                        (String.uppercase_ascii (Host_config.string_of_proto proto)) p
                        (String.concat ", " (List.filter_map (fun (proto', a, p') ->
                            if proto' = proto && p' = p then
                                Some (Unix.string_of_inet_addr a)
                            else None) sockets))) ports)))) in
    (* The program's own address, on the network of the interface's first one
     * of its family (else on no network), or else all of the interface's: *)
    let* addresses =
        match own_ip with
        | Some ip ->
            let width =
                List.find_map_opt (fun c ->
                    let a, w = (c : Ip.Cidr.t :> Ip.Addr.t * int) in
                    if Ip.Addr.is_v6 a = Ip.Addr.is_v6 ip then Some w else None)
                    host.addresses |? Ip.Addr.length ip in
            Ok [ Ip.Cidr.o (ip, width) ]
        | None when host.addresses = [] ->
            Error (Setup (Printf.sprintf "Interface %s has no IP address." ifname))
        | None -> Ok host.addresses in
    let rules =
        let own = List.map (fun c -> fst (c : Ip.Cidr.t :> Ip.Addr.t * int)) addresses in
        Crafty_typing.address_rules ~own % Option.default [] in
    let* () =
        match Crafty_typing.denied_literals ~local:(Some (rules permissions.local_ips))
                  ~remote:(Some (rules permissions.remote_ips))
                  ~mac:(if flag permissions.mac_spoofing then None else Some host.mac)
                  program.body with
        | [] -> Ok ()
        | es -> Error (Denied es) in
    let speed = speed |? (iface.speed |? EthSpeed.Eth1Gbps)
    and full_duplex = full_duplex |? (iface.full_duplex |? true)
    and mtu = mtu |? host.mtu in
    if !Host_config.verbose then (
        info (Printf.sprintf "Interface %s: %s %s-duplex, MTU %d." ifname
            (EthSpeed.to_string speed) (if full_duplex then "full" else "half") mtu) ;
        info (Printf.sprintf "Routing: %s." (if kernel_routing then "the kernel's" else "manual")) ;
        info (Printf.sprintf "Budget: %s." (if limits.budget = [] then "none" else
            String.concat ", " (List.map (fun (n, l) ->
                n ^" "^ Crafty_value.(to_string (Crafty_typing.type_of_literal l) (of_literal l)))
                limits.budget))) ;
        info (Printf.sprintf "Ports: %s." (if ports = [] then "any" else
            String.concat ", " (List.map (fun (r : Host_config.port_range) ->
                String.uppercase_ascii (Host_config.string_of_proto r.proto) ^" "^
                Host_config.string_of_range r) ports))) ;
        let rules rs =
            String.concat ", " (List.map Firewall.string_of_rule
                                    (Firewall.of_address_rules (rules rs))) in
        info (Printf.sprintf "Permissions: local IPs %s; remote IPs %s; MAC spoofing %b; \
                              exfiltration %b; promiscuous %b."
            (rules permissions.local_ips) (rules permissions.remote_ips)
            (flag permissions.mac_spoofing) (flag permissions.exfiltration) promisc)) ;
    let forward_drop =
        Option.map_default (fun ip -> Host_config.ip_forward ~v6:(Ip.Addr.is_v6 ip) ())
                           false own_ip in
    let* () =
        refuse ((fw || own_ip <> None) && not iface.rx_offloads_off)
            (Printf.sprintf "Interface %s was set up with its RX offloads on, \
                             which a run that changes the host needs off." ifname) in
    let changes_host = fw || forward_drop in
    let* () = refuse (changes_host && not (Privileges.has_net_admin ())) (needs_net_admin ifname) in
    let* () =
        if not changes_host then Ok () else
        try Ok (Host_config.require ("nft" :: (if fw then [ "sysctl" ] else [])))
        with e -> Error (Setup (Printexc.to_string e)) in
    let* changes =
        if not changes_host then Ok None else (
            if !Host_config.verbose then
                info (Printf.sprintf "Configuring interface %s..." ifname) ;
            let t = Host_config.changes "crafty" in
            try
                if fw then (
                    Host_config.firewall t ~ifname ~ports () ;
                    Host_config.reserve_ports t ports) ;
                if forward_drop then
                    Option.may (fun ip ->
                        Host_config.firewall t ~ifname ~forward_drop:ip ()) own_ip ;
                Ok (Some t)
            with e ->
                Host_config.undo t ;
                Error (Configure (cannot_configure ifname e))) in
    Ok (Fun.protect ~finally:(fun () -> Option.may Host_config.undo changes) (fun () ->
    (* The simulation: the program, a firewall, a policer and the interface.
     * What is sent is injected through a handle that captures nothing, so
     * that the other one, capturing either way, sees it leave, before
     * whatever it causes comes back: *)
    let sim = Simulation.make "crafty" in
    let open_iface ?blocking ~direction ~filter () =
        Pcap.open_iface ~widget:(Widget.make ~parent:sim.root ifname)
            ~promisc ~direction ~caplen:(Pcap.caplen_of_mtu mtu)
            ?blocking ~filter ifname in
    (* Blocking, so that the program sends no faster than the kernel takes: *)
    let injector =
        open_iface ~blocking:true ~direction:Pcap.Out ~filter:"less 0" () in
    Fun.protect ~finally:(fun () -> Pcap.close_iface injector) (fun () ->
    let pcap =
        open_iface ~direction:Pcap.InOut
            ~filter:(Host_config.pcap_filter ?ip:(if promisc then None else own_ip) ports) () in
    Fun.protect ~finally:(fun () -> Pcap.close_iface pcap) (fun () ->
    let instant () = Simulation.now sim in
    let secs () = Clock.Time.to_secs (instant ()) in
    let warn w = on_warning (instant ()) w in
    let tell_stream what n =
        let t = instant () in
        on_stream t what n ;
        List.iter (fun (name, v) ->
            match v with
            | Crafty_value.Int c
              when c <> 0 && List.exists (List.mem name % snd) suspicious_stats ->
                on_suspicious t n name c
            | _ -> ()
        ) (Crafty_tree.stats n) in
    let sent = ref 0 and pkts_out = ref 0 and pkts_in = ref 0
    and bytes_out = ref 0 and bytes_in = ref 0
    and wire_pkts = ref 0 and wire_bytes = ref 0 in
    let status = ref Crafty_interp.Running and limit = ref None in
    (* The handle, which the program is given no event before [run]
     * returns: *)
    let handle = ref None in
    let idle () = Option.map_default (fun h -> h.Crafty_interp.idle ()) true !handle in
    (* Whether to be done with lingering, and whether the streams still open
     * were reset, which lifts the limits of the policer for the RSTs to go
     * out: *)
    let hurry = ref false and reset = ref false and lift_limits = ref ignore in
    let reset_streams () =
        reset := true ;
        !lift_limits () ;
        Option.may (fun h -> h.Crafty_interp.reset_streams ()) !handle in
    (* The interface given goes first: the kernel takes for on-link what has
     * no route through it. Otherwise it is free to tell of no route, or of
     * another interface. Link-local addresses mean nothing without one: *)
    let oif_of dst =
        if not any_iface || (Ip.Addr.is_v6 dst && Ip.Addr.is_link_local dst)
        then ifname else "" in
    let router =
        if not kernel_routing then None else
        Some (Crafty_layers.make_router ~ifname
                  ~on_unrouted:(fun dst reason -> warn (Unrouted (dst, reason)))
                  ~lookup:(fun dst -> Kernel_route.lookup ~oif:(oif_of dst) dst)) in
    let dev, h =
        Crafty_interp.run ~parent:sim.root ~mac:host.mac ~addresses
            ~speed ~full_duplex ~mtu ?router
            ~gateways:(List.map (fun gw -> Eth.Gateway.Ip gw) host.gateways)
            (* The kernel answers for its own address: *)
            ~answer_requests:(own_ip <> None) ~promisc
            ~limits ?format ?args ~resolver
            ?report:on_report
            ~print:(fun s -> on_print (instant ()) s)
            ~print_err:(fun s -> on_print_err (instant ()) s)
            ~on_warning:(fun e -> warn (Program e))
            ~on_closed:(tell_stream `Closed)
            (* What comes in was received by the real interface already: *)
            ~rx_wire:false
            ~on_exit:(fun s ->
                status := s ;
                (* Streams that are closing, and frames on their way, go on
                 * for as long as packets keep going out or coming in, until
                 * none did for [linger] (or none at all once stopped). Then
                 * the streams still open are reset, for their peers not to
                 * keep sending, and the run stops; checked from the next
                 * tick, once the kernel has sent all that was injected, and
                 * once the clock has caught up with the wall clock, which
                 * dates what is captured, and which blocking injections
                 * leave it behind: *)
                let linger = Clock.Interval.to_secs linger
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
                           (idle () || !reset || !hurry || secs () >= deadline) then (
                            if idle () || !reset then stop ()
                            else (reset_streams () ; check pkts' deadline))
                        else check pkts' deadline) () in
                if s = Crafty_interp.Stopped then reset_streams () ;
                check (!pkts_out + !pkts_in) (secs () +. linger))
            program in
    handle := Some h ;
    let finished = ref false in
    (* For a program that waits, which the interpreter does not look at. From a
     * thread rather than a recurring event, as an event pending slows down
     * every statement: *)
    let ram_watch =
        if not (List.mem_assoc "max_ram" limits.budget) then None else
        Some (Thread.create (fun () ->
            while not !finished && not (h.over_ram ()) do Thread.delay 1. done ;
            if not !finished then Simulation.asap sim.root.power h.stop ()) ()) in
    let budget_int n =
        match List.assoc_opt n limits.budget with Some (Crafty_ast.Int i) -> Some i | _ -> None
    and budget_float n =
        match List.assoc_opt n limits.budget with Some (Crafty_ast.Float x) -> Some x | _ -> None in
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
                    info (Printf.sprintf "Limit reached: %s." (Policer.string_of_limit l)) ;
                    h.stop ()))
            "policer" in
    lift_limits := (fun () -> Policer.lift_limits policer) ;
    (* The first packet sent that the permissions deny, which stops the
     * program, and how many of those were sent and received: *)
    let denied = ref None and denied_out = ref 0 and denied_in = ref 0 in
    let firewall =
        Firewall.make ~parent:sim.root
            ~inside:(Firewall.of_address_rules (rules permissions.local_ips))
            ~outside:(Firewall.of_address_rules (rules permissions.remote_ips))
            ?mac:(if flag permissions.mac_spoofing then None else Some host.mac)
            ~promiscuous:promisc
            ~on_drop:(fun dir cause bits ->
                match dir with
                | Firewall.In -> incr denied_in
                | Firewall.Out ->
                    incr denied_out ;
                    if !denied = None then (
                        denied := Some (cause, bits) ;
                        h.stop ()))
            "firewall" in
    let tell dir bits =
        if Option.map_default (fun f -> h.matches f bits) true packet_filter then
            on_packet dir (instant ()) bits in
    let before = Hub.VirtTap.make ~rev_mirror:ignore (fun _ -> incr sent)
    and after =
        Hub.VirtTap.make
            ~rev_mirror:(fun bits ->
                incr pkts_in ; bytes_in := !bytes_in + Tools.bytelength bits ; tell In bits)
            (fun bits ->
                incr pkts_out ; bytes_out := !bytes_out + Tools.bytelength bits ; tell Out bits) in
    Tools.(dev <--> before.ins) ;
    Tools.(before.out <--> firewall.widget.ports.dev 0) ;
    Tools.(firewall.widget.ports.dev 1 <--> policer.widget.ports.dev 0) ;
    Tools.(policer.widget.ports.dev 1 <--> after.ins) ;
    (* What was injected and not seen leaving yet, oldest first, of which
     * those that are never seen are passed by the next that is. A frame seen
     * leaving takes the marks of the one injected: *)
    let injected = Queue.create () in
    let was_injected frame =
        let is_it bits = Crafty_tree.(is_emitted (Frame bits) frame) in
        if Queue.fold (fun found bits -> found || is_it bits) false injected then (
            let rec pop () =
                let bits = Queue.pop injected in
                if is_it bits then bits else pop () in
            Mark.carry ~src:(pop ()) ~dst:frame ~at:0 ;
            true
        ) else false in
    let not_injected = ref 0 in
    Tools.(after.out --> sink (fun bits ->
        Queue.push bits injected ;
        try Pcap.inject injector.handler bits
        with Failure msg ->
            if !not_injected = 0 then warn (Not_injected msg) ;
            incr not_injected)) ;
    Simulation.run_startup sim ;
    Simulation.power_up firewall.widget.power ;
    Simulation.power_up policer.widget.power ;
    (* The host refusing what is for a port the program uses, once per
     * port: *)
    let refused = Hashtbl.create 3 in
    let warn_refused bits =
        match Host_config.refused_port bits with
        | Some (proto, p)
          when not (Hashtbl.mem refused (proto, p)) &&
               h.uses_port (Host_config.string_of_proto proto) p ->
            Hashtbl.add refused (proto, p) () ;
            warn (Host_refused (proto, p))
        | _ -> () in
    (* What leaves is what was injected, or else what the host sends, which
     * has the interface's address: *)
    let sniffer =
        Pcap.sniffer pcap ~while_:(fun () -> not !finished) (fun bits ->
            let injected = was_injected bits in
            if injected ||
               (match Eth.Pdu.unpack bits with
               | Ok f -> Eth.Addr.eq f.src host.mac
               | Error _ -> false)
            then (
                if not injected then warn_refused bits ;
                incr wire_pkts ; wire_bytes := !wire_bytes + Tools.bytelength bits ;
                h.emitted bits
            ) else after.out.write bits) in
    let stops = Atomic.make 0 in
    on_start
        { stop = (fun () ->
            if Atomic.fetch_and_add stops 1 = 0 then
                Simulation.asap sim.root.power (fun () -> hurry := true ; h.stop ()) ()
            else ignore (Thread.create (Simulation.stop sim) ())) ;
          now = instant } ;
    Fun.protect ~finally:(fun () ->
        finished := true ;
        Thread.join sniffer ;
        Option.may Thread.join ram_watch ;
        Simulation.delete sim) (fun () ->
    Simulation.run sim true ;
    List.iter (tell_stream `Open) (h.open_streams ()) ;
    { status = !status ; limit = !limit ; denied = !denied ;
      stopped = Atomic.get stops > 0 ; over_ram = h.over_ram () ;
      duration = Clock.Time.to_interval (instant ()) ;
      counters =
        { sent = !sent ; pkts_out = !pkts_out ; bytes_out = !bytes_out ;
          pkts_in = !pkts_in ; bytes_in = !bytes_in ;
          denied_out = !denied_out ; denied_in = !denied_in ;
          not_injected = !not_injected ; not_captured = Pcap.dropped pcap.handler ;
          wire_pkts = !wire_pkts ; wire_bytes = !wire_bytes } })))))
