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
module Ast = Crafty_ast
module Itp = Crafty_interp
module Prs = Crafty_parser
module Typ = Crafty_typing

type error =
    (* The host is as it was, nothing or all of it undone: *)
    | Setup of string
    (* The program would send what its permissions deny: *)
    | Denied of Prs.error list
    (* Changing the host failed, and what was changed is undone: *)
    | Configure of string

let string_of_error = function
    | Setup e ->
        "Error during setup: "^ e
    | Denied es ->
        Printf.sprintf2 "Denied: %a" (List.print Prs.print_error) es
    | Configure s ->
        "Error during configuration: "^ s

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
            | name, v -> Unix.putenv (Itp.user_env_prefix ^ name) v
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

let cannot_capture ifname e =
    if String.exists e "not permitted" then
        Printf.sprintf "Capturing on interface %s takes root or cap_net_raw (%s); \
                        have you tried under sudo, or given crafty its capabilities \
                        with setcap cap_net_raw,cap_net_admin=ep?" ifname e
    else Printf.sprintf "Cannot capture on interface %s: %s" ifname e

(** The stats of streams that tell what may go unnoticed, by what they tell: *)
let suspicious_stats =
    [ "IP fragmentation", [ "fragmented" ; "frags_in" ] ;
      "incomplete IP packets", [ "reasm_timeouts" ] ;
      "TCP retransmissions", [ "retrans" ; "timeouts" ] ;
      "TCP duplicate acks", [ "dupacks" ] ;
      "gaps in received TCP data", [ "holes_in" ] ;
      "TCP segments out of order", [ "ooo_in" ] ;
      "duplicate TCP segments", [ "dup_in" ] ]

(** The stats of stream [n] among {!suspicious_stats} that are not 0: *)
let suspicious n =
    List.filter_map (fun (name, v) ->
        match v with
        | Crafty_value.Int c
          when c <> 0 && List.exists (List.mem name % snd) suspicious_stats ->
            Some (name, c)
        | _ -> None
    ) (Crafty_tree.stats n)

type warning =
    | Program of Prs.error
    (* No route to that address, and why: *)
    | Unrouted of Ip.Addr.t * string
    (* The host reset that TCP port, or refused that UDP port, which the
     * program uses; once per port: *)
    | Host_refused of Host_config.proto * int
    (* Why the first frame not injected was not: *)
    | Not_injected of string
    (* How many more frames went uncaptured, the capture having dropped them
     * or never seen those injected; at most once a second: *)
    | Not_captured of int

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
      (* That the capture dropped, or that were injected but never seen
       * leaving: *)
      not_captured : int ;
      (* Captured going out, the host's included: *)
      wire_pkts : int ; wire_bytes : int }

type outcome =
    { status : Itp.status ;
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
      now : unit -> Clock.Time.t ;
      (* Whether a frame, sent or received, matches a filter; from the
       * callbacks only: *)
      matches : Itp.filter -> Bitstring.bitstring -> bool ;
      (* As of now: *)
      counters : unit -> counters }

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
          changes : Host_config.changes option ;
          (* The runs in progress, by their own address (unless promiscuous)
           * and ports, which say what they capture: *)
          mutable runs : (Ip.Addr.t option * Host_config.port_range list) list ;
          lock : Mutex.t }

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
                { ifname ; host ; speed ; full_duplex ; rx_offloads_off ; changes ;
                  runs = [] ; lock = Mutex.create () } in
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

    let locked t f =
        Mutex.lock t.lock ;
        Fun.protect ~finally:(fun () -> Mutex.unlock t.lock) f

    (* Why a run capturing for address [ip] (or any) and [ports] (or any)
     * cannot run alongside those in progress, if it cannot: none may capture
     * what is for another, and two may not answer for the same address.
     * Otherwise it is in progress until the function returned is called. *)
    let enter t ip ports =
        let overlap (r : Host_config.port_range) (r' : Host_config.port_range) =
            r.proto = r'.proto && r.lo <= r'.hi && r'.lo <= r.hi in
        let conflicts (ip', ports') =
            (match ip, ip' with
             | Some a, Some b -> Ip.Addr.compare a b = 0
             | _ -> ports = [] || ports' = [] ||
                    List.exists (fun r -> List.exists (overlap r) ports') ports) in
        let me = (ip, ports) in
        locked t (fun () ->
            match List.find_opt conflicts t.runs with
            | Some (Some a, _) when ip <> None ->
                Error (Setup (Printf.sprintf
                    "Another run on interface %s has address %s already."
                    t.ifname (Ip.Addr.to_dotted_string a)))
            | Some _ ->
                Error (Setup (Printf.sprintf
                    "Another run on interface %s may capture what is for this \
                     one: give them addresses, or ports, of their own." t.ifname))
            | None ->
                t.runs <- me :: t.runs ;
                Ok (fun () -> locked t (fun () -> t.runs <- List.filter ((!=) me) t.runs)))
end

(** {2 Running} *)

(** The limits [program] runs with, given [extra_limits] (default: none), or
 * why it cannot run with them: the budget and ports that both allow, and the
 * permissions of {!Crafty_typing.resolve_permissions}, where the rules of
 * [extra_limits] go first and its flags win. *)
let effective_limits ?(extra_limits=Typ.no_limits) (program : Itp.program) =
    Typ.combine ~program:program.limits ~cli:extra_limits |>
    Result.map (fun (l : Typ.limits) ->
        { l with permissions =
            Typ.resolve_permissions ~program:program.limits.permissions
                                    ~cli:extra_limits.permissions })

(** The interface through which the kernel routes the destinations [program]
 * sends to that are literals, as {!Crafty_interp.Partial.block} makes them,
 * if there are any; or which go through which interface, if not all through
 * the same. Link-local addresses, and those the kernel does not route away,
 * are not counted. *)
let route_ifname (program : Itp.program) =
    let routes =
        Typ.destinations program.body |>
        List.filter_map (fun dst ->
            if Ip.Addr.is_v6 dst && Ip.Addr.is_link_local dst then None else
            match Kernel_route.lookup dst with
            | Ok { kind = Unicast | Broadcast | Multicast ; ifname ; _ } -> Some (ifname, dst)
            | _ -> None) |>
        (* The first destination through each interface: *)
        List.fold_left (fun acc (i, d) ->
            if List.mem_assoc i acc then acc else (i, d) :: acc) [] |>
        List.rev in
    match routes with
    | [] -> Ok None
    | [ ifname, _ ] -> Ok (Some ifname)
    | routes ->
        Error (Printf.sprintf "The kernel routes %s"
            (String.concat ", " (List.map (fun (i, d) ->
                Ip.Addr.to_dotted_string d ^" through "^ i) routes)))

(** Run [program], as {!Crafty_interp.Partial.block} may have made it, on
 * [iface], with its {!effective_limits} given [extra_limits], and
 * return how it went, once it is over and what it changed on the host undone;
 * or why it did not run.
 *
 * Runs on the same interface at once must not capture each other's frames:
 * with addresses of their own, or else ports of their own.
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
 * - [time_wait]: how long a local port is not picked again once its stream
 *   went away (default: 0).
 * - [strict_ports]: fail on a source port given out of the program's ports,
 *   rather than warn of it; which runs that share an address need, lest one
 *   takes the port of another.
 * - [format]: what [format()] writes.
 * - [args], [resolver], [getenv]: for [arg()], [resolve()] and [hostname()],
 *   and [getenv()].
 *
 * The callbacks are given the instant of the simulation. They run in its
 * thread, under its lock, and must neither take long nor stop it otherwise
 * than through [control.stop]:
 *
 * - [on_start]: once running and before any frame, with what controls it.
 * - [info]: with {!Host_config.verbose}, the settings of the run; and when a
 *   limit of the budget is reached.
 * - [on_print], [on_print_err], [on_report]: what the program prints and
 *   reports ([on_report] defaults to printing).
 * - [on_warning]: what the program, or the run, warns of.
 * - [on_packet]: each frame on the wire, as libpcap captured it and with the
 *   instant it did: leaving the interface, what the program sent (with the
 *   marks of the frame sent) and what the host sent from its address;
 *   arriving, what is for the program, before the firewall and the policer.
 * - [on_stream]: each stream as it closes, then those still open at the end. *)
let run (iface : Iface.t) ?own_ip ?(fw=false) ?kernel_routing ?(any_iface=false)
        ?speed ?full_duplex ?mtu ?(linger=Clock.Interval.sec 2.) ?(time_wait=Clock.Interval.zero) ?strict_ports ?format ?args
        ~resolver ~getenv ?extra_limits
        ?(on_start=ignore) ?(info=ignore)
        ?(on_print=fun _ _ -> ()) ?(on_print_err=fun _ _ -> ()) ?on_report
        ?(on_warning=fun _ _ -> ()) ?(on_packet=fun _ _ _ -> ())
        ?(on_stream=fun _ _ _ -> ())
        (program : Itp.program) =
    let ( let* ) = Stdlib.Result.bind in
    let refuse cond e = if cond then Error (Setup e) else Ok () in
    let* limits =
        Result.map_error (fun e -> Setup (e ^" the program's PORTS and the extra ports."))
                         (effective_limits ?extra_limits program) in
    let ifname = iface.ifname and host = iface.host in
    let ports =
        Option.map_default (fun (p : Typ.ports) ->
            let ranges proto = List.map (fun (lo, hi) -> Host_config.{ proto ; lo ; hi }) in
            ranges Host_config.Tcp p.tcp @ ranges Host_config.Udp p.udp
        ) [] limits.ports in
    let permissions = limits.permissions in
    let flag = Option.default false in
    let promisc = flag permissions.promiscuous in
    (* Unless allowed, nothing received is sent: *)
    let* () =
        if flag permissions.exfiltration then Ok () else
        match Typ.exfiltrations ?public_env:permissions.public_env program.body with
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
        Typ.address_rules ~own % Option.default [] in
    let* () =
        match Typ.denied_literals ~local:(Some (rules permissions.local_ips))
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
                n ^" "^ Crafty_value.(to_string (Typ.type_of_literal l) (of_literal l)))
                limits.budget))) ;
        info (Printf.sprintf "Ports: %s; time wait %s." (if ports = [] then "any" else
            String.concat ", " (List.map (fun (r : Host_config.port_range) ->
                String.uppercase_ascii (Host_config.string_of_proto r.proto) ^" "^
                Host_config.string_of_range r) ports))
            (Clock.Interval.to_string time_wait)) ;
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
    let* leave =
        Iface.enter iface (if promisc then None else own_ip) ports in
    Fun.protect ~finally:leave (fun () ->
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
    Fun.protect ~finally:(fun () -> Option.may Host_config.undo changes) (fun () ->
    (* The simulation: the program, a firewall, a policer and the interface.
     * What is sent is injected through a handle that captures nothing, so
     * that the other one, capturing either way, sees it leave, before
     * whatever it causes comes back: *)
    let sim = Simulation.make "crafty" in
    let open_iface ?blocking ~direction ~filter () =
        try
            Ok (Pcap.open_iface ~widget:(Widget.make ~parent:sim.root ifname)
                    ~promisc ~direction ~caplen:(Pcap.caplen_of_mtu mtu)
                    ?blocking ~filter ifname)
        with Failure e -> Error (Setup (cannot_capture ifname e)) in
    (* Blocking, so that the program sends no faster than the kernel takes: *)
    let* injector =
        open_iface ~blocking:true ~direction:Pcap.Out ~filter:"less 0" () in
    Fun.protect ~finally:(fun () -> Pcap.close_iface injector) (fun () ->
    let* pcap =
        open_iface ~direction:Pcap.InOut
            ~filter:(Host_config.pcap_filter ?ip:(if promisc then None else own_ip) ports) () in
    Fun.protect ~finally:(fun () -> Pcap.close_iface pcap) (fun () ->
    let instant () = Simulation.now sim in
    let secs () = Clock.Time.to_secs (instant ()) in
    (* When libpcap captured [bits], on the timeline of the simulation, which
     * dispatches a frame captured in its past at once: *)
    let captured_at bits =
        match Pcap.captured bits with
        | Some ts -> Simulation.of_wall_clock sim ts
        | None -> instant () in
    let warn w = on_warning (instant ()) w in
    let tell_stream what n = on_stream (instant ()) what n in
    let sent = ref 0 and pkts_out = ref 0 and pkts_in = ref 0
    and bytes_out = ref 0 and bytes_in = ref 0
    and wire_pkts = ref 0 and wire_bytes = ref 0 in
    let status = ref Itp.Running and limit = ref None in
    (* The handle, which the program is given no event before [run]
     * returns: *)
    let handle = ref None in
    let idle () = Option.map_default (fun h -> h.Itp.idle ()) true !handle in
    (* Whether to be done with lingering, and whether the streams still open
     * were reset, which lifts the limits of the policer for the RSTs to go
     * out: *)
    let hurry = ref false and reset = ref false and lift_limits = ref ignore in
    let reset_streams () =
        reset := true ;
        !lift_limits () ;
        Option.may (fun h -> h.Itp.reset_streams ()) !handle in
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
        Itp.run ~parent:sim.root ~mac:host.mac ~addresses
            ~speed ~full_duplex ~mtu ?router
            ~gateways:(List.map (fun gw -> Eth.Gateway.Ip gw) host.gateways)
            (* The kernel answers for its own address: *)
            ~answer_requests:(own_ip <> None) ~promisc ~time_wait ?strict_ports
            ~limits ?format ?args ~resolver ~getenv
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
                if s = Itp.Stopped then reset_streams () ;
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
        match List.assoc_opt n limits.budget with Some (Ast.Int i) -> Some i | _ -> None
    and budget_float n =
        match List.assoc_opt n limits.budget with Some (Ast.Float x) -> Some x | _ -> None in
    let policer =
        Policer.make ~parent:sim.root
            ?max_duration:(match List.assoc_opt "max_duration" limits.budget with
                           | Some (Ast.Interval d) -> Some d | _ -> None)
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
                | Out ->
                    incr denied_out ;
                    if !denied = None then (
                        denied := Some (cause, bits) ;
                        h.stop ()))
            "firewall" in
    let tell dir bits = on_packet dir (captured_at bits) bits in
    let before = Hub.VirtTap.make ~rev_mirror:ignore (fun _ -> incr sent)
    and after =
        Hub.VirtTap.make
            ~rev_mirror:(fun bits ->
                incr pkts_in ; bytes_in := !bytes_in + Tools.bytelength bits ; tell In bits)
            (fun bits ->
                incr pkts_out ; bytes_out := !bytes_out + Tools.bytelength bits) in
    Tools.(dev <--> before.ins) ;
    Tools.(before.out <--> firewall.widget.ports.dev 0) ;
    Tools.(firewall.widget.ports.dev 1 <--> policer.widget.ports.dev 0) ;
    Tools.(policer.widget.ports.dev 1 <--> after.ins) ;
    (* What was injected and not seen leaving yet, oldest first, of which
     * those that are never seen are passed by the next that is, or else
     * pushed out by the newest. A frame seen leaving takes the marks of the
     * one injected: *)
    let injected = Queue.create () and max_injected = 1000 in
    (* Injected and pushed out of [injected] unseen, and dropped by the
     * capture as of when last asked, which only the thread of the sniffer
     * does: *)
    let unseen = ref 0 and pcap_dropped = ref 0 in
    let not_captured () = !unseen + !pcap_dropped in
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
        if Queue.length injected > max_injected then (
            ignore (Queue.pop injected) ;
            incr unseen) ;
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
    (* How many uncaptured frames were warned of: *)
    let told_uncaptured = ref 0 in
    let tell_uncaptured () =
        let n = not_captured () in
        if n > !told_uncaptured then (
            warn (Not_captured (n - !told_uncaptured)) ;
            told_uncaptured := n) in
    (* Before each capture, from the thread of the sniffer, which alone uses
     * the handle: *)
    let last_asked = ref 0. in
    let ask_dropped () =
        let now = Unix.gettimeofday () in
        if now -. !last_asked >= 1. then (
            last_asked := now ;
            pcap_dropped := Pcap.dropped pcap.handler ;
            if not_captured () > !told_uncaptured then
                Simulation.asap sim.root.power tell_uncaptured ()) in
    let counters () =
        { sent = !sent ; pkts_out = !pkts_out ; bytes_out = !bytes_out ;
          pkts_in = !pkts_in ; bytes_in = !bytes_in ;
          denied_out = !denied_out ; denied_in = !denied_in ;
          not_injected = !not_injected ; not_captured = not_captured () ;
          wire_pkts = !wire_pkts ; wire_bytes = !wire_bytes } in
    let stops = Atomic.make 0 in
    on_start
        { stop = (fun () ->
            if Atomic.fetch_and_add stops 1 = 0 then
                Simulation.asap sim.root.power (fun () -> hurry := true ; h.stop ()) ()
            else ignore (Thread.create (Simulation.stop sim) ())) ;
          now = instant ;
          matches = h.matches ;
          counters } ;
    (* What leaves is what was injected, or else what the host sends, which
     * has the interface's address: *)
    let sniffer =
        Pcap.sniffer pcap ~while_:(fun () -> ask_dropped () ; not !finished) (fun bits ->
            let injected = was_injected bits in
            if injected ||
               (match Eth.Pdu.unpack bits with
               | Ok f -> Eth.Addr.eq f.src host.mac
               | Error _ -> false)
            then (
                if not injected then warn_refused bits ;
                tell Out bits ;
                incr wire_pkts ; wire_bytes := !wire_bytes + Tools.bytelength bits ;
                h.emitted bits
            ) else after.out.write bits) in
    let sniffing = ref true in
    let stop_sniffing () =
        finished := true ;
        if !sniffing then (sniffing := false ; Thread.join sniffer) in
    Fun.protect ~finally:(fun () ->
        stop_sniffing () ;
        Option.may Thread.join ram_watch ;
        Simulation.delete sim) (fun () ->
    Simulation.run sim true ;
    List.iter (tell_stream `Open) (h.open_streams ()) ;
    (* The simulation is over, and so is the sniffer then: *)
    stop_sniffing () ;
    pcap_dropped := Pcap.dropped pcap.handler ;
    tell_uncaptured () ;
    Ok { status = !status ; limit = !limit ; denied = !denied ;
         stopped = Atomic.get stops > 0 ; over_ram = h.over_ram () ;
         duration = Clock.Time.to_interval (instant ()) ;
         counters = counters () })))))
