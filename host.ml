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
  Simple hosts with a single Eth network interface with a full IP stack.

  Hosts are merely simple IP stacks with a eth device at the bottom and a name.
  These makes the link between the network and programs such as browsers or http
  servers (see {!Browser} and {!Opache}).

  Hosts also comes with a logger (see {!Log}).

  See also {!Localhost} for a special kind of host that's running on top of
  guest system real IP stack.
*)
open Batteries
open Bitstring
open Tools

type addr = IPv4 of Ip.Addr.t | Name of string

(* FIXME: that's plenty of closures which only state is the host.
 * To make host object smaller we should store a single backlink to it,
 * and then use regular functions for everything.
 * But then, the reason why we have this is because of localhost, which has no
 * host record.  Basically, we want in host_trx everything that's doable both on
 * a simulated host or on the local host, and the host record [t] to be the
 * state required for the simulated host (the state for the local host is the
 * operating system).  Another way to do it is to have an optional state, or a
 * more explicit host_state = SimState of {...} | OperatingSystem, and have the
 * underlying functions to switch ; or use a module with those implementation
 * and state (would be unit for the local hot) and a first class module as the
 * state. *)

type host_trx = {
    name          : string ;
    logger        : Log.logger ;
    tcp_connect   : addr -> ?src_port:Tcp.Port.t -> Tcp.Port.t -> (Tcp.TRX.tcp_trx option -> unit) -> unit ;
    udp_connect   : addr -> ?src_port:Udp.Port.t -> Udp.Port.t -> (Udp.TRX.udp_trx -> bitstring -> unit) -> (Udp.TRX.udp_trx option -> unit) -> unit ;
    udp_send      : addr -> ?src_port:Udp.Port.t -> Udp.Port.t -> bitstring -> unit ;
    ping          : ?id:int -> ?seq:int -> addr -> unit ;
    gethostbyname : string -> (Ip.Addr.t list option -> unit) -> unit ;
    tcp_server    : Tcp.Port.t -> (Tcp.TRX.tcp_trx -> unit) -> unit ;
    udp_server    : Udp.Port.t -> (Udp.TRX.udp_trx -> unit) -> unit ;
    signal_err    : string -> unit ;
    dev           : dev ; (* as seen from the outside *)
    get_mac       : unit -> Eth.Addr.t (* FIXME: or just move t.eth up here? *) ;
    get_ip        : unit -> Ip.Addr.t option (* FIXME: or just...? *) ;
    arp_set       : Ip.Addr.t -> Eth.Addr.t option -> unit ;
    power_on      : ?on_ip:(t -> unit) -> unit -> unit ;
    power_off     : ?timeout:Clock.Interval.t -> unit -> unit ;
    (* FIXME: Problem is: when the resources is successfully used and closed nothing
     * remove the killer. *)
    add_killer    : ((unit -> unit) -> unit) -> unit }

and tcp_socks = { ip_4_tcp : trx ;
                   (* Available sockets per IP dest.
                      The user of TCP does not remove these entries, so the TRX is still there
                      for some time. We should probably "garbage collect" them once in a while,
                      if they are closed for long enough. *)
                   tcps : (Tcp.Port.t * Tcp.Port.t (* local, remote *), Tcp.TRX.tcp_trx) Hashtbl.t }

and udp_socks = { ip_4_udp : trx ;
                   (* The user of UDP does not remove them neither, and we probably should have
                      a "close" for UDP (since once closed all incoming packets must be rejected,
                      contrary to TCP where we still want to handle incoming FIN). *)
                   udps : (Udp.Port.t * Udp.Port.t (* local, remote *), Udp.TRX.udp_trx) Hashtbl.t }

and t = { mutable host_trx : host_trx ;
          mutable on : bool ; (* If that host is powered on *)
          mutable my_ip : Ip.Addr.t ;
          (* Called at shutdown. New processes must add their own destructor
           * (see [add_killer]) : *)
          mutable killers : ((unit -> unit) -> unit) list ;
          eth : Eth.TRX.eth_trx ;
          tcp_socks   : (Ip.Addr.t, tcp_socks) Hashtbl.t ;
          udp_socks   : (Ip.Addr.t, udp_socks) Hashtbl.t ;
          icmp_socks  : (Ip.Addr.t, trx) Hashtbl.t ;
          (* the listening servers *)
          tcp_servers : (Tcp.Port.t, (Tcp.TRX.tcp_trx -> unit)) Hashtbl.t ;
          udp_servers : (Udp.Port.t, (Udp.TRX.udp_trx -> unit)) Hashtbl.t ;
          (* the resolver *)
          search_sfx : string option ;
          nameserver : Ip.Addr.t option ;
          mutable resolv_trx : trx option ;
          dns_queries : (string, ((Ip.Addr.t list option -> unit) * Clock.Time.t option)) Hashtbl.t ;
          dns_cache   : (string, Ip.Addr.t list) Hashtbl.t }

let print oc trx = String.print oc trx.name
let make_tcp_socks ip = { ip_4_tcp = ip ; tcps = Hashtbl.create 3 }
let make_udp_socks ip = { ip_4_udp = ip ; udps = Hashtbl.create 3 }

exception No_socket

let signal_err t str =
    (* later, change this into a nice log *)
    Printf.fprintf stderr "Host %s: %s\n%!" t.host_trx.name str

(* Forward the payload to the socket function or to the server function *)
let tcp_sock_rx t socks bits =
    match Tcp.Pdu.unpack bits with
        | None -> ()
        | Some tcp ->
            let key = tcp.Tcp.Pdu.dst_port, tcp.Tcp.Pdu.src_port in
            try
                let trx =
                    hash_find_or_insert socks.tcps key (fun () ->
                        if tcp.Tcp.Pdu.flags.Tcp.Pdu.syn then (
                            let server = try Hashtbl.find t.tcp_servers tcp.Tcp.Pdu.dst_port
                                         with Not_found -> (
                                            Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "We have no server listening on port %s" (Tcp.Port.to_string tcp.Tcp.Pdu.dst_port)))) ;
                                            raise No_socket
                                        ) in
                            let tcp = Tcp.TRX.make tcp.Tcp.Pdu.dst_port tcp.Tcp.Pdu.src_port t.host_trx.logger in
                            tcp.Tcp.TRX.tcp_trx.Tcp.TRX.trx =-> socks.ip_4_tcp.ins.write ;
                            server tcp.Tcp.TRX.tcp_trx ; (* supposed to set the recver of this tcp trx *)
                            tcp.Tcp.TRX.tcp_trx
                        ) else (
                            Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "We have a server but so socket for ports %s:%s and TCP flags=%s" (Tcp.Port.to_string tcp.Tcp.Pdu.dst_port) (Tcp.Port.to_string tcp.Tcp.Pdu.src_port) (Tcp.Pdu.string_of_flags tcp.Tcp.Pdu.flags)))) ;
                            raise No_socket
                        )) in
                rx trx.Tcp.TRX.trx bits (* will reorder fragments and transmit the messages up to its emit function *)
            with No_socket ->
                Tcp.Pdu.make_reset_of tcp |> Tcp.Pdu.pack |> tx socks.ip_4_tcp

let udp_sock_rx t socks bits =
    match Udp.Pdu.unpack bits with
        | None -> ()
        | Some udp ->
            let key = udp.Udp.Pdu.dst_port, udp.Udp.Pdu.src_port in
            try
                let trx =
                    hash_find_or_insert socks.udps key (fun () ->
                        let server = try Hashtbl.find t.udp_servers udp.Udp.Pdu.dst_port
                                     with Not_found -> raise No_socket in
                        let trx = Udp.TRX.make udp.Udp.Pdu.dst_port udp.Udp.Pdu.src_port t.host_trx.logger in
                        trx.Udp.TRX.trx =-> socks.ip_4_udp.ins.write ;
                        server trx ; (* supposed to set the recver of this udp trx *)
                        trx) in
                rx trx.Udp.TRX.trx bits
            with No_socket ->
                Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "No socket for UDP packet on port %s" (Udp.Port.to_string udp.Udp.Pdu.dst_port))))
                (* TODO: send ICMP error *)

let icmp_rx _t ip_trx bits =
    match Icmp.Pdu.unpack bits with
        | None -> ()
        | Some icmp when Icmp.Pdu.is_echo_request icmp ->
            (match icmp.Icmp.Pdu.payload with
                | Icmp.Pdu.Ids (id, seq, pld) ->
                    Icmp.Pdu.make_echo_reply id seq ~pld |>
                    Icmp.Pdu.pack |>
                    tx ip_trx
                | _ -> should_not_happen ())
        | _ -> ()

let rec find_alive_tcp tcps key =
    match Hashtbl.find_option tcps key with
    | None -> None
    | Some tcp ->
        if not (tcp.Tcp.TRX.is_closed ()) then Some tcp else (
            Hashtbl.remove tcps key ;
            find_alive_tcp tcps key
        )

exception AlreadyConnected
exception NoIp
exception CannotResolveName
exception DnsTimeout

let string_of_addr = function
    | IPv4 ip  -> Ip.Addr.to_string ip
    | Name str -> str

let tcp_cnxs_ok  = Metric.Atomic.make "Host/Tcp/Connect/Ok"
let tcp_cnxs_err = Metric.Atomic.make "Host/Tcp/Connect/Err"
let udp_cnxs_ok  = Metric.Atomic.make "Host/Udp/Connect/Ok"
let udp_cnxs_err = Metric.Atomic.make "Host/Udp/Connect/Err"
let resolution_timeouts  = Metric.Atomic.make "Host/Resolver/Timeouts"
let resolution_cachehits = Metric.Atomic.make "Host/Resolver/CacheHits"
let resolutions = Metric.Timed.make "Host/Resolver/Queries"

let ip_is_set t =
    t.my_ip <> Ip.Addr.zero

let rec with_resolver_trx t cont =
    let dns_recv _trx bits = (match Dns.Pdu.unpack bits with
        | None -> ()
        | Some pdu ->
            Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Received DNS %s, opcode %d" (if pdu.Dns.Pdu.is_query then "query" else "response") pdu.Dns.Pdu.opcode))) ;
            if not pdu.Dns.Pdu.is_query &&
               pdu.Dns.Pdu.opcode = Dns.std_query (* status? *) &&
               List.length pdu.Dns.Pdu.questions = 1
            then (
                let name, qtype, qclass = List.hd pdu.Dns.Pdu.questions in
                if qtype = Dns.QType.a && qclass = Dns.qclass_inet then (
                    (* TODO: use the A and CNAME results to feed the cache? *)
                    let ips =
                        List.filter_map (fun (_name, qtype, qclass, _ttl, data) ->
                            if qclass = Dns.qclass_inet && qtype = Dns.QType.a then
                                Some (Ip.Addr.of_bitstring (bitstring_of_bytes data))
                            else None
                        ) pdu.Dns.Pdu.answer_rrs in
                    let conts = Hashtbl.find_all t.dns_queries name in
                    Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Awakening %d clients that were waiting for the address of '%s'" (List.length conts) name))) ;
                    List.iter (fun (cont, start_opt) ->
                        Option.may (fun start -> Metric.Timed.stop resolutions start name) start_opt ;
                        cont (Some ips)) conts ;
                    Hashtbl.remove_all t.dns_queries name ;
                    (* cache the result *)
                    if Hashtbl.length t.dns_cache > 10 then Hashtbl.clear t.dns_cache ; (* FIXME *)
                    Hashtbl.add t.dns_cache name ips
                )
            ) (* Else the waiters will eventually be timeouted *)
        )
    in
    match t.resolv_trx, t.nameserver with
    | Some trx, _    ->
        Log.(log t.host_trx.logger Debug (lazy "Use previous resolver trx")) ;
        cont (Some trx)
    | None, None     ->
        Log.(log t.host_trx.logger Error (lazy (Printf.sprintf "Cannot resolve, no DNS"))) ;
        cont None
    | None, Some srv ->
        Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Create a resolving TRX to DNS %s" (Ip.Addr.to_string srv)))) ;
        udp_connect t (IPv4 srv) (Udp.Port.o 53) ~src_port:(Udp.Port.o 53) dns_recv (function
        | None -> cont None
        | Some trx ->
            t.resolv_trx <- Some trx.Udp.TRX.trx ;
            cont (Some trx.Udp.TRX.trx))

and gethostbyname t name cont =
    (* If the name is already an IP do not try to resolve it, otherwise host without DNS server cannot use IP addresses neither *)
    match Ip.Addr.of_dotted_string name with
    | Some ip -> cont (Some [ip])
    | None -> do_gethostbyname t name cont

and do_gethostbyname t name cont =
    Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Resolving '%s'" name))) ;
    let dns_timeout_delay = Clock.Interval.sec 3. in
    let is_fqdn n = n.[String.length n - 1] = '.' in
    let is_complete n = is_fqdn n || String.exists n "." in
    let name = match t.search_sfx with
    | Some sfx ->
        (* send the query using host IPv4 stack, with as recv a decoding function *)
        if is_complete name then name else name ^ "." ^ sfx
    | None -> name in
    let name = if is_fqdn name then name else name ^ "." in
    let dns_timeout () = (* use the name redefined above *)
        let conts = Hashtbl.find_all t.dns_queries name in
        let nb_conts = List.length conts in
        if nb_conts > 0 then (
            Log.(log t.host_trx.logger Warning (lazy (Printf.sprintf "Timeouting %d clients that were waiting for the address of '%s'" nb_conts name))) ;
            Metric.Atomic.fire resolution_timeouts ;
            List.iter (fun (cont, start_opt) ->
                Option.may (fun start -> Metric.Timed.stop resolutions start name) start_opt ;
                cont None) conts ;
            Hashtbl.remove_all t.dns_queries name
        ) in
    (* Try to find the IP in the cache *)
    match Hashtbl.find_option t.dns_cache name with
        | Some ips ->
            Metric.Atomic.fire resolution_cachehits ;
            cont (Some ips)
        | None ->
            Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Start resolver..."))) ;
            with_resolver_trx t (function
            | None ->
                cont None
            | Some resolv_trx ->
                let pending = Hashtbl.mem t.dns_queries name in
                Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Add a query for resolution of '%s' (%s)" name (if pending then "one was already pending" else "first one")))) ;
                if not pending then (
                    (* add a timeout event that will awake all waiters for this name after some time *)
                    Clock.delay dns_timeout_delay dns_timeout () ;
                    (* Then actually sends the query *)
                    let start = Metric.Timed.start resolutions in
                    Hashtbl.add t.dns_queries name (cont, Some start) ;
                    Dns.Pdu.make_query name |> Dns.Pdu.pack |> tx resolv_trx
                ) else (
                    Hashtbl.add t.dns_queries name (cont, None)
                )
            )

and tcp_connect t dst ?src_port (dst_port : Tcp.Port.t) cont =
    (* Fail if we do not have an IP yet *)
    if not (t.on && ip_is_set t) then cont None else
    let connect dst_ip =
        Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Connecting to %s:%d" (Ip.Addr.to_string dst_ip) (dst_port :> int)))) ;
        let socks = hash_find_or_insert t.tcp_socks dst_ip (fun () ->
            let trx = Ip.TRX.make t.my_ip dst_ip Ip.Proto.tcp t.host_trx.logger in
            let socks = make_tcp_socks trx in
            (tcp_sock_rx t socks) <-= trx =-> t.eth.Eth.TRX.trx.ins.write ;
            socks) in
        (* Try to find a unused port if none was given, or ensure the given one is free *)
        let src_port = match src_port with
            | None ->
                let start = Random.int (0x10000 - 1024) + 1024 in
                let rec aux pnum =
                    if find_alive_tcp socks.tcps (Tcp.Port.o pnum, dst_port) = None then (
                        Some (Tcp.Port.o pnum)
                    ) else (
                        let next = pnum + 1 in
                        let next = if next < 0x10000 then next else 1024 in
                        ensure (next <> start) "Host: No more ports available?" ;
                        aux next
                    ) in
                aux start
            | Some src_port ->
                if None = find_alive_tcp socks.tcps (src_port, dst_port) then (
                    Some src_port
                ) else (
                    Metric.Atomic.fire tcp_cnxs_err ;
                    Log.(log t.host_trx.logger Error (lazy "Already connected")) ;
                    None
                ) in
        (* Check we have a source port *)
        match src_port with
            | None ->
                cont None
            | Some src_port ->
                let tcp = Tcp.TRX.make src_port dst_port t.host_trx.logger in
                tcp.Tcp.TRX.tcp_trx.Tcp.TRX.trx.out.set_read socks.ip_4_tcp.ins.write ;
                Hashtbl.add socks.tcps (src_port, dst_port) tcp.Tcp.TRX.tcp_trx ;
                Tcp.TRX.connect tcp (function
                | Some trx ->
                    Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf2 "Connection established with %s:%d" (Ip.Addr.to_string dst_ip) (dst_port :> int)))) ;
                    Metric.Atomic.fire tcp_cnxs_ok ;
                    cont (Some trx)
                | None ->
                    Metric.Atomic.fire tcp_cnxs_err ;
                    Log.(log t.host_trx.logger Error (lazy (Printf.sprintf2 "Cannot connect to %s:%d" (Ip.Addr.to_string dst_ip) (dst_port :> int)))) ;
                    cont None)
    in
    match dst with
        | IPv4 dst_ip ->
            connect dst_ip
        | Name name ->
            gethostbyname t name (function
            | None -> cont None
            | Some dst_ips ->
                Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf2 "Got these IPs for '%s' : %a" name (List.print Ip.Addr.print') dst_ips))) ;
                if dst_ips <> [] then (
                    connect (List.hd dst_ips)
                ) else (
                    Log.(log t.host_trx.logger Error (lazy ("Cannot resolve "^name))) ;
                    cont None
                ))

and udp_connect t dst ?src_port dst_port client_f cont =
    (* Fail if we do not have an IP yet *)
    if not (ip_is_set t) then cont None else
    let connect dst_ip =
        let socks = hash_find_or_insert t.udp_socks dst_ip (fun () ->
            let trx = Ip.TRX.make t.my_ip dst_ip Ip.Proto.udp t.host_trx.logger in
            let socks = make_udp_socks trx in
            (udp_sock_rx t socks) <-= trx =-> t.eth.Eth.TRX.trx.ins.write ;
            socks) in
        let src_port = may_default src_port (fun () -> Udp.Port.o (Random.int 0x10000)) in
        let key = src_port, dst_port in
        if Hashtbl.mem socks.udps key then (
            Metric.Atomic.fire udp_cnxs_err ;
            Log.(log t.host_trx.logger Error (lazy "Already connected")) ;
            cont None
        ) else (
            let trx = Udp.TRX.make src_port dst_port t.host_trx.logger in
            (* connect this udp to the underlaying ip *)
            (client_f trx) <-= trx.Udp.TRX.trx =-> socks.ip_4_udp.ins.write ;
            Hashtbl.add socks.udps key trx ;
            Metric.Atomic.fire udp_cnxs_ok ;
            cont (Some trx)
        )
    in
    match dst with
        | IPv4 dst_ip ->
            connect dst_ip
        | Name name ->
            gethostbyname t name (function
            | None -> cont None
            | Some dst_ips ->
                connect (List.hd dst_ips))


let udp_send t dst ?src_port dst_port bits =
    let send dst_ip =
        Udp.Pdu.make ~src_port:(Option.default dst_port src_port)
                     ~dst_port bits |>
            Udp.Pdu.pack |>
            Ip.Pdu.make Ip.Proto.udp t.my_ip dst_ip |>
            Ip.Pdu.pack |>
            tx t.eth.Eth.TRX.trx in
    match dst with
        | IPv4 dst_ip -> send dst_ip
        | Name name   ->
            gethostbyname t name (function
            | None -> ()
            | Some dst_ips ->
                send (List.hd dst_ips))

let ping t ?(id=1) ?(seq=1) dst =
    let do_ping dst_ip =
        Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Transmitting a ping to %s" (Ip.Addr.to_string dst_ip)))) ;
        Icmp.Pdu.make_echo_request id seq |>
        Icmp.Pdu.pack |>
        Ip.Pdu.make Ip.Proto.icmp t.my_ip dst_ip |>
        Ip.Pdu.pack |>
        tx t.eth.Eth.TRX.trx in
    match dst with
        | IPv4 dst_ip ->
            do_ping dst_ip
        | Name name ->
            gethostbyname t name (function
            | None -> ()
            | Some dst_ips ->
                if dst_ips <> [] then
                    do_ping (List.hd dst_ips))


let tcp_server t src_port server_f = Hashtbl.add t.tcp_servers src_port server_f
let udp_server t src_port server_f = Hashtbl.add t.udp_servers src_port server_f

(* The recv of the eth is responsible for handling the payload to the correct Ip.TRX *)
let ip_recv t bits = match Ip.Pdu.unpack bits with
    | None -> ()
    (* Shouldn't we check first that the dest IP is my_ip? or broadcast? *)
    | Some ip when ip.Ip.Pdu.proto = Ip.Proto.tcp ->
        let sock = hash_find_or_insert t.tcp_socks ip.Ip.Pdu.src (fun () ->
            let ip_trx = Ip.TRX.make t.my_ip ip.Ip.Pdu.src ip.Ip.Pdu.proto t.host_trx.logger in
            let socks = make_tcp_socks ip_trx in
            (tcp_sock_rx t socks) <-= ip_trx =-> (tx t.eth.Eth.TRX.trx) ;
            socks) in
        rx sock.ip_4_tcp bits (* will handle fragmentation then pass payload to its emit function *)
    | Some ip when ip.Ip.Pdu.proto = Ip.Proto.udp ->
        let sock = hash_find_or_insert t.udp_socks ip.Ip.Pdu.src (fun () ->
            let ip_trx = Ip.TRX.make t.my_ip ip.Ip.Pdu.src ip.Ip.Pdu.proto t.host_trx.logger in
            let socks = make_udp_socks ip_trx in
            (udp_sock_rx t socks) <-= ip_trx =-> (tx t.eth.Eth.TRX.trx) ;
            socks) in
        rx sock.ip_4_udp bits
    | Some ip when ip.Ip.Pdu.proto = Ip.Proto.icmp ->
        let ip_trx = hash_find_or_insert t.icmp_socks ip.Ip.Pdu.src (fun () ->
            let ip_trx = Ip.TRX.make t.my_ip ip.Ip.Pdu.src ip.Ip.Pdu.proto t.host_trx.logger in
            (icmp_rx t ip_trx) <-= ip_trx =-> (tx t.eth.Eth.TRX.trx) ;
            ip_trx) in
        rx ip_trx bits
    | _ -> ()

let power_off ?timeout t =
    let to_kill = ref (List.length t.killers) in
    let do_power_off () =
        Log.(log t.host_trx.logger Info (lazy
            (Printf.sprintf "Halting (%d processes left)." !to_kill))) ;
        t.my_ip <- Ip.Addr.zero ;
        t.resolv_trx <- None ;
        Hashtbl.clear t.tcp_socks ;
        Hashtbl.clear t.udp_socks ;
        Hashtbl.clear t.icmp_socks ;
        Hashtbl.clear t.tcp_servers ;
        Hashtbl.clear t.udp_servers ;
        Hashtbl.clear t.dns_queries ;
        Hashtbl.clear t.dns_cache ;
    in
    Option.may (fun d ->
        Clock.delay d (fun () ->
            if !to_kill > 0 then do_power_off ()) ()
    ) timeout ;
    List.iter (fun k ->
        k (fun () ->
            decr to_kill ;
            if !to_kill <= 0 then do_power_off ())
    ) t.killers ;
    t.killers <- []

let make name ?gw ?search_sfx ?nameserver ?(on=true) ~(init : ?on_ip:(t -> unit) -> t -> unit) my_mac =
    let logger = Log.make name 50 in
    let if_on t what f x =
        if t.on then f x else Log.(log logger Debug (lazy (Printf.sprintf "Ignoring %s since I'm off" what))) in
    let rec t =
        { my_ip       = Ip.Addr.zero ;
          on          = on ;
          killers     = [] ;
          eth         = Eth.TRX.make my_mac ?gw Arp.HwProto.ip4 [] logger ; (* FIXME: Don't use the GW for same net IP! *)
          tcp_socks   = Hashtbl.create 11 ;
          udp_socks   = Hashtbl.create 11 ;
          icmp_socks  = Hashtbl.create 11 ;
          tcp_servers = Hashtbl.create 11 ;
          udp_servers = Hashtbl.create 11 ;
          nameserver  = nameserver ;
          resolv_trx  = None ;
          search_sfx  = search_sfx ;
          dns_queries = Hashtbl.create 3 ;
          dns_cache   = Hashtbl.create 3 ;
          host_trx    = host_trx }
    and host_trx =
        { name ; logger ;
          dev           = { write = (fun bits ->
                               Log.(log logger Debug (lazy (Printf.sprintf "got written to %d bits" (bitstring_length bits)))) ;
                               rx t.eth.Eth.TRX.trx bits) ;
                            set_read = (fun f -> t.eth.Eth.TRX.trx =-> f) } ;
          tcp_connect   = (fun addr ?src_port dst cont -> if_on t "tcp_connect" (tcp_connect t addr ?src_port dst) cont) ;
          udp_connect   = (fun dst ?src_port dst_port client_f cont -> if_on t "udp_connect" (udp_connect t dst ?src_port dst_port client_f) cont) ;
          udp_send      = (fun dst ?src_port dst_port bits -> if_on t "udp_send" (udp_send t dst ?src_port dst_port) bits) ;
          ping          = (fun ?id ?seq dst -> if_on t "ping" (ping t ?id ?seq) dst) ;
          gethostbyname = (fun name cont -> if_on t "gethostbyname" (gethostbyname t name) cont) ;
          tcp_server    = (fun src_port server_f -> if_on t "tcp_server" (tcp_server t src_port) server_f) ;
          udp_server    = (fun src_port server_f -> if_on t "udp_server" (udp_server t src_port) server_f) ;
          signal_err    = (fun str -> signal_err t str) ;
          get_mac       = (fun () -> t.eth.Eth.TRX.get_source ()) ;
          get_ip        = (fun () -> if ip_is_set t then Some t.my_ip else None) ;
          arp_set       = (fun ip haddr_opt -> if_on t "arp_set" (t.eth.Eth.TRX.arp_set (Ip.Addr.to_bitstring ip)) haddr_opt) ;
          power_on      = (fun ?on_ip () ->
                              Log.(log logger Debug (lazy "Powering on")) ;
                              assert (not t.on) ; t.on <- true ;
                              init ?on_ip t) ;
          power_off     = (fun ?timeout () -> assert t.on ; power_off ?timeout t ; t.on <- false) ;
          add_killer    = (fun f -> t.killers <- f :: t.killers) }
    in
    Log.(log t.host_trx.logger Info (lazy (Printf.sprintf "New host '%s'" name))) ;
    if t.on then init t ;
    t

let set_ip t ip netmask =
    Log.(log t.host_trx.logger Info (lazy (Printf.sprintf "Setting my IP to %s" (Ip.Addr.to_string ip)))) ;
    t.my_ip <- ip ;
    t.eth.Eth.TRX.set_addresses Eth.[ { addr = Ip.Addr.to_bitstring ip ; netmask = Ip.Addr.to_bitstring netmask } ] ;
    ignore ((ip_recv t) <-= t.eth.Eth.TRX.trx)

let make_static name ?gw ?search_sfx ?nameserver ?on my_mac ?(netmask=Ip.Addr.all_ones) my_ip =
    let init ?on_ip t =
        set_ip t my_ip netmask ;
        (* TODO: Send a gratuitous ARP request? *)
        Option.may (fun on_ip -> Clock.asap on_ip t) on_ip
    in
    let t = make name ?gw ?search_sfx ?nameserver ?on ~init my_mac in
    t.host_trx

let make_dhcp name ?gw ?search_sfx ?nameserver ~on ~netmask my_mac =
    let init ?on_ip t =
        (* Will receive all eth frames until we got an IP address *)
        let dhcp_client bits = (match Ip.Pdu.unpack bits with
            | None -> ()
            | Some ip ->
                if ip.Ip.Pdu.proto <> Ip.Proto.udp then (
                    Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Ignoring IP packet of proto %s while waiting for DHCP offer" (Ip.Proto.to_string ip.Ip.Pdu.proto))))
                ) else (match Udp.Pdu.unpack (ip.Ip.Pdu.payload :> bitstring) with
                    | None -> ()
                    | Some udp ->
                        if udp.Udp.Pdu.src_port <> (Udp.Port.o 67) || udp.Udp.Pdu.dst_port <> (Udp.Port.o 68) then (
                            Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Ignoring UDP packet from %s:%s to %s:%s while waiting for DHCP offer"
                                (Ip.Addr.to_string ip.Ip.Pdu.src) (Udp.Port.to_string udp.Udp.Pdu.src_port)
                                (Ip.Addr.to_string ip.Ip.Pdu.dst) (Udp.Port.to_string udp.Udp.Pdu.dst_port))))
                        ) else (
                            match Dhcp.Pdu.unpack (udp.Udp.Pdu.payload :> bitstring) with
                            | None -> ()
                            | Some ({ Dhcp.Pdu.msg_type = Some op ; _ } as dhcp) when op = Dhcp.MsgType.offer ->
                                Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Got DHCP OFFER from %s, accepting it" (Ip.Addr.to_string ip.Ip.Pdu.src)))) ;
                                (* TODO: check the Xid? *)
                                let pdu = Dhcp.Pdu.make_request ~mac:(t.eth.Eth.TRX.get_source ()) ~xid:dhcp.Dhcp.Pdu.xid ~name dhcp.Dhcp.Pdu.yiaddr dhcp.Dhcp.Pdu.server_id in
                                let pdu = Udp.Pdu.make ~src_port:(Udp.Port.o 68) ~dst_port:(Udp.Port.o 67) (Dhcp.Pdu.pack pdu) in
                                let pdu = Ip.Pdu.make Ip.Proto.udp Ip.Addr.zero Ip.Addr.broadcast (Udp.Pdu.pack pdu) in
                                tx t.eth.Eth.TRX.trx (Ip.Pdu.pack pdu)
                            | Some ({ Dhcp.Pdu.msg_type = Some op ; _ } as dhcp) when op = Dhcp.MsgType.ack ->
                                Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Got DHCP ACK from %s" (Ip.Addr.to_string ip.Ip.Pdu.src)))) ;
                                (* TODO: set other params than IP *)
                                set_ip t dhcp.Dhcp.Pdu.yiaddr netmask ;
                                (* TODO: Send a gratuitous ARP request? *)
                                Option.may (fun on_ip -> Clock.asap on_ip t) on_ip
                            | Some _ ->
                                (* TODO: print it *)
                                t.host_trx.signal_err "Ignoring a DHCP message"))) in
        let rec send_discover () =
            if t.my_ip = Ip.Addr.zero then (
                Log.(log t.host_trx.logger Debug (lazy "Sending DHCP DISCOVER")) ;
                Dhcp.Pdu.make_discover ~mac:(t.eth.Eth.TRX.get_source ()) ~name () |>
                    Dhcp.Pdu.pack |>
                    Udp.Pdu.make ~src_port:(Udp.Port.o 68) ~dst_port:(Udp.Port.o 67) |>
                    Udp.Pdu.pack |>
                    Ip.Pdu.make Ip.Proto.udp Ip.Addr.zero Ip.Addr.broadcast |>
                    Ip.Pdu.pack |>
                    tx t.eth.Eth.TRX.trx ;
                Clock.delay (Clock.Interval.sec (5.+.(Random.float 3.))) send_discover ()
            ) in
        ignore (dhcp_client <-= t.eth.Eth.TRX.trx) ;
        (* The client should wait a random time between one and ten seconds to desynchronize
           the use of DHCP at startup - RFC 2131 *)
        let delay = Clock.Interval.sec (1.+.(Random.float 9.)) in
        Log.(log t.host_trx.logger Debug (lazy
            (Printf.sprintf "Waiting %s before using DHCP..."
                (Clock.Interval.to_string delay)))) ;
        Clock.delay delay send_discover ()
    in
    let t = make name ?gw ?search_sfx ?nameserver ~on ~init my_mac in
    t.host_trx

module Name = struct
    let random () =
        randstr ~charset:"abcdefghijklmnopqrstuvwxyz" (5 + (Random.int 25))
end
