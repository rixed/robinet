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
    (* The widget of the host this speaks for: will have the properties of a
     * [Host.t] for a simulated host, whereas the localhost's has no properties. *)
    widget        : Widget.t ;
    tcp_connect   : addr -> ?src_port:Tcp.Port.t -> Tcp.Port.t -> (Tcp.TRX.tcp_trx option -> unit) -> unit ;
    udp_connect   : addr -> ?src_port:Udp.Port.t -> Udp.Port.t -> (Udp.TRX.udp_trx -> bitstring -> unit) -> (Udp.TRX.udp_trx option -> unit) -> unit ;
    udp_send      : addr -> ?src_port:Udp.Port.t -> Udp.Port.t -> bitstring -> unit ;
    ping          : ?id:int -> ?seq:int -> addr -> unit ;
    gethostbyname : string -> (Ip.Addr.t list option -> unit) -> unit ;
    tcp_server    : Tcp.Port.t -> (Tcp.TRX.tcp_trx -> unit) -> unit ;
    udp_server    : Udp.Port.t -> (Udp.TRX.udp_trx -> unit) -> unit ;
    signal_err    : string -> unit ;
    dev           : dev ; (* as seen from the outside *)
    arp_set       : Ip.Addr.t -> Eth.Addr.t option -> unit ;
    power_on      : ?on_ip:(t -> unit) -> unit -> unit ;
    power_off     : unit -> unit ;
    (* The two halves of a power cycle, without the power: [start] runs the
     * host's initialisation, [reset] throws away the state a cut invalidates.
     * They are for whoever *shares* this host's supply with other hosts and
     * therefore has to switch the supply itself, once for all of them -- a
     * router does, its admin hosts being interfaces of the same box. A host
     * that has a supply of its own wants [power_on] and [power_off]. *)
    start         : ?on_ip:(t -> unit) -> unit -> unit ;
    reset         : unit -> unit ;
    (* This host's power supply, which everything it schedules draws from: its
     * adapter, its sockets, its timers, and whatever process runs on it.
     * Switching it off is all there is to powering the host down -- what it
     * had planned to do ceases to exist, rather than being asked politely to
     * stop. *)
    power         : Simulation.power }

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

and t = { mutable trx : host_trx ;
          eth_state   : Eth.State.t ;
          eth_trx     : trx ;
          tcp_socks   : (Ip.Addr.t, tcp_socks) Hashtbl.t ;
          udp_socks   : (Ip.Addr.t, udp_socks) Hashtbl.t ;
          icmp_socks  : (Ip.Addr.t, trx) Hashtbl.t ;
          (* the listening servers *)
          tcp_servers : (Tcp.Port.t, (Tcp.TRX.tcp_trx -> unit)) Hashtbl.t ;
          udp_servers : (Udp.Port.t, (Udp.TRX.udp_trx -> unit)) Hashtbl.t ;
          (* Whether this host has an IP configuration of its own to apply
             when it boots. It has, unless it speaks through somebody else's
             adapter -- a router's admin host does -- in which case the
             address, the netmask and the reader belong to that owner and must
             be left alone. *)
          own_ip_config : bool ;
          (* The configuration as the reader set it, which is a property of
             the host and outlives any number of power cycles. What DHCP
             grants is kept apart in the [leased_] fields below. *)
          mutable search_sfx : string option ;
          mutable nameserver : Ip.Addr.t option ;
          mutable static_ip : Ip.Addr.t option ;
          mutable host_name : string ;
          mutable netmask : Ip.Addr.t option ;
          (* What the current lease granted, if anything. A lease is not a
             property of the host but of the moment: it goes when the power
             does (see [reset]), and what it does not carry falls back on the
             static configuration above. *)
          mutable leased_netmask : Ip.Addr.t option ;
          mutable leased_gateway : Ip.Addr.t option ;
          mutable leased_nameserver : Ip.Addr.t option ;
          mutable leased_search_sfx : string option ;
          mutable leased_host_name : string option ;
          mutable resolv_trx : trx option ;
          dns_queries : (string, ((Ip.Addr.t list option -> unit) * Metric.Timed.stop_func option)) Hashtbl.t ;
          dns_cache   : (string, Ip.Addr.t list) Hashtbl.t ;
          resolutions : Metric.Timed.t ;
          (* ICMP errors want to embed the first 8 bytes of the IP packet so we save
           * it here: *)
          mutable last_ip_packet : Ip.Pdu.t option }

type Widget.device += T of t

(* The host a widget stands for, when it stands for one. Set by [make] and not
   by [make_from_eth]: a host built on somebody else's adapter, as a router's
   admin host is, shares that owner's widget tree and is not what the widget
   holding it stands for. *)
let of_widget (w : Widget.t) =
    match w.device with
    | Some (T t) -> Some t
    | _ -> None

(* The configuration in use: what the current lease granted, or, for whatever
   it did not grant, what the reader configured. *)
let cur_netmask t = if t.leased_netmask <> None then t.leased_netmask
                    else t.netmask
let cur_nameserver t = if t.leased_nameserver <> None then t.leased_nameserver
                       else t.nameserver
let cur_search_sfx t = if t.leased_search_sfx <> None then t.leased_search_sfx
                       else t.search_sfx
let cur_host_name t = t.leased_host_name |? t.host_name

let print oc trx = String.print oc trx.widget.Widget.name
let make_tcp_socks ip = { ip_4_tcp = ip ; tcps = Hashtbl.create 3 }
let make_udp_socks ip = { ip_4_udp = ip ; udps = Hashtbl.create 3 }

exception No_socket

let signal_err t str =
    (* later, change this into a nice log *)
    Printf.fprintf stderr "Host %s: %s\n%!" t.trx.widget.name str

(* Forward the payload to the socket function or to the server function *)
let tcp_sock_rx t socks bits =
    match Tcp.Pdu.unpack bits with
        | Error s ->
            Log.(log t.trx.widget.logger Warning s)
        | Ok tcp ->
            let key = tcp.Tcp.Pdu.dst_port, tcp.Tcp.Pdu.src_port in
            try
                let trx =
                    hash_find_or_insert socks.tcps key (fun () ->
                        if tcp.Tcp.Pdu.flags.Tcp.Pdu.syn then (
                            let server = try Hashtbl.find t.tcp_servers tcp.Tcp.Pdu.dst_port
                                         with Not_found -> (
                                            Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "We have no server listening on port %s" (Tcp.Port.to_string tcp.Tcp.Pdu.dst_port)))) ;
                                            raise No_socket
                                        ) in
                            let tcp = Tcp.TRX.make t.trx.power tcp.Tcp.Pdu.dst_port tcp.Tcp.Pdu.src_port t.trx.widget.logger in
                            tcp.Tcp.TRX.tcp_trx.Tcp.TRX.trx =-> tx socks.ip_4_tcp ;
                            server tcp.Tcp.TRX.tcp_trx ; (* supposed to set the recver of this tcp trx *)
                            tcp.Tcp.TRX.tcp_trx
                        ) else (
                            Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "We have a server but so socket for ports %s:%s and TCP flags=%s" (Tcp.Port.to_string tcp.Tcp.Pdu.dst_port) (Tcp.Port.to_string tcp.Tcp.Pdu.src_port) (Tcp.Pdu.string_of_flags tcp.Tcp.Pdu.flags)))) ;
                            raise No_socket
                        )) in
                rx trx.Tcp.TRX.trx bits (* will reorder fragments and transmit the messages up to its emit function *)
            with No_socket ->
                Log.(log t.trx.widget.logger Debug (lazy "Sending a TCP-RST")) ;
                Tcp.Pdu.make_reset_of tcp |> Tcp.Pdu.pack |> tx socks.ip_4_tcp

let udp_sock_rx t socks icmp_trx bits =
    match Udp.Pdu.unpack bits with
        | Error s ->
            Log.(log t.trx.widget.logger Warning s)
        | Ok udp ->
            let key = udp.Udp.Pdu.dst_port, udp.Udp.Pdu.src_port in
            try
                let trx =
                    hash_find_or_insert socks.udps key (fun () ->
                        let server = try Hashtbl.find t.udp_servers udp.Udp.Pdu.dst_port
                                     with Not_found -> raise No_socket in
                        let trx = Udp.TRX.make t.trx.power udp.Udp.Pdu.dst_port udp.Udp.Pdu.src_port t.trx.widget.logger in
                        trx.Udp.TRX.trx =-> tx socks.ip_4_udp ;
                        server trx ; (* supposed to set the recver of this udp trx *)
                        trx) in
                rx trx.Udp.TRX.trx bits
            with No_socket ->
                Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "No socket for UDP packet on port %s, sending ICMP error" (Udp.Port.to_string udp.Udp.Pdu.dst_port)))) ;
                (* Send ICMP error *)
                match t.last_ip_packet with
                | None ->
                    Printf.eprintf "No last IP packet!?\n%!" ;
                    assert false
                | Some last_ip_packet ->
                    let icmp_err = Icmp.Pdu.make_port_unreachable last_ip_packet in
                    let icmp_bits = Icmp.Pdu.pack icmp_err in
                    tx icmp_trx icmp_bits

let icmp_rx t ip_trx bits =
    match Icmp.Pdu.unpack bits with
        | Error s ->
            Log.(log t.trx.widget.logger Warning s)
        | Ok Icmp.Pdu.{ msg_type ; payload = Ids (id, seq, pld) ; _ }
            when Icmp.MsgType.is_echo_request msg_type ->
                Log.(log t.trx.widget.logger Debug (lazy "Answering a PING")) ;
                Icmp.Pdu.make_echo_reply id seq ~pld |>
                Icmp.Pdu.pack |>
                tx ip_trx
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

let addr_of_string s =
   try IPv4 (Ip.Addr.of_string s)
   with _ -> Name s

(* Waiting to be attached to the widget of the host that owns them, which will
 * supply the clock they must be dated with:

let tcp_cnxs_ok  = Metric.Atomic.make "Host/Tcp/Connect/Ok"
let tcp_cnxs_err = Metric.Atomic.make "Host/Tcp/Connect/Err"
let udp_cnxs_ok  = Metric.Atomic.make "Host/Udp/Connect/Ok"
let udp_cnxs_err = Metric.Atomic.make "Host/Udp/Connect/Err"
let resolution_timeouts  = Metric.Atomic.make "Host/Resolver/Timeouts"
let resolution_cachehits = Metric.Atomic.make "Host/Resolver/CacheHits"
*)

let ip_is_set t =
    try ignore (Eth.State.find_ip4 t.eth_state) ; true
    with Not_found -> false

let rec with_resolver_trx t cont =
    let dns_recv _trx bits = (match Dns.Pdu.unpack bits with
        | Error s ->
            Log.(log t.trx.widget.logger Warning s)
        | Ok pdu ->
            Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Received DNS %s, opcode %d" (if pdu.Dns.Pdu.is_query then "query" else "response") pdu.Dns.Pdu.opcode))) ;
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
                    Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Awakening %d clients that were waiting for the address of '%s'" (List.length conts) name))) ;
                    List.iter (fun (cont, timer_stop_opt) ->
                        Option.may (fun f ->
                            let now = Simulation.Widget.now t.trx.widget in
                            f ~now (Metric.Params.singleton "status" (Metric.Param.String "ok"))
                        ) timer_stop_opt ;
                        cont (Some ips)) conts ;
                    Hashtbl.remove_all t.dns_queries name ;
                    (* cache the result *)
                    if Hashtbl.length t.dns_cache > 10 then Hashtbl.clear t.dns_cache ; (* FIXME *)
                    Hashtbl.add t.dns_cache name ips
                )
            ) (* Else the waiters will eventually be timeouted *)
        )
    in
    match t.resolv_trx, cur_nameserver t with
    | Some trx, _    ->
        Log.(log t.trx.widget.logger Debug (lazy "Use previous resolver trx")) ;
        cont (Some trx)
    | None, None     ->
        Log.(log t.trx.widget.logger Error (lazy (Printf.sprintf "Cannot resolve, no DNS"))) ;
        cont None
    | None, Some srv ->
        Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Create a resolving TRX to DNS %s" (Ip.Addr.to_string srv)))) ;
        udp_connect t (IPv4 srv) (Udp.Port.o 53) ~src_port:(Udp.Port.o 53) dns_recv (function
        | None -> cont None
        | Some trx ->
            t.resolv_trx <- Some trx.Udp.TRX.trx ;
            cont (Some trx.Udp.TRX.trx))

and gethostbyname t name cont =
    (* If the name is already an IP do not try to resolve it, otherwise host without DNS server cannot use IP addresses neither *)
    match Ip.Addr.of_dotted_string name with
    | exception _ -> do_gethostbyname t name cont
    | ip -> cont (Some [ip])

and do_gethostbyname t name cont =
    Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Resolving '%s'" name))) ;
    let dns_timeout_delay = Clock.Interval.sec 3. in
    let is_fqdn n = n.[String.length n - 1] = '.' in
    let is_complete n = is_fqdn n || String.exists n "." in
    let name = match cur_search_sfx t with
    | Some sfx ->
        (* send the query using host IPv4 stack, with as recv a decoding function *)
        if is_complete name then name else name ^ "." ^ sfx
    | None -> name in
    let name = if is_fqdn name then name else name ^ "." in
    let dns_timeout () = (* use the name redefined above *)
        let conts = Hashtbl.find_all t.dns_queries name in
        let num_conts = List.length conts in
        if num_conts > 0 then (
            Log.(log t.trx.widget.logger Warning (lazy (Printf.sprintf "Timeouting %d clients that were waiting for the address of '%s'" num_conts name))) ;
            (* Metric.Atomic.fire resolution_timeouts ; *)
            List.iter (fun (cont, timer_stop_opt) ->
                Option.may (fun f ->
                    let now = Simulation.Widget.now t.trx.widget in
                    f ~now (Metric.Params.singleton "status" (Metric.Param.String "timeout"))
                ) timer_stop_opt ;
                cont None) conts ;
            Hashtbl.remove_all t.dns_queries name
        ) in
    (* Try to find the IP in the cache *)
    match Hashtbl.find_option t.dns_cache name with
        | Some ips ->
            (* Metric.Atomic.fire resolution_cachehits ; *)
            cont (Some ips)
        | None ->
            Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Start resolver..."))) ;
            with_resolver_trx t (function
            | None ->
                cont None
            | Some resolv_trx ->
                let pending = Hashtbl.mem t.dns_queries name in
                Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Add a query for resolution of '%s' (%s)" name (if pending then "one was already pending" else "first one")))) ;
                if not pending then (
                    (* add a timeout event that will awake all waiters for this name after some time *)
                    Simulation.delay t.trx.power dns_timeout_delay dns_timeout () ;
                    (* Then actually sends the query *)
                    let now = Simulation.Widget.now t.trx.widget in
                    let params = Metric.(Params.singleton "name" (Param.String name)) in
                    let stop = Metric.Timed.start ~now ~params t.resolutions in
                    Hashtbl.add t.dns_queries name (cont, Some stop) ;
                    Dns.Pdu.make_query name |> Dns.Pdu.pack |> tx resolv_trx
                ) else (
                    Hashtbl.add t.dns_queries name (cont, None)
                )
            )

and tcp_connect t dst ?src_port (dst_port : Tcp.Port.t) cont =
    (* Fail if we do not have an IP yet *)
    if not (t.trx.power.Simulation.on && ip_is_set t) then cont None else
    let my_ip = Eth.State.find_ip4 t.eth_state in
    let connect dst_ip =
        Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Connecting to %s:%d" (Ip.Addr.to_string dst_ip) (dst_port :> int)))) ;
        let socks = hash_find_or_insert t.tcp_socks dst_ip (fun () ->
            let trx = Ip.TRX.make t.trx.power my_ip dst_ip Ip.Proto.tcp t.trx.widget.logger in
            let socks = make_tcp_socks trx in
            (tcp_sock_rx t socks) <-= trx =-> tx t.eth_trx ;
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
                    (* Metric.Atomic.fire tcp_cnxs_err ; *)
                    Log.(log t.trx.widget.logger Error (lazy "Already connected")) ;
                    None
                ) in
        (* Check we have a source port *)
        match src_port with
            | None ->
                cont None
            | Some src_port ->
                let tcp = Tcp.TRX.make t.trx.power src_port dst_port t.trx.widget.logger in
                tcp.Tcp.TRX.tcp_trx.Tcp.TRX.trx.out.set_read socks.ip_4_tcp.ins.write ;
                Hashtbl.add socks.tcps (src_port, dst_port) tcp.Tcp.TRX.tcp_trx ;
                Tcp.TRX.connect tcp (function
                | Some trx ->
                    Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf2 "Connection established with %s:%d" (Ip.Addr.to_string dst_ip) (dst_port :> int)))) ;
                    (* Metric.Atomic.fire tcp_cnxs_ok ; *)
                    cont (Some trx)
                | None ->
                    (* Metric.Atomic.fire tcp_cnxs_err ; *)
                    Log.(log t.trx.widget.logger Error (lazy (Printf.sprintf2 "Cannot connect to %s:%d" (Ip.Addr.to_string dst_ip) (dst_port :> int)))) ;
                    cont None)
    in
    match dst with
        | IPv4 dst_ip ->
            connect dst_ip
        | Name name ->
            gethostbyname t name (function
            | None -> cont None
            | Some dst_ips ->
                Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf2 "Got these IPs for '%s' : %a" name (List.print Ip.Addr.print') dst_ips))) ;
                if dst_ips <> [] then (
                    connect (List.hd dst_ips)
                ) else (
                    Log.(log t.trx.widget.logger Error (lazy ("Cannot resolve "^name))) ;
                    cont None
                ))

and udp_connect t dst ?src_port dst_port client_f cont =
    (* Fail if we do not have an IP yet *)
    if not (t.trx.power.Simulation.on && ip_is_set t) then cont None else
    let my_ip = Eth.State.find_ip4 t.eth_state in
    let connect dst_ip =
        let socks = hash_find_or_insert t.udp_socks dst_ip (fun () ->
            let icmp_trx = Ip.TRX.make t.trx.power my_ip dst_ip Ip.Proto.icmp t.trx.widget.logger in
            icmp_trx =-> tx t.eth_trx ;
            let ip_trx = Ip.TRX.make t.trx.power my_ip dst_ip Ip.Proto.udp t.trx.widget.logger in
            let socks = make_udp_socks ip_trx in
            (udp_sock_rx t socks icmp_trx) <-= ip_trx =-> tx t.eth_trx ;
            socks) in
        let src_port = may_default src_port (fun () -> Udp.Port.o (Random.int 0x10000)) in
        let key = src_port, dst_port in
        if Hashtbl.mem socks.udps key then (
            (* Metric.Atomic.fire udp_cnxs_err ; *)
            Log.(log t.trx.widget.logger Error (lazy "Already connected")) ;
            cont None
        ) else (
            let trx = Udp.TRX.make t.trx.power src_port dst_port t.trx.widget.logger in
            (* connect this udp to the underlaying ip *)
            (client_f trx) <-= trx.Udp.TRX.trx =-> tx socks.ip_4_udp ;
            Hashtbl.add socks.udps key trx ;
            (* Metric.Atomic.fire udp_cnxs_ok ; *)
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

let with_my_ip t f =
    if t.trx.power.Simulation.on then
        match Eth.State.find_ip4 t.eth_state with
        | exception Not_found -> ()
        | my_ip -> f my_ip

let udp_send t dst ?src_port dst_port bits =
    with_my_ip t (fun my_ip ->
        let send dst_ip =
            Udp.Pdu.make ~src_port:(Option.default dst_port src_port)
                         ~dst_port bits |>
                Udp.Pdu.pack |>
                Ip.Pdu.make Ip.Proto.udp my_ip dst_ip |>
                Ip.Pdu.pack |>
                tx t.eth_trx in
        match dst with
            | IPv4 dst_ip -> send dst_ip
            | Name name   ->
                gethostbyname t name (function
                | None -> ()
                | Some dst_ips ->
                    send (List.hd dst_ips)))

let ping t ?(id=1) ?(seq=1) dst =
    with_my_ip t (fun my_ip ->
        let do_ping dst_ip =
            Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Transmitting a ping to %s" (Ip.Addr.to_string dst_ip)))) ;
            Icmp.Pdu.make_echo_request id seq |>
            Icmp.Pdu.pack |>
            Ip.Pdu.make Ip.Proto.icmp my_ip dst_ip |>
            Ip.Pdu.pack |>
            tx t.eth_trx in
        match dst with
            | IPv4 dst_ip ->
                do_ping dst_ip
            | Name name ->
                gethostbyname t name (function
                | None -> ()
                | Some dst_ips ->
                    if dst_ips <> [] then
                        do_ping (List.hd dst_ips)))


let tcp_server t src_port server_f = Hashtbl.add t.tcp_servers src_port server_f
let udp_server t src_port server_f = Hashtbl.add t.udp_servers src_port server_f

(* The recv of the eth is responsible for handling the payload to the correct Ip.TRX *)
let ip_recv t bits =
    with_my_ip t (fun my_ip ->
        match Ip.Pdu.unpack bits with
        | Error s ->
            Log.(log t.trx.widget.logger Warning s)
        (* Shouldn't we check first that the dest IP is my_ip? or broadcast? *)
        | Ok ip ->
            Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Received an IP packet."))) ;
            t.last_ip_packet <- Some ip ;
            if ip.Ip.Pdu.proto = Ip.Proto.tcp then (
                let sock = hash_find_or_insert t.tcp_socks ip.Ip.Pdu.src (fun () ->
                    let ip_trx = Ip.TRX.make t.trx.power my_ip ip.Ip.Pdu.src ip.Ip.Pdu.proto t.trx.widget.logger in
                    let socks = make_tcp_socks ip_trx in
                    (tcp_sock_rx t socks) <-= ip_trx =-> tx t.eth_trx ;
                    socks) in
                rx sock.ip_4_tcp bits (* will handle fragmentation then pass payload to its emit function *)
            ) else if ip.Ip.Pdu.proto = Ip.Proto.udp then (
                let sock = hash_find_or_insert t.udp_socks ip.Ip.Pdu.src (fun () ->
                    let icmp_trx = Ip.TRX.make t.trx.power my_ip ip.Ip.Pdu.src Ip.Proto.icmp t.trx.widget.logger in
                    icmp_trx =-> tx t.eth_trx ;
                    let ip_trx = Ip.TRX.make t.trx.power my_ip ip.Ip.Pdu.src ip.Ip.Pdu.proto t.trx.widget.logger in
                    let socks = make_udp_socks ip_trx in
                    (udp_sock_rx t socks icmp_trx) <-= ip_trx =-> tx t.eth_trx ;
                    socks) in
                rx sock.ip_4_udp bits
            ) else if ip.Ip.Pdu.proto = Ip.Proto.icmp then (
                let ip_trx = hash_find_or_insert t.icmp_socks ip.Ip.Pdu.src (fun () ->
                    let ip_trx = Ip.TRX.make t.trx.power my_ip ip.Ip.Pdu.src ip.Ip.Pdu.proto t.trx.widget.logger in
                    (icmp_rx t ip_trx) <-= ip_trx =-> tx t.eth_trx ;
                    ip_trx) in
                rx ip_trx bits
            ))

(* The default route a lease installed on the adapter, taken off it again.
 * There is at most one at a time, so this is for whoever grants another as
 * much as for whoever cuts the power. Only the route that was added: the
 * reader may have configured one that says the very same thing, and that one
 * is not a lease's to remove. *)
let drop_leased_gateway t =
    Option.may (fun gw ->
        let route = Eth.State.gw_selector (), Some (Eth.Gateway.IPv4 gw) in
        t.eth_state.gateways <- List.remove t.eth_state.gateways route
    ) t.leased_gateway ;
    t.leased_gateway <- None

(* Cutting the power is enough to stop the host doing anything further, since
 * everything it had planned goes with it. What is left is the state those
 * plans were about: sockets, servers, resolver cache. It has to go too, or a
 * host powered back on would answer for connections nobody on the other end
 * still has. *)
let reset t =
    Eth.State.reset t.eth_state ;
    t.resolv_trx <- None ;
    (* The address and the reader go too, so that a host powered back on
       configures itself afresh rather than keeping a lease nobody granted it
       twice. Only for a host that has an address of its own to manage: one
       built on somebody else's adapter shares that owner's addresses and that
       owner's reader, and a router's admin host taking down either would stop
       the router routing. See [own_ip_config]. *)
    if t.own_ip_config then (
        t.eth_state.my_addresses <- [] ;
        ignore <-= t.eth_trx |> ignore
    ) ;
    (* And so does everything else the lease brought, the default route it
       installed included: a lease is granted to a running host, and this one
       has stopped. *)
    drop_leased_gateway t ;
    t.leased_netmask <- None ;
    t.leased_nameserver <- None ;
    t.leased_search_sfx <- None ;
    t.leased_host_name <- None ;
    Hashtbl.clear t.tcp_socks ;
    Hashtbl.clear t.udp_socks ;
    Hashtbl.clear t.icmp_socks ;
    Hashtbl.clear t.tcp_servers ;
    Hashtbl.clear t.udp_servers ;
    Hashtbl.clear t.dns_queries ;
    Hashtbl.clear t.dns_cache

let power_off t =
    Log.(log t.trx.widget.logger Debug (lazy "Halting.")) ;
    Simulation.power_down t.trx.power ;
    reset t

let set_ip t my_ip netmask =
    Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Setting my IP to %s" (Ip.Addr.to_string my_ip)))) ;
    t.eth_state.my_addresses <- [ Eth.State.make_my_ip_address ~netmask my_ip ] ;
    ip_recv t <-= t.eth_trx |> ignore

(* What a host is built from belongs within it, which is what the interface
   being built under the host's own widget buys. *)
(*$T make
  (let sim = Simulation.make ~realtime:false "test-tree" in \
   let h = \
     make ~parent:sim.Simulation.root \
          ~netmask:(Ip.Addr.of_string "255.255.255.0") \
          ~static_ip:(Ip.Addr.of_string "192.168.1.1") "h" in \
   List.exists (fun (w : Widget.t) -> w.name = "eth") h.trx.widget.Widget.children && \
   not (List.exists (fun (w : Widget.t) -> w.name = "eth") \
                    sim.Simulation.root.Widget.children))
 *)

(* A host with no configuration of its own to apply is somebody else's
   adapter that it speaks through, and whoever owns that adapter hands it its
   packets. Calling [set_ip] here would have it read the wire as well, which
   is exactly what a router's admin host must not do. *)
let init_nothing ?(on_ip:(t -> unit) option) (_t : t) =
    ignore on_ip

let init_static ?on_ip t =
    match t.static_ip with
    | Some static_ip ->
        (* A static address given without a netmask is a host that knows only
           itself: everything else is reached through a gateway. *)
        set_ip t static_ip (t.netmask |? Ip.Addr.all_ones) ;
        (* TODO: Send a gratuitous ARP request? *)
        Option.may (fun on_ip -> Simulation.asap t.trx.power on_ip t) on_ip
    | None ->
        (* [init] sends a host here only with one. *)
        assert false

(* The parameters a client asks for, most wanted first. Whatever is asked for
   here has to be applied by [apply_lease] below, and the other way about: a
   server serves what it is asked for and nothing else. *)
let dhcp_request_list =
    Dhcp.Option.(make_request_list
        [ subnet_mask ; routers ; domain_name_servers ; domain_name ;
          host_name ])

(* Take the parameters an accepted lease came with. Only those it carries: a
   lease that says nothing about the name server leaves the one the reader
   configured in use. *)
let apply_lease t (dhcp : Dhcp.Pdu.t) =
    let netmask =
        match dhcp.subnet_mask with
        | Some _ as m -> m
        | None -> t.netmask in
    let netmask =
        match netmask with
        | Some netmask -> netmask
        | None ->
            (* An address must have a netmask, and neither the lease nor the
               reader gave one: this one reaches nobody but through a
               gateway. *)
            Log.(log t.trx.widget.logger Warning (lazy
                "Leased an address with no netmask, assuming /32")) ;
            Ip.Addr.all_ones in
    t.leased_netmask <- Some netmask ;
    Option.may (fun ns -> t.leased_nameserver <- Some ns)
               dhcp.domain_name_server ;
    Option.may (fun sfx -> t.leased_search_sfx <- Some sfx) dhcp.search_sfx ;
    (* A server that names the client is naming this very host: the name it
       goes by is the one it is given, and not the one it asked for. *)
    Option.may (fun name -> t.leased_host_name <- Some name) dhcp.host_name ;
    (* A default route, added after the ones the reader configured, which are
       more specific and must keep the upper hand. [reset] takes it away
       again. *)
    drop_leased_gateway t ;
    Option.may (fun gw ->
        let route = Eth.State.gw_selector (), Some (Eth.Gateway.IPv4 gw) in
        t.eth_state.gateways <- t.eth_state.gateways @ [ route ] ;
        t.leased_gateway <- Some gw
    ) dhcp.router ;
    Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf
        "Leased %s/%s, gateway %s, name server %s, name %s"
            (Ip.Addr.to_string dhcp.yiaddr) (Ip.Addr.to_string netmask)
            (Option.map_default Ip.Addr.to_string "none" t.leased_gateway)
            (Option.map_default Ip.Addr.to_string "none" (cur_nameserver t))
            (cur_host_name t)))) ;
    set_ip t dhcp.yiaddr netmask

let init_dhcp ?on_ip t =
    (* Will receive all eth frames until we got an IP address *)
    let dhcp_client bits = (match Ip.Pdu.unpack bits with
        | Error s ->
            Log.(log t.trx.widget.logger Warning s)
        | Ok (ip : Ip.Pdu.t) ->
            if ip.proto <> Ip.Proto.udp then (
                Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Ignoring IP packet of proto %s while waiting for DHCP offer" (Ip.Proto.to_string ip.proto))))
            ) else (match Udp.Pdu.unpack (ip.payload :> bitstring) with
                | Error s ->
                    Log.(log t.trx.widget.logger Warning s)
                | Ok (udp : Udp.Pdu.t) ->
                    if udp.src_port <> (Udp.Port.o 67) || udp.dst_port <> (Udp.Port.o 68) then (
                        Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Ignoring UDP packet from %s:%s to %s:%s while waiting for DHCP offer"
                            (Ip.Addr.to_string ip.src) (Udp.Port.to_string udp.src_port)
                            (Ip.Addr.to_string ip.dst) (Udp.Port.to_string udp.dst_port))))
                    ) else (
                        match Dhcp.Pdu.unpack (udp.payload :> bitstring) with
                        | Error s ->
                            Log.(log t.trx.widget.logger Warning s)
                        | Ok (Dhcp.Pdu.{ op = BootReply ; msg_type = Some op ; _ } as dhcp) when op = Dhcp.MsgType.offer ->
                            Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Got DHCP OFFER from %s, accepting it" (Ip.Addr.to_string ip.src)))) ;
                            (* TODO: check the Xid? *)
                            let pdu = Dhcp.Pdu.make_request ~chaddr:(t.eth_state.mac :> bitstring) ~xid:dhcp.xid ~host_name:(cur_host_name t) ~request_list:dhcp_request_list ?server_id:dhcp.server_id dhcp.yiaddr in
                            let pdu = Udp.Pdu.make ~src_port:(Udp.Port.o 68) ~dst_port:(Udp.Port.o 67) (Dhcp.Pdu.pack pdu) in
                            let pdu = Ip.Pdu.make Ip.Proto.udp Ip.Addr.zero Ip.Addr.broadcast (Udp.Pdu.pack pdu) in
                            tx t.eth_trx (Ip.Pdu.pack pdu)
                        | Ok (Dhcp.Pdu.{ op = BootReply ; msg_type = Some op ; _ } as dhcp) when op = Dhcp.MsgType.ack ->
                            Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Got DHCP ACK from %s" (Ip.Addr.to_string ip.src)))) ;
                            apply_lease t dhcp ;
                            (* TODO: Send a gratuitous ARP request? *)
                            Option.may (fun on_ip ->
                                Simulation.asap t.trx.power on_ip t) on_ip
                        | Ok (Dhcp.Pdu.{ op = BootReply ; msg_type = Some op ; message ; _ })
                          when op = Dhcp.MsgType.nack ->
                            (* Nothing to do but keep asking, which the
                               discover timer is already seeing to. *)
                            Log.(log t.trx.widget.logger Warning (lazy
                                (Printf.sprintf "Got DHCP NAK from %s: %s"
                                    (Ip.Addr.to_string ip.src)
                                    (message |? "no reason given"))))
                        | Ok _ ->
                            (* TODO: print it *)
                            t.trx.signal_err "Ignoring a DHCP message"))) in
    let rec send_discover () =
        if not (ip_is_set t) then (
            Log.(log t.trx.widget.logger Debug (lazy "Sending DHCP DISCOVER")) ;
            Dhcp.Pdu.make_discover ~chaddr:(t.eth_state.mac :> bitstring) ~host_name:(cur_host_name t) ~request_list:dhcp_request_list () |>
                Dhcp.Pdu.pack |>
                Udp.Pdu.make ~src_port:(Udp.Port.o 68) ~dst_port:(Udp.Port.o 67) |>
                Udp.Pdu.pack |>
                Ip.Pdu.make Ip.Proto.udp Ip.Addr.zero Ip.Addr.broadcast |>
                Ip.Pdu.pack |>
                tx t.eth_trx ;
            Simulation.delay t.trx.power (Clock.Interval.sec (5.+.(Random.float 3.))) send_discover ()
        ) in
    ignore (dhcp_client <-= t.eth_trx) ;
    (* The client should wait a random time between one and ten seconds to desynchronize
       the use of DHCP at startup - RFC 2131 *)
    let delay = Clock.Interval.sec (1.+.(Random.float 9.)) in
    Log.(log t.trx.widget.logger Debug (lazy
        (Printf.sprintf "Waiting %s before using DHCP..."
            (Clock.Interval.to_string delay)))) ;
    Simulation.delay t.trx.power delay send_discover ()

let make_from_eth ?search_sfx ?nameserver ?static_ip ?netmask
                  ?(own_ip_config=true) ?(on=true) ~widget
                  (eth_state : Eth.State.t) eth_trx name =
    (* For the API a cable reaches a host but in reality it reaches its
       adapter. *)
    widget.Widget.ports <- Widget.ports_of eth_state.iface.widget ;
    (* The adapter's supply is the host's: they are the same machine, and an
       adapter that went on emitting after its host went down would be a host
       that is only half off. Taken from the adapter rather than made here
       because the adapter is built first, and something has to give it one --
       and a host built on somebody else's adapter, as a router's admin host
       is, shares that owner's switch, being the same box as well. *)
    let power = eth_state.iface.power in
    if not on then Simulation.power_down power ;
    let if_on t what f x =
        if t.trx.power.Simulation.on then f x else Log.(log widget.Widget.logger Debug (lazy (Printf.sprintf "Ignoring %s since I'm off" what))) in
    let rec t =
        { eth_state ;
          eth_trx ;
          tcp_socks     = Hashtbl.create 11 ;
          udp_socks     = Hashtbl.create 11 ;
          icmp_socks    = Hashtbl.create 11 ;
          tcp_servers   = Hashtbl.create 11 ;
          udp_servers   = Hashtbl.create 11 ;
          own_ip_config ;
          nameserver ;
          host_name     = name ;
          static_ip ;
          netmask ;
          leased_netmask = None ;
          leased_gateway = None ;
          leased_nameserver = None ;
          leased_search_sfx = None ;
          leased_host_name = None ;
          resolv_trx    = None ;
          search_sfx    = search_sfx ;
          dns_queries   = Hashtbl.create 3 ;
          dns_cache     = Hashtbl.create 3 ;
          resolutions   = Metric.Timed.make () ;
          trx           = host_trx ;
          last_ip_packet = None }
    (* Read afresh at every boot, and not chosen once here: which of the three
       applies is a fact about the host as it stands, and the reader may have
       changed it since. *)
    and init () =
        if not t.own_ip_config then init_nothing
        else if t.static_ip = None then init_dhcp
        else init_static
    and host_trx =
        { widget ;
          dev           = { write = (fun bits ->
                               Log.(log widget.logger Debug (lazy (Printf.sprintf "got written to %d bits" (bitstring_length bits)))) ;
                               rx t.eth_trx bits) ;
                            set_read = (fun f -> t.eth_trx =-> f) } ;
          tcp_connect   = (fun addr ?src_port dst cont -> if_on t "tcp_connect" (tcp_connect t addr ?src_port dst) cont) ;
          udp_connect   = (fun dst ?src_port dst_port client_f cont -> if_on t "udp_connect" (udp_connect t dst ?src_port dst_port client_f) cont) ;
          udp_send      = (fun dst ?src_port dst_port bits -> if_on t "udp_send" (udp_send t dst ?src_port dst_port) bits) ;
          ping          = (fun ?id ?seq dst -> if_on t "ping" (ping t ?id ?seq) dst) ;
          gethostbyname = (fun name cont -> if_on t "gethostbyname" (gethostbyname t name) cont) ;
          tcp_server    = (fun src_port server_f -> if_on t "tcp_server" (tcp_server t src_port) server_f) ;
          udp_server    = (fun src_port server_f -> if_on t "udp_server" (udp_server t src_port) server_f) ;
          signal_err    = (fun str -> signal_err t str) ;
          (* This call is needed by dhcpd servers running on this host: *)
          arp_set       = (fun ip haddr_opt -> if_on t "arp_set" (Eth.State.set_arp t.eth_state (Ip.Addr.to_bitstring ip)) haddr_opt) ;
          (* Guarded rather than asserted: with a shared supply, whether the
             power is on is a fact about the box, not about this host, so
             being asked to do again what has already been done is a
             possibility rather than a mistake. *)
          power_on      = (fun ?on_ip () ->
                              if t.trx.power.Simulation.on then
                                  Log.(log widget.logger Debug (lazy
                                      "Ignoring power on: already on"))
                              else (
                                  Log.(log widget.logger Debug (lazy "Powering on")) ;
                                  Simulation.power_up t.trx.power ;
                                  init () ?on_ip t
                              )) ;
          power_off     = (fun () ->
                              if not t.trx.power.Simulation.on then
                                  Log.(log widget.logger Debug (lazy
                                      "Ignoring power off: already off"))
                              else power_off t) ;
          start         = (fun ?on_ip () -> init () ?on_ip t) ;
          reset         = (fun () -> reset t) ;
          power }
    in
    (* No "on" property here: the switch belongs to whoever minted the supply,
       which for a host built on somebody else's adapter is somebody else. See
       [make], and [Router.make] for the other case. *)
    (* The configuration a host is running with is not always the one it was
       given: a DHCP lease overrides the reader's own settings for as long as
       it lasts. So these read as what is in use and write what the reader
       configured, which is what comes back when the lease goes. *)
    Widget.add_properties widget Widget.[
        property "hostname" ~kind:String
            ~descr:"Name this host goes by (a DHCP lease may override it)."
            ~getter:(fun () -> `String (cur_host_name t))
            ~setter:(fun v -> t.host_name <- to_string v) ;
        property "search suffix" ~kind:String
            ~descr:"Search suffix (a DHCP lease may override it)."
            ~getter:(fun () -> `String (cur_search_sfx t |? ""))
            ~setter:(fun v -> t.search_sfx <- match to_string v with "" -> None | s -> Some s) ;
        metric_property "DNS resolutions" ~descr:"DNS resolution times."
            (Metric.Timed.T t.resolutions) ] ;
    Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "New host '%s'" name))) ;
    if t.trx.power.Simulation.on then init () t ;
    t

let make ?gateways ?search_sfx ?nameserver ?mac ?on ?static_ip ?netmask
         ~parent ?location name =
    let widget = Widget.make ~parent ?location ~device_type:"host" name in
    let eth_state =
        (* FIXME: Don't use the GW for same net IP! *)
        Eth.State.make ?mac ?gateways ~parent:widget
                       ~power:(Simulation.make_power
                                   (Simulation.of_widget widget) name) () in
    let eth_trx = Eth.TRX.make eth_state in
    let t = make_from_eth ?search_sfx ?nameserver ?on ~widget ?static_ip
                          ?netmask eth_state eth_trx name in
    (* This host minted the supply above, so the switch for it goes here, and
       so does stopping it for good. And it is a whole machine, unlike a host
       built on somebody else's adapter. *)
    widget.device <- Some (T t) ;
    widget.on_delete <- (fun () -> t.trx.power_off ()) ;
    Widget.add_properties widget Widget.[
        property "on" ~descr:"The host is powered on." ~kind:Bool
            ~getter:(fun () -> `Bool t.trx.power.Simulation.on)
            ~setter:(fun v ->
                if to_bool v then t.trx.power_on () else t.trx.power_off ()) ;
        property "static-ip" ~kind:(Optional String)
            ~descr:"IP given at boot (if none, will use DHCP)."
            ~getter:(fun () -> json_of_optional Ip.Addr.to_json t.static_ip)
            ~setter:(fun v ->
                t.static_ip <- to_option (Ip.Addr.of_json "static-ip") v) ;
        property "static-netmask" ~kind:(Optional String)
            ~descr:"Netmask of the static IP configuration."
            ~getter:(fun () -> json_of_optional Ip.Addr.to_json t.netmask)
            ~setter:(fun v ->
                t.netmask <- to_option (Ip.Addr.of_json "netmask") v) ;
        property "netmask" ~kind:(Optional String)
            ~descr:"Netmask in use (from the lease, if there is one)."
            ~getter:(fun () -> json_of_optional Ip.Addr.to_json (cur_netmask t)) ;
        property "nameserver" ~kind:(Optional String)
            ~descr:"Address of the DNS server (a DHCP lease may override it)."
            ~getter:(fun () ->
                json_of_optional Ip.Addr.to_json (cur_nameserver t))
            ~setter:(fun v ->
                t.nameserver <- to_option (Ip.Addr.of_json "nameserver") v) ] ;
    t

(* A host boots into the configuration it has at that moment, and not the one
   it was built with: what the reader changed between two boots is the whole
   point of keeping the configuration on the host rather than in the closure
   that applies it. *)
(*$R make
    let sim = Simulation.make ~realtime:false "test-reboot" in
    let netmask = Ip.Addr.of_string "255.255.255.0" in
    let h =
        make ~parent:sim.Simulation.root ~netmask
             ~static_ip:(Ip.Addr.of_string "192.168.1.10") "h" in
    let prop name =
        List.find (fun (p : Widget.property) -> p.Widget.name = name)
                  h.trx.widget.Widget.properties in
    let set name v = (Option.get (prop name).Widget.setter) v in
    let reboot () = set "on" (`Bool false) ; set "on" (`Bool true) in
    let address () =
        match Eth.State.find_ip4 h.eth_state with
        | exception Not_found -> "none"
        | ip -> Ip.Addr.to_dotted_string ip in
    assert_equal ~printer:identity "192.168.1.10" (address ()) ;
    set "on" (`Bool false) ;
    (* Its address goes with its power: an address it kept while off would be
       one it had never been granted when it came back. *)
    assert_equal ~printer:identity "none" (address ()) ;
    set "on" (`Bool true) ;
    assert_equal ~printer:identity "192.168.1.10" (address ()) ;

    (* Told to use DHCP instead, it must come back with nothing and go asking,
       rather than with the address it used to have. *)
    set "static-ip" `Null ;
    reboot () ;
    assert_equal ~printer:identity "none" (address ()) ;

    (* And the other way about: a host that was left to DHCP takes the address
       it is given here, without being rebuilt. *)
    set "static-ip" (`String "192.168.1.11") ;
    reboot () ;
    assert_equal ~printer:identity "192.168.1.11" (address ()) ;

    (* A static address given with no netmask is still applied: it is a host
       that knows only itself, and reaches everything else through a gateway. *)
    set "static-netmask" `Null ;
    reboot () ;
    assert_equal ~printer:identity "192.168.1.11" (address ())
 *)

module Name = struct
    let random () =
        randstr ~charset:"abcdefghijklmnopqrstuvwxyz" (5 + (Random.int 25))
end
