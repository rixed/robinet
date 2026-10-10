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

  See also {!Localhost} for a special kind of host that's running on top of
  guest system real IP stack.
*)
open Batteries
open SimTypes
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
    (* Starting a server on a port that already has one, or stopping one on a
       port that has none, raises [Widget.Bad_value]. *)
    tcp_server_start : Tcp.Port.t -> (Tcp.TRX.tcp_trx -> unit) -> unit ;
    (* Also closes the connections that server accepted. *)
    tcp_server_stop  : Tcp.Port.t -> unit ;
    udp_server_start : Udp.Port.t -> (Udp.TRX.udp_trx -> unit) -> unit ;
    udp_server_stop  : Udp.Port.t -> unit ;
    signal_err    : string -> unit ;
    dev           : dev ; (* as seen from the outside *)
    arp_set       : Ip.Addr.t -> Eth.Addr.t option -> unit ;
    (* List of things to do once this host gets its IP address *)
    mutable on_ip : (t -> unit) list }

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

(* A listening server: what to do with a new connection, and the connections
   it was handed, so that stopping it can close them. *)
and tcp_server = { tcp_accept : Tcp.TRX.tcp_trx -> unit ;
                   (* With the table and key each is registered under. Closed
                      ones are pruned on each accept. *)
                   mutable tcp_cnxs : (tcp_socks * (Tcp.Port.t * Tcp.Port.t) * Tcp.TRX.tcp_trx) list }

(* UDP has nothing to close, but the sockets a server was handed must stop
   receiving when it stops: *)
and udp_server = { udp_accept : Udp.TRX.udp_trx -> unit ;
                   mutable udp_peers : (udp_socks * (Udp.Port.t * Udp.Port.t)) list }

and t = { mutable trx : host_trx ;
          eth_state   : Eth.State.t ;
          eth_trx     : trx ;
          tcp_socks   : (Ip.Addr.t, tcp_socks) Hashtbl.t ;
          udp_socks   : (Ip.Addr.t, udp_socks) Hashtbl.t ;
          icmp_socks  : (Ip.Addr.t, trx) Hashtbl.t ;
          (* the listening servers *)
          tcp_servers : (Tcp.Port.t, tcp_server) Hashtbl.t ;
          udp_servers : (Udp.Port.t, udp_server) Hashtbl.t ;
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
          (* Who is waiting for an ICMP echo reply.
           * Indexed by ICMP id (which is also the action_state's id).
           * One waiter may wait for several echo requests (with various seq
           * number) *)
          echo_waiters : (int (* ICMP id *), int -> unit) Hashtbl.t ;
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

(* IP packets are sized for the host's only interface, and TCP segments for
 * those packets (IP and TCP headers without options): *)
let ip_mtu t = t.eth_state.Eth.State.mtu
let tcp_mss t = ip_mtu t - Ip.Pdu.no_opt_hdr_len - Tcp.Pdu.no_opt_hdr_len

let print oc trx = String.print oc trx.widget.name
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
                            let tcp = Tcp.TRX.make t.trx.widget.power ~mss:(tcp_mss t) tcp.Tcp.Pdu.dst_port tcp.Tcp.Pdu.src_port t.trx.widget.logger in
                            tcp.Tcp.TRX.tcp_trx.Tcp.TRX.trx =-> tx socks.ip_4_tcp ;
                            server.tcp_cnxs <-
                                (socks, key, tcp.Tcp.TRX.tcp_trx) ::
                                List.filter (fun (_, _, (c : Tcp.TRX.tcp_trx)) ->
                                    not (c.is_closed ())) server.tcp_cnxs ;
                            server.tcp_accept tcp.Tcp.TRX.tcp_trx ; (* supposed to set the recver of this tcp trx *)
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
                        let trx = Udp.TRX.make t.trx.widget.power udp.Udp.Pdu.dst_port udp.Udp.Pdu.src_port t.trx.widget.logger in
                        trx.Udp.TRX.trx =-> tx socks.ip_4_udp ;
                        server.udp_peers <- (socks, key) :: server.udp_peers ;
                        server.udp_accept trx ; (* supposed to set the recver of this udp trx *)
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
        (* A reply nobody is waiting for is dropped. *)
        | Ok Icmp.Pdu.{ msg_type ; payload = Ids (id, seq, _) ; _ }
            when Icmp.MsgType.is_echo_reply msg_type ->
                Option.may (fun waiter -> waiter seq)
                           (Hashtbl.find_option t.echo_waiters id)
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
                            f ~now Metric.(Params.singleton "status" (Param.String "ok"))
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
                    Simulation.delay t.trx.widget.power
                                     dns_timeout_delay dns_timeout () ;
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
    if not (t.trx.widget.power.on && ip_is_set t) then cont None else
    let my_ip = Eth.State.find_ip4 t.eth_state in
    let connect dst_ip =
        Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Connecting to %s:%d" (Ip.Addr.to_string dst_ip) (dst_port :> int)))) ;
        let socks = hash_find_or_insert t.tcp_socks dst_ip (fun () ->
            let trx = Ip.TRX.make t.trx.widget.power ~mtu:(ip_mtu t) my_ip dst_ip Ip.Proto.tcp t.trx.widget.logger in
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
                let tcp = Tcp.TRX.make t.trx.widget.power ~mss:(tcp_mss t) src_port dst_port t.trx.widget.logger in
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
    if not (t.trx.widget.power.on && ip_is_set t) then cont None else
    let my_ip = Eth.State.find_ip4 t.eth_state in
    let connect dst_ip =
        let socks = hash_find_or_insert t.udp_socks dst_ip (fun () ->
            let icmp_trx = Ip.TRX.make t.trx.widget.power ~mtu:(ip_mtu t) my_ip dst_ip Ip.Proto.icmp t.trx.widget.logger in
            icmp_trx =-> tx t.eth_trx ;
            let ip_trx = Ip.TRX.make t.trx.widget.power ~mtu:(ip_mtu t) my_ip dst_ip Ip.Proto.udp t.trx.widget.logger in
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
            let trx = Udp.TRX.make t.trx.widget.power src_port dst_port t.trx.widget.logger in
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
            | Some (dst_ip :: _) -> connect dst_ip
            | Some [] ->
                Log.(log t.trx.widget.logger Error (lazy ("Cannot resolve "^name))) ;
                cont None)

let with_my_ip t f =
    if t.trx.widget.power.on then
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

let tcp_server_start t port tcp_accept =
    if Hashtbl.mem t.tcp_servers port then
        Widget.bad_value "TCP port %s already has a server"
            (Tcp.Port.to_string port) ;
    Hashtbl.add t.tcp_servers port { tcp_accept ; tcp_cnxs = [] }

(* An established connection is closed. A half-open one cannot be, and is
   forgotten instead: the peer's next segment then draws a reset. *)
let tcp_server_stop t port =
    match Hashtbl.find_option t.tcp_servers port with
    | None ->
        Widget.bad_value "No TCP server on port %s" (Tcp.Port.to_string port)
    | Some server ->
        Hashtbl.remove t.tcp_servers port ;
        List.iter (fun (socks, key, (cnx : Tcp.TRX.tcp_trx)) ->
            if not (cnx.is_closed ()) then
                if cnx.is_established () then cnx.close ()
                else Hashtbl.remove socks.tcps key
        ) server.tcp_cnxs

let udp_server_start t port udp_accept =
    if Hashtbl.mem t.udp_servers port then
        Widget.bad_value "UDP port %s already has a server"
            (Udp.Port.to_string port) ;
    Hashtbl.add t.udp_servers port { udp_accept ; udp_peers = [] }

let udp_server_stop t port =
    match Hashtbl.find_option t.udp_servers port with
    | None ->
        Widget.bad_value "No UDP server on port %s" (Udp.Port.to_string port)
    | Some server ->
        Hashtbl.remove t.udp_servers port ;
        List.iter (fun (socks, key) -> Hashtbl.remove socks.udps key)
                  server.udp_peers

(* A port takes one server at a time, and a stopped server stops answering,
   including the peers it was already talking to. *)
(*$R tcp_server_stop
    let sim = Simulation.make ~realtime:false "server-stop" in
    let ip n = Ip.Addr.of_string ("192.168.0." ^ string_of_int n) in
    let host n =
        make ~parent:sim.root ~static_ip:(ip n)
             ~netmask:(Ip.Addr.of_string "255.255.255.0")
             ("h" ^ string_of_int n) in
    let a = host 1 and b = host 2 in
    let st = Eth.Cable.State.make ~parent:sim.root ~name:"c" () in
    Eth.Cable.plug st (a.trx.widget, 0) (b.trx.widget, 0) ;
    Simulation.run_startup sim ;
    let refused f = try f () ; false with Widget.Bad_value _ -> true in
    let port = Tcp.Port.o 7 in
    b.trx.tcp_server_start port ignore ;
    assert_bool "a busy port is refused"
        (refused (fun () -> b.trx.tcp_server_start port ignore)) ;
    assert_bool "stopping nothing is refused"
        (refused (fun () -> b.trx.tcp_server_stop (Tcp.Port.o 8))) ;
    let cnx = ref None and closed = ref false in
    let connect () =
        cnx := None ;
        a.trx.tcp_connect (IPv4 (ip 2)) port (fun c ->
            cnx := c ;
            Option.may (fun (c : Tcp.TRX.tcp_trx) ->
                c.trx.ins.set_read (fun bits ->
                    if Bitstring.bitstring_length bits = 0 then closed := true)
            ) c) ;
        Simulation.run sim false in
    connect () ;
    assert_bool "connected" (!cnx <> None) ;
    tcp_server_stop b port ;
    Simulation.run sim false ;
    assert_bool "the server closed the connection" !closed ;
    connect () ;
    assert_bool "and accepts no more" (!cnx = None) ;
    (* The port is free again: *)
    b.trx.tcp_server_start port ignore ;
    connect () ;
    assert_bool "until restarted" (!cnx <> None) ;

    let uport = Udp.Port.o 5000 and served = ref 0 in
    let serve () =
        b.trx.udp_server_start uport (fun udp ->
            udp.Udp.TRX.trx.ins.set_read (fun _ -> incr served)) in
    let send () =
        a.trx.udp_send (IPv4 (ip 2)) ~src_port:(Udp.Port.o 6000) uport
                       (Bitstring.zeroes_bitstring 64) ;
        Simulation.run sim false in
    serve () ;
    assert_bool "a busy UDP port is refused" (refused serve) ;
    send () ; send () ;
    assert_equal ~printer:string_of_int 2 !served ;
    b.trx.udp_server_stop uport ;
    send () ;
    assert_equal ~printer:string_of_int ~msg:"a known peer is not served" 2 !served ;
    serve () ;
    send () ;
    assert_equal ~printer:string_of_int ~msg:"until restarted" 3 !served
 *)

(* The recv of the eth is responsible for handling the payload to the correct Ip.TRX *)
let ip_recv t bits =
    with_my_ip t (fun my_ip ->
        match Ip.Pdu.unpack bits with
        | Error s ->
            Log.(log t.trx.widget.logger Warning s)
        | Ok ip when Ip.Addr.compare my_ip ip.dst = 0 ||
                     Ip.Addr.(is_broadcast ip.dst || is_multicast ip.dst) ->
            Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "Received an IP packet."))) ;
            t.last_ip_packet <- Some ip ;
            if ip.Ip.Pdu.proto = Ip.Proto.tcp then (
                let sock = hash_find_or_insert t.tcp_socks ip.Ip.Pdu.src (fun () ->
                    let ip_trx = Ip.TRX.make t.trx.widget.power ~mtu:(ip_mtu t) my_ip ip.Ip.Pdu.src ip.Ip.Pdu.proto t.trx.widget.logger in
                    let socks = make_tcp_socks ip_trx in
                    (tcp_sock_rx t socks) <-= ip_trx =-> tx t.eth_trx ;
                    socks) in
                rx sock.ip_4_tcp bits (* will handle fragmentation then pass payload to its emit function *)
            ) else if ip.Ip.Pdu.proto = Ip.Proto.udp then (
                let sock = hash_find_or_insert t.udp_socks ip.Ip.Pdu.src (fun () ->
                    let icmp_trx = Ip.TRX.make t.trx.widget.power ~mtu:(ip_mtu t) my_ip ip.Ip.Pdu.src Ip.Proto.icmp t.trx.widget.logger in
                    icmp_trx =-> tx t.eth_trx ;
                    let ip_trx = Ip.TRX.make t.trx.widget.power ~mtu:(ip_mtu t) my_ip ip.Ip.Pdu.src ip.Ip.Pdu.proto t.trx.widget.logger in
                    let socks = make_udp_socks ip_trx in
                    (udp_sock_rx t socks icmp_trx) <-= ip_trx =-> tx t.eth_trx ;
                    socks) in
                rx sock.ip_4_udp bits
            ) else if ip.Ip.Pdu.proto = Ip.Proto.icmp then (
                let ip_trx = hash_find_or_insert t.icmp_socks ip.Ip.Pdu.src (fun () ->
                    let ip_trx = Ip.TRX.make t.trx.widget.power ~mtu:(ip_mtu t) my_ip ip.Ip.Pdu.src ip.Ip.Pdu.proto t.trx.widget.logger in
                    (icmp_rx t ip_trx) <-= ip_trx =-> tx t.eth_trx ;
                    ip_trx) in
                rx ip_trx bits
            )
        | Ok ip ->
            Log.(log t.trx.widget.logger Info (lazy (Printf.sprintf
                "Received an IP packet for %s (I'm %s)"
                (Ip.Addr.to_string ip.dst) (Ip.Addr.to_string my_ip)))))

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
    (* What it was serving stays: a machine switched off and on again comes
       back running what it runs, and the conversations it was having are what
       it loses. Clearing these left a gateway that had been switched off
       answering neither DHCP nor DNS, with nothing to register them again. *)
    Hashtbl.iter (fun _ s -> s.tcp_cnxs <- []) t.tcp_servers ;
    Hashtbl.iter (fun _ s -> s.udp_peers <- []) t.udp_servers ;
    Hashtbl.clear t.dns_queries ;
    Hashtbl.clear t.dns_cache ;
    Hashtbl.clear t.echo_waiters

let power_off t =
    Log.(log t.trx.widget.logger Debug (lazy "Halting.")) ;
    Simulation.power_down t.trx.widget.power ;
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
     make ~parent:sim.root \
          ~netmask:(Ip.Addr.of_string "255.255.255.0") \
          ~static_ip:(Ip.Addr.of_string "192.168.1.1") "h" in \
   List.exists (fun (w : Widget.t) -> w.name = "eth") h.trx.widget.children && \
   not (List.exists (fun (w : Widget.t) -> w.name = "eth") \
                    sim.root.children))
 *)

let init_static t =
    match t.static_ip with
    | Some static_ip ->
        (* A static address given without a netmask is a host that knows only
           itself: everything else is reached through a gateway. *)
        set_ip t static_ip (t.netmask |? Ip.Addr.all_ones) ;
        (* TODO: Send a gratuitous ARP request? *)
        (* Note: even if on_ip is unset, it might be set before [asap]! *)
        Simulation.asap t.trx.widget.power (fun () ->
            List.iter (fun f -> f t) t.trx.on_ip
        ) ()
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

let init_dhcp t =
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
                            Simulation.asap t.trx.widget.power (fun () ->
                                List.iter (fun f -> f t) t.trx.on_ip
                            ) ()
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
            Simulation.delay t.trx.widget.power
                             (Clock.Interval.sec (5.+.(Random.float 3.)))
                             send_discover ()
        ) in
    ignore (dhcp_client <-= t.eth_trx) ;
    (* The client should wait a random time between one and ten seconds to desynchronize
       the use of DHCP at startup - RFC 2131 *)
    let delay = Clock.Interval.sec (1.+.(Random.float 9.)) in
    Log.(log t.trx.widget.logger Debug (lazy
        (Printf.sprintf "Waiting %s before using DHCP..."
            (Clock.Interval.to_string delay)))) ;
    Simulation.delay t.trx.widget.power delay send_discover ()

(* Build the host from its ethernet adapter.
 * you probably want [eth_state] to share its power source with [widget]. *)
let make_from_eth ?search_sfx ?nameserver ?static_ip ?netmask
                  ?(own_ip_config=true) ~widget
                  (eth_state : Eth.State.t) eth_trx name =
    (* For the API a cable reaches a host but in reality it reaches its
       adapter. *)
    widget.ports <- Widget.ports_of eth_state.iface.widget ;
    (* Whether this host runs is whether its supply is on, and nothing else:
     * one flag, in the source, however many widgets draw on it. *)
    let if_on t what f x =
        if t.trx.widget.power.on then f x
        else Log.(log widget.logger Debug (lazy (Printf.sprintf "Ignoring %s since I'm off" what))) in
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
          echo_waiters  = Hashtbl.create 3 ;
          trx           = host_trx ;
          last_ip_packet = None }
    (* Read afresh at every boot, and not chosen once here: which of the three
       applies is a fact about the host as it stands, and the reader may have
       changed it since. *)
    and init () =
        (* A host with no configuration of its own to apply is somebody else's
           adapter that it speaks through, and whoever owns that adapter hands it its
           packets. Calling [set_ip] here would have it read the wire as well, which
           is exactly what a router's admin host must not do. *)
        if not t.own_ip_config then ignore
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
          (* Not [if_on]: what a machine runs is what it is configured with and
             not something it does, and a box is configured while it is dark --
             born that way, and switched on by its power-on when the network
             around it stands. A server on a box that is off still cannot
             answer: what it would send is scheduled on the box's supply, and
             there is none. *)
          tcp_server_start = (fun port server_f -> tcp_server_start t port server_f) ;
          tcp_server_stop  = (fun port -> tcp_server_stop t port) ;
          udp_server_start = (fun port server_f -> udp_server_start t port server_f) ;
          udp_server_stop  = (fun port -> udp_server_stop t port) ;
          signal_err    = (fun str -> signal_err t str) ;
          (* This call is needed by dhcpd servers running on this host: *)
          arp_set       = (fun ip haddr_opt -> if_on t "arp_set" (Eth.State.set_arp t.eth_state (Ip.Addr.to_bitstring ip)) haddr_opt) ;
          on_ip         = [] }
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
    (* What this host does when its supply is switched: boot, and forget what
       a cut invalidates. Called by [Simulation.power_up] and
       [Simulation.power_down], which find it by walking the tree. *)
    widget.power_up <- (fun () -> init () t) ;
    widget.power_down <- (fun () -> reset t) ;
    Log.(log t.trx.widget.logger Debug (lazy (Printf.sprintf "New host '%s'" name))) ;
    (* A host built into a box that is already running -- an admin host on an
       interface configured after the fact -- boots now, since the supply will
       not be switched again to tell it to. One built with a supply of its own
       is still dark, and boots when [make] switches that on. *)
    if t.trx.widget.power.on then init () t ;
    t

(* What a host can be asked to do. For now: ping.
 *
 * The run's own number is what its replies are recognised by -- an ICMP echo
 * carries an id chosen by whoever sent it, and two pings from one host at the
 * same time must not read each other's replies. The handler is registered in
 * [echo_waiters] for as long as the run lasts.
 *
 * The requests are spaced by [interval] and the last one is given [timeout] to
 * be answered; the run ends when every request has been answered or that delay
 * has passed, whichever comes first. If the host is switched off in between,
 * neither happens: the delay was an event of the host's own supply and went
 * with it, and the run goes on reading as running. That is the hole {!Action}
 * describes, and this is the first thing to fall into it. *)
let ping_action t =
    let widget = t.trx.widget in
    Widget.action "ping"
        ~descr:"Send echo requests to that address and count what comes back."
        ~params:Widget.[
            param "target" ~kind:(hint "192.168.0.1" String)
                ~descr:"What to ping: an address, or a name to be resolved." ;
            param "count" ~kind:(IRange (1, 10_000)) ~default:(`Int 3)
                ~descr:"How many requests to send." ;
            (* Durations rather than ranges: what the interface draws for a
               range is a slider, which is not how a delay is typed in. What a
               range would have refused is refused below instead. *)
            param "interval" ~kind:Duration ~units:"secs" ~default:(`Float 1.)
                ~descr:"How long to wait between two requests." ;
            param "timeout" ~kind:Duration ~units:"secs" ~default:(`Float 4.)
                ~descr:"How long to wait for the last reply before giving up." ]
        ~result:Widget.(record [| "sent", Int ;
                                  "received", Int ;
                                  (* Null when nothing came back: there is no
                                     round trip to report the length of. *)
                                  "min", optional Duration ;
                                  "avg", optional Duration ;
                                  "max", optional Duration |])
        ~handler:(fun state ->
            let target = Widget.arg_string state.params "target"
            and count = Widget.arg_int state.params "count"
            and interval = Widget.arg_float state.params "interval"
            and timeout = Widget.arg_float state.params "timeout" in
            if interval <= 0. then
                Widget.bad_value "interval must be above zero, not %g" interval ;
            if timeout <= 0. then
                Widget.bad_value "timeout must be above zero, not %g" timeout ;
            let dst = addr_of_string target in
            let id = state.id land 0xffff in
            let sim = Widget.sim widget
            and power = t.trx.widget.power in
            (* When each request went out, by sequence number, and emptied as
               the replies come in: what is left in it is what is still
               awaited. *)
            let sent_at = Hashtbl.create count in
            let sent = ref 0 and received = ref 0
            and rtt_min = ref infinity and rtt_max = ref 0.
            and rtt_total = ref 0. and over = ref false in
            (* Nothing more is to be sent, and nothing more is awaited: what
               this run was holding, given up. Called when it ends of its own
               accord and when it is found to have ended without us -- which is
               what a cancel is (see {!Action.cancel}). *)
            let release () =
                over := true ;
                Hashtbl.remove t.echo_waiters id in
            let finish () =
                if not !over then (
                    release () ;
                    let rtt f = if !received = 0 then `Null else `Float f in
                    Action.stop state ~result:(`Assoc [
                        "sent", `Int !sent ;
                        "received", `Int !received ;
                        "min", rtt !rtt_min ;
                        "avg", rtt (!rtt_total /. float_of_int !received) ;
                        "max", rtt !rtt_max ])) in
            Hashtbl.add t.echo_waiters id (fun seq ->
                if not (Action.is_running state) then release () else
                match Hashtbl.find_option sent_at seq with
                (* A reply to a request this run did not send, or the second
                   copy of one it did: neither is a round trip. *)
                | None -> ()
                | Some at ->
                    Hashtbl.remove sent_at seq ;
                    incr received ;
                    let rtt =
                        Clock.Interval.to_secs (Clock.Time.diff (Simulation.now sim) at) in
                    rtt_total := !rtt_total +. rtt ;
                    if rtt < !rtt_min then rtt_min := rtt ;
                    if rtt > !rtt_max then rtt_max := rtt ;
                    Log.(log widget.logger Info (lazy (Printf.sprintf
                        "Echo reply from %s: seq=%d, %gs" target seq rtt))) ;
                    (* Everything sent, and nothing left awaited: no point
                       waiting out the timeout. *)
                    if !sent >= count && Hashtbl.is_empty sent_at then
                        finish ()) ;
            let rec send seq () =
                (* Somebody stopped this run between two requests: the events
                   it had scheduled are still ours to drop, since nothing else
                   can tell them from the rest of the host's. *)
                if not (Action.is_running state) then release () else (
                incr sent ;
                Hashtbl.replace sent_at seq (Simulation.now sim) ;
                (* Every request after the first goes out from a scheduled
                   callback, where an exception would be caught by the
                   dispatcher, printed, and lost: the run would then wait out
                   its timeout and report what it had, saying nothing of why it
                   stopped sending. *)
                match t.trx.ping ~id ~seq dst with
                | exception e ->
                    over := true ;
                    Hashtbl.remove t.echo_waiters id ;
                    Action.fail state "cannot ping %s: %s" target
                        (match e with
                        | Widget.Bad_value m -> m
                        | e -> Printexc.to_string e)
                | () ->
                    if seq < count then
                        Simulation.delay power (Clock.Interval.sec interval)
                            (send (seq + 1)) ()
                    else
                        Simulation.delay power (Clock.Interval.sec timeout)
                            finish ()) in
            send 1 ())

(* {2 Servers and clients}
 *
 * What a host can be asked to run to have some traffic flowing. Each runs
 * under a widget of its own below the host, named after its port --
 * "server-tcp:5001", "client-udp:6000" -- or, for a client given no source
 * port, after what it connects to: "client-tcp:10.0.0.2:5001". That widget
 * shows what was exchanged so far and offers [stop], and goes when the server
 * or client stops, however that happens: stopped, deleted, its run cancelled
 * or its host switched off. What was exchanged is then the result of the run
 * that started it.
 *
 * A cancelled run is noticed by the next callback of that server or client
 * (see {!Action.cancel}), so one with no traffic lingers until stopped. *)

type behavior =
    | Sink
    | Echo
    (* Sizes uniform within those bounds, and intervals exponentially
       distributed with that mean, in seconds: *)
    | Random of { min_size : int ; max_size : int ; interval : float }

(* Of messages up to [max_size] bytes, the largest the protocol can carry: *)
let behavior_kind ~max_size =
    let size = IRange (1, max_size) in
    Widget.(variant [|
        "sink", None ;
        "echo", None ;
        "random", Some (record [| "min size", size ; "max size", size ;
                                  "interval", Duration |]) |])

let behavior_param ~max_size =
    Widget.param "behavior" ~kind:(behavior_kind ~max_size)
        ~default:(`Assoc [ "sink", `Null ])
        ~descr:"What to do with the traffic: discard what comes in (sink), \
                send it back (echo), or send messages of sizes between min \
                size and max size bytes, at intervals of that mean in seconds \
                (random)."

let json_of_behavior = function
    | Sink -> `Assoc [ "sink", `Null ]
    | Echo -> `Assoc [ "echo", `Null ]
    | Random { min_size ; max_size ; interval } ->
        `Assoc [ "random", `Assoc [ "min size", `Int min_size ;
                                    "max size", `Int max_size ;
                                    "interval", `Float interval ] ]

(* Of a value already coerced to [behavior_kind], so of a known case and of
 * sizes within bounds. *)
let behavior_of_json =
    Widget.to_case (fun case v ->
        match case with
        | "sink" -> Sink
        | "echo" -> Echo
        | _ ->
            let min_size = Widget.to_field "min size" Widget.to_int v
            and max_size = Widget.to_field "max size" Widget.to_int v
            and interval = Widget.to_field "interval" Widget.to_float v in
            if max_size < min_size then
                Widget.bad_value "max size must not be below min size (%d), \
                                  not %d" min_size max_size ;
            if interval <= 0. then
                Widget.bad_value "interval must be above zero, not %g" interval ;
            Random { min_size ; max_size ; interval })

let port_arg params name =
    let p = Widget.arg_int params name in
    if p < 1 || p > 0xffff then
        Widget.bad_value "%s must be between 1 and 65535, not %d" name p ;
    p

(* What a UDP datagram can carry: *)
let max_udp_payload = 65507

(* Bytes, both ways, of a whole server or client: *)
type traffic = { mutable sent : int ; mutable received : int }

(* One conversation, whichever the protocol: *)
type flow =
    { send : bitstring -> unit ;
      (* Whether [send] may be called now: not before a TCP connection is
         established, nor once it is closed. *)
      writable : unit -> bool ;
      (* Whether it is over for good: *)
      finished : unit -> bool ;
      close : unit -> unit }

(* [closed] is called when the peer closes the connection. *)
let tcp_flow (cnx : Tcp.TRX.tcp_trx) ~recv ~closed =
    cnx.trx.ins.set_read (fun bits ->
        if bitstring_length bits = 0 then closed () else recv bits) ;
    let writable () = cnx.is_established () && not (cnx.is_closed ()) in
    { send = tx cnx.trx ; writable ; finished = cnx.is_closed ;
      close = (fun () -> if writable () then cnx.close ()) }

let udp_flow (udp : Udp.TRX.udp_trx) =
    { send = tx udp.trx ; writable = (fun () -> true) ;
      finished = (fun () -> false) ; close = ignore }

let random_payload n =
    bitstring_of_string (String.init n (fun _ -> Char.chr (Random.int 256)))

(* Have [flow] behave as told, for as long as it lasts and [alive] says, and
   return what is to receive from it. [counted] is called after every message, sent or
   received. *)
let talk power traffic behavior ~alive ~counted flow =
    let send bits =
        traffic.sent <- traffic.sent + bytelength bits ;
        flow.send bits in
    (match behavior with
    | Random { min_size ; max_size ; interval } ->
        let wait () =
            Clock.Interval.sec (-. interval *. log (1. -. Random.float 1.)) in
        let going () = alive () && not (flow.finished ()) in
        let rec loop () =
            if going () then (
                if flow.writable () then (
                    send (random_payload
                        (min_size + Random.int (max_size - min_size + 1))) ;
                    counted ()) ;
                if going () then Simulation.delay power (wait ()) loop ()) in
        Simulation.delay power (wait ()) loop ()
    | Sink | Echo -> ()) ;
    fun bits ->
        if alive () then (
            traffic.received <- traffic.received + bytelength bits ;
            (match behavior with
            | Echo when flow.writable () -> send bits
            | _ -> ()) ;
            counted ())

let traffic_properties traffic = Widget.[
    property "sent" ~kind:Int ~units:"bytes" ~descr:"Bytes sent so far."
        ~getter:(fun () -> `Int traffic.sent) ;
    property "received" ~kind:Int ~units:"bytes"
        ~descr:"Bytes received so far."
        ~getter:(fun () -> `Int traffic.received) ]

(* Whether [state] is still running; and if it was cancelled, have what it
   holds given up, from outside of whatever callback noticed. *)
let still_running power over state release =
    let running = Action.is_running state in
    if not running && not !over then
        Simulation.asap power (fun () -> release ~remove:true) () ;
    running && not !over

(* [peers] names what is counted of the flows it accepts. [listen] and
   [unlisten] are the host's server start and stop, and [serve] makes a flow of
   what [listen] hands over. *)
let server_action t ~proto ~peers ~max_size ~listen ~unlisten ~serve =
    let host = t.trx.widget in
    let result_kind =
        Widget.(record [| peers, Int ; "sent", Int ; "received", Int |]) in
    Widget.action ("start "^ String.uppercase_ascii proto ^" server")
        ~descr:"Listen to a port, and answer whoever connects to it as told."
        ~params:Widget.[ param "port" ~kind:Int ~descr:"The port to listen to." ;
                         behavior_param ~max_size ]
        ~result:result_kind
        ~handler:(fun state ->
            let port = port_arg state.params "port"
            and behavior = behavior_of_json (Widget.arg state.params "behavior") in
            let power = host.power in
            let traffic = { sent = 0 ; received = 0 }
            and flows = ref 0 and over = ref false in
            let result () =
                `Assoc [ peers, `Int !flows ;
                         "sent", `Int traffic.sent ;
                         "received", `Int traffic.received ] in
            let widget =
                Widget.make ~parent:host (Printf.sprintf "server-%s:%d" proto port) in
            (* Whoever stops it first, once. [remove] is false when the widget
               is already being removed. *)
            let release ~remove =
                if not !over then (
                    over := true ;
                    unlisten port ;
                    if Action.is_running state then
                        Action.stop state ~result:(result ()) ;
                    if remove then Simulation.remove_widget widget) in
            let alive () = still_running power over state release in
            (match
                listen port (fun x ->
                    if alive () then (
                        incr flows ;
                        let recv = ref ignore in
                        let flow = serve x ~recv:(fun bits -> !recv bits) in
                        recv := talk power traffic behavior ~alive
                                     ~counted:ignore flow))
            with
            | exception e ->
                Simulation.remove_widget widget ;
                raise e
            | () -> ()) ;
            widget.on_delete <- (fun () -> release ~remove:false) ;
            widget.power_down <- (fun () -> release ~remove:true) ;
            Widget.add_properties widget Widget.(
                property "behavior" ~descr:"What it does with the traffic."
                    ~kind:(behavior_kind ~max_size)
                    ~getter:(fun () -> json_of_behavior behavior) ::
                property peers ~kind:Int ~descr:"How many it was reached by."
                    ~getter:(fun () -> `Int !flows) ::
                traffic_properties traffic) ;
            Widget.add_actions widget [
                Widget.action "stop" ~result:result_kind
                    ~descr:"Stop listening, closing what connections it has."
                    ~handler:(fun s ->
                        Action.stop s ~result:(result ()) ;
                        release ~remove:true) ])

let tcp_server_action t =
    server_action t ~proto:"tcp" ~peers:"connections" ~max_size:max_int
        ~listen:(fun p -> tcp_server_start t (Tcp.Port.o p))
        ~unlisten:(fun p -> tcp_server_stop t (Tcp.Port.o p))
        ~serve:(fun cnx ~recv ->
            (* The peer closing is answered by Tcp itself: *)
            tcp_flow cnx ~recv ~closed:ignore)

let udp_server_action t =
    server_action t ~proto:"udp" ~peers:"peers" ~max_size:max_udp_payload
        ~listen:(fun p -> udp_server_start t (Udp.Port.o p))
        ~unlisten:(fun p -> udp_server_stop t (Udp.Port.o p))
        ~serve:(fun udp ~recv ->
            udp.Udp.TRX.trx.ins.set_read recv ;
            udp_flow udp)

(* [connect dst ~src_port port ~recv ~closed cont] opens a flow and hands it
   to [cont], or [None] if it cannot. *)
let client_action t ~proto ~max_size ~connect =
    let host = t.trx.widget in
    let result_kind =
        Widget.(record [| "sent", Int ; "received", Int ;
                          "duration", Duration |]) in
    Widget.action ("start "^ String.uppercase_ascii proto ^" client")
        ~descr:"Connect to a server and talk to it as told, until one of the \
                limits is reached, the server closes the connection, or it \
                is stopped."
        ~params:Widget.[
            param "target" ~kind:(hint "192.168.0.1" String)
                ~descr:"What to connect to: an address, or a name to be resolved." ;
            param "port" ~kind:Int ~descr:"The port to connect to." ;
            param "source port" ~kind:(optional Int)
                ~descr:"The port to connect from, which then also names it \
                        (random if unset)." ;
            behavior_param ~max_size ;
            param "duration" ~kind:(optional Duration) ~units:"secs"
                ~descr:"Stop after that long." ;
            param "volume" ~kind:(optional Int) ~units:"bytes"
                ~descr:"Stop once that many bytes were sent and received." ]
        ~result:result_kind
        ~handler:(fun state ->
            let params = state.params in
            let target = Widget.arg_string params "target"
            and port = port_arg params "port"
            and src_port =
                Widget.arg_opt params "source port" (fun v ->
                    port_arg [ "source port", v ] "source port")
            and behavior = behavior_of_json (Widget.arg params "behavior")
            and duration = Widget.arg_opt params "duration" Widget.to_float
            and volume = Widget.arg_opt params "volume" Widget.to_int in
            Option.may (fun d ->
                if d <= 0. then
                    Widget.bad_value "duration must be above zero, not %g" d
            ) duration ;
            if not host.power.on then
                Widget.bad_value "%s is off" (Widget.full_name host) ;
            let power = host.power and sim = Widget.sim host in
            let started = Simulation.now sim in
            let traffic = { sent = 0 ; received = 0 }
            and flow = ref None and over = ref false in
            let result () =
                `Assoc [ "sent", `Int traffic.sent ;
                         "received", `Int traffic.received ;
                         "duration", `Float (Clock.Interval.to_secs
                            (Clock.Time.diff (Simulation.now sim) started)) ] in
            let name =
                match src_port with
                | Some p -> Printf.sprintf "client-%s:%d" proto p
                | None -> Printf.sprintf "client-%s:%s:%d" proto target port in
            let widget = Widget.make ~parent:host name in
            (* Whoever stops it first, once. [remove] is false when the widget
               is already being removed. *)
            let release ~remove =
                if not !over then (
                    over := true ;
                    Option.may (fun f -> f.close ()) !flow ;
                    if remove then Simulation.remove_widget widget) in
            let finish ~remove =
                if Action.is_running state then
                    Action.stop state ~result:(result ()) ;
                release ~remove in
            let alive () = still_running power over state release in
            let counted () =
                match volume with
                | Some v when traffic.sent + traffic.received >= v ->
                    finish ~remove:true
                | _ -> () in
            widget.on_delete <- (fun () -> finish ~remove:false) ;
            widget.power_down <- (fun () -> release ~remove:true) ;
            Widget.add_properties widget Widget.(
                property "behavior" ~descr:"What it does with the traffic."
                    ~kind:(behavior_kind ~max_size)
                    ~getter:(fun () -> json_of_behavior behavior) ::
                traffic_properties traffic) ;
            Widget.add_actions widget [
                Widget.action "stop" ~result:result_kind
                    ~descr:"Stop talking, closing the connection."
                    ~handler:(fun s ->
                        Action.stop s ~result:(result ()) ;
                        finish ~remove:true) ] ;
            Option.may (fun d ->
                Simulation.delay power (Clock.Interval.sec d)
                    (fun () -> if not !over then finish ~remove:true) ()
            ) duration ;
            let recv = ref ignore in
            connect (addr_of_string target) ~src_port port
                    ~recv:(fun bits -> !recv bits)
                    ~closed:(fun () -> finish ~remove:true) (function
                | None ->
                    if not !over then (
                        Action.fail state "cannot connect to %s:%d" target port ;
                        release ~remove:true)
                | Some f ->
                    if !over then f.close () else (
                        flow := Some f ;
                        recv := talk power traffic behavior ~alive ~counted f)))

let tcp_client_action t =
    client_action t ~proto:"tcp" ~max_size:max_int
        ~connect:(fun dst ~src_port port ~recv ~closed cont ->
            let src_port = Option.map Tcp.Port.o src_port in
            t.trx.tcp_connect dst ?src_port (Tcp.Port.o port) (function
                | None -> cont None
                | Some cnx -> cont (Some (tcp_flow cnx ~recv ~closed))))

let udp_client_action t =
    client_action t ~proto:"udp" ~max_size:max_udp_payload
        ~connect:(fun dst ~src_port port ~recv ~closed:_ cont ->
            let src_port = Option.map Udp.Port.o src_port in
            t.trx.udp_connect dst ?src_port (Udp.Port.o port)
                (fun _ bits -> recv bits) (function
                | None -> cont None
                | Some udp -> cont (Some (udp_flow udp))))

let make ?gateways ?search_sfx ?nameserver ?mac ?(on=true) ?static_ip ?netmask
         ~parent ?(own_power=true) ?location name =
    (* A host can take its power source from some larger equipment, and
       mints one of its own when it is a machine in its own right. *)
    let widget =
        Widget.make ~parent ?location ~device_type:"host" ~own_power ~on name in
    let eth_state =
        (* FIXME: Don't use the GW for same net IP! *)
        Eth.State.make ?mac ?gateways ~parent:widget () in
    let eth_trx = Eth.TRX.make eth_state in
    let t = make_from_eth ?search_sfx ?nameserver ~widget ?static_ip
                          ?netmask eth_state eth_trx name in
    (* This host minted the supply above, so the switch for it goes here, and
       so does stopping it for good. And it is a whole machine, unlike a host
       built on somebody else's adapter. *)
    widget.device <- Some (T t) ;
    Widget.add_properties widget Widget.[
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
    (* TODO: properties for TCP initial_rto, min_rto_var, max_rto and max_timeouts *)
    Widget.add_actions widget
        [ ping_action t ;
          tcp_server_action t ; udp_server_action t ;
          tcp_client_action t ; udp_client_action t ] ;
    (* It does not run yet: its supply is its own and was minted switched off,
       and what switches it on is the power-on that building it put in the
       startup list -- run when the simulation starts running, by which time
       the network is whole. A host built as a part of something larger has
       neither, and leaves both to the box whose supply it shares. *)
    t

(* A host boots into the configuration it has at that moment, and not the one
   it was built with: what the reader changed between two boots is the whole
   point of keeping the configuration on the host rather than in the closure
   that applies it. *)
(*$R make
    let sim = Simulation.make ~realtime:false "test-reboot" in
    let netmask = Ip.Addr.of_string "255.255.255.0" in
    let h =
        make ~parent:sim.root ~netmask
             ~static_ip:(Ip.Addr.of_string "192.168.1.10") "h" in
    (* Born dark, as every box is: what switches it on is its power-on in the
       startup list, which a test that is not going through [run] runs for
       itself. *)
    Simulation.run_startup sim ;
    let prop name =
        List.find (fun (p : Widget.property) -> p.name = name)
                  h.trx.widget.properties in
    let set name v = (Option.get (prop name).setter) v in
    (* Through its supply, which a host of its own mints and owns: there is no
       switch on the widget any more. *)
    let reboot () =
        Simulation.power_down h.trx.widget.power ;
        Simulation.power_up h.trx.widget.power in
    let address () =
        match Eth.State.find_ip4 h.eth_state with
        | exception Not_found -> "none"
        | ip -> Ip.Addr.to_dotted_string ip in
    assert_equal ~printer:identity "192.168.1.10" (address ()) ;
    Simulation.power_down h.trx.widget.power ;
    (* Its address goes with its power: an address it kept while off would be
       one it had never been granted when it came back. *)
    assert_equal ~printer:identity "none" (address ()) ;
    Simulation.power_up h.trx.widget.power ;
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

(* Servers and clients, asked as the API asks: each under a widget of its own
   while it runs, and its run ending with what it exchanged, however it
   stops. *)
(*$R make
    let sim = Simulation.make ~realtime:false "traffic" in
    let ip n = Ip.Addr.of_string ("192.168.0." ^ string_of_int n) in
    let host n =
        make ~parent:sim.root ~static_ip:(ip n)
             ~netmask:(Ip.Addr.of_string "255.255.255.0")
             ("h" ^ string_of_int n) in
    let a = host 1 and b = host 2 in
    let st = Eth.Cable.State.make ~parent:sim.root ~name:"c" () in
    Eth.Cable.plug st (a.trx.widget, 0) (b.trx.widget, 0) ;
    Simulation.run_startup sim ;
    let run (w : Widget.t) name params =
        Action.start w (Option.get (Action.find w name)) params in
    let child (h : t) name =
        List.find_opt (fun (w : Widget.t) -> w.name = name)
                      h.trx.widget.children in
    let get (s : Action.state) field =
        match s.ended with
        | Some (_, Value (Some (`Assoc l))) -> List.assoc field l
        | _ -> `Null in
    let int s field = match get s field with `Int i -> i | _ -> -1 in
    let prop (w : Widget.t) name =
        (List.find (fun (p : Widget.property) -> p.name = name)
                   w.properties).getter () in
    let target = "target", `String "192.168.0.2" in
    let random ?(max_size=1000) interval =
        "behavior", `Assoc [ "random", `Assoc [ "min size", `Int 1 ;
                                                "max size", `Int max_size ;
                                                "interval", `Float interval ] ] in
    let refused w action params =
        try ignore (run w action params) ; false
        with Widget.Bad_value _ -> true in

    (* Random against echo, until a volume is reached: *)
    let version = sim.tree_version in
    let srv = run b.trx.widget "start TCP server"
                  [ "port", `Int 7 ; "behavior", `Assoc [ "echo", `Null ] ] in
    let srv_w = Option.get (child b "server-tcp:7") in
    assert_bool "a new server reshapes the tree" (sim.tree_version > version) ;
    assert_equal ~printer:Yojson.Basic.to_string ~msg:"says what it does"
        (`Assoc [ "echo", `Null ]) (prop srv_w "behavior") ;
    assert_bool "one server per port"
        (refused b.trx.widget "start TCP server" [ "port", `Int 7 ]) ;
    assert_bool "and the refused one leaves no widget behind"
        (child b "server-tcp:7-2" = None) ;
    let bad behavior =
        refused b.trx.widget "start UDP server"
                [ "port", `Int 8 ; "behavior", behavior ] in
    assert_bool "a sink carries nothing"
        (bad (`Assoc [ "sink", `Int 1 ])) ;
    assert_bool "random needs its sizes and interval"
        (bad (`Assoc [ "random", `Null ])) ;
    assert_bool "no larger than a datagram" (bad (snd (random ~max_size:70_000 1.))) ;
    assert_bool "nor reversed"
        (bad (`Assoc [ "random", `Assoc [ "min size", `Int 9 ;
                                          "max size", `Int 8 ;
                                          "interval", `Float 1. ] ])) ;
    assert_bool "nor without delay" (bad (snd (random 0.))) ;
    assert_bool "and none of those leaves a widget behind"
        (child b "server-udp:8" = None) ;
    let cli = run a.trx.widget "start TCP client"
                  [ target ; "port", `Int 7 ; random 0.01 ;
                    "volume", `Int 100_000 ] in
    assert_bool "a client is named after its target"
        (child a "client-tcp:192.168.0.2:7" <> None) ;
    let version = sim.tree_version in
    Simulation.run sim false ;
    assert_bool "the volume ends the client" (not (Action.is_running cli)) ;
    assert_bool "and so does a client going" (sim.tree_version > version) ;
    assert_bool "which is then gone" (child a "client-tcp:192.168.0.2:7" = None) ;
    let sent = int cli "sent" and received = int cli "received" in
    assert_bool "up to that volume" (sent + received >= 100_000) ;
    assert_bool "and echoed" (received > 0) ;
    assert_equal ~printer:Yojson.Basic.to_string ~msg:"all of it reached the server"
        (`Int sent) (prop srv_w "received") ;
    let stop = run srv_w "stop" [] in
    assert_equal ~printer:string_of_int 1 (int stop "connections") ;
    assert_bool "stopping the server ends its run" (not (Action.is_running srv)) ;
    assert_equal ~printer:string_of_int sent (int srv "received") ;
    assert_bool "and takes its widget" (child b "server-tcp:7" = None) ;

    (* Random against a sink, for a duration, from a given port: *)
    let srv = run b.trx.widget "start UDP server" [ "port", `Int 9 ] in
    let cli = run a.trx.widget "start UDP client"
                  [ target ; "port", `Int 9 ; "source port", `Int 6000 ;
                    random 0.1 ; "duration", `Float 5. ] in
    assert_bool "a client given a port is named after it"
        (child a "client-udp:6000" <> None) ;
    Simulation.run sim false ;
    assert_bool "the duration ends the client" (not (Action.is_running cli)) ;
    assert_equal ~printer:Yojson.Basic.to_string (`Float 5.) (get cli "duration") ;
    assert_equal ~printer:string_of_int 0 (int cli "received") ;
    assert_bool "having sent" (int cli "sent" > 0) ;
    (* Deleting a server is stopping it: *)
    Simulation.remove_widget (Option.get (child b "server-udp:9")) ;
    assert_equal ~printer:string_of_int (int cli "sent") (int srv "received") ;

    (* A random server pushing to a sink, until the client is cancelled: *)
    let srv = run b.trx.widget "start TCP server"
                  [ "port", `Int 7 ; random 0.1 ] in
    let cli = run a.trx.widget "start TCP client"
                  [ target ; "port", `Int 7 ; "source port", `Int 1234 ] in
    Simulation.delay sim.root.power (Clock.Interval.sec 3.)
        (fun () -> Action.cancel cli) () ;
    Simulation.run sim false ;
    assert_bool "a cancelled client is gone" (child a "client-tcp:1234" = None) ;
    assert_bool "the server is still there" (Action.is_running srv) ;
    assert_bool "having sent something"
        (prop (Option.get (child b "server-tcp:7")) "sent" <> `Int 0) ;

    (* And everything goes with the power: *)
    Simulation.power_down b.trx.widget.power ;
    assert_bool "a server goes with the power" (child b "server-tcp:7" = None) ;
    assert_bool "and its run" (not (Action.is_running srv)) ;
    Simulation.power_up b.trx.widget.power ;
    ignore (run b.trx.widget "start TCP server" [ "port", `Int 7 ]) ;
    assert_bool "leaving its port free" (child b "server-tcp:7" <> None)
 *)

module Name = struct
    let random () =
        randstr ~charset:"abcdefghijklmnopqrstuvwxyz" (5 + (Random.int 25))
end
