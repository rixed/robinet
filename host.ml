(* vim:sw=4 ts=4 sts=4 expandtab
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
(*
  Hosts are merely simple IP stacks with a eth device at the bottom and a name.
  These makes the link between programs and links.

  Hosts are also TRX: you tx to them higher level commands in a special host protocol, and read back
  the result.
*)
open Batteries
open Bitstring
open Tools

type addr = IPv4 of Ip.addr | Name of string

type host_trx = {
    name          : string ;
    logger        : Log.logger ;
    tcp_connect   : addr -> ?src_port:int -> int -> Tcp.TRX.tcp_trx Lwt.t ;
    udp_connect   : addr -> ?src_port:int -> int -> (Tools.trx -> Tools.payload -> unit) -> trx Lwt.t ;
    gethostbyname : string -> Ip.addr list Lwt.t ;
    tcp_server    : int -> (Tcp.TRX.tcp_trx -> unit) -> unit ;
    udp_server    : int -> (trx -> unit ) -> unit ;
    signal_err    : string -> unit ;
    set_emit      : (payload -> unit) -> unit ;
    rx            : payload -> unit }

type socks = { ip : trx ;
               (* Available sockets per IP dest.
                  The user of TCP does not remove these entries, so the TRX is still there
                  for some time. We should probably "garbage collect" them once in a while,
                  if they are closed for long enough.
                  The user of UDP does not remove them neither, and we probably should have
                  a "close" for UDP (since once closed all incoming packets must be rejected,
                  contrary to TCP where we still want to handle incoming FIN).
                  *)
               tcps : (Tcp.port * Tcp.port (* local, remote *), Tcp.TRX.tcp_trx) Hashtbl.t ;
               udps : (Udp.port * Udp.port (* local, remote *), trx) Hashtbl.t }

type t = { mutable host_trx : host_trx ;
           mutable my_ip : Ip.addr ;
           eth : Eth.TRX.eth_trx ;
           socks : (Ip.addr, socks) Hashtbl.t ;
           (* the listening servers *)
           tcp_servers : (Tcp.port, (Tcp.TRX.tcp_trx -> unit)) Hashtbl.t ;
           udp_servers : (Udp.port, (trx -> unit)) Hashtbl.t ;
           (* the resolver *)
           search_sfx : string option ;
           nameserver : Ip.addr option ;
           mutable resolv_trx : trx option ;
           dns_queries : (string, (Ip.addr list Lwt.u * Clock.time option)) Hashtbl.t ;
           dns_cache   : (string, Ip.addr list) Hashtbl.t }

exception No_socket

let signal_err t str =
    (* later, change this into a nice log *)
    Printf.fprintf stderr "Host %s: %s\n%!" t.host_trx.name str

let make_socks ip = { ip = ip ; 
                      tcps = Hashtbl.create 3 ;
                      udps = Hashtbl.create 3 }

(* Forward the payload to the socket function or to the server function *)
let sock_rx t proto socks bits =
    if proto = Ip.proto_tcp then (match Tcp.Pdu.unpack bits with
        | None -> ()
        | Some tcp ->
            let key = tcp.Tcp.Pdu.dst_port, tcp.Tcp.Pdu.src_port in
            try
                let trx =
                    hash_find_or_insert socks.tcps key (fun () ->
                        if tcp.Tcp.Pdu.syn then (
                            let server = try Hashtbl.find t.tcp_servers tcp.Tcp.Pdu.dst_port
                                         with Not_found -> raise No_socket in
                            let trx = Tcp.TRX.accept tcp.Tcp.Pdu.dst_port tcp.Tcp.Pdu.src_port in
                            trx.Tcp.TRX.trx.Tools.set_emit socks.ip.tx ;
                            server trx ; (* supposed to set the recver of this tcp trx *)
                            trx
                        ) else raise No_socket) in
                trx.Tcp.TRX.trx.Tools.rx bits (* will reorder fragments and transmit the messages up to its emit function *)
            with No_socket ->
                Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "No socket for TCP packet on port %d" tcp.Tcp.Pdu.dst_port))) ;
                Tcp.Pdu.make_reset_of tcp |> Tcp.Pdu.pack |> socks.ip.tx
    ) else if proto = Ip.proto_udp then (match Udp.Pdu.unpack bits with
        | None -> ()
        | Some udp ->
            let key = udp.Udp.Pdu.dst_port, udp.Udp.Pdu.src_port in
            try
                let trx =
                    hash_find_or_insert socks.udps key (fun () ->
                        let server = try Hashtbl.find t.udp_servers udp.Udp.Pdu.dst_port
                                     with Not_found -> raise No_socket in
                        let trx = Udp.TRX.make ~dst:udp.Udp.Pdu.src_port udp.Udp.Pdu.dst_port in
                        trx.Tools.set_emit socks.ip.tx ;
                        server trx ; (* supposed to set the recver of this udp trx *)
                        trx) in
                trx.Tools.rx bits
            with No_socket ->
                Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "No socket for UDP packet on port %d" udp.Udp.Pdu.dst_port))) ;
                (* TODO: send ICMP error *)
    ) else signal_err t "Sock is neither TCP nor UDP"

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
    | IPv4 ip  -> Ip.string_of_addr ip
    | Name str -> str

let tcp_cnxs_ok  = Metric.Atomic.make "Host/Tcp/Connect/Ok"
let tcp_cnxs_err = Metric.Atomic.make "Host/Tcp/Connect/Err"
let udp_cnxs_ok  = Metric.Atomic.make "Host/Udp/Connect/Ok"
let udp_cnxs_err = Metric.Atomic.make "Host/Udp/Connect/Err"
let resolution_timeouts  = Metric.Atomic.make "Host/Resolver/Timeouts"
let resolution_cachehits = Metric.Atomic.make "Host/Resolver/CacheHits"
let resolutions = Metric.Timed.make "Host/Resolver/Queries"

let rec resolver t =
    let dns_recv _trx bits = (match Dns.Pdu.unpack bits with
        | None -> ()
        | Some pdu ->
            Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Received DNS %s, opcode %d" (if pdu.Dns.Pdu.is_query then "query" else "response") pdu.Dns.Pdu.opcode))) ;
            if not pdu.Dns.Pdu.is_query &&
               pdu.Dns.Pdu.opcode = Dns.std_query (* status? *) &&
               List.length pdu.Dns.Pdu.questions = 1
            then (
                let name, qtype, qclass = List.hd pdu.Dns.Pdu.questions in
                if qtype = Dns.qtype_a && qclass = Dns.qclass_inet then (
                    (* TODO: usr the A and CNAME results to feed the cache? *)
                    let ips =
                        List.filter_map (fun (_name, qtype, qclass, _ttl, data) ->
                            if qclass = Dns.qclass_inet && qtype = Dns.qtype_a then
                                Some (Ip.addr_of_bitstring (bitstring_of_string data))
                            else None
                        ) pdu.Dns.Pdu.answer_rrs in
                    let waiters = Hashtbl.find_all t.dns_queries name in
                    Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Awakening %d clients that were waiting for the address of '%s'" (List.length waiters) name))) ;
                    List.iter (fun (waiter, start_opt) ->
                        Option.may (fun start -> Metric.Timed.stop resolutions start name) start_opt ;
                        Lwt.wakeup waiter ips) waiters ;
                    Hashtbl.remove_all t.dns_queries name ;
                    (* cache the result *)
                    if Hashtbl.length t.dns_cache > 10 then Hashtbl.clear t.dns_cache ; (* FIXME *)
                    Hashtbl.add t.dns_cache name ips
                )
            ) (* Else the waiters will eventually be timeouted *)
        )
    in
    match t.resolv_trx, t.nameserver with
    | Some trx, _    -> Lwt.return trx
    | None, None     -> Lwt.fail CannotResolveName
    | None, Some srv ->
        lwt resolv_trx = udp_connect t (IPv4 srv) 53 ~src_port:53 dns_recv in
        t.resolv_trx <- Some resolv_trx ;
        Lwt.return resolv_trx

and gethostbyname t name =
    let dns_timeout_delay = Clock.sec 3. in
    let is_fqdn n = n.[String.length n - 1] = '.' in
    let is_complete n = is_fqdn n || String.exists n "." in
    let name = match t.search_sfx with
    | Some sfx ->
        (* send the query using host IPv4 stack, with as recv a decoding function *)
        if is_complete name then name else name ^ "." ^ sfx
    | None -> name in
    let name = if is_fqdn name then name else name ^ "." in
    let dns_timeout () = (* use the name redefined above *)
        let waiters = Hashtbl.find_all t.dns_queries name in
        let nb_waiters = List.length waiters in
        if nb_waiters > 0 then (
            Log.(log t.host_trx.logger Warning (lazy (Printf.sprintf "Timeouting %d clients that were waiting for the address of '%s'" (List.length waiters) name))) ;
            Metric.Atomic.fire resolution_timeouts ;
            List.iter (fun (waiter, start_opt) ->
                Option.may (fun start -> Metric.Timed.stop resolutions start name) start_opt ;
                Lwt.wakeup_exn waiter DnsTimeout) waiters ;
            Hashtbl.remove_all t.dns_queries name
        ) in
    match Hashtbl.find_option t.dns_cache name with
        | Some ips ->
            Metric.Atomic.fire resolution_cachehits ;
            Lwt.return ips
        | None ->
            let waiter, wakener = Lwt.wait () in
            lwt resolv_trx = resolver t in
            let pending = Hashtbl.mem t.dns_queries name in
            Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Add a query for resolution of '%s' (%s)" name (if pending then "one was already pending" else "first one")))) ;
            if not pending then (
                (* add a timeout event that will awake all waiters for this name after some time *)
                Clock.delay dns_timeout_delay dns_timeout () ;
                (* Then actually sends the query *)
                let start = Metric.Timed.start resolutions in
                Hashtbl.add t.dns_queries name (wakener, Some start) ;
                let pdu = Dns.Pdu.make_query name in
                resolv_trx.tx (Dns.Pdu.pack pdu)
            ) else (
                Hashtbl.add t.dns_queries name (wakener, None)
            ) ;
            waiter

and tcp_connect t dst ?src_port dst_port =
    let connect dst_ip =
        Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Connecting to %s" (Ip.string_of_addr dst_ip)))) ;
        let socks = hash_find_or_insert t.socks dst_ip (fun () ->
            let trx = Ip.TRX.make t.my_ip dst_ip Ip.proto_tcp in
            let socks = make_socks trx in
            trx.Tools.set_emit t.eth.Eth.TRX.trx.tx ;
            trx.set_recv (sock_rx t Ip.proto_tcp socks) ;
            socks) in
        lwt src_port = match src_port with
            | None ->
                let start = Random.int (0x10000 - 1024) + 1024 in
                let rec aux src_port =
                    if find_alive_tcp socks.tcps (src_port, dst_port) = None then (
                        Lwt.return src_port
                    ) else (
                        let next = src_port + 1 in
                        let next = if next < 0x10000 then next else 1024 in
                        ensure (next <> start) "Host: No more ports available?" ;
                        aux next
                    ) in
                aux start
            | Some src_port ->
                if None = find_alive_tcp socks.tcps (src_port, dst_port) then (
                    Lwt.return src_port
                ) else (
                    Metric.Atomic.fire tcp_cnxs_err ;
                    Lwt.fail AlreadyConnected
                ) in
        lwt trx_opt = Tcp.TRX.connect src_port dst_port in
        match trx_opt with
        | Some trx ->
            (* connect this tcp to the underlaying ip *)
            trx.Tcp.TRX.trx.Tools.set_emit socks.ip.tx ;
            Hashtbl.add socks.tcps (src_port, dst_port) trx ;
            Metric.Atomic.fire tcp_cnxs_ok ;
            Lwt.return trx
        | None ->
            Metric.Atomic.fire tcp_cnxs_err ;
            Lwt.fail (Failure "Cannot connect")
    in
    match dst with
        | IPv4 dst_ip ->
            connect dst_ip
        | Name name ->
            lwt dst_ips = gethostbyname t name in
            Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf2 "Got these IPs for '%s' : %a" name (List.print Ip.print_addr') dst_ips))) ;
            if dst_ips <> [] then
                connect (List.hd dst_ips)
            else
                Lwt.fail (Failure ("Cannot resolve "^name))

and udp_connect t dst ?src_port dst_port client_f =
    let connect dst_ip =
        let socks = hash_find_or_insert t.socks dst_ip (fun () ->
            let trx = Ip.TRX.make t.my_ip dst_ip Ip.proto_udp in
            let socks = make_socks trx in
            trx.Tools.set_emit t.eth.Eth.TRX.trx.tx ;
            trx.set_recv (sock_rx t Ip.proto_udp socks) ;
            socks) in
        let src_port = may_default src_port (fun () -> Random.int 0x10000) in
        let key = src_port, dst_port in
        if Hashtbl.mem socks.udps key then (
            Metric.Atomic.fire udp_cnxs_err ;
            Lwt.fail AlreadyConnected
        ) else
        let trx = Udp.TRX.make ~dst:dst_port src_port in
        (* connect this udp to the underlaying ip *)
        trx.Tools.set_emit socks.ip.tx ;
        trx.set_recv (client_f trx) ;
        Hashtbl.add socks.udps key trx ;
        Metric.Atomic.fire udp_cnxs_ok ;
        Lwt.return trx
    in
    match dst with
        | IPv4 dst_ip ->
            connect dst_ip
        | Name name ->
            lwt dst_ips = gethostbyname t name in
            connect (List.hd dst_ips)

let tcp_server t src_port server_f = Hashtbl.add t.tcp_servers src_port server_f
let udp_server t src_port server_f = Hashtbl.add t.udp_servers src_port server_f

(* the recv of the eth is responsible for handling the payload to the correct Ip.TRX *)
let ip_recv t bits = (match Ip.Pdu.unpack bits with
    | None -> ()
    | Some ip ->
        if ip.Ip.Pdu.proto <> Ip.proto_tcp &&
           ip.Ip.Pdu.proto <> Ip.proto_udp then
            signal_err t (Printf.sprintf "Cannot handle socket for proto %d" ip.Ip.Pdu.proto)
        else
            let sock =
                hash_find_or_insert t.socks ip.Ip.Pdu.src (fun () ->
                    let ip_trx = Ip.TRX.make t.my_ip ip.Ip.Pdu.src ip.Ip.Pdu.proto in
                    let socks = make_socks ip_trx in
                    ip_trx.set_recv (sock_rx t ip.Ip.Pdu.proto socks) ;
                    ip_trx.Tools.set_emit t.eth.Eth.TRX.trx.tx ;
                    socks) in
            sock.ip.Tools.rx bits (* will handle fragmentation then pass payload to its emit function *)
    )

let make name ?gw ?search_sfx ?nameserver my_mac =
    let rec t =
        { my_ip       = Ip.addr_zero ;
          eth         = Eth.TRX.make my_mac ?gw:gw Eth.proto_ip4 [] ; (* FIXME: ne pas utiliser le gw systématiquement. Il faudrait vraissemblablement des routes, avec un eth par route ip *)
          socks       = Hashtbl.create 11 ;
          tcp_servers = Hashtbl.create 11 ;
          udp_servers = Hashtbl.create 11 ;
          nameserver  = nameserver ;
          resolv_trx  = None ;
          search_sfx  = search_sfx ;
          dns_queries = Hashtbl.create 3 ;
          dns_cache   = Hashtbl.create 3 ;
          host_trx    = host_trx }
    and host_trx =
        { name          = name ;
          logger        = Log.make ("Host/" ^ name) 50 ;
          tcp_connect   = (fun addr ?src_port dst -> tcp_connect t addr ?src_port dst) ;
          udp_connect   = (fun dst ?src_port dst_port client_f -> udp_connect t dst ?src_port dst_port client_f) ;
          gethostbyname = (fun name -> gethostbyname t name) ;
          tcp_server    = (fun src_port server_f -> tcp_server t src_port server_f) ;
          udp_server    = (fun src_port server_f -> udp_server t src_port server_f) ;
          signal_err    = (fun str -> signal_err t str) ;
          set_emit      = (fun f -> t.eth.Eth.TRX.trx.Tools.set_emit f) ;
          rx            = (fun pld -> t.eth.Eth.TRX.trx.Tools.rx pld) } in
    Log.(log t.host_trx.logger Info (lazy (Printf.sprintf "New host '%s'" name))) ;
    t

let set_ip t ip =
    Log.(log t.host_trx.logger Info (lazy (Printf.sprintf "Setting my IP to %s" (Ip.string_of_addr ip)))) ;
    t.my_ip <- ip ;
    t.eth.Eth.TRX.set_addresses [ Ip.bitstring_of_addr t.my_ip ] ;
    t.eth.Eth.TRX.trx.set_recv (ip_recv t)

let make_static name ?gw ?search_sfx ?nameserver my_mac my_ip =
    let t = make name ?gw ?search_sfx ?nameserver my_mac in
    set_ip t my_ip ;
    t.host_trx

let make_dhcp name ?gw ?search_sfx ?nameserver my_mac =
    let t = make name ?gw ?search_sfx ?nameserver my_mac in
    (* Will receive all eth frames until we got an IP address *)
    let dhcp_client bits = (match Ip.Pdu.unpack bits with
        | None -> ()
        | Some ip ->
            if ip.Ip.Pdu.proto <> Ip.proto_udp then (
                Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Ignoring IP packet of proto %d while waiting for DHCP offer" ip.Ip.Pdu.proto)))
            ) else (match Udp.Pdu.unpack ip.Ip.Pdu.payload with
                | None -> ()
                | Some udp ->
                    if udp.Udp.Pdu.src_port <> 67 || udp.Udp.Pdu.dst_port <> 68 then (
                        Log.(log t.host_trx.logger Debug (lazy (Printf.sprintf "Ignoring UDP packet from %s:%d to %s:%d while waiting for DHCP offer"
                            (Ip.string_of_addr ip.Ip.Pdu.src) udp.Udp.Pdu.src_port
                            (Ip.string_of_addr ip.Ip.Pdu.dst) udp.Udp.Pdu.dst_port)))
                    ) else (match Dhcp.Pdu.unpack udp.Udp.Pdu.payload with
                        | None -> ()
                        | Some ({ Dhcp.Pdu.msg_type = Some op ; _ } as dhcp) when op = Dhcp.offer ->
                            Log.(log t.host_trx.logger Info (lazy (Printf.sprintf "Got DHCP OFFER from %s" (Ip.string_of_addr ip.Ip.Pdu.src)))) ;
                            (* TODO: check the Xid? *)
                            let pdu = Dhcp.Pdu.make_request ~mac:my_mac ~xid:dhcp.Dhcp.Pdu.xid ~name dhcp.Dhcp.Pdu.yiaddr dhcp.Dhcp.Pdu.server_id in
                            let pdu = Udp.Pdu.make ~src_port:68 ~dst_port:67 (Dhcp.Pdu.pack pdu) in
                            let pdu = Ip.Pdu.make Ip.proto_udp Ip.addr_zero Ip.addr_broadcast (Udp.Pdu.pack pdu) in
                            t.eth.Eth.TRX.trx.Tools.tx (Ip.Pdu.pack pdu)
                        | Some ({ Dhcp.Pdu.msg_type = Some op ; _ } as dhcp) when op = Dhcp.ack ->
                            Log.(log t.host_trx.logger Info (lazy (Printf.sprintf "Got DHCP ACK from %s" (Ip.string_of_addr ip.Ip.Pdu.src)))) ;
                            (* TODO: set other params than IP *)
                            set_ip t dhcp.Dhcp.Pdu.yiaddr
                        | Some _ ->
                            (* TODO: print it *)
                            t.host_trx.signal_err "Ignoring a DHCP message"))) in
    let rec send_discover () =
        if t.my_ip = Ip.addr_zero then (
            Log.(log t.host_trx.logger Info (lazy "Sending DHCP DISCOVER")) ;
            let pdu = Dhcp.Pdu.make_discover ~mac:my_mac ~name () in
            let pdu = Udp.Pdu.make ~src_port:68 ~dst_port:67 (Dhcp.Pdu.pack pdu) in
            let pdu = Ip.Pdu.make Ip.proto_udp Ip.addr_zero Ip.addr_broadcast (Udp.Pdu.pack pdu) in
            t.eth.Eth.TRX.trx.Tools.tx (Ip.Pdu.pack pdu) ;
            Clock.delay (Clock.sec (5.+.(Random.float 3.))) send_discover ()
        ) in
    t.eth.Eth.TRX.trx.set_recv dhcp_client ;
    (* The client should wait a random time between one and ten seconds to desynchronize
       the use of DHCP at startup - RFC 2131 *)
    Clock.delay (Clock.sec (1.+.(Random.float 9.))) send_discover () ;
    send_discover () ;
    t.host_trx

