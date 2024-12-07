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
  Equipment for routing/NATing traffic
 *)
open Batteries

open Bitstring
open Tools

(** The lowest port number used by the address translation *)
let min_port = 1024

(** How many bytes to consider when hashing the packet prefix for load-balancing *)
let lb_prefix_length = ref 5

(** Network Address Translation (N.A.T.) is the process of replacing on the fly non routable
 * addresses used within a LAN by a unique routable address, so that hosts from the LAN
 * can communicate with the outside world by sharing the only routable IP address.
 * A [Nat.t] is a two sided device, with an inside and an outside, and an affected Ip address,
 * that will translate outgoing source addresses with it's own and restore it in incoming
 * packets. To match these incoming packets with the outgoing one it must use the UDP or
 * TCP client port and an internal memory of currently forwarded connections. This memory
 * is of bounded size.
 * Note that any packet that reach it will be forwarded.
 * A Nat.t is a TRX at IP level (it expects Ip packets). *)
module Nat =
struct
    (**
    Behavior on incoming packets:
{v
    [Nat] <----------------------------- [Outside host]
              Src: outside_addr,
              Dst: nat_addr
            Ports: outside_port:nat_port
v}
    Lookup (outside_addr, outside_port, nat_port, proto) in in_cnxs_h.
    If the cnx is found then replace the nat_addr:nat_port by cnx.in_addr:cnx.in_port.
    If nothing is found, just ignore the packet (or forward it to the sink host
    without changing the dest port).

    Behavior on outgoing packets:
{v
    [Inside host] -----------------------------> [Nat]
                      Src: inside_addr,
                      Dst: outside_addr,
                    Ports: inside_port:outside_port
v}
    Lookup (inside_addr, inside_port, nat_port, proto) in out_cnxs_h.
    If the cnx is found then replace the inside_addr:inside_port by nat_addr:cnx.out_port.
    If nothing is found, create the cnx as:
    {[ { out_port=random_port; in_addr=inside_addr; in_port=inside_port } ]}
    and insert it with the above key in out_cnxs_h.
    Also, insert this cnx in in_cnxs_h with key (outside_addr, outside_port, random_port, proto).

    *)

    type socket = {       proto : Ip.Proto.t ;  (** the IP protocol *)
                       nat_port : int ;         (** the Nat ports *)
                    remote_addr : Ip.Addr.t ;   (** the other peer's address *)
                    remote_port : int }         (** the port used by the other peer *)

    type cnx = {  in_addr : Ip.Addr.t ;   (** the inside lan's host IP *)
                  in_port : int ;         (** the origin port used by this host *)
                 out_port : int }         (** the random port used by NAS in the outside *)

    (* TODO: add an optional sink inside IP *)
    type t = {      addr : Ip.Addr.t ;                  (** our IP addr *)
                    cnxs : cnx OrdArray.t ;             (** all the cnxs we remember *)
               in_cnxs_h : (socket, int) Hashtbl.t ;    (** the hash to retrieve cnxs of packets coming from the outside *)
              out_cnxs_h : (socket, int) Hashtbl.t ;    (** the hash to retrieve cnxs of packets coming from the inside *)
            mutable emit : bitstring -> unit ;          (** the emit function (ie. carry packets to the outside *)
            mutable recv : bitstring -> unit ;          (** the receive functon (ie. forward incoming packets from the outside *)
                  logger : Log.logger }

    let patch_src_port proto bits port =
        if proto = Ip.Proto.tcp then (
            let pdu = Option.get (Tcp.Pdu.unpack bits) in
            Tcp.Pdu.pack { pdu with Tcp.Pdu.src_port = Tcp.Port.o port }
        ) else if proto = Ip.Proto.udp then (
            let pdu = Option.get (Udp.Pdu.unpack bits) in
            Udp.Pdu.pack { pdu with Udp.Pdu.src_port = Udp.Port.o port }
        ) else should_not_happen ()

    let patch_dst_port proto bits port =
        if proto = Ip.Proto.tcp then (
            let pdu = Option.get (Tcp.Pdu.unpack bits) in
            Tcp.Pdu.pack { pdu with Tcp.Pdu.dst_port = Tcp.Port.o port }
        ) else if proto = Ip.Proto.udp then (
            let pdu = Option.get (Udp.Pdu.unpack bits) in
            Udp.Pdu.pack { pdu with Udp.Pdu.dst_port = Udp.Port.o port }
        ) else should_not_happen ()

    let do_nat t ip src_port dst_port =
        (* Do we already follow this socket? *)
        let out_sock = {       proto = ip.Ip.Pdu.proto ;
                            nat_port = dst_port ;
                         remote_addr = ip.Ip.Pdu.src ;
                         remote_port = src_port } in
        let n = hash_find_or_insert t.out_cnxs_h out_sock (fun () ->
            let random_port = min_port + Random.int (65536-min_port) in
            let last_idx = OrdArray.last t.cnxs in
            OrdArray.set t.cnxs last_idx
                {  in_addr = ip.Ip.Pdu.src ;
                   in_port = src_port ;
                  out_port = random_port } ;
            (* replace also entry in in_cnxs_h *)
            let in_sock = {       proto = ip.Ip.Pdu.proto ;
                               nat_port = random_port ;
                            remote_addr = ip.Ip.Pdu.dst ;
                            remote_port = dst_port } in
            Hashtbl.replace t.in_cnxs_h in_sock last_idx ;
            last_idx) in
        OrdArray.promote t.cnxs n ;
        (* perform source NAT *)
        let new_src_port = (OrdArray.get t.cnxs n).out_port in
        let payload = Payload.o (patch_src_port ip.Ip.Pdu.proto
                                                (ip.Ip.Pdu.payload :> bitstring)
                                                new_src_port) in
        let ip = { ip with Ip.Pdu.src = t.addr ; payload } in
        t.emit (Ip.Pdu.pack ip)

    (** bits are flowing from LAN to outside world *)
    let tx t bits =
        match Ip.Pdu.unpack_with_ports bits with
        | None ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Ignoring packet of %d bytes since it's not IP" (bytelength bits))))
        | Some (ip, src_port, dst_port) ->
            if Ip.Addr.is_natable ip.Ip.Pdu.src then (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Transmitting packet of %d bytes from %s:%d to %s:%d" (bytelength bits) (Ip.Addr.to_string ip.src) src_port (Ip.Addr.to_string ip.dst) dst_port))) ;
                do_nat t ip src_port dst_port
            ) else (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Ignoring packet from non NATable address %s" (Ip.Addr.to_string ip.src))))
            )

    let rx t bits =
        Log.(log t.logger Debug (lazy (Printf.sprintf "Received %d bytes" (bytelength bits)))) ;
        Ip.Pdu.unpack_with_ports bits |>
        Option.may (fun (ip, src_port, dst_port) ->
            let in_sock = {       proto = ip.Ip.Pdu.proto ;
                               nat_port = dst_port ;
                            remote_addr = ip.Ip.Pdu.src ;
                            remote_port = src_port } in
            Hashtbl.find_option t.in_cnxs_h in_sock |>
            Option.may (fun n ->
                let cnx = OrdArray.get t.cnxs n in
                let payload = Payload.o (patch_dst_port ip.Ip.Pdu.proto
                                                        (ip.Ip.Pdu.payload :> bitstring)
                                                        cnx.in_port) in
                let ip = { ip with Ip.Pdu.dst = cnx.in_addr ; payload } in
                t.recv (Ip.Pdu.pack ip)))

    (** [make ip n] returns a {!Tools.trx} corresponding to a NAT device (tx is for transmitting from the LAN to the outside) that can track [n] sockets. *)
    let make addr num_max_cnxs logger =
        Log.(log logger Debug (lazy (Printf.sprintf "Creating a NATer for IP %s, with %d cnxs max" (Ip.Addr.to_string addr) num_max_cnxs))) ;
        let t = { addr ;
                  cnxs = OrdArray.make num_max_cnxs { in_addr = Ip.Addr.zero ;
                                                      in_port = 0 ;
                                                      out_port = 0 } ;
                  in_cnxs_h = Hashtbl.create num_max_cnxs ;
                  out_cnxs_h = Hashtbl.create num_max_cnxs ;
                  emit = ignore_bits ;
                  recv = ignore_bits ;
                  logger } in
        { ins = { write = tx t ;
                  set_read = fun f -> t.recv <- f } ;
          out = { write = rx t ;
                  set_read = fun f -> t.emit <- f } }
end

(** A router is a device with N IP/Eth devices and a routing
 * table with rules on interface number, Ip addresses, proto, ports.
 * IP packets TTL is decremented and expired with optional support for ICMP
 * expiration error messages. *)
module Router =
struct
    (*$< Router *)

    (* If we had a generic port module, this would go there *)
    type port_range = int * int (** Inclusive port range *)

    let port_in_range p (min, max) = p >= min && p <= max

    (** A [route] is a set of optional tests and an output port and optional
     * gateway. *)
    type route = { (* Tests *)
                   iface_num : int option ;         (** Test on incoming iface *)
                    src_mask : Ip.Cidr.t option ;   (** Test on source IP *)
                    dst_mask : Ip.Cidr.t option ;   (** Test on dest IP *)
                    ip_proto : Ip.Proto.t option ;  (** Test on IP protocol *)
                    src_port : port_range option ;  (** Test on source IP port *)
                    dst_port : port_range option ;  (** Test on dest IP port *)
                   (* Output *)
                    out_port : int ;                (** Output port *)
                         via : Eth.gw_addr option } (** Optional gateway *)

    let make_route ?iface_num ?src_mask ?dst_mask ?ip_proto ?src_port ?dst_port
                   ?via out_port =
        { iface_num ; src_mask ; dst_mask ; ip_proto ; src_port ; dst_port ;
          out_port ; via }

    let print_route oc r =
        Printf.fprintf oc "in_port:%a, src_mask:%a, dst_mask:%a -> out_port:%d, via:%a"
            (Option.print Int.print) r.iface_num
            (Option.print Ip.Cidr.printf) r.src_mask
            (Option.print Ip.Cidr.printf) r.dst_mask
            r.out_port
            (Option.print Eth.gw_addr_print) r.via

    (** Test an incoming packet against a route. *)
    let test_route route ifn src_opt dst_opt proto_opt src_port_opt dst_port_opt =
        (* If the route test is set, then the value is required. *)
        let test_opt opt1 test opt2 =
            match opt2 with
            | Some opt -> Option.map_default (test opt) true opt1
            | None     -> Option.is_none opt1 in
        let cidr_mem_rev ip cidr = Ip.Cidr.mem cidr ip in
        test_opt route.iface_num (=) (Some ifn) &&
        test_opt route.src_mask cidr_mem_rev src_opt &&
        test_opt route.dst_mask cidr_mem_rev dst_opt &&
        test_opt route.ip_proto (=) proto_opt &&
        test_opt route.src_port port_in_range src_port_opt &&
        test_opt route.dst_port port_in_range dst_port_opt

    type port = {         trx : trx ;
                          mac : Eth.Addr.t ;
                           ip : Ip.Addr.t ;
                  rx_counters : counters ;
                  tx_counters : counters ;
                    connected : bool ref }

    (** A router is an array of ports and a route table *)
    type t = {         ports : port array ;
              mutable routes : route list ;
                      notify : notify ;
                      logger : Log.logger ;
              load_balancing : load_balancing }
    and load_balancing = NoLoadBalancing | Random | PrefixHash
    (* Probability to send ICMP expiry messages after TTL expiration, and after
     * which delay (TODO: should also depend on how busy the router is): *)
    and notify = { probability : float ; delay : float }

    (* Add a route (the added route becomes top priority *)
    let add_route t route =
        t.routes <- route :: t.routes

    let send_icmp_expiry t n ip delay =
        let icmp = Icmp.Pdu.make_ttl_expired_in_transit ip in
        let ip_pld = Icmp.Pdu.pack icmp in
        let ip_pkt = Ip.Pdu.make Ip.Proto.icmp t.ports.(n).ip ip.Ip.Pdu.src ip_pld in
        let bits = Ip.Pdu.pack ip_pkt in
        Clock.delay (Clock.Interval.o delay) (tx t.ports.(n).trx) bits

    (* The [route] function receives the IP packets from the Eth trx.
     * The integer [in_port] is the input interface number. *)
    let route in_port t bits =
        Log.(log t.logger Debug (lazy (Printf.sprintf "rx from port %d" in_port))) ;
        let ip_opt, src_opt, dst_opt, ttl_opt, proto_opt =
            match Ip.Pdu.unpack bits with
            | None ->
                None, None, None, None, None
            | Some ip ->
                Some ip, Some ip.Ip.Pdu.src, Some ip.dst, Some ip.ttl, Some ip.proto in
        let src_port_opt, dst_port_opt =
            match Option.bind ip_opt Ip.Pdu.get_ports with
            | Some (src_port, dst_port) -> Some src_port, Some dst_port
            | None -> None, None in
        match List.find_all (fun r ->
                test_route r in_port src_opt dst_opt proto_opt src_port_opt dst_port_opt
              ) t.routes with
        | [] ->
            Log.(log t.logger Debug (lazy "dropping packet since no route match"))
        | out_ports ->
            (* Forward the packet to port [r]: *)
            let forward r =
                let forward bits =
                    let trx = t.ports.(r.out_port).trx in
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Forwarding packet to port %d" r.out_port))) ;
                    tx trx bits ;
                    Log.(log t.logger Debug (lazy "Done")) in
                match ttl_opt with
                | Some (0 | 1) ->
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Expiring packet from %d" in_port))) ;
                    if Random.float 1. > t.notify.probability then (
                        let delay = jitter 0.1 t.notify.delay in
                        let ip = Option.get ip_opt in
                        send_icmp_expiry t in_port ip delay)
                | Some ttl ->
                    let ip = Option.get ip_opt in
                    let ip = Ip.Pdu.{ ip with ttl = ttl - 1 } in
                    let bits = Ip.Pdu.pack ip in
                    forward bits
                | None ->
                    forward bits
            and lb_port = function
                | NoLoadBalancing ->
                    0
                | Random ->
                    Random.bits ()
                | PrefixHash ->
                    let bits =
                        try takebytes !lb_prefix_length bits
                        with Invalid_argument _ -> bits in
                    do_sum bits
            in
            let rs = List.enum out_ports // (fun r -> r.out_port <> in_port) |> Array.of_enum in
            let rs_len = Array.length rs in
            if rs_len = 0 then
                Log.(log t.logger Debug (lazy (Printf.sprintf "Dropping packet since port dest (%d) = source" (List.at out_ports 0).out_port)))
            else if rs_len = 1 then
                forward rs.(0)
            else
                forward rs.(lb_port t.load_balancing mod rs_len)

    (** Change the emitter of port N. Note that the emitter may also be preset in the trx array given to [make]. *)
    let set_read t n f =
        Log.(log t.logger Debug (lazy (Printf.sprintf "setting emitter for port %d" n))) ;
        t.ports.(n).trx =-> f

    (* TODO: similarly, a write n b = t.ports.(n).trx.write b *)

    (* Not for the general public: *)
    let make_port ~mac ~ip trx =
        let ins, tx_counters = counting trx.ins
        and out, rx_counters = counting trx.out in
        let connected = ref false in
        let set_read f =
            connected := true ;
            out.set_read f in
        let out = { out with set_read } in
        let trx = { ins ; out } in
        { trx ; mac ; ip ; rx_counters ; tx_counters ; connected }

    (* Come handy for 2 stages initialization of ports: *)
    let make_dummy_ports num =
        let counters_zero = { num_writes = 0 ; num_bits = 0 } in
        let dummy_port =
            { trx = null_trx ; mac = Eth.Addr.zero ; ip = Ip.Addr.zero ;
              rx_counters = counters_zero ; tx_counters = counters_zero ;
              connected = ref false } in
        Array.make num dummy_port

    let is_connected port =
        !(port.connected)

    let first_free_port t =
        Array.findi (not % is_connected) t.ports

    let notify_never = { probability = 0. ; delay = 0. }
    let notify_always ?(delay=0.) () = { probability = 1. ; delay }

    (** Build a [t] routing through these {!Tools.trx} according to the given routing table. *)
    let make ?(notify=notify_always ()) ?(load_balancing=NoLoadBalancing) ports routes logger =
        (* Display the routing table (debug) *)
        Log.(log logger Debug (lazy
            (Printf.sprintf2 "Creating a router with routing table:%a"
                (List.print ~first:(if routes=[] then "" else "\n\t")
                            ~sep:"\n\t" ~last:"" print_route) routes))) ;
        (* Check we route only from/to the given ports *)
        let max_used_port =
            List.fold_left (fun prev r ->
                max r.out_port (Option.default 0 r.iface_num) |>
                max prev)
                0 routes in
        assert (max_used_port < Array.length ports) ;
        let t = { ports ; routes ; logger ; notify ; load_balancing } in
        Array.iteri (fun i port -> port.trx.ins.set_read (route i t)) ports ;
        t

    (* Returns both the router and the eth trxs (ins is inside router) created for you *)

    (* Assuming the network addresses are reachable from different ports of a
     * switch, output a trivial routing table that selects the output according
     * to the destination IP only: *)
    let routes_of_addrs addrs =
        let tbl = ref [] in
        for i = 0 to Array.length addrs - 1 do
            let ip_netmask_vias, _mac = addrs.(i) in
            List.iter (fun (ip, netmask, via) ->
                let route =
                    { iface_num = None ;
                      src_mask = None ;
                      (* [of_netmask] will clear non masked bits: *)
                      dst_mask = Some (Ip.Cidr.of_netmask ip netmask) ;
                      ip_proto = None ;
                      src_port = None ;
                      dst_port = None ;
                      out_port = i ;
                      via } in
                tbl := route :: !tbl
            ) ip_netmask_vias
        done ;
        List.rev !tbl

    (* [addrs] is an array (one entry for each port of the router) of list of
     * networks reachable via this port (with optional gateway for each of them).
     * The router address on each port is given by the subnet address itself
     * (lan address must clear the non masked bits) *)
    let make_from_addrs ?notify ?delay ?loss ?load_balancing addrs logger =
        let routes = routes_of_addrs addrs in
        let rec my_address n = function
            | [] ->
                Printf.sprintf "Router definition has no local address for port %d" n |>
                failwith
            | (ip, netmask, None) :: _ -> ip, netmask
            | _ :: rest -> my_address n rest in
        let rec my_gateways res = function
            | [] -> res
            | (ip, netmask, gw) :: rest ->
                let res = (ip, netmask, gw) :: res in
                my_gateways res rest in
        let ports =
            Array.mapi (fun n (ip_netmask_vias, mac) ->
                let ip, netmask = my_address n ip_netmask_vias in
                let gw = my_gateways [] ip_netmask_vias in
                let addr = Ip.Addr.to_bitstring ip
                and netmask = Ip.Addr.to_bitstring netmask in
                let eth = Eth.TRX.make ?delay ?loss ~gw mac Arp.HwProto.ip4 [ { addr ; netmask } ] logger in
                make_port ~mac ~ip eth.Eth.TRX.trx
            ) addrs in
        make ?notify ?load_balancing ports routes logger

    (*$R make_from_addrs
        (* Suppose we have a router for these 3 networks: *)
        let addrs = [| [ Ip.Addr.of_string "192.168.1.254", Ip.Addr.of_string "255.255.255.0", None ], Eth.Addr.random () ;
                       [ Ip.Addr.of_string "192.168.2.254", Ip.Addr.of_string "255.255.255.0", None ], Eth.Addr.random () ;
                       [ Ip.Addr.of_string "192.168.3.254", Ip.Addr.of_string "255.255.255.0", None ], Eth.Addr.random () |] in
        let logger = Log.make "test" in
        let router = make_from_addrs addrs logger in

        (* Now we will count incoming packets from each port (ARP requests, actually) : *)
        let counts = Array.create 3 0 in
        for i = 0 to Array.length counts - 1 do
            set_read router i (fun _ ->
                counts.(i) <- succ counts.(i))
        done ;
        let tot_count () = Array.reduce (+) counts
        and reset_count () = Array.iteri (fun i _ -> counts.(i) <- 0) counts in

        (* We are going to send some IP packets with a given destination: *)
        let easy_send n dst =
            { (Ip.Pdu.random ()) with Ip.Pdu.dst = Ip.Addr.of_string dst ; ttl = 9 } |>
            Ip.Pdu.pack |>
            Eth.Pdu.make Arp.HwProto.ip4 (Eth.Addr.random ()) (snd addrs.(n)) |>
            Eth.Pdu.pack |>
            router.ports.(n).trx.out.write in

        (* Let's play! *)
        easy_send 0 "1.2.3.4" ;
        easy_send 1 "1.2.3.4" ;
        Clock.run false ;
        "no match means dropped" @? (tot_count () = 0) ;

        reset_count () ;
        easy_send 0 "192.168.3.42" ;
        Clock.run false ;
        "route from 0 to 2" @? (tot_count () = 1 && counts.(2) = 1) ;

        reset_count () ;
        easy_send 2 "192.168.2.42" ;
        Clock.run false ;
        "route from 2 to 1" @? (tot_count () = 1 && counts.(1) = 1) ;

        reset_count () ;
        easy_send 0 "192.168.1.42" ;
        Clock.run false ;
        "no revert" @? (tot_count () = 0) ;
    *)

    (*$>*)
end

(** A gateway is a device with 2 Eth interfaces, with a public IP address
 * and a private network address, performing routing between these two,
 * NAT, DHCP and relaying DNS for the LAN.
 * The returned TRX is seen from the LAN (ie, tx for going out).
 * Internally, it's made of a 3 ports hub, with the dhcp/name server
 * attached to port 1, the NATing router to port 2, and the LAN to port 0:
 *
 *          GW: 192.168.0.1
 *           /-----------\
 *    LAN -- :0  (hub)   2:--<:0-router-1:>-- NAT --- Internet
 *           \____ 1 ____/
 *                 |
 *                 |
 *            dhcpd/named (192.168.0.2)
 *)
let make_gw ?delay ?loss ?(num_max_cnxs=500) ?nameserver ?(name="gw") ?notify public_ip local_cidr =
    let local_ips = Ip.Cidr.local_addrs local_cidr in
    let netmask = Ip.Cidr.to_netmask local_cidr in
    let hub = Hub.Repeater.make 3 (name^"/hub") in
    let gw_mac = Eth.Addr.random () in
    let gw_ip = Enum.get_exn local_ips in   (* first IP of the subnet is the GW *)
    let gw = [ Ip.Addr.zero, Ip.Addr.zero, Some (Eth.Mac gw_mac) ] in
    let srv_ip = Enum.get_exn local_ips in    (* second the dhcp/name servers *)
    (* Always on as there is no way to turn it on later: *)
    let h = Host.make_static ?nameserver ~gw ~on:true (name^"/gw") (Eth.Addr.random ()) ~netmask srv_ip in
    Hub.Repeater.set_read hub 1 h.Host.dev.write ;
    h.Host.dev.set_read (Hub.Repeater.write hub 1) ;
    (* Create and connect the first port of our router *)
    let router_logger = Log.sub h.Host.logger "router" in
    let gw_eth_logger = Log.sub router_logger "eth" in
    let gw_eth = Eth.TRX.make ?delay ?loss gw_mac Arp.HwProto.ip4 [ Eth.{ addr = Ip.Addr.to_bitstring gw_ip ; netmask = Ip.Addr.to_bitstring netmask } ] gw_eth_logger in
    Hub.Repeater.set_read hub 2 gw_eth.Eth.TRX.trx.out.write ;
    gw_eth.Eth.TRX.trx.out.set_read (Hub.Repeater.write hub 2) ;
    (* The second port of our router (facing internet) is the NAT *)
    let nat_logger = Log.sub router_logger "nat" in
    let nat = Nat.make public_ip num_max_cnxs nat_logger in
    (* Which we equip with an Eth TRX on the outside *)
    let nat_mac = Eth.Addr.random () in
    let nat_eth =
        let eth = Eth.TRX.make nat_mac Arp.HwProto.ip4 [ Eth.{ addr = Ip.Addr.to_bitstring public_ip ; netmask = Ip.Addr.(to_bitstring zero) } ] (Log.sub nat_logger "eth") in
        pipe nat eth.Eth.TRX.trx in
    (* Build this router then *)
    let _router =
        Router.(make ?notify
            [| make_port ~mac:gw_mac ~ip:gw_ip gw_eth.Eth.TRX.trx ;
               make_port ~mac:nat_mac ~ip:public_ip nat_eth |]
            [   (* route everything from anywhere to LAN if dest fits local_cidr *)
                { iface_num = None ; src_mask = None ; dst_mask = Some local_cidr ;
                  ip_proto = None ; src_port = None ; dst_port = None ;
                  out_port = 0 ; via = None } ;
                (* or zero IP address *)
                { iface_num = None ; src_mask = Some (Ip.Cidr.single Ip.Addr.zero) ; dst_mask = None ;
                 ip_proto = None ; src_port = None ; dst_port = None ;
                 out_port = 0 ; via = None } ;
                (* route everything else toward nat *)
                { iface_num = None ; src_mask = None ; dst_mask = None ;
                  ip_proto = None ; src_port = None ; dst_port = None ;
                  out_port = 1 ; via = None } ]
            router_logger) in
    (* TODO: local named could serve the local names according to the dhcp
     * leases and hostname options *)
    Dhcpd.serve h local_ips ;
    Named.serve h (fun _ -> None) ; (* Delegate everything to nameserver *)
    { ins = { write = (fun bits -> Hub.Repeater.write hub 0 bits) ;
              set_read = fun f -> Hub.Repeater.set_read hub 0 f } ;
      out = nat_eth.out }
(*$R make_gw
    (*Log.console_lvl := Log.Debug ;*)
    Clock.realtime := false ;
    let public_ip = Ip.Addr.of_string "80.82.17.127" in
    let gw_trx = make_gw public_ip (Ip.Cidr.of_string "192.168.0.0/16") in
    let gw = [ Ip.Addr.zero, Ip.Addr.zero, Some (Eth.IPv4 (Ip.Addr.of_string "192.168.0.1")) ] in
    let desktop = Host.make_dhcp "desktop" ~on:true ~netmask:Ip.Addr.all_ones
                                 ~gw (Eth.Addr.random ()) in
    desktop.Host.dev.set_read gw_trx.ins.write ;
    ignore (desktop.Host.dev.write <-= gw_trx) ;
    let logger = Log.make "test" in
    let server_ip = Ip.Addr.of_string "42.43.44.45" in
    let server_eth = Eth.TRX.make (Eth.Addr.random ()) Arp.HwProto.ip4 [ Eth.TRX.make_my_address (Ip.Addr.to_bitstring server_ip) ] logger in
    let src = ref None in
    let server_recv bits = (* check source IP is the public one (NATed) *)
        let ip = Ip.Pdu.unpack bits |> Option.get in
        src := Some ip.Ip.Pdu.src in
    ignore (server_recv <-= server_eth.Eth.TRX.trx) ;
    gw_trx <==> server_eth.Eth.TRX.trx ;
    Clock.delay (Clock.Interval.sec 10.) (fun () ->
        desktop.Host.udp_send (Host.IPv4 server_ip) (Udp.Port.o 80) empty_bitstring) () ;
    Clock.run false ;
    Clock.realtime := true ;
    assert_bool "Desktop was NATed" (!src = Some public_ip)
 *)
