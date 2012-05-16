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
open Batteries
open Bitstring
open Tools

let debug = true

(** the lowest port number used by the address translation *)
let min_port = 1024

(** Network Address Translation (N.A.T.) is the process of replacing on the fly non routable
 * addresses used within a LAN by a unique routable address, so that hosts from the LAN
 * can communicate with the outside world by sharing the only routable IP address.
 * A [Nat.t] is a two sided device, with an inside and an outside, and an affected Ip address,
 * that will translate outgoing source addresses with it's own and restore it in incoming
 * packets. To match these incoming packets with the outgoing one it must use the UDP or
 * TCP client port and an internal memory of currently forwarded connections. This memory
 * is of bounded size.
 * Note that any packet that reach it will be forwarded. *)
module Nat =
struct

    (**
    Behavior on incomming packets:
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
            mutable recv : bitstring -> unit }          (** the receive functon (ie. forward incoming packets from the outside *)

    let patch_src_port proto bits port =
        if proto = Ip.Proto.tcp then (
            Tcp.Pdu.pack { Option.get (Tcp.Pdu.unpack bits) with Tcp.Pdu.src_port = Tcp.Port.o port }
        ) else if proto = Ip.Proto.udp then (
            Udp.Pdu.pack { Option.get (Udp.Pdu.unpack bits) with Udp.Pdu.src_port = Udp.Port.o port }
        ) else should_not_happen ()

    let patch_dst_port proto bits port =
        if proto = Ip.Proto.tcp then (
            Tcp.Pdu.pack { Option.get (Tcp.Pdu.unpack bits) with Tcp.Pdu.dst_port = Tcp.Port.o port }
        ) else if proto = Ip.Proto.udp then (
            Udp.Pdu.pack { Option.get (Udp.Pdu.unpack bits) with Udp.Pdu.dst_port = Udp.Port.o port }
        ) else should_not_happen ()

    (** bits are flowing from LAN to outside world *)
    let tx t bits =
        match Ip.Pdu.unpack_with_ports bits with
        | None -> ()
        | Some (ip, src_port, dst_port) ->
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

    let rx t bits =
        Ip.Pdu.unpack_with_ports bits |>
        Option.bind (fun (ip, src_port, dst_port) ->
            let in_sock = {       proto = ip.Ip.Pdu.proto ;
                               nat_port = dst_port ;
                            remote_addr = ip.Ip.Pdu.src ;
                            remote_port = src_port } in
            Hashtbl.find_option t.in_cnxs_h in_sock |>
            Option.bind (fun n ->
                let cnx = OrdArray.get t.cnxs n in
                let payload = Payload.o (patch_dst_port ip.Ip.Pdu.proto
                                                        (ip.Ip.Pdu.payload :> bitstring)
                                                        cnx.in_port) in
                let ip = { ip with Ip.Pdu.dst = cnx.in_addr ; payload } in
                Some (t.recv (Ip.Pdu.pack ip)))) |>
        ignore

    (** [make ip n] returns a {!Tools.trx} corresponding to a NAT device (tx is for transmitting from the LAN to the outside) that can track [n] sockets. *)
    let make addr nb_max_cnxs =
        if debug then Printf.printf "router: Creating a NATer for IP %s, with %d cnxs max\n%!" (Ip.Addr.to_string addr) nb_max_cnxs ;
        let t = { addr ;
                  cnxs = OrdArray.make nb_max_cnxs { in_addr = Ip.Addr.zero ;
                                                     in_port = 0 ;
                                                    out_port = 0 } ;
                  in_cnxs_h = Hashtbl.create nb_max_cnxs ;
                  out_cnxs_h = Hashtbl.create nb_max_cnxs ;
                  emit = ignore ; recv = ignore } in
        { tx = tx t ;
          rx = rx t ;
          set_emit = (fun f -> t.emit <- f) ;
          set_recv = (fun f -> t.recv <- f) }
end

(** A router is a device with N IP transmitters and a routing
 * table with rules on interface number, Ip addresses, proto, ports. *)
module Router =
struct
    (*$< Router *)

    (* If we had a generic port module, this would go there *)
    type port_range = int * int (** Inclusive port range *)
    let port_in_range p (min, max) = p >= min && p <= max

    (** A [route] is a set of optional tests. *)
    type route = { iface_num : int option ;         (** Test on incoming iface *)
                    src_mask : Ip.Cidr.t option ;   (** Test on source IP *)
                    dst_mask : Ip.Cidr.t option ;   (** Test on dest IP *)
                    ip_proto : Ip.Proto.t option ;  (** Test on IP protocol *)
                    src_port : port_range option ;  (** Test on source port *)
                    dst_port : port_range option }  (** Test on dest port *)

    (** Test an incoming packet against a route. *)
    let test_route route ifn src_opt dst_opt proto_opt src_port_opt dst_port_opt =
        (* If the route test is set, then the value is required. *)
        let test_opt opt1 test opt2 = match opt2 with
            | Some opt -> Option.map_default (test opt) true opt1
            | None     -> Option.is_none opt1
        and cidr_mem_rev ip cidr = Ip.Cidr.mem cidr ip in
        test_opt route.iface_num (=) (Some ifn) &&
        test_opt route.src_mask cidr_mem_rev src_opt &&
        test_opt route.dst_mask cidr_mem_rev dst_opt &&
        test_opt route.ip_proto (=) proto_opt &&
        test_opt route.src_port port_in_range src_port_opt &&
        test_opt route.dst_port port_in_range dst_port_opt

    (** A router is an array of trxs and a route table *)
    (* FIXME: add a logger *)
    type t = {      trxs : trx array ;
               route_tbl : (route * int) array }    (** The route table is an array of route to output interface index. *)

    (** Call [rx n t bits] when an IP packet ([bits]) is received on interface [n]. *)
    let rx n t bits =
        if debug then Printf.printf "Router: rx from port %d\n" n ;
        let ip_opt = Ip.Pdu.unpack bits
        and ip_ports_opt = Ip.Pdu.unpack_with_ports bits in
        let src_opt = Option.map (fun ip -> ip.Ip.Pdu.src) ip_opt
        and dst_opt = Option.map (fun ip -> ip.Ip.Pdu.dst) ip_opt
        and proto_opt = Option.map (fun ip -> ip.Ip.Pdu.proto) ip_opt
        and src_port_opt = Option.map Tuple3.second ip_ports_opt
        and dst_port_opt = Option.map Tuple3.second ip_ports_opt in
        try let o = snd (Array.find (fun (r, _) ->
                test_route r n src_opt dst_opt proto_opt src_port_opt dst_port_opt)
                t.route_tbl) in
            if o <> n then (
                if debug then Printf.printf "Router: forwarding packet to port %d\n" o ;
                t.trxs.(o).tx bits
            ) else (
                if debug then Printf.printf "Router: dropping packet since dest = source\n" ;
            )
        with Not_found ->
            if debug then Printf.printf "Router: dropping packet since no route match\n"

    (** Change the emitter of port N. Note that the emitter may also be preset in the trx array given to [make]. *)
    let set_emit n t emit =
        if debug then Printf.printf "Router: setting emmitter for port %d\n" n ;
        t.trxs.(n).set_emit emit

    (** Build a [t] routing through these {!Tools.trx} according to the given routing table. *)
    let make trxs route_tbl =
        (* Check we route only from/to the given ports *)
        let max_used_port =
            Array.fold_left (fun prev (r, o) ->
                max prev (max o (Option.default 0 r.iface_num)))
                0 route_tbl in
        assert (max_used_port < Array.length trxs) ;
        let t = { trxs ; route_tbl } in
        Array.iteri (fun i trx -> trx.set_recv (rx i t)) trxs ;
        t

    let make_from_addrs addrs route_tbl =
        let trxs = addrs /@ (fun (ip, mac) ->
            let eth = Eth.TRX.make mac Arp.HwProto.ip4 [ Ip.Addr.to_bitstring ip ] in
            eth.Eth.TRX.trx) |>
            Array.of_enum in
        make trxs route_tbl

    (*$R
        (* Suppose we have a router for these 3 networks: *)
        let addrs = [| Ip.Addr.of_string "192.168.1.254", Eth.Addr.random () ;
                       Ip.Addr.of_string "192.168.2.254", Eth.Addr.random () ;
                       Ip.Addr.of_string "192.168.3.254", Eth.Addr.random () |] in
        (* With the obvious rules: *)
        let route_tbl = [| { iface_num = None ; src_mask = None ; dst_mask = Some (Ip.Cidr.of_string "192.168.1.0/24") ;
                             ip_proto = None ; src_port = None ; dst_port = None }, 0 ;
                           { iface_num = None ; src_mask = None ; dst_mask = Some (Ip.Cidr.of_string "192.168.2.0/24") ;
                             ip_proto = None ; src_port = None ; dst_port = None }, 1 ;
                           { iface_num = None ; src_mask = None ; dst_mask = Some (Ip.Cidr.of_string "192.168.3.0/24") ;
                             ip_proto = None ; src_port = None ; dst_port = None }, 2 |] in
        let router = make_from_addrs (Array.enum addrs) route_tbl in
        
        (* Now we will count incoming packets from each port (ARP requests, actually) : *)
        let counts = Array.create 3 0 in
        for i = 0 to Array.length counts - 1 do
            set_emit i router (fun _ -> counts.(i) <- succ counts.(i))
        done ;
        let tot_count () = Array.reduce (+) counts
        and reset_count () = Array.iteri (fun i _ -> counts.(i) <- 0) counts in

        (* We are going to send some IP packets with a given destination: *)
        let easy_send n dst =
            let ip = { Ip.Pdu.random () with Ip.Pdu.dst = Ip.Addr.of_string dst } in
            rx n router (Ip.Pdu.pack ip) in

        (* Let's play! *)
        easy_send 0 "1.2.3.4" ;
        easy_send 1 "1.2.3.4" ;
        "no match means dropped" @? (tot_count () = 0) ;

        reset_count () ;
        easy_send 0 "192.168.3.42" ;
        "route from 0 to 2" @? (tot_count () = 1 && counts.(2) = 1) ;

        reset_count () ;
        easy_send 2 "192.168.2.42" ;
        "route from 2 to 1" @? (tot_count () = 1 && counts.(1) = 1) ;

        reset_count () ;
        easy_send 0 "192.168.1.42" ;
        "no revert" @? (tot_count () = 0) ;
     *)

    (*$>*)
end

(** A gateway is a host with 2 Eth interfaces, with a public IP address
 * and a private network address, performing routing between these two,
 * NAT and DHCP for the LAN. *)
(* TODO *)