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
   This test program build a cascade of routers in between a target host and
   an interface, to test traceroute-like tools.
*)
open Batteries
open Tools
open Router

let debug = true

let forward_traffic logger ifname input_dev =
    let log_paquet what to_string f b =
        Log.(log logger Debug (lazy (Printf.sprintf "%s: %s" what (to_string b)))) ;
        f b in
    let iface = Pcap.openif ifname in
    let pcap_to_string b =
        let len = Bitstring.bitstring_length b / 8 in
        Printf.sprintf "packet of %d byte(s)" len in
    input_dev.set_read
        (log_paquet "spitting" pcap_to_string (fun b -> Pcap.inject iface b)) ;
    Pcap.sniffer iface
        (log_paquet "swallowing" pcap_to_string input_dev.write) |> ignore ;
    Log.(log logger Info (lazy (Printf.sprintf "You can send traffic to %s now" ifname))) ;
    Clock.run true

(* The router IP will be the first IP of each of those CIDR. Targets will be
 * allocated in sequence. TODO: also spawn a DNS server with all the names and
 * IPs, connected to the input interface via a switch. *)


(* Routers referenced in [interfaces] are connected if already defined,
 * otherwise the port is left unconnected.
 * Hosts must have been created beforehand with as many interfaces as
 * required. *)
let make_router logger interfaces =
    (* TODO: trxs, route_tbl, logger *)
    let addrs =
        Array.map (fun (mac, cidr, _) ->
            (* [make_from_addrs] wants ip address, ip mask and MAC: *)
            let cidr = Ip.Cidr.of_string cidr in
            Ip.Cidr.first_addr cidr,
            Ip.Cidr.to_netmask cidr,
            mac
        ) interfaces in
    Router.make_from_addrs addrs logger

(* Build the network described in the [routers] hash and returns the device
 * representing the entry point of the network: *)
let build_network router_specs =
    ensure (router_specs <> []) "Invalid router specifications" ;
    (* Build all routers *)
    let routers = Hashtbl.create 10 in
    List.iter (fun (name, interfaces) ->
        let logger = Log.make name 50 in
        let router = make_router logger interfaces in
        Hashtbl.add routers name router
    ) router_specs ;
    (* Connect all routers together.
     * There is no actual hosts on the sub-networks so connects the output of
     * a router directly to the input of another: *)
    List.iter (fun (name, interfaces) ->
        let emitter = Hashtbl.find routers name in
        Array.iteri (fun i (_mac, subnet, receivers) ->
            (* Build an emitting function for this port that just writes into
             * each of the connected routers: *)
            let port_trx, subnet_ip = emitter.Router.trxs.(i) in
            let dev_of_receiver dest_name =
                match Hashtbl.find routers dest_name with
                | exception Not_found ->
                    (* If not a router, then create a host *)
                    let cidr = Ip.Cidr.of_string subnet in
                    let gw = Eth.IPv4 subnet_ip
                    and netmask = Ip.Cidr.to_netmask cidr
                    and mac = Eth.Addr.random ()
                    and ip = Ip.Cidr.second_addr cidr in
                    Host.(make_static dest_name ~gw ~on:true mac ~netmask ip).dev
                | dest_router ->
                    (* For each of connected routers, look for their corresponding
                     * interface by subnet name: *)
                    let dest_ports = List.assoc dest_name router_specs in
                    (match
                        Array.findi (fun (_, subnet', _) ->
                            subnet = subnet'
                        ) dest_ports with
                    | exception Not_found ->
                        error "Bad input data"
                    | i' ->
                        let trx = fst dest_router.Router.trxs.(i') in
                        trx.ins) in
            let connected_devs = List.map dev_of_receiver receivers in
            let emit bits =
                List.iter (fun dest_dev ->
                    dest_dev.write bits
                ) connected_devs in
            (* make that [emit] function the emitter for port [i] of [emitter]: *)
            port_trx =-> emit ;
            (* Also connect all output from those hosts to the router input port: *)
            List.iter (fun dest_dev ->
                dest_dev.set_read port_trx.out.write
            ) connected_devs
        ) interfaces
    ) router_specs ;
    (* Return the input device for the first port of the first router: *)
    let fst_router_name = List.hd router_specs |> fst in
    let fst_router = Hashtbl.find routers fst_router_name in
    let fst_trx = fst fst_router.Router.trxs.(0) in
    fst_trx.out

(* We need the name of the interface we are going to read from, and the IP
 * addresses of the routers will later come from the configuration file: *)
let main =
    let ifname = ref "veth1" in
    let in_cidr = ref "192.168.0.0/24" in
    let in_mac = ref (*(Eth.Addr.random ()) in*) (Eth.Addr.of_iface !ifname) in
    let routers = ref [
        "router0", [| !in_mac, !in_cidr (* TODO: patcher apres *), [] ;
(*                      "192.168.1.0/24", [ "router1" ] |] ;
        "router1", [| Eth.Addr.random (), "192.168.1.0/24", [ "router0" ] ;
                      Eth.Addr.random (), "192.168.2.0/24", [ "router2" ] |] ;
        "router2", [| Eth.Addr.random (), "192.168.2.0/24", [ "router1" ] ;*)
                      Eth.Addr.random (), "192.168.3.0/24", [ "target" ] |] ]
    in
    Arg.parse [
        "-i", Arg.Set_string ifname,
              "Input interface name (optional, default br0)" ]
        (fun _ -> raise (Arg.Bad "Unknown parameter"))
        "Hide a host behind routers" ;
    let logger = Log.make "routerz" 1000 in
    Log.console_lvl := Log.Debug ;
    Log.(log logger Info (lazy "Building network...")) ;
    let input_dev = build_network !routers in
    Log.(log logger Info (lazy "Forwarding traffic...")) ;
    forward_traffic logger !ifname input_dev
