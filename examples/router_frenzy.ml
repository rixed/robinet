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

(* The router IP is given by the subnet CIDR IP (not masked). Targets will be
 * allocated in sequence. TODO: also spawn a DNS server with all the names and
 * IPs, connected to the input interface via a switch. *)

(* Routers referenced in [interfaces] are connected if already defined,
 * otherwise the port is left unconnected.
 * Hosts must have been created beforehand with as many interfaces as
 * required. *)
let make_router logger interfaces router_specs =
    let addr_of_interface ?via cidr =
        (* [make_from_addrs] wants ip address, ip mask and MAC: *)
        match String.split ~by:"/" cidr with
        | exception Not_found ->
            failwith ("Invalid CIDR "^ cidr)
        | my_ip, _ ->
            let my_ip = Ip.Addr.of_string my_ip in
            let cidr = Ip.Cidr.of_string cidr in
            my_ip,
            Ip.Cidr.to_netmask cidr,
            via in
    let addrs =
        Array.map (fun (mac, lan_cidr, peer_routers) ->
            let lan = addr_of_interface lan_cidr in
            (* Then for each peer routers, add all reachable networks from them with
             * that peer as a gateway: *)
            let rec find_routes res lan_cidr via interfaces =
                (* For all ports but the one with the same subnet as
                 * [lan_cidr], add a route via this router: *)
                let lan_cidr' = Ip.Cidr.of_string lan_cidr in
                Array.fold_left (fun res (_mac, cidr, peer_routers) ->
                    let cidr' = Ip.Cidr.of_string cidr in
                    if cidr' = lan_cidr' then res else
                    let res = addr_of_interface ~via cidr :: res in
                    List.fold_left (fun res peer_router ->
                        match List.assoc peer_router router_specs with
                        | exception Not_found ->
                            (* This must be a host then *)
                            res
                        | interfaces ->
                            find_routes res cidr via interfaces
                    ) res peer_routers
                ) res interfaces in
            let lan_cidr' = Ip.Cidr.of_string lan_cidr in
            List.fold_left (fun res peer_router ->
                (* First of all, the gateway to use is always going to be
                 * the port of [peer_router] on the common subnet (the one
                 * we are connected to): *)
                match List.assoc peer_router router_specs with
                | exception Not_found ->
                    (* This must be a host then *)
                    res
                | interfaces ->
                    (match
                        Array.find_map (fun (mac, cidr, _) ->
                                          let cidr' = Ip.Cidr.of_string cidr in
                                          if cidr' = lan_cidr' then Some mac else None
                        ) interfaces
                    with
                    | None ->
                        failwith "Bad input: no common subnet between connected routers"
                    | Some gw ->
                        let via = Eth.Mac gw in
                        find_routes res lan_cidr via interfaces)
            ) [lan] peer_routers,
            mac
        ) interfaces in
    Router.make_from_addrs addrs logger

(* Build the network described in the [routers] hash and returns the device
 * representing the entry point of the network: *)
let build_network logger router_specs =
    ensure (router_specs <> []) "Invalid router specifications" ;
    (* Build all routers *)
    let routers = Hashtbl.create 10 in
    List.iter (fun (name, interfaces) ->
        let logger = Log.make name 50 in
        let router = make_router logger interfaces router_specs in
        Hashtbl.add routers name router
    ) router_specs ;
    (* Connect all routers together. *)
    List.iter (fun (name, interfaces) ->
        let emitter = Hashtbl.find routers name in
        Array.iteri (fun i (_mac, cidr, receivers) ->
            (* Build an emitting function for this port that just writes into
             * each of the connected routers/hosts: *)
            let cidr = Ip.Cidr.of_string cidr in
            let port_trx, _port_mac, port_ip = emitter.Router.trxs.(i) in
            let dev_of_receiver dest_name =
                match Hashtbl.find routers dest_name with
                | exception Not_found ->
                    (* If not a router, then create a host *)
                    let gw = [ Ip.Addr.zero, Ip.Addr.zero, Some (Eth.IPv4 port_ip) ]
                    and netmask = Ip.Cidr.to_netmask cidr
                    and mac = Eth.Addr.random ()
                    and ip = try Ip.Addr.of_string dest_name
                             with Invalid_argument _ -> Ip.Cidr.second_addr cidr in
                    Host.(make_static dest_name ~gw ~on:true mac ~netmask ip).dev
                | dest_router ->
                    (* For each of connected routers, look for their corresponding
                     * interface by subnet name: *)
                    let dest_ports = List.assoc dest_name router_specs in
                    (match
                        Array.findi (fun (_, cidr', _) ->
                            let cidr' = Ip.Cidr.of_string cidr' in
                            cidr' = cidr
                        ) dest_ports with
                    | exception Not_found ->
                        error "Bad input data"
                    | i' ->
                        let trx, _, _ = dest_router.Router.trxs.(i') in
                        trx.out) in
            let connected_devs =
                List.map (fun name -> name, dev_of_receiver name) receivers in
            Log.(log logger Info (lazy (Printf.sprintf2 "emit function for port %s to %a" (Ip.Addr.to_string port_ip) (List.print (fun oc (name, _) -> String.print oc name)) connected_devs))) ;
            let emit bits =
                List.iter (fun (name, dest_dev) ->
                    Log.(log logger Info (lazy (Printf.sprintf "Writing packet to %s" name))) ;
                    dest_dev.write bits
                ) connected_devs in
            (* make that [emit] function the emitter for port [i] of [emitter]: *)
            port_trx =-> emit ;
            (* Also connect all output from those hosts to the router input port: *)
            List.iter (fun (_name, dest_dev) ->
                dest_dev.set_read port_trx.out.write
            ) connected_devs
        ) interfaces
    ) router_specs ;
    (* Return the input device for the first port of the first router: *)
    let fst_router_name = List.hd router_specs |> fst in
    let fst_router = Hashtbl.find routers fst_router_name in
    let fst_trx, _, _ = fst_router.Router.trxs.(0) in
    fst_trx.out

(* We need the name of the interface we are going to read from, and the IP
 * addresses of the routers will later come from the configuration file: *)
let main =
    let ifname = ref "veth1" in
    let in_cidr = ref "192.168.0.1/24" in
    let in_mac = ref (*(Eth.Addr.random ()) in*) (Eth.Addr.of_iface !ifname) in
    let routers = ref [
        "router0", [| !in_mac, !in_cidr (* TODO: patcher apres *), [] ;
                      Eth.Addr.random (), "192.168.1.1/24", [ "192.168.1.3" ; "router1" ] |] ;
        "router1", [| Eth.Addr.random (), "192.168.1.2/24", [ "router0" (* Do not repeat 192.168.1.3 here! *) ] ;
                      Eth.Addr.random (), "192.168.2.1/24", [ "router2" ; "192.168.2.3" ] |] ;
        "router2", [| Eth.Addr.random (), "192.168.2.2/24", [ "router1" ] ;
                      Eth.Addr.random (), "192.168.3.1/24", [ "192.168.3.2" ; "192.168.3.3" ] |] ]
    in
    Arg.parse [
        "-i", Arg.Set_string ifname,
              "Input interface name (optional, default br0)" ]
        (fun _ -> raise (Arg.Bad "Unknown parameter"))
        "Hide a host behind routers" ;
    let logger = Log.make "routerz" 1000 in
    Log.console_lvl := Log.Debug ;
    Log.(log logger Info (lazy "Building network...")) ;
    let input_dev = build_network logger !routers in
    Log.(log logger Info (lazy "Forwarding traffic...")) ;
    forward_traffic logger !ifname input_dev
