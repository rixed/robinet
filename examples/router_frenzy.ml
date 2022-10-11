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
let make_router name logger interfaces router_specs delays losses lb_configs =
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
        List.enum interfaces |>
        Enum.map (fun (mac, lan_cidr, peer_routers) ->
            let lan = addr_of_interface lan_cidr in
            (* Then for each peer routers, add all reachable networks from them with
             * that peer as a gateway: *)
            let rec find_routes res lan_cidr via interfaces =
                (* For all ports but the one with the same subnet as
                 * [lan_cidr], add a route via this router: *)
                let lan_cidr' = Ip.Cidr.of_string lan_cidr in
                List.fold_left (fun res (_mac, cidr, peer_routers) ->
                    let cidr' = Ip.Cidr.of_string cidr in
                    if cidr' = lan_cidr' then res else
                    let res = addr_of_interface ~via cidr :: res in
                    List.fold_left (fun res peer_router ->
                        match Hashtbl.find router_specs peer_router with
                        | exception Not_found ->
                            (* This must be a host then *)
                            res
                        | ports ->
                            find_routes res cidr via ports
                    ) res peer_routers
                ) res interfaces in
            let lan_cidr' = Ip.Cidr.of_string lan_cidr in
            List.fold_left (fun res peer_router ->
                (* First of all, the gateway to use is always going to be
                 * the port of [peer_router] on the common subnet (the one
                 * we are connected to): *)
                match Hashtbl.find router_specs peer_router with
                | exception Not_found ->
                    (* This must be a host then *)
                    res
                | ports ->
                    (match
                        List.find_map (fun (mac, cidr, _) ->
                                          let cidr' = Ip.Cidr.of_string cidr in
                                          if cidr' = lan_cidr' then Some mac else None
                        ) ports
                    with
                    | exception Not_found ->
                        failwith "Bad input: no common subnet between connected routers"
                    | gw ->
                        let via = Eth.Mac gw in
                        find_routes res lan_cidr via ports)
            ) [lan] peer_routers,
            mac
        ) |>
        Array.of_enum  in
    let delay = List.assoc_opt name delays
    and loss = List.assoc_opt name losses
    and load_balancing = List.assoc_opt name lb_configs in
    Router.make_from_addrs ?delay ?loss ?load_balancing addrs logger

(* Build the network described in the [routers] hash and returns the device
 * representing the entry point of the network: *)
let build_network logger router_specs fst_router_name delays losses lb_configs =
    ensure (Hashtbl.length router_specs > 0) "Invalid router specifications" ;
    let connections = Hashtbl.create 40 in
    let devices = Hashtbl.create 40 in
    (* Build all routers *)
    let routers =
        Hashtbl.map (fun name ports ->
            let logger = Log.make name 50 in
            make_router name logger ports router_specs delays losses lb_configs
        ) router_specs in
    (* Connect all routers together. *)
    Hashtbl.iter (fun name ports ->
        let emitter = Hashtbl.find routers name in
        List.iteri (fun i (_mac, cidr, receivers) ->
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
                    dest_name,
                    Host.(make_static dest_name ~gw ~on:true mac ~netmask ip).dev
                | dest_router ->
                    (* For each of connected routers, look for their corresponding
                     * interface by subnet name: *)
                    let dest_ports = Hashtbl.find router_specs dest_name in
                    (match
                        List.findi (fun _i (_, cidr', _) ->
                            let cidr' = Ip.Cidr.of_string cidr' in
                            cidr' = cidr
                        ) dest_ports with
                    | exception Not_found ->
                        error "Bad input data"
                    | i', _ ->
                        let trx, _, _ = dest_router.Router.trxs.(i') in
                        dest_name ^"#"^ string_of_int i',
                        trx.out) in
            (* Register all those connections: *)
            List.iter (fun dest_name ->
                let add_once connections k v =
                    let vs = Hashtbl.find_all connections k in
                    if not (List.mem v vs) then Hashtbl.add connections k v in
                let dst_name, dst_dev = dev_of_receiver dest_name
                and src_name = name ^"#"^ string_of_int i in
                (* Record the device for this name: *)
                add_once devices src_name port_trx.out ;
                add_once devices dst_name dst_dev ;
                add_once connections src_name dst_name ;
                add_once connections dst_name src_name
            ) receivers
        ) ports
    ) router_specs ;
    (* Actually connect the devices: *)
    Hashtbl.keys connections |>
    Enum.uniq |> (* Filter out duplicate names *)
    Enum.iter (fun src_name ->
        let dests = Hashtbl.find_all connections src_name in
        Log.(log logger Info (lazy (Printf.sprintf2 "%s --> %a" src_name (List.print String.print) dests))) ;
        let emit bits =
            List.iter (fun dst_name ->
                Log.(log logger Info (lazy (Printf.sprintf "Writing packet to %s" dst_name))) ;
                let dst_dev = Hashtbl.find devices dst_name in
                dst_dev.write bits
            ) dests in
        (* make that [emit] function the emitter for port [i] of [emitter]: *)
        let src_dev = Hashtbl.find devices src_name in
        src_dev.set_read emit) ;
    (* Return the input device for the first port of the first router: *)
    let fst_router = Hashtbl.find routers fst_router_name in
    let fst_trx, _, _ = fst_router.Router.trxs.(0) in
    fst_trx.out

(* We need the name of the interface we are going to read from, and the IP
 * addresses of the routers will later come from the configuration file: *)
let main =
    let ifname = ref "veth1" in
    let subnet_seq = ref 0 in
    let subnet_size = Hashtbl.create 10 in  (* seq -> num of IPs *)
    let input_subnet = ref "" in
    let routers = Hashtbl.create 10
    and delays = ref []
    and losses = ref []
    and lb_configs = ref []
    and fst_router_name = ref ""
    and lst_router_name = ref ""
    in
    let next_ip_of_subnet s =
        let n = Hashtbl.find subnet_size s + 1 in
        Hashtbl.replace subnet_size s n ;
        "192.168."^ string_of_int s ^"."^ string_of_int n in
    let next_cidr_of_subnet s =
        next_ip_of_subnet s ^"/24" in
    let next_subnet () =
        let s = !subnet_seq in
        incr subnet_seq ;
        Hashtbl.add subnet_size s 0 ;
        s in
    let set_subnet_seq n =
        if Hashtbl.length routers <> 0 then
            failwith "-s option must come before -l options!" ;
        subnet_seq := n ;
        input_subnet := next_cidr_of_subnet (next_subnet ()) in
    let add_port router_name cidr targets =
        match Hashtbl.find routers router_name with
        | exception Not_found ->
            Hashtbl.add routers router_name [ Eth.Addr.random (), cidr, targets ]
        | ports ->
            Hashtbl.replace routers router_name
                (ports @ [ Eth.Addr.random (), cidr, targets ]) in
    let add_router s =
        if !input_subnet = "" then set_subnet_seq 0 ;
        match String.split ~by:":" s with
        | exception Not_found ->
            failwith "should be: -l R1:R2"
        | r1, r2 ->
            let s = next_subnet () in
            add_port r1 (next_cidr_of_subnet s) [ r2 ] ;
            add_port r2 (next_cidr_of_subnet s) [ r1 ] in
    let print_port oc (mac, net, targets) =
        Printf.fprintf oc "eth:%s, net:%s, %a"
            (Eth.Addr.to_string mac)
            net
            (List.print String.print) targets in
    let add_delay s =
        match String.split ~by:":" s with
        | exception Not_found ->
            failwith "should be: -d ROUTER:DELAY"
        | r, d ->
            delays := (r, float_of_string d) :: !delays in
    let add_loss s =
        match String.split ~by:":" s with
        | exception Not_found ->
            failwith "should be: -d ROUTER:LOSS"
        | r, l ->
            let l = float_of_string l in
            if l < 0. || l > 1. then
                failwith "loss should be between 0 and 1" ;
            losses := (r, l) :: !losses in
    let add_lb lb s =
        lb_configs := (s, lb) :: !lb_configs in
    Arg.parse [
        "-i", Arg.Set_string ifname,
                "Input interface name (optional, default br0)" ;
        "-s", Arg.Int set_subnet_seq,
                "Starting number for 192.168.X.0 subnet \
                 (must come before -l options!)" ;
        "-l", Arg.String add_router,
                "Add a link between two routers (first router mentioned is \
                 the input router and last the exit router)" ;
        "-first", Arg.Set_string fst_router_name,
                    "Name of the input router" ;
        "-last", Arg.Set_string lst_router_name,
                   "Name of the last router before the target" ;
        "-delay", Arg.String add_delay,
                    "Set delay for specified router" ;
        "-loss", Arg.String add_loss,
                   "Set loss for specified router" ;
        "-lb-random", Arg.String (add_lb Router.Random),
                        "configure load balancer for this router \
                         (random port method)" ;
        "-lb-prefix", Arg.String (add_lb Router.PrefixHash),
                        "configure load balancer for this router \
                         (hash of prefix method)" ]
        (fun _ -> raise (Arg.Bad "Unknown parameter"))
        "Hide a host behind routers" ;
    if Hashtbl.length routers = 0 then (
        Printf.printf "Example:\n\
            router_frenzy -l router0:router1 -l router1:router2 -first router0 -last router2\n\n" ;
        exit 0) ;
    (* Add a port for entry, with input mac address. Must be the first port
     * of that router: *)
    if !fst_router_name = "" then
        failwith "Must specify the name of the input router" ;
    (match Hashtbl.find routers !fst_router_name with
    | exception Not_found ->
        failwith "Cannot find first router in the specifications"
    | [] ->
        assert false (* because we push at least one port per router *)
    | ports ->
        let ports = (Eth.Addr.of_iface !ifname, !input_subnet, []) :: ports in
        Hashtbl.replace routers !fst_router_name ports) ;
    (* Add target: *)
    if !lst_router_name = "" then
        failwith "Must set name of last router" ;
    if not (Hashtbl.mem routers !lst_router_name) then
        failwith "Cannot find last router in the specifications" ;
    let s = next_subnet () in
    let cidr = next_cidr_of_subnet s in
    let targets = [ next_ip_of_subnet s ] in
    add_port !lst_router_name cidr targets ;
    (* Start the simulation *)
    let logger = Log.make "routerz" 1000 in
    Log.console_lvl := Log.Debug ;
    Log.(log logger Info (lazy
        (Printf.sprintf2 "Building network with:\n%a\n"
            (Hashtbl.print String.print (List.print print_port)) routers))) ;
    let input_dev =
        build_network logger routers !fst_router_name !delays !losses !lb_configs in
    Log.(log logger Info (lazy "Forwarding traffic...")) ;
    forward_traffic logger !ifname input_dev
