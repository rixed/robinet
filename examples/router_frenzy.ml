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
 * otherwise the iface is left unconnected.
 * Hosts must have been created beforehand with as many interfaces as
 * required. *)
let make_router name logger interfaces router_specs delays err_delays losses err_losses lb_configs =
    let addr_of_interface ?via cidr =
        (* [make_from_addrs] wants ip address, ip mask and MAC: *)
        match String.split ~by:"/" cidr with
        | exception Not_found ->
            failwith ("Invalid CIDR "^ cidr)
        | my_ip, _ ->
            let dest_ip = Ip.Addr.of_string my_ip in
            let mask = Ip.Cidr.(of_string cidr |> to_netmask) in
            dest_ip, mask, via in
    (* Store all routes in a hash indexed by destination CIDR (as a string), with
     * values = the output MAC (aka iface of that router, the depth of that route,
     * then the route itself.
     * Later this hash is going to be converted into the array of lists as required
     * by [Router.make_from_addrs]. *)
    let tbl : (Ip.Cidr.t, (Eth.Addr.t * int * (Ip.Addr.t * Ip.Addr.t * Eth.Gateway.t option))) Hashtbl.t = Hashtbl.create 10 in
    List.iter (fun (mac, lan_cidr, peer_routers) ->
        let depth = 1 in
        let lan_cidr' = Ip.Cidr.of_string lan_cidr in
        Hashtbl.replace tbl lan_cidr' (mac, depth, addr_of_interface lan_cidr) ;
        (* Then for each peer routers, add all reachable networks from them with
         * that peer as a gateway: *)
        let rec find_routes depth lan_cidr via interfaces =
            (* For all ifaces but the one with the same subnet as
             * [lan_cidr], add a route via this router: *)
            let lan_cidr' = Ip.Cidr.of_string lan_cidr in
            List.iter (fun (_mac, cidr, peer_routers) ->
                let cidr' = Ip.Cidr.of_string cidr in
                if cidr' <> lan_cidr' then (
                    (* Look for previous route in [tbl] and if new one is better
                     * then replace, or stop: *)
                    let todo, replace =
                        match Hashtbl.find tbl cidr' with
                        | exception Not_found ->
                            true, false (* Add it *)
                        | _mac, depth', _addr ->
                            (* Add or replace depending on depths*)
                            depth <= depth', depth < depth' in
                    if todo then (
                        (if replace then Hashtbl.replace else Hashtbl.add)
                            tbl cidr' (mac, depth, addr_of_interface ~via cidr) ;
                        List.iter (fun peer_router ->
                            match Hashtbl.find router_specs peer_router with
                            | exception Not_found ->
                                () (* This must be a host then *)
                            | ifaces ->
                                find_routes (depth + 1) cidr via ifaces
                        ) peer_routers
                    )
                )
            ) interfaces in
        List.iter (fun peer_router ->
            (* First of all, the gateway to use is always going to be
             * the iface of [peer_router] on the common subnet (the one
             * we are connected to): *)
            match Hashtbl.find router_specs peer_router with
            | exception Not_found ->
                (* This must be a host then *)
                ()
            | ifaces ->
                (match
                    List.find_map (fun (mac, cidr, _) ->
                                      let cidr' = Ip.Cidr.of_string cidr in
                                      if cidr' = lan_cidr' then Some mac else None
                    ) ifaces
                with
                | exception Not_found ->
                    failwith "Bad input: no common subnet between connected routers"
                | gw ->
                    let via = Eth.Gateway.Mac gw in
                    find_routes (depth + 1) lan_cidr via ifaces)
        ) peer_routers ;
    ) interfaces ;
    Printf.printf "tbl=\n%a\n%!"
        (Hashtbl.print
            Ip.Cidr.printf
            (fun oc (mac, depth, (ip, mask, via)) ->
                Printf.fprintf oc "mac=%a, depth=%d, dest %a/%a via %a"
                    Eth.Addr.printf mac
                    depth
                    Ip.Addr.printf ip
                    Ip.Addr.printf mask
                    (Option.print Eth.Gateway.print) via)) tbl ;
    let lst =
        List.map (fun (mac, _lan_cidr, _peer_routers) ->
            Hashtbl.fold (fun _cidr (mac', _depth, addr) lst ->
                if mac = mac' then addr :: lst else lst
            ) tbl [],
            mac
        ) interfaces in
    let addrs = Array.of_list lst in
    let delay = List.assoc_opt name delays
    and loss = List.assoc_opt name losses
    and load_balancing = List.assoc_opt name lb_configs
    and notify = Router.{
        probability = List.assoc_opt name err_losses |? 0. ;
        delay = List.assoc_opt name err_delays |? 0. } in
    Router.make_from_addrs ~notify ?delay ?loss ?load_balancing addrs logger

(* Build the network described in the [routers] hash and returns the device
 * representing the entry point of the network: *)
let build_network logger router_specs fst_router_name delays err_delays losses err_losses lb_configs =
    ensure (Hashtbl.length router_specs > 0) "Invalid router specifications" ;
    let connections = Hashtbl.create 40 in
    let devices = Hashtbl.create 40 in
    (* Build all routers *)
    let routers =
        Hashtbl.map (fun name ifaces ->
            let logger = Log.make name in
            if debug then Printf.printf "Build router %s\n%!" name ;
            make_router name logger ifaces router_specs delays err_delays losses err_losses lb_configs
        ) router_specs in
    (* Connect all routers together. *)
    Hashtbl.iter (fun name ifaces ->
        if debug then Printf.printf "Connecting router %s\n%!" name ;
        let emitter = Hashtbl.find routers name in
        List.iteri (fun i (_mac, cidr, receivers) ->
            if debug then Printf.printf "\tport %d...\n%!" i ;
            (* Build an emitting function for this iface that just writes into
             * each of the connected routers/hosts: *)
            let cidr = Ip.Cidr.of_string cidr in
            let iface : Router.iface = emitter.Router.ifaces.(i) in
            let dev_of_receiver dest_name =
                match Hashtbl.find routers dest_name with
                | exception Not_found ->
                    if debug then Printf.printf "\tBuild host %s\n%!" dest_name ;
                    (* If not a router, then create a host *)
                    let gw_ip = Eth.State.find_ip4 iface.eth in
                    let gateways = [ Eth.State.gw_selector (), Some Eth.Gateway.(IPv4 gw_ip) ]
                    and netmask = Ip.Cidr.to_netmask cidr
                    and ip = try Ip.Addr.of_string dest_name
                             with Invalid_argument _ -> Ip.Cidr.second_addr cidr in
                    dest_name,
                    Host.(make_static ~gateways ~netmask ip dest_name).trx.dev
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
                        dest_name ^"#"^ string_of_int i',
                        dest_router.Router.ifaces.(i').trx.out) in
            (* Register all those connections: *)
            List.iter (fun dest_name ->
                if debug then Printf.printf "\tRegistering connection %s\n%!" dest_name ;
                let add_once connections k v =
                    let vs = Hashtbl.find_all connections k in
                    if not (List.mem v vs) then Hashtbl.add connections k v in
                let dst_name, dst_dev = dev_of_receiver dest_name
                and src_name = name ^"#"^ string_of_int i in
                (* Record the device for this name: *)
                add_once devices src_name iface.Router.trx.out ;
                add_once devices dst_name dst_dev ;
                add_once connections src_name dst_name ;
                add_once connections dst_name src_name
            ) receivers
        ) ifaces
    ) router_specs ;
    (* Actually connect the devices: *)
    if debug then Printf.printf "Actually connect the devices...\n%!" ;
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
        (* make that [emit] function the emitter for iface [i] of [emitter]: *)
        let src_dev = Hashtbl.find devices src_name in
        src_dev.set_read emit) ;
    (* Return the input device for the first iface of the first router: *)
    let fst_router = Hashtbl.find routers fst_router_name in
    fst_router.Router.ifaces.(0).trx.out

(* We need the name of the interface we are going to read from, and the IP
 * addresses of the routers will later come from the configuration file: *)
let main =
    let ifname = ref "veth1" in
    let subnet_seq = ref 0 in
    let subnet_size = Hashtbl.create 10 in  (* seq -> num of IPs *)
    let input_subnet = ref "" in
    let routers = Hashtbl.create 10
    and delays = ref []
    and err_delays = ref []
    and losses = ref []
    and err_losses = ref []
    and lb_configs = ref []
    and fst_router_name = ref ""
    and lst_router_name = ref ""
    and targets = ref []
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
        | ifaces ->
            Hashtbl.replace routers router_name
                (ifaces @ [ Eth.Addr.random (), cidr, targets ]) in
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
    let add_param ?(is_rate=false) opt_name param_name lst s =
        match String.split ~by:":" s with
        | exception Not_found ->
            failwith ("should be: -"^ opt_name ^" ROUTER:"^ param_name)
        | r, d ->
            let d = float_of_string d in
            if is_rate && (d < 0. || d > 1.) then
                failwith (opt_name ^" should be between 0 and 1")
            else if d < 0. then
                failwith (opt_name ^" should be greater then 0") ;
            lst := (r, d) :: !lst in
    let add_fwd_delay s =
        add_param "fwd-delay" "DELAY" delays s in
    let add_err_delay s =
        add_param "err-delay" "DELAY" err_delays s in
    let add_fwd_loss s =
        add_param ~is_rate:true "fwd-loss" "LOSS" losses s in
    let add_err_loss s =
        add_param ~is_rate:true "err-loss" "LOSS" err_losses s in
    let add_lb lb s =
        lb_configs := (s, lb) :: !lb_configs in
    let add_target s =
        targets := s :: !targets in
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
        "-fwd-delay", Arg.String add_fwd_delay,
                      "Set forwarding delay for specified router" ;
        "-err-delay", Arg.String add_err_delay,
                      "Set delay for ICMP errors echoed by this router" ;
        "-fwd-loss", Arg.String add_fwd_loss,
                     "Set loss for forwarded packets for this router" ;
        "-err-loss", Arg.String add_err_loss,
                     "Set loss for ICMP errors echoed by this router" ;
        "-lb-random", Arg.String (add_lb Router.Random),
                      "Configure load balancer for this router \
                       (random port method)" ;
        "-lb-prefix", Arg.String (add_lb Router.PrefixHash),
                      "Configure load balancer for this router \
                       (hash of prefix method)" ;
        "-target", Arg.String add_target,
                   "Attach this target to the last router \
                    (random single target by default)" ]
        (fun _ -> raise (Arg.Bad "Unknown parameter"))
        "Hide a host behind routers" ;
    if Hashtbl.length routers = 0 then (
        (* We might still have a single router mentioned in [fst_router_name]
         * and [lst_router_name]: *)
        if !fst_router_name <> "" then (
            if !lst_router_name = "" then
                lst_router_name := !fst_router_name ;
            if !input_subnet = "" then set_subnet_seq 0 ;
            let s = next_subnet () in
            add_port !fst_router_name (next_cidr_of_subnet s) []
        ) else (
            Printf.printf "Example:\n\
                router_frenzy -l router0:router1 -l router1:router2 -first router0 -last router2\n\n" ;
            exit 0
        )
    ) ;
    (* Add a iface for entry, with input mac address. Must be the first iface
     * of that router: *)
    if !fst_router_name = "" then
        failwith "Must specify the name of the input router" ;
    (match Hashtbl.find routers !fst_router_name with
    | exception Not_found ->
        failwith "Cannot find first router in the specifications"
    | [] ->
        assert false (* because we push at least one iface per router *)
    | ifaces ->
        let ifaces = (Eth.Addr.of_iface !ifname, !input_subnet, []) :: ifaces in
        Hashtbl.replace routers !fst_router_name ifaces) ;
    (* Add target: *)
    if !lst_router_name = "" then
        failwith "Must set name of last router" ;
    if not (Hashtbl.mem routers !lst_router_name) then
        failwith "Cannot find last router in the specifications" ;
    let targets, target_cidr =
        if !targets <> [] then (
            let target_ips = List.map Ip.Addr.of_string !targets in
            let cidr = Ip.Cidr.smallest (List.enum target_ips) in
            (* We need an IP for the router itself on that CIDR: *)
            let cidr = Ip.Cidr.enlarge cidr 1 in
            let next_ip =
                Ip.Cidr.enum cidr |>
                Enum.find (fun ip -> not (List.mem ip target_ips)) in
            let cidr = Ip.Addr.to_string next_ip ^"/"^
                       string_of_int (Ip.Cidr.width cidr) in
            !targets, cidr
        ) else (
            (* Random target *)
            let s = next_subnet () in
            let cidr = next_cidr_of_subnet s in
            [ next_ip_of_subnet s ], cidr
        ) in
    add_port !lst_router_name target_cidr targets ;
    (* Print the configuration: *)
    Hashtbl.iter (fun name ifaces ->
        Printf.printf "Router %s has IP %a\n"
            name
            (List.print ~first:"" ~last:"" ~sep:", "
                (fun oc (_mac, net, _targets) ->
                    String.print oc net)) ifaces
    ) routers ;
    List.iter (fun target ->
        Printf.printf "Target IP is %s\n"
            target
    ) targets ;
    (* Start the simulation *)
    let logger = Log.make ~size:1000 "routerz" in
    Log.console_lvl := Log.Debug ;
    Log.(log logger Info (lazy
        (Printf.sprintf2 "Building network with:\n%a\n\
                          Try to hit targets:\n%a\n"
            (Hashtbl.print String.print (List.print print_port)) routers
            (List.print String.print) targets))) ;
    let input_dev =
        build_network logger routers !fst_router_name !delays !err_delays !losses !err_losses !lb_configs in
    Printf.printf "Forwarding traffic...\n" ;
    forward_traffic logger !ifname input_dev
