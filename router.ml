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
  Equipment for routing traffic
 *)
open Batteries

open Bitstring
open Tools
module Nat = Ip_nat

(** Routes are instructions where to forward each incoming packet. *)
module Route =
struct
    (* If we had a generic port module, this would go there *)
    type port_range = int * int (** Inclusive IP port range *)

    let string_of_port_range (mi, ma) =
        "from port "^ string_of_int mi ^" to "^ string_of_int ma

    let port_in_range p (mi, ma) = p >= mi && p <= ma

    let port_in_range_opt p = function
        | None -> true
        | Some r -> port_in_range p r

    (** A [route] is a set of optional tests and an output iface and optional
     * gateway. *)
    type target =
        | Forward of { out_iface : int ;                  (** Output iface *)
                             via : Eth.Gateway.t option } (** Optional gateway *)
        | Admin (* Packets are for the admin interface (TODO) *)
        (* TODO: MirrorTo, Deny, Ignore, with a default behavior for packets
         * dropping out of the routing table... *)

    (* TODO: add usage count *)
    type t = { (* Tests *)
               in_iface : int option ;              (** Test on incoming iface *)
               src_mask : Ip.Cidr.t option ;        (** Test on source IP *)
               dst_mask : Ip.Cidr.t option ;        (** Test on dest IP *)
               ip_proto : Ip.Proto.t option ;       (** Test on IP protocol *)
               src_port : port_range option ;       (** Test on source IP port *)
               dst_port : port_range option ;       (** Test on dest IP port *)
                 target : target }

    let make ?in_iface ?src_mask ?dst_mask ?ip_proto ?src_port ?dst_port
             target =
        { in_iface ; src_mask ; dst_mask ; ip_proto ; src_port ; dst_port ;
          target }

    let forward ?in_iface ?src_mask ?dst_mask ?ip_proto ?src_port ?dst_port
                ?via out_iface =
        let target = Forward { out_iface  ; via } in
        make ?in_iface ?src_mask ?dst_mask ?ip_proto ?src_port ?dst_port target

    let admin ?in_iface ?src_mask ?ip_proto ?src_port ?dst_port my_ip =
        let dst_mask = Ip.Cidr.single my_ip in
        make ?in_iface ?src_mask ~dst_mask ?ip_proto ?src_port ?dst_port Admin

    let print oc t =
        let optionally f = function
            | Some n -> f n
            | None -> "" in
        let string_of_in_iface n = "received at iface#"^ string_of_int n ^", "
        and string_of_proto p = "of "^ Ip.Proto.to_string p ^" protocol, "
        and string_of_ip_mask what cidr = what ^ Ip.Cidr.to_string cidr ^" "
        and string_of_port r = "port "^ string_of_port_range r ^" "
        and string_of_target = function
            | Forward { out_iface ; via } ->
                "iface#"^ string_of_int out_iface ^
                (match via with
                | None -> ", direct"
                | Some gw -> ", using gateway "^ Eth.Gateway.to_string gw)
            | Admin ->
                "admin"
        in
        "Packets " ^
            (optionally string_of_in_iface t.in_iface) ^
            (optionally string_of_proto t.ip_proto) ^
            (optionally (string_of_ip_mask "from ") t.src_mask) ^
            (optionally string_of_port t.src_port) ^
            (optionally (string_of_ip_mask "to ") t.dst_mask) ^
            (optionally string_of_port t.dst_port) ^
        "will be sent to " ^
            (string_of_target t.target) |>
        String.print oc

    (** Test an incoming packet against a route. *)
    let test t logger ifn src_opt dst_opt proto_opt src_port_opt dst_port_opt =
        let tests = ref [] in
        (* If the route test is set, then the value is required. *)
        let test_opt what opt1 test opt2 =
            tests := what :: !tests ;
            match opt2 with
            | Some opt -> Option.map_default (test opt) true opt1
            | None     -> Option.is_none opt1 in
        let cidr_mem_rev ip cidr = Ip.Cidr.mem cidr ip in
        let ok =
            test_opt "in_face" t.in_iface (=) ifn &&
            test_opt "src_ip" t.src_mask cidr_mem_rev src_opt &&
            test_opt "dst_ip" t.dst_mask cidr_mem_rev dst_opt &&
            test_opt "ip_proto" t.ip_proto (=) proto_opt &&
            test_opt "src_port" t.src_port port_in_range src_port_opt &&
            test_opt "dst_port" t.dst_port port_in_range dst_port_opt in
        Log.(log logger Debug (lazy (
            let last = if ok then " ✓" else " ¡☠!" in
            Printf.sprintf2 "Routing: route=%a: %a"
                print t
                (List.print ~first:"" ~sep:", " ~last String.print)
                    (List.rev !tests)))) ;
        ok
end

(** A router is a device with N IP/Eth devices and a routing
 * table with rules on interface number, Ip addresses, proto, ports.
 * IP packets TTL is decremented and expired with optional support for ICMP
 * expiration error messages. *)
module Router =
struct
    (*$< Router *)

    type iface = { mutable trx : trx ; (** Can come handy to splice another trx there. *)
                           eth : Eth.State.t ;
                        logger : Log.logger ;
        (** Any traffic arriving in this interface and directed to Admin is
         * forwarded to this host. There is one per interface so they have
         * totally independent IP stacks. If all the admin_hosts of a router
         * were to be made to edit the router's global configuration then
         * they would have to share that storage area of course. *)
            mutable admin_host : Host.t option }

    type load_balancing = First | Random | PrefixHash

    (* Probability to send ICMP expiry messages after TTL expiration, and after
     * which delay (TODO: should also depend on how busy the router is): *)
    type icmp_probability = { probability : float ; delay : float }

    (** A router is mainly an array of ifaces and a route table *)
    type t = {        ifaces : iface array ;
              mutable routes : Route.t list ;
                 (** How diligently to report errors with ICMP *)
                 notify_errs : icmp_probability ;
               (** Answers from admin should go through routing, as opposed
                * to return via the same interface: *)
               admin_reroute : bool ;
                      logger : Log.logger ;
              load_balancing : load_balancing ;
                     ingress : Metric.Counter.t ;
                      egress : Metric.Counter.t }

    (* Add a route (the added route becomes top priority *)
    let add_route (t : t) r =
        Log.(log t.logger Debug (lazy (Printf.sprintf2 "Adding route: %a" Route.print r))) ;
        t.routes <- r :: t.routes

    (** How many bytes to consider when hashing the packet prefix for load-balancing *)
    let lb_prefix_length = ref 5

    let target_routes ?in_iface ?src_ip ?dst_ip ?proto ?src_port ?dst_port t =
        List.filter_map (fun r ->
            if Route.test r t.logger in_iface src_ip dst_ip proto
                          src_port dst_port then
                Some r.target
            else
                None
        ) t.routes

    (* Sending will perform routing again *)
    let rec maybe_send_icmp t n ip icmp_maker =
        match Eth.State.find_ip4 t.ifaces.(n).eth with
        | exception Not_found ->
            Log.(log t.logger Debug (lazy "Cannot send an ICMP error: I have no IP!"))
        | my_ip ->
            if Random.float 1. < t.notify_errs.probability then
                let delay = jitter 0.1 t.notify_errs.delay in
                let icmp = icmp_maker ip in
                let ip_pld = Icmp.Pdu.pack icmp in
                let ip_pkt = Ip.Pdu.make Ip.Proto.icmp my_ip ip.Ip.Pdu.src ip_pld in
                let bits = Ip.Pdu.pack ip_pkt in
                Clock.delay (Clock.Interval.o delay) (route None t) bits

    (* The [route] function receives the IP packets from the Eth trx.
     * The integer [in_iface_opt] is the input interface number, unless
     * it's coming from the admin. *)
    and route in_iface_opt t bits =
        Log.(log t.logger Debug (lazy (match in_iface_opt with
            | Some n -> Printf.sprintf "rx from iface %d" n
            | None -> "generated traffic"))) ;
        Option.may (fun in_iface ->
            Metric.(Counter.add t.ingress ~params:(Params.singleton "port" (Param.Int in_iface)) (bytelength bits))
        ) in_iface_opt ;
        let ip_opt, src_opt, dst_opt, ttl_opt, proto_opt =
            match Ip.Pdu.unpack bits with
            | Error _ ->
                None, None, None, None, None
            | Ok ip ->
                Some ip, Some ip.Ip.Pdu.src, Some ip.dst, Some ip.ttl, Some ip.proto in
        let src_port_opt, dst_port_opt =
            match Option.bind ip_opt (Result.to_option % Ip.Pdu.get_ports) with
            | Some (src_port, dst_port) -> Some src_port, Some dst_port
            | None -> None, None in
        match target_routes ?in_iface:in_iface_opt
                            ?src_ip:src_opt ?dst_ip:dst_opt ?proto:proto_opt
                            ?src_port:src_port_opt ?dst_port:dst_port_opt t with
        | [] ->
            (match in_iface_opt, ip_opt with
            | None, _ ->
                Log.(log t.logger Warning (lazy "Cannot route my own packet"))
            | _, None ->
                Log.(log t.logger Debug (lazy "Dropping non-routable non IP packet"))
            | Some n, Some ip ->
                Log.(log t.logger Debug (lazy "No route match that packet")) ;
                maybe_send_icmp t n ip Icmp.Pdu.make_host_unreachable)
        | targets ->
            (* Forward the packet to that target: *)
            let forward = function
                | Route.Forward { out_iface ; via } ->
                    let do_forward bits =
                        Log.(log t.logger Debug (lazy (Printf.sprintf "Forwarding packet to iface %d" out_iface))) ;
                        Metric.(Counter.add t.egress ~params:(Params.singleton "port" (Param.Int out_iface)) (bytelength bits)) ;
                        let iface = t.ifaces.(out_iface) in
                        (* So we want to set the gateway for this packet but cannot
                         * call Etc.TRX.tx directly because some additional processing
                         * might be hidden in the TRX (NAT...) *)
                        iface.eth.via <- via ;
                        tx iface.trx bits ;
                        Log.(log t.logger Debug (lazy "Done")) in
                    (match in_iface_opt, ttl_opt with
                    | None, _ ->
                        do_forward bits
                    | Some n, Some (0 | 1) ->
                        Log.(log t.logger Debug (lazy (Printf.sprintf "Expiring packet from %d" n))) ;
                        let ip = Option.get ip_opt in
                        maybe_send_icmp t n ip Icmp.Pdu.make_ttl_expired_in_transit
                    | Some _, Some ttl ->
                        let ip = Option.get ip_opt in
                        let ip = Ip.Pdu.{ ip with ttl = ttl - 1 } in
                        let bits = Ip.Pdu.pack ip in
                        do_forward bits
                    | Some _, None ->
                        do_forward bits)
                | Admin ->
                    (match in_iface_opt with
                    | None ->
                        Log.(log t.logger Error (lazy "Generated traffic to admin!?"))
                    | Some in_iface ->
                        (match t.ifaces.(in_iface).admin_host with
                        | None ->
                            Log.(log t.logger Warning (lazy (Printf.sprintf "There is no admin on interface %d, now what?" in_iface)))
                        | Some host ->
                            Log.(log t.logger Debug (lazy "Delivering to the admin host")) ;
                            Host.ip_recv host bits)) in
            let targets =
                List.enum targets // (function
                    (* Actually, that's OK if out=in but then the router should
                     * generate also an ICMP redirect (see Stevens section 9.5) *)
                    | Forward { out_iface ; _ }
                        when in_iface_opt <> Some out_iface -> true
                    | Admin -> true
                    | _ -> false
                 ) |> Array.of_enum in
            let rs_len = Array.length targets in
            if rs_len = 0 then
                Log.(log t.logger Debug (lazy ("Dropping packet with no targets")))
            else match t.load_balancing with
                | First ->
                    forward targets.(0)
                | Random ->
                    let n = Random.bits () mod rs_len in
                    forward targets.(n)
                | PrefixHash ->
                    let bits =
                        try takebytes !lb_prefix_length bits
                        with Invalid_argument _ -> bits in
                    let n = do_sum bits mod rs_len in
                    forward targets.(n)

    (** Change the emitter of iface N. *)
    let set_read (t : t) n f =
        Log.(log t.logger Debug (lazy (Printf.sprintf "setting emitter for iface %d" n))) ;
        t.ifaces.(n).trx =-> f

    let is_connected iface =
        iface.eth.Eth.State.connected

    let first_free_iface t =
        try Some (Array.findi (not % is_connected) t.ifaces)
        with Not_found -> None

    (* TODO: similarly, a write n b = t.ifaces.(n).trx.write b *)

    let set_proxy_arp t n v =
        t.ifaces.(n).eth.do_proxy_arp <-
            if v then
                fun (arp : Arp.Pdu.t) ->
                    match Ip.Addr.of_bitstring arp.sender_proto,
                          Ip.Addr.of_bitstring arp.target_proto with
                    | src_ip, dst_ip ->
                        let targets =
                            target_routes ~in_iface:n ~src_ip ~dst_ip t in
                        targets <> [] &&
                        not (List.exists (function
                                | Route.Forward { out_iface ; _ } -> out_iface = n
                                | _ -> false
                            ) targets)
            else
                fun _ -> false

    let make_iface ?proto ?mtu ?delay ?loss ?mac ?my_addresses
                   ?(parent_logger=Log.default) n =
        let name = "#"^ string_of_int n in
        let logger = Log.sub parent_logger name in
        (* For our ifaces we force the GW on a packet by packet basis according
         * to the dynamic (and likely still unset) routing table. *)
        let eth = Eth.State.make ?proto ?mtu ?delay ?loss ?mac ?my_addresses
                                 ~parent_logger:logger () in
        let trx = Eth.TRX.make eth in
        { trx ; eth ; logger ; admin_host = None }

    let notify_never = { probability = 0. ; delay = 0. }
    let notify_always ?(delay=0.) () = { probability = 1. ; delay }

    let make ?(notify_errs=notify_always ()) ?(admin_reroute=true)
             ?(load_balancing=First)
             ?delay ?loss ?mtu ?(macs=[||])
             num_ifaces routes logger =
        (* Display the routing table (debug) *)
        Log.(log logger Debug (lazy
            (Printf.sprintf2 "Creating a router with routing table:%a"
                (List.print ~first:(if routes=[] then "" else "\n\t")
                            ~sep:"\n\t" ~last:"" Route.print) routes))) ;
        (* Check we route only from/to the given ifaces *)
        let max_used_iface =
            List.fold_left (fun prev (r : Route.t) ->
                max prev (
                    match r.target with
                    | Forward { out_iface ; _ } -> out_iface
                    | Admin -> 0
                ) |>
                max (r.in_iface |? 0)
            ) 0 routes in
        if max_used_iface >= num_ifaces then
            Printf.sprintf "Router.make: routing table uses up to iface#%d but router has only %d ifaces" max_used_iface num_ifaces |>
            invalid_arg ;
        let ifaces =
            Array.init num_ifaces (fun n ->
                (* Look for my admin IP in the routing table: *)
                let my_addresses =
                    List.find_map_opt (fun (r : Route.t) ->
                        match r.dst_mask with
                        | Some addr ->
                            if r.target = Admin &&
                               (r.in_iface = None || r.in_iface = Some n) then
                                (* We assume the Cidr is the actual IP and
                                 * the actual netmask, such as for instance:
                                 * 34.35.36.37/16 *)
                                let addr = Ip.Cidr.subnet addr |>
                                           Ip.Addr.to_bitstring
                                and netmask = Ip.Cidr.to_netmask addr |>
                                              Ip.Addr.to_bitstring in
                                Some [ Eth.State.{ addr ; netmask } ]
                            else
                                None
                        | _ -> None
                    ) routes in
                let mac =
                    (* Caller can set the MAC addresses: *)
                    if n >= Array.length macs then None else Some macs.(n) in
                make_iface ?delay ?loss ?mtu ?mac ?my_addresses
                           ~parent_logger:logger n
            ) in
        let ingress = Metric.Counter.make (logger.full_name ^"/ingress") "bytes" in
        let egress = Metric.Counter.make (logger.full_name ^"/egress") "bytes" in
        let t = { ifaces ; routes ; logger ; notify_errs ; admin_reroute ;
                  load_balancing ; ingress ; egress } in
        Array.iteri (fun n iface ->
            if iface.eth.my_addresses <> [] then (
                (* Make that interface a host with an IP stack on top of eth: *)
                let name = "admin@"^ string_of_int n in
                let logger = Log.sub iface.logger "admin" in
                (* On output, the host will be able to write onto that TRX and that
                 * will be output from that iface, properly updating the counters.
                 * Unless we want to give a chance for the answer to go through
                 * another route (usually safer): *)
                let trx =
                    if admin_reroute then
                        { ins = { write = route None t ; set_read = ignore } ;
                          out = { write = ignore_bits ; set_read = ignore } }
                    else
                        iface.trx in
                (* On the other way around it's a bit more convoluted: the host
                 * takes the reader callback only when set_ip is called, which
                 * we don't have to do here. The router is going call the host
                 * [ip_recv] function whenever that's the routing decision. *)
                iface.admin_host <-
                    Some (Host.make_from_eth ~logger iface.eth trx name)
            ) ;
            (* When packets are received from the outside, go to routing: *)
            iface.trx.ins.set_read (route (Some n) t)
        ) t.ifaces ;
        t

    (* Returns both the router and the eth trxs (ins is inside router) created for you *)

    (* Assuming the network addresses are reachable from different ifaces of a
     * switch, output a trivial routing table that selects the output according
     * to the destination IP only.
     * Assume an admin interface on every network reachable without gateway. *)
    let routes_of_addrs addrs =
        let is_my_address dest_ip mask addr =
            addr = None &&
            Int32.logand (Int32.lognot (Ip.Addr.to_int32 mask))
                         (Ip.Addr.to_int32 dest_ip) <> Int32.zero in
        Array.fold_lefti (fun tbl i (gws, _) ->
            List.fold_left (fun tbl (dest_ip, mask, addr) ->
                (* First route: to reach that network: *)
                let open Route in
                let target = Forward { out_iface = i ;
                                       via = addr } in
                let route =
                    { in_iface = None ;
                      src_mask = None ;
                      (* [of_netmask] will clear non masked bits: *)
                      dst_mask = Some (Ip.Cidr.of_netmask dest_ip mask) ;
                      ip_proto = None ;
                      src_port = None ;
                      dst_port = None ;
                      target } in
                let tbl = route :: tbl in
                let tbl =
                    (* Second route: to the admin interface: *)
                    if is_my_address dest_ip mask addr then (
                        { route with
                            dst_mask = Some Ip.Cidr.(single dest_ip) ;
                            target = Admin } :: tbl
                    ) else tbl
                    in
                tbl
            ) tbl gws
        ) [] addrs |>
        List.rev

    (* [addrs] is an array (one entry for each iface of the router) of list of
     * networks reachable via this iface (as an Etx.Gateway.t, which has an
     * optional gateway addr).
     * The router address on each iface is given by the subnet address itself
     * (if it's not a mere network address with all masked bits zeroed, and
     * if no ethernet gateway is defined for this route).  *)
    (* [addrs] also, for each iface, has the MAC address of the router on that
     * iface. *)
    let make_from_addrs ?notify_errs ?admin_reroute ?load_balancing ?delay ?loss
                        addrs logger =
        let routes = routes_of_addrs addrs in
        let num_ifaces = Array.length addrs in
        let macs = Array.map snd addrs in
        make ?notify_errs ?admin_reroute ?load_balancing ?delay ?loss ~macs
             num_ifaces routes logger

    (*$R make_from_addrs
        (* Suppose we have a router for these 3 networks: *)
        let addrs =
            [| [ Ip.Addr.of_string "192.168.1.254", Ip.Addr.of_string "255.255.255.0", None ], Eth.Addr.random () ;
               [ Ip.Addr.of_string "192.168.2.254", Ip.Addr.of_string "255.255.255.0", None ], Eth.Addr.random () ;
               [ Ip.Addr.of_string "192.168.3.254", Ip.Addr.of_string "255.255.255.0", None ], Eth.Addr.random () |] in
        let logger = Log.make "test" in
        let router = make_from_addrs addrs logger in

        (* Now we will count incoming packets from each iface (ARP requests, actually) : *)
        let counts = Array.create 3 0 in
        for i = 0 to Array.length counts - 1 do
            set_read router i (fun _ ->
                counts.(i) <- succ counts.(i))
        done ;
        let reset_count () = Array.iteri (fun i _ -> counts.(i) <- 0) counts in

        (* We are going to send some IP packets with a given destination: *)
        let easy_send n dst =
            Ip.Pdu.{ (random ()) with dst = Ip.Addr.of_string dst ; ttl = 9 } |>
            Ip.Pdu.pack |>
            Eth.Pdu.make Arp.HwProto.ip4 (Eth.Addr.random ()) (snd addrs.(n)) |>
            Eth.Pdu.pack |>
            router.ifaces.(n).trx.out.write in

        (* Let's play! *)
        easy_send 0 "1.2.3.4" ;
        easy_send 1 "1.2.3.4" ;
        Clock.run false ;
        "no match means dropped" @? (counts = [| 0;0;0 |]) ;

        reset_count () ;
        easy_send 0 "192.168.3.42" ;
        Clock.run false ;
        "route from 0 to 2" @? (counts = [| 0;0;1 |]) ;

        reset_count () ;
        easy_send 2 "192.168.2.42" ;
        Clock.run false ;
        "route from 2 to 1" @? (counts = [| 0;1;0 |]) ;

        reset_count () ;
        easy_send 0 "192.168.1.42" ;
        Clock.run false ;
        "no revert" @? (counts = [| 0;0;0 |]) ;
    *)

    (*$>*)
end

(** A gateway is a device with 2 Eth interfaces, with a public IP address
 * and a private network address, performing routing between these two,
 * NAT, DHCP and relaying DNS for the LAN.
 * The returned TRX is seen from the LAN (ie, tx for going out).
 * Internally, it's made of a 3 ifaces hub, with the dhcp/name server
 * attached to iface 1, the NATing router to iface 2, and the LAN to iface 0:
 *
 *          GW: 192.168.0.1
 *           /-----------\
 *    LAN -- :0  (hub)   2:--<:0-router-1:>-- NAT --- Internet
 *           \____ 1 ____/
 *                 |
 *                 |
 *            dhcpd/named (192.168.0.2)
 *)

type gw_trx =
    { trx : trx ;
      logger : Log.logger ;
      dhcp_state : Dhcpd.State.t ;
      dns_state : Named.State.t ;
      nat_state : Nat.State.t }

(* Returns a [gw_trx] that gives access to the dhcpd leases, the named zones
 * and the NAT tables.
 * Unless [dhcp_range] is set, all local IPs (but those used by the GW itself)
 * will be distributed via DHCP. *)
let make_gw ?delay ?loss ?mtu ?(num_max_cnxs=500) ?nameserver ?dhcp_range
            ?(name="gw") ?notify_errs ?admin_reroute ?(parent_logger=Log.default)
            ?public_netmask ?public_gw public_ip local_cidr =
    (* We want all parts inherit this logger: *)
    let parent_logger = Log.sub parent_logger name in
    let local_ips = Ip.Cidr.local_addrs local_cidr in
    let netmask = Ip.Cidr.to_netmask local_cidr in
    let broadcast = Ip.Cidr.all1s_addr local_cidr in
    (* Build the output router *)
    let router_logger = Log.sub parent_logger "router" in
    let router =
        Router.(make ?delay ?loss ?mtu ?notify_errs ?admin_reroute 2
            [ (* route everything from anywhere to LAN if dest fits local_cidr *)
              Route.forward ~dst_mask:local_cidr 0 ;
              (* or zero IP address *)
              Route.forward ~src_mask:(Ip.Cidr.single Ip.Addr.zero) 0 ;
              (* route everything else toward the outside *)
              Route.forward ?via:public_gw 1 ]
            router_logger) in
    (* Configure those 2 ifaces: *)
    (* 1st iface is for the GW: *)
    let gw_mac = router.ifaces.(0).eth.mac in
    let gw_ip = Enum.get_exn local_ips in   (* first IP of the subnet is the GW *)
    Eth.State.add_ip4 router.ifaces.(0).eth ~netmask gw_ip ;
    (* The second iface of our router (facing internet) is the NAT *)
    Eth.State.add_ip4 router.ifaces.(1).eth ?netmask:public_netmask public_ip ;
    let nat_state = Nat.State.make ~num_max_cnxs ~parent_logger public_ip in
    let nat_trx = Nat.TRX.make nat_state in
    (* Which we pipe *before* the iface eth (NAT operates at the IP level): *)
    router.ifaces.(1).trx <- pipe nat_trx router.ifaces.(1).trx ;
    (* FIXME: if we had directly a "mutable read" function rather than a
     * set_reader, the pipe operator (and others) could do the right thing here: *)
    router.ifaces.(1).trx.ins.set_read (Router.route (Some 1) router) ;
    (* This iface will become the outside side of out global TRX: *)
    let out_trx = router.ifaces.(1).trx in
    (* Create the "host" and configure its gateway, although we probably don't
     * want this host on the internet: *)
    let srv_ip = Enum.get_exn local_ips in    (* second the dhcp/name servers *)
    let h : Host.t =
        let gateways = [ Eth.State.gw_selector (), Some (Eth.Gateway.Mac gw_mac) ] in
        Host.make_static ?nameserver ~gateways ~netmask ~parent_logger srv_ip "srv" in
    (* Now we need the repeater and the services: *)
    (* FIXME: instead of a Hub that forces us into having 2 IPs make a simple TRX directly, that inspects the protostack and if
     * the dest IP is gw_ip == src_iv then forward it to the host and if not forward it to the NAT. *)
    let hub = Hub.Repeater.make ~parent_logger 3 "hub" in
    Hub.Repeater.set_read hub 1 h.trx.dev.write ;
    h.trx.dev.set_read (Hub.Repeater.write hub 1) ;
    (* Connect the first iface of our router *)
    Hub.Repeater.set_read hub 2 router.ifaces.(0).trx.out.write ;
    router.ifaces.(0).trx.out.set_read (Hub.Repeater.write hub 2) ;
    (* The entrance of the hub (iface 0) is also the entrance of the whole TRX: *)
    let in_trx = { write = (fun bits -> Hub.Repeater.write hub 0 bits) ;
                   set_read = fun f -> Hub.Repeater.set_read hub 0 f } in
    (* Now prepare the services that will run on the host [h]: *)
    (* TODO: local named could serve the local names according to the dhcp
     * leases and hostname options *)
    (* [nameserver] is the nameserver for the gateway but the nameserver for the
     * local machines is the gateway itself: *)
    let mtu = router.ifaces.(0).eth.mtu
    and dns = srv_ip
    and dhcp_range =
        Option.default_delayed (fun () ->
            [ Enum.get_exn local_ips, Ip.Cidr.all1s_addr local_cidr ]
        ) dhcp_range in
    let dhcp_state =
        Dhcpd.State.make ~netmask ~broadcast ~gw:gw_ip ~mtu ~dns
                         ~parent_logger:h.trx.logger dhcp_range in
    (* TODO: register a callback when leasing/releasing that updates the dns lookup function *)
    Dhcpd.serve dhcp_state h.trx ;
    let dns_state = Named.State.make ~parent_logger:h.trx.logger (fun _ -> None) in (* Delegate everything to nameserver *)
    (* FIXME: revisit that! Here we want a table (state must not contain functions
     * because we want to be able to serialize them) *)
    Named.serve dns_state h.trx ;
    let trx =
        { ins = in_trx ;
          out = out_trx.out } in
    { trx ; logger = parent_logger ; dhcp_state ; dns_state ; nat_state }

(*$R make_gw
    (*Log.console_lvl := Log.Debug ;*)
    Clock.realtime := false ;
    let public_ip = Ip.Addr.of_string "80.82.17.127" in
    let gw_trx = make_gw public_ip (Ip.Cidr.of_string "192.168.0.0/16") in
    let gateways = Eth.[ State.gw_selector (), Some (Gateway.of_string "192.168.0.1") ] in
    let netmask = Ip.Addr.of_string "255.255.255.0" in
    let desktop : Host.t = Host.make_dhcp ~netmask ~gateways "desktop" in
    desktop.trx.dev.set_read gw_trx.trx.ins.write ;
    ignore (desktop.trx.dev.write <-= gw_trx.trx) ;
    let server_ip = Ip.Addr.of_string "42.43.44.45" in
    let server_eth = Eth.(TRX.make State.(make ~my_addresses:[ make_my_ip_address server_ip ] ())) in
    let src = ref None in
    let server_recv bits = (* check source IP is the public one (NATed) *)
        let ip = Ip.Pdu.unpack bits |> Result.get_ok in
        src := Some ip.Ip.Pdu.src in
    ignore (server_recv <-= server_eth) ;
    gw_trx.trx <==> server_eth ;
    Clock.delay (Clock.Interval.sec 10.) (fun () ->
        Log.(log desktop.trx.logger Debug (lazy "Sending UDP packet to server")) ;
        desktop.trx.udp_send (Host.IPv4 server_ip) (Udp.Port.o 80) empty_bitstring) () ;
    Clock.run false ;
    Clock.realtime := true ;
    assert_bool "Desktop was NATed" (!src = Some public_ip)
 *)
