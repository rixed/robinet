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
(** A gateway is a device with 2 Eth interfaces, with a public IP address
 * and a private network address, performing routing between these two,
 * NAT, DHCP and relaying DNS for the LAN.
 * The returned TRX is seen from the LAN (ie, tx for going out).
 * Internally, it's made of a 3 ifaces hub, with the dhcp/name server
 * attached to iface 1, the NATing router to iface 2, and the LAN to iface 0:
 *
 *          GW: 192.168.0.1
 *           /-----------\
 *    LAN -- :0 (demux)  2:--<:0-router-1:>-- NAT --- Internet
 *           \____ 1 ____/
 *                 |
 *                 |
 *            dhcpd/named (192.168.0.1, the same)
 *
 * One machine on the LAN, wearing one address: what is addressed to the
 * gateway itself goes to the server, what is passing through goes to the
 * router, and the demux is what tells them apart (see [Demux]). The LAN
 * cable negotiates with the router's LAN adapter, which is the adapter really
 * behind that socket.
 *)
open Batteries
open SimTypes

open Bitstring
open Tools
module Nat = Ip_nat


(* What joins a gateway's parts, where a repeater used to be.
 *
 * A gateway is one machine on its LAN -- one address, one hardware address --
 * and two things inside it wear them: the router, which forwards what is
 * merely passing through, and the server, which answers the DHCP and DNS
 * addressed to the gateway itself. What tells them apart is the frame, so
 * neither needs an address of its own to be reached by.
 *
 * No delay, no speed and no collisions: this is the inside of a box and not a
 * length of wire. *)
module Demux =
struct
    type t = {
        (* The gateway's own addresses, which the router and the server share. *)
        mac : Eth.Addr.t ;
        ip : Ip.Addr.t ;
        (* What counts as sent to everyone rather than to the gateway. *)
        lan : Ip.Cidr.t ;
        bcast : Ip.Addr.t ;
        logger : Log.t ;
        (* Where the three ways out go. [to_lan] is set when a cable lands. *)
        mutable to_lan : bitstring -> unit ;
        mutable to_srv : bitstring -> unit ;
        mutable to_router : bitstring -> unit ;
        mutable lan_connected : bool }

    let make ~mac ~ip ~lan ~bcast ~logger =
        { mac ; ip ; lan ; bcast ; logger ;
          to_lan = ignore ; to_srv = ignore ; to_router = ignore ;
          lan_connected = false }

    let log t what where =
        Log.(log t.logger Debug (lazy (what ^" -> "^ where)))

    (* The IPv4 destination of [bits], when it has one. *)
    let ipv4_dst (frame : Eth.Pdu.t) =
        if frame.proto <> Eth.Proto.ip4 then None
        else
            match Ip.Pdu.unpack (frame.payload :> bitstring) with
            | Ok ip -> Some ip.Ip.Pdu.dst
            | Error _ -> None

    (* Addressed to everyone rather than to anyone. *)
    let is_bcast t (d : Ip.Addr.t) =
        d = Ip.Addr.broadcast || d = t.bcast

    (* From the LAN. What is for the gateway itself is the server's, and the
     * rest the router's -- including ARP, which the router answers for the
     * address they share. A frame addressed to some other machine is none of
     * our business. *)
    let from_lan t bits =
        match Eth.Pdu.unpack bits with
        | Error _ ->
            log t "Unparseable frame" "dropped"
        | Ok frame ->
            (* [eq] and not [=]: an address is a bitstring, and two of them
               with the same bytes at different offsets are not structurally
               equal. *)
            if not (Eth.Addr.is_broadcast frame.dst ||
                    Eth.Addr.eq frame.dst t.mac) then
                log t "Frame for someone else" "dropped"
            else
                match ipv4_dst frame with
                | Some d when d = t.ip || is_bcast t d ->
                    log t "For the gateway itself" "server" ;
                    t.to_srv bits
                | _ ->
                    log t "Passing through" "router" ;
                    t.to_router bits

    (* From the server: out to the LAN, unless it is talking to the world --
     * resolving a name it was asked for -- in which case the router is what
     * gets it there. *)
    let from_srv t bits =
        let out =
            match Eth.Pdu.unpack bits with
            | Error _ -> `Lan
            | Ok frame ->
                (match ipv4_dst frame with
                | None -> `Lan
                | Some d ->
                    if is_bcast t d || Ip.Cidr.mem t.lan d then `Lan
                    else `Router) in
        match out with
        | `Lan -> log t "From the server" "LAN" ; t.to_lan bits
        | `Router -> log t "From the server, outward" "router" ; t.to_router bits

    (* From the router: out to the LAN, unless it is what the server asked the
     * world for, which comes back addressed to the gateway. *)
    let from_router t bits =
        let for_srv =
            match Eth.Pdu.unpack bits with
            | Error _ -> false
            | Ok frame ->
                (match ipv4_dst frame with
                | Some d -> d = t.ip
                | None -> false) in
        if for_srv then (
            log t "Answer for the gateway itself" "server" ;
            t.to_srv bits
        ) else (
            log t "From the router" "LAN" ;
            t.to_lan bits
        )

    (* The LAN socket, as something a cable plugs into. *)
    let lan_dev t =
        { write = from_lan t ;
          set_read = (fun f -> t.to_lan <- f ; t.lan_connected <- true) }

    let disconnect t =
        if t.lan_connected then (
            t.to_lan <- ignore ;
            t.lan_connected <- false
        ) else
            Log.(log t.logger Debug (lazy
                "Ignoring request to unplug a LAN socket with nothing on it"))
end

type t =
    { trx : trx ;
      widget : Widget.t ;
      mutable dhcp_state : Dhcpd.State.t option ;
      mutable dns_state : Named.State.t option ;
      nat_state : Nat.State.t }

type Widget.device += T of t

(* The gateway a widget stands for, when it stands for one. *)
let of_widget (w : Widget.t) =
    match w.device with
    | Some (T t) -> Some t
    | _ -> None

(* Returns a [gw_trx] that gives access to the dhcpd leases, the named zones
 * and the NAT tables.
 * Unless [dhcp_range] is set, all local IPs (but those used by the GW itself)
 * will be distributed via DHCP. *)
let make ?delay ?loss ?mtu ?(num_max_cnxs=500) ?nameserver
         ?dhcp_range ?dhcp_mtu ?lease_time_sec ?mac
         ?(name="gw") ?notify_errs ?admin_reroute
         ~parent ?location ?(own_power=true)
         ?public_netmask ?public_gw ?port_forwards public_ip local_cidr =
    (* We want all parts inherit this widget: *)
    let widget = Widget.make ~parent ?location ~own_power name in
    (* A whole machine, whatever it is made of inside. *)
    widget.device_type <- Some "gateway" ;
    let local_ips = Ip.Cidr.local_addrs local_cidr in
    let netmask = Ip.Cidr.to_netmask local_cidr in
    let broadcast = Ip.Cidr.all1s_addr local_cidr in
    (* Build the output router *)
    let router =
        Router.(make ~parent:widget ~own_power:false ?delay ?loss ?mtu ?notify_errs
                     ?admin_reroute ?macs:(Option.map (Array.make 1) mac) 2
            [ (* route everything from anywhere to LAN if dest fits local_cidr *)
              Route.forward ~dst_mask:local_cidr 0 ;
              (* or zero IP address *)
              Route.forward ~src_mask:(Ip.Cidr.single Ip.Addr.zero) 0 ;
              (* route everything else toward the outside *)
              Route.forward ?via:public_gw 1 ]
            "router") in
    (* Configure those 2 ifaces: *)
    (* 1st iface is for the GW: *)
    let gw_mac = router.ifaces.(0).eth.mac in
    let gw_ip = Enum.get_exn local_ips in   (* first IP of the subnet is the GW *)
    Eth.State.add_ip4 router.ifaces.(0).eth ~netmask gw_ip ;
    (* The second iface of our router (facing internet) is the NAT *)
    Eth.State.add_ip4 router.ifaces.(1).eth ?netmask:public_netmask public_ip ;
    let nat_state =
        Nat.State.make ~num_max_cnxs ~parent:widget ?port_forwards public_ip in
    let nat_trx = Nat.TRX.make nat_state in
    (* Which we pipe *before* the iface eth (NAT operates at the IP level): *)
    router.ifaces.(1).trx <- pipe nat_trx router.ifaces.(1).trx ;
    (* FIXME: if we had directly a "mutable read" function rather than a
     * set_reader, the pipe operator (and others) could do the right thing here: *)
    router.ifaces.(1).trx.ins.set_read (Router.route (Some 1) router) ;
    (* This iface will become the outside side of out global TRX: *)
    let out_trx = router.ifaces.(1).trx in
    (* Create the "host" that answers for the gateway. It wears the gateway's
     * own address and hardware address rather than a second pair: on the LAN
     * a gateway is one machine, and which of its two halves answers a frame is
     * settled inside (see [Demux]). Its gateway is the router beside it,
     * for the names it has to go and ask the world about. *)
    let h : Host.t =
        let gateways = [ Eth.State.gw_selector (), Some (Eth.Gateway.Mac gw_mac) ] in
        (* On the box's supply, which is switched off until the end of this
         * function: a host that is running does its boot-time configuration
         * then and there, and what it is to do once it has an address is hung
         * on it a few lines further down. *)
        Host.make ?nameserver ~gateways ~netmask ~static_ip:gw_ip ~mac:gw_mac
                  ~parent:widget ~own_power:false "srv" in
    (* Now what joins those parts, and the services: *)
    let demux =
        Demux.make ~mac:gw_mac ~ip:gw_ip ~lan:local_cidr ~bcast:broadcast
                      ~logger:widget.logger in
    demux.Demux.to_srv <- h.trx.dev.write ;
    h.trx.dev.set_read (Demux.from_srv demux) ;
    (* Connect the first iface of our router *)
    demux.Demux.to_router <- router.ifaces.(0).trx.out.write ;
    router.ifaces.(0).trx.out.set_read (Demux.from_router demux) ;
    (* Its LAN side is the entrance of the whole TRX: *)
    let in_trx = Demux.lan_dev demux in
    let trx =
        { ins = in_trx ;
          out = out_trx.out } in
    let gw =
        { trx ; widget ; dhcp_state = None ; dns_state = None ; nat_state } in
    (* Now prepare the services that will run on the host [h]: *)
    (* TODO: local named could serve the local names according to the dhcp
     * leases and hostname options *)
    (* [nameserver] is the nameserver for the gateway but the nameserver for the
     * local machines is the gateway itself: *)
    (* TODO: save this dhcp_range into the state, and make it an editable property
     * so that we can change the range and restart dhcpd. *)
    let dhcp_range =
        Option.default_delayed (fun () ->
            (* Default range: from first available IP to the all-ones: *)
            [ Enum.get_exn local_ips, Ip.Cidr.all1s_addr local_cidr ]
        ) dhcp_range in
    let start_dhcpd gw =
        (* Built afresh on every start, so that it takes up what the host's
         * configuration has become; the one it replaces goes with it, or a
         * gateway switched off and on again would grow another pair of parts
         * every time. *)
        Option.may (fun (st : Dhcpd.State.t) -> Simulation.remove_widget st.Dhcpd.State.widget)
                   gw.dhcp_state ;
        (* Get from the host what could be edited there (TODO: dhcp_mtu,
         * lease_time_sec etc could also be part of the config) *)
        let netmask = h.netmask in
        let st =
            Dhcpd.State.make
                ?netmask ~broadcast ~gw:gw_ip ?mtu:dhcp_mtu ~dns:gw_ip
                ?lease_time_sec ~parent:h.trx.widget dhcp_range in
        gw.dhcp_state <- Some st ;
        (* TODO: register a callback when leasing/releasing that updates the dns lookup function *)
        Dhcpd.serve st h.trx in
    let start_dns gw =
        Option.may (fun (st : Named.State.t) -> Simulation.remove_widget st.Named.State.widget)
                   gw.dns_state ;
        let st =
            Named.State.make ~parent:h.trx.widget (fun _ -> None) in (* Delegate everything to nameserver *)
        gw.dns_state <- Some st ;
        (* FIXME: revisit that! Here we want a table (state must not contain functions
         * because we want to be able to serialize them) *)
        Named.serve st h.trx in
    (* Make the host [h] start dhcpd and dns when it is powered on: *)
    h.trx.on_ip <- (fun _h -> start_dhcpd gw ; start_dns gw) :: h.trx.on_ip ;
    Widget.add_properties widget Widget.[
        property "nat-max-cnxs" ~kind:Int
            ~descr:"Max number of connections tracked by the NAT."
            ~getter:(fun () -> `Int num_max_cnxs) ] ;
    (* Two visible ports only: outside, inside. *)
    widget.ports <- Widget.{
        count = (fun () -> 2) ;
        is_connected = (function
            | 0 -> router.ifaces.(1).eth.iface.is_connected
            | _ -> demux.Demux.lan_connected) ;
        dev = (function 0 -> out_trx.out | _ -> in_trx) ;
        (* Either socket belongs to the router adapter behind it: the outward
           one to its second, the LAN one to its first. *)
        owner = (function
            | 0 -> (Router.ports router.ifaces.(1)).owner 0
            | _ -> (Router.ports router.ifaces.(0)).owner 0) ;
        disconnect = (function
            | 0 -> (Router.ports router.ifaces.(1)).disconnect 0
            | _ -> Demux.disconnect demux) ;
        (* The LAN cable settles with the router's first adapter, which is
           the one really behind that socket. *)
        get_capabilities = (fun ?peer -> function
            | 0 -> (Router.ports router.ifaces.(1)).get_capabilities ?peer 0
            | _ -> (Router.ports router.ifaces.(0)).get_capabilities ?peer 0) ;
        set_capabilities = (fun n c ->
            match n with
            | 0 -> (Router.ports router.ifaces.(1)).set_capabilities 0 c
            | _ ->
                (* Both adapters behind that socket, and not merely the one
                   that answered: they are the same machine, and one left
                   slower than the other is still busy with the frame before
                   when the next arrives, and drops it. *)
                (Router.ports router.ifaces.(0)).set_capabilities 0 c ;
                h.trx.widget.ports.set_capabilities 0 c) } ;
    widget.device <- Some (T gw) ;
    gw

(* A gateway serves DHCP from a host built inside it, which goes down and comes
 * back with the box. That has broken twice, in two different ways -- a load
 * that powered everything down and up again, and a switch that powered the
 * host off and never back on -- and neither was caught by anything here, since
 * nothing here asked the gateway for an address after switching it. This does.
 *)
(*$R make
    let sim = Simulation.make ~realtime:false "gw-dhcp" in
    let gw =
        make ~parent:sim.root
             (Ip.Addr.of_string "80.82.17.127")
             (Ip.Cidr.of_string "192.168.0.0/24") in
    (* No address of its own, so it asks for one. *)
    let client : Host.t = Host.make ~parent:sim.root "client" in
    client.Host.trx.Host.dev.set_read gw.trx.ins.write ;
    ignore (client.Host.trx.Host.dev.write <-= gw.trx) ;
    let address () =
        match Eth.State.find_ip4 client.Host.eth_state with
        | exception Not_found -> "none"
        | ip -> Ip.Addr.to_dotted_string ip in
    Simulation.run sim false ;
    assert_bool ("a client on the LAN is leased an address, not "^ address ())
                (address () <> "none") ;
    (* The box off and on again, which takes its server with it both ways. *)
    let flip (w : Widget.t) on =
        (if on then Simulation.power_up else Simulation.power_down)
            w.power in
    flip gw.widget false ;
    flip gw.widget true ;
    (* And a client that asks afterwards has to be answered. It is rebooted
       rather than believed: the address it holds is one it was granted before
       any of this. *)
    flip client.Host.trx.Host.widget false ;
    assert_equal ~printer:identity "none" (address ()) ;
    flip client.Host.trx.Host.widget true ;
    Simulation.run sim false ;
    assert_bool ("a client asking after the gateway was switched off and on \
                  again is leased one, not "^ address ())
                (address () <> "none")
 *)

(* A gateway is one machine on its LAN, at one address: what is addressed to
   that address the server answers, and what is merely passing through the
   router forwards -- both from the same client, over the same cable. *)
(*$R make
    let sim = Simulation.make ~realtime:false "gw-one-address" in
    let gw =
        make ~parent:sim.root
             (Ip.Addr.of_string "80.82.17.127")
             (Ip.Cidr.of_string "192.168.0.0/24") in
    (* Something out there to reach, wired to the gateway's public side. *)
    let far : Host.t =
        Host.make ~parent:sim.root ~netmask:Ip.Addr.zero
                  ~static_ip:(Ip.Addr.of_string "80.82.17.1") "far" in
    far.Host.trx.Host.dev.set_read gw.trx.out.write ;
    gw.trx.out.set_read far.Host.trx.Host.dev.write ;
    (* No address of its own, so it asks the gateway for one. *)
    let client : Host.t = Host.make ~parent:sim.root "client" in
    client.Host.trx.Host.dev.set_read gw.trx.ins.write ;
    ignore (client.Host.trx.Host.dev.write <-= gw.trx) ;
    Simulation.run sim false ;
    (* The address it was handed is the one right after the gateway's own: no
       second address is taken for a server any more. *)
    assert_equal ~printer:identity ~msg:"the pool starts right after the gateway"
        "192.168.0.2"
        (Ip.Addr.to_dotted_string (Eth.State.find_ip4 client.Host.eth_state)) ;
    (* Ping through the same socket and count what comes back. *)
    let ping id dst =
        let replies = ref 0 in
        Hashtbl.replace client.Host.echo_waiters id (fun _seq -> incr replies) ;
        client.Host.trx.Host.ping ~id ~seq:1 (Host.IPv4 (Ip.Addr.of_string dst)) ;
        Simulation.run sim false ;
        Hashtbl.remove client.Host.echo_waiters id ;
        !replies in
    assert_equal ~printer:string_of_int
        ~msg:"the gateway answers at its own LAN address" 1
        (ping 1 "192.168.0.1") ;
    assert_equal ~printer:string_of_int
        ~msg:"and still routes what is only passing through" 1
        (ping 2 "80.82.17.1")
 *)

(* And the two halves are not sealed off from each other: a name the server
   cannot answer for it goes and asks the world about, which means out through
   the router beside it and back again -- the answer arriving addressed to the
   gateway, as the question left it. *)
(*$R make
    let sim = Simulation.make ~realtime:false "gw-resolves" in
    let far_ip = Ip.Addr.of_string "80.82.17.1" in
    let gw =
        make ~parent:sim.root ~nameserver:far_ip
             (Ip.Addr.of_string "80.82.17.127")
             (Ip.Cidr.of_string "192.168.0.0/24") in
    (* The only nameserver in the world, out beyond the gateway. *)
    let far : Host.t =
        Host.make ~parent:sim.root ~netmask:Ip.Addr.zero ~static_ip:far_ip
                  "far" in
    Named.serve
        (Named.State.make ~parent:sim.root (function
            | "popo" -> Some (Ip.Addr.of_string "1.2.3.4")
            | _ -> None))
        far.Host.trx ;
    far.Host.trx.Host.dev.set_read gw.trx.out.write ;
    gw.trx.out.set_read far.Host.trx.Host.dev.write ;
    let client : Host.t = Host.make ~parent:sim.root "client" in
    client.Host.trx.Host.dev.set_read gw.trx.ins.write ;
    ignore (client.Host.trx.Host.dev.write <-= gw.trx) ;
    Simulation.run sim false ;
    (* Asking the gateway, which is the nameserver its own lease named. *)
    let answer = ref "nothing came back" in
    client.Host.trx.Host.gethostbyname "popo" (fun ips ->
        answer :=
            match ips with
            | None | Some [] -> "no such host"
            | Some ips ->
                String.concat "," (List.map Ip.Addr.to_dotted_string ips)) ;
    Simulation.run sim false ;
    assert_equal ~printer:identity "1.2.3.4" !answer
 *)

(* What joins a gateway's parts is a backplane and not a segment of wire, so
   the LAN settles with the router's adapter and is not held to a repeater's
   10 or 100Mbps. The server's adapter is settled along with it: the three are
   one segment, and one of them left slower would drop what the others send. *)
(*$R make
    let sim = Simulation.make ~realtime:false "gw-lan-speed" in
    let gw =
        make ~parent:sim.root
             (Ip.Addr.of_dotted_string "80.82.17.127")
             (Ip.Cidr.of_string "192.168.0.0/24") in
    let h =
        Host.make ~parent:sim.root ~netmask:(Ip.Addr.of_string "255.255.255.0")
                  ~static_ip:(Ip.Addr.of_string "192.168.0.10") "h" in
    let cable = Eth.Cable.State.make ~parent:sim.root ~name:"lan" () in
    Eth.Cable.plug cable (gw.widget, 1) (h.Host.trx.Host.widget, 0) ;
    let link path =
        let w = Option.get (Widget.find_within gw.widget path) in
        match (List.find (fun (p : Widget.property) -> p.name = "link")
                         w.properties).getter () with
        | `String s -> s
        | _ -> "?" in
    let printer = identity in
    assert_equal ~printer ~msg:"the LAN adapter takes what the cable settled on"
        "5Gbps full-duplex" (link "router/#0") ;
    assert_equal ~printer ~msg:"and so does the server behind it"
        "5Gbps full-duplex" (link "srv/eth")
 *)

(* A gateway offers what a gateway has sockets for, and not one port per end
   that happens to exist within it: the router's two interfaces, the bus's three
   and the server's adapter are all spoken for inside. *)
(*$T make
  let sim = Simulation.make ~realtime:false "gw-ports" in \
  let gw = make ~parent:sim.root \
                (Ip.Addr.of_dotted_string "80.82.17.127") \
                (Ip.Cidr.of_string "192.168.0.0/16") in \
  gw.widget.ports.count () = 2 && \
  gw.widget.ports.dev 0 == gw.trx.out && \
  gw.widget.ports.dev 1 == gw.trx.ins && \
  (* Either socket belongs to the router adapter behind it, the bus joining
     the parts inside being no end of a link. *) \
  (gw.widget.ports.owner 0).name = "#1" && \
  (gw.widget.ports.owner 1).name = "#0" && \
  gw.widget.ports.owner 0 != gw.widget.ports.owner 1 && \
  List.for_all (fun (c : Widget.t) -> c.ports.count() <= 3) \
               gw.widget.children
 *)

(*$R make
    (*Log.console_lvl := Log.Debug ;*)
    let sim = Simulation.make ~realtime:false "test-gw" in
    let public_ip = Ip.Addr.of_string "80.82.17.127" in
    let gw_trx = make ~parent:sim.root public_ip (Ip.Cidr.of_string "192.168.0.0/16") in
    let gateways = Eth.[ State.gw_selector (), Some (Gateway.of_string "192.168.0.1") ] in
    let netmask = Ip.Addr.of_string "255.255.255.0" in
    let desktop : Host.t = Host.make ~parent:sim.root ~netmask ~gateways "desktop" in
    desktop.trx.dev.set_read gw_trx.trx.ins.write ;
    ignore (desktop.trx.dev.write <-= gw_trx.trx) ;
    let server_ip = Ip.Addr.of_string "42.43.44.45" in
    let server_eth = Eth.(TRX.make State.(make ~parent:sim.root ~power:sim.root.power ~my_addresses:[ make_my_ip_address server_ip ] ())) in
    let src = ref None in
    let server_recv bits = (* check source IP is the public one (NATed) *)
        let ip = Ip.Pdu.unpack bits |> Result.get_ok in
        src := Some ip.Ip.Pdu.src in
    ignore (server_recv <-= server_eth) ;
    gw_trx.trx <==> server_eth ;
    Simulation.delay sim.root.power (Clock.Interval.sec 10.) (fun () ->
        Log.(log desktop.trx.widget.logger Debug (lazy "Sending UDP packet to server")) ;
        desktop.trx.udp_send (Host.IPv4 server_ip) (Udp.Port.o 80) empty_bitstring) () ;
    Simulation.run sim false ;
    assert_bool "Desktop was NATed" (!src = Some public_ip)
 *)

