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
open Batteries
open Bitstring

open Clock
open Tools
open Dhcp

(** DHCP server *)

module Lease =
struct
    type t =
        { hostname : string option ;
          ip : Ip.Addr.t ;
          until : Time.t }

    let make ?hostname ~until ip =
        { hostname ; ip ; until }
end

module State =
struct
    type t =
        { widget : Widget.t ;
          mutable authoritative : bool ;
          mutable lease_time_sec : int ;
          (* The network parameters served to clients. All editable, and
           * whatever writes one of them must set [parameters] back to [None];
           * see there. *)
          mutable netmask : Ip.Addr.t option ;
          mutable broadcast : Ip.Addr.t option ;
          mutable gw : Ip.Addr.t option ;
          mutable mtu : int option ;
          mutable dns : Ip.Addr.t option ;
          mutable domain_name : string option ;
          mutable ntp : Ip.Addr.t option ;
          (* The whole range available. Must deduce those leased: *)
          ip_range : Ip.Range.t ;
          (* The state updated by the service: *)
          offers : (string, Ip.Addr.t) Hashtbl.t ;
          (* Indexed by the client hardware address. Written through
           * [set_lease], which keeps [num_leases] in step with it. *)
          leases : Lease.t BitHash.t ;
          mutable used_ips : Ip.Set.t ;
          (* The options served to clients, which are built once and then kept
           * until something they are made of changes. Whatever writes such a
           * field -- [lease_time_sec] is the only mutable one so far -- must
           * set this back to [None], or the server would go on offering what
           * it no longer holds. *)
          mutable parameters : parameters option ;
          (* How many leases stand, as a metric rather than a plain count, so
           * that the interface can plot how the pool fills up. *)
          num_leases : Metric.Gauge.t ;
          queries : Metric.Atomic.t }

    (* The options every offer carries, and those a client may ask for (which
     * include the former). *)
    and parameters =
        { mandatory : (int * bitstring) list ;
          host : (int * bitstring) list }

    let make ?(authoritative=true) ?(lease_time_sec=3600) ?netmask ?broadcast
             ?gw ?mtu ?dns ?domain_name ?ntp ~parent ip_range =
        let widget = Widget.make ~parent "dhcpd" in
        (* Offered IPs (and options), indexed by client-ids: *)
        let offers = Hashtbl.create 8 in
        let leases = BitHash.create 8 in
        let used_ips = Ip.Set.empty in
        let queries = Metric.Atomic.make () in
        let num_leases = Metric.Gauge.make () in
        let t = {
            widget ; authoritative ; lease_time_sec ;
            netmask ; broadcast ; gw ; mtu ; dns ; domain_name ; ntp ;
            ip_range ; offers ; leases ; used_ips ;
            parameters = None ; num_leases ; queries } in
        (* Those options may have no value, which is what [`Null] says; an
         * empty string would be a value, and a nonsensical one at that. *)
        let json_of_ip_opt = function
            | None -> `Null
            | Some ip -> `String (Ip.Addr.to_string ip) in
        (* An address the server may or may not have one of to offer. It is one
         * of the options served, so setting it takes those away. *)
        let ip_property name ~descr get set =
            Widget.(property name ~kind:(optional (hint "1.2.3.4" String)) ~descr
                ~getter:(fun () -> json_of_ip_opt (get ()))
                ~setter:(fun v ->
                    set (to_option (Ip.Addr.of_json name) v) ;
                    t.parameters <- None)) in
        Widget.add_properties widget Widget.[
            property "authoritative" ~kind:Bool
                ~descr:"Is this server authoritative"
                ~getter:(fun () -> `Bool t.authoritative)
                ~setter:(fun v -> t.authoritative <- to_bool v) ;
            property "lease time" ~kind:(IRange (0, max_int)) ~units:"secs"
                ~descr:"Lease time for the offers"
                ~getter:(fun () -> `Int t.lease_time_sec)
                ~setter:(fun v ->
                    t.lease_time_sec <- to_int_range ~min:0 v ;
                    (* It is one of the options served: *)
                    t.parameters <- None) ;
            ip_property "netmask" ~descr:"Netmask of the served network"
                (fun () -> t.netmask) (fun v -> t.netmask <- v) ;
            ip_property "broadcast" ~descr:"Broadcast address of that network"
                (fun () -> t.broadcast) (fun v -> t.broadcast <- v) ;
            ip_property "gateway" ~descr:"Default route to offer"
                (fun () -> t.gw) (fun v -> t.gw <- v) ;
            ip_property "DNS" ~descr:"Name server to offer"
                (fun () -> t.dns) (fun v -> t.dns <- v) ;
            ip_property "NTP" ~descr:"Time server to offer"
                (fun () -> t.ntp) (fun v -> t.ntp <- v) ;
            property "domain name" ~kind:(optional (hint "example.com" String))
                ~descr:"Domain clients are to search names in"
                ~getter:(fun () -> json_of_optional (fun s -> `String s)
                                                    t.domain_name)
                ~setter:(fun v ->
                    t.domain_name <- to_option to_string v ;
                    (* It is one of the options served: *)
                    t.parameters <- None) ;
            (* Clients are told the MTU only when there is one to tell them
             * about, so this is the whole of [int option]: no value at all,
             * or one that must be a possible MTU. *)
            property "MTU" ~kind:(optional (IRange (68, 65535))) ~units:"bytes"
                ~descr:"Interface MTU to offer, if any"
                ~getter:(fun () ->
                    match t.mtu with None -> `Null | Some m -> `Int m)
                ~setter:(fun v ->
                    t.mtu <- to_option (to_int_range ~min:68 ~max:65535) v ;
                    (* It is one of the options served: *)
                    t.parameters <- None) ;
            (* Who holds what, which is the whole of what this server has
             * done. Read-only: a lease is not something to be written down
             * here but the outcome of an exchange with the client that holds
             * it. Ordered by address, so that a table read twice in a row
             * reads the same way. *)
            property "leases" ~descr:"The addresses currently leased"
                ~kind:(list (record [| "client", String ;
                                       "hostname", optional String ;
                                       "address", String ;
                                       "expires in (s)", Float |]))
                ~getter:(fun () ->
                    let now = Simulation.Widget.now t.widget in
                    BitHash.fold (fun chaddr (l : Lease.t) rows ->
                        (l.ip, chaddr, l) :: rows
                    ) t.leases [] |>
                    List.sort (fun (a, _, _) (b, _, _) -> Ip.Addr.compare a b) |>
                    List.map (fun (ip, chaddr, (l : Lease.t)) ->
                        `Assoc [
                            "client",
                                `String (Eth.Addr.to_hexstring
                                            (Eth.Addr.o chaddr)) ;
                            "hostname",
                                json_of_optional (fun n -> `String n)
                                                 l.Lease.hostname ;
                            "address", `String (Ip.Addr.to_dotted_string ip) ;
                            (* What is left of it, and not when it began: a
                             * date in simulated time means nothing to a
                             * reader, and a lease already over reads as the
                             * negative it is. *)
                            "expires in (s)",
                                `Float (Interval.to_secs
                                            (Time.diff l.Lease.until now)) ]) |>
                    (fun rows -> `List rows)) ;
            metric_property "leased addresses"
                ~descr:"Number of addresses currently leased"
                (Metric.Gauge.T t.num_leases) ;
            metric_property "queries" ~descr:"Count queries per status"
                (Metric.Atomic.T t.queries) ] ;
        t

    (* The options as they stand, built on the first ask after a change. *)
    let get_parameters t =
        match t.parameters with
        | Some p -> p
        | None ->
            let mandatory =
                [ Dhcp.Option.lease_time,
                  bitstring_of_int32 t.lease_time_sec ] in
            let host =
                let add opt_val code enc lst =
                    match opt_val with
                    | None -> lst
                    | Some v -> (code, enc v) :: lst in
                let open Dhcp.Option in
                mandatory |>
                add t.netmask subnet_mask Ip.Addr.to_bitstring |>
                add t.gw routers Ip.Addr.to_bitstring |>
                add t.broadcast broadcast_address Ip.Addr.to_bitstring |>
                add t.dns domain_name_servers Ip.Addr.to_bitstring |>
                add t.domain_name domain_name bitstring_of_string |>
                add t.mtu interface_mtu bitstring_of_int16 |>
                add t.ntp ntp_servers Ip.Addr.to_bitstring in
            let p = { mandatory ; host } in
            t.parameters <- Some p ;
            p

    (* Return a list in the same order as the request_list:
     * The client MAY list the options in order of preference.  The DHCP
     * server is not required to return the options in the requested order,
     * but MUST try to insert the requested options in the order requested
     * by the client. *)
    (* FIXME: instead of this, just add the min of lease_time_sec and the client's
     * requested lease_time! *)
    (* [host_name] is the name of the very client being answered, which is not
     * a parameter of the server but of that one exchange, and so is served
     * beside those. *)
    let get_options ?host_name t request_list =
        let parameters = get_parameters t in
        let servable =
            match host_name with
            | None -> parameters.host
            | Some n ->
                (Dhcp.Option.host_name, bitstring_of_string n) ::
                parameters.host in
        String.fold_right (fun c opts ->
            let c = int_of_char c in
            (* What is served in any case is served once: a client that asks
             * for the lease time must not be sent two of them. *)
            if List.mem_assoc c parameters.mandatory then opts else
            match List.find (fun (code, _) -> code = c) servable with
            | exception Not_found -> opts
            | opt -> opt :: opts
        ) (request_list |? "") [] |>
        List.rev_append parameters.mandatory

    (* The options served are built once and then kept, so anything that
       changes one of them has to say so: the lease time clients are offered
       must be the one that has been set. *)
    (*$< State *)
    (*$R get_options
        let sim = Simulation.make ~realtime:false "test-lease" in
        let st = make ~lease_time_sec:3600 ~parent:sim.root
                      (Ip.Range.of_cidr (Ip.Cidr.random ())) in
        let offered () =
            List.assoc Dhcp.Option.lease_time (get_options st None) in
        assert_bool "the lease time is offered as it was given"
            (Bitstring.equals (offered ()) (bitstring_of_int32 3600)) ;
        let set_lease_time =
            List.find (fun (p : Widget.property) -> p.Widget.name = "lease time")
                      st.widget.Widget.properties |>
            (fun p -> Option.get p.Widget.setter) in
        set_lease_time (`Int 60) ;
        assert_bool "and follows when it is changed"
            (Bitstring.equals (offered ()) (bitstring_of_int32 60)) ;
        (* Same for an option that may be there or not: asking for it when
           there is none must bring nothing back. *)
        let set_mtu =
            List.find (fun (p : Widget.property) -> p.Widget.name = "MTU")
                      st.widget.Widget.properties |>
            (fun p -> Option.get p.Widget.setter) in
        let mtu_asked () =
            let request = String.of_char (Char.chr Dhcp.Option.interface_mtu) in
            List.mem_assoc Dhcp.Option.interface_mtu (get_options st (Some request)) in
        assert_bool "an option that has no value is not served" (not (mtu_asked ())) ;
        set_mtu (`Int 1400) ;
        assert_bool "and is served once it has one" (mtu_asked ()) ;
        set_mtu `Null ;
        assert_bool "and stops being served when it loses it" (not (mtu_asked ()))
     *)
    (*$>*)

    (* Grant a lease, or renew one. Whatever writes [leases] goes through here,
     * so that the gauge and the table never disagree about what is held. *)
    let set_lease t chaddr lease =
        BitHash.replace t.leases chaddr lease ;
        let now = Simulation.Widget.now t.widget in
        Metric.Gauge.set ~now t.num_leases (BitHash.length t.leases)

    (* Returns the next unused IP from the range, and mark it as used: *)
    let get_free_ip t =
        Ip.Range.enum t.ip_range |>
        Enum.filter (fun ip -> not (Ip.Set.mem ip t.used_ips)) |>
        Enum.get |>
        option_tap (fun ip ->
            t.used_ips <- Ip.Set.add ip t.used_ips)
end

(** [serve host ips] listen on host DHCP port and allocate the
 * given ips to any requester. *)
let serve ?(port=Udp.Port.o 67) (st : State.t) (host : Host.host_trx) =
    let count cmd =
        let now = Simulation.Widget.now st.widget in
        let params = Metric.(Params.make Param.[ "cmd", String cmd ]) in
        Metric.Atomic.fire ~now ~params st.queries in
    (* Offered IPs (and options), indexed by client-ids: *)
    Log.(log st.widget.logger Debug (lazy "Listening for requests...")) ;
    host.Host.udp_server port (fun udp ->
        udp.Udp.TRX.trx.ins.set_read (fun bits ->
            Log.(log st.widget.logger Debug (lazy "Received an UDP packet...")) ;
            let src_port, dst_port = udp.Udp.TRX.get_ports () in
            match Pdu.unpack bits with
            | Error s ->
                Log.(log st.widget.logger Debug (lazy ("Not DHCP: "^ Lazy.force s)))
            | Ok (Pdu.{ op = BootRequest ; htype ; hlen = 6 ; chaddr ; client_id ; _ } as dhcp)
              when dhcp.Pdu.htype = Arp.HwType.eth &&
                   dhcp.Pdu.msg_type = Some MsgType.discover ->
                Log.(log st.widget.logger Debug (lazy (Printf.sprintf "Received a DHCP Discover from %s" (hexstring_of_bitstring chaddr)))) ;
                count "discover" ;
                (match State.get_free_ip st with
                | Some offered_ip ->
                    (* Add this entry to our ARP cache.
                     * FIXME: actually, shouldn't we wait for the ack, in case the
                     * offer is rejected? We could clean the ARP cache then. *)
                    host.Host.arp_set offered_ip (Some (Eth.Addr.o chaddr)) ;
                    (* Store the offer *before* spawning the responding thread *)
                    let offer_key = Dhcp.Option.default_client_id ~htype chaddr in
                    Hashtbl.replace st.offers offer_key offered_ip ;
                    (* Send the offer *)
                    let options =
                        State.get_options ?host_name:dhcp.host_name st
                                          dhcp.request_list in
                    Log.(log st.widget.logger Debug (lazy (Printf.sprintf "Offering IP %s to %s" (Ip.Addr.to_string offered_ip) (hexstring_of_bitstring chaddr)))) ;
                    Pdu.make_offer ~chaddr ~xid:dhcp.Pdu.xid ~options ?client_id offered_ip |>
                    Pdu.pack |>
                    (* We can't use 'udp.tx offer' since we have to force both IP and Eth dest addr *)
                    host.Host.udp_send (Host.IPv4 offered_ip) ~src_port dst_port
                | None ->
                    Log.(log st.widget.logger Debug (lazy "No more unused IP, cannot make offer")))
            | Ok (Pdu.{ op = BootRequest ; htype ; hlen = 6 ; chaddr ; xid ; client_id ; requested_ip = Some requested_ip ; _ } as dhcp)
              when dhcp.Pdu.htype = Arp.HwType.eth &&
                   dhcp.Pdu.msg_type = Some MsgType.request ->
                Log.(log st.widget.logger Debug (lazy (Printf.sprintf "Received a DHCP Request from %s" (hexstring_of_bitstring chaddr)))) ;
                (* Look for previous offers *)
                let offer_key = Dhcp.Option.default_client_id ~htype chaddr
                and now = Simulation.now (Simulation.of_widget st.widget) in
                let offered_ip =
                    Hashtbl.find_option st.offers offer_key |>
                    option_default_delayed_opt (fun () ->
                        match BitHash.find_option st.leases chaddr with
                        | Some lease when Time.is_after lease.Lease.until now ->
                                Some lease.ip
                        | _ -> None) in
                (match offered_ip with
                | Some offered_ip when requested_ip = offered_ip ->
                    Hashtbl.remove st.offers offer_key ;
                    let until = Time.add now (Interval.sec (float_of_int st.lease_time_sec)) in
                    (* TODO: clean [leases] from time to time! *)
                    (* TODO: mask that previous leased IP as free, if any: *)
                    (* The name is the client's own, which it gives with every
                     * request: the server keeps it so that whoever looks at
                     * the leases sees who holds them, and hands it back to
                     * clients that ask for it. *)
                    State.set_lease st chaddr
                        (Lease.make ?hostname:dhcp.host_name ~until offered_ip) ;
                    Log.(log st.widget.logger Debug (lazy "ACKing it")) ;
                    count "ack" ;
                    let options =
                        State.get_options ?host_name:dhcp.host_name st
                                          dhcp.request_list in
                    Pdu.make_ack ~chaddr ~xid ?client_id ~options offered_ip |>
                    Pdu.pack |>
                    host.Host.udp_send (Host.IPv4 offered_ip) ~src_port dst_port
                | _ ->
                    if st.authoritative then (
                        Log.(log st.widget.logger Warning (lazy (Printf.sprintf "I never offered anything to %s (or I forgot about it). Denying since I'm in charge here." (Eth.Addr.to_string (Eth.Addr.o dhcp.Pdu.chaddr))))) ;
                        count "nack" ;
                        Pdu.make_nak ~chaddr ~xid ?client_id ~message:"go away" () |>
                        Pdu.pack |>
                        host.Host.udp_send (Host.IPv4 requested_ip) ~src_port dst_port
                        (* We could answer to the emitter with `udp.trx.ins.write`
                         * but it's likely a broadcast anyway. *)
                    ) else (
                        Log.(log st.widget.logger Warning (lazy (Printf.sprintf "I never offered anything to %s (or I forgot about it). Leaving it to another dhcp server." (Eth.Addr.to_string (Eth.Addr.o dhcp.Pdu.chaddr))))) ;
                        count "no-authority"
                    ))
            (* TODO: handle release & decline *)
            (* TODO: handle intermediary renewal (Requests or preallocated IPs) *)
            | Ok (Pdu.{ msg_type = Some msg_type ; _ }) ->
                Log.(log st.widget.logger Debug (lazy (Printf.sprintf "Ignoring DHCP %s" (Dhcp.MsgType.to_string msg_type)))) ;
                count "bad-type"
            | _ ->
                Log.(log st.widget.logger Debug (lazy "Ignoring DHCP message")) ;
                count "err"))

(*$R serve
    let sim = Simulation.make ~realtime:false "test-dhcpd" in
    (*Log.console_lvl := Log.Debug ;*)
    let netmask = Ip.Addr.all_ones in
    let srv : Host.t = Host.make ~parent:sim.root ~netmask ~static_ip:(Ip.Addr.random ()) "server" in
    let my_net = Ip.Cidr.random () in
    let st = State.make ~parent:sim.root (Ip.Range.of_cidr my_net) in
    serve st srv.trx ;
    let clt : Host.t = Host.make ~parent:sim.root ~netmask "client" in
    srv.trx.dev.set_read clt.trx.dev.write ;
    clt.trx.dev.set_read srv.trx.dev.write ;
    Simulation.run sim false ;
    assert_bool "Client got an IP" (Host.ip_is_set clt) ;
    assert_bool "IP is within net" (Eth.State.find_ip4 clt.eth_state |> Ip.Cidr.mem my_net)
 *)

(* A host taken off its static address has to go and ask for one, and the
   address it is still holding at the moment it is told must not be what stops
   it: that address was granted by nobody. *)
(*$R serve
    let sim = Simulation.make ~realtime:false "test-dhcpd-reboot" in
    let netmask = Ip.Addr.all_ones in
    let srv : Host.t =
        Host.make ~parent:sim.root ~netmask ~static_ip:(Ip.Addr.random ())
                  "server" in
    (* A range the client's own address is not in, so that a lease is telling. *)
    let my_net = Ip.Cidr.of_string "192.168.42.0/24" in
    let st = State.make ~parent:sim.root (Ip.Range.of_cidr my_net) in
    serve st srv.trx ;
    let clt : Host.t =
        Host.make ~parent:sim.root ~netmask
                  ~static_ip:(Ip.Addr.of_string "10.99.99.99") "client" in
    srv.trx.dev.set_read clt.trx.dev.write ;
    clt.trx.dev.set_read srv.trx.dev.write ;
    assert_bool "the client starts on its static address"
        (Eth.State.find_ip4 clt.eth_state |> Ip.Addr.to_dotted_string
         = "10.99.99.99") ;
    let static_ip =
        List.find (fun (p : Widget.property) -> p.Widget.name = "static-ip")
                  clt.Host.trx.Host.widget.Widget.properties in
    (Option.get static_ip.Widget.setter) `Null ;
    clt.trx.power_off () ;
    clt.trx.power_on () ;
    Simulation.run sim false ;
    assert_bool "and is leased one after a reboot" (Host.ip_is_set clt) ;
    assert_bool "from the server's range"
        (Eth.State.find_ip4 clt.eth_state |> Ip.Cidr.mem my_net)
 *)

(* An address alone is not a configuration: the parameters the lease carries
   are the ones the client ends up running with, and it has to ask for them. *)
(*$R serve
    let sim = Simulation.make ~realtime:false "test-dhcpd-options" in
    let srv : Host.t =
        Host.make ~parent:sim.root ~netmask:Ip.Addr.all_ones
                  ~static_ip:(Ip.Addr.of_dotted_string "192.168.42.1")
                  "server" in
    let my_net = Ip.Cidr.of_string "192.168.42.0/24"
    and gw = Ip.Addr.of_dotted_string "192.168.42.254"
    and dns = Ip.Addr.of_dotted_string "192.168.42.53" in
    let st =
        State.make ~parent:sim.root
                   ~netmask:(Ip.Addr.of_dotted_string "255.255.255.0")
                   ~gw ~dns ~domain_name:"example.com"
                   (Ip.Range.of_cidr my_net) in
    serve st srv.trx ;
    (* No configuration of its own: all it runs with comes from the lease. *)
    let clt : Host.t = Host.make ~parent:sim.root "client" in
    srv.trx.dev.set_read clt.trx.dev.write ;
    clt.trx.dev.set_read srv.trx.dev.write ;
    Simulation.run sim false ;
    assert_bool "the client is leased an address" (Host.ip_is_set clt) ;
    assert_equal ~printer:identity "255.255.255.0"
        (Option.map_default Ip.Addr.to_dotted_string "none"
            (Host.cur_netmask clt)) ;
    assert_equal ~printer:identity "192.168.42.53"
        (Option.map_default Ip.Addr.to_dotted_string "none"
            (Host.cur_nameserver clt)) ;
    assert_equal ~printer:identity "example.com"
        (Host.cur_search_sfx clt |? "none") ;
    let default_route = Eth.State.gw_selector (), Some (Eth.Gateway.IPv4 gw) in
    let has_default_route () =
        List.mem default_route Eth.State.(clt.eth_state.gateways) in
    assert_bool "and a default route to the offered gateway"
        (has_default_route ()) ;
    (* The netmask reaches the adapter, and not merely the host: it is what
       tells apart a neighbour from something to send to that gateway. *)
    assert_bool "the adapter holds that netmask"
        (List.exists (fun (a : Eth.State.my_address) ->
            Bitstring.equals a.Eth.State.netmask
                (Ip.Addr.to_bitstring (Ip.Addr.of_dotted_string "255.255.255.0")))
            Eth.State.(clt.eth_state.my_addresses)) ;
    (* The name the client gave is the one the server knows it by, and the
       lease table is where a reader of the interface sees it. *)
    let lease = BitHash.find_option st.leases (clt.eth_state.Eth.State.mac :> bitstring) in
    assert_equal ~printer:identity "client"
        (Option.map_default (fun (l : Lease.t) -> l.Lease.hostname |? "none")
                            "no lease" lease) ;
    let prop name =
        List.find (fun (p : Widget.property) -> p.Widget.name = name)
                  st.widget.Widget.properties in
    (match (prop "leases").Widget.getter () with
    | `List [ `Assoc row ] ->
        assert_equal ~printer:identity "client"
            (match List.assoc "hostname" row with
            | `String n -> n | _ -> "none") ;
        assert_equal ~printer:identity
            (Ip.Addr.to_dotted_string (Eth.State.find_ip4 clt.eth_state))
            (match List.assoc "address" row with
            | `String a -> a | _ -> "none")
    | v ->
        assert_failure ("one lease, not "^ Yojson.Basic.to_string v)) ;
    (* And the gauge beside it is what a plot of the pool is drawn from. *)
    assert_equal ~printer:string_of_int 1
        (match (prop "leased addresses").Widget.getter () with
        | `Assoc l ->
            (match List.assoc "values" l with
            | `List [ `Assoc row ] ->
                (match List.assoc "value" row with
                | `Assoc v ->
                    (match List.assoc "current" v with `Int c -> c | _ -> -1)
                | _ -> -1)
            | _ -> -1)
        | _ -> -1) ;
    (* None of it outlives the power: a host coming back up is a host that has
       been granted nothing yet. *)
    clt.trx.power_off () ;
    assert_bool "the netmask goes with the power" (Host.cur_netmask clt = None) ;
    assert_bool "and so does the name server"
        (Host.cur_nameserver clt = None) ;
    assert_bool "and so does the default route" (not (has_default_route ()))
 *)
