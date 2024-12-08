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
open Tools
open Dhcp

(** DHCP server *)

(* Return a list in the same order as the request_list:
 * The client MAY list the options in order of preference.  The DHCP
 * server is not required to return the options in the requested order,
 * but MUST try to insert the requested options in the order requested
 * by the client. *)
let get_options host_parameters mandatory_parameters request_list =
    String.fold_right (fun c opts ->
        let c = int_of_char c in
        match List.find (fun (code, _) -> code = c) host_parameters with
        | exception Not_found -> opts
        | opt -> opt :: opts
    ) (request_list |? "") [] |>
    List.rev_append mandatory_parameters

(** [serve host ips] listen on host DHCP port and allocate the
 * given ips to any requester. *)
let serve ?(port=Udp.Port.o 67) (host : Host.host_trx)
          ?(lease_time_sec=3600) ?netmask ?broadcast ?gw ?mtu ?dns ?ntp ips =
    (* Build host_parameters according to given host: *)
    let rem_cidr = ref ips in
    let mandatory_parameters =
        [ Dhcp.Option.lease_time, bitstring_of_int32 lease_time_sec ] in
    let host_parameters =
        let add opt_val code enc lst =
            match opt_val with
            | None -> lst
            | Some v -> (code, enc v) :: lst in
        let open Dhcp.Option in
        mandatory_parameters |>
        add netmask subnet_mask Ip.Addr.to_bitstring |>
        add gw routers Ip.Addr.to_bitstring |>
        add broadcast broadcast_address Ip.Addr.to_bitstring |>
        add dns name_servers Ip.Addr.to_bitstring |>
        add mtu interface_mtu bitstring_of_int16 |>
        add ntp time_servers Ip.Addr.to_bitstring in
    let get_options = get_options host_parameters mandatory_parameters in
    (* Offered IPs (and options), indexed by client-ids: *)
    let offers = Hashtbl.create 8 in
    let leases = BitHash.create 8 in
    let logger = Log.sub host.logger "dhcpd" in
    Log.(log logger Debug (lazy "Listening for requests...")) ;
    host.Host.udp_server port (fun udp ->
        udp.Udp.TRX.trx.ins.set_read (fun bits ->
            Log.(log logger Debug (lazy "Received an UDP packet...")) ;
            let src_port, dst_port = udp.Udp.TRX.get_ports () in
            match Pdu.unpack bits with
            | None ->
                Log.(log logger Debug (lazy "Not a DHCP message, ignoring"))
            | Some (Pdu.{ op = BootRequest ; htype ; hlen = 6 ; chaddr ; client_id ; _ } as dhcp)
              when dhcp.Pdu.htype = Arp.HwType.eth &&
                   dhcp.Pdu.msg_type = Some MsgType.discover ->
                Log.(log logger Debug (lazy (Printf.sprintf "Received a DHCP Discover from %s" (hexstring_of_bitstring dhcp.Pdu.chaddr)))) ;
                (match Enum.get !rem_cidr with
                | Some offered_ip ->
                    (* Add this entry to our ARP cache.
                     * FIXME: actually, shouldn't we wait for the ack, in case the offer is rejected!? *)
                    host.Host.arp_set offered_ip (Some (Eth.Addr.o dhcp.Pdu.chaddr)) ;
                    (* Store the offer *before* spawning the responding thread *)
                    let offer_key = Dhcp.Option.default_client_id ~htype chaddr in
                    Hashtbl.replace offers offer_key offered_ip ;
                    (* Send the offer *)
                    let options = get_options dhcp.request_list in
                    Log.(log logger Debug (lazy (Printf.sprintf "Offering IP %s to %s" (Ip.Addr.to_string offered_ip) (hexstring_of_bitstring dhcp.Pdu.chaddr)))) ;
                    Pdu.make_offer ~chaddr:(dhcp.chaddr) ~xid:dhcp.Pdu.xid ~options ?client_id offered_ip |>
                    Pdu.pack |>
                    (* We can't use 'udp.tx offer' since we have to force both IP and Eth dest addr *)
                    host.Host.udp_send (Host.IPv4 offered_ip)
                                       ~src_port
                                       dst_port
                | None ->
                    Log.(log logger Debug (lazy "No more unused IP, cannot make offer")))
            | Some (Pdu.{ op = BootRequest ; htype ; hlen = 6 ; chaddr ; xid ; client_id ; _ } as dhcp)
              when dhcp.Pdu.htype = Arp.HwType.eth &&
                   dhcp.Pdu.msg_type = Some MsgType.request ->
                Log.(log logger Debug (lazy (Printf.sprintf "Received a DHCP Request from %s" (hexstring_of_bitstring dhcp.Pdu.chaddr)))) ;
                (* Look for previous offers *)
                let offer_key = Dhcp.Option.default_client_id ~htype chaddr in
                (match Hashtbl.find_option offers offer_key with
                | Some offered_ip ->
                    Hashtbl.remove offers offer_key ;
                    BitHash.replace leases dhcp.Pdu.chaddr offered_ip ;
                    Log.(log logger Debug (lazy "ACKing it")) ;
                    let options = get_options dhcp.request_list in
                    Pdu.make_ack ~chaddr ~xid ?client_id ~options offered_ip |>
                    Pdu.pack |>
                    host.Host.udp_send (Host.IPv4 offered_ip)
                                       ~src_port
                                       dst_port
                | None ->
                    Log.(log logger Warning (lazy (Printf.sprintf "I never offered anything to %s (or I forgot about it)" (Eth.Addr.to_string (Eth.Addr.o dhcp.Pdu.chaddr))))) ;
                    (* ignore it *) ())
            (* TODO: handle release & decline *)
            | _ ->
                Log.(log logger Debug (lazy "Ignoring DHCP message"))))

(*$R serve
    Clock.realtime := false ;
    (*Log.console_lvl := Log.Debug ;*)
    let srv = Host.make_static "server" (Eth.Addr.random ()) (Ip.Addr.random ()) ~on:true ~netmask:Ip.Addr.all_ones in
    let my_net = Ip.Cidr.random () in
    serve srv (Ip.Cidr.enum my_net) ;
    let clt = Host.make_dhcp "client" (Eth.Addr.random ()) ~on:true ~netmask:Ip.Addr.all_ones in
    srv.Host.dev.set_read clt.Host.dev.write ;
    clt.Host.dev.set_read srv.Host.dev.write ;
    Clock.run false ;
    Clock.realtime := true ;
    assert_bool "Client got an IP" (clt.Host.get_ip () <> None) ;
    assert_bool "IP is within net" (Ip.Cidr.mem my_net (Option.get (clt.Host.get_ip ())))
 *)
