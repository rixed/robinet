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
open Dhcp

(** DHCP server *)

(** [serve host ips] listen on host DHCP port and allocate the
 * given ips to any requester. *)
let serve ?(port=Udp.Port.o 67) host ips =
    let rem_cidr = ref ips in
    let offers = BitHash.create 4 in
    let leases = BitHash.create 8 in
    let logger = Log.(make (Printf.sprintf "%s/Dhcpd" host.Host.logger.name) 50) in
    host.Host.udp_server port (fun udp ->
        udp.Udp.TRX.trx.ins.set_read (fun bits ->
            let src_port, dst_port = udp.Udp.TRX.get_ports () in
            match Pdu.unpack bits with
            | None ->
                Log.(log logger Debug (lazy "Not a DHCP message, ignoring"))
            | Some ({ Pdu.op = BootRequest ; Pdu.hlen = 6 ; _ } as dhcp)
              when dhcp.Pdu.htype = Arp.HwType.eth &&
                   dhcp.Pdu.msg_type = Some MsgType.discover ->
                Log.(log logger Debug (lazy (Printf.sprintf "Received a DHCP Discover from %s" (hexstring_of_bitstring dhcp.Pdu.chaddr)))) ;
                (match Enum.get !rem_cidr with
                | Some offered_ip ->
                    (* Add this entry to our ARP cache *)
                    host.Host.arp_set offered_ip (Some (Eth.Addr.o dhcp.Pdu.chaddr)) ;
                    (* Store the offer *before* spawning the responding thread *)
                    BitHash.replace offers dhcp.Pdu.chaddr offered_ip ;
                    (* Send the offer *)
                    Pdu.make_offer ~mac:(host.Host.get_mac ())
                                   ~xid:dhcp.Pdu.xid offered_ip
                                   dhcp.Pdu.client_id |>
                    Pdu.pack |>
                    (* We can't use 'udp.tx offer' since we have to force both IP and Eth dest addr *)
                    host.Host.udp_send (Host.IPv4 offered_ip)
                                       ~src_port
                                       dst_port
                | None ->
                    Log.(log logger Debug (lazy "No more unused IP, cannot make offer")))
            | Some ({ Pdu.op = BootRequest ; Pdu.hlen = 6 ; _ } as dhcp)
              when dhcp.Pdu.htype = Arp.HwType.eth &&
                   dhcp.Pdu.msg_type = Some MsgType.request ->
                Log.(log logger Debug (lazy (Printf.sprintf "Received a DHCP Request from %s" (hexstring_of_bitstring dhcp.Pdu.chaddr)))) ;
                (* Look for previous offers *)
                (match BitHash.find_option offers dhcp.Pdu.chaddr with
                | Some offered_ip ->
                    BitHash.remove offers dhcp.Pdu.chaddr ;
                    BitHash.replace leases dhcp.Pdu.chaddr offered_ip ;
                    Pdu.make_ack ~mac:(host.Host.get_mac ())
                                 ~xid:dhcp.Pdu.xid
                                 offered_ip dhcp.Pdu.client_id |>
                    Pdu.pack |>
                    host.Host.udp_send (Host.IPv4 offered_ip)
                                       ~src_port
                                       dst_port
                | None ->
                    Log.(log logger Warning (lazy (Printf.sprintf "I never offered anythin to %s (or I fogot about it)" (Eth.Addr.to_string (Eth.Addr.o dhcp.Pdu.chaddr))))) ;
                    (* ignore it *) ())
            (* TODO: handle release & decline *)
            | _ ->
                Log.(log logger Debug (lazy "Ignoring DHCP message"))))

(*$R serve
    Clock.realtime := false ;
    Log.console_lvl := Log.Debug ;
    let srv = Host.make_static "server" (Eth.Addr.random ()) (Ip.Addr.random ()) in
    let my_net = Ip.Cidr.random () in
    serve srv (Ip.Cidr.to_enum my_net) ;
    let clt = Host.make_dhcp "client" (Eth.Addr.random ()) in
    srv.Host.dev.set_read clt.Host.dev.write ;
    clt.Host.dev.set_read srv.Host.dev.write ;
    Clock.run false ;
    Clock.realtime := true ;
    assert_bool "Client got an IP" (clt.Host.get_ip () <> None) ;
    assert_bool "IP is within net" (Ip.Cidr.mem my_net (Option.get (clt.Host.get_ip ())))
 *)
