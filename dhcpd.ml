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
        { logger : Log.logger ; (* Should be: logger.state *)
          authoritative : bool ;
          lease_time_sec : int ;
          netmask : Ip.Addr.t option ;
          broadcast : Ip.Addr.t option ;
          gw : Ip.Addr.t option ;
          mtu : int option ;
          dns : Ip.Addr.t option ;
          ntp : Ip.Addr.t option ;
          (* The whole range available. Must deduce those leased: *)
          ip_range : Ip.Range.t ;
          (* The state updated by the service: *)
          offers : (string, Ip.Addr.t) Hashtbl.t ;
          leases : Lease.t BitHash.t ;
          mutable used_ips : Ip.Set.t ;
          (* Precomputed for the service: *)
          mandatory_parameters : (int * bitstring) list ;
          host_parameters : (int * bitstring) list }

    let make ?(authoritative=true) ?(lease_time_sec=3600) ?netmask ?broadcast
             ?gw ?mtu ?dns ?ntp ?(parent_logger=Log.default) ip_range =
        let logger = Log.sub parent_logger "dhcpd" in
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
            add dns domain_name_servers Ip.Addr.to_bitstring |>
            add mtu interface_mtu bitstring_of_int16 |>
            add ntp time_servers Ip.Addr.to_bitstring in
        (* Offered IPs (and options), indexed by client-ids: *)
        let offers = Hashtbl.create 8 in
        let leases = BitHash.create 8 in
        let used_ips = Ip.Set.empty in
        { logger ; authoritative ; lease_time_sec ;
          netmask ; broadcast ; gw ; mtu ; dns ; ntp ;
          ip_range ; offers ; leases ; used_ips ;
          mandatory_parameters ; host_parameters }

    (* Return a list in the same order as the request_list:
     * The client MAY list the options in order of preference.  The DHCP
     * server is not required to return the options in the requested order,
     * but MUST try to insert the requested options in the order requested
     * by the client. *)
    (* FIXME: instead of this, just add the min of lease_time_sec and the client's
     * requested lease_time! *)
    let get_options t request_list =
        String.fold_right (fun c opts ->
            let c = int_of_char c in
            match List.find (fun (code, _) -> code = c) t.host_parameters with
            | exception Not_found -> opts
            | opt -> opt :: opts
        ) (request_list |? "") [] |>
        List.rev_append t.mandatory_parameters

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
    let counter = Metric.Atomic.make ("hosts/"^ host.Host.name ^"/dhcpd/queries") in
    let count cmd =
        let params = Metric.(Params.make Param.[ "cmd", String cmd ]) in
        Metric.Atomic.fire ~params counter in
    (* Offered IPs (and options), indexed by client-ids: *)
    Log.(log st.logger Debug (lazy "Listening for requests...")) ;
    host.Host.udp_server port (fun udp ->
        udp.Udp.TRX.trx.ins.set_read (fun bits ->
            Log.(log st.logger Debug (lazy "Received an UDP packet...")) ;
            let src_port, dst_port = udp.Udp.TRX.get_ports () in
            match Pdu.unpack bits with
            | Error s ->
                Log.(log st.logger Debug (lazy ("Not DHCP: "^ Lazy.force s)))
            | Ok (Pdu.{ op = BootRequest ; htype ; hlen = 6 ; chaddr ; client_id ; _ } as dhcp)
              when dhcp.Pdu.htype = Arp.HwType.eth &&
                   dhcp.Pdu.msg_type = Some MsgType.discover ->
                Log.(log st.logger Debug (lazy (Printf.sprintf "Received a DHCP Discover from %s" (hexstring_of_bitstring chaddr)))) ;
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
                    let options = State.get_options st dhcp.request_list in
                    Log.(log st.logger Debug (lazy (Printf.sprintf "Offering IP %s to %s" (Ip.Addr.to_string offered_ip) (hexstring_of_bitstring chaddr)))) ;
                    Pdu.make_offer ~chaddr ~xid:dhcp.Pdu.xid ~options ?client_id offered_ip |>
                    Pdu.pack |>
                    (* We can't use 'udp.tx offer' since we have to force both IP and Eth dest addr *)
                    host.Host.udp_send (Host.IPv4 offered_ip) ~src_port dst_port
                | None ->
                    Log.(log st.logger Debug (lazy "No more unused IP, cannot make offer")))
            | Ok (Pdu.{ op = BootRequest ; htype ; hlen = 6 ; chaddr ; xid ; client_id ; requested_ip = Some requested_ip ; _ } as dhcp)
              when dhcp.Pdu.htype = Arp.HwType.eth &&
                   dhcp.Pdu.msg_type = Some MsgType.request ->
                Log.(log st.logger Debug (lazy (Printf.sprintf "Received a DHCP Request from %s" (hexstring_of_bitstring chaddr)))) ;
                (* Look for previous offers *)
                let offer_key = Dhcp.Option.default_client_id ~htype chaddr
                and now = now () in
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
                    BitHash.replace st.leases chaddr (Lease.make ~until offered_ip) ;
                    Log.(log st.logger Debug (lazy "ACKing it")) ;
                    count "ack" ;
                    let options = State.get_options st dhcp.request_list in
                    Pdu.make_ack ~chaddr ~xid ?client_id ~options offered_ip |>
                    Pdu.pack |>
                    host.Host.udp_send (Host.IPv4 offered_ip) ~src_port dst_port
                | _ ->
                    if st.authoritative then (
                        Log.(log st.logger Warning (lazy (Printf.sprintf "I never offered anything to %s (or I forgot about it). Denying since I'm in charge here." (Eth.Addr.to_string (Eth.Addr.o dhcp.Pdu.chaddr))))) ;
                        count "nack" ;
                        Pdu.make_nak ~chaddr ~xid ?client_id ~message:"go away" () |>
                        Pdu.pack |>
                        host.Host.udp_send (Host.IPv4 requested_ip) ~src_port dst_port
                        (* We could answer to the emitter with `udp.trx.ins.write`
                         * but it's likely a broadcast anyway. *)
                    ) else (
                        Log.(log st.logger Warning (lazy (Printf.sprintf "I never offered anything to %s (or I forgot about it). Leaving it to another dhcp server." (Eth.Addr.to_string (Eth.Addr.o dhcp.Pdu.chaddr))))) ;
                        count "no-authority"
                    ))
            (* TODO: handle release & decline *)
            | Ok (Pdu.{ msg_type = Some msg_type ; _ }) ->
                Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring DHCP %s" (Dhcp.MsgType.to_string msg_type)))) ;
                count "bad-type"
            | _ ->
                Log.(log st.logger Debug (lazy "Ignoring DHCP message")) ;
                count "err"))

(*$R serve
    Clock.realtime := false ;
    (*Log.console_lvl := Log.Debug ;*)
    let netmask = Ip.Addr.all_ones in
    let srv : Host.t = Host.make_static ~netmask (Ip.Addr.random ()) "server" in
    let my_net = Ip.Cidr.random () in
    let st = State.make (Ip.Range.of_cidr my_net) in
    serve st srv.trx ;
    let clt : Host.t = Host.make_dhcp ~netmask "client" in
    srv.trx.dev.set_read clt.trx.dev.write ;
    clt.trx.dev.set_read srv.trx.dev.write ;
    Clock.run false ;
    Clock.realtime := true ;
    assert_bool "Client got an IP" (Host.ip_is_set clt) ;
    assert_bool "IP is within net" (Eth.State.find_ip4 clt.eth_state |> Ip.Cidr.mem my_net)
 *)
