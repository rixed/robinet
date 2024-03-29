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
   Small tool to load a web server by creating a herd of virtual hosts browsing randomly
   from a given URL.
*)
open Batteries
open Tools

let run ifname src_range nb_srcs ?gw ?search_sfx ?nameserver ?pause max_depth start_url =
    (* Build the hosts *)
    let mac_of_ip ip = (*Eth.addr_of_string "00:26:5e:0a:d2:b9" in*)
        let bs = Ip.Addr.to_bitstring ip in
        let%bitstring b = {| 0x1234 : 16 ; bs : 32 : bitstring |} in
        Eth.Addr.o b in
    let netmask = Ip.Cidr.to_netmask src_range in
    let host_of_ip ip =
        Host.make_static ~on:true (Ip.Addr.to_dotted_string ip) ?gw ?search_sfx ?nameserver ~netmask (mac_of_ip ip) ip in
    let hosts = List.of_enum (Ip.Cidr.random_addrs src_range nb_srcs /@ host_of_ip)
    in
    (* Build the HUB and link it to hosts *)
    let hub     = Hub.Repeater.make (nb_srcs+1) "hub"
    and gigabit = Eth.limited (Clock.Interval.msec 10.) 1_000_000_000. in
    List.iteri (fun i h ->
        (* notice that the cable is not full duplex *)
        h.Host.dev.set_read (gigabit (Hub.Repeater.write i hub)) ;
        Hub.Repeater.set_read i hub (gigabit h.Host.dev.write)
    ) hosts ;
    (* Link all these to the real world *)
    let iface = Pcap.openif ifname in
    Hub.Repeater.set_read nb_srcs hub (Pcap.inject iface) ;
    (* Start the browsers *)
    List.iter (fun h ->
        let browser = Browser.make h in
        match pause with
        | Some pause -> Browser.user browser ~pause:pause max_depth (Url.of_string start_url)
        | None       -> Browser.spider browser max_depth (Url.of_string start_url)) hosts ;
    (* Prepare a timeout in 15s *)
    Clock.delay (Clock.Interval.sec 15.) failwith "timeout" ;
    (* Run everything *)
    ignore (Pcap.sniffer iface (Hub.Repeater.write nb_srcs hub)) ;
    Clock.run false

let main =
    let ifname        = ref "eth0"
    and src_range_str = ref "192.168.0.0/16"
    and nb_srcs       = ref 1
    and gw_str        = ref None
    and search_sfx    = ref None
    and dns_str       = ref None
    and start_url     = ref "http://www.google.com"
    and max_depth     = ref 5
    and pause         = ref None
    in
    Arg.parse [ "-i",      Arg.Set_string ifname, "Interface to inject traffic to (default: eth0)" ;
                "-cidr",   Arg.Set_string src_range_str, "IP range (CIDR) for the HTTP clients (default: 192.168.0.0/16)" ;
                "-n",      Arg.Set_int nb_srcs, "How many clients to create (default: 1)" ;
                "-search", Arg.String (fun sfx -> search_sfx := Some sfx), "DNS search suffix" ;
                "-gw",     Arg.String (fun str -> gw_str := Some str), "optional gateway IP address" ;
                "-dns",    Arg.String (fun str -> dns_str := Some str), "optional IP of the DNS (default: same as gw)" ;
                "-url",    Arg.Set_string start_url, "Url to start spiding from (default: http://www.google.com)" ;
                "-depth",  Arg.Set_int max_depth, "Max depth (default: 5)" ;
                "-pause",  Arg.Float (fun p -> pause := Some p), "instead of swallowing the web, simulate a user with this average think time" ]
              (fun _ -> raise (Arg.Bad "unknown parameter"))
              "Load an HTTP server by simulating browsing" ;
    if !dns_str = None && !gw_str <> None then dns_str := !gw_str ;
    Random.self_init () ;
    let gw  = Option.map (fun gw -> [ Ip.Addr.zero, Ip.Addr.zero,
                                      Some (Eth.gw_addr_of_string gw) ]) !gw_str
    and nameserver = Option.map (fun ip -> Ip.Addr.of_string ip) !dns_str in
    ignore (Metric.report_thread stdout 10.) ;
    run !ifname (Ip.Cidr.of_string !src_range_str) !nb_srcs
                ?gw ?search_sfx:!search_sfx ?nameserver ?pause:!pause !max_depth !start_url

