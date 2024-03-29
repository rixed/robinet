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
  This test program performs an HTTP GET from an unknown IP and an unknown MAC addr,
  which is correct enough to get an actual response from the server.
*)
open Bitstring
open Tools

let perform_get my_ip my_mac peer_ip ?nameserver ?gw ifname url =
    let iface = Pcap.openif ifname in
    let get   = Printf.sprintf "GET %s HTTP/1.0\r\n\r\n" url in
    let host  = Host.make_static ~on:true "tester" ?nameserver ?gw ~netmask:Ip.Addr.all_ones my_mac my_ip in
    host.Host.dev.set_read (Pcap.inject iface) ;
    ignore (Pcap.sniffer iface host.Host.dev.write) ;
    host.Host.tcp_connect (Host.IPv4 peer_ip) (Tcp.Port.o 80) (function
    | None -> ()
    | Some tcp ->
        tcp.Tcp.TRX.trx.ins.set_read (fun bits ->
            if bitstring_is_empty bits then tcp.Tcp.TRX.close ()) ;
        (* Send the get *)
        tx tcp.Tcp.TRX.trx (bitstring_of_string get) ;
        let rec wait_close () =
            if not (tcp.Tcp.TRX.is_closed ()) then
                Clock.delay (Clock.Interval.sec 1.) wait_close ()
            else (
                Printf.printf "We are done with the GET...\n" ;
                exit 0
            ) in
        wait_close ()) ;
    Clock.run false

let main =
    let src_ip_str  = ref "192.168.1.66"
    and src_eth_str = ref "12:34:56:78:9a:bc"
    and dst_ip_str  = ref "192.168.1.254"
    and gw_eth_str  = ref None
    and dns_ip      = ref None
    and ifname      = ref "eth0"
    and url         = ref "/Am/I/a/credible/request?"
    in
    Arg.parse [ "-src-ip",  Arg.Set_string src_ip_str,  "IP to use as the HTTP client (default: 192.168.1.66)" ;
                "-src-mac", Arg.Set_string src_eth_str, "MAC to use as the HTTP client (default: 12:34:56:78:9a:bc)" ;
                "-dst-ip",  Arg.Set_string dst_ip_str,  "IP to send the HTTP GET to (default: 192.168.1.254)" ;
                "-gw",      Arg.String (fun gw ->
                                            gw_eth_str := Some [ Ip.Addr.zero, Ip.Addr.zero,
                                                                 Some (Eth.gw_addr_of_string gw) ]),
                                                        "Gateway MAC address (optional)" ;
                "-dns",     Arg.String (fun str -> dns_ip := Some (Ip.Addr.of_string str)), "IP of the DNS (optional)" ;
                "-i",       Arg.Set_string ifname,      "Interface to use (default: eth0)" ;
                "-url",     Arg.Set_string url,         "The URL to GET" ]
              (fun _ -> raise (Arg.Bad "Unknown parameter"))
              "Perform an HTTP get with faked addresses" ;
    perform_get (Ip.Addr.of_string !src_ip_str) (Eth.Addr.of_string !src_eth_str)
                (Ip.Addr.of_string !dst_ip_str)
                ?nameserver:!dns_ip ?gw:!gw_eth_str
                !ifname !url

