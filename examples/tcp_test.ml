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

let perform_get my_ip my_netmask mac peer_ip ?nameserver ?gw ifname url =
    let iface = Pcap.openif ifname in
    let get   = Printf.sprintf "GET %s HTTP/1.0\r\n\r\n" url in
    let host  = Host.make_static ?nameserver ?gw ~mac ~netmask:my_netmask my_ip "tester" in
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
    let src_ip  = ref "192.168.1.66"
    and netmask = ref "255.255.255.0"
    and src_eth = ref "12:34:56:78:9a:bc"
    and dst_ip  = ref "192.168.1.254"
    and gw_eth  = ref None
    and dns_ip  = ref None
    and ifname  = ref "eth0"
    and url     = ref "/Am/I/a/credible/request?"
    in
    Arg.parse [ "-src-ip",  Arg.Set_string src_ip,  "IP to use as the HTTP client (default: "^ !src_ip ^")" ;
                "-netmask", Arg.Set_string netmask, "Client's netmask (default: "^ !netmask ^")" ;
                "-src-mac", Arg.Set_string src_eth, "MAC to use as the HTTP client (default: "^ !src_eth ^")" ;
                "-dst-ip",  Arg.Set_string dst_ip,  "IP to send the HTTP GET to (default: "^ !dst_ip ^")" ;
                "-gw",      Arg.String (fun gw ->
                                            gw_eth := Some Eth.Gateway.[ make ~addr:(addr_of_string gw) () ]),
                                                    "Gateway MAC address (optional)" ;
                "-dns",     Arg.String (fun str -> dns_ip := Some (Ip.Addr.of_string str)), "IP of the DNS (optional)" ;
                "-i",       Arg.Set_string ifname,  "Interface to use (default: "^ !ifname ^")" ;
                "-url",     Arg.Set_string url,     "The URL to GET" ]
              (fun _ -> raise (Arg.Bad "Unknown parameter"))
              "Perform an HTTP get with faked addresses" ;
    perform_get (Ip.Addr.of_string !src_ip) (Ip.Addr.of_string !netmask)
                (Eth.Addr.of_string !src_eth)
                (Ip.Addr.of_string !dst_ip)
                ?nameserver:!dns_ip ?gw:!gw_eth
                !ifname !url
