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
   This test program build a gateway that tunnel every received eth frame into an http tunnel
   to a given destination.
*)
open Batteries
open Bitstring
open Tools

let tunnel ifname tun_ip tun_mac gw search_sfx nameserver dst dst_port src_port =
    let iface = Pcap.openif ifname true "" 1800
    and host = Host.make_static "tun" ?gw ?search_sfx ?nameserver tun_mac tun_ip
    and http = Http.TRX.make [ "Content-Type", "tun/eth" ] in
    host.Host.dev.set_read (Pcap.inject_pdu iface) ;
    let connect_tunnel tcp =
        Printf.printf "Tunnel: We are now connected!\n%!" ;
        http =-> (tx tcp.Tcp.TRX.trx) ;
        tcp.Tcp.TRX.trx.ins.set_read (fun bits ->
            if bitstring_is_empty bits then (
                (* close the socket *)
                Printf.printf "Tunnel: The HTTP connection was closed\n%!" ;
                http =-> ignore ;
                rx http bits ;    (* signal the end of the socket to http parser *)
                tcp.Tcp.TRX.close ()
                (* TODO: if client, quit or reconnect *)
            ) else rx http bits) in
    (* Eveything written to http will be sent to designated target,
       and eveything received for this host on http will be read from http.
       Now we need to put this host's eth device in promiscuous mode, and tunnel in
       all frames that are not for us. *)
    (*let recv_promisc bits =
        Printf.printf "Tunnel: sending an eth frame into the HTTP tunnel\n%!" ;
        http.tx x
    in
     * FIXME: Non, set_promiscuous n'a rien à faire dans l'API du host.
     *        Non, un host n'a rien à faire ici. Il faut construire un http/tcp/ip/eth à la main
     *        et se connecter soit même en tcp etc !
     * host.Host.eth.Eth.TRX.set_promiscuous recv_promisc ; *)
    let recv_http bits =
        Printf.printf "Tunnel: Received an eth frame from the HTTP tunnel, injecting\n%!" ;
        (* to use our GW: Eth.TRX.tx host.Host.eth x *)
        Pcap.inject_pdu iface bits
    in
    ignore (recv_http <-= http) ;
    ignore (Pcap.sniffer iface host.Host.dev.write) ;
    (match dst with
        | Some addr ->
            host.Host.tcp_connect addr ?src_port dst_port (function
            | None -> ()
            | Some tcp ->
                connect_tunnel tcp)
        | None ->
            Printf.printf "Tunnel: Waiting for connections on port %s...\n%!" (Tcp.Port.to_string dst_port) ;
            host.Host.tcp_server dst_port connect_tunnel) ;
    Clock.run true

let main =
    let ifname      = ref "eth0"
    and tun_ip      = ref "192.168.1.66"
    and tun_mac     = ref "12:34:56:78:9a:bc"
    and gw          = ref None
    and search_sfx  = ref None
    and nameserver  = ref None
    and dst         = ref None
    and http_port   = ref 80
    and src_port    = ref None
    in
    Arg.parse [ "-i",         Arg.Set_string ifname,      "Interface name (optional, default eth0)" ;
                "-tun-ip",    Arg.Set_string tun_ip,      "Tunnel IP address (this end)" ;
                "-tun-mac",   Arg.Set_string tun_mac,     "Tunnel MAC address (this end ; optional, default random)" ;
                "-gw",        Arg.String (fun str -> gw := Some (Eth.IPv4 (Ip.Addr.of_string str))),
                                                          "Gateway IP address (optional)" ;
                "-search",    Arg.String (fun str -> search_sfx := Some str),
                                                          "DNS search suffix (optional)" ;
                "-dns",       Arg.String (fun str -> nameserver := Some (Ip.Addr.of_string str)),
                                                          "IP of the DNS (optional)" ;
                "-dst-ip",    Arg.String (fun str -> dst := Some (Host.Name str)),
                                                          "Other end IP address (will wait for connections if not set)" ;
                "-http-port", Arg.Set_int http_port,      "Destination port (optional, default: 80)" ;
                "-src-port",  Arg.Int (fun i -> src_port := Some (Tcp.Port.o i)),
                                                          "Source port (optional, default: random)" ]
              (fun _ -> raise (Arg.Bad "Unknown parameter"))
              "Tunnel traffic into HTTP" ;
    tunnel !ifname
           (Ip.Addr.of_string  !tun_ip)
           (Eth.Addr.of_string !tun_mac)
           !gw  !search_sfx !nameserver
           !dst (Tcp.Port.o !http_port)  !src_port
