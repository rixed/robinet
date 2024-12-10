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
open Batteries
open Tools

let iface = Pcap.openif "eth0"

let main =
    let src_ip  = ref "192.168.1.66"
    and netmask = ref "255.255.255.0"
    and src_eth = ref "12:34:56:78:9a:bc"
    and dst_ip  = ref "192.168.1.254"
    and gw      = ref ""
    and search  = ref "local"
    and names   = ref []
    in
    Arg.parse [ "-src-ip",  Arg.Set_string src_ip,  "IP to use as the client (default: "^ !src_ip ^")" ;
                "-netmask", Arg.Set_string netmask, "Client's netmask (default: "^ !netmask ^")" ;
                "-src-mac", Arg.Set_string src_eth, "MAC to use as the client (default: "^ !src_eth ^")" ;
                "-dst-ip",  Arg.Set_string dst_ip,  "IP to send the request to (ie. name server)" ;
                "-gw",      Arg.Set_string gw,      "Gateway MAC or IP address (optional)" ]
              (fun name -> names := name :: !names)
              "Perform a DNS A query with faked addresses" ;
    let emit bits =
        hexstring_of_bitstring bits |> Printf.printf "Injecting '%s'\n" ;
        Pcap.inject iface bits in
    let gateways =
        (if !gw = "" then None else Some (Eth.Gateway.of_string !gw)) |>
        Option.map (fun gw -> [ Eth.State.gw_selector (), Some gw ]) in
    let host : Host.t =
        Host.make_static ?gateways
                         ~nameserver:(Ip.Addr.of_string !dst_ip)
                         ~search_sfx:!search
                         ~mac:(Eth.Addr.of_string !src_eth)
                         ~netmask:(Ip.Addr.of_string !netmask)
                         (Ip.Addr.of_string !src_ip)
                         "requester" in
    host.trx.dev.set_read emit ;
    List.iter (Clock.asap (fun name ->
        host.trx.gethostbyname name (function
        | None -> ()
        | Some ips ->
            List.print (fun oc ip -> Printf.fprintf oc "%s\n" (Ip.Addr.to_dotted_string ip)) stdout ips))) !names ;
    ignore (Pcap.sniffer iface host.trx.dev.write) ;
    Clock.run false
