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
   Small HTTP server for tests
*)
open Batteries
open Tools

let run iface =
    let host = Host.make_dhcp "tester" (Eth.Addr.of_string "00:23:8b:5f:09:c1") in
    host.Host.dev.set_read (Pcap.inject iface) ;
    Pcap.sniffer iface host.Host.dev.write

let main =
    Random.self_init () ;
    let iface = Pcap.openif "eth0" in
    ignore (run iface) ;
    Clock.run true

