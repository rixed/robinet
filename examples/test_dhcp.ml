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

let run sim iface =
    let netmask = Ip.Addr.of_string "255.255.255.0" in (* FIXME in make_dhcp *)
    let host = Host.make_dhcp ~parent:sim.Simulation.root ~mac:(Eth.Addr.of_string "00:23:8b:5f:09:c1") ~netmask "tester" in
    host.trx.dev.set_read (Pcap.inject iface) ;
    Pcap.sniffer iface host.trx.dev.write

let main =
    (* Everything this program does happens in this simulation. *)
    let sim = Simulation.make "test_dhcp" in
    Random.self_init () ;
    let ifname = "eth0" in
    let widget = Widget.make ~parent:sim.root ifname in
    let iface = Pcap.openif ~widget ifname in
    ignore (run sim iface) ;
    Simulation.run sim true
