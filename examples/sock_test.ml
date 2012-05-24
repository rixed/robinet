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
  This test program test communications between two hosts
*)
open Bitstring
open Tools

let server_f _h tcp bits =
    Printf.printf "Server received '%s'\n" (string_of_bitstring bits) ;
    if bitstring_length bits > 0 then
        tx tcp.Tcp.TRX.trx bits  (* echo *)
    else (
        Printf.printf "Closing\n" ;
        tcp.Tcp.TRX.close ()
    )

let run () =
    let h1 = Host.make_static "server"
                              (Eth.Addr.of_string "12:34:56:78:90:ab")
                              (Ip.Addr.of_string "192.168.0.1")
    and h2 = Host.make_static "client"
                              (Eth.Addr.of_string "ab:cd:ef:01:23:45")
                              (Ip.Addr.of_string "192.168.0.2")
    and hub = Hub.Repeater.make 3
    in
    let gigabit = Eth.limited (Clock.Interval.msec 1.) 1_000_000_000. in
    h1.Host.dev.set_read (gigabit (Hub.Repeater.rx 0 hub)) ;
    Hub.Repeater.set_emit 0 hub (gigabit h1.Host.dev.write) ;
    h2.Host.dev.set_read (gigabit (Hub.Repeater.rx 1 hub)) ;
    Hub.Repeater.set_emit 1 hub (gigabit h2.Host.dev.write) ;
    (* Save everything into sock_test.pcap *)
    Hub.Repeater.set_emit 2 hub (Pcap.save "sock_test.pcap") ;
    (* Start a server on h1 *)
    h1.Host.tcp_server (Tcp.Port.o 7) (fun tcp -> tcp.Tcp.TRX.trx.ins.set_read (server_f h1 tcp)) ;
    (* Client connects and write a msg *)
    let client_f tcp bits =
        Printf.printf "Client received '%s'\n" (string_of_bitstring bits) ;
        if bitstring_length bits > 0 then
            tcp.Tcp.TRX.close ()
        else (
            Printf.printf "Received unexpected close\n%!" ;
            assert false
        )
    in
    lwt tcp = h2.Host.tcp_connect (Host.IPv4 (Ip.Addr.of_string "192.168.0.1")) (Tcp.Port.o 7) in
    tcp.Tcp.TRX.trx.ins.set_read (client_f tcp) ;
    tx tcp.Tcp.TRX.trx (bitstring_of_string "Hello world!") ;
    Lwt.return ()

let main =
    Lwt_main.run (run ())
