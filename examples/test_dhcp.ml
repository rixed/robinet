(* vim:sw=4 ts=4 sts=4 expandtab
   Small HTTP server for tests
*)
open Batteries
open Bitstring
open Tools

let run iface =
    let host = Host.make_dhcp "tester" (Eth.addr_of_string "00:23:8b:5f:09:c1") in
    host.Host.set_emit (Pcap.inject_pdu iface) ;
    Pcap.sniffer iface host.Host.rx

let main =
    Random.self_init () ;
    let iface = Pcap.openif "eth0" true "" 1500 in
    Lwt_main.run (
        Lwt.join [ run iface ; Clock.run () ]
    )

