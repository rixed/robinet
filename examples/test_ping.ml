(* vim:sw=4 ts=4 sts=4 expandtab
*)
(*
   Test that a host answer a ping
*)
open Batteries
open Bitstring
open Tools

let run () =
    let host_ip = Ip.Addr.random () and my_ip = Ip.Addr.random () in
    (* Build the stack *)
    let host = Host.make_static "test" (Eth.Addr.random ()) host_ip in
    let eth = Eth.TRX.make (Eth.Addr.random ()) Arp.HwProto.ip4 [ Ip.Addr.to_bitstring my_ip ] in
    let ip  = Ip.TRX.make my_ip host_ip Ip.Proto.icmp in
    (* save everything in a pcap *)
    let save = Pcap.save "/tmp/test_ping.pcap" in
    (* downlink *)
    ip.set_emit eth.Eth.TRX.trx.tx ;
    eth.Eth.TRX.trx.set_emit (fun bits -> save bits ; host.Host.rx bits) ;
    (* uplink *)
    host.Host.set_emit (fun bits -> save bits ; eth.Eth.TRX.trx.rx bits);
    eth.Eth.TRX.trx.set_recv ip.rx ;
    ip.set_recv (fun bits -> match Icmp.Pdu.unpack bits with
        | None -> error "Cannot decode echo reply"
        | Some { Icmp.Pdu.msg_type = msg_type ; Icmp.Pdu.payload = payload } ->
            assert (Icmp.MsgType.type_of msg_type = 0) ;
            assert (Icmp.MsgType.code_of msg_type = 0) ;
            (match payload with
                | Icmp.Pdu.Ids (id, seq, _) ->
                    Printf.printf "Got ICMP echo answer id=%d, seq=%d\n" id seq ;
                    assert (id = 42 && seq = 1)
                | _ -> error "Bad msg payload")) ;
    (* Send an echo request *)
    let req = Icmp.Pdu.make_echo_request 42 1 in
    ip.tx (Icmp.Pdu.pack req) ;
    Lwt.join [ Clock.run false ]

let main =
    Random.self_init () ;
    Lwt_main.run (Lwt.join [ run () ]) ;

