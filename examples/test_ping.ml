(* vim:sw=4 ts=4 sts=4 expandtab
*)
(*
   Test that a host answer a ping
*)
open Batteries
open Tools

let run () =
    let host_ip = Ip.Addr.random () and my_ip = Ip.Addr.random () in
    (* Build the stack *)
    let host = Host.make_static ~on:true ~netmask:Ip.Addr.all_ones "test" (Eth.Addr.random ()) host_ip in
    let eth_state = Eth.State.make ~my_addresses:[ Eth.State.make_my_ip_address my_ip ] ~parent_logger:host.Host.logger () in
    let eth = Eth.TRX.make eth_state in
    let ip  = Ip.TRX.make my_ip host_ip Ip.Proto.icmp host.Host.logger in
    (* What to do when receiving an ip pck *)
    let my_recv bits = match Icmp.Pdu.unpack bits with
        | None -> error "Cannot decode echo reply"
        | Some { Icmp.Pdu.msg_type = msg_type ; Icmp.Pdu.payload = payload } ->
            assert (Icmp.MsgType.type_of msg_type = 0) ;
            assert (Icmp.MsgType.code_of msg_type = 0) ;
            (match payload with
                | Icmp.Pdu.Ids (id, seq, _) ->
                    Printf.printf "Got ICMP echo answer id=%d, seq=%d\n" id seq ;
                    assert (id = 42 && seq = 1)
                | _ -> error "Bad msg payload") in
    (* Connect everything *)
    my_recv <-= ip ==> eth =-> host.Host.dev.write ;
    host.Host.dev.set_read (rx eth) ;
    (* Send an echo request *)
    let req = Icmp.Pdu.make_echo_request 42 1 in
    tx ip (Icmp.Pdu.pack req) ;
    Clock.run false

let main =
    Random.self_init () ;
    run ()

