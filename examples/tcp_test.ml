(* vim:sw=4 ts=4 sts=4 expandtab
  This test program performs an HTTP GET from an unknown IP and an unknown MAC addr,
  which is correct enough to get an actual response from the server.
*)
open Bitstring
open Tools

let perform_get my_ip my_mac peer_ip ?nameserver ?gw ifname url =
    let iface = Pcap.openif ifname true "" 1800 in
    let get   = Printf.sprintf "GET %s HTTP/1.0\r\n\r\n" url in
    let host  = Host.make_static "tester" ?nameserver ?gw my_mac my_ip in
    host.Host.set_emit (Pcap.inject_pdu iface) ;
    let run () =
        lwt tcp = host.Host.tcp_connect (Host.IPv4 peer_ip) 80 in
        tcp.Tcp.TRX.trx.set_recv (fun bits ->
            if bitstring_is_empty bits then tcp.Tcp.TRX.close ()) ;
        (* Send the get *)
        tcp.Tcp.TRX.trx.tx (bitstring_of_string get) ;
        let rec wait_close () =
            if tcp.Tcp.TRX.is_closed () then Lwt.return ()
            else
                lwt _ = Lwt_main.yield () in wait_close () in
        wait_close ()
    in
    Lwt.choose [ Pcap.sniffer iface host.Host.rx ;
                 Clock.run () ;
                 run () ]

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
                "-gw",      Arg.String (fun gw -> gw_eth_str := Some (Eth.Mac (Eth.addr_of_string gw))), "Gateway MAC address (optional)" ;
                "-dns",     Arg.String (fun str -> dns_ip := Some (Ip.addr_of_string str)), "IP of the DNS (optional)" ;
                "-i",       Arg.Set_string ifname,      "Interface to use (default: eth0)" ;
                "-url",     Arg.Set_string url,         "The URL to GET" ]
              (fun _ -> raise (Arg.Bad "Unknown parameter"))
              "Perform an HTTP get with faked addresses" ;
    Lwt_main.run (
        perform_get (Ip.addr_of_string !src_ip_str) (Eth.addr_of_string !src_eth_str)
                    (Ip.addr_of_string !dst_ip_str)
                    ?nameserver:!dns_ip ?gw:!gw_eth_str
                    !ifname !url
    )

