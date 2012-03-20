(* vim:sw=4 ts=4 sts=4 expandtab
  This test program performs an HTTP GET from an unknown IP and an unknown MAC addr,
  which is correct enough to get an actual response from the server.
*)
open Batteries
open Bitstring
open Tools

let iface = Pcap.openif "eth0" true "" 1800

let main =
    let src_ip_str  = ref "192.168.1.66"
    and src_eth_str = ref "12:34:56:78:9a:bc"
    and dst_ip_str  = ref "192.168.1.254"
    and gw_eth_str  = ref None
    and search      = ref "local"
    and names       = ref []
    in
    Arg.parse [ "-src-ip",  Arg.Set_string src_ip_str,  "IP to use as the client" ;
                "-src-mac", Arg.Set_string src_eth_str, "MAC to use as the client" ;
                "-dst-ip",  Arg.Set_string dst_ip_str,  "IP to send the request to (ie. name server)" ;
                "-gw",      Arg.String (fun gw -> gw_eth_str := Some (Eth.Mac (Eth.addr_of_string gw))), "Gateway MAC address" ]
              (fun name -> names := name :: !names)
              "Perform a DNS A query with faked addresses" ;
    Lwt_main.run (
        let emit bits = Pcap.inject iface (string_of_bitstring bits) in
        let host = Host.make_static "requester" ?gw:!gw_eth_str ~nameserver:(Ip.addr_of_string !dst_ip_str) ~search_sfx:!search (Eth.addr_of_string !src_eth_str) (Ip.addr_of_string !src_ip_str) in
        host.Host.set_emit emit ;
        let query = Lwt_list.iter_p (fun name ->
            lwt ips = host.Host.gethostbyname name in
            List.print (fun oc ip -> Printf.fprintf oc "%s\n" (Ip.string_of_addr ip)) stdout ips ;
            Lwt.return ()) !names in
        Lwt.choose [ query ;
                     Pcap.sniffer iface host.Host.rx ;
                     Clock.run () ]
    )


