(* vim:sw=4 ts=4 sts=4 expandtab
*)
open Bitstring

(* TODO: make this a parameter.
         make eth0 a command line arg *)
let iface = Pcap.openif "eth0" true "" 1800

let arp_query src_eth src_ip target_ip =
    let arp = Arp.Pdu.make_request Arp.hw_type_eth Eth.proto_ip4
                                   (Eth.bitstring_of_addr src_eth)
                                   ( Ip.bitstring_of_addr src_ip)
                                   ( Ip.bitstring_of_addr target_ip) in
    let eth = Eth.Pdu.make Eth.proto_arp src_eth Eth.addr_broadcast (Arp.Pdu.pack arp) in
    Pcap.inject iface (string_of_bitstring (Eth.Pdu.pack eth))

let rec wait_answer target_ip_bits =
    (* TODO: times out *)
    let rec aux () =
        let _ts, packet = Pcap.sniff iface in
        (match Eth.Pdu.unpack (bitstring_of_string packet) with
        | None -> failwith "Cannot unpack Eth"
        | Some eth ->
            if eth.Eth.Pdu.proto <> Eth.proto_arp then aux () else 
            (match Arp.Pdu.unpack eth.Eth.Pdu.payload with
            | None -> failwith "Cannot unpack ARP"
            | Some arp ->
                if arp.Arp.Pdu.operation <> Arp.op_reply ||
                   not (Bitstring.equals arp.Arp.Pdu.sender_proto target_ip_bits) then aux ()
                else
                    arp.Arp.Pdu.sender_hw
            )
        )
    in aux ()

let main =
    let src_ip_str = ref "192.168.66.147" and src_eth_str = ref "01:23:45:67:89:ab" in
    let resolve_one target_ip_str =
        let target_ip      = Ip.addr_of_string target_ip_str in
        let target_ip_bits = Ip.bitstring_of_addr target_ip
        and src_eth        = Eth.addr_of_string !src_eth_str
        and src_ip         =  Ip.addr_of_string !src_ip_str in
        arp_query src_eth src_ip target_ip ;
        let answer = Eth.addr_of_bitstring (wait_answer target_ip_bits) in
        Printf.printf "%s: %s\n" (Ip.string_of_addr target_ip) (Eth.string_of_addr answer)
    in
    Arg.parse [ "-src-ip",  Arg.Set_string src_ip_str,  "IP to use as the query sender" ;
                "-src-mac", Arg.Set_string src_eth_str, "MAC to use as the query sender" ]
              resolve_one
              "Send and receive ARP queries for some target IP"

