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
open Batteries
open Bitstring
open Tools

let debug = false

(* Private Types *)

let show_addr_with_vendor = ref true

let string_of_sfx l sfx =
    let rec aux prev l rem =
        if l <= 0 then prev else
        aux ((Printf.sprintf ":%02Lx" (Int64.logand rem 0xffL))^prev)
            (l-8)
            (Int64.shift_right_logical rem 8) in
    aux "" l sfx
(*$T string_of_sfx
  string_of_sfx  8 0xabL = ":ab"
  string_of_sfx 12 0x123L = ":01:23"
  string_of_sfx  0 0x123L = ""
  string_of_sfx 48 0x123456789abcL = ":12:34:56:78:9a:bc"
*)

external vendor_lookup : int64 -> (string * int) option = "wrap_eth_vendor_lookup"

let string_of_mac mac =
    let simple_name mac64 =
        String.lchop (string_of_sfx 48 mac64) in
    bitmatch mac with
        | { mac64 : 48 } ->
            if !show_addr_with_vendor then (
                match vendor_lookup mac64 with
                    | None -> simple_name mac64
                    | Some (name, bits) ->
                        let sfx_bits = 48 - bits in
                        let sfx = Int64.logand mac64 (Int64.pred (Int64.shift_left 1L sfx_bits)) in
                        name ^ (string_of_sfx sfx_bits sfx)
            ) else (
                simple_name mac64
            )
        | { _ } -> should_not_happen ()
(*$T string_of_mac
  string_of_mac ((Eth.addr_of_string "00:23:8b:5f:09:ce") :> bitstring) = "QuantaCo:5f:09:ce"
  string_of_mac ((Eth.addr_of_string "80:ee:73:07:76:f1") :> bitstring) = "Shuttle:07:76:f1"
  string_of_mac (Eth.addr_broadcast :> bitstring) = "Broadcast"
  string_of_mac ((Eth.addr_of_string "00:50:c2:00:0a:bc") :> bitstring) = "TLS:0a:bc"
  string_of_mac ((Eth.addr_of_string "ff:ff:07:c0:00:04") :> bitstring) = "ff:ff:07:c0:00:04"
*)

module Addr = MakePrivate(struct
    type t = bitstring
    let to_string = string_of_mac
    let is_valid t = bitstring_length t = 48
    let repl_tag = "addr"
end)

let addr_of_string str =
    let pack_addr a b c d e f =
        Addr.o (BITSTRING { a : 8 ; b : 8 ; c : 8 ; d : 8 ; e : 8 ; f : 8 }) in
    Scanf.sscanf str "%x:%x:%x:%x:%x:%x" pack_addr

let addr_broadcast = addr_of_string "FF:FF:FF:FF:FF:FF"
let addr_zero = addr_of_string "00:00:00:00:00:00"
let addr_eq (a : Addr.t) (b : Addr.t) =
    Bitstring.equals (a :> bitstring) (b :> bitstring)

(* Gateways can be given either a MAC or an IP address *)

type gw_addr = Mac of Addr.t | IPv4 of Ip.Addr.t
let string_of_gw_addr = function
    | Mac mac -> Addr.to_string mac
    | IPv4 ip -> Ip.Addr.to_string ip

let gw_addr_of_string str =
    try Mac (addr_of_string str)
    with _ -> IPv4 (Ip.addr_of_string str)

(* Ethernet frames *)

module Pdu = struct
    type t = { src : Addr.t ; dst : Addr.t ;
               vlan : int option ;
               proto : Arp.HwProto.t ;
               payload : bitstring }

    let make ?vlan proto src dst payload =
        { src ; dst ; vlan ; proto ; payload }

    let pack t =
        (* TODO: pad into minimal (64bytes) size? *)
        concat [ (match t.vlan with
            | None -> (BITSTRING {
                        (t.dst :> bitstring) : 6*8 : bitstring ;
                        (t.src :> bitstring) : 6*8 : bitstring ;
                        (t.proto :> int) : 16 })
            | Some v -> (BITSTRING {
                        (t.dst :> bitstring) : 6*8 : bitstring ;
                        (t.src :> bitstring) : 6*8 : bitstring ;
                        (Arp.proto_8021q :> int) : 16 ;
                        v : 16 ;
                        (t.proto :> int) : 16 })) ;
            t.payload ]

    let unpack bits = bitmatch bits with (* FIXME: decode 8021q vlans *)
        | { dst : 6*8 : bitstring ;
            src : 6*8 : bitstring ;
            proto : 16 ;    (* FIXME: might not be a proto if < 1500 *)
            payload : -1 : bitstring } ->
            Some { src = Addr.o src ; dst = Addr.o dst ;
                   vlan = None ; proto = Arp.HwProto.o proto ; payload }
        | { _ } ->
            err "Not Eth"
end

(* Transceiver (create it with a proto and a src MAC address and default GW dst MAC
   address, it will find the dst MAC itself using ARP).
   So this require to know the proto, and will be able to resolve addr for this proto only. *)

module TRX =
struct
    type t =
        { src : Addr.t ; gw : gw_addr option ;
          proto : Arp.HwProto.t ; mtu : int ;
          mutable my_addresses : bitstring list ;
          mutable emit : payload -> unit ;
          mutable recv : payload -> unit ;
          mutable promisc : payload -> unit ;
          (* TODO: these two should be timeouted, requiring a clock *)
          arp_cache : Addr.t option BitHash.t ;     (* proto_addr -> hw_addr option (None when resolving) *)
          delayed : bitstring BitHash.t }  (* dest_proto_addr -> msg *)
    type eth_trx =
        { trx : trx ;
          set_promiscuous : (payload -> unit) -> unit ;
          set_addresses : bitstring list -> unit }

    let send t proto dst bits =
        let pdu = Pdu.make proto t.src dst bits in
        if debug then Printf.printf "Eth: Emitting an Eth packet, proto %s, from %s to %s (content '%s')\n%!" (Arp.HwProto.to_string proto) (Addr.to_string t.src) (Addr.to_string dst) (string_of_bitstring bits) ;
        t.emit (Pdu.pack pdu)

    let resolve_proto_addr t bits sender_proto_addr target_proto_addr =
        let request = Arp.Pdu.make_request Arp.hw_type_eth t.proto (t.src :> bitstring) sender_proto_addr target_proto_addr in
        send t Arp.proto_arp addr_broadcast (Arp.Pdu.pack request) ;
        if debug then Printf.printf "Eth: Delaying a msg for '%s'\n%!" (hexstring_of_bitstring target_proto_addr) ;
        BitHash.add t.delayed target_proto_addr bits

    type dst = Delayed | Dst of Addr.t
    let arp_resolve_ipv4 t bits sender_ip target_ip =
        if target_ip = (Ip.bitstring_of_addr Ip.addr_broadcast) then Dst addr_broadcast
        else (
            try Dst (Option.get (BitHash.find t.arp_cache target_ip)) ;
            with Not_found ->
                if debug then Printf.printf "Eth: Cannot find HW addr for '%s' in ARP cache\n%!" (hexstring_of_bitstring target_ip) ;
                BitHash.add t.arp_cache target_ip None ;
                resolve_proto_addr t bits sender_ip target_ip ;
                Delayed
               | Invalid_argument _ ->
                if debug then Printf.printf "Eth: HW addr for '%s' is still resolving\n%!" (hexstring_of_bitstring target_ip) ;
                Delayed
        )

    let dst_for t bits =
        match t.gw with
        | None -> (* FIXME: or if the routes tells us that dest in on the same LAN than us *)
            (match t.proto with
            | x when x = Arp.proto_ip4 ->
                Option.Monad.bind (Ip.Pdu.unpack bits) (fun ip ->
                    let sender_ip = Ip.bitstring_of_addr ip.Ip.Pdu.src
                    and target_ip = Ip.bitstring_of_addr ip.Ip.Pdu.dst in
                    Some (arp_resolve_ipv4 t bits sender_ip target_ip))
            | _ -> err "Don't know how to resolve address for this protocol")
        | Some (Mac addr) -> Some (Dst addr)
        | Some (IPv4 ip)  -> Some (arp_resolve_ipv4 t bits (List.hd t.my_addresses) (Ip.bitstring_of_addr ip))

    let tx t bits =
        if debug then Printf.printf "Eth: TX a payload of %d bytes (while MTU=%d)\n" (bytelength bits) t.mtu ;
        if bytelength bits <= t.mtu then (
            match dst_for t bits with
            | Some (Dst dst) -> send t t.proto dst bits
            | Some Delayed -> if debug then Printf.printf "Eth:...delayed\n"
            | None -> if debug then Printf.printf "Eth:...no destination?!\n"
        )

    let rx t bits = (match Pdu.unpack bits with
        | None -> ()
        | Some frame ->
            if debug then Printf.printf "Eth: Got an eth frame of proto %s for %s\n%!" (Arp.HwProto.to_string frame.Pdu.proto) (Addr.to_string frame.Pdu.dst) ;
            if frame.Pdu.proto = t.proto &&
               (addr_eq frame.Pdu.dst t.src || addr_eq frame.Pdu.dst addr_broadcast) then (
                if debug then Printf.printf "Eth:...for me!\n%!" ;
                if bitstring_length frame.Pdu.payload > 0 then t.recv frame.Pdu.payload
            ) else if frame.Pdu.proto = Arp.proto_arp then (
                match Arp.Pdu.unpack frame.Pdu.payload with
                | None -> ()
                | Some arp ->
                    if debug then Printf.printf "Eth:...an ARP of opcode %s\n%!" (Arp.Op.to_string arp.Arp.Pdu.operation) ;
                    if arp.Arp.Pdu.hw_type = Arp.hw_type_eth then (
                        if debug then Printf.printf "Eth:...regarding an ethernet device!\n%!" ;
                        let sender_hw = Addr.o arp.Arp.Pdu.sender_hw (* will raise if not of the advertised type *)
                        and merge_flag = ref false in
                        if arp.Arp.Pdu.proto_type = t.proto then (
                            if debug then Printf.printf "Eth:...transporting same proto than me!\n%!" ;
                            if BitHash.mem t.arp_cache arp.Arp.Pdu.sender_proto then (
                                if debug then Printf.printf "Eth:...updating entry %s->%s in ARP cache\n%!" (hexstring_of_bitstring arp.Arp.Pdu.sender_proto) (Addr.to_string sender_hw) ;
                                merge_flag := true ;
                                BitHash.replace t.arp_cache arp.Arp.Pdu.sender_proto (Some sender_hw)
                            ) ;
                            if debug then Printf.printf "Eth:...concerning '%s' (I'm '%s')\n" (hexstring_of_bitstring arp.Arp.Pdu.target_proto) (hexstring_of_bitstring (List.hd t.my_addresses)) ;
                            if List.exists (Bitstring.equals arp.Arp.Pdu.target_proto) t.my_addresses then (
                                if debug then Printf.printf "Eth:...It's about me!!\n%!" ;
                                if not !merge_flag then (
                                    BitHash.add t.arp_cache arp.Arp.Pdu.sender_proto (Some sender_hw) ;
                                    if debug then Printf.printf "Eth:...adding %s->%s in ARP cache\n%!" (hexstring_of_bitstring arp.Arp.Pdu.sender_proto) (Addr.to_string sender_hw) ;
                                ) ;
                                if arp.Arp.Pdu.operation = Arp.op_request then (
                                    if debug then Printf.printf "Eth:...It's a request, let's reply!\n%!" ;
                                    let reply = Arp.Pdu.make_reply arp.Arp.Pdu.hw_type arp.Arp.Pdu.proto_type
                                                                   (t.src :> bitstring) arp.Arp.Pdu.target_proto
                                                                   arp.Arp.Pdu.sender_hw arp.Arp.Pdu.sender_proto in
                                    send t Arp.proto_arp sender_hw (Arp.Pdu.pack reply)
                                )
                            ) ;
                            (* Now that we may have gained knowledge, try to send the msg in waiting queue *)
                            (* TODO: timeout some? *)
                            if debug then Printf.printf "Eth:...Do I have a msg waiting for '%s'?\n%!" (hexstring_of_bitstring arp.Arp.Pdu.sender_proto) ;
                            while BitHash.mem t.delayed arp.Arp.Pdu.sender_proto do
                                if debug then Printf.printf "Eth:...Yes!! Let's send it!\n%!" ;
                                let msg = BitHash.find t.delayed arp.Arp.Pdu.sender_proto in
                                send t t.proto sender_hw msg ;
                                BitHash.remove t.delayed arp.Arp.Pdu.sender_proto
                            done
                        )
                    )
            ) else ( (* not for me, send to promisc function *)
                if debug then Printf.printf "Eth:...not for me!\n%!" ;
                if bitstring_length frame.Pdu.payload > 0 then t.promisc frame.Pdu.payload
            ))

    let make ?(mtu=1500) src ?gw ?(promisc=ignore) proto my_addresses =
        if debug then Printf.printf "Eth: Creating an eth TRX with %d addresses\n%!" (List.length my_addresses) ;
        let t = { src ; gw ; proto ;
                  emit = ignore ; recv = ignore ;
                  mtu ; promisc ; my_addresses ;
                  arp_cache = BitHash.create 3 ;
                  delayed = BitHash.create 3 } in
        { trx = { tx = tx t ;
                  rx = rx t ;
                  set_emit = (fun f -> t.emit <- f) ;
                  set_recv = (fun f -> t.recv <- f) } ;
          set_promiscuous = (fun f -> t.promisc <- f) ;
          set_addresses = (fun l -> t.my_addresses <- l) }

end

(* for throughput, remember the timestamp where the link will be available again *)
(* It may seams bogus to have throughput as a cable caracteristic instead of
 * device caracteristic, but it acknoledges the fact that both ends of a same
 * cable must agree on throughput. In other words, throughput negociation
 * already happened and you pass the resulting throughput here.
 * Also, notice that you can use the same [limited x y] in both directions,
 * thus having something similar than a half-duplex cable ;-) *)
let limited latency throughput =
    let next_avlb = ref 0. in
    (fun emit bits ->
        let min_start = Clock.now () +. latency in
        let start = max min_start !next_avlb
        and nb_bits = float_of_int (min (bitstring_length bits) 368) in
        let duration = max (Clock.usec 1.) (nb_bits /. throughput) in
        next_avlb := start +. duration ;
        Clock.at start emit bits)

(* TODO: module bridge *)

