(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
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
(**
 * Everything related to IPv4 packets: (un)packing, addresses, transceiver...
 *
 * TODO: Some usual IP options should be understood.
 *)
open Batteries
open Bitstring
open Tools

(** {2 Private Types} *)

(** {3 Protocols} *)

module ToS = struct
    include Private.Make (struct
        type t = int
        let to_string t =
            (* We don't know how it's used by the network (ToS, DSCP,
             * intserv...) so let's stick to the int repr: *)
            string_of_int t
        let is_valid t = t >= 0 && t < 0x100
        let repl_tag = "tos"
    end)

    (* Some DSCP well known values for when ToS is used for DSCP: *)
    let dscp_default = 0b000000
    let dscp_cs1 = 0b001000
    let dscp_cs2 = 0b010000
    let dscp_cs3 = 0b011000
    let dscp_cs4 = 0b100000
    let dscp_cs5 = 0b101000
    let dscp_cs6 = 0b110000
    let dscp_cs7 = 0b111000

    let no_ecn = 0b00
    let ecn_capable = 0b01
    let ecn_congested = 0b10

    let make ?(dscp=0) ?(ecn=0) () =
        (dscp lsl 2) lor ecn

    let string_of_dscp = function
        | 0b000000 -> "default"
        | 0b001000 -> "cs1"
        | 0b010000 -> "cs2"
        | 0b011000 -> "cs3"
        | 0b100000 -> "cs4"
        | 0b101000 -> "cs5"
        | 0b110000 -> "cs6"
        | 0b111000 -> "cs7"
        | v -> "unknown DSCP:"^ string_of_int v

    let string_of_ecn = function
        | 0b00 -> "no ECN"
        | 0b01 -> "ECN capable"
        | 0b10 -> "Congested"
        | v -> "unknown ECN:"^ string_of_int v

    let to_dscp_string t =
        let t = (t : t :> int) in
        let dscp = t lsr 2
        and ecn = t land 0b11 in
        string_of_dscp dscp ^","^ string_of_ecn ecn

    let random () = o (randi 8)
end

(** Internet protocols, as in [/etc/protocols]. *)
module Proto = struct
    include Private.Make (struct
        type t = int
        let to_string t =
            try (Unix.getprotobynumber t).Unix.p_name
            with Not_found ->
                Printf.sprintf "Protocol(%d)" t
        let is_valid t = t >= 0 && t < 0x100
        let repl_tag = "proto"
    end)

    (** Some well know IP protocols. *)

    let icmp = o 1
    let tcp  = o 6
    let udp  = o 17
    let ipv6 = o 41
    let icmpv6 = o 58

    let random () = o (randi 8)

    (** The protocol of the layer named [name] (see
     * [Packet.Pdu.name_of_layer]), when it is one of these. *)
    let of_layer = function
        | "Icmp" -> Some icmp
        | "Tcp" -> Some tcp
        | "Udp" -> Some udp
        | "Ip6" -> Some ipv6
        | _ -> None

    (** The protocols this module has a name for, as the choices of a kind
     * (see [Widget.one_of]). A datagram may of course carry any of the 256.
     *
     * Spelt out rather than taken from [to_string], which asks the system and
     * gets [/etc/protocols] back: those names are lower case by convention and
     * differ from one machine to another, and what belongs beside "IP" and
     * "ARP" in the same interface is "UDP", not "udp". *)
    let choices =
        [| (icmp :> int), "ICMP" ;
           (tcp :> int), "TCP" ;
           (udp :> int), "UDP" ;
           (ipv6 :> int), "IPv6" ;
           (icmpv6 :> int), "ICMPv6" |]
end

(** {3 Addresses} *)

(** {4 inet_addr}
 *
 * Stdlib [Unix] module already have a type for IP addresses:
 * [Unix.inet_addr] (actually a [string]). We use a private type
 * nonetheless so that we can have a custom printer. *)

(** Printer (in the sense of Batteries) for inet_addrs *)
let inet_addr_print oc a =
    Printf.fprintf oc "%s" (Unix.string_of_inet_addr a)

(** {4 IP Addresses as Unix.inet_addr (ie. strings)} *)

module Addr = struct
    (*$< Addr *)
    (** If true, use the system's name resolver to find a name for each IP
     * addresses that are printed. This can be very slow so is disabled by
     * default, but you can change it to suit your taste:
     * {[# let ip = Ip.Addr.of_string "217.70.184.38";;]}
     * {[val ip : Ip.Addr.t = 217.70.184.38]}
     * {[# Ip.Addr.print_as_names := true;;]}
     * {[# ip;;]}
     * {[- : Ip.Addr.t = webredir.vip.gandi.net]}
     *
     * This affects only printing of IP addresses, though, and thus is not
     * expected to impact a simulation. *)
    let print_as_names = ref false

    include Private.Make (struct
        type t = Unix.inet_addr

        (** Converts an address to its string representation. *)
        let to_string t =
            if !print_as_names then
                try (Unix.gethostbyaddr t).Unix.h_name
                with Not_found ->
                    Unix.string_of_inet_addr (t :> Unix.inet_addr)
            else
                Unix.string_of_inet_addr (t :> Unix.inet_addr)
        let is_valid _ = true
        let repl_tag = "addr"
    end)

    let length (t : t) =
        let str : string = Obj.magic (t :> Unix.inet_addr) in
        8 * String.length str
    (*$= length & ~printer:dump
         32 (length (of_string "1.2.3.4"))
         128 (length (of_string "3ffe:507:0:1:8c2:b0ff:feab:d5d9"))
    *)

    (** Regardless of the above setting, return the dotted representation (a
     * [string]) of a given address. *)
    let to_dotted_string (t : t) = Unix.string_of_inet_addr (t :> Unix.inet_addr)
    (*$= to_dotted_string & ~printer:identity
      "1.2.3.4" (to_dotted_string (Addr.of_string "1.2.3.4"))
      "2a05:d050:8000::" (to_dotted_string (Addr.of_string "2a05:d050:8000::"))
    *)

    (** Convert from dotted representation (useful to allow DNS-less hosts to 'resolve' some name) *)
    let of_dotted_string str =
        o (Unix.inet_addr_of_string str)

    let of_dotted_string_opt str =
        try Some (of_dotted_string str)
        with Failure _ -> None

    (* An address as one types it, and not as the resolver would have it:
     * [Ip.Addr.of_string] asks the system to look the name up, which would hold the
     * simulation still for as long as a DNS server feels like taking. *)
    let of_json name v =
        let s = Widget.to_string v in
        try of_dotted_string s
        with _ -> Widget.bad_value "%s: %S is not an IP address" name s

    let to_json t =
        `String (to_dotted_string t)

    (** Some predefined addresses *)

    (* FIXME: take bitlength in parameter *)
    let zero = o (Unix.inet_addr_of_string "0.0.0.0")
    let all_ones = o (Unix.inet_addr_of_string "255.255.255.255")
    let broadcast = all_ones
    let mask width =
        if width > 32 then invalid_arg "Ip.Addr.mask" ;
        Bitstring.concat [ ones_bitstring width ; zeroes_bitstring (32 - width) ]

    (** Convert an {!Ip.Addr} to a [bitstring]. *)
    let to_bitstring (t : t) =
        let str : string = Obj.magic t in
        bitstring_of_string str

    let to_bytes (t : t) : bytes =
        Obj.magic t

    let of_bytes bytes : t =
        let len = Bytes.length bytes in
        if len = 4 || len = 16 then Obj.magic bytes
        else invalid_arg "Ip.Addr.of_bytes"

    let compare t1 t2 =
        Bytes.compare (to_bytes t1) (to_bytes t2)

    (** Convert a [bitstring] into an {!Ip.Addr}. *)
    let of_bitstring bits =
        match bitstring_length bits with
        | 32 | 128 ->
            let str = string_of_bitstring bits in
            o (Obj.magic str)
        | x -> error ("IP addr must be 32 or 128 bits length not "^ string_of_int x)

    let list_of_string str =
        let extract_addr info = match info.Unix.ai_addr with
            | Unix.ADDR_INET (addr, _) -> Some (o addr)
            | _ -> None in
        List.filter_map extract_addr (Unix.getaddrinfo str "" [])

    let of_string str = match list_of_string str with
        | [] -> invalid_arg str
        | fst::_ -> fst

    (* Output a hexstring suitable for a pcap filter for instance (but
     * remember that a pcap filter can match at 1, 2 or 4 bytes only,
     * so split it if it's an IPv6!): *)
    let to_hexstring (t : t) =
        let str : string = Obj.magic t in
        Tools.hexstring ~sep:"" str

    (** Returns a random {!Ip.Addr} (apart from broadcast and zero). *)
    let rec random ?(v4=true) () =
        let str = randstr (if v4 then 4 else 16) in
        let t : Unix.inet_addr = Obj.magic str in
        let ip = o t in
        if ip = broadcast || ip = zero then random ()
        else ip

    let is_routable t =
        match%bitstring (to_bitstring t) with
        (* Private as per RFC 1918: *)
        | {| 10 : 8 ; _ : 24 |} -> false
        | {| 0xAC1 : 12 ; _ : 20 |} -> false
        | {| 0xC0A8 : 16 ; _ : 16 |} -> false
        (* Loopback (127.0.0.0/8) *)
        | {| 127 : 8 ; _ : 24 |} -> false
        (* Link-Local / APIPA (169.254.0.0/16) *)
        | {| 0xA9Fe : 16 ; _ : 16 |} -> false
        (* CG-NAT (100.64.0.0/10) *)
        | {| 0b1100100101 : 10 ; _ : 22 |} -> false
        (* Examples (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) *)
        | {| 0xC00002 : 24 ; _ : 8 |} -> false
        | {| 0xC63364 : 24 ; _ : 8 |} -> false
        | {| 0xCB0071 : 24 ; _ : 8 |} -> false
        (* Multicast (224.0.0.0/4) *)
        | {| 0x1110 : 4 ; _ : 28 |} -> false
        (* Class E, reserved *)
        | {| 0b1111 : 4 ; _ : 28 |} -> false
        (* IPv6 link-local (fe80::/10) *)
        | {| 0b1111111010 : 10 ; _ : 54 ; _ : 64 |} -> false
        (* IPv6 unique Local (fc00::/7) *)
        | {| 0b1111110 : 7 ; _ : 57 ; _ : 64 |} -> false
        (* IPv6 loopback (::1/128) *)
        | {| 0L : 64 ; 1L : 64 |} -> false
        (* IPv6 unspecified (::/128) *)
        | {| 0L : 64 ; 0L : 64 |} -> false
        (* Examples (2001:db8::/32) *)
        | {| 0x2001_0DB8l : 32 ; _ : 32 ; 0L : 64 |} -> false
        (* Discard prefix (100::/64) *)
        | {| 0x0100_0000_0000_0000L : 64 ; _ : 64 |} -> false
        (* IPv4 Mapped (::ffff:0:0/96) *)
        | {| 0L : 64 ; 0x0000_FFFFl : 32 ; _ : 32 |} -> false
        (* Everything else should be routable *)
        | {| _ |} -> true

    (*$T is_routable
       is_routable (of_string "135.12.0.42")
       is_routable (of_string "5402:7f8:5b:66b0::2")
       is_routable (of_string "2a01:4f8:1c1e:808e::1")
       not (is_routable (of_string "192.168.10.1"))
       not (is_routable (of_string "10.20.30.40"))
       not (is_routable (of_string "172.18.3.4"))
       not (is_routable (of_string "240.0.92.35"))
       not (is_routable (of_string "fe80::1234:5678"))
     *)

    let is_local t =
        match%bitstring (to_bitstring t) with
        | {| 127 : 8 ; _ : 24 |} -> true
        | {| 0L : 64 ; 1L : 64 |} -> false
        | {| _ |} -> false

    let is_broadcast t =
        match%bitstring (to_bitstring t) with
        | {| 0xffffffffl : 32 |} -> true
        | {| _ |} -> false

    let is_multicast t =
        match%bitstring (to_bitstring t) with
        | {| 0b1110 : 4 ; _ : 28 |} -> true
        | {| _ |} -> false

    let is_zero t =
        match%bitstring (to_bitstring t) with
        | {| 0l : 32 |} -> true
        | {| _ |} -> false

    (* not (is_local || is_broadcast || is_zero || is_discard(?)),
     * but faster: *)
    let is_natable t =
        match%bitstring (to_bitstring t) with
        | {| (0l | 0xffffffffl) : 32 |} -> false  (* all 0s/1s *)
        | {| 127 : 8 ; _ : 24 |} -> false  (* localhost *)
        | {| 0b1110 : 4 ; _ : 28 |} -> false (* multicast *)
        | {| 0L : 64 ; 1L : 64 |} -> false (* localhost *)
        | {| 100L : 64 ; _ : 64 |} -> false (* discard *)
        | {| _ |} -> true

    let is_v6 (t : t) =
        Unix.is_inet6_addr (t :> Unix.inet_addr)

    let is_v4 = not % is_v6

    (** This printer can be composed with others (for instance to print a list of ips.
     FIXME: always use batteries IO to print instead of Format printer? *)
    let print' oc ip =
        Printf.fprintf oc "%s" (to_string ip)

    let of_inet_addr ip = o ip
    let to_inet_addr (t : t) = (t :> Unix.inet_addr)

    (* make an Addr.t from a int32 *)
    let o32 i32 : t =
        let%bitstring bs = {| i32 : 32 |} in
        let str = string_of_bitstring bs in
        Obj.magic str

    (* The other way around *)
    let to_int32 (t : t) =
        match%bitstring (to_bitstring t) with
        | {| n : 32 |} -> n
        | {| _ |} -> should_not_happen ()

    let higher_bits (ip : t) n =
        let bs = to_bitstring ip in
        let l = bitstring_length bs in
        if n >= l then ip else
        Bitstring.concat [ takebits n bs ; create_bitstring (l-n) ] |>
        of_bitstring
    (*$= higher_bits & ~printer:to_string
       (o32 0x01000000l) (higher_bits (o32 0x01020305l) 10)
       (o32 0x01020304l) (higher_bits (o32 0x01020305l) 30)
       (o32 0x01020305l) (higher_bits (o32 0x01020305l) 32)
       (o32 0x01020305l) (higher_bits (o32 0x01020305l) 33)
     *)

    let in_mask ip ip_mask mask =
        let ip = to_bitstring ip
        and ip_mask = to_bitstring ip_mask
        and mask = to_bitstring mask in
        match_mask mask ip ip_mask

    (*$T in_mask
       in_mask (of_string "192.168.1.42") (of_string "192.168.0.0") (of_string "255.255.0.0")
       not (in_mask (of_string "192.168.1.42") (of_string "192.168.0.0") (of_string "255.255.255.0"))
       not (in_mask (of_string "192.168.1.42") (of_string "192.168.0.0") (of_string "255.255.255.254"))
     *)

    (*$>*)
end

(** {4 CIDR Addresses} *)

(** CIDR addresses are a concise way to write network addresses,
 * with network IP then netmask length, like: 192.168.0.0/16.
 * Can also be used to write a IP + its netmask concisely. *)
module Cidr = struct
    (*$< Cidr *)
    include Private.Make (struct
        type t = Addr.t * int

        (** Converts a CIDR to its string representation. *)
        let to_string ((ip : Addr.t), n) =
            Addr.to_dotted_string ip ^ "/" ^ String.of_int n
        let is_valid _ = true
        let repl_tag = "addr"
    end)

    let of_string str =
        let ip_str, width_str =
            try String.split ~by:"/" str
            with Not_found -> error (Printf.sprintf "not a CIDR: %s" str) in
        o (Addr.of_string ip_str, Int.of_string width_str)

    (* Test that we actually keep the masked bits, so a Cidr can be
     * used to write a network address _or_ a host+netmask (such as when
     * we manipulate gateway addresses) *)
    (*$= of_string & ~printer:to_string
      (o (Addr.o32 0x01020380l, 25)) (of_string "1.2.3.128/25")
      (o (Addr.o32 0x0102038El, 25)) (of_string "1.2.3.142/25")
      (o (Addr.of_string "2a05:d050:8000::", 40)) (of_string "2a05:d050:8000::/40")
     *)

    let abbrev (_t : t) =
        todo "abbrev"

    (* Will assume [ip] has all high bits at 1 and low bits at 0 *)
    let width_of_netmask ip =
        let ip = Addr.to_bitstring ip in
        let len = bitstring_length ip in
        let rec loop n =
            if n >= len then n else
            (* [is_set] count bits from the highest one: *)
            if Bitstring.is_set ip n then loop (n + 1) else
            n in
        loop 0
    (*$= width_of_netmask & ~printer:string_of_int
       0 (width_of_netmask (Addr.of_string "0.0.0.0"))
       1 (width_of_netmask (Addr.of_string "128.0.0.0"))
       8 (width_of_netmask (Addr.of_string "255.0.0.0"))
       5 (width_of_netmask (Addr.of_string "F800::"))
     *)

    (* Fail if [netmask] is not made of 1s and then 0s: *)
    let of_netmask ip netmask =
        let n = width_of_netmask netmask in
        let net = Addr.higher_bits ip n in
        o (net, n)

    let random ?mask () =
        let mask = Option.default (Random.int 32 + 1) mask in
        let net = Addr.higher_bits (Addr.random ()) mask in
        o (net, mask)
    (*$Q of_string
      (Q.make (fun _ -> random () |> to_string)) (fun t -> t = to_string (of_string t))
     *)

    (** Build a CIDR from a single address *)
    let single ip = o (ip, 32)

    let mem (t : t) =
        let net, width = (t :> Addr.t * int) in
        let len = Addr.length net in
        let net_hi = takebits width (Addr.to_bitstring net) in
        fun (ip : Addr.t) ->
            Addr.length ip = len &&
            let ip_hi = takebits width (Addr.to_bitstring ip) in
            Bitstring.equals net_hi ip_hi
    (*$= mem & ~printer:string_of_bool
      true  (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.0"))
      true  (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.1"))
      true  (mem (of_string "192.168.10.7/28") (Addr.of_string "192.168.10.15"))
      true  (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.15"))
      false (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.16"))
      false (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.17"))
      false (mem (of_string "192.168.10.7/28") (Addr.of_string "192.168.10.17"))
      false (mem (of_string "0.0.0.0/0") (Addr.of_string "2001:db8::1"))
      false (mem (of_string "::/0") (Addr.of_string "10.0.0.1"))
     *)

    let width (t : t) =
        let _, width = (t :> Addr.t * int) in
        width

    (* Number of IPs in that range *)
    let count (t : t) =
        let net, width = (t :> Addr.t * int) in
        let tot_width = Addr.length net in
        1 lsl (tot_width - width)
    (*$= count & ~printer:string_of_int
      256 (count (of_string "192.168.1.0/24"))
    *)

    let enlarge (t : t) n =
        let net, width = (t :> Addr.t * int) in
        o (net, width + n)

    let enum (t : t) =
        let net, width = (t :> Addr.t * int) in
        let net = Addr.to_bitstring net in
        let prefix = takebits width net
        and l = bitstring_length net - width in
        all_bits l /@
        (fun suffix ->
            Bitstring.concat [ prefix ; suffix ] |>
            Addr.of_bitstring)
    (*$= enum & ~printer:(IO.to_string (List.print String.print))
      [ "192.168.10.42" ] (enum (of_string "192.168.10.42/32") /@ \
                           Addr.to_dotted_string |> \
                           List.of_enum)
      [ "192.168.10.42" ; "192.168.10.43" ] \
                           (enum (of_string "192.168.10.42/31") /@ \
                           Addr.to_dotted_string |> \
                           List.of_enum)
     *)
    let to_enum = enum  (* Backward compatibility *)

    (** Returns the subnet part of a CIDR, without zeroing it *)
    let subnet (t : t) =
        let net, _width = (t :> Addr.t * int) in
        net (* Cf is_valid *)

    (** Returns the subnet-zero address of a CIDR *)
    let zero_addr (t : t) =
        let net, width = (t :> Addr.t * int) in
        Addr.higher_bits net width (* Cf is_valid *)
    (*$= zero_addr & ~printer:identity
      "192.168.1.0" (zero_addr (of_string "192.168.1.0/28") |> \
                     Addr.to_dotted_string)
      "192.168.1.0" (zero_addr (of_string "192.168.1.3/28") |> \
                     Addr.to_dotted_string)
     *)

    (** Returns the all-ones address of a CIDR *)
    let all1s_addr (t : t) =
        let net, width = (t :> Addr.t * int) in
        let net_bs = Addr.to_bitstring net in
        let l = bitstring_length net_bs in
        if width >= l then net else
        let prefix = takebits width net_bs in
        Bitstring.concat [ prefix ; ones_bitstring (l-width) ] |>
        Addr.of_bitstring
    (*$= all1s_addr & ~printer:identity
      "192.168.1.15"  (all1s_addr (of_string "192.168.1.0/28") |> \
                       Addr.to_dotted_string)
      "192.168.2.255" (all1s_addr (of_string "192.168.2.0/24") |> \
                       Addr.to_dotted_string)
     *)

    (** Returns the set (as an [Enum]) of all IP addresses in the given CIDR
     * range (that is, all minus subnet zero, all-ones subnet and the IP of
     * the netmask itself if it's not the zero). *)
    let local_addrs (t : t) =
        let net, width = (t :> Addr.t * int) in
        if width >= Addr.length net then Enum.empty () else
        let zero = zero_addr t and all1s = all1s_addr t in
        enum t // (fun ip -> ip <> zero && ip <> all1s && ip <> net)
    (*$= local_addrs & ~printer:dump
      []                  (local_addrs (of_string "192.168.10.42/32") /@ \
                           Addr.to_dotted_string |> \
                           List.of_enum)
      []                  (local_addrs (of_string "192.168.10.42/31") \
                           |> List.of_enum)
      [ "192.168.0.1" ; "192.168.0.2" ] \
                          (local_addrs (of_string "192.168.0.0/30") /@ \
                           Addr.to_dotted_string |> \
                           List.of_enum)
      [ "192.168.0.2" ]   (local_addrs (of_string "192.168.0.1/30") /@ \
                           Addr.to_dotted_string |> \
                           List.of_enum)
      [ "2a05:d050:8000::1" ; "2a05:d050:8000::2" ] \
                          (local_addrs (of_string "2a05:d050:8000::/40") /@ \
                           Addr.to_dotted_string |> \
                           Enum.take 2 |> \
                           List.of_enum)
    *)

    (* Returns the first routable address of a CIDR, or fail if the Cidr is empty
     * (handy for a router own address for instance) *)
    let first_addr (t : t) =
        local_addrs t |> Enum.peek |> Option.get

    (* Also useful: the second routable address: *)
    let second_addr (t : t) =
        local_addrs t |> Enum.skip 1 |> Enum.peek |> Option.get

    let random_addrs t n =
        enum t |> Random.multi_choice n

    (** One address of that network, drawn at random. Much faster than
     * building the enumeration when only one is wanted. *)
    let random_addr (t : t) =
        let net, width = (t :> Addr.t * int) in
        let net = Addr.to_bitstring net in
        let tot_width = net |> bitstring_length in
        Bitstring.(concat [ takebits width net ;
                            randbits (tot_width - width) ]) |>
        Addr.of_bitstring
    (*$Q random_addr
       Q.unit (fun () -> \
        let cidr = random () in \
        let ip = random_addr cidr in \
        mem cidr ip)
    *)

    let to_netmask (t : t) =
        let net, width = (t :> Addr.t * int) in
        let tot_width = Addr.length net in
        Bitstring.concat [ ones_bitstring width ;
                           zeroes_bitstring (tot_width - width) ] |>
        Addr.of_bitstring

    (*$= to_netmask
      "255.255.255.0" (Ip.Addr.to_string (to_netmask (of_string "192.168.0.0/24")))
     *)

    (* Returns the smallest CIDR encompassing all passed IP addresses *)
    let smallest e =
        let ip_n =
            Enum.fold (fun ip_n ip' ->
                let ip' = Addr.to_bitstring ip' in
                match ip_n with
                | None ->
                    Some (ip', 32)
                | Some (ip, n) ->
                    let n' = bitstring_common_prefix_length ip ip' in
                    Some (ip, min n n')
            ) None e in
        match ip_n with
        | None ->
            invalid_arg "smallest"
        | Some (ip, n) ->
            let ip = Addr.higher_bits (Addr.of_bitstring ip) n in
            o (ip, n)

    (*$>*)
end

(** {4 IP Sets} *)

module Set = BatSet.Make (Addr)

(** {4 IP Ranges} *)

module Range = struct
    (** Actually, a list of ranges, assumed to be sorted and with no overlap: *)
    type t = (Addr.t * Addr.t) list

    let make lst =
        List.sort (fun (a1, _) (a2, _) -> Addr.compare a1 a2) lst

    let of_cidr cidr =
        Cidr.[ zero_addr cidr, all1s_addr cidr ]

    (** Enumerate the addresses of a single interval: *)
    let addrs a1 a2 =
        (* TODO: probably faster with the bytes representation *)
        bitstring_enum ~from:(Addr.to_bitstring a1)
                      ~until:(Addr.to_bitstring a2) |>
        Enum.map Addr.of_bitstring

    (* Enumerate all IP addresses of the range: *)
    let enum t =
        List.enum t |>
        Enum.map (fun (a1, a2) -> addrs a1 a2) |>
        Enum.concat
end

(** {2 IP packet} *)

(** (Un)Packing an IP packet. *)
module Pdu = struct
    (*$< Pdu *)

    (* Size of an IP header without options: *)
    let no_opt_hdr_len = 20

    let id_seq = ref 0
    let next_id () = id_seq := (!id_seq + 1) land 0xffff ; !id_seq

    type t = { tos : ToS.t ; tot_len : int ;
               id : int ; dont_frag : bool ; more_frags : bool ; frag_offset : int ;
               ttl : int ; proto : Proto.t ; src : Addr.t ; dst : Addr.t ;
               options : bitstring ; payload : Payload.t }

    let make ?(tos=ToS.o 0) ?tot_len
             ?id ?(dont_frag=false) ?(more_frags=false)
             ?(frag_offset=0) ?(ttl=64)
             ?(options=empty_bitstring)
             proto src dst bits =
        let hdr_len = no_opt_hdr_len + bytelength options
        and id = may_default id next_id in
        let tot_len = match tot_len with Some v -> v | None ->
            bytelength bits + hdr_len in
        { tos ; tot_len ; id ; dont_frag ; more_frags ; frag_offset ;
          ttl ; proto ; src ; dst ; options ; payload = Payload.o bits }

    let random () =
        make ~tos:(ToS.random ()) ~id:(randi 16) ~dont_frag:(randb ())
             ~more_frags:(randb ()) ~frag_offset:(randi 13)
             ~ttl:(randi 8) ~options:(randbs (4*(randi 3)))
             (Proto.random ()) (Addr.random ()) (Addr.random ()) (randbs (Random.int 10 + no_opt_hdr_len))

    let pseudo_header t () =
        let%bitstring r = {|
            (Addr.to_int32 t.src) : 32 ; (Addr.to_int32 t.dst) : 32 ;
            0 : 8 ; (t.proto :> int) : 8 ; Payload.length (t.payload) : 16 |} in
        r

    let patch_checksum ?(fixit=identity) offset pseudo_header (pld : Payload.t) =
        match%bitstring (pld :> bitstring) with
        | {| head : offset : bitstring ;
             chk  : 16 ;
             tail : -1 : bitstring |} (* FIXME: for TCP, force urgent pointer at 0 if the urgent flag is unset *) ->
            if chk = 0 then (
                let chk = sum (concat [ pseudo_header () ; head ; zeroes_bitstring 16 ; tail ]) |>
                          fixit in
                let%bitstring pld = {| head : offset : bitstring ; chk : 16 ; tail : -1 : bitstring |} in
                Payload.o pld
            ) else pld
        | {| _ |} ->
            Printf.eprintf "Ip: Cannot patch checksum at offset %d, payload: %s\n"
                offset (hexstring_of_bitstring_abbrev ~bits:(offset + 16) (pld :> bitstring)) ;
            pld

    let pack_header t =
        let hdr_len = no_opt_hdr_len + bytelength t.options in
        assert (hdr_len < 64) ;
        assert (t.tot_len < 65536) ;
        assert (t.id < 65536) ;
        assert (t.frag_offset < 8192) ;
        assert (t.ttl < 256) ;
        assert ((t.proto :> int) < 256) ;
        let%bitstring hdr = {|
            4 : 4 ; hdr_len/4 : 4 ; (t.tos :> int) : 8 ;
            t.tot_len : 16 ;
            t.id : 16 ; false : 1 ; t.dont_frag : 1 ; t.more_frags : 1 ; t.frag_offset : 13 ;
            t.ttl : 8 ; (t.proto :> int) : 8 ; 0 : 16 ;
            (Addr.to_int32 t.src) : 32 ; (Addr.to_int32 t.dst) : 32 |} in
        let header = concat [ hdr ; t.options ] in
        let%bitstring s = {| sum header : 16 |} in
        concat [ takebits 80 header ; s ; dropbits 96 header ]

    let is_fragment t = t.more_frags || t.frag_offset > 0

    let pack_payload t =
        (* Patch TCP/UDP checksums since they use some fields of the IP header.
         * The checksum covers the whole L4 PDU, so a fragment is left alone: *)
        if is_fragment t then t.payload
        else if t.proto = Proto.tcp then patch_checksum 128 (pseudo_header t) t.payload
        else if t.proto = Proto.udp then patch_checksum 48 (pseudo_header t) t.payload
        else t.payload

    let pack t =
        let header = pack_header t
        and payload = pack_payload t in
        concat [ header ; (payload :> bitstring) ]

    (* The options that go into every fragment (copied flag set), padded to
     * a multiple of 4 bytes: *)
    let copied_options opts =
        let rec loop acc opts =
            match%bitstring opts with
            | {| 0 : 8 ; _ : -1 : bitstring |} -> acc (* end of options *)
            | {| 1 : 8 ; rest : -1 : bitstring |} -> loop acc rest (* no-op *)
            | {| copied : 1 ; _ : 7 ; len : 8 ;
                 _ : (len - 2) * 8 : bitstring ; rest : -1 : bitstring |} ->
                loop (if copied then takebits (len * 8) opts :: acc else acc) rest
            | {| _ |} -> acc in
        let opts = concat (List.rev (loop [] opts)) in
        let pad = (4 - bytelength opts mod 4) mod 4 in
        concat [ opts ; zeroes_bitstring (pad * 8) ]
    (*$= copied_options & ~printer:identity
      "\x82\x03\x00\x00" \
        (Bitstring.string_of_bitstring (copied_options \
          (Bitstring.bitstring_of_string "\x07\x03\x00\x01\x82\x03\x00\x00")))
      "" (Bitstring.string_of_bitstring (copied_options Bitstring.empty_bitstring))
    *)

    (** Split [t] into packets of at most [mtu] bytes. [t] can itself be a
     * fragment, so offsets and MF flag are relative to its own. The DF flag is
     * not checked.
     * Raises Invalid_argument if [mtu] leaves no room for 8 bytes of payload. *)
    let fragment mtu t =
        let len = Payload.length t.payload in
        let hdr_len opts = no_opt_hdr_len + bytelength opts in
        if hdr_len t.options + len <= mtu then [ pack t ] else
        let t = { t with payload = pack_payload t } in (* before splitting *)
        let rec loop options pos acc =
            let max_pld = (mtu - hdr_len options) land (lnot 7) in
            if max_pld < 8 then invalid_arg "Ip.Pdu.fragment: MTU too small" ;
            let last = len - pos <= max_pld in
            let n = if last then len - pos else max_pld in
            let frag =
                { t with tot_len = hdr_len options + n ; options ;
                         more_frags = t.more_frags || not last ;
                         frag_offset = t.frag_offset + pos lsr 3 ;
                         payload = Payload.sub pos n t.payload } in
            let bits = pack frag in
            if last then List.rev (bits :: acc)
            else loop (copied_options t.options) (pos + n) (bits:: acc) in
        loop t.options 0 []

    let unpack bits = match%bitstring bits with
        | {| 4 : 4 ; hdr_len : 4 ; tos : 8 ; tot_len : 16 ;
             id : 16 ; false : 1 ; dont_frag : 1 ; more_frags : 1 ; frag_offset : 13 ;
             ttl : 8 ; proto : 8 ; _checksum : 16 ;
             src : 32 ;
             dst : 32 ;
             options : (hdr_len-5)*32 : bitstring ;
             rest : -1 : bitstring |}
          when hdr_len >= 5 && tot_len >= hdr_len * 4 ->
            (* TODO: control the checksum ? *)
            (* payload must have some extra padding at the end, or may have
             * been truncated: *)
            let payload_len = (tot_len - hdr_len*4) * 8 in
            let payload =
                if bitstring_length rest > payload_len then
                    takebits payload_len rest
                else
                    rest in
            Ok { tos = ToS.o tos ; tot_len ;
               id ; dont_frag ; more_frags ; frag_offset ;
               ttl ; proto = Proto.o proto ;
               src = Addr.o32 src ; dst = Addr.o32 dst ; options ;
               payload = Payload.o payload }
        | {| 4 : 4 ; hdr_len : 4 ; _tos : 8 ; tot_len : 16 ; _ |} ->
            Error (lazy (Printf.sprintf
                "Bogus IPv4 header: announces a header of %d bytes in a \
                 packet of %d" (hdr_len * 4) tot_len))
        | {| 6 : 4 ; _ |} ->
            Error (lazy "IPv4 looks like v6")
        | {| _ |} ->
            Error (lazy ("Not IPv4: "^ hexstring_of_bitstring_abbrev bits))

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)

    (* A cable with an error rate flips bits wherever it pleases, the length
       fields included: whatever comes out, [unpack] must judge it rather than
       raise -- an exception here escapes into the event handler and takes the
       simulation with it. *)
    (*$T unpack
      (let bits0 = pack (make Proto.udp (Addr.random ()) (Addr.random ()) (randbs 8)) in \
       let ok = ref true in \
       for i = 0 to bitstring_length bits0 - 1 do \
         let bits = bitstring_copy bits0 in \
         bitstring_shift i bits ; \
         (try ignore (unpack bits) with _ -> ok := false) \
       done ; \
       !ok)
     *)
    (*$T unpack
      Result.is_bad (unpack (bitstring_of_string ("\x45\x00\x00\x03" ^ String.make 24 '\x00')))
      Result.is_bad (unpack (bitstring_of_string ("\x40\x00\x00\x1c" ^ String.make 24 '\x00')))
      Result.is_ok  (unpack (bitstring_of_string ("\x45\x00\x00\x1c" ^ String.make 24 '\x00')))
     *)

    (* Returns the source/dest ports from an IP PDU: *)
    let get_ports ip =
        if ip.proto = Proto.tcp then (
            Result.bind (Tcp.Pdu.unpack (ip.payload :> bitstring))
            (fun tcp ->
                Ok ((tcp.Tcp.Pdu.src_port :> int),
                    (tcp.Tcp.Pdu.dst_port :> int)))
        ) else if ip.proto = Proto.udp then (
            Result.bind (Udp.Pdu.unpack (ip.payload :> bitstring))
            (fun udp ->
                Ok ((udp.Udp.Pdu.src_port :> int),
                    (udp.Udp.Pdu.dst_port :> int)))
        ) else Error (lazy "Not TCP nor UDP")

    (** Unpack an ip packets and return the ip PDU, source port and dest port. *)
    let unpack_with_ports bits =
        Result.bind (unpack bits) (fun ip ->
            Result.bind (get_ports ip) (fun (src_port, dst_port) ->
                Ok (ip, src_port, dst_port)))
    (*$= unpack_with_ports & ~printer:dump
        (Ok (42, 12)) ( \
            pack (make Proto.udp (Ip.Addr.random ()) (Ip.Addr.random ()) \
                        (Udp.Pdu.make ~src_port:(Udp.Port.o 42) \
                                      ~dst_port:(Udp.Port.o 12) \
                                      (randbs 10) |> \
                        Udp.Pdu.pack)) |> \
            unpack_with_ports |> \
            flip Result.bind \
                (fun (_, src, dst) -> Ok (src, dst)) \
        )
     *)

    (** What a datagram's header says.
     *
     * The version and the header length are not in [t]: the first is what this
     * module is, and the second follows from the options. Neither is the
     * checksum, which [pack_header] computes. The total length is, and is
     * shown as the number it is -- computing it is what an editor would offer,
     * and the editor is still to come.
     *
     * The type of service is one byte and is shown as one, rather than split
     * into the six bits of a DSCP and the two of an ECN: [t] holds the byte,
     * and a reader who wants it read out has [ToS.to_dscp_string]. *)
    module Kinds =
    struct
        open SimTypes
        let tos = IRange (0, 0xff)
        let tot_len = IRange (0, 0xffff)
        let id = IRange (0, 0xffff)
        let frag_offset = IRange (0, 0x1fff)
        let ttl = IRange (0, 0xff)
        let proto = Widget.one_of ~range:(0, 0xff) Proto.choices
        let addr = Widget.hint "192.168.0.1" Ipv4
        let options = BRange (0, 40)
        let payload = BRange (0, 0xffff - no_opt_hdr_len)
    end

    let kind =
        let open SimTypes in
        Widget.record
            [| "type of service", Kinds.tos ;
               "total length", Kinds.tot_len ;
               "id", Kinds.id ;
               "don't fragment", Bool ;
               "more fragments", Bool ;
               "fragment offset", Kinds.frag_offset ;
               "time to live", Kinds.ttl ;
               "protocol", Kinds.proto ;
               "source", Kinds.addr ;
               "destination", Kinds.addr ;
               "options", Kinds.options ;
               "payload", Kinds.payload |]

    let to_json (t : t) =
        `Assoc [ "type of service", `Int (t.tos :> int) ;
                 "total length", `Int t.tot_len ;
                 "id", `Int t.id ;
                 "don't fragment", `Bool t.dont_frag ;
                 "more fragments", `Bool t.more_frags ;
                 "fragment offset", `Int t.frag_offset ;
                 "time to live", `Int t.ttl ;
                 "protocol", `Int (t.proto :> int) ;
                 (* The dotted form and not [to_string]'s, which may name the
                    host instead: what is shown is what can be typed back. *)
                 "source", Addr.to_json t.src ;
                 "destination", Addr.to_json t.dst ;
                 "options", Widget.json_of_bytes t.options ;
                 "payload", Widget.json_of_bytes (t.payload :> bitstring) ]

    (* Where each field is in [kind], which [of_synth] reads them by: *)
    module Field =
    struct
        let i = Widget.field_index kind
        let tos = i "type of service"
        let tot_len = i "total length"
        let id = i "id"
        let dont_frag = i "don't fragment"
        let more_frags = i "more fragments"
        let frag_offset = i "fragment offset"
        let ttl = i "time to live"
        let proto = i "protocol"
        let src = i "source"
        let dst = i "destination"
        let options = i "options"
        let payload = i "payload"
    end

    (* [r] are the fields of a synth of [kind] (see [Generator.fields]): *)
    let of_synth r ?upper ?prev gen_values =
        let open Generator in
        let int i ?auto kind f =
            int_of_nth r i gen_values ?auto kind f
        and bool ?auto i =
            of_nth r i gen_values ?auto SimTypes.Bool Widget.to_bool
        and addr i =
            of_nth r i gen_values Kinds.addr
                   (Addr.of_dotted_string % Widget.to_string) in
        (* An automatic value is what a packet would plausibly carry and not
         * any value the field could hold: a random fragment offset makes a
         * fragment of every packet, and random option bytes a header nothing
         * can read past -- either way what is above is no longer a segment
         * anybody recognises. *)
        let options =
            bs_of_nth r Field.options gen_values
                      ~auto:(fun () -> empty_bitstring) Kinds.options
        and payload = payload_of_nth ?upper r Field.payload gen_values
                                     Kinds.payload in
        { tos = int Field.tos ~auto:(fun () -> ToS.o 0) Kinds.tos ToS.o ;
          tot_len = int Field.tot_len
                        ~auto:(fun () ->
                            no_opt_hdr_len + bytelength options + bytelength payload)
                        Kinds.tot_len identity ;
          id = int Field.id ?auto:(Option.map (fun p () ->
                                      (p.id + 1) land 0xffff) prev)
                   Kinds.id identity ;
          dont_frag = bool Field.dont_frag ;
          more_frags = bool ~auto:(fun () -> false) Field.more_frags ;
          frag_offset = int Field.frag_offset ~auto:(fun () -> 0)
                            Kinds.frag_offset identity ;
          (* Enough hops to cross any simulated network, and not the 0 that a
           * random one is 1 time in 256, which no router would forward. *)
          ttl = int Field.ttl ~auto:(fun () -> 64) Kinds.ttl identity ;
          proto = int Field.proto ?auto:(from_upper upper Proto.of_layer)
                      Kinds.proto Proto.o ;
          src = addr Field.src ;
          dst = addr Field.dst ;
          options ;
          payload = Payload.o payload }

    (*$Q of_synth
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_consts (fun js g -> \
            of_synth (Generator.fields_of_synth kind js) g) kind to_json)
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_autos (fun js g -> \
            of_synth (Generator.fields_of_synth kind js) g) kind to_json)
     *)

    (*$Q kind
      (Q.make (fun _ -> random ())) (fun t -> \
        try Widget.check_value kind (to_json t) ; true \
        with _ -> false)
     *)
    (*$>*)
end

(** {2 Transceiver} *)

module TRX = struct

    type t = {
        logger : Log.t ;
        power : Simulation.power ;
        src : Addr.t ; dst : Addr.t ;
        proto : Proto.t ;
        (* Fragment if the packet is larger than that (set to max_int to disable fragmentation: *)
        mtu : int ;
        (* Set the DF bit of emitted packets (and fragments!) to this value: *)
        dont_frag : bool ;
        (* Perform reassembly before handing over received frames: *)
        reassemble : bool ;
        mutable emit : bitstring -> unit ;
        mutable recv : bitstring -> unit ;
        (* TODO: timeout reassembly lines *)
        reassembled : (reassemble_key, Pdu.t list (* sorted by frag_offset *)) Hashtbl.t
    }

    (* We might want to reassemble packets that are not destined to [t.src] (broadcast, ICMP
     * error, wtv) so let's use the IPs in additon to the ID to identify reassembled packets: *)
    and reassemble_key = Addr.t * Addr.t * Proto.t * int (* src, dst, proto, id *)

    (* Emitted packets have no options, thus a 20 bytes header: *)
    let hdr_len = Pdu.no_opt_hdr_len

    let tx t bits =
        if bitstring_length bits > 0 then (
            let pdu = Pdu.make ~dont_frag:t.dont_frag t.proto t.src t.dst bits in
            Pdu.fragment t.mtu pdu |>
            List.iter (fun bits ->
                Log.(log t.logger Debug (lazy (Printf.sprintf "Ip: Emitting an IP packet from %s to %s of length %d (content '%s')" (Addr.to_dotted_string t.src) (Addr.to_dotted_string t.dst) (Payload.length pdu.payload) (hexstring_of_bitstring bits)))) ;
                Simulation.asap t.power t.emit bits)
        )

    let reassemble t (ip : Pdu.t) =
        let key = ip.src, ip.dst, ip.proto, ip.id in
        match Hashtbl.find t.reassembled key with
        | exception Not_found ->
            Hashtbl.add t.reassembled key [ ip ] ;
            None
        | frags ->
            (* Insert the fragment: *)
            let rec loop prevs = function
                | [] ->
                    List.rev (ip :: prevs)
                | ((f : Pdu.t) :: rest) ->
                    (* if [ip] starts before [f] then insert [ip] here.
                     * if they start at the same place, keep the longest.
                     * if [ip] starts after [f] then keep going. *)
                    if ip.frag_offset < f.frag_offset then
                        List.rev_append (ip :: prevs) (f :: rest)
                    else if ip.frag_offset = f.frag_offset then
                        if Payload.bitlength ip.payload > Payload.bitlength f.payload then
                            List.rev_append (ip :: prevs) rest
                        else
                            frags (* the original list *)
                    else
                        loop (f :: prevs) rest in
            let frags = loop [] frags in
            (* Offsets and lengths in bits: *)
            let start (f : Pdu.t) = f.frag_offset lsl 6
            and stop (f : Pdu.t) = (f.frag_offset lsl 6) + Payload.bitlength f.payload in
            (* Complete when the fragments cover from 0 without a gap, up to
             * the end of one without more_frags: *)
            let rec is_complete covered more_frags = function
                | [] ->
                    not more_frags
                | f :: rest ->
                    if start f > covered then false
                    else if stop f <= covered then is_complete covered more_frags rest
                    else is_complete (stop f) f.Pdu.more_frags rest in
            if is_complete 0 true frags then (
                Hashtbl.remove t.reassembled key ;
                (* Rebuild the payload, skipping whatever is already covered: *)
                let rec loop covered plds = function
                    | [] ->
                        Bitstring.concat (List.rev plds)
                    | (f : Pdu.t) :: rest ->
                        if stop f <= covered then
                            loop covered plds rest
                        else
                            let pld = dropbits (covered - start f) (f.payload :> bitstring) in
                            loop (stop f) (pld :: plds) rest in
                Some (loop 0 [] frags)
            ) else (
                Hashtbl.replace t.reassembled key frags ;
                None
            )

    (* TODO: check checksum? *)
    let rx (t : t) bits =
        match Pdu.unpack bits with
        | Error s ->
            Log.(log t.logger Warning s)
        | Ok (ip : Pdu.t) ->
            if Payload.bitlength ip.payload = 0 then
                Log.(log t.logger Debug (lazy (Printf.sprintf "Ip: Ignoring an empty packet from %s to %s"
                    (Addr.to_dotted_string ip.src) (Addr.to_dotted_string ip.dst))))
            else (
                (* Perform reassembly if needed: *)
                if (ip.more_frags || ip.frag_offset > 0) && t.reassemble then (
                    reassemble t ip |>
                    Option.may (Simulation.asap t.power t.recv)
                ) else
                    Simulation.asap t.power t.recv (ip.payload :> bitstring)
            )

    (* Note: In Eth we do not require dst addr since the trx know (using ARP) how to get dest addr itself.
     *       IP cannot do this since the application layer won't tell him the destination hostname. Or
     *       we must add the destination to any tx call, making host layer simpler only at the expense of
     *       this layer. *)
    let make power ?(mtu=1420) ?(dont_frag=false) ?(reassemble=true) src dst proto logger =
        ensure (mtu >= hdr_len + 8) "Ip: MTU must leave room for at least 8 bytes of payload" ;
        let t = { logger ; power ; src ; dst ; proto ; mtu ; dont_frag ; reassemble ;
                  emit = ignore_bits ~logger ;
                  recv = ignore_bits ~logger ;
                  reassembled = Hashtbl.create 10 } in
        { ins = { write = tx t ;
                  set_read = fun f -> t.recv <- f } ;
          out = { write = rx t ;
                  set_read = fun f -> t.emit <- f } }

    (*$< TRX *)
    (* [frags_of s] is what a TRX from [a] to [b] emits for [s]; [frag off len mf]
     * is a hand made fragment of [msg] (offsets and lengths in bytes); and
     * [receive pkts] is what [b] hands over after receiving [pkts] in order. *)
    (*$inject
      let sim = Simulation.make ~realtime:false "ip-frags"
      let a = Addr.of_string "10.0.0.1" and b = Addr.of_string "10.0.0.2"
      let msg = "0123456789abcdefghijklmnopqrstuvwxyzABCD"

      let frags_of ?(mtu=36) s =
        let trx = make sim.root.power ~mtu a b Proto.udp sim.root.logger in
        let out = ref [] in
        trx.out.set_read (fun bits -> out := bits :: !out) ;
        trx.ins.write (Bitstring.bitstring_of_string s) ;
        Simulation.run sim false ;
        List.rev !out

      let frag ?(id=42) off len more_frags =
        Bitstring.bitstring_of_string (String.sub msg off len) |>
        Pdu.make ~id ~frag_offset:(off / 8) ~more_frags Proto.udp a b |>
        Pdu.pack

      let receive ?reassemble pkts =
        let trx = make sim.root.power ?reassemble b a Proto.udp sim.root.logger in
        let got = ref [] in
        trx.ins.set_read (fun bits -> got := Bitstring.string_of_bitstring bits :: !got) ;
        List.iter trx.out.write pkts ;
        Simulation.run sim false ;
        List.rev !got

      let refrag mtu pkts =
        List.concat_map (fun bits ->
          Pdu.fragment mtu (Result.get_ok (Pdu.unpack bits))
        ) pkts

      let with_opts =
        Bitstring.bitstring_of_string msg |>
        Pdu.make ~options:(Bitstring.bitstring_of_string "\x07\x03\x00\x01\x82\x03\x00\x00")
                 Proto.udp a b

      let udp_wants_chk = "\x00\x01\x00\x02\x00\x30\x00\x00" ^ msg

      let printer = IO.to_string (List.print String.print)
    *)
    (*$= receive & ~printer
      [ "hello" ] (receive (frags_of "hello"))
      [ msg ] (receive (frags_of msg))
      [ msg ] (receive (List.rev (frags_of msg)))
      [ msg ] (receive (frags_of ~mtu:28 msg))
      [ msg ] (receive (frags_of ~mtu:60 msg))
      [ String.sub msg 0 16 ; String.sub msg 16 16 ; String.sub msg 32 8 ] \
        (receive ~reassemble:false (frags_of ~mtu:43 msg))
      [ String.sub msg 0 16 ; String.sub msg 16 16 ; String.sub msg 32 8 ] \
        (receive ~reassemble:false (frags_of msg))
      [ msg ] (receive [ frag 16 16 true ; frag 32 8 false ; frag 0 16 true ])
      [] (receive [ frag 0 16 true ; frag 32 8 false ])
      [] (receive [ frag 16 16 true ; frag 32 8 false ])
      [] (receive [ frag 0 16 true ; frag 16 16 true ])
      [ msg ] (receive [ frag 0 16 true ; frag 0 16 true ; frag 16 16 true ; \
                         frag 16 16 true ; frag 32 8 false ])
      [ msg ] (receive [ frag 0 8 true ; frag 0 24 true ; frag 24 16 false ])
      [ msg ] (receive [ frag 0 24 true ; frag 8 8 true ; frag 24 16 false ])
      [ msg ] (receive [ frag 8 8 true ; frag 0 24 true ; frag 16 24 false ])
      [ msg ] (receive [ frag 0 16 true ; frag 8 24 true ; frag 32 8 false ])
      [ msg ] (receive [ frag 0 16 true ; frag 16 16 true ; frag 32 8 false ; \
                         frag 16 16 true ; frag 32 8 false ])
      [ msg ; msg ] (receive [ frag 0 16 true ; frag ~id:43 0 16 true ; \
                               frag 16 24 false ; frag ~id:43 16 24 false ])
      [ msg ] (receive (refrag 36 (frags_of ~mtu:60 msg)))
      [ msg ] (receive (refrag 28 (frags_of msg)))
      [ msg ] (receive (List.rev (refrag 28 (frags_of msg))))
      [ msg ] (receive (Pdu.fragment 36 with_opts))
      [ msg ] (receive (Pdu.fragment 40 with_opts))
      (receive (frags_of ~mtu:1500 udp_wants_chk)) (receive (frags_of udp_wants_chk))
    *)
    (*$= frags_of & ~printer:string_of_int
      1 (List.length (frags_of ~mtu:60 msg))
    *)
    (*$= refrag & ~printer:string_of_int
      3 (List.length (refrag 36 (frags_of ~mtu:60 msg)))
      5 (List.length (refrag 28 (frags_of msg)))
      3 (List.length (refrag 60 (frags_of msg)))
    *)
    (*$= with_opts & ~printer:string_of_int
      4 (match Pdu.fragment 36 with_opts with \
         | _ :: f :: _ -> \
             let f = Pdu.unpack f |> Result.get_ok in \
             Bitstring.bitstring_length f.options / 8 \
         | _ -> -1)
    *)
    (*$>*)
end
