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
            bits_equal net_hi ip_hi
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

    (** The options of an IP header (RFC 791). *)
    module Opt =
    struct
        (*$< Opt *)

        (* What a timestamp option records, according to its flag: *)
        type stamps =
            | Stamps of int32 list (* flag 0 *)
            | Addr_stamps of (Addr.t * int32) list (* flag 1 *)
            | Prespecified of (Addr.t * int32) list (* flag 3 *)

        (* Pointers are in bytes from the start of the option, 1 based: *)
        type t =
            | Eol of bitstring (* the padding *)
            | Nop
            | Rr of int * Addr.t list (* pointer and route *)
            | Lsr of int * Addr.t list
            | Ssr of int * Addr.t list
            | Ts of int * int * stamps (* pointer, overflow and stamps *)
            | Other of bitstring (* an unknown or malformed option, type and length included *)

        (* For the header length to fit in its 4 bits: *)
        let max_len = 40

        (* Whether the fragments after the first carry it too: *)
        let copied = function
            | Lsr _ | Ssr _ -> true
            | Other bits -> bitstring_length bits > 0 && is_set bits 0
            | Eol _ | Nop | Rr _ | Ts _ -> false

        let pack_addr a = [%bitstring {| (Addr.to_int32 a) : 32 |}]

        let pack_route typ ptr route =
            concat ([%bitstring {| typ : 8 ; 3 + 4 * List.length route : 8 ; ptr : 8 |}] ::
                    List.map pack_addr route)

        let pack_one = function
            | Eol rest ->
                concat [ [%bitstring {| 0 : 8 |}] ; rest ]
            | Nop ->
                [%bitstring {| 1 : 8 |}]
            | Rr (ptr, route) ->
                pack_route 7 ptr route
            | Lsr (ptr, route) ->
                pack_route 131 ptr route
            | Ssr (ptr, route) ->
                pack_route 137 ptr route
            | Ts (ptr, overflow, stamps) ->
                let stamp s = [%bitstring {| s : 32 |}] in
                let addr_stamp (a, s) = concat [ pack_addr a ; stamp s ] in
                let flag, data =
                    match stamps with
                    | Stamps l -> 0, List.map stamp l
                    | Addr_stamps l -> 1, List.map addr_stamp l
                    | Prespecified l -> 3, List.map addr_stamp l in
                let data = concat data in
                concat [ [%bitstring {| 68 : 8 ; 4 + bytelength data : 8 ; ptr : 8 ;
                                        overflow : 4 ; flag : 4 |}] ; data ]
            | Other bits ->
                bits

        (* Zero padded to a whole number of 32 bits words: *)
        let pack opts =
            let bits = concat (List.map pack_one opts) in
            match bytelength bits land 3 with
            | 0 -> bits
            | r -> concat [ bits ; zeroes_bitstring (8 * (4 - r)) ]

        let rec addrs bits =
            match%bitstring bits with
            | {| a : 32 ; rest : -1 : bitstring |} -> Addr.o32 a :: addrs rest
            | {| _ |} -> []

        let rec stamps bits =
            match%bitstring bits with
            | {| s : 32 ; rest : -1 : bitstring |} -> s :: stamps rest
            | {| _ |} -> []

        let rec addr_stamps bits =
            match%bitstring bits with
            | {| a : 32 ; s : 32 ; rest : -1 : bitstring |} -> (Addr.o32 a, s) :: addr_stamps rest
            | {| _ |} -> []

        (* [tlv] is a whole option, of the length it says: *)
        let decode tlv =
            match%bitstring tlv with
            | {| typ : 8 ; len : 8 ; ptr : 8 ; route : -1 : bitstring |}
              when (typ = 7 || typ = 131 || typ = 137) && (len - 3) land 3 = 0 ->
                let route = addrs route in
                if typ = 7 then Rr (ptr, route)
                else if typ = 131 then Lsr (ptr, route)
                else Ssr (ptr, route)
            | {| 68 : 8 ; len : 8 ; ptr : 8 ; overflow : 4 ; flag : 4 ; data : -1 : bitstring |}
              when flag = 0 && (len - 4) land 3 = 0 ->
                Ts (ptr, overflow, Stamps (stamps data))
            | {| 68 : 8 ; len : 8 ; ptr : 8 ; overflow : 4 ; flag : 4 ; data : -1 : bitstring |}
              when (flag = 1 || flag = 3) && (len - 4) land 7 = 0 ->
                let l = addr_stamps data in
                Ts (ptr, overflow, if flag = 1 then Addr_stamps l else Prespecified l)
            | {| _ |} -> Other tlv

        (* Past an option whose length cannot be right, there is no telling
         * where the next one starts: *)
        let rec unpack bits =
            match%bitstring bits with
            | {| 0 : 8 ; rest : -1 : bitstring |} ->
                [ Eol rest ]
            | {| 1 : 8 ; rest : -1 : bitstring |} ->
                Nop :: unpack rest
            | {| _ : 8 ; len : 8 |} when len >= 2 && 8 * len <= bitstring_length bits ->
                decode (takebytes len bits) :: unpack (dropbytes len bits)
            | {| _ |} ->
                if bitstring_length bits = 0 then [] else [ Other bits ]

        (* In the manner of tcpdump, empty slots of a route included: *)
        let to_string =
            let route name ptr route =
                Printf.sprintf "%s ptr=%d%s" name ptr
                    (String.concat "" (List.map (fun a ->
                        " "^ Addr.to_dotted_string a) route))
            and addr_stamps l =
                String.concat "" (List.map (fun (a, s) ->
                    Printf.sprintf " %s@%lu" (Addr.to_dotted_string a) s) l) in
            function
            | Eol _ -> "EOL"
            | Nop -> "NOP"
            | Rr (ptr, r) -> route "RR" ptr r
            | Lsr (ptr, r) -> route "LSR" ptr r
            | Ssr (ptr, r) -> route "SSR" ptr r
            | Ts (ptr, overflow, stamps) ->
                Printf.sprintf "TS ptr=%d oflw=%d%s" ptr overflow
                    (match stamps with
                    | Stamps l ->
                        String.concat "" (List.map (Printf.sprintf " %lu") l)
                    | Addr_stamps l -> " addr" ^ addr_stamps l
                    | Prespecified l -> " prespec" ^ addr_stamps l)
            | Other bits -> "opt " ^ hexstring ~sep:"" (string_of_bitstring bits)

        let list_to_string opts =
            String.concat ", " (List.map to_string opts)

        (*$= unpack & ~printer:identity
          "RR ptr=8 1.2.3.4 0.0.0.0, NOP, EOL" \
            (list_to_string (unpack (bitstring_of_string \
              "\x07\x0b\x08\x01\x02\x03\x04\x00\x00\x00\x00\x01\x00\x00\x00\x00")))
          "LSR ptr=4 10.0.0.1, SSR ptr=4 10.0.0.2" \
            (list_to_string (unpack (bitstring_of_string \
              "\x83\x07\x04\x0a\x00\x00\x01\x89\x07\x04\x0a\x00\x00\x02")))
          "TS ptr=9 oflw=2 1 2, EOL" \
            (list_to_string (unpack (bitstring_of_string \
              "\x44\x0c\x09\x20\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00")))
          "TS ptr=13 oflw=0 addr 1.2.3.4@7, TS ptr=5 oflw=0 prespec 5.6.7.8@0" \
            (list_to_string (unpack (bitstring_of_string \
              ("\x44\x0c\x0d\x01\x01\x02\x03\x04\x00\x00\x00\x07" ^ \
               "\x44\x0c\x05\x03\x05\x06\x07\x08\x00\x00\x00\x00"))))
          "opt 820300, NOP" \
            (list_to_string (unpack (bitstring_of_string "\x82\x03\x00\x01")))
          "opt 07040000, NOP" \
            (list_to_string (unpack (bitstring_of_string "\x07\x04\x00\x00\x01")))
          "NOP, opt 070800" \
            (list_to_string (unpack (bitstring_of_string "\x01\x07\x08\x00")))
          "opt 440500004E, NOP" \
            (list_to_string (unpack (bitstring_of_string "\x44\x05\x00\x00\x4e\x01")))
         *)
        (*$Q unpack
          Q.(int_bound 10) (fun n -> \
            let b = randbs (4 * n) in Bitstring.equals b (pack (unpack b)))
         *)
        (*$= copied & ~printer:identity
          "opt 820300, LSR ptr=4" \
            (list_to_string (List.filter copied (unpack (bitstring_of_string \
              "\x07\x03\x00\x01\x82\x03\x00\x83\x03\x04\x00\x00"))))
         *)

        let random () =
            let route () = List.init (Random.int 3) (fun _ -> Addr.random ()) in
            let ptr () = 4 + 4 * Random.int 3 in
            let addr_stamps () =
                List.init (Random.int 3) (fun _ -> Addr.random (), rand32 ()) in
            let one () =
                match Random.int 6 with
                | 0 -> Nop
                | 1 -> Rr (ptr (), route ())
                | 2 -> if Random.bool () then Lsr (ptr (), route ())
                       else Ssr (ptr (), route ())
                | 3 ->
                    let stamps =
                        match Random.int 3 with
                        | 0 -> Stamps (List.init (Random.int 3) (fun _ -> rand32 ()))
                        | 1 -> Addr_stamps (addr_stamps ())
                        | _ -> Prespecified (addr_stamps ()) in
                    Ts (1 + ptr (), Random.int 16, stamps)
                | _ ->
                    let typ = 30 + 32 * Random.int 3 (* experimental, RFC 4727 *)
                    and len = 2 + Random.int 5 in
                    Other (concat [ [%bitstring {| typ : 8 ; len : 8 |}] ; randbs (len - 2) ]) in
            let opts = List.init (Random.int 4) (fun _ -> one ()) in
            let opts =
                if Random.bool () then opts
                else opts @ [ Eol (randbs (Random.int 4)) ] in
            let rec fit opts =
                if bytelength (pack opts) <= max_len then opts
                else fit (List.take (List.length opts - 1) opts) in
            fit opts

        module Kinds =
        struct
            open SimTypes
            let after_eol = BRange (0, max_len - 1)
            let ptr = IRange (0, 0xff)
            let addr = Widget.hint "192.168.0.1" Ipv4
            let route = Widget.record [| "pointer", ptr ; "route", Widget.list addr |]
            let stamp = IRange (0, 0xffff_ffff)
            let addr_stamp = Widget.row [| "address", addr ; "timestamp", stamp |]
            let stamps =
                Widget.variant [|
                    "timestamps", Some (Widget.list stamp) ;
                    "addresses and timestamps", Some (Widget.list addr_stamp) ;
                    "prespecified", Some (Widget.list addr_stamp) |]
            let overflow = IRange (0, 15)
            let timestamp =
                Widget.record [| "pointer", ptr ; "overflow", overflow ; "stamps", stamps |]
            let other = BRange (1, max_len)
            let opt =
                Widget.variant [|
                    "EOL", Some after_eol ;
                    "NOP", None ;
                    "record route", Some route ;
                    "loose source route", Some route ;
                    "strict source route", Some route ;
                    "timestamp", Some timestamp ;
                    "other", Some other |]
        end

        let to_json opt : Yojson.Basic.t =
            let u32 n = `Int (uint32 n) in
            let route ptr r =
                `Assoc [ "pointer", `Int ptr ; "route", `List (List.map Addr.to_json r) ]
            and addr_stamps l =
                `List (List.map (fun (a, s) ->
                    `Assoc [ "address", Addr.to_json a ; "timestamp", u32 s ]) l) in
            match opt with
            | Eol rest -> `Assoc [ "EOL", Widget.json_of_bytes rest ]
            | Nop -> `Assoc [ "NOP", `Null ]
            | Rr (ptr, r) -> `Assoc [ "record route", route ptr r ]
            | Lsr (ptr, r) -> `Assoc [ "loose source route", route ptr r ]
            | Ssr (ptr, r) -> `Assoc [ "strict source route", route ptr r ]
            | Ts (ptr, overflow, stamps) ->
                let stamps =
                    match stamps with
                    | Stamps l -> `Assoc [ "timestamps", `List (List.map u32 l) ]
                    | Addr_stamps l -> `Assoc [ "addresses and timestamps", addr_stamps l ]
                    | Prespecified l -> `Assoc [ "prespecified", addr_stamps l ] in
                `Assoc [ "timestamp", `Assoc [ "pointer", `Int ptr ;
                                               "overflow", `Int overflow ;
                                               "stamps", stamps ] ]
            | Other bits -> `Assoc [ "other", Widget.json_of_bytes bits ]

        (* [js] is the synth of an option of [Kinds.opt], as [Generator.expand]
         * leaves it. Automatic values make an option with one empty slot: *)
        let of_synth gen_values js =
            let open Generator in
            let int ~auto name kind v = int_of_field name gen_values ~auto kind identity v
            and addr v =
                of_value gen_values ~auto:(fun () -> Addr.zero) Kinds.addr
                         (Addr.of_dotted_string % Widget.to_string) v
            and stamp v =
                Int32.of_int (of_value gen_values ~auto:(fun () -> 0) Kinds.stamp
                                       Widget.to_int v) in
            (* An automatic list has one element: *)
            let list kind f = function
                | `Null -> [ f `Null ]
                | v -> expand gen_values kind v |> Widget.to_list f in
            let addr_stamp v =
                let v = expand gen_values Kinds.addr_stamp v in
                Widget.to_field "address" addr v, Widget.to_field "timestamp" stamp v in
            let route make v =
                let v = expand gen_values Kinds.route v in
                make (int ~auto:(fun () -> 4) "pointer" Kinds.ptr v,
                      Widget.to_field "route" (list (Widget.list Kinds.addr) addr) v) in
            match js with
            | `Assoc [ "EOL", v ] ->
                Eol (bs_of_value gen_values ~auto:(fun () -> empty_bitstring)
                                 Kinds.after_eol v)
            | `Assoc [ "NOP", _ ] ->
                Nop
            | `Assoc [ "record route", v ] -> route (fun (p, r) -> Rr (p, r)) v
            | `Assoc [ "loose source route", v ] -> route (fun (p, r) -> Lsr (p, r)) v
            | `Assoc [ "strict source route", v ] -> route (fun (p, r) -> Ssr (p, r)) v
            | `Assoc [ "timestamp", v ] ->
                let v = expand gen_values Kinds.timestamp v in
                let stamps =
                    match Widget.to_field "stamps" identity v with
                    | `Null -> Stamps [ 0l ]
                    | s ->
                        (match expand gen_values Kinds.stamps s with
                        | `Assoc [ "timestamps", l ] ->
                            Stamps (list (Widget.list Kinds.stamp) stamp l)
                        | `Assoc [ "addresses and timestamps", l ] ->
                            Addr_stamps (list (Widget.list Kinds.addr_stamp) addr_stamp l)
                        | `Assoc [ "prespecified", l ] ->
                            Prespecified (list (Widget.list Kinds.addr_stamp) addr_stamp l)
                        | js -> Widget.bad_value "not timestamps: %s" (Yojson.Basic.to_string js)) in
                Ts (int ~auto:(fun () -> 5) "pointer" Kinds.ptr v,
                    int ~auto:(fun () -> 0) "overflow" Kinds.overflow v, stamps)
            | `Assoc [ "other", v ] ->
                (* An option of an experimental type (RFC 4727), carrying nothing: *)
                Other (bs_of_value gen_values ~auto:(fun () -> bitstring_of_string "\x1e\x02")
                                   Kinds.other v)
            | js ->
                Widget.bad_value "not an IP option: %s" (Yojson.Basic.to_string js)

        (*$>*)
    end

    (* IP ids are the top 16 bits of a xorshift32 generator: not sequential,
     * and of period 2^32-1. Faster than what's doable with Random and
     * independent of the simulation random generator. *)
    let id_seq = ref 0
    let next_id () =
        let x = !id_seq in
        let x = if x = 0 then 1 + Random.full_int 0xffff_ffff else x in
        let x = x lxor ((x lsl 13) land 0xffff_ffff) in
        let x = x lxor (x lsr 17) in
        let x = x lxor ((x lsl 5) land 0xffff_ffff) in
        id_seq := x ;
        x lsr 16

    type t = { tos : ToS.t ; tot_len : int ;
               id : int ; dont_frag : bool ; more_frags : bool ; frag_offset : int ;
               ttl : int ; proto : Proto.t ; src : Addr.t ; dst : Addr.t ;
               options : Opt.t list ; payload : Payload.t }

    let hdr_len t = no_opt_hdr_len + bytelength (Opt.pack t.options)

    let make ?(tos=ToS.o 0) ?tot_len
             ?id ?(dont_frag=false) ?(more_frags=false)
             ?(frag_offset=0) ?(ttl=64)
             ?(options=[])
             proto src dst bits =
        let hdr_len = no_opt_hdr_len + bytelength (Opt.pack options)
        and id = may_default id next_id in
        let tot_len = match tot_len with Some v -> v | None ->
            bytelength bits + hdr_len in
        { tos ; tot_len ; id ; dont_frag ; more_frags ; frag_offset ;
          ttl ; proto ; src ; dst ; options ; payload = Payload.o bits }

    let random () =
        make ~tos:(ToS.random ()) ~id:(randi 16) ~dont_frag:(randb ())
             ~more_frags:(randb ()) ~frag_offset:(randi 13)
             ~ttl:(randi 8) ~options:(Opt.random ())
             (Proto.random ()) (Addr.random ()) (Addr.random ()) (randbs (Random.int 10 + no_opt_hdr_len))

    let pseudo_header t () =
        let%bitstring r = {|
            (Addr.to_int32 t.src) : 32 ; (Addr.to_int32 t.dst) : 32 ;
            0 : 8 ; (t.proto :> int) : 8 ; Payload.length (t.payload) : 16 |} in
        r

    (* The checksum to write [offset] bits into [pld] for it to cover
     * [pseudo_header] too, unless it has one already: *)
    let missing_checksum ?(fixit=identity) offset pseudo_header (pld : Payload.t) =
        match%bitstring (pld :> bitstring) with
        | {| head : offset : bitstring ;
             chk  : 16 ;
             tail : -1 : bitstring |} (* FIXME: for TCP, force urgent pointer at 0 if the urgent flag is unset *) ->
            if chk = 0 then
                Some (sum_list [ pseudo_header () ; head ; zeroes_bitstring 16 ; tail ] |>
                      fixit)
            else None
        | {| _ |} ->
            Printf.eprintf "Ip: Cannot patch checksum at offset %d, payload: %s\n"
                offset (hexstring_of_bitstring_abbrev ~bits:(offset + 16) (pld :> bitstring)) ;
            None

    (* [offset] is whole bytes, as the checksum of every protocol lies: *)
    let patch_checksum ?fixit offset pseudo_header (pld : Payload.t) =
        match missing_checksum ?fixit offset pseudo_header pld with
        | None -> pld
        | Some chk ->
            let (b, _, _) as bits = concat [ (pld :> bitstring) ] in
            Bytes.set_uint16_be b (offset lsr 3) chk ;
            Payload.o bits

    let pack_header t =
        let options = Opt.pack t.options in
        if bytelength options > Opt.max_len then
            invalid_arg "Ip.Pdu.pack: more than 40 bytes of options" ;
        let hdr_len = no_opt_hdr_len + bytelength options in
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
        let header = concat [ hdr ; options ] in
        let%bitstring s = {| sum header : 16 |} in
        concat [ takebits 80 header ; s ; dropbits 96 header ]

    let is_fragment t = t.more_frags || t.frag_offset > 0

    (* Where the TCP/UDP checksum lies in the payload, in bits, since it uses
     * some fields of the IP header. It covers the whole L4 PDU, so a fragment
     * has none of its own: *)
    let checksum_offset t =
        if is_fragment t then None
        else if t.proto = Proto.tcp then Some 128
        else if t.proto = Proto.udp then Some 48
        else None

    let pack_payload t =
        match checksum_offset t with
        | Some offset -> patch_checksum offset (pseudo_header t) t.payload
        | None -> t.payload

    let pack t =
        let header = pack_header t in
        let missing =
            Option.bind (checksum_offset t) (fun offset ->
                Option.map (fun chk -> offset, chk)
                    (missing_checksum offset (pseudo_header t) t.payload)) in
        match missing with
        | Some (offset, chk) when is_whole_bytes header ->
            (* Written straight into the packet rather than into a copy of the
             * payload: *)
            let (b, _, _) as bits = concat [ header ; (t.payload :> bitstring) ] in
            Bytes.set_uint16_be b (bytelength header + offset lsr 3) chk ;
            bits
        | Some _ ->
            concat [ header ; (pack_payload t :> bitstring) ]
        | None ->
            concat [ header ; (t.payload :> bitstring) ]

    (** [bits], a packet [unpack] accepted with a TTL above 0, with that TTL
     * one less and its header checksum adjusted to match (RFC 1624), cut to
     * the total length it announces. Nothing else changes, the checksum of
     * the payload included. *)
    let decr_ttl bits =
        let tot_len = match%bitstring bits with
            | {| _ : 16 ; tot_len : 16 ; _ |} -> tot_len
            | {| _ |} -> invalid_arg "Ip.Pdu.decr_ttl" in
        let len = min (bitstring_length bits) (tot_len * 8) in
        let b = Bytes.unsafe_of_string (string_of_bitstring (takebits len bits)) in
        let old_w = Bytes.get_uint16_be b 8 in
        let new_w = old_w - 0x100 in
        Bytes.set_uint16_be b 8 new_w ;
        let s = (lnot (Bytes.get_uint16_be b 10) land 0xffff) +
                (lnot old_w land 0xffff) + new_w in
        let rec wrap s =
            if s < 0x10000 then s else wrap ((s land 0xffff) + (s lsr 16)) in
        Bytes.set_uint16_be b 10 (lnot (wrap s) land 0xffff) ;
        b, 0, len
    (*$Q decr_ttl
      (Q.make (fun _ -> random ())) (fun t -> \
        t.ttl = 0 || \
        Bitstring.equals (decr_ttl (pack t)) (pack { t with ttl = t.ttl - 1 }))
     *)

    (** Split [t] into packets of at most [mtu] bytes. [t] can itself be a
     * fragment, so offsets and MF flag are relative to its own. The DF flag is
     * not checked.
     * Raises Invalid_argument if [mtu] leaves no room for 8 bytes of payload. *)
    let fragment mtu t =
        let len = Payload.length t.payload in
        let hdr_len options = hdr_len { t with options } in
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
            else loop (List.filter Opt.copied t.options) (pos + n) (bits:: acc) in
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
               src = Addr.o32 src ; dst = Addr.o32 dst ;
               options = Opt.unpack options ; payload = Payload.o payload }
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
        let options = Widget.list Opt.Kinds.opt
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
                 "options", `List (List.map Opt.to_json t.options) ;
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
         * fragment of every packet, and random options a header nothing
         * can read past -- either way what is above is no longer a segment
         * anybody recognises. *)
        let options =
            nth r Field.options (function
                | `Null -> []
                | js -> expand gen_values Kinds.options js |>
                        Widget.to_list (Opt.of_synth gen_values)) in
        let options_len = bytelength (Opt.pack options) in
        if options_len > Opt.max_len then
            Widget.bad_value "options: %d bytes, more than %d" options_len Opt.max_len ;
        let payload = payload_of_nth ?upper r Field.payload gen_values
                                     Kinds.payload in
        { tos = int Field.tos ~auto:(fun () -> ToS.o 0) Kinds.tos ToS.o ;
          tot_len = int Field.tot_len
                        ~auto:(fun () ->
                            no_opt_hdr_len + options_len + bytelength payload)
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
        (* Set the DF bit of emitted packets (and fragments!) to this value,
         * unless [tx] is told otherwise: *)
        dont_frag : bool ;
        (* Perform reassembly before handing over received frames: *)
        reassemble : bool ;
        (* [tos], [ttl] and [options] (up to 40 bytes) for all emitted
         * packets, unless [tx] is told otherwise: *)
        tos : ToS.t ;
        ttl : int ;
        options : Pdu.Opt.t list ;
        next_id : unit -> int ;
        mutable emit : bitstring -> unit ;
        mutable emit_busy_for : unit -> Clock.Interval.t ;
        mutable recv : bitstring -> unit ;
        mutable recv_busy_for : unit -> Clock.Interval.t ;
        (* Fragments, sorted by frag_offset. The ref is to compare with `==`.
         * See [reassemble_into]. *)
        reassembled : (reassemble_key, Pdu.t list ref) Hashtbl.t
    }

    (* We might want to reassemble packets that are not destined to [t.src] (broadcast, ICMP
     * error, wtv) so let's use the IPs in additon to the ID to identify reassembled packets: *)
    and reassemble_key = Addr.t * Addr.t * Proto.t * int (* src, dst, proto, id *)

    let options_len options = bytelength (Pdu.Opt.pack options)

    let check_options options =
        ensure (options_len options <= Pdu.Opt.max_len) "Ip: options must fit in 40 bytes"

    (* Raises Invalid_argument if the MTU leaves no room for 8 bytes of
     * payload after the options: *)
    let tx ?tos ?ttl ?id ?dont_frag ?options t bits =
        Option.may check_options options ;
        if bitstring_length bits > 0 then (
            let tos = tos |? t.tos
            and ttl = ttl |? t.ttl
            and id = may_default id t.next_id
            and dont_frag = dont_frag |? t.dont_frag
            and options = options |? t.options in
            let pdu =
                Pdu.make ~tos ~ttl ~id ~dont_frag ~options t.proto t.src t.dst bits in
            Pdu.fragment t.mtu pdu |>
            List.iter (fun bits ->
                Log.(log t.logger Debug (lazy (Printf.sprintf "Ip: Emitting an IP packet from %s to %s of length %d (content '%s')" (Addr.to_dotted_string t.src) (Addr.to_dotted_string t.dst) (Payload.length pdu.payload) (hexstring_of_bitstring bits)))) ;
                Simulation.asap t.power t.emit bits)
        )

    (* As Linux's ipfrag_time: *)
    let reassembly_timeout = Clock.Interval.sec 30.

    (** The payload of the packet [ip] is a fragment of, once [reassembled]
     * (the fragments received so far) has all of them, unless it took more
     * than [reassembly_timeout] since the first one. *)
    let reassemble_into power reassembled (ip : Pdu.t) =
        let key = ip.src, ip.dst, ip.proto, ip.id in
        match Hashtbl.find reassembled key with
        | exception Not_found ->
            let line = ref [ ip ] in
            Hashtbl.add reassembled key line ;
            (* A later packet may have reused the key by then.
             * TODO: an ICMP Time Exceeded (code 1) if the first fragment
             * was received (RFC 792). *)
            Simulation.delay power reassembly_timeout (fun () ->
                match Hashtbl.find_option reassembled key with
                | Some l when l == line -> Hashtbl.remove reassembled key
                | _ -> ()) () ;
            None
        | line ->
            let frags = !line in
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
                Hashtbl.remove reassembled key ;
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
                line := frags ;
                None
            )

    let reassemble t ip = reassemble_into t.power t.reassembled ip

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
    let create power ?(mtu=1500) ?(dont_frag=false) ?(reassemble=true)
               ?(tos=ToS.o 0) ?(ttl=64) ?(options=[]) ?(next_id=Pdu.next_id)
               src dst proto logger =
        check_options options ;
        ensure (mtu >= Pdu.no_opt_hdr_len + options_len options + 8)
            "Ip: MTU must leave room for at least 8 bytes of payload" ;
        { logger ; power ; src ; dst ; proto ; mtu ; dont_frag ; reassemble ;
          tos ; ttl ; options ; next_id ;
          emit = ignore_bits ~logger ; emit_busy_for = never_busy ;
          recv = ignore_bits ~logger ; recv_busy_for = never_busy ;
          reassembled = Hashtbl.create 10 }

    let trx_of t =
        { ins = { write = tx t ;
                  busy_for = (fun () -> t.emit_busy_for ()) ;
                  set_read = fun f busy_for ->
                      t.recv <- f ; t.recv_busy_for <- busy_for } ;
          out = { write = rx t ;
                  busy_for = (fun () -> t.recv_busy_for ()) ;
                  set_read = fun f busy_for ->
                      t.emit <- f ; t.emit_busy_for <- busy_for } }

    let make power ?mtu ?dont_frag ?reassemble ?tos ?ttl ?options ?next_id
             src dst proto logger =
        trx_of (create power ?mtu ?dont_frag ?reassemble ?tos ?ttl ?options
                       ?next_id src dst proto logger)

    (*$< TRX *)
    (* [frags_of s] is what a TRX from [a] to [b] emits for [s]; [frag off len mf]
     * is a hand made fragment of [msg] (offsets and lengths in bytes);
     * [receive pkts] is what [b] hands over after receiving [pkts] in order;
     * and [emitted t s] the ToS, TTL and id of what [t] emits for [s]. *)
    (*$inject
      let sim = Simulation.make ~realtime:false "ip-frags"
      let a = Addr.of_string "10.0.0.1" and b = Addr.of_string "10.0.0.2"
      let msg = "0123456789abcdefghijklmnopqrstuvwxyzABCD"

      let frags_of ?(mtu=36) s =
        let trx = make sim.root.power ~mtu a b Proto.udp sim.root.logger in
        let out = ref [] in
        trx.out --> sink (fun bits -> out := bits :: !out) ;
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
        trx.ins --> sink (fun bits -> got := Bitstring.string_of_bitstring bits :: !got) ;
        List.iter trx.out.write pkts ;
        Simulation.run sim false ;
        List.rev !got

      let refrag mtu pkts =
        List.concat_map (fun bits ->
          Pdu.fragment mtu (Result.get_ok (Pdu.unpack bits))
        ) pkts

      let with_opts =
        Bitstring.bitstring_of_string msg |>
        Pdu.make ~options:(Pdu.Opt.unpack (Bitstring.bitstring_of_string "\x07\x03\x00\x01\x82\x03\x00\x00"))
                 Proto.udp a b

      let udp_wants_chk = "\x00\x01\x00\x02\x00\x30\x00\x00" ^ msg

      let printer = IO.to_string (List.print String.print)

      let emitted ?tos ?ttl ?id t s =
        let out = ref [] in
        (trx_of t).out --> sink (fun bits -> out := Result.get_ok (Pdu.unpack bits) :: !out) ;
        tx ?tos ?ttl ?id t (Bitstring.bitstring_of_string s) ;
        Simulation.run sim false ;
        List.rev_map (fun (p : Pdu.t) -> (p.tos :> int), p.ttl, p.id) !out

      let counter () =
        let n = ref 6 in
        fun () -> incr n ; !n

      let hdr_printer = IO.to_string (List.print (Tuple3.print Int.print Int.print Int.print))
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
    (*$R
      (* Fragments [d] apart: *)
      let receive_apart d =
        let trx = make sim.root.power b a Proto.udp sim.root.logger in
        let got = ref [] in
        trx.ins --> sink (fun bits -> got := Bitstring.string_of_bitstring bits :: !got) ;
        trx.out.write (frag 0 16 true) ;
        Simulation.delay sim.root.power d trx.out.write (frag 16 24 false) ;
        Simulation.run sim false ;
        !got in
      assert_equal ~printer [ msg ] (receive_apart (Clock.Interval.sec 29.)) ;
      assert_equal ~printer [] (receive_apart (Clock.Interval.sec 31.))
    *)
    (*$= emitted & ~printer:hdr_printer
      [ 0x10, 3, 7 ] \
        (emitted (create sim.root.power ~tos:(ToS.o 0x10) ~ttl:3 ~next_id:(counter ()) \
                         a b Proto.udp sim.root.logger) "hello")
      [ 0x20, 1, 99 ] \
        (emitted ~tos:(ToS.o 0x20) ~ttl:1 ~id:99 \
                 (create sim.root.power ~tos:(ToS.o 0x10) ~ttl:3 ~next_id:(counter ()) \
                         a b Proto.udp sim.root.logger) "hello")
      [ 0x20, 1, 7 ; 0x20, 1, 7 ; 0x20, 1, 7 ] \
        (emitted ~tos:(ToS.o 0x20) ~ttl:1 \
                 (create sim.root.power ~mtu:36 ~next_id:(counter ()) \
                         a b Proto.udp sim.root.logger) msg)
    *)
    (*$R tx
      let t = create sim.root.power ~dont_frag:true a b (Proto.o 99) sim.root.logger in
      let dfs = ref [] in
      (trx_of t).out --> sink (fun bits ->
          dfs := (Result.get_ok (Pdu.unpack bits)).Pdu.dont_frag :: !dfs) ;
      tx t (Bitstring.bitstring_of_string "a") ;
      tx ~dont_frag:false t (Bitstring.bitstring_of_string "b") ;
      Simulation.run sim false ;
      assert_equal [ true ; false ] (List.rev !dfs)
    *)
    (*$R tx
      let t = create sim.root.power ~options:Pdu.Opt.[ Rr (4, [ Addr.zero ]) ]
                     a b (Proto.o 99) sim.root.logger in
      let opts = ref [] in
      (trx_of t).out --> sink (fun bits ->
          opts := Pdu.Opt.list_to_string (Result.get_ok (Pdu.unpack bits)).Pdu.options :: !opts) ;
      tx t (Bitstring.bitstring_of_string "a") ;
      tx ~options:[] t (Bitstring.bitstring_of_string "b") ;
      Simulation.run sim false ;
      assert_equal ~printer [ "RR ptr=4 0.0.0.0, EOL" ; "" ] (List.rev !opts)
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
             Bitstring.bitstring_length (Pdu.Opt.pack f.options) / 8 \
         | _ -> -1)
    *)
    (*$>*)
end
