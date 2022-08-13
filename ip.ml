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

(** Internet protocols, as in [/etc/protocols]. *)
module Proto = struct
    include Private.Make (struct
        type t = int
        let to_string t =
            try (Unix.getprotobynumber t).Unix.p_name
            with Not_found ->
                Printf.sprintf "Protocol(%d)" t
        let is_valid t = t < 0x100
        let repl_tag = "proto"
    end)

    (** Some well know IP protocols. *)

    let icmp = o 1
    let tcp  = o 6
    let udp  = o 17
    let ipv6 = o 41
    let icmpv6 = o 58

    let random () = o (randi 8)
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

        (** Converts an address to it's string representation. *)
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
      (to_dotted_string (Addr.of_string "1.2.3.4")) "1.2.3.4"
    *)

    (** Convert from dotted representation (useful to allow DNS-less hosts to 'resolve' some name) *)
    let of_dotted_string str =
        try Some (o (Unix.inet_addr_of_string str))
        with Failure _ -> None

    (** Some predefined addresses *)

    (* FIXME: take bitlength in parameter *)
    let zero = o (Unix.inet_addr_of_string "0.0.0.0")
    let all_ones = o (Unix.inet_addr_of_string "255.255.255.255")
    let broadcast = all_ones

    (** Convert an {!Ip.Addr.t} to a [bitstring]. *)
    let to_bitstring (t : t) =
        let str : string = Obj.magic t in
        bitstring_of_string str

    let to_bytes (t : t) =
        Obj.magic t

    (** Convert a [bitstring] into an {!Ip.Addr.t}. *)
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

    (** Returns a random {!Ip.Addr.t} (apart from broadcast and zero). *)
    let rec random ?(v4=true) () =
        let str = randstr (if v4 then 4 else 16) in
        let t : Unix.inet_addr = Obj.magic str in
        let ip = o t in
        if ip = broadcast || ip = zero then random ()
        else ip

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

    (*$>*)
end

(** {4 CIDR Addresses} *)

(** CIDR addresses are a concise way to write network addresses,
 * with network IP then netmask length, like: 192.168.0.0/16. *)
module Cidr = struct
    (*$< Cidr *)
    include Private.Make (struct
        type t = Addr.t * int

        (** Converts a CIDR to its string representation. *)
        let to_string ((ip : Addr.t), n) =
            Addr.to_dotted_string ip ^ "/" ^ String.of_int n
        let is_valid ((ip : Addr.t), n) =
            Addr.higher_bits ip n = ip
        let repl_tag = "addr"
    end)

    let of_string str =
        let ip_str, width_str =
            try String.split str "/"
            with Not_found -> error (Printf.sprintf "not a CIDR: %s" str) in
        let ip, n = Addr.of_string ip_str, Int.of_string width_str in
        (* mask off unsignificant bits of IP *)
        o (Addr.higher_bits ip n, n)
    (*$= of_string & ~printer:to_string
      (o (Addr.o32 0x01020380l, 25)) (of_string "1.2.3.128/25")
      (o (Addr.o32 0x01020380l, 25)) (of_string "1.2.3.142/25")
     *)

    let random ?mask () =
        let mask = Option.default (Random.int 32 + 1) mask in
        let net = Addr.higher_bits (Addr.random ()) mask in
        o (net, mask)
    (*$Q of_string
      (Q.make (fun _ -> random () |> to_string)) (fun t -> t = to_string (of_string t))
     *)

    (** Build a CIDR from a single address *)
    let single ip = o (ip, 32)

    let mem (t : t) (ip : Addr.t) =
        let net, width = (t :> Addr.t * int) in
        let hb = Addr.higher_bits ip width in
        hb = net
    (*$= mem & ~printer:string_of_bool
      true  (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.0"))
      true  (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.1"))
      true  (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.15"))
      false (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.16"))
      false (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.17"))
     *)

    let to_enum (t : t) =
        let net, width = (t :> Addr.t * int) in
        let net = Addr.to_bitstring net in
        let prefix = takebits width net
        and l = bitstring_length net - width in
        all_bits l /@
        (fun suffix ->
            Bitstring.concat [ prefix ; suffix ] |>
            Addr.of_bitstring)
    (*$= to_enum & ~printer:(IO.to_string (List.print String.print))
      [ "192.168.10.42" ] (to_enum (of_string "192.168.10.42/32") /@ \
                           Addr.to_dotted_string |> \
                           List.of_enum)
      [ "192.168.10.42" ; "192.168.10.43" ] \
                           (to_enum (of_string "192.168.10.42/31") /@ \
                           Addr.to_dotted_string |> \
                           List.of_enum)
     *)

    (** Returns the subnet-zero address of a CIDR *)
    let zero_addr (t : t) =
        let net, _width = (t :> Addr.t * int) in
        net (* Cf is_valid *)
    (*$= zero_addr & ~printer:identity
      "192.168.1.0" (zero_addr (of_string "192.168.1.0/28") |> \
                     Addr.to_dotted_string)
     *)

    (** Returns the all-ones address of a CIDR *)
    let all1s_addr (t : t) =
        let net, width = (t :> Addr.t * int) in
        let prefix = takebits width (Addr.to_bitstring net) in
        Addr.of_bitstring (Bitstring.concat [ prefix ; ones_bitstring (if width >= 32 then 0 else 32 - width) ])
    (*$= all1s_addr & ~printer:identity
      "192.168.1.15"  (all1s_addr (of_string "192.168.1.0/28") |> \
                       Addr.to_dotted_string)
      "192.168.2.255" (all1s_addr (of_string "192.168.2.0/24") |> \
                       Addr.to_dotted_string)
     *)

    (** Returns the set (as an [Enum]) of all IP addresses in the given CIDR range (that is, all minus
     * subnet zero and all-ones subnet). For /32, returns the /32 singleton. For /31, return the empty
     * enum. *)
    let local_addrs (t : t) =
        let net, width = (t :> Addr.t * int) in
        if width >= Addr.length net then Enum.singleton net else
        let zero = zero_addr t and all1s = all1s_addr t in
        to_enum t // (fun ip -> ip <> zero && ip <> all1s)
    (*$= local_addrs & ~printer:dump
      [ "192.168.10.42" ] (local_addrs (of_string "192.168.10.42/32") /@ \
                           Addr.to_dotted_string |> \
                           List.of_enum)
      []                  (local_addrs (of_string "192.168.10.42/31") \
                           |> List.of_enum)
      [ "192.168.0.1" ; "192.168.0.2" ] \
                          (local_addrs (of_string "192.168.0.0/30") /@ \
                           Addr.to_dotted_string |> \
                           List.of_enum)
    *)

    let random_addrs t n =
        to_enum t |> Random.multi_choice n

    let to_netmask (t : t) =
        let net, width = (t :> Addr.t * int) in
        let tot_width = Addr.to_bitstring net |> bitstring_length in
        Bitstring.concat [ ones_bitstring width ;
                           zeroes_bitstring (tot_width - width) ] |>
        Addr.of_bitstring

    (*$= to_netmask
      "255.255.255.0" (Ip.Addr.to_string (to_netmask (of_string "192.168.0.0/24")))
     *)

    (*$>*)
end

(** {2 IP packet} *)

(** (Un)Packing an IP packet. *)
module Pdu = struct
    (*$< Pdu *)

    let id_seq = ref 0
    let next_id () = id_seq := (!id_seq + 1) land 0xffff ; !id_seq

    type t = { tos : int ; tot_len : int ;
               id : int ; dont_frag : bool ; more_frags : bool ; frag_offset : int ;
               ttl : int ; proto : Proto.t ; src : Addr.t ; dst : Addr.t ;
               options : bitstring ; payload : Payload.t }

    let make ?(tos=0) ?tot_len
             ?id ?(dont_frag=false) ?(more_frags=false)
             ?(frag_offset=0) ?(ttl=64)
             ?(options=empty_bitstring)
             proto src dst bits =
        let hdr_len = 20 + bytelength options
        and id = may_default id next_id in
        let tot_len = match tot_len with Some v -> v | None ->
            bytelength bits + hdr_len in
        { tos ; tot_len ; id ; dont_frag ; more_frags ; frag_offset ;
          ttl ; proto ; src ; dst ; options ; payload = Payload.o bits }

    let random () =
        make ~tos:(randi 8) ~id:(randi 16) ~dont_frag:(randb ())
             ~more_frags:(randb ()) ~frag_offset:(randi 13)
             ~ttl:(randi 8) ~options:(randbs (4*(randi 3)))
             (Proto.random ()) (Addr.random ()) (Addr.random ()) (randbs (Random.int 10 + 20))

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
            Printf.fprintf stderr "Ip: Cannot patch checksum at offset %d" offset ;
            pld

    let pack_header t =
        let hdr_len = 20 + bytelength t.options in
        assert (hdr_len < 64) ;
        assert (t.tot_len < 65536) ;
        assert (t.id < 65536) ;
        assert (t.frag_offset < 8192) ;
        assert (t.ttl < 256) ;
        assert ((t.proto :> int) < 256) ;
        let%bitstring hdr = {|
            4 : 4 ; hdr_len/4 : 4 ; t.tos : 8 ;
            t.tot_len : 16 ;
            t.id : 16 ; false : 1 ; t.dont_frag : 1 ; t.more_frags : 1 ; t.frag_offset : 13 ;
            t.ttl : 8 ; (t.proto :> int) : 8 ; 0 : 16 ;
            (Addr.to_int32 t.src) : 32 ; (Addr.to_int32 t.dst) : 32 |} in
        let header = concat [ hdr ; t.options ] in
        let%bitstring s = {| sum header : 16 |} in
        concat [ takebits 80 header ; s ; dropbits 96 header ]

    let pack_payload t =
        (* Patch TCP/UDP checksums since they use some fields of the IP header *)
        if t.proto = Proto.tcp then patch_checksum 128 (pseudo_header t) t.payload
        else if t.proto = Proto.udp then patch_checksum 48 (pseudo_header t) t.payload
        else t.payload

    let pack t =
        let header = pack_header t
        and payload = pack_payload t in
        concat [ header ; (payload :> bitstring) ]

    let unpack bits = match%bitstring bits with
        | {| 4 : 4 ; hdr_len : 4 ; tos : 8 ; tot_len : 16 ;
             id : 16 ; false : 1 ; dont_frag : 1 ; more_frags : 1 ; frag_offset : 13 ;
             ttl : 8 ; proto : 8 ; _checksum : 16 ;
             src : 32 ;
             dst : 32 ;
             options : (hdr_len-5)*32 : bitstring ;
             payload : (tot_len - hdr_len*4)*8 : bitstring ;
             _padding : -1 : bitstring |} ->
            (* TODO: control the checksum ? *)
            Some { tos ; tot_len ;
               id ; dont_frag ; more_frags ; frag_offset ;
               ttl ; proto = Proto.o proto ;
               src = Addr.o32 src ; dst = Addr.o32 dst ; options ;
               payload = Payload.o payload }
        | {| version : 4 |} when version <> 4 ->
            if version <> 6 then
                err (Printf.sprintf "Ip: Bad version (%d)" version)
            else None
        | {| _ |} ->
            err "Ip: Not IP"

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Option.get (unpack t)))
     *)

    (* Returns the source/dest ports from an IP PDU: *)
    let get_ports ip =
        if ip.proto = Proto.tcp then (
            Option.bind (Tcp.Pdu.unpack (ip.payload :> bitstring))
            (fun tcp ->
                Some ((tcp.Tcp.Pdu.src_port :> int),
                      (tcp.Tcp.Pdu.dst_port :> int)))
        ) else if ip.proto = Proto.udp then (
            Option.bind (Udp.Pdu.unpack (ip.payload :> bitstring))
            (fun udp ->
                Some ((udp.Udp.Pdu.src_port :> int),
                      (udp.Udp.Pdu.dst_port :> int)))
        ) else None

    (** Unpack an ip packets and return the ip PDU, source port and dest port. *)
    let unpack_with_ports bits =
        Option.bind (unpack bits) (fun ip ->
            Option.bind (get_ports ip) (fun (src_port, dst_port) ->
                Some (ip, src_port, dst_port)))
    (*$= unpack_with_ports & ~printer:dump
        (Some (42, 12)) ( \
            pack (make Proto.udp (Ip.Addr.random ()) (Ip.Addr.random ()) \
                        (Udp.Pdu.make ~src_port:(Udp.Port.o 42) \
                                      ~dst_port:(Udp.Port.o 12) \
                                      (randbs 10) |> \
                        Udp.Pdu.pack)) |> \
            unpack_with_ports |> \
            flip Option.bind \
                (fun (_, src, dst) -> Some (src, dst)) \
        )
     *)
    (*$>*)
end

(** {2 Transceiver} *)

module TRX = struct

    type t = {
        logger : Log.logger ;
        src : Addr.t ; dst : Addr.t ;
        proto : Proto.t ; mtu : int ;
        mutable emit : bitstring -> unit ;
        mutable recv : bitstring -> unit }

    let tx t bits =
        let id = Pdu.next_id () in
        let rec aux bit_offset =
            if bit_offset < bitstring_length bits then (
                let pld = dropbits bit_offset bits in
                let pld, more_frags = if bitstring_length pld <= t.mtu*8 then pld, false
                                      else takebits (t.mtu*8) pld, true in
                (* The frag_offset is given in unit of 8 bytes.
                   So the MTU is required to be a multiple of 8 bytes as well. *)
                let pdu = Pdu.make ~id ~more_frags ~frag_offset:((bit_offset+7) lsr 6) t.proto t.src t.dst pld in
                Log.(log t.logger Debug (lazy (Printf.sprintf "Ip: Emitting an IP packet from %s to %s of length %d (content '%s')" (Addr.to_dotted_string t.src) (Addr.to_dotted_string t.dst) (bytelength pld) (hexstring_of_bitstring bits)))) ;
                Clock.asap t.emit (Pdu.pack pdu) ;
                aux (bit_offset + bitstring_length pld)
            ) in
        aux 0

    (* TODO: check checksum? *)
    (* TODO: handle fragmentation *)
    let rx t bits = (match Pdu.unpack bits with
        | None -> ()
        | Some ip ->
            if Payload.bitlength ip.Pdu.payload > 0 then Clock.asap t.recv (ip.Pdu.payload :> bitstring))

    (* Note: In Eth we do not require dst addr since the trx know (using ARP) how to get dest addr itself.
     *       IP cannot do this since the application layer won't tell him the destination hostname. Or
     *       we must add the destination to any tx call, making host layer simpler only at the expense of
     *       this layer. *)
    let make ?(mtu=1400) src dst proto logger =
        ensure ((mtu mod 8) = 0) "Ip: MTU is required to be a multiple of 8 bytes" ;
        let t = { logger ; src ; dst ; proto ; mtu ;
                  emit = ignore_bits logger ; recv = ignore_bits logger } in
        { ins = { write = tx t ;
                  set_read = fun f -> t.recv <- f } ;
          out = { write = rx t ;
                  set_read = fun f -> t.emit <- f } }

end

