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
(**
 * Everything related to IPv4 packets: (un)packing, addresses, transceiver...
 *
 * TODO: Some usual IP options should be understood.
 *)
open Batteries
open Bitstring
open Tools

let debug = false

(** {2 Private Types} *)

(** {3 Protocols} *)

(** Internet protocols, as in [/etc/protocols]. *)
module Proto = struct
    include MakePrivate(struct
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

    let random () = o (randi 8)
end

(** {3 Addresses} *)

(** {4 inet_addr}
 *
 * Stdlib [Unix] module already have a type for IP addresses:
 * [Unix.inet_addr] (actually a [string]). Here are the functions
 * to convert our address ([int32]) from/to [inet_addr]. *)

(** Convert an [inet_addr] into an [int32]... *)
let int32_of_inet_addr a =
    bitmatch (bitstring_of_string (Obj.magic a)) with
    | { i : 32 } -> i

(** ... and the other way around. *)
let inet_addr_of_int32 i : Unix.inet_addr =
    Obj.magic (string_of_bitstring (BITSTRING { i : 32 }))

(** Printer (in the sense of Batteries) for inet_addrs *)
let inet_addr_print oc a =
    Printf.fprintf oc "%s" (Unix.string_of_inet_addr a)

(** {4 IP Addresses as int32} *)

(** We use a private type for IPv4 addresses so that we can have a
 * custom printer, but it's actually an [int32] and you can cast with:
 * [(addr :> int32)] in one direction and [Ip.Addr.o int] in the other. *)
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

    (** Regardless of the above setting, return the dotted representation (a
     * [string] of a given [int32]. *)
    let dotted_string_of_int32 i = bitmatch (BITSTRING { i : 32 }) with
        { a : 8 ; b : 8 ; c : 8 ; d : 8 } -> Printf.sprintf "%d.%d.%d.%d" a b c d
    (*$= dotted_string_of_int32 & ~printer:identity
      (dotted_string_of_int32 ((Addr.of_string "1.2.3.4") :> int32)) "1.2.3.4"
    *)

    include MakePrivate(struct
        type t = int32
        (** Converts an address to it's string representation. *)
        let to_string t =
            if !print_as_names then
                try (Unix.gethostbyaddr (inet_addr_of_int32 t)).Unix.h_name
                with Not_found ->
                    dotted_string_of_int32 t
            else
                dotted_string_of_int32 t
        let is_valid _ = true
        let repl_tag = "addr"
    end)

    (** Some predefined addresses *)

    let zero = o 0l
    let broadcast = o 0xffffffffl

    (** Convert an {!Ip.Addr.t} to dotted representation. *)
    let to_dotted_string (t : t) = dotted_string_of_int32 (t :> int32)

    (** Convert an {!Ip.Addr.t} to a [bitstring]. *)
    let to_bitstring (t : t) = (BITSTRING { (t :> int32) : 32 })
    (** Convert a [bitstring] into an {!Ip.Addr.t}. *)
    let of_bitstring bits = bitmatch bits with
        | { ip : 32 } -> o ip
        | { _ } -> should_not_happen ()
    let list_of_string str =
        let extract_addr info = match info.Unix.ai_addr with
            | Unix.ADDR_INET (addr, _) -> Some (o (int32_of_inet_addr addr))
            | _ -> None in
        List.filter_map extract_addr (Unix.getaddrinfo str "" [])
    let of_string str = match list_of_string str with
        | [] -> invalid_arg str
        | fst::_ -> fst

    (** Returns a random {!Ip.Addr.t} (apart from broadcast and zero). *)
    let rec random () =
        let a = o (rand32 ()) in
        if a = broadcast || a = zero then random ()
        else a

    (** This printer can be composed with others (for instance to print a list of ips.
     FIXME: always use batteries IO to print instead of Format printer? *)
    let print' oc ip =
        Printf.fprintf oc "%s" (to_string ip)

    let of_inet_addr ip = o (int32_of_inet_addr ip)
    let to_inet_addr (t : t) = inet_addr_of_int32 (t :> int32)

    let higher_bits (ip : t) n =
        if n >= 32 then ip else (* since Int32.shift_left is actually a rotation *)
        o (Int32.logand (ip :> int32)
                        (Int32.shift_left
                              (Int32.pred (Int32.shift_left 1l n))
                              (32-n)))
    (*$= higher_bits & ~printer:to_string
       (o 0x01000000l) (higher_bits (o 0x01020305l) 10)
       (o 0x01020304l) (higher_bits (o 0x01020305l) 30)
       (o 0x01020305l) (higher_bits (o 0x01020305l) 32)
       (o 0x01020305l) (higher_bits (o 0x01020305l) 33)
     *)

(*    type net = t * t (** Network addr and network mask *)

    let in_net (ip : t) ((net : t), (mask : t)) =
        let ip = (ip :> int32) and net = (net :> int32) and mask = (mask :> int32) in
        (Int32.logand ip mask) = (Int32.logand net mask)

    (*$T in_net
        in_net (of_string "192.168.10.9") ((of_string "192.168.10.1"), \
                                           (of_string "255.255.255.0"))
        not (in_net (of_string "192.168.11.1") ((of_string "192.168.10.1"), \
                                                (of_string "255.255.255.0")))
     *)
*)
    (*$>*)
end

(** {4 CIDR Addresses} *)

(** CIDR addresses are a concise way to write network addresses,
 * with network IP then netmask length, like: 192.168.0.0/16. *)
module Cidr = struct
    (*$< Cidr *)
    include MakePrivate(struct
        type t = Addr.t * int
        (** Converts a CIDR to its string representation. *)
        let to_string (ip, n) =
            Addr.to_dotted_string ip ^ "/" ^ String.of_int n
        let is_valid ((ip : Addr.t), n) =
            Int32.logand (ip :> int32)
                         (Int32.pred (Int32.shift_left 1l (32-n))) = 0l
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
      (o (Addr.o 0x01020380l, 25)) (of_string "1.2.3.128/25")
      (o (Addr.o 0x01020380l, 25)) (of_string "1.2.3.142/25")
     *)

    let random ?mask () =
        let mask = Option.default (Random.int 32 + 1) mask in
        let net = Addr.higher_bits (Addr.random ()) mask in
        o (net, mask)
    (*$Q of_string
      ((random |- to_string), identity) (fun t -> t = to_string (of_string t))
     *)

    (** Build a CIDR from a single address *)
    let single ip = o (ip, 32)

    let mem (t : t) (ip : Addr.t) =
        let net, width = (t :> Addr.t * int) in
        let a = takebits width (BITSTRING { (net :> int32) : 32 })
        and b = takebits width (BITSTRING { (ip  :> int32) : 32 }) in
        Bitstring.equals a b
    (*$= mem & ~printer:string_of_bool
      true  (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.0"))
      true  (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.1"))
      true  (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.15"))
      false (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.16"))
      false (mem (of_string "192.168.10.0/28") (Addr.of_string "192.168.10.17"))
     *)

    let to_enum (t : t) =
        let net, width = (t :> Addr.t * int) in
        if width >= 32 then Enum.singleton net else
        let prefix = takebits width (BITSTRING { (net :> int32) : 32 })
        and l = 32 - width in
        Enum.init (1 lsl l) (fun i ->
            Addr.of_bitstring (BITSTRING { prefix : width : bitstring ;
                                           Int64.of_int i : l }))
    (*$= to_enum & ~printer:dump
      [ "192.168.10.42" ] (to_enum (of_string "192.168.10.42/32") /@ \
                           Addr.to_dotted_string |> \
                           List.of_enum)
     *)

    (** Returns the subnet-zero address of a CIDR *)
    let zero_addr (t : t) =
        let net, width = (t :> Addr.t * int) in
        let prefix = takebits width (BITSTRING { (net :> int32) : 32 }) in
        Addr.of_bitstring (Bitstring.concat [ prefix ; zeroes_bitstring (if width >= 32 then 0 else 32 - width) ])
    (*$= zero_addr & ~printer:identity
      "192.168.1.0" (zero_addr (of_string "192.168.1.0/28") |> \
                     Addr.to_dotted_string)
     *)

    (** Returns the all-ones address of a CIDR *)
    let all1s_addr (t : t) =
        let net, width = (t :> Addr.t * int) in
        let prefix = takebits width (BITSTRING { (net :> int32) : 32 }) in
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
        if width >= 32 then Enum.singleton net else
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

    (*$>*)
end

(** {2 IP packet} *)

(** (Un)Packing an IP packet. *)
module Pdu = struct
    (*$< Pdu *)

    let id_seq = ref 0
    let next_id () = id_seq := (!id_seq + 1) mod 0xffff ; !id_seq

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

    let patch_tcp_checksum t (pld : Payload.t) = bitmatch (pld :> bitstring) with
        | { head : 128 : bitstring ;
            chk  : 16  ;
            tail : -1 : bitstring (* FIXME: force urgent pointer at 0 if the urgent flag is unset *) (* FIXME: remove tcp payload? *) } ->
            if chk = 0 then (
                let chk = sum (BITSTRING {
                    (t.src :> int32) : 32 ; (t.dst :> int32) : 32 ;
                    0 : 8 ; (t.proto :> int) : 8 ; Payload.length pld : 16 ;
                    head : 128 : bitstring ; 0 : 16 ; tail : -1 : bitstring (* all tail?? *)}) in
                Payload.o (BITSTRING { head : 128 : bitstring ; chk : 16 ; tail : -1 : bitstring })
            ) else pld
        | { _ } ->
            Printf.fprintf stderr "Ip: Cannot patch checksum in TCP packet\n" ;
            pld

    let patch_udp_checksum t (pld : Payload.t) = bitmatch (pld :> bitstring) with
        | { head : 48 : bitstring ;
            chk  : 16  ;
            tail : -1 : bitstring } ->
            if chk = 0 then (
                let chk = sum (BITSTRING {
                    (t.src :> int32) : 32 ; (t.dst :> int32) : 32 ;
                    0 : 8 ; (t.proto :> int) : 8 ; Payload.length pld : 16 ;
                    head : 48 : bitstring ; 0 : 16 ;
                    tail : -1 : bitstring }) in
                Payload.o (BITSTRING { head : 48 : bitstring ; chk : 16 ; tail : -1 : bitstring })
            ) else pld
        | { _ } ->
            Printf.fprintf stderr "Ip: Cannot patch checksum in UDP packet\n" ;
            pld

    let pack t =
        let header =
            let hdr_len = 20 + bytelength t.options in
            concat [ (BITSTRING {
                4 : 4 ; hdr_len/4 : 4 ; t.tos : 8 ;
                t.tot_len : 16 ;
                t.id : 16 ; false : 1 ; t.dont_frag : 1 ; t.more_frags : 1 ; t.frag_offset : 13 ;
                t.ttl : 8 ; (t.proto :> int) : 8 ; 0 : 16 ;
                (t.src :> int32) : 32 ; (t.dst :> int32) : 32 }) ;
            t.options ]
            in
        let header = (* patch actual IP checksum *)
            let s = sum header in
            concat [ takebits 80 header ;
                     (BITSTRING { s : 16 }) ;
                     dropbits 96 header ]
        and payload = (* and actual TCP/UDP checksums as well since they use some fields of the IP header *)
            if t.proto = Proto.tcp then patch_tcp_checksum t t.payload
            else if t.proto = Proto.udp then patch_udp_checksum t t.payload
            else t.payload in
        concat [ header ; (payload :> bitstring) ]

    let unpack bits = bitmatch bits with
        | { 4 : 4 ; hdr_len : 4 ; tos : 8 ; tot_len : 16 ;
            id : 16 ; false : 1 ; dont_frag : 1 ; more_frags : 1 ; frag_offset : 13 ;
            ttl : 8 ; proto : 8 ; _checksum : 16 ;
            src : 32 ;
            dst : 32 ;
            options : (hdr_len-5)*32 : bitstring ;
            payload : (tot_len - hdr_len*4)*8 : bitstring ;
            _padding : -1 : bitstring } ->
        (* TODO: control the checksum ? *)
        Some { tos ; tot_len ;
               id ; dont_frag ; more_frags ; frag_offset ;
               ttl ; proto = Proto.o proto ;
               src = Addr.o src ; dst = Addr.o dst ; options ;
               payload = Payload.o payload }
        | { version : 4 } when version <> 4 ->
            err (Printf.sprintf "Ip: Bad version (%d)" version)
        | { _ } ->
            err "Ip: Not IP"

    (*$Q pack
      ((random |- pack), dump) (fun t -> t = pack (Option.get (unpack t)))
     *)

    (** Unpack an ip packets and return the ip PDU, source port and dest port. *)
    let unpack_with_ports bits =
        unpack bits |> Option.bind (fun ip ->
            if ip.proto = Proto.tcp then (
                Tcp.Pdu.unpack (ip.payload :> bitstring) |>
                Option.bind (fun tcp ->
                    Some (ip,
                          (tcp.Tcp.Pdu.src_port :> int),
                          (tcp.Tcp.Pdu.dst_port :> int)))
            ) else if ip.proto = Proto.udp then (
                Udp.Pdu.unpack (ip.payload :> bitstring) |>
                Option.bind (fun udp ->
                    Some (ip,
                          (udp.Udp.Pdu.src_port :> int),
                          (udp.Udp.Pdu.dst_port :> int)))
            ) else None)
    (*$= unpack_with_ports & ~printer:dump
        (Some (42, 12)) ( \
            pack (make Proto.udp (Ip.Addr.random ()) (Ip.Addr.random ()) \
                        (Udp.Pdu.make ~src_port:(Udp.Port.o 42) \
                                      ~dst_port:(Udp.Port.o 12) \
                                      (randbs 10) |> \
                        Udp.Pdu.pack)) |> \
            unpack_with_ports |> \
            Option.bind (fun (_, src, dst) -> Some (src, dst)) \
        )
     *)
    (*$>*)
end

(** {2 Transceiver} *)

module TRX = struct

    type t = { src : Addr.t ; dst : Addr.t ;
               proto : Proto.t ; mtu : int ;
               mutable emit : bitstring -> unit ;
               mutable recv : bitstring -> unit }

    let tx t bits =
        if debug then Printf.printf "Ip: Emitting a packet from %s to %s, length %d, content '%s'\n%!" (Addr.to_string t.src) (Addr.to_string t.dst) (bytelength bits) (string_of_bitstring bits) ;
        let id = Pdu.next_id () in
        let rec aux bit_offset =
            if bit_offset < bitstring_length bits then (
                let pld = dropbits bit_offset bits in
                let pld, more_frags = if bitstring_length pld <= t.mtu*8 then pld, false
                                      else takebits (t.mtu*8) pld, true in
                (* The frag_offset is given in unit of 8 bytes.
                   So the MTU is required to be a multiple of 8 bytes as well. *)
                let pdu = Pdu.make ~id ~more_frags ~frag_offset:((bit_offset+7) lsr 6) t.proto t.src t.dst pld in
                if debug then Printf.printf "Ip: Emitting an IP packet from %s to %s of length %d (content '%s')\n%!" (Addr.dotted_string_of_int32 (t.src :> int32)) (Addr.dotted_string_of_int32 (t.dst :> int32)) (bytelength pld) (string_of_bitstring bits);
                t.emit (Pdu.pack pdu) ;
                aux (bit_offset + bitstring_length pld)
            ) in
        aux 0

    (* TODO: check checksum? *)
    (* TODO: handle fragmentation *)
    let rx t bits = (match Pdu.unpack bits with
        | None -> ()
        | Some ip ->
            if Payload.bitlength ip.Pdu.payload > 0 then t.recv (ip.Pdu.payload :> bitstring))

    let make ?(mtu=1400) src dst proto =
        ensure ((mtu mod 8) = 0) "Ip: MTU is required to be a multiple of 8 bytes" ;
        let t = { src ; dst ; proto ; mtu ;
                  emit = ignore ; recv = ignore } in
        { ins = { write = tx t ;
                  set_read = fun f -> t.recv <- f } ;
          out = { write = rx t ;
                  set_read = fun f -> t.emit <- f } }

end

