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

(* Protocols *)

type proto = int

let proto_icmp : proto = 1
let proto_tcp  : proto = 6
let proto_udp  : proto = 17

let string_of_proto (p : proto) = match p with
    |  1 -> "ICMP"
    |  6 -> "TCP"
    | 17 -> "UDP"
    |  x -> Printf.sprintf "Protocol(%d)" x

let print_proto fmt (p : proto) =
    Format.fprintf fmt "@{<proto>%s@}" (string_of_proto p)

(* Addresses *)

type addr = int32

let addr_zero = 0l
let addr_broadcast = 0xffffffffl

let int32_of_inet_addr a : addr =
    bitmatch (bitstring_of_string (Obj.magic a)) with
    | { addr : 32 } -> addr

let addrs_of_string str =
    let extract_addr info = match info.Unix.ai_addr with
        | Unix.ADDR_INET (addr, _) -> Some (int32_of_inet_addr addr)
        | _ -> None in
    List.filter_map extract_addr (Unix.getaddrinfo str "" [])

let addr_of_bitstring bits : addr = bitmatch bits with
    | { ip : 32 } -> ip
    | { _ } -> 0l (* FIXME: either monadic error or anything... *)

let bitstring_of_addr (ip : addr) = (BITSTRING { ip : 32 })

let addr_of_string str = List.hd (addrs_of_string str)

let string_of_addr (ip : addr) = bitmatch (BITSTRING { ip : 32 }) with
      { a : 8 ; b : 8 ; c : 8 ; d : 8 } -> Printf.sprintf "%d.%d.%d.%d" a b c d
    | { _ } -> "Not an IP addr (should not happen)" (* FIXME: either Option.Monad or a non local exit *)
(*$T string_of_addr
  string_of_addr (addr_of_string "1.2.3.4") = "1.2.3.4"
*)

let print_addr fmt (ip : addr) =
    Format.fprintf fmt "@{<addr>%s@}" (string_of_addr ip)

(* FIXME: use batteries IO to print instead of Format printer *)
let print_addr' oc ip =
    Printf.fprintf oc "%s" (string_of_addr ip)


type cidr = addr * int
(* TODO: printer, etc *)

let cidr_of_string str =
    let ip_str, width_str =
        try String.split str "/"
        with Not_found -> error (Printf.sprintf "cidr_of_string %s" str)
    in addr_of_string ip_str, int_of_string width_str

let string_of_cidr (ip, width) =
    (string_of_addr ip) ^ "/" ^ (string_of_int width)

let print_cidr fmt (cidr : cidr) =
    Format.fprintf fmt "@{<addr>%s@}" (string_of_cidr cidr)

let addr_in_cidr (net, mask) ip =
    let a = takebits mask (BITSTRING { net : 32 })
    and b = takebits mask (BITSTRING { ip  : 32 }) in
    a = b

let addrs_of_cidr (ip, mask) =
    if mask >= 32 then [ ip ] else
    let prefix = takebits mask (BITSTRING { ip : 32 })
    and l = 32 - mask in
    List.init (1 lsl l) (fun i ->
        addr_of_bitstring (BITSTRING { prefix : mask : bitstring ; Int64.of_int i : l }))

let random_addrs_of_cidr cidr n =
    addrs_of_cidr cidr |> List.enum |> Random.multi_choice n

(* IP packet *)

module Pdu = struct
    (*$< Pdu *)

    let id_seq = ref 0
    let next_id () = id_seq := (!id_seq + 1) mod 0xffff ; !id_seq

    type t = { hdr_len : int ; tos : int ; tot_len : int ;
               id : int ; dont_frag : bool ; more_frags : bool ; frag_offset : int ;
               ttl : int ; proto : int ; checksum : int option ;
               src : int32 ; dst : int32 ;
               options : bitstring ; payload : bitstring }

    let make ?(tos=0) ?tot_len
             ?id ?(dont_frag=false) ?(more_frags=false)
             ?(frag_offset=0) ?(ttl=64)
             ?checksum
             ?(options=empty_bitstring)
             proto src dst payload =
        let hdr_len = 20
        and id = may_default id next_id in
        let tot_len = match tot_len with Some v -> v | None ->
            bytelength payload + hdr_len in
        { hdr_len ; tos ; tot_len ; id ; dont_frag ; more_frags ; frag_offset ;
          ttl ; proto ; checksum ; src ; dst ; options ; payload }

    let sum bits =
        let rec aux s bits = bitmatch bits with
            | { w : 16 ; rest : -1 : bitstring } -> aux (s + w) rest
            | { b : 8 } -> s + (b lsl 8)
            | { _ } -> s in
        let s = aux 0 (concat [ bits ; zeroes_bitstring 7 ]) in
        let rec wrap s =
            if s < 0x10000 then s else wrap ((s land 0xffff) + (s lsr 16)) in
        (lnot (wrap s)) land 0xffff
    (*$T sum
      sum (bitstring_of_string "\x45\x00\x00\xaa\x03\xa6\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x45\xd1\x55\xe3\x67") = 0xfffd
    *)

    let patch_tcp_checksum t pld = bitmatch pld with
        | { head : 128 : bitstring ;
            chk  : 16  ;
            tail : -1 : bitstring (* FIXME: force urgent pointer at 0 if the urgent flag is unset *) (* FIXME: remove tcp payload? *) } ->
            if chk = 0 then (
                let chk = sum (BITSTRING {
                    t.src : 32 ; t.dst : 32 ;
                    0 : 8 ; t.proto : 8 ; bytelength pld : 16 ;
                    head : 128 : bitstring ; 0 : 16 ; tail : -1 : bitstring (* all tail?? *)}) in
                (BITSTRING { head : 128 : bitstring ; chk : 16 ; tail : -1 : bitstring })
            ) else pld
        | { _ } ->
            Printf.fprintf stderr "Ip: Cannot patch checksum in TCP packet\n" ;
            pld

    let patch_udp_checksum t pld = bitmatch pld with
        | { head : 48 : bitstring ;
            chk  : 16  ;
            tail : -1 : bitstring } ->
            if chk = 0 then (
                let chk = sum (BITSTRING {
                    t.src : 32 ; t.dst : 32 ;
                    0 : 8 ; t.proto : 8 ; bytelength pld : 16 ;
                    head : 48 : bitstring ; 0 : 16 ;
                    tail : -1 : bitstring }) in
                (BITSTRING { head : 48 : bitstring ; chk : 16 ; tail : -1 : bitstring })
            ) else pld
        | { _ } ->
            Printf.fprintf stderr "Ip: Cannot patch checksum in TCP packet\n" ;
            pld

    let pack t =
        let header = (BITSTRING {
            4 : 4 ; t.hdr_len/4 : 4 ; t.tos : 8 ;
            t.tot_len : 16 ;
            t.id : 16 ; false : 1 ; t.dont_frag : 1 ; t.more_frags : 1 ; t.frag_offset : 13 ;
            t.ttl : 8 ; t.proto : 8 ; Option.default 0 t.checksum : 16 ;
            t.src : 32 ; t.dst : 32 }) in
        let header = if t.checksum <> None then header else ( (* patch actual checksum *)
            let s = sum header in
            concat [ takebits 80 header ;
                     (BITSTRING { s : 16 }) ;
                     dropbits 96 header ]
        )
        and payload =
            if t.proto = proto_tcp then patch_tcp_checksum t t.payload
            else if t.proto = proto_udp then patch_udp_checksum t t.payload
            else t.payload in
        concat [ header ; payload ]

    let unpack bits = bitmatch bits with
        | { 4 : 4 ; hdr_len : 4 ; tos : 8 ;
            tot_len : 16 ;
            id : 16 ; false : 1 ; dont_frag : 1 ; more_frags : 1 ; frag_offset : 13 ;
            ttl : 8 ; proto : 8 ; checksum : 16 ;
            src : 32 ; dst : 32 ;
            options : (hdr_len-5)*32 : bitstring ;
            payload : (tot_len - hdr_len*4)*8 : bitstring ;
            _padding : -1 : bitstring } ->
        Some { hdr_len = hdr_len ; tos = tos ; tot_len = tot_len ;
               id = id ; dont_frag = dont_frag ; more_frags = more_frags ; frag_offset = frag_offset ;
               ttl = ttl ; proto = proto ; checksum = Some checksum ;
               src = src ; dst = dst ; options = options ; payload = payload }
        | { _version : 4 } ->
            err "Ip: Bad version"
        | { _ } ->
            err "Ip: Not IP"
    (*$>*)
end

(* Transceiver *)

module TRX = struct

    type t = { src : addr ; dst : addr ;
               proto : proto ; mtu : int ;
               mutable emit : payload -> unit ;
               mutable recv : payload -> unit }

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
                if debug then Printf.printf "Ip: Emitting an IP packet from %s to %s of length %d (content '%s')\n%!" (string_of_addr t.src) (string_of_addr t.dst) (bytelength pld) (string_of_bitstring bits);
                t.emit (Pdu.pack pdu) ;
                aux (bit_offset + bitstring_length pld)
            ) in
        aux 0

    (* TODO: check checksum? *)
    (* TODO: handle fragmentation *)
    let rx t bits = (match Pdu.unpack bits with
        | None -> ()
        | Some ip ->
            if bitstring_length ip.Pdu.payload > 0 then t.recv ip.Pdu.payload)

    let make ?(mtu=1400) src dst proto =
        ensure ((mtu mod 8) = 0) "Ip: MTU is required to be a multiple of 8 bytes" ;
        let t = { src = src ; dst = dst ;
                  proto = proto ; mtu = mtu ;
                  emit = ignore ; recv = ignore } in
        { tx = tx t ;
          rx = rx t ;
          set_emit = (fun f -> t.emit <- f) ;
          set_recv = (fun f -> t.recv <- f) }

end

