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
    let icmp = o 1
    let tcp  = o 6
    let udp  = o 17

    let random () = o (randi 8)
end

(* Addresses *)

(* actual type of Unix.inet_addr is string *)
let int32_of_inet_addr a =
    bitmatch (bitstring_of_string (Obj.magic a)) with
    | { i : 32 } -> i
let inet_addr_of_int32 i : Unix.inet_addr =
    Obj.magic (string_of_bitstring (BITSTRING { i : 32 }))

let dotted_string_of_int32 i = bitmatch (BITSTRING { i : 32 }) with
      { a : 8 ; b : 8 ; c : 8 ; d : 8 } -> Printf.sprintf "%d.%d.%d.%d" a b c d
(*$= dotted_string_of_int32 & ~printer:identity
  (dotted_string_of_int32 ((Addr.of_string "1.2.3.4") :> int32)) "1.2.3.4"
*)

module Addr = struct
    let print_as_names = ref false

    include MakePrivate(struct
        type t = int32
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

    let zero = o 0l
    let broadcast = o 0xffffffffl

    let to_dotted_string (t : t) = dotted_string_of_int32 (t :> int32)
    let to_bitstring (t : t) = (BITSTRING { (t :> int32) : 32 })
    let of_bitstring bits = bitmatch bits with
        | { ip : 32 } -> o ip
        | { _ } -> should_not_happen ()
    let list_of_string str =
        let extract_addr info = match info.Unix.ai_addr with
            | Unix.ADDR_INET (addr, _) -> Some (o (int32_of_inet_addr addr))
            | _ -> None in
        List.filter_map extract_addr (Unix.getaddrinfo str "" [])
    let of_string str = List.hd (list_of_string str)
    let random () = o (rand32 ())
end

(* This printer can be composed with others (for instance to print a list of ips.
 FIXME: always use batteries IO to print instead of Format printer? *)
let print_addr' oc ip =
    Printf.fprintf oc "%s" (Addr.to_string ip)


type cidr = Addr.t * int
(* TODO: printer, etc *)

let cidr_of_string str =
    let ip_str, width_str =
        try String.split str "/"
        with Not_found -> error (Printf.sprintf "cidr_of_string %s" str)
    in Addr.of_string ip_str, int_of_string width_str

let string_of_cidr ((ip : Addr.t), width) =
    (dotted_string_of_int32 (ip :> int32)) ^ "/" ^ (string_of_int width)

let print_cidr fmt (cidr : cidr) =
    Format.fprintf fmt "@{<addr>%s@}" (string_of_cidr cidr)

let addr_in_cidr (net, mask) ip =
    let a = takebits mask (BITSTRING { net : 32 })
    and b = takebits mask (BITSTRING { ip  : 32 }) in
    a = b

let addrs_of_cidr ((ip : Addr.t), mask) =
    if mask >= 32 then [ ip ] else
    let prefix = takebits mask (BITSTRING { (ip :> int32) : 32 })
    and l = 32 - mask in
    List.init (1 lsl l) (fun i ->
        Addr.of_bitstring (BITSTRING { prefix : mask : bitstring ; Int64.of_int i : l }))

let random_addrs_of_cidr cidr n =
    addrs_of_cidr cidr |> List.enum |> Random.multi_choice n

(* IP packet *)

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
             proto src dst payload =
        let hdr_len = 20 + bytelength options
        and id = may_default id next_id in
        let tot_len = match tot_len with Some v -> v | None ->
            Payload.length payload + hdr_len in
        { tos ; tot_len ; id ; dont_frag ; more_frags ; frag_offset ;
          ttl ; proto ; src ; dst ; options ; payload }

    let random () =
        make ~tos:(randi 8) ~id:(randi 16) ~dont_frag:(randb ())
             ~more_frags:(randb ()) ~frag_offset:(randi 13)
             ~ttl:(randi 8) ~options:(randbs (4*(randi 3)))
             (Proto.random ()) (Addr.random ()) (Addr.random ()) (Payload.random (Random.int 10 + 20))

    let sum bits =
        let rec aux s bits = bitmatch bits with
            | { w : 16 ; rest : -1 : bitstring } -> aux (s + w) rest
            | { b : 8 } -> s + (b lsl 8)
            | { _ } -> s in
        let s = aux 0 (concat [ bits ; zeroes_bitstring 7 ]) in
        let rec wrap s =
            if s < 0x10000 then s else wrap ((s land 0xffff) + (s lsr 16)) in
        (lnot (wrap s)) land 0xffff
    (*$= sum & ~printer:(fun d -> Printf.sprintf "%x" d)
      (sum (bitstring_of_string "\x45\x00\x00\xaa\x03\xa6\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x45\xd1\x55\xe3\x67")) 0xfffd
    *)

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
            err "Ip: Bad version"
        | { _ } ->
            err "Ip: Not IP"
    (*$Q pack
      ((random |- pack), dump) (fun t -> t = pack (Option.get (unpack t)))
     *)
    (*$>*)
end

(* Transceiver *)

module TRX = struct

    type t = { src : Addr.t ; dst : Addr.t ;
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
                let pdu = Pdu.make ~id ~more_frags ~frag_offset:((bit_offset+7) lsr 6) t.proto t.src t.dst (Payload.o pld) in
                if debug then Printf.printf "Ip: Emitting an IP packet from %s to %s of length %d (content '%s')\n%!" (dotted_string_of_int32 (t.src :> int32)) (dotted_string_of_int32 (t.dst :> int32)) (bytelength pld) (string_of_bitstring bits);
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
        { tx = tx t ;
          rx = rx t ;
          set_emit = (fun f -> t.emit <- f) ;
          set_recv = (fun f -> t.recv <- f) }

end

