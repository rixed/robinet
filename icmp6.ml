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
 * Internet Control Message Protocol for IPv6 (ICMPv6, RFC 4443) and Neighbor
 * Discovery (RFC 4861), (un)packing and tools.
 *)
open Batteries
open Bitstring
open Tools

(** {2 Private types} *)

module MsgType =
struct
    module Outer = struct
        type t = int * int (* type, code *)
        let to_string = function
            |   1, 0 -> "No route to destination"
            |   1, 1 -> "Communication with destination administratively prohibited  "
            |   1, 2 -> "Beyond scope of source address"
            |   1, 3 -> "Address unreachable"
            |   1, 4 -> "Port unreachable"
            |   1, 5 -> "Source address failed ingress/egress policy"
            |   1, 6 -> "Reject route to destination"
            |   1, 7 -> "Error in Source Routing Header"
            |   1, y -> Printf.sprintf "Destination Unreachable (%d)" y
            |   2, 0 -> "Packet Too Big"
            |   2, y -> Printf.sprintf "Packet Too Big (%d)" y
            |   3, 0 -> "Hop limit exceeded in transit"
            |   3, 1 -> "Fragment reassembly time exceeded"
            |   3, y -> Printf.sprintf "Time Exceeded (%d)" y
            |   4, 0 -> "Erroneous header field encountered"
            |   4, 1 -> "Unrecognized Next Header type encountered"
            |   4, 2 -> "Unrecognized IPv6 option encountered"
            |   4, y -> Printf.sprintf "Parameter Problem (%d)" y
            | 128, 0 -> "Echo Request"
            | 129, 0 -> "Echo Reply"
            | 130, 0 -> "Multicast Listener Query"
            | 131, 0 -> "Multicast Listener Report"
            | 132, 0 -> "Multicast Listener Done"
            | 133, 0 -> "Router Solicitation"
            | 134, 0 -> "Router Advertisement"
            | 135, 0 -> "Neighbor Solicitation"
            | 136, 0 -> "Neighbor Advertisement"
            | 137, 0 -> "Redirect Message"
            | 138, 0 -> "Router Renumbering Command"
            | 138, 1 -> "Router Renumbering Result"
            | 138, 2 -> "Sequence Number Reset"
            | 138, y -> Printf.sprintf "Router Renumbering (%d)" y
            | 139, 0 -> "The Data field contains an IPv6 address which is the Subject of this Query"
            | 139, 1 -> "The Data field contains a name which is the Subject of this Query, or is empty, as in the case of a NOOP"
            | 139, 2 -> "The Data field contains an IPv4 address which is the Subject of this Query"
            | 140, 0 -> "A successful reply. The Reply Data field may or may not be empty"
            | 140, 1 -> "The Responder refuses to supply the answer. The Reply Data field will be empty"
            | 140, 2 -> "The Qtype of the Query is unknown to the Responder. The Reply Data field will be empty"
            | 141, 0 -> "Inverse Neighbor Discovery (Solicitation Message)"
            | 142, 0 -> "Inverse Neighbor Discovery (Advertisement Message)"
            | 144, 0 -> "Home Agent Address Discovery (Request Message)"
            | 145, 0 -> "Home Agent Address Discovery (Reply Message)"
            | 146, 0 -> "Mobile Prefix Solicitation"
            | 147, 0 -> "Mobile Prefix Advertisement"
            | 148, 0 -> "Certification Path Solicitation"
            | 149, 0 -> "Certification Path Advertisement"
            | 151, 0 -> "Multicast Router Advertisement"
            | 152, 0 -> "Multicast Router Solicitation"
            | 153, 0 -> "Multicast Router Termination"
            | 154, 0 -> "Reserved [RFC5568]"
            | 154, 1 -> "Reserved [RFC5568]"
            | 154, 2 -> "RtSolPr [RFC5568]"
            | 154, 3 -> "PrRtAdv [RFC5568]"
            | 154, 4 -> "HI - Deprecated (Unavailable for Assignment) [RFC5568]"
            | 154, 5 -> "HAck - Deprecated (Unavailable for Assignment)"
            | 155, 0 -> "RPL Control Message"
            |   x, y -> Printf.sprintf "Reserved(%d,%d)" x y
        let is_valid (x, y) = x < 256 && y < 256
        let repl_tag = "code"
    end
    include Private.Make (Outer)

    let rec random () =
        let m = Random.int 155, Random.int 7 in
        if Outer.is_valid m then o m else random ()

    let type_of (t : t) = fst (t :> int*int)
    let code_of (t : t) = snd (t :> int*int)

    (** The types that have a name of their own, as the choices of a kind
     * (see [Widget.one_of]). *)
    let type_choices =
        [|   1, "Destination Unreachable" ;
             2, "Packet Too Big" ;
             3, "Time Exceeded" ;
             4, "Parameter Problem" ;
           128, "Echo Request" ;
           129, "Echo Reply" ;
           130, "Multicast Listener Query" ;
           131, "Multicast Listener Report" ;
           132, "Multicast Listener Done" ;
           133, "Router Solicitation" ;
           134, "Router Advertisement" ;
           135, "Neighbor Solicitation" ;
           136, "Neighbor Advertisement" ;
           137, "Redirect Message" ;
           143, "Multicast Listener Report v2" |]

    (** Those types only (see [Icmp.MsgType.types]). *)
    let types typs =
        Array.filter (fun (t, _) -> Array.mem t typs) type_choices
end

(** Codes of the Destination Unreachable messages (type 1): *)
module Unreachable = struct
    let no_route = 0
    let prohibited = 1
    let beyond_scope = 2
    let address = 3
    let port = 4
    let policy = 5
    let reject = 6
end

(** {2 Neighbor Discovery options (RFC 4861, 4.6)} *)

module Opt =
struct
    (*$< Opt *)

    type t =
        (* Link-layer addresses, of 6 bytes as Ethernet has them: *)
        | Source_lla of string
        | Target_lla of string
        | Prefix of { prefix_len : int ; on_link : bool ; autonomous : bool ;
                      flags : int (* the 6 other bits *) ;
                      valid : int ; preferred : int ; prefix : Ip.Addr.t }
        (* The start of the redirected packet, a multiple of 8 bytes: *)
        | Redirected of Payload.t
        | Mtu of int
        | Other of bitstring (* type, length and data *)

    let pack_one = function
        | Source_lla a | Target_lla a as o ->
            if String.length a <> 6 then
                invalid_arg "Icmp6.Opt.pack: not a 6 bytes link-layer address" ;
            let typ = match o with Source_lla _ -> 1 | _ -> 2 in
            concat [ [%bitstring {| typ : 8 ; 1 : 8 |}] ; bitstring_of_string a ]
        | Prefix p ->
            [%bitstring {| 3 : 8 ; 4 : 8 ; p.prefix_len : 8 ;
                           p.on_link : 1 ; p.autonomous : 1 ; p.flags : 6 ;
                           Int32.of_int p.valid : 32 ;
                           Int32.of_int p.preferred : 32 ; 0l : 32 ;
                           Ip.Addr.to_bitstring p.prefix : 128 : bitstring |}]
        | Redirected pld ->
            let len = Payload.length pld in
            if len land 7 <> 0 then
                invalid_arg "Icmp6.Opt.pack: redirected header not a multiple of 8 bytes" ;
            concat [ [%bitstring {| 4 : 8 ; 1 + len / 8 : 8 ; 0L : 48 |}] ;
                     (pld :> bitstring) ]
        | Mtu mtu ->
            [%bitstring {| 5 : 8 ; 1 : 8 ; 0 : 16 ; Int32.of_int mtu : 32 |}]
        | Other bits ->
            bits

    let pack opts = concat (List.map pack_one opts)

    (* [o] is a whole option, of the length it says: *)
    let decode o =
        match%bitstring o with
        | {| (1|2) as typ : 8 ; 1 : 8 ; a : 48 : bitstring |} ->
            let a = string_of_bitstring a in
            if typ = 1 then Source_lla a else Target_lla a
        | {| 3 : 8 ; 4 : 8 ; prefix_len : 8 ;
             on_link : 1 ; autonomous : 1 ; flags : 6 ;
             valid : 32 ; preferred : 32 ; reserved : 32 ;
             prefix : 128 : bitstring |} when reserved = 0l ->
            Prefix { prefix_len ; on_link ; autonomous ; flags ;
                     valid = uint32 valid ; preferred = uint32 preferred ;
                     prefix = Ip.Addr.of_bitstring prefix }
        | {| 4 : 8 ; _ : 8 ; 0L : 48 ; pld : -1 : bitstring |} ->
            Redirected (Payload.o pld)
        | {| 5 : 8 ; 1 : 8 ; 0 : 16 ; mtu : 32 |} ->
            Mtu (uint32 mtu)
        | {| _ |} ->
            Other o

    (* Past an option whose length is 0 or overflows, all is [Other]: *)
    let rec unpack bits =
        match%bitstring bits with
        | {| _ : 8 ; len : 8 |} when len > 0 && 64 * len <= bitstring_length bits ->
            decode (takebytes (8 * len) bits) :: unpack (dropbytes (8 * len) bits)
        | {| _ |} ->
            if bitstring_length bits = 0 then [] else [ Other bits ]

    let string_of_lla a =
        String.lowercase_ascii (hexstring ~sep:":" a)

    let to_string = function
        | Source_lla a -> "src lla "^ string_of_lla a
        | Target_lla a -> "tgt lla "^ string_of_lla a
        | Prefix p ->
            Printf.sprintf "prefix %s/%d%s%s%s valid %d pref %d"
                (Ip.Addr.to_dotted_string p.prefix) p.prefix_len
                (if p.on_link then " L" else "")
                (if p.autonomous then " A" else "")
                (if p.flags <> 0 then Printf.sprintf " flags 0x%02x" p.flags else "")
                p.valid p.preferred
        | Redirected pld -> Printf.sprintf "redirected len %d" (Payload.length pld)
        | Mtu mtu -> Printf.sprintf "mtu %d" mtu
        | Other bits -> "opt "^ hex_of_bitstring bits

    let list_to_string opts =
        String.concat ", " (List.map to_string opts)

    (*$= unpack & ~printer:identity
      "src lla 02:00:00:00:00:01, mtu 1500" \
        (list_to_string (unpack (bitstring_of_string \
          "\x01\x01\x02\x00\x00\x00\x00\x01\x05\x01\x00\x00\x00\x00\x05\xdc")))
      "prefix 2001:db8::/64 L A valid 2592000 pref 604800" \
        (list_to_string (unpack (bitstring_of_string \
          ("\x03\x04\x40\xc0\x00\x27\x8d\x00\x00\x09\x3a\x80\x00\x00\x00\x00" ^ \
           "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))))
      "opt 050100010000000A, opt 0000" \
        (list_to_string (unpack (bitstring_of_string \
          "\x05\x01\x00\x01\x00\x00\x00\x0a\x00\x00")))
     *)
    (*$Q unpack
      Q.(int_bound 6) (fun n -> \
        let b = randbs (8 * n) in Bitstring.equals b (pack (unpack b)))
     *)

    let random () =
        let one () =
            match Random.int 6 with
            | 0 -> Source_lla (string_of_bitstring (randbs 6))
            | 1 -> Target_lla (string_of_bitstring (randbs 6))
            | 2 -> Prefix { prefix_len = Random.int 129 ;
                            on_link = Random.bool () ; autonomous = Random.bool () ;
                            flags = randi 6 ; valid = randi 32 ; preferred = randi 32 ;
                            prefix = Ip.Addr.random ~v4:false () }
            | 3 -> Redirected (Payload.o (randbs (8 * Random.int 4)))
            | 4 -> Mtu (randi 32)
            | _ ->
                (* An experimental type (RFC 4727): *)
                let len = 1 + Random.int 2 in
                Other (concat [ [%bitstring {| 253 : 8 ; len : 8 |}] ;
                                randbs (8 * len - 2) ]) in
        List.init (Random.int 4) (fun _ -> one ())

    module Kinds =
    struct
        open SimTypes
        let lla = Widget.hint "02:00:00:00:00:01" Mac
        let u32 = IRange (0, 0xffff_ffff)
        let prefix_len = IRange (0, 0xff)
        let flags = IRange (0, 0x3f)
        let addr = Widget.hint "2001:db8::" Ipv6
        let prefix =
            Widget.record [|
                "prefix length", prefix_len ;
                "on-link", Bool ;
                "autonomous", Bool ;
                "flags", flags ;
                "valid lifetime", u32 ;
                "preferred lifetime", u32 ;
                "prefix", addr |]
        let redirected = BRange (0, 2032)
        let other = BRange (2, 2040)
        let opt =
            Widget.variant [|
                "source link-layer address", Some lla ;
                "target link-layer address", Some lla ;
                "prefix information", Some prefix ;
                "redirected header", Some redirected ;
                "MTU", Some u32 ;
                "other", Some other |]
        let options = Widget.list opt
    end

    let to_json opt : Yojson.Basic.t =
        match opt with
        | Source_lla a -> `Assoc [ "source link-layer address", `String (string_of_lla a) ]
        | Target_lla a -> `Assoc [ "target link-layer address", `String (string_of_lla a) ]
        | Prefix p ->
            `Assoc [ "prefix information", `Assoc [
                "prefix length", `Int p.prefix_len ;
                "on-link", `Bool p.on_link ;
                "autonomous", `Bool p.autonomous ;
                "flags", `Int p.flags ;
                "valid lifetime", `Int p.valid ;
                "preferred lifetime", `Int p.preferred ;
                "prefix", Ip.Addr.to_json p.prefix ] ]
        | Redirected pld -> `Assoc [ "redirected header", Widget.json_of_bytes (pld :> bitstring) ]
        | Mtu mtu -> `Assoc [ "MTU", `Int mtu ]
        | Other bits -> `Assoc [ "other", Widget.json_of_bytes bits ]

    (* [js] is the synth of an option of [Kinds.opt], as [Generator.expand]
     * leaves it. A redirected header is zero padded to a multiple of 8 bytes;
     * an automatic prefix is a /64 on-link and autonomous, for a day: *)
    let of_synth gen_values js =
        let open Generator in
        let int ?auto name kind v = int_of_field name gen_values ?auto kind identity v
        and bool ~auto name v =
            of_field name gen_values ~auto:(fun () -> auto) SimTypes.Bool Widget.to_bool v
        and lla v =
            of_value gen_values Kinds.lla
                     (string_of_bitstring % bitstring_of_hexstring % Widget.to_string) v in
        match js with
        | `Assoc [ "source link-layer address", v ] -> Source_lla (lla v)
        | `Assoc [ "target link-layer address", v ] -> Target_lla (lla v)
        | `Assoc [ "prefix information", v ] ->
            let v = expand gen_values Kinds.prefix v in
            let day () = 86400 in
            Prefix { prefix_len = int ~auto:(fun () -> 64) "prefix length" Kinds.prefix_len v ;
                     on_link = bool ~auto:true "on-link" v ;
                     autonomous = bool ~auto:true "autonomous" v ;
                     flags = int ~auto:(fun () -> 0) "flags" Kinds.flags v ;
                     valid = int ~auto:day "valid lifetime" Kinds.u32 v ;
                     preferred = int ~auto:day "preferred lifetime" Kinds.u32 v ;
                     prefix = of_field "prefix" gen_values Kinds.addr
                                       (Ip.Addr.of_dotted_string % Widget.to_string) v }
        | `Assoc [ "redirected header", v ] ->
            let bits = bs_of_value gen_values ~auto:(fun () -> empty_bitstring)
                                   Kinds.redirected v in
            let pad = (8 - bytelength bits land 7) land 7 in
            Redirected (Payload.o (concat [ bits ; zeroes_bitstring (8 * pad) ]))
        | `Assoc [ "MTU", v ] ->
            Mtu (of_value gen_values ~auto:(fun () -> 1500) Kinds.u32 Widget.to_int v)
        | `Assoc [ "other", v ] ->
            Other (bs_of_value gen_values
                               ~auto:(fun () -> bitstring_of_string "\xfd\x01\x00\x00\x00\x00\x00\x00")
                               Kinds.other v)
        | js ->
            Widget.bad_value "not a neighbor discovery option: %s"
                             (Yojson.Basic.to_string js)

    (*$>*)
end

(** {2 ICMPv6 Messages} *)

(** This module handle ICMPv6 messages (un)packing. *)
module Pdu = struct
    (*$< Pdu *)

    (* Neighbor discovery messages (RFC 4861) are of code 0, any other code
     * making them [Unknown]: *)
    type payload =
        (* Echo request and reply: *)
        | Ids of int * int * Payload.t
        (* Types 1 to 4: what is unused, the MTU or the pointer, then as much
         * of the invoking packet as fits: *)
        | Err of { param : int ; pld : Payload.t }
        | Router_solicit of Opt.t list
        | Router_advert of { hop_limit : int ; managed : bool ;
                             other_config : bool ; flags : int (* 6 bits *) ;
                             lifetime : int ; reachable : int ; retrans : int ;
                             options : Opt.t list }
        | Neighbor_solicit of { target : Ip.Addr.t ; options : Opt.t list }
        | Neighbor_advert of { router : bool ; solicited : bool ;
                               override : bool ; target : Ip.Addr.t ;
                               options : Opt.t list }
        | Redirect of { target : Ip.Addr.t ; dst : Ip.Addr.t ;
                        options : Opt.t list }
        | Unknown of Payload.t

    (** Unpacked ICMPv6 message. *)
    type t = { msg_type : MsgType.t ;
               payload  : payload }

    let random () =
        let addr () = Ip.Addr.random ~v4:false () in
        let ndp typ payload = { msg_type = MsgType.o (typ, 0) ; payload } in
        match Random.int 8 with
        | 0 ->
            { msg_type = MsgType.o (128 + Random.int 2, randi 8) ;
              payload = Ids (randi 16, randi 16, Payload.random (8 * Random.int 10)) }
        | 1 ->
            { msg_type = MsgType.o (1 + Random.int 4, randi 8) ;
              payload = Err { param = randi 32 ; pld = Payload.random (8 * Random.int 60) } }
        | 2 -> ndp 133 (Router_solicit (Opt.random ()))
        | 3 -> ndp 134 (Router_advert {
                   hop_limit = randi 8 ; managed = Random.bool () ;
                   other_config = Random.bool () ; flags = randi 6 ;
                   lifetime = randi 16 ; reachable = randi 32 ; retrans = randi 32 ;
                   options = Opt.random () })
        | 4 -> ndp 135 (Neighbor_solicit { target = addr () ; options = Opt.random () })
        | 5 -> ndp 136 (Neighbor_advert {
                   router = Random.bool () ; solicited = Random.bool () ;
                   override = Random.bool () ; target = addr () ;
                   options = Opt.random () })
        | 6 -> ndp 137 (Redirect { target = addr () ; dst = addr () ;
                                   options = Opt.random () })
        | _ ->
            (* Multicast listener discovery, which is not decoded: *)
            { msg_type = MsgType.o (130 + Random.int 3, 0) ;
              payload = Unknown (Payload.random (8 * Random.int 30)) }

    let make_echo_request ?(pld=Payload.empty) id seq =
        { msg_type = MsgType.o (128, 0) ;
          payload  = Ids (id, seq, pld) }

    let make_echo_reply ?(pld=Payload.empty) id seq =
        { msg_type = MsgType.o (129, 0) ;
          payload  = Ids (id, seq, pld) }

    let is_echo_request t =
        MsgType.type_of t.msg_type = 128 && MsgType.code_of t.msg_type = 0

    (* So that the error fits in the minimum MTU of 1280 bytes (RFC 4443,
     * 2.4): *)
    let max_quoted = 1280 - 40 - 8

    (* An error of type [typ] about the IPv6 packet [ip]: *)
    let make_error typ code ?(param=0) ip =
        let bits = Ip6.Pdu.pack ip in
        let bits =
            if bytelength bits <= max_quoted then bits
            else takebytes max_quoted bits in
        { msg_type = MsgType.o (typ, code) ;
          payload = Err { param ; pld = Payload.o bits } }

    let make_destination_unreachable code ip = make_error 1 code ip
    let make_port_unreachable = make_destination_unreachable Unreachable.port
    let make_packet_too_big mtu ip = make_error 2 0 ~param:mtu ip
    let make_time_exceeded code ip = make_error 3 code ip
    let make_hop_limit_exceeded = make_time_exceeded 0
    let make_parameter_problem code ptr ip = make_error 4 code ~param:ptr ip

    (*$T make_packet_too_big
      let ip n = Ip6.Pdu.make Ip.Proto.udp (Ip.Addr.of_string "2001:db8::1") \
                   (Ip.Addr.of_string "2001:db8::2") (randbs n) in \
      let quoted n = match (make_packet_too_big 1280 (ip n)).payload with \
        | Err { param = 1280 ; pld } -> Payload.length pld | _ -> -1 in \
      quoted 10 = 50 && quoted 2000 = max_quoted
     *)

    let make_router_solicit ?src_lla () =
        { msg_type = MsgType.o (133, 0) ;
          payload = Router_solicit (Option.map_default (fun a -> [ Opt.Source_lla a ]) [] src_lla) }

    let make_router_advert ?(hop_limit=64) ?(managed=false) ?(other_config=false)
                           ?(lifetime=1800) ?(reachable=0) ?(retrans=0) options =
        { msg_type = MsgType.o (134, 0) ;
          payload = Router_advert { hop_limit ; managed ; other_config ; flags = 0 ;
                                    lifetime ; reachable ; retrans ; options } }

    let make_neighbor_solicit ?src_lla target =
        { msg_type = MsgType.o (135, 0) ;
          payload = Neighbor_solicit {
              target ;
              options = Option.map_default (fun a -> [ Opt.Source_lla a ]) [] src_lla } }

    let make_neighbor_advert ?(router=false) ?(solicited=false) ?(override=true)
                             ?tgt_lla target =
        { msg_type = MsgType.o (136, 0) ;
          payload = Neighbor_advert {
              router ; solicited ; override ; target ;
              options = Option.map_default (fun a -> [ Opt.Target_lla a ]) [] tgt_lla } }

    (* The redirected packet [ip] is quoted as far as it fits in the minimum
     * MTU, in a whole number of 8 bytes: *)
    let make_redirect ?tgt_lla target dst ip =
        let bits = Ip6.Pdu.pack ip in
        let len = min (bytelength bits) (1280 - 40 - 40 - 8 - (if tgt_lla = None then 0 else 8)) in
        let bits = takebytes (len land (lnot 7)) bits in
        { msg_type = MsgType.o (137, 0) ;
          payload = Redirect {
              target ; dst ;
              options = Option.map_default (fun a -> [ Opt.Target_lla a ]) [] tgt_lla @
                        [ Opt.Redirected (Payload.o bits) ] } }

    let pack t =
        let addr a = Ip.Addr.to_bitstring a in
        let pack_payload = function
            | Ids (id, seq, pld) ->
                [%bitstring {| id : 16 ; seq : 16 ; (pld :> bitstring) : -1 : bitstring |}]
            | Err { param ; pld } ->
                [%bitstring {| Int32.of_int param : 32 ; (pld :> bitstring) : -1 : bitstring |}]
            | Router_solicit options ->
                concat [ zeroes_bitstring 32 ; Opt.pack options ]
            | Router_advert r ->
                concat [ [%bitstring {| r.hop_limit : 8 ; r.managed : 1 ;
                                        r.other_config : 1 ; r.flags : 6 ;
                                        r.lifetime : 16 ;
                                        Int32.of_int r.reachable : 32 ;
                                        Int32.of_int r.retrans : 32 |}] ;
                         Opt.pack r.options ]
            | Neighbor_solicit n ->
                concat [ zeroes_bitstring 32 ; addr n.target ; Opt.pack n.options ]
            | Neighbor_advert n ->
                concat [ [%bitstring {| n.router : 1 ; n.solicited : 1 ;
                                        n.override : 1 ; 0 : 29 |}] ;
                         addr n.target ; Opt.pack n.options ]
            | Redirect r ->
                concat [ zeroes_bitstring 32 ; addr r.target ; addr r.dst ;
                         Opt.pack r.options ]
            | Unknown pld -> (pld :> bitstring) in
        let typ, cod = (t.msg_type :> int*int) in
        (* The checksum is patched by [Ip6.Pdu.pack], which knows the
         * addresses: *)
        concat [ [%bitstring {| typ : 8 ; cod : 8 ; 0 : 16 |}] ;
                 pack_payload t.payload ]

    let unpack bits =
        let addr = Ip.Addr.of_bitstring in
        let payload =
            match%bitstring bits with
            | {| (128|129) : 8 ; _ : 8 ; _ : 16 ;
                 id : 16 ; seq : 16 ; pld : -1 : bitstring |} ->
                Some (Ids (id, seq, Payload.o pld))
            | {| typ : 8 ; _ : 8 ; _ : 16 ; param : 32 ; pld : -1 : bitstring |}
              when typ >= 1 && typ <= 4 ->
                Some (Err { param = uint32 param ; pld = Payload.o pld })
            | {| 133 : 8 ; 0 : 8 ; _ : 16 ; 0l : 32 ; opts : -1 : bitstring |} ->
                Some (Router_solicit (Opt.unpack opts))
            | {| 134 : 8 ; 0 : 8 ; _ : 16 ; hop_limit : 8 ; managed : 1 ;
                 other_config : 1 ; flags : 6 ; lifetime : 16 ;
                 reachable : 32 ; retrans : 32 ; opts : -1 : bitstring |} ->
                Some (Router_advert { hop_limit ; managed ; other_config ; flags ;
                                      lifetime ; reachable = uint32 reachable ;
                                      retrans = uint32 retrans ;
                                      options = Opt.unpack opts })
            | {| 135 : 8 ; 0 : 8 ; _ : 16 ; 0l : 32 ; target : 128 : bitstring ;
                 opts : -1 : bitstring |} ->
                Some (Neighbor_solicit { target = addr target ;
                                         options = Opt.unpack opts })
            | {| 136 : 8 ; 0 : 8 ; _ : 16 ; router : 1 ; solicited : 1 ;
                 override : 1 ; 0 : 29 ; target : 128 : bitstring ;
                 opts : -1 : bitstring |} ->
                Some (Neighbor_advert { router ; solicited ; override ;
                                        target = addr target ;
                                        options = Opt.unpack opts })
            | {| 137 : 8 ; 0 : 8 ; _ : 16 ; 0l : 32 ; target : 128 : bitstring ;
                 dst : 128 : bitstring ; opts : -1 : bitstring |} ->
                Some (Redirect { target = addr target ; dst = addr dst ;
                                 options = Opt.unpack opts })
            | {| _ |} ->
                None in
        match%bitstring bits with
        | {| typ : 8 ; cod : 8 ; _checksum : 16 ; pld : -1 : bitstring |} ->
            Ok { msg_type = MsgType.o (typ, cod) ;
                 payload = payload |? Unknown (Payload.o pld) }
        | {| _ |} ->
            Error (lazy "Not ICMPv6")

    (* Every message packs back to what it was read from, but for the
     * checksum, which is left to the IPv6 layer: *)
    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
      Q.(int_bound 80) (fun n -> \
        let b = Bitstring.concat [ randbs 2 ; Bitstring.zeroes_bitstring 16 ; randbs n ] in \
        match unpack b with \
        | Ok t -> Bitstring.equals b (pack t) \
        | Error _ -> n = 0)
     *)

    let opts_to_string = function
        | [] -> ""
        | opts -> " ["^ Opt.list_to_string opts ^"]"

    (** In the manner of tcpdump. *)
    let to_string t =
        let name = MsgType.to_string t.msg_type in
        match t.payload with
        | Ids (id, seq, pld) ->
            Printf.sprintf "%s id %d seq %d len %d" name id seq (Payload.length pld)
        | Err { param ; pld } ->
            Printf.sprintf "%s%s len %d" name
                (match MsgType.type_of t.msg_type with
                 | 2 -> Printf.sprintf " mtu %d" param
                 | 4 -> Printf.sprintf " ptr %d" param
                 | _ -> "")
                (Payload.length pld)
        | Router_solicit opts ->
            name ^ opts_to_string opts
        | Router_advert r ->
            Printf.sprintf "%s hlim %d%s%s lifetime %d%s" name r.hop_limit
                (if r.managed then " M" else "") (if r.other_config then " O" else "")
                r.lifetime (opts_to_string r.options)
        | Neighbor_solicit n ->
            Printf.sprintf "%s who has %s%s" name
                (Ip.Addr.to_dotted_string n.target) (opts_to_string n.options)
        | Neighbor_advert n ->
            Printf.sprintf "%s tgt is %s%s%s%s%s" name
                (Ip.Addr.to_dotted_string n.target)
                (if n.router then " R" else "") (if n.solicited then " S" else "")
                (if n.override then " O" else "") (opts_to_string n.options)
        | Redirect r ->
            Printf.sprintf "%s %s to %s%s" name (Ip.Addr.to_dotted_string r.dst)
                (Ip.Addr.to_dotted_string r.target) (opts_to_string r.options)
        | Unknown pld ->
            Printf.sprintf "%s len %d" name (Payload.length pld)

    (*$= to_string & ~printer:identity
      "Neighbor Solicitation who has 2001:db8::1 [src lla 02:00:00:00:00:01]" \
        (to_string (make_neighbor_solicit ~src_lla:"\x02\x00\x00\x00\x00\x01" \
                      (Ip.Addr.of_string "2001:db8::1")))
     *)

    (** What a message holds, by shape as for {!Icmp.Pdu.kind}: the type is
     * inside the case and narrowed to what that shape can be, and the
     * neighbor discovery messages, which are of a single type and code, have
     * neither. No checksum, that [Ip6.Pdu.pack] computes. *)
    module Kinds =
    struct
        open SimTypes
        let echo_type = Widget.one_of (MsgType.types [| 128 ; 129 |])
        let error_type = Widget.one_of (MsgType.types [| 1 ; 2 ; 3 ; 4 |])
        let other_type = Widget.one_of ~range:(0, 0xff) MsgType.type_choices
        let code = IRange (0, 0xff)
        let u16 = IRange (0, 0xffff)
        let u32 = IRange (0, 0xffff_ffff)
        let hop_limit = IRange (0, 0xff)
        let flags = IRange (0, 0x3f)
        let addr = Widget.hint "2001:db8::1" Ipv6
        let options = Opt.Kinds.options
        let payload = BRange (0, 0xffff)
        let echo =
            Widget.record [| "type", echo_type ; "code", code ; "id", u16 ;
                             "sequence", u16 ; "payload", payload |]
        let error =
            Widget.record [| "type", error_type ; "code", code ;
                             "parameter", u32 ; "payload", payload |]
        let router_advert =
            Widget.record [|
                "hop limit", hop_limit ;
                "managed", Bool ;
                "other configuration", Bool ;
                "flags", flags ;
                "router lifetime", u16 ;
                "reachable time", u32 ;
                "retransmission timer", u32 ;
                "options", options |]
        let router_solicit = Widget.record [| "options", options |]
        let neighbor_solicit =
            Widget.record [| "target", addr ; "options", options |]
        let neighbor_advert =
            Widget.record [| "router", Bool ; "solicited", Bool ;
                             "override", Bool ; "target", addr ;
                             "options", options |]
        let redirect =
            Widget.record [| "target", addr ; "destination", addr ;
                             "options", options |]
        let other =
            Widget.record [| "type", other_type ; "code", code ;
                             "payload", payload |]
        let message =
            Widget.variant [|
                "echo", Some echo ;
                (* Destination unreachable, packet too big, time exceeded and
                   parameter problem, the parameter being unused, the MTU or
                   the pointer: *)
                "error", Some error ;
                "router solicitation", Some router_solicit ;
                "router advertisement", Some router_advert ;
                "neighbor solicitation", Some neighbor_solicit ;
                "neighbor advertisement", Some neighbor_advert ;
                "redirect", Some redirect ;
                "other", Some other |]
    end

    let kind = Kinds.message

    let to_json (t : t) =
        let typ = MsgType.type_of t.msg_type
        and cod = MsgType.code_of t.msg_type in
        let bytes (pld : Payload.t) = Widget.json_of_bytes (pld :> bitstring) in
        let options opts = `List (List.map Opt.to_json opts) in
        let case name fields = `Assoc [ name, `Assoc fields ] in
        match t.payload with
        | Ids (id, seq, pld) ->
            case "echo" [ "type", `Int typ ; "code", `Int cod ;
                          "id", `Int id ; "sequence", `Int seq ;
                          "payload", bytes pld ]
        | Err { param ; pld } ->
            case "error" [ "type", `Int typ ; "code", `Int cod ;
                           "parameter", `Int param ; "payload", bytes pld ]
        | Router_solicit opts ->
            case "router solicitation" [ "options", options opts ]
        | Router_advert r ->
            case "router advertisement"
                [ "hop limit", `Int r.hop_limit ;
                  "managed", `Bool r.managed ;
                  "other configuration", `Bool r.other_config ;
                  "flags", `Int r.flags ;
                  "router lifetime", `Int r.lifetime ;
                  "reachable time", `Int r.reachable ;
                  "retransmission timer", `Int r.retrans ;
                  "options", options r.options ]
        | Neighbor_solicit n ->
            case "neighbor solicitation"
                [ "target", Ip.Addr.to_json n.target ; "options", options n.options ]
        | Neighbor_advert n ->
            case "neighbor advertisement"
                [ "router", `Bool n.router ; "solicited", `Bool n.solicited ;
                  "override", `Bool n.override ;
                  "target", Ip.Addr.to_json n.target ;
                  "options", options n.options ]
        | Redirect r ->
            case "redirect"
                [ "target", Ip.Addr.to_json r.target ;
                  "destination", Ip.Addr.to_json r.dst ;
                  "options", options r.options ]
        | Unknown pld ->
            case "other" [ "type", `Int typ ; "code", `Int cod ;
                           "payload", bytes pld ]

    (* The payload of an echo, an error or another message is the layer
     * above, if any. Automatic values are those of a host that has nothing
     * special to say: code 0, no options, a packet too big for the minimum
     * MTU, a router advertisement as RFC 4861 defaults it. *)
    let of_synth js ?upper ?prev gen_values =
        ignore prev ;
        let open Generator in
        let int ?auto fname kind js = int_of_field fname gen_values ?auto kind identity js
        and bool ~auto name js =
            of_field name gen_values ~auto:(fun () -> auto) SimTypes.Bool Widget.to_bool js
        and addr name js =
            of_field name gen_values Kinds.addr
                     (Ip.Addr.of_dotted_string % Widget.to_string) js
        and options js =
            Widget.to_field "options" (function
                | `Null -> []
                | l -> expand gen_values Kinds.options l |>
                       Widget.to_list (Opt.of_synth gen_values)) js
        and payload js =
            Payload.o (payload_of_field ?upper gen_values Kinds.payload js)
        and zero () = 0 in
        let ndp typ payload = { msg_type = MsgType.o (typ, 0) ; payload } in
        expand gen_values Kinds.message js |>
        Widget.to_case (fun case js ->
            match case with
            | "echo" ->
                { msg_type = MsgType.o (int "type" Kinds.echo_type js,
                                        int ~auto:zero "code" Kinds.code js) ;
                  payload = Ids (int "id" Kinds.u16 js,
                                 int "sequence" Kinds.u16 js, payload js) }
            | "error" ->
                let typ = int "type" Kinds.error_type js in
                { msg_type = MsgType.o (typ, int ~auto:zero "code" Kinds.code js) ;
                  payload = Err {
                      param = int ~auto:(fun () -> if typ = 2 then 1280 else 0)
                                  "parameter" Kinds.u32 js ;
                      pld = payload js } }
            | "router solicitation" ->
                ndp 133 (Router_solicit (options js))
            | "router advertisement" ->
                ndp 134 (Router_advert {
                    hop_limit = int ~auto:(fun () -> 64) "hop limit" Kinds.hop_limit js ;
                    managed = bool ~auto:false "managed" js ;
                    other_config = bool ~auto:false "other configuration" js ;
                    flags = int ~auto:zero "flags" Kinds.flags js ;
                    lifetime = int ~auto:(fun () -> 1800) "router lifetime" Kinds.u16 js ;
                    reachable = int ~auto:zero "reachable time" Kinds.u32 js ;
                    retrans = int ~auto:zero "retransmission timer" Kinds.u32 js ;
                    options = options js })
            | "neighbor solicitation" ->
                ndp 135 (Neighbor_solicit { target = addr "target" js ;
                                            options = options js })
            | "neighbor advertisement" ->
                ndp 136 (Neighbor_advert {
                    router = bool ~auto:false "router" js ;
                    solicited = bool ~auto:true "solicited" js ;
                    override = bool ~auto:true "override" js ;
                    target = addr "target" js ;
                    options = options js })
            | "redirect" ->
                ndp 137 (Redirect { target = addr "target" js ;
                                    dst = addr "destination" js ;
                                    options = options js })
            | "other" ->
                { msg_type = MsgType.o (int "type" Kinds.other_type js,
                                        int ~auto:zero "code" Kinds.code js) ;
                  payload = Unknown (payload js) }
            | case ->
                Widget.bad_value "no ICMPv6 message is %S" case)

    (*$Q of_synth
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_consts (fun js g -> of_synth js g) kind to_json)
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_autos (fun js g -> of_synth js g) kind to_json)
     *)

    (*$Q kind
      (Q.make (fun _ -> random ())) (fun t -> \
        try Widget.check_value kind (to_json t) ; true \
        with _ -> false)
     *)
    (*$>*)
end
