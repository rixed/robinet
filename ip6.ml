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
 * Everything related to IPv6 packets.
 * For addresses and CIDR, see ip.ml.
 *)
open Batteries
open Bitstring
open Tools

let debug = false

(** {2 Extension headers (RFC 8200)}
 *
 * Decoded to be shown and packed back to the very same bytes: whatever would
 * not pack back identically (non-zero reserved bits, padding that is not
 * zeroes...) is kept as [Other]. Nothing pads by itself. *)

module Extension = struct
    (*$< Extension *)

    (* Unpacks TLVs of the format shared by IPv6 options and SRH TLVs, where
     * [pad1] is the type of the one byte long padding: *)
    let rec unpack_tlvs pad1 decode bits =
        match%bitstring bits with
        | {| typ : 8 ; rest : -1 : bitstring |} when typ = pad1 ->
            `Pad1 :: unpack_tlvs pad1 decode rest
        | {| _ : 8 ; len : 8 |} when 8 * (2 + len) <= bitstring_length bits ->
            decode (takebytes (2 + len) bits) ::
                unpack_tlvs pad1 decode (dropbytes (2 + len) bits)
        | {| _ |} ->
            if bitstring_length bits = 0 then [] else [ `Other bits ]

    (** The options of the hop-by-hop and destination options headers. *)
    module Options =
    struct
        (*$< Options *)

        type t =
            | Pad1
            | PadN of int (* that many zero bytes *)
            (* RFC 8250: *)
            | Pdm of { scale_dtlr : int ; scale_dtls : int (* signed *) ;
                       psn_this : int ; psn_last : int ;
                       delta_last_recv : int ; delta_last_sent : int }
            (* RFC 9343: *)
            | Alt_mark of { flow_mon_id : int ; loss : bool ; delay : bool }
            (* RFC 9268; [rtn_pmtu] is even, its lowest bit being [r]: *)
            | Min_pmtu of { min_pmtu : int ; rtn_pmtu : int ; r : bool }
            | Other of bitstring (* type, length and data *)

        let pack_one = function
            | Pad1 ->
                [%bitstring {| 0 : 8 |}]
            | PadN n ->
                concat [ [%bitstring {| 1 : 8 ; n : 8 |}] ; zeroes_bitstring (8 * n) ]
            | Pdm p ->
                [%bitstring {| 0x0f : 8 ; 10 : 8 ;
                               p.scale_dtlr : 8 ; p.scale_dtls land 0xff : 8 ;
                               p.psn_this : 16 ; p.psn_last : 16 ;
                               p.delta_last_recv : 16 ; p.delta_last_sent : 16 |}]
            | Alt_mark a ->
                [%bitstring {| 0x12 : 8 ; 4 : 8 ; a.flow_mon_id : 20 ;
                               a.loss : 1 ; a.delay : 1 ; 0 : 10 |}]
            | Min_pmtu m ->
                [%bitstring {| 0x30 : 8 ; 4 : 8 ; m.min_pmtu : 16 ;
                               m.rtn_pmtu lsr 1 : 15 ; m.r : 1 |}]
            | Other bits ->
                bits

        let pack opts = concat (List.map pack_one opts)

        (* [tlv] is a whole option, of the length it says: *)
        let decode tlv =
            match%bitstring tlv with
            | {| 1 : 8 ; n : 8 ; pad : -1 : bitstring |} when is_zeroes pad ->
                PadN n
            | {| 0x0f : 8 ; 10 : 8 ; scale_dtlr : 8 ; scale_dtls : 8 : signed ;
                 psn_this : 16 ; psn_last : 16 ;
                 delta_last_recv : 16 ; delta_last_sent : 16 |} ->
                Pdm { scale_dtlr ; scale_dtls ; psn_this ; psn_last ;
                      delta_last_recv ; delta_last_sent }
            | {| 0x12 : 8 ; 4 : 8 ; flow_mon_id : 20 ;
                 loss : 1 ; delay : 1 ; 0 : 10 |} ->
                Alt_mark { flow_mon_id ; loss ; delay }
            | {| 0x30 : 8 ; 4 : 8 ; min_pmtu : 16 ; rtn : 15 ; r : 1 |} ->
                Min_pmtu { min_pmtu ; rtn_pmtu = rtn lsl 1 ; r }
            | {| _ |} ->
                Other tlv

        (* Past an option whose length overflows, all is [Other]: *)
        let unpack bits =
            unpack_tlvs 0 (fun tlv -> `Opt (decode tlv)) bits |>
            List.map (function `Pad1 -> Pad1 | `Opt o -> o | `Other b -> Other b)

        let to_string = function
            | Pad1 -> "Pad1"
            | PadN n -> Printf.sprintf "PadN %d" n
            | Pdm p ->
                Printf.sprintf "PDM psn %d/%d delta %d<<%d/%d<<%d"
                    p.psn_this p.psn_last
                    p.delta_last_recv p.scale_dtlr p.delta_last_sent p.scale_dtls
            | Alt_mark a ->
                Printf.sprintf "AltMark %d%s%s" a.flow_mon_id
                    (if a.loss then " L" else "") (if a.delay then " D" else "")
            | Min_pmtu m ->
                Printf.sprintf "MinPMTU %d rtn %d%s" m.min_pmtu m.rtn_pmtu
                    (if m.r then " R" else "")
            | Other bits -> "opt " ^ hex_of_bitstring bits

        let list_to_string opts =
            String.concat ", " (List.map to_string opts)

        (*$= unpack & ~printer:identity
          "Pad1, PadN 2, AltMark 74565 L" \
            (list_to_string (unpack (bitstring_of_string \
              "\x00\x01\x02\x00\x00\x12\x04\x12\x34\x58\x00")))
          "PDM psn 1/2 delta 3<<0/4<<-1, MinPMTU 1280 rtn 1500 R" \
            (list_to_string (unpack (bitstring_of_string \
              ("\x0f\x0a\x00\xff\x00\x01\x00\x02\x00\x03\x00\x04" ^ \
               "\x30\x04\x05\x00\x05\xdd"))))
          "opt 010107, opt 120412345801" \
            (list_to_string (unpack (bitstring_of_string \
              "\x01\x01\x07\x12\x04\x12\x34\x58\x01")))
          "opt 3E0501" \
            (list_to_string (unpack (bitstring_of_string "\x3e\x05\x01")))
         *)
        (*$Q unpack
          Q.(int_bound 40) (fun n -> \
            let b = randbs n in Bitstring.equals b (pack (unpack b)))
         *)

        let random () =
            let one () =
                match Random.int 6 with
                | 0 -> Pad1
                | 1 -> PadN (Random.int 6)
                | 2 -> Pdm { scale_dtlr = randi 8 ; scale_dtls = randi 7 - 64 ;
                             psn_this = randi 16 ; psn_last = randi 16 ;
                             delta_last_recv = randi 16 ;
                             delta_last_sent = randi 16 }
                | 3 -> Alt_mark { flow_mon_id = randi 20 ;
                                  loss = Random.bool () ; delay = Random.bool () }
                | 4 -> Min_pmtu { min_pmtu = randi 16 ;
                                  rtn_pmtu = randi 15 lsl 1 ; r = Random.bool () }
                | _ ->
                    let len = Random.int 6 in
                    (* An experimental type (RFC 4727), to be skipped: *)
                    Other (concat [ [%bitstring {| 0x1e : 8 ; len : 8 |}] ;
                                    randbs len ]) in
            List.init (Random.int 4) (fun _ -> one ())

        module Kinds =
        struct
            open SimTypes
            let u8 = IRange (0, 0xff)
            let u16 = IRange (0, 0xffff)
            let pdm =
                Widget.record [|
                    "scale DTLR", u8 ;
                    "scale DTLS", IRange (-128, 127) ;
                    "PSN this packet", u16 ;
                    "PSN last received", u16 ;
                    "delta time last received", u16 ;
                    "delta time last sent", u16 |]
            let flow_mon_id = IRange (0, 0xfffff)
            let alt_mark =
                Widget.record [| "flow monitoring id", flow_mon_id ;
                                 "loss", Bool ; "delay", Bool |]
            let min_pmtu =
                Widget.record [| "minimum", u16 ; "returned", u16 ; "R", Bool |]
            let other = BRange (2, 0x101)
            let opt =
                Widget.variant [|
                    "Pad1", None ;
                    "PadN", Some u8 ;
                    "PDM", Some pdm ;
                    "alternate marking", Some alt_mark ;
                    "minimum path MTU", Some min_pmtu ;
                    "other", Some other |]
        end

        let to_json opt : Yojson.Basic.t =
            match opt with
            | Pad1 -> `Assoc [ "Pad1", `Null ]
            | PadN n -> `Assoc [ "PadN", `Int n ]
            | Pdm p ->
                `Assoc [ "PDM", `Assoc [
                    "scale DTLR", `Int p.scale_dtlr ;
                    "scale DTLS", `Int p.scale_dtls ;
                    "PSN this packet", `Int p.psn_this ;
                    "PSN last received", `Int p.psn_last ;
                    "delta time last received", `Int p.delta_last_recv ;
                    "delta time last sent", `Int p.delta_last_sent ] ]
            | Alt_mark a ->
                `Assoc [ "alternate marking", `Assoc [
                    "flow monitoring id", `Int a.flow_mon_id ;
                    "loss", `Bool a.loss ; "delay", `Bool a.delay ] ]
            | Min_pmtu m ->
                `Assoc [ "minimum path MTU", `Assoc [
                    "minimum", `Int m.min_pmtu ;
                    "returned", `Int m.rtn_pmtu ; "R", `Bool m.r ] ]
            | Other bits -> `Assoc [ "other", Widget.json_of_bytes bits ]

        (* [js] is the synth of an option of [Kinds.opt], as [Generator.expand]
         * leaves it. The flow monitoring id is random when automatic, as RFC
         * 9343 wants it, and all else is zero but the minimum path MTU: *)
        let of_synth gen_values js =
            let open Generator in
            let int ?auto name kind v = int_of_field name gen_values ?auto kind identity v
            and bool name v =
                of_field name gen_values ~auto:(fun () -> false) SimTypes.Bool
                         Widget.to_bool v
            and zero () = 0 in
            match js with
            | `Assoc [ "Pad1", _ ] ->
                Pad1
            | `Assoc [ "PadN", v ] ->
                PadN (of_value gen_values ~auto:zero Kinds.u8 Widget.to_int v)
            | `Assoc [ "PDM", v ] ->
                let v = expand gen_values Kinds.pdm v in
                let u16 name = int ~auto:zero name Kinds.u16 v in
                Pdm { scale_dtlr = int ~auto:zero "scale DTLR" Kinds.u8 v ;
                      scale_dtls = int ~auto:zero "scale DTLS" (IRange (-128, 127)) v ;
                      psn_this = u16 "PSN this packet" ;
                      psn_last = u16 "PSN last received" ;
                      delta_last_recv = u16 "delta time last received" ;
                      delta_last_sent = u16 "delta time last sent" }
            | `Assoc [ "alternate marking", v ] ->
                let v = expand gen_values Kinds.alt_mark v in
                Alt_mark { flow_mon_id = int "flow monitoring id" Kinds.flow_mon_id v ;
                           loss = bool "loss" v ; delay = bool "delay" v }
            | `Assoc [ "minimum path MTU", v ] ->
                let v = expand gen_values Kinds.min_pmtu v in
                Min_pmtu { min_pmtu = int ~auto:(fun () -> 1500) "minimum" Kinds.u16 v ;
                           rtn_pmtu = int ~auto:zero "returned" Kinds.u16 v land 0xfffe ;
                           r = bool "R" v }
            | `Assoc [ "other", v ] ->
                (* An option of an experimental type (RFC 4727), carrying nothing: *)
                Other (bs_of_value gen_values ~auto:(fun () -> bitstring_of_string "\x1e\x00")
                                   Kinds.other v)
            | js ->
                Widget.bad_value "not an IPv6 option: %s" (Yojson.Basic.to_string js)

        (*$>*)
    end

    (** The Segment Routing Header (SRH, cf RFC8754). *)
    module Routing =
    struct
        (*$< Routing *)

        (* The TLVs of a segment routing header: *)
        type tlv =
            | Pad1
            | PadN of int (* that many zero bytes *)
            | Hmac of { d : bool ; key_id : int32 ; hmac : bitstring }
            | Other_tlv of bitstring (* type, length and data *)

        type t =
            (* RFC 8754. [segments] are in the header's order, the final
             * destination first: *)
            | Srh of { segments_left : int ; flags : int ; tag : int ;
                       segments : Ip.Addr.t list ; tlvs : tlv list }
            | Other of { typ : int ; segments_left : int ; data : bitstring }

        let pack_tlv = function
            | Pad1 ->
                [%bitstring {| 0 : 8 |}]
            | PadN n ->
                concat [ [%bitstring {| 4 : 8 ; n : 8 |}] ; zeroes_bitstring (8 * n) ]
            | Hmac h ->
                concat [ [%bitstring {| 5 : 8 ; 6 + bytelength h.hmac : 8 ;
                                        h.d : 1 ; 0 : 15 ; h.key_id : 32 |}] ;
                         h.hmac ]
            | Other_tlv bits ->
                bits

        let decode_tlv tlv =
            match%bitstring tlv with
            | {| 4 : 8 ; n : 8 ; pad : -1 : bitstring |} when is_zeroes pad ->
                PadN n
            | {| 5 : 8 ; len : 8 ; d : 1 ; 0 : 15 ; key_id : 32 ;
                 hmac : -1 : bitstring |} when len >= 6 ->
                Hmac { d ; key_id ; hmac }
            | {| _ |} ->
                Other_tlv tlv

        let unpack_tlvs bits =
            unpack_tlvs 0 (fun tlv -> `Tlv (decode_tlv tlv)) bits |>
            List.map (function `Pad1 -> Pad1 | `Tlv t -> t | `Other b -> Other_tlv b)

        (* What follows the length byte: *)
        let pack = function
            | Srh s ->
                let last_entry = List.length s.segments - 1 in
                if last_entry < 0 then
                    invalid_arg "Ip6.Extension.Routing.pack: no segment" ;
                concat ([%bitstring {| 4 : 8 ; s.segments_left : 8 ;
                                       last_entry : 8 ; s.flags : 8 ; s.tag : 16 |}] ::
                        List.map Ip.Addr.to_bitstring s.segments @
                        List.map pack_tlv s.tlvs)
            | Other o ->
                concat [ [%bitstring {| o.typ : 8 ; o.segments_left : 8 |}] ;
                         o.data ]

        let rec addrs n bits =
            if n = 0 then Some ([], bits) else
            match%bitstring bits with
            | {| a : 128 : bitstring ; rest : -1 : bitstring |} ->
                Option.map (fun (l, rest) -> Ip.Addr.of_bitstring a :: l, rest)
                           (addrs (n - 1) rest)
            | {| _ |} -> None

        let unpack bits =
            let other () =
                match%bitstring bits with
                | {| typ : 8 ; segments_left : 8 ; data : -1 : bitstring |} ->
                    Other { typ ; segments_left ; data }
                | {| _ |} ->
                    invalid_arg "Ip6.Extension.Routing.unpack: too short" in
            match%bitstring bits with
            | {| 4 : 8 ; segments_left : 8 ; last_entry : 8 ; flags : 8 ;
                 tag : 16 ; rest : -1 : bitstring |} ->
                (match addrs (last_entry + 1) rest with
                | Some (segments, tlvs) ->
                    Srh { segments_left ; flags ; tag ; segments ;
                          tlvs = unpack_tlvs tlvs }
                | None -> other ())
            | {| _ |} -> other ()

        let tlv_to_string = function
            | Pad1 -> "Pad1"
            | PadN n -> Printf.sprintf "PadN %d" n
            | Hmac h ->
                Printf.sprintf "HMAC%s key %lu %s" (if h.d then " D" else "")
                    h.key_id (hex_of_bitstring h.hmac)
            | Other_tlv bits -> "tlv " ^ hex_of_bitstring bits

        let to_string = function
            | Srh s ->
                Printf.sprintf "SRH left %d%s%s [%s]%s" s.segments_left
                    (if s.flags <> 0 then Printf.sprintf " flags 0x%02x" s.flags else "")
                    (if s.tag <> 0 then Printf.sprintf " tag %d" s.tag else "")
                    (String.concat ", " (List.map Ip.Addr.to_dotted_string s.segments))
                    (if s.tlvs = [] then "" else
                     " "^ String.concat ", " (List.map tlv_to_string s.tlvs))
            | Other o ->
                Printf.sprintf "routing type %d left %d %s"
                    o.typ o.segments_left (hex_of_bitstring o.data)

        let random () =
            let segments =
                List.init (1 + Random.int 3) (fun _ -> Ip.Addr.random ~v4:false ()) in
            let tlv () =
                match Random.int 4 with
                | 0 -> Pad1
                | 1 -> PadN (Random.int 6)
                | 2 -> Hmac { d = Random.bool () ; key_id = rand32 () ;
                              hmac = randbs (8 * Random.int 5) }
                | _ ->
                    let len = Random.int 6 in
                    Other_tlv (concat [ [%bitstring {| 0x7e : 8 ; len : 8 |}] ;
                                        randbs len ]) in
            if Random.int 4 = 0 then
                Other { typ = Random.int 4 ; segments_left = randi 8 ;
                        data = randbs (4 + 8 * Random.int 3) }
            else
                Srh { segments_left = Random.int (List.length segments + 1) ;
                      flags = randi 8 ; tag = randi 16 ; segments ;
                      tlvs = List.init (Random.int 3) (fun _ -> tlv ()) }

        module Kinds =
        struct
            open SimTypes
            let u8 = IRange (0, 0xff)
            let tag = IRange (0, 0xffff)
            let addr = Widget.hint "2001:db8::1" Ipv6
            let key_id = IRange (0, 0xffff_ffff)
            let hmac_bytes = BRange (0, 0xff - 6)
            let hmac = Widget.record [| "D", Bool ; "key id", key_id ;
                                        "HMAC", hmac_bytes |]
            let other_tlv = BRange (2, 0x101)
            let tlv =
                Widget.variant [|
                    "Pad1", None ;
                    "PadN", Some u8 ;
                    "HMAC", Some hmac ;
                    "other", Some other_tlv |]
            let srh =
                Widget.record [|
                    "segments left", u8 ;
                    "flags", u8 ;
                    "tag", tag ;
                    "segments", Widget.list addr ;
                    "TLVs", Widget.list tlv |]
            (* So that the header is at most 2048 bytes long: *)
            let data = BRange (0, 2044)
            let other =
                Widget.record [| "type", u8 ; "segments left", u8 ; "data", data |]
            let routing =
                Widget.variant [|
                    "segment routing", Some srh ;
                    "other", Some other |]
        end

        let tlv_to_json : tlv -> Yojson.Basic.t = function
            | Pad1 -> `Assoc [ "Pad1", `Null ]
            | PadN n -> `Assoc [ "PadN", `Int n ]
            | Hmac h ->
                `Assoc [ "HMAC", `Assoc [ "D", `Bool h.d ;
                                          "key id", `Int (uint32 h.key_id) ;
                                          "HMAC", Widget.json_of_bytes h.hmac ] ]
            | Other_tlv bits -> `Assoc [ "other", Widget.json_of_bytes bits ]

        let to_json : t -> Yojson.Basic.t = function
            | Srh s ->
                `Assoc [ "segment routing", `Assoc [
                    "segments left", `Int s.segments_left ;
                    "flags", `Int s.flags ;
                    "tag", `Int s.tag ;
                    "segments", `List (List.map Ip.Addr.to_json s.segments) ;
                    "TLVs", `List (List.map tlv_to_json s.tlvs) ] ]
            | Other o ->
                `Assoc [ "other", `Assoc [
                    "type", `Int o.typ ;
                    "segments left", `Int o.segments_left ;
                    "data", Widget.json_of_bytes o.data ] ]

        (* As [Options.of_synth]. An automatic SRH has one empty segment,
         * that is still to visit; an automatic other routing header is of an
         * experimental type (RFC 4727): *)
        let of_synth gen_values js =
            let open Generator in
            let int ?auto name kind v = int_of_field name gen_values ?auto kind identity v
            and zero () = 0 in
            let tlv = function
                | `Assoc [ "Pad1", _ ] ->
                    Pad1
                | `Assoc [ "PadN", v ] ->
                    PadN (of_value gen_values ~auto:zero Kinds.u8 Widget.to_int v)
                | `Assoc [ "HMAC", v ] ->
                    let v = expand gen_values Kinds.hmac v in
                    Hmac { d = of_field "D" gen_values ~auto:(fun () -> false)
                                        SimTypes.Bool Widget.to_bool v ;
                           key_id = Int32.of_int (int ~auto:zero "key id" Kinds.key_id v) ;
                           hmac = bs_of_field "HMAC" gen_values
                                              ~auto:(fun () -> empty_bitstring)
                                              Kinds.hmac_bytes v }
                | `Assoc [ "other", v ] ->
                    Other_tlv (bs_of_value gen_values
                                           ~auto:(fun () -> bitstring_of_string "\x7e\x00")
                                           Kinds.other_tlv v)
                | js ->
                    Widget.bad_value "not an SRH TLV: %s" (Yojson.Basic.to_string js) in
            let addr =
                of_value gen_values ~auto:(fun () -> Ip.Addr.zero6) Kinds.addr
                         (Ip.Addr.of_dotted_string % Widget.to_string) in
            match js with
            | `Assoc [ "segment routing", v ] ->
                let v = expand gen_values Kinds.srh v in
                let segments =
                    Widget.to_field "segments" (function
                        | `Null -> [ addr `Null ]
                        | l -> expand gen_values (Widget.list Kinds.addr) l |>
                               Widget.to_list addr) v in
                Srh { segments_left = int ~auto:(fun () -> List.length segments - 1)
                                          "segments left" Kinds.u8 v ;
                      flags = int ~auto:zero "flags" Kinds.u8 v ;
                      tag = int ~auto:zero "tag" Kinds.tag v ;
                      segments ;
                      tlvs = Widget.to_field "TLVs" (function
                          | `Null -> []
                          | l -> expand gen_values (Widget.list Kinds.tlv) l |>
                                 Widget.to_list tlv) v }
            | `Assoc [ "other", v ] ->
                let v = expand gen_values Kinds.other v in
                Other { typ = int ~auto:(fun () -> 253) "type" Kinds.u8 v ;
                        segments_left = int ~auto:zero "segments left" Kinds.u8 v ;
                        data = bs_of_field "data" gen_values
                                           ~auto:(fun () -> empty_bitstring) Kinds.data v }
            | js ->
                Widget.bad_value "not a routing header: %s" (Yojson.Basic.to_string js)

        (*$>*)
    end

    type t =
        | Hop_by_hop of Options.t list
        | Dest_opts of Options.t list
        | Routing of Routing.t
        (* [offset] in 8 bytes units: *)
        | Fragment of { offset : int ; more : bool ; id : int32 }
        (* [body] is the whole header but its next header byte: *)
        | Other of { typ : int ; body : bitstring }

    let hop_by_hop = 0 and routing = 43 and fragment = 44 and dest_opts = 60

    let typ = function
        | Hop_by_hop _ -> hop_by_hop
        | Dest_opts _ -> dest_opts
        | Routing _ -> routing
        | Fragment _ -> fragment
        | Other { typ ; _ } -> typ

    (* The IANA list of extension headers, but ESP that ends the chain: *)
    let is_extension typ =
        Array.mem typ [| 0 ; 43 ; 44 ; 51 ; 60 ; 135 ; 139 ; 140 ; 253 ; 254 |]

    (* [data] is what follows the length byte: *)
    let pack_generic next data =
        let len = 2 + bytelength data in
        if len land 7 <> 0 then
            invalid_arg "Ip6.Extension.pack: not a multiple of 8 bytes" ;
        concat [ [%bitstring {| next : 8 ; len / 8 - 1 : 8 |}] ; data ]

    let pack_one next = function
        | Hop_by_hop opts | Dest_opts opts ->
            pack_generic next (Options.pack opts)
        | Routing r ->
            pack_generic next (Routing.pack r)
        | Fragment f ->
            [%bitstring {| next : 8 ; 0 : 8 ; f.offset : 13 ; 0 : 2 ;
                           f.more : 1 ; f.id : 32 |}]
        | Other o ->
            concat [ [%bitstring {| next : 8 |}] ; o.body ]

    (** The next header field of the IPv6 header and the extensions [exts]
     * packed, for an upper-layer protocol [proto]. *)
    let pack exts proto =
        let rec loop = function
            | [] -> []
            | [ e ] -> [ pack_one proto e ]
            | e :: (e' :: _ as rest) -> pack_one (typ e') e :: loop rest in
        (match exts with [] -> proto | e :: _ -> typ e),
        concat (loop exts)

    (* [hdr] is a whole header of type [typ]: *)
    let decode typ hdr =
        match%bitstring hdr with
        | {| _ : 8 ; _ : 8 ; data : -1 : bitstring |} when typ = hop_by_hop ->
            Hop_by_hop (Options.unpack data)
        | {| _ : 8 ; _ : 8 ; data : -1 : bitstring |} when typ = dest_opts ->
            Dest_opts (Options.unpack data)
        | {| _ : 8 ; _ : 8 ; data : -1 : bitstring |} when typ = routing ->
            Routing (Routing.unpack data)
        | {| _ : 8 ; 0 : 8 ; offset : 13 ; 0 : 2 ; more : 1 ; id : 32 |}
          when typ = fragment ->
            Fragment { offset ; more ; id }
        | {| _ : 8 ; body : -1 : bitstring |} ->
            Other { typ ; body }

    (** The extensions starting [bits], which follow a header announcing
     * [typ], the upper-layer protocol and its payload. The chain ends at
     * the first header that is not an extension or that is truncated, and
     * after the fragment header of a fragment but the first, what follows it
     * being the middle of a packet. *)
    let rec unpack typ bits =
        let stop () = [], typ, bits in
        if not (is_extension typ) then stop () else
        match%bitstring bits with
        | {| next : 8 ; len : 8 |} ->
            let len =
                if typ = fragment then 8
                else if typ = 51 then 4 * (len + 2) (* AH *)
                else 8 * (len + 1) in
            if 8 * len > bitstring_length bits then stop () else
            (match decode typ (takebytes len bits) with
            | Fragment { offset ; _ } as e when offset > 0 ->
                [ e ], next, dropbytes len bits
            | e ->
                let exts, proto, payload = unpack next (dropbytes len bits) in
                e :: exts, proto, payload)
        | {| _ |} ->
            stop ()

    let to_string = function
        | Hop_by_hop opts -> "HBH ["^ Options.list_to_string opts ^"]"
        | Dest_opts opts -> "DSTOPT ["^ Options.list_to_string opts ^"]"
        | Routing r -> Routing.to_string r
        | Fragment f ->
            Printf.sprintf "frag id %lu off %d%s" f.id (f.offset * 8)
                (if f.more then "+" else "")
        | Other o -> Printf.sprintf "ext %d %s" o.typ (hex_of_bitstring o.body)

    let list_to_string exts =
        String.concat ", " (List.map to_string exts)

    (* The padding that makes [len] bytes of data after the length byte a
     * multiple of 8: *)
    let padding len pad1 padn =
        match (2 + len) land 7 with
        | 0 -> []
        | 7 -> [ pad1 ]
        | r -> [ padn (6 - r) ]

    (** [e] padded to a multiple of 8 bytes, as [pack] wants it, with Pad1
     * or PadN, or zeroes after the data of an unknown routing header. *)
    let pad e =
        let pad_opts opts =
            opts @ padding (bytelength (Options.pack opts))
                           Options.Pad1 (fun n -> Options.PadN n) in
        match e with
        | Hop_by_hop opts -> Hop_by_hop (pad_opts opts)
        | Dest_opts opts -> Dest_opts (pad_opts opts)
        | Routing (Routing.Srh s as r) ->
            let tlvs =
                s.tlvs @ padding (bytelength (Routing.pack r))
                                 Routing.Pad1 (fun n -> Routing.PadN n) in
            Routing (Routing.Srh { s with tlvs })
        | Routing (Routing.Other o as r) ->
            let missing = (6 - bytelength (Routing.pack r)) land 7 in
            Routing (Routing.Other { o with data = concat [ o.data ;
                                                            zeroes_bitstring (8 * missing) ] })
        | e -> e

    let random () =
        let one () =
            match Random.int 5 with
            | 0 -> Hop_by_hop (Options.random ())
            | 1 -> Dest_opts (Options.random ())
            | 2 -> Routing (Routing.random ())
            | 3 -> Fragment { offset = randi 13 ; more = Random.bool () ;
                              id = rand32 () }
            | _ ->
                (* An AH, which counts in 4 bytes units: *)
                let len = Random.int 4 in
                Other { typ = 51 ;
                        body = concat [ [%bitstring {| len : 8 |}] ;
                                        randbs (4 * (len + 2) - 2) ] } in
        (* A later fragment's header ends the chain: *)
        let rec cut = function
            | [] -> []
            | Fragment { offset ; _ } as e :: _ when offset > 0 -> [ e ]
            | e :: rest -> e :: cut rest in
        cut (List.init (Random.int 4) (fun _ -> pad (one ())))

    module Kinds =
    struct
        open SimTypes
        let options = Widget.list Options.Kinds.opt
        let fragment_offset = IRange (0, 0x1fff)
        let fragment_id = IRange (0, 0xffff_ffff)
        let fragment =
            Widget.record [| "offset", fragment_offset ;
                             "more fragments", Bool ;
                             "id", fragment_id |]
        let typ = IRange (0, 0xff)
        let body = BRange (1, 0x7ff)
        let other = Widget.record [| "type", typ ; "body", body |]
        let ext =
            Widget.variant [|
                "hop-by-hop options", Some options ;
                "destination options", Some options ;
                "routing", Some Routing.Kinds.routing ;
                "fragment", Some fragment ;
                "other", Some other |]
        let extensions = Widget.list ext
    end

    let to_json : t -> Yojson.Basic.t = function
        | Hop_by_hop opts ->
            `Assoc [ "hop-by-hop options", `List (List.map Options.to_json opts) ]
        | Dest_opts opts ->
            `Assoc [ "destination options", `List (List.map Options.to_json opts) ]
        | Routing r ->
            `Assoc [ "routing", Routing.to_json r ]
        | Fragment f ->
            `Assoc [ "fragment", `Assoc [ "offset", `Int f.offset ;
                                          "more fragments", `Bool f.more ;
                                          "id", `Int (uint32 f.id) ] ]
        | Other o ->
            `Assoc [ "other", `Assoc [ "type", `Int o.typ ;
                                       "body", Widget.json_of_bytes o.body ] ]

    (* [js] is the synth of an extension of [Kinds.ext], as
     * [Generator.expand] leaves it; the result is [pad]ded. Automatic
     * options are none, an automatic fragment is the first and only one,
     * and an automatic other header is an experimental one (RFC 4727) as
     * short as can be: *)
    let of_synth gen_values js =
        let open Generator in
        let options = function
            | `Null -> []
            | l -> expand gen_values Kinds.options l |>
                   Widget.to_list (Options.of_synth gen_values) in
        pad (match js with
        | `Assoc [ "hop-by-hop options", v ] ->
            Hop_by_hop (options v)
        | `Assoc [ "destination options", v ] ->
            Dest_opts (options v)
        | `Assoc [ "routing", v ] ->
            Routing (Routing.of_synth gen_values
                                      (expand gen_values Routing.Kinds.routing v))
        | `Assoc [ "fragment", v ] ->
            let v = expand gen_values Kinds.fragment v in
            Fragment {
                offset = int_of_field "offset" gen_values ~auto:(fun () -> 0)
                                      Kinds.fragment_offset identity v ;
                more = of_field "more fragments" gen_values ~auto:(fun () -> false)
                                SimTypes.Bool Widget.to_bool v ;
                id = Int32.of_int (int_of_field "id" gen_values Kinds.fragment_id
                                                identity v) }
        | `Assoc [ "other", v ] ->
            let v = expand gen_values Kinds.other v in
            Other { typ = int_of_field "type" gen_values ~auto:(fun () -> 253)
                                       Kinds.typ identity v ;
                    body = bs_of_field "body" gen_values
                                       ~auto:(fun () -> zeroes_bitstring 56)
                                       Kinds.body v }
        | js ->
            Widget.bad_value "not an IPv6 extension header: %s"
                             (Yojson.Basic.to_string js))

    (* Automatic extensions pack, and are read back: *)
    (*$= of_synth & ~printer:identity
      ("HBH [MinPMTU 1500 rtn 0, AltMark 0, PadN 0], SRH left 0 [::], " ^ \
       "routing type 253 left 0 00000000, " ^ \
       "DSTOPT [PDM psn 0/0 delta 0<<0/0<<0, opt 1E00], " ^ \
       "frag id 0 off 0, ext 253 00000000000000") \
        (let autos ?(gen=[]) kind = \
          `Assoc (Array.to_list (Widget.field_names kind) |> List.map (fun n -> \
            n, if List.mem n gen then `Assoc [ "gen", `Int 0 ] else `Null)) in \
        let exts = \
          Generator.expand [| 0 |] Kinds.extensions (`List [ \
            `Assoc [ "hop-by-hop options", `List [ \
              `Assoc [ "minimum path MTU", autos Options.Kinds.min_pmtu ] ; \
              `Assoc [ "alternate marking", \
                       autos ~gen:[ "flow monitoring id" ] Options.Kinds.alt_mark ] ] ] ; \
            `Assoc [ "routing", `Assoc [ "segment routing", autos Routing.Kinds.srh ] ] ; \
            `Assoc [ "routing", `Assoc [ "other", autos Routing.Kinds.other ] ] ; \
            `Assoc [ "destination options", `List [ \
              `Assoc [ "PDM", autos Options.Kinds.pdm ] ; `Assoc [ "other", `Null ] ] ] ; \
            `Assoc [ "fragment", autos ~gen:[ "id" ] Kinds.fragment ] ; \
            `Assoc [ "other", autos Kinds.other ] ]) |> \
          Widget.to_list (of_synth [| 0 |]) in \
        let next, bits = pack exts 6 in \
        let exts, _, _ = unpack next bits in \
        list_to_string exts)
     *)

    (*$Q pack
      (Q.make ~print:list_to_string (fun _ -> random ())) (fun exts -> \
        let next, bits = pack exts 6 in \
        let exts', proto, rest = unpack next bits in \
        list_to_string exts' = list_to_string exts && proto = 6 && Bitstring.bitstring_length rest = 0)
      Q.(pair (int_bound 255) (int_bound 64)) (fun (typ, n) -> \
        let b = randbs n in \
        let exts, proto, rest = unpack typ b in \
        let next, bits = pack exts proto in \
        next = typ && Bitstring.equals b (Bitstring.concat [ bits ; rest ]))
     *)

    (*$>*)
end

(** {2 IPv6 Packet} *)

(** (Un)Packing an IPv6 packet. *)

module Pdu = struct
    (*$< Pdu *)

    (* [proto] is the upper-layer protocol, which follows the extensions: *)
    type t = { ttl : int ; proto : Ip.Proto.t ;
               diff_serv : int ; ecn : int ; flow_label : int ;
               src : Ip.Addr.t ; dst : Ip.Addr.t ;
               extensions : Extension.t list ;
               payload : Payload.t }

    let make ?(ttl=64) ?(diff_serv=0) ?(ecn=0) ?(flow_label=0)
             ?(extensions=[]) proto src dst payload =
        { ttl ; proto ; diff_serv ; ecn ; flow_label ; src ; dst ;
          extensions ; payload = Payload.o payload }

    let random () =
        make ~extensions:(Extension.random ()) (Ip.Proto.random ())
             (Ip.Addr.random ~v4:false ())
             (Ip.Addr.random ~v4:false ())
             (randbs (Random.int 10 + 20))

    (* The offset and more fragments flag of the fragment header, if any: *)
    let fragment t =
        List.find_map_opt (function
            | Extension.Fragment f -> Some (f.offset, f.more)
            | _ -> None) t.extensions

    (** Whether the payload is a part only of the upper-layer packet. *)
    let is_fragment t =
        match fragment t with
        | Some (offset, more) -> offset > 0 || more
        | None -> false

    (** Whether the payload is a part of the upper-layer packet but its
     * first. *)
    let is_later_fragment t =
        match fragment t with
        | Some (offset, _) -> offset > 0
        | None -> false

    (** The TCP or UDP ports, unless the payload is a later fragment: *)
    let get_ports t =
        if is_later_fragment t then Error (lazy "Not the first fragment")
        else Ip.Pdu.ports_of t.proto t.payload

    (** [bits], an IPv6 packet, with a hop limit one less: *)
    let decr_hop_limit bits =
        let b = Bytes.of_string (string_of_bitstring bits) in
        if Bytes.length b < 8 then invalid_arg "Ip6.Pdu.decr_hop_limit" ;
        Bytes.set_uint8 b 7 ((Bytes.get_uint8 b 7 - 1) land 0xff) ;
        bitstring_of_string (Bytes.unsafe_to_string b)
    (*$T decr_hop_limit
      let bits = make ~ttl:9 Ip.Proto.udp (Ip.Addr.of_string "::1") \
                    (Ip.Addr.of_string "::2") (Bitstring.zeroes_bitstring 64) |> pack in \
      let bits' = decr_hop_limit bits in \
      Bitstring.equals (Bitstring.takebits 56 bits) (Bitstring.takebits 56 bits') && \
      Bitstring.equals (Bitstring.dropbits 64 bits) (Bitstring.dropbits 64 bits') && \
      (match unpack bits' with Ok ip -> ip.ttl = 8 | Error _ -> false)
     *)

    (** The extensions all fragments repeat, and those that are fragmented
     * with the upper-layer packet: what is past the last routing header, or
     * past the hop-by-hop options if there is none (RFC 8200, 4.5). *)
    let split_unfragmentable exts =
        let n, _ =
            List.fold_left (fun (n, i) -> function
                | Extension.Routing _ -> i + 1, i + 1
                | Extension.Hop_by_hop _ when i = 0 -> 1, 1
                | _ -> n, i + 1) (0, 0) exts in
        List.takedrop n exts

    (** Where the upper-layer packet goes (RFC 8200, 8.1). *)
    let final_dst t =
        List.find_map_opt (function
            | Extension.Routing (Srh { segments = d :: _ ; _ }) -> Some d
            | _ -> None) t.extensions |? t.dst

    let pseudo_header t () =
        let%bitstring hdr = {|
            Ip.Addr.to_bitstring t.src : 128 : bitstring ;
            Ip.Addr.to_bitstring (final_dst t) : 128 : bitstring ;
            Payload.length t.payload : 16 ;
            0 : 24 ;
            (t.proto :> int) : 8 |} in
        hdr

    let pack t =
        let next, extensions = Extension.pack t.extensions (t.proto :> int) in
        let%bitstring header = {|
            6 : 4 ; t.diff_serv : 6 ; t.ecn : 2 ; t.flow_label : 20 ;
            bytelength extensions + Payload.length t.payload : 16 ;
            next : 8 ; t.ttl : 8 ;
            Ip.Addr.to_bitstring t.src : 128 : bitstring ;
            Ip.Addr.to_bitstring t.dst : 128 : bitstring |} in
        (* must we patch some checksum? Not of a fragment, which has only a
         * part of what it covers. *)
        let payload =
            let fix_udp_checksum = function 0 -> 0xffff | x -> x in (* As per rfc2460, 8.1 *)
            if is_fragment t then t.payload
            else if t.proto = Ip.Proto.tcp then Ip.Pdu.patch_checksum 128 (pseudo_header t) t.payload
            else if t.proto = Ip.Proto.udp then Ip.Pdu.patch_checksum 48 (pseudo_header t) ~fixit:fix_udp_checksum t.payload
            else if t.proto = Ip.Proto.icmpv6 then Ip.Pdu.patch_checksum 16 (pseudo_header t) t.payload
            else t.payload in
        concat [ header ; extensions ; (payload :> bitstring) ]

    (* With [truncated], a packet may lack the end of its payload, as one an
     * ICMPv6 error quotes: *)
    let unpack ?(truncated=false) bits = match%bitstring bits with
        | {| 6 : 4 ; diff_serv : 6 ; ecn : 2 ; flow_label : 20 ;
             payload_len : 16 ; next : 8 ; ttl : 8 ;
             src : 128 : bitstring ; dst : 128 : bitstring ;
             rest : -1 : bitstring |}
          when truncated || bitstring_length rest >= payload_len * 8 ->
            let payload = takebits (min (payload_len * 8) (bitstring_length rest)) rest in
            let extensions, proto, payload = Extension.unpack next payload in
            Ok { diff_serv ; ecn ; flow_label ;
                 proto = Ip.Proto.o proto ; ttl ;
                 src = Ip.Addr.of_bitstring src ;
                 dst = Ip.Addr.of_bitstring dst ;
                 extensions ; payload = Payload.o payload }
        | {| 4 : 4 ; _ |} ->
            Error (lazy "IPv6 looks like v4")
        | {| _ |} ->
            Error (lazy ("Not IPv6: "^ hexstring_of_bitstring_abbrev bits))

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)
    (*$T unpack
      let p = make Ip.Proto.udp (Ip.Addr.of_string "2001:db8::1") \
                   (Ip.Addr.of_string "2001:db8::2") (randbs 100) in \
      let cut = takebytes 60 (pack p) in \
      Result.is_error (unpack cut) && \
      (match unpack ~truncated:true cut with \
       | Ok q -> q.src = p.src && Payload.length q.payload = 20 \
       | Error _ -> false)
    *)
    (* The checksum is patched for the final destination, and not in
     * fragments: *)
    (*$T pack
      let udp = Udp.Pdu.(pack (make (Bitstring.bitstring_of_string "x"))) \
      and a = Ip.Addr.of_string "2001:db8::1" \
      and b = Ip.Addr.of_string "2001:db8::2" \
      and c = Ip.Addr.of_string "2001:db8::3" in \
      let chk exts dst = \
        match unpack (pack (make ~extensions:exts Ip.Proto.udp a dst udp)) with \
        | Ok t -> Bitstring.takebits 16 (Bitstring.dropbits 48 (t.payload :> Bitstring.bitstring)) \
        | Error _ -> Bitstring.empty_bitstring in \
      let srh = Extension.(Routing (Routing.Srh { segments_left = 1 ; flags = 0 ; tag = 0 ; \
                                                  segments = [ c ; b ] ; tlvs = [] })) in \
      Bitstring.equals (chk [ srh ] b) (chk [] c) && \
      not (Bitstring.equals (chk [] b) (chk [] c)) && \
      Bitstring.equals (chk [ Extension.Fragment { offset = 0 ; more = true ; id = 1l } ] b) \
                       (Bitstring.zeroes_bitstring 16)
     *)

    (** [t], which is not a fragment, packed in packets of at most [mtu]
     * bytes: itself if it fits, or else fragments of an id from [next_id].
     * The checksum is patched before splitting.
     * Raises Invalid_argument if [mtu] leaves no room for 8 bytes of
     * fragment data. *)
    let fragment ?(next_id=fun () -> Int32.of_int (Ip.Pdu.next_rand32 ())) mtu t =
        let bits = pack t in
        if bytelength bits <= mtu then [ bits ] else
        let unfrag, frag = split_unfragmentable t.extensions in
        let unfrag_len = 40 + bytelength (snd (Extension.pack unfrag 0)) in
        let next, _ = Extension.pack frag (t.proto :> int) in
        let data = dropbytes unfrag_len bits in
        let max_len = (mtu - unfrag_len - 8) land (lnot 7) in
        if max_len < 8 then invalid_arg "Ip6.Pdu.fragment: MTU too small" ;
        let len = bytelength data and id = next_id () in
        let rec loop pos acc =
            let last = len - pos <= max_len in
            let n = if last then len - pos else max_len in
            let f = Extension.Fragment { offset = pos lsr 3 ; more = not last ; id } in
            let bits =
                pack { t with extensions = unfrag @ [ f ] ; proto = Ip.Proto.o next ;
                              payload = Payload.o (takebytes n (dropbytes pos data)) } in
            if last then List.rev (bits :: acc) else loop (pos + n) (bits :: acc) in
        loop 0 []

    (* TODO: unpack with ports a la ip.ml? *)

    (** What a datagram's header says. No payload length: [t] has none, it
     * being however long the payload is; and no version, that being what this
     * module is.
     *
     * The traffic class is split in two here, unlike IPv4's type of service,
     * because [t] holds it split.
     *
     * The next header is the upper layer's: the next header fields of the
     * extensions follow from their list. *)
    module Kinds =
    struct
        open SimTypes
        let diff_serv = IRange (0, 0x3f)
        let ecn = IRange (0, 3)
        let flow_label = IRange (0, 0xfffff)
        let proto = Widget.one_of ~range:(0, 0xff) Ip.Proto.choices
        let ttl = IRange (0, 0xff)
        let addr = Widget.hint "2001:db8::1" Ipv6
        let extensions = Extension.Kinds.extensions
        let payload = BRange (0, 0xffff)
    end

    let kind =
        Widget.record
            [| "differentiated services", Kinds.diff_serv ;
               "explicit congestion notification", Kinds.ecn ;
               "flow label", Kinds.flow_label ;
               "next header", Kinds.proto ;
               "hop limit", Kinds.ttl ;
               "source", Kinds.addr ;
               "destination", Kinds.addr ;
               "extensions", Kinds.extensions ;
               "payload", Kinds.payload |]

    let to_json (t : t) =
        `Assoc [ "differentiated services", `Int t.diff_serv ;
                 "explicit congestion notification", `Int t.ecn ;
                 "flow label", `Int t.flow_label ;
                 "next header", `Int (t.proto :> int) ;
                 "hop limit", `Int t.ttl ;
                 "source", Ip.Addr.to_json t.src ;
                 "destination", Ip.Addr.to_json t.dst ;
                 "extensions", `List (List.map Extension.to_json t.extensions) ;
                 "payload", Widget.json_of_bytes (t.payload :> bitstring) ]

    (* Where each field is in [kind], which [of_synth] reads them by: *)
    module Field =
    struct
        let i = Widget.field_index kind
        let diff_serv = i "differentiated services"
        let ecn = i "explicit congestion notification"
        let flow_label = i "flow label"
        let proto = i "next header"
        let ttl = i "hop limit"
        let src = i "source"
        let dst = i "destination"
        let extensions = i "extensions"
        let payload = i "payload"
    end

    (* [r] are the fields of a synth of [kind] (see [Generator.fields]): *)
    let of_synth r ?upper ?prev gen_values =
        ignore prev ;
        let open Generator in
        let int i ?auto kind f =
            int_of_nth r i gen_values ?auto kind f
        and addr i =
            of_nth r i gen_values Kinds.addr
                   (Ip.Addr.of_dotted_string % Widget.to_string) in
        (* As for IPv4: an automatic value is what a packet would plausibly
         * carry. *)
        { diff_serv = int Field.diff_serv ~auto:(fun () -> 0)
                          Kinds.diff_serv identity ;
          ecn = int Field.ecn ~auto:(fun () -> 0) Kinds.ecn identity ;
          flow_label = int Field.flow_label Kinds.flow_label identity ;
          proto = int Field.proto ?auto:(from_upper upper Ip.Proto.of_layer)
                      Kinds.proto Ip.Proto.o ;
          ttl = int Field.ttl ~auto:(fun () -> 64) Kinds.ttl identity ;
          src = addr Field.src ;
          dst = addr Field.dst ;
          extensions = nth r Field.extensions (function
              | `Null -> []
              | js -> expand gen_values Kinds.extensions js |>
                      Widget.to_list (Extension.of_synth gen_values)) ;
          payload = Payload.o (payload_of_nth ?upper r Field.payload
                                              gen_values Kinds.payload) }

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

    (* Fragments are told apart by their source, destination and id (RFC
     * 8200, 4.5): *)
    type reassemble_key = Ip.Addr.t * Ip.Addr.t * int32

    (* What a reassembled packet takes from its first fragment: that packet
     * with only the extensions before the fragment header, and the next
     * header that one announces. *)
    type reassembled = (reassemble_key, (Pdu.t * int) Ip.TRX.frag list ref) Hashtbl.t

    type t = { logger : Log.t ;
               power : Simulation.power ;
               src : Ip.Addr.t ; dst : Ip.Addr.t ;
               proto : Ip.Proto.t ;
               (* A larger packet leaves in fragments. See [set_mtu]. *)
               mutable mtu : int ;
               (* The traffic class, as [Ip.TRX]'s type of service, and the
                * hop limit of all emitted packets unless [tx] is told
                * otherwise: *)
               tos : Ip.ToS.t ;
               ttl : int ;
               mutable emit : bitstring -> unit ;
               mutable emit_busy_for : unit -> Clock.Interval.t ;
               mutable recv : bitstring -> unit ;
               mutable recv_busy_for : unit -> Clock.Interval.t ;
               reassembled : reassembled ;
               counters : Ip.TRX.counters }

    let check_mtu mtu =
        ensure (mtu >= 1280) "Ip6: MTU must be at least 1280 bytes"

    (* Applies from the next packet [tx] is given: *)
    let set_mtu t mtu =
        check_mtu mtu ;
        t.mtu <- mtu

    let tx ?tos ?ttl t bits =
        let tos = (tos |? t.tos :> int) and ttl = ttl |? t.ttl in
        let pdu = Pdu.make ~ttl ~diff_serv:(tos lsr 2) ~ecn:(tos land 3)
                           t.proto t.src t.dst bits in
        let frags = Pdu.fragment t.mtu pdu in
        (match List.length frags with
        | 1 -> ()
        | n ->
            t.counters.fragmented <- t.counters.fragmented + 1 ;
            t.counters.frags_out <- t.counters.frags_out + n) ;
        List.iter (fun bits ->
            Log.(log t.logger Debug (lazy (Printf.sprintf
                "Ip6: Emitting an IPv6 packet from %s to %s of length %d (content '%s')"
                (Ip.Addr.to_dotted_string t.src) (Ip.Addr.to_dotted_string t.dst)
                (bytelength bits) (hexstring_of_bitstring bits)))) ;
            Simulation.asap t.power t.emit bits) frags

    (* As Linux's ip6frag_time, and RFC 8200, 4.5: *)
    let reassembly_timeout = Clock.Interval.sec 60.

    (** The packet [ip], a fragment, is of, as if it had not been
     * fragmented, once [reassembled] has all of its fragments. Its header and
     * the extensions before the fragment header are those of the first.
     * Overlapping fragments are dropped, and so is one but the last whose
     * length is not a multiple of 8. *)
    let reassemble_into power counters (reassembled : reassembled) (ip : Pdu.t) =
        match List.span (function Extension.Fragment _ -> false | _ -> true)
                        ip.extensions with
        | unfrag, Extension.Fragment f :: after ->
            (* What follows the fragment header, as it was sent: *)
            let next, after = Extension.pack after (ip.proto :> int) in
            let data = concat [ after ; (ip.payload :> bitstring) ] in
            if f.more && bytelength data land 7 <> 0 then None else
            Ip.TRX.reassemble_frags power counters ~strict:true
                ~timeout:reassembly_timeout reassembled (ip.src, ip.dst, f.id)
                { Ip.TRX.offset = f.offset ; more = f.more ; data ;
                  hdr = { ip with extensions = unfrag ;
                                  payload = Payload.o empty_bitstring }, next } |>
            Option.map (fun (((first : Pdu.t), next), data) ->
                let after, proto, payload = Extension.unpack next data in
                { first with extensions = first.extensions @ after ;
                             proto = Ip.Proto.o proto ;
                             payload = Payload.o payload })
        | _ ->
            Some ip

    let rx (t : t) bits =
        match Pdu.unpack bits with
        | Error s ->
            Log.(log t.logger Warning s)
        | Ok ip ->
            let ip =
                if Pdu.is_fragment ip then
                    reassemble_into t.power t.counters t.reassembled ip
                else Some ip in
            Option.may (fun (ip : Pdu.t) ->
                if Payload.bitlength ip.payload > 0 then
                    Simulation.asap t.power t.recv (ip.payload :> bitstring)
            ) ip

    (* Note: In Eth we do not require dst addr since the trx knows (using ARP) how to get dest addr itself.
     *       IP cannot do this since the application layer won't tell him the destination hostname. Or
     *       we must add the destination to any tx call, making host layer simpler only at the expense of
     *       this layer. *)
    let create power ?(mtu=1500) ?(tos=Ip.ToS.o 0) ?(ttl=64)
               ?(counters=Ip.TRX.make_counters ()) src dst proto logger =
        check_mtu mtu ;
        { logger ; power ; src ; dst ; proto ; mtu ; tos ; ttl ;
          emit = ignore_bits ~logger ; emit_busy_for = never_busy ;
          recv = ignore_bits ~logger ; recv_busy_for = never_busy ;
          reassembled = Hashtbl.create 10 ; counters }

    let trx_of t =
        { ins = { write = tx t ;
                  busy_for = (fun () -> t.emit_busy_for ()) ;
                  set_read = fun f busy_for ->
                      t.recv <- f ; t.recv_busy_for <- busy_for } ;
          out = { write = rx t ;
                  busy_for = (fun () -> t.recv_busy_for ()) ;
                  set_read = fun f busy_for ->
                      t.emit <- f ; t.emit_busy_for <- busy_for } }

    let make power ?mtu ?tos ?ttl ?counters src dst proto logger =
        trx_of (create power ?mtu ?tos ?ttl ?counters src dst proto logger)

    (*$< TRX *)
    (* [frags_of s] is what a TRX of [mtu] from [a] to [b] emits for [s], of a
     * protocol whose checksum is not patched in; [frag s off len more] is a
     * hand made fragment of [s] (offsets and lengths in bytes). *)
    (*$inject
      let sim = Simulation.make ~realtime:false "ip6-trx"
      let a = Ip.Addr.of_string "2001:db8::1" and b = Ip.Addr.of_string "2001:db8::2"

      let emitted ?tos ?ttl n =
        let t = create sim.root.power ?tos ?ttl a b Ip.Proto.udp sim.root.logger in
        let out = ref [] in
        (trx_of t).out --> sink (fun bits -> out := bits :: !out) ;
        tx t (randbs n) ;
        Simulation.run sim false ;
        List.map (fun bits -> Result.get_ok (Pdu.unpack bits)) !out

      let received_bits bits =
        let trx = make sim.root.power b a Ip.Proto.udp sim.root.logger in
        let got = ref [] in
        trx.ins --> sink (fun bits -> got := Bitstring.string_of_bitstring bits :: !got) ;
        List.iter trx.out.write bits ;
        Simulation.run sim false ;
        List.rev !got

      let received pkts = received_bits (List.map Pdu.pack pkts)

      let frags_of ?(mtu=1280) s =
        let t = create sim.root.power ~mtu a b (Ip.Proto.o 99) sim.root.logger in
        let out = ref [] in
        (trx_of t).out --> sink (fun bits -> out := bits :: !out) ;
        tx t (Bitstring.bitstring_of_string s) ;
        Simulation.run sim false ;
        List.rev !out

      let frag s off len more =
        Pdu.make ~extensions:[ Extension.Fragment { offset = off / 8 ; more ; id = 7l } ]
                 (Ip.Proto.o 99) a b (Bitstring.bitstring_of_string (String.sub s off len))

      let big = String.init 3000 (fun i -> Char.chr (i land 0xff))
    *)
    (*$T emitted
      match emitted ~tos:(Ip.ToS.o 0xb9) ~ttl:7 10 with \
      | [ p ] -> p.ttl = 7 && p.diff_serv = 0x2e && p.ecn = 1 \
      | _ -> false
      emitted (1500 - 40) |> List.length = 1
      emitted (1500 - 39) |> List.length = 2
    *)
    (* Fragments are as large as the MTU allows, but the last, all of the same
     * id, and their data a multiple of 8 bytes but the last: *)
    (*$T frags_of
      let frags = List.map (Result.get_ok % Pdu.unpack) (frags_of big) in       List.map (fun bits -> Tools.bytelength bits) (frags_of big) = [ 1280 ; 1280 ; 584 ] &&       (match List.map (fun (p : Pdu.t) -> p.extensions) frags with        | [ [ Extension.Fragment f0 ] ; [ Extension.Fragment f1 ] ; [ Extension.Fragment f2 ] ] ->            f0.id = f1.id && f1.id = f2.id &&            f0.offset = 0 && f1.offset = 154 && f2.offset = 308 &&            f0.more && f1.more && not f2.more        | _ -> false)
    *)
    (*$T set_mtu
      let t = create sim.root.power a b Ip.Proto.udp sim.root.logger in \
      let count () = \
        let out = ref 0 in \
        (trx_of t).out --> sink (fun _ -> incr out) ; \
        tx t (randbs (1300 - 40)) ; \
        Simulation.run sim false ; \
        !out in \
      let before = count () in \
      set_mtu t 1280 ; \
      before = 1 && count () = 2
    *)
    (*$T received
      received [ Pdu.make Ip.Proto.udp a b (Bitstring.bitstring_of_string "x") ; \
                 Pdu.make ~extensions:[ Extension.Fragment { offset = 0 ; more = true ; id = 1l } ] \
                          Ip.Proto.udp a b (Bitstring.bitstring_of_string "y") ] = [ "x" ]
    *)
    (*$= received_bits & ~printer:(IO.to_string (List.print String.print))
      [ big ] (received_bits (frags_of big))
      [ big ] (received_bits (List.rev (frags_of big)))
      [ big ] (received_bits (frags_of ~mtu:1500 big))
    *)
    (* Duplicates are ignored, overlaps drop the packet, as does a fragment
     * but the last that is not a multiple of 8 bytes; an atomic fragment is a
     * whole packet: *)
    (*$= received & ~printer:(IO.to_string (List.print String.print))
      [ String.sub big 0 24 ] \
        (received [ frag big 0 16 true ; frag big 0 16 true ; frag big 16 8 false ])
      [] (received [ frag big 0 16 true ; frag big 8 16 false ])
      [] (received [ frag big 0 16 true ; frag big 0 24 true ; frag big 24 8 false ])
      [ String.sub big 0 8 ] (received [ frag big 0 8 false ])
      [] (received [ frag big 0 12 true ; frag big 12 12 false ])
    *)
    (* Extensions past the last routing header travel in the fragments, and are
     * read back as sent: *)
    (*$T reassemble_into
      let srh = Extension.(Routing (Routing.Srh { segments_left = 0 ; flags = 0 ; tag = 0 ; \
                                                  segments = [ b ] ; tlvs = [] })) \
      and dopts = Extension.pad (Extension.Dest_opts [ Extension.Options.PadN 4 ]) in \
      let p = Pdu.make ~extensions:[ Extension.Hop_by_hop [ Extension.Options.PadN 4 ] ; srh ; dopts ] \
                       Ip.Proto.udp a b (Udp.Pdu.(pack (make (Bitstring.bitstring_of_string big)))) in \
      let frags = Pdu.fragment 1280 p in \
      let r = Hashtbl.create 1 in \
      let got = List.filter_map (fun bits -> \
        reassemble_into sim.root.power (Ip.TRX.make_counters ()) r \
                        (Result.get_ok (Pdu.unpack bits))) frags in \
      List.length frags = 3 && \
      List.for_all (fun bits -> \
        match Pdu.unpack bits with \
        | Ok q -> List.length q.extensions >= 3 \
        | Error _ -> false) frags && \
      (match got with \
       | [ q ] -> Bitstring.equals (Pdu.pack q) (Pdu.pack p) \
       | _ -> false)
    *)
    (*$>*)
end
