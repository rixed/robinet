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
(** Transmission Control Protocol. *)
open Batteries
open Bitstring
open Tools

(** {2 Private Types} *)

let show_ports_by_name = ref true
module MakePort (Serv : sig val srv : string end) =
struct
    include Private.Make (struct
        type t = int
        let to_string p =
            if !show_ports_by_name then (
                try (Unix.getservbyport p Serv.srv).Unix.s_name
                with Not_found -> string_of_int p
            ) else string_of_int p
        let is_valid p = p < 0x10000
        let repl_tag = "port"
    end)

    let random () = o (Random.int 0x10000)
end

module Port = MakePort (struct let srv = "tcp" end)

module SeqNum = Private.Make (struct
    type t = int32
    let to_string t = Printf.sprintf "0x%08lX" t
    let is_valid _ = true
    let repl_tag = "seqnum"
end)

(** {2 TCP segments} *)

module Pdu =
struct
    (*$< Pdu *)

    (* Size of a TCP header without options: *)
    let no_opt_hdr_len = 20

    type flags = {
        urg : bool ;
        ack : bool ;
        psh : bool ;
        rst : bool ;
        syn : bool ;
        fin : bool }
    let string_of_flags f =
        Printf.sprintf "%s%s%s%s%s%s"
            (if f.urg then "Urg" else "")
            (if f.ack then "Ack" else "")
            (if f.psh then "Psh" else "")
            (if f.rst then "Rst" else "")
            (if f.syn then "Syn" else "")
            (if f.fin then "Fin" else "")
    let print_flags fmt f = Format.fprintf fmt "@{<flags>%s@}" (string_of_flags f)

    (** TCP options. Decoding never fails, and packing what was decoded gives
     * back the same bytes: what is not understood is an [Other], and what
     * follows an EOL, padding included, is the value of the [Eol]. *)
    module Opt =
    struct
        (*$< Opt *)

        type t =
            | Eol of bitstring (* the padding *)
            | Nop
            | Mss of int
            | Wscale of int (* the shift *)
            | Sack_permitted
            | Sack of (int32 * int32) list (* left and right edges of each block *)
            | Timestamps of int32 * int32 (* value and echo reply *)
            | Other of bitstring (* an unknown or malformed option, kind and length included *)

        (* For the header length to fit in its 4 bits: *)
        let max_len = 40

        let pack_one = function
            | Eol rest ->
                concat [ [%bitstring {| 0 : 8 |}] ; rest ]
            | Nop ->
                [%bitstring {| 1 : 8 |}]
            | Mss mss ->
                [%bitstring {| 2 : 8 ; 4 : 8 ; mss : 16 |}]
            | Wscale shift ->
                [%bitstring {| 3 : 8 ; 3 : 8 ; shift : 8 |}]
            | Sack_permitted ->
                [%bitstring {| 4 : 8 ; 2 : 8 |}]
            | Sack blocks ->
                concat ([%bitstring {| 5 : 8 ; 2 + 8 * List.length blocks : 8 |}] ::
                        List.map (fun (l, r) -> [%bitstring {| l : 32 ; r : 32 |}]) blocks)
            | Timestamps (v, e) ->
                [%bitstring {| 8 : 8 ; 10 : 8 ; v : 32 ; e : 32 |}]
            | Other bits ->
                bits

        (* Zero padded to a whole number of 32 bits words: *)
        let pack opts =
            let bits = concat (List.map pack_one opts) in
            match bytelength bits land 3 with
            | 0 -> bits
            | r -> concat [ bits ; zeroes_bitstring (8 * (4 - r)) ]

        let rec sack_blocks bits =
            match%bitstring bits with
            | {| l : 32 ; r : 32 ; rest : -1 : bitstring |} -> (l, r) :: sack_blocks rest
            | {| _ |} -> []

        (* [tlv] is a whole option, of the length it says: *)
        let decode tlv =
            match%bitstring tlv with
            | {| 2 : 8 ; 4 : 8 ; mss : 16 |} -> Mss mss
            | {| 3 : 8 ; 3 : 8 ; shift : 8 |} -> Wscale shift
            | {| 4 : 8 ; 2 : 8 |} -> Sack_permitted
            | {| 5 : 8 ; len : 8 ; blocks : -1 : bitstring |}
              when len > 2 && (len - 2) land 7 = 0 -> Sack (sack_blocks blocks)
            | {| 8 : 8 ; 10 : 8 ; v : 32 ; e : 32 |} -> Timestamps (v, e)
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

        (* In the manner of tcpdump: *)
        let to_string = function
            | Eol _ -> "eol"
            | Nop -> "nop"
            | Mss mss -> Printf.sprintf "mss %d" mss
            | Wscale shift -> Printf.sprintf "wscale %d" shift
            | Sack_permitted -> "sackOK"
            | Sack blocks ->
                Printf.sprintf "sack %d %s" (List.length blocks)
                    (String.concat " " (List.map (fun (l, r) ->
                        Printf.sprintf "{%lu:%lu}" l r) blocks))
            | Timestamps (v, e) -> Printf.sprintf "TS val %lu ecr %lu" v e
            | Other bits -> "opt " ^ hexstring ~sep:"" (string_of_bitstring bits)

        let list_to_string opts =
            String.concat "," (List.map to_string opts)

        (*$= list_to_string & ~printer:identity
          "mss 1380,nop,nop,TS val 2355191939 ecr 0,nop,wscale 7" \
            (list_to_string (unpack (bitstring_of_string \
              "\x02\x04\x05\x64\x01\x01\x08\x0a\x8c\x61\x60\x83\x00\x00\x00\x00\x01\x03\x03\x07")))
          "sackOK,sack 2 {1:2} {3:4},eol" \
            (list_to_string [ Sack_permitted ; Sack [ 1l, 2l ; 3l, 4l ] ; Eol empty_bitstring ])
          "nop,opt 020800" \
            (list_to_string (unpack (bitstring_of_string "\x01\x02\x08\x00")))
         *)

        (*$= unpack & ~printer:Yojson.Basic.to_string
          (`List (List.map to_json \
            [ Mss 1380 ; Nop ; Nop ; Timestamps (0x8c616083l, 0l) ; Nop ; Wscale 7 ])) \
            (`List (List.map to_json (unpack (bitstring_of_string \
              "\x02\x04\x05\x64\x01\x01\x08\x0a\x8c\x61\x60\x83\x00\x00\x00\x00\x01\x03\x03\x07"))))
          (`List (List.map to_json [ Mss 1460 ; Eol (bitstring_of_string "\x00\x00\x00") ])) \
            (`List (List.map to_json (unpack (bitstring_of_string "\x02\x04\x05\xb4\x00\x00\x00\x00"))))
          (`List (List.map to_json [ Nop ; Eol (bitstring_of_string "\x00\x07") ])) \
            (`List (List.map to_json (unpack (bitstring_of_string "\x01\x00\x00\x07"))))
          (`List (List.map to_json [ Sack [ 1l, 2l ] ; Nop ; Nop ])) \
            (`List (List.map to_json (unpack (bitstring_of_string \
              "\x05\x0a\x00\x00\x00\x01\x00\x00\x00\x02\x01\x01"))))
          (`List (List.map to_json [ Other (bitstring_of_string "\x02\x05\x00\x00\x00") ; Nop ; Nop ; Nop ])) \
            (`List (List.map to_json (unpack (bitstring_of_string "\x02\x05\x00\x00\x00\x01\x01\x01"))))
          (`List (List.map to_json [ Nop ; Other (bitstring_of_string "\x02\x08\x00") ])) \
            (`List (List.map to_json (unpack (bitstring_of_string "\x01\x02\x08\x00"))))
         *)
        (*$Q unpack
          Q.(int_bound 10) (fun n -> \
            let b = randbs (4 * n) in Bitstring.equals b (pack (unpack b)))
         *)

        let random () =
            let one () =
                match Random.int 7 with
                | 0 -> Nop
                | 1 -> Mss (Random.int 0x10000)
                | 2 -> Wscale (Random.int 15)
                | 3 -> Sack_permitted
                | 4 -> Sack (List.init (1 + Random.int 2) (fun _ -> rand32 (), rand32 ()))
                | 5 -> Timestamps (rand32 (), rand32 ())
                | _ ->
                    let kind = 253 + Random.int 2 and len = 2 + Random.int 5 in
                    Other (concat [ [%bitstring {| kind : 8 ; len : 8 |}] ; randbs (len - 2) ]) in
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
            let mss = IRange (0, 0xffff)
            let shift = IRange (0, 0xff)
            let edge = IRange (0, 0xffff_ffff)
            let sack_block = Widget.row [| "left edge", edge ; "right edge", edge |]
            let sack = Widget.list sack_block
            let timestamps = Widget.record [| "value", edge ; "echo reply", edge |]
            let other = BRange (1, max_len)
            let opt =
                Widget.variant [|
                    "EOL", Some after_eol ;
                    "NOP", None ;
                    "MSS", Some mss ;
                    "window scale", Some shift ;
                    "SACK permitted", None ;
                    "SACK", Some sack ;
                    "timestamps", Some timestamps ;
                    "other", Some other |]
        end

        let to_json opt : Yojson.Basic.t =
            let u32 n = `Int (uint32 n) in
            match opt with
            | Eol rest -> `Assoc [ "EOL", Widget.json_of_bytes rest ]
            | Nop -> `Assoc [ "NOP", `Null ]
            | Mss mss -> `Assoc [ "MSS", `Int mss ]
            | Wscale shift -> `Assoc [ "window scale", `Int shift ]
            | Sack_permitted -> `Assoc [ "SACK permitted", `Null ]
            | Sack blocks ->
                `Assoc [ "SACK", `List (List.map (fun (l, r) ->
                    `Assoc [ "left edge", u32 l ; "right edge", u32 r ]) blocks) ]
            | Timestamps (v, e) ->
                `Assoc [ "timestamps", `Assoc [ "value", u32 v ; "echo reply", u32 e ] ]
            | Other bits -> `Assoc [ "other", Widget.json_of_bytes bits ]

        (* [js] is the synth of an option of [Kinds.opt], as [Generator.expand]
         * leaves it. Automatic values are small, so that a few options fit: *)
        let of_synth gen_values js =
            let open Generator in
            let int ~auto kind v = of_value gen_values ~auto kind Widget.to_int v
            and edge name js =
                Int32.of_int (int_of_field name gen_values Kinds.edge identity js) in
            match js with
            | `Assoc [ "EOL", v ] ->
                Eol (bs_of_value gen_values ~auto:(fun () -> empty_bitstring)
                                 Kinds.after_eol v)
            | `Assoc [ "NOP", _ ] ->
                Nop
            | `Assoc [ "MSS", v ] ->
                Mss (int ~auto:(fun () -> 1460) Kinds.mss v)
            | `Assoc [ "window scale", v ] ->
                Wscale (int ~auto:(fun () -> 7) Kinds.shift v)
            | `Assoc [ "SACK permitted", _ ] ->
                Sack_permitted
            | `Assoc [ "SACK", v ] ->
                let v = if v = `Null then `List [ `Null ] else v in
                Sack (expand gen_values Kinds.sack v |>
                      Widget.to_list (fun b ->
                          let b = expand gen_values Kinds.sack_block b in
                          edge "left edge" b, edge "right edge" b))
            | `Assoc [ "timestamps", v ] ->
                let v = expand gen_values Kinds.timestamps v in
                Timestamps (edge "value" v, edge "echo reply" v)
            | `Assoc [ "other", v ] ->
                (* An option of an experimental kind (RFC 4727), carrying nothing: *)
                Other (bs_of_value gen_values ~auto:(fun () -> bitstring_of_string "\xfd\x02")
                                   Kinds.other v)
            | js ->
                Widget.bad_value "not a TCP option: %s" (Yojson.Basic.to_string js)

        (*$>*)
    end

    (** An unpacked TCP segment. The checksum will be overwritten by {!Ip.Pdu.pack}
     * if left to 0 (since it's computed over some IP fields. *)
    type t = {
        src_port : Port.t ;
        dst_port : Port.t ;
        seq_num  : SeqNum.t ;
        ack_num  : SeqNum.t ;
        win_size : int ;
        flags    : flags ;
        urg_ptr  : int ;
        options  : Opt.t list ;
        checksum : int ;
        payload  : Payload.t }

    let make ?(src_port = Port.o 1024) ?(dst_port = Port.o 80)
             ?(seq_num = SeqNum.o 0l) ?(ack_num = SeqNum.o 0l)
             ?(urg=false) ?(ack=false) ?(psh=false) ?(rst=false) ?(syn=false) ?(fin=false)
             ?(win_size=1024) ?(urg_ptr=0) ?(options=[]) ?(checksum=0)
             bits =
        { src_port ; dst_port ;
          seq_num  ; ack_num ;
          flags = { urg ; ack ; psh ; rst ; syn ; fin } ;
          win_size ; urg_ptr  ; options ; checksum ;
          payload = Payload.o bits }

    let random () =
        make ~src_port:(Port.o (randi 16)) ~dst_port:(Port.o (randi 16))
             ~seq_num:(SeqNum.o (rand32 ())) ~ack_num:(SeqNum.o (rand32 ()))
             ~urg:(randb ()) ~ack:(randb ()) ~psh:(randb ()) ~rst:(randb ()) ~syn:(randb ()) ~fin:(randb ())
             ~win_size:(randi 16) ~urg_ptr:(if randb () then randi 16 else 0)
             ~options:(Opt.random ())
             (randbs 64)

    let make_reset_of pdu =
        make ~src_port:pdu.dst_port ~dst_port:pdu.src_port
             ~seq_num:pdu.ack_num ~ack_num:(SeqNum.o (Int32.succ (pdu.seq_num:>int32)))
             ~ack:true ~rst:true empty_bitstring

    let pack t =
        let options = Opt.pack t.options in
        if bytelength options > Opt.max_len then
            invalid_arg "Tcp.Pdu.pack: more than 40 bytes of options" ;
        let hdr_len = no_opt_hdr_len + bytelength options in
        let%bitstring hdr = {|
            (t.src_port :> int) : 16 ; (t.dst_port :> int) : 16 ;
            (t.seq_num :> int32)  : 32 ; (t.ack_num :> int32)  : 32 ;
            hdr_len lsr 2 : 4 ; 0 : 6 ;
            t.flags.urg : 1 ; t.flags.ack : 1 ; t.flags.psh : 1 ;
            t.flags.rst : 1 ; t.flags.syn : 1 ; t.flags.fin : 1 ;
            t.win_size : 16 ; t.checksum : 16 ;
            t.urg_ptr  : 16 ; options : -1 : bitstring |} in
        concat [ hdr ; (t.payload :> bitstring) ]

    let unpack bits = match%bitstring bits with
        | {| src_port : 16 ; dst_port : 16 ;
             seq_num  : 32 ; ack_num  : 32 ;
             hdr_len  : 4  ; 0 : 6 ;
             urg : 1 ; ack : 1 ; psh : 1 ; rst : 1 ; syn : 1 ; fin : 1 ;
             win_size : 16 ; checksum : 16 ; urg_ptr  : 16 ;
             options : ((hdr_len lsl 2) - no_opt_hdr_len) * 8 : bitstring ;
             payload  : -1 : bitstring |} ->
            Ok { src_port = Port.o src_port ; dst_port = Port.o dst_port ;
                 seq_num  = SeqNum.o seq_num  ; ack_num  = SeqNum.o ack_num ;
                 flags = { urg ; ack ; psh ; rst ; syn ; fin } ;
                 win_size ; urg_ptr  ; options = Opt.unpack options ;
                 checksum ; payload = Payload.o payload }
        | {| _ |} -> Error (lazy "Not TCP")

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)

    let has_payload t =
        Payload.length t.payload = 0

    (** The six flags, as the choices of a set: which of them are raised is
     * what a segment says, and any of them may be. Numbered by their places,
     * having no numbers of their own -- each is a bit of the header, and a bit
     * is not a value. *)
    let flag_choices =
        Widget.choices [| "Urg" ; "Ack" ; "Psh" ; "Rst" ; "Syn" ; "Fin" |]

    (** What a segment holds, for the interface to show and, later, to edit.
     *
     * No checksum: it is normally computed over fields of the IP header below
     * (see [Ip.Pdu.pack]), so there is nothing here to show.  The options are
     * those of [Opt.Kinds.opt]. *)
    module Kinds =
    struct
        open SimTypes
        let port = IRange (0, 0xffff)
        let seq_num = IRange (0, 0xffff_ffff)
        let flags = Set flag_choices
        let win_size = IRange (0, 0xffff)
        let urg_ptr = IRange (0, 0xffff)
        let options = Widget.list Opt.Kinds.opt
        let payload = BRange (0, 0xffff)
    end

    let kind =
        Widget.record
            [| "source port", Kinds.port ;
               "destination port", Kinds.port ;
               "sequence number", Kinds.seq_num ;
               "acknowledgment number", Kinds.seq_num ;
               "flags", Kinds.flags ;
               "window size", Kinds.win_size ;
               "urgent pointer", Kinds.urg_ptr ;
               "options", Kinds.options ;
               "payload", Kinds.payload |]

    let to_json (t : t) =
        let raised =
            [ t.flags.urg ; t.flags.ack ; t.flags.psh ;
              t.flags.rst ; t.flags.syn ; t.flags.fin ] |>
            List.filteri_map (fun i up -> if up then Some (`Int i) else None) in
        `Assoc [ "source port", `Int (t.src_port :> int) ;
                 "destination port", `Int (t.dst_port :> int) ;
                 "sequence number", `Int (uint32 (t.seq_num :> int32)) ;
                 "acknowledgment number", `Int (uint32 (t.ack_num :> int32)) ;
                 "flags", `List raised ;
                 "window size", `Int t.win_size ;
                 "urgent pointer", `Int t.urg_ptr ;
                 "options", `List (List.map Opt.to_json t.options) ;
                 "payload", Widget.json_of_bytes (t.payload :> bitstring) ]

    (* Where each field is in [kind], which [of_synth] reads them by: *)
    module Field =
    struct
        let i = Widget.field_index kind
        let src_port = i "source port"
        let dst_port = i "destination port"
        let seq_num = i "sequence number"
        let ack_num = i "acknowledgment number"
        let flags = i "flags"
        let win_size = i "window size"
        let urg_ptr = i "urgent pointer"
        let options = i "options"
        let payload = i "payload"
    end

    (* [r] are the fields of a synth of [kind] (see [Generator.fields]): *)
    let of_synth r ?upper ?prev gen_values =
        let open Generator in
        let int i ?auto kind =
            int_of_nth r i gen_values ?auto kind identity in
        let port i prev_port =
            int_of_nth r i gen_values ?auto:(mostly_same prev_port Port.random)
                       Kinds.port Port.o in
        (* An automatic value is what a segment would plausibly carry: the
         * flags of a segment carrying data, rather than any of the 64
         * combinations of them -- half of which no stack would ever send. The
         * places are those [flag_choices] names, which [raised] reads back. *)
        let flags =
            of_nth r Field.flags gen_values ~auto:(fun () -> [ 1 (* Ack *) ])
                   Kinds.flags (Widget.to_choices flag_choices) in
        let raised i = List.mem i flags in
        let seq32 (n : SeqNum.t) = uint32 (n :> int32) in
        (* Given the previous segment: the sequence number that follows it, and
         * an acknowledgment number that moves on now and then, what goes the
         * other way being unknown. *)
        let seq_num =
            int Field.seq_num Kinds.seq_num ?auto:(Option.map (fun p () ->
                let one b = if b then 1 else 0 in
                (seq32 p.seq_num + Payload.length p.payload +
                 one p.flags.syn + one p.flags.fin) land 0xffff_ffff) prev)
        and ack_num =
            int Field.ack_num Kinds.seq_num ?auto:(Option.map (fun p () ->
                let ack = seq32 p.ack_num in
                if Random.bool () then ack
                else (ack + 1000 + Random.int 2000) land 0xffff_ffff) prev) in
        (* No options when automatic, rather than random ones: *)
        let options =
            nth r Field.options (function
                | `Null -> []
                | js -> expand gen_values Kinds.options js |>
                        Widget.to_list (Opt.of_synth gen_values)) in
        let len = bytelength (Opt.pack options) in
        if len > Opt.max_len then
            Widget.bad_value "options: %d bytes, more than %d" len Opt.max_len ;
        { src_port = port Field.src_port (Option.map (fun p -> p.src_port) prev) ;
          dst_port = port Field.dst_port (Option.map (fun p -> p.dst_port) prev) ;
          seq_num = SeqNum.o (Int32.of_int seq_num) ;
          ack_num = SeqNum.o (Int32.of_int ack_num) ;
          win_size = int Field.win_size Kinds.win_size ;
          flags = { urg = raised 0 ; ack = raised 1 ; psh = raised 2 ;
                    rst = raised 3 ; syn = raised 4 ; fin = raised 5 } ;
          (* Where the urgent data ends, which is nowhere unless Urg says so: *)
          urg_ptr = int Field.urg_ptr ~auto:(fun () -> 0) Kinds.urg_ptr ;
          options ; checksum = 0 ;
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

    (*$R of_synth
      (* The ways docs/simulation.md says options are written: *)
      let synth options =
          match Generator.wrap kind (fun _ -> `Null) (to_json (make empty_bitstring)) with
          | `Assoc fields ->
              `Assoc (List.map (fun (n, v) -> n, if n = "options" then options else v) fields)
          | _ -> assert false in
      let read options =
          let t = of_synth (Generator.fields_of_synth kind (synth options)) [||] in
          `List (List.map Opt.to_json t.options) in
      let expect opts = `List (List.map Opt.to_json opts) in
      assert_equal ~printer:Yojson.Basic.to_string
          (expect Opt.[ Mss 1460 ; Nop ; Wscale 7 ; Eol empty_bitstring ])
          (read (`List [ `Assoc [ "MSS", `Assoc [ "const", `Int 1460 ] ] ;
                         `Assoc [ "NOP", `Null ] ;
                         `Assoc [ "window scale", `Null ] ;
                         `Assoc [ "EOL", `Null ] ])) ;
      assert_equal ~printer:Yojson.Basic.to_string
          (expect Opt.[ Mss 1400 ])
          (read (`Assoc [ "const", `List [ `Assoc [ "MSS", `Int 1400 ] ] ])) ;
      assert_equal ~printer:Yojson.Basic.to_string (expect []) (read `Null) ;
      assert_bool "more than 40 bytes refused"
          (try ignore (read (`List (List.init 11 (fun _ -> `Assoc [ "MSS", `Null ])))) ; false
           with Widget.Bad_value _ -> true)
    *)

    (*$Q kind
      (Q.make (fun _ -> random ())) (fun t -> \
        try Widget.check_value kind (to_json t) ; true \
        with _ -> false)
     *)

    (*$>*)
end

(** {2 Transceiver} *)

(* This TRX encode a TCP socket. Create it with the local and remote ports (so
 * after you received the initial SYN if you want to simulate a listening host). *)

module TRX =
struct
    type rcvd_pkt = int * Pdu.t (* offset * packet - we keep the whole packet so we also have the flags *)
    module Streambuf = Set.Make (
        struct
            type t = rcvd_pkt
            let compare (o1, _) (o2, _) = Int.compare o1 o2
        end)

    (* Loss recovery, and the sent_pld at which it ends: *)
    type recovery =
        | Open
        | Fast of int (* after 3 dup acks *)
        | Timeout of int (* after the retransmission timer expired *)

    (* What went on since the TRX was made: *)
    type counters = {
        mutable segs_out : int ; (* manual ones and retransmissions included *)
        mutable bytes_out : int ; (* of their payloads *)
        mutable segs_in : int ;
        mutable bytes_in : int ; (* of their payloads, duplicates included *)
        mutable bytes_acked : int ; (* of what was sent *)
        mutable bytes_received : int ; (* handed in order to the reader *)
        mutable retrans : int ; (* segments retransmitted *)
        mutable dupacks : int ; (* duplicate acks received *)
        mutable rto_expired : int ;
        mutable ooo_in : int ; (* segments with data beyond what was received in order *)
        mutable dup_in : int ; (* segments with data all already received in order *)
        mutable rtt_samples : int }

    type tcp_trx = {
        trx : trx ;
        close : unit -> unit ; (* close the trx (only once established) *)
        is_closed : unit -> bool ; (* nothing more can be written *)
        is_established : unit -> bool ;
        is_over : unit -> bool ; (* gone for good: its ports are free *)
        (* Whether a SYN with that sequence number may take its ports: *)
        may_reopen : SeqNum.t -> bool }
    type t = {
        logger : Log.t ;
        power : Simulation.power ;
        mutable tcp_trx : tcp_trx ;
        mutable src : Port.t ;
        mutable dst : Port.t ;
        mutable emit : bitstring -> unit ;
        mutable emit_busy_for : unit -> Clock.Interval.t ;
        mutable recv : bitstring -> unit ;
        mutable recv_busy_for : unit -> Clock.Interval.t ;
        rcv_mss : int ; (* the max segment size we advertise, ie. we can receive *)
        mutable snd_mss : int ; (* the max segment size we send: ours, capped by the peer's *)
        isn : SeqNum.t ; (* initial seq num *)
        mutable rcvd_isn : SeqNum.t option ;
        mutable closed : bool ;  (* set whenever the user want to close or we received a FIN *)
        mutable sent_fin : bool ;
        mutable closed_first : bool ; (* our FIN went before the peer's *)
        (* When the ports become free: at once when aborted, else once both
         * FINs went through and ours was acked, after time_wait for the side
         * that closed first: *)
        mutable over_at : Clock.Time.t option ;
        time_wait : Clock.Interval.t ;
        mutable sent_pld : int ;  (* what was already send, with syn and fin counting as 1 *)
        mutable sent_acked : int ;  (* what was acked from what we sent (must be <= sent_pld) *)
        mutable rcvd_pld : int ;  (* what was already received (sequentially), with same remark *)
        mutable rcvd_acked : int ;  (* what we have acked so far (must be <= rcvd_pld) *)
        mutable rcvd_pkts : Streambuf.t ; (* what we received but haven't given to application yet *)
        mutable to_send : bitstring list ; (* what we must send next *) (* FIXME: s/list/dequeue/ *)
        mutable to_send_len : int ; (* bytes in to_send *)
        snd_buf : int ; (* to_send makes writers wait once it has that many bytes *)
        mutable unacked_tx : Streambuf.t ; (* previous packet we sent but that were not acked yet *)
        mutable rcvd_fin : bool ; (* if we already passed the fin to the application *)
        rcv_buf : int ; (* the window we advertise and enforce (at most 0xffff without window scaling) *)
        rcv_wscale : int ; (* the shift we offer: the smallest that makes rcv_buf fit in 16 bits *)
        mutable offered_wscale : bool ; (* once a SYN of ours offered rcv_wscale *)
        mutable snd_wscale : int option ; (* the peer's shift, once its SYN offered one (RFC 7323) *)
        mutable snd_wnd : int ; (* the window the peer advertises: bytes allowed in flight *)
        mutable snd_wl1 : int ; (* rcvd offset of the segment that set snd_wnd... *)
        mutable snd_wl2 : int ; (* ...and its ack (RFC 793) *)
        mutable max_snd_wnd : int ; (* largest snd_wnd seen *)
        mutable persist_gen : int ; (* only the last armed persist timer is live *)
        mutable persist_armed : bool ;
        mutable probes : int ; (* window probes since we last sent data *)
        mutable unanswered_probes : int ; (* window probes since the peer last acked anything *)
        mutable cwnd : int ;  (* congestion window: bytes allowed in flight (sent_pld - sent_acked) *)
        initial_window : int ; (* the cwnd before any data is sent, in segments *)
        mutable ssthresh : int ; (* slow start threshold (TODO: cached per dest in a host to avoid initial overshoot) *)
        mutable ca_acked : int ; (* bytes acked toward the next cwnd increase *)
        mutable dup_acks : int ; (* consecutive duplicate acks received *)
        mutable recovery : recovery ;
        mutable rtt : (Clock.Interval.t * Clock.Interval.t) option ; (* smoothed RTT and its variation, once measured *)
        mutable rtt_probe : (int * Clock.Time.t) option ; (* sent_pld after the timed segment, and when it was sent *)
        mutable rto : Clock.Interval.t ; (* retransmission timeout *)
        min_rto_var : Clock.Interval.t ; (* lower bound of the variation term of rto *)
        max_rto : Clock.Interval.t ;
        max_timeouts : int ; (* consecutive timeouts before giving up on the cnx *)
        max_syn_timeouts : int ; (* the same while our SYN is not acked *)
        mutable rto_gen : int ; (* only the last armed timer is live *)
        mutable rto_armed : bool ;
        mutable timeouts : int ; (* consecutive expirations of the retransmission timer *)
        mutable cnx_established_cont : (tcp_trx option -> unit) option ; (* what to do once the handshake completes, or fails *)
        counters : counters ;
        sync_recv : bool (* whether what is received is handed to the reader at once rather than from the scheduler *) }

    let is_closed t () = t.closed

    let is_over t () =
        match t.over_at with
        | Some at -> Clock.Time.compare (Simulation.now t.power.sim) at >= 0
        | None -> false

    let check_over t =
        if t.over_at = None && t.sent_fin && t.rcvd_fin && t.sent_acked >= t.sent_pld then (
            let now = Simulation.now t.power.sim in
            Log.(log t.logger Debug (lazy (if t.closed_first then "Tcp: TIME_WAIT" else "Tcp: Over"))) ;
            t.over_at <- Some (if t.closed_first then Clock.Time.add now t.time_wait else now))

    (* Hands [bits] to the reader, an empty bitstring signaling the close: *)
    let deliver t bits =
        if t.sync_recv then t.recv bits
        else Simulation.asap t.power t.recv bits

    let int_of_bool x = if x then 1 else 0

    let count_out t (tcp : Pdu.t) =
        t.counters.segs_out <- t.counters.segs_out + 1 ;
        t.counters.bytes_out <- t.counters.bytes_out + Payload.length tcp.payload

    let emit_segment t tcp =
        count_out t tcp ;
        Simulation.asap t.power t.emit (Pdu.pack tcp)
    let (+/) = Int32.add and (-/) = Int32.sub
    let next_seq_num t = SeqNum.o ((Int32.of_int t.sent_pld) +/ (t.isn :> int32))
    let next_ack_num t =
        if t.rcvd_pld > 0 then
            Some (SeqNum.o ((Int32.of_int t.rcvd_pld) +/ ((Option.get t.rcvd_isn) :> int32)))
        else None

    let in_flight t = t.sent_pld - t.sent_acked

    let acked_of t tcp = Int32.to_int ((tcp.Pdu.ack_num :> int32) -/ (t.isn :> int32))

    (* Window scaling is on once the peer's SYN offered it, as we offer it in
     * every SYN but a SYN-ACK to a peer that did not. The window of a SYN is
     * never scaled. *)

    (* What the window field of our segments says: *)
    let adv_wnd ?(syn=false) t =
        match t.snd_wscale with
        | Some _ when not syn -> min 0xffff (t.rcv_buf lsr t.rcv_wscale)
        | _ -> min 0xffff t.rcv_buf

    (* The window we enforce, ie. what that field means to the peer: *)
    let rcv_wnd t =
        match t.snd_wscale with
        | Some _ -> adv_wnd t lsl t.rcv_wscale
        | None -> adv_wnd t

    (* The window the peer advertises in [tcp]: *)
    let peer_wnd t tcp =
        match t.snd_wscale with
        | Some shift when not tcp.Pdu.flags.Pdu.syn -> tcp.Pdu.win_size lsl shift
        | _ -> tcp.Pdu.win_size

    let syn_options t =
        Pdu.Opt.Mss t.rcv_mss ::
        if t.rcvd_isn = None || t.snd_wscale <> None then
            Pdu.Opt.[ Nop ; Wscale t.rcv_wscale ]
        else []

    (* The MSS assumed of a peer that advertises none (RFC 9293, for IPv4), and
     * the smallest we accept (as Linux), lest no segment carries anything: *)
    let default_snd_mss = 536
    let min_snd_mss = 88

    (* Re-emit the oldest unacked segment, with an up to date ack *)
    let retransmit_first t =
        match Streambuf.min_elt_opt t.unacked_tx with
        | None -> ()
        | Some (offset, tcp) ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Retransmitting from %d" offset))) ;
            t.rtt_probe <- None ; (* Karn's algorithm: the ack would be ambiguous *)
            let tcp = match next_ack_num t with
                | Some ack_num ->
                    t.rcvd_acked <- t.rcvd_pld ;
                    { tcp with ack_num ; win_size = adv_wnd ~syn:tcp.flags.syn t ;
                               flags = { tcp.flags with ack = true } }
                | None ->
                    tcp in
            t.counters.retrans <- t.counters.retrans + 1 ;
            emit_segment t tcp

    (* Retransmission timer (RFC 6298), with a lower bound on the variation term
     * (as Linux does) so that delayed acks do not cause spurious timeouts: *)
    let update_rtt t sample =
        let open Clock in
        let srtt, rttvar =
            match t.rtt with
            | None ->
                sample, Interval.div sample 2.
            | Some (srtt, rttvar) ->
                Interval.(add (mul srtt 0.875) (mul sample 0.125)),
                Interval.(add (mul rttvar 0.75) (mul (abs (sub srtt sample)) 0.25)) in
        t.rtt <- Some (srtt, rttvar) ;
        t.counters.rtt_samples <- t.counters.rtt_samples + 1 ;
        t.rto <- min t.max_rto (Interval.add srtt (max t.min_rto_var (Interval.mul rttvar 4.))) ;
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: RTT sample %s, srtt %s, rto %s"
            (Interval.to_string sample) (Interval.to_string srtt) (Interval.to_string t.rto))))

    let stop_rto t =
        t.rto_gen <- t.rto_gen + 1 ;
        t.rto_armed <- false

    (* Give up on the cnx, as if it was reset *)
    let abort t =
        Log.(log t.logger Debug (lazy "Tcp: Aborting the cnx")) ;
        stop_rto t ;
        t.over_at <- Some (Simulation.now t.power.sim) ;
        t.closed <- true ;
        t.sent_fin <- true ;
        t.rcvd_fin <- true ;
        t.to_send <- [] ;
        t.to_send_len <- 0 ;
        t.unacked_tx <- Streambuf.empty ;
        (* Nor is anything acked any more: *)
        t.rcvd_acked <- t.rcvd_pld

    (* Calls, once, what waits for the handshake: *)
    let establish_cnx t ok =
        match t.cnx_established_cont with
        | Some f ->
            t.cnx_established_cont <- None ;
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: handshake %s on port %d" (if ok then "complete" else "failed") (t.src :> int)))) ;
            f (if ok then Some t.tcp_trx else None)
        | None -> ()

    let rec arm_rto t =
        stop_rto t ;
        t.rto_armed <- true ;
        Simulation.delay t.power t.rto (on_rto t) t.rto_gen

    and on_rto t gen =
        if gen = t.rto_gen then (
            t.timeouts <- t.timeouts + 1 ;
            t.counters.rto_expired <- t.counters.rto_expired + 1 ;
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Retransmission timeout #%d" t.timeouts))) ;
            if t.timeouts > (if t.sent_acked = 0 then t.max_syn_timeouts else t.max_timeouts) then (
                abort t ;
                establish_cnx t false ;
                deliver t empty_bitstring (* signal the close *)
            ) else (
                (* Only the first timeout tells about the window that was in flight: *)
                if t.timeouts = 1 then t.ssthresh <- max (in_flight t / 2) (2 * t.snd_mss) ;
                t.cwnd <- t.snd_mss ;
                t.ca_acked <- 0 ;
                t.dup_acks <- 0 ;
                t.recovery <- Timeout t.sent_pld ;
                t.rto <- min t.max_rto (Clock.Interval.mul t.rto 2.) ;
                retransmit_first t ;
                arm_rto t
            )
        )

    (* TX a single segment *)
    let emit_one t ?(psh=false) ?(rst=false) ?(syn=false) ?(fin=false) bits =
        let src_port = t.src and dst_port = t.dst
        and seq_num = next_seq_num t and ack_num = next_ack_num t in
        let ack = ack_num <> None in
        if ack || psh || rst || syn || fin || bitstring_length bits > 0 then (
            let options = if syn then syn_options t else [] in
            if List.exists (function Pdu.Opt.Wscale _ -> true | _ -> false) options then
                t.offered_wscale <- true ;
            let tcp = Pdu.make ~src_port ~dst_port ~seq_num ?ack_num
                               ~win_size:(adv_wnd ~syn t) ~ack ~psh ~rst ~syn ~fin
                               ~options bits in
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Emitting a packet from %s to %s, seq %s, length %d, content '%s'" (Port.to_string src_port) (Port.to_string dst_port) (SeqNum.to_string seq_num) (bytelength bits) (string_of_bitstring bits)))) ;
            emit_segment t tcp ;
            if ack then t.rcvd_acked <- t.rcvd_pld ;
            let seq_len = bytelength bits + int_of_bool syn + int_of_bool fin in
            if seq_len > 0 then (
                t.unacked_tx <- Streambuf.add (t.sent_pld, tcp) t.unacked_tx ;
                if t.rtt_probe = None then
                    t.rtt_probe <- Some (t.sent_pld + seq_len, Simulation.now t.power.sim) ;
                if not t.rto_armed then arm_rto t
            ) ;
            t.sent_pld <- t.sent_pld + seq_len
        )

    (* Byte counting (RFC 3465), with L = 2 MSS in slow start *)
    let grow_cwnd t newly_acked =
        if t.cwnd < t.ssthresh then
            t.cwnd <- t.cwnd + min newly_acked (2 * t.snd_mss)
        else (
            t.ca_acked <- t.ca_acked + newly_acked ;
            if t.ca_acked >= t.cwnd then (
                t.ca_acked <- t.ca_acked - t.cwnd ;
                t.cwnd <- t.cwnd + t.snd_mss
            )
        ) ;
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: cwnd is now %d" t.cwnd)))

    (* Fast retransmit and fast recovery (RFC 5681 and 6582) *)
    let fast_retransmit t =
        t.ssthresh <- max (in_flight t / 2) (2 * t.snd_mss) ;
        t.cwnd <- t.ssthresh + 3 * t.snd_mss ; (* the 3 dup acks are segments that left the network *)
        t.ca_acked <- 0 ;
        t.recovery <- Fast t.sent_pld ;
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Loss detected, ssthresh is now %d" t.ssthresh))) ;
        retransmit_first t

    (* How long a lone segment's ack may wait: Linux's TCP_DELACK_MIN, well
     * within the 200ms the RTO leaves above the RTT. *)
    let tcp_delack_min = Clock.Interval.msec 40.

    let delayed_ack (t : t) =
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: I acked %d / %d received bytes" t.rcvd_acked t.rcvd_pld))) ;
        if t.rcvd_acked < t.rcvd_pld then emit_one t empty_bitstring

    (* The cnx is established (ie its behavior is driven by the rcvd and sent streambuf)
     * whenever we had the two syns, not when they are acked. The handshake
     * completes once our SYN is acked too, and before any data is delivered. *)
    let rec try_really_rx t =
        if not (Streambuf.is_empty t.rcvd_pkts) then (
            let (o, tcp) as first = Streambuf.min_elt t.rcvd_pkts in
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: First of incoming waiting pkts starts at offset %d (while I've received up to %d)" o t.rcvd_pld))) ;
            if o > t.rcvd_pld then (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp:...keep it for later")))
            ) else ( (* recv now *)
                let skip = t.rcvd_pld - o in
                if skip <= Payload.length tcp.Pdu.payload then (
                    if t.rcvd_pld = 0 then (
                        ensure tcp.Pdu.flags.Pdu.syn "Tcp: Should not happen: not a syn" ;
                        t.rcvd_pld <- 1 ;
                        (* inconditionnaly answer the SYN before the client starts writing *)
                        emit_one t ~syn:(t.sent_pld=0) empty_bitstring ;
                        if t.sent_acked > 0 then establish_cnx t true
                    ) ;
                    let pld = dropbytes skip (tcp.Pdu.payload :> bitstring) in
                    t.rcvd_pld <- t.rcvd_pld + (bytelength pld) ;
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: I have now read %d bytes" t.rcvd_pld))) ;
                    t.counters.bytes_received <- t.counters.bytes_received + bytelength pld ;
                    if bitstring_length pld > 0 then deliver t pld ;
                    if tcp.Pdu.flags.Pdu.fin && not t.rcvd_fin then (
                        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: received a FIN"))) ;
                        t.rcvd_pld <- t.rcvd_pld + 1 ;
                        t.rcvd_fin <- true ;
                        t.closed <- true ;
                        deliver t empty_bitstring (* signal the close *) (* FIXME: which is not very easy to use when the TRX is piped into another one. An Err would suit better *)
                    ) else if tcp.Pdu.flags.Pdu.rst && not t.rcvd_fin then (
                        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: received a RST"))) ;
                        (* Nothing is sent after it, not even a FIN: *)
                        abort t ;
                        deliver t empty_bitstring (* signal the close *)
                    )
                ) else (
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp:...obsolete packet")))
                ) ;
                t.rcvd_pkts <- Streambuf.remove first t.rcvd_pkts ;
                try_really_rx t
            )
        )

    and drop_unacked_tx t =
        let seqlen tcp =
            Payload.length tcp.Pdu.payload + int_of_bool tcp.Pdu.flags.Pdu.fin + int_of_bool tcp.Pdu.flags.Pdu.syn in
        if not (Streambuf.is_empty t.unacked_tx) then (
            let (offset, tcp) as first = Streambuf.min_elt t.unacked_tx in
            let next_byte = offset + seqlen tcp in
            if t.sent_acked >= next_byte then (
                t.unacked_tx <- Streambuf.remove first t.unacked_tx ;
                drop_unacked_tx t
            )
        )

    and update_snd_wnd t offset acked win =
        if offset > t.snd_wl1 || offset = t.snd_wl1 && acked >= t.snd_wl2 then (
            if win <> t.snd_wnd then
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Peer window is now %d" win))) ;
            t.snd_wnd <- win ;
            t.snd_wl1 <- offset ;
            t.snd_wl2 <- acked ;
            t.max_snd_wnd <- max t.max_snd_wnd win
        )

    and inqueue_pkt t tcp =
        let offset = Int32.to_int ((tcp.Pdu.seq_num :> int32) -/ ((Option.get t.rcvd_isn) :> int32)) in
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Got a packet with %d bytes, %spush" (Payload.length tcp.Pdu.payload) (if tcp.Pdu.flags.Pdu.psh then "" else "don't ")))) ;
        let len = Payload.length tcp.Pdu.payload in
        if tcp.Pdu.flags.Pdu.ack then (
            let acked = acked_of t tcp in
            if acked > t.sent_acked then (
                if acked > t.sent_pld then (
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Acking %d while we only sent %d bytes" acked t.sent_pld)))
                    (* FIXME: raise an error? *)
                ) else (
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Acked %d/%d" acked t.sent_pld))) ;
                    let newly_acked = acked - max 1 t.sent_acked (* the SYN does not count *) in
                    t.counters.bytes_acked <-
                        t.counters.bytes_acked + newly_acked -
                        int_of_bool (t.sent_fin && acked = t.sent_pld) ;
                    t.sent_acked <- acked ;
                    t.dup_acks <- 0 ;
                    drop_unacked_tx t ;
                    (match t.rtt_probe with
                    | Some (seq, sent) when acked >= seq ->
                        t.rtt_probe <- None ;
                        update_rtt t (Clock.Time.diff (Simulation.now t.power.sim) sent)
                    | _ -> ()) ;
                    t.timeouts <- 0 ;
                    if in_flight t = 0 then stop_rto t else arm_rto t ;
                    (* Partial acks: the next hole is lost too *)
                    match t.recovery with
                    | Open ->
                        grow_cwnd t newly_acked
                    | Fast recover when acked < recover ->
                        t.cwnd <- max t.snd_mss (t.cwnd - newly_acked + t.snd_mss) ;
                        retransmit_first t
                    | Timeout recover when acked < recover ->
                        grow_cwnd t newly_acked ;
                        retransmit_first t
                    | Fast _ ->
                        Log.(log t.logger Debug (lazy "Tcp: Recovered")) ;
                        t.recovery <- Open ;
                        t.cwnd <- min t.ssthresh (in_flight t + t.snd_mss)
                    | Timeout _ ->
                        Log.(log t.logger Debug (lazy "Tcp: Recovered")) ;
                        t.recovery <- Open
                )
            ) else if acked = t.sent_acked && len = 0 && peer_wnd t tcp = t.snd_wnd &&
                      offset >= t.rcvd_pld && (* not a window probe *)
                      not (tcp.Pdu.flags.Pdu.syn || tcp.Pdu.flags.Pdu.fin) &&
                      not (Streambuf.is_empty t.unacked_tx) then (
                t.dup_acks <- t.dup_acks + 1 ;
                t.counters.dupacks <- t.counters.dupacks + 1 ;
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Duplicate ack #%d for %d" t.dup_acks acked))) ;
                match t.recovery with
                | Open -> if t.dup_acks = 3 then fast_retransmit t
                | Fast _ -> t.cwnd <- t.cwnd + t.snd_mss (* another segment left the network *)
                | Timeout _ -> ()
            )
        ) ;
        (* Only after the ack, which must not see a window update as a dup ack: *)
        if tcp.Pdu.flags.Pdu.ack then (
            t.unanswered_probes <- 0 ;
            let acked = acked_of t tcp in
            if acked >= t.sent_acked && acked <= t.sent_pld then
                update_snd_wnd t offset acked (peer_wnd t tcp)
        ) else if tcp.Pdu.flags.Pdu.syn then
            update_snd_wnd t offset 0 (peer_wnd t tcp) ;
        if t.sent_acked > 0 && t.rcvd_pld > 0 then establish_cnx t true ;
        (* Out of order, filling a gap, or already received: *)
        let unexpected = offset <> t.rcvd_pld || not (Streambuf.is_empty t.rcvd_pkts) in
        let is_probe = len = 0 && offset < t.rcvd_pld in
        if len > 0 && offset > t.rcvd_pld then
            t.counters.ooo_in <- t.counters.ooo_in + 1 ;
        if len > 0 && offset + len <= t.rcvd_pld then
            t.counters.dup_in <- t.counters.dup_in + 1 ;
        (* With an application that reads at once, our window is all of rcv_buf,
         * out of order data included: *)
        let beyond_wnd = len > 0 && offset >= t.rcvd_pld + rcv_wnd t in
        if beyond_wnd then
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Dropping data at %d, beyond our window" offset)))
        else
            t.rcvd_pkts <- Streambuf.add (offset, tcp) t.rcvd_pkts ;
        try_really_rx t ;
        try_really_tx t ; (* because the advertized window may have changed, we might want to send a FIN, etc *)
        (* Data (or SYN/FIN) is acked at once when unexpected (so the sender sees
         * duplicate acks, or a lost ack is replaced), when more than one MSS is
         * unacked (ie. every second full segment) or on FIN, otherwise after at
         * most tcp_delack_min. A segment below what was received (a window probe) or
         * beyond our window is acked at once, for its sender to learn our window. *)
        let consumes_seq = len > 0 || tcp.Pdu.flags.Pdu.syn || tcp.Pdu.flags.Pdu.fin in
        if is_probe || beyond_wnd ||
           consumes_seq && (unexpected ||
                            t.rcvd_acked < t.rcvd_pld && tcp.Pdu.flags.Pdu.fin ||
                            t.rcvd_pld - t.rcvd_acked > t.rcv_mss) then
            emit_one t empty_bitstring
        else if t.rcvd_acked < t.rcvd_pld then
            Simulation.delay t.power tcp_delack_min delayed_ack t ;
        check_over t

    and is_established t = t.sent_pld > 0 && t.rcvd_pld > 0

    and rx (t : t) bits = (match Pdu.unpack bits with (* If rx were receiving unpacked PDUs then we could bind unpack to rx *)
        | Error s ->
            Log.(log t.logger Warning s)
        | Ok tcp ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Received a segment!"))) ;
            t.counters.segs_in <- t.counters.segs_in + 1 ;
            t.counters.bytes_in <- t.counters.bytes_in + Payload.length tcp.Pdu.payload ;
            (* TODO: check checksum *)
            if tcp.Pdu.flags.Pdu.syn then (
                if t.rcvd_pld > 0 then (
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: ignoring Syn while inbound cnx is established"))) ;
                    if t.rcvd_isn = Some tcp.Pdu.seq_num then (
                        (* retransmission of the syn: our SYN-ACK may have been lost *)
                        if t.sent_acked = 0 then retransmit_first t
                        else inqueue_pkt t tcp
                    )
                ) else (
                    t.rcvd_isn <- Some tcp.Pdu.seq_num ;
                    t.snd_wscale <-
                        List.fold_left (fun found -> function
                            | Pdu.Opt.Wscale shift -> Some (min shift 14) (* RFC 7323 *)
                            | _ -> found) None tcp.Pdu.options ;
                    Log.(log t.logger Debug (lazy (match t.snd_wscale with
                        | Some shift -> Printf.sprintf "Tcp: Window scaling, peer's shift %d, ours %d" shift t.rcv_wscale
                        | None -> "Tcp: No window scaling"))) ;
                    let peer_mss =
                        List.fold_left (fun found -> function
                            | Pdu.Opt.Mss mss -> mss
                            | _ -> found) default_snd_mss tcp.Pdu.options in
                    t.snd_mss <- min t.rcv_mss (max min_snd_mss peer_mss) ;
                    t.cwnd <- t.initial_window * t.snd_mss ; (* no data was sent yet *)
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: peer's MSS %d, sending segments up to %d" peer_mss t.snd_mss))) ;
                    inqueue_pkt t tcp
                )
            ) else if tcp.Pdu.flags.Pdu.rst && t.rcvd_pld = 0 then (
                (* A reset of our SYN refuses the connection (RFC 793): *)
                if tcp.Pdu.flags.Pdu.ack && t.sent_pld > 0 && acked_of t tcp = t.sent_pld then (
                    Log.(log t.logger Debug (lazy "Tcp: connection refused")) ;
                    abort t ;
                    establish_cnx t false)
            ) else if not (is_established t) then (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: ignoring recvd packet while cnx is not established")))
            ) else inqueue_pkt t tcp)

    (* Persist timer: with nothing in flight, no ack would tell that the peer's
     * window reopened, so we ask, backing off up to max_rto. *)
    and arm_persist t =
        t.persist_armed <- true ;
        let rec backoff d n =
            if n = 0 || d >= t.max_rto then min d t.max_rto
            else backoff (Clock.Interval.mul d 2.) (n - 1) in
        Simulation.delay t.power (backoff t.rto t.probes) (on_persist t) t.persist_gen

    and stop_persist t =
        t.persist_gen <- t.persist_gen + 1 ;
        t.persist_armed <- false ;
        t.probes <- 0

    and on_persist t gen =
        if gen = t.persist_gen then (
            t.persist_armed <- false ;
            if t.to_send <> [] && in_flight t = 0 then (
                if t.snd_wnd > 0 then (
                    (* Open, but too small for SWS avoidance: send what fits *)
                    tx_queued t true
                ) else if t.unanswered_probes >= t.max_timeouts then (
                    abort t ;
                    deliver t empty_bitstring (* signal the close *)
                ) else (
                    send_probe t ;
                    t.probes <- t.probes + 1 ;
                    t.unanswered_probes <- t.unanswered_probes + 1 ;
                    arm_persist t
                )
            )
        )

    (* As Linux does, an empty segment one byte below what was sent, which the
     * peer must ack, rather than one byte beyond its window: *)
    and send_probe t =
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Window probe #%d" (t.probes + 1)))) ;
        let seq_num = SeqNum.o ((Int32.of_int (t.sent_pld - 1)) +/ (t.isn :> int32))
        and ack_num = next_ack_num t in
        if ack_num <> None then t.rcvd_acked <- t.rcvd_pld ;
        let tcp = Pdu.make ~src_port:t.src ~dst_port:t.dst ~seq_num ?ack_num
                           ~ack:(ack_num <> None) ~win_size:(adv_wnd t) empty_bitstring in
        emit_segment t tcp

    and try_really_tx t = tx_queued t false

    (* Data is sent one segment at a time, only while the whole segment fits in cwnd.
     * Each ack calls back here to send what cwnd now allows.
     * Limited Transmit (RFC 3042): each of the first two dup acks allows one more
     * segment, so that small windows still get the 3 dup acks of a fast retransmit.
     * The peer's window is never exceeded, but a segment is cut down to fit it
     * if that sends at least half the largest window seen (RFC 1122 SWS avoidance),
     * or if [force]d to.
     * With nothing in flight, only the peer's window can hold data back, and
     * then the persist timer is armed. *)
    and tx_queued t force = match t.to_send with
        | bits :: to_send' ->
            let bits_len = bytelength bits in
            let rwnd_room = t.snd_wnd - in_flight t in
            let len =
                let len = min bits_len t.snd_mss in
                if len <= rwnd_room then len
                else if rwnd_room > 0 && (force || 2 * rwnd_room >= t.max_snd_wnd) then rwnd_room
                else 0 in
            let wnd =
                if t.recovery = Open then t.cwnd + min t.dup_acks 2 * t.snd_mss
                else t.cwnd in
            if len > 0 && in_flight t + len <= wnd then (
                let is_last = len = bits_len in
                stop_persist t ;
                emit_one t ~psh:is_last (takebytes len bits) ;
                t.to_send <- if is_last then to_send' else dropbytes len bits :: to_send' ;
                t.to_send_len <- t.to_send_len - len ;
                try_really_tx t
            ) else (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: window full (%d in flight, cwnd %d, peer window %d)" (in_flight t) wnd t.snd_wnd))) ;
                if in_flight t = 0 && not t.persist_armed then arm_persist t
            )
        | [] ->
            if t.closed && not t.sent_fin then (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: sending FIN"))) ;
                t.sent_fin <- true ;
                t.closed_first <- not t.rcvd_fin ;
                emit_one t ~fin:true empty_bitstring (* TODO: pack the FIN into the last payload? *)
            ) else ( (* maybe we should ack something ? *)
            )

    and close t () =
        ensure (is_established t) "Tcp: Closing a cnx that's not established" ;
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Will close the cnx"))) ;
        t.closed <- true ;
        try_really_tx t

    and tx t bits =
        (* TODO (in try_really_tx): Nagle algorithm: keep the data to send in a buffer
         * if it's smaller than a segment and we have sent unacked data *)
        if t.closed then (
            Printf.fprintf stderr "Tcp: writing to a closed TRX!"
        ) else if not (is_established t) then (
            Printf.fprintf stderr "Tcp: writing to a non-established TRX!"
        ) else (
            t.to_send <- t.to_send @ [ bits ] ;
            t.to_send_len <- t.to_send_len + bytelength bits ;
            try_really_tx t
        )

    (* A full send buffer drains as acks come back, so in about an RTT; and
     * what does leave it then waits for what is below. *)
    let busy_for t () =
        let own =
            if t.to_send_len < t.snd_buf then Clock.Interval.zero
            else match t.rtt with Some (srtt, _) -> srtt | None -> t.rto in
        max own (t.emit_busy_for ())

    (* In TIME_WAIT, a SYN beyond what was received is from a new connection
     * (RFC 6191): *)
    let may_reopen t seq =
        is_over t () ||
        t.over_at <> None &&
        match next_ack_num t with
        | Some nxt -> Int32.compare ((seq : SeqNum.t :> int32) -/ (nxt :> int32)) 0l > 0
        | None -> false

    let default_snd_buf = 65536
    (* The maximum of Linux's tcp_rmem: *)
    let default_rcv_buf = 6 * 1024 * 1024
    (* What the largest window scaling allows to advertise: *)
    let max_rcv_buf = 0xffff lsl 14

    (* Retransmission defaults are those of Linux, as are the initial window
     * (RFC 6928) and TIME_WAIT: *)
    let default_time_wait = Clock.Interval.sec 60.

    (* With [sync_recv], what is received in order is handed to the reader
     * while the segment that completes it is being received. *)
    let make power ?(sync_recv=false) ?isn ?(mss=536) ?(ssthresh=max_int) ?(initial_window=10) ?(snd_buf=default_snd_buf) ?(rcv_buf=default_rcv_buf)
             ?(initial_rto=Clock.Interval.sec 1.) ?(min_rto_var=Clock.Interval.msec 200.)
             ?(max_rto=Clock.Interval.sec 120.) ?(max_timeouts=15) ?(max_syn_timeouts=5)
             ?(time_wait=default_time_wait)
             src dst logger =
        let t = { logger ; power ;
                  src = src ;
                  dst = dst ;
                  emit = ignore_bits ~logger ;
                  emit_busy_for = never_busy ;
                  recv = ignore_bits ~logger ;
                  recv_busy_for = never_busy ;
                  rcv_mss = mss ; snd_mss = mss ; cwnd = initial_window * mss ; initial_window ; ssthresh ; ca_acked = 0 ; dup_acks = 0 ; recovery = Open ;
                  rtt = None ; rtt_probe = None ; rto = initial_rto ; rto_gen = 0 ;
                  min_rto_var ; max_rto ; max_timeouts ; max_syn_timeouts ;
                  rto_armed = false ; timeouts = 0 ;
                  isn = may_default isn (fun () -> SeqNum.o (rand32 ())) ;
                  rcvd_isn = None ;
                  closed = false ; sent_fin = false ; closed_first = false ;
                  over_at = None ; time_wait ;
                  sent_pld = 0 ; sent_acked = 0 ; rcvd_pld = 0 ; rcvd_acked = 0 ;
                  rcvd_pkts = Streambuf.empty ;
                  to_send = [] ; to_send_len = 0 ; snd_buf ;
                  unacked_tx = Streambuf.empty ;
                  rcvd_fin = false ;
                  rcv_buf ; snd_wscale = None ; offered_wscale = false ;
                  rcv_wscale = (let rec shift s =
                                    if s >= 14 || rcv_buf lsr s <= 0xffff then s
                                    else shift (s + 1) in
                                shift 0) ;
                  snd_wnd = 0 ; snd_wl1 = -1 ; snd_wl2 = 0 ; max_snd_wnd = 0 ;
                  persist_gen = 0 ; persist_armed = false ; probes = 0 ; unanswered_probes = 0 ;
                  cnx_established_cont = None ; sync_recv ;
                  counters = { segs_out = 0 ; bytes_out = 0 ; segs_in = 0 ; bytes_in = 0 ;
                               bytes_acked = 0 ; bytes_received = 0 ;
                               retrans = 0 ; dupacks = 0 ; rto_expired = 0 ; ooo_in = 0 ; dup_in = 0 ;
                               rtt_samples = 0 } ;
                  tcp_trx = { trx = null_trx ~logger ;
                              close = ignore ;
                              is_closed = (fun _ -> true) ;
                              is_established = (fun _ -> false) ;
                              is_over = (fun _ -> true) ;
                              may_reopen = (fun _ -> true) } } in
        t.tcp_trx <- { trx =  { ins = { write = tx t ;
                                        busy_for = busy_for t ;
                                        set_read = fun f busy_for ->
                                            t.recv <- f ;
                                            t.recv_busy_for <- busy_for } ;
                                out = { write = rx t ;
                                        busy_for = (fun () -> t.recv_busy_for ()) ;
                                        set_read = fun f busy_for ->
                                            t.emit <- f ;
                                            t.emit_busy_for <- busy_for } } ;
                       close = close t ;
                       is_closed = is_closed t ;
                       is_established = (fun () -> is_established t) ;
                       is_over = is_over t ;
                       may_reopen = may_reopen t } ;
        t

    let may_timeout t =
        if not (is_established t) then (
            establish_cnx t false ;
            abort t
        )
    let default_connect_timeout = Clock.Interval.sec 15.
    let connect ?(timeout=default_connect_timeout) t cont =
        t.cnx_established_cont <- Some cont ;
        Simulation.delay t.power timeout may_timeout t ;
        emit_one t ~syn:true empty_bitstring

    (* Accounts for [tcp], a segment emitted beside [t] at its [next_seq_num],
     * so that what [t] emits next follows it: its payload, SYN and FIN advance
     * the sequence numbers, a FIN closes the stream and a RST aborts it. Not
     * being retransmitted, such a segment that is lost stalls the stream. *)
    let sent_manually t (tcp : Pdu.t) =
        count_out t tcp ;
        if tcp.flags.ack && Some tcp.ack_num = next_ack_num t then
            t.rcvd_acked <- t.rcvd_pld ;
        t.sent_pld <- t.sent_pld + Payload.length tcp.payload +
                      int_of_bool tcp.flags.syn + int_of_bool tcp.flags.fin ;
        if tcp.flags.rst then abort t
        else if tcp.flags.fin then (
            t.closed <- true ;
            t.closed_first <- not t.rcvd_fin ;
            t.sent_fin <- true
        )

end

(*$< TRX *)
(*$R make
    (* [a] sends [size] bytes to [b], which advertises [rcv_buf] in segments
     * that [b_to_a] may then rewrite or drop, as [a_to_b] may those going the
     * other way, over 10ms of latency each way (without which the RTO would
     * be no longer than a delayed ack). Returns [a], the most that was
     * in flight, the bytes received, the window probes sent and how far beyond
     * what it received [b] ever held data; [b] is left in [last_b]. *)
    let last_b = ref None in
    let transfer ?rcv_buf ?(mss=100) ?b_mss ?max_timeouts ?(a_to_b=fun p -> Some p)
                 ?(b_to_a=fun _ p -> Some p) size =
        let sim = Simulation.make ~realtime:false "peer-window" in
        let power = sim.root.power and logger = Log.make () in
        let a = make power ~mss ?max_timeouts (Port.o 1) (Port.o 2) logger
        and b = make power ~mss:(b_mss |? mss) ?rcv_buf (Port.o 2) (Port.o 1) logger in
        last_b := Some b ;
        let max_in_flight = ref 0 and rcvd = ref 0 and probes = ref 0 and ahead = ref 0 in
        let later f = Simulation.delay power (Clock.Interval.msec 10.) f () in
        a.tcp_trx.trx.out --> sink (fun bits ->
            max_in_flight := max !max_in_flight (in_flight a) ;
            let p = Result.get_ok (Pdu.unpack bits) in
            if Payload.length p.Pdu.payload = 0 && not p.Pdu.flags.Pdu.syn &&
               (p.Pdu.seq_num :> int32) = Int32.pred (next_seq_num a :> int32) then
                incr probes ;
            later (fun () ->
                Option.may (fun p -> b.tcp_trx.trx.out.write (Pdu.pack p)) (a_to_b p) ;
                Streambuf.iter (fun (o, p) ->
                    ahead := max !ahead (o + Payload.length p.Pdu.payload - b.rcvd_pld)
                ) b.rcvd_pkts)) ;
        b.tcp_trx.trx.out --> sink (fun bits ->
            let p = b_to_a (Simulation.now sim) (Result.get_ok (Pdu.unpack bits)) in
            later (fun () -> Option.may (fun p -> a.tcp_trx.trx.out.write (Pdu.pack p)) p)) ;
        b.tcp_trx.trx.ins --> sink (fun bits -> rcvd := !rcvd + bytelength bits) ;
        connect a (fun _ -> a.tcp_trx.trx.ins.write (zeroes_bitstring (8 * size))) ;
        Simulation.run sim false ;
        a, !max_in_flight, !rcvd, !probes, !ahead in
    let a, m, rcvd, _, _ = transfer 1000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 1000 rcvd ;
    assert_equal ~printer:string_of_int ~msg:"all in the initial window" 1000 m ;
    assert_equal ~printer:string_of_int ~msg:"default window, scaled" (6 * 1024 * 1024) a.snd_wnd ;
    assert_equal ~msg:"peer's shift" (Some 7) a.snd_wscale ;
    assert_bool "offered by both" (a.offered_wscale && (Option.get !last_b).offered_wscale) ;
    let _, m, rcvd, _, _ = transfer ~mss:1000 500_000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 500_000 rcvd ;
    assert_bool "more than 64KiB in flight" (m > 0xffff) ;
    (* A peer that knows nothing of window scaling: *)
    let a_to_b p = Some { p with Pdu.options = [] } in
    let a, m, rcvd, _, _ = transfer ~mss:1000 ~a_to_b 500_000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 500_000 rcvd ;
    assert_equal ~msg:"no shift" None a.snd_wscale ;
    assert_bool "offered by the opener only" (a.offered_wscale && not (Option.get !last_b).offered_wscale) ;
    assert_equal ~printer:string_of_int ~msg:"unscaled window" 0xffff a.snd_wnd ;
    assert_bool "at most 64KiB in flight" (m <= 0xffff) ;
    (* Segments are sized for the smaller MSS, or 536 if the peer gives none: *)
    let largest = ref 0 in
    let a_to_b p = largest := max !largest (Payload.length p.Pdu.payload) ; Some p in
    let _, _, rcvd, _, _ = transfer ~mss:1000 ~b_mss:300 ~a_to_b 5000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 5000 rcvd ;
    assert_equal ~printer:string_of_int ~msg:"peer's MSS" 300 !largest ;
    largest := 0 ;
    let _, _, rcvd, _, _ = transfer ~mss:300 ~b_mss:1000 ~a_to_b 5000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 5000 rcvd ;
    assert_equal ~printer:string_of_int ~msg:"our MSS" 300 !largest ;
    largest := 0 ;
    let b_to_a _ p = Some { p with Pdu.options = [] } in
    let _, _, rcvd, _, _ = transfer ~mss:1000 ~a_to_b ~b_to_a 5000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 5000 rcvd ;
    assert_equal ~printer:string_of_int ~msg:"default MSS" 536 !largest ;
    let _, m, rcvd, _, _ = transfer ~rcv_buf:250 2000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 2000 rcvd ;
    assert_bool "whole segments within the window" (m = 200) ;
    let _, m, rcvd, _, _ = transfer ~rcv_buf:60 2000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 2000 rcvd ;
    assert_bool "segments cut down to a window below the MSS" (m = 60) ;
    (* A window closed until 5s: *)
    let b_to_a now p =
        let opened = now >= Clock.Time.of_secs 5. in
        Some { p with Pdu.win_size = if opened then 0xffff else 0 } in
    let _, _, rcvd, probes, _ = transfer ~b_to_a 2000 in
    assert_equal ~printer:string_of_int ~msg:"all received once reopened" 2000 rcvd ;
    assert_bool "probed, backing off" (probes >= 3 && probes <= 6) ;
    (* A window too small for SWS avoidance to ever use: *)
    let b_to_a _ p =
        Some { p with Pdu.win_size = if p.Pdu.flags.Pdu.syn then 1000 else 100 } in
    let _, _, rcvd, _, _ = transfer ~mss:200 ~rcv_buf:0xffff ~b_to_a 2000 in
    assert_equal ~printer:string_of_int ~msg:"all received in small segments" 2000 rcvd ;
    (* A closed window, and a peer that answers no probe: *)
    let b_to_a _ p =
        if p.Pdu.flags.Pdu.syn then Some { p with Pdu.win_size = 0 } else None in
    let a, _, rcvd, probes, _ = transfer ~max_timeouts:3 ~b_to_a 2000 in
    assert_equal ~printer:string_of_int ~msg:"nothing received" 0 rcvd ;
    assert_equal ~printer:string_of_int ~msg:"probes before giving up" 3 probes ;
    assert_bool "gave up" a.closed ;
    (* A sender told a larger window than [b] enforces: *)
    let b_to_a _ p = Some { p with Pdu.win_size = 0xffff } in
    let _, _, rcvd, _, ahead = transfer ~rcv_buf:300 ~b_to_a 3000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 3000 rcvd ;
    assert_bool "nothing held beyond the window" (ahead <= 300) ;
    (* Acks lost for 1s, so that [a] resends what [b] has: *)
    let b_to_a now p =
        if p.Pdu.flags.Pdu.syn || now >= Clock.Time.of_secs 1. then Some p else None in
    let a, _, rcvd, _, _ = transfer ~b_to_a 2000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 2000 rcvd ;
    assert_bool "resent" (a.counters.retrans > 0) ;
    let b = Option.get !last_b in
    assert_bool "duplicates received" (b.counters.dup_in > 0) ;
    assert_bool "no more duplicates than resent" (b.counters.dup_in <= a.counters.retrans)
*)
(*$R sent_manually
    (* [a] connects to [b], over 10ms each way, then runs [steps] 1ms apart.
     * Each step is given [a] and a function to emit a segment to [b] beside
     * [a]. Returns [a], [b], what [b] received and whether it saw the end of
     * the stream. *)
    let exchange ?isn steps =
        let sim = Simulation.make ~realtime:false "manual" in
        let power = sim.root.power and logger = Log.make () in
        let a = make power ?isn (Port.o 1) (Port.o 2) logger
        and b = make power (Port.o 2) (Port.o 1) logger in
        let later f x = Simulation.delay power (Clock.Interval.msec 10.) f x in
        let to_b = later b.tcp_trx.trx.out.write
        and to_a = later a.tcp_trx.trx.out.write in
        a.tcp_trx.trx.out --> sink to_b ;
        b.tcp_trx.trx.out --> sink to_a ;
        let rcvd = ref "" and eof = ref false in
        b.tcp_trx.trx.ins --> sink (fun bits ->
            if bitstring_is_empty bits then eof := true
            else rcvd := !rcvd ^ string_of_bitstring bits) ;
        connect a (fun _ ->
            List.iteri (fun i step ->
                Simulation.delay power (Clock.Interval.msec (float_of_int (i + 1)))
                    (fun () -> step a (fun tcp -> to_b (Pdu.pack tcp))) ()
            ) steps) ;
        Simulation.run sim false ;
        a, b, !rcvd, !eof in
    let write str a _ = a.tcp_trx.trx.ins.write (bitstring_of_string str) in
    let manual ?(rst=false) ?(fin=false) str a emit =
        let ack_num = next_ack_num a in
        let tcp = Pdu.make ~src_port:a.src ~dst_port:a.dst ~seq_num:(next_seq_num a) ?ack_num
                           ~ack:(ack_num <> None) ~psh:(str <> "") ~rst ~fin
                           (bitstring_of_string str) in
        emit tcp ;
        sent_manually a tcp in
    let _, _, rcvd, eof = exchange [ write "hello " ; manual "manual " ; write "world" ] in
    assert_equal ~printer:identity "hello manual world" rcvd ;
    assert_bool "still open" (not eof) ;
    let a, _, rcvd, eof = exchange [ write "bye" ; manual ~fin:true "" ] in
    assert_equal ~printer:identity "bye" rcvd ;
    assert_bool "FIN received" eof ;
    assert_bool "closed by the FIN" (a.closed && a.sent_fin) ;
    assert_equal ~printer:string_of_int ~msg:"FIN acked" a.sent_pld a.sent_acked ;
    let a, b, rcvd, eof = exchange [ write "hello" ; manual ~rst:true "" ] in
    assert_equal ~printer:identity "hello" rcvd ;
    assert_bool "RST received" eof ;
    assert_bool "aborted by the RST" (a.closed && not a.rto_armed) ;
    assert_bool "the peer aborted, with no FIN to send" (b.closed && b.sent_fin) ;
    (* Sequence numbers wrap around: *)
    let _, _, rcvd, _ =
        exchange ~isn:(SeqNum.o 0xFFFFFFF8l) [ write "hello " ; manual "manual " ; write "world" ] in
    assert_equal ~printer:identity "hello manual world" rcvd
*)
(* The passive side is handed the connection when the handshake completes,
 * answers a retransmitted SYN with its SYN-ACK, and gives up after
 * max_syn_timeouts timeouts: *)
(*$R connect
    let handshake ~synack_lost =
        let sim = Simulation.make ~realtime:false "handshake" in
        let power = sim.root.power and logger = Log.make () in
        let a = make power (Port.o 1) (Port.o 2) logger
        and b = make power (Port.o 2) (Port.o 1) logger in
        let later f x = Simulation.delay power (Clock.Interval.msec 10.) f x in
        let all_synacks = ref true in
        a.tcp_trx.trx.out --> sink (later b.tcp_trx.trx.out.write) ;
        b.tcp_trx.trx.out --> sink (fun bits ->
            (match Pdu.unpack bits with
            | Ok tcp -> if not tcp.flags.syn then all_synacks := false
            | Error _ -> ()) ;
            if not synack_lost then later a.tcp_trx.trx.out.write bits) ;
        let outcome cnx = Option.is_some cnx, Simulation.now sim in
        let a_ok = ref None and b_ok = ref None in
        b.cnx_established_cont <- Some (fun c -> b_ok := Some (outcome c)) ;
        connect a (fun c -> a_ok := Some (outcome c)) ;
        Simulation.run sim false ;
        b, !all_synacks, Option.get !a_ok, Option.get !b_ok in
    let _, _, (a_ok, a_at), (b_ok, b_at) = handshake ~synack_lost:false in
    assert_bool "established" (a_ok && b_ok) ;
    assert_bool "on the final ACK, one trip after the SYN-ACK"
        (Clock.Interval.compare (Clock.Time.diff b_at a_at) (Clock.Interval.msec 10.) >= 0) ;
    let b, all_synacks, (a_ok, _), (b_ok, b_at) = handshake ~synack_lost:true in
    assert_bool "failed" (not a_ok && not b_ok) ;
    assert_bool "only SYN-ACKs" all_synacks ;
    (* 1+2+4+8+16+32 seconds: *)
    assert_bool "gave up after 63s"
        (Clock.Time.(compare b_at (of_secs 63.) > 0 && compare b_at (of_secs 64.) < 0)) ;
    assert_bool "over" (b.tcp_trx.is_over ())
*)
(* The side that closes first waits in TIME_WAIT, where only a SYN beyond what
 * it received may reopen its ports: *)
(*$R may_reopen
    let sim = Simulation.make ~realtime:false "time-wait" in
    let power = sim.root.power and logger = Log.make () in
    let a = make power (Port.o 1) (Port.o 2) logger
    and b = make power (Port.o 2) (Port.o 1) logger in
    let later f x = Simulation.delay power (Clock.Interval.msec 10.) f x in
    a.tcp_trx.trx.out --> sink (later b.tcp_trx.trx.out.write) ;
    b.tcp_trx.trx.out --> sink (later a.tcp_trx.trx.out.write) ;
    connect a (fun _ -> a.tcp_trx.close ()) ;
    Simulation.run sim false ;
    assert_bool "the last to close is over" (b.tcp_trx.is_over ()) ;
    assert_bool "the first to close is not" (not (a.tcp_trx.is_over ())) ;
    let nxt = Option.get (next_ack_num a) in
    assert_bool "an old SYN may not reopen" (not (may_reopen a (Option.get a.rcvd_isn))) ;
    assert_bool "nor one at what is expected" (not (may_reopen a nxt)) ;
    assert_bool "a newer SYN may" (may_reopen a (SeqNum.o ((nxt :> int32) +/ 1l))) ;
    Simulation.delay power default_time_wait ignore () ;
    Simulation.run sim false ;
    assert_bool "over after TIME_WAIT" (a.tcp_trx.is_over ())
*)
(*$= make & ~printer:string_of_bool
    false (let sim = Simulation.make ~realtime:false "isn" in \
           let mk () = make sim.root.power (Port.o 1) (Port.o 2) (Log.make ()) in \
           (mk ()).isn = (mk ()).isn)
*)
(* A reset of the SYN refuses the connection, which is then neither retried
 * nor timed out: *)
(*$R connect
    let sim = Simulation.make ~realtime:false "refused" in
    let a = make sim.root.power (Port.o 1) (Port.o 2) (Log.make ()) in
    let syns = ref 0 and conts = ref [] in
    a.tcp_trx.trx.out --> sink (fun bits ->
        match Pdu.unpack bits with
        | Ok tcp when tcp.flags.syn ->
            incr syns ;
            Simulation.asap sim.root.power a.tcp_trx.trx.out.write
                (Pdu.pack (Pdu.make_reset_of tcp))
        | _ -> ()) ;
    connect a (fun r -> conts := Option.is_some r :: !conts) ;
    Simulation.run sim false ;
    assert_equal ~printer:string_of_int ~msg:"SYNs" 1 !syns ;
    assert_equal ~printer:(IO.to_string (List.print Bool.print)) [ false ] !conts ;
    assert_bool "closed" a.closed
*)
(*$>*)
