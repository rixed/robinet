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
(** Domain Name System *)
open Batteries
open Bitstring
open Tools

let debug = false

(** {2 Opcodes, query types and classes} *)

let std_query = 0
let inv_query = 1
let srv_status_request = 2

module QType = struct
    include Private.Make (struct
        type t = int
        let to_string = function
            |  1 -> "A"
            |  2 -> "NS"
            |  5 -> "CNAME"
            | 12 -> "PTR"
            | 13 -> "HINFO"
            | 15 -> "MX"
            | 28 -> "AAAA"
            |  x -> string_of_int x
        let is_valid t = t < 0x10000
        let repl_tag = "code"
    end)
    let a     = o 1
    let ns    = o 2
    let cname = o 5
    let ptr   = o 12
    let hinfo = o 13
    let mx    = o 15
    let aaaa  = o 28

    let random () = randi 16

    (** The record types this module has a name for, as the choices of a kind
     * (see [Widget.one_of]), labelled by [to_string]. There are many more. *)
    let choices =
        [| a ; ns ; cname ; ptr ; hinfo ; mx ; aaaa |] |>
        Array.map (fun (q : t) -> (q :> int), to_string q)
end

let qclass_inet = 1

(** {2 DNS messages} *)

module Pdu =
struct
    (*$< Pdu *)
    type question = string * QType.t * int

    (* A name as it travels: a run of labels, the last of them the empty root
     * label, which is what the trailing dot writes. So "www.example.com." is
     * one and "." is the root itself.
     *
     * Everything that builds a message normalises what it is given (see
     * [fqdn]), since a caller resolving "www.example.com" means the name and
     * not a malformed one; what is refused is what no normalising would save
     * -- an empty label in the middle, or one longer than the 63 bytes its
     * length is written in. *)
    let label_is_valid l = String.length l > 0 && String.length l <= 63

    let name_is_valid name =
        (* The root is the one name that is nothing but that last label. *)
        name = "." ||
        (match List.rev (String.split_on_char '.' name) with
        | "" :: labels -> labels <> [] && List.for_all label_is_valid labels
        | _ -> false)

    (* The name [name] means, with the root label it may have been written
     * without. Raises [Invalid_argument] for what is no name at all. *)
    let fqdn name =
        let name = if name = "" then "." else name in
        let name =
            if name.[String.length name - 1] = '.' then name else name ^ "." in
        if not (name_is_valid name) then
            invalid_arg ("Dns: no name is "^ name) ;
        name

    let questions_are_valid questions =
        List.for_all (fun (name, _, _) -> name_is_valid name) questions

    let fqdn_questions questions =
        List.map (fun (name, qtype, qclass) -> fqdn name, qtype, qclass)
                 questions

    (*$T fqdn
      fqdn "www.example.com" = "www.example.com."
      fqdn "www.example.com." = "www.example.com."
      (* The root, however it is written: *) \
      fqdn "." = "." && fqdn "" = "."
      try ignore (fqdn ".example.com") ; false with Invalid_argument _ -> true
      try ignore (fqdn "www..com") ; false with Invalid_argument _ -> true
      try ignore (fqdn (String.make 64 'a' ^ ".com")) ; false \
      with Invalid_argument _ -> true
     *)

    type rr = string * QType.t * int (* qclass *) * int32 (* TTL *) * bytes
    type t = { id : int ; is_query : bool ; opcode : int ;
               is_auth : bool ; truncated : bool ;
               rec_desired : bool ; rec_avlb : bool ;
               authentic_data : bool ; checking_disabled : bool ;
               status : int ;
               questions : question list ;
               answer_rrs : rr list ;
               authority_rrs : rr list ;
               additional_rrs : rr list }

    let make_query =
        let id = ref 0 in
        (fun name ->
            let name = fqdn name in
            incr id ;
            { id = !id ; is_query = true ; opcode = std_query ;
              is_auth = false ; truncated = false ;
              rec_desired = true ; rec_avlb = false ;
              authentic_data = false ; checking_disabled = true ;
              status = 0 ;
              questions = [ name, QType.a, qclass_inet ] ;
              answer_rrs = [] ; authority_rrs = [] ; additional_rrs = [] })

    let make_answer id questions answer_rrs =
        let questions = fqdn_questions questions in
        { id ; is_query = false ; opcode = std_query ; is_auth = true ;
          truncated = false ; rec_desired = true ; rec_avlb = false ;
          authentic_data = false ; checking_disabled = true ;
          status = 0 ; questions ;
          answer_rrs ; authority_rrs = [] ; additional_rrs = [] }

    (* TODO: make_answer *)

    let random () =
        make_query (rand_hostname ())

    let unpack_name pkt rest =
        let rec aux prevs o =
            if o >= Bytes.length pkt then Error (lazy "DNS: Cannot unpack_name") else
            let count = Char.code (Bytes.get pkt o) in
            if count = 0 then Ok (""::prevs, o+1) else
            if count < 0xC0 then (
                let part = Bytes.sub pkt (o+1) count |> Bytes.to_string in
                aux (part :: prevs) (o+1+count)
            ) else (
                let offset = ((count land 0x3F) lsl 8) lor Char.code (Bytes.get pkt (o+1)) in
                Result.Monad.bind (aux prevs offset) (fun (parts, _) ->
                    Ok (parts, o+2))
            ) in
        Result.Monad.bind (aux [] rest) (fun (parts, rest) ->
            let name = String.concat "." (List.rev parts) in
            (* A message asking after the root carries that label and no
             * other, which concatenates to nothing: "." is how that name is
             * written here, as every other name ends in it. *)
            let name = if name = "" then "." else name in
            Ok (name, rest))

    let read_n16 pkt o =
        if o >= Bytes.length pkt - 1 then invalid_arg "packet too short" ;
        ((Char.code (Bytes.get pkt o)) lsl 8) + Char.code (Bytes.get pkt (o+1))
    let read_n32 pkt o =
        let hi = Int32.of_int (read_n16 pkt o)
        and lo = Int32.of_int (read_n16 pkt (o+2)) in
        Int32.logor (Int32.shift_left hi 16) lo

    let unpack_questions pkt rest num_qs =
        let rec aux qs rest num_qs =
            if num_qs = 0 then Ok (qs, rest) else (
                Result.Monad.bind (unpack_name pkt rest)
                    (fun (name, rest) ->
                        let qtype = QType.o (read_n16 pkt rest)
                        and qclass = read_n16 pkt (rest+2) in
                        if debug then Printf.printf "Dns: Decoded question name '%s', qtype=%s, qclass=%d\n%!" name (QType.to_string qtype) qclass ;
                        aux ((name, qtype, qclass) :: qs) (rest+4) (num_qs - 1))
            ) in
        aux [] rest num_qs

    let unpack_rrs pkt rest num_rrs =
        let rec aux rrs rest num_rrs =
            if num_rrs = 0 then (
                Ok (rrs, rest)
            ) else (
                Result.Monad.bind (unpack_questions pkt rest 1) (function
                    | [ name, qtype, qclass ], rest ->
                        let ttl = read_n32 pkt rest in
                        if debug then Printf.printf "Dns: Decoded RR %d name '%s', qtype=%s, qclass=%d, ttl=%ld\n%!" num_rrs name (QType.to_string qtype) qclass ttl ;
                        let res_data_len = read_n16 pkt (rest+4) in
                        let res_data = Bytes.sub pkt (rest+6) res_data_len in
                        aux ((name, qtype, qclass, ttl, res_data) :: rrs) (rest+4+2+res_data_len) (num_rrs-1)
                    | _ -> Error (lazy "Should not happen"))
            ) in
        aux [] rest num_rrs

    (* What is written is what the header counts, whoever built the record:
       a question nothing could write is one the message does not claim. *)
    (*$R pack
      let q name = name, QType.a, qclass_inet in
      let t = make_query "example.com" in
      let t = { t with questions = [ q "example.com." ; q "not a name" ] } in
      match unpack (pack t) with
      | Ok read ->
          assert_equal ~printer:string_of_int 1 (List.length read.questions)
      | Error e ->
          assert_failure (Lazy.force e)
     *)

    (* Every name a message carries ends in the root label, however it was
       written on the way in. *)
    (*$= make_query & ~printer:identity
      "www.example.com." (List.hd (make_query "www.example.com").questions |> \
                          fun (n, _, _) -> n)
      "." (List.hd (make_query ".").questions |> fun (n, _, _) -> n)
     *)

    let unpack bits = match%bitstring bits with
        | {| id : 16 ;
             qr : 1 ; opcode : 4 ; aa : 1 ; tc : 1 ; rd : 1 ; ra : 1 ; false : 1 ; ad : 1 ; cd : 1 ; rcode : 4 ;
             num_questions : 16 ; num_answer_rrs : 16 ;
             num_authority_rrs : 16 ; num_additional_rrs : 16 |} ->
            let pkt = bytes_of_bitstring bits
            and rest = 12 (* offset of the rest of the pkt *)
            in (
            try Result.Monad.bind (unpack_questions pkt rest num_questions) (fun (questions, rest) ->
                Result.Monad.bind (unpack_rrs pkt rest num_answer_rrs) (fun (answer_rrs, rest) ->
                Result.Monad.bind (unpack_rrs pkt rest num_authority_rrs) (fun (authority_rrs, rest) ->
                Result.Monad.bind (unpack_rrs pkt rest num_additional_rrs) (fun (additional_rrs, rest) ->
                if debug && Bytes.length pkt > rest then
                    Error (lazy "Dns: Trailing datas in msg")
                else if not (questions_are_valid questions) then
                    Error (lazy "Dns: Invalid questions")
                else
                    Ok { id = id ; is_query = not qr ; opcode = opcode ;
                         is_auth = aa ; truncated = tc ;
                         rec_desired = rd ; rec_avlb = ra ;
                         authentic_data = ad ; checking_disabled = cd ;
                         status = rcode ;
                         questions ;
                         answer_rrs ;
                         authority_rrs ;
                         additional_rrs }))))
            with Invalid_argument _ -> (* One of our Bytes.sub went wrong *)
                Error (lazy "Cannot decode names"))
        | {| _ |} ->
            Error (lazy "Not DNS")

    let pack_n16 v str o =
        Bytes.set str o (Char.chr ((v lsr 8) land 0xff)) ;
        Bytes.set str (o+1) (Char.chr (v land 0xff))

    let pack_n32 v str o =
        let lo = Int32.to_int (Int32.logand v 0xffffl)
        and hi = Int32.to_int (Int32.logand (Int32.shift_right_logical v 16) 0xffffl) in
        pack_n16 hi str o ;
        pack_n16 lo str (o+2)

    let rec pack_name name s str d =
        let len = String.length name - s in
        if len = 0 then (
            Bytes.set str d (Char.chr 0) ;
            Ok (d + 1)
        ) else (
            let e = String.index_from name s '.' in
            let c = e - s in
            if c > 63 then (
                Error (lazy (Printf.sprintf "Dns: Bad name '%s'" name))
            ) else (
                Bytes.set str d (Char.chr c) ;
                Bytes.blit (Bytes.of_string name) s str (d+1) c ;
                pack_name name (e+1) str (d+1+c)
            )
        )

    let pack_question (name, (qtype : QType.t), qclass) =
        if not (name_is_valid name) then (
            Error (lazy (Printf.sprintf "Dns: Bad qname '%s'" name))
        ) else (
            let str = Bytes.create (String.length name + 1 + 4) in
            Result.Monad.bind (pack_name name 0 str 0) (fun o ->
                pack_n16 (qtype :> int) str o ;
                pack_n16 qclass str (o + 2) ;
                Ok str)
        )

    let pack_questions qs =
        (List.filter_map (Result.to_option % pack_question) qs) |>
        Bytes.concat Bytes.empty

    let pack_rr (name, rtype, rclass, ttl, data) =
        Result.Monad.bind (pack_question (name, rtype, rclass)) (fun q ->
            let datalen = Bytes.length data in
            let str = Bytes.create (6 + datalen) in
            pack_n32 ttl str 0 ;
            pack_n16 datalen str 4 ;
            Bytes.blit data 0 str 6 datalen ;
            Ok (Bytes.cat q str))

    let pack_rrs rrs =
        (List.filter_map (Result.to_option % pack_rr) rrs) |>
        Bytes.concat Bytes.empty

    let pack t =
        (* What can be written, which is everything unless this record was
         * built by hand: everything that makes one names it properly (see
         * [fqdn]). The header counts what is written rather than what was
         * meant, so that a message that loses a question is still a message
         * somebody can read -- and not a header that counts one the body does
         * not carry. *)
        let ok_questions =
            List.filter (fun (name, _, _) -> name_is_valid name) t.questions
        and ok_rrs =
            List.filter (fun (name, _, _, _, _) -> name_is_valid name) in
        let answer_rrs = ok_rrs t.answer_rrs
        and authority_rrs = ok_rrs t.authority_rrs
        and additional_rrs = ok_rrs t.additional_rrs in
        let%bitstring header = {|
            t.id : 16 ;
            not t.is_query : 1 ; t.opcode : 4 ; t.is_auth : 1 ; t.truncated : 1 ;
            t.rec_desired : 1 ; t.rec_avlb : 1 ;
            false : 1 ; t.authentic_data : 1 ; t.checking_disabled : 1 ;
            t.status : 4 ;
            List.length ok_questions : 16 ;
            List.length answer_rrs : 16 ;
            List.length authority_rrs : 16 ;
            List.length additional_rrs : 16 |} in
        let questions  = pack_questions ok_questions
        and answers    = pack_rrs answer_rrs
        and authority  = pack_rrs authority_rrs
        and additional = pack_rrs additional_rrs in
        concat [ header ;
                 bitstring_of_bytes questions ;
                 bitstring_of_bytes answers ;
                 bitstring_of_bytes authority ;
                 bitstring_of_bytes additional ]

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)

    (* The four sections of a message are four tables of the same shape, bar
       the three columns only a resource record has. *)
    module Kinds =
    struct
        open SimTypes
        let id = IRange (0, 0xffff)
        let opcode =
            Widget.one_of ~range:(0, 0xf)
                [| 0, "query" ; 1, "inverse query" ; 2, "status request" |]
        let status = IRange (0, 0xf)
        (* With the root label the name ends on, which [pack_question] refuses
           a name without. *)
        let name = Widget.hint "www.example.com." String
        let qtype = Widget.one_of ~range:(0, 0xffff) QType.choices
        let qclass = Widget.one_of ~range:(0, 0xffff) [| 1, "IN" |]
        let ttl = IRange (0, 0xffff_ffff)
        let data = BRange (0, 0xffff)
        let questions =
            Widget.list
                (Widget.row [| "name", name ; "type", qtype ; "class", qclass |])
        let rrs =
            Widget.list
                (Widget.row [| "name", name ; "type", qtype ; "class", qclass ;
                               "TTL", ttl ; "data", data |])
    end

    (** What a message says. No payload: DNS is where a packet ends.
     *
     * The counts of the four sections are not here either, being the lengths
     * of the four lists below -- which is what [pack] writes them from. *)
    let kind =
        let open SimTypes in
        Widget.record
            [| "id", Kinds.id ;
               "query", Bool ;
               "opcode", Kinds.opcode ;
               "authoritative", Bool ;
               "truncated", Bool ;
               "recursion desired", Bool ;
               "recursion available", Bool ;
               "authentic data", Bool ;
               "checking disabled", Bool ;
               "status", Kinds.status ;
               "questions", Kinds.questions ;
               "answers", Kinds.rrs ;
               "authority", Kinds.rrs ;
               "additional", Kinds.rrs |]

    let to_json (t : t) =
        let json_of_question (name, qtype, qclass) =
            `Assoc [ "name", `String name ;
                     "type", `Int (qtype : QType.t :> int) ;
                     "class", `Int qclass ] in
        let json_of_rr (name, qtype, qclass, ttl, data) =
            `Assoc [ "name", `String name ;
                     "type", `Int (qtype : QType.t :> int) ;
                     "class", `Int qclass ;
                     "TTL", `Int (uint32 ttl) ;
                     "data", Widget.json_of_bytes
                                 (bitstring_of_string (Bytes.to_string data)) ] in
        let section f l = `List (List.map f l) in
        `Assoc [ "id", `Int t.id ;
                 "query", `Bool t.is_query ;
                 "opcode", `Int t.opcode ;
                 "authoritative", `Bool t.is_auth ;
                 "truncated", `Bool t.truncated ;
                 "recursion desired", `Bool t.rec_desired ;
                 "recursion available", `Bool t.rec_avlb ;
                 "authentic data", `Bool t.authentic_data ;
                 "checking disabled", `Bool t.checking_disabled ;
                 "status", `Int t.status ;
                 "questions", section json_of_question t.questions ;
                 "answers", section json_of_rr t.answer_rrs ;
                 "authority", section json_of_rr t.authority_rrs ;
                 "additional", section json_of_rr t.additional_rrs ]

    let of_synth js ?upper ?prev gen_values =
        ignore upper ;
        let open Generator in
        let int fname ?auto kind f js =
            int_of_field fname gen_values ?auto kind f js
        and bool fname =
            of_field fname gen_values SimTypes.Bool Widget.to_bool js in
        (* A name of the shape names have: a random string of up to fifty
         * thousand characters is no label anything can pack (a label is 63
         * bytes at the outside), and [pack_question] drops the question it
         * cannot write -- leaving a message whose header counts a question it
         * does not carry. The trailing dot is one of the things it refuses a
         * name without: what it writes is the root label too. *)
        let name js =
            of_field "name" gen_values
                     ~auto:(fun () ->
                         Printf.sprintf "h%d.example.com." (Random.int 1000))
                     Kinds.name (fqdn % Widget.to_string) js
        and qtype js = int "type" Kinds.qtype QType.o js
        and qclass js = int "class" Kinds.qclass identity js in
        let question js = name js, qtype js, qclass js
        and rr js =
            name js, qtype js, qclass js,
            Int32.of_int (int "TTL" Kinds.ttl identity js),
            Bytes.of_string (string_of_bitstring
                                 (bs_of_field "data" gen_values Kinds.data js)) in
        let section fname kind f =
            sub_of_field fname gen_values kind (Widget.to_list f) js in
        { id = int "id" ?auto:(Option.map (fun p () ->
                                  (p.id + 1) land 0xffff) prev)
                   Kinds.id identity js ;
          is_query = bool "query" ;
          opcode = int "opcode" Kinds.opcode identity js ;
          is_auth = bool "authoritative" ;
          truncated = bool "truncated" ;
          rec_desired = bool "recursion desired" ;
          rec_avlb = bool "recursion available" ;
          authentic_data = bool "authentic data" ;
          checking_disabled = bool "checking disabled" ;
          status = int "status" Kinds.status identity js ;
          questions = section "questions" Kinds.questions question ;
          answer_rrs = section "answers" Kinds.rrs rr ;
          authority_rrs = section "authority" Kinds.rrs rr ;
          additional_rrs = section "additional" Kinds.rrs rr }

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
