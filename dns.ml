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

    let random () = randi 16
end

let qclass_inet = 1

(** {2 DNS messages} *)

module Pdu =
struct
    (*$< Pdu *)
    type question = string * QType.t * int
    type rr = string * QType.t * int * int32 (* TTL *) * bytes
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
            incr id ;
            { id = !id ; is_query = true ; opcode = std_query ;
              is_auth = false ; truncated = false ;
              rec_desired = true ; rec_avlb = false ;
              authentic_data = false ; checking_disabled = true ;
              status = 0 ;
              questions = [ name, QType.a, qclass_inet ] ;
              answer_rrs = [] ; authority_rrs = [] ; additional_rrs = [] })

    let make_answer id questions answer_rrs =
        { id ; is_query = false ; opcode = std_query ; is_auth = true ;
          truncated = false ; rec_desired = true ; rec_avlb = false ;
          authentic_data = false ; checking_disabled = true ;
          status = 0 ; questions ;
          answer_rrs ; authority_rrs = [] ; additional_rrs = [] }

    (* TODO: make_answer *)

    let random () =
        make_query (rand_hostname () ^ ".")

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
        let len = String.length name in
        if len <> 0 && (name.[0] = '.' || name.[len-1] <> '.') then (
            Error (lazy (Printf.sprintf "Dns: Bad qname '%s'" name))
        ) else (
            let str = Bytes.create (len + 1 + 4) in
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
        let%bitstring header = {|
            t.id : 16 ;
            not t.is_query : 1 ; t.opcode : 4 ; t.is_auth : 1 ; t.truncated : 1 ;
            t.rec_desired : 1 ; t.rec_avlb : 1 ;
            false : 1 ; t.authentic_data : 1 ; t.checking_disabled : 1 ;
            t.status : 4 ;
            List.length t.questions : 16 ;
            List.length t.answer_rrs : 16 ;
            List.length t.authority_rrs : 16 ;
            List.length t.additional_rrs : 16 |} in
        let questions  = pack_questions t.questions
        and answers    = pack_rrs t.answer_rrs
        and authority  = pack_rrs t.authority_rrs
        and additional = pack_rrs t.additional_rrs in
        concat [ header ;
                 bitstring_of_bytes questions ;
                 bitstring_of_bytes answers ;
                 bitstring_of_bytes authority ;
                 bitstring_of_bytes additional ]

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)
    (*$>*)
end
