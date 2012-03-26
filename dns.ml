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

(* Opcodes, query types and classes *)

let std_query = 0
let inv_query = 1
let srv_status_request = 2

module QType = struct
    include MakePrivate(struct
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

(* DNS messages *)

module Pdu =
struct
    (*$< Pdu *)
    type question = string * QType.t * int
    type rr = string * QType.t * int * int32 * string
    type t = { id : int ; is_query : bool ; opcode : int ;
               is_auth : bool ; truncated : bool ;
               rec_desired : bool ; rec_avlb : bool ;
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
              status = 0 ;
              questions = [ name, QType.a, qclass_inet ] ;
              answer_rrs = [] ; authority_rrs = [] ; additional_rrs = [] })

    (* TODO: make_answer *)

    let random () =
        make_query (rand_hostname () ^ ".")
        
    let unpack_name pkt rest =
        let rec aux prevs o =
            if o >= String.length pkt then err "DNS: Cannot unpack_name" else
            let count = Char.code pkt.[o] in
            if count = 0 then Some (""::prevs, o+1) else
            if count < 0xC0 then (
                let part = String.sub pkt (o+1) count in
                aux (part :: prevs) (o+1+count)
            ) else (
                let offset = ((count land 0x3F) lsl 8) lor Char.code pkt.[o+1] in
                Option.Monad.bind (aux prevs offset) (fun (parts, _) ->
                    Some (parts, o+2))
            ) in
        Option.Monad.bind (aux [] rest) (fun (parts, rest) ->
            let name = String.concat "." (List.rev parts) in
            Some (name, rest))
 
    let read_n16 pkt o =
        ensure (o < String.length pkt - 1) "dns.ml: read_n16: offset greater then pkt length";
        ((Char.code pkt.[o]) lsl 8) + Char.code pkt.[o+1]
    let read_n32 pkt o =
        let hi = Int32.of_int (read_n16 pkt o)
        and lo = Int32.of_int (read_n16 pkt (o+2)) in
        Int32.logor (Int32.shift_left hi 16) lo

    let unpack_questions pkt rest nb_qs =
        let rec aux qs rest nb_qs =
            if nb_qs = 0 then Some (qs, rest) else (
                Option.Monad.bind (unpack_name pkt rest)
                    (fun (name, rest) ->
                        let qtype = QType.o (read_n16 pkt rest)
                        and qclass = read_n16 pkt (rest+2) in
                        if debug then Printf.printf "Dns: Decoded question name '%s', qtype=%s, qclass=%d\n%!" name (QType.to_string qtype) qclass ;
                        aux ((name, qtype, qclass) :: qs) (rest+4) (nb_qs - 1))
            ) in
        aux [] rest nb_qs

    let unpack_rrs pkt rest nb_rrs =
        let rec aux rrs rest nb_rrs =
            if nb_rrs = 0 then (
                Some (rrs, rest)
            ) else (
                Option.Monad.bind (unpack_questions pkt rest 1) (function
                    | [ name, qtype, qclass ], rest ->
                        let ttl = read_n32 pkt rest in
                        if debug then Printf.printf "Dns: Decoded RR %d name '%s', qtype=%s, qclass=%d, ttl=%ld\n%!" nb_rrs name (QType.to_string qtype) qclass ttl ;
                        let res_data_len = read_n16 pkt (rest+4) in
                        (* FIXME: catch String.sub errors *)
                        let res_data = String.sub pkt (rest+6) res_data_len in
                        aux ((name, qtype, qclass, ttl, res_data) :: rrs) (rest+4+2+res_data_len) (nb_rrs-1)
                    | _ -> err "Should not happen")
            ) in
        aux [] rest nb_rrs

    let unpack bits = bitmatch bits with
        | { id : 16 ;
            qr : 1 ; opcode : 4 ; aa : 1 ; tc : 1 ; rd : 1 ; ra : 1 ; 0 : 3 ; rcode : 4 ;
            nb_questions : 16 ; nb_answer_rrs : 16 ;
            nb_authority_rrs : 16 ; nb_additional_rrs : 16 } ->
            let pkt = string_of_bitstring bits
            and rest = 12 (* offset of the rest of the pkt *)
            in
            Option.Monad.bind (unpack_questions pkt rest nb_questions) (fun (questions, rest) ->
            Option.Monad.bind (unpack_rrs pkt rest nb_answer_rrs) (fun (answer_rrs, rest) ->
            Option.Monad.bind (unpack_rrs pkt rest nb_authority_rrs) (fun (authority_rrs, rest) ->
            Option.Monad.bind (unpack_rrs pkt rest nb_additional_rrs) (fun (additional_rrs, rest) ->
            if String.length pkt > rest then err "Dns: Trailing datas in msg" else
            Some { id = id ; is_query = not qr ; opcode = opcode ;
                   is_auth = aa ; truncated = tc ;
                   rec_desired = rd ; rec_avlb = ra ;
                   status = rcode ;
                   questions = questions ;
                   answer_rrs = answer_rrs ;
                   authority_rrs = authority_rrs ;
                   additional_rrs = additional_rrs }))))
        | { _ } -> err "Not DNS"

    let pack_n16 v str o =
        str.[o]   <- Char.chr ((v lsr 8) land 0xff) ;
        str.[o+1] <- Char.chr (v land 0xff)

    let pack_n32 v str o =
        let lo = Int32.to_int (Int32.logand v 0xffffl)
        and hi = Int32.to_int (Int32.logand (Int32.shift_right_logical v 16) 0xffffl) in
        pack_n16 hi str o ;
        pack_n16 lo str (o+2)

    let rec pack_name name s str d =
        let len = String.length name - s in
        if len = 0 then (
            str.[d] <- Char.chr 0 ;
            Some (d+1)
        ) else (
            let e = String.index_from name s '.' in
            let c = e - s in
            if c > 63 then (
                err (Printf.sprintf "Dns: Bad name '%s'" name)
            ) else (
                str.[d] <- Char.chr c ;
                String.blit name s str (d+1) c ;
                pack_name name (e+1) str (d+1+c)
            )
        )

    let pack_question (name, (qtype : QType.t), qclass) =
        let len = String.length name in
        if len = 0 || name.[0] = '.' || name.[len-1] <> '.' then (
            err "Dns: Bad name"
        ) else (
            let str = String.create (len + 1 + 4) in
            Option.Monad.bind (pack_name name 0 str 0) (fun o ->
                pack_n16 (qtype :> int) str o ;
                pack_n16 qclass str (o + 2) ;
                Some str)
        )

    let pack_questions qs =
        String.concat "" (List.filter_map pack_question qs)

    let pack_rr (name, rtype, rclass, ttl, data) =
        Option.Monad.bind (pack_question (name, rtype, rclass)) (fun q ->
            let datalen = String.length data in
            let str = String.create (6 + datalen) in
            pack_n32 ttl str 0 ;
            pack_n16 datalen str 4 ;
            String.blit data 0 str 6 datalen ;
            Some (q ^ str))

    let pack_rrs rrs =
        String.concat "" (List.filter_map pack_rr rrs)

    let pack t =
        let header = (BITSTRING {
            t.id : 16 ;
            not t.is_query : 1 ; t.opcode : 4 ; t.is_auth : 1 ; t.truncated : 1 ;
            t.rec_desired : 1 ; t.rec_avlb : 1 ; 0 : 3 ; t.status : 4 ;
            List.length t.questions : 16 ;
            List.length t.answer_rrs : 16 ;
            List.length t.authority_rrs : 16 ;
            List.length t.additional_rrs : 16 }) in
        let questions  = pack_questions t.questions
        and answers    = pack_rrs t.answer_rrs
        and authority  = pack_rrs t.authority_rrs
        and additional = pack_rrs t.additional_rrs in
        concat [ header ;
                 bitstring_of_string questions ;
                 bitstring_of_string answers ;
                 bitstring_of_string authority ;
                 bitstring_of_string additional ]

    (*$Q pack
      ((random |- pack), dump) (fun t -> t = pack (Option.get (unpack t)))
     *)
    (*$>*)
end

