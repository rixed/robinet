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
open Batteries
open Tools
open Dns

(** DNS server *)

module State =
struct
    type t =
        { logger : Log.logger ;
          default_ttl : int ;
          lookup : string -> Ip.Addr.t option }

    (* [lookup] is a function taking names as string and returning
     * IP addresses or None in which case the server will delegate.
     * FIXME: any serializable/inspectable datastructure *)
    let make ?(default_ttl=3600) ?(parent_logger=Log.default) lookup =
        let logger = Log.sub parent_logger "named" in
        { logger ; default_ttl ; lookup }

    let lookup st qname =
        st.lookup qname
end

(** [serve host] listen on host name port and
 * answer queries (or delegates to its own nameserver). *)
let serve ?(port=Udp.Port.o 53) (st : State.t) host =
    Log.(log st.logger Debug (lazy "Listening for requests...")) ;
    host.Host.udp_server port (fun udp ->
        udp.Udp.TRX.trx.ins.set_read (fun bits ->
            Log.(log st.logger Debug (lazy "Received an UDP packet...")) ;
            match Pdu.unpack bits with
            | None ->
                Log.(log st.logger Debug (lazy "Not a DNS message, ignoring"))
            | Some (Pdu.{ is_query = true ; _ } as query)
              when query.opcode = std_query && query.Pdu.questions <> [] ->
                let num_questions = List.length query.Pdu.questions in
                Log.(log st.logger Debug (lazy (Printf.sprintf "Received a DNS query with %d questions" num_questions))) ;
                let answers = Array.make num_questions None in
                let check_all_answered () =
                  if Array.for_all ((<>) None) answers then (
                    let answer_rrs =
                      List.fold_lefti (fun lst i (qname, qtype, qclass) ->
                        match  Option.get answers.(i) with
                        | None -> lst
                        | Some (_auth, ip) ->
                            let ttl = Int32.of_int st.default_ttl in
                            (qname, qtype, qclass, ttl, Ip.Addr.to_bytes ip) :: lst
                      ) [] query.Pdu.questions in
                    Log.(log st.logger Debug (lazy "Answering")) ;
                    Pdu.make_answer query.Pdu.id query.Pdu.questions answer_rrs |>
                    Pdu.pack |>
                    tx udp.trx)
                in
                List.iteri (fun i (qname, _qtype, _qclass) ->
                    (* TODO: also pass qtype to lookup? *)
                    let qname =
                        if String.ends_with qname "." then String.rchop qname else qname in
                    match State.lookup st qname with
                    | None ->
                        Log.(log st.logger Debug (lazy (Printf.sprintf "Don't know %S, delegating" qname))) ;
                        host.Host.gethostbyname qname (fun ip_opt ->
                            (match ip_opt with
                            | None | Some [] ->
                                Log.(log st.logger Debug (lazy "Got error from delegated query")) ;
                                answers.(i) <- Some None
                            | Some [ ip ] ->
                                Log.(log st.logger Debug (lazy "Got answer from delegated query")) ;
                                answers.(i) <- Some (Some (false, ip))
                            | Some lst ->
                                Log.(log st.logger Warning (lazy (Printf.sprintf "Bogus answer from delegated query with %d answers!" (List.length lst)))) ;
                                answers.(i) <- Some None) ;
                            check_all_answered ())
                    | Some ip ->
                        Log.(log st.logger Debug (lazy (Printf.sprintf "I know host %S!" qname))) ;
                        answers.(i) <- Some (Some (true, ip)) ;
                        check_all_answered ()
                ) query.Pdu.questions
            | _ ->
                Log.(log st.logger Debug (lazy "Ignoring that DNS message"))))

(*$R serve
    let logger = Log.make "test" in
    Clock.realtime := false ;
    (*Log.console_lvl := Log.Debug ;*)
    let netmask = Ip.Addr.all_ones in
    let srv : Host.t = Host.make_static ~netmask (Ip.Addr.of_dotted_string_exc "1.1.1.1") "server" in
    let lookup = function
        | "popo" -> Some (Ip.Addr.of_dotted_string_exc "1.1.1.1")
        | _ -> None in
    let st = State.make ~parent_logger:logger lookup in
    serve st srv.trx ;
    let nameserver = Ip.Addr.of_dotted_string_exc "1.1.1.1" in
    let clt : Host.t = Host.make_static ~nameserver ~netmask (Ip.Addr.random ()) "client" in
    srv.trx.dev.set_read clt.trx.dev.write ;
    clt.trx.dev.set_read srv.trx.dev.write ;
    let got_ip = ref false in
    clt.trx.gethostbyname "popo" (fun _ -> got_ip := true) ;
    Clock.run false ;
    Clock.realtime := true ;
    assert_bool "Client got popo's IP" !got_ip
 *)
