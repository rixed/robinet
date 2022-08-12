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

(** [serve host lookup] listen on host name port and
 * answer queries (or delegates to its own nameserver).
 * [lookup] is a function taking names as string and returning
 * IP addresses or None in which case the server will delegate. *)
let serve ?(port=Udp.Port.o 53) host lookup =
    let default_ttl = 3600l in
    let logger = host.Host.logger in
    Log.(log logger Debug (lazy "named: Listening for requests...")) ;
    host.Host.udp_server port (fun udp ->
        udp.Udp.TRX.trx.ins.set_read (fun bits ->
            Log.(log logger Debug (lazy "named: Received an UDP packet...")) ;
            match Pdu.unpack bits with
            | None ->
                Log.(log logger Debug (lazy "named: Not a DNS message, ignoring"))
            | Some (Pdu.{ is_query = true ; _ } as query)
              when query.opcode = std_query && query.Pdu.questions <> [] ->
                let nb_questions = List.length query.Pdu.questions in
                Log.(log logger Debug (lazy (Printf.sprintf "named: Received a DNS query with %d questions" nb_questions))) ;
                let answers = Array.make nb_questions None in
                let check_all_answered () =
                  if Array.for_all ((<>) None) answers then (
                    let answer_rrs =
                      List.fold_lefti (fun lst i (qname, qtype, qclass) ->
                        match  Option.get answers.(i) with
                        | None -> lst
                        | Some (_auth, ip) ->
                            (qname, qtype, qclass, default_ttl, Ip.Addr.to_bytes ip) :: lst
                      ) [] query.Pdu.questions in
                    Log.(log logger Debug (lazy "named: Answering")) ;
                    Pdu.make_answer query.Pdu.id query.Pdu.questions answer_rrs |>
                    Pdu.pack |>
                    tx udp.trx)
                in
                List.iteri (fun i (qname, _qtype, _qclass) ->
                    (* TODO: also pass qtype to lookup? *)
                    let qname =
                        if String.ends_with qname "." then String.rchop qname else qname in
                    match lookup qname with
                    | None ->
                        Log.(log logger Debug (lazy (Printf.sprintf "named: Don't know %S, delegating" qname))) ;
                        host.Host.gethostbyname qname (fun ip_opt ->
                            (match ip_opt with
                            | None | Some [] ->
                                Log.(log logger Debug (lazy "named: Got error from delegated query")) ;
                                answers.(i) <- Some None
                            | Some [ ip ] ->
                                Log.(log logger Debug (lazy "named: Got answer from delegated query")) ;
                                answers.(i) <- Some (Some (false, ip))
                            | Some lst ->
                                Log.(log logger Warning (lazy (Printf.sprintf "named: bogus answer from delegated query with %d answers!" (List.length lst)))) ;
                                answers.(i) <- Some None) ;
                            check_all_answered ())
                    | Some ip ->
                        Log.(log logger Debug (lazy (Printf.sprintf "named: I know host %S!" qname))) ;
                        answers.(i) <- Some (Some (true, ip)) ;
                        check_all_answered ()
                ) query.Pdu.questions
            | _ ->
                Log.(log logger Debug (lazy "named: Ignoring that DNS message"))))

(*$R serve
    Clock.realtime := false ;
    (*Log.console_lvl := Log.Debug ;*)
    let srv = Host.make_static "server" ~on:true ~netmask:Ip.Addr.all_ones (Eth.Addr.random ()) (Ip.Addr.of_dotted_string "1.1.1.1" |> Option.get) in
    serve srv (function "popo" -> Some (Ip.Addr.of_dotted_string "1.1.1.1" |> Option.get) | _ -> None) ;
    let clt = Host.make_static "client" ~nameserver:(Ip.Addr.of_dotted_string "1.1.1.1" |> Option.get) (Eth.Addr.random ()) (Ip.Addr.random ()) in
    srv.Host.dev.set_read clt.Host.dev.write ;
    clt.Host.dev.set_read srv.Host.dev.write ;
    let got_ip = ref false in
    clt.Host.gethostbyname "popo" (fun _ -> got_ip := true) ;
    Clock.run false ;
    Clock.realtime := true ;
    assert_bool "Client got popo's IP" !got_ip
 *)
