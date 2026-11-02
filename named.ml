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
        { widget : Widget.t ;
          mutable default_ttl : int ;
          lookup : string -> Ip.Addr.t option }

    (* [lookup] is a function taking names as string and returning
     * IP addresses or None in which case the server will delegate.
     * FIXME: any serializable/inspectable datastructure *)
    let make ?(default_ttl=3600) ~parent lookup =
        let widget = Widget.make ~parent "named" in
        let t = { widget ; default_ttl ; lookup } in
        Widget.add_properties widget Widget.[
            property "default TTL" ~kind:Int ~units:"secs"
                ~descr:"Default TTL for DNS answers."
                ~getter:(fun () -> `Int t.default_ttl)
                ~setter:(fun v -> t.default_ttl <- to_int v) ] ;
        t

    let lookup st qname =
        st.lookup qname
end

(* The resource record answering that question with [ip], if [ip] is of the
 * family the question asks for: *)
let answer_rr ttl (qname, qtype, qclass) ip =
    if qtype = QType.a && Ip.Addr.is_v4 ip ||
       qtype = QType.aaaa && Ip.Addr.is_v6 ip
    then Some (qname, qtype, qclass, ttl, Ip.Addr.to_bytes ip)
    else None
(*$T answer_rr
  answer_rr 1l ("a.", Dns.QType.a, 1) (Ip.Addr.of_string "1.2.3.4") <> None
  answer_rr 1l ("a.", Dns.QType.aaaa, 1) (Ip.Addr.of_string "::1") <> None
  answer_rr 1l ("a.", Dns.QType.aaaa, 1) (Ip.Addr.of_string "1.2.3.4") = None
  answer_rr 1l ("a.", Dns.QType.a, 1) (Ip.Addr.of_string "::1") = None
  answer_rr 1l ("a.", Dns.QType.ptr, 1) (Ip.Addr.of_string "1.2.3.4") = None
 *)

(** [serve host] listen on host name port and
 * answer queries (or delegates to its own nameserver). *)
let serve ?(port=Udp.Port.o 53) (st : State.t) host =
    (* Waiting to be attached to this server's widget, which will supply the
     * clock it must be dated with:
    let timed = Metric.Timed.make ("hosts/"^ host.Host.widget.name ^"/named/queries") in
    *)
    Log.(log st.widget.logger Debug (lazy "Listening for requests...")) ;
    host.Host.udp_server_start port (fun udp ->
        udp.Udp.TRX.trx.ins --> sink (fun bits ->
            Log.(log st.widget.logger Debug (lazy "Received an UDP packet...")) ;
            match Pdu.unpack bits with
            | Error s ->
                Log.(log st.widget.logger Debug (lazy ("Not DNS: "^ Lazy.force s)))
            | Ok (Pdu.{ is_query = true ; _ } as query)
              when query.opcode = std_query && query.Pdu.questions <> [] ->
                let num_questions = List.length query.Pdu.questions in
                Log.(log st.widget.logger Debug (lazy (Printf.sprintf "Received a DNS query with %d questions" num_questions))) ;
                let stop_func () = (*
                    let open Metric in
                    let params =
                       Params.make Param.[ "questions", Int num_questions ] in
                    Timed.start ~params timed *) () in
                let answers = Array.make num_questions None in
                let check_all_answered () =
                  if Array.for_all ((<>) None) answers then (
                    let answer_rrs =
                      List.fold_lefti (fun lst i question ->
                        match  Option.get answers.(i) with
                        | None -> lst
                        | Some (_auth, ip) ->
                            let ttl = Int32.of_int st.default_ttl in
                            match answer_rr ttl question ip with
                            | None -> lst
                            | Some rr -> rr :: lst
                      ) [] query.Pdu.questions in
                    Log.(log st.widget.logger Debug (lazy "Answering")) ;
                    stop_func () ; (* stop_func Metric.Params.(make []) ; *)
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
                        Log.(log st.widget.logger Debug (lazy (Printf.sprintf "Don't know %S, delegating" qname))) ;
                        host.Host.gethostbyname qname (fun ip_opt ->
                            (match ip_opt with
                            | None | Some [] ->
                                Log.(log st.widget.logger Debug (lazy "Got error from delegated query")) ;
                                answers.(i) <- Some None
                            | Some [ ip ] ->
                                Log.(log st.widget.logger Debug (lazy "Got answer from delegated query")) ;
                                answers.(i) <- Some (Some (false, ip))
                            | Some lst ->
                                Log.(log st.widget.logger Warning (lazy (Printf.sprintf "Bogus answer from delegated query with %d answers!" (List.length lst)))) ;
                                answers.(i) <- Some None) ;
                            check_all_answered ())
                    | Some ip ->
                        Log.(log st.widget.logger Debug (lazy (Printf.sprintf "I know host %S!" qname))) ;
                        answers.(i) <- Some (Some (true, ip)) ;
                        check_all_answered ()
                ) query.Pdu.questions
            | _ ->
                Log.(log st.widget.logger Debug (lazy "Ignoring that DNS message"))))

(*$R serve
    let sim = Simulation.make ~realtime:false "test-named" in
    (*Log.console_lvl := Log.Debug ;*)
    let netmask = Ip.Addr.all_ones in
    let srv : Host.t = Host.make ~parent:sim.root ~netmask ~static_ip:(Ip.Addr.of_dotted_string "1.1.1.1") "server" in
    let lookup = function
        | "popo" -> Some (Ip.Addr.of_dotted_string "1.1.1.1")
        | _ -> None in
    let st = State.make ~parent:sim.root lookup in
    serve st srv.trx ;
    let nameserver = Ip.Addr.of_dotted_string "1.1.1.1" in
    let clt : Host.t = Host.make ~parent:sim.root ~nameserver ~netmask ~static_ip:(Ip.Addr.random ()) "client" in
    srv.trx.dev --> clt.trx.dev ;
    clt.trx.dev --> srv.trx.dev ;
    (* Both boxes are born dark, and the client cannot ask before it is on. *)
    Simulation.run_startup sim ;
    let got_ip = ref false in
    clt.trx.gethostbyname "popo" (fun _ -> got_ip := true) ;
    Simulation.run sim false ;
    assert_bool "Client got popo's IP" !got_ip
 *)

(* A dual-stack client asks for both families, of a server reached over
 * IPv6, and gets its preferred one first. *)
(*$R serve
    let sim = Simulation.make ~realtime:false "test-named-v6" in
    let a s = Ip.Addr.of_string s in
    let host ?nameserver n =
        Host.make ~parent:sim.root ?nameserver
                  ~static_ip:(a ("10.0.0." ^ n)) ~netmask:(a "255.255.255.0")
                  ~addresses:[ Ip.Cidr.of_string ("2001:db8::" ^ n ^ "/64") ]
                  ("h" ^ n) in
    let srv = host "1" in
    let st = State.make ~parent:sim.root (function
        | "v4" -> Some (a "10.0.0.9")
        | "v6" -> Some (a "2001:db8::9")
        | _ -> None) in
    serve st srv.trx ;
    let clt = host ~nameserver:(a "2001:db8::1") "2" in
    let c = Eth.Cable.State.make ~parent:sim.root ~name:"c" () in
    Eth.Cable.plug c (srv.trx.widget, 0) (clt.trx.widget, 0) ;
    Simulation.run_startup sim ;
    let resolve name =
        let res = ref None in
        clt.trx.gethostbyname name (fun ips -> res := ips) ;
        Simulation.run sim false ;
        Option.map (List.map Ip.Addr.to_string) !res in
    let printer = function
        | None -> "None"
        | Some l -> String.concat "," l in
    assert_equal ~printer (Some [ "2001:db8::9" ]) (resolve "v6") ;
    assert_equal ~printer (Some [ "10.0.0.9" ]) (resolve "v4") ;
    assert_equal ~printer (Some []) (resolve "nope")
 *)
