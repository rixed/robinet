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
  A simple HTTP server.
*)
open Batteries
open Tools
open Http

(* Returns a hash of all GET variables *)
let params_of_query q =
    let vars = Hashtbl.create 7 in
    let q = if String.length q > 0 && q.[0] = '?' then String.lchop q else q in
    (* get variables *)
    String.split_on_char '&' q |>
        List.filter_map (fun q ->
            try
                let eq = String.index_from q 1 '=' in
                Some (String.sub q 0 eq, String.lchop ~n:(eq+1) q)
            with Not_found -> Some (q, "")
               | Invalid_argument _ -> None) |>
        List.iter (fun (name, value) ->
            (* Now that all the parsing is done, we can url-decode: *)
            let name = Url.decode name and value = Url.decode value in
            Hashtbl.add vars name value) ;
    vars

(*$= params_of_query & ~printer:dump
    [ "foo", "bar" ] \
        (params_of_query "foo=bar" |> Hashtbl.enum |> List.of_enum |> List.sort Stdlib.compare)
    [ "bar", "baz" ; "foo", "bar" ] \
        (params_of_query "foo=bar&bar=baz" |> Hashtbl.enum |> List.of_enum |> List.sort Stdlib.compare)
*)

(**
  Listen HTTP connections arriving at [host] on given [port],
  passing incoming messages to a user supplied function [f].

  A simple server may be used like:

  {[
    (* Server *)
    let server = Host.make_static "server" (Eth.Addr.random ()) (Ip.Addr.of_string "192.168.1.1");;
    let content_of file = File.lines_of file |> List.of_enum |> String.concat "";;
    Opache.serve server (Tcp.Port.o 8080) (fun trx _msg _log ->
        Http.TRXtop.tx trx (Http.Pdu.make_response 200 ["Content-Type", "text/plain"] (content_of "test.ml")));;
    (* Our client *)
    let client = Host.make_static "client" (Eth.Addr.random ()) (Ip.Addr.of_string "192.168.1.2");;
    let browser = Browser.make client;;
    (* Link with a tap in between *)
    let tap = Hub.Tap.make (Pcap.save "http.pcap");;
    client.Host.dev <--> tap.ins ; tap.out <--> server.Host.dev;;
    (* Send a request *)
    Browser.request browser ~headers:["Connection", "close"]
                    (Url.of_string "http://192.168.1.1:8080/") (function
        | None -> Printf.printf "fail\n"
        | Some (headers, body) ->
            Printf.printf "\nResult:\n%a\n\n%s\n" Http.print_headers headers body);;
    Clock.run false;;
  ]}

  Notice that this example, if copied into test.ml, will generate a pcap containing the source code that
  generates the pcap :-)
*)
let serve host ?(port=Tcp.Port.o 80) f =
    let logger = Log.sub host.Host.logger ("httpd:"^ Tcp.Port.to_string port) in
    host.tcp_server port (fun (tcp : Tcp.TRX.tcp_trx) ->
        (* once we obtain the transport layer, build an http on top of it *)
        Log.(log logger Debug (lazy "Building a new HTTP.TRXtop")) ;
        let http = TRXtop.make () in
        TRXtop.set_emit http (tx tcp.trx) ;
        TRXtop.set_recv http (function
            | TRXtop.HttpError x ->
                Log.(log logger Debug (lazy (Printf.sprintf "Got error %s" x))) ;
                tcp.close ()
            | TRXtop.HttpMsg (pdu, opened) ->
                Log.(log logger Debug (lazy "Got HTTP msg")) ;
                if not opened then (
                    Log.(log logger Debug (lazy (Printf.sprintf "Close the Tcp cnx"))) ;
                    tcp.close ()
                ) ;
                (match pdu with
                | { Pdu.cmd = Request (_cmd, url) ; _ } ->
                    Log.(log logger Debug (lazy (Printf.sprintf "Http msg is a request for %s" url))) ;
                    (* Force the callback to return unit to get better diagnostic: *)
                    let () = f host http pdu logger in
                    Log.(log logger Debug (lazy (Printf.sprintf "Headers were %s, so we must%s close" (string_of_headers pdu.Pdu.headers) (if must_close_cnx pdu.Pdu.headers then "" else " not")))) ;
                    if must_close_cnx pdu.Pdu.headers then tcp.close ()
                | _ ->
                    Log.(log logger Debug (lazy (Printf.sprintf "Http msg is unknown"))) ;
                    Pdu.make_response 500 |> TRXtop.tx http ;
                    tcp.close ())) ;
        (* Only when everything's set up do we connect the tcp recv to http rx *)
        let verbose_rx bits =
            Log.(log logger Debug (lazy "Got some bits for HTTP!")) ;
            TRXtop.rx http bits in
        ignore (verbose_rx <-= tcp.trx))

(** {2 HTTP servicing functions}
  These functions build a function taking an {Http.TRXtop.t}, an incomming {Http.Pdu.t} and
  responsible for sending the answer. They are mean to be used by [multiplexer].
 *)

let print_vars oc vars =
    Printf.fprintf oc "%a" (Hashtbl.print String.print String.print) vars

(* The exception a resource can throw to signal an error *)
exception ResourceError of int * string

let content_type_from_filename name =
    try let last_dot = String.rindex name '.' in
        match String.sub name (last_dot+1) (String.length name - last_dot - 1) with
        | "txt"   -> "text/plain"
        | "html"  -> "text/html"
        | "js"    -> "text/javascript"
        | "css"   -> "text/css"
        | "csv"   -> "text/csv"
        | "xhtml" -> "application/xhtml+xml"
        | "png"   -> "image/png"
        | "ico"   -> "image/ico"
        | "jpg"
        | "jpeg"  -> "image/jpeg"
        | _       -> "text/plain"
    with Not_found -> "text/plain"

(* Serve static files from given root directory *)
let static_file_server root _mth path_matches _params _qry_body resp_body =
    let have_dotdot file =
        try ignore (String.find file "/../"); true
        with Not_found -> false in
    let serve_file file =
        (try File.with_file_in file (fun ic ->
                BatIO.copy ic resp_body)
        with Sys_error _ -> raise (ResourceError (404, "No such file "^file))) ;
        [ "Content-Type", content_type_from_filename file ] in
    match path_matches with
        | [ _url ] ->
            serve_file root
        | [ _url ; file ] ->
            if have_dotdot file then raise (ResourceError (403, "Parent dir not allowed"))
            else serve_file (Filename.concat root file)
        | _ ->
            raise (ResourceError (400, "Bad path"))

let it_works _mth path_matches _params _qry_body resp_body =
    Printf.fprintf resp_body {|
<html><head><title>It Works!</title></head>
<body><h1>It works, too!</h1>
Your requested: '%s'<br/>
</body></html>|}
        (List.first path_matches) ;
    [ "Content-Type", "text/html" ]

(*type params = (string, string) Hashtbl.t
type resource = (Str.regexp * (string -> string list -> params -> string -> unit BatIO.output -> Http.header list)) list*)
(* list of (regex matching URL * (function of method, matches, parameters hash and output stream to list of headers)) *)
let multiplexer res host http msg logger =
    (* We'd rather have one such metric per host: *)
    let counter = Metric.Atomic.make ("hosts/"^ host.Host.name ^"/httpd/queries") in
    let handle mth url _headers ext_params qry_body =
        let url = Url.of_string url in
        let count_query status =
            let open Metric in
            let params =
                Params.make Param.[ "method", String mth ;
                                    "path", String url.path ;
                                    "status", Int status ] in
            Metric.Atomic.fire ~params counter in
        match List.find_map (fun (re, f) ->
                if Str.string_match re url.Url.path 0
                then Some (str_all_matches url.Url.path, f)
                else None) res with
        | exception Not_found ->
            Log.(log logger Debug (lazy (Printf.sprintf "Multiplexer: No taker for url '%s'" url.Url.path))) ;
            let code = 404 in
            count_query code ;
            TRXtop.tx http { Pdu.cmd = Status code ;
                             Pdu.headers = [] ;
                             Pdu.body = "" }
        | matches, f ->
            Log.(log logger Debug (lazy (Printf.sprintf2 "Multiplexer: Found a match for url '%s', matches=%a" url.Url.path (List.print String.print) matches))) ;
            let vars = params_of_query url.Url.query in
            hash_merge vars (params_of_query ext_params) ;
            let str = BatIO.output_string () in
            (try
                let headers = f mth matches vars qry_body str in
                let headers =
                    if Http.headers_find "Content-Type" headers = None then
                        ("Content-Type", "text/html") :: headers
                    else headers in
                let body = BatIO.close_out str in
                let code = 200 in
                count_query code ;
                TRXtop.tx http { Pdu.cmd = Status code ;
                                 Pdu.headers = ("Content-Length", Printf.sprintf "%d" (String.length body)) :: headers ;
                                 Pdu.body = body }
            with ResourceError (code, str) ->
                let err_msg = "It failed again! This time because:\n" ^ str in
                count_query code ;
                TRXtop.tx http { Pdu.cmd = Status code ;
                                 Pdu.headers = [ "Content-Type", "text/plain" ;
                                                 "Content-Length", Printf.sprintf "%d" (String.length err_msg) ] ;
                                 Pdu.body = err_msg }) in
    match msg with
    | { Pdu.cmd = Request ("GET" as mth, url) ; headers ; body } ->
        handle mth url headers "" body
    | { Pdu.cmd = Request ("POST" as mth, url) ; headers ; body }
    | { Pdu.cmd = Request ("PUT" as mth, url) ; headers ; body } ->
        let is_submit =
            (match Http.headers_find "Content-Type" headers with
            | Some ct when String.icompare ct "application/x-www-form-urlencoded" = 0 -> true
            | _ -> false) in
        if is_submit then (
            handle mth url headers (Http.post_decode body) ""
        ) else (
            handle mth url headers "" body
        )
    | _ ->
        Log.(log logger Debug (lazy ("Multiplexer: Don't know how to handle this HTTP message, returning 501"))) ;
        let body = "Don't know how to process this" in
        TRXtop.tx http { Pdu.cmd = Status 501 ;
                         (* We are suposed to have a message-body *)
                         Pdu.headers = [ "Content-Length", Printf.sprintf "%d" (String.length body) ;
                                         "Content-Type", "text/plain" ] ;
                         Pdu.body = body }
