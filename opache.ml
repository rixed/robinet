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
(*
  A simple HTTP server
*)
open Batteries
open Tools
open Http

(* Returns a hash of all GET variables *)
let params_of_query q =
    let vars = Hashtbl.create 7 in
    let q = if String.length q > 0 && q.[0] = '?' then String.lchop q else q in
    (* get variables *)
    String.nsplit q "&" |>
        List.filter_map (fun q ->
            try
                let eq = String.index_from q 1 '=' in
                Some (String.sub q 0 eq, String.lchop ~n:(eq+1) q)
            with Not_found -> Some (q, "")
               | Invalid_argument _ -> None) |>
        List.iter (fun (name, value) -> Hashtbl.add vars name value) ;
    vars

(*$= params_of_query & ~printer:dump
    [ "foo", "bar" ] \
        (params_of_query "foo=bar" |> Hashtbl.enum |> List.of_enum |> List.sort Pervasives.compare)
    [ "bar", "baz" ; "foo", "bar" ] \
        (params_of_query "foo=bar&bar=baz" |> Hashtbl.enum |> List.of_enum |> List.sort Pervasives.compare)
*)

let rec stripped url =
    if url = "" || url = "/" then "root"
    else
        let l = String.length url in
        let start = if url.[0] = '/' then 1 else 0
        and stop = if url.[l-1] = '/' then l-1 else l in
        if start = 0 && stop = l then url
        else stripped (String.sub url start (stop-start))

(*$= stripped & ~printer:identity
    "foo" (stripped "foo")
    "foo" (stripped "/foo")
    "foo" (stripped "foo/")
    "foo" (stripped "/foo/")
    "foo" (stripped "///foo//")
    "root" (stripped "")
    "root" (stripped "/")
    "root" (stripped "//")
    "root" (stripped "////")
*)

(* Main entry point: build an HTTP TRX and pass incoming messages to a user supplied function *)
let serve host port f =
    let logger = Log.(make (Printf.sprintf "%s/Httpd:%s" host.Host.logger.name (Tcp.Port.to_string port)) 50) in
    let count_queries_per_url = Hashtbl.create 11 in
    let count_query cmd url =
        let key = cmd^"/"^(stripped url) in
        let counter = hash_find_or_insert count_queries_per_url key (fun () ->
            Metric.Atomic.make ("Hosts/"^host.Host.name^"/Httpd/queries/"^key)) in
        Metric.Atomic.fire counter in
    host.Host.tcp_server port (fun tcp ->
        (* once we obtain the transport layer, build an http on top of it *)
        Log.(log logger Debug (lazy "Building a new HTTP.TRXtop")) ;
        let http = TRXtop.make () in
        TRXtop.set_emit http tcp.Tcp.TRX.trx.tx ;
        TRXtop.set_recv http (function
            | TRXtop.HttpError x ->
                Log.(log logger Debug (lazy (Printf.sprintf "Got error %s" x))) ;
                tcp.Tcp.TRX.close ()
            | TRXtop.HttpMsg (pdu, opened) ->
                Log.(log logger Debug (lazy "Got HTTP msg")) ;
                if not opened then (
                    Log.(log logger Debug (lazy (Printf.sprintf "Close the Tcp cnx"))) ;
                    tcp.Tcp.TRX.close ()
                ) ;
                (match pdu with
                | { Pdu.cmd = Request (cmd, url) ; _ } ->
                    Log.(log logger Debug (lazy (Printf.sprintf "Http msg is a request for %s" url))) ;
                    count_query cmd url ;
                    f http pdu logger
                | _ ->
                    Log.(log logger Debug (lazy (Printf.sprintf "Http msg is unknown"))) ;
                    TRXtop.tx http { Pdu.cmd = Status 500 ; Pdu.headers = [] ; Pdu.body = "" } ;
                    tcp.Tcp.TRX.close ())) ;
        (* Only when everything's set up do we connect the tcp recv to http rx *)
        tcp.Tcp.TRX.trx.set_recv (TRXtop.rx http))

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
    Printf.fprintf resp_body "
<html><head><title>It Works!</title></head>
<body><h1>It works, too!</h1>
Your requested: '%s'<br/>
</body></html>"
        (List.first path_matches) ;
    [ "Content-Type", "text/html" ]

type params = (string, string) Hashtbl.t
type resource = (Str.regexp * (string -> string list -> params -> string -> string BatIO.output -> Http.header list)) list
(* list of (regex matching URL * (function of method, matches, parameters hash and output stream to list of headers)) *)
let multiplexer (res:resource) http msg logger =
    let handle mth url _headers ext_params qry_body =
        let url = Url.of_string url in
        match none_if_not_found
            (List.find_map (fun (re, f) ->
                if Str.string_match re url.Url.path 0
                then Some (str_all_matches url.Url.path, f)
                else None)) res with
        | Some (matches, f) ->
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
                TRXtop.tx http { Pdu.cmd = Status 200 ;
                                 Pdu.headers = ("Content-Length", Printf.sprintf "%d" (String.length body)) :: headers ;
                                 Pdu.body = body }
            with ResourceError (code, str) ->
                let err_msg = "It failed again! This time because:\n" ^ str in
                TRXtop.tx http { Pdu.cmd = Status code ;
                                 Pdu.headers = [ "Content-Type", "text/plain" ;
                                                 "Content-Length", Printf.sprintf "%d" (String.length err_msg) ] ;
                                 Pdu.body = err_msg })
        | None ->
            Log.(log logger Debug (lazy (Printf.sprintf "Multiplexer: No taker for url '%s'" url.Url.path))) ;
            TRXtop.tx http { Pdu.cmd = Status 404 ;
                             Pdu.headers = [] ;
                             Pdu.body = "" } in
    match msg with
    | { Pdu.cmd = Request ("GET", url) ; headers ; body } ->
        handle "GET" url headers "" body
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

