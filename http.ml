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
(** HyperText Transfert Protocol *)
open Batteries
open Bitstring
open Tools
open Peg

let debug = false

(** {2 HTTP Error codes} *)

type code = int

let text_of_code (c : code) = match c with
	  100 -> "Continue"
	| 101 -> "Switching Protocols"
	| 102 -> "Processing"
	| 122 -> "Request-URI too long"
	| 200 -> "OK"
	| 201 -> "Created"
	| 202 -> "Accepted"
	| 203 -> "Non-Authoritative Information"
	| 204 -> "No Content"
	| 205 -> "Reset Content"
	| 206 -> "Partial Content"
	| 207 -> "Multi-Status"
	| 226 -> "IM Used"
	| 300 -> "Multiple Choices"
	| 301 -> "Moved Permanently"
	| 302 -> "Found"
	| 303 -> "See Other"
	| 304 -> "Not Modified"
	| 305 -> "Use Proxy"
	| 306 -> "Switch Proxy"
	| 307 -> "Temporary Redirect"
	| 400 -> "Bad Request"
	| 401 -> "Unauthorized"
	| 402 -> "Payment Required"
	| 403 -> "Forbidden"
	| 404 -> "Not Found"
	| 405 -> "Method Not Allowed"
	| 406 -> "Not Acceptable"
	| 407 -> "Proxy Authentication Required"
	| 408 -> "Request Timeout"
	| 409 -> "Conflict"
	| 410 -> "Gone"
	| 411 -> "Length Required"
	| 412 -> "Precondition Failed"
	| 413 -> "Request Entity Too Large"
	| 414 -> "Request-URI Too Long"
	| 415 -> "Unsupported Media Type"
	| 416 -> "Requested Range Not Satisfiable"
	| 417 -> "Expectation Failed"
	| 418 -> "I'm a teapot"
	| 422 -> "Unprocessable Entity"
	| 423 -> "Locked"
	| 424 -> "Failed Dependency"
	| 425 -> "Unordered Collection"
	| 426 -> "Upgrade Required"
	| 444 -> "No Response"
	| 449 -> "Retry With"
	| 450 -> "Blocked by Windows Parental Controls"
	| 499 -> "Client Closed Request"
	| 500 -> "Internal Server Error"
	| 501 -> "Not Implemented"
	| 502 -> "Bad Gateway"
	| 503 -> "Service Unavailable"
	| 504 -> "Gateway Timeout"
	| 505 -> "HTTP Version Not Supported"
	| 506 -> "Variant Also Negotiates"
	| 507 -> "Insufficient Storage"
	| 509 -> "Bandwidth Limit Exceeded"
	| 510 -> "Not Extended"
    | _   -> "Unknown HTTP Error"

let string_of_code (c : code) =
    Printf.sprintf "%d %s" c (text_of_code c)

let print_code fmt (c : code) =
    Format.fprintf fmt "@{<code>%s@}" (string_of_code c)

(** {2 HTTP commands, headers... } *)

type cmd = Status of code | Request of string (* post, get... *) * string (* URL *)
type header  = string * string
let string_of_header (n, v) = Printf.sprintf "%s: %s" n v
let print_header oc h = Printf.fprintf oc "%s" (string_of_header h)
let print_headers oc headers = List.print print_header oc headers
let string_of_headers headers =
    (String.join "\r\n" (List.map string_of_header headers)) ^ "\r\n"

let header_content_length_re = Str.regexp_case_fold "^Content-Length: +\\(.+\\)$"
let chunked_transfert_encoding_re = Str.regexp_case_fold "^Transfer-Encoding: +chunked"

let rec headers_find f = function
    | [] -> None
    | (f', v) :: hs' ->
        if String.icompare f' f = 0 then Some v else headers_find f hs'

let headers_find_all f hs =
    let matching_h = List.filter (fun (f', _) -> String.icompare f' f = 0) hs in
    List.map snd matching_h

let header_present n v hs = match headers_find n hs with
    | Some str when String.icompare str v = 0 -> true
    | _ -> false

let must_close_cnx = header_present "Connection" "close"

(** {2 HTTP Messages} *)

module Pdu =
struct
    type t = { cmd : cmd ; headers : header list ; body : string }

    let string_of_cmd = function
        | Request (req, path) -> Printf.sprintf "%s %s HTTP/1.1" req (if String.length path <> 0 then path else "/")
        | Status c -> Printf.sprintf "HTTP/1.1 %d %s" c (text_of_code c)

    (* An HTTP parser *)

    type parse_item = [ `HttpRequest of string * string
                      | `HttpResponse of int * string
                      | `HttpHeaders of header list ]

    let make_request req path ?(body="") headers =
        { cmd = Request (req, path) ;
          headers = headers ;
          body = body }

    let make_response ?(headers=[]) ?(body="") code =
        let content_length = "Content-Length", string_of_int (String.length body) in
        { cmd = Status code ;
          headers = content_length :: headers ;
          body }

    let parzer () =
        let crlf = [ '\r'; '\n' ] in
        let msg_of status_line headers body =
            Option.Monad.bind (match status_line with
                | `HttpRequest (cmd, url) -> Some (Request (String.uppercase cmd, url))
                | `HttpResponse (code, _) -> Some (Status code)
                | _ -> None) (fun cmd ->
                    Some { cmd = cmd ;
                           headers = headers ;
                           body = String.of_list body }) in
        let spaces () = several (item ' ') in
        let non_spaces () = several (cond (fun c -> c <> ' ' && c <> '\r' && c <> '\n')) in
        let http_version () =
            seq [ item 'H' ; item 'T' ; item 'T' ; item 'P' ; item '/' ;
                  numeric () ; item '.' ; numeric () ] in
        let request_line () =
            map (seqf [ some (map (non_spaces ()) String.of_list) ;
                        none (spaces ()) ;
                        some (map (non_spaces ()) String.of_list) ;
                        none (spaces ()) ;
                        none (http_version ()) ;
                        none (Peg.crlf ()) ]) (function
                    | [c;u] -> `HttpRequest (c, u)
                    | _ -> should_not_happen ())
        and status_line () =
            map (seqf [ none (http_version ()) ;
                        none (spaces ()) ;
                        some (map (several (numeric ())) String.of_list) ;
                        none (spaces ()) ;
                        some (map (many (cond (fun c -> c <> '\r'))) String.of_list) ;
                        none (Peg.crlf ()) ]) (function
                    | [s;m] ->
                        if debug then Printf.printf "Http: got response %s, %s\n" s m ;
                        `HttpResponse (int_of_string s, m)
                    | _ -> should_not_happen ()) in
        let start_line () =
            either [ request_line () ; status_line () ] in
        let header () =
            map (seqf [ some (map (several (cond (fun c -> c <> ':' && c <> '\r' && c <> '\n'))) String.of_list) ;
                        none (item ':') ;
                        none (spaces ()) ;
                        some (map (upto ['\r' ; '\n']) (fun l ->
                            String.strip ~chars:"\t\r\n " (String.of_list l))) ]) (function
                    | [f;v] ->
                        if debug then Printf.printf "Http: Got header %s, %s\n" f v ;
                        f, v
                    | _ -> should_not_happen ()) in
        let headers () = map (many (header ())) (fun hs ->
            if debug then Printf.printf "Http: got headers\n" ;
            `HttpHeaders hs) in
        let chunk_header () = map (upto crlf) (fun l ->
            let str = String.of_list l in
            let str = String.strip ~chars:" \t\r\n" str in
            if debug then Printf.printf "Http: got a chunk of size %s\n" str ;
            Option.default 0 (int_of_hexstring str)) in
        let chunk () =
            map (seq [ bind (chunk_header ()) take ;
                       Peg.crlf () ]) (fun x ->
                    if debug then Printf.printf "Http: chunk completed\n" ;
                    List.hd x) in
        let chunks () =
            map (repeat_until List.is_empty (chunk ())) (fun x ->
                if debug then Printf.printf "Http: got all chunks\n" ;
                List.concat x) in
        let body () = function
            | [ start ; `HttpHeaders hs ] ->
                (* "Any response message which "MUST NOT" include a message-body (such as the 1xx,
                   204, and 304 responses and any response to a HEAD request) is always terminated
                   by the first empty line after the header fields, regardless of the entity-header
                   fields present in the message."
                    - http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4.
                   TODO: for responses to HEAD, we do not handle this case yet. *)
                let body_parser = (match start with
                    | `HttpResponse (code, _) when (code >= 100 && code <= 199) || code = 204 || code = 304 ->
                        if debug then Printf.printf "Http: msg required to have no body\n" ;
                        return []
                    | `HttpRequest ("GET", _) ->
                        if debug then Printf.printf "Http: request required to have no body\n" ;
                        return []
                    | _ -> (match headers_find "Transfer-Encoding" hs with
                        (* FIXME: when te _contains_ "chunked"? *)
                        | Some te when String.icompare te "chunked" = 0 ->
                            if debug then Printf.printf "Http: msg chunked\n" ;
                            chunks ()
                        | _ -> (match headers_find "Content-Length" hs with
                            | Some cl ->
                                let cl = int_of_string cl in
                                if debug then Printf.printf "Http: msg of size %d\n" cl ;
                                take cl
                            | _ ->
                                if debug then Printf.printf "Http: msg up to end of data\n" ;
                                all ()))) in
                map_filter body_parser (msg_of start hs)
            | _ -> should_not_happen () in
        bind (seqf [ none (many (Peg.crlf ())) ;
                     some (start_line ()) ;
                     some (headers ());
                     none (Peg.crlf ()) ]) (body ())

    let pack { cmd = cmd ; headers = headers ; body = body } =
        bitstring_of_string (
            (string_of_cmd cmd) ^ "\r\n" ^
            (string_of_headers headers) ^ "\r\n" ^
            body)

    let unpack bits =
        let str = string_of_bitstring bits
        and p = parzer () in
        match p (String.to_list str) false with
            | Res (msg, []) -> Some msg
            | Wait          -> err "Http: unpack: Cannot unpack (truncated?)"
            | Fail          -> err "Http: unpack: not HTTP"
            | Res (_, l)    -> err (Printf.sprintf "Http: unpack: %d bytes left" (List.length l))
end


(** {2 TRX for HTTP messages} *)

(** Special kind of transceiver, useful when it's on top of a TRX stack, that
    receive and tx Pdu.t messages (instead of bitstring). *)
module TRXtop =
struct
    type result =
        | HttpError of string
        | HttpMsg of Pdu.t * bool (* tells whether the underlying transport is still open *)
    type t = { parzer  : (Pdu.t, char) parzer ; (* The parser we use for reconstructing the PDU *)
               mutable emit : bitstring -> unit ;
               mutable recv : result -> unit }

    let set_emit t emit = t.emit <- emit
    let set_recv t recv = t.recv <- recv

    let make () =
        { parzer = Pdu.parzer () ;
          emit = ignore ; recv = ignore }

    let tx t pdu =
        let pdu = Pdu.pack pdu in
        if debug then Printf.printf "Http: sending '%s'\n%!" (abbrev ~len:100 (string_of_bitstring pdu)) ;
        t.emit pdu

    let rec rx t bits =
        let str = string_of_bitstring bits in
        if debug then Printf.printf "Http: have to parse %d bytes\n" (String.length str) ;
        let items = String.to_list str in
        (match t.parzer items (not (bitstring_is_empty bits)) with
            | Fail ->
                if debug then Printf.printf "Http: Cannot parse as HTTP : '%s'\n" (string_of_bitstring bits) ;
                (* Close the socket since we lost the cursor *)
                t.recv (HttpError "Cannot parse as HTTP")
            | Wait ->
                if debug then Printf.printf "Http:...wait\n" (* except if bits = empty_bitstring maybe? *)
            | Res (res, rem) ->
                if debug then Printf.printf "Http:...got a result\n" ;
                t.recv (HttpMsg (res, not (bitstring_is_empty bits))) ;
                if rem <> [] then (
                    rx t (bitstring_of_string (String.of_list rem))
                ))
end


(** {2 TRX for any payload} *)

(** Once build (as a poster or server), the Http.TRX handle the whole connection(s).
    Used to tx a body (packed into a 200 Ok response or a post).
    This is mostly useful to use HTTP as a transport layer (for instance as a tunnel). *)
module TRX =
struct
    type t = { cmd : cmd ;
               headers : header list ;
               mutable recv : bitstring -> unit ;
               top : TRXtop.t }

    let tx t bits =
        let str = string_of_bitstring bits in
        TRXtop.tx t.top {
            Pdu.cmd = t.cmd ;
            Pdu.headers = ("Content-Length", string_of_int (String.length str)) :: t.headers ;
            body = str }

    let rx t pld = TRXtop.rx t.top pld

    let make ?(cmd=(Status 200)) headers =
        let top = TRXtop.make () in
        let t = { cmd = cmd ; headers = headers ;
                  recv = ignore ; top = top } in
        TRXtop.set_recv top (function
            | TRXtop.HttpMsg (msg, opened) ->
                t.recv (bitstring_of_string msg.Pdu.body) ;
                if not opened then t.recv empty_bitstring
            | TRXtop.HttpError x ->
                    if debug then Printf.printf "Http: Error: %s\n" x) ;
        { ins = { write = tx t ;
                  set_read = fun f -> t.recv <- f } ;
          out = { write = rx t ;
                  set_read = fun f -> TRXtop.set_emit t.top f } }

end

let post_decode body =
    Url.decode (String.nreplace ~str:body ~sub:"+" ~by:" ")

let post_encode body =
    String.nreplace ~str:(Url.encode body) ~sub:" " ~by:"+"

(* Checks *)

(*$R
    let simple_msg = bitstring_of_string "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n12345" in
    assert_bool "unpack simple msg" (match Pdu.unpack simple_msg with
        | Some { Pdu.cmd = Status 200 ;
                 Pdu.headers = [ "Content-Type", "text/plain" ] ;
                 Pdu.body = "12345" } -> true
        | Some x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: simple_msg: got %s\n" (string_of_bitstring msg) ;
            false
        | None ->
            Printf.printf "Http: Fail: cannot Unpack\n" ;
            false) ;
*)
(*$R
    let simple_msg2 = bitstring_of_string "GET /toto HTTP/1.1\r\n\r\n" in
    assert_bool "unpack simple msg (2)" (match Pdu.unpack simple_msg2 with
        | Some { Pdu.cmd = Request ("GET", "/toto") ;
                 Pdu.headers = [] ;
                 Pdu.body = "" } -> true
        | Some x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: simple_msg2: got %s\n" (string_of_bitstring msg) ;
            false
        | None ->
            Printf.printf "Http: Fail: Cannot unpack simple_msg2\n" ;
            false) ;
*)
(*$R
    let complex_msg = bitstring_of_string (file_content "tests/http.real") in
    assert_bool "unpack complex msg" (match Pdu.unpack complex_msg with
        | Some { Pdu.cmd = Status 200 ;
                 Pdu.headers = hs ;
                 Pdu.body = body } ->
            (if List.length hs <> 9 then (Printf.printf "Http: Fail: bad header count\n" ; false) else true) &&
            (if headers_find "Connection" hs <> Some "Keep-Alive" then (Printf.printf "Http: Fail: Cannot find header\n" ; false) else true) &&
            (if String.length body <> 2175 then (Printf.printf "Http: Fail: Bad body length (%d)\n" (String.length body) ; false) else true)
        | Some x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: complex_msg: got %s\n" (string_of_bitstring msg) ;
            false
        | None ->
            Printf.printf "Http: Fail: Cannot unpack complex_msg\n" ;
            false) ;
*)
(*$R
    let chunked_msg = bitstring_of_string (file_content "tests/http.chunked") in
    assert_bool "unpack chunked msg" (match Pdu.unpack chunked_msg with
        | Some { Pdu.cmd = Status 200 ;
                 Pdu.headers = hs ;
                 Pdu.body = body } ->
            (if List.length hs <> 9 then (Printf.printf "Http: Fail: bad header count\n" ; false) else true) &&
            (if headers_find "Server" hs <> Some "gws" then (Printf.printf "Http: Fail: Cannot find header\n" ; false) else true) &&
            (if String.length body <> 0x1000+0xCEA+0x97C then (Printf.printf "Http: Fail: Bad body length (%d)\n" (String.length body) ; false) else true)
        | Some x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: chunked_msg: got %s\n" (string_of_bitstring msg) ;
            false
        | None ->
            Printf.printf "Http: Fail: Cannot unpack chunked_msg\n" ;
            false) ;
*)
(*$R
    let err403_msg = bitstring_of_string (file_content "tests/http.403") in
    assert_bool "unpack err 403" (match Pdu.unpack err403_msg with
        | Some { Pdu.cmd = Status 403 ;
                 Pdu.headers = hs ;
                 Pdu.body = body } ->
            (if List.length hs <> 4 then (Printf.printf "Http: Fail: bad header count\n" ; false) else true) &&
            (if headers_find "Server" hs <> Some "GFE/2.0" then (Printf.printf "Http: Fail: Cannot find header\n" ; false) else true) &&
            (if String.length body <> 1207 then (Printf.printf "Http: Fail: Bad body length (%d)\n" (String.length body) ; false) else true)
        | Some x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: err403_msg: got %s\n" (string_of_bitstring msg) ;
            false
        | None ->
            Printf.printf "Http: Fail: Cannot unpack err403_msg\n" ;
            false) ;
*)
(*$R
    let post_msg = bitstring_of_string (file_content "tests/http.post") in
    assert_bool "unpack POST" (match Pdu.unpack post_msg with
        | Some { Pdu.cmd = Request ("POST", "/nevrax/do_login.html") ;
                 Pdu.headers = hs ;
                 Pdu.body = "login=admin&password=admin&submit=Connexion&came_from=%2F" } ->
            (if List.length hs <> 12 then (Printf.printf "Http: Fail: bad header count\n" ; false) else true) &&
            (if headers_find "Connection" hs <> Some "keep-alive" then (Printf.printf "Http: Fail: Cannot find header\n" ; false) else true)
        | Some x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: http.post: got %s\n" (string_of_bitstring msg) ;
            false
        | None ->
            Printf.printf "Http: Fail: Cannot unpack http.post\n" ;
            false)
*)
