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
    (* [version] as on the first line, such as "HTTP/1.1": *)
    type t = { cmd : cmd ; version : string ; headers : header list ; body : string }

    let default_version = "HTTP/1.1"

    let string_of_cmd version = function
        | Request (req, path) -> Printf.sprintf "%s %s %s" req (if String.length path <> 0 then path else "/") version
        | Status c -> Printf.sprintf "%s %d %s" version c (text_of_code c)

    let make_request req path ?(body="") headers =
        { cmd = Request (req, path) ;
          version = default_version ;
          headers = headers ;
          body = body }

    let make_response ?(headers=[]) ?(body="") code =
        let content_length = "Content-Length", string_of_int (String.length body) in
        { cmd = Status code ;
          version = default_version ;
          headers = content_length :: headers ;
          body }

    (* What the beginning of a buffer holds: *)
    type parsed =
        | Parsed of t * int (* the message and how many bytes it took *)
        | Truncated of int  (* the buffer length below which parsing again is useless *)
        | Not_http

    exception Need of int
    exception Bad

    let is_version v =
        String.length v = 8 && String.starts_with v "HTTP/" &&
        Char.is_digit v.[5] && v.[6] = '.' && Char.is_digit v.[7]

    let cmd_of_line l =
        match List.filter ((<>) "") (String.split_on_char ' ' l) with
        | [ meth ; url ; v ] when is_version v ->
            Request (String.uppercase_ascii meth, url), v
        | v :: code :: _ when is_version v && String.length code = 3 &&
                              String.for_all Char.is_digit code ->
            Status (int_of_string code), v
        | _ -> raise Bad

    let header_of_line l =
        match String.index_opt l ':' with
        | Some k when k > 0 ->
            String.sub l 0 k,
            String.strip ~chars:" \t" (String.sub l (k + 1) (String.length l - k - 1))
        | _ -> raise Bad

    (** Parse the message at the beginning of [s]. [eof] tells that nothing
        will follow [s], which ends a body that has no explicit length. *)
    let parse s eof =
        let len = String.length s in
        let need n = if len < n then raise (Need n) in
        (* Position of the CRLF ending the line starting at [i]: *)
        let eol i =
            try String.find_from s i "\r\n"
            with Not_found -> raise (Need (len + 1)) in
        let line i j = String.sub s i (j - i) in
        let rec skip_crlfs i =
            if i + 1 < len && s.[i] = '\r' && s.[i + 1] = '\n' then skip_crlfs (i + 2)
            else i in
        let rec headers hs i =
            let j = eol i in
            if j = i then List.rev hs, i + 2
            else headers (header_of_line (line i j) :: hs) (j + 2) in
        let rec chunks buf i =
            let j = eol i in
            (* Chunk extensions, after ';', are ignored *)
            let size = String.strip (List.hd (String.split_on_char ';' (line i j))) in
            let n = match int_of_string_opt ("0x" ^ size) with
                | Some n when n >= 0 -> n
                | _ -> raise Bad in
            let i = j + 2 in
            need (i + n + 2) ;
            if s.[i + n] <> '\r' || s.[i + n + 1] <> '\n' then raise Bad ;
            Stdlib.Buffer.add_substring buf s i n ;
            if n = 0 then Stdlib.Buffer.contents buf, i + 2
            else chunks buf (i + n + 2) in
        try
            let i = skip_crlfs 0 in
            let j = eol i in
            let cmd, version = cmd_of_line (line i j) in
            let headers, i = headers [] (j + 2) in
            let body, stop =
                match cmd with
                | Status c when (c >= 100 && c <= 199) || c = 204 || c = 304 ->
                    (* TODO: so is the response to a HEAD *)
                    "", i
                | _ ->
                    (* FIXME: when Transfer-Encoding _contains_ "chunked"? *)
                    match headers_find "Transfer-Encoding" headers,
                          headers_find "Content-Length" headers, cmd with
                    | Some te, _, _ when String.icompare te "chunked" = 0 ->
                        chunks (Stdlib.Buffer.create 4096) i
                    | _, Some cl, _ ->
                        let n = match int_of_string_opt (String.trim cl) with
                            | Some n when n >= 0 -> n
                            | _ -> raise Bad in
                        need (i + n) ;
                        String.sub s i n, i + n
                    | _, _, Request _ ->
                        (* Only a response can be delimited by the end of the connection
                           (RFC 7230 3.3.3) *)
                        "", i
                    | _ ->
                        if eof then String.sub s i (len - i), len
                        else raise (Need max_int) in
            Parsed ({ cmd ; version ; headers ; body }, stop)
        with Need n -> Truncated n
           | Bad -> Not_http

    let pack { cmd ; version ; headers ; body } =
        bitstring_of_string (
            (string_of_cmd version cmd) ^ "\r\n" ^
            (string_of_headers headers) ^ "\r\n" ^
            body)

    let unpack bits =
        let str = string_of_bitstring bits in
        match parse str true with
            | Parsed (msg, n) when n = String.length str -> Ok msg
            | Parsed (_, n) -> Error (Printf.sprintf "Http: unpack: %d bytes left" (String.length str - n))
            | Truncated _ -> Error "Http: unpack: Cannot unpack (truncated?)"
            | Not_http -> Error "Http: unpack: not HTTP"
end


(** {2 TRX for HTTP messages} *)

(** Special kind of transceiver, useful when it's on top of a TRX stack, that
    receive and tx Pdu.t messages (instead of bitstring). *)
module TRXtop =
struct
    type result =
        | HttpError of string
        | HttpMsg of Pdu.t * bool (* tells whether the underlying transport is still open *)
    type t = { pending : Stdlib.Buffer.t ; (* received bytes not yet part of a message *)
               mutable wanted : int ; (* no message before [pending] is that long *)
               mutable hand_over_to : (bitstring -> unit) option ;
               mutable emit : bitstring -> unit ;
               mutable emit_busy_for : unit -> Clock.Interval.t ;
               mutable recv : result -> unit }

    (* Emit into [dev]: *)
    let set_emit t dev =
        t.emit <- dev.write ;
        t.emit_busy_for <- dev.busy_for

    let busy_for t () = t.emit_busy_for ()
    let set_recv t recv = t.recv <- recv

    let make () =
        { pending = Stdlib.Buffer.create 4096 ; wanted = 0 ; hand_over_to = None ;
          emit = ignore ; emit_busy_for = never_busy ; recv = ignore }

    let tx t pdu =
        let pdu = Pdu.pack pdu in
        if debug then Printf.printf "Http: sending '%s'\n%!" (abbrev ~len:100 (string_of_bitstring pdu)) ;
        t.emit pdu

    (** Stop parsing HTTP: from now on [f] receives what the transport
        delivers, starting with what was received after the last message. *)
    let hand_over t f =
        t.hand_over_to <- Some f ;
        if Stdlib.Buffer.length t.pending > 0 then (
            let rest = Stdlib.Buffer.contents t.pending in
            Stdlib.Buffer.clear t.pending ;
            f (bitstring_of_string rest))

    (* An empty [bits] tells the transport is closed. *)
    let rx t bits =
        match t.hand_over_to with
        | Some f -> f bits
        | None ->
        let eof = bitstring_is_empty bits in
        Stdlib.Buffer.add_string t.pending (string_of_bitstring bits) ;
        let error msg =
            Stdlib.Buffer.clear t.pending ;
            t.wanted <- 0 ;
            t.recv (HttpError msg) in
        let rec parse () =
            let str = Stdlib.Buffer.contents t.pending in
            match Pdu.parse str eof with
            | Pdu.Not_http ->
                if debug then Printf.printf "Http: Cannot parse as HTTP: '%s'\n" (abbrev str) ;
                error "Cannot parse as HTTP"
            | Pdu.Truncated n ->
                if eof then error "Truncated HTTP message"
                else t.wanted <- n
            | Pdu.Parsed (msg, n) ->
                Stdlib.Buffer.clear t.pending ;
                Stdlib.Buffer.add_substring t.pending str n (String.length str - n) ;
                t.wanted <- 0 ;
                t.recv (HttpMsg (msg, not eof)) ;
                if t.hand_over_to = None && Stdlib.Buffer.length t.pending > 0 then parse () in
        if eof || Stdlib.Buffer.length t.pending >= t.wanted then parse ()
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
               mutable recv_busy_for : unit -> Clock.Interval.t ;
               top : TRXtop.t }

    let tx t bits =
        let str = string_of_bitstring bits in
        TRXtop.tx t.top {
            Pdu.cmd = t.cmd ;
            version = Pdu.default_version ;
            Pdu.headers = ("Content-Length", string_of_int (String.length str)) :: t.headers ;
            body = str }

    let rx t pld = TRXtop.rx t.top pld

    let make ?(cmd=(Status 200)) headers =
        let top = TRXtop.make () in
        let t = { cmd = cmd ; headers = headers ;
                  recv = ignore ; recv_busy_for = never_busy ; top = top } in
        TRXtop.set_recv top (function
            | TRXtop.HttpMsg (msg, opened) ->
                t.recv (bitstring_of_string msg.Pdu.body) ;
                if not opened then t.recv empty_bitstring
            | TRXtop.HttpError x ->
                    if debug then Printf.printf "Http: Error: %s\n" x) ;
        { ins = { write = tx t ;
                  busy_for = TRXtop.busy_for t.top ;
                  set_read = fun f busy_for ->
                      t.recv <- f ; t.recv_busy_for <- busy_for } ;
          out = { write = rx t ;
                  busy_for = (fun () -> t.recv_busy_for ()) ;
                  set_read = fun write busy_for ->
                      TRXtop.set_emit t.top { write ; busy_for ;
                                              set_read = fun _ _ -> () } } }

end

let post_decode body =
    Url.decode (String.nreplace ~str:body ~sub:"+" ~by:" ")

let post_encode body =
    String.nreplace ~str:(Url.encode body) ~sub:" " ~by:"+"

(* Checks *)

(*$R
    let simple_msg = bitstring_of_string "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n12345" in
    assert_bool "unpack simple msg" (match Pdu.unpack simple_msg with
        | Ok { Pdu.cmd = Status 200 ;
               Pdu.headers = [ "Content-Type", "text/plain" ] ;
               Pdu.body = "12345" } -> true
        | Ok x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: simple_msg: got %s\n" (string_of_bitstring msg) ;
            false
        | Error _ ->
            Printf.printf "Http: Fail: cannot Unpack\n" ;
            false) ;
*)
(*$R
    let simple_msg2 = bitstring_of_string "GET /toto HTTP/1.1\r\n\r\n" in
    assert_bool "unpack simple msg (2)" (match Pdu.unpack simple_msg2 with
        | Ok { Pdu.cmd = Request ("GET", "/toto") ;
               Pdu.headers = [] ;
               Pdu.body = "" } -> true
        | Ok x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: simple_msg2: got %s\n" (string_of_bitstring msg) ;
            false
        | Error _ ->
            Printf.printf "Http: Fail: Cannot unpack simple_msg2\n" ;
            false) ;
*)
(*$R
    let complex_msg = bitstring_of_string (file_content "tests/http.real") in
    assert_bool "unpack complex msg" (match Pdu.unpack complex_msg with
        | Ok { Pdu.cmd = Status 200 ;
               Pdu.headers = hs ;
               Pdu.body = body } ->
            (if List.length hs <> 9 then (Printf.printf "Http: Fail: bad header count\n" ; false) else true) &&
            (if headers_find "Connection" hs <> Some "Keep-Alive" then (Printf.printf "Http: Fail: Cannot find header\n" ; false) else true) &&
            (if String.length body <> 2175 then (Printf.printf "Http: Fail: Bad body length (%d)\n" (String.length body) ; false) else true)
        | Ok x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: complex_msg: got %s\n" (string_of_bitstring msg) ;
            false
        | Error _ ->
            Printf.printf "Http: Fail: Cannot unpack complex_msg\n" ;
            false) ;
*)
(*$R
    let chunked_msg = bitstring_of_string (file_content "tests/http.chunked") in
    assert_bool "unpack chunked msg" (match Pdu.unpack chunked_msg with
        | Ok { Pdu.cmd = Status 200 ;
               Pdu.headers = hs ;
               Pdu.body = body } ->
            (if List.length hs <> 9 then (Printf.printf "Http: Fail: bad header count\n" ; false) else true) &&
            (if headers_find "Server" hs <> Some "gws" then (Printf.printf "Http: Fail: Cannot find header\n" ; false) else true) &&
            (if String.length body <> 0x1000+0xCEA+0x97C then (Printf.printf "Http: Fail: Bad body length (%d)\n" (String.length body) ; false) else true)
        | Ok x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: chunked_msg: got %s\n" (string_of_bitstring msg) ;
            false
        | Error _ ->
            Printf.printf "Http: Fail: Cannot unpack chunked_msg\n" ;
            false) ;
*)
(*$R
    let err403_msg = bitstring_of_string (file_content "tests/http.403") in
    assert_bool "unpack err 403" (match Pdu.unpack err403_msg with
        | Ok { Pdu.cmd = Status 403 ;
               Pdu.headers = hs ;
               Pdu.body = body } ->
            (if List.length hs <> 4 then (Printf.printf "Http: Fail: bad header count\n" ; false) else true) &&
            (if headers_find "Server" hs <> Some "GFE/2.0" then (Printf.printf "Http: Fail: Cannot find header\n" ; false) else true) &&
            (if String.length body <> 1207 then (Printf.printf "Http: Fail: Bad body length (%d)\n" (String.length body) ; false) else true)
        | Ok x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: err403_msg: got %s\n" (string_of_bitstring msg) ;
            false
        | Error _ ->
            Printf.printf "Http: Fail: Cannot unpack err403_msg\n" ;
            false) ;
*)
(*$R
    let post_msg = bitstring_of_string (file_content "tests/http.post") in
    assert_bool "unpack POST" (match Pdu.unpack post_msg with
        | Ok { Pdu.cmd = Request ("POST", "/nevrax/do_login.html") ;
               Pdu.headers = hs ;
               Pdu.body = "login=admin&password=admin&submit=Connexion&came_from=%2F" } ->
            (if List.length hs <> 12 then (Printf.printf "Http: Fail: bad header count\n" ; false) else true) &&
            (if headers_find "Connection" hs <> Some "keep-alive" then (Printf.printf "Http: Fail: Cannot find header\n" ; false) else true)
        | Ok x ->
            let msg = Pdu.pack x in
            Printf.printf "Http: Fail: http.post: got %s\n" (string_of_bitstring msg) ;
            false
        | Error _ ->
            Printf.printf "Http: Fail: Cannot unpack http.post\n" ;
            false)
*)
(*$R
    (* The messages a TRXtop receives from [segs], before and after the
       transport closes: *)
    let receive segs =
        let t = TRXtop.make () and got = ref [] in
        TRXtop.set_recv t (fun r -> got := r :: !got) ;
        List.iter (fun s -> TRXtop.rx t (bitstring_of_string s)) segs ;
        let before = List.rev !got in
        got := [] ;
        TRXtop.rx t empty_bitstring ;
        before, List.rev !got in
    let split n str =
        let rec aux prev i =
            if i >= String.length str then List.rev prev
            else aux (String.sub str i (min n (String.length str - i)) :: prev) (i + n) in
        aux [] 0 in
    let body_lengths = List.filter_map (function
        | TRXtop.HttpMsg (msg, opened) -> Some (String.length msg.Pdu.body, opened)
        | TRXtop.HttpError _ -> None) in
    let real = file_content "tests/http.real"
    and chunked = file_content "tests/http.chunked" in
    let printer (a, b) =
        let p l = IO.to_string (List.print (Tuple2.print Int.print Bool.print)) l in
        p a ^", "^ p b in
    List.iter (fun n ->
        let before, after = receive (split n (real ^ chunked)) in
        assert_equal ~printer ([ 2175, true ; 0x1000+0xCEA+0x97C, true ], [])
            (body_lengths before, body_lengths after) ;
        assert_equal ~printer:string_of_int (List.length before) 2
    ) [ 1 ; 7 ; 100 ; 3000 ; 20000 ] ;
    (* A response with no length is delimited by the end of the transport: *)
    let before, after = receive [ "HTTP/1.1 200 OK\r\n\r\nabc" ; "de" ] in
    assert_equal ~printer ([], [ 5, false ]) (body_lengths before, body_lengths after)
*)
(*$R
    (* Once handed over, what follows the last message is no longer parsed: *)
    let t = TRXtop.make () and msgs = ref 0 and rest = ref [] in
    let f bits = rest := string_of_bitstring bits :: !rest in
    TRXtop.set_recv t (function
        | TRXtop.HttpMsg _ -> incr msgs ; TRXtop.hand_over t f
        | TRXtop.HttpError _ -> assert_failure "error") ;
    TRXtop.rx t (bitstring_of_string "GET / HTTP/1.1\r\n\r\nGET /x HTTP/1.1\r\n") ;
    TRXtop.rx t (bitstring_of_string "\r\n") ;
    TRXtop.rx t empty_bitstring ;
    assert_equal ~printer:string_of_int 1 !msgs ;
    assert_equal ~printer:dump [ "" ; "\r\n" ; "GET /x HTTP/1.1\r\n" ] !rest
*)
