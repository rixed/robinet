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
(** A simple web browser.

 This simulates an HTTP browser, ie it can get pages (with all dependancies
 but without javascript execution of course), then return a list of available
 links from this page, and a dom-like representation so that the programmer can
 easily extract some informations (such as session ids) to forge next gets of
 a test plan (or use regex on content?).

*)
open Batteries
open Tools
open Http
open Html

let debug = false

(** {2 Browser} *)

type cookie = { name : string ; value : string ; domain : string ; path : string }

type vacant_cnx = { tcp : Tcp.TRX.tcp_trx ; http : TRXtop.t ; last_used : Clock.Time.t }

(** A browser is build from a host, and has a set of cookies and of connections. *)
type t = { host : Host.host_trx ;
           user_agent : string ;
           mutable cookies : cookie list ;
           (* We maintain a pool of unused cnx to some destination/port, so that
              we can reuse them if necessary. These are closed after some time,
              and we do not keep more than a given number (10, specifically) *)
           mutable vacant_cnxs : (Host.addr * Tcp.Port.t, vacant_cnx) Hashtbl.t ;
           max_vacant_cnx : int ;
           max_idle_cnx : Clock.Interval.t ;
           (* When it has been ordered to stop: *)
           mutable killed : bool }

let make ?(user_agent="RobiNet") ?(max_vacant_cnx=10) ?(max_idle_cnx=Clock.Interval.sec 15.) host =
    { host = host ;
      user_agent = user_agent ;
      cookies = [] ;
      vacant_cnxs = Hashtbl.create 7 ;
      max_vacant_cnx = max_vacant_cnx ;
      max_idle_cnx = max_idle_cnx ;
      killed = false }

(** {2 Cookies}

   Cookies (as of RFC 6265).
   Note: all our cookies are "session cookies", ie we keep them only in the browser memory. *)

let string_of_cookie { name = n ; value = v ; domain = d ; path = p } =
    Printf.sprintf "%s=%s ; Domain=%s ; Path=%s" n v d p

(* Returns true if d1 is within d2 (or equal). *)
let domain_matches str domain =
    str = domain ||
    let len = String.length domain in
    String.ends_with str domain &&
    str.[String.length str - len - 1] = '.' (* TODO: && str is not an IP address *)

(*$T domain_matches
    (domain_matches "foo.example.com" "example.com")
    (domain_matches "example.com" "example.com")
    (domain_matches ".example.com" "example.com")
    (not (domain_matches "example.com" "foo.example.com"))
    (not (domain_matches "foo.example.com" "foobar.com"))
*)

let path_matches request_path cookie_path =
    request_path = cookie_path ||
    let len = String.length cookie_path in
    String.starts_with request_path cookie_path && (
        cookie_path.[len-1] = '/' ||
        request_path.[len] = '/'
    )

(*$T path_matches
    (path_matches "/foo/bar/" "/foo/bar/")
    (path_matches "/foo/bar" "/foo/bar")
    (path_matches "/foo/bar" "/foo/")
    (path_matches "/foo/bar" "/foo")
    (path_matches "/foo/bar" "/")
    (path_matches "/" "/")
    (not (path_matches "/" "foo"))
    (not (path_matches "/foo/bar" "/baz"))
*)

let parse_cookie host path cookie_str : cookie option =
    let lchop_dot s = if String.starts_with s "." then String.lchop s else s in
    let parts = List.filter_map (fun s ->
        try
            let eq = String.index s '=' in
            Some (String.trim (String.sub s 0 eq), String.trim (String.lchop ~n:(eq+1) s))
        with Not_found | Invalid_argument _ ->
            None)
        (String.split_on_char ';' cookie_str) in
    match parts with
        | (name, value)::rest when name <> "" ->
            let domain = Option.default host (headers_find "Domain" rest)
            and path'  = Option.default path (headers_find "Path" rest) in
            if debug then Printf.printf "Browser: parsing cookie %s=%s, Domain=%s, Path=%s\n" name value domain path' ;
            if domain <> "" then
                Some { name = name ; value = value ;
                       domain = lchop_dot (String.lowercase domain) ;
                       path = if path' == "" || path'.[0] <> '/' then path else path' }
            else
                None
        | _ -> None

(*$= parse_cookie & ~printer:dump
    (Some { name = "SID" ; value = "31d4d96e407aad42" ; domain = "www.ex1.com" ; path = "/foo" }) \
        (parse_cookie "www.ex1.com" "/foo" "SID=31d4d96e407aad42")
    (Some { name = "SID" ; value = "31d4d96e407aad42" ; domain = "example.com" ; path = "/" }) \
        (parse_cookie "www.ex1.com" "/foo" "SID=31d4d96e407aad42; Path=/; Domain=example.com")
    (Some { name = "SID" ; value = "31d4d96e407aad42" ; domain = "www.ex1.com" ; path = "/" }) \
        (parse_cookie "www.ex1.com" "/foo" "SID=31d4d96e407aad42; Path=/; Secure; HttpOnly")
    (Some { name = "lang" ; value = "en-US" ; domain = "example.com" ; path = "/" }) \
        (parse_cookie "www.ex1.com" "/foo" "lang=en-US; Path=/; Domain=example.com")
    (Some { name = "lang" ; value = "en-US" ; domain = "www.ex1.com" ; path = "/foo" }) \
        (parse_cookie "www.ex1.com" "/foo" "lang=en-US; Expires=Wed, 09 Jun 2021 10:18:14 GMT")
    (Some { name = "lang" ; value = "" ; domain = "www.ex1.com" ; path = "/foo" }) \
        (parse_cookie "www.ex1.com" "/foo" "lang=; Expires=Sun, 06 Nov 1994 08:49:37 GMT")
*)

let cookie_dirname path =
    let len = String.length path in
    if len = 0 || path.[0] <> '/' then "/" else
    let last_slash = String.rindex path '/' in
    if last_slash = 0 then "/" else
    String.sub path 0 last_slash

(*$= cookie_dirname & ~printer:identity
    "/" (cookie_dirname "")
    "/" (cookie_dirname "/")
    "/" (cookie_dirname "/foo")
    "/foo" (cookie_dirname "/foo/")
    "/foo" (cookie_dirname "/foo/bar")
*)

(* returns nothing but stores the cookies in t *)
let store_cookies t host path headers =
    let path = cookie_dirname path in
    let store_cookie ({ name = n ; value = v ; domain = d ; path = p } as cookie) =
        if domain_matches host d then (
            if debug then Printf.printf "Browser: Storing cookie '%s'\n" (string_of_cookie cookie) ;
            t.cookies <- List.filter (fun c ->
                c.name <> n || c.domain <> d || c.path <> p) t.cookies ;
            (* TODO: use expiration date instead of value to remove cookies *)
            if v <> "" then t.cookies <- cookie :: t.cookies
        ) else if debug then Printf.printf "Browser: Skip cookie '%s' since domain %s does not match domain %s\n" (string_of_cookie cookie) d host ;
    in
    foreach ((headers_find_all "Set-Cookie" headers |> List.enum) //@
        (parse_cookie host path))
        store_cookie

(* returns a list of cookies to be sent *)
let cookies_to_sent t host path =
    List.filter (fun c ->
        domain_matches host c.domain &&
        path_matches path c.path)
        t.cookies

let cookie_string t host path =
    String.concat "; " (List.map (fun c ->
        Printf.sprintf "%s=%s" c.name c.value)
        (cookies_to_sent t host path))

(*$R
    let host = Host.make_static (Ip.Addr.of_dotted_string_exc "1.2.3.4") "test" in
    let t = make host in
    store_cookies t "www.example.com" "/" [ "Set-Cookie", "SID=31d4" ] ;
    assert_bool "retrieve cokie"
        (cookie_string t "www.example.com" "/" = "SID=31d4") ;

    store_cookies t "www.example2.com" "/" [ "Set-Cookie", "SID=31d4;Path=/; Domain=example2.com" ] ;
    assert_bool "retrieve cookie within domain"
        (cookie_string t "www.example2.com" "/" = "SID=31d4") ;

    store_cookies t "www.example3.com" "/" [ "Set-Cookie", "SID=31d4; Path=/; Secure; HttpOnly" ;
                                             "Set-Cookie", "lang=en-US; Path=/; Domain=example3.com" ] ;
    let str = cookie_string t "www.example3.com" "/" in
    assert_bool "retrieve cookie with params"
        (str = "SID=31d4; lang=en-US" || str = "lang=en-US; SID=31d4") ;

    store_cookies t "example3.com" "/" [ "Set-Cookie", "lang=; Expires=Sun, 06 Nov 1994 08:49:37 GMT" ] ;
    assert_bool "retrieve cookie despite deleting in another domain"
        (cookie_string t "www.example3.com" "/" = "SID=31d4")
*)

let message_get = Metric.Timed.make "Browser/Msg/Get" (* FIXME: instead of Get use request name *)
let per_status  = Hashtbl.create 11

(* Returns an unused HTTP.TRXtop * tcp TRX (and removes it from the pool *)
let find_vacant_cnx t addr port =
    match Hashtbl.find_option t.vacant_cnxs (addr, port) with
    | None -> None
    | Some x ->
        if debug then Printf.printf "Browser: (re)use a vaccant cnx\n" ;
        Hashtbl.remove t.vacant_cnxs (addr, port) ;
        Some x

let clean_vacant_cnxs t =
    let count = ref 0
    and now = Clock.now () in
    let age t = Clock.Time.sub now t in
    t.vacant_cnxs <- Hashtbl.filter (fun v ->
        incr count ;
        if v.tcp.Tcp.TRX.is_closed () then (
            if debug then Printf.printf "Browser: clean_vacant_cnxs: cleaning a closed trx\n" ;
            false
        ) else if !count > t.max_vacant_cnx || Clock.Interval.compare (age v.last_used) t.max_idle_cnx > 0 then (
            if debug then Printf.printf "Browser: clean_vacant_cnxs: making room\n" ;
            v.tcp.Tcp.TRX.close () ;
            false
        ) else true) t.vacant_cnxs

(* Place this cnx into the pool of vacant cnx *)
let make_vacant_cnx t tcp http addr port =
    clean_vacant_cnxs t ;
    Hashtbl.add t.vacant_cnxs (addr, port) { tcp ; http ; last_used = Clock.now () }

(* Takes an URL and an optional body and call the continuation with the obtained document *)
let rec request t ?(command="GET") ?(headers=[]) ?body url cont =
    let get_msg addr port cont =
        (* connect *)
        (* Use a pool of tcp cnx already established _and_not_used_by_any_thread_ *)
        (* FIXME: this should be a pool of Http.TRXtop (optionaly with Tcp if we can't close the Tcp cnx in any other way) DONE? *)
        if debug then Printf.printf "Browser: connecting to addr %s\n" (Host.string_of_addr addr) ;
        let with_http_cnx = function
        | None -> cont None
        | Some (http, tcp) ->
            TRXtop.set_recv http (fun msg ->
                TRXtop.set_recv http ignore ; (* we only want to trigger once *)
                cont (Some (msg, http, tcp))) ;
            (* now that the receive function is ready, send the query *)
            let path = url.Url.path^url.Url.params^url.Url.query in
            let add_headers n v hs = if headers_find n headers = None then (n, v)::hs else hs in
            let headers = add_headers "User-Agent" t.user_agent headers in
            let headers = add_headers "Host" url.Url.net_loc headers in
            let headers = add_headers "Connection" "Keep-Alive" headers in
            let headers = add_headers "Accept" "*/*" headers in
            let headers =
                let cookie_str = cookie_string t url.Url.net_loc url.Url.path in
                if cookie_str <> "" then (
                    if debug then Printf.printf "Browser: sent cookies: %s for get %s\n" cookie_str path ;
                    ("Cookie", cookie_str)::headers
                ) else headers in
            let headers = match body with
                | None -> headers
                | Some b -> ["Content-Length", string_of_int (String.length b)] @ headers
            in
            Pdu.make_request command path ?body headers |>
            TRXtop.tx http in
        match find_vacant_cnx t addr port with
            | None ->
                if debug then Printf.printf "Browser: establishing new cnx to %s\n" (Host.string_of_addr addr) ;
                let http = TRXtop.make () in
                t.host.Host.tcp_connect addr port (function
                | None -> cont None
                | Some tcp ->
                    ignore ((TRXtop.rx http) <-= tcp.Tcp.TRX.trx) ;
                    TRXtop.set_emit http (tx tcp.Tcp.TRX.trx) ;
                    with_http_cnx (Some (http, tcp)))
            | Some v ->
                with_http_cnx (Some (v.http, v.tcp)) in
    if url.Url.scheme <> "http" then (
        Printf.printf "Browser: bad scheme: %s" (Url.to_string url)
    ) else (
        let get_start = Metric.Timed.start message_get in
        let addr, port =
            (* Try to use the port present in the URL *)
            try let n = String.index url.Url.net_loc ':' in
                Host.Name (String.sub url.Url.net_loc 0 n),
                String.lchop ~n:(n+1) url.Url.net_loc |>
                int_of_string |> Tcp.Port.o
            with _ ->
                Host.Name url.Url.net_loc, Tcp.Port.o 80 in
        get_msg addr port (function
        | None -> cont None
        | Some (msg, http, tcp) ->
            Metric.Timed.stop message_get get_start (Url.to_string url) ;
            match msg with
                | TRXtop.HttpError x ->
                    if debug then Printf.printf "Browser: got error %s\n%!" x ;
                    tcp.Tcp.TRX.close () ;
                    cont None
                | TRXtop.HttpMsg (pdu, opened) ->
                    (* Close the TCP cnx if we are done with it, or relieve it *)
                    if opened && not (must_close_cnx pdu.Pdu.headers) then (
                        make_vacant_cnx t tcp http addr port ;
                    ) else (
                        if debug then Printf.printf "Browser: closing the Tcp cnx\n%!" ;
                        tcp.Tcp.TRX.close ()
                    ) ;
                    (* update Get metric *)
                    (match pdu with
                        | { Pdu.cmd = Status s ; _ } ->
                            let ev = hash_find_or_insert per_status s (fun () ->
                                Metric.Atomic.make ("Browser/Get."^(string_of_int s))) in
                            Metric.Atomic.fire ev
                        | _ -> ()) ;
                    (* store cookies from any response *)
                    (match pdu with
                        | { Pdu.cmd = Status _ ; Pdu.headers = headers ; _ } ->
                            store_cookies t url.Url.net_loc url.Url.path headers
                        | _ -> ()) ;
                    (* handle HTTP errors, redirections, etc... *)
                    (match pdu with
                        | { Pdu.cmd = Status 301 ; Pdu.headers = headers ; _ }
                        | { Pdu.cmd = Status 302 ; Pdu.headers = headers ; _ } ->
                            if debug then Printf.printf "Browser: page %s moved!\n" (Url.to_string url) ;
                            (match headers_find "Location" headers with
                                | Some location ->
                                    let url' = Url.resolve url (Url.of_string location) in
                                    if url' <> url then request t ~command:"GET" url' cont (* FIXME: better handling of redirection loops *) (* FIXME: check we are supposed to go from POST to GET *)
                                    else cont None
                                | None -> cont None)
                        | { Pdu.cmd = Status 200 ; Pdu.body = body ; Pdu.headers = headers } ->
                            if debug then Printf.printf "Browser: Got HTTP 200 Ok for %s\n%!" (Url.to_string url) ;
                            cont (Some (headers, body))
                        | _ ->
                            if debug then Printf.printf "Browser: Cannot get %s\n%!" (Url.to_string url) ;
                            cont None))
    )

(* Takes an URL and returns headers and body *)
let get t ?headers url cont =
    if debug then Printf.printf "Browser: get %s\n%!" (Url.to_string url) ;
    request t ?headers url cont

let post t ?(headers=[]) url vars cont =
    if debug then Printf.printf "Browser: post %s\n%!" (Url.to_string url) ;
    let headers = [ "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8" ] @ headers in
    let body = List.map (fun (n, v) ->
                            (Http.post_encode n)^"="^(Http.post_encode v))
                        vars |>
               String.concat "&" in
    request t ~command:"POST" ~body ~headers url cont

let spider t max_depth start =
    let fetched = Hashtbl.create 100 in
    let rec aux max_depth url =
        if not t.killed then (
            if debug then Printf.printf "Browser: spider: fetching %s with max_depth %d\n%!" (Url.to_string url) max_depth ;
            Hashtbl.add fetched url true ;
            get t url (function
            | None -> ()
            | Some (headers, body) ->
                if max_depth > 1 then (
                    let content_type = headers_find "Content-type" headers in
                    if (match content_type with None -> true | Some str -> String.exists (String.lowercase str) "text/html") then (
                        match Html.parse body with
                        | Some tree ->
                            extract_links ~default_base:url headers tree //
                                (Hashtbl.mem fetched %> not) |>
                                List.of_enum |>
                                List.iter (fun url ->
                                    Clock.asap (aux (max_depth-1)) url)
                        | None ->
                            if debug then Printf.printf "Browser: Cannot parse HTML from %s\n" (Url.to_string url)
                    )
                )
            )
        ) in
    aux max_depth (Url.resolve Url.empty start) ;
    if debug then Printf.printf "Browser: done spiding web\n"

let user t ?pause max_depth start =
    let fetched = Hashtbl.create 100 in
    let rec aux max_depth url =
        if not t.killed then (
            if debug then Printf.printf "Browser: user: fetching %s with max_depth %d\n%!" (Url.to_string url) max_depth ;
            Hashtbl.add fetched url true ;
            get t url (function
            | None -> ()
            | Some (headers, body) ->
                if max_depth > 1 then (
                    let content_type = headers_find "Content-type" headers in
                    if (match content_type with None -> true | Some str -> String.exists (String.lowercase str) "text/html") then (
                        (* Fetch eveything a browser would fetch at once (images, etc) *)
                        extract_links_simple ~same_page:true ~default_base:url headers body //
                            (Hashtbl.mem fetched %> not) |>
                            List.of_enum |>
                            tap (fun l -> if debug then Printf.printf "Browser: will iter on %d urls\n" (List.length l)) |>
                            List.iter (fun url' ->
                                if debug then Printf.printf "Browser: user: fetching %s for %s\n" (Url.to_string url') (Url.to_string url) ;
                                Clock.asap (aux (max_depth-1)) url') ;
                        (* fetch sequentially, depth first, a links *)
                        (* TODO: get only one URL amongst the possible links but keep all
                         * encountered URL in this set of possible next links. Also,
                         * sleep in between 2 clicks according to the read_time
                         * distribution. *)
                        let urls = extract_links_simple ~same_page:false ~default_base:url headers body //
                            (Hashtbl.mem fetched %> not) in
                        let rec fetch_next () =
                            match Enum.get urls with
                            | None -> ()
                            | Some url' ->
                                let d = match pause with
                                    | None -> 0.
                                    | Some t -> Random.float (2.*.t) in
                                Clock.delay (Clock.Interval.o d) (fun () ->
                                    if debug then Printf.printf "Browser: user: fetching %s after %s\n" (Url.to_string url') (Url.to_string url) ;
                                    aux (max_depth-1) url' ;
                                    fetch_next ()) () in
                        fetch_next () ;
                        if debug then Printf.printf "Browser: done with %s\n" (Url.to_string url)
                    )
                )
            )
        ) in
    aux max_depth (Url.resolve Url.empty start) ;
    if debug then Printf.printf "Browser: done using browser.\n%!"

let kill t k =
    t.killed <- true ;
    (* effective immediately: *)
    k ()

module Plan =
struct
    type form_input = { url : Str.regexp ; form : Str.regexp ; input : Str.regexp }

    type t = { form_values : (form_input * string) array ;
               next_hop : (Str.regexp * (Str.regexp * float) array) array ;
               check_presence : (Str.regexp * (Str.regexp array)) array ;
               check_absence  : (Str.regexp * (Str.regexp array)) array ;
               allowed_urls   : Str.regexp array ;
               forbidden_urls : Str.regexp array } (* checked only if not allowed *)
end
