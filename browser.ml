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

 This simulates an HTTP browser, ie it can get pages (with all dependancies
 but without javascript execution of course), then return a list of available
 links from this page, and a dom-like representation so that the programmer can
 easily extract some informations (such as session ids) to forge next gets of
 a test plan (or use regex on content?).

*)
open Batteries
open Bitstring
open Tools
open Http
open Lwt
open Html

let debug = false

type cookie = { name : string ; value : string ; domain : string ; path : string }

type vacant_cnx = { trx : Tcp.TRX.tcp_trx ; last_used : Clock.Time.t }

type t = { host : Host.host_trx ;
           user_agent : string ;
           mutable cookies : cookie list ;
           (* We maintain a pool of unused cnx to some destination/port, so that
              we can reuse them if necessary. These are closed after some time,
              and we do not keep more than a given number (10, specifically) *)
           mutable vacant_cnxs : (Host.addr * Tcp.Port.t, vacant_cnx) Hashtbl.t ;
           max_vacant_cnx : int ; max_idle_cnx : Clock.Interval.t }

let make ?(user_agent="RobiNet") ?(max_vacant_cnx=10) ?(max_idle_cnx=Clock.Interval.sec 15.) host =
    { host = host ;
      user_agent = user_agent ;
      cookies = [] ;
      vacant_cnxs = Hashtbl.create 7 ;
      max_vacant_cnx = max_vacant_cnx ;
      max_idle_cnx = max_idle_cnx }

type page = { links : string list ; total_size : int }

(* Cookies (as of RFC 6265)
   Note: all our cookies are "session cookies", ie we keep them only in the browser memory. *)

let string_of_cookie { name = n ; value = v ; domain = d ; path = p } =
    Printf.sprintf "%s=%s ; Domain=%s ; Path=%s" n v d p

(* Returns true if d1 is within d2 (or equal). *)
let domain_matches str domain =
    str = domain ||
    let len = String.length domain in
    String.ends_with str domain &&
    str.[String.length str - len - 1] = '.' (* TODO: && str is not an IP address *)

let path_matches request_path cookie_path =
    request_path = cookie_path ||
    let len = String.length cookie_path in
    String.starts_with request_path cookie_path && (
        cookie_path.[len-1] = '/' ||
        request_path.[len] = '/'
    )

let parse_cookie host path cookie_str : cookie option =
    let lchop_dot s = if String.starts_with s "." then String.lchop s else s in
    let parts = List.filter_map (fun s ->
        try
            let eq = String.index s '=' in
            Some (String.trim (String.sub s 0 eq), String.trim (String.lchop ~n:(eq+1) s))
        with Not_found | Invalid_argument _ ->
            None)
        (String.nsplit cookie_str ";") in
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

let cookie_dirname path =
    let len = String.length path in
    if len = 0 || path.[0] <> '/' then "/" else
    let last_slash = String.rindex path '/' in
    if last_slash = 0 then "/" else
    String.sub path 0 last_slash

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

let cookie_check () =
    (parse_cookie "www.ex1.com" "/foo" "SID=31d4d96e407aad42" =
        Some { name = "SID" ; value = "31d4d96e407aad42" ; domain = "www.ex1.com" ; path = "/foo" }) &&
    (parse_cookie "www.ex1.com" "/foo" "SID=31d4d96e407aad42; Path=/; Domain=example.com" =
        Some { name = "SID" ; value = "31d4d96e407aad42" ; domain = "example.com" ; path = "/" }) &&
    (parse_cookie "www.ex1.com" "/foo" "SID=31d4d96e407aad42; Path=/; Secure; HttpOnly" =
        Some { name = "SID" ; value = "31d4d96e407aad42" ; domain = "www.ex1.com" ; path = "/" }) &&
    (parse_cookie "www.ex1.com" "/foo" "lang=en-US; Path=/; Domain=example.com" =
        Some { name = "lang" ; value = "en-US" ; domain = "example.com" ; path = "/" }) &&
    (parse_cookie "www.ex1.com" "/foo" "lang=en-US; Expires=Wed, 09 Jun 2021 10:18:14 GMT" =
        Some { name = "lang" ; value = "en-US" ; domain = "www.ex1.com" ; path = "/foo" }) &&
    (parse_cookie "www.ex1.com" "/foo" "lang=; Expires=Sun, 06 Nov 1994 08:49:37 GMT" =
        Some { name = "lang" ; value = "" ; domain = "www.ex1.com" ; path = "/foo" }) &&
    (domain_matches "foo.example.com" "example.com") &&
    (domain_matches "example.com" "example.com") &&
    (domain_matches ".example.com" "example.com") &&
    (not (domain_matches "example.com" "foo.example.com")) &&
    (not (domain_matches "foo.example.com" "foobar.com")) &&
    (path_matches "/foo/bar/" "/foo/bar/") &&
    (path_matches "/foo/bar" "/foo/bar") &&
    (path_matches "/foo/bar" "/foo/") &&
    (path_matches "/foo/bar" "/foo") &&
    (path_matches "/foo/bar" "/") &&
    (path_matches "/" "/") &&
    (not (path_matches "/" "foo")) &&
    (not (path_matches "/foo/bar" "/baz")) &&
    (cookie_dirname "" = "/") &&
    (cookie_dirname "/" = "/") &&
    (cookie_dirname "/foo" = "/") &&
    (cookie_dirname "/foo/" = "/foo") &&
    (cookie_dirname "/foo/bar" = "/foo") &&
    let host = Host.make_static "test"
                    (Eth.Addr.of_string "12:34:56:78:90:ab") (Ip.Addr.of_string "1.2.3.4") in
    let t = make host in
    (store_cookies t "www.example.com" "/"
        [ "Set-Cookie", "SID=31d4" ] ;
    cookie_string t "www.example.com" "/" = "SID=31d4") &&
    (store_cookies t "www.example2.com" "/"
        [ "Set-Cookie", "SID=31d4; Path=/; Domain=example2.com" ] ;
    cookie_string t "www.example2.com" "/" = "SID=31d4") &&
    (store_cookies t "www.example3.com" "/"
        [ "Set-Cookie", "SID=31d4; Path=/; Secure; HttpOnly" ;
          "Set-Cookie", "lang=en-US; Path=/; Domain=example3.com" ] ;
    let str = cookie_string t "www.example3.com" "/" in
        str = "SID=31d4; lang=en-US" || str = "lang=en-US; SID=31d4"
    ) &&
    (store_cookies t "example3.com" "/"
        [ "Set-Cookie", "lang=; Expires=Sun, 06 Nov 1994 08:49:37 GMT" ] ;
    cookie_string t "www.example3.com" "/" = "SID=31d4")


let message_get = Metric.Timed.make "Browser/Msg/Get" (* FIXME: instead of Get use request name *)
let per_status  = Hashtbl.create 11

(* Returns an unused tcp TRX (and removes it from the pool *)
let find_vacant_cnx t addr port =
    match Hashtbl.find_option t.vacant_cnxs (addr, port) with
    | None -> None
    | Some cnx ->
        Hashtbl.remove t.vacant_cnxs (addr, port) ;
        Some cnx.trx

let clean_vacant_cnxs t =
    let count = ref 0
    and now = Clock.now () in
    let age t = Clock.Time.sub now t in
    t.vacant_cnxs <- Hashtbl.filter (fun v ->
        incr count ;
        if v.trx.Tcp.TRX.is_closed () then (
            if debug then Printf.printf "Browser: clean_vacant_cnxs: cleaning a closed trx\n" ;
            false
        ) else if !count > t.max_vacant_cnx || Clock.Interval.compare (age v.last_used) t.max_idle_cnx > 0 then (
            if debug then Printf.printf "Browser: clean_vacant_cnxs: making room\n" ;
            v.trx.Tcp.TRX.close () ;
            false
        ) else true) t.vacant_cnxs

(* Place this cnx into the pool of vacant cnx *)
let make_vacant_cnx t tcp addr port =
    clean_vacant_cnxs t ;
    Hashtbl.add t.vacant_cnxs (addr, port) { trx = tcp ; last_used = Clock.now () }

(* Takes an URL and an optional body and return the associated optional document *)
let rec request t ?(command="GET") ?(headers=[]) ?body url =
    let must_close_cnx headers =
        match headers_find "Connection" headers with
        | Some str when String.icompare str "close" = 0 -> true
        | _ -> false in
    let get_msg addr port =
        (* connect *)
        (* Use a pool of tcp cnx already established _and_not_used_by_any_thread_ *)
        (* FIXME: this should be a pool of Http.TRXtop (optionaly with Tcp if we can't close the Tcp cnx in any other way) *)
        lwt tcp = match find_vacant_cnx t addr port with
            | None ->
                t.host.Host.tcp_connect addr port
            | Some tcp ->
                Lwt.return tcp in
        let http = TRXtop.make () in
        tcp.Tcp.TRX.trx.set_recv (TRXtop.rx http) ;
        TRXtop.set_emit http tcp.Tcp.TRX.trx.tx ;
        let waiter, wakener = wait () in
        TRXtop.set_recv http (fun msg ->
            TRXtop.set_recv http ignore ; (* we only want to trigger once *)
            wakeup wakener (msg, tcp)) ;
        (* send query *)
        let path = url.Url.path^url.Url.params^url.Url.query in
        let headers = [ "User-Agent", t.user_agent ;
                        "Host", url.Url.net_loc ;
                        "Connection", "Keep-Alive" ;
                        "Accept", "*/*" ] @ headers in
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
        let pdu = Pdu.make_request command path ?body headers in
        TRXtop.tx http pdu ;
        (* wait for response *)
        waiter in
    if url.Url.scheme <> "http" then (
        return (err (Printf.sprintf "Browser: bad scheme: %s" (Url.to_string url)))
    ) else (
        let get_start = Metric.Timed.start message_get in
        let addr = Host.Name url.Url.net_loc
        and port = Tcp.Port.o 80 in
        Lwt.catch (fun () ->
            lwt msg, tcp = get_msg addr port in
            Metric.Timed.stop message_get get_start (Url.to_string url) ;
            (match msg with
                | TRXtop.HttpError x ->
                    if debug then Printf.printf "Browser: got error %s\n%!" x ;
                    tcp.Tcp.TRX.close () ;
                    return None
                | TRXtop.HttpMsg (pdu, opened) ->
                    (* Close the TCP cnx if we are done with it, or relieve it *)
                    if opened && not (must_close_cnx pdu.Pdu.headers) then (
                        make_vacant_cnx t tcp addr port ;
                    ) else (
                        if debug then Printf.printf "Browser: close the Tcp cnx\n%!" ;
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
                                    if url' <> url then request t ~command:"GET" url' (* FIXME: better handling of redirection loops *) (* FIXME: check we are supposed to go from POST to GET *)
                                    else return None
                                | None -> return None)
                        | { Pdu.cmd = Status 200 ; Pdu.body = body ; Pdu.headers = headers } ->
                            if debug then Printf.printf "Browser: Got HTTP 200 Ok for %s\n%!" (Url.to_string url) ;
                            return (Some (headers, body))
                        | _ ->
                            if debug then Printf.printf "Browser: Cannot get %s\n%!" (Url.to_string url) ;
                            return None)))
            (fun _exn -> return None)
    )

(* Takes an URL and returns headers and body *)
let get t ?headers url =
    if debug then Printf.printf "Browser: get %s\n%!" (Url.to_string url) ;
    request t ?headers url

let post t ?(headers=[]) url vars =
    if debug then Printf.printf "Browser: get %s\n%!" (Url.to_string url) ;
    let headers = [ "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8" ] @ headers in
    let body = List.map (fun (n, v) ->
                            (Http.post_encode n)^"="^(Http.post_encode v))
                        vars |>
               String.concat "&" in
    request t ~command:"POST" ~body ~headers url

let spider t max_depth start =
    let fetched = Hashtbl.create 100 in
    let rec aux max_depth url =
        if debug then Printf.printf "Browser: spider: fetching %s with max_depth %d\n%!" (Url.to_string url) max_depth ;
        Hashtbl.add fetched url true ;
        lwt doc = get t url in
        if max_depth > 1 && doc <> None then (
            let headers, body = Option.get doc in
            let content_type = headers_find "Content-type" headers in
            if (match content_type with None -> true | Some str -> String.exists (String.lowercase str) "text/html") then (
                match Html.parse body with
                | Some tree ->
                    extract_links ~default_base:url headers tree //
                        (Hashtbl.mem fetched |- not) |>
                        List.of_enum |>
                        Lwt_list.iter_p (aux (max_depth-1))
                | None ->
                    if debug then Printf.printf "Browser: Cannot parse HTML from %s\n" (Url.to_string url) ;
                    Lwt.return ()
            ) else return ()
        ) else return () in
    aux max_depth (Url.resolve Url.empty start)

let user t ?pause max_depth start =
    let fetched = Hashtbl.create 100 in
    let rec aux max_depth url =
        if debug then Printf.printf "Browser: spider: fetching %s with max_depth %d\n%!" (Url.to_string url) max_depth ;
        Hashtbl.add fetched url true ;
        lwt doc = get t url in
        if max_depth > 1 && doc <> None then (
            let headers, body = Option.get doc in
            let content_type = headers_find "Content-type" headers in
            if (match content_type with None -> true | Some str -> String.exists (String.lowercase str) "text/html") then (
                (* Fetch eveything a browser would fetch at once (images, etc) *)
                lwt _ = extract_links_simple ~same_page:true ~default_base:url headers body //
                    (Hashtbl.mem fetched |- not) |>
                    List.of_enum |>
                    tap (fun l -> if debug then Printf.printf "Browser: will iter_p on %d urls\n" (List.length l)) |>
                    Lwt_list.iter_p (fun url' ->
                        if debug then Printf.printf "Browser: spider: fetching %s for %s\n" (Url.to_string url') (Url.to_string url);
                        lwt _ = get t url' in
                        return ()) in
                (* fetch sequentially, depth first, a links *)
                lwt _ = extract_links_simple ~same_page:false ~default_base:url headers body //
                    (Hashtbl.mem fetched |- not) |>
                    List.of_enum |>
                    tap (fun l -> if debug then Printf.printf "Browser: will iter_s on %d urls\n" (List.length l)) |>
                    Lwt_list.iter_s (fun url' ->
                        lwt () = match pause with
                            | None -> Lwt.return ()
                            | Some t ->
                                let p = Clock.Interval.o (Random.float (2.*.t)) in
                                if debug then Printf.printf "Browser: Will pause for %s\n%!" (Clock.Interval.to_string p) ;
                                Clock.sleep p in
                        if debug then Printf.printf "Browser: spider: fetching %s after %s\n" (Url.to_string url') (Url.to_string url) ;
                        aux (max_depth-1) url') in
                if debug then Printf.printf "Browser: done with %s\n" (Url.to_string url) ;
                return ()
            ) else return ()
        ) else return () in
    aux max_depth (Url.resolve Url.empty start)

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

let check () =
    cookie_check ()

