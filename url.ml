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
(** Uniform Resource Locator *)
(**
  Most of this is taken from RFC1808.
  See: http://tools.ietf.org/html/rfc1808
*)
open Batteries
open Tools

let debug = false

(** The type for a (parsed) URL *)
type t = { scheme : string ; net_loc : string ; path : string ; params : string ; query : string }

let empty = { scheme = "" ; net_loc = "" ; path = "" ; params = "" ; query = "" }
let is_empty = function
    | { scheme = "" ; net_loc = "" ; path = "" ; params = "" ; query = "" } -> true
    | _ -> false

let is_in_set set c = try ignore (String.index set c); true with Not_found -> false

let reserved_chars = "!*'();:@&=+$,/?#[]"
let unreseved_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
let is_reserved = is_in_set reserved_chars
let is_unreserved = is_in_set unreseved_chars

(** [decode str] will decode every URL encoded char present in str *)
let decode s =
    let len = String.length s in
    let s' = String.create len in
    let rec aux o o' =
        if o < len then (
            let skip = ref 1 in
            if o < len - 2 && s.[o] = '%' then (
                skip := 3 ;
                let c =
                    try (int_of_hexchar s.[o+1] lsl 4) + int_of_hexchar s.[o+2]
                    with Invalid_argument _ -> Char.code '?' in
                s'.[o'] <- Char.chr c
            ) else (
                s'.[o'] <- s.[o]
            ) ;
            aux (o + !skip) (o'+1)
        ) else o' in
    let len' = aux 0 0 in
    let res = String.sub s' 0 len' in
    if debug then Printf.printf "Url: decode: '%s' -> '%s'\n" s res ;
    res

(*$= decode & ~printer:identity
    "came_from=/" (decode "came_from=%2F")
*)

let char_encode c =
    let c = Char.code c in
    Printf.sprintf "%%%X%X" (c lsr 4) (c land 0xf)

(** [encode str] will encode any reserved char present in str into the alternative %xx syntax. *)
let encode ?(reserved=true) s =
    let rep c =
        if is_unreserved c || (not reserved && is_reserved c) then String.of_char c
        else char_encode c in
    let res = String.replace_chars rep s in
    if debug then Printf.printf "Url: encode: '%s' -> '%s'\n" s res ;
    res

(*$= encode & ~printer:identity
    "a%20%2B%20b%20%3D%3D%2013%25%21" (encode "a + b == 13%!")
    "/glop/pas%20glop/" (encode ~reserved:false "/glop/pas glop/")
*)

(** [Url.of_string str] will return the {!Url.t} corresponding to the given [str] *)
let of_string ?(force_absolute=false) str =
    if debug then Printf.printf "Url: of_string: parse '%s'\n%!" str ;
    let str = decode str in
    (* If we insist this url must be absolute, then add the missing scheme *)
    let str =
        if force_absolute then (
            try ignore (String.index str ':') ; str (* not enough when host:port syntax is used *)
            with Not_found -> "http://" ^ str
        ) else str in
    (* Parsing the Fragment Identifier *)
    let str = try
            let crosshatch = String.index str '#' in
            String.sub str 0 crosshatch
        with Not_found -> str in
    (* Parsing the Scheme *)
    let is_alphanum c = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') in
    let allowed_in_scheme c = is_alphanum c || c = '+' || c = '.' || c = '-' in
    let rec find_colon i =
        if i >= String.length str then raise Not_found ;
        let c = str.[i] in
        if i >= 1 && c = ':' then i
        else if not (allowed_in_scheme c) then raise Not_found
        else find_colon (i+1) in
    let scheme, str = try
            let colonpos = find_colon 0 in
            String.sub str 0 colonpos,
            String.lchop ~n:(colonpos+1) str
        with Not_found -> "", str in
    (* Parsing the Network Location/Login *)
    let net_loc, str =
        if String.length str >= 2 && str.[0] = '/' && str.[1] = '/' then (
            let end_of_netloc = try string_find_first ~from:2 (fun c -> c = '/' || c = '?') str
                                with Not_found -> String.length str in
            String.sub str 2 (end_of_netloc-2), String.lchop ~n:end_of_netloc str
        ) else "", str in
    (* Parsing the Query Information *)
    let query, str = try
            let qmpos = String.index str '?' in
            String.lchop ~n:(qmpos+1) str, String.sub str 0 qmpos
        with Not_found -> "", str in
    (* Parsing the Parameters *)
    let params, str = try
            let scpos = String.index str ';' in
            String.lchop ~n:(scpos+1) str, String.sub str 0 scpos
        with Not_found -> "", str in
    (* Parsing the Path *)
    let path = str in
    { scheme  = String.lowercase scheme ;
      net_loc = String.lowercase net_loc ;
      path    = path ;
      params  = params ;
      query   = query }

(*$= of_string & ~printer:dump
    { scheme = "http" ; net_loc = "www.google.com" ; path = "/search" ; params = "" ; query = "ocaml" } \
        (of_string "http://www.google.com/search?ocaml")
    { scheme = "" ; net_loc = "" ; path = "/search" ; params = "" ; query = "" } \
        (of_string "/search?")
    { scheme = "" ; net_loc = "" ; path = "../../rel" ; params = "" ; query = "yo" } \
        (of_string "../../rel?yo#anchor")
    { scheme = "http" ; net_loc = "bla.com" ; path = "" ; params = "" ; query = "" } \
        (of_string ~force_absolute:true "bla.com")
    { scheme = "http" ; net_loc = "www.google.com" ; path = "" ; params = "" ; query = "" } \
        (of_string "http://www.google.com")
*)
(* Notice: on that last test we had no path. Thus absolute url will depend on the base *)

(** the opposite of of_string *)
let to_string url =
    Printf.sprintf "%s%s%s%s%s%s%s%s%s"
        url.scheme (if url.scheme <> "" then "://" else "")
        (encode ~reserved:false url.net_loc)
        (if url.path <> "" && url.path.[0] <> '/' then "/" else "")
        (encode ~reserved:false url.path)
        (if url.params <> "" then ";" else "") (encode url.params)
        (if url.query <> "" then "?" else "") (encode url.query)

let dotslash_re = Str.regexp "\\(^\\|/\\)\\./"
let updir_re = Str.regexp "\\(^\\|/\\)\\([^/]+\\)/\\.\\.\\/"

(** [resolve base url] will return the absolute version of [url], given it's relative to [base]. *)
let resolve base url =
    let aux base url =
        if is_empty base then (
            if url.path = "" || url.path.[0] != '/' then { url with path = "/"^url.path }
            else  url
        ) else if is_empty url then base
        else if url.scheme <> "" then url
        else if url.net_loc <> "" then { url with scheme = base.scheme }
        else if url.path <> "" && url.path.[0] = '/' then { url with scheme = base.scheme ; net_loc = base.net_loc }
        else if url.path = "" then (
            if url.params <> "" then { url with scheme = base.scheme ; net_loc = base.net_loc ; path = base.path }
            else if url.query <> "" then { base with query = url.query }
            else base (* should not happen *)
        ) else ( (* we have a relative url.path *)
            let u_path = try
                    let righmost_slash = String.rindex base.path '/' in
                    (String.sub base.path 0 (righmost_slash+1)) ^ url.path
                with Not_found -> url.path in
            (* Replace ^./ by / *)
            let u_path =
                let rec aux s =
                    if String.starts_with s "./" then aux (String.lchop ~n:2 s) else s in
                aux u_path in
            (* we wrap Str.global_substitute for two reasons :
                - we don't want our callback to be passed the whole string but the matching part (the two actually)
                - we want to substitute even in the substituted segment, ie. retry until the string is no more changed *)
            let rec really_global_substitute re f s =
                let changed = ref false in
                let s' = Str.global_substitute re (fun s ->
                    let m = Str.matched_string s in
                    let m' = f s m in
                    if m' != m then changed := true ;
                    m') s in
                if not !changed then s' else really_global_substitute re f s' in
            (* Remove all other "./" *)
            let u_path = really_global_substitute dotslash_re (fun _ m ->
                let r = if String.starts_with m "/" then "/" else "" in
                if debug then Printf.printf "Url: substituting '%s' with '%s'\n" m r ;
                r) u_path in
            (* Remove ending . (if it's a complete path segment *)
            let u_path =
                if u_path = "." then ""
                else if String.ends_with u_path "/." then String.rchop u_path
                else u_path in
            (* removes "path/../" *)
            let u_path = really_global_substitute updir_re (fun s m ->
                if debug then Printf.printf "Url: substituting '%s', which \\2 = '%s' ?\n" m (Str.matched_group 2 s) ;
                if Str.matched_group 2 s = ".." then (
                    if debug then Printf.printf "Url:...no!\n" ;
                    m
                ) else if String.starts_with m "/" then (
                    if debug then Printf.printf "Url:...replace with /\n" ;
                    "/"
                ) else (
                    if debug then Printf.printf "Url:...replace with nothing\n" ;
                    ""
                )) u_path in
            (* removes final "path/.." *)
            let u_path =
                let rec aux s =
                    if String.ends_with s "/.." && String.length s > 3 then (
                        if debug then Printf.printf "Url: trim final path/.. from '%s'\n" s ;
                        let c = try (String.rindex_from s (String.length s - 4) '/') + 1 with Not_found -> 0 in
                        aux (String.sub s 0 c)
                    ) else s in
                aux u_path in
            (* done! *)
            { url with scheme = base.scheme ; net_loc = base.net_loc ; path = u_path }
        )
    in
    let res = aux base url in
    if debug then Printf.printf "Url: resolving %s in %s -> %s\n"
        (to_string url) (to_string base) (to_string res) ;
    res

(*$= resolve & ~printer:dump
    { scheme = "http" ; net_loc = "www.google.com" ; path = "/try" ; params = "" ; query = "" } \
        (resolve (of_string "http://www.google.com/search?ocaml") \
                 (of_string "try"))

    { scheme = "http" ; net_loc = "www.google.com" ; path = "/" ; params = "" ; query = "" } \
        ((* empty path is made absolute *) \
         resolve empty { scheme = "http" ; net_loc = "www.google.com" ; path = "" ; params = "" ; query = "" })

    { scheme = "http" ; net_loc = "www.ex.com:8080" ; path = "/" ; params = "" ; query = "" } \
        (resolve (of_string "http://www.google.com/search?ocaml") \
                 (of_string "http://www.ex.com:8080/"))

    { scheme = "http" ; net_loc = "www.amazon.ca" ; path = "" ; params = ""; query = "glop=pasglop" } \
        (resolve (of_string "http://www.google.com/search?ocaml") \
                 (of_string "http://www.amazon.ca?glop=pasglop"))

    { scheme = "http" ; net_loc = "www.amazon.ca" ; path = "/somepage" ; params = ""; query = "glop=pasglop" } \
        (resolve (of_string "http://www.amazon.ca/somepage") \
                 (of_string "?glop=pasglop"))

    { scheme = "http" ; net_loc = "www.amazon.ca" ; path = "" ; params = ""; query = "glop=pasglop" } \
        (resolve (of_string "http://www.amazon.ca") \
                 (of_string "?glop=pasglop"))
*)
(*$T resolve
    (* these tests are taken from RFC 1808 *) \
    let base = of_string "http://a/b/c/d;p?q#f" in \
    let test url_ exp_ = \
        let url = resolve base (of_string url_) and exp = of_string exp_ in \
        if url <> exp then ( \
            Printf.printf "Error: %s -> %s (expected: %s ie. %s)\n" url_ (to_string url) exp_ (to_string exp) ; \
            false \
        ) else true \
    in \
    test "g:h" "g:h" && \
    test "g" "http://a/b/c/g" && \
    test "./g" "http://a/b/c/g" && \
    test "g/" "http://a/b/c/g/" && \
    test "/g" "http://a/g" && \
    test "//g" "http://g" && \
    test "?y" "http://a/b/c/d;p?y" && \
    test "g?y" "http://a/b/c/g?y" && \
    test "g?y/./x" "http://a/b/c/g?y/./x" && \
    test "#s" "http://a/b/c/d;p?q#s" && \
    test "g#s" "http://a/b/c/g#s" && \
    test "g#s/./x" "http://a/b/c/g#s/./x" && \
    test "g?y#s" "http://a/b/c/g?y#s" && \
    test ";x" "http://a/b/c/d;x" && \
    test "g;x" "http://a/b/c/g;x" && \
    test "g;x?y#s" "http://a/b/c/g;x?y#s" && \
    test "." "http://a/b/c/" && \
    test "./" "http://a/b/c/" && \
    test ".." "http://a/b/" && \
    test "../" "http://a/b/" && \
    test "../g" "http://a/b/g" && \
    test "../.." "http://a/" && \
    test "../../" "http://a/" && \
    test "../../g" "http://a/g" && \
    (* abnormal examples *) \
    test "" "http://a/b/c/d;p?q#f" && \
    test "../../../g" "http://a/../g" && \
    test "../../../../g" "http://a/../../g" && \
    test "/./g" "http://a/./g" && \
    test "/../g" "http://a/../g" && \
    test "g." "http://a/b/c/g." && \
    test ".g" "http://a/b/c/.g" && \
    test "g.." "http://a/b/c/g.." && \
    test "..g" "http://a/b/c/..g" && \
    test "./../g" "http://a/b/g" && \
    test "./g/." "http://a/b/c/g/" && \
    test "g/./h" "http://a/b/c/g/h" && \
    test "g/../h" "http://a/b/c/h"
*)
