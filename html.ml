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
  This handles html documents.
  For instance it can parse a body, compose a POST, etc...
*)
open Batteries
open Tools
open Http
open Peg

let debug = false

(* From bytes (char) to characters (char) *)

let bad_attr_chars = Metric.Atomic.make "Html/ParseError/attrChars"

let c2i c =
    if c >= '0' && c <= '9' then
        int_of_char c - int_of_char '0'
    else if c >= 'a' && c <= 'z' then
        int_of_char c - int_of_char 'a' + 10
    else if c >= 'A' && c <= 'Z' then
        int_of_char c - int_of_char 'A' + 10
    else error (Printf.sprintf "Cannot convert char '%c' to int" c)

let i2c i =
    if i >= 0 && i <= 9 then char_of_int (int_of_char '0' + i)
    else if i >= 10 && i <= 35 then char_of_int (int_of_char 'a' + i - 10)
    else error (Printf.sprintf "Cannot convert int '%d' to digit" i)

let digit base =
    map (cond (fun c ->
            (c >= '0' && c <= '9' && c < (char_of_int (int_of_char '0' + base))) ||
            (base > 10 && (
                (c >= 'a' && c < (char_of_int (int_of_char 'a' + (base - 10)))) ||
                (c >= 'A' && c < (char_of_int (int_of_char 'A' + (base - 10))))
            )))) c2i

let number base =
    map (several (digit base)) (fun ds ->
        let rec aux n = function
            | [] -> n
            | d :: d' ->
                aux (d + n*base) d' in
        aux 0 ds)

let decimal_number () = number 10
let hexadecimal_number () = number 16

let num_char_ref_dec () =
    seqf [ none (item '&') ;
           none (item '#') ;
           some (decimal_number ()) ;
           none (item ';') ]

let num_char_ref_hex () =
    seqf [ none (item '&') ;
           none (item '#') ;
           none (either [ item 'x' ; item 'X' ]) ;
           some (hexadecimal_number ()) ;
           none (item ';') ]

let num_char_ref () =
    map (either [ num_char_ref_dec () ; num_char_ref_hex () ]) (function
        | [n] -> `CharRef n
        | _ -> should_not_happen ())

let char_entity_ref () =
    map (seqf [ none (item '&') ;
                some (repeat ~min:2 ~max:9 (cond (fun c -> c <> ';'))) ;
                none (item ';') ]) (function
        | [cs] -> `EntityRef (String.of_list cs)
        | _ -> should_not_happen ())

let num_printer oc d = Printf.fprintf oc "%d" d
let rec var_printer oc = function
    | `CharRef d          -> Printf.fprintf oc "CharRef %d" d
    | `EntityRef s        -> Printf.fprintf oc "EntityRef %s" s
    | `Attr (n, v)        -> Printf.fprintf oc "Attr (%s, %s)" n v
    | `Tag (n, attrs)     -> Printf.fprintf oc "Tag (%s, %a)" n (List.print var_printer) attrs
    | `OpenTag (n, attrs) -> Printf.fprintf oc "OpenTag (%s, %a)" n (List.print var_printer) attrs
    | `CloseTag n         -> Printf.fprintf oc "CloseTag %s" n
    | `Blank              -> Printf.fprintf oc "Blank"
    | `Content            -> Printf.fprintf oc "Content"
let check_results res_printer p bs m expected =
    let print_res oc = function
        | Wait -> Printf.fprintf oc "Wait"
        | Fail -> Printf.fprintf oc "Fail"
        | Res (res, rem) -> Printf.fprintf oc "Res (%a, \"%s\")"
                                res_printer res (String.of_list rem) in
    let res = p (String.to_list bs) m in
    let ok = res = expected in
    Printf.printf "Html: \"%s\" -> %a " bs print_res res ;
    if ok then Printf.printf "OK\n"
    else Printf.printf "FAIL! (expecting %a)\n" print_res expected ;
    ok

let check_chars () =
    assert (c2i '5' = 5) ;
    assert (i2c 5 = '5') ;
    assert (c2i 'f' = 15) ;
    assert (i2c 15 = 'f') ;
    assert (c2i 'F' = 15) ;
    let p = number 16 in
    check_results num_printer p "13ed0XY" false (Res (0x13ed0, ['X' ; 'Y'])) &&
    let p = num_char_ref () in
    check_results var_printer p "&#229;" true (Res (`CharRef 229, [])) &&
    check_results var_printer p "&#xE5;" true (Res (`CharRef 0xe5, [])) &&
    check_results var_printer p "&#Xe5;" true (Res (`CharRef 0xe5, [])) &&
    check_results var_printer p "&#1048;" true (Res (`CharRef 1048, [])) &&
    check_results var_printer p "&#x6C34;XY" false (Res (`CharRef 0x6c34, ['X' ; 'Y'])) &&
    let p = char_entity_ref () in
    check_results var_printer p "&lt;XY" false (Res (`EntityRef "lt", ['X' ; 'Y']))

let ext_alphabetic () =
    either [ item '_' ; item '-' ; item ':' ; item '.' ;
             (* not legal but yet often encountered *)
             map (item '#') (fun x -> Metric.Atomic.fire bad_attr_chars ; x) ]

let first_char_name () =
    either [ alphabetic () ; ext_alphabetic () ;
             (* illegal but often encountered in the wild *)
             map (numeric ()) (fun x -> Metric.Atomic.fire bad_attr_chars ; x) ]

let ext_alphanum () =
    either [ first_char_name () ; numeric () ;
             (* illegal but often encountered *)
             map (item '%') (fun x -> Metric.Atomic.fire bad_attr_chars ; x) ]

let name () =
    map (seq [ map (first_char_name ()) (fun c -> [c]) ; many (ext_alphanum ()) ]) (fun ll ->
        String.of_list (List.flatten ll))

let value q =
    map (many (cond (fun c -> c <> q && c <> '>'))) String.of_list
let quoted_value_with q =   (* Notice that the attribute values are stripped *)
    map (seqf [ none (item q) ;
                none (many (blank ())) ;
                some (value q) ;
                none (many (blank ())) ;
                none (item q) ]) (function
        | [n] -> n
        | _ -> should_not_happen ())
let unquoted_value () =
    map (seqf [ none (many (blank ())) ;
                some (name ()) ]) (function
        | [n] -> n
        | _ -> should_not_happen ())
let quoted_value () =
    either [ quoted_value_with '\'' ; quoted_value_with '"' ; unquoted_value () ]
let attr_with_value () =
    map (seqf [ some (name ()) ;
                none (many (blank ())) ;
                none (item '=') ;
                none (many (blank ())) ;
                some (quoted_value ()) ]) (function
        | [ n ; v ] -> `Attr (String.lowercase n, v)
        | _         -> should_not_happen ())
let attr_without_value () =
    map (name ()) (fun n -> `Attr (String.lowercase n, ""))
let attr () =
    either [ attr_with_value () ; attr_without_value () ]

let attr_seq () =
    many (map (seqf [ none (many (blank ())) ;
                      some (attr ()) ]) (function
                          | [ x ] -> x
                          | _ -> should_not_happen ()))

let autoclose_tag () =
    map (seqf [ none (item '<') ;
                none (many (blank ())) ;
                some (map (name ()) (fun n -> [`Tag (n, [])])) ;
                some (attr_seq ()) ;
                none (many (blank ())) ;
                none (item '/') ;
                none (item '>') ]) (function
                        | [ [`Tag (tagname, [])] ; attrs ] -> `Tag (String.lowercase tagname, attrs)
                        | _ -> should_not_happen ())

let open_tag () =
    map (seqf [ none (item '<') ;
                none (many (blank ())) ;
                some (map (name ()) (fun n -> [`Tag (n, [])])) ;
                some (attr_seq ()) ;
                none (many (blank ())) ;
                none (item '>') ]) (function
                        | [ [`Tag (tagname, [])] ; attrs ] -> `OpenTag (String.lowercase tagname, attrs)
                        | _ -> should_not_happen ())

let close_tag () =
    map (seqf [ none (item '<') ;
                none (item '/') ;
                none (many (blank ())) ;
                some (name ()) ;
                none (many (blank ())) ;
                none (item '>') ]) (function
                    | [ n ] -> `CloseTag (String.lowercase n)
                    | _ -> should_not_happen ())

let special_tag name =
    map (seqf [ none (item '<') ;
                none (many (blank ())) ;
                none (char_seq name) ;
                none (many (blank ())) ;
                some (attr_seq ()) ;
                none (many (blank ())) ;
                none (item '>') ;
                (* FIXME: allow for blanks between '</' and tag name *)
                none (upto ([ '<' ; '/' ] @ (String.to_list name))) ;
                none (many (blank ())) ;
                none (item '>') ]) (function
                        | [attrs] -> `Tag (name, attrs)
                        | _ -> should_not_happen ())

let tag () =
    either [ autoclose_tag () ; open_tag () ; close_tag () ]

let xml_decl () =
    map (seq [
        char_seq "<?xml" ;
        upto ['>'] ]) (fun _ -> `Blank)

let doctype () =
    map (seq [
        char_seq "<!doctype" ;
        upto ['>'] ]) (fun _ -> `Blank)

(* Note: maybe we should keep content and comment texts? *)
let comment () =
    map (seq [
        char_seq "<!--" ;
        (* FIXME: blanks must be allowed between "--" and ">" *)
        upto [ '-'; '-'; '>' ] ]) (fun _ -> `Blank)

let content () =
    map (several (cond (fun c -> c <> '<'))) (fun _ -> `Content)

let blanks () =
    map (several (blank ())) (fun _ -> `Blank)

let tag_seq () =
    map (seq [
        many (either [ blanks () ; comment () ; xml_decl () ; doctype () ]) ;
        (* for content between script and style tags, do not consider '<'
           as ending the content, but swallow eveything up to the next ending of this tag. *)
        many (either [ blanks () ; comment () ;
                       special_tag "script" ; special_tag "style" ;
                       tag () ; content () ]) ]) (function
            | [ _decls ; doc ] -> doc
            | _ -> should_not_happen ())

let check_parse () =
    let p = attr () in
    check_results var_printer p "attr=\"value\"" false (Res (`Attr ("attr", "value"), [])) &&
    let p = attr () in
    check_results var_printer p "attr" false (Res (`Attr ("attr", ""), [])) &&
    let p = tag () in
    check_results var_printer p "<name attr1='val\"ue1' attr2 = \"val'ue2\" attr3 />" true
        (Res (`Tag ("name", [`Attr ("attr1", "val\"ue1") ; `Attr ("attr2", "val'ue2") ; `Attr ("attr3", "")]), [])) &&
    check_results var_printer p "<NaMe attr1 attr2=value2>" true
        (Res (`OpenTag ("name", [`Attr ("attr1", "") ; `Attr ("attr2", "value2") ]), [])) &&
    check_results var_printer p "</Name>XY" false
        (Res (`CloseTag "name", ['X'; 'Y']))

let comply new_tag pending_tag =
    let constraints =
        let tag_in l = function
            | `OpenTag (t, _) when not (List.mem t l) -> false
            | `CloseTag t when not (List.mem t l) -> false
            | _ -> true in
        let is_empty = function `Blank -> true | _ -> false in
        let is_pcdata = function `Blank -> true | `Content -> true | _ -> false in
        let is_cdata x = is_pcdata x in (* ? *)
        let is_fontstyle x = tag_in ["tt"; "i"; "b"; "big"; "small"] x in
        let is_phrase x = tag_in ["em"; "strong"; "dfn"; "code"; "samp"; "kbd"; "var"; "cite"; "abbr"; "acronym"] x in
        let is_special x = tag_in ["a"; "img"; "object"; "br"; "script"; "map"; "q"; "sub"; "sup"; "span"; "bdo"] x in
        let is_formctrl x = tag_in ["input"; "select"; "textarea"; "label"; "button"] x in
        let is_inline x = is_pcdata x || is_fontstyle x || is_phrase x || is_special x || is_formctrl x in
        let is_heading x = tag_in ["h1"; "h2"; "h3"; "h4"; "h5"; "h6"] x in
        let is_list x = tag_in ["ul"; "ol"] x in
        let is_preformatted x = tag_in ["pre"] x in
        let is_block x = tag_in ["p"; "dl"; "div"; "noscript"; "blockquote"; "form"; "hr"; "table"; "fieldset"; "address"] x || is_heading x || is_list x || is_preformatted x in
        let is_flow x = is_block x || is_inline x in
        let is_tr x = tag_in ["tr"] x in
        let is_col x = tag_in ["col"] x in
        let is_bodyok x = is_block x || tag_in ["script"; "ins"; "del"] x in
        let is_head_content x = tag_in ["title"; "base"] x in
        let is_head_misc x = tag_in ["script"; "style"; "meta"; "link"; "object"] x in
        let is_headok x = is_head_content x || is_head_misc x in
        let is_html_content x = tag_in ["head"; "body"] x in
        let is_objectok x = is_flow x || tag_in ["param"] x in
        let is_blockquoteok x = is_block x || tag_in ["script"] x in
        let is_formok x = not (tag_in ["form"] x) && (is_block x || tag_in ["script"] x) in
        let is_labelok x = not (tag_in ["label"] x) && is_inline x in
        [ "tt", is_inline ; "i", is_inline ; "b", is_inline ; "big", is_inline ;
          "small", is_inline ; "em", is_inline ; "strong", is_inline ; "dfn", is_inline ;
          "code", is_inline ; "samp", is_inline ; "kbd", is_inline ; "var", is_inline ;
          "cite", is_inline ; "abbr", is_inline ; "acronym", is_inline ;
          "sub", is_inline ; "sup", is_inline ; "span", is_inline ; "bdo", is_inline ;
          "br", is_empty ; "body", is_bodyok ; "address", is_inline ; "div", is_flow ;
          "a", (fun x -> not (tag_in ["a"] x) && is_inline x) ;
          "map", is_block ; "area", is_empty ; "link", is_empty ;
          "img", is_empty ; "object", is_objectok ; "param", is_empty ; "hr", is_empty ;
          "p", is_inline ; "h1", is_inline ; "h2", is_inline ; "h3", is_inline ;
          "h4", is_inline ; "h5", is_inline ; "h6", is_inline ;
          "pre", (fun x -> not (tag_in ["img";"object";"big";"small";"sub";"sup"] x) && is_inline x) ;
          "q", is_inline ; "blockquote", is_blockquoteok ; "ins", is_flow ; "del", is_flow ;
          "dl", tag_in ["dt";"dd"] ; "dt", is_inline ; "dd", is_flow ; "ol", tag_in ["li"] ;
          "ul", tag_in ["li"] ; "li", is_flow ; "form", is_formok ; "label", is_labelok ;
          "input", is_empty ; "select", tag_in ["optgroup"; "option"] ; "legend", is_inline ;
          "optgroup", tag_in ["option"] ; "option", is_pcdata ; "textarea", is_pcdata ;
          "fieldset", (fun x -> is_pcdata x || is_flow x || tag_in ["legend"] x) ;
          "button", (fun x -> not (is_formctrl x || tag_in ["a";"form";"fieldset"] x) && is_flow x) ;
          "table", tag_in ["caption";"col";"colgroup";"thead";"tfoot";"tbody"] ;
          "caption", is_inline ; "thead", is_tr ; "tfoot", is_tr ; "tbody", is_tr ;
          "colgroup", is_col ; "col", is_empty ; "tr", tag_in ["th"; "td"] ;
          "th", is_flow ; "td", is_flow ; "head", is_headok ; "title", is_pcdata ;
          "base", is_empty ; "meta", is_empty ; "style", is_cdata ; "script", is_cdata ;
          "noscript", is_block ; "html", is_html_content ] in
    (* We are always allowed to close the opened tag *)
    if new_tag = `CloseTag pending_tag then true
    else try
        let f = List.assoc pending_tag constraints in
        f new_tag
    with Not_found -> true

let autocloses = Metric.Atomic.make "Html/ParseError/badTagContent"
let uncloseds = Metric.Atomic.make "Html/ParseError/unclosedTag"

let autoclose l =
    let remove_first t ts =
        let rec aux prev = function
            | [] -> List.rev prev
            | x::x' ->
                if x = t then List.rev_append prev x'
                else aux (x::prev) x' in
        aux [] ts in
    let rec aux prev pending_tags = function
        | [] -> (match pending_tags with
            | [] ->
                List.rev prev
            | t :: t' ->
                Metric.Atomic.fire uncloseds ;
                aux ((`CloseTag t)::prev) t' [])
        | new_tag :: next ->
            (* Does this break one of our pending constraint ? *)
            let still_pending, violated = List.partition (comply new_tag) pending_tags in
            if violated <> [] then Metric.Atomic.fire autocloses ;
            let new_doc = new_tag :: (List.map (fun v -> `CloseTag v) violated) @ prev in
            let new_pending_tags = (match new_tag with
                | `OpenTag (t, _) -> t :: still_pending
                | `CloseTag t -> remove_first t still_pending
                | _ -> still_pending) in
            aux new_doc new_pending_tags next
    in
    aux [] [] l

let check_varlist op str expected =
    match tag_seq () (String.to_list str) false with
        | Fail -> Printf.printf "Html: %s -> Fail?!\n" str ; false
        | Wait -> Printf.printf "Html: %s -> Wait?!\n" str ; false
        | Res (res, []) ->
            let closed = op res in
            let ok = closed = expected in
            Printf.printf "Html: %s -> %a " str (List.print var_printer) closed ;
            if ok then (
                Printf.printf "OK\n"
            ) else (
                Printf.printf "FAIL! (expected %a)\n" (List.print var_printer) expected
            ) ;
            ok
        | Res (_, _::_) ->
            Printf.printf "Html: %s -> Res with some rest?!\n" str ; false

let check_autoclose () =
    let do_check = check_varlist autoclose in
    do_check "<html>bla</html>" [ `OpenTag ("html", []) ; `Content ; `CloseTag ("html") ] &&
    do_check "<br>bla<br>" [ `OpenTag ("br", []) ; `CloseTag "br"; `Content ;
                                `OpenTag ("br", []) ; `CloseTag "br" ] &&
    do_check "<p class=toto>bla<dd>burps</html>"
        [ `OpenTag ("p", [`Attr ("class", "toto")]) ; `Content ; `CloseTag "p" ;
          `OpenTag ("dd", []) ; `Content ; `CloseTag "dd" ; `CloseTag "html" ] &&
    do_check "bla<br/>blop" [ `Content ; `Tag ("br", []) ; `Content ] &&
    do_check "<html><head></head><title></title></html>"
        [ `OpenTag ("html", []) ; `OpenTag ("head", []) ; `CloseTag "head" ;
          (* The html tag is closed that early because title is not allowed within it *)
          `CloseTag "html" ; `OpenTag ("title", []) ; `CloseTag "title" ; `CloseTag "html" ]

let reorder l =
    (* Some ending tags may be ordered eroneously (especially after autoclose was applied).
       Try to reorder them so that they are closed in reverse order of opening.
       Also, remove spurious closes *)
    let rec aux prev open_stack next = match open_stack, next with
        | [], [] ->
            List.rev prev
        | t::t', [] ->
            aux ((`CloseTag t)::prev) t' []
        | _, (`OpenTag (t, _) as new_tag :: next') ->
            aux (new_tag::prev) (t::open_stack) next'
        | t::t', (`CloseTag ct as new_tag) :: next' when ct = t ->
            aux (new_tag::prev) t' next'
        | _, `CloseTag ct :: next' ->
            if debug then Printf.printf "Html: reorder: skip spurious close of tag %s\n" ct ;
            aux prev open_stack next'
        | _, new_tag :: next' ->
            aux (new_tag::prev) open_stack next' in
    aux [] [] l

let check_reorder () =
    let do_check = check_varlist reorder in
    let res = [ `OpenTag ("a", []) ; `OpenTag ("b", []) ; `Content ;
                `CloseTag "b" ; `CloseTag "a" ] in
    do_check "<a><b>bla</a></b>" res &&
    do_check "<a><b>bla</b></a>" res &&
    do_check "bla<br/>blop" [ `Content ; `Tag ("br", []) ; `Content ] &&
    do_check "<x><h></h><t></t></x>"
        [ `OpenTag ("x", []) ; `OpenTag ("h", []) ; `CloseTag "h" ;
          `OpenTag ("t", []) ; `CloseTag "t" ; `CloseTag "x" ]

type tree = Content | Node of node
and node = { name : string ;
             attrs : (string * string) list ;
             children : tree list }

let print_attr oc (name, value) = match value with
    | "" -> Printf.fprintf oc "%s" name
    | v  -> Printf.fprintf oc "%s=\"%s\"" name v

let indentation level = String.make level ' '
let rec print_trees ?(level=0) oc t =
    List.print ~first:"" ~last:"" ~sep:"" (print_tree ~level) oc t
and print_tree ?(level=0) oc t =
    let indent = indentation level in
    match t with
    | Content ->
        Printf.fprintf oc "\n%s..." indent
    | Node n  ->
        Printf.fprintf oc "\n%s<%s%a>%a\n%s</%s>"
            indent n.name
            (List.print ~first:" " ~last:"" ~sep:" " print_attr) n.attrs
            (print_trees ~level:(level+2)) n.children
            indent n.name

let rec find_attr name = function
    | [] -> None
    | (n, v)::a' -> if n = name then Some v else find_attr name a'

let rec iter_nodes f = function
    | [] -> ()
    | Content :: rest -> iter_nodes f rest
    | Node n :: rest  ->
        f n ;
        iter_nodes f n.children ;
        iter_nodes f rest

let iter_node f tree = iter_nodes f [tree]

exception Found_node of node
let rec find_first_node f tree =
    try
        iter_node (fun n -> if f n then raise (Found_node n)) tree ;
        None
    with Found_node n ->
        Some n

let filter_map_node f tree =
    let rec aux prevs = function
        | [] -> prevs
        | Content :: rest -> aux prevs rest
        | Node n :: rest  ->
            let prevs' = (match f n with None -> prevs | Some x -> x::prevs) in
            let l = aux prevs' rest in
            aux l n.children in
    aux [] [tree]

let rec attrs_of l =
    let rec aux prev = function
        | [] -> prev
        | `Attr x :: l' -> aux (x::prev) l'
        | _ -> should_not_happen () in
    aux [] l

(* returns a list of documents and the remainder of the list *)
let rec to_tree ?up_to = function
    | [] -> [], []
    | `Blank :: rest ->
        to_tree ?up_to rest
    | `Content :: rest ->
        let siblings, rest' = to_tree ?up_to rest in
        Content :: siblings, rest'
    | `Tag (n, attrs) :: rest ->
        let siblings, rest' = to_tree ?up_to rest in
        Node { name = n ; attrs = attrs_of attrs ; children = [] } :: siblings, rest'
    | `OpenTag (n, attrs) :: rest ->
        let children, rest' = to_tree ~up_to:n rest in
        let siblings, rest''= to_tree ?up_to rest' in
        Node { name = n ; attrs = attrs_of attrs ; children = children } :: siblings, rest''
    | `CloseTag n :: rest ->
        ensure (up_to = None || up_to = Some n) "Incoherent sequence of tag" ;
        [], rest

let check_tree op str expected =
    match tag_seq () (String.to_list str) false with
    | Fail -> Printf.printf "Html: check_tree: %s -> Fail?!\n" str ; false
    | Wait -> Printf.printf "Html: check_tree: %s -> Wait?!\n" str ; false
    | Res (_, _::_) ->
        Printf.printf "Html: check_tree: %s -> Cannot parse entirely?!\n" str ; false
    | Res (res, []) ->
        let trees = op res in
        let ok = trees = expected in
        Printf.printf "Html: check_tree: %s -> %a " str (print_trees ~level:0) trees ;
        if ok then Printf.printf " OK\n"
        else Printf.printf "FAIL! (expected %a)\n" (print_trees ~level:0) expected ;
        ok

let check_to_tree () =
    let do_check = check_tree (fun r ->
        let trees, rem = to_tree (reorder (autoclose r)) in
        if rem <> [] then Printf.printf "Html: check_to_tree: some tags left?!\n" ;
        trees) in
    do_check "<html><body>blabla</body></html>"
        [ Node { name = "html" ; attrs = [] ; children =
            [ Node { name = "body" ; attrs = [] ; children = [ Content ] } ] } ] &&
    do_check "<html><head></head><body>bla</body></html>"
        [ Node { name = "html" ; attrs = [] ; children =
            [ Node { name = "head" ; attrs = [] ; children = [] } ;
              Node { name = "body"; attrs = [] ; children = [ Content ] } ] } ]

(* No tag are allowed in another one when that goes against HTML rules.
   As a result, to_tree may return many small pieces that we must now reassemble
   while maintaining HTML compliance (which might not be possible without
   inserting some new tags. *)
let unify trees =
    let strip_root = function
        | Node { name = _ ; attrs = _ ; children = c } -> c
        | Content -> [] in
    (* First, locate or create the root "html" element *)
    let roots, non_roots =
        List.partition (function Node { name = "html" ; _ } -> true | _ -> false) trees in
    let root, non_roots =
        if roots = [] then Node { name = "html" ; attrs = [] ; children = non_roots }, []
        else List.hd roots, (List.tl roots |> List.map strip_root |> List.concat) @ non_roots in
    if debug then (
        Printf.printf "Html: unify: root = %a\n%d non_roots = %a\n"
            (print_tree ~level:0) root
            (List.length non_roots)
            (print_trees ~level:0) non_roots
    ) ;
    (* Merge others into roots, returning new roots and unmerged *)
    let rec merge ?(strict=true) prevs roots others = match roots, others with
        | _, [] -> (* we are done *)
            List.rev_append prevs roots, []
        | [], _ -> (* damn, no tries left *)
            if debug then Printf.printf "Html: unify: nowhere to merge %a\n" (print_tree ~level:0) (List.hd others) ;
            List.rev prevs, others
        | Content :: roots', Content :: others' -> (* we can always merge content with content *)
            merge ~strict prevs (Content::roots') others'
        | Content :: roots', Node _ :: _ -> (* we can't merge a node into a content *)
            merge ~strict (Content::prevs) roots' others
        | Node r :: roots', other :: others' -> (* we may be allowed to add another tree to r *)
            if not strict ||
               comply (match other with
                | Content -> `Content
                | Node n -> `OpenTag (n.name, n.attrs)) r.name
            then (
                if debug then Printf.printf "Html: unify: Merge %a into %a\n"
                    (print_tree ~level:0) other
                    (print_tree ~level:0) (Node r) ;
                let new_r = { r with children = r.children @ [other] } in
                merge ~strict prevs (Node new_r :: roots') others'
            ) else (
                if debug then Printf.printf "Html: unify: Cannot merge %a into %a\n"
                    (print_tree ~level:0) other
                    (print_tree ~level:0) (Node r) ;
                let new_children, unmerged = merge ~strict [] r.children [other] in
                if unmerged = [] then (
                    let new_r = { r with children = new_children } in
                    merge ~strict prevs (Node new_r :: roots') others'
                ) else (
                    merge ~strict (Node r :: prevs) roots' others
                )
            ) in
    let new_roots, unmerged = merge [] [root] non_roots in
    if debug && unmerged <> [] then
        Printf.printf "Html: unify: Have to pack %d trees not strictly!\n" (List.length unmerged) ;
    (* Maybe we should try to insert unmergeds into an englobing div to see if it change anything? *)
    (* In non-strict mode, we merely pack everything in the back of the root, which is not
       ideal since the root in the html, not the body. *)
    let new_roots, unmerged = merge ~strict:false [] new_roots unmerged in
    assert (unmerged = []) ;
    assert (List.length new_roots = 1) ;
    List.hd new_roots

let check_unify () =
    let do_check = check_tree (fun r ->
        let trees, rem = to_tree (reorder (autoclose r)) in
        if rem <> [] then Printf.printf "Html: check_to_tree: some tags left?!\n" ;
        [unify trees]) in
    do_check "<html><head></head><title>bla</title></html>"
        [ Node { name = "html" ; attrs = [] ; children =
            [ Node { name = "head" ; attrs = [] ; children = [
                  Node { name = "title"; attrs = [] ; children = [ Content ] } ] } ] } ]

let parzer () =
    map (tag_seq ()) (fun r ->
        let trees, rem = to_tree (reorder (autoclose r)) in
        if rem <> [] then Printf.fprintf stderr "Html: check_to_tree: some tags left?!\n" ;
        unify trees)

let unparsable = Metric.Counter.make "Html/Unparseable" "bytes"

let parse str =
    let p = parzer () in
    match p (String.to_list str) false with
        | Fail ->
            if debug then Printf.printf "Html: parzer failed\n" ;
            None
        | Wait ->
            should_not_happen () (* since we signaled we have no more inputs *)
        | Res (res, rem) ->
            if debug && rem <> [] then (
                let tot_len = String.length str
                and rem_len = List.length rem in
                Printf.fprintf stdout "Html: parzer stopped after %d/%d bytes (at '%s')\n" (tot_len - rem_len) tot_len (abbrev (String.of_list rem)) ;
                Metric.Counter.increase unparsable (Int64.of_int rem_len)
            ) ;
            Some res

let check_parser () =
    match parse (file_content "tests/basic.html") with
        | Some
            (Node { name = "html" ; attrs = [] ; children =
                [ Node { name = "body" ; attrs = [ "onload", "blabla" ] ; children =
                    [ Node { name = "div" ; attrs = [ "fst", "" ] ; children = [ Content ] } ;
                      Node { name = "div" ; attrs = [ "snd", "" ] ; children = [ Content ] } ] } ] }) ->
            Printf.printf "Html: check_parser: OK\n" ; true
        | Some tree ->
            Printf.printf "Html: check_parser: FAIL (got %a)\n"
                (print_tree ~level:0) tree ;
            false
        | None ->
            Printf.printf "Html: check_parser: FAIL (got nothing)\n" ;
            false

(* TODO: a function to index a tree so that we can search the dom quickly by id? *)

(* Takes a body and return a list of urls *)
let extract_links_simple ?same_page ?(default_base=Url.empty) headers body =
    let link_res =
        List.map (fun (same_page, regex) -> same_page, Str.regexp_case_fold regex)
            [ false, "\\(\\bhref *= *\\(\"\\|'\\)\\([^\"']+\\)\\2\\)" ;
              true, "\\(\\bsrc *= *\\(\"\\|'\\)\\([^\"']+\\)\\2\\)" ;
              true, "\\(\\bbackground *= *\\(\"\\|'\\)\\([^\"']+\\)\\2\\)" ;
              true, "\\(\\bcite *= *\\(\"\\|'\\)\\([^\"']+\\)\\2\\)" ;
              true, "\\(\\bclassid *= *\\(\"\\|'\\)\\([^\"']+\\)\\2\\)" ;
              true, "\\(\\bdata *= *\\(\"\\|'\\)\\([^\"']+\\)\\2\\)" ;
              true, "\\(\\bcodebase *= *\\(\"\\|'\\)\\([^\"']+\\)\\2\\)" ;
              true, "\\(\\busemap *= *\\(\"\\|'\\)\\([^\"']+\\)\\2\\)" ;
              true, "\\(\\blongdesc *= *\\(\"\\|'\\)\\([^\"']+\\)\\2\\)" ;
              true, "\\(\\bprofile *= *\\(\"\\|'\\)\\([^\"']+\\)\\2\\)" ]
    and base_re = Str.regexp_case_fold "< *base +href *= *\\(\"\\|'\\)\\([^\"']+\\)\\1" in
    let base = try (* URL within document *)
            ignore (Str.search_forward base_re body 0) ;
            Url.of_string ~force_absolute:true (Str.matched_group 2 body)
        with Not_found -> (match headers_find "Base" headers with
            | Some base when String.length base > 13 ->
                Url.of_string ~force_absolute:true (String.sub base 5 ((String.length base)-6))
            | _ -> default_base) in
    let links_of prev (sp, re) =
        let rec aux prev offset =
            try
                ignore (Str.search_forward re body offset) ;
                (* We must take this offset _before_ Url.resolve will perform some other regex... *)
                let offset' = Str.match_end ()
                and prev' = (Str.matched_group 3 body |>
                        tap (if debug then Printf.printf "Html: extract_links_simple: found in '%s': '%s'\n%!" (Str.matched_group 0 body) else ignore) |>
                        Url.of_string |>
                        Url.resolve base) :: prev in
                aux prev' offset'
            with Not_found -> prev in
        if same_page = None || same_page = Some sp then aux prev 0
        else prev
        in
    List.fold_left links_of [] link_res |> List.enum

let extract_links ?(default_base=Url.empty) headers tree =
    let base_href = (Option.Monad.bind (find_first_node (fun n -> n.name = "base") tree)
                                       (fun n -> find_attr "href" n.attrs)) in
    if debug then Printf.printf "Base href found in html header: %a\n"
        (Option.print String.print) base_href ;
    let base_href = if base_href <> None then base_href else (
        (* if no base_href was found, look into the headers *)
        (match headers_find "Base" headers with
            | Some base when String.length base > 13 ->
                Some (String.sub base 5 (String.length base - 6))
            | _ -> None)) in
    if debug then Printf.printf "Base href found in html or http headers: %a\n"
        (Option.print String.print) base_href ;
    let base = match base_href with
        | Some href -> Url.of_string ~force_absolute:true href
        | None      -> default_base in
    let urls = ref [] in
    let may_add_url u_opt =
        Option.may (fun u ->
            let url = Url.resolve base (Url.of_string u) in
            urls := url::!urls) u_opt in
    iter_node (function
        | { name = "form"       ; attrs = attrs ; _ } ->
            if (match find_attr "method" attrs with
                | None -> true
                | Some x when String.icompare x "get" = 0 -> true
                | _ -> false) then may_add_url (find_attr "action" attrs)
        | { name = "body"       ; attrs = attrs ; _ } -> may_add_url (find_attr "background" attrs)
        | { name = "blockquote" ; attrs = attrs ; _ }
        | { name = "q"          ; attrs = attrs ; _ }
        | { name = "del"        ; attrs = attrs ; _ }
        | { name = "ins"        ; attrs = attrs ; _ } -> may_add_url (find_attr "cite" attrs)
        | { name = "object"     ; attrs = attrs ; _ } -> may_add_url (find_attr "classid" attrs) ;
                                                         may_add_url (find_attr "data" attrs) ;
                                                         may_add_url (find_attr "codebase" attrs) ;
                                                         may_add_url (find_attr "usemap" attrs)
        | { name = "applet"     ; attrs = attrs ; _ } -> may_add_url (find_attr "codebase" attrs)
        | { name = "a"          ; attrs = attrs ; _ }
        | { name = "area"       ; attrs = attrs ; _ }
        | { name = "link"       ; attrs = attrs ; _ } -> may_add_url (find_attr "href" attrs)
        | { name = "img"        ; attrs = attrs ; _ } -> may_add_url (find_attr "src" attrs) ;
                                                         may_add_url (find_attr "longdesc" attrs) ;
                                                         may_add_url (find_attr "usemap" attrs)
        | { name = "frame"      ; attrs = attrs ; _ } -> may_add_url (find_attr "src" attrs) ;
                                                         may_add_url (find_attr "longdesc" attrs) ;
                                                         may_add_url (find_attr "usemap" attrs)
        | { name = "iframe"     ; attrs = attrs ; _ } -> may_add_url (find_attr "src" attrs) ;
                                                         may_add_url (find_attr "longdesc" attrs) ;
                                                         may_add_url (find_attr "usemap" attrs)
        | { name = "head"       ; attrs = attrs ; _ } -> may_add_url (find_attr "profile" attrs)
        | { name = "script"     ; attrs = attrs ; _ }
        | { name = "input"      ; attrs = attrs ; _ } -> may_add_url (find_attr "src" attrs) ;
                                                         may_add_url (find_attr "usemap" attrs)
        | _ -> ()) tree ;
    List.enum !urls

let check_extraction () =
    Printf.printf "Html: check_extraction: test 1: %s\n"
        (if extract_links_simple [] "bla <a href=\"glop1\"> bla <src = 'glop2' >" /@
                Url.to_string |>
                List.of_enum |>
                List.sort compare = [ "/glop1" ; "/glop2" ] then "OK" else "FAIL!") ;
    Printf.printf "Html: check_extraction: test 2: " ;
    match parse (file_content "tests/simple.html") with
    | None -> (Printf.printf "parse FAIL!\n" ; false)
    | Some tree ->
        let res = extract_links [] tree /@
            Url.to_string |>
            List.of_enum |>
            List.sort compare in
        if res = [ "http://rixed.free.fr/news.html" ;
                   "http://rixed.free.fr/projects.html" ;
                   "mailto:///rixed@free.fr" ]
        then (Printf.printf "OK\n" ; true)
        else (Printf.printf "FAIL! (got %a)" (List.print String.print) res ; false)

let check () =
    check_extraction () &&
    check_chars () &&
    check_parse () &&
    check_autoclose () &&
    check_reorder () &&
    check_to_tree () &&
    check_unify () &&
    check_parser ()

