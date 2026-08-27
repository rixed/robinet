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
  The REST API the administration UI is built upon.

  Widgets are addressed by their [Widget.id], which is stable: names are not
  unique and a widget can be moved in the hierarchy. For convenience the
  collection can also be filtered by path, and every widget carries its
  [full_name] alongside its id.

  Routes (see [resources] at the end of this file):

  {v
    GET    /api/clock                       simulation time and event queue
    GET    /api/widgets                     every widget; ?path=/a/b to filter
    GET    /api/widgets/<id>                one widget
    DELETE /api/widgets/<id>                delete it, and its children
    GET    /api/widgets/<id>/properties     all properties, with their values
    GET    /api/widgets/<id>/properties/<name>
    PUT    /api/widgets/<id>/properties/<name>   body is the raw value
  v}

  Property names are used as-is in the URL (url-encoded): they are already
  unique within a widget and readable enough to serve as identifiers.
*)
open Batteries

(* Anything a getter or a setter raises is reported to the caller as a 400
 * rather than dropped: the UI is expected to validate beforehand, so reaching
 * this means the input really was refused. *)
let bad_request fmt =
    Printf.ksprintf (fun s -> raise (Opache.ResourceError (400, s))) fmt

let not_found fmt =
    Printf.ksprintf (fun s -> raise (Opache.ResourceError (404, s))) fmt

let json_headers = [ "Content-Type", "application/json" ]

let respond resp json =
    Yojson.Safe.to_string json |> String.print resp ;
    200, json_headers

(* [matches] holds the whole url first, then one string per group of the
 * regexp that selected this resource. *)
let matched matches n =
    match List.nth matches n with
    | exception _ ->
        bad_request "Missing part #%d of the path" n
    | s -> s

let widget_of_matches matches n =
    let s = matched matches n in
    match int_of_string s with
    | exception _ ->
        bad_request "Not a widget id: %S" s
    | id ->
        (match Widget.find id with
        | None -> not_found "No widget with id %d" id
        | Some w -> w)

let property_of_matches (widget : Widget.t) matches n =
    let name = Url.decode (matched matches n) in
    match List.find (fun (p : Widget.property) -> p.name = name)
                    widget.properties with
    | exception Not_found ->
        not_found "Widget %s has no property %S" (Widget.full_name widget) name
    | p -> p

(*
 * Serialization
 *)

let json_of_property (p : Widget.property) =
    (* The value is read through the getter, which may fail on us: *)
    let value =
        match p.getter () with
        | exception e ->
            bad_request "Cannot read property %S: %s" p.name
                (Printexc.to_string e)
        | v -> `String v in
    `Assoc [ "name", `String p.name ;
             "descr", `String p.descr ;
             "read_only", `Bool (p.setter = None) ;
             "value", value ]

let json_of_peer (p : Widget.peer) =
    `Assoc [ "widget", `Int p.widget.id ;
             "via", (match p.via with None -> `Null
                                    | Some v -> `Int v.id) ]

let json_of_widget (w : Widget.t) =
    `Assoc [ "id", `Int w.id ;
             "name", `String w.name ;
             "full_name", `String (Widget.full_name w) ;
             "parent", (match w.parent with None -> `Null
                                          | Some p -> `Int p.id) ;
             "children", `List (List.map (fun (c : Widget.t) -> `Int c.id)
                                         w.children) ;
             "peers", `List (List.map json_of_peer w.peers) ;
             (* Only the names here: values are a separate request, since they
              * are live and this listing is not. *)
             "properties", `List (List.map (fun (p : Widget.property) ->
                                     `String p.name) w.properties) ]

(*
 * Handlers
 *)

let get_clock _mth _matches _vars _qry_body resp =
    let now = Clock.now () in
    respond resp (`Assoc [
        "now", `Float (Clock.Time.to_timestamp now) ;
        "now_str", `String (Clock.Time.to_string now) ;
        "wall_clock", `Float (Clock.Time.to_timestamp (Clock.Time.wall_clock ())) ;
        "realtime", `Bool !Clock.realtime ;
        "running", `Bool !Clock.continue ;
        "pending_events", `Int (Clock.Map.cardinal Clock.current.events) ])

let get_widgets _mth _matches vars _qry_body resp =
    let widgets =
        match Hashtbl.find_option vars "path" with
        | Some path -> Widget.find_by_path path
        | None -> Hashtbl.values Widget.all |> List.of_enum in
    let widgets =
        List.sort (fun (a : Widget.t) b -> Int.compare a.id b.id) widgets in
    respond resp (`List (List.map json_of_widget widgets))

let get_widget _mth matches _vars _qry_body resp =
    let w = widget_of_matches matches 1 in
    respond resp (json_of_widget w)

let delete_widget _mth matches _vars _qry_body resp =
    let w = widget_of_matches matches 1 in
    let full_name = Widget.full_name w in
    Widget.delete w ;
    respond resp (`Assoc [ "deleted", `String full_name ])

let get_properties _mth matches _vars _qry_body resp =
    let w = widget_of_matches matches 1 in
    respond resp (`List (List.map json_of_property w.properties))

let get_property _mth matches _vars _qry_body resp =
    let w = widget_of_matches matches 1 in
    let p = property_of_matches w matches 2 in
    respond resp (json_of_property p)

(* The body is the raw value, not JSON: property values are strings all the way
 * down to the setter, so there is nothing to decode. *)
let set_property _mth matches vars qry_body resp =
    let w = widget_of_matches matches 1 in
    let p = property_of_matches w matches 2 in
    let value =
        (* Accept the value either as the body or as a "value" parameter, so
         * that a plain HTML form can be used as well: *)
        match Hashtbl.find_option vars "value" with
        | Some v -> v
        | None -> qry_body in
    match p.setter with
    | None ->
        raise (Opache.ResourceError (
            405, Printf.sprintf "Property %S of %s is read only"
                     p.name (Widget.full_name w)))
    | Some setter ->
        (match setter value with
        | exception e ->
            bad_request "Cannot set property %S to %S: %s"
                p.name value (Printexc.to_string e)
        | () ->
            Log.(log w.logger Info (lazy (
                Printf.sprintf "Property %S set to %S" p.name value))) ;
            respond resp (json_of_property p))

(*
 * Routing
 *)

(* Opache reports a [ResourceError] as plain text, which would force every
 * caller of this API to special case error responses. Answer with JSON
 * throughout instead. Handlers write their body last, so nothing has been
 * emitted yet by the time we get here. *)
let json_errors f mth matches vars qry_body resp =
    let fail code msg =
        Yojson.Safe.to_string (`Assoc [ "status", `Int code ;
                                        "error", `String msg ]) |>
        String.print resp ;
        code, json_headers in
    match f mth matches vars qry_body resp with
    | exception Opache.ResourceError (code, msg) -> fail code msg
    | exception e -> fail 500 (Printexc.to_string e)
    | res -> res

(* Beware that the multiplexer picks the first matching regexp, so the more
 * specific routes must come first. *)
let resources : (Str.regexp * Opache.resource) list =
    List.map (fun (re, f) -> re, json_errors f) [
    Str.regexp "/api/clock$", get_clock ;
    Str.regexp "/api/widgets/\\([0-9]+\\)/properties/\\(.+\\)$",
        (fun mth matches vars qry_body resp ->
            match mth with
            | "GET" -> get_property mth matches vars qry_body resp
            | "PUT" | "POST" -> set_property mth matches vars qry_body resp
            | _ -> raise (Opache.ResourceError (405, "Method not allowed"))) ;
    Str.regexp "/api/widgets/\\([0-9]+\\)/properties$", get_properties ;
    Str.regexp "/api/widgets/\\([0-9]+\\)$",
        (fun mth matches vars qry_body resp ->
            match mth with
            | "GET" -> get_widget mth matches vars qry_body resp
            | "DELETE" -> delete_widget mth matches vars qry_body resp
            | _ -> raise (Opache.ResourceError (405, "Method not allowed"))) ;
    Str.regexp "/api/widgets$", get_widgets ]
