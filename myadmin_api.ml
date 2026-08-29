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
    GET    /api/simulations                 every simulation, with its clock
    GET    /api/simulations/<id>            one of them
    POST   /api/simulations/<id>/pause      freeze its clock
    POST   /api/simulations/<id>/resume     and let it run again
    POST   /api/simulations/<id>/step       run one event (?n= for more)
    GET    /api/simulations/<s>/widgets    its widgets; ?path=/a/b to filter
    GET    /api/simulations/<s>/widgets/<w>
    DELETE /api/simulations/<s>/widgets/<w> delete it, and its children
    GET    /api/simulations/<s>/widgets/<w>/properties
    GET    /api/simulations/<s>/widgets/<w>/properties/<name>
    PUT    /api/simulations/<s>/widgets/<w>/properties/<name>  body is the value
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
    Yojson.Basic.to_string json |> String.print resp ;
    200, json_headers

(* [matches] holds the whole url first, then one string per group of the
 * regexp that selected this resource. *)
let matched matches n =
    match List.nth matches n with
    | exception _ ->
        bad_request "Missing part #%d of the path" n
    | s -> s

(* A widget is identified by the pair (simulation, widget), since its
 * inventory is its simulation's tree. *)
let widget_of_matches (sim : Simulation.t) matches n =
    let s = matched matches n in
    match int_of_string s with
    | exception _ ->
        bad_request "Not a widget id: %S" s
    | id ->
        (match Widget.find sim.root id with
        | None ->
            not_found "Simulation %s has no widget %d" (Simulation.name sim) id
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
    (* The value goes out as whatever it is -- a number stays a number -- so
     * that the interface has nothing to parse and nothing to guess. *)
    let value =
        match p.getter () with
        | exception e ->
            bad_request "Cannot read property %S: %s" p.name
                (Printexc.to_string e)
        | v -> v in
    let kind =
        match p.kind with
        | Widget.String -> `Assoc [ "type", `String "string" ]
        | Int -> `Assoc [ "type", `String "int" ]
        | Float -> `Assoc [ "type", `String "float" ]
        | Bool -> `Assoc [ "type", `String "bool" ]
        | Enum choices ->
            `Assoc [ "type", `String "enum" ;
                     "choices", `List (List.map (fun c -> `String c) choices) ]
        (* Both ranges take the same shape, since the interface builds the same
         * input out of either one; [int] says which values are acceptable, and
         * therefore how the input must step.
         * A bound that means "no bound" goes out as null rather than as its
         * value: an infinity is not representable in JSON and would abort the
         * serialization of the whole answer, and [max_int] is both meaningless
         * as a slider end and beyond what a JSON number can carry exactly. *)
        | FRange (mi, ma) ->
            let bound f = if Float.is_finite f then `Float f else `Null in
            `Assoc [ "type", `String "range" ; "int", `Bool false ;
                     "min", bound mi ; "max", bound ma ]
        | IRange (mi, ma) ->
            let bound i =
                if i = min_int || i = max_int then `Null else `Int i in
            `Assoc [ "type", `String "range" ; "int", `Bool true ;
                     "min", bound mi ; "max", bound ma ]
        (* Counter, gauge or timed comes with the value: the metric says what
         * it is. *)
        | Metric ->
            `Assoc [ "type", `String "metric" ] in
    `Assoc [ "name", `String p.name ;
             "descr", `String p.descr ;
             "read_only", `Bool (p.setter = None) ;
             "kind", kind ;
             "value", value ]

let json_of_peer (p : Widget.peer) =
    `Assoc [ "widget", `Int p.widget.id ;
             "via", (match p.via with None -> `Null
                                    | Some v -> `Int v.id) ]

let json_of_widget (w : Widget.t) =
    `Assoc [ "id", `Int w.id ;
             "sim", `Int w.sim ;
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

let json_of_simulation (s : Simulation.t) =
        `Assoc [ "id", `Int s.id ;
             "name", `String s.name ;
             "root", `Int s.root.Widget.id ;
             "now", `Float (Clock.Time.to_timestamp (Simulation.now s)) ;
             "now_str", `String (Clock.Time.to_string (Simulation.now s)) ;
             "realtime", `Bool s.realtime ;
             (* Null is "as fast as it can", and is what a realtime simulation
              * reports too: its speed is not ours to choose. *)
             "speed_ratio", (match s.speed_ratio with
                            | None -> `Null
                            | Some r -> `Float r) ;
             "late", `Float (s.late :> float) ;
             "running", `Bool s.continue ;
             "paused", `Bool s.paused ;
             "paused_total", `Float (s.paused_total :> float) ;
             "pending_events", `Int (Simulation.Events.cardinal s.events) ]

(* Reading a simulation's state means borrowing it from its own thread. *)
let simulation_of_matches matches n =
    let s = matched matches n in
    match int_of_string s with
    | exception _ -> bad_request "Not a simulation id: %S" s
    | id ->
        (match Simulation.find id with
        | None -> not_found "No simulation with id %d" id
        | Some s -> s)

let get_simulations _mth _matches _vars _qry_body resp =
    let sims =
        Simulation.all () |>
        List.sort (fun (a : Simulation.t) b ->
            Int.compare a.Simulation.id b.Simulation.id) in
    respond resp
        (`List (List.map (fun s ->
            Simulation.borrow s (fun () -> json_of_simulation s)) sims))

let get_simulation _mth matches _vars _qry_body resp =
    let s = simulation_of_matches matches 1 in
    respond resp (Simulation.borrow s (fun () -> json_of_simulation s))

(* Pause/resume/step. Note myadmin runs in its own realtime simulation, so it
 * stays responsive whatever it does to the others. *)
let control_simulation serving _mth matches vars _qry_body resp =
    let s = simulation_of_matches matches 1 in
    let action = Url.decode (matched matches 2) in
    (* Pausing the simulation that serves this API would freeze the very thread
     * about to answer, and nothing would be left to resume it. This is exactly
     * why myadmin belongs in a simulation of its own. *)
    if s == serving then
        bad_request "Simulation %s serves this API and cannot control itself"
            s.Simulation.name ;
    (match action with
    | "pause" -> Simulation.pause s ()
    | "resume" -> Simulation.resume s ()
    | "speed" ->
        if s.Simulation.realtime then
            bad_request "Simulation %s follows the wall clock: its speed is \
                         not ours to set" s.Simulation.name ;
        let ratio =
            match Hashtbl.find_option vars "ratio" with
            | None | Some "full" -> None
            | Some r ->
                (match float_of_string r with
                | exception _ -> bad_request "Not a speed: %S" r
                | r when not (Float.is_finite r) || r <= 0. ->
                    bad_request "%g is not a speed (use \"full\" to run as \
                                 fast as possible)" r
                | r -> Some r) in
        Simulation.set_speed_ratio s ratio
    | "step" ->
        let n =
            match Hashtbl.find_option vars "n" with
            | None -> 1
            | Some n ->
                (match int_of_string n with
                | exception _ -> bad_request "Not a number of steps: %S" n
                | n -> n) in
        Simulation.step ~n s ()
    | _ ->
        bad_request "Unknown action %S (pause, resume, speed or step)" action) ;
    respond resp (Simulation.borrow s (fun () -> json_of_simulation s))

let get_widgets _mth matches vars _qry_body resp =
    let sim = simulation_of_matches matches 1 in
    Simulation.borrow sim (fun () ->
        let widgets =
            match Hashtbl.find_option vars "path" with
            | Some path -> Widget.find_by_path sim.root path
            | None -> Simulation.widgets sim in
        let widgets =
            List.sort (fun (a : Widget.t) b -> Int.compare a.id b.id) widgets in
        respond resp (`List (List.map json_of_widget widgets)))

let get_widget _mth matches _vars _qry_body resp =
    let sim = simulation_of_matches matches 1 in
    Simulation.borrow sim (fun () ->
        respond resp (json_of_widget (widget_of_matches sim matches 2)))

let delete_widget _mth matches _vars _qry_body resp =
    let sim = simulation_of_matches matches 1 in
    Simulation.borrow sim (fun () ->
        let w = widget_of_matches sim matches 2 in
        if w == sim.root then
            bad_request "%s is the root of simulation %s and cannot be deleted"
                (Widget.full_name w) (Simulation.name sim) ;
        let full_name = Widget.full_name w in
        Widget.delete w ;
        respond resp (`Assoc [ "deleted", `String full_name ]))

let get_properties _mth matches _vars _qry_body resp =
    let sim = simulation_of_matches matches 1 in
    Simulation.borrow sim (fun () ->
        let w = widget_of_matches sim matches 2 in
        respond resp (`List (List.map json_of_property w.properties)))

let get_property _mth matches _vars _qry_body resp =
    let sim = simulation_of_matches matches 1 in
    Simulation.borrow sim (fun () ->
        let w = widget_of_matches sim matches 2 in
        let p = property_of_matches w matches 3 in
        respond resp (json_of_property p))

(* The body is the value, as JSON: 42.5 for a number, "foo" for a string.
 * Anything that is not JSON at all is taken to be a bare string, so that a
 * value typed by hand at a shell prompt still works. *)
let set_property _mth matches vars qry_body resp =
    let sim = simulation_of_matches matches 1 in
    Simulation.borrow sim (fun () ->
    let w = widget_of_matches sim matches 2 in
    let p = property_of_matches w matches 3 in
    let raw =
        (* Accept the value either as the body or as a "value" parameter, so
         * that a plain HTML form can be used as well: *)
        match Hashtbl.find_option vars "value" with
        | Some v -> v
        | None -> qry_body in
    let value =
        match Yojson.Basic.from_string raw with
        | exception _ -> `String raw
        | v -> v in
    match p.setter with
    | None ->
        raise (Opache.ResourceError (
            405, Printf.sprintf "Property %S of %s is read only"
                     p.name (Widget.full_name w)))
    | Some setter ->
        (match setter value with
        | exception e ->
            bad_request "Cannot set property %S to %s: %s"
                p.name (Yojson.Basic.to_string value)
                (match e with
                | Widget.Bad_value m -> m
                | e -> Printexc.to_string e)
        | () ->
            Log.(log w.logger Info (lazy (
                Printf.sprintf "Property %S set to %s" p.name
                    (Yojson.Basic.to_string value)))) ;
            respond resp (json_of_property p)))

(*
 * Routing
 *)

(* Opache reports a [ResourceError] as plain text, which would force every
 * caller of this API to special case error responses. Answer with JSON
 * throughout instead. Handlers write their body last, so nothing has been
 * emitted yet by the time we get here. *)
let json_errors f mth matches vars qry_body resp =
    let fail code msg =
        Yojson.Basic.to_string (`Assoc [ "status", `Int code ;
                                        "error", `String msg ]) |>
        String.print resp ;
        code, json_headers in
    match f mth matches vars qry_body resp with
    | exception Opache.ResourceError (code, msg) -> fail code msg
    | exception e -> fail 500 (Printexc.to_string e)
    | res -> res

(* Beware that the multiplexer picks the first matching regexp, so the more
 * specific routes must come first. *)
(* [serving] is the simulation this API runs in: it is the one that must never
 * be paused, and the only one it can be asked to control that it must refuse. *)
let resources serving : (Str.regexp * Opache.resource) list =
    List.map (fun (re, f) -> re, json_errors f) [
    Str.regexp "/api/simulations/\\([0-9]+\\)/\\(pause\\|resume\\|speed\\|step\\)$",
        control_simulation serving ;
    Str.regexp "/api/simulations/\\([0-9]+\\)$", get_simulation ;
    Str.regexp "/api/simulations$", get_simulations ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets/\\([0-9]+\\)/properties/\\(.+\\)$",
        (fun mth matches vars qry_body resp ->
            match mth with
            | "GET" -> get_property mth matches vars qry_body resp
            | "PUT" | "POST" -> set_property mth matches vars qry_body resp
            | _ -> raise (Opache.ResourceError (405, "Method not allowed"))) ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets/\\([0-9]+\\)/properties$",
        get_properties ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets/\\([0-9]+\\)$",
        (fun mth matches vars qry_body resp ->
            match mth with
            | "GET" -> get_widget mth matches vars qry_body resp
            | "DELETE" -> delete_widget mth matches vars qry_body resp
            | _ -> raise (Opache.ResourceError (405, "Method not allowed"))) ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets$", get_widgets ]
