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
    GET    /api/device-types               what can be built, and what each
                                            kind of device has to be told
    GET    /api/simulations/<s>/widgets    its widgets; ?path=/a/b to filter
                                            (each carries "ports" and
                                             "free_ports": how many cables it
                                             takes, and how many it has room
                                             for)
    POST   /api/simulations/<s>/widgets    add a device to it; the body is
                                            {"type": ..., "name": ...,
                                             "params": {...}}
    GET    /api/simulations/<s>/widgets/<w>
    DELETE /api/simulations/<s>/widgets/<w> take it out of the simulation for
                                            good: it, everything it is made
                                            of, and the cables that reached it
    PUT    /api/simulations/<s>/widgets/<w>/location
                                            where it is in the world; the body
                                            is {"lat": ..., "lon": ...}, or
                                            null to take it off the map
    GET    /api/simulations/<s>/widgets/<w>/properties
    GET    /api/simulations/<s>/widgets/<w>/properties/<name>
    PUT    /api/simulations/<s>/widgets/<w>/properties/<name>  body is the value
    GET    /api/simulations/<s>/widgets/<w>/properties/<name>/history
                                            what that metric has been worth;
                                            ?since=<simulated time> for the
                                            points taken after that one
    GET    /api/simulations/<s>/widgets/<w>/properties/<name>/file
                                            the file that property names, for
                                            a property of kind FileName
    GET    /api/simulations/<s>/widgets/<w>/logs
                                            what it logged; ?since=<simulated
                                            time> for what came after, and
                                            ?level=<name> for how deep to go
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

(* What the value looks like, so that the interface can offer the right input.
 * Shared by the properties of a widget and by the parameters a device is built
 * from: the dialog that asks for the one is the panel that edits the other. *)
let rec json_of_kind = function
    | Widget.String -> `Assoc [ "type", `String "string" ]
    (* A string, and a file to go with it: the interface reads the value as it
       reads any other string, and offers the download beside it. *)
    | FileName -> `Assoc [ "type", `String "filename" ]
    | Int -> `Assoc [ "type", `String "int" ]
    | Float -> `Assoc [ "type", `String "float" ]
    | Bool -> `Assoc [ "type", `String "bool" ]
    | Enum choices ->
        `Assoc [ "type", `String "enum" ;
                 "choices",
                    `List (Array.to_list choices |>
                           List.map (fun c -> `String c)) ]
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
        `Assoc [ "type", `String "metric" ]
    (* Another widget of the same simulation, by id. The interface has them
       all in hand and offers them by name. *)
    | Widget_id ->
        `Assoc [ "type", `String "widget" ]
    (* The interface builds the input for what is inside and puts a tick
       box in front of it; the value itself is null when there is none. *)
    | Optional k ->
        `Assoc [ "type", `String "optional" ; "of", json_of_kind k ]
    (* Any number of values of the same kind: the interface repeats the input
       for one of them, as a column, or as a table when what is repeated is a
       record. *)
    | List k ->
        `Assoc [ "type", `String "list" ; "of", json_of_kind k ]
    (* Named values, in the order they are to be laid out: an array rather than
       an object, since JSON says nothing about the order of an object's keys
       and that order is what the columns are. *)
    | Record fields ->
        `Assoc [ "type", `String "record" ;
                 "fields",
                 `List (Array.to_list fields |>
                        List.map (fun (name, k) ->
                            `Assoc [ "name", `String name ;
                                     "kind", json_of_kind k ])) ]
    (* Not a shape of its own on the wire: an example of how the value inside
       is written, said alongside what that value is, so that the interface
       reads it off whatever input it was going to build anyway. *)
    | Hint (h, k) ->
        (match json_of_kind k with
        | `Assoc l -> `Assoc (l @ [ "placeholder", `String h ])
        | j -> j)

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
    `Assoc [ "name", `String p.name ;
             "descr", `String p.descr ;
             (* What the figure is counted in, if anything: an empty string is
                simply a property that has nothing to add to its number. *)
             "units", `String p.units ;
             "read_only", `Bool (p.setter = None) ;
             (* Say so even when there is a value to show: what the UI does
                with a property must not depend on the moment it asked. *)
             "only_when_set", `Bool p.only_when_set ;
             "kind", json_of_kind p.kind ;
             "value", value ]

(* Where the widget is in the world, or null: most widgets are nowhere, and the
 * map places those itself. It travels with the widget as well as through the
 * read-only "latitude" and "longitude" properties, because the map wants every
 * position at once, in the one listing it already fetches -- not one request
 * per box. The properties are how a position is read beside the rest of what a
 * widget says about itself; this is how the map reads them all. *)
let json_of_location = function
    | None -> `Null
    | Some (l : Widget.location) ->
        `Assoc [ "lat", `Float l.lat ; "lon", `Float l.lon ]

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
             (* What kind of device this is, when it is a whole one, named as
                /api/device-types names it. Null for a part of a device -- an
                adapter, an interface -- and for a kind this interface cannot
                build, so a name that is not in that catalogue is a device that
                cannot be deleted here either. *)
             "device", (match w.device with None -> `Null
                                          | Some d -> `String d) ;
             (* And whether that is a device this interface will remove, which
                is not the same question: the repeater inside a switch is a
                repeater, and still not something to be taken out on its own. *)
             "deletable", `Bool (Device.of_widget w <> None) ;
             (* How many cables this widget takes, and how many of those ports
                are still free -- which is what the interface needs in order to
                offer it as an end of a new cable. Two numbers rather than one
                answer per port: a device may have a great many of them, this
                listing is polled, and "is there room on it" is the whole of
                what is asked. Zero for most widgets, which are not things a
                cable reaches. *)
             "ports", `Int (w.ports.count ()) ;
             "free_ports", `Int (Widget.free_ports w) ;
             "location", json_of_location w.location ;
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

(* What can be built, and what each of them has to be told. Independent of any
 * simulation: the same catalogue builds into all of them. *)
let get_device_types _mth _matches _vars _qry_body resp =
    respond resp (`List (List.map (fun (t : Device.t) ->
        `Assoc [ "type", `String t.name ;
                 "descr", `String t.descr ;
                 "params", `List (List.map (fun (p : Device.param) ->
                     `Assoc [ "name", `String p.name ;
                              "descr", `String p.descr ;
                              "units", `String p.units ;
                              "kind", json_of_kind p.kind ;
                              (* What an empty input is to show: an example of
                                 the value, or what leaving it out will do. *)
                              "placeholder", `String p.placeholder ;
                              (* What the dialog offers before anything is
                                 typed. Null for a parameter that has no value
                                 of its own until one is given. *)
                              "default", p.default ]) t.params) ]
    ) Device.all))

(* Add a device to a simulation: the body says which kind, what to call it, and
 * the characteristics that kind is built from (see [get_device_types]).
 *
 *   { "type": "switch", "name": "sw1", "params": { "ports": 24 } }
 *
 * The name may be left out, or left empty, for one to be picked that nothing
 * else here answers to -- "switch-3", or, for a cable, the names of its two
 * ends. That is what the interface sends when the reader did not type one, and
 * it is the only way to be sure of a free name: a name checked beforehand and
 * sent afterwards is one something else may have taken in between.
 *
 * Only whole devices, at the top of the tree, with the few characteristics that
 * have to be settled before there is anything to configure. Everything else
 * about the new device is a property of it, edited afterwards -- which is also
 * the only order that can work, since which properties it has is decided by
 * what is answered here.
 *
 * Answers with the widget that was built, as [get_widget] would. *)
let create_widget _mth matches _vars qry_body resp =
    let sim = simulation_of_matches matches 1 in
    let json =
        match Yojson.Basic.from_string qry_body with
        | exception _ ->
            bad_request "Not a device: %S (expected {\"type\": ..., \"name\": \
                         ..., \"params\": {...}})" qry_body
        | `Assoc _ as j -> j
        | j -> bad_request "Not a device: %s" (Yojson.Basic.to_string j) in
    let field ?absent name =
        match Yojson.Basic.Util.member name json with
        | `String s -> s
        | `Null ->
            (match absent with
            | Some s -> s
            | None -> bad_request "A device needs a %S" name)
        | v -> bad_request "%S must be a string, not %s" name
                   (Yojson.Basic.to_string v) in
    (* An absent name is an empty one, which is what [Device.make] reads as
       "pick one". *)
    let type_ = field "type" and name = field ~absent:"" "name" in
    if Device.find type_ = None then
        bad_request "There is no such thing as a %S. See /api/device-types \
                     for what there is" type_ ;
    let params =
        match Yojson.Basic.Util.member "params" json with
        | `Null -> []
        | `Assoc l -> l
        | v -> bad_request "%S must be an object, not %s" "params"
                   (Yojson.Basic.to_string v) in
    Simulation.borrow sim (fun () ->
        (* Under the lock, since building a device wires it into a graph the
         * simulation is walking, and may schedule its first events. *)
        match Device.make type_ ~parent:sim.root name params with
        | exception Widget.Bad_value m ->
            bad_request "Cannot make a %s: %s" type_ m
        | w ->
            Log.(log sim.root.logger Info (lazy (
                Printf.sprintf "Added %s %S" type_ (Widget.full_name w)))) ;
            respond resp (json_of_widget w))

let delete_widget _mth matches _vars _qry_body resp =
    let sim = simulation_of_matches matches 1 in
    Simulation.borrow sim (fun () ->
        let w = widget_of_matches sim matches 2 in
        if w == sim.root then
            bad_request "%s is the root of simulation %s and cannot be deleted"
                (Widget.full_name w) (Simulation.name sim) ;
        (* What cannot be built cannot be removed either: a part of a device is
         * not a device, and offering to delete a host's adapter -- leaving a
         * host whose port answers for a widget nobody can see -- would be
         * offering something the API has no way to undo. *)
        if Device.of_widget w = None then
            bad_request "%s is not a device this interface can delete. \
                         See /api/device-types for the ones it can"
                (Widget.full_name w) ;
        let full_name = Widget.full_name w in
        (* Under the lock like every other change, and rather more so: this
         * stops devices and unplugs cables the simulation may be walking. *)
        Widget.destroy w ;
        Log.(log sim.root.logger Info (lazy (
            Printf.sprintf "Deleted %S" full_name))) ;
        respond resp (`Assoc [ "deleted", `String full_name ]))

(* Place a widget on the map, or take its place away with a body of "null".
 *
 * The one way in: the "latitude" and "longitude" properties only read (a place
 * is a pair, and setting one half at a time would put a widget somewhere nobody
 * asked for). A refused coordinate is a 400 like a refused property value,
 * since it is the same kind of mistake. *)
let set_location _mth matches _vars qry_body resp =
    let sim = simulation_of_matches matches 1 in
    Simulation.borrow sim (fun () ->
        let w = widget_of_matches sim matches 2 in
        let json =
            match Yojson.Basic.from_string qry_body with
            | exception _ ->
                bad_request "Not a location: %S (expected {\"lat\": ..., \
                             \"lon\": ...} or null)" qry_body
            | j -> j in
        let location =
            match json with
            | `Null -> None
            | `Assoc _ ->
                let field name =
                    match Yojson.Basic.Util.member name json with
                    | `Null -> bad_request "A location needs a %S" name
                    | v ->
                        (match Widget.to_float v with
                        | exception Widget.Bad_value m ->
                            bad_request "%s: %s" name m
                        | f -> f) in
                Some Widget.{ lat = field "lat" ; lon = field "lon" }
            | _ ->
                bad_request "Not a location: %s"
                    (Yojson.Basic.to_string json) in
        (match Widget.place w location with
        | exception Invalid_argument m -> bad_request "%s" m
        | () -> ()) ;
        Log.(log w.logger Info (lazy (
            match location with
            | None -> "Taken off the map"
            | Some l -> Printf.sprintf "Placed at %g, %g" l.lat l.lon))) ;
        respond resp (json_of_widget w))

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

(* What a metric has been worth, as the simulation wrote it down: one list of
 * points per parameter row.
 *
 * [since] is the time of the last point the caller already has, and the answer
 * holds what was taken strictly after it -- so polling with the last [t] seen
 * asks exactly for what is missing, and asking with no [since] at all brings
 * back the whole history that is kept.
 *
 * [now] and [rate] come along because a plot needs to know where the present
 * is and how far apart the points were meant to be: a gap wider than the rate
 * is a simulation that had nothing to do, not points that went missing. *)
let get_property_history _mth matches vars _qry_body resp =
    let sim = simulation_of_matches matches 1 in
    (* Only finding the property needs the simulation held still. Reading the
       history out of the ring does not (see [Simulation.metric_history]), and
       neither does writing the answer -- which, for a first request that asks
       for the whole ring, is the longest part of the lot. *)
    let w, p, metric =
        Simulation.borrow sim (fun () ->
            let w = widget_of_matches sim matches 2 in
            let p = property_of_matches w matches 3 in
            match p.metric with
            | Some m -> w, p, m
            | None ->
                bad_request "Property %S of %s is not a metric, and nothing \
                             is written down about it"
                    p.name (Widget.full_name w)) in
    let since =
        match Hashtbl.find_option vars "since" with
        | None -> None
        | Some s ->
            (match float_of_string s with
            | exception _ ->
                bad_request "since must be a simulated time, not %S" s
            | f when not (Float.is_finite f) ->
                bad_request "since must be a simulated time, not %S" s
            | f -> Some (Clock.Time.o f)) in
    let series = Simulation.metric_history ?since sim w.id p.name in
    let json_of_point (t, v) =
        `Assoc [ "t", `Float (t : Clock.Time.t :> float) ;
                 "value", Metric.value_to_json v ] in
    let json_of_series (params, points) =
        `Assoc [ "params",
                 Yojson.Safe.to_basic (Metric.Params.to_yojson params) ;
                 "points", `List (List.map json_of_point points) ] in
    respond resp (`Assoc [
        "now", `Float (Simulation.now sim : Clock.Time.t :> float) ;
        "rate", `Float (Simulation.metrics_sample_rate sim :
                            Clock.Interval.t :> float) ;
        "kind", `String (Metric.kind_name metric) ;
        "units", `String p.units ;
        "series", `List (List.map json_of_series series) ])

(* What a widget logged, oldest first.
 *
 * [since] is exclusive and is a simulated time, which is enough to ask for
 * exactly what one has not seen: see [Log.messages] for why one timestamp is
 * one dispatch and cannot be delivered by halves.
 *
 * [lost] says that something logged after [since] has since been overwritten:
 * the queues are small, and a window that just stopped showing lines without
 * saying so would claim a continuity it does not have. It is a flag rather
 * than a count because what a reader can do about it is the same either way --
 * slow the simulation down. *)
(* The bytes of the file a [FileName] property names.
 *
 * The path is the widget's own answer, never the caller's: this route names a
 * widget and one of its properties, and what that property returns is what is
 * served. Nothing sent by a client reaches the filesystem, which is why there
 * is no traversal to guard against here -- and why a widget declares a
 * property of that kind only for a file it means to hand over.
 *
 * Opened, and its length taken, while the simulation is held still; read
 * afterwards. A recording grows as it is fetched, and what is served is the
 * length it had when it was asked for: for a pcap flushed packet by packet
 * (see [Pcap.Pdu.save]) that is a whole number of records, and so a file that
 * can be read rather than one that stops in the middle of one. *)
let get_property_file _mth matches _vars _qry_body resp =
    let sim = simulation_of_matches matches 1 in
    let ic, len, fname =
        Simulation.borrow sim (fun () ->
            let w = widget_of_matches sim matches 2 in
            let p = property_of_matches w matches 3 in
            let rec names_a_file = function
                | Widget.FileName -> true
                | Widget.Optional k | Widget.Hint (_, k) -> names_a_file k
                | _ -> false in
            if not (names_a_file p.kind) then
                bad_request "Property %S of %s does not name a file"
                    p.name (Widget.full_name w) ;
            let path =
                match p.getter () with
                | `String path -> path
                | `Null ->
                    not_found "Property %S of %s names no file yet"
                        p.name (Widget.full_name w)
                | v ->
                    bad_request "Property %S of %s is not a file name but %s"
                        p.name (Widget.full_name w) (Yojson.Basic.to_string v) in
            match Stdlib.open_in_bin path with
            | exception Sys_error m -> not_found "%s" m
            | ic ->
                (* What to call it once it is saved: the widget's name, which
                   is what the reader knows it by, and the extension of the
                   file it really is. Not the file's own name -- that is an
                   internal matter (see [Pcap.next_recorder_file]) and says
                   nothing to whoever asked for it. *)
                let fname = w.Widget.name ^ Filename.extension path in
                ic, Stdlib.in_channel_length ic, fname) in
    let body =
        match Stdlib.really_input_string ic len with
        | exception e ->
            Stdlib.close_in_noerr ic ;
            bad_request "Cannot read %s: %s" fname (Printexc.to_string e)
        | body -> Stdlib.close_in ic ; body in
    String.print resp body ;
    (* Saved rather than shown. Percent-escaped, since the name came from
       whoever built the widget and this is a header: a quote or a newline in
       it would end this header and begin another. Given twice, as RFC 6266
       has it -- the starred form is percent-decoded by the browser, and so
       arrives back as the name that was typed, while the plain one is the
       ASCII anything older falls back to. *)
    let escaped = Tools.escape_fname fname in
    200, [ "Content-Type", "application/octet-stream" ;
           "Content-Disposition",
           Printf.sprintf "attachment; filename=\"%s\"; filename*=UTF-8''%s"
               escaped escaped ]

let get_logs _mth matches vars _qry_body resp =
    let sim = simulation_of_matches matches 1 in
    let level =
        match Hashtbl.find_option vars "level" with
        | None -> Log.max_level
        | Some name ->
            (match List.find (fun lvl ->
                       Log.string_of_int_level lvl = String.lowercase name)
                       (List.init Log.num_levels identity) with
            | exception Not_found ->
                bad_request "No such log level: %S. One of %s" name
                    (List.init Log.num_levels Log.string_of_int_level |>
                     String.join ", ")
            | lvl -> lvl) in
    let since =
        match Hashtbl.find_option vars "since" with
        | None -> None
        | Some s ->
            (match float_of_string s with
            | exception _ ->
                bad_request "since must be a simulated time, not %S" s
            | f when not (Float.is_finite f) ->
                bad_request "since must be a simulated time, not %S" s
            | f -> Some (Clock.Time.o f)) in
    (* Held only while the messages are collected: a logger is written to by
       the dispatcher, and reading one halfway through a dispatch would give
       half of what that dispatch had to say. Forcing them into JSON afterwards
       needs nothing of the simulation. *)
    let w, lost, msgs =
        Simulation.borrow sim (fun () ->
            let w = widget_of_matches sim matches 2 in
            let lost, msgs = Log.messages ?since ~max_level:level w.logger in
            w, lost, msgs) in
    let json_of_msg (ts, lvl, text) =
        `Assoc [ "t", `Float (ts : Clock.Time.t :> float) ;
                 "level", `String (Log.string_of_level lvl) ;
                 "text", `String text ] in
    respond resp (`Assoc [
        "now", `Float (Simulation.now sim : Clock.Time.t :> float) ;
        "widget", `Int w.id ;
        "lost", `Bool lost ;
        "messages", `List (List.map json_of_msg msgs) ])

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
    (* Before the property itself, whose [.+] would otherwise swallow the
       trailing /history. *)
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets/\\([0-9]+\\)/properties/\\(.+\\)/history$",
        (fun mth matches vars qry_body resp ->
            match mth with
            | "GET" -> get_property_history mth matches vars qry_body resp
            | _ -> raise (Opache.ResourceError (405, "Method not allowed"))) ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets/\\([0-9]+\\)/properties/\\(.+\\)/file$",
        (fun mth matches vars qry_body resp ->
            match mth with
            | "GET" -> get_property_file mth matches vars qry_body resp
            | _ -> raise (Opache.ResourceError (405, "Method not allowed"))) ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets/\\([0-9]+\\)/properties/\\(.+\\)$",
        (fun mth matches vars qry_body resp ->
            match mth with
            | "GET" -> get_property mth matches vars qry_body resp
            | "PUT" | "POST" -> set_property mth matches vars qry_body resp
            | _ -> raise (Opache.ResourceError (405, "Method not allowed"))) ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets/\\([0-9]+\\)/properties$",
        get_properties ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets/\\([0-9]+\\)/logs$",
        get_logs ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets/\\([0-9]+\\)/location$",
        (fun mth matches vars qry_body resp ->
            match mth with
            | "PUT" | "POST" -> set_location mth matches vars qry_body resp
            | _ -> raise (Opache.ResourceError (405, "Method not allowed"))) ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets/\\([0-9]+\\)$",
        (fun mth matches vars qry_body resp ->
            match mth with
            | "GET" -> get_widget mth matches vars qry_body resp
            | "DELETE" -> delete_widget mth matches vars qry_body resp
            | _ -> raise (Opache.ResourceError (405, "Method not allowed"))) ;
    Str.regexp "/api/simulations/\\([0-9]+\\)/widgets$",
        (fun mth matches vars qry_body resp ->
            match mth with
            | "GET" -> get_widgets mth matches vars qry_body resp
            | "POST" -> create_widget mth matches vars qry_body resp
            | _ -> raise (Opache.ResourceError (405, "Method not allowed"))) ;
    Str.regexp "/api/device-types$", get_device_types ]
