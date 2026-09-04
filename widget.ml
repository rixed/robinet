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
  Any object that can be visualized and manipulated via the API
 *)
open Batteries

(* Where a widget is in the world, when it is anywhere.
 *
 * Degrees of latitude and longitude, as GeoIP hands them out and as simwan
 * reads them to derive a cable's length and hence its latency: the picture and
 * the timings it is supposed to explain must be computed from the same
 * numbers, or the picture explains nothing.
 *
 * Only what the map draws on its plane -- routers, LANs, hosts -- has a place
 * of its own. What is inside one of those boxes is at the same place as the
 * box, and a TCP layer is nowhere at all, so a widget's location is an option
 * and [None] means "no place of its own". It is not 0,0, which is a real spot
 * in the Gulf of Guinea. *)
type location = { lat : float ; lon : float }

type t =
    { (* The stable identity of a widget.
       * Names are not stable: a widget can be moved elsewhere in the tree, and
       * is renamed when it arrives among siblings that have its name (see
       * [unique_among]). The administration UI, the browser URL and
       * (eventually) the saved topology all need a handle that survives those
       * changes, so that handle is this id. *)
      id : int ;
      (* Which simulation this widget belongs to. An id rather than the
       * simulation itself, because a simulation holds the root of its widget
       * tree and this module is therefore compiled before it. A widget only
       * ever relates to widgets of its own simulation: a cable cannot span two
       * clocks. *)
      sim : int ;
      (* A mere label. Must not contain '/' so that [full_name] stays
       * unambiguous, and differs from every sibling's so that [full_name]
       * names this widget and no other. Mutable because that second rule is
       * enforced on arrival, and a widget arrives twice: when it is built and
       * whenever it is moved. *)
      mutable name : string ;
      (* We want to be able to navigate the logs/stats/characteristics of
       * every simulated things (aka "widgets").
       * Widgets are connected with TRX in various ways, sometime "vertically",
       * as a stack of layers to assemble composed objects (ex: a service with
       * a host with an HTTP layer with a TCP layer with an IP layer with an
       * ETH layer), and sometimes "horizontally" as connections between various
       * objects, mostly via cables.
       * From the point of view of the simulator, all these are just trxs
       * connected together.
       * Those relationships are indicated at construction time.
       *
       * Parent / children: widgets form a hierarchical tree. The full_name of a
       * widget indicates that hierarchy. *)
      mutable parent : t option ;
      mutable children : t list ;
      (* Siblings: When widgets are connected "horizontally" to others.
       * Widget names are then unrelated. *)
      mutable peers : peer list ;
      (* Where it is, if it is anywhere: see [location]. Mutable because
       * placing a box is something the reader does, from the map. *)
      mutable location : location option ;
      logger : Log.t ;
      (* Where a cable reaches the device this widget stands for, if anywhere *)
      mutable ports : ports ;
      (* What kind of device this widget stands for -- "host", "switch" --
       * named the way the catalogue of buildable devices names it (see
       * [Device.all]), or [None] when the widget is a *part* of a device
       * rather than a whole one: an adapter, a router's interface, a server
       * running on a host.
       *
       * Set by the constructor of the device itself, not by the catalogue, so
       * that a network wired up by an OCaml program is described the same way
       * as one built through the API. What the catalogue then says is which of
       * these kinds it knows how to build -- and therefore, the API refusing
       * to remove what it could not put back, which ones it will delete. *)
      mutable device : string option ;
      (* How to stop the thing this widget stands for, called by [destroy]
       * before the widget leaves the tree: cut its power, unplug the cable.
       * Set by whoever built that thing, since nothing else knows how to stop
       * it -- and only by whoever gave it its own power supply, so that
       * deleting one of several devices sharing a supply does not switch off
       * the others.
       *
       * Nothing here undoes the wiring *within* a device: its trxs point at
       * one another and at nothing else, so they go when the last reference to
       * them does. Only cables cross from one device to another, and only they
       * have to be told. *)
      mutable on_delete : unit -> unit ;
      (* Setter and getter of configurable properties: *)
      mutable properties : property list }

(* From a high-level perspective (the API), a cable reaches "port n of device d",
 * not some internal TRX. Ports are a way to designate and reach those user
 * visible sockets where a cable can be attached.
 *
 * A device made of other devices answers by calling theirs, and in doing so
 * decides which of its parts each of its port numbers reaches. That decision is
 * the point. A gateway is a router, a hub and a server wired together, and
 * offers two ports -- the outside and the LAN -- while every other end inside it
 * is already spoken for.
 *
 * Most widgets have none. *)
and ports =
    { (* How many cables the device takes. *)
      count : unit -> int ;
      (* Whether port [n] has one already. *)
      is_connected : int -> bool ;
      (* Port [n], as something to plug a cable into. *)
      dev : int -> Tools.dev ;
      (* The widget port [n] really belongs to, which is what a cable joining it
       * is recorded as reaching: a host's adapter rather than the host, a
       * router's interface rather than the router. Itself, for a device whose
       * ports are not widgets of their own -- a hub's and a switch's are
       * interchangeable, and a number for them would mean nothing. *)
      owner : int -> t ;
      (* Undo what plugging a cable into port [n] did: the port stops emitting
       * and says it is free again. There is no way back through [dev], since
       * installing a reader is what marks a port connected in the first place,
       * so the device has to offer the way out as well as the way in. *)
      disconnect : int -> unit }

and peer = { widget : t ;
             via : t option }

and property = { name : string ;
                descr : string ;
                units : string ;
               getter : (unit -> value) ;
               (* If that property can be set *)
               setter : (value -> unit) option ;
               (* The metric this property reads, when it reads one. The getter
                * renders it for display and the kind says so; this is the
                * thing itself, for whoever wants its figures rather than their
                * rendering -- the sampler that keeps a history of them does,
                * and reading them back out of the getter's JSON would be
                * absurd. *)
               metric : Metric.metric option ;
               (* What the value looks like, so that the UI can offer the right
                * input and reject nonsense before submitting it. Values still
                * travel as strings: this only says how to render one. *)
                 kind : kind ;
               (* Whether a row of the property panel is worth spending on this
                * when it reads as nothing.
                *
                * Absence usually says something: a DHCP server that serves no
                * gateway is configured that way, and the reader has to be able
                * to see it. But a property every widget carries whether or not
                * it means anything for that widget -- where it is on the map --
                * says nothing at all when it is absent, and there are two of
                * those on every widget in the tree. Those are the ones this is
                * for. *)
               only_when_set : bool }

(* A property value, in the shape the administration interface speaks.
 *
 * Not a string: properties exist only for that interface, so its own type is
 * their natural one, and keeping values typed all the way to the setter spares
 * every property author from inventing a string encoding -- and from getting it
 * wrong, which is easier than it sounds (string_of_float renders 5. as "5.",
 * which is not a number any browser will accept).
 *
 * [Basic] rather than [Safe]: the three extra constructors Safe carries --
 * Intlit, Tuple, Variant -- cannot mean anything here, and would only show up
 * as dead branches, or worse, be swallowed by a catch-all. *)
and value = Yojson.Basic.t

and kind =
    | String
    (* A string that happens to name a file the widget has written, which the
     * API will therefore hand over on request (see the property "file" route)
     * and the interface offers to download. What a property of this kind
     * returns is what gets served, so a widget puts a path here only if it
     * means to give that file away. *)
    | FileName
    | Int
    | Float
    (* "true" or "false", as the setter reads them *)
    | Bool
    (* One of those values, and nothing else *)
    | Enum of string array
    (* The id of another widget of the same simulation: what a cable's two ends
     * are. Not an [Int], although that is what travels: the UI has the widgets
     * of the simulation in hand and can offer them by name, which no number box
     * can do. *)
    | Widget_id
    (* A number known to lie within those bounds *)
    | FRange of float * float
    | IRange of int * int
    (* A family of counts or measures, keyed by the parameters of the events
     * they come from: it reads as a small table, and the only thing a write
     * does is reset it. Which sort of metric it is comes with the value, which
     * a metric, unlike a range, describes itself. *)
    | Metric
    (* A value that may be absent, which is [`Null] on the wire. Build one with
     * [optional] rather than by hand, so that the combinations that mean
     * nothing cannot be written. *)
    | Optional of kind
    (* Any number of values of the same kind, in order, which is a [`List] on
     * the wire. The interface draws it as a column of inputs, or as a table
     * when what is repeated is a record. Build one with [list]. *)
    | List of kind
    (* A fixed set of named values, which is an [`Assoc] on the wire. The
     * interface draws it as a row of named inputs, and as one row of the table
     * when it is what a list repeats.
     *
     * An array rather than an association list because the order is the order
     * of the columns: it is decided once, by whoever declares the property,
     * and every value of that property is then laid out the same way. Build
     * one with [record]. *)
    | Record of (string * kind) array
    (* A value written a particular way, with an example of it: what the
     * interface shows in the input while it is empty. Not a kind of its own --
     * it is one more thing said about the value inside it -- and where a
     * description explains what a value is for, this shows what one looks
     * like. Build one with [hint]. *)
    | Hint of string * kind

(* What a kind is called when a refusal has to name it. *)
let rec kind_name = function
    | String -> "a string"
    | FileName -> "a file name"
    | Int -> "a whole number"
    | Float -> "a number"
    | Bool -> "a boolean"
    | Enum _ -> "a choice"
    | Widget_id -> "a widget"
    | FRange _ | IRange _ -> "a range"
    | Metric -> "a metric"
    | Optional k -> "an optional value ("^ kind_name k ^")"
    | List k -> "a list of "^ kind_name k
    | Record _ -> "a record"
    | Hint (_, k) -> kind_name k

(* Only a value can be absent, and only once: [Optional (Optional _)] has no
 * second absence to describe, and a metric is a table that is always there --
 * an empty one when nothing has happened yet. A list has none either: a list
 * that is not there and an empty one would read the same in the interface,
 * and mean the same to every setter. *)
let optional = function
    | (Optional _ | Metric | List _) as k ->
        invalid_arg ("Widget.optional: nothing to make optional in "^
                     kind_name k)
    | k -> Optional k

(*$T optional
  optional Int = Optional Int
  (try ignore (optional (Optional Int)) ; false with Invalid_argument _ -> true)
  (try ignore (optional Metric) ; false with Invalid_argument _ -> true)
  (try ignore (optional (list Int)) ; false with Invalid_argument _ -> true)
 *)

(** [k], with an example of how it is written: a port range as "min-max", an
 * address as "192.168.0.1". It is shown in the input while that input is
 * empty, so it is worth having wherever the name of a field does not say how
 * to fill it in.
 *
 * Only what is typed into a single input has a shape to show. A table has no
 * one input to show it in, and a value that may be absent is hinted through
 * the value it may hold: [optional (hint "min-max" String)]. *)
let hint h = function
    | (Optional _ | Metric | List _ | Record _ | Hint _) as k ->
        invalid_arg ("Widget.hint: nothing to write an example in for "^
                     kind_name k)
    | k -> Hint (h, k)

(*$T hint
  hint "a-b" String = Hint ("a-b", String)
  optional (hint "a-b" String) = Optional (Hint ("a-b", String))
  (try ignore (hint "x" (optional Int)) ; false with Invalid_argument _ -> true)
  (try ignore (hint "x" (hint "y" Int)) ; false with Invalid_argument _ -> true)
  (try ignore (hint "x" (list Int)) ; false with Invalid_argument _ -> true)
 *)

(** A list of [k]. What may be repeated is a value the interface has a single
 * input for, or a record of those: those are the two shapes it can draw, a
 * column and a table.
 *
 * A list of lists has no such shape, and neither has a list of values that may
 * each be absent -- an element that is not there is one the list does not
 * hold. *)
let list = function
    | (Optional _ | Metric | List _) as k ->
        invalid_arg ("Widget.list: cannot repeat "^ kind_name k)
    | k -> List k

(*$T list
  list Int = List Int
  (try ignore (list (list Int)) ; false with Invalid_argument _ -> true)
  (try ignore (list (optional Int)) ; false with Invalid_argument _ -> true)
  (try ignore (list Metric) ; false with Invalid_argument _ -> true)
 *)

(** A record of those named fields, in the order the interface must lay them
 * out.
 *
 * A field is a value with a single input, or one that may be absent: a record
 * is a row, and a row is made of cells. A field that is itself a record or a
 * list is not a cell, and would have to be drawn inside one.
 *
 * Names are what the fields are keyed by on the wire, so there must be no two
 * alike, and none empty. *)
let record fields =
    if Array.length fields = 0 then
        invalid_arg "Widget.record: a record with no field describes nothing" ;
    Array.iter (fun (name, k) ->
        if name = "" then
            invalid_arg "Widget.record: a field must have a name" ;
        match k with
        | List _ | Record _ | Metric ->
            invalid_arg ("Widget.record: field "^ name ^" cannot be "^
                         kind_name k)
        | _ -> ()
    ) fields ;
    Array.iteri (fun i (name, _) ->
        Array.iteri (fun j (name', _) ->
            if j > i && name = name' then
                invalid_arg ("Widget.record: two fields named "^ name)
        ) fields
    ) fields ;
    Record fields

(*$T record
  record [| "a", Int ; "b", optional String |] = \
      Record [| "a", Int ; "b", Optional String |]
  (try ignore (record [||]) ; false with Invalid_argument _ -> true)
  (try ignore (record [| "a", Int ; "a", Int |]) ; \
   false with Invalid_argument _ -> true)
  (try ignore (record [| "", Int |]) ; false with Invalid_argument _ -> true)
  (try ignore (record [| "a", list Int |]) ; \
   false with Invalid_argument _ -> true)
  (try ignore (record [| "a", record [| "b", Int |] |]) ; \
   false with Invalid_argument _ -> true)
 *)

(* A table of records is the one that is worth having, and the reason for both:
   see the routing tables. *)
(*$T list
  list (record [| "dest", String ; "via", optional String |]) = \
      List (Record [| "dest", String ; "via", Optional String |])
 *)

let property ?(descr="") ?(units="") ?metric ?setter ?(kind=String)
             ?(only_when_set=false) ~getter name =
    { name ; descr ; units ; getter ; setter ; kind ; metric ; only_when_set }

(* Add new properties before default ones: *)
let add_properties t properties =
    t.properties <- properties @ t.properties

(** A metric, as a property: it reads as the metric's current figures, and the
 * only thing that can be written to it is a reset -- whatever the value. *)
let metric_property ?descr ?units ?(resettable=true) name metric =
    property name ?descr ?units ~kind:Metric ~metric
        ~getter:(fun () -> Metric.to_json metric)
        ?setter:(if resettable then Some (fun _ -> Metric.reset metric) else None)

(** What a setter raises when handed something it cannot use. The API turns it
 * into a 400 with this message, like any other exception a setter throws. *)
exception Bad_value of string

let bad_value fmt =
    Printf.ksprintf (fun s -> raise (Bad_value s)) fmt

(* Coercions for setters to read their argument with.
 *
 * JSON has a single number type while Yojson has two, so a UI sending a round
 * number for a float property delivers `Int, not `Float: a setter that matched
 * only `Float would refuse 42 and accept 42.5, which is the kind of bug that
 * only shows up when a user happens to type a whole number. These accept both,
 * and a string besides, so that a value typed by hand also works. *)

let to_float = function
    | `Float f -> f
    | `Int i -> float_of_int i
    | `String s ->
        (try float_of_string s
        with _ -> bad_value "not a number: %S" s)
    | v -> bad_value "expected a number, not %s" (Yojson.Basic.to_string v)

let to_float_range ?(min=neg_infinity) ?(max=infinity) v =
    let f = to_float v in
    if f < min || f > max then
        (* An end that is not there is left blank rather than spelled out: the
         * reader of "not in range (0…inf)" has to work out that the infinity
         * is us saying there is no upper bound. *)
        let bound b = if Float.is_finite b then Printf.sprintf "%g" b else "" in
        bad_value "%g is not in range (%s…%s)" f (bound min) (bound max)
    else f

let to_int = function
    | `Int i -> i
    | `Float f when f = float_of_int (int_of_float f) -> int_of_float f
    | `Float f -> bad_value "expected a whole number, not %g" f
    | `String s ->
        (try int_of_string s
        with _ -> bad_value "not a whole number: %S" s)
    | v -> bad_value "expected a whole number, not %s" (Yojson.Basic.to_string v)

let to_int_range ?(min=min_int) ?(max=max_int) v =
    let i = to_int v in
    if i < min || i > max then
        (* [min_int] and [max_int] are how "no bound on this side" is spelled,
         * here as in what the API sends the interface: naming them would only
         * puzzle whoever reads the refusal. *)
        let bound b = if b = min_int || b = max_int then ""
                      else string_of_int b in
        bad_value "%d is not in range (%s…%s)" i (bound min) (bound max)
    else i

(*$T to_field
  (try ignore (to_field "a" to_int (`Assoc [ "a", `String "x" ])) ; false \
   with Bad_value m -> m = "a: not a whole number: \"x\"")
  (try ignore (to_field "b" to_int (`Assoc [ "a", `Int 1 ])) ; false \
   with Bad_value _ -> true)
  to_field "a" to_int (`Assoc [ "a", `Int 1 ]) = 1
 *)

(*$T to_list
  (try ignore (to_list to_int (`List [ `Int 1 ; `String "x" ])) ; false \
   with Bad_value m -> m = "row 2: not a whole number: \"x\"")
  to_list to_int (`List [ `Int 1 ; `Int 2 ]) = [ 1 ; 2 ]
 *)

(** Read a value that may be absent: [`Null] is the absence, anything else is
 * read by [f]. The counterpart of an [Optional] kind, for the setter of a
 * property whose field is an option. *)
let to_option f = function
    | `Null -> None
    | v -> Some (f v)

(** Read a list of values, each with [f]. The counterpart of a [List] kind.
 *
 * The whole list is what a setter is handed: the interface sends what the
 * table holds after the edit, not the edit itself, so a setter replaces its
 * list rather than patching it. *)
let to_list f = function
    (* Which row was refused, counted the way the interface numbers them: a
     * table of a dozen routes that comes back "not a port number" leaves the
     * reader to find which of them it was about. *)
    | `List l ->
        List.mapi (fun i v ->
            try f v
            with Bad_value msg -> bad_value "row %d: %s" (i + 1) msg
        ) l
    | v -> bad_value "expected a list, not %s" (Yojson.Basic.to_string v)

(** Read the field [name] of a record with [f]. The counterpart of a [Record]
 * kind, one field at a time, which is how a setter rebuilds its own record:
 * it knows what it wants out of it, and in what order.
 *
 * A field that is not there is refused rather than read as absent: absence is
 * [`Null], and only for a field whose kind says it may be. *)
let to_field name f = function
    | `Assoc l as v ->
        (match List.assoc name l with
        | exception Not_found ->
            bad_value "no field %S in %s" name (Yojson.Basic.to_string v)
        (* Whatever [f] refuses, it refuses about this field, and a record of
         * eight of them has to say which one. Named here, once, rather than by
         * the reader of every field of every record. *)
        | v ->
            (try f v with Bad_value msg -> bad_value "%s: %s" name msg))
    | v -> bad_value "expected a record, not %s" (Yojson.Basic.to_string v)

let to_bool = function
    | `Bool b -> b
    | `String ("true" | "1") -> true
    | `String ("false" | "0") -> false
    | v -> bad_value "expected true or false, not %s" (Yojson.Basic.to_string v)

let to_string = function
    | `String s -> s
    (* Anything else is rendered as it would be on the wire, so that a property
     * declared as a string still gets something usable when handed a number. *)
    | v -> Yojson.Basic.to_string v

(* Some common encoder to JSON: *)

let json_of_optional sub = function
    | None -> `Null
    | Some v -> sub v

(* Most widgets have no ports: *)
let no_ports = {
    count = (fun () -> 0) ;
    (* Should never be called: *)
    is_connected = (fun _ -> assert false) ;
    dev = (fun _ -> assert false) ;
    owner = (fun _ -> assert false) ;
    disconnect = (fun _ -> assert false) }

(* Beware that the widget graph is cyclic (parent/children and peers point back
 * at each other), so widgets must never be compared with the polymorphic
 * equality; use physical equality throughout. *)

let full_name t =
    let rec loop full_name = function
        | None -> full_name
        | Some p -> loop ("/"^ p.name ^ full_name) p.parent in
    loop ("/"^ t.name) t.parent

(* Ids are unique across the whole process rather than merely within a
 * simulation, which costs nothing: allocating one needs no simulation in hand,
 * and widget creation is vanishingly rare on the time scale of a simulation.
 * They remain unique within a simulation, which is all the API asks of them. *)
let next_id =
    let seq = ref 0 in
    fun () ->
        let id = !seq in
        incr seq ;
        id

(* A latitude and a longitude, or nothing that can be drawn: an out of range
 * coordinate is not a placement that happens to be odd, it is one that has no
 * spot on any map. Checked in the one place a location is ever stored, so that
 * neither a caller nor the API can install one that the map would then have to
 * cope with. *)
(* The mean radius of the Earth, in metres. A sphere: the difference from the
 * ellipsoid is a couple of parts in a thousand, which is nothing beside the
 * question a distance is asked here -- how long a cable between two places has
 * to be, and hence how long a frame takes to cross it. *)
let earth_radius = 6_371_008.8

(** How far apart two places are, in metres, along the ground. *)
let distance a b =
    let rad d = d *. Float.pi /. 180. in
    let hav x = let s = sin (x /. 2.) in s *. s in
    let h = hav (rad (b.lat -. a.lat)) +.
            cos (rad a.lat) *. cos (rad b.lat) *. hav (rad (b.lon -. a.lon)) in
    (* [min 1.] because a rounding error above one has no arcsine, and the two
     * places that produce it are the antipodes. *)
    2. *. earth_radius *. asin (sqrt (min 1. h))

(* Paris to Lyon, a place to itself, and the antipodes -- the last of which is
   where a rounding error above one would have turned the arcsine into a nan. *)
(*$T distance
  distance { lat = 48.8566 ; lon = 2.3522 } { lat = 45.764 ; lon = 4.8357 } \
      |> Float.round |> ( = ) 391499.
  distance { lat = 12. ; lon = 34. } { lat = 12. ; lon = 34. } = 0.
  distance { lat = -90. ; lon = 0. } { lat = 90. ; lon = 0. } \
      |> Float.round |> ( = ) 20015114.
 *)

let check_location { lat ; lon } =
    if not (Float.is_finite lat) || lat < -90. || lat > 90. then
        invalid_arg (Printf.sprintf
            "Widget.location: latitude %g is not in (-90…90)" lat) ;
    if not (Float.is_finite lon) || lon < -180. || lon > 180. then
        invalid_arg (Printf.sprintf
            "Widget.location: longitude %g is not in (-180…180)" lon)

(** The name a widget will answer to under [parent]: the one asked for, or that
 * name with a number appended when a sibling has it already.
 *
 * Sibling names have to differ, and nothing wider than that is required: a path
 * then names a single widget (see [find_by_path]), while two hosts are both
 * free to call their adapter "eth", since the rest of the path tells those two
 * apart.
 *
 * Callers that name a part after what it is -- "eth", "nat", "dhcpd" -- get the
 * numbering for free, and are meant to: what they name is the kind of part,
 * not the instance. A name that came from the reader is a different matter, and
 * {!Device.make} refuses that one rather than quietly altering it. *)
let unique_among parent name =
    let taken n = List.exists (fun c -> c.name = n) parent.children in
    if not (taken name) then name else
    let rec loop i =
        let n = Printf.sprintf "%s-%d" name i in
        if taken n then loop (i + 1) else n in
    loop 2

(* The one place a widget is built. *)
let make_ ?parent ~sim ?now ?size ?location ?(properties=[]) ?device name =
    if String.contains name '/' then
        invalid_arg ("Widget.make: name must not contain '/': "^ name) ;
    let name =
        match parent with
        | None -> name
        | Some p -> unique_among p name in
    Option.may check_location location ;
    let logger = Log.make ?size ?now () in
    let t = {
        id = next_id () ;
        sim ;
        name ;
        parent ;
        children = [] ;
        peers = [] ;
        device ;
        on_delete = ignore ;
        location ;
        logger ;
        ports = no_ports ;
        properties } in
    (* Linking it to its parent is all the registration there is: a simulation's
     * inventory of widgets is that tree, reachable from its root.
     * Appended rather than prepended so that children stay in creation order,
     * which is the order they are then enumerated, listed by the API and shown
     * in the UI. Quadratic in the number of siblings, which is irrelevant:
     * widgets are created once, at set-up. *)
    Option.may (fun p -> p.children <- p.children @ [ t ]) parent ;
    (* Where it is, as something to read in the property panel. Every widget
     * gets the pair, whether it is placed or not: a widget is placed and taken
     * off the map long after it is built, and a property list that changed as
     * that happened would be one the UI could not keep a place for. An unplaced
     * widget reads as null, which is why the kind is optional -- and why the UI
     * leaves it out until there is something to show.
     *
     * Read through [t] rather than off the [location] argument, for the same
     * reason: the field moves, the argument does not. *)
    let coord f () =
        match t.location with None -> `Null | Some l -> `Float (f l) in
    add_properties t [
        property "latitude" ~units:"deg" ~kind:(optional Float) ~only_when_set:true
            ~descr:"Where it is, north of the equator."
            ~getter:(coord (fun l -> l.lat)) ;
        property "longitude" ~units:"deg" ~kind:(optional Float) ~only_when_set:true
            ~descr:"Where it is, east of Greenwich."
            ~getter:(coord (fun l -> l.lon)) ] ;
    t

(** Create a widget below [parent], in [parent]'s simulation and reading the
 * time from [parent]'s clock.
 *
 * A parent is always required, and always available: a caller either has the
 * widget it is building this one under, or has the simulation, whose root is
 * one [Simulation.root] away. That is what keeps the root the only parentless
 * widget of a simulation, and hence keeps it a complete inventory. *)
let make ~parent ?size ?location ?properties ?device name =
    make_ ~parent ~sim:parent.sim ~now:parent.logger.Log.now
          ?size ?location ?properties ?device name

(** Create the root of a simulation's widget tree: the only widget with no
 * parent, and the only one that has to be told which simulation it is in and
 * where to read the time. Called by [Simulation.make], and nowhere else. *)
let make_root ~sim ~now ?size ?location ?properties name =
    make_ ~sim ~now ?size ?location ?properties name

(** Enumerate [t] and all of its descendants, depth first. *)
let rec enum t =
    Enum.append
        (Enum.singleton t)
        (Enum.flatten (List.enum t.children /@ enum))

(** [t] and all of its descendants. *)
let descendants t =
    enum t |> List.of_enum

(** Lookup a widget by id within a tree. *)
let find root id =
    try
        enum root |>
        Enum.find (fun w -> w.id = id) |>
        Option.some
    with Not_found ->
        None

(** Lookup a widget by its [full_name] within a tree. Siblings differ in name
 * (see [unique_among]), so this returns at most one widget -- a list all the
 * same, since a path that names nothing has to come back as something. The
 * first component of the path is the root's own name. *)
let find_by_path root path =
    let names =
        String.split_on_char '/' path |>
        List.filter (fun n -> n <> "") in
    let matching name widgets =
        List.filter (fun w -> w.name = name) widgets in
    let rec loop candidates = function
        | [] -> candidates
        | name :: rest ->
            let children =
                List.concat (List.map (fun w -> w.children) candidates) in
            loop (matching name children) rest in
    match names with
    | [] -> []
    | first :: rest -> loop (matching first [ root ]) rest

(* Is [a] [t] itself or one of its ancestors? *)
let rec is_ancestor a t =
    a == t ||
    (match t.parent with
    | None -> false
    | Some p -> is_ancestor a p)

let unlink_from_parent t =
    Option.may (fun p ->
        p.children <- List.filter (fun c -> c != t) p.children
    ) t.parent

(** Delete a widget and, recursively, all of its children: a widget is made of
 * its children, so they cannot outlive it.
 *
 * Any peering relationship involving the deleted widgets is dropped, including
 * those where they merely served as the intermediary: a cable *is* the link, so
 * removing it disconnects its two ends.
 *
 * Unlinking it from its parent is all there is to it: nothing else holds a
 * reference, since a simulation's widgets are just its root's subtree. *)
let rec delete t =
    (* [List.iter] walks the list value we have now, which is unaffected by the
     * children unlinking themselves from [t.children] as they go: *)
    List.iter delete t.children ;
    t.children <- [] ;
    let mentions p =
        p.widget == t ||
        (match p.via with Some v -> v == t | None -> false) in
    let unlink w =
        w.peers <- List.filter (fun p -> not (mentions p)) w.peers in
    List.iter (fun p ->
        unlink p.widget ;
        Option.may unlink p.via
    ) t.peers ;
    t.peers <- [] ;
    unlink_from_parent t ;
    t.parent <- None

(** Take out of the simulation, for good, the thing a widget stands for.
 *
 * Where [delete] takes the picture apart, this takes the thing apart first:
 * everything within the doomed subtree is stopped (see [on_delete]), and every
 * cable reaching into it from outside is unplugged and deleted as well -- a
 * cable *is* the link, so it cannot outlive either of the two things it
 * joined.
 *
 * It lives here rather than with the devices because none of them can see the
 * whole of what is being deleted; each of them left behind an [on_delete]
 * saying how to stop itself, and this walks them. *)
let destroy t =
    let doomed = descendants t in
    (* A cable's widget usually sits outside the subtree -- under the root, or
     * under whatever groups the two ends -- so the walk above does not reach
     * it. Both of its ends name it when both are doomed, hence the [memq]. *)
    let cables =
        List.fold_left (fun cables (d : t) ->
            List.fold_left (fun cables p ->
                match p.via with
                | Some v when not (List.memq v cables) -> v :: cables
                | _ -> cables
            ) cables d.peers
        ) [] doomed in
    List.iter (fun (c : t) -> c.on_delete ()) cables ;
    List.iter (fun (d : t) -> d.on_delete ()) doomed ;
    (* After the cables have been unplugged, so that a port is told it is free
     * before the widget that owns it stops being reachable. *)
    List.iter delete cables ;
    delete t

(** Move a widget (and therefore its whole subtree) elsewhere in the hierarchy.
 *
 * It may be renamed on the way, if its new siblings include one of its name:
 * what a widget is called is only ever unique where it sits, so a move is the
 * other moment that has to be made to hold (see [unique_among]).
 *
 * Nothing else has to be updated: the id is unchanged and [full_name] is
 * computed on demand. A widget cannot leave its simulation. *)
let reparent t new_parent =
    if new_parent.sim <> t.sim then
        invalid_arg ("Widget.reparent: "^ full_name new_parent ^
                     " belongs to another simulation") ;
    if is_ancestor t new_parent then
        invalid_arg ("Widget.reparent: "^ full_name new_parent ^" is within "^
                     full_name t ^", that would create a cycle") ;
    unlink_from_parent t ;
    (* After the unlinking, so that a widget moved to the parent it already has
     * is not renamed after itself. *)
    t.name <- unique_among new_parent t.name ;
    t.parent <- Some new_parent ;
    new_parent.children <- t :: new_parent.children

(** Put a widget somewhere in the world, or nowhere with [None].
 *
 * Nowhere is a perfectly good answer and the usual one: a widget with no place
 * of its own is drawn wherever the map finds room for it, until someone says
 * where it belongs. *)
let place t location =
    Option.may check_location location ;
    t.location <- location

(** How many of [t]'s ports have no cable on them.
 *
 * A count rather than the ports themselves: what a reader is offered a device
 * for is whether there is room on it, and a device may have a great many
 * ports. Every [is_connected] is a lookup, so this is a walk that allocates
 * nothing -- if that ever became too much in itself, the device would have to
 * keep the tally as cables come and go. *)
let free_ports t =
    let ports = t.ports.count () in
    let rec loop free n =
        if n >= ports then free
        else loop (if t.ports.is_connected n then free else free + 1) (n + 1) in
    loop 0 0

(** The first port of [t] with no cable, if it has one left. *)
let first_free_port t =
    let rec loop n =
        if n >= t.ports.count () then None
        else if t.ports.is_connected n then loop (n + 1)
        else Some n in
    loop 0

(** The ports of [w], to be answered as one's own: for a device reached through
 * one of its parts and numbering its ports the same way -- a host through its
 * adapter, a router interface through its own. A device that has to say which
 * of several parts each port reaches writes the three functions itself. *)
let ports_of w =
    (* All three read [w.ports] when they are called, not now: it is a mutable
     * field, and a borrower that took [count] from the current record and
     * [dev] from an older one would answer for ports it cannot reach. *)
    { count = (fun () -> w.ports.count ()) ;
      is_connected = (fun n -> w.ports.is_connected n) ;
      dev = (fun n -> w.ports.dev n) ;
      owner = (fun n -> w.ports.owner n) ;
      disconnect = (fun n -> w.ports.disconnect n) }

(* Siblings differ, cousins need not, and a move into a parent that has the
   name renames the arrival. *)
(*$T unique_among
  ignore unique_among ; (* Called by reparent *) \
  let r = make_root ~sim:0 ~now:(fun () -> Clock.Time.o 0.) "r" in \
  let h1 = make ~parent:r "h" and h2 = make ~parent:r "h" in \
  h1.name = "h" && h2.name = "h-2" && \
  (make ~parent:h1 "eth").name = "eth" && \
  (make ~parent:h2 "eth").name = "eth" && \
  (reparent (make ~parent:h1 "h") r ; List.length r.children = 3 && \
   (List.nth r.children 0).name = "h-3")
 *)

(*$T check_location
  (try check_location { lat = 45.75 ; lon = 4.85 } ; true with _ -> false)
  (try check_location { lat = -90. ; lon = 180. } ; true with _ -> false)
  (try check_location { lat = 91. ; lon = 0. } ; false with Invalid_argument _ -> true)
  (try check_location { lat = 0. ; lon = -181. } ; false with Invalid_argument _ -> true)
  (try check_location { lat = nan ; lon = 0. } ; false with Invalid_argument _ -> true)
 *)

(* The properties read the field, not the location the widget was built with:
   a widget is placed, moved and taken off the map long after that. *)
(*$T place
  let w = make_root ~sim:0 ~now:(fun () -> Clock.Time.o 0.) "w" in \
  let read n = (List.find (fun p -> p.name = n) w.properties).getter () in \
  read "latitude" = `Null && read "longitude" = `Null && \
  (place w (Some { lat = 45.75 ; lon = 4.85 }) ; \
   read "latitude" = `Float 45.75 && read "longitude" = `Float 4.85) && \
  (place w None ; read "latitude" = `Null)
 *)

let same_via v1 v2 =
    match v1, v2 with
    | None, None -> true
    | Some a, Some b -> a == b
    | _ -> false

let has_peer t peer via =
    List.exists (fun p -> p.widget == peer && same_via p.via via) t.peers

let make_peers ?via t1 t2 =
    if t1.sim <> t2.sim then
        invalid_arg ("Widget.make_peers: "^ full_name t1 ^" and "^ full_name t2 ^
                     " belong to different simulations") ;
    (match via with
    | Some v when v.sim <> t1.sim ->
        invalid_arg ("Widget.make_peers: "^ full_name v ^
                     " belongs to another simulation")
    | _ -> ()) ;
    if t1 == t2 then
        invalid_arg ("Widget.make_peers: "^ full_name t1 ^
                     " cannot be its own peer") ;
    (match via with
    | Some v when v == t1 || v == t2 ->
        invalid_arg ("Widget.make_peers: "^ full_name v ^
                     " cannot be both an end and the intermediary")
    | _ -> ()) ;
    if has_peer t1 t2 via then
        invalid_arg ("Widget.make_peers: "^ full_name t1 ^" and "^
                     full_name t2 ^" are already peers via the same \
                     intermediary") ;
    t1.peers <- { widget = t2 ; via } :: t1.peers ;
    t2.peers <- { widget = t1 ; via } :: t2.peers ;
    Option.may (fun via ->
        via.peers <- { widget = t1 ; via = None } ::
                     { widget = t2 ; via = None } :: via.peers
    ) via
