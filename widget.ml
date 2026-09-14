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
open SimTypes

type t = widget

(* The types this module is about are declared in {!SimTypes}, with the
 * simulation and the power source they refer to and that refer back to them.
 * Named here as well, where a caller looks for them: an alias for each, and a
 * re-export for the extensible one, so that a module can still add its own
 * device without knowing where the type came from. *)
type device = SimTypes.device = ..
type location = SimTypes.location
type power = SimTypes.power
type property = SimTypes.property
type value = SimTypes.value
type kind = SimTypes.kind
type peer = SimTypes.peer
type ports = SimTypes.ports

(** Which simulation a widget belongs to: the one its power source schedules
 * on. It is not a field of its own -- there would then be two answers to keep
 * in step -- and a widget is never without one, since it takes its parent's
 * source and the root of a tree is built with its simulation's mains.
 *
 * A widget only ever relates to widgets of its own simulation: a cable cannot
 * span two clocks. *)
let sim (t : t) = t.power.sim

(* What a kind is called when a refusal has to name it. *)
let rec kind_name = function
    | String -> "a string"
    | Text -> "a text"
    | FileName -> "a file name"
    | Int -> "a whole number"
    | Float -> "a number"
    | Bool -> "a boolean"
    | Enum _ -> "a choice"
    | Set _ -> "a set of choices"
    | Widget_id -> "a widget"
    | FRange _ | IRange _ -> "a range"
    | Time -> "a timestamp"
    | Packet -> "a packet"
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
    | (Optional _ | Metric | List _ | Set _) as k ->
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
    | (Optional _ | Metric | List _ | Record _ | Hint _ | Set _) as k ->
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
 * hold. A set has one: a cell of ticked choices. *)
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

let property ?(descr="") ?(units="") ?metric ?setter ?can_set ?(kind=String)
             ?(only_when_set=false) ~getter name =
    (* No setter, no setting, so there is one way to ask and callers need not
     * check both. A setter with nothing said about when it applies is one that
     * always applies. *)
    let can_set =
        match setter with
        | None -> (fun () -> false)
        | Some _ -> can_set |? (fun () -> true) in
    { name ; descr ; units ; getter ; setter ; can_set ; kind ; metric ;
      only_when_set }

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

(** Read which of [choices] a value names: the interface sends a choice by its
 * place among them (see the [Enum] kind), and a number that is the place of
 * none of them is refused rather than stored -- a property that answers with a
 * value outside its own choices is one the interface can only show as a
 * number. *)
let to_choice choices v =
    let i = to_int v in
    let n = Array.length choices in
    if i < 0 || i >= n then
        bad_value "%d is none of the %d choices" i n
    else i

(*$T to_choice
  to_choice [| "a" ; "b" |] (`Int 1) = 1
  (try ignore (to_choice [| "a" ; "b" |] (`Int 2)) ; false \
   with Bad_value m -> m = "2 is none of the 2 choices")
  (try ignore (to_choice [| "a" ; "b" |] (`Int (-1))) ; false \
   with Bad_value _ -> true)
 *)

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

(*$T to_choices
  to_choices [| "a" ; "b" ; "c" |] (`List [ `Int 2 ; `Int 0 ]) = [ 0 ; 2 ]
  to_choices [| "a" ; "b" |] (`List [ `Int 1 ; `Int 1 ]) = [ 1 ]
  to_choices [| "a" ; "b" |] (`List []) = []
  (try ignore (to_choices [| "a" ; "b" |] (`List [ `Int 2 ])) ; false \
   with Bad_value _ -> true)
  (try ignore (to_choices [| "a" |] (`Int 0)) ; false \
   with Bad_value _ -> true)
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

(** Read which of [choices] a value names, any number of them: the counterpart
 * of the [Set] kind, as [to_choice] is of [Enum].
 *
 * What comes back is in order and without repetition, whatever order the
 * interface ticked them in and however many times: a set is what it holds, so
 * two equal sets must read as equal values, and a setter reading its own
 * property back must find what it wrote. *)
let to_choices choices = function
    (* Not [to_list], although a set travels as one: what that says when it
     * refuses an element is which row of a table it was, and a set is not a
     * table -- it is a row of boxes, and which choice is not one of the
     * choices already names itself. *)
    | `List l ->
        List.map (to_choice choices) l |>
        List.sort_unique compare
    | v ->
        bad_value "expected a set of choices, not %s" (Yojson.Basic.to_string v)

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

(* Every instant this interface hands out is a simulated one: seconds since
 * the simulation began, which is what a simulation dates everything by and
 * what comes back in a "since". What the world outside called that beginning
 * is the "epoch" of the simulation (see /api/simulations), and adding the two
 * is how a reader turns one of these into a date -- which only whoever
 * displays it has to do. *)
let json_of_time (t : Clock.Time.t) =
    `Float (Clock.Time.to_secs t)

(** A frame in a few words -- "Icmp/Ip/Eth" -- which is what the interface
 * shows for a packet before the reader asks to see more of it.
 *
 * A forward reference, because the module that can answer is {!Packet}, and
 * {!Packet} knows every protocol there is while every protocol knows this one:
 * it is compiled long after. Whoever wants packets described sets this (see
 * myadmin_api.ml), and until something does, a packet is its bytes and nothing
 * else -- which is what a program that never links {!Packet} gets. *)
let describe_packet : (Bitstring.bitstring -> string) ref =
    ref (fun _ -> "")

(** A frame, as the interface reads one: the bytes themselves, and what they
 * amount to.
 *
 * Both, and not one or the other, because they answer different questions and
 * neither can be had from the other where it is asked: the description is what
 * a reader skims a list of frames by, and the bytes are what a reader who has
 * found the one they wanted goes on to look at -- and what the packet editor
 * will be handed when it comes to open one. *)
let json_of_packet bits =
    `Assoc [ "bits", `String (Tools.hexstring_of_bitstring bits) ;
             "descr", `String (!describe_packet bits) ]

(* Most widgets have no ports: *)
let no_ports = {
    count = (fun () -> 0) ;
    (* Should never be called: *)
    is_connected = (fun _ -> assert false) ;
    dev = (fun _ -> assert false) ;
    owner = (fun _ -> assert false) ;
    disconnect = (fun _ -> assert false) ;
    get_capabilities = (fun _ -> Capabilities.Any) ;
    set_capabilities = (fun _ _ -> ()) }

(* Beware that the widget graph is cyclic (parent/children and peers point back
 * at each other), so widgets must never be compared with the polymorphic
 * equality; use physical equality throughout. *)

let full_name (t : t) =
    let rec loop full_name = function
        | None -> full_name
        | Some (p : t) -> loop ("/"^ p.name ^ full_name) p.parent in
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
let unique_among (parent : t) name =
    let taken n = List.exists (fun (c : t) -> c.name = n) parent.children in
    if not (taken name) then name else
    let rec loop i =
        let n = Printf.sprintf "%s-%d" name i in
        if taken n then loop (i + 1) else n in
    loop 2

(* The one place a widget is built. *)
(* A source of its own for [t], named after it, and switched off: a network is
 * built dark and lit once it stands, so that nothing in it goes looking for
 * what is not there yet -- a host for a DHCP server, a gateway's server for
 * the address it serves from. Whoever mints one switches it on as the last
 * thing it does, unless it was asked for a device that is to stay off. *)
let mint_power (t : t) =
    t.power <- { on = false ; name = full_name t ; sim = sim t } ;
    t.owns_power <- true

(* The properties every widget carries, whatever it stands for. Applied here
 * rather than written into the record, since a root widget is built by
 * [Simulation.make] and not by [make] (see there) and must carry them too.
 *
 * Read through [t] rather than off the arguments it was built with: what they
 * read moves, and a widget is placed, moved and taken off the map long after
 * it is built. *)
let add_common_properties (t : t) =
    let coord f () =
        match t.location with None -> `Null | Some l -> `Float (f l) in
    add_properties t [
        (* Every widget gets the pair, whether it is placed or not: a property
         * list that changed as one was placed would be one the UI could not
         * keep a place for. An unplaced widget reads as null, which is why the
         * kind is optional -- and why the UI leaves it out until there is
         * something to show. *)
        property "latitude" ~units:"deg" ~kind:(optional Float) ~only_when_set:true
            ~descr:"Where it is, north of the equator."
            ~getter:(coord (fun l -> l.lat)) ;
        property "longitude" ~units:"deg" ~kind:(optional Float) ~only_when_set:true
            ~descr:"Where it is, east of Greenwich."
            ~getter:(coord (fun l -> l.lon)) ;
        (* Read-only, and therefore not written into a saved network: what
         * went wrong here is a fact about this run. *)
        property "error" ~kind:(optional String) ~only_when_set:true
            ~descr:"What went wrong the last time it was switched."
            ~getter:(fun () ->
                match t.error with None -> `Null | Some m -> `String m) ]

(** Create a widget below [parent]: in [parent]'s simulation, reading the time
 * and numbering its messages from [parent]'s clock, and drawing on [parent]'s
 * power source unless it is handed one ([power]) or mints one of its own
 * ([own_power]).
 *
 * A parent is always required, and always available: a caller either has the
 * widget it is building this one under, or has the simulation, whose root is
 * one [Simulation.root] away. That is what keeps the root the only parentless
 * widget of a simulation, and hence keeps it a complete inventory -- and the
 * root is the one widget this does not build, since it cannot be built before
 * the simulation it belongs to (see [Simulation.make]). *)
let make ~parent ?power ?(own_power=false) ?size ?location
         ?(properties=[]) ?device_type name =
    if String.contains name '/' then
        invalid_arg ("Widget.make: name must not contain '/': "^ name) ;
    let name = unique_among parent name in
    Option.may check_location location ;
    let logger =
        Log.make ?size ~now:parent.logger.Log.now ~seq:parent.logger.Log.seq () in
    let t = {
        id = next_id () ;
        name ;
        parent = Some parent ;
        children = [] ;
        peers = [] ;
        device_type ;
        device = None ;
        made_with = None ;
        on_delete = ignore ;
        (* What it draws on until [own_power] says otherwise: what it was
         * handed, or what its parent draws on. *)
        power = (match power with Some p -> p | None -> parent.power) ;
        owns_power = false ;
        power_up = ignore ;
        power_down = ignore ;
        error = None ;
        location ;
        logger ;
        ports = no_ports ;
        properties } in
    if own_power then mint_power t ;
    (* Linking it to its parent is all the registration there is: a simulation's
     * inventory of widgets is that tree, reachable from its root.
     * Appended rather than prepended so that children stay in creation order,
     * which is the order they are then enumerated, listed by the API and shown
     * in the UI. Quadratic in the number of siblings, which is irrelevant:
     * widgets are created once, at set-up. *)
    parent.children <- parent.children @ [ t ] ;
    add_common_properties t ;
    t

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
        List.filter (fun (w : t) -> w.name = name) widgets in
    let rec loop candidates = function
        | [] -> candidates
        | name :: rest ->
            let children =
                List.concat (List.map (fun (w : t) -> w.children) candidates) in
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

(** Every cable reaching into [doomed] from outside it, which is where a cable
 * usually sits: under the root, or under whatever groups the two ends it
 * joins, and so out of reach of a walk of the subtree itself.
 *
 * Both of its ends name it when both are doomed, hence the [memq]. *)
let cables_of doomed =
    List.fold_left (fun cables (d : t) ->
        List.fold_left (fun cables p ->
            match p.via with
            | Some v when not (List.memq v cables) -> v :: cables
            | _ -> cables
        ) cables d.peers
    ) [] doomed

(** Move a widget (and therefore its whole subtree) elsewhere in the hierarchy.
 *
 * It may be renamed on the way, if its new siblings include one of its name:
 * what a widget is called is only ever unique where it sits, so a move is the
 * other moment that has to be made to hold (see [unique_among]).
 *
 * Nothing else has to be updated: the id is unchanged and [full_name] is
 * computed on demand. A widget cannot leave its simulation.
 *
 * It keeps the power source it draws on, which is its old parent's unless it
 * minted one. Moving a part of one box into another is not something anything
 * does today -- what moves is a whole device, which has its own source -- and
 * the day something does, this is where the question is: a part is switched by
 * the box it is in, and after a move it is in another one. *)
let reparent t new_parent =
    if sim new_parent != sim t then
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
      disconnect = (fun n -> w.ports.disconnect n) ;
      get_capabilities = (fun n -> w.ports.get_capabilities n) ;
      set_capabilities = (fun n c -> w.ports.set_capabilities n c) }

(* Siblings differ, cousins need not, and a move into a parent that has the
   name renames the arrival. *)
(*$T unique_among
  ignore unique_among ; (* Called by reparent *) \
  let r = (Simulation.make ~realtime:false "r").root in \
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
  let w = (Simulation.make ~realtime:false "w").root in \
  let read n = \
      (List.find (fun (p : property) -> p.name = n) w.properties).getter () in \
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
    if sim t1 != sim t2 then
        invalid_arg ("Widget.make_peers: "^ full_name t1 ^" and "^ full_name t2 ^
                     " belong to different simulations") ;
    (match via with
    | Some v when sim v != sim t1 ->
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
