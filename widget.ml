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
open Tools

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
type action = SimTypes.action
type action_state = SimTypes.action_state
type action_origin = SimTypes.action_origin = Startup | Api
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
    | Variant _ -> "one of several shapes"
    | Widget_id -> "a widget"
    | FRange _ | IRange _ -> "a range"
    | Time -> "a timestamp"
    | Duration -> "a length of time"
    | Packet -> "a packet"
    | Synth -> "a synthesized packet"
    | Bytes -> "some bytes"
    | BRange (mi, ma) -> Printf.sprintf "%d to %d bytes" mi ma
    | Ipv4 -> "an IPv4 address"
    | Ipv6 -> "an IPv6 address"
    | Mac -> "a MAC address"
    | Metric -> "a metric"
    | Optional k -> "an optional value ("^ kind_name k ^")"
    | List k -> "a list of "^ kind_name k
    | Row _ -> "a row"
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

(** Those names as choices, numbered by their places among them.
 *
 * What an [Enum] or a [Set] of alternatives with no numbers of its own is
 * built from: which link speeds an interface offers, which way a router
 * balances its load. A caller whose choices have numbers of their own -- a
 * protocol number, an ICMP type -- writes the pairs itself, since that number
 * is what has to travel. *)
let choices names =
    Array.mapi (fun i name -> i, name) names

(*$T choices
  choices [| "a" ; "b" |] = [| 0, "a" ; 1, "b" |]
  choices [||] = [||]
 *)

(** A number, of those known ones or -- when [range] says so -- of any other
 * between those two bounds.
 *
 * A set of alternatives that is all there is leaves [range] out: there are
 * three ways a router can balance its load and a fourth would be a mistake. A
 * set of numbers that merely has some well known members gives it: a module
 * names the protocols it knows, and a frame may carry any of the 65536 there
 * are.
 *
 * A known choice must lie within the bounds when there are bounds, or the
 * kind would offer what it refuses; and no two may share a number, since a
 * number is what a value is. *)
let one_of ?range choices =
    if Array.length choices = 0 then
        invalid_arg "Widget.one_of: no choice to make" ;
    Array.iteri (fun i (v, name) ->
        if name = "" then
            invalid_arg "Widget.one_of: a choice must have a name" ;
        Array.iteri (fun j (v', _) ->
            if j > i && v = v' then
                invalid_arg (Printf.sprintf
                                 "Widget.one_of: two choices worth %d" v)
        ) choices
    ) choices ;
    Option.may (fun (mi, ma) ->
        if mi > ma then
            invalid_arg (Printf.sprintf "Widget.one_of: %d is above %d" mi ma) ;
        Array.iter (fun (v, name) ->
            if v < mi || v > ma then
                invalid_arg (Printf.sprintf
                    "Widget.one_of: %s is worth %d, outside %d..%d" name v mi ma)
        ) choices
    ) range ;
    Enum (choices, range)

(*$T one_of
  one_of (choices [| "a" ; "b" |]) = Enum ([| 0, "a" ; 1, "b" |], None)
  one_of ~range:(0, 0xffff) [| 0x800, "IP" |] = \
      Enum ([| 0x800, "IP" |], Some (0, 0xffff))
  (try ignore (one_of [||]) ; false with Invalid_argument _ -> true)
  (try ignore (one_of [| 1, "a" ; 1, "b" |]) ; false \
   with Invalid_argument _ -> true)
  (try ignore (one_of [| 1, "" |]) ; false with Invalid_argument _ -> true)
  (try ignore (one_of ~range:(5, 0) [| 1, "a" |]) ; false \
   with Invalid_argument _ -> true)
  (try ignore (one_of ~range:(0, 10) [| 99, "a" |]) ; false \
   with Invalid_argument _ -> true)
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
    | (Optional _ | Metric | List _ | Row _ | Record _ | Variant _ | Hint _
      | Set _ | Bytes | BRange _ | Synth) as k ->
        invalid_arg ("Widget.hint: nothing to write an example in for "^
                     kind_name k)
    | k -> Hint (h, k)

(*$T hint
  hint "a-b" String = Hint ("a-b", String)
  optional (hint "a-b" String) = Optional (Hint ("a-b", String))
  (try ignore (hint "x" (optional Int)) ; false with Invalid_argument _ -> true)
  (try ignore (hint "x" (hint "y" Int)) ; false with Invalid_argument _ -> true)
  (try ignore (hint "x" (list Int)) ; false with Invalid_argument _ -> true)
  (try ignore (hint "de ad" Bytes) ; false with Invalid_argument _ -> true)
 *)

(** A list of [k]. What may be repeated is a value the interface has a single
 * input for, a row of those, or a record: a column, a table, and a form drawn
 * again for each element.
 *
 * A list of lists has none of those shapes, and neither has a list of values
 * that may each be absent -- an element that is not there is one the list does
 * not hold. A set has one: a cell of ticked choices. *)
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

(* The fields a row or a record is made of, named and in the order the
 * interface lays them out: no two alike, since names are what they are keyed
 * by on the wire, and none empty. [what] says which of the two is being built,
 * so that a refusal names it. *)
let check_fields what fields =
    if Array.length fields = 0 then
        invalid_arg ("Widget."^ what ^": one with no field describes nothing") ;
    Array.iter (fun (name, _) ->
        if name = "" then
            invalid_arg ("Widget."^ what ^": a field must have a name")
    ) fields ;
    Array.iteri (fun i (name, _) ->
        Array.iteri (fun j (name', _) ->
            if j > i && name = name' then
                invalid_arg ("Widget."^ what ^": two fields named "^ name)
        ) fields
    ) fields

(** One row of a table: those named fields, laid out left to right, a cell
 * each.
 *
 * A field is therefore a value with a single input, or one that may be absent.
 * A field that is itself a row, a record or a list is not a cell, and what
 * wants to hold one of those is a [record]. *)
let row fields =
    check_fields "row" fields ;
    Array.iter (fun (name, k) ->
        match k with
        | List _ | Row _ | Record _ | Variant _ | Metric | Synth ->
            invalid_arg ("Widget.row: field "^ name ^" cannot be "^
                         kind_name k)
        | _ -> ()
    ) fields ;
    Row fields

(*$T row
  row [| "a", Int ; "b", optional String |] = \
      Row [| "a", Int ; "b", Optional String |]
  (try ignore (row [||]) ; false with Invalid_argument _ -> true)
  (try ignore (row [| "a", Int ; "a", Int |]) ; \
   false with Invalid_argument _ -> true)
  (try ignore (row [| "", Int |]) ; false with Invalid_argument _ -> true)
  (try ignore (row [| "a", list Int |]) ; \
   false with Invalid_argument _ -> true)
  (try ignore (row [| "a", row [| "b", Int |] |]) ; \
   false with Invalid_argument _ -> true)
 *)

(* A table of rows is what the two are for, and the reason a row is flat: see
   the routing tables. *)
(*$T list
  list (row [| "dest", String ; "via", optional String |]) = \
      List (Row [| "dest", String ; "via", Optional String |])
 *)

(** Those named fields, one to a line, one under the next: a form, and what a
 * thing with an inside reads as -- a packet's layers, and the fields of each
 * of them.
 *
 * A field may be anything at all, a record or a list included: those are drawn
 * indented under the line that names them, which is what a row cannot do and
 * the whole difference between the two. A metric is still not one: it is what
 * a widget has counted, and it belongs to the widget and not to a value of
 * its. *)
let record fields =
    check_fields "record" fields ;
    Array.iter (fun (name, k) ->
        match k with
        | Metric ->
            invalid_arg ("Widget.record: field "^ name ^" cannot be "^
                         kind_name k)
        | _ -> ()
    ) fields ;
    Record fields

(* The second and third are what a row refuses and this is for: a field with an
   inside of its own. Said here rather than within the block, since qtest ends
   an injected block at the first comment terminator it meets. *)
(*$T record
  record [| "a", Int ; "b", optional String |] = \
      Record [| "a", Int ; "b", Optional String |]
  record [| "a", record [| "b", Int |] |] = \
      Record [| "a", Record [| "b", Int |] |]
  record [| "a", list (row [| "b", Int |]) |] = \
      Record [| "a", List (Row [| "b", Int |]) |]
  (try ignore (record [||]) ; false with Invalid_argument _ -> true)
  (try ignore (record [| "a", Int ; "a", Int |]) ; \
   false with Invalid_argument _ -> true)
  (try ignore (record [| "", Int |]) ; false with Invalid_argument _ -> true)
  (try ignore (record [| "a", Metric |]) ; \
   false with Invalid_argument _ -> true)
 *)

(** A value that is one of those named shapes, each carrying what its own kind
 * says.
 *
 * Names are what a case is known by on the wire, so there must be no two alike
 * and none empty -- the same rule as a record's fields, and for the same
 * reason. A case may carry anything a record field may. *)
let variant cases =
    check_fields "variant" cases ;
    Array.iter (fun (name, k) ->
        match k with
        | Metric ->
            invalid_arg ("Widget.variant: case "^ name ^" cannot be "^
                         kind_name k)
        | _ -> ()
    ) cases ;
    Variant cases

(*$T variant
  variant [| "a", Int ; "b", record [| "c", Int |] |] = \
      Variant [| "a", Int ; "b", Record [| "c", Int |] |]
  (try ignore (variant [||]) ; false with Invalid_argument _ -> true)
  (try ignore (variant [| "a", Int ; "a", Float |]) ; \
   false with Invalid_argument _ -> true)
  (try ignore (variant [| "", Int |]) ; false with Invalid_argument _ -> true)
  (try ignore (variant [| "a", Metric |]) ; \
   false with Invalid_argument _ -> true)
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

(** One thing this widget can be asked to do (see {!SimTypes.action}).
 *
 * [handler] is handed the record of the run and returns at once; what the
 * action really does is whatever it schedules from there, and it is that
 * scheduled work that eventually calls {!Action.stop}. *)
let action ?(descr="") ?(params=[]) ?result ?can_run ~handler name =
    { name ; descr ; params ; result ;
      can_run = can_run |? (fun () -> true) ;
      handler }

(* As with properties, what a widget adds comes before what it got by being a
 * widget at all. *)
let add_actions t actions =
    t.actions <- actions @ t.actions

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

let to_bitstring = function
    | `String s ->
        (try bitstring_of_hexstring s
        with _ -> bad_value "not a bitstring: %S" s)
    | v -> bad_value "expected a bitstring, not %s" (Yojson.Basic.to_string v)

(** Read which number a value names, of [choices] or of [range] (see the [Enum]
 * kind).
 *
 * Without a range the choices are all there is, and anything else is refused
 * rather than stored: a property that answers with a value outside its own
 * choices is one the interface can only show as a number. With one, the bounds
 * are what is checked -- every known choice lies within them, [enum] having
 * seen to that -- and a number nobody has a name for is a perfectly good
 * value. *)
let to_choice ?range choices v =
    let i = to_int v in
    match range with
    | Some (mi, ma) ->
        if i >= mi && i <= ma then i
        else bad_value "%d is not between %d and %d" i mi ma
    | None ->
        if Array.exists (fun (i', _) -> i' = i) choices then i
        else bad_value "%d is none of the %d choices" i (Array.length choices)

(*$T to_choice
  to_choice (choices [| "a" ; "b" |]) (`Int 1) = 1
  to_choice [| 0x0800, "IP" ; 0x0806, "ARP" |] (`Int 0x0806) = 0x0806
  to_choice ~range:(0, 0xffff) [| 0x0800, "IP" |] (`Int 0x1234) = 0x1234
  (try ignore (to_choice ~range:(0, 0xffff) [| 0x0800, "IP" |] (`Int 0x10000)) ; \
   false with Bad_value _ -> true)
  (try ignore (to_choice (choices [| "a" ; "b" |]) (`Int 2)) ; false \
   with Bad_value m -> m = "2 is none of the 2 choices")
  (try ignore (to_choice (choices [| "a" ; "b" |]) (`Int (-1))) ; false \
   with Bad_value _ -> true)
  (try ignore (to_choice [| 0x0800, "IP" |] (`Int 0)) ; false \
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
  to_choices (choices [| "a" ; "b" ; "c" |]) (`List [ `Int 2 ; `Int 0 ]) = [ 0 ; 2 ]
  to_choices (choices [| "a" ; "b" |]) (`List [ `Int 1 ; `Int 1 ]) = [ 1 ]
  to_choices (choices [| "a" ; "b" |]) (`List []) = []
  (try ignore (to_choices (choices [| "a" ; "b" |]) (`List [ `Int 2 ])) ; false \
   with Bad_value _ -> true)
  (try ignore (to_choices (choices [| "a" |]) (`Int 0)) ; false \
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
let to_choices ?range choices = function
    (* Not [to_list], although a set travels as one: what that says when it
     * refuses an element is which row of a table it was, and a set is not a
     * table -- it is a row of boxes, and which choice is not one of the
     * choices already names itself. *)
    | `List l ->
        List.map (to_choice ?range choices) l |>
        List.sort_unique compare
    | v ->
        bad_value "expected a set of choices, not %s" (Yojson.Basic.to_string v)

(** Read a value that is one of several shapes: [f] is given the name of the
 * case and what it carries, and answers with whatever the caller wants of it.
 *
 * The counterpart of a [Variant] kind, as [to_field] is of a record's: a value
 * of one is an object of a single field, whose name says which case it is. *)
let to_case f = function
    | `Assoc [ name, v ] -> f name v
    | v ->
        bad_value "expected one named shape, not %s" (Yojson.Basic.to_string v)

(*$T to_case
  to_case (fun n v -> n, to_int v) (`Assoc [ "a", `Int 1 ]) = ("a", 1)
  (try ignore (to_case (fun n _ -> n) (`Assoc [])) ; false \
   with Bad_value _ -> true)
  (try ignore (to_case (fun n _ -> n) (`Assoc [ "a", `Int 1 ; "b", `Int 2 ])) ; \
   false with Bad_value _ -> true)
  (try ignore (to_case (fun n _ -> n) (`Int 1)) ; false \
   with Bad_value _ -> true)
 *)

(** Retrieve the JSON value of field [name] of record [t]. *)
let json_of_field name = function
    | `Assoc l as v ->
        (try List.assoc name l
        with Not_found ->
            bad_value "no field %S in %s" name (Yojson.Basic.to_string v))
    | v -> bad_value "expected a record, not %s" (Yojson.Basic.to_string v)

(** Read the field [name] of a record with [f]. The counterpart of a [Record]
 * kind, one field at a time, which is how a setter rebuilds its own record:
 * it knows what it wants out of it, and in what order.
 *
 * A field that is not there is refused rather than read as absent: absence is
 * [`Null], and only for a field whose kind says it may be. *)
let to_field name f js =
    let v = json_of_field name js in
    try f v with Bad_value msg -> bad_value "%s: %s" name msg

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

(** Whether [v] is a value of [k], raising [Bad_value] naming what is not.

 * Not {!Device.coerce}, although the two walk the same language. That one
 * reads what a reader typed and is lenient on purpose -- a number arrives as
 * the string of it, and a field is coerced rather than merely looked at. This
 * one checks what a program wrote against the kind that same program wrote to
 * describe it, which is a pair kept in step by hand: every protocol describes
 * its own PDU twice over, once as a kind and once as a value, and nothing else
 * would catch a field renamed in one half and not in the other.
 *
 * A metric is the exception: it says what it is in its own value, and there is
 * nothing in the kind to check it against. *)
let rec check_value ?(name="value") k v =
    let wrong () =
        bad_value "%s should be %s, not %s" name (kind_name k)
            (Yojson.Basic.to_string v)
    and within what mi ma x =
        if x < mi || x > ma then
            bad_value "%s is %s, outside %s..%s" name (what x) (what mi)
                (what ma) in
    let field_named fields n =
        Array.exists (fun (n', _) -> n' = n) fields in
    match k, v with
    | (String | Text | FileName | Bytes), `String _ -> ()
    | Int, `Int _ -> ()
    (* Both, since JSON has one number type and Yojson two: a round float
     * written out and read back is an [`Int] again. *)
    | Float, (`Float _ | `Int _) -> ()
    | Bool, `Bool _ -> ()
    | Widget_id, `Int _ -> ()
    | (Time | Duration), (`Float _ | `Int _) -> ()
    | IRange (mi, ma), `Int i -> within string_of_int mi ma i
    | FRange (mi, ma), `Float f -> within string_of_float mi ma f
    | FRange (mi, ma), `Int i -> within string_of_float mi ma (float_of_int i)
    | Enum (choices, range), (`Int _ as v) ->
        (try ignore (to_choice ?range choices v)
         with Bad_value m -> bad_value "%s: %s" name m)
    | Set choices, (`List _ as v) ->
        (try ignore (to_choices choices v)
         with Bad_value m -> bad_value "%s: %s" name m)
    (* Its bytes and what they amount to, which is what [json_of_packet]
     * writes. *)
    | Packet, `Assoc [ "bits", `String _ ; "descr", `String _ ] -> ()
    (* A named layer to each entry, outermost first, and no more than that:
     * what is inside one is a field of some protocol, and which fields those
     * are is [Packet]'s answer and not this module's (see [describe_packet]).
     * What checks them is [Synth.Packet.of_synth], reading them. *)
    | Synth, `List layers ->
        List.iteri (fun i layer ->
            let wrong what =
                bad_value "%s[%d] should be %s" name i what in
            match layer with
            | `Assoc _ ->
                (match json_of_field "name" layer with
                | `String _ -> ()
                | _ -> wrong "a layer named by its protocol") ;
                (match json_of_field "fields" layer with
                | `Assoc _ -> ()
                | _ -> wrong "a layer and the fields it is made of")
            | _ ->
                wrong "a layer and the fields it is made of"
        ) layers
    | Metric, _ -> ()
    | Optional _, `Null -> ()
    | Optional k, v -> check_value ~name k v
    | Hint (_, k), v -> check_value ~name k v
    | List k, `List l ->
        List.iteri (fun i v ->
            check_value ~name:(Printf.sprintf "%s[%d]" name i) k v
        ) l
    (* The same on the wire whichever way they are drawn: every field the kind
     * names, and no other. *)
    | (Row fields | Record fields), `Assoc given ->
        List.iter (fun (n, _) ->
            if not (field_named fields n) then
                bad_value "%s has no field %S" name n
        ) given ;
        Array.iter (fun (fname, k) ->
            match List.assoc_opt fname given with
            | None -> bad_value "%s has no %S" name fname
            | Some v -> check_value ~name:(name ^"."^ fname) k v
        ) fields
    | Variant cases, (`Assoc [ _ ] as v) ->
        to_case (fun case v ->
            match Array.find_opt (fun (c, _) -> c = case) cases with
            | None ->
                bad_value "%s: %S is none of its %d shapes" name case
                    (Array.length cases)
            | Some (_, k) -> check_value ~name:(name ^"."^ case) k v
        ) v
    | (Ipv4 | Ipv6), `String s ->
        let family = if k = Ipv4 then Unix.PF_INET else Unix.PF_INET6 in
        (match Unix.inet_addr_of_string s with
        | exception Failure _ -> wrong ()
        | a ->
            if Unix.domain_of_sockaddr (Unix.ADDR_INET (a, 0)) <> family then
                wrong ())
    | Mac, `String s ->
        let is_hex c =
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F') in
        let is_byte p =
            let n = String.length p in
            n >= 1 && n <= 2 && is_hex p.[0] && is_hex p.[n - 1] in
        (match String.split_on_char ':' s with
        | [ _ ; _ ; _ ; _ ; _ ; _ ] as bytes when List.for_all is_byte bytes -> ()
        | _ -> wrong ())
    | BRange (mi, ma), `String s ->
        let len = Bitstring.bitstring_length (bitstring_of_hexstring s) / 8 in
        if len < mi || len > ma then
            bad_value "%s is %d bytes long, outside %d..%d" name len mi ma
    | _ -> wrong ()

(*$T check_value
  check_value Ipv4 (`String "192.168.0.1") = ()
  check_value Ipv6 (`String "2001:db8::1") = ()
  check_value Mac (`String "a4:BA:db:e6:15:fa") = ()
  check_value (BRange (2, 3)) (`String "de ad") = ()
  (try check_value Ipv4 (`String "2001:db8::1") ; false with Bad_value _ -> true)
  (try check_value Ipv4 (`String "www.example.com") ; false with Bad_value _ -> true)
  (try check_value Ipv6 (`String "192.168.0.1") ; false with Bad_value _ -> true)
  (try check_value Mac (`String "a4:ba:db:e6:15") ; false with Bad_value _ -> true)
  (try check_value Mac (`String "a4:ba:db:e6:15:fa0") ; false with Bad_value _ -> true)
  (try check_value (BRange (2, 3)) (`String "de") ; false with Bad_value _ -> true)
 *)

(*$T check_value
  check_value Int (`Int 1) = ()
  check_value (optional Int) `Null = ()
  check_value Bytes (`String "de ad") = ()
  check_value (record [| "a", Int |]) (`Assoc [ "a", `Int 1 ]) = ()
  check_value (list (row [| "a", Int |])) (`List [ `Assoc [ "a", `Int 1 ] ]) = ()
  check_value (variant [| "a", Int |]) (`Assoc [ "a", `Int 1 ]) = ()
  check_value (one_of ~range:(0, 9) [| 3, "c" |]) (`Int 7) = ()
  (try check_value Int (`String "1") ; false with Bad_value _ -> true)
  (try check_value (IRange (0, 9)) (`Int 10) ; false with Bad_value _ -> true)
  (try check_value (one_of [| 3, "c" |]) (`Int 7) ; false \
   with Bad_value _ -> true)
  (try check_value (record [| "a", Int |]) (`Assoc [ "b", `Int 1 ]) ; false \
   with Bad_value _ -> true)
  (try check_value (record [| "a", Int |]) \
         (`Assoc [ "a", `Int 1 ; "b", `Int 2 ]) ; false \
   with Bad_value _ -> true)
  (try check_value (variant [| "a", Int |]) (`Assoc [ "b", `Int 1 ]) ; false \
   with Bad_value _ -> true)
 *)

(** {2 What a thing has to be told}
 *
 * The arguments of a call the interface makes: the characteristics a device is
 * built from (see {!Device}) and the parameters an action is run with (see
 * {!Action}). One notion for both, so that there is one way to declare them,
 * one place where a value that is not one is refused, and one dialog in the
 * interface that fills either in. *)

(** One of them, asked for once, when the call is made. *)
type param = SimTypes.param =
    { name : string ;
      descr : string ;
      units : string ;
      kind : kind ;
      (* What an empty input shows: an address of the shape expected, or what
       * leaving the parameter out will do. It is the description's examples,
       * moved to where they are read -- so keep it out of [descr]. Only ever
       * seen by a parameter with no [default], since a default fills the input
       * in. *)
      placeholder : string ;
      (* What the dialog offers before anything is typed, and what is used when
       * the parameter is left out. [`Null] for a parameter with no value of its
       * own, which an [Optional] kind is then obliged to accept. *)
      default : value }

let param ?(descr="") ?(units="") ?(placeholder="") ?(default=`Null) ~kind
          name =
    { name ; descr ; units ; kind ; placeholder ; default }

(* Coerce a value to what the parameter says it is, and check whatever the kind
 * knows how to check. Every refusal a parameter can meet before the call is
 * made happens here, once, rather than in each callee. *)
let rec coerce name (kind : kind) v =
    match kind with
    | String | Text | FileName -> `String (to_string v)
    | Int -> `Int (to_int v)
    | Float -> `Float (to_float v)
    (* A number of seconds, and only its rendering sets it apart. *)
    | Duration -> `Float (to_float v)
    | Bool -> `Bool (to_bool v)
    | Widget_id -> `Int (to_int v)
    | IRange (min, max) -> `Int (to_int_range ~min ~max v)
    | FRange (min, max) -> `Float (to_float_range ~min ~max v)
    | Ipv4 | Ipv6 | Mac ->
        check_value ~name kind v ;
        v
    | Time | Packet | Bytes | BRange _ | Synth ->
        (* As for a metric below: these are what a widget has seen, and nothing
         * is handed what it is meant to produce. Bytes joins them for a reason
         * of its own -- they are read and never written, whoever is looking at
         * them. *)
        bad_value "%s cannot be given as a parameter" name
    | Enum (choices, range) ->
        (try `Int (to_choice ?range choices v)
        with Bad_value m -> bad_value "%s: %s" name m)
    (* In order and without repetition, however it was sent: the callee is
       handed the set itself, and has nothing left to check about it. *)
    | Set choices ->
        (try `List (to_choices choices v |>
                    List.map (fun i -> `Int i))
        with Bad_value m -> bad_value "%s: %s" name m)
    | Optional k ->
        (match v with `Null -> `Null | v -> coerce name k v)
    (* How a value is written is the interface's business; what arrives here is
       the value. *)
    | Hint (_, k) -> coerce name k v
    | List k ->
        `List (to_list (coerce name k) v)
    (* The same on the wire, whichever way the interface draws them. *)
    | Row fields | Record fields ->
        (* Every field declared, in that order, and nothing else: a name it
           does not know is a misspelling, and quietly dropping it would call
           for something other than what was asked for -- the same reason
           [args_of] refuses an unknown parameter. *)
        (match v with
        | `Assoc given ->
            List.iter (fun (n, _) ->
                if not (Array.exists (fun (n', _) -> n' = n) fields) then
                    bad_value "%s has no field %S" name n
            ) given ;
            `Assoc (
                Array.to_list fields |>
                List.map (fun (fname, k) ->
                    match List.assoc_opt fname given with
                    | None -> bad_value "%s has no %S" name fname
                    | Some v -> fname, coerce (name ^"."^ fname) k v))
        | v ->
            bad_value "%s must be a set of named fields, not %s" name
                (Yojson.Basic.to_string v))
    (* Which shape it is, and then that shape: a value of a variant is an
       object of a single field whose name says the case (see [Variant]). A
       name that is none of the cases is a misspelling, as an unknown field of
       a record is. *)
    | Variant cases ->
        to_case (fun case v ->
            match Array.find_opt (fun (c, _) -> c = case) cases with
            | None ->
                bad_value "%s: %S is none of its %d shapes" name case
                    (Array.length cases)
            | Some (_, k) ->
                `Assoc [ case, coerce (name ^"."^ case) k v ]
        ) v
    | Metric ->
        (* Nothing has one, and nothing should: a metric is what a widget has
         * counted, which is never an argument. *)
        bad_value "%s cannot be given as a parameter" name

(*$= coerce & ~printer:Yojson.Basic.to_string
  (`Int 3) (coerce "n" Int (`String "3"))
  (`Int 3) (coerce "n" (IRange (0, 5)) (`Int 3))
  `Null (coerce "n" (optional Int) `Null)
  (`Int 3) (coerce "n" (optional Int) (`Int 3))
 *)
(*$T coerce
  (try ignore (coerce "n" (IRange (0, 5)) (`Int 9)) ; false \
   with Bad_value _ -> true)
  (try ignore (coerce "n" (one_of (choices [| "a" |])) (`Int 9)) ; \
   false \
   with Bad_value _ -> true)
  (try ignore (coerce "n" Metric (`Int 0)) ; false \
   with Bad_value _ -> true)
 *)

(* A choice is its own number and not its place among the others, which is what
   a protocol number needs: what travels for IP is 0x0800. *)
(*$= coerce & ~printer:Yojson.Basic.to_string
  (`Int 0x0800) \
    (coerce "p" (one_of [| 0x0800, "IP" ; 0x0806, "ARP" |]) (`Int 0x0800))
 *)
(*$T coerce
  (try ignore (coerce "p" (one_of [| 0x0800, "IP" |]) (`Int 0)) ; \
   false \
   with Bad_value _ -> true)
 *)

(* One shape of several, which is an object of a single field named after the
   case: what it carries is then read as that case's own kind says. *)
(*$= coerce & ~printer:Yojson.Basic.to_string
  (`Assoc [ "ids", `Assoc [ "id", `Int 1 ] ]) \
    (coerce "v" (variant [| "ids", row [| "id", Int |] ; \
                            "mtu", Int |]) \
                (`Assoc [ "ids", `Assoc [ "id", `String "1" ] ]))
 *)
(*$T coerce
  (try ignore (coerce "v" (variant [| "a", Int |]) \
                          (`Assoc [ "z", `Int 1 ])) ; \
   false with Bad_value _ -> true)
  (try ignore (coerce "v" (variant [| "a", Int |]) \
                          (`Assoc [ "a", `Int 1 ; "b", `Int 2 ])) ; \
   false with Bad_value _ -> true)
  (try ignore (coerce "v" (variant [| "a", IRange (0, 5) |]) \
                          (`Assoc [ "a", `Int 9 ])) ; \
   false with Bad_value _ -> true)
 *)

(** The arguments of a call, read from what was asked for: every parameter
 * [params] declares, coerced, with the ones left out taking their default.
 * Anything else is refused rather than ignored, since a misspelt parameter
 * that is quietly dropped calls for something other than what was asked for.
 *
 * [what] names the callee in that refusal -- "a switch", "ping". *)
let args_of what params given =
    List.iter (fun (name, _) ->
        if not (List.exists (fun (p : param) -> p.name = name) params) then
            bad_value "%s takes no %S" what name
    ) given ;
    List.map (fun (p : param) ->
        let v = match List.assoc_opt p.name given with
                | None -> p.default
                | Some v -> v in
        p.name, coerce p.name p.kind v
    ) params

(* The arguments handed to a callee are the parameters it declares, already
 * coerced, so these need no error of their own: a name that is not there is
 * the callee disagreeing with itself. *)
let arg args name =
    try List.assoc name args
    with Not_found -> invalid_arg ("Widget.arg: no parameter "^ name)

let arg_bool args name = to_bool (arg args name)
let arg_int args name = to_int (arg args name)
let arg_float args name = to_float (arg args name)
let arg_string args name = to_string (arg args name)
let arg_opt args name f = to_option f (arg args name)
let arg_list args name f = to_list f (arg args name)

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

(** A length of time, in seconds, as [json_of_time] hands out an instant: the
 * interface writes it out as a length -- "38min 25s" -- which is the whole
 * difference between the two. *)
let json_of_duration (i : Clock.Interval.t) =
    `Float (Clock.Interval.to_secs i)

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

(** A run of octets, as the interface reads one: the hexadecimal of it, which
 * is the same string a packet's bytes travel as.
 *
 * All of it, however long: which two ends of it to show, and how much of it a
 * reader can be handed at once, is the interface's to decide and not the
 * simulator's. *)
let json_of_bytes bits =
    `String (Tools.hexstring_of_bitstring bits)

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
        (* "destructor" for the few widgets that hold resources that are not
         * garbage collected, such as file handlers, or that need to "unlink"
         * themselves from some data structure on deletion: *)
        on_delete = ignore ;
        (* What it draws on until [own_power] says otherwise: what it was
         * handed, or what its parent draws on. *)
        power = power |? parent.power ; (* altered below if [own_power] *)
        owns_power = own_power ;
        (* Behavior on power-up: *)
        power_up = ignore ;
        (* Behavior on power-down: *)
        power_down = ignore ;
        error = None ;
        location ;
        logger ;
        ports = no_ports ;
        properties ;
        actions = [] } in
    (* power starts off by default: *)
    if own_power then t.power <- { on = false ; name = full_name t ; sim = sim t } ;
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
