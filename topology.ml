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
   The description of a network, as a document one saves and reopens.

   What is written down is the network and not the simulation: the devices it
   is made of, how they are configured and what joins them, and nothing of what
   is happening. A simulation cannot be resumed where it stopped -- its queue is
   a closure per pending event, closed over the whole graph -- and does not need
   to be: pause, step and speed are what an interactive checkpoint would have
   been for. So a load builds the network again and lets it run from the
   beginning, and the clock, the counters, the logs, the address tables and the
   frames in flight do not come back.

   Only what the catalogue built can be written down. That is not a line between
   programs and the administration interface: a program is expected to build
   through {!Device.make} as well, handing its parameters as JSON values, which
   is a small price for not writing a serializer per constructor's argument
   list. What falls outside is a network wired by hand, calling the constructors
   and {!Eth.Cable.plug} directly; such a device cannot say what it was built
   with (see {!Widget.made_with}) and a save leaves it out rather than guessing.
 *)
open Batteries

(** {2 The document} *)

(** What one device is, in a document.
 *
 * Its parameters are those its catalogue entry declares, as they were coerced
 * when it was built -- with, for a device that had a choice to make, the choice
 * it made rather than the freedom it was given. *)
type device =
    { (* The catalogue entry that builds this, as {!Device.all} names it. *)
      type_ : string ;
      (* Where it sits, as a path relative to the simulation's root: the file
       * describes a network and not one instance of one, and must load into a
       * simulation of another name. The last component is the device's own
       * name, the rest its parent. *)
      path : string ;
      (* Where it is in the world, if it is anywhere. Travels beside the
       * properties rather than within them because a place is not something a
       * device is configured with: its two properties only read. *)
      location : Widget.location option ;
      params : (string * Widget.value) list ;
      (* Every property that can be set, of the device and of each of its parts,
       * keyed by the path of the widget that carries it relative to the device
       * itself -- the empty string being the device.
       *
       * The parts and not merely the device, because that is where the
       * configuration lives: a switch's speeds and inter-frame gaps are on its
       * interfaces, a router's addresses and gateways on its adapters. *)
      properties : (string * (string * Widget.value) list) list }

type t =
    { (* What version of this format the document is in. Bumped when a document
       * written by an older robinet would be read wrongly rather than merely
       * incompletely, which is the only kind of change a reader cannot absorb
       * on its own. *)
      version : int ;
      (* What the network is called. The name of the simulation it was saved
       * from, and no more than a label: loading does not rename anything. *)
      name : string ;
      (* In the order they must be built, which is the order they were built in
       * the first place. *)
      devices : device list }

let current_version = 1

(** {2 On the wire} *)

let json_of_location = function
    | None -> `Null
    | Some (l : Widget.location) ->
        `Assoc [ "lat", `Float l.lat ; "lon", `Float l.lon ]

let json_of_device d =
    `Assoc [ "type", `String d.type_ ;
             "path", `String d.path ;
             "at", json_of_location d.location ;
             "params", `Assoc d.params ;
             "properties",
                `Assoc (List.map (fun (path, props) ->
                            path, `Assoc props
                        ) d.properties) ]

let to_json t =
    `Assoc [ "version", `Int t.version ;
             "name", `String t.name ;
             "devices", `List (List.map json_of_device t.devices) ]

(** A document as it is written to a file: indented, since it is meant to be
 * read and edited by hand as much as by the interface. *)
let to_string t =
    Yojson.Basic.pretty_to_string (to_json t)

(* Everything below refuses with {!Widget.Bad_value}, which the API answers with
 * a 400: a document that cannot be read is the caller's mistake, and the
 * message is what tells them where to look. *)

let member what name = function
    | `Assoc l ->
        (match List.assoc_opt name l with
        | Some v -> v
        | None -> Widget.bad_value "%s has no %S" what name)
    | j ->
        Widget.bad_value "%s must be an object, not %s" what
            (Yojson.Basic.to_string j)

let to_assoc what = function
    | `Assoc l -> l
    | j -> Widget.bad_value "%s must be an object, not %s" what
               (Yojson.Basic.to_string j)

let to_string_ what = function
    | `String s -> s
    | j -> Widget.bad_value "%s must be a string, not %s" what
               (Yojson.Basic.to_string j)

let location_of_json what = function
    | `Null -> None
    | j ->
        let coord name =
            match member what name j with
            | `Float f -> f
            | `Int i -> float_of_int i
            | v -> Widget.bad_value "%s: %S must be a number, not %s" what name
                       (Yojson.Basic.to_string v) in
        let l = Widget.{ lat = coord "lat" ; lon = coord "lon" } in
        (* The same refusal a location meets anywhere else: a coordinate out of
         * range is not a placement that happens to be odd, it is one that has
         * no spot on any map. *)
        (try Widget.check_location l
         with Invalid_argument m -> Widget.bad_value "%s: %s" what m) ;
        Some l

let device_of_json j =
    let what = "a device" in
    let path = to_string_ (what ^": \"path\"") (member what "path" j) in
    let what = "device "^ path in
    { type_ = to_string_ (what ^": \"type\"") (member what "type" j) ;
      path ;
      location = location_of_json (what ^": \"at\"") (member what "at" j) ;
      params = to_assoc (what ^": \"params\"") (member what "params" j) ;
      properties =
        to_assoc (what ^": \"properties\"") (member what "properties" j) |>
        List.map (fun (p, props) ->
            p, to_assoc (what ^": properties of "^ p) props) }

let of_json j =
    let what = "a topology" in
    let version =
        match member what "version" j with
        | `Int v -> v
        | v -> Widget.bad_value "%s: %S must be a number, not %s" what "version"
                   (Yojson.Basic.to_string v) in
    (* A version from the future is refused rather than read hopefully: this
     * reader knows what it does not know. *)
    if version > current_version then
        Widget.bad_value "%s was written by a later robinet (version %d, and \
                          this one reads up to %d)" what version
            current_version ;
    { version ;
      name = to_string_ (what ^": \"name\"") (member what "name" j) ;
      devices =
        match member what "devices" j with
        | `List l -> List.map device_of_json l
        | v -> Widget.bad_value "%s: %S must be a list, not %s" what "devices"
                   (Yojson.Basic.to_string v) }

let of_string s =
    match Yojson.Basic.from_string s with
    | exception _ ->
        Widget.bad_value "This is not a topology: it is not even JSON"
    | j -> of_json j

(*$= of_string & ~printer:dump
  [ "sw", [ "" , [ "cut-through", `Bool true ] ] ] \
    (let t = of_string \
        "{\"version\":1,\"name\":\"n\",\"devices\":[\
           {\"type\":\"switch\",\"path\":\"sw\",\"at\":null,\
            \"params\":{\"ports\":4},\
            \"properties\":{\"\":{\"cut-through\":true}}}]}" in \
     List.map (fun d -> d.path, d.properties) t.devices)
 *)

(*$T of_string
  (* A document reads back as what was written, whatever it holds: *) \
  (let t = { version = current_version ; name = "n" ; \
             devices = [ { type_ = "switch" ; path = "a/sw" ; \
                           location = Some Widget.{ lat = 45.75 ; lon = 4.85 } ; \
                           params = [ "ports", `Int 4 ] ; \
                           properties = [ "", [ "cut-through", `Bool true ] ; \
                                          "iface#0", [ "MTU", `Int 1500 ] ] } ] } in \
   to_json (of_string (to_string t)) = to_json t)
  (* And what cannot be read says so rather than coming back half built: *) \
  (try ignore (of_string "not json") ; false with Widget.Bad_value _ -> true)
  (try ignore (of_string "{\"version\":1,\"name\":\"n\"}") ; false \
   with Widget.Bad_value _ -> true)
  (try ignore (of_string "{\"version\":99,\"name\":\"n\",\"devices\":[]}") ; \
   false with Widget.Bad_value _ -> true)
  (try ignore (of_string "{\"version\":1,\"name\":\"n\",\"devices\":\
                          [{\"type\":\"switch\",\"path\":\"sw\",\
                            \"at\":{\"lat\":91.0,\"lon\":0.0},\
                            \"params\":{},\"properties\":{}}]}") ; false \
   with Widget.Bad_value _ -> true)
 *)
