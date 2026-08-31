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
   The catalogue of things a network can be built out of, from the outside.

   A simulation is normally assembled by an OCaml program that calls the
   constructors directly, with every parameter each of them takes. This is the
   other way in: what the administration interface offers when the reader asks
   for one more switch. It is deliberately a much smaller vocabulary -- a
   handful of physical devices, each with the few characteristics one is asked
   for when buying the real thing -- because everything else is a property, and
   properties are edited afterwards, on the thing itself once it's added to the
   simulation (like a physical device is chosen according to some physical
   characteristics and then, once turned on, is configured).

   Each entry says what it needs in the same vocabulary properties are described
   with ({!Widget.kind}), so the interface renders the dialog with the code it
   already has for the property panel, and a new device type is added here and
   nowhere else.
 *)
open Batteries
open Tools

(** {2 What a device has to be told} *)

(** One characteristic, asked for once, when the device is built. *)
type param =
    { name : string ;
      descr : string ;
      units : string ;
      kind : Widget.kind ;
      (* What the dialog offers before anything is typed, and what is used when
       * the parameter is left out. [`Null] for a parameter with no value of its
       * own, which an [Optional] kind is then obliged to accept. *)
      default : Widget.value }

let param ?(descr="") ?(units="") ?(default=`Null) ~kind name =
    { name ; descr ; units ; kind ; default }

(** A kind of device: what it is called, what it needs, and how to build one.
 *
 * [make] is handed the parent to build under and the arguments already coerced
 * and bounds-checked against the [params] above, so it can read them without
 * checking them again. It raises {!Widget.Bad_value} for what only it can
 * refuse -- an address that is not one, an end that cannot take a cable. *)
type t =
    { name : string ;
      descr : string ;
      params : param list ;
      make : parent:Widget.t -> string -> (string * Widget.value) list ->
             Widget.t }

(** {2 Where a cable can be plugged} *)

(* The port to use on [widget]: the one asked for, or the first one it has left,
 * as the widget it really belongs to and the device to write frames into.
 *
 * Which ports a widget has, and which of them are free, is the widget's own
 * answer (see [Widget.ports]) -- the device keeps that where it already had to,
 * so a cable plugged in by an OCaml program counts just as much as one plugged
 * in from here. *)
let plug (widget : Widget.t) port =
    let ports = widget.ports.count () in
    if ports = 0 then
        Widget.bad_value "%s is not something a cable can be plugged into"
            (Widget.full_name widget) ;
    let p =
        match port with
        | Some p ->
            if p < 0 || p >= ports then
                Widget.bad_value "%s has no port %d (it has %d)"
                    (Widget.full_name widget) p ports ;
            if widget.ports.is_connected p then
                Widget.bad_value "%s already has a cable on port %d"
                    (Widget.full_name widget) p ;
            p
        | None ->
            (match Widget.first_free_port widget with
            | None ->
                Widget.bad_value "every port of %s is taken (it has %d)"
                    (Widget.full_name widget) ports
            | Some p -> p) in
    widget.ports.owner p, widget.ports.dev p

(** {2 Reading the arguments} *)

(* Coerce a value to what the parameter says it is, and check whatever the kind
 * knows how to check. Every refusal a parameter can meet before the device is
 * built happens here, once, rather than in each [make]. *)
let rec coerce name (kind : Widget.kind) v =
    match kind with
    | String -> `String (Widget.to_string v)
    | Int -> `Int (Widget.to_int v)
    | Float -> `Float (Widget.to_float v)
    | Bool -> `Bool (Widget.to_bool v)
    | Widget_id -> `Int (Widget.to_int v)
    | IRange (min, max) -> `Int (Widget.to_int_range ~min ~max v)
    | FRange (min, max) -> `Float (Widget.to_float_range ~min ~max v)
    | Enum choices ->
        let s = Widget.to_string v in
        if not (List.mem s choices) then
            Widget.bad_value "%s must be one of %s, not %S"
                name (String.concat ", " choices) s ;
        `String s
    | Optional k ->
        (match v with `Null -> `Null | v -> coerce name k v)
    | Metric ->
        (* Nothing has one, and nothing should: a metric is what a device has
         * counted, which at birth is nothing. *)
        Widget.bad_value "%s cannot be given when building a device" name

(** The arguments of [t], read from what was asked for: every parameter it
 * declares, coerced, with the ones left out taking their default. Anything else
 * is refused rather than ignored, since a misspelt parameter that is quietly
 * dropped builds a device that is not the one that was asked for. *)
let args_of t given =
    List.iter (fun (name, _) ->
        if not (List.exists (fun (p : param) -> p.name = name) t.params) then
            Widget.bad_value "a %s takes no %S" t.name name
    ) given ;
    List.map (fun (p : param) ->
        let v = match List.assoc_opt p.name given with
                | None -> p.default
                | Some v -> v in
        p.name, coerce p.name p.kind v
    ) t.params

(* The arguments handed to [make] are the parameters of the device that is being
 * built, already coerced, so these need no error of their own: a name that is
 * not there is this file disagreeing with itself. *)
let arg args name =
    try List.assoc name args
    with Not_found -> invalid_arg ("Device.arg: no parameter "^ name)

let int args name = Widget.to_int (arg args name)
let float args name = Widget.to_float (arg args name)
let string args name = Widget.to_string (arg args name)
let opt args name f = Widget.to_option f (arg args name)

(* An address as one types it, and not as the resolver would have it:
 * [Ip.Addr.of_string] asks the system to look the name up, which would hold the
 * simulation still for as long as a DNS server feels like taking. *)
let addr name v =
    let s = Widget.to_string v in
    match Ip.Addr.of_dotted_string_opt s with
    | Some ip -> ip
    | None -> Widget.bad_value "%s: %S is not an IP address" name s

let mac name v =
    let s = Widget.to_string v in
    try Eth.Addr.of_string s
    with _ -> Widget.bad_value "%s: %S is not a MAC address" name s

(** {2 The catalogue} *)

let hub =
    { name = "hub" ;
      descr = "A repeater: whatever reaches one port leaves by every other." ;
      params = [
          param "ports" ~kind:(IRange (2, 1024)) ~default:(`Int 8)
              ~descr:"How many cables it takes." ] ;
      make = fun ~parent name args ->
          let t = Hub.Repeater.make ~parent (int args "ports") name in
          t.Hub.Repeater.widget }

let switch =
    { name = "switch" ;
      descr = "Forwards frames to the port it last saw their destination on." ;
      params = [
          param "ports" ~kind:(IRange (2, 1024)) ~default:(`Int 8)
              ~descr:"How many cables it takes." ;
          param "MACs" ~kind:(IRange (1, 1_000_000)) ~default:(`Int 1024)
              ~descr:"How many addresses it can remember at once." ] ;
      make = fun ~parent name args ->
          let t = Hub.Switch.make ~parent (int args "ports") (int args "MACs")
                                  name in
          t.Hub.Switch.widget }

let host =
    { name = "host" ;
      descr = "A machine with a single network adapter." ;
      params = [
          (* The one parameter that cannot be an afterthought: with an address
           * the host is configured statically, without one it goes looking for
           * a DHCP server, and the two are different machines from here on. *)
          param "address" ~kind:(Widget.optional String)
              ~descr:"Its IP address; leave it out to ask a DHCP server." ;
          param "netmask" ~kind:String ~default:(`String "255.255.255.0")
              ~descr:"Which addresses it can reach without a gateway." ;
          param "gateway" ~kind:(Widget.optional String)
              ~descr:"Where to send what the netmask does not cover." ;
          param "nameserver" ~kind:(Widget.optional String)
              ~descr:"Which DNS server to ask." ;
          param "search suffix" ~kind:(Widget.optional String)
              ~descr:"Appended to the names it is asked to resolve." ;
          param "MAC" ~kind:(Widget.optional String)
              ~descr:"Its hardware address. One is drawn at random if left \
                      out." ] ;
      make = fun ~parent name args ->
          let netmask = addr "netmask" (arg args "netmask")
          and gateways =
              match opt args "gateway" (fun v ->
                        Eth.Gateway.IPv4 (addr "gateway" v)) with
              | None -> []
              | Some gw -> [ Eth.State.gw_selector (), Some gw ]
          and nameserver = opt args "nameserver" (addr "nameserver")
          and search_sfx = opt args "search suffix" Widget.to_string
          and mac = opt args "MAC" (mac "MAC") in
          let t =
              match opt args "address" (addr "address") with
              | Some ip ->
                  Host.make_static ~parent ~gateways ?search_sfx ?nameserver
                                   ?mac ~netmask ip name
              | None ->
                  Host.make_dhcp ~parent ~gateways ?search_sfx ?nameserver
                                 ?mac ~netmask name in
          t.Host.trx.Host.widget }

(* A cable is built like any other device, from a form with two fields that
 * happen to name other devices. It is the only one that cannot exist on its
 * own, which is why the two ends are parameters and not something set
 * afterwards: a cable with one end loose is not a cable that needs finishing,
 * it is nothing at all. *)
let cable =
    { name = "cable" ;
      descr = "Joins two devices, and delays and corrupts what crosses it." ;
      params = [
          param "from" ~kind:Widget_id ~descr:"One end." ;
          param "to" ~kind:Widget_id ~descr:"The other." ;
          param "from port" ~kind:(Widget.optional Int)
              ~descr:"Which port of it; the first free one if left out." ;
          param "to port" ~kind:(Widget.optional Int)
              ~descr:"Likewise, at the other end." ;
          param "length" ~kind:(Widget.optional (FRange (0., infinity)))
              ~units:"meters"
              ~descr:"How long it is, and hence how long a frame takes to \
                      cross it. Measured between the two ends when they are \
                      both on the map." ;
          param "error rate" ~kind:(FRange (0., 1.)) ~default:(`Float 0.)
              ~descr:"Faulty bits per bit transmitted." ] ;
      make = fun ~parent name args ->
          let sim = Simulation.of_widget parent in
          let end_ which =
              let id = int args which in
              match Widget.find sim.Simulation.root id with
              | Some w -> w
              | None ->
                  Widget.bad_value "%s: no widget %d in this simulation"
                      which id in
          let a = end_ "from" and b = end_ "to" in
          if a == b then
              Widget.bad_value "a cable joins two devices, and %s is one"
                  (Widget.full_name a) ;
          (* What the reader said, or what the map already knows. Only when both
           * ends are somewhere: one end placed and the other not says nothing
           * about the distance between them. *)
          let length =
              match opt args "length" Widget.to_float with
              | Some l -> Some l
              | None ->
                  (match a.location, b.location with
                  | Some la, Some lb -> Some (Float.round (Widget.distance la lb))
                  | _ -> None) in
          (* Both ports before the cable, so that a refusal at the second end
           * does not leave a cable hanging off the first. *)
          let end_a, dev_a = plug a (opt args "from port" Widget.to_int)
          and end_b, dev_b = plug b (opt args "to port" Widget.to_int) in
          if end_a == end_b then
              Widget.bad_value "both ends of this cable are %s"
                  (Widget.full_name end_a) ;
          let st =
              Eth.Cable.State.make ~parent ?length
                                   ~error_rate:(float args "error rate")
                                   ~name () in
          (* [Eth.Cable.connect] is the same thing between two trxs; the ports
           * of the devices here are plain [dev]s. *)
          let trx = Eth.Cable.make st in
          dev_a -=> trx <=-> dev_b ;
          (* Peered with what the cable reaches, not with what was named to ask
           * for it: "port 2 of R1" is a convenient way of saying "R1's third
           * adapter", and the widget graph is where the network itself is
           * recorded. Which is also what lets a topology be written down and
           * read back with no port numbers in it. *)
          Widget.make_peers ~via:st.Eth.Cable.State.widget end_a end_b ;
          st.Eth.Cable.State.widget }

(** Every kind of device that can be asked for, in the order the interface
 * offers them: what a network is mostly made of first. *)
let all = [ host ; switch ; hub ; cable ]

let find name =
    List.find_opt (fun t -> t.name = name) all

(** Build one: [make "switch" ~parent "sw1" [ "ports", `Int 24 ]].
 *
 * Raises {!Widget.Bad_value} for anything the caller got wrong -- an unknown
 * kind of device, a parameter that is not one, a value out of range -- which
 * the API answers with a 400. *)
let make type_ ~parent name args =
    match find type_ with
    | None ->
        Widget.bad_value "there is no such thing as a %S" type_
    | Some t ->
        if String.contains name '/' then
            Widget.bad_value "a name must not contain '/': %S" name ;
        t.make ~parent name (args_of t args)

(*$= coerce & ~printer:Yojson.Basic.to_string
  (`Int 3) (coerce "n" Widget.Int (`String "3"))
  (`Int 3) (coerce "n" (Widget.IRange (0, 5)) (`Int 3))
  `Null (coerce "n" (Widget.optional Widget.Int) `Null)
  (`Int 3) (coerce "n" (Widget.optional Widget.Int) (`Int 3))
 *)
(*$T coerce
  (try ignore (coerce "n" (Widget.IRange (0, 5)) (`Int 9)) ; false \
   with Widget.Bad_value _ -> true)
  (try ignore (coerce "n" (Widget.Enum [ "a" ]) (`String "b")) ; false \
   with Widget.Bad_value _ -> true)
  (try ignore (coerce "n" Widget.Metric (`Int 0)) ; false \
   with Widget.Bad_value _ -> true)
 *)

(*$T args_of
  args_of switch [] |> List.assoc "ports" = `Int 8
  args_of switch [ "ports", `Int 24 ] |> List.assoc "ports" = `Int 24
  (try ignore (args_of switch [ "port", `Int 24 ]) ; false \
   with Widget.Bad_value _ -> true)
  (try ignore (args_of switch [ "ports", `Int 0 ]) ; false \
   with Widget.Bad_value _ -> true)
 *)

(*$T find
  find "switch" <> None
  find "Switch" = None
 *)
