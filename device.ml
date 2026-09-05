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
      (* What an empty input shows: an address of the shape expected, or what
       * leaving the parameter out will do. It is the description's examples,
       * moved to where they are read -- so keep it out of [descr]. Only ever
       * seen by a parameter with no [default], since a default fills the input
       * in. *)
      placeholder : string ;
      (* What the dialog offers before anything is typed, and what is used when
       * the parameter is left out. [`Null] for a parameter with no value of its
       * own, which an [Optional] kind is then obliged to accept. *)
      default : Widget.value }

let param ?(descr="") ?(units="") ?(placeholder="") ?(default=`Null) ~kind
          name =
    { name ; descr ; units ; kind ; placeholder ; default }

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

(* The port to use on [widget]: the one asked for, or the first one it has left.
 *
 * Which ports a widget has, and which of them are free, is the widget's own
 * answer (see [Widget.ports]) -- the device keeps that where it already had to,
 * so a cable plugged in by an OCaml program counts just as much as one plugged
 * in from here. *)
let free_port (widget : Widget.t) port =
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
    p

(** {2 Reading the arguments} *)

(* Coerce a value to what the parameter says it is, and check whatever the kind
 * knows how to check. Every refusal a parameter can meet before the device is
 * built happens here, once, rather than in each [make]. *)
let rec coerce name (kind : Widget.kind) v =
    match kind with
    | String | FileName -> `String (Widget.to_string v)
    | Int -> `Int (Widget.to_int v)
    | Float -> `Float (Widget.to_float v)
    | Bool -> `Bool (Widget.to_bool v)
    | Widget_id -> `Int (Widget.to_int v)
    | IRange (min, max) -> `Int (Widget.to_int_range ~min ~max v)
    | FRange (min, max) -> `Float (Widget.to_float_range ~min ~max v)
    | Enum choices ->
        let i = Widget.to_int v in
        if i < 0 || i >= Array.length choices then
            Widget.bad_value "Out of range value (%s) for %s"
                (Yojson.Basic.to_string v) name ;
        `Int i
    | Optional k ->
        (match v with `Null -> `Null | v -> coerce name k v)
    (* How a value is written is the interface's business; what arrives here is
       the value. *)
    | Hint (_, k) -> coerce name k v
    | List k ->
        `List (Widget.to_list (coerce name k) v)
    | Record fields ->
        (* Every field the record declares, in that order, and nothing else: a
           name it does not know is a misspelling, and quietly dropping it
           would build something other than what was asked for -- the same
           reason [args_of] refuses an unknown parameter. *)
        (match v with
        | `Assoc given ->
            List.iter (fun (n, _) ->
                if not (Array.exists (fun (n', _) -> n' = n) fields) then
                    Widget.bad_value "%s has no field %S" name n
            ) given ;
            `Assoc (
                Array.to_list fields |>
                List.map (fun (fname, k) ->
                    match List.assoc_opt fname given with
                    | None -> Widget.bad_value "%s has no %S" name fname
                    | Some v -> fname, coerce (name ^"."^ fname) k v))
        | v ->
            Widget.bad_value "%s must be a record, not %s" name
                (Yojson.Basic.to_string v))
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

let bool args name = Widget.to_bool (arg args name)
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

let mac_of_string name s =
    try Eth.Addr.of_string s
    with _ -> Widget.bad_value "%s: %S is not a MAC address" name s

let mac name v =
    mac_of_string name (Widget.to_string v)

(* [Ip.Cidr.of_string] resolves the address half, and resolving a name would
 * hold the simulation's lock across a DNS lookup. *)
let cidr name v =
    let s = Widget.to_string v in
    match String.split_on_char '/' s with
    | [ addr ; width ] ->
        (match Ip.Addr.of_dotted_string_opt addr, int_of_string_opt width with
        | Some a, Some w when w >= 0 && w <= 32 -> Ip.Cidr.o (a, w)
        | _ -> Widget.bad_value "%s: %S is not a CIDR" name s)
    | _ -> Widget.bad_value "%s: %S is not a CIDR" name s

(* An address within the range those leading octets describe, the rest picked
 * at random. An empty range means [Eth.Addr.random], which picks a locally
 * administered individual address rather than any 48 bits at all. *)
let random_mac range =
    if range = "" then Eth.Addr.random () else
    let given = String.split_on_char ':' range |> List.filter ((<>) "") in
    let n = List.length given in
    if n > 5 then
        Widget.bad_value "MAC range: %S leaves nothing to pick" range ;
    List.iter (fun o ->
        match int_of_string_opt ("0x"^ o) with
        | Some v when v >= 0 && v <= 255 -> ()
        | _ -> Widget.bad_value "MAC range: %S is not an octet" o
    ) given ;
    let rest =
        List.init (6 - n) (fun _ -> Printf.sprintf "%02x" (Random.int 256)) in
    Eth.Addr.of_string (String.concat ":" (given @ rest))

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
              ~placeholder:"asked of a DHCP server"
              ~descr:"Its IP address." ;
          param "netmask" ~kind:String ~default:(`String "255.255.255.0")
              ~descr:"Which addresses it can reach without a gateway." ;
          param "gateway" ~kind:(Widget.optional String)
              ~placeholder:"192.168.0.1"
              ~descr:"Where to send what the netmask does not cover." ;
          param "nameserver" ~kind:(Widget.optional String)
              ~placeholder:"192.168.0.1"
              ~descr:"Which DNS server to ask." ;
          param "search suffix" ~kind:(Widget.optional String)
              ~placeholder:"example.com"
              ~descr:"Appended to the names it is asked to resolve." ;
          param "MAC" ~kind:(Widget.optional String)
              ~placeholder:"drawn at random"
              ~descr:"Its hardware address." ] ;
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
              ~placeholder:"the first free one"
              ~descr:"Which port of it." ;
          param "to port" ~kind:(Widget.optional Int)
              ~placeholder:"the first free one"
              ~descr:"Likewise, at the other end." ;
          param "length" ~kind:(Widget.optional (FRange (0., infinity)))
              ~units:"meters" ~placeholder:"distance on the map"
              ~descr:"How long it is, and hence how long a frame takes to \
                      cross it." ;
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
          let pa = free_port a (opt args "from port" Widget.to_int)
          and pb = free_port b (opt args "to port" Widget.to_int) in
          (* What the cable will really reach. "Port 2 of R1" is a convenient
           * way of saying "R1's third adapter", and it is the adapter the
           * graph records -- which is what lets a topology be written down and
           * read back with no port numbers in it. *)
          if a.ports.owner pa == b.ports.owner pb then
              Widget.bad_value "both ends of this cable are %s"
                  (Widget.full_name (a.ports.owner pa)) ;
          let st =
              Eth.Cable.State.make ~parent ?length
                                   ~error_rate:(float args "error rate")
                                   ~name () in
          Eth.Cable.plug st (a, pa) (b, pb) ;
          st.Eth.Cable.State.widget }

(*$T random_mac
  let pfx m = Bitstring.subbitstring (m : Eth.Addr.t :> Bitstring.t) 0 24 in \
  Bitstring.equals (pfx (random_mac "00:11:22")) \
                   (pfx (Eth.Addr.of_string "00:11:22:33:44:55"))
  not (Eth.Addr.eq (random_mac "00:11:22") (random_mac "00:11:22"))
  not (Eth.Addr.eq (random_mac "") (random_mac ""))
  (try ignore (random_mac "zz") ; false with Widget.Bad_value _ -> true)
  (try ignore (random_mac "00:11:22:33:44:55") ; false \
   with Widget.Bad_value _ -> true)
 *)

(* One address per interface: the ones that were named, or ones picked within
 * the range. *)
let macs_of args n =
    match String.trim (string args "MACs") with
    | "" ->
        let range = String.trim (string args "MAC range") in
        Array.init n (fun _ -> random_mac range)
    | s ->
        let l =
            String.split_on_char ',' s |>
            List.map (fun a -> mac_of_string "MACs" (String.trim a)) in
        if List.length l <> n then
            Widget.bad_value "MACs: %d address(es) for %d port(s)"
                (List.length l) n ;
        Array.of_list l

(* The two entries below build a machine and nothing more. A router arrives
 * with an empty routing table and interfaces with no address, a gateway with
 * whatever its two networks were said to be -- what a packet is to be done
 * with is configuration, and configuration is what properties are for. What
 * stays here is what a machine cannot be reconfigured into: how many sockets
 * it has, and how big its tables are. *)
let mac_params = [
    param "MAC range" ~kind:String ~default:(`String "")
        ~placeholder:"00:11:22"
        ~descr:"The leading octets every interface's address shares, the rest \
                being picked at random. Empty for addresses picked at random \
                entirely." ;
    param "MACs" ~kind:String ~default:(`String "")
        ~placeholder:"00:11:22:33:44:55, ..."
        ~descr:"The addresses themselves instead, one per port, for when \
                picking them is not good enough." ]

let router =
    { name = "router" ;
      descr = "Forwards packets between its interfaces. It arrives with an \
               empty routing table: where a packet is to go is \
               configuration, not something the machine is built with." ;
      params =
          param "ports" ~kind:(IRange (1, 1024)) ~default:(`Int 4)
              ~descr:"How many interfaces it has, each taking one cable." ::
          mac_params ;
      make = fun ~parent name args ->
          let n = int args "ports" in
          let macs = macs_of args n in
          let widget = Widget.make ~parent name in
          let (_ : Router.Router.t) = Router.Router.make ~macs n [] widget in
          widget }

let gateway =
    { name = "gateway" ;
      descr = "A router with a NAT, a DHCP server and a resolver behind it: \
               one port to the outside world, one to the network it \
               serves." ;
      params = [
          param "public address" ~kind:String ~default:(`String "192.0.2.1")
              ~descr:"The address it is known by on the outside, and the one \
                      it translates its network's traffic to." ;
          param "LAN" ~kind:String ~default:(`String "192.168.0.0/24")
              ~descr:"The network behind it, in CIDR notation. Its first \
                      address is the gateway itself, the second the server that \
                      hands out the rest." ;
          param "max connections" ~kind:(IRange (1, 1_000_000))
              ~default:(`Int 500)
              ~descr:"How many translations its NAT holds at once." ] ;
      make = fun ~parent name args ->
          let public = addr "public address" (arg args "public address")
          and lan = cidr "LAN" (arg args "LAN") in
          let gw =
              Router.make_gw ~parent ~name
                  ~num_max_cnxs:(int args "max connections") public lan in
          gw.Router.widget }

let portal =
    { name = "portal" ;
      descr = "Open a host's real interface to exchange packets with the real \
               world. Will turn this simulation into real-time mode." ;
      params = [
          param "promisc" ~kind:Bool ~default:(`Bool true)
              ~descr:"Open this interface in promiscuous mode." ;
          param "filter" ~kind:String ~default:(`String "")
              ~descr:"Filter to select packets to capture." ;
          param "caplen" ~kind:(Optional (IRange (1, 65535))) ~default:`Null
              ~descr:"Capture length (default to the interface MTU)." ] ;
      make = fun ~parent name args ->
          let promisc = bool args "promisc"
          and filter = string args "filter"
          and caplen = opt args "caplen" Widget.to_int in
          let portal = Pcap.portal ~parent ~promisc ~filter ?caplen name in
          portal.widget }

let recorder =
    { name = "recorder" ;
      descr = "Save every received packet into a pcap file." ;
      params = [
          (* What to play. If unset (as after creation, or after the file is
           * taken out) then there is nothing to play and nothing is sent. *)
          param "file name"
              ~kind:(Optional (Hint ("capture.pcap", String))) ~default:`Null
              ~descr:"Name of the first file to record, in the pcap library." ;
          param "caplen" ~kind:(Optional (IRange (1, 65535))) ~default:`Null
              ~descr:"Capture length (default to the interface MTU)." ;
          param "DLT" ~kind:(Optional Int)
              ~default:(`Int (Pcap.Dlt.to_int Pcap.default_dlt))
              ~descr:"DLT to use to create the pcap file." ] ;
      make = fun ~parent name args ->
          let fname = opt args "file name" Widget.to_string
          and caplen = opt args "caplen" Widget.to_int in
          let dlt = opt args "DLT" (Pcap.Dlt.o % Int32.of_int % Widget.to_int) in
          let recorder = Pcap.recorder ~parent ?fname ?caplen ?dlt name in
          recorder.widget }

let replayer =
    { name = "replayer" ;
      descr = "Replay the packets from a pcap file." ;
      params = [
          (* Where to record. If unset (after creation or eject) then do not
           * record anything. *)
          param "file name"
              ~kind:(Optional (Hint ("capture.pcap", String))) ~default:`Null
              ~descr:"Name of the file to replay, in the pcap library." ;
          param "loop"
              ~kind:Bool ~default:(`Bool false)
              ~descr:"Whether to restart replaying from the beginning at the \
                      end." ] ;
      make = fun ~parent name args ->
          let fname = opt args "file name" Widget.to_string
          and loop = bool args "loop" in
          let replayer = Pcap.replayer ~parent ?fname ~loop name in
          replayer.widget }

(** Every kind of device that can be asked for, in the order the interface
 * offers them: what a network is mostly made of first. *)
let all =
    [ host ; switch ; hub ; router ; gateway ; portal ; recorder ; replayer ;
      cable ]

let find name =
    List.find_opt (fun t -> t.name = name) all

(** {2 Naming a new device} *)

(* The lowest "stem-N" no child of [parent] answers to. From 1 rather than from
 * a bare "stem", since a name the machine picked is one of a series and reads
 * better as one. *)
let numbered_name (parent : Widget.t) stem =
    let taken n =
        List.exists (fun (w : Widget.t) -> w.name = n) parent.children in
    let rec loop i =
        let n = Printf.sprintf "%s-%d" stem i in
        if taken n then loop (i + 1) else n in
    loop 1

(* A cable is better named after the two things it joins than after a number:
 * "r1-sw1" says what "cable-7" cannot, and the ends are known here because
 * they are parameters. Falls back to the numbering when either end is not a
 * widget of this simulation -- [cable.make] is about to say so properly, and
 * naming is not the place to raise that. *)
let cable_name (parent : Widget.t) args =
    let sim = Simulation.of_widget parent in
    let end_ which =
        match List.assoc_opt which args with
        | None -> None
        | Some v ->
            (match Widget.to_int v with
            | exception _ -> None
            | id ->
                Option.map (fun (w : Widget.t) -> w.name)
                           (Widget.find sim.Simulation.root id)) in
    match end_ "from", end_ "to" with
    | Some a, Some b -> a ^"-"^ b
    | _ -> numbered_name parent "cable"

(** What a device is called when it is not given a name: what kind of thing it
 * is, and the lowest free number.
 *
 * A cable is named after its two ends instead, which is the one name here that
 * may be taken already -- by the second cable between the same pair.
 * {!Widget.unique_among} numbers that one, as it does any name that is taken
 * by the time the widget is built. *)
let default_name parent t args =
    (* Physical equality on the catalogue entry: there is one value per kind of
     * device, and this is a property of the cable itself rather than of
     * anything that happens to be called "cable". *)
    if t == cable then cable_name parent args
    else numbered_name parent t.name

(*$T numbered_name
  let r = Widget.make_root ~sim:0 ~now:(fun () -> Clock.Time.o 0.) "r" in \
  numbered_name r "host" = "host-1" && \
  (ignore (Widget.make ~parent:r "host-1") ; \
   numbered_name r "host" = "host-2")
 *)

(** The catalogue entry a widget was built from, if this catalogue knows how to
 * build its kind at all.
 *
 * [None] for a part of a device rather than a whole one, and for a kind this
 * catalogue does not offer -- a router, for now. That is what makes it the
 * answer to "may the API remove this?": what it cannot put back, it will not
 * take away. *)
let of_widget (w : Widget.t) =
    (* Nothing inside a device is one: the repeater within a switch is a
     * repeater all right, and the router within a gateway is a router, but
     * they are that switch's and that gateway's. One does not order, or
     * return, the parts of a machine separately. Said once here rather than by
     * every composite remembering to disown its parts. *)
    let rec within_a_device (w : Widget.t) =
        match w.parent with
        | None -> false
        | Some p -> p.Widget.device <> None || within_a_device p in
    if within_a_device w then None
    else Option.bind w.Widget.device find

(** Build one: [make "switch" ~parent "sw1" [ "ports", `Int 24 ]].
 *
 * An empty name asks for one to be picked (see [default_name]), which is what
 * the interface sends when the reader left the field alone. A name that was
 * actually typed and is already a sibling's is refused instead of being
 * numbered like a part's would be: what the reader named, the reader named.
 *
 * Raises {!Widget.Bad_value} for anything the caller got wrong -- an unknown
 * kind of device, a parameter that is not one, a value out of range, a name
 * that is taken -- which the API answers with a 400. *)
let make type_ ~parent name args =
    match find type_ with
    | None ->
        Widget.bad_value "there is no such thing as a %S" type_
    | Some t ->
        if String.contains name '/' then
            Widget.bad_value "a name must not contain '/': %S" name ;
        (* Before the name, since a cable is named after the ends its arguments
         * point at. *)
        let args = args_of t args in
        let name =
            match String.trim name with
            | "" -> default_name parent t args
            | name ->
                if List.exists (fun (w : Widget.t) -> w.name = name)
                               parent.Widget.children then
                    Widget.bad_value "there is already something called %S \
                                      here" name ;
                name in
        t.make ~parent name args

(*$= coerce & ~printer:Yojson.Basic.to_string
  (`Int 3) (coerce "n" Widget.Int (`String "3"))
  (`Int 3) (coerce "n" (Widget.IRange (0, 5)) (`Int 3))
  `Null (coerce "n" (Widget.optional Widget.Int) `Null)
  (`Int 3) (coerce "n" (Widget.optional Widget.Int) (`Int 3))
 *)
(*$T coerce
  (try ignore (coerce "n" (Widget.IRange (0, 5)) (`Int 9)) ; false \
   with Widget.Bad_value _ -> true)
  (try ignore (coerce "n" (Widget.Enum [| "a" |]) (`Int 9)) ; false \
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
