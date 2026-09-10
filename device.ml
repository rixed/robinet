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

(** {2 What a device is built from} *)

(** Everything one device needs to be told, at the type it is really wanted at.
 *
 * This is what an OCaml program builds a network out of, and what the
 * interface's JSON is turned into before anything is built, so that a
 * misspelt parameter or an address that is not one is refused in one place
 * rather than in the middle of a constructor.
 *
 * A constructor that has a choice to make -- the first free port, an address
 * drawn at random -- returns the model with that choice filled in, and it is
 * that model, not the one it was handed, that is written down. A choice not
 * written down is one that would be made again, and differently, the next time
 * the network is built from what was saved of it.
 *
 * The [T] prefix keeps these apart from the modules of the same name, since a
 * host model and the [Host] module are named after the same thing and read
 * side by side here. *)
type model =
    | THub of { ports : int ; speed : Eth.Speed.t }
    | TSwitch of { ports : int ; speeds : Eth.Speed.t list ;
                   full_duplex : bool ; macs : int }
    | THost of { static_ip : Ip.Addr.t option ; netmask : Ip.Addr.t option ;
                 gateway : Ip.Addr.t option ; nameserver : Ip.Addr.t option ;
                 search_sfx : string option ; mac : Eth.Addr.t option }
    (* The two ends are widget ids, which is what the interface has to name
       them with, and what a topology turns into paths on the way out. *)
    | TCable of { from_ : int ; to_ : int ;
                  from_port : int option ; to_port : int option ;
                  length : float option ; error_rate : float }
    (* [mac_range] is what to draw the addresses from and [macs] the addresses
       themselves. A model that has been built carries the addresses and an
       empty range: once they are written down the range has nothing left to
       say. *)
    | TRouter of { ports : int ; mac_range : string ; macs : Eth.Addr.t list }
    | TGateway of { public : Ip.Addr.t ; lan : Ip.Cidr.t ;
                    max_cnxs : int ; mac : Eth.Addr.t option }
    | TPortal of { promisc : bool ; filter : string ; caplen : int option }
    | TRecorder of { fname : string option ; caplen : int option ;
                     dlt : Pcap.Dlt.t option }
    | TReplayer of { fname : string option ; loop : bool }
    | TNote of { text : string }

(** A kind of device: what it is called, what it needs, and how to read what it
 * needs out of what was asked for.
 *
 * [of_params] is handed the arguments already coerced and bounds-checked
 * against the [params] above, so it reads them without checking them again,
 * and raises {!Widget.Bad_value} for what only it can refuse -- an address
 * that is not one, a count of addresses that does not match a count of ports.
 * What it returns is a {!model}, and building is [make]'s business from there.
 *
 * The two halves are declared together and belong read together: this is the
 * one seam the compiler cannot check, since nothing ties a parameter named
 * here to a field read there. See the round-trip tests at the end. *)
type t =
    { name : string ;
      descr : string ;
      params : param list ;
      of_params : (string * Widget.value) list -> model }

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
        (try `Int (Widget.to_choice choices v)
        with Widget.Bad_value m -> Widget.bad_value "%s: %s" name m)
    (* In order and without repetition, however it was sent: [make] is handed
       the set itself, and has nothing left to check about it. *)
    | Set choices ->
        (try `List (Widget.to_choices choices v |>
                    List.map (fun i -> `Int i))
        with Widget.Bad_value m -> Widget.bad_value "%s: %s" name m)
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
let list args name f = Widget.to_list f (arg args name)

(** Record on [widget] what it was really built with, for a [make] that had a
 * choice to make: [changed] replaces those of [args] it names, and the rest
 * stand as they were given.
 *
 * A choice that is not written down here is one that will be made again, and
 * differently, when this device is built back from what was saved of it: the
 * first free port of a device is not the same port once something has been
 * unplugged from it, and an address drawn at random is never the same twice.
 * [Device.make] records the model as it came back for every device that had
 * nothing to choose, and leaves alone the ones that came through here. *)
let made_with (widget : Widget.t) args changed =
    widget.Widget.made_with <-
        Some (
            List.map (fun (name, v) ->
                name, (List.assoc_opt name changed |? v)
            ) args)

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
              ~descr:"How many cables it takes." ;
          param "speed" ~kind:(Enum Hub.Repeater.speed_names) ~default:(`Int 1)
              ~descr:"Hub speed." ] ;
      of_params = fun args ->
          THub { ports = int args "ports" ;
                 speed = Hub.Repeater.speeds.(int args "speed") } }

let switch =
    { name = "switch" ;
      descr = "Forwards frames to the port it last saw their destination on." ;
      params = [
          param "ports" ~kind:(IRange (2, 1024)) ~default:(`Int 8)
              ~descr:"How many cables it takes." ;
          param "speeds" ~kind:(Set Eth.Speed.names)
              ~default:(`List (List.map (fun s -> `Int (Eth.Speed.to_enum s))
                                        Eth.Iface.default_speeds))
              ~descr:"Speeds accepted by every ports (can be updated later)." ;
          param "full duplex" ~kind:Bool ~default:(`Bool true)
              ~descr:"Do ports support full-duplex by default?" ;
          param "MACs" ~kind:(IRange (1, 1_000_000)) ~default:(`Int 1024)
              ~descr:"How many addresses it can remember at once." ] ;
      of_params = fun args ->
          TSwitch {
              ports = int args "ports" ;
              speeds =
                  list args "speeds" (fun v ->
                      Eth.Speed.all.(Widget.to_choice Eth.Speed.names v)) ;
              full_duplex = bool args "full duplex" ;
              macs = int args "MACs" } }

let host =
    { name = "host" ;
      descr = "A machine with a single network adapter." ;
      params = [
          (* The one parameter that cannot be an afterthought: with an address
           * the host is configured statically, without one it goes looking for
           * a DHCP server, and the two are different machines from here on. *)
          param "static-ip" ~kind:(Widget.optional String)
              ~placeholder:"static IP (or use DHCP)"
              ~descr:"Its static IP address." ;
          (* A host that is given an address of its own is given the netmask
           * that goes with it; one left to DHCP is told by the lease, and has
           * this only to fall back on -- so it may be left out entirely,
           * although the usual answer is offered rather than an empty field. *)
          param "netmask" ~kind:(Widget.optional String)
              ~default:(`String "255.255.255.0")
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
      of_params = fun args ->
          THost {
              static_ip = opt args "static-ip" (Ip.Addr.of_json "static-ip") ;
              netmask = opt args "netmask" (Ip.Addr.of_json "netmask") ;
              gateway = opt args "gateway" (Ip.Addr.of_json "gateway") ;
              nameserver = opt args "nameserver" (Ip.Addr.of_json "nameserver") ;
              search_sfx = opt args "search suffix" Widget.to_string ;
              mac = opt args "MAC" (mac "MAC") } }

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
      of_params = fun args ->
          TCable {
              from_ = int args "from" ;
              to_ = int args "to" ;
              from_port = opt args "from port" Widget.to_int ;
              to_port = opt args "to port" Widget.to_int ;
              length = opt args "length" Widget.to_float ;
              error_rate = float args "error rate" } }

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
let macs_of ~range ~macs n =
    match macs with
    | [] -> List.init n (fun _ -> random_mac range)
    | l ->
        if List.length l <> n then
            Widget.bad_value "MACs: %d address(es) for %d port(s)"
                (List.length l) n ;
        l

(* The addresses a "MACs" parameter names, in order, or none at all when it is
 * left empty and they are to be picked from the range instead. *)
let macs_of_string name s =
    match String.trim s with
    | "" -> []
    | s ->
        String.split_on_char ',' s |>
        List.map (fun a -> mac_of_string name (String.trim a))

let string_of_macs macs =
    List.map Eth.Addr.to_hexstring macs |> String.concat ", "

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
      of_params = fun args ->
          TRouter {
              ports = int args "ports" ;
              mac_range = String.trim (string args "MAC range") ;
              macs = macs_of_string "MACs" (string args "MACs") } }

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
              ~descr:"How many translations its NAT holds at once." ;
          param "MAC" ~kind:(Widget.optional String)
              ~placeholder:"drawn at random"
              ~descr:"Its hardware address on the side of the network it \
                      serves, which is the one the machines behind it send \
                      to." ] ;
      of_params = fun args ->
          TGateway {
              public =
                  Ip.Addr.of_json "public address" (arg args "public address") ;
              lan = cidr "LAN" (arg args "LAN") ;
              max_cnxs = int args "max connections" ;
              mac = opt args "MAC" (mac "MAC") } }

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
      of_params = fun args ->
          TPortal { promisc = bool args "promisc" ;
                    filter = string args "filter" ;
                    caplen = opt args "caplen" Widget.to_int } }

let recorder =
    { name = "recorder" ;
      descr = "Save every received packet into a pcap file." ;
      params = [
          (* What to play. If unset (as after creation, or after the file is
           * taken out) then there is nothing to play and nothing is sent. *)
          param "file name"
              ~kind:(Optional (Hint ("capture.pcap", FileName))) ~default:`Null
              ~descr:"Name of the first file to record, in the pcap library." ;
          param "caplen" ~kind:(Optional (IRange (1, 65535))) ~default:`Null
              ~descr:"Capture length (default to the interface MTU)." ;
          param "DLT" ~kind:(Optional Int)
              ~default:(`Int (Pcap.Dlt.to_int Pcap.default_dlt))
              ~descr:"DLT to use to create the pcap file." ] ;
      of_params = fun args ->
          TRecorder {
              fname = opt args "file name" Widget.to_string ;
              caplen = opt args "caplen" Widget.to_int ;
              dlt =
                  opt args "DLT"
                      (Pcap.Dlt.o % Int32.of_int % Widget.to_int) } }

let replayer =
    { name = "replayer" ;
      descr = "Replay the packets from a pcap file." ;
      params = [
          (* Where to record. If unset (after creation or eject) then do not
           * record anything. *)
          param "file name"
              ~kind:(Optional (Hint ("capture.pcap", FileName))) ~default:`Null
              ~descr:"Name of the file to replay, in the pcap library." ;
          param "loop"
              ~kind:Bool ~default:(`Bool false)
              ~descr:"Whether to restart replaying from the beginning at the \
                      end." ] ;
      of_params = fun args ->
          TReplayer { fname = opt args "file name" Widget.to_string ;
                      loop = bool args "loop" } }

(* The one entry that is not a device at all: a label on the map, with no
 * ports, no power and nothing to simulate. It is here because everything the
 * interface offers to add, place, edit, delete and save goes through this
 * catalogue, and a network one cannot write on is one the reader has to
 * remember rather than read.
 *
 * The last thing left of net.ml, which had it and which nothing else replaced.
 * Its text is a parameter as well as a property so that a note can be written
 * as it is put down, rather than put down blank and then filled in. *)
let note =
    { name = "note" ;
      descr = "Something written on the map: a name for a part of the \
               network, a reminder, a question." ;
      params = [
          param "text" ~kind:String ~default:(`String "")
              ~descr:"What it says." ] ;
      of_params = fun args -> TNote { text = string args "text" } }

(** {2 Building one} *)

(** What kind of device a model describes, named as the catalogue names it. *)
let type_of = function
    | THub _ -> "hub"
    | TSwitch _ -> "switch"
    | THost _ -> "host"
    | TCable _ -> "cable"
    | TRouter _ -> "router"
    | TGateway _ -> "gateway"
    | TPortal _ -> "portal"
    | TRecorder _ -> "recorder"
    | TReplayer _ -> "replayer"
    | TNote _ -> "note"

(** A model written back out as the parameters it was read from, which is the
 * shape a topology is saved in and the shape the interface speaks.
 *
 * Every parameter the kind declares, so that what comes back out can be read
 * straight back in. The other half of each entry's [of_params], and the pair
 * of them is what the round-trip test at the end of this file checks. *)
let to_params =
    let ip_opt = function
        | None -> `Null
        | Some ip -> `String (Ip.Addr.to_dotted_string ip)
    and str_opt = function None -> `Null | Some s -> `String s
    and int_opt = function None -> `Null | Some i -> `Int i
    and float_opt = function None -> `Null | Some f -> `Float f
    (* In hex and not [Eth.Addr.to_string], which may name the vendor instead
       and is then not an address any more. *)
    and mac_opt = function
        | None -> `Null
        | Some m -> `String (Eth.Addr.to_hexstring m) in
    function
    | THub { ports ; speed } ->
        [ "ports", `Int ports ;
          "speed", `Int (Array.findi ((=) speed) Hub.Repeater.speeds) ]
    | TSwitch { ports ; speeds ; full_duplex ; macs } ->
        [ "ports", `Int ports ;
          "speeds", `List (List.map (fun s -> `Int (Eth.Speed.to_enum s))
                                    speeds) ;
          "full duplex", `Bool full_duplex ;
          "MACs", `Int macs ]
    | THost { static_ip ; netmask ; gateway ; nameserver ; search_sfx ; mac } ->
        [ "static-ip", ip_opt static_ip ;
          "netmask", ip_opt netmask ;
          "gateway", ip_opt gateway ;
          "nameserver", ip_opt nameserver ;
          "search suffix", str_opt search_sfx ;
          "MAC", mac_opt mac ]
    | TCable { from_ ; to_ ; from_port ; to_port ; length ; error_rate } ->
        [ "from", `Int from_ ;
          "to", `Int to_ ;
          "from port", int_opt from_port ;
          "to port", int_opt to_port ;
          "length", float_opt length ;
          "error rate", `Float error_rate ]
    | TRouter { ports ; mac_range ; macs } ->
        [ "ports", `Int ports ;
          "MAC range", `String mac_range ;
          "MACs", `String (string_of_macs macs) ]
    | TGateway { public ; lan ; max_cnxs ; mac } ->
        [ "public address", `String (Ip.Addr.to_dotted_string public) ;
          "LAN", `String (Ip.Cidr.to_string lan) ;
          "max connections", `Int max_cnxs ;
          "MAC", mac_opt mac ]
    | TPortal { promisc ; filter ; caplen } ->
        [ "promisc", `Bool promisc ;
          "filter", `String filter ;
          "caplen", int_opt caplen ]
    | TRecorder { fname ; caplen ; dlt } ->
        [ "file name", str_opt fname ;
          "caplen", int_opt caplen ;
          "DLT", (match dlt with
                 | None -> `Null
                 | Some d -> `Int (Pcap.Dlt.to_int d)) ]
    | TReplayer { fname ; loop } ->
        [ "file name", str_opt fname ;
          "loop", `Bool loop ]
    | TNote { text } ->
        [ "text", `String text ]

(* Build the thing itself, and answer with the model that was really used: the
 * one handed in, with whatever it left open filled in with what was chosen.
 * See [model] for why that matters. *)
let build ~parent name = function
    | THub { ports ; speed } as m ->
        let t = Hub.Repeater.make ~parent ~speed ports name in
        t.Hub.Repeater.widget, m
    | TSwitch { ports ; speeds ; full_duplex ; macs } as m ->
        let t = Hub.Switch.make ~parent ~speeds ~full_duplex ports macs name in
        t.Hub.Switch.widget, m
    | THost ({ static_ip ; netmask ; gateway ; nameserver ; search_sfx ;
               mac } as h) ->
        let gateways =
            match gateway with
            | None -> []
            | Some gw ->
                [ Eth.State.gw_selector (), Some (Eth.Gateway.IPv4 gw) ] in
        let t =
            Host.make ~parent ~gateways ?search_sfx ?nameserver ?static_ip
                      ?netmask ?mac name in
        (* The address it ended up with, drawn at random when it was not given
           one. Its "MAC" property is read-only, so nothing else would bring it
           back. *)
        t.Host.trx.Host.widget,
        THost { h with mac = Some t.Host.eth_state.Eth.State.mac }
    | TCable { from_ ; to_ ; from_port ; to_port ; length ; error_rate } ->
        let sim = Simulation.of_widget parent in
        let end_ which id =
            match Widget.find sim.Simulation.root id with
            | Some w -> w
            | None ->
                Widget.bad_value "%s: no widget %d in this simulation"
                    which id in
        let a = end_ "from" from_ and b = end_ "to" to_ in
        if a == b then
            Widget.bad_value "a cable joins two devices, and %s is one"
                (Widget.full_name a) ;
        (* What the reader said, or what the map already knows. Only when both
         * ends are somewhere: one end placed and the other not says nothing
         * about the distance between them. *)
        let length =
            match length with
            | Some l -> Some l
            | None ->
                (match a.location, b.location with
                | Some la, Some lb -> Some (Float.round (Widget.distance la lb))
                | _ -> None) in
        (* Both ports before the cable, so that a refusal at the second end
         * does not leave a cable hanging off the first. *)
        let pa = free_port a from_port
        and pb = free_port b to_port in
        (* What the cable will really reach. "Port 2 of R1" is a convenient
         * way of saying "R1's third adapter", and it is the adapter the
         * graph records -- which is what lets a topology be written down and
         * read back with no port numbers in it. *)
        if a.ports.owner pa == b.ports.owner pb then
            Widget.bad_value "both ends of this cable are %s"
                (Widget.full_name (a.ports.owner pa)) ;
        let st =
            Eth.Cable.State.make ~parent ?length ~error_rate ~name () in
        Eth.Cable.plug st (a, pa) (b, pb) ;
        (* The ports it took and the length it ended up with, all three of
           which it may have been left to work out for itself. *)
        st.Eth.Cable.State.widget,
        TCable { from_ ; to_ ; from_port = Some pa ; to_port = Some pb ;
                 length = Some st.Eth.Cable.State.length ; error_rate }
    | TRouter { ports ; mac_range ; macs } ->
        let macs = macs_of ~range:mac_range ~macs ports in
        let widget = Widget.make ~parent name in
        let (_ : Router.Router.t) =
            Router.Router.make ~macs:(Array.of_list macs) ports [] widget in
        (* The addresses themselves, whether they were named or drawn from the
           range: a range that picks is a choice like any other, and once the
           addresses are written down it has nothing left to say. *)
        widget, TRouter { ports ; mac_range = "" ; macs }
    | TGateway ({ public ; lan ; max_cnxs ; mac } as g) ->
        (* Drawn here rather than left to the gateway to draw, so that what it
           ends up with can be written down: it keeps no property of its
           address, and a network whose machines come back sending to somewhere
           else is not the one that was saved. *)
        let mac = Option.default_delayed Eth.Addr.random mac in
        let gw =
            Router.make_gw ~parent ~name ~mac ~num_max_cnxs:max_cnxs public
                           lan in
        gw.Router.widget, TGateway { g with mac = Some mac }
    | TPortal { promisc ; filter ; caplen } as m ->
        let portal = Pcap.portal ~parent ~promisc ~filter ?caplen name in
        portal.Pcap.widget, m
    | TRecorder { fname ; caplen ; dlt } as m ->
        let recorder = Pcap.recorder ~parent ?fname ?caplen ?dlt name in
        recorder.Pcap.widget, m
    | TReplayer { fname ; loop } as m ->
        let replayer = Pcap.replayer ~parent ?fname ~loop name in
        replayer.Pcap.widget, m
    | TNote { text } as m ->
        let widget = Widget.make ~parent ~device_type:"note" name in
        let text = ref text in
        Widget.add_properties widget Widget.[
            property "text" ~kind:String ~descr:"What it says."
                ~getter:(fun () -> `String !text)
                ~setter:(fun v -> text := to_string v) ] ;
        widget, m
(** Every kind of device that can be asked for, in the order the interface
 * offers them: what a network is mostly made of first, and what is not a
 * device at all last. *)
let all =
    [ host ; switch ; hub ; router ; gateway ; portal ; recorder ; replayer ;
      cable ; note ]

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
 * widget of this simulation -- [build] is about to say so properly, and naming
 * is not the place to raise that. *)
let cable_name (parent : Widget.t) from_ to_ =
    let sim = Simulation.of_widget parent in
    let end_ id =
        Option.map (fun (w : Widget.t) -> w.name)
                   (Widget.find sim.Simulation.root id) in
    match end_ from_, end_ to_ with
    | Some a, Some b -> a ^"-"^ b
    | _ -> numbered_name parent "cable"

(** What a device is called when it is not given a name: what kind of thing it
 * is, and the lowest free number.
 *
 * A cable is named after its two ends instead, which is the one name here that
 * may be taken already -- by the second cable between the same pair.
 * {!Widget.unique_among} numbers that one, as it does any name that is taken
 * by the time the widget is built. *)
let default_name parent = function
    | TCable { from_ ; to_ ; _ } -> cable_name parent from_ to_
    | m -> numbered_name parent (type_of m)

(*$T numbered_name
  let r = Widget.make_root ~sim:0 ~now:(fun () -> Clock.Time.zero) "r" in \
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
        | Some p -> p.Widget.device_type <> None || within_a_device p in
    if within_a_device w then None
    else Option.bind w.Widget.device_type find

(** The model a set of parameters describes:
 * [model_of_params "switch" [ "ports", `Int 24 ]].
 *
 * This is the whole of the untyped boundary. Past it a device is built from a
 * {!model}, and nothing looks a parameter up by name again.
 *
 * Raises {!Widget.Bad_value} for anything the caller got wrong -- an unknown
 * kind of device, a parameter that is not one, a value out of range -- which
 * the API answers with a 400. *)
let model_of_params type_ given =
    match find type_ with
    | None ->
        Widget.bad_value "there is no such thing as a %S" type_
    | Some t ->
        t.of_params (args_of t given)

(** Build one: [make ~parent "sw1" (TSwitch { ... })].
 *
 * An empty name asks for one to be picked (see [default_name]), which is what
 * the interface sends when the reader left the field alone. A name that was
 * actually typed and is already a sibling's is refused instead of being
 * numbered like a part's would be: what the reader named, the reader named.
 *
 * What the widget is left carrying is the model as it was really built, so
 * that a save writes down the choices the constructor made rather than the
 * blanks it was handed. *)
let make ~parent name model =
    if String.contains name '/' then
        Widget.bad_value "a name must not contain '/': %S" name ;
    let name =
        match String.trim name with
        | "" -> default_name parent model
        | name ->
            if List.exists (fun (w : Widget.t) -> w.name = name)
                           parent.Widget.children then
                Widget.bad_value "there is already something called %S here"
                    name ;
            name in
    let w, built = build ~parent name model in
    w.Widget.made_with <- Some (to_params built) ;
    w

(** Both at once, for a caller that has parameters rather than a model: the
 * interface, and a topology being read back. *)
let make_from_params type_ ~parent name given =
    make ~parent name (model_of_params type_ given)

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

(* A root to build under. A simulation's own and not a bare [Widget.make_root]:
 * a device reaches for the simulation it is being built in, to draw its power
 * and to schedule on its clock, and finds it by the number its root carries. *)
(*$inject
  let root () =
      (Simulation.make ~realtime:false "r").Simulation.root
 *)

(* A root to build under. A simulation's own and not a bare [Widget.make_root]:
 * a device reaches for the simulation it is being built in, to draw its power
 * and to schedule on its clock, and finds it by the number its root carries. *)
(* [sample_params] below is every parameter of [t] at its declared default. A
 * cable is the one kind with no complete set of those: a cable that joins
 * nothing is not a cable, so its two ends have no default and are named here.
 *
 * Said out here because a comment inside an inject block ends it at the first
 * comment terminator it meets. *)
(*$inject
  let root () =
      (Simulation.make ~realtime:false "r").Simulation.root

  let sample_params t =
      args_of t (if t == cable then [ "from", `Int 1 ; "to", `Int 2 ] else [])
 *)

(* The one seam the compiler cannot check: a parameter this file declares and a
   field it reads are tied by a string and nothing else. So for each kind of
   device, read its own declared parameters into a model and write that model
   back out, and expect what was declared.

   That catches a parameter renamed on one side only, one the reader forgets,
   and one the writer invents, which between them are every way the two halves
   can part company. *)
(*$T all
  List.for_all (fun t -> \
      let declared = sample_params t in \
      to_params (t.of_params declared) = declared \
  ) all
 *)

(* And the other way about, which is what a save and a reload really do. *)
(*$T all
  List.for_all (fun t -> \
      let m = t.of_params (sample_params t) in \
      t.of_params (args_of t (to_params m)) = m \
  ) all
 *)

(* Every kind the catalogue offers is a kind it can name back. *)
(*$T type_of
  List.for_all (fun t -> type_of (t.of_params (sample_params t)) = t.name) all
 *)

(* What a device is built with is written down, and what it chose for itself is
   written down as chosen rather than as the blank it was handed. A choice that
   went unrecorded would be made again, and differently, on the way back in. *)
(*$T make
  (let w = make ~parent:(root ()) "sw" (TSwitch { ports = 24 ; macs = 8 ; \
               speeds = Eth.Iface.default_speeds ; full_duplex = true }) in \
   match w.Widget.made_with with \
   | Some args -> List.assoc "ports" args = `Int 24 \
   | None -> false)
  (* Handed no address, a host comes back with the one it drew: *) \
  (let w = make ~parent:(root ()) "h" (THost { static_ip = None ; \
               netmask = Some (Ip.Addr.of_string "255.255.255.0") ; \
               gateway = None ; \
               nameserver = None ; search_sfx = None ; mac = None }) in \
   match w.Widget.made_with with \
   | Some args -> List.assoc "MAC" args <> `Null \
   | None -> false)
  (* And a hand-wired widget still answers nothing at all: *) \
  (ignore make ; \
   Widget.make ~parent:(root ()) "by hand").Widget.made_with = None
 *)

(* A widget built here can be turned back into the thing it stands for, which
   is what a program needs to run anything on a host it just asked for. Each
   module answers for its own kind and for no other, so asking the wrong one is
   how a caller finds out it has the wrong sort of device. *)
(*$T make_from_params
  (match Host.of_widget \
             (make_from_params "host" ~parent:(root ()) "h" []) with \
   | Some (h : Host.t) -> h.Host.trx.Host.widget.Widget.name = "h" \
   | None -> false)
  (match Hub.Switch.of_widget \
             (make_from_params "switch" ~parent:(root ()) "sw" []) with \
   | Some (s : Hub.Switch.t) -> Array.length s.Hub.Switch.ifaces = 8 \
   | None -> false)
  Hub.Switch.of_widget (make_from_params "host" ~parent:(root ()) "h" []) = None
  (* A part of a device is not a device: the adapter within a host stands for \
     nothing on its own. *) \
  (match (make_from_params "host" ~parent:(root ()) "h" []).Widget.children \
   with \
   | [ eth ] -> Host.of_widget eth = None \
   | _ -> false)
  (* A misspelt parameter is refused rather than ignored, before anything is \
     built: *) \
  (try ignore (make_from_params "switch" ~parent:(root ()) "sw" \
                   [ "port", `Int 4 ]) ; false \
   with Widget.Bad_value _ -> true)
 *)
