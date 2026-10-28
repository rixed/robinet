(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(* Copyright 2026, Cedric Cellier
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
(** A box between an inside, its port 0, and an outside, its port 1, that
   passes the IPv4 packets whose addresses its rules accept.

   The inside rules judge the addresses on the inside: the source of what
   goes out, the destination of what comes in; the outside rules those on
   the outside. A rule is a verdict and a CIDR; the first rule that matches
   an address decides, and an address no rule matches is denied.

   A quoted IP header, in an ICMP error, travelled the other way, so its
   source is judged by the rules of the other side. An ICMP error that comes
   in is judged by its quoted header only, so that the routers that send
   them need not be accepted.

   ARP passes. What cannot be inspected (neither IPv4 nor ARP, IPv4 carrying
   IP, an ICMP error quoting no IPv4 header) takes the verdict
   [uninspectable]. What goes out may also be required to have a given
   Ethernet source. Switched off, it passes nothing. *)
open Batteries
open Bitstring
open SimTypes
open Tools

type verdict = Accept | Deny

let verdict_names = [| "accept" ; "deny" |]

let int_of_verdict = function Accept -> 0 | Deny -> 1

let verdict_of_int = function 0 -> Accept | _ -> Deny

let string_of_verdict v = verdict_names.(int_of_verdict v)

type rule = verdict * Ip.Cidr.t

let string_of_rule (v, cidr) =
    string_of_verdict v ^" "^ Ip.Cidr.to_string cidr

(** An IPv4 CIDR, with no bit set beyond its mask, or an address standing
 * for its /32: *)
let cidr_of_string s =
    let s = String.trim s in
    let bad () = Widget.bad_value "not a CIDR: %S" s in
    let ip, width =
        match String.split s ~by:"/" with
        | exception Not_found -> s, "32"
        | ip, w -> ip, w in
    match Ip.Addr.of_dotted_string ip, int_of_string_opt width with
    | exception _ -> bad ()
    | ip, Some w when Ip.Addr.length ip = 32 && w >= 0 && w <= 32 ->
        if Ip.Addr.compare (Ip.Addr.higher_bits ip w) ip <> 0 then
            Widget.bad_value "%S has bits set beyond its mask" s ;
        Ip.Cidr.o (ip, w)
    | _ -> bad ()

(*$T cidr_of_string
  Ip.Cidr.to_string (cidr_of_string " 10.0.0.1 ") = "10.0.0.1/32"
  Ip.Cidr.to_string (cidr_of_string "10.0.0.0/8") = "10.0.0.0/8"
  (try ignore (cidr_of_string "10.0.0") ; false with Widget.Bad_value _ -> true)
  (try ignore (cidr_of_string "10.0.0.0/33") ; false with Widget.Bad_value _ -> true)
  (try ignore (cidr_of_string "localhost") ; false with Widget.Bad_value _ -> true)
  (try ignore (cidr_of_string "::1/128") ; false with Widget.Bad_value _ -> true)
  (try ignore (cidr_of_string "10.0.0.1/8") ; false \
   with Widget.Bad_value m -> m = "\"10.0.0.1/8\" has bits set beyond its mask")
*)

(** Out from port 0 to port 1, in from port 1 to port 0: *)
type direction = Out | In

let string_of_direction = function Out -> "out" | In -> "in"

(** Why a frame was dropped: *)
type cause =
    | Inside of Ip.Addr.t
    | Outside of Ip.Addr.t
    | Mac of Eth.Addr.t
    | Uninspectable

let string_of_cause = function
    | Inside ip -> "inside address "^ Ip.Addr.to_dotted_string ip ^" denied"
    | Outside ip -> "outside address "^ Ip.Addr.to_dotted_string ip ^" denied"
    | Mac mac -> "Ethernet source "^ Eth.Addr.to_hexstring mac ^" denied"
    | Uninspectable -> "uninspectable"

let cause_name = function
    | Inside _ -> "inside"
    | Outside _ -> "outside"
    | Mac _ -> "MAC"
    | Uninspectable -> "uninspectable"

type t =
    { widget : Widget.t ;
      mutable inside : rule list ;
      mutable outside : rule list ;
      mutable uninspectable : verdict ;
      (* The Ethernet source of what goes out, if imposed: *)
      mutable mac : Eth.Addr.t option ;
      (* Called on each frame dropped: *)
      mutable on_drop : direction -> cause -> unit ;
      (* Per port, whether a cable is on it and what to emit into it: *)
      forward : (bool * (bitstring -> unit)) array ;
      (* Per port, the port the cable on it reaches (see {!Hub.Tap}): *)
      peers : (Widget.t * int) option array ;
      passed : Metric.Counter.t ;
      dropped : Metric.Counter.t }

type Widget.device += T of t

let of_widget (w : Widget.t) =
    match w.device with
    | Some (T t) -> Some t
    | _ -> None

let verdict rules ip =
    match List.find_opt (fun (_, cidr) -> Ip.Cidr.mem cidr ip) rules with
    | Some (v, _) -> v
    | None -> Deny

(*$= verdict
  Accept (verdict [ Deny, cidr_of_string "10.0.0.1" ; \
                    Accept, cidr_of_string "10.0.0.0/8" ] \
                  (Ip.Addr.of_string "10.0.0.2"))
  Deny (verdict [ Deny, cidr_of_string "10.0.0.1" ; \
                  Accept, cidr_of_string "10.0.0.0/8" ] \
                (Ip.Addr.of_string "10.0.0.1"))
  Deny (verdict [ Accept, cidr_of_string "10.0.0.0/8" ] \
                (Ip.Addr.of_string "192.168.0.1"))
  Deny (verdict [] (Ip.Addr.of_string "10.0.0.1"))
*)

(* What is read of an IPv4 header, which may be truncated beyond its
 * addresses, as a quoted one may be: *)
type ip_header =
    { proto : int ; first_frag : bool ;
      src : Ip.Addr.t ; dst : Ip.Addr.t ;
      payload : bitstring }

let ip_header bits =
    match%bitstring bits with
    | {| 4 : 4 ; ihl : 4 ; _ : 8 ; _ : 16 ; _ : 16 ; _ : 3 ; frag_offset : 13 ;
         _ : 8 ; proto : 8 ; _ : 16 ; src : 32 ; dst : 32 ;
         rest : -1 : bitstring |} when ihl >= 5 ->
        let opts = (ihl - 5) * 32 in
        Some { proto ; first_frag = frag_offset = 0 ;
               src = Ip.Addr.o32 src ; dst = Ip.Addr.o32 dst ;
               payload =
                   if bitstring_length rest >= opts then dropbits opts rest
                   else empty_bitstring }
    | {| _ |} -> None

(* Protocols that carry IP, whose inner addresses are not inspected:
 * IP in IP, IPv6 and GRE. *)
let encapsulations = [ 4 ; 41 ; 47 ]

(* The ICMP types that quote the datagram they are about: *)
let icmp_errors = [ 3 ; 4 ; 5 ; 11 ; 12 ]

(* The header quoted by [ip], if it is an ICMP error: *)
let quote ip =
    if ip.proto <> (Ip.Proto.icmp :> int) || not ip.first_frag then `None
    else match%bitstring ip.payload with
        | {| typ : 8 ; _ : 56 ; quoted : -1 : bitstring |}
          when List.mem typ icmp_errors ->
            (match ip_header quoted with
            | Some q -> `Quote q
            | None -> `Unreadable)
        | {| _ |} -> `None

(* Why addresses [src] and [dst] are denied, if they are, [src_inside]
 * telling which side the source is on: *)
let judge t ~src_inside src dst =
    let check inside ip =
        if verdict (if inside then t.inside else t.outside) ip = Accept then None
        else Some (if inside then Inside ip else Outside ip) in
    match check src_inside src with
    | None -> check (not src_inside) dst
    | c -> c

(** Why that frame, going that way, is dropped, if it is: *)
let inspect t dir bits =
    let uninspectable () =
        if t.uninspectable = Accept then None else Some Uninspectable in
    match Eth.Pdu.unpack bits with
    | Error _ -> uninspectable ()
    | Ok eth ->
        match t.mac with
        | Some mac when dir = Out && not (Eth.Addr.eq eth.src mac) ->
            Some (Mac eth.src)
        | _ ->
            if eth.proto = Arp.HwProto.arp then None
            else if eth.proto <> Arp.HwProto.ip4 then uninspectable ()
            else match ip_header (eth.payload :> bitstring) with
            | None -> uninspectable ()
            | Some ip when List.mem ip.proto encapsulations -> uninspectable ()
            | Some ip ->
                let src_inside = dir = Out in
                let outer () = judge t ~src_inside ip.src ip.dst in
                match quote ip with
                | `None -> outer ()
                | `Unreadable -> uninspectable ()
                | `Quote q ->
                    let quoted () =
                        judge t ~src_inside:(not src_inside) q.src q.dst in
                    if dir = In then quoted ()
                    else match outer () with
                        | None -> quoted ()
                        | c -> c

let now t = Simulation.Widget.now t.widget

let filter t dir bits =
    if t.widget.power.on then (
        let direction = "direction", Metric.Param.String (string_of_direction dir) in
        match inspect t dir bits with
        | Some cause ->
            Metric.Counter.inc t.dropped ~now:(now t)
                ~params:(Metric.Params.make [
                    direction ;
                    "cause", Metric.Param.String (cause_name cause) ]) ;
            t.on_drop dir cause
        | None ->
            Metric.Counter.inc t.passed ~now:(now t)
                ~params:(Metric.Params.make [ direction ]) ;
            (snd t.forward.(if dir = Out then 1 else 0)) bits)

(** {2 Rules as properties} *)

let rule_kind =
    Widget.row [|
        "verdict", Widget.one_of (Widget.choices verdict_names) ;
        "CIDR", Widget.hint "10.0.0.0/8" String |]

let rules_kind = Widget.list rule_kind

let rules_to_json rules =
    `List (List.map (fun (v, cidr) ->
        `Assoc [ "verdict", `Int (int_of_verdict v) ;
                 "CIDR", `String (Ip.Cidr.to_string cidr) ]) rules)

let rules_of_json =
    Widget.(to_list (fun row ->
        verdict_of_int
            (to_field "verdict" (to_choice (choices verdict_names)) row),
        to_field "CIDR" (cidr_of_string % to_string) row))

(*$T rules_of_json
  rules_of_json (rules_to_json [ Deny, cidr_of_string "10.0.0.1" ; \
                                 Accept, cidr_of_string "0.0.0.0/0" ]) = \
    [ Deny, cidr_of_string "10.0.0.1/32" ; Accept, cidr_of_string "0.0.0.0/0" ]
  (try ignore (rules_of_json (`List [ `Assoc [ "verdict", `Int 0 ; \
                                               "CIDR", `String "nope" ] ])) ; false \
   with Widget.Bad_value m -> m = "row 1: CIDR: not a CIDR: \"nope\"")
*)

let mac_kind = Widget.hint "aa:bb:cc:dd:ee:ff" String

let mac_of_string s =
    try Eth.Addr.of_string (String.trim s)
    with _ -> Widget.bad_value "not a MAC address: %S" s

(** Accept everything: *)
let accept_all = [ Accept, Ip.Cidr.of_string "0.0.0.0/0" ]

let num_ports = 2

let make ~parent ?location ?(inside=accept_all) ?(outside=accept_all)
         ?(uninspectable=Deny) ?mac ?(on_drop=fun _ _ -> ()) name =
    let widget =
        Widget.make ~parent ?location ~device_type:"firewall" ~own_power:true
                    name in
    let t = { widget ; inside ; outside ; uninspectable ; mac ; on_drop ;
              forward = Array.make num_ports (false, ignore) ;
              peers = Array.make num_ports None ;
              passed = Metric.Counter.make () ;
              dropped = Metric.Counter.make () } in
    widget.device <- Some (T t) ;
    widget.ports <- Widget.{
        count = (fun () -> num_ports) ;
        is_connected = (fun n -> fst t.forward.(n)) ;
        dev = (fun n ->
            { write = filter t (if n = 0 then Out else In) ;
              busy_for = never_busy ;
              set_read = fun f _ -> t.forward.(n) <- true, f }) ;
        owner = (fun _ -> t.widget) ;
        disconnect = (fun n ->
            t.forward.(n) <- false, ignore ;
            t.peers.(n) <- None) ;
        (* Transparent to negotiation, as a tap is: *)
        get_capabilities = (fun ?peer n ->
            Option.may (fun p -> t.peers.(n) <- Some p) peer ;
            match t.peers.(n lxor 1) with
            | None -> NoCapabilities
            | Some p -> ForwardTo p) ;
        set_capabilities = (fun _ _ -> ())
    } ;
    Widget.add_properties widget Widget.[
        property "inside rules" ~kind:rules_kind
            ~descr:"The rules for the addresses on the inside (port 0), \
                    tried in order; an address none matches is denied."
            ~getter:(fun () -> rules_to_json t.inside)
            ~setter:(fun v -> t.inside <- rules_of_json v) ;
        property "outside rules" ~kind:rules_kind
            ~descr:"The rules for the addresses on the outside (port 1), \
                    tried in order; an address none matches is denied."
            ~getter:(fun () -> rules_to_json t.outside)
            ~setter:(fun v -> t.outside <- rules_of_json v) ;
        property "uninspectable" ~kind:(one_of (choices verdict_names))
            ~descr:"The verdict for what is neither IPv4 nor ARP, or carries \
                    IP in IP."
            ~getter:(fun () -> `Int (int_of_verdict t.uninspectable))
            ~setter:(fun v ->
                t.uninspectable <-
                    verdict_of_int (to_choice (choices verdict_names) v)) ;
        property "MAC" ~kind:(optional mac_kind)
            ~descr:"The Ethernet source that what goes out must have, if any."
            ~getter:(fun () ->
                match t.mac with
                | None -> `Null
                | Some m -> `String (Eth.Addr.to_hexstring m))
            ~setter:(fun v ->
                t.mac <- to_option (mac_of_string % to_string) v) ;
        metric_property "passed"
            ~descr:"Packets passed, by direction."
            (Metric.Counter.T t.passed) ;
        metric_property "dropped"
            ~descr:"Packets dropped, by direction and cause."
            (Metric.Counter.T t.dropped) ] ;
    t

(* [through ?rules dir frame] is what the firewall makes of [frame] sent
 * [dir]: "passed", or the cause of its drop. Inside is 10.0.0.0/8, outside
 * is anything but 192.0.2.66. *)
(*$inject
  let addr = Ip.Addr.of_string
  let mine = Eth.Addr.of_string "02:00:00:00:00:01"
  let frame ?(src_mac=mine) ?(proto=Arp.HwProto.ip4) payload =
      Eth.Pdu.(pack (make proto src_mac (Eth.Addr.random ()) payload))
  let ip ?(proto=Ip.Proto.o 253) ?(payload=Bitstring.empty_bitstring) src dst =
      Ip.Pdu.make proto (addr src) (addr dst) payload
  let packet ?proto ?payload src dst =
      frame (Ip.Pdu.pack (ip ?proto ?payload src dst))
  let error_about ~src ~dst quoted =
      packet ~proto:Ip.Proto.icmp src dst
          ~payload:Icmp.Pdu.(pack (make_ttl_expired_in_transit quoted))
  let through ?(mac=mine) dir bits =
      let sim = Simulation.make ~realtime:false "firewall" in
      let cause = ref "passed" in
      let t = make ~parent:sim.root ~mac
                ~inside:[ Accept, cidr_of_string "10.0.0.0/8" ]
                ~outside:[ Deny, cidr_of_string "192.0.2.66" ;
                           Accept, cidr_of_string "0.0.0.0/0" ]
                ~on_drop:(fun _ c -> cause := string_of_cause c) "fw" in
      Simulation.power_up t.widget.power ;
      (t.widget.ports.dev (if dir = Out then 0 else 1)).write bits ;
      !cause
*)
(*$= through & ~printer:identity
  "passed" (through Out (packet "10.0.0.1" "192.0.2.1"))
  "passed" (through In (packet "192.0.2.1" "10.0.0.1"))
  "inside address 192.168.0.1 denied" \
    (through Out (packet "192.168.0.1" "192.0.2.1"))
  "outside address 192.0.2.66 denied" \
    (through Out (packet "10.0.0.1" "192.0.2.66"))
  "outside address 192.0.2.66 denied" \
    (through In (packet "192.0.2.66" "10.0.0.1"))
  "passed" \
    (through In (error_about ~src:"192.0.2.66" ~dst:"10.0.0.1" \
                   (ip "10.0.0.1" "192.0.2.1")))
  "outside address 192.0.2.66 denied" \
    (through In (error_about ~src:"192.0.2.1" ~dst:"10.0.0.1" \
                   (ip "10.0.0.1" "192.0.2.66")))
  "passed" \
    (through Out (error_about ~src:"10.0.0.1" ~dst:"192.0.2.1" \
                    (ip "192.0.2.1" "10.0.0.2")))
  "inside address 192.168.0.1 denied" \
    (through Out (error_about ~src:"10.0.0.1" ~dst:"192.0.2.1" \
                    (ip "192.0.2.1" "192.168.0.1")))
  "passed" (through Out (frame ~proto:Arp.HwProto.arp (Bitstring.create_bitstring 224)))
  "uninspectable" \
    (through Out (frame ~proto:Arp.HwProto.ip6 (Bitstring.create_bitstring 320)))
  "uninspectable" \
    (through Out (packet ~proto:Ip.Proto.ipv6 "10.0.0.1" "192.0.2.1"))
  "Ethernet source 02:00:00:00:00:02 denied" \
    (through Out (frame ~src_mac:(Eth.Addr.of_string "02:00:00:00:00:02") \
                    (Ip.Pdu.pack (ip "10.0.0.1" "192.0.2.1"))))
  "passed" \
    (through In (frame ~src_mac:(Eth.Addr.of_string "02:00:00:00:00:02") \
                   (Ip.Pdu.pack (ip "192.0.2.1" "10.0.0.1"))))
*)
