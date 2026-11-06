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
  Equipment for routing traffic
 *)
open Batteries
open SimTypes

open Bitstring
open Tools

(** Routes are instructions where to forward each incoming packet. *)
module Route =
struct
    (*$< Route *)
    (* If we had a generic port module, this would go there *)
    type port_range = int * int (** Inclusive IP port range *)

    let string_of_port_range (mi, ma) =
        "from port "^ string_of_int mi ^" to "^ string_of_int ma

    let port_in_range p (mi, ma) = p >= mi && p <= ma

    let port_in_range_opt p = function
        | None -> true
        | Some r -> port_in_range p r

    (** A [route] is a set of optional tests and an output iface and optional
     * gateway. *)
    type target =
        | Forward of { out_iface : int ;                  (** Output iface *)
                             via : Eth.Gateway.t option } (** Optional gateway *)
        | Admin (* Packets are for the admin interface (TODO) *)
        (* TODO: MirrorTo, Deny, Ignore, with a default behavior for packets
         * dropping out of the routing table... *)

    (* TODO: add usage count *)
    type t = { (* Tests *)
               in_iface : int option ;              (** Test on incoming iface *)
               src_mask : (Ip.Cidr.t * (Ip.Addr.t -> bool)) option ;
                                                    (** Test on source IP *)
               dst_mask : (Ip.Cidr.t * (Ip.Addr.t -> bool)) option ;
                                                    (** Test on dest IP *)
               ip_proto : Ip.Proto.t option ;       (** Test on IP protocol *)
               src_port : port_range option ;       (** Test on source IP port *)
               dst_port : port_range option ;       (** Test on dest IP port *)
                 target : target }

    let make ?in_iface ?src_mask ?dst_mask ?ip_proto ?src_port ?dst_port
             target =
        let to_mask_test = Option.map (fun cidr -> cidr, Ip.Cidr.mem cidr) in
        { src_mask = to_mask_test src_mask ;
          dst_mask = to_mask_test dst_mask ;
          in_iface ; ip_proto ; src_port ; dst_port ; target }

    let forward ?in_iface ?src_mask ?dst_mask ?ip_proto ?src_port ?dst_port
                ?via out_iface =
        let target = Forward { out_iface  ; via } in
        make ?in_iface ?src_mask ?dst_mask ?ip_proto ?src_port ?dst_port target

    let admin ?in_iface ?src_mask ?ip_proto ?src_port ?dst_port my_ip =
        let dst_mask = Ip.Cidr.single my_ip in
        make ?in_iface ?src_mask ~dst_mask ?ip_proto ?src_port ?dst_port Admin

    let print oc t =
        let optionally f = function
            | Some n -> f n
            | None -> "" in
        let string_of_in_iface n = "received at iface#"^ string_of_int n ^", "
        and string_of_proto p = "of "^ Ip.Proto.to_string p ^" protocol, "
        and string_of_ip_mask what (cidr, _) = what ^ Ip.Cidr.to_string cidr ^" "
        and string_of_port r = "port "^ string_of_port_range r ^" "
        and string_of_target = function
            | Forward { out_iface ; via } ->
                "iface#"^ string_of_int out_iface ^
                (match via with
                | None -> ", direct"
                | Some gw -> ", using gateway "^ Eth.Gateway.to_string gw)
            | Admin ->
                "admin"
        in
        "Packets " ^
            (optionally string_of_in_iface t.in_iface) ^
            (optionally string_of_proto t.ip_proto) ^
            (optionally (string_of_ip_mask "from ") t.src_mask) ^
            (optionally string_of_port t.src_port) ^
            (optionally (string_of_ip_mask "to ") t.dst_mask) ^
            (optionally string_of_port t.dst_port) ^
        "will be sent to " ^
            (string_of_target t.target) |>
        String.print oc

    (* If the route test is set, then the value is required. *)
    let test_opt opt1 test opt2 =
        match opt2 with
        | Some opt -> Option.map_default (test opt) true opt1
        | None     -> Option.is_none opt1

    let cidr_mem_rev ip (_, f) = f ip

    (** Test an incoming packet against a route, considering all fields but for
     * its destination. *)
    let test_but_dst t ifn src_opt proto_opt src_port_opt dst_port_opt =
        test_opt t.in_iface (=) ifn &&
        test_opt t.src_mask cidr_mem_rev src_opt &&
        test_opt t.ip_proto (=) proto_opt &&
        test_opt t.src_port port_in_range src_port_opt &&
        test_opt t.dst_port port_in_range dst_port_opt

    (** Test an incoming packet against a route. *)
    let test t ifn src_opt dst_opt proto_opt src_port_opt dst_port_opt =
        test_opt t.dst_mask cidr_mem_rev dst_opt &&
        test_but_dst t ifn src_opt proto_opt src_port_opt dst_port_opt

    (*$Q test
      (Q.make (fun st -> \
        let rnd = Random.State.int st in \
        let opt f = if rnd 3 = 0 then None else Some (f ()) in \
        let addr () = \
          if rnd 6 = 0 then Ip.Addr.of_dotted_string "2001:db8::1" \
          else Ip.Addr.o32 (Int32.of_int (0x0a000000 + rnd 4 * 256 + rnd 4)) in \
        let cidr () = \
          Ip.Cidr.o (addr (), [| 0 ; 8 ; 16 ; 23 ; 24 ; 31 ; 32 |].(rnd 7)) in \
        let proto () = if rnd 2 = 0 then Ip.Proto.tcp else Ip.Proto.udp in \
        let routes = List.init (rnd 20) (fun _ -> \
          forward ?in_iface:(opt (fun () -> rnd 3)) ?dst_mask:(opt cidr) \
                  ?ip_proto:(opt proto) (rnd 3)) \
        and pkts = List.init 20 (fun _ -> \
          opt (fun () -> rnd 3), opt addr, opt proto) in \
        routes, pkts)) \
      (fun (routes, pkts) -> \
        let t = Table.make routes in \
        List.for_all (fun (ifn, dst, proto) -> \
          let linear = List.filter (fun r -> \
            test r ifn None dst proto None None) routes \
          and indexed = Table.matching t ifn None dst proto None None in \
          List.length linear = List.length indexed && \
          List.for_all2 (==) linear indexed) pkts)
     *)

    (* Widget.kind for a route: the tests a packet must pass, then where it
     * goes. Every test may be left out, and one left out is one not made.
     *
     * The fields whose name does not say how to fill them in carry an example
     * of it (see [Widget.hint]): "src mask" is a network and not an address,
     * and a port range is written in a way nobody would guess. *)
    let kind num_ports =
        Widget.(Row [|
            "input port", optional (IRange (0, num_ports-1)) ;
            "src mask", optional (hint "192.168.0.0/24" String) ;
            "dst mask", optional (hint "192.168.0.0/24" String) ;
            "ip proto", optional (IRange (0, 255)) ;
            "src port", optional (hint "min-max" String) ;
            "dst port", optional (hint "min-max" String) ;
            "output port", optional (IRange (0, num_ports-1)) ;
            "via", optional (hint "MAC or IP address" String) |])

    (* One end of a port range, or one port on its own. Which field it was
       about is added by whoever asked for it (see [Widget.to_field]). *)
    let port_of_string s =
        match int_of_string (String.trim s) with
        | exception _ ->
            Widget.bad_value "%S is not a port number" s
        | p when p < 0 || p > 65535 ->
            Widget.bad_value "port %d is not in 0…65535" p
        | p -> p

    (** Read a range of ports, written as the interface offers it: "min-max",
     * or "min-" and "-max" for a range open at that end, or a single port on
     * its own. Spaces anywhere are ignored, since a reader typing "80 - 443"
     * has said exactly what they meant. *)
    let port_range_of_string s =
        let mi, ma =
            match String.split_on_char '-' s with
            (* No dash at all: one port, which is the range of that one port.
               Written that way it is what most rules are about. *)
            | [ one ] ->
                let p = port_of_string one in p, p
            (* An end left blank is that end of what a port can be, which is
               what "everything above 1024" has to mean. *)
            | [ lo ; hi ] ->
                (if String.trim lo = "" then 0 else port_of_string lo),
                (if String.trim hi = "" then 65535 else port_of_string hi)
            | _ ->
                Widget.bad_value
                    "%S is not a port or a range of them (min-max)" s in
        if mi > ma then
            Widget.bad_value "%d-%d holds no port at all" mi ma ;
        mi, ma

    (*$= port_range_of_string & ~printer:dump
      (80, 80)      (port_range_of_string "80")
      (80, 443)     (port_range_of_string "80-443")
      (80, 65535)   (port_range_of_string "80-")
      (0, 443)      (port_range_of_string "-443")
      (0, 65535)    (port_range_of_string "-")
      (80, 443)     (port_range_of_string "  80 - 443  ")
      (80, 80)      (port_range_of_string " 80 ")
     *)
    (*$T port_range_of_string
      (try ignore (port_range_of_string "http") ; false \
       with Widget.Bad_value _ -> true)
      (try ignore (port_range_of_string "70000") ; false \
       with Widget.Bad_value _ -> true)
      (try ignore (port_range_of_string "443-80") ; false \
       with Widget.Bad_value _ -> true)
      (try ignore (port_range_of_string "1-2-3") ; false \
       with Widget.Bad_value _ -> true)
     *)
    (*$>*)
end

(** A routing table indexed by destination: for every address length and
 * prefix width some dst mask has, the rows by the network they name. The
 * rows whose dst mask holds an address are then found with one lookup per
 * width. *)
module Table =
struct
    type t = { routes : Route.t list ; (** What it was made of *)
               rows : Route.t array ;
               any_dst : int list ; (** Rows with no dst mask *)
               by_width : ((int * int) * int list StrHash.t) list }

    (* The first [width] bits of [addr], the rest of their byte zeroed: *)
    let prefix addr width =
        let n = (width + 7) / 8 in
        let s = Bytes.sub addr 0 n in
        if width land 7 <> 0 then
            Bytes.set s (n - 1) (Char.chr (
                Char.code (Bytes.get s (n - 1)) land
                ((0xff lsl (8 - width land 7)) land 0xff))) ;
        Bytes.unsafe_to_string s

    let make routes =
        let rows = Array.of_list routes in
        let any_dst = ref [] and by_width = ref [] in
        Array.iteri (fun i (r : Route.t) ->
            match r.dst_mask with
            | None ->
                any_dst := i :: !any_dst
            | Some (cidr, _) ->
                let net, width = (cidr :> Ip.Addr.t * int) in
                let net = Ip.Addr.to_bytes net in
                let len = Bytes.length net in
                let width = max 0 (min width (8 * len)) in
                let h =
                    try List.assoc (len, width) !by_width
                    with Not_found ->
                        let h = StrHash.create 16 in
                        by_width := ((len, width), h) :: !by_width ;
                        h in
                StrHash.modify_def [] (prefix net width) (List.cons i) h
        ) rows ;
        { routes ; rows ; any_dst = !any_dst ; by_width = !by_width }

    (** The rows that may match a packet to [dst_opt], in table order. *)
    let candidates t dst_opt =
        match dst_opt with
        | None ->
            List.rev t.any_dst
        | Some dst ->
            let addr = Ip.Addr.to_bytes dst in
            List.fold_left (fun acc ((len, width), h) ->
                if len <> Bytes.length addr then acc else
                List.rev_append
                    (StrHash.find_default h (prefix addr width) []) acc
            ) t.any_dst t.by_width |>
            List.sort Int.compare

    (** The rows matching that packet, in table order. *)
    let matching t ifn src_opt dst_opt proto_opt src_port_opt dst_port_opt =
        candidates t dst_opt |>
        List.filter_map (fun i ->
            let r = t.rows.(i) in
            if Route.test_but_dst r ifn src_opt proto_opt src_port_opt
                                  dst_port_opt
            then Some r else None)
end


(** A router is a device with N IP/Eth devices and a routing
 * table with rules on interface number, Ip addresses, proto, ports.
 * IP packets TTL is decremented and expired with optional support for ICMP
 * expiration error messages. *)

(* Probability to send ICMP expiry messages after TTL expiration, and after
 * which delay (TODO: should also depend on how busy the router is): *)
type icmp_probability = {
    mutable probability : float ;
          mutable delay : float }

let notify_never = { probability = 0. ; delay = 0. }
let notify_always ?(delay=0.) () = { probability = 1. ; delay }

type iface = { mutable trx : trx ; (** Can come handy to splice another trx there. *)
                       eth : Eth.State.t ;
        (** Any traffic arriving in this interface and directed to Admin is
         * forwarded to this host. There is one per interface so they have
         * totally independent IP stacks. If all the admin_hosts of a router
         * were to be made to edit the router's global configuration then
         * they would have to share that storage area of course. *)
        mutable admin_host : Host.t option ;
(** Fragment IPv4 packets larger than the MTU, unless they have DF set. *)
mutable link_fragmentation : bool ;
               (** Longest a frame may wait in this interface's queue, which
                * caps its backlog at that much of its negotiated speed: *)
               mutable max_queue_delay : float ;
               (** Errors about packets received here are reported with the product
                * of this and the router's probability, after the sum of both
                * delays: *)
               notify_errs : icmp_probability ;
               (** Whether router advertisements are sent from here, and the
                * router lifetime they give, in seconds: *)
               mutable advertise : bool ;
               mutable router_lifetime : int ;
               (* The unsolicited advertisements scheduled by an older
                * [start_router_adverts] stop when this changes: *)
               mutable ra_gen : int ;
               (* Whether a solicited advertisement is due: *)
               mutable ra_pending : bool }

type load_balancing =
    | First (* Forward a packet to its first matching route *)
    | Flow (* Forward a packet to one matching route based on the socket pair *)
    | Random (* Pick a matching route at random *)
    | RoundRobin (* Take the matching routes in turn, one packet each *)
    [@@deriving enum]

(* TODO: to_string_array with ppx_deriving.show if it happens again: *)
let all_load_balancing =
    [| "first matching" ; "track flow" ; "random" ; "round robin" |]

(** A router is mainly an array of ifaces and a route table *)
type t = {         ifaces : iface array ;
           mutable routes : Route.t list ;
           (** [routes] indexed, remade whenever it is found to be made of
            * another list: *)
            mutable table : Table.t ;
             (** How diligently to report errors with ICMP *)
              notify_errs : icmp_probability ;
           (** Answers from admin should go through routing, as opposed
            * to return via the same interface: *)
    mutable admin_reroute : bool ;
mutable can_forward_after : int option ;
                   widget : Widget.t ;
   mutable load_balancing : load_balancing ;
        (** Where [RoundRobin] left off. One cursor for the whole box and
         * not one per destination: what is being shared out is the
         * router's own outgoing links. *)
        mutable lb_cursor : int ;
          (** Max total RAM available to buffer frames, a third of which is
           * reserved to the ports, in equal parts. [None] for just enough
           * for every port to fill its [max_queue_delay] at once: *)
  mutable buffer_capacity : int option ;
                 (** RAM used by all queued frames or reserved per port
                  * space, as of its last refresh: *)
                 buffered : Metric.Gauge.t ;
  (** Whether a refresh of [buffered] is scheduled: *)
  mutable refresh_pending : bool ;
             (** Count the frames dropped for out of RAM *)
             tail_dropped : Metric.Counter.t ;
  (** Drop, rather than forward unchanged, the IPv6 packets with a
   * hop-by-hop options header, or a segment routing header: *)
  mutable drop_hop_by_hop : bool ;
         mutable drop_srh : bool ;
        extension_dropped : Metric.Counter.t }

type Widget.device += T of t

(* The router a widget stands for, when it stands for one. A gateway's
   widget stands for the gateway, not for the router inside it, and answers
   [None] here; see [gw_of_widget]. *)
let of_widget (w : Widget.t) =
    match w.device with
    | Some (T t) -> Some t
    | _ -> None

(* Add a route (the added route becomes top priority *)
let add_route (t : t) r =
    Log.(log t.widget.logger Debug (lazy (Printf.sprintf2 "Adding route: %a" Route.print r))) ;
    t.routes <- r :: t.routes

let target_routes ?in_iface ?src_ip ?dst_ip ?proto ?src_port ?dst_port t =
    if t.table.routes != t.routes then
        t.table <- Table.make t.routes ;
    Table.matching t.table in_iface src_ip dst_ip proto src_port
                         dst_port |>
    List.map (fun (r : Route.t) -> r.target)

(* Most bytes [iface] may have queued, or [None] while it has no link (and
 * drops everything anyway): *)
let max_backlog iface =
    Option.map (fun (speed, _) ->
        int_of_float (iface.max_queue_delay *. EthSpeed.to_bps speed /. 8.)
    ) iface.eth.iface.negotiated

let actual_buffer_capacity t =
    match t.buffer_capacity with
    | Some c -> c
    | None ->
        Array.fold_left (fun sum iface ->
            match max_backlog iface with
            | Some m -> sum + m
            | None -> sum
        ) 0 t.ifaces

(* RAM reserved to each port alone, out of [capacity]: *)
let reserved_of_capacity t capacity =
    capacity / 3 / Array.length t.ifaces

let buffer_reserved t =
    reserved_of_capacity t (actual_buffer_capacity t)

(* What a port takes from the shared pool when [backlog] bytes are queued on
 * it: *)
let shared_use ~reserved backlog =
    Stdlib.Int.max 0 (backlog - reserved)

(* RAM used by the queued frames and the reserves, [reserved] to each port.
 * The queues being those of the Eth interfaces, this is never out of step
 * with what they hold. *)
let buffer_used_with t reserved =
    Array.fold_left (fun sum iface ->
        let backlog = Eth.Iface.backlog iface.eth.iface in
        sum + reserved + shared_use ~reserved backlog
    ) 0 t.ifaces

let buffer_used t =
    buffer_used_with t (buffer_reserved t)

(* Set [buffered] from the queues, then again when the last frame queued so
 * far has left, until all are empty. *)
let rec refresh_buffered t () =
    let now = Simulation.Widget.now t.widget in
    Metric.Gauge.set t.buffered ~now (buffer_used t) ;
    let drained_at =
        Array.fold_left (fun m iface ->
            Clock.Time.max m iface.eth.iface.tx_busy_until
        ) now t.ifaces in
    t.refresh_pending <- Clock.Time.compare drained_at now > 0 ;
    if t.refresh_pending then
        Simulation.at t.widget.power drained_at (refresh_buffered t) ()

(* Whether port [n] has room to queue a frame of [len] bytes: up to its
 * reserve, then from what the shared pool has left, and never beyond its own
 * [max_backlog] -- unless its queue is empty, so that a frame is never
 * dropped for being larger than that. *)
let buffer_alloc t n len =
    let iface = t.ifaces.(n) in
    let backlog = Eth.Iface.backlog iface.eth.iface in
    let capacity = actual_buffer_capacity t in
    let reserved = reserved_of_capacity t capacity in
    let extra =
        shared_use ~reserved (backlog + len) - shared_use ~reserved backlog in
    let over_max =
        match max_backlog iface with
        | Some m -> backlog > 0 && backlog + len > m
        | None -> false in
    if over_max ||
       extra > 0 && extra > capacity - buffer_used_with t reserved then (
        let now = Simulation.Widget.now t.widget in
        let params = Metric.dir_params ~port:n "tail-dropped" in
        Metric.Counter.inc t.tail_dropped ~now ~params ;
        false
    ) else (
        (* The frame reaches the Eth queue later than now: *)
        if not t.refresh_pending then (
            t.refresh_pending <- true ;
            Simulation.asap t.widget.power (refresh_buffered t) ()
        ) ;
        true
    )

(* What routing reads of an IP packet, of either version: *)
type packet = V4 of Ip.Pdu.t | V6 of Ip6.Pdu.t

let unpack_packet bits =
    match%bitstring bits with
    | {| 6 : 4 ; _ |} -> Result.map (fun ip -> V6 ip) (Ip6.Pdu.unpack bits)
    | {| _ |} -> Result.map (fun ip -> V4 ip) (Ip.Pdu.unpack bits)

let packet_src = function V4 ip -> ip.Ip.Pdu.src | V6 ip -> ip.Ip6.Pdu.src
let packet_dst = function V4 ip -> ip.Ip.Pdu.dst | V6 ip -> ip.Ip6.Pdu.dst
let packet_ttl = function V4 ip -> ip.Ip.Pdu.ttl | V6 ip -> ip.Ip6.Pdu.ttl
let packet_proto = function V4 ip -> ip.Ip.Pdu.proto | V6 ip -> ip.Ip6.Pdu.proto
let packet_ports = function
    | V4 ip -> Ip.Pdu.get_ports ip
    | V6 ip -> Ip6.Pdu.get_ports ip

(* Link-local unicast and multicast of link or node scope, which no router
 * forwards (RFC 4291, 2.5.6 and 2.7): *)
let is_link_scoped a =
    Ip.Addr.is_v6 a &&
    (Ip.Addr.is_link_local a ||
     Ip.Addr.is_multicast a &&
     Char.code (Bytes.get (Ip.Addr.to_bytes a) 1) land 0xf <= 2)
(*$T is_link_scoped
  is_link_scoped (Ip.Addr.of_string "fe80::1")
  is_link_scoped (Ip.Addr.of_string "ff02::1")
  not (is_link_scoped (Ip.Addr.of_string "ff05::1"))
  not (is_link_scoped (Ip.Addr.of_string "2001:db8::1"))
  not (is_link_scoped (Ip.Addr.of_string "169.254.0.1"))
 *)

(* Whether [ip] carries an extension header that [t] is told to drop: *)
let unwelcome t (ip : Ip6.Pdu.t) =
    List.exists (function
        | Ip6.Extension.Hop_by_hop _ -> t.drop_hop_by_hop
        | Routing (Srh _) -> t.drop_srh
        | _ -> false) ip.extensions

(* The errors a router reports: *)
type error =
    | No_route
    | Unresolved (* no neighbor answered for the next hop *)
    | Expired
    | Too_big of int (* the MTU of the next hop *)

(* No ICMPv6 error about an ICMPv6 error, nor about a packet whose source does
 * not single out its sender, nor, unless it is too big, about one sent to a
 * multicast group (RFC 4443, 2.4 (e)): *)
let may_report_v6 err (ip : Ip6.Pdu.t) =
    let is_error =
        ip.proto = Ip.Proto.icmpv6 && not (Ip6.Pdu.is_later_fragment ip) &&
        match%bitstring (ip.payload :> bitstring) with
        | {| typ : 8 ; _ |} -> typ < 128
        | {| _ |} -> false in
    not is_error &&
    not Ip.Addr.(is_multicast ip.src || compare ip.src zero6 = 0) &&
    (match err with Too_big _ -> true | _ -> not (Ip.Addr.is_multicast ip.dst))

(* Either [Ok] the packets to emit on [iface] in place of [bits], or [Error p]
 * if [p] does not fit the MTU and cannot be fragmented, which IPv6 packets
 * never are. What is not an IP packet is left whole for Eth to deal with. *)
let maybe_fragment iface bits =
    if bytelength bits <= iface.eth.mtu then Ok [ bits ]
    else match unpack_packet bits with
        | Error _ -> Ok [ bits ]
        | Ok (V6 _ as p) -> Error p
        | Ok (V4 ip as p) ->
            if ip.dont_frag || not iface.link_fragmentation then Error p
            else match Ip.Pdu.fragment iface.eth.mtu ip with
                | exception Invalid_argument _ -> Error p
                | frags -> Ok frags

(* {2 Router advertisements (RFC 4861, section 6)} *)

(* Prefix lifetimes, as radvd's defaults: *)
let ra_valid = 86400 * 30
let ra_preferred = 86400 * 7

(* The IPv6 prefixes on the link of interface [n], but link-local: those of
 * its addresses, and those routed out of it with no gateway that hold one of
 * them. As lengths and addresses: *)
let on_link_prefixes t n =
    let mine =
        List.filter (fun (a : Eth.State.my_address) ->
            bitstring_length a.addr = 128 &&
            not (Ip.Addr.is_link_local (Ip.Addr.of_bitstring a.addr))
        ) t.ifaces.(n).eth.my_addresses in
    let prefix len addr =
        if len > 0 && len < 128 then
            Some (len, concat [ takebits len addr ; zeroes_bitstring (128 - len) ])
        else None in
    let of_addrs =
        List.filter_map (fun (a : Eth.State.my_address) ->
            prefix a.prefix_len a.addr) mine
    and of_routes =
        List.filter_map (fun (r : Route.t) ->
            match r.target, r.dst_mask with
            | Forward { out_iface ; via = None }, Some (cidr, _)
              when out_iface = n ->
                let addr, len = (cidr : Ip.Cidr.t :> Ip.Addr.t * int) in
                if Ip.Addr.is_v6 addr &&
                   List.exists (fun (a : Eth.State.my_address) ->
                       Ip.Cidr.mem cidr (Ip.Addr.of_bitstring a.addr)) mine then
                    prefix len (Ip.Addr.to_bitstring addr)
                else None
            | _ -> None) t.routes in
    List.unique ~eq:(fun (l1, p1) (l2, p2) -> l1 = l2 && bits_equal p1 p2)
                (of_addrs @ of_routes) |>
    List.map (fun (len, p) -> len, Ip.Addr.of_bitstring p)
(*$T on_link_prefixes
  let c = Ip.Cidr.of_string in \
  let r = make_from_addrs ~parent:(Simulation.make ~realtime:false "p").root \
            [| [ c "2001:db8:1::fe/64", None ; c "10.0.0.1/24", None ], \
               Eth.Addr.random () |] "r" in \
  List.map (fun (l, p) -> Ip.Addr.to_string p ^"/"^ string_of_int l) \
           (on_link_prefixes r 0) = [ "2001:db8:1::/64" ]
 *)

(* The advertisement of interface [n], if it has on-link prefixes: those,
 * autonomous if /64, its MTU and its MAC. *)
let router_advert t n =
    let iface = t.ifaces.(n) in
    let prefixes = on_link_prefixes t n in
    if prefixes = [] then None else
    Some (Icmp6.Pdu.make_router_advert ~lifetime:iface.router_lifetime (
        Icmp6.Opt.Source_lla (Eth.Ndp.lla iface.eth.mac) ::
        Icmp6.Opt.Mtu iface.eth.mtu ::
        List.map (fun (prefix_len, prefix) ->
            Icmp6.Opt.Prefix { prefix_len ; on_link = true ;
                               autonomous = prefix_len = 64 ; flags = 0 ;
                               valid = ra_valid ; preferred = ra_preferred ;
                               prefix }
        ) prefixes))

(* To all nodes, from the link-local address of interface [n]: *)
let send_router_advert t n =
    let iface = t.ifaces.(n) in
    let link_local =
        List.find_opt (fun (a : Eth.State.my_address) ->
            bitstring_length a.addr = 128 &&
            Ip.Addr.is_link_local (Ip.Addr.of_bitstring a.addr)
        ) iface.eth.my_addresses in
    match router_advert t n, link_local with
    | Some ra, Some ll ->
        Log.(log iface.eth.iface.widget.logger Debug (lazy "Advertising")) ;
        Eth.Ndp.packet ll.addr Eth.Ndp.all_nodes ra |> tx iface.trx
    | _ -> ()

(* As RFC 4861, section 10, and radvd's default intervals: *)
let max_initial_rtr_advertisements = 3
let max_initial_rtr_advert_interval = 16.
let max_ra_delay_time = 0.5
let min_rtr_adv_interval = 200.
let max_rtr_adv_interval = 600.

(* The unsolicited advertisements of interface [n], from within a second, if
 * it advertises and is on: the initial ones, then one every 200 to 600s.
 * In the background, as hosts solicit one when they boot. *)
let start_router_adverts t n =
    let iface = t.ifaces.(n) in
    iface.ra_gen <- iface.ra_gen + 1 ;
    let gen = iface.ra_gen and power = t.widget.power in
    let rec loop i () =
        if iface.ra_gen = gen && iface.advertise then (
            send_router_advert t n ;
            let interval =
                if i < max_initial_rtr_advertisements then
                    max_initial_rtr_advert_interval
                else
                    min_rtr_adv_interval +.
                    Random.float (max_rtr_adv_interval -. min_rtr_adv_interval) in
            Simulation.delay ~background:true power
                (Clock.Interval.sec interval) (loop (i + 1)) ()) in
    if power.on && iface.advertise then
        Simulation.delay ~background:true power
            (Clock.Interval.sec (Random.float 1.)) (loop 1) ()

(* A router solicitation received by interface [n]: one advertisement for all
 * the solicitations of the next half second. *)
let router_solicited t n =
    let iface = t.ifaces.(n) in
    if iface.advertise && not iface.ra_pending then (
        iface.ra_pending <- true ;
        Simulation.delay t.widget.power
            (Clock.Interval.sec (Random.float max_ra_delay_time)) (fun () ->
                iface.ra_pending <- false ;
                send_router_advert t n) ())

let is_router_solicit (ip : Ip6.Pdu.t) =
    ip.proto = Ip.Proto.icmpv6 && ip.ttl = 255 &&
    match Icmp6.Pdu.unpack (ip.payload :> bitstring) with
    | Ok { payload = Router_solicit _ ; _ } -> true
    | _ -> false

(* Report [err] about [p], received at interface [n], from the address of
 * that interface [p]'s source is reached from. Sending performs routing
 * again. *)
let rec maybe_send_icmp t n p err =
    let src = packet_src p in
    match Eth.State.src_for t.ifaces.(n).eth src with
    | None ->
        Log.(log t.widget.logger Debug (lazy "Cannot send an ICMP error: I have no IP!"))
    | Some my_ip ->
        let iface_errs = t.ifaces.(n).notify_errs in
        if (match p with V6 ip -> may_report_v6 err ip | V4 _ -> true) &&
           Random.float 1. <
           t.notify_errs.probability *. iface_errs.probability then
            let delay =
                jitter 0.1 (t.notify_errs.delay +. iface_errs.delay) in
            let bits =
                match p with
                | V4 ip ->
                    let icmp =
                        match err with
                        | No_route | Unresolved ->
                            Icmp.Pdu.make_host_unreachable ip
                        | Expired -> Icmp.Pdu.make_ttl_expired_in_transit ip
                        | Too_big mtu ->
                            Icmp.(Pdu.make_destination_unreachable
                                ~next_hop_mtu:mtu
                                Unreachable.fragmentation_needed ip) in
                    Icmp.Pdu.pack icmp |>
                    Ip.Pdu.make Ip.Proto.icmp my_ip src |>
                    Ip.Pdu.pack
                | V6 ip ->
                    let icmp =
                        match err with
                        | No_route ->
                            Icmp6.(Pdu.make_destination_unreachable
                                Unreachable.no_route ip)
                        | Unresolved ->
                            Icmp6.(Pdu.make_destination_unreachable
                                Unreachable.address ip)
                        | Expired -> Icmp6.Pdu.make_hop_limit_exceeded ip
                        | Too_big mtu -> Icmp6.Pdu.make_packet_too_big mtu ip in
                    Icmp6.Pdu.pack icmp |>
                    Ip6.Pdu.make Ip.Proto.icmpv6 my_ip src |>
                    Ip6.Pdu.pack in
            Simulation.delay t.widget.power
                         (Clock.Interval.sec delay) (route None t) bits

(* The [route] function receives the IP packets from the Eth trx.
 * The integer [in_iface_opt] is the input interface number, unless
 * it's coming from the admin. *)
and route in_iface_opt t bits =
    Log.(log t.widget.logger Debug (lazy (match in_iface_opt with
        | Some n -> Printf.sprintf "rx from iface %d" n
        | None -> "generated traffic"))) ;
    let p_opt = Result.to_option (unpack_packet bits) in
    let src_opt = Option.map packet_src p_opt
    and dst_opt = Option.map packet_dst p_opt
    and ttl_opt = Option.map packet_ttl p_opt
    and proto_opt = Option.map packet_proto p_opt in
    let src_port_opt, dst_port_opt =
        match Option.bind p_opt (Result.to_option % packet_ports) with
        | Some (src_port, dst_port) -> Some src_port, Some dst_port
        | None -> None, None in
    let link_scoped =
        match p_opt with
        | Some (V6 ip) -> is_link_scoped ip.src || is_link_scoped ip.dst
        | _ -> false in
    match in_iface_opt, p_opt with
    | Some n, Some (V6 ip) when is_router_solicit ip ->
        router_solicited t n
    | _ ->
    match target_routes ?in_iface:in_iface_opt
                        ?src_ip:src_opt ?dst_ip:dst_opt ?proto:proto_opt
                        ?src_port:src_port_opt ?dst_port:dst_port_opt t with
    | [] ->
        (match in_iface_opt, p_opt with
        | None, _ ->
            Log.(log t.widget.logger Warning (lazy "Cannot route my own packet"))
        | _, None ->
            Log.(log t.widget.logger Debug (lazy "Dropping non-routable non IP packet"))
        | Some _, Some _ when link_scoped ->
            Log.(log t.widget.logger Debug (lazy "No route match that link-scoped packet"))
        | Some n, Some p ->
            Log.(log t.widget.logger Debug (lazy "No route match that packet")) ;
            maybe_send_icmp t n p No_route)
    | targets ->
        (* Forward the packet to that target: *)
        let forward = function
            | Route.Forward { out_iface ; via } ->
                let do_forward bits =
                    Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Forwarding packet to iface %d" out_iface))) ;
                    let iface = t.ifaces.(out_iface) in
                    match maybe_fragment iface bits with
                    | Ok frags ->
                        List.iter (fun bits ->
                            (* So we want to set the gateway for this packet but
                             * cannot call Etc.TRX.tx directly because some
                             * additional processing might be hidden in the TRX
                             * (NAT...) *)
                            let len = Eth.Pdu.header_length + bytelength bits in
                            if buffer_alloc t out_iface len then (
                                iface.eth.via <- via ;
                                (match in_iface_opt, p_opt with
                                | Some n, Some p ->
                                    iface.eth.unresolved <- (fun () ->
                                        maybe_send_icmp t n p Unresolved)
                                | _ ->
                                    iface.eth.unresolved <- ignore) ;
                                tx iface.trx bits
                            )
                        ) frags
                    | Error p ->
                        Log.(log t.widget.logger Debug (lazy "Dropping a packet larger than the MTU")) ;
                        Option.may (fun n ->
                            maybe_send_icmp t n p (Too_big iface.eth.mtu)
                        ) in_iface_opt in
                (match in_iface_opt, ttl_opt, p_opt with
                | None, _, _ ->
                    do_forward bits
                | Some _, _, _ when link_scoped ->
                    Log.(log t.widget.logger Debug (lazy "Not forwarding a link-scoped packet"))
                | Some _, _, Some (V6 ip) when unwelcome t ip ->
                    Log.(log t.widget.logger Debug (lazy "Dropping a packet for its extension headers")) ;
                    Metric.Counter.inc t.extension_dropped
                                       ~now:(Simulation.Widget.now t.widget)
                | Some n, Some (0 | 1), Some p ->
                    Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Expiring packet from %d" n))) ;
                    maybe_send_icmp t n p Expired
                | Some _, _, Some (V4 _) ->
                    do_forward (Ip.Pdu.decr_ttl bits)
                | Some _, _, Some (V6 _) ->
                    do_forward (Ip6.Pdu.decr_hop_limit bits)
                | Some _, _, None ->
                    do_forward bits)
            | Admin ->
                (match in_iface_opt with
                | None ->
                    Log.(log t.widget.logger Error (lazy "Generated traffic to admin!?"))
                | Some in_iface ->
                    (match t.ifaces.(in_iface).admin_host with
                    | None ->
                        Log.(log t.widget.logger Warning (lazy (Printf.sprintf "There is no admin on interface %d, now what?" in_iface)))
                    | Some host ->
                        Log.(log t.widget.logger Debug (lazy "Delivering to the admin host")) ;
                        Host.ip_recv host bits)) in
        let targets =
            List.filter (function
                (* Actually, that's OK if out=in but then the router should
                 * generate also an ICMP redirect (see Stevens section 9.5) *)
                | Route.Forward { out_iface ; _ } ->
                    (match in_iface_opt with
                    | Some n -> n <> out_iface
                    | None -> true)
                | Admin -> true
             ) targets |> Array.of_list in
        let rs_len = Array.length targets in
        if rs_len = 0 then
            Log.(log t.widget.logger Debug (lazy ("Dropping packet with no targets")))
        else match t.load_balancing with
            | First ->
                forward targets.(0)
            | Flow ->
                let h = Hashtbl.hash (src_opt, dst_opt, proto_opt,
                                      src_port_opt, dst_port_opt) in
                forward targets.(h mod rs_len)
            | Random ->
                let n = Random.int rs_len in
                forward targets.(n)
            | RoundRobin ->
                (* The cursor counts packets and is reduced only here, so
                 * that it keeps its place whatever the length of the
                 * choice this packet was offered. *)
                let n = t.lb_cursor mod rs_len in
                t.lb_cursor <- t.lb_cursor + 1 ;
                forward targets.(n)

(* The addresses the routing table gives interface [n]: those its [Admin]
 * routes name it by, since a route to the router itself is how the table
 * says which address is the router's.
 *
 * The CIDR is read as the address and the netmask that goes with it, such
 * as 34.35.36.37/16, and not as the network 34.35.0.0/16. *)
let my_addresses_of routes n =
    List.filter_map (fun (r : Route.t) ->
        match r.dst_mask with
        | Some (addr, _test) ->
            if r.target = Admin &&
               (r.in_iface = None || r.in_iface = Some n) then
                let prefix_len = Ip.Cidr.width addr
                and addr = Ip.Cidr.subnet addr |> Ip.Addr.to_bitstring in
                Some Eth.State.{ addr ; prefix_len }
            else
                None
        | _ -> None
    ) routes

(* Give interface [n] the addresses its routing table names, and the host
 * that answers for them -- or take both away, when the table has stopped
 * naming any.
 *
 * Called whenever the table is set and not only when the router is built,
 * because a router the catalogue builds arrives with an empty table: every
 * address such a router answers for, replies to ARP for and sends its ICMP
 * errors from is one a later [routes] gave it. *)
let configure_iface t n =
    let iface = t.ifaces.(n) in
    let my_addresses =
        my_addresses_of t.routes n |> Eth.State.with_link_local iface.eth.mac in
    let same_addresses =
        List.equal Eth.State.my_address_equal
            my_addresses iface.eth.my_addresses in
    if not same_addresses then (
        iface.eth.my_addresses <- my_addresses ;
        (* The one it had was for the address it no longer has. *)
        Option.may (fun (h : Host.t) ->
            Simulation.remove_widget h.Host.trx.Host.widget
        ) iface.admin_host ;
        iface.admin_host <- None ;
        if my_addresses <> [] then (
            (* Make that interface a host with an IP stack on top of eth: *)
            (* On output, the host will be able to write onto that TRX and that
             * will be output from that iface, properly updating the counters.
             * Unless we want to give a chance for the answer to go through
             * another route (usually safer): *)
            let trx =
                if t.admin_reroute then
                    { ins = sink (route None t) ;
                      out = sink ignore_bits }
                else
                    iface.trx in
            (* On the other way around it's a bit more convoluted: the host
             * takes the reader callback only when set_ip is called, which
             * we don't have to do here. The router is going call the host
             * [ip_recv] function whenever that's the routing decision. *)
            let name = "admin@"^ string_of_int n in
            let widget = Widget.make ~parent:iface.eth.iface.widget name in
            iface.admin_host <-
                (* This host configures nothing at boot, neither
                   statically nor over DHCP: the address it speaks from is
                   the router's own. It has the router's supply, through
                   the router's adapter: one box, one switch. *)
                Some (Host.make_from_eth ~own_ip_config:false ~widget
                                         iface.eth trx name)
        )
    )

let is_connected iface =
    iface.eth.iface.is_connected

let ports iface =
    iface.eth.iface.widget.ports

(* TODO: similarly, a write n b = t.ifaces.(n).trx.write b *)

(* With [v], interface [n] answers ARP requests for the addresses it routes
   out of another interface. IPv4 only: neighbor solicitations are never
   proxied. *)
let set_proxy_arp t n v =
    t.ifaces.(n).eth.do_proxy_arp <-
        if v then
            fun (arp : Arp.Pdu.t) ->
                match Ip.Addr.of_bitstring arp.sender_proto,
                      Ip.Addr.of_bitstring arp.target_proto with
                | src_ip, dst_ip ->
                    let targets =
                        target_routes ~in_iface:n ~src_ip ~dst_ip t in
                    targets <> [] &&
                    not (List.exists (function
                            | Route.Forward { out_iface ; _ } -> out_iface = n
                            | _ -> false
                        ) targets)
        else
            fun _ -> false

let iface_make ?speeds ?mtu ?delay ?loss ?inter_frame_gap
               ?can_forward_after ?mac ?my_addresses ?(link_fragmentation=true)
               ?(max_queue_delay=0.2)
               ?(notify_errs=notify_always ()) ~parent n =
    let name = "#"^ string_of_int n in
    (* For our ifaces we force the GW on a packet by packet basis according
     * to the dynamic (and likely still unset) routing table. *)
    let eth =
        Eth.State.make ?speeds ?mtu ?delay ?loss ?inter_frame_gap
                       ?can_forward_after ?mac ?my_addresses ~name
                       ~parent () in
    eth.groups <- [ Eth.Ndp.all_routers ] ;
    let trx = Eth.TRX.make eth in
    let iface =
        { trx ; eth ; admin_host = None ; link_fragmentation ;
          max_queue_delay ; notify_errs ; advertise = false ;
          router_lifetime = 1800 ; ra_gen = 0 ; ra_pending = false } in
    Widget.add_properties eth.iface.widget Widget.[
        property "link fragmentation" ~kind:Bool
            ~descr:"Fragment IPv4 packets larger than the MTU, unless they \
                    say not to. Those not fragmented are dropped and reported \
                    with ICMP."
            ~getter:(fun () -> `Bool iface.link_fragmentation)
            ~setter:(fun v -> iface.link_fragmentation <- to_bool v) ;
        property "max queue delay" ~kind:Duration ~units:"secs"
            ~descr:"Longest a frame may wait to leave by this interface, at \
                    its negotiated speed. Frames that would wait longer are \
                    dropped."
            ~getter:(fun () -> `Float iface.max_queue_delay)
            ~setter:(fun v -> iface.max_queue_delay <- to_float_range ~min:0. v) ;
        property "errors probability" ~kind:(FRange (0., 1.))
            ~descr:"Probability to report errors about packets received \
                    here with ICMP, times the router's."
            ~getter:(fun () -> `Float iface.notify_errs.probability)
            ~setter:(fun v ->
                iface.notify_errs.probability <-
                    to_float_range ~min:0. ~max:1. v) ;
        property "errors delay" ~kind:Float ~units:"secs"
            ~descr:"Report ICMP errors about packets received here after \
                    that delay, on top of the router's."
            ~getter:(fun () -> `Float iface.notify_errs.delay)
            ~setter:(fun v -> iface.notify_errs.delay <- to_float v) ] ;
    iface

let make ~parent ?(own_power=true) ?(notify_errs=notify_always ())
         ?(admin_reroute=true) ?(load_balancing=First) ?buffer_capacity
         ?can_forward_after ?delay ?loss ?speeds ?mtu ?(macs=[||])
         num_ifaces routes name =
    let widget = Widget.make ~parent ~own_power name in
    (* Display the routing table (debug) *)
    Log.(log widget.logger Debug (lazy
        (Printf.sprintf2 "Creating a router with routing table:%a"
            (List.print ~first:(if routes=[] then "" else "\n\t")
                        ~sep:"\n\t" ~last:"" Route.print) routes))) ;
    (* Check we route only from/to the given ifaces *)
    let max_used_iface =
        List.fold_left (fun prev (r : Route.t) ->
            max prev (
                match r.target with
                | Forward { out_iface ; _ } -> out_iface
                | Admin -> 0
            ) |>
            max (r.in_iface |? 0)
        ) 0 routes in
    if max_used_iface >= num_ifaces then
        Printf.sprintf "Router.make: routing table uses up to iface#%d but router has only %d ifaces" max_used_iface num_ifaces |>
        invalid_arg ;
    let buffered = Metric.Gauge.make () in
    let tail_dropped = Metric.Counter.make () in
    let ifaces =
        Array.init num_ifaces (fun n ->
            let mac =
                (* Caller can set the MAC addresses: *)
                if n >= Array.length macs then None else Some macs.(n) in
            iface_make ?speeds ?delay ?loss ?can_forward_after ?mtu ?mac
                       ~parent:widget n
        ) in
    let t = { ifaces ; routes ; table = Table.make routes ;
              widget ; notify_errs ; admin_reroute ;
              can_forward_after ; load_balancing ; lb_cursor = 0 ;
              buffer_capacity ; buffered ; refresh_pending = false ;
              tail_dropped ; drop_hop_by_hop = false ; drop_srh = false ;
              extension_dropped = Metric.Counter.make () } in
    (* The reserves are taken from the start: *)
    Metric.Gauge.set buffered ~now:(Simulation.Widget.now widget)
                     (buffer_used t) ;
    (* One supply for the whole box, and this is what the router itself
       does when it is cut: what its admin hosts do about it is their own,
       and the supply asks each of them in turn. Every interface is reset,
       including the ones no admin host was built on, which nothing else
       would reach. *)
    widget.power_up <- (fun () ->
        Array.iteri (fun n _ -> start_router_adverts t n) t.ifaces) ;
    widget.power_down <- (fun () ->
        Array.iter (fun iface ->
            Eth.State.reset iface.eth ;
            iface.ra_pending <- false) t.ifaces ;
        (* Powering down cancelled any pending refresh: *)
        t.refresh_pending <- false ;
        let now = Simulation.Widget.now widget in
        Metric.Gauge.set buffered ~now (buffer_used t)) ;
    widget.device_type <- Some "router" ;
    widget.device <- Some (T t) ;
    widget.ports <- Widget.{
        count = (fun () -> Array.length t.ifaces) ;
        is_connected = (fun n -> (ports t.ifaces.(n)).is_connected 0) ;
        dev = (fun n -> (ports t.ifaces.(n)).dev 0) ;
        owner = (fun n -> (ports t.ifaces.(n)).owner 0) ;
        disconnect = (fun n -> (ports t.ifaces.(n)).disconnect 0) ;
        get_capabilities = (fun ?peer n ->
            (ports t.ifaces.(n)).get_capabilities ?peer 0) ;
        set_capabilities = (fun n c ->
            (ports t.ifaces.(n)).set_capabilities 0 c) } ;
    Widget.add_properties widget Widget.[
        property "errors probability" ~kind:(FRange (0., 1.))
            ~descr:"Probability to report errors with ICMP."
            ~getter:(fun () -> `Float t.notify_errs.probability)
            ~setter:(fun v ->
                t.notify_errs.probability <- to_float_range ~min:0. ~max:1. v) ;
        property "errors delay" ~kind:Float ~units:"secs"
            ~descr:"Report ICMP errors after that delay."
            ~getter:(fun () -> `Float t.notify_errs.delay)
            ~setter:(fun v -> t.notify_errs.delay <- to_float v) ;
        property "routes" ~kind:(list (Route.kind num_ifaces))
            ~descr:"The routing table"
            ~getter:(fun () ->
                `List (
                    List.map (fun (r : Route.t) ->
                        let of_port_range (mi, ma) =
                            `String (Printf.sprintf "%d-%d" mi ma) in
                        `Assoc [
                            "input port", json_of_optional (fun i -> `Int i) r.in_iface ;
                            "src mask", json_of_optional (fun (c, _) -> `String (Ip.Cidr.to_string c)) r.src_mask ;
                            "dst mask", json_of_optional (fun (c, _) -> `String (Ip.Cidr.to_string c)) r.dst_mask ;
                            "ip proto", json_of_optional (fun (p : Ip.Proto.t) -> `Int (p :> int)) r.ip_proto ;
                            "src port", json_of_optional of_port_range r.src_port ;
                            "dst port", json_of_optional of_port_range r.dst_port ;
                            "output port",
                                (match r.target with Admin -> `Null
                                | Forward { out_iface ; _ } -> `Int out_iface) ;
                            "via",
                                (match r.target with
                                | Forward { via = Some v ; _ } ->
                                    Eth.Gateway.to_json v
                                | _ -> `Null) ]
                    ) t.routes))
            ~setter:(fun v ->
                (* The whole table, read before any of it is installed: a
                   table with one bad row leaves the old one alone rather
                   than a half-replaced one behind. The order is the order
                   the rows arrive in, which is the order they are tried
                   in -- so moving a row up the table in the interface is
                   what gives it priority. *)
                t.routes <-
                    to_list (fun row ->
                        (* A field typed into. Blank is a field nobody
                           filled in, which reads as one left out: an empty
                           test is no test. Read through [to_field] rather
                           than after it, so that whatever [f] refuses is
                           refused under this field's name. *)
                        let text what f =
                            to_field what (function
                                | `Null -> None
                                | v ->
                                    let s = String.trim (to_string v) in
                                    if s = "" then None else Some (f s)
                            ) row in
                        let num what f = to_field what (to_option f) row in
                        let iface what =
                            num what (to_int_range ~min:0
                                                   ~max:(num_ifaces - 1)) in
                        let cidr s =
                            match Ip.Cidr.of_string s with
                            | exception _ ->
                                bad_value "%S is not a network \
                                           (address/width)" s
                            | cidr -> cidr, Ip.Cidr.mem cidr in
                        let gateway = Eth.Gateway.of_typed in
                        let in_iface = iface "input port"
                        and src_mask = text "src mask" cidr
                        and dst_mask = text "dst mask" cidr
                        and ip_proto =
                            num "ip proto" (fun v ->
                                Ip.Proto.o (to_int_range ~min:0 ~max:255 v))
                        and src_port = text "src port" Route.port_range_of_string
                        and dst_port = text "dst port" Route.port_range_of_string
                        and out_iface = iface "output port"
                        and via = text "via" gateway in
                        (* No way out is not a route that goes nowhere: it
                           is a route to the router itself, which is what
                           [Admin] is. The gateway goes with the way out,
                           so with no way out there is nothing for it to
                           qualify and it is dropped -- the getter will say
                           so on the next read. *)
                        let target =
                            match out_iface with
                            | None -> Route.Admin
                            | Some out_iface -> Route.Forward { out_iface ; via } in
                        Route.{ in_iface ; src_mask ; dst_mask ; ip_proto ;
                                src_port ; dst_port ; target }
                    ) v ;
                (* Which address is the router's is part of what the table
                   says, so the interfaces are told again. *)
                Array.iteri (fun n _ -> configure_iface t n) t.ifaces) ;
        property "cut-through bytes" ~kind:(Optional (IRange (6, 256)))
            ~descr:"If the router can forward a frame while still receiving it,
                    how many bytes of the header does it need to read."
            ~getter:(fun () ->
                json_of_optional (fun i -> `Int i) t.can_forward_after)
            ~setter:(fun v ->
                t.can_forward_after <-
                    to_option (to_int_range ~min:6 ~max:256) v ;
                (* Propagate to all individual eth adapters: *)
                Array.iter (fun iface ->
                    iface.eth.iface.can_forward_after <- t.can_forward_after
                ) t.ifaces) ;
        property "load balancing"
            ~kind:(one_of (choices all_load_balancing))
            ~descr:"Load balancing between matching routes."
            ~getter:(fun () -> `Int (load_balancing_to_enum t.load_balancing))
            ~setter:(fun v ->
                match load_balancing_of_enum (to_int v) with
                | None -> bad_value "Invalid enum for load_balancing: %s"
                            (Yojson.Basic.to_string v)
                | Some lb -> t.load_balancing <- lb) ;
        property "reroute admin" ~kind:Bool
            ~descr:"Answers from the admin interface go through routing \
                    instead of returning via the same interface it came from."
            ~getter:(fun () -> `Bool t.admin_reroute)
            ~setter:(fun v -> t.admin_reroute <- to_bool v) ;
        property "buffer capacity" ~kind:(optional Int) ~units:"bytes"
            ~descr:"RAM to queue frames waiting to be emitted, a third of \
                    which is reserved to the ports in equal parts while the \
                    rest is shared. Unset, just enough for every port to \
                    fill its max queue delay at once."
            ~getter:(fun () ->
                match t.buffer_capacity with None -> `Null | Some c -> `Int c)
            ~setter:(fun v ->
                t.buffer_capacity <- to_option (to_int_range ~min:0) v ;
                (* Extremes seen with other reserves would mislead: *)
                Metric.Gauge.reset t.buffered ;
                let now = Simulation.Widget.now widget in
                Metric.Gauge.set t.buffered ~now (buffer_used t)) ;
        property "actual buffer capacity" ~kind:Int ~units:"bytes"
            ~descr:"The buffer capacity, or what it is worked out to be \
                    from the links when unset."
            ~getter:(fun () -> `Int (actual_buffer_capacity t)) ;
        metric_property "buffered" ~units:"bytes"
            ~descr:"RAM taken by the queued frames and the ports' reserves."
            (Metric.Gauge.T t.buffered) ;
        metric_property "tail-dropped"
            ~descr:"Number of frames dropped due to memory constraints."
            (Metric.Counter.T t.tail_dropped) ;
        property "drop hop-by-hop" ~kind:Bool
            ~descr:"Drop the IPv6 packets to forward that have a hop-by-hop \
                    options header, rather than forward them unchanged."
            ~getter:(fun () -> `Bool t.drop_hop_by_hop)
            ~setter:(fun v -> t.drop_hop_by_hop <- to_bool v) ;
        property "drop segment routing" ~kind:Bool
            ~descr:"Drop the IPv6 packets to forward that have a segment \
                    routing header, rather than forward them unchanged."
            ~getter:(fun () -> `Bool t.drop_srh)
            ~setter:(fun v -> t.drop_srh <- to_bool v) ;
        metric_property "extension-dropped"
            ~descr:"Number of IPv6 packets dropped for their extension headers."
            (Metric.Counter.T t.extension_dropped) ;
        property "tot ports" ~kind:Int ~descr:"Total number of ports."
            ~getter:(fun () -> `Int num_ifaces) ] ;
    let addressed () =
        Array.exists (fun iface -> iface.eth.my_addresses <> []) t.ifaces in
    Widget.add_actions widget Widget.[
        action "announce addresses"
            ~descr:"Announce the router's addresses on every port that \
                    has one."
            ~can_run:(fun () -> widget.power.on && addressed ())
            ~handler:(fun s ->
                Array.iter (fun iface ->
                    Eth.State.announce iface.eth) t.ifaces ;
                Action.stop s) ] ;
    Array.iteri (fun n iface ->
        Widget.add_properties iface.eth.iface.widget Widget.[
            property "router advertisements" ~kind:Bool
                ~descr:"Advertise the IPv6 prefixes on this interface's link, \
                        for hosts to configure themselves with SLAAC and \
                        route through this one."
                ~getter:(fun () -> `Bool iface.advertise)
                ~setter:(fun v ->
                    iface.advertise <- to_bool v ;
                    start_router_adverts t n) ;
            property "router lifetime" ~kind:(IRange (0, 9000)) ~units:"secs"
                ~descr:"How long hosts may route through this one after an \
                        advertisement; 0 is not to be used as a default \
                        router."
                ~getter:(fun () -> `Int iface.router_lifetime)
                ~setter:(fun v ->
                    iface.router_lifetime <- to_int_range ~min:0 ~max:9000 v) ] ;
        configure_iface t n ;
        (* When packets are received from the outside, go to routing: *)
        iface.trx.ins --> sink (route (Some n) t)
    ) t.ifaces ;
    t

(* Assuming the networks are reachable from different ifaces of a switch,
 * output a trivial routing table that selects the output according to the
 * destination IP only. A network reached without a gateway and written with
 * host bits set, such as 10.0.0.1/24, has that address as the router's
 * own on that iface. *)
let routes_of_addrs addrs =
    let is_my_address cidr via =
        via = None &&
        Ip.Addr.compare (Ip.Cidr.zero_addr cidr) (Ip.Cidr.subnet cidr) <> 0 in
    Array.fold_lefti (fun tbl i (nets, _) ->
        List.fold_left (fun tbl (cidr, via) ->
            let dst_mask =
                Ip.Cidr.o (Ip.Cidr.zero_addr cidr, Ip.Cidr.width cidr) in
            let tbl = Route.forward ~dst_mask ?via i :: tbl in
            if is_my_address cidr via then
                Route.admin ~in_iface:i (Ip.Cidr.subnet cidr) :: tbl
            else tbl
        ) tbl nets
    ) [] addrs |>
    List.rev
(*$= routes_of_addrs & ~printer:string_of_int
  2 (List.length (routes_of_addrs \
        [| [ Ip.Cidr.of_string "10.0.0.1/24", None ], Eth.Addr.random () |]))
  1 (List.length (routes_of_addrs \
        [| [ Ip.Cidr.of_string "10.0.0.0/24", None ], Eth.Addr.random () |]))
  4 (List.length (routes_of_addrs \
        [| [ Ip.Cidr.of_string "10.0.0.1/24", None ; \
             Ip.Cidr.of_string "2001:db8::1/64", None ], Eth.Addr.random () |]))
 *)

(* [addrs] is an array (one entry for each iface of the router) of the
 * networks reachable via this iface, each with an optional gateway, and the
 * MAC address of the router on that iface. *)
let make_from_addrs
        ~parent ?notify_errs ?admin_reroute ?load_balancing ?delay ?loss
        addrs name =
    let routes = routes_of_addrs addrs in
    let num_ifaces = Array.length addrs in
    let macs = Array.map snd addrs in
    make ~parent ?notify_errs ?admin_reroute ?load_balancing ?delay ?loss ~macs
         num_ifaces routes name

(*$R make_from_addrs
    (* Suppose we have a router for these 3 networks: *)
    let addrs =
        [| [ Ip.Cidr.of_string "192.168.1.254/24", None ], Eth.Addr.random () ;
           [ Ip.Cidr.of_string "192.168.2.254/24", None ], Eth.Addr.random () ;
           [ Ip.Cidr.of_string "192.168.3.254/24", None ], Eth.Addr.random () |] in
    let sim = Simulation.make ~realtime:false "test-router" in
    let router = make_from_addrs ~parent:sim.root addrs "test" in

    (* Now we will count incoming packets from each iface (ARP requests, actually,
     * none of them answered) : *)
    let counts = Array.create 3 0 in
    for i = 0 to Array.length counts - 1 do
        router.ifaces.(i).trx =-> sink (fun _ -> counts.(i) <- succ counts.(i))
    done ;
    let reset_count () = Array.iteri (fun i _ -> counts.(i) <- 0) counts in

    (* Frames are not written into an interface then and there: [run]
     * returns as soon as the queue is empty, which is while the previous
     * frame is still going out, and a half duplex port that is
     * transmitting takes nothing in (as would a real one: whoever sent
     * this would have sensed the carrier and waited). A millisecond
     * later every wire is quiet again. *)
    let send n bits =
        Simulation.delay sim.root.power (Clock.Interval.msec 1.)
                         router.ifaces.(n).trx.out.write bits in

    (* We are going to send some IP packets with a given destination: *)
    let easy_send n dst =
        Ip.Pdu.{ (random ()) with dst = Ip.Addr.of_string dst ; ttl = 9 } |>
        Ip.Pdu.pack |>
        Eth.Pdu.make Arp.HwProto.ip4 (Eth.Addr.random ()) (snd addrs.(n)) |>
        Eth.Pdu.pack |>
        send n in

    (* Let's play! *)
    easy_send 0 "1.2.3.4" ;
    easy_send 1 "1.2.3.4" ;
    Simulation.run sim false ;
    "no match means dropped" @? (counts = [| 0;0;0 |]) ;

    reset_count () ;
    easy_send 0 "192.168.3.42" ;
    Simulation.run sim false ;
    let n = Eth.TRX.max_solicits in
    "route from 0 to 2" @? (counts = [| 0;0;n |]) ;

    reset_count () ;
    easy_send 2 "192.168.2.42" ;
    Simulation.run sim false ;
    "route from 2 to 1" @? (counts = [| 0;n;0 |]) ;

    reset_count () ;
    easy_send 0 "192.168.1.42" ;
    Simulation.run sim false ;
    "no revert" @? (counts = [| 0;0;0 |]) ;

    (* One box, one supply, one switch. This router has three admin hosts,
     * one per addressed interface, and all of them draw on the router's,
     * which is what puts the switch on the router and nowhere else. *)
    "the router owns the supply" @? router.widget.owns_power ;
    "and its admin hosts draw on that one" @?
        Array.for_all (fun iface ->
            match iface.admin_host with
            | None -> false
            | Some h ->
                let w = h.Host.trx.Host.widget in
                not w.owns_power &&
                w.power == router.widget.power
        ) router.ifaces ;

    (* A packet for the router itself goes to that interface's admin host,
     * which remembers the peer it came from -- state that must not survive
     * the box being switched off.
     *
     * Every interface is given one, and every one of them is counted: they
     * share the box's supply, so whatever switching the box off does to
     * them it has to do to all of them, and a check on the first alone
     * passes just as well when only the first is reached. *)
    let admin_socks () =
        Array.fold_left (fun n iface ->
            match iface.admin_host with
            | None -> n
            | Some h -> n + Hashtbl.length h.Host.sockets
        ) 0 router.ifaces in
    let port = Udp.Port.o 9 in
    Array.iter (fun iface ->
        Option.may (fun (h : Host.t) -> h.trx.udp_server_start port ignore)
                   iface.admin_host
    ) router.ifaces ;
    let poke n =
        Udp.Pdu.make ~src_port:port ~dst_port:port (Bitstring.zeroes_bitstring 64) |>
        Udp.Pdu.pack |>
        Ip.Pdu.make Ip.Proto.udp (Ip.Addr.of_string "10.0.0.1")
                    (Ip.Addr.of_string (Printf.sprintf "192.168.%d.254" (n + 1))) |>
        Ip.Pdu.pack |>
        Eth.Pdu.make Arp.HwProto.ip4 (Eth.Addr.random ()) (snd addrs.(n)) |>
        Eth.Pdu.pack |>
        send n in
    poke 0 ; poke 1 ; poke 2 ;
    Simulation.run sim false ;
    "every admin host answers for its interface's own address" @?
        (admin_socks () = 3) ;

    let flip on =
        (if on then Simulation.power_up else Simulation.power_down)
            router.widget.power in

    (* Switched off, the box stops routing: what it had scheduled went with
     * its power, and it takes on nothing new. *)
    flip false ;
    reset_count () ;
    easy_send 0 "192.168.3.42" ;
    Simulation.run sim false ;
    "an off router routes nothing" @? (counts = [| 0;0;0 |]) ;
    "and forgets what its admin hosts knew" @? (admin_socks () = 0) ;

    flip true ;
    reset_count () ;
    easy_send 0 "192.168.3.42" ;
    Simulation.run sim false ;
    "and routes again once switched back on" @? (counts = [| 0;0;n |]) ;

    (* An expiring packet is reported back the way it came, which here
     * starts with an ARP request for its sender; a new sender each time,
     * so that each report asks again. *)
    let expire src =
        Ip.Pdu.{ (random ()) with src = Ip.Addr.of_string src ;
                                  dst = Ip.Addr.of_string "192.168.3.42" ;
                                  ttl = 1 } |>
        Ip.Pdu.pack |>
        Eth.Pdu.make Arp.HwProto.ip4 (Eth.Addr.random ()) (snd addrs.(0)) |>
        Eth.Pdu.pack |>
        send 0 in
    reset_count () ;
    expire "192.168.1.43" ;
    Simulation.run sim false ;
    "expiry is reported" @? (counts = [| n;0;0 |]) ;

    router.ifaces.(2).notify_errs.probability <- 0. ;
    reset_count () ;
    expire "192.168.1.44" ;
    Simulation.run sim false ;
    "as the receiving port allows, not the leaving one" @?
        (counts = [| n;0;0 |]) ;

    router.ifaces.(0).notify_errs.probability <- 0. ;
    reset_count () ;
    expire "192.168.1.45" ;
    Simulation.run sim false ;
    "a port can be silenced alone" @? (counts = [| 0;0;0 |]) ;
*)

(* IPv6 is forwarded with its hop limit one less, and never fragmented; what
 * cannot be forwarded is reported with ICMPv6, from the receiving port's
 * address. Link-scoped packets stay on their link, and the unwelcome
 * extension headers can be dropped. *)
(*$R make_from_addrs
    let a = Ip.Addr.of_string in
    let macs = [| Eth.Addr.random () ; Eth.Addr.random () |] in
    let addrs = [| [ Ip.Cidr.of_string "2001:db8:1::fe/64", None ], macs.(0) ;
                   [ Ip.Cidr.of_string "2001:db8:2::fe/64", None ], macs.(1) |] in
    let sim = Simulation.make ~realtime:false "router-v6" in
    let r = make_from_addrs ~parent:sim.root addrs "r" in
    Simulation.run_startup sim ;
    let src = a "2001:db8:1::1" and dst = a "2001:db8:2::1" in
    Eth.State.set_neighbor r.ifaces.(0).eth (Ip.Addr.to_bitstring src)
                           (Some (Eth.Addr.random ())) ;
    Eth.State.set_neighbor r.ifaces.(1).eth (Ip.Addr.to_bitstring dst)
                           (Some (Eth.Addr.random ())) ;
    let out = Array.make 2 [] in
    Array.iteri (fun i iface ->
        iface.trx =-> sink (fun bits ->
            match Eth.Pdu.unpack bits with
            | Error _ -> ()
            | Ok eth ->
                match Ip6.Pdu.unpack (eth.payload :> bitstring) with
                | Ok ip -> out.(i) <- ip :: out.(i)
                | Error _ -> ())) r.ifaces ;
    let send ?(ttl=9) ?(extensions=[]) ?(len=8) ?(src=src) dst =
        Array.fill out 0 2 [] ;
        Ip6.Pdu.make ~ttl ~extensions Ip.Proto.udp src dst
                     (Bitstring.zeroes_bitstring (len * 8)) |>
        Ip6.Pdu.pack |>
        Eth.Pdu.make Arp.HwProto.ip6 (Eth.Addr.random ()) macs.(0) |>
        Eth.Pdu.pack |>
        Simulation.delay sim.root.power (Clock.Interval.msec 1.)
                         r.ifaces.(0).trx.out.write ;
        Simulation.run sim false in
    let forwarded () =
        match out with
        | [| [] ; [ ip ] |] -> Some ip.Ip6.Pdu.ttl
        | _ -> None in
    (* The type, code and parameter of the one error sent back: *)
    let error () =
        match out with
        | [| [ ip ] ; [] |] ->
            assert_equal ~printer:Ip.Addr.to_string (a "2001:db8:1::fe") ip.src ;
            (match Icmp6.Pdu.unpack (ip.payload :> bitstring) with
            | Ok { msg_type ; payload = Err { param ; _ } } ->
                Some Icmp6.MsgType.(type_of msg_type, code_of msg_type, param)
            | _ -> None)
        | _ -> None in
    let nothing () = out = [| [] ; [] |] in
    send dst ;
    assert_equal (Some 8) (forwarded ()) ;
    send ~ttl:1 dst ;
    assert_equal (Some (3, 0, 0)) (error ()) ;
    send (a "2001:db8:3::1") ;
    assert_equal (Some (1, 0, 0)) (error ()) ;
    send ~len:1500 dst ;
    assert_equal (Some (2, 0, 1500)) (error ()) ;
    (* Solicited in vain on the far side, then reported: *)
    send (a "2001:db8:2::9") ;
    out.(1) <- [] ;
    assert_equal (Some (1, 3, 0)) (error ()) ;
    send (a "ff02::1") ;
    "link-scoped destination" @? nothing () ;
    send ~src:(a "fe80::1") dst ;
    "link-scoped source" @? nothing () ;
    let hbh = [ Ip6.Extension.(pad (Hop_by_hop [])) ]
    and srh = [ Ip6.Extension.(pad (Routing (Routing.Srh {
                    segments_left = 1 ; flags = 0 ; tag = 0 ;
                    segments = [ a "2001:db8:2::2" ; dst ] ; tlvs = [] }))) ] in
    send ~extensions:hbh dst ;
    assert_equal (Some 8) (forwarded ()) ;
    send ~extensions:srh dst ;
    assert_equal (Some 8) (forwarded ()) ;
    r.drop_hop_by_hop <- true ;
    send ~extensions:hbh dst ;
    "hop-by-hop dropped" @? nothing () ;
    send ~extensions:srh dst ;
    assert_equal (Some 8) (forwarded ()) ;
    r.drop_srh <- true ;
    send ~extensions:srh dst ;
    "segment routing dropped" @? nothing () ;
    assert_equal ~printer:string_of_int 2 (Metric.Counter.get r.extension_dropped)
 *)

(* Dual-stack hosts on two subnets talk through a dual-stack router, which
 * answers for its address on their side. *)
(*$R make_from_addrs
    let a = Ip.Addr.of_string and c = Ip.Cidr.of_string in
    let sim = Simulation.make ~realtime:false "router-dual-stack" in
    let r =
        make_from_addrs ~parent:sim.root
            [| [ c "10.0.1.254/24", None ; c "2001:db8:1::fe/64", None ],
               Eth.Addr.random () ;
               [ c "10.0.2.254/24", None ; c "2001:db8:2::fe/64", None ],
               Eth.Addr.random () |] "r" in
    let host n =
        let gateways =
            [ Eth.State.gw_selector (),
              Some (Eth.Gateway.Ip (a (Printf.sprintf "10.0.%d.254" n))) ;
              Eth.State.gw_selector ~v6:true (),
              Some (Eth.Gateway.Ip (a (Printf.sprintf "2001:db8:%d::fe" n))) ] in
        let h =
            Host.make ~parent:sim.root ~gateways
                ~static_ip:(a (Printf.sprintf "10.0.%d.1" n))
                ~netmask:(a "255.255.255.0")
                ~addresses:[ c (Printf.sprintf "2001:db8:%d::1/64" n) ]
                ("h" ^ string_of_int n) in
        let st = Eth.Cable.State.make ~parent:sim.root
                                      ~name:("c" ^ string_of_int n) () in
        Eth.Cable.plug st (h.trx.widget, 0) (r.widget, n - 1) ;
        h in
    let h1 = host 1 and h2 = host 2 in
    Simulation.run_startup sim ;
    let port = Tcp.Port.o 7 in
    h2.trx.tcp_server_start port (fun (cnx : Tcp.TRX.tcp_trx) ->
        cnx.trx.ins --> sink (fun bits ->
            if Bitstring.bitstring_length bits > 0 then tx cnx.trx bits)) ;
    let echoed dst =
        let got = ref 0 in
        h1.trx.tcp_connect (Host.Ip (a dst)) port (function
            | None -> ()
            | Some (cnx : Tcp.TRX.tcp_trx) ->
                cnx.trx.ins --> sink (fun bits ->
                    got := !got + Bitstring.bitstring_length bits / 8) ;
                tx cnx.trx (Bitstring.zeroes_bitstring (3000 * 8))) ;
        Simulation.run sim false ;
        !got in
    assert_equal ~printer:string_of_int 3000 (echoed "2001:db8:2::1") ;
    assert_equal ~printer:string_of_int 3000 (echoed "10.0.2.1") ;
    let replies = ref [] in
    Hashtbl.add h1.echo_waiters 7 (fun seq -> replies := seq :: !replies) ;
    h1.trx.ping ~id:7 ~seq:1 (Host.Ip (a "2001:db8:1::fe")) ;
    h1.trx.ping ~id:7 ~seq:2 (Host.Ip (a "2001:db8:2::1")) ;
    Simulation.run sim false ;
    assert_equal ~printer:(IO.to_string (List.print Int.print))
        [ 1 ; 2 ] (List.sort Int.compare !replies)
 *)

(* Hosts with SLAAC take an address in the prefix of the interface they are
 * on and route through it, once it advertises; the others keep to their
 * link-local address. *)
(*$R make
    let a = Ip.Addr.of_string and c = Ip.Cidr.of_string in
    let sim = Simulation.make ~realtime:false "router-slaac" in
    let r =
        make_from_addrs ~parent:sim.root
            [| [ c "2001:db8:1::fe/64", None ], Eth.Addr.random () ;
               [ c "2001:db8:2::fe/64", None ], Eth.Addr.random () |] "r" in
    let host n mac =
        let h = Host.make ~parent:sim.root ~slaac:true ~mac:(Eth.Addr.of_string mac)
                          ("h" ^ string_of_int n) in
        let st = Eth.Cable.State.make ~parent:sim.root
                                      ~name:("c" ^ string_of_int n) () in
        Eth.Cable.plug st (h.trx.widget, 0) (r.widget, n - 1) ;
        h in
    let h1 = host 1 "02:00:00:00:00:01" and h2 = host 2 "02:00:00:00:00:02" in
    let advertise b = Array.iter (fun i -> i.advertise <- b) r.ifaces in
    let autoconf (h : Host.t) =
        List.map (fun m -> Printf.sprintf2 "%a" Eth.State.print_my_address m)
                 h.autoconf |> String.concat ", " in
    advertise true ;
    r.ifaces.(0).eth.mtu <- 1400 ;
    Simulation.run sim false ;
    assert_equal ~printer:identity
        "fe80::ff:fe00:1/64, 2001:db8:1::ff:fe00:1/64" (autoconf h1) ;
    assert_equal ~printer:identity
        "fe80::ff:fe00:2/64, 2001:db8:2::ff:fe00:2/64" (autoconf h2) ;
    (* The advertised MTU sizes IPv6 only: *)
    assert_equal ~printer:string_of_int 1340
        (Host.tcp_mss h1 (a "2001:db8:1::ff:fe00:1")) ;
    assert_equal ~printer:string_of_int 1460 (Host.tcp_mss h1 (a "10.0.0.1")) ;
    assert_equal ~printer:string_of_int 1440
        (Host.tcp_mss h2 (a "2001:db8:2::ff:fe00:2")) ;
    let replies = ref [] in
    Hashtbl.add h1.echo_waiters 7 (fun seq -> replies := seq :: !replies) ;
    h1.trx.ping ~id:7 ~seq:1 (Host.Ip (a "2001:db8:2::ff:fe00:2")) ;
    Simulation.run sim false ;
    assert_equal ~printer:(IO.to_string (List.print Int.print))
        ~msg:"routed through the advertised router" [ 1 ] !replies ;
    (* Rebooted, h1 solicits an advertisement, which has to be answered as
     * the initial ones are over: *)
    Simulation.power_down h1.trx.widget.power ;
    Simulation.power_up h1.trx.widget.power ;
    Simulation.run sim false ;
    assert_equal ~printer:identity
        "fe80::ff:fe00:1/64, 2001:db8:1::ff:fe00:1/64" (autoconf h1) ;
    (* Periodic advertisements renew the default route beyond its lifetime,
     * which runs out between two of them when shorter: *)
    let at secs f = Simulation.delay sim.root.power (Clock.Interval.sec secs) f () in
    let seen = ref [] in
    let see () = seen := (h1.eth_state.gateways <> []) :: !seen in
    at 2000. see ;
    Simulation.run sim false ;
    r.ifaces.(0).router_lifetime <- 10 ;
    start_router_adverts r 0 ;
    at 5. see ;
    at 14. see ;
    Simulation.run sim false ;
    assert_equal ~printer:(IO.to_string (List.print Bool.print))
        [ true ; true ; false ] (List.rev !seen) ;
    r.ifaces.(0).router_lifetime <- 1800 ;
    (* Without advertisements, or without SLAAC, the link-local only: *)
    let reboot () =
        Simulation.power_down h1.trx.widget.power ;
        Simulation.power_up h1.trx.widget.power ;
        Simulation.run sim false in
    advertise false ;
    reboot () ;
    assert_equal ~printer:identity "fe80::ff:fe00:1/64" (autoconf h1) ;
    advertise true ;
    h1.slaac <- false ;
    h1.addresses <- [ c "2001:db8:1::1/64" ] ;
    reboot () ;
    assert_equal ~printer:identity "fe80::ff:fe00:1/64" (autoconf h1) ;
    assert_bool "no default route" (h1.eth_state.gateways = [])
 *)

(* An interface with no address of its own gets no admin host, so nothing
 * else would clear what its adapter learnt when the box is switched off. *)
(*$R make
    let sim = Simulation.make ~realtime:false "router-off" in
    let r = make ~parent:sim.root 2 [] "r" in
    let eth = r.ifaces.(0).eth in
    "an interface with no address has no admin host" @?
        (r.ifaces.(0).admin_host = None) ;
    "a router of its own mints the supply it draws on" @?
        r.widget.owns_power ;
    let flip on =
        (if on then Simulation.power_up else Simulation.power_down)
            r.widget.power in
    (* Born dark, as every box is, and a supply that is already off is not
       switched off again: there is something to forget only once the box
       has been switched on. *)
    flip true ;
    Eth.State.set_neighbor eth
        (Ip.Addr.to_bitstring (Ip.Addr.of_dotted_string "1.2.3.4"))
        (Some (Eth.Addr.random ())) ;
    "and its adapter still learns" @?
        (Tools.BitHash.length eth.Eth.State.neighbors = 1) ;
    flip false ;
    "which the box forgets when it is switched off" @?
        (Tools.BitHash.length eth.Eth.State.neighbors = 0) ;
    flip true ;
    (* Deleting it takes its future with it, which is what stops a deleted
       thing for good. Not its destructor's doing: what a widget holds of
       its own is one thing, and what it has scheduled is another. *)
    Simulation.delay r.widget.power (Clock.Interval.sec 1.) ignore () ;
    Simulation.remove_widget r.widget ;
    "a deleted router has nothing left scheduled" @?
        (Events.for_all (fun (p, _, _) -> p != r.widget.power) sim.events) ;
    "and out of the tree" @?
        (Widget.find sim.root r.widget.id = None)
 *)

(* Two ports receiving at line rate and forwarding to a third of the same
   speed fill its queue twice as fast as it drains: the router queues what it
   has room for, drops the rest, and has its RAM back once the queue is
   empty. *)
(*$R buffer_alloc
    ignore buffer_alloc ;
    let sim = Simulation.make ~realtime:false "router-congestion" in
    let via = Some (Eth.Gateway.Mac (Eth.Addr.random ())) in
    let routes = [ Route.make (Forward { out_iface = 2 ; via }) ] in
    let r = make ~parent:sim.root ~speeds:[ EthSpeed.Eth10Mbps ]
                 ~buffer_capacity:30_000 3 routes "r" in
    Simulation.power_up r.widget.power ;
    Array.iter (fun iface ->
        (ports iface).set_capabilities 0 Capabilities.Any) r.ifaces ;
    let emitted = ref 0 in
    r.ifaces.(2).trx =-> sink (fun _ -> incr emitted) ;
    let num_sent = 100 in
    let frame n =
        Ip.Pdu.make Ip.Proto.udp (Ip.Addr.of_string "10.0.0.1")
                    (Ip.Addr.of_string "10.0.1.1")
                    (Bitstring.create_bitstring (1000 * 8)) |>
        Ip.Pdu.pack |>
        Eth.Pdu.make Arp.HwProto.ip4 (Eth.Addr.random ())
                     r.ifaces.(n).eth.Eth.State.mac |>
        Eth.Pdu.pack in
    for i = 1 to num_sent do
        List.iter (fun n ->
            Simulation.delay sim.root.power
                (Clock.Interval.msec (float_of_int i))
                r.ifaces.(n).trx.out.write (frame n)
        ) [ 0 ; 1 ]
    done ;
    Simulation.run sim false ;
    let dropped =
        Metric.Counter.get r.tail_dropped
            ~params:(Metric.dir_params ~port:2 "tail-dropped") in
    "some frames are dropped" @? (dropped > 0) ;
    assert_equal ~msg:"the others are emitted" ~printer:string_of_int
                 (2 * num_sent) (!emitted + dropped) ;
    let all_reserved = 3 * ((30_000 / 3) / 3) in
    let buffered = Metric.Gauge.get r.buffered in
    "the shared pool was used" @? (buffered.max > all_reserved) ;
    "but no more than there is" @? (buffered.max <= 30_000) ;
    assert_equal ~msg:"and given back once drained" ~printer:string_of_int
                 all_reserved buffered.current ;
    (* The capacity is a property, and the reserves follow it: *)
    let p = List.find (fun (p : Widget.property) ->
                p.name = "buffer capacity") r.widget.properties in
    (Option.get p.setter) (`String "60000") ;
    assert_equal ~msg:"the reserves follow the capacity"
                 ~printer:string_of_int
                 (3 * ((60_000 / 3) / 3)) (Metric.Gauge.get r.buffered).current ;
    "and a negative capacity is refused" @?
        (try (Option.get p.setter) (`Int (-1)) ; false
         with _ -> true)
 *)

(* Unset, the capacity is what every port needs to queue its max queue delay
   at its negotiated speed, and no port queues more than that, however much
   RAM is left. *)
(*$R max_backlog
    ignore max_backlog ;
    let sim = Simulation.make ~realtime:false "router-queue-delay" in
    let via = Some (Eth.Gateway.Mac (Eth.Addr.random ())) in
    let routes = [ Route.make (Forward { out_iface = 2 ; via }) ] in
    let r = make ~parent:sim.root
                 ~speeds:EthSpeed.[ Eth10Mbps ; Eth100Mbps ] 3 routes "r" in
    Simulation.power_up r.widget.power ;
    assert_equal ~msg:"no link, no buffer" ~printer:string_of_int
                 0 (actual_buffer_capacity r) ;
    let slow = Capabilities.(Eth { speeds = [ EthSpeed.Eth10Mbps ] ;
                                   full_duplex = true }) in
    (ports r.ifaces.(0)).set_capabilities 0 Capabilities.Any ;
    (ports r.ifaces.(1)).set_capabilities 0 Capabilities.Any ;
    (ports r.ifaces.(2)).set_capabilities 0 slow ;
    assert_equal ~msg:"200ms of each negotiated speed" ~printer:string_of_int
                 (2_500_000 + 2_500_000 + 250_000) (actual_buffer_capacity r) ;
    let emitted = ref 0 in
    r.ifaces.(2).trx =-> sink (fun _ -> incr emitted) ;
    let send_all () =
        let num_sent = 100 in
        let frame n =
            Ip.Pdu.make Ip.Proto.udp (Ip.Addr.of_string "10.0.0.1")
                        (Ip.Addr.of_string "10.0.1.1")
                        (Bitstring.create_bitstring (1000 * 8)) |>
            Ip.Pdu.pack |>
            Eth.Pdu.make Arp.HwProto.ip4 (Eth.Addr.random ())
                         r.ifaces.(n).eth.Eth.State.mac |>
            Eth.Pdu.pack in
        for i = 1 to num_sent do
            List.iter (fun n ->
                Simulation.delay sim.root.power
                    (Clock.Interval.msec (float_of_int i))
                    r.ifaces.(n).trx.out.write (frame n)
            ) [ 0 ; 1 ]
        done ;
        Simulation.run sim false ;
        Metric.Counter.get r.tail_dropped
            ~params:(Metric.dir_params ~port:2 "tail-dropped") in
    (* Twice 8Mbps into 10Mbps for 100ms queues less than 100KB, which is
       less than 200ms: *)
    assert_equal ~msg:"within 200ms, all is queued" ~printer:string_of_int
                 0 (send_all ()) ;
    r.ifaces.(2).max_queue_delay <- 0.01 ;
    "beyond 10ms, some is dropped" @? (send_all () > 0)
 *)

(* Which address is a router's own is part of its routing table, so a
   router that is handed one later -- which is every router the catalogue
   builds, since those arrive with an empty table -- takes its address
   from that table and not only from the one it was made with. *)
(*$R configure_iface
    ignore configure_iface ;
    let sim = Simulation.make ~realtime:false "late-admin" in
    let r = make ~parent:sim.root 2 [] "r" in
    let set_routes rows =
        match List.find_opt (fun (p : Widget.property) ->
                  p.name = "routes") r.widget.properties with
        | None -> "the router has a routing table" @? false
        | Some p -> (Option.get p.setter) (`List rows) in
    (* A route to the router itself: no way out, and the address it
       answers on as the destination. *)
    let admin = [ `Assoc [ "input port", `Null ;
                           "src mask", `Null ;
                           "dst mask", `String "1.2.3.4/24" ;
                           "ip proto", `Null ;
                           "src port", `Null ;
                           "dst port", `Null ;
                           "output port", `Null ;
                           "via", `Null ] ] in
    "a router made with no table has no address" @?
        (r.ifaces.(0).eth.Eth.State.my_addresses = []) ;
    set_routes admin ;
    "the one its table names is the router's own" @?
        (Eth.State.find_ip4 r.ifaces.(0).eth =
         Ip.Addr.of_dotted_string "1.2.3.4") ;
    "on every interface the route does not single out" @?
        (Eth.State.find_ip4 r.ifaces.(1).eth =
         Ip.Addr.of_dotted_string "1.2.3.4") ;
    "and something answers for it" @?
        (r.ifaces.(0).admin_host <> None) ;
    (* Set again, to the same table: what is there is left alone. *)
    let host = r.ifaces.(0).admin_host in
    set_routes admin ;
    "a table that says the same thing changes nothing" @?
        (r.ifaces.(0).admin_host == host) ;
    set_routes [] ;
    "and a table that stops naming one takes it away" @?
        (r.ifaces.(0).eth.Eth.State.my_addresses = [] &&
         r.ifaces.(0).admin_host = None)
 *)

(* A router announces itself on its ports, and a neighbour learns it from
   that only if it accepts announcements. *)
(*$R make
    let sim = Simulation.make ~realtime:false "gratuitous-arp" in
    let router name addr =
        let r = make ~parent:sim.root 1 [] name in
        (match List.find_opt (fun (p : Widget.property) ->
                   p.name = "routes") r.widget.properties with
        | None -> "the router has a routing table" @? false
        | Some p ->
            (Option.get p.setter) (`List [
                `Assoc [ "input port", `Null ; "src mask", `Null ;
                         "dst mask", `String (addr ^"/24") ;
                         "ip proto", `Null ; "src port", `Null ;
                         "dst port", `Null ; "output port", `Null ;
                         "via", `Null ] ])) ;
        r in
    let r1 = router "r1" "10.0.0.1" and r2 = router "r2" "10.0.0.2" in
    let a = r1.widget.ports.dev 0 and b = r2.widget.ports.dev 0 in
    Tools.(a <--> b) ;
    let eth2 = r2.ifaces.(0).eth in
    let knows_r1 () =
        match Tools.BitHash.find_option eth2.Eth.State.neighbors
                (Ip.Addr.to_bitstring (Ip.Addr.of_dotted_string "10.0.0.1")) with
        | Some (Some mac) -> Eth.Addr.eq mac r1.ifaces.(0).eth.Eth.State.mac
        | _ -> false in
    (* Which switches both on. *)
    Simulation.run sim false ;
    "not before it has been told" @? not (knows_r1 ()) ;
    Eth.State.announce r1.ifaces.(0).eth ;
    Simulation.run sim false ;
    "a neighbour that does not accept them learns nothing" @?
        not (knows_r1 ()) ;
    eth2.Eth.State.accept_announcements <- true ;
    let announce = Option.get (Action.find r1.widget "announce addresses") in
    ignore (Action.start r1.widget announce []) ;
    Simulation.run sim false ;
    "one that does learns the router's address on that port" @?
        knows_r1 ()
 *)

(* A router's port n is its interface n, whatever order its parts were built
   in, and whether it has a cable is the adapter's own answer. *)
(*$T make
  let sim = Simulation.make ~realtime:false "router-ports" in \
  let r = make ~parent:sim.root 4 [] "r" in \
  r.widget.ports.count () = 4 && \
  not (r.widget.ports.is_connected 2) && \
  (Tools.(r.widget.ports.dev 2 --> sink ignore) ; \
   r.widget.ports.is_connected 2 && \
   (ports r.ifaces.(2)).is_connected 0) && \
  (* A cable to port n reaches interface n's adapter, and that is what a
     cable joining it is recorded as reaching. An interface is that
     adapter and nothing else, so it is the adapter that carries the
     interface's name. *) \
  List.for_all (fun n -> \
      r.widget.ports.owner n == (ports r.ifaces.(n)).owner 0 && \
      (r.widget.ports.owner n).name = "#"^ string_of_int n) [ 0 ; 1 ; 2 ; 3 ]
 *)

(* A host told by the router that its packets are too big for the next hop
 * resizes them, for the connections already open as for later ones; with
 * path MTU discovery off, IPv4 is fragmented on the way instead. *)
(*$R make
    let a = Ip.Addr.of_string and c = Ip.Cidr.of_string in
    let sim = Simulation.make ~realtime:false "router-pmtud" in
    let r =
        make_from_addrs ~parent:sim.root
            [| [ c "10.0.1.254/24", None ; c "2001:db8:1::fe/64", None ],
               Eth.Addr.random () ;
               [ c "10.0.2.254/24", None ; c "2001:db8:2::fe/64", None ],
               Eth.Addr.random () |] "r" in
    r.ifaces.(1).eth.mtu <- 1400 ;
    let host n =
        let gateways =
            [ Eth.State.gw_selector (),
              Some (Eth.Gateway.Ip (a (Printf.sprintf "10.0.%d.254" n))) ;
              Eth.State.gw_selector ~v6:true (),
              Some (Eth.Gateway.Ip (a (Printf.sprintf "2001:db8:%d::fe" n))) ] in
        let h =
            Host.make ~parent:sim.root ~gateways
                ~static_ip:(a (Printf.sprintf "10.0.%d.1" n))
                ~netmask:(a "255.255.255.0")
                ~addresses:[ c (Printf.sprintf "2001:db8:%d::1/64" n) ]
                ("h" ^ string_of_int n) in
        let st = Eth.Cable.State.make ~parent:sim.root
                                      ~name:("c" ^ string_of_int n) () in
        Eth.Cable.plug st (h.trx.widget, 0) (r.widget, n - 1) ;
        h in
    let h1 = host 1 and h2 = host 2 in
    Simulation.run_startup sim ;
    let pmtus (h : Host.t) =
        match (List.find (fun (p : Widget.property) -> p.name = "path MTUs")
                         h.trx.widget.properties).getter () with
        | `List l -> List.map (function `String s -> s | _ -> "?") l |>
                     List.sort String.compare |> String.concat ", "
        | _ -> "?" in
    let received = ref 0 in
    h2.trx.tcp_server_start (Tcp.Port.o 9) (fun (cnx : Tcp.TRX.tcp_trx) ->
        cnx.trx.ins --> sink (fun bits ->
            received := !received + Bitstring.bitstring_length bits / 8)) ;
    let send dst size =
        received := 0 ;
        h1.trx.tcp_connect (Host.Ip (a dst)) (Tcp.Port.o 9) (function
            | None -> ()
            | Some (cnx : Tcp.TRX.tcp_trx) ->
                tx cnx.trx (Bitstring.zeroes_bitstring (size * 8))) ;
        Simulation.run sim false ;
        !received in
    let frags_in () = h2.ip_counters.Ip.TRX.frags_in in
    (* IPv4-only hosts do not do it unless told to: *)
    assert_bool "on with IPv6" (Host.pmtud h1) ;
    assert_bool "off without"
        (not (Host.pmtud (Host.make ~parent:sim.root ~static_ip:(a "10.0.9.1") "h9"))) ;
    assert_equal ~printer:string_of_int ~msg:"IPv4" 100_000 (send "10.0.2.1" 100_000) ;
    assert_equal ~printer:identity "10.0.2.1 1400" (pmtus h1) ;
    assert_equal ~printer:string_of_int ~msg:"not fragmented" 0 (frags_in ()) ;
    assert_equal ~printer:string_of_int ~msg:"IPv6" 100_000 (send "2001:db8:2::1" 100_000) ;
    assert_equal ~printer:identity "10.0.2.1 1400, 2001:db8:2::1 1400" (pmtus h1) ;
    (* Known from the start, for a new connection: *)
    assert_equal ~printer:string_of_int ~msg:"again" 100_000 (send "10.0.2.1" 100_000) ;
    assert_equal ~printer:string_of_int ~msg:"still not fragmented" 0 (frags_in ()) ;
    (* Forgotten after the timeout, unless there is none: *)
    let wait secs =
        Simulation.delay h1.trx.widget.power (Clock.Interval.sec secs) ignore () ;
        Simulation.run sim false in
    h1.pmtu_timeout <- None ;
    Hashtbl.clear h1.pmtus ;
    ignore (send "10.0.2.1" 100_000) ;
    wait 1000. ;
    assert_equal ~printer:identity ~msg:"forever" "10.0.2.1 1400" (pmtus h1) ;
    Hashtbl.clear h1.pmtus ;
    h1.pmtu_timeout <- Some 600 ;
    ignore (send "10.0.2.1" 100_000) ;
    wait 601. ;
    assert_equal ~printer:identity ~msg:"expired" "" (pmtus h1) ;
    (* With path MTU discovery off, IPv4 goes in fragments: *)
    h1.pmtud <- Some false ;
    assert_equal ~printer:string_of_int ~msg:"off" 100_000 (send "10.0.2.1" 100_000) ;
    assert_equal ~printer:identity ~msg:"nothing learnt" "" (pmtus h1) ;
    assert_bool "fragmented" (frags_in () > 0) ;
    h1.pmtud <- None ;
    (* UDP: the first datagram is lost, the next one fragmented: *)
    let datagrams = ref 0 in
    h2.trx.udp_server_start (Udp.Port.o 9) (fun (u : Udp.TRX.udp_trx) ->
        u.trx.ins --> sink (fun _ -> incr datagrams)) ;
    let frags = frags_in () in
    let send_udp () =
        Host.udp_send h1 (Host.Ip (a "10.0.2.1")) (Udp.Port.o 9)
                      (Bitstring.zeroes_bitstring (1450 * 8)) ;
        Simulation.run sim false in
    send_udp () ;
    assert_equal ~printer:string_of_int ~msg:"lost" 0 !datagrams ;
    send_udp () ;
    assert_equal ~printer:string_of_int ~msg:"then received" 1 !datagrams ;
    assert_equal ~printer:string_of_int ~msg:"in two fragments" (frags + 2) (frags_in ()) ;
    (* What an error is checked for: *)
    Hashtbl.clear h1.pmtus ;
    let error ?(proto=Ip.Proto.udp) ?(size=1500) ?(l4=Bitstring.empty_bitstring) mtu =
        Host.path_mtu_rx h1 ~local:(a "10.0.1.1") ~remote:(a "10.0.2.1")
                         ~proto ~size ~mtu l4 ;
        let s = pmtus h1 in
        Hashtbl.clear h1.pmtus ;
        s in
    assert_equal ~printer:identity ~msg:"plateau" "10.0.2.1 1492" (error 0) ;
    assert_equal ~printer:identity ~msg:"minimum" "10.0.2.1 68" (error 50) ;
    assert_equal ~printer:identity ~msg:"not below the packet" "" (error ~size:1000 1000) ;
    assert_equal ~printer:identity ~msg:"not above the link" "" (error 1500) ;
    let%bitstring l4 = {| 1234 : 16 ; 9 : 16 ; 0l : 32 |} in
    assert_equal ~printer:identity ~msg:"about no connection" ""
        (error ~proto:Ip.Proto.tcp ~l4 1400) ;
    (* A router that reports nothing is a black hole: *)
    r.notify_errs.probability <- 0. ;
    assert_bool "black hole" (send "10.0.2.1" 100_000 < 100_000) ;
    assert_equal ~printer:identity ~msg:"nothing learnt" "" (pmtus h1)
 *)
