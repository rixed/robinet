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
module Nat = Ip_nat

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

    (** Test an incoming packet against a route, but for its destination. *)
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
               by_width : ((int * int) * (string, int list) Hashtbl.t) list }

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
                        let h = Hashtbl.create 16 in
                        by_width := ((len, width), h) :: !by_width ;
                        h in
                Hashtbl.modify_def [] (prefix net width) (List.cons i) h
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
                    (Hashtbl.find_default h (prefix addr width) []) acc
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
module Router =
struct
    (*$< Router *)

    type iface = { mutable trx : trx ; (** Can come handy to splice another trx there. *)
                           eth : Eth.State.t ;
        (** Any traffic arriving in this interface and directed to Admin is
         * forwarded to this host. There is one per interface so they have
         * totally independent IP stacks. If all the admin_hosts of a router
         * were to be made to edit the router's global configuration then
         * they would have to share that storage area of course. *)
            mutable admin_host : Host.t option }

    type load_balancing =
        | First (* Forward a packet to its first matching route *)
        | Flow (* Forward a packet to one matching route based on the socket pair *)
        | Random (* Pick a matching route at random *)
        | RoundRobin (* Take the matching routes in turn, one packet each *)
        [@@deriving enum]

    (* TODO: to_string_array with ppx_deriving.show if it happens again: *)
    let all_load_balancing =
        [| "first matching" ; "track flow" ; "random" ; "round robin" |]

    (* Probability to send ICMP expiry messages after TTL expiration, and after
     * which delay (TODO: should also depend on how busy the router is): *)
    type icmp_probability = {
        mutable probability : float ;
              mutable delay : float }

    (** A router is mainly an array of ifaces and a route table *)
    type t = {        ifaces : iface array ;
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
              (** RAM used by all queued frames: *)
                    buffered : Metric.Gauge.t }

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

    (** How many bytes to consider when hashing the packet prefix for load-balancing *)
    let lb_prefix_length = ref 5

    let target_routes ?in_iface ?src_ip ?dst_ip ?proto ?src_port ?dst_port t =
        if t.table.routes != t.routes then
            t.table <- Table.make t.routes ;
        Table.matching t.table in_iface src_ip dst_ip proto src_port
                             dst_port |>
        List.map (fun (r : Route.t) -> r.target)

    (* Sending will perform routing again *)
    let rec maybe_send_icmp t n ip icmp_maker =
        match Eth.State.find_ip4 t.ifaces.(n).eth with
        | exception Not_found ->
            Log.(log t.widget.logger Debug (lazy "Cannot send an ICMP error: I have no IP!"))
        | my_ip ->
            if Random.float 1. < t.notify_errs.probability then
                let delay = jitter 0.1 t.notify_errs.delay in
                let icmp = icmp_maker ip in
                let ip_pld = Icmp.Pdu.pack icmp in
                let ip_pkt = Ip.Pdu.make Ip.Proto.icmp my_ip ip.Ip.Pdu.src ip_pld in
                let bits = Ip.Pdu.pack ip_pkt in
                Simulation.delay t.widget.power
                             (Clock.Interval.sec delay) (route None t) bits

    (* The [route] function receives the IP packets from the Eth trx.
     * The integer [in_iface_opt] is the input interface number, unless
     * it's coming from the admin. *)
    and route in_iface_opt t bits =
        Log.(log t.widget.logger Debug (lazy (match in_iface_opt with
            | Some n -> Printf.sprintf "rx from iface %d" n
            | None -> "generated traffic"))) ;
        let ip_opt, src_opt, dst_opt, ttl_opt, proto_opt =
            match Ip.Pdu.unpack bits with
            | Error _ ->
                None, None, None, None, None
            | Ok ip ->
                Some ip, Some ip.Ip.Pdu.src, Some ip.dst, Some ip.ttl, Some ip.proto in
        let src_port_opt, dst_port_opt =
            match Option.bind ip_opt (Result.to_option % Ip.Pdu.get_ports) with
            | Some (src_port, dst_port) -> Some src_port, Some dst_port
            | None -> None, None in
        match target_routes ?in_iface:in_iface_opt
                            ?src_ip:src_opt ?dst_ip:dst_opt ?proto:proto_opt
                            ?src_port:src_port_opt ?dst_port:dst_port_opt t with
        | [] ->
            (match in_iface_opt, ip_opt with
            | None, _ ->
                Log.(log t.widget.logger Warning (lazy "Cannot route my own packet"))
            | _, None ->
                Log.(log t.widget.logger Debug (lazy "Dropping non-routable non IP packet"))
            | Some n, Some ip ->
                Log.(log t.widget.logger Debug (lazy "No route match that packet")) ;
                maybe_send_icmp t n ip Icmp.Pdu.make_host_unreachable)
        | targets ->
            (* Forward the packet to that target: *)
            let forward = function
                | Route.Forward { out_iface ; via } ->
                    let do_forward bits =
                        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Forwarding packet to iface %d" out_iface))) ;
                        let now = Simulation.Widget.now t.widget in
                        let len = bytelength bits in
                        Metric.Gauge.add t.buffered ~now len ;
                        let iface = t.ifaces.(out_iface) in
                        (* So we want to set the gateway for this packet but cannot
                         * call Etc.TRX.tx directly because some additional processing
                         * might be hidden in the TRX (NAT...) *)
                        iface.eth.via <- via ;
                        tx iface.trx bits ;
                        Log.(log t.widget.logger Debug (lazy "Done")) in
                    (match in_iface_opt, ttl_opt with
                    | None, _ ->
                        do_forward bits
                    | Some n, Some (0 | 1) ->
                        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "Expiring packet from %d" n))) ;
                        let ip = Option.get ip_opt in
                        maybe_send_icmp t n ip Icmp.Pdu.make_ttl_expired_in_transit
                    | Some _, Some ttl ->
                        let ip = Option.get ip_opt in
                        let ip = Ip.Pdu.{ ip with ttl = ttl - 1 } in
                        let bits = Ip.Pdu.pack ip in
                        do_forward bits
                    | Some _, None ->
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
                List.enum targets // (function
                    (* Actually, that's OK if out=in but then the router should
                     * generate also an ICMP redirect (see Stevens section 9.5) *)
                    | Forward { out_iface ; _ } -> in_iface_opt <> Some out_iface
                    | Admin -> true
                 ) |> Array.of_enum in
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

    (* The address the routing table gives interface [n]: the one an [Admin]
     * route names it by, since a route to the router itself is how the table
     * says which address is the router's.
     *
     * The CIDR is read as the address and the netmask that goes with it, such
     * as 34.35.36.37/16, and not as the network 34.35.0.0/16. *)
    let my_addresses_of routes n =
        List.find_map_opt (fun (r : Route.t) ->
            match r.dst_mask with
            | Some (addr, _test) ->
                if r.target = Admin &&
                   (r.in_iface = None || r.in_iface = Some n) then
                    let addr = Ip.Cidr.subnet addr |>
                               Ip.Addr.to_bitstring
                    and netmask = Ip.Cidr.to_netmask addr |>
                                  Ip.Addr.to_bitstring in
                    Some [ Eth.State.{ addr ; netmask } ]
                else
                    None
            | _ -> None
        ) routes

    (* Give interface [n] the address its routing table names, and the host
     * that answers for it -- or take both away, when the table has stopped
     * naming one.
     *
     * Called whenever the table is set and not only when the router is built,
     * because a router the catalogue builds arrives with an empty table: every
     * address such a router answers for, replies to ARP for and sends its ICMP
     * errors from is one a later [routes] gave it. *)
    let configure_iface t n =
        let iface = t.ifaces.(n) in
        let my_addresses = my_addresses_of t.routes n |? [] in
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
                        { ins = { write = route None t ; set_read = ignore } ;
                          out = { write = ignore_bits ; set_read = ignore } }
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

    (** Change the emitter of iface N. *)
    let set_read (t : t) n f =
        Log.(log t.widget.logger Debug (lazy (Printf.sprintf "setting emitter for iface %d" n))) ;
        (* Also decrease memory usage on the router *)
        let f bits =
            let len = bytelength bits in
            let now = Simulation.Widget.now t.widget in
            Metric.Gauge.sub ~now t.buffered len ;
            f bits in
        t.ifaces.(n).trx =-> f

    let is_connected iface =
        iface.eth.iface.is_connected

    let ports iface =
        iface.eth.iface.widget.ports

    (* TODO: similarly, a write n b = t.ifaces.(n).trx.write b *)

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

    let make_iface ?speeds ?proto ?mtu ?delay ?loss ?inter_frame_gap
                   ?can_forward_after ?mac ?my_addresses ~parent n =
        let name = "#"^ string_of_int n in
        (* For our ifaces we force the GW on a packet by packet basis according
         * to the dynamic (and likely still unset) routing table. *)
        let eth =
            Eth.State.make ?speeds ?proto ?mtu ?delay ?loss ?inter_frame_gap
                           ?can_forward_after ?mac ?my_addresses ~name
                           ~parent () in
        let trx = Eth.TRX.make eth in
        { trx ; eth ; admin_host = None }

    let notify_never = { probability = 0. ; delay = 0. }
    let notify_always ?(delay=0.) () = { probability = 1. ; delay }

    let make ~parent ?(own_power=true) ?(notify_errs=notify_always ())
             ?(admin_reroute=true) ?(load_balancing=First)
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
        let ifaces =
            Array.init num_ifaces (fun n ->
                let mac =
                    (* Caller can set the MAC addresses: *)
                    if n >= Array.length macs then None else Some macs.(n) in
                make_iface ?speeds ?delay ?loss ?can_forward_after ?mtu ?mac
                           ~parent:widget n
            ) in
        let buffered = Metric.Gauge.make () in
        let t = { ifaces ; routes ; table = Table.make routes ;
                  widget ; notify_errs ; admin_reroute ;
                  can_forward_after ; load_balancing ; lb_cursor = 0 ;
                  buffered } in
        (* One supply for the whole box, and this is what the router itself
           does when it is cut: what its admin hosts do about it is their own,
           and the supply asks each of them in turn. Every interface is reset,
           including the ones no admin host was built on, which nothing else
           would reach. *)
        widget.power_down <- (fun () ->
            Array.iter (fun iface -> Eth.State.reset iface.eth) t.ifaces) ;
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
                                        (match v with
                                        | Eth.Gateway.Mac mac ->
                                            `String (Eth.Addr.to_hexstring mac)
                                        | IPv4 ip ->
                                            `String (Ip.Addr.to_dotted_string ip))
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
                            (* A MAC when it reads as one, an IP otherwise: the
                               two things a gateway can be named by. *)
                            let gateway s =
                                match Eth.Addr.of_string s with
                                | exception _ ->
                                    (match Ip.Addr.of_dotted_string_opt s with
                                    | Some ip -> Eth.Gateway.IPv4 ip
                                    | None ->
                                        bad_value "%S is neither a MAC nor an \
                                                   IP address" s)
                                | mac -> Eth.Gateway.Mac mac in
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
            metric_property "buffered" ~units:"bytes"
                ~descr:"Volume of buffered packets, in bytes."
                (Metric.Gauge.T t.buffered) ;
            property "tot ports" ~kind:Int ~descr:"Total number of ports."
                ~getter:(fun () -> `Int num_ifaces) ] ;
        let addressed () =
            Array.exists (fun iface -> iface.eth.my_addresses <> []) t.ifaces in
        Widget.add_actions widget Widget.[
            action "emit gratuitous ARP"
                ~descr:"Announce the router's addresses on every port that \
                        has one."
                ~can_run:(fun () -> widget.power.on && addressed ())
                ~handler:(fun s ->
                    Array.iter (fun iface ->
                        Eth.State.emit_gratuitous_arp iface.eth) t.ifaces ;
                    Action.stop s) ] ;
        Array.iteri (fun n iface ->
            configure_iface t n ;
            (* When packets are received from the outside, go to routing: *)
            iface.trx.ins.set_read (route (Some n) t)
        ) t.ifaces ;
        t

    (* Assuming the network addresses are reachable from different ifaces of a
     * switch, output a trivial routing table that selects the output according
     * to the destination IP only.
     * Assume an admin interface on every network reachable without gateway. *)
    let routes_of_addrs addrs =
        let is_my_address dest_ip mask addr =
            addr = None &&
            Int32.logand (Int32.lognot (Ip.Addr.to_int32 mask))
                         (Ip.Addr.to_int32 dest_ip) <> Int32.zero in
        Array.fold_lefti (fun tbl i (gws, _) ->
            List.fold_left (fun tbl (dest_ip, mask, addr) ->
                (* First route: to reach that network: *)
                let open Route in
                let target = Forward { out_iface = i ;
                                       via = addr } in
                let cidr_test cidr = Some (cidr, Ip.Cidr.mem cidr) in
                let route =
                    { in_iface = None ;
                      src_mask = None ;
                      (* [of_netmask] will clear non masked bits: *)
                      dst_mask = cidr_test (Ip.Cidr.of_netmask dest_ip mask) ;
                      ip_proto = None ;
                      src_port = None ;
                      dst_port = None ;
                      target } in
                let tbl = route :: tbl in
                let tbl =
                    (* Second route: to the admin interface: *)
                    if is_my_address dest_ip mask addr then (
                        { route with
                            in_iface = Some i ;
                            dst_mask = cidr_test Ip.Cidr.(single dest_ip) ;
                            target = Admin } :: tbl
                    ) else tbl
                    in
                tbl
            ) tbl gws
        ) [] addrs |>
        List.rev

    (* [addrs] is an array (one entry for each iface of the router) of list of
     * networks reachable via this iface (as an Etx.Gateway.t, which has an
     * optional gateway addr).
     * The router address on each iface is given by the subnet address itself
     * (if it's not a mere network address with all masked bits zeroed, and
     * if no ethernet gateway is defined for this route).  *)
    (* [addrs] also, for each iface, has the MAC address of the router on that
     * iface. *)
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
            [| [ Ip.Addr.of_string "192.168.1.254", Ip.Addr.of_string "255.255.255.0", None ], Eth.Addr.random () ;
               [ Ip.Addr.of_string "192.168.2.254", Ip.Addr.of_string "255.255.255.0", None ], Eth.Addr.random () ;
               [ Ip.Addr.of_string "192.168.3.254", Ip.Addr.of_string "255.255.255.0", None ], Eth.Addr.random () |] in
        let sim = Simulation.make ~realtime:false "test-router" in
        let router = make_from_addrs ~parent:sim.root addrs "test" in

        (* Now we will count incoming packets from each iface (ARP requests, actually) : *)
        let counts = Array.create 3 0 in
        for i = 0 to Array.length counts - 1 do
            set_read router i (fun _ ->
                counts.(i) <- succ counts.(i))
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
        "route from 0 to 2" @? (counts = [| 0;0;1 |]) ;

        reset_count () ;
        easy_send 2 "192.168.2.42" ;
        Simulation.run sim false ;
        "route from 2 to 1" @? (counts = [| 0;1;0 |]) ;

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
                | Some h -> n + Hashtbl.length h.Host.udp_socks
            ) 0 router.ifaces in
        let poke n =
            Ip.Pdu.{ (random ()) with
                     dst = Ip.Addr.of_string
                               (Printf.sprintf "192.168.%d.254" (n + 1)) ;
                     proto = Ip.Proto.udp ; ttl = 9 } |>
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
        "and routes again once switched back on" @? (counts = [| 0;0;1 |]) ;
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
        Eth.State.set_arp eth
            (Ip.Addr.to_bitstring (Ip.Addr.of_dotted_string "1.2.3.4"))
            (Some (Eth.Addr.random ())) ;
        "and its adapter still learns" @?
            (Tools.BitHash.length eth.Eth.State.arp_cache = 1) ;
        flip false ;
        "which the box forgets when it is switched off" @?
            (Tools.BitHash.length eth.Eth.State.arp_cache = 0) ;
        flip true ;
        (* Deleting it takes its future with it, which is what stops a deleted
           thing for good. Not its destructor's doing: what a widget holds of
           its own is one thing, and what it has scheduled is another. *)
        Simulation.delay r.widget.power (Clock.Interval.sec 1.) ignore () ;
        Simulation.remove_widget r.widget ;
        "a deleted router has nothing left scheduled" @?
            (Events.for_all (fun _ (p, _) -> p != r.widget.power) sim.events) ;
        "and out of the tree" @?
            (Widget.find sim.root r.widget.id = None)
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
       that only if it accepts gratuitous ARP. *)
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
        a.Tools.set_read b.Tools.write ;
        b.Tools.set_read a.Tools.write ;
        let eth2 = r2.ifaces.(0).eth in
        let knows_r1 () =
            match Tools.BitHash.find_option eth2.Eth.State.arp_cache
                    (Ip.Addr.to_bitstring (Ip.Addr.of_dotted_string "10.0.0.1")) with
            | Some (Some mac) -> Eth.Addr.eq mac r1.ifaces.(0).eth.Eth.State.mac
            | _ -> false in
        (* Which switches both on. *)
        Simulation.run sim false ;
        "not before it has been told" @? not (knows_r1 ()) ;
        Eth.State.emit_gratuitous_arp r1.ifaces.(0).eth ;
        Simulation.run sim false ;
        "a neighbour that does not accept them learns nothing" @?
            not (knows_r1 ()) ;
        eth2.Eth.State.accept_gratuitous_arp <- true ;
        let announce = Option.get (Action.find r1.widget "emit gratuitous ARP") in
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
      ((r.widget.ports.dev 2).Tools.set_read ignore ; \
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

    (*$>*)
end

(** A gateway is a device with 2 Eth interfaces, with a public IP address
 * and a private network address, performing routing between these two,
 * NAT, DHCP and relaying DNS for the LAN.
 * The returned TRX is seen from the LAN (ie, tx for going out).
 * Internally, it's made of a 3 ifaces hub, with the dhcp/name server
 * attached to iface 1, the NATing router to iface 2, and the LAN to iface 0:
 *
 *          GW: 192.168.0.1
 *           /-----------\
 *    LAN -- :0 (demux)  2:--<:0-router-1:>-- NAT --- Internet
 *           \____ 1 ____/
 *                 |
 *                 |
 *            dhcpd/named (192.168.0.1, the same)
 *
 * One machine on the LAN, wearing one address: what is addressed to the
 * gateway itself goes to the server, what is passing through goes to the
 * router, and the demux is what tells them apart (see [Demux]). The LAN
 * cable negotiates with the router's LAN adapter, which is the adapter really
 * behind that socket.
 *)

(* What joins a gateway's parts, where a repeater used to be.
 *
 * A gateway is one machine on its LAN -- one address, one hardware address --
 * and two things inside it wear them: the router, which forwards what is
 * merely passing through, and the server, which answers the DHCP and DNS
 * addressed to the gateway itself. What tells them apart is the frame, so
 * neither needs an address of its own to be reached by.
 *
 * No delay, no speed and no collisions: this is the inside of a box and not a
 * length of wire. *)
module Gateway =
struct
    (*$< Gateway *)
    module Demux =
    struct
        type t = {
            (* The gateway's own addresses, which the router and the server share. *)
            mac : Eth.Addr.t ;
            ip : Ip.Addr.t ;
            (* What counts as sent to everyone rather than to the gateway. *)
            lan : Ip.Cidr.t ;
            bcast : Ip.Addr.t ;
            logger : Log.t ;
            (* Where the three ways out go. [to_lan] is set when a cable lands. *)
            mutable to_lan : bitstring -> unit ;
            mutable to_srv : bitstring -> unit ;
            mutable to_router : bitstring -> unit ;
            mutable lan_connected : bool }

        let make ~mac ~ip ~lan ~bcast ~logger =
            { mac ; ip ; lan ; bcast ; logger ;
              to_lan = ignore ; to_srv = ignore ; to_router = ignore ;
              lan_connected = false }

        let log t what where =
            Log.(log t.logger Debug (lazy (what ^" -> "^ where)))

        (* The IPv4 destination of [bits], when it has one. *)
        let ipv4_dst (frame : Eth.Pdu.t) =
            if frame.proto <> Eth.Proto.ip4 then None
            else
                match Ip.Pdu.unpack (frame.payload :> bitstring) with
                | Ok ip -> Some ip.Ip.Pdu.dst
                | Error _ -> None

        (* Addressed to everyone rather than to anyone. *)
        let is_bcast t (d : Ip.Addr.t) =
            d = Ip.Addr.broadcast || d = t.bcast

        (* From the LAN. What is for the gateway itself is the server's, and the
         * rest the router's -- including ARP, which the router answers for the
         * address they share. A frame addressed to some other machine is none of
         * our business. *)
        let from_lan t bits =
            match Eth.Pdu.unpack bits with
            | Error _ ->
                log t "Unparseable frame" "dropped"
            | Ok frame ->
                (* [eq] and not [=]: an address is a bitstring, and two of them
                   with the same bytes at different offsets are not structurally
                   equal. *)
                if not (Eth.Addr.is_broadcast frame.dst ||
                        Eth.Addr.eq frame.dst t.mac) then
                    log t "Frame for someone else" "dropped"
                else
                    match ipv4_dst frame with
                    | Some d when d = t.ip || is_bcast t d ->
                        log t "For the gateway itself" "server" ;
                        t.to_srv bits
                    | _ ->
                        log t "Passing through" "router" ;
                        t.to_router bits

        (* From the server: out to the LAN, unless it is talking to the world --
         * resolving a name it was asked for -- in which case the router is what
         * gets it there. *)
        let from_srv t bits =
            let out =
                match Eth.Pdu.unpack bits with
                | Error _ -> `Lan
                | Ok frame ->
                    (match ipv4_dst frame with
                    | None -> `Lan
                    | Some d ->
                        if is_bcast t d || Ip.Cidr.mem t.lan d then `Lan
                        else `Router) in
            match out with
            | `Lan -> log t "From the server" "LAN" ; t.to_lan bits
            | `Router -> log t "From the server, outward" "router" ; t.to_router bits

        (* From the router: out to the LAN, unless it is what the server asked the
         * world for, which comes back addressed to the gateway. *)
        let from_router t bits =
            let for_srv =
                match Eth.Pdu.unpack bits with
                | Error _ -> false
                | Ok frame ->
                    (match ipv4_dst frame with
                    | Some d -> d = t.ip
                    | None -> false) in
            if for_srv then (
                log t "Answer for the gateway itself" "server" ;
                t.to_srv bits
            ) else (
                log t "From the router" "LAN" ;
                t.to_lan bits
            )

        (* The LAN socket, as something a cable plugs into. *)
        let lan_dev t =
            { write = from_lan t ;
              set_read = (fun f -> t.to_lan <- f ; t.lan_connected <- true) }

        let disconnect t =
            if t.lan_connected then (
                t.to_lan <- ignore ;
                t.lan_connected <- false
            ) else
                Log.(log t.logger Debug (lazy
                    "Ignoring request to unplug a LAN socket with nothing on it"))
    end

    type t =
        { trx : trx ;
          widget : Widget.t ;
          mutable dhcp_state : Dhcpd.State.t option ;
          mutable dns_state : Named.State.t option ;
          nat_state : Nat.State.t }

    type Widget.device += T of t

    (* The gateway a widget stands for, when it stands for one. *)
    let of_widget (w : Widget.t) =
        match w.device with
        | Some (T t) -> Some t
        | _ -> None

    (* Returns a [gw_trx] that gives access to the dhcpd leases, the named zones
     * and the NAT tables.
     * Unless [dhcp_range] is set, all local IPs (but those used by the GW itself)
     * will be distributed via DHCP. *)
    let make ?delay ?loss ?mtu ?(num_max_cnxs=500) ?nameserver
             ?dhcp_range ?dhcp_mtu ?lease_time_sec ?mac
             ?(name="gw") ?notify_errs ?admin_reroute
             ~parent ?location ?(own_power=true)
             ?public_netmask ?public_gw ?port_forwards public_ip local_cidr =
        (* We want all parts inherit this widget: *)
        let widget = Widget.make ~parent ?location ~own_power name in
        (* A whole machine, whatever it is made of inside. *)
        widget.device_type <- Some "gateway" ;
        let local_ips = Ip.Cidr.local_addrs local_cidr in
        let netmask = Ip.Cidr.to_netmask local_cidr in
        let broadcast = Ip.Cidr.all1s_addr local_cidr in
        (* Build the output router *)
        let router =
            Router.(make ~parent:widget ~own_power:false ?delay ?loss ?mtu ?notify_errs
                         ?admin_reroute ?macs:(Option.map (Array.make 1) mac) 2
                [ (* route everything from anywhere to LAN if dest fits local_cidr *)
                  Route.forward ~dst_mask:local_cidr 0 ;
                  (* or zero IP address *)
                  Route.forward ~src_mask:(Ip.Cidr.single Ip.Addr.zero) 0 ;
                  (* route everything else toward the outside *)
                  Route.forward ?via:public_gw 1 ]
                "router") in
        (* Configure those 2 ifaces: *)
        (* 1st iface is for the GW: *)
        let gw_mac = router.ifaces.(0).eth.mac in
        let gw_ip = Enum.get_exn local_ips in   (* first IP of the subnet is the GW *)
        Eth.State.add_ip4 router.ifaces.(0).eth ~netmask gw_ip ;
        (* The second iface of our router (facing internet) is the NAT *)
        Eth.State.add_ip4 router.ifaces.(1).eth ?netmask:public_netmask public_ip ;
        let nat_state =
            Nat.State.make ~num_max_cnxs ~parent:widget ?port_forwards public_ip in
        let nat_trx = Nat.TRX.make nat_state in
        (* Which we pipe *before* the iface eth (NAT operates at the IP level): *)
        router.ifaces.(1).trx <- pipe nat_trx router.ifaces.(1).trx ;
        (* FIXME: if we had directly a "mutable read" function rather than a
         * set_reader, the pipe operator (and others) could do the right thing here: *)
        router.ifaces.(1).trx.ins.set_read (Router.route (Some 1) router) ;
        (* This iface will become the outside side of out global TRX: *)
        let out_trx = router.ifaces.(1).trx in
        (* Create the "host" that answers for the gateway. It wears the gateway's
         * own address and hardware address rather than a second pair: on the LAN
         * a gateway is one machine, and which of its two halves answers a frame is
         * settled inside (see [Demux]). Its gateway is the router beside it,
         * for the names it has to go and ask the world about. *)
        let h : Host.t =
            let gateways = [ Eth.State.gw_selector (), Some (Eth.Gateway.Mac gw_mac) ] in
            (* On the box's supply, which is switched off until the end of this
             * function: a host that is running does its boot-time configuration
             * then and there, and what it is to do once it has an address is hung
             * on it a few lines further down. *)
            Host.make ?nameserver ~gateways ~netmask ~static_ip:gw_ip ~mac:gw_mac
                      ~parent:widget ~own_power:false "srv" in
        (* Now what joins those parts, and the services: *)
        let demux =
            Demux.make ~mac:gw_mac ~ip:gw_ip ~lan:local_cidr ~bcast:broadcast
                          ~logger:widget.logger in
        demux.Demux.to_srv <- h.trx.dev.write ;
        h.trx.dev.set_read (Demux.from_srv demux) ;
        (* Connect the first iface of our router *)
        demux.Demux.to_router <- router.ifaces.(0).trx.out.write ;
        router.ifaces.(0).trx.out.set_read (Demux.from_router demux) ;
        (* Its LAN side is the entrance of the whole TRX: *)
        let in_trx = Demux.lan_dev demux in
        let trx =
            { ins = in_trx ;
              out = out_trx.out } in
        let gw =
            { trx ; widget ; dhcp_state = None ; dns_state = None ; nat_state } in
        (* Now prepare the services that will run on the host [h]: *)
        (* TODO: local named could serve the local names according to the dhcp
         * leases and hostname options *)
        (* [nameserver] is the nameserver for the gateway but the nameserver for the
         * local machines is the gateway itself: *)
        (* TODO: save this dhcp_range into the state, and make it an editable property
         * so that we can change the range and restart dhcpd. *)
        let dhcp_range =
            Option.default_delayed (fun () ->
                (* Default range: from first available IP to the all-ones: *)
                [ Enum.get_exn local_ips, Ip.Cidr.all1s_addr local_cidr ]
            ) dhcp_range in
        let start_dhcpd gw =
            (* Built afresh on every start, so that it takes up what the host's
             * configuration has become; the one it replaces goes with it, or a
             * gateway switched off and on again would grow another pair of parts
             * every time. *)
            Option.may (fun (st : Dhcpd.State.t) -> Simulation.remove_widget st.Dhcpd.State.widget)
                       gw.dhcp_state ;
            (* Get from the host what could be edited there (TODO: dhcp_mtu,
             * lease_time_sec etc could also be part of the config) *)
            let netmask = h.netmask in
            let st =
                Dhcpd.State.make
                    ?netmask ~broadcast ~gw:gw_ip ?mtu:dhcp_mtu ~dns:gw_ip
                    ?lease_time_sec ~parent:h.trx.widget dhcp_range in
            gw.dhcp_state <- Some st ;
            (* TODO: register a callback when leasing/releasing that updates the dns lookup function *)
            Dhcpd.serve st h.trx in
        let start_dns gw =
            Option.may (fun (st : Named.State.t) -> Simulation.remove_widget st.Named.State.widget)
                       gw.dns_state ;
            let st =
                Named.State.make ~parent:h.trx.widget (fun _ -> None) in (* Delegate everything to nameserver *)
            gw.dns_state <- Some st ;
            (* FIXME: revisit that! Here we want a table (state must not contain functions
             * because we want to be able to serialize them) *)
            Named.serve st h.trx in
        (* Make the host [h] start dhcpd and dns when it is powered on: *)
        h.trx.on_ip <- (fun _h -> start_dhcpd gw ; start_dns gw) :: h.trx.on_ip ;
        Widget.add_properties widget Widget.[
            property "nat-max-cnxs" ~kind:Int
                ~descr:"Max number of connections tracked by the NAT."
                ~getter:(fun () -> `Int num_max_cnxs) ] ;
        (* Two visible ports only: outside, inside. *)
        widget.ports <- Widget.{
            count = (fun () -> 2) ;
            is_connected = (function
                | 0 -> router.ifaces.(1).eth.iface.is_connected
                | _ -> demux.Demux.lan_connected) ;
            dev = (function 0 -> out_trx.out | _ -> in_trx) ;
            (* Either socket belongs to the router adapter behind it: the outward
               one to its second, the LAN one to its first. *)
            owner = (function
                | 0 -> (Router.ports router.ifaces.(1)).owner 0
                | _ -> (Router.ports router.ifaces.(0)).owner 0) ;
            disconnect = (function
                | 0 -> (Router.ports router.ifaces.(1)).disconnect 0
                | _ -> Demux.disconnect demux) ;
            (* The LAN cable settles with the router's first adapter, which is
               the one really behind that socket. *)
            get_capabilities = (fun ?peer -> function
                | 0 -> (Router.ports router.ifaces.(1)).get_capabilities ?peer 0
                | _ -> (Router.ports router.ifaces.(0)).get_capabilities ?peer 0) ;
            set_capabilities = (fun n c ->
                match n with
                | 0 -> (Router.ports router.ifaces.(1)).set_capabilities 0 c
                | _ ->
                    (* Both adapters behind that socket, and not merely the one
                       that answered: they are the same machine, and one left
                       slower than the other is still busy with the frame before
                       when the next arrives, and drops it. *)
                    (Router.ports router.ifaces.(0)).set_capabilities 0 c ;
                    h.trx.widget.ports.set_capabilities 0 c) } ;
        widget.device <- Some (T gw) ;
        gw

    (* A gateway serves DHCP from a host built inside it, which goes down and comes
     * back with the box. That has broken twice, in two different ways -- a load
     * that powered everything down and up again, and a switch that powered the
     * host off and never back on -- and neither was caught by anything here, since
     * nothing here asked the gateway for an address after switching it. This does.
     *)
    (*$R make
        let sim = Simulation.make ~realtime:false "gw-dhcp" in
        let gw =
            make ~parent:sim.root
                 (Ip.Addr.of_string "80.82.17.127")
                 (Ip.Cidr.of_string "192.168.0.0/24") in
        (* No address of its own, so it asks for one. *)
        let client : Host.t = Host.make ~parent:sim.root "client" in
        client.Host.trx.Host.dev.set_read gw.trx.ins.write ;
        ignore (client.Host.trx.Host.dev.write <-= gw.trx) ;
        let address () =
            match Eth.State.find_ip4 client.Host.eth_state with
            | exception Not_found -> "none"
            | ip -> Ip.Addr.to_dotted_string ip in
        Simulation.run sim false ;
        assert_bool ("a client on the LAN is leased an address, not "^ address ())
                    (address () <> "none") ;
        (* The box off and on again, which takes its server with it both ways. *)
        let flip (w : Widget.t) on =
            (if on then Simulation.power_up else Simulation.power_down)
                w.power in
        flip gw.widget false ;
        flip gw.widget true ;
        (* And a client that asks afterwards has to be answered. It is rebooted
           rather than believed: the address it holds is one it was granted before
           any of this. *)
        flip client.Host.trx.Host.widget false ;
        assert_equal ~printer:identity "none" (address ()) ;
        flip client.Host.trx.Host.widget true ;
        Simulation.run sim false ;
        assert_bool ("a client asking after the gateway was switched off and on \
                      again is leased one, not "^ address ())
                    (address () <> "none")
     *)

    (* A gateway is one machine on its LAN, at one address: what is addressed to
       that address the server answers, and what is merely passing through the
       router forwards -- both from the same client, over the same cable. *)
    (*$R make
        let sim = Simulation.make ~realtime:false "gw-one-address" in
        let gw =
            make ~parent:sim.root
                 (Ip.Addr.of_string "80.82.17.127")
                 (Ip.Cidr.of_string "192.168.0.0/24") in
        (* Something out there to reach, wired to the gateway's public side. *)
        let far : Host.t =
            Host.make ~parent:sim.root ~netmask:Ip.Addr.zero
                      ~static_ip:(Ip.Addr.of_string "80.82.17.1") "far" in
        far.Host.trx.Host.dev.set_read gw.trx.out.write ;
        gw.trx.out.set_read far.Host.trx.Host.dev.write ;
        (* No address of its own, so it asks the gateway for one. *)
        let client : Host.t = Host.make ~parent:sim.root "client" in
        client.Host.trx.Host.dev.set_read gw.trx.ins.write ;
        ignore (client.Host.trx.Host.dev.write <-= gw.trx) ;
        Simulation.run sim false ;
        (* The address it was handed is the one right after the gateway's own: no
           second address is taken for a server any more. *)
        assert_equal ~printer:identity ~msg:"the pool starts right after the gateway"
            "192.168.0.2"
            (Ip.Addr.to_dotted_string (Eth.State.find_ip4 client.Host.eth_state)) ;
        (* Ping through the same socket and count what comes back. *)
        let ping id dst =
            let replies = ref 0 in
            Hashtbl.replace client.Host.echo_waiters id (fun _seq -> incr replies) ;
            client.Host.trx.Host.ping ~id ~seq:1 (Host.IPv4 (Ip.Addr.of_string dst)) ;
            Simulation.run sim false ;
            Hashtbl.remove client.Host.echo_waiters id ;
            !replies in
        assert_equal ~printer:string_of_int
            ~msg:"the gateway answers at its own LAN address" 1
            (ping 1 "192.168.0.1") ;
        assert_equal ~printer:string_of_int
            ~msg:"and still routes what is only passing through" 1
            (ping 2 "80.82.17.1")
     *)

    (* And the two halves are not sealed off from each other: a name the server
       cannot answer for it goes and asks the world about, which means out through
       the router beside it and back again -- the answer arriving addressed to the
       gateway, as the question left it. *)
    (*$R make
        let sim = Simulation.make ~realtime:false "gw-resolves" in
        let far_ip = Ip.Addr.of_string "80.82.17.1" in
        let gw =
            make ~parent:sim.root ~nameserver:far_ip
                 (Ip.Addr.of_string "80.82.17.127")
                 (Ip.Cidr.of_string "192.168.0.0/24") in
        (* The only nameserver in the world, out beyond the gateway. *)
        let far : Host.t =
            Host.make ~parent:sim.root ~netmask:Ip.Addr.zero ~static_ip:far_ip
                      "far" in
        Named.serve
            (Named.State.make ~parent:sim.root (function
                | "popo" -> Some (Ip.Addr.of_string "1.2.3.4")
                | _ -> None))
            far.Host.trx ;
        far.Host.trx.Host.dev.set_read gw.trx.out.write ;
        gw.trx.out.set_read far.Host.trx.Host.dev.write ;
        let client : Host.t = Host.make ~parent:sim.root "client" in
        client.Host.trx.Host.dev.set_read gw.trx.ins.write ;
        ignore (client.Host.trx.Host.dev.write <-= gw.trx) ;
        Simulation.run sim false ;
        (* Asking the gateway, which is the nameserver its own lease named. *)
        let answer = ref "nothing came back" in
        client.Host.trx.Host.gethostbyname "popo" (fun ips ->
            answer :=
                match ips with
                | None | Some [] -> "no such host"
                | Some ips ->
                    String.concat "," (List.map Ip.Addr.to_dotted_string ips)) ;
        Simulation.run sim false ;
        assert_equal ~printer:identity "1.2.3.4" !answer
     *)

    (* What joins a gateway's parts is a backplane and not a segment of wire, so
       the LAN settles with the router's adapter and is not held to a repeater's
       10 or 100Mbps. The server's adapter is settled along with it: the three are
       one segment, and one of them left slower would drop what the others send. *)
    (*$R make
        let sim = Simulation.make ~realtime:false "gw-lan-speed" in
        let gw =
            make ~parent:sim.root
                 (Ip.Addr.of_dotted_string "80.82.17.127")
                 (Ip.Cidr.of_string "192.168.0.0/24") in
        let h =
            Host.make ~parent:sim.root ~netmask:(Ip.Addr.of_string "255.255.255.0")
                      ~static_ip:(Ip.Addr.of_string "192.168.0.10") "h" in
        let cable = Eth.Cable.State.make ~parent:sim.root ~name:"lan" () in
        Eth.Cable.plug cable (gw.widget, 1) (h.Host.trx.Host.widget, 0) ;
        let link path =
            let w = Option.get (Widget.find_within gw.widget path) in
            match (List.find (fun (p : Widget.property) -> p.name = "link")
                             w.properties).getter () with
            | `String s -> s
            | _ -> "?" in
        let printer = identity in
        assert_equal ~printer ~msg:"the LAN adapter takes what the cable settled on"
            "5Gbps full-duplex" (link "router/#0") ;
        assert_equal ~printer ~msg:"and so does the server behind it"
            "5Gbps full-duplex" (link "srv/eth")
     *)

    (* A gateway offers what a gateway has sockets for, and not one port per end
       that happens to exist within it: the router's two interfaces, the bus's three
       and the server's adapter are all spoken for inside. *)
    (*$T make
      let sim = Simulation.make ~realtime:false "gw-ports" in \
      let gw = make ~parent:sim.root \
                    (Ip.Addr.of_dotted_string "80.82.17.127") \
                    (Ip.Cidr.of_string "192.168.0.0/16") in \
      gw.widget.ports.count () = 2 && \
      gw.widget.ports.dev 0 == gw.trx.out && \
      gw.widget.ports.dev 1 == gw.trx.ins && \
      (* Either socket belongs to the router adapter behind it, the bus joining
         the parts inside being no end of a link. *) \
      (gw.widget.ports.owner 0).name = "#1" && \
      (gw.widget.ports.owner 1).name = "#0" && \
      gw.widget.ports.owner 0 != gw.widget.ports.owner 1 && \
      List.for_all (fun (c : Widget.t) -> c.ports.count() <= 3) \
                   gw.widget.children
     *)

    (*$R make
        (*Log.console_lvl := Log.Debug ;*)
        let sim = Simulation.make ~realtime:false "test-gw" in
        let public_ip = Ip.Addr.of_string "80.82.17.127" in
        let gw_trx = make ~parent:sim.root public_ip (Ip.Cidr.of_string "192.168.0.0/16") in
        let gateways = Eth.[ State.gw_selector (), Some (Gateway.of_string "192.168.0.1") ] in
        let netmask = Ip.Addr.of_string "255.255.255.0" in
        let desktop : Host.t = Host.make ~parent:sim.root ~netmask ~gateways "desktop" in
        desktop.trx.dev.set_read gw_trx.trx.ins.write ;
        ignore (desktop.trx.dev.write <-= gw_trx.trx) ;
        let server_ip = Ip.Addr.of_string "42.43.44.45" in
        let server_eth = Eth.(TRX.make State.(make ~parent:sim.root ~power:sim.root.power ~my_addresses:[ make_my_ip_address server_ip ] ())) in
        let src = ref None in
        let server_recv bits = (* check source IP is the public one (NATed) *)
            let ip = Ip.Pdu.unpack bits |> Result.get_ok in
            src := Some ip.Ip.Pdu.src in
        ignore (server_recv <-= server_eth) ;
        gw_trx.trx <==> server_eth ;
        Simulation.delay sim.root.power (Clock.Interval.sec 10.) (fun () ->
            Log.(log desktop.trx.widget.logger Debug (lazy "Sending UDP packet to server")) ;
            desktop.trx.udp_send (Host.IPv4 server_ip) (Udp.Port.o 80) empty_bitstring) () ;
        Simulation.run sim false ;
        assert_bool "Desktop was NATed" (!src = Some public_ip)
     *)
    (*$>*)
end
