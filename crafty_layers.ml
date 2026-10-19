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
(** The protocol layers crafty knows of: what the parser, the typer, the tree
   of parsers and the packet generator all read from.

   Names of layers, fields and constants are case insensitive. Constants are
   reserved names, valid anywhere, as are the layers.

   Each layer also tells how its nodes in the tree of parsers send: building
   its header in manual mode, filling in what the stack leaves out, or
   handing the payload to a robinet TRX in self-driven mode. And how a
   received packet is decoded, layer by layer, each telling what is on top
   of it. *)
open Batteries
open Bitstring
open Crafty_ast
module V = Crafty_value

(** A layer is either crafted packet by packet ([Manual], written with a
 * bang), or left to a robinet TRX that drives a whole stream ([Driven]). *)
type mode = Manual | Driven

let string_of_mode = function Manual -> "manual" | Driven -> "self-driven"

(** How a discriminant that a stack leaves out is chosen: *)
type pick =
    | Required
    (* The IPv4 address of the interface: *)
    | Local_address
    (* At random within these bounds, and distinct from the siblings': *)
    | Random_in of int * int

type field =
    { name : string ;
      typ : Type.t ;
      (* The modes in which the field can be given as an option, and those in
       * which a condition can read it. Some are read only (computed or
       * virtual, such as [is_fragment]), and some are options of a TRX that
       * are not header fields (such as TCP's [mss]): *)
      set_in : mode list ;
      read_in : mode list ;
      (* Whether it tells streams apart, which the tree of parsers keys its
       * nodes on: *)
      discriminant : bool ;
      (* For a discriminant that is not told by the layer on top (as the
       * protocol of IP is): *)
      pick : pick option ;
      (* The field of a received packet that holds the value of this one in
       * the packets sent (the source port is the destination port of a
       * reply): *)
      peer : string }

(* Instantiated only once so can be compared with == and != *)
(** {2 Nodes}
 *
 * What a node of the tree of parsers does with the packets of its layer,
 * behind closures that keep its state (counters, TRXs). *)

(** What a layer tells the layer below it about itself, by the names of the
 * fields of that one (the protocol of IP, the type of ICMP...): *)
type hints = (string * V.value) list

(** The fields of a node by name: its key and the options of a stack. *)
type fields = string -> V.value option

(** A layer of a received packet, decoded: *)
type unpacked =
    { (* The fields that can be read, by name: *)
      values : (string * V.value) list ;
      (* The name of the layer on top, if any: *)
      upper : string option ;
      payload : bitstring ;
      (* What the layer on top needs to know (the code of an ICMP error): *)
      up_hints : hints ;
      (* This layer and what is on top of it: *)
      bits : bitstring }

type ops =
    { (* Manual mode: this layer around [payload], and the hints for the
       * layer below: *)
      pack : fields -> hints -> bitstring -> bitstring * hints ;
      (* Self-driven mode: [payload] handed to its TRX: *)
      send : fields -> hints -> bitstring -> unit ;
      (* What goes on from a received layer, with the modes that see it:
       * nothing (a frame for another host), that layer, or others (a
       * fragment, seen as it is in manual mode, then the reassembled packet,
       * seen by the self-driven stream): *)
      receive : unpacked -> (unpacked * mode list) list }

(** What a node is made with: *)
type context =
    { eth : Eth.State.t ;
      (* That of the node below, but for the root: *)
      below : ops option }

let int_value name lo hi = function
    | V.Int v ->
        if v < lo || v > hi then
            V.fail "The %s must be between %d and %d, not %d" name lo hi v ;
        v
    | _ -> invalid_arg ("Crafty_layers: "^ name ^" is not an int")

(* The int field [name] of [layer], from [fields], or else from [hints], or
 * else [def]: *)
let int_of ?(hints=[]) ?def (fields : fields) layer name lo hi =
    match fields name with
    | Some v -> int_value name lo hi v
    | None ->
        (match List.assoc_opt name hints, def with
        | Some v, _ -> int_value name lo hi v
        | None, Some d -> d
        | None, None -> V.fail "%s needs a %s" layer name)

let opt_int (fields : fields) name lo hi =
    Option.map (int_value name lo hi) (fields name)

let opt_bool (fields : fields) name =
    match fields name with
    | Some (V.Bool b) -> Some b
    | None -> None
    | Some _ -> invalid_arg ("Crafty_layers: "^ name ^" is not a bool")

let bool_of fields name ~def = opt_bool fields name |? def

let bytes_of (fields : fields) name =
    Option.map_default V.bits_of_bytes empty_bitstring (fields name)

(* Key fields, which a node always has: *)
let ip_of (fields : fields) name =
    match fields name with
    | Some (V.Ip a) -> a
    | _ -> invalid_arg ("Crafty_layers: no address "^ name)

let not_driven _ _ _ = invalid_arg "Crafty_layers: not a self-driven layer"

let both = [ Manual ; Driven ]

let pass u = [ u, both ]

let bytes_value bits = V.bytes_of_string (string_of_bitstring bits)

let unpacked ?upper ?(up_hints=[]) ?(payload=empty_bitstring) values bits =
    Some { values ; upper ; payload ; up_hints ; bits }

let ip4 = (Eth.Proto.ip4 :> int)

(* Where a frame of [proto] carrying [payload] goes, from what the interface
 * knows already, as ARP is not asked: *)
let next_mac (st : Eth.State.t) proto payload =
    let arp ip =
        match Tools.BitHash.find st.arp_cache ip with
        | Some mac -> mac
        | None | exception Not_found ->
            V.fail "The MAC address of %s is not known: Eth! needs a dst"
                (Ip.Addr.to_dotted_string (Ip.Addr.of_bitstring ip)) in
    match Eth.Pdu.extract_dst_proto Eth.Proto.ip4 payload with
    | Ok dst when proto = ip4 ->
        if Bitstring.equals dst Eth.TRX.broadcast_bits then Eth.Addr.broadcast
        else if Eth.State.on_my_subnet st dst then arp dst
        else (match Eth.TRX.gw_for_ip st (Ip.Addr.of_bitstring dst) with
            | None -> arp dst
            | Some (Eth.Gateway.Mac mac) -> mac
            | Some (Eth.Gateway.IPv4 gw) -> arp (Ip.Addr.to_bitstring gw))
    | _ -> V.fail "Eth! needs a dst"

let unpack_eth _ bits =
    match Eth.Pdu.unpack bits with
    | Error _ -> None
    | Ok e ->
        let proto = (e.proto :> int) in
        unpacked [ "src", V.Mac e.src ; "dst", V.Mac e.dst ; "proto", V.Int proto ]
                 ~upper:(if proto = ip4 then "IP" else "Bytes")
                 ~payload:(e.payload :> bitstring) bits

(* The root: an Ethernet interface, which a self-driven Eth sends IPv4
 * through, resolving with ARP. It answers ARP itself, and takes the frames
 * for its address: *)
let eth_node ctx =
    let st = ctx.eth in
    let trx = Eth.TRX.make st in
    let receive (u : unpacked) =
        match List.assoc "proto" u.values, List.assoc "dst" u.values with
        | V.Int p, _ when p = (Eth.Proto.arp :> int) ->
            Eth.TRX.rx st u.bits ;
            []
        | _, V.Mac dst when Eth.Addr.eq dst st.mac || Eth.Addr.eq dst Eth.Addr.broadcast ->
            pass u
        | _ -> [] in
    { pack = (fun fields hints payload ->
        let proto = int_of ~hints fields "Eth!" "proto" 0 0xffff in
        let src = match fields "src" with Some (V.Mac m) -> m | _ -> st.mac in
        let dst =
            match fields "dst" with
            | Some (V.Mac m) -> m
            | _ -> next_mac st proto payload in
        Eth.Pdu.(pack (make (Eth.Proto.o proto) src dst payload)), []) ;
      send = (fun _ hints payload ->
        if List.assoc_opt "proto" hints <> Some (V.Int ip4) then
            V.fail "A self-driven Eth carries only IPv4: use Eth!" ;
        Tools.tx trx payload) ;
      receive }

let ip_upper (ip : Ip.Pdu.t) =
    if Ip.Pdu.is_fragment ip then "Bytes"
    else if ip.proto = Ip.Proto.icmp then "ICMP"
    else if ip.proto = Ip.Proto.udp then "UDP"
    else if ip.proto = Ip.Proto.tcp then "TCP"
    else "Bytes"

let ip_values (ip : Ip.Pdu.t) =
    [ "src", V.Ip ip.src ; "dst", V.Ip ip.dst ; "proto", V.Int (ip.proto :> int) ;
      "tos", V.Int (ip.tos :> int) ; "ttl", V.Int ip.ttl ;
      "dont_frag", V.Bool ip.dont_frag ; "id", V.Int ip.id ;
      "more_frags", V.Bool ip.more_frags ; "frag_offset", V.Int ip.frag_offset ;
      "tot_len", V.Int ip.tot_len ; "options", bytes_value ip.options ;
      "is_fragment", V.Bool (Ip.Pdu.is_fragment ip) ]

(* A fragment goes on as bytes: *)
let unpack_ip _ bits =
    match Ip.Pdu.unpack bits with
    | Error _ -> None
    | Ok ip ->
        unpacked (ip_values ip) ~upper:(ip_upper ip)
                 ~payload:(ip.payload :> bitstring) bits

(* Both modes share the ids. A self-driven IP has a TRX per protocol. The
 * fragments received are seen in manual mode, and reassembled for the
 * self-driven mode, which sees the whole packet once complete: *)
let ip_node ctx =
    let st = ctx.eth in
    let below = Option.get ctx.below in
    let id = ref (Random.int 0x10000) in
    let next_id () = id := (!id + 1) land 0xffff ; !id in
    let trxs = Hashtbl.create 3 in
    let fragments = Hashtbl.create 3 in
    let receive (u : unpacked) =
        if List.assoc "is_fragment" u.values <> V.Bool true then pass u else
        let fragment = u, [ Manual ] in
        match Ip.Pdu.unpack u.bits with
        | Error _ -> [ fragment ]
        | Ok ip ->
            (match Ip.TRX.reassemble_into fragments ip with
            | None -> [ fragment ]
            | Some payload ->
                let ip =
                    { ip with more_frags = false ; frag_offset = 0 ;
                              tot_len = 20 + Tools.bytelength ip.options +
                                        Tools.bytelength payload ;
                              payload = Payload.o payload } in
                [ fragment ;
                  { values = ip_values ip ; upper = Some (ip_upper ip) ;
                    payload ; up_hints = [] ; bits = Ip.Pdu.pack ip }, [ Driven ] ]) in
    let proto fields hints = int_of ~hints fields "IP" "proto" 0 0xff in
    { pack = (fun fields hints payload ->
        let int ~def name hi = int_of ~def fields "IP!" name 0 hi
        and options = bytes_of fields "options" in
        if Tools.bytelength options mod 4 <> 0 || Tools.bytelength options > 40 then
            V.fail "The options of IP must be a multiple of 4 bytes, up to 40" ;
        let tot_len = opt_int fields "tot_len" 0 0xffff in
        if tot_len = None &&
           20 + Tools.bytelength options + Tools.bytelength payload > 0xffff then
            V.fail "Too long for an IP packet" ;
        let id = Option.default_delayed next_id (opt_int fields "id" 0 0xffff) in
        Ip.Pdu.make ~tos:(Ip.ToS.o (int ~def:0 "tos" 0xff)) ?tot_len ~id
            ~dont_frag:(bool_of fields "dont_frag" ~def:false)
            ~more_frags:(bool_of fields "more_frags" ~def:false)
            ~frag_offset:(int ~def:0 "frag_offset" 0x1fff)
            ~ttl:(int ~def:64 "ttl" 0xff) ~options
            (Ip.Proto.o (proto fields hints))
            (ip_of fields "src") (ip_of fields "dst") payload |>
        Ip.Pdu.pack, [ "proto", V.Int ip4 ]) ;
      send = (fun fields hints payload ->
        if Tools.bytelength payload = 0 then
            V.fail "A self-driven IP sends no empty packet: use IP!" ;
        let proto = proto fields hints in
        let t =
            match Hashtbl.find_option trxs proto with
            | Some t -> t
            | None ->
                let t =
                    Ip.TRX.create st.iface.widget.power ~mtu:st.mtu ~next_id
                        (ip_of fields "src") (ip_of fields "dst")
                        (Ip.Proto.o proto) st.iface.widget.logger in
                Tools.((Ip.TRX.trx_of t).out -->
                    sink (below.send (fun _ -> None) [ "proto", V.Int ip4 ])) ;
                Hashtbl.add trxs proto t ;
                t in
        Ip.TRX.tx ?tos:(Option.map Ip.ToS.o (opt_int fields "tos" 0 0xff))
                  ?ttl:(opt_int fields "ttl" 0 0xff)
                  ?dont_frag:(opt_bool fields "dont_frag") t payload) ;
      receive }

let unpack_udp _ bits =
    match Udp.Pdu.unpack bits with
    | Error _ -> None
    | Ok u ->
        let payload = (u.payload :> bitstring) in
        unpacked [ "src", V.Int (u.src_port :> int) ; "dst", V.Int (u.dst_port :> int) ;
                   "length", V.Int u.length ; "checksum", V.Int u.checksum ]
                 ?upper:(if bitstring_length payload > 0 then Some "Bytes" else None)
                 ~payload bits

(* The checksum is left to IP: *)
let udp_node _ =
    { pack = (fun fields _ payload ->
        let port name = Udp.Port.o (int_of fields "UDP" name 0 0xffff) in
        let length = opt_int fields "length" 0 0xffff in
        if length = None && 8 + Tools.bytelength payload > 0xffff then
            V.fail "Too long for a UDP datagram" ;
        Udp.Pdu.make ~src_port:(port "src") ~dst_port:(port "dst") ?length
                     ?checksum:(opt_int fields "checksum" 0 0xffff) payload |>
        Udp.Pdu.pack, [ "proto", V.Int (Ip.Proto.udp :> int) ]) ;
      send = not_driven ; receive = pass }

let tcp_node _ =
    let unsupported _ _ _ = V.fail "TCP is not supported yet" in
    { pack = unsupported ; send = unsupported ; receive = pass }

let icmp_upper = function
    | 0 | 8 -> Some "Echo"
    | 3 -> Some "DestUnreachable"
    | 11 -> Some "TimeExceeded"
    | _ -> None

(* What is on top is what follows the checksum, and is told the type and
 * code: *)
let unpack_icmp _ bits =
    match%bitstring bits with
    | {| typ : 8 ; code : 8 ; _checksum : 16 ; payload : -1 : bitstring |} ->
        unpacked [ "type", V.Int typ ; "code", V.Int code ] ?upper:(icmp_upper typ)
                 ~up_hints:[ "type", V.Int typ ; "code", V.Int code ] ~payload bits
    | {| _ |} -> None

(* The message on top tells the type and code, and its own bits are what
 * follows them: *)
let icmp_node _ =
    { pack = (fun _ hints payload ->
        let int name =
            match List.assoc_opt name hints with
            | Some v -> int_value name 0 0xff v
            | None -> V.fail "ICMP needs a message on top" in
        let typ = int "type" and code = int "code" in
        let msg chk =
            let%bitstring hdr = {| typ : 8 ; code : 8 ; chk : 16 |} in
            concat [ hdr ; payload ] in
        msg (Tools.sum (msg 0)), [ "proto", V.Int (Ip.Proto.icmp :> int) ]) ;
      send = not_driven ; receive = pass }

(* The message on top is told by the type: *)
let unpack_echo hints bits =
    match%bitstring bits with
    | {| id : 16 ; payload : -1 : bitstring |} ->
        let upper =
            match List.assoc_opt "type" hints with
            | Some (V.Int 8) -> Some "Request"
            | Some (V.Int 0) -> Some "Reply"
            | _ -> None in
        unpacked [ "id", V.Int id ] ?upper ~payload bits
    | {| _ |} -> None

(* The id of the stream; the message on top tells its type: *)
let echo_node _ =
    { pack = (fun fields hints payload ->
        let id = int_of fields "Echo" "id" 0 0xffff in
        let%bitstring hdr = {| id : 16 |} in
        concat [ hdr ; payload ], hints) ;
      send = not_driven ; receive = pass }

let unpack_echo_message _ bits =
    match%bitstring bits with
    | {| seq : 16 ; payload : -1 : bitstring |} ->
        unpacked [ "seq", V.Int seq ; "payload", bytes_value payload ] bits
    | {| _ |} -> None

(* Its node lasts as long as its Echo, so the sequence numbers count from 1
 * along the stream, unless given: *)
let echo_message_node typ _ =
    let seq = ref 0 in
    { pack = (fun fields _ _ ->
        let seq =
            match opt_int fields "seq" 0 0xffff with
            | Some s -> s
            | None -> seq := (!seq + 1) land 0xffff ; !seq in
        let%bitstring hdr = {| seq : 16 |} in
        concat [ hdr ; bytes_of fields "payload" ],
        [ "type", V.Int typ ; "code", V.Int 0 ]) ;
      send = not_driven ; receive = pass }

let unpack_icmp_error ~mtu hints bits =
    match%bitstring bits with
    | {| _ : 16 ; mtu_value : 16 ; payload : -1 : bitstring |} ->
        unpacked ((if mtu then [ "mtu", V.Int mtu_value ] else []) @
                  [ "code", List.assoc_opt "code" hints |? V.Int 0 ;
                    "payload", bytes_value payload ]) bits
    | {| _ |} -> None

let icmp_error_node typ ~mtu _ =
    { pack = (fun fields _ _ ->
        let code = int_of ~def:0 fields "ICMP" "code" 0 0xff
        and mtu = if mtu then int_of ~def:0 fields "ICMP" "mtu" 0 0xffff else 0 in
        let%bitstring hdr = {| 0 : 16 ; mtu : 16 |} in
        concat [ hdr ; bytes_of fields "payload" ],
        [ "type", V.Int typ ; "code", V.Int code ]) ;
      send = not_driven ; receive = pass }

let unpack_bytes _ bits = unpacked [ "data", bytes_value bits ] bits

let bytes_node _ =
    { pack = (fun fields _ _ -> bytes_of fields "data", []) ;
      send = not_driven ; receive = pass }

(** {2 Layers} *)

type layer =
    { name : string ;
      (* The layers it can be on top of, by name; none for the root: *)
      above : string list ;
      (* Whether it has a self-driven mode distinct from the manual one; for
       * those that have not, a bang is ignored and they behave manually: *)
      driven : bool ;
      (* Whether nothing can be on top of it. Emitting a terminal layer is
       * what sends packets: *)
      terminal : bool ;
      fields : field array ;
      (* The index of the field that a lone option, or a lone condition that
       * is not a boolean, is about ([Bytes("x")]): *)
      default_field : int option ;
      (* The constants for its fields ([flags & RST]): *)
      constants : (string * literal) list ;
      (* The operations of a new node of this layer: *)
      node : context -> ops ;
      (* Decodes this layer of a received packet, given the hints of the
       * layer below: *)
      unpack : hints -> bitstring -> unpacked option }

let field ?(set_in=[ Manual ]) ?(read_in=[ Manual ]) ?(discriminant=false)
          ?pick ?peer name typ =
    { name ; typ ; set_in ; read_in ; discriminant ; pick ; peer = peer |? name }

let random_port = Random_in (49152, 65535)

let unsendable name _ =
    let fail _ _ _ = V.fail "%s cannot be sent" name in
    { pack = fail ; send = fail ; receive = pass }

let layer ?(above=[]) ?(driven=false) ?(terminal=false) ?default
          ?(constants=[]) ?node ?(unpack=fun _ _ -> None) name fields =
    let fields = Array.of_list fields in
    let default_field =
        Option.map (fun d ->
            try Array.findi (fun (f : field) -> f.name = d) fields
            with Not_found ->
                invalid_arg ("Crafty_layers: no field "^ d ^" in "^ name)
        ) default in
    { name ; above ; driven ; terminal ; fields ; default_field ; constants ;
      node = node |? unsendable name ; unpack }

let eth =
    layer "Eth" ~driven:true ~node:eth_node ~unpack:unpack_eth [
        field "src" Type.Mac ~read_in:both ;
        field "dst" Type.Mac ~read_in:both ;
        field "proto" Type.Int ~read_in:both ~discriminant:true ]

let ip =
    layer "IP" ~above:[ "eth" ] ~driven:true ~node:ip_node ~unpack:unpack_ip [
        field "src" Type.Ip ~set_in:both ~read_in:both ~discriminant:true
              ~pick:Local_address ~peer:"dst" ;
        field "dst" Type.Ip ~set_in:both ~read_in:both ~discriminant:true
              ~pick:Required ~peer:"src" ;
        field "proto" Type.Int ~set_in:both ~read_in:both ~discriminant:true ;
        field "tos" Type.Int ~set_in:both ~read_in:both ;
        field "ttl" Type.Int ~set_in:both ~read_in:both ;
        field "dont_frag" Type.Bool ~set_in:both ~read_in:both ;
        field "id" Type.Int ;
        field "more_frags" Type.Bool ;
        field "frag_offset" Type.Int ;
        field "tot_len" Type.Int ;
        field "options" Type.bytes ;
        field "is_fragment" Type.Bool ~set_in:[] ]

let tcp =
    layer "TCP" ~above:[ "ip" ] ~driven:true ~node:tcp_node
        ~constants:[ "FIN", Int 1 ; "SYN", Int 2 ; "RST", Int 4 ; "PSH", Int 8 ;
                     "ACK", Int 16 ; "URG", Int 32 ] [
        field "src" Type.Int ~set_in:both ~read_in:both ~discriminant:true
              ~pick:random_port ~peer:"dst" ;
        field "dst" Type.Int ~set_in:both ~read_in:both ~discriminant:true
              ~pick:Required ~peer:"src" ;
        field "seq_num" Type.Int ;
        field "ack_num" Type.Int ;
        field "flags" Type.Int ;
        field "win_size" Type.Int ;
        field "urg_ptr" Type.Int ;
        field "mss" Type.Int ~set_in:[ Driven ] ~read_in:[] ]

let udp =
    layer "UDP" ~above:[ "ip" ] ~node:udp_node ~unpack:unpack_udp [
        field "src" Type.Int ~discriminant:true ~pick:random_port ~peer:"dst" ;
        field "dst" Type.Int ~discriminant:true ~pick:Required ~peer:"src" ;
        field "length" Type.Int ;
        field "checksum" Type.Int ]

(* The kind of message is told by the layer on top of it: *)
let icmp =
    layer "ICMP" ~above:[ "ip" ] ~node:icmp_node ~unpack:unpack_icmp [
        field "type" Type.Int ~set_in:[] ;
        field "code" Type.Int ~set_in:[] ]

(* The stream of the requests and replies of an id: *)
let echo =
    layer "Echo" ~above:[ "icmp" ] ~node:echo_node ~unpack:unpack_echo [
        field "id" Type.Int ~discriminant:true ~pick:(Random_in (0, 65535)) ]

let echo_message name typ =
    layer name ~above:[ "echo" ] ~terminal:true ~default:"payload"
          ~node:(echo_message_node typ) ~unpack:unpack_echo_message [
        field "seq" Type.Int ;
        field "payload" Type.bytes ]

(* Whose payload is the beginning of the packet that caused it, kept as
 * bytes: *)
let icmp_error name typ codes ~mtu =
    layer name ~above:[ "icmp" ] ~terminal:true ~default:"payload"
          ~node:(icmp_error_node typ ~mtu) ~unpack:(unpack_icmp_error ~mtu)
        ~constants:(List.map (fun (n, c) -> n, Int c) codes) (
        field "code" Type.Int ::
        (if mtu then [ field "mtu" Type.Int ] else []) @
        [ field "payload" Type.bytes ])

let dest_unreachable =
    icmp_error "DestUnreachable" 3 ~mtu:true Icmp.Unreachable.[
        "NET_UNREACHABLE", network ; "HOST_UNREACHABLE", host ;
        "PROTOCOL_UNREACHABLE", protocol ; "PORT_UNREACHABLE", port ;
        "FRAG_NEEDED", fragmentation_needed ;
        "SOURCE_ROUTE_FAILED", source_route_failed ]

let time_exceeded =
    icmp_error "TimeExceeded" 11 ~mtu:false
        [ "TTL_EXCEEDED", 0 ; "REASSEMBLY_TIMEOUT", 1 ]

(* What is carried by a layer that is not decoded any further: *)
let bytes =
    layer "Bytes" ~above:[ "eth" ; "ip" ; "tcp" ; "udp" ] ~terminal:true
        ~node:bytes_node ~unpack:unpack_bytes
        ~default:"data" [ field "data" Type.bytes ]

let all =
    [ eth ; ip ; tcp ; udp ; icmp ; echo ; echo_message "Request" 8 ;
      echo_message "Reply" 0 ;
      dest_unreachable ; time_exceeded ; bytes ]

let same_name a b = String.lowercase_ascii a = String.lowercase_ascii b

(** All the names of layers, in lower case. *)
let names =
    List.map (fun (l : layer) -> String.lowercase_ascii l.name) all |>
    List.unique

let is_layer name = List.mem (String.lowercase_ascii name) names

(** The layer of that name that can be on top of [below], or that is the
 * root if no [below]. *)
let find ?below name =
    List.find_opt (fun (l : layer) ->
        same_name l.name name &&
        match below with
        | None -> l.above = []
        | Some (b : layer) -> List.exists (same_name b.name) l.above) all

(** The layers that can be on top of [l]. *)
let uppers (l : layer) =
    List.filter (fun (u : layer) -> List.exists (same_name l.name) u.above) all

let root = eth

(** The index of that field of [l]. *)
let find_field (l : layer) name =
    try Some (Array.findi (fun (f : field) -> same_name f.name name) l.fields)
    with Not_found -> None

(** All the constants, of all the layers. *)
let constants = List.concat_map (fun (l : layer) -> l.constants) all

(** The value of that constant. *)
let find_constant name =
    List.find_opt (fun (n, _) -> same_name n name) constants |>
    Option.map snd

(** The indices of the discriminants of [l] that are not told by the layer
 * on top: what tells apart its nodes under a same parent. *)
let key_fields (l : layer) =
    Array.to_list l.fields |>
    List.mapi (fun i (f : field) -> i, f) |>
    List.filter_map (fun (i, (f : field)) ->
        if f.pick <> None then Some i else None)

(** The mode a layer runs in when written with a bang or not. *)
let mode_of (l : layer) ~bang =
    if bang || not l.driven then Manual else Driven

(** The record of the fields of [l] that can be read in [mode], as found in a
 * matched packet. *)
let record_type (l : layer) mode =
    Type.Record (Array.to_list l.fields |> List.filter_map (fun (f : field) ->
        if List.mem mode f.read_in then Some (f.name, f.typ) else None))

(*$T find
  (find "eth" |> Option.map (fun (l : layer) -> l.name)) = Some "Eth"
  find "IP" = None
  (find ~below:eth "ip" |> Option.map (fun (l : layer) -> l.name)) = Some "IP"
  (find ~below:echo "reQUEST" |> Option.map (fun (l : layer) -> l.name)) = \
    Some "Request"
  find ~below:icmp "Request" = None
  find ~below:tcp "Bytes" <> None
  find ~below:bytes "Bytes" = None
*)
(*$T find_field
  find_field bytes "DATA" = Some 0
  find_field tcp "mss" = Some 7
  find_field tcp "payload" = None
*)
(* Defaults are found by name: *)
(*$T
  bytes.default_field = Some 0
  (echo_message "Request" 8).default_field = Some 1
  tcp.default_field = None
*)
(*$T key_fields
  key_fields ip = [ 0 ; 1 ]
  key_fields icmp = []
  key_fields echo = [ 0 ]
  key_fields (echo_message "Reply" 0) = []
*)
(*$T find_constant
  find_constant "rst" = Some (Crafty_ast.Int 4)
  find_constant "port_unreachable" = Some (Crafty_ast.Int 3)
  find_constant "src" = None
*)
(*$= record_type & ~printer:Crafty_ast.Type.to_string
  (Crafty_ast.Type.Record [ "src", Crafty_ast.Type.Int ; "dst", Crafty_ast.Type.Int ]) (record_type tcp Driven)
  (Crafty_ast.Type.Record [ "data", Crafty_ast.Type.bytes ]) (record_type bytes Manual)
*)
(* The registry holds together: *)
(*$T
  List.for_all (fun (l : layer) -> \
      List.for_all (fun b -> is_layer b) l.above) all
  List.for_all (fun (l : layer) -> \
      l.terminal = (uppers l = [])) all
  List.length (List.filter (fun (l : layer) -> l.above = []) all) = 1
  List.for_all (fun (l : layer) -> \
      l.driven || List.for_all (fun (f : field) -> \
        not (List.mem Driven f.set_in) && not (List.mem Driven f.read_in)) \
        (Array.to_list l.fields)) all
  List.for_all (fun (l : layer) -> \
      Array.for_all (fun (f : field) -> \
        f.pick = None || (f.discriminant && f.set_in <> [])) l.fields) all
  List.for_all (fun (l : layer) -> \
      let names = List.map (fun (f : field) -> String.lowercase_ascii f.name) \
                      (Array.to_list l.fields) in \
      List.length (List.unique names) = List.length names) all
  List.for_all (fun (l : layer) -> List.for_all (fun (b : layer) -> \
      l == b || not (same_name l.name b.name) || \
      List.for_all (fun a -> not (List.exists (same_name a) b.above)) l.above) all) all
*)
(* Constants are names of their own, apart from any other: *)
(*$T
  let names = List.map (fun (n, _) -> String.lowercase_ascii n) constants in \
  List.length (List.unique names) = List.length names && \
  List.for_all (fun n -> \
      not (is_layer n) && \
      not (List.mem n Crafty_ast.(keywords @ unsupported @ functions @ predefined)) && \
      List.for_all (fun (l : layer) -> find_field l n = None) all) names
*)
