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

   Names of layers and fields are case insensitive; constants are upper
   case. Constants are reserved names, valid anywhere, as are the layers.

   Each layer also tells how its nodes in the tree of parsers send: building
   its header in manual mode, filling in what the stack leaves out, or
   handing the payload to a robinet TRX in self-driven mode. And how a
   received packet is decoded, layer by layer, each telling what is on top
   of it. *)
open Batteries
open Bitstring
open Crafty_ast
module V = Crafty_value
module N = Layer_name

(** A layer is either crafted packet by packet ([Manual], written with a
 * bang), or left to a robinet TRX that drives a whole stream ([Driven]). *)
type mode = Manual | Driven

let string_of_mode = function Manual -> "manual" | Driven -> "self-driven"

(** How a discriminant that a stack leaves out is chosen: *)
type pick =
    | Required
    (* Told by the layer on top, as the first message is sent, and else
     * required: *)
    | Told
    (* The IPv4 address of the interface: *)
    | Local_address
    (* At random within these bounds, and distinct from the siblings': *)
    | Random_in of int * int
    (* As [Random_in], within the port ranges of the tree for that layer: *)
    | Local_port

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
      peer : string ;
      (* What a self-driven layer sends when it is not given, if that is
       * known before it sends: *)
      driven_default : V.value option }

(* Instantiated only once so can be compared with == and != *)
(** {2 Nodes}
 *
 * What a node of the tree of parsers does with the packets of its layer,
 * behind closures that keep its state (counters, TRXs). *)

(** What a layer tells the layer below it about itself, by the names of the
 * fields of that one (the protocol of IP, the type of ICMP, the port of a
 * DNS server...): *)
type hints = (string * V.value) list

(** The fields of a node by name: its key and the options of a stack. *)
type fields = string -> V.value option

(** What a decoded layer tells of the layer on top of it: *)
type upper =
    | Nothing
    (* The one its header names (the protocol of IP): *)
    | Only of N.t
    (* Whichever can be on top of it, as each decodes it; but for this one
     * when there is nothing to go by: *)
    | Any of N.t

(** A layer of a received packet, decoded: *)
type unpacked =
    { (* The fields that can be read, by name: *)
      values : (string * V.value) list ;
      upper : upper ;
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
      receive : unpacked -> (unpacked * mode list) list ;
      (* A self-driven pattern made the node (TCP accepts a connection): *)
      listen : unit -> unit ;
      (* The node is no longer used: once what it has to finish is (TCP
       * closing), the continuation removes it: *)
      close : (unit -> unit) -> unit ;
      (* How long what is sent now would wait in this node before it
       * leaves it, for senders to pace themselves on: *)
      busy_for : unit -> Clock.Interval.t ;
      (* Self-driven, it keeps what it is given until it can send it (TCP),
       * so that how busy the nodes below it are is no concern of senders: *)
      buffered : bool ;
      (* Calls the function, once, from an event of its own, when the node
       * is no longer busy, if it can tell sooner than [busy_for] did (TCP,
       * once connected or once its send buffer drained); or never: *)
      on_ready : (unit -> unit) -> unit ;
      (* What it tells of its stream, by name, among the [stats] of its layer
       * or the counts of {!stream_stats}, which it then replaces: *)
      stats : unit -> (string * V.value) list }

(** What a node is made with: *)
type context =
    { eth : Eth.State.t ;
      (* Its own key, and that of the node below: *)
      key : fields ;
      below_key : fields ;
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

(* The operations of a node with no stream, building a header in manual
 * mode: *)
let manual pack =
    { pack ; send = not_driven ; receive = pass ;
      listen = ignore ; close = (fun k -> k ()) ; busy_for = Tools.never_busy ;
      buffered = false ; on_ready = ignore ; stats = (fun () -> []) }

let bytes_value bits = V.bytes_of_string (string_of_bitstring bits)

let unpacked ?(upper=Nothing) ?(up_hints=[]) ?(payload=empty_bitstring) values bits =
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
        (* [ts] is for the receiver to tell: *)
        unpacked [ "src", V.Mac e.src ; "dst", V.Mac e.dst ; "proto", V.Int proto ;
                   "ts", V.Time (Clock.Wall.of_secs 0.) ]
                 ~upper:(Only (if proto = ip4 then N.IP else N.Bytes))
                 ~payload:(e.payload :> bitstring) bits

(* The root: an Ethernet interface, which a self-driven Eth sends IPv4
 * through, resolving with ARP. It answers ARP itself, and takes the frames
 * for its address, or all of them if promiscuous: *)
let eth_node ctx =
    let st = ctx.eth in
    let trx = Eth.TRX.make st in
    let receive (u : unpacked) =
        match List.assoc "proto" u.values, List.assoc "dst" u.values with
        | V.Int p, _ when p = (Eth.Proto.arp :> int) ->
            Eth.TRX.rx st u.bits ;
            []
        | _, V.Mac dst when st.promisc <> None || Eth.Addr.eq dst st.mac ||
                            Eth.Addr.eq dst Eth.Addr.broadcast ->
            pass u
        | _ -> [] in
    { (manual @@ fun fields hints payload ->
        let proto = int_of ~hints fields "Eth!" "proto" 0 0xffff in
        let src = match fields "src" with Some (V.Mac m) -> m | _ -> st.mac in
        let dst =
            match fields "dst" with
            | Some (V.Mac m) -> m
            | _ -> next_mac st proto payload in
        Eth.Pdu.(pack (make (Eth.Proto.o proto) src dst payload)), []) with
      send = (fun _ hints payload ->
        if List.assoc_opt "proto" hints <> Some (V.Int ip4) then
            V.fail "A self-driven Eth carries only IPv4: use Eth!" ;
        Tools.tx trx payload) ;
      receive ;
      busy_for = Eth.Iface.tx_busy_for st.iface }

let ip_upper (ip : Ip.Pdu.t) =
    if Ip.Pdu.is_fragment ip then N.Bytes
    else if ip.proto = Ip.Proto.icmp then N.ICMP
    else if ip.proto = Ip.Proto.udp then N.UDP
    else if ip.proto = Ip.Proto.tcp then N.TCP
    else N.Bytes

let ip_values (ip : Ip.Pdu.t) =
    [ "src", V.Ip ip.src ; "dst", V.Ip ip.dst ; "proto", V.Int (ip.proto :> int) ;
      "tos", V.Int (ip.tos :> int) ; "ttl", V.Int ip.ttl ;
      "dont_frag", V.Bool ip.dont_frag ; "id", V.Int ip.id ;
      "more_frags", V.Bool ip.more_frags ; "frag_offset", V.Int ip.frag_offset ;
      "tot_len", V.Int ip.tot_len ; "options", bytes_value (Ip.Pdu.Opt.pack ip.options) ;
      "is_fragment", V.Bool (Ip.Pdu.is_fragment ip) ]

(* A fragment goes on as bytes: *)
let unpack_ip _ bits =
    match Ip.Pdu.unpack bits with
    | Error _ -> None
    | Ok ip ->
        unpacked (ip_values ip) ~upper:(Only (ip_upper ip))
                 ~payload:(ip.payload :> bitstring) bits

let ip_proto fields hints = int_of ~hints fields "IP" "proto" 0 0xff

(* Bytes in crafty, that unpack to options that pack back to them: *)
let ip_options fields =
    let options = bytes_of fields "options" in
    if Tools.bytelength options mod 4 <> 0 || Tools.bytelength options > 40 then
        V.fail "The options of IP must be a multiple of 4 bytes, up to 40" ;
    Ip.Pdu.Opt.unpack options

(* An IPv4 header as given around [payload], its id from [next_id] if not: *)
let pack_ip next_id fields hints payload =
    let int ~def name hi = int_of ~def fields "IP!" name 0 hi
    and options = ip_options fields in
    let tot_len = opt_int fields "tot_len" 0 0xffff in
    if tot_len = None &&
       20 + Tools.bytelength (Ip.Pdu.Opt.pack options) + Tools.bytelength payload > 0xffff then
        V.fail "Too long for an IP packet" ;
    let id = Option.default_delayed next_id (opt_int fields "id" 0 0xffff) in
    Ip.Pdu.make ~tos:(Ip.ToS.o (int ~def:0 "tos" 0xff)) ?tot_len ~id
        ~dont_frag:(bool_of fields "dont_frag" ~def:false)
        ~more_frags:(bool_of fields "more_frags" ~def:false)
        ~frag_offset:(int ~def:0 "frag_offset" 0x1fff)
        ~ttl:(int ~def:64 "ttl" 0xff) ~options
        (Ip.Proto.o (ip_proto fields hints))
        (ip_of fields "src") (ip_of fields "dst") payload |>
    Ip.Pdu.pack, [ "proto", V.Int ip4 ]

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
            (match Ip.TRX.reassemble_into st.iface.widget.power fragments ip with
            | None -> [ fragment ]
            | Some payload ->
                let ip =
                    { ip with more_frags = false ; frag_offset = 0 ;
                              tot_len = Ip.Pdu.hdr_len ip + Tools.bytelength payload ;
                              payload = Payload.o payload } in
                [ fragment ;
                  { values = ip_values ip ; upper = Only (ip_upper ip) ;
                    payload ; up_hints = [] ; bits = Ip.Pdu.pack ip }, [ Driven ] ]) in
    { (manual (pack_ip next_id)) with
      send = (fun fields hints payload ->
        if Tools.bytelength payload = 0 then
            V.fail "A self-driven IP sends no empty packet: use IP!" ;
        let proto = ip_proto fields hints
        and options = ip_options fields in
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
                  ?dont_frag:(opt_bool fields "dont_frag") ~options t payload) ;
      receive }

let unpack_udp _ bits =
    match Udp.Pdu.unpack bits with
    | Error _ -> None
    | Ok u ->
        let payload = (u.payload :> bitstring) in
        unpacked [ "src", V.Int (u.src_port :> int) ; "dst", V.Int (u.dst_port :> int) ;
                   "length", V.Int u.length ; "checksum", V.Int u.checksum ]
                 ~upper:(if bitstring_length payload > 0 then Any N.Bytes else Nothing)
                 ~payload bits

(* The checksum is left to IP: *)
let udp_node _ =
    manual (fun fields _ payload ->
        let port name = Udp.Port.o (int_of fields "UDP" name 0 0xffff) in
        let length = opt_int fields "length" 0 0xffff in
        if length = None && 8 + Tools.bytelength payload > 0xffff then
            V.fail "Too long for a UDP datagram" ;
        Udp.Pdu.make ~src_port:(port "src") ~dst_port:(port "dst") ?length
                     ?checksum:(opt_int fields "checksum" 0 0xffff) payload |>
        Udp.Pdu.pack, [ "proto", V.Int (Ip.Proto.udp :> int) ])

let tcp_proto = (Ip.Proto.tcp :> int)

(* Sequence numbers as unsigned ints: *)
let int_of_seq_num (n : Tcp.SeqNum.t) = Int32.to_int (n :> int32) land 0xffff_ffff

let unpack_tcp _ bits =
    match Tcp.Pdu.unpack bits with
    | Error _ -> None
    | Ok t ->
        let f = t.flags and bit b v = if b then v else 0 in
        let flags =
            bit f.fin 1 lor bit f.syn 2 lor bit f.rst 4 lor bit f.psh 8 lor
            bit f.ack 16 lor bit f.urg 32 in
        let payload = (t.payload :> bitstring) in
        unpacked [ "src", V.Int (t.src_port :> int) ; "dst", V.Int (t.dst_port :> int) ;
                   "seq_num", V.Int (int_of_seq_num t.seq_num) ;
                   "ack_num", V.Int (int_of_seq_num t.ack_num) ;
                   "flags", V.Int flags ; "win_size", V.Int t.win_size ;
                   "urg_ptr", V.Int t.urg_ptr ; "checksum", V.Int t.checksum ]
                 ~upper:(if bitstring_length payload > 0 then Any N.Bytes else Nothing)
                 ~payload bits

(* A connection: robinet's TRX, what was written before it was established,
 * whether it is to be closed, and what removes the node once it is: *)
type tcp_stream =
    { trx : Tcp.TRX.t ;
      mutable pending : bitstring list ;
      mutable closing : bool ;
      mutable on_closed : (unit -> unit) option }

type tcp_state = Idle | Listening | Stream of tcp_stream

(* A node without a connection is idle, or listening if a self-driven
 * pattern made it, until a SYN comes; the first packet sent self-driven
 * connects it, and waits for the connection, as what follows does. A
 * manual segment takes the sequence and ack numbers of the connection if not
 * given, and the connection then accounts for it. The connection's data is
 * seen in self-driven mode, as it comes in order, and each segment in manual
 * mode. Once the node is unused, the connection is closed after what was
 * written, and the node removed once both ends are closed (or after 2
 * minutes): *)
let tcp_node ctx =
    let st = ctx.eth and below = Option.get ctx.below in
    let power = st.iface.widget.power and logger = st.iface.widget.logger in
    let port name = Tcp.Port.o (int_of ctx.key "TCP" name 0 0xffff) in
    let state = ref Idle in
    (* What the connection hands while a segment is received: *)
    let received = ref [] in
    (* The sequence number of manual segments without a connection: *)
    let manual_seq = ref (Random.bits () lsl 2 land 0xffff_ffff) in
    let over s =
        let t = s.trx in
        t.closed && t.rcvd_fin && (t.sent_acked >= t.sent_pld || not t.rto_armed) in
    let removed s =
        match s.on_closed with
        | Some k when over s ->
            s.on_closed <- None ;
            Simulation.asap power k ()
        | _ -> () in
    let try_close s =
        if s.closing && Tcp.TRX.is_established s.trx && not s.trx.sent_fin then
            s.trx.tcp_trx.close () ;
        removed s in
    (* What is written before the connection is established waits for it, as
     * what fills the send buffer does: *)
    let busy_for () =
        match !state with
        | Stream s when List.fold_left (fun n b -> n + Tools.bytelength b) 0 s.pending
                        >= s.trx.snd_buf ->
            s.trx.rto
        | Stream s -> Tcp.TRX.busy_for s.trx ()
        | Idle | Listening -> Clock.Interval.zero in
    (* Those waiting for the node not to be busy, told when the connection is
     * established or fails, and as segments come in: *)
    let waiters = ref [] in
    let wake () =
        if Clock.Interval.compare (busy_for ()) Clock.Interval.zero <= 0 then (
            let ks = !waiters in
            waiters := [] ;
            List.iter (fun k -> Simulation.asap power k ()) ks) in
    let established s = function
        | Some _ ->
            List.iter (Tcp.TRX.tx s.trx) (List.rev s.pending) ;
            s.pending <- [] ;
            try_close s ;
            wake ()
        | None ->
            Tcp.TRX.abort s.trx ;
            s.pending <- [] ;
            removed s ;
            wake () in
    let new_stream ?(mss=st.mtu - 40) () =
        (match !state with
        | Stream s -> Tcp.TRX.abort s.trx ; removed s
        | _ -> ()) ;
        let t = Tcp.TRX.make power ~sync_recv:true ~mss (port "src") (port "dst") logger in
        Tools.(t.tcp_trx.trx.out --> sink (below.send ctx.below_key [ "proto", V.Int tcp_proto ])) ;
        Tools.(t.tcp_trx.trx.ins --> sink (fun bits ->
            if bitstring_length bits > 0 then received := bits :: !received)) ;
        let s = { trx = t ; pending = [] ; closing = false ; on_closed = None } in
        t.cnx_established_cont <- Some (established s) ;
        state := Stream s ;
        s in
    (* The connection to send to, a new one if there is none or it is being
     * closed (the node being used again): *)
    let stream fields =
        match !state with
        | Stream s when not s.closing -> s
        | _ ->
            let s = new_stream ?mss:(opt_int fields "mss" 1 0xffff) () in
            Tcp.TRX.connect s.trx (established s) ;
            s in
    { pack = (fun fields _ payload ->
        let trx = match !state with Stream s -> Some s.trx | _ -> None in
        Option.may (fun t ->
            if not (Tcp.TRX.is_established t || t.closed) then
                V.fail "TCP! cannot go into a connection that is not established yet") trx ;
        let given name = opt_int fields name 0 0xffff_ffff in
        let seq_given = given "seq_num" in
        let seq =
            match seq_given, trx with
            | Some n, _ -> n
            | None, Some t -> int_of_seq_num (Tcp.TRX.next_seq_num t)
            | None, None -> !manual_seq in
        let ack =
            match given "ack_num", trx with
            | Some n, _ -> Some n
            | None, Some t -> Option.map int_of_seq_num (Tcp.TRX.next_ack_num t)
            | None, None -> None in
        let flags =
            match opt_int fields "flags" 0 0x3f with
            | Some f -> f
            | None ->
                (if ack <> None then 16 else 0) lor
                (if bitstring_length payload > 0 then 8 else 0) in
        let bit b = flags land b <> 0 in
        let win_size =
            match opt_int fields "win_size" 0 0xffff, trx with
            | Some w, _ -> w
            | None, Some t -> Tcp.TRX.adv_wnd t
            | None, None -> 0xffff in
        let seq_num n = Tcp.SeqNum.o (Int32.of_int n) in
        let pdu =
            Tcp.Pdu.make ~src_port:(port "src") ~dst_port:(port "dst")
                ~seq_num:(seq_num seq) ~ack_num:(seq_num (ack |? 0))
                ~fin:(bit 1) ~syn:(bit 2) ~rst:(bit 4) ~psh:(bit 8) ~ack:(bit 16)
                ~urg:(bit 32) ~win_size
                ~urg_ptr:(int_of ~def:0 fields "TCP!" "urg_ptr" 0 0xffff)
                ?checksum:(opt_int fields "checksum" 0 0xffff) payload in
        (match seq_given, trx with
        | None, Some t -> Tcp.TRX.sent_manually t pdu
        | None, None ->
            manual_seq :=
                (seq + Tools.bytelength payload + (if bit 2 then 1 else 0) +
                 (if bit 1 then 1 else 0)) land 0xffff_ffff
        | Some _, _ -> ()) ;
        Tcp.Pdu.pack pdu, [ "proto", V.Int tcp_proto ]) ;
      send = (fun fields _ payload ->
        let s = stream fields in
        if bitstring_length payload > 0 then
            if s.trx.closed then V.fail "This TCP connection is closed"
            else if Tcp.TRX.is_established s.trx then Tcp.TRX.tx s.trx payload
            else s.pending <- payload :: s.pending) ;
      receive = (fun u ->
        (match !state, List.assoc "flags" u.values with
        | Listening, V.Int f when f land 2 <> 0 && f land 16 = 0 ->
            ignore (new_stream ())
        | _ -> ()) ;
        let raw = u, [ Manual ] in
        match !state with
        | Stream s ->
            received := [] ;
            Tools.rx s.trx.tcp_trx.trx u.bits ;
            let data = List.rev !received in
            received := [] ;
            removed s ;
            wake () ;
            (* What a segment that fills a gap releases comes up at once, as
             * a pattern matches at most once per segment: *)
            raw :: (match data with
                | [] -> []
                | data ->
                    let d = Bitstring.concat data in
                    [ { u with payload = d ; upper = Any N.Bytes ; bits = d }, [ Driven ] ])
        | Idle | Listening -> [ raw ]) ;
      listen = (fun () -> match !state with Idle -> state := Listening | _ -> ()) ;
      close = (fun k ->
        match !state with
        | Idle | Listening -> k ()
        | Stream s ->
            s.closing <- true ;
            s.on_closed <- Some k ;
            try_close s ;
            Simulation.delay power (Clock.Interval.min 2.) (fun () ->
                if Option.is_some s.on_closed then (
                    Tcp.TRX.abort s.trx ;
                    Option.may (fun k -> s.on_closed <- None ; k ()) s.on_closed)) ()) ;
      busy_for ; buffered = true ;
      on_ready = (fun k -> waiters := k :: !waiters) ;
      stats = (fun () ->
        match !state with
        | Idle | Listening -> []
        | Stream s ->
            let t = s.trx and c = s.trx.counters in
            let srtt, rttvar = t.rtt |? Clock.Interval.(zero, zero) in
            [ "packets_out", V.Int c.segs_out ; "bytes_out", V.Int c.bytes_out ;
              "packets_in", V.Int c.segs_in ; "bytes_in", V.Int c.bytes_in ;
              "bytes_acked", V.Int c.bytes_acked ;
              "bytes_received", V.Int c.bytes_received ;
              "retrans", V.Int c.retrans ; "dupacks", V.Int c.dupacks ;
              "timeouts", V.Int c.rto_expired ; "ooo_in", V.Int c.ooo_in ;
              "dup_in", V.Int c.dup_in ;
              "srtt", V.Interval srtt ; "rttvar", V.Interval rttvar ;
              "rtt_samples", V.Int c.rtt_samples ; "rto", V.Interval t.rto ;
              "snd_mss", V.Int t.snd_mss ; "rcv_mss", V.Int t.rcv_mss ;
              (* Infinite until a loss, which Linux tells as 2^31-1: *)
              "cwnd", V.Int t.cwnd ; "ssthresh", V.Int (min t.ssthresh 0x7fff_ffff) ;
              "snd_wnd", V.Int t.snd_wnd ; "rcv_wnd", V.Int (Tcp.TRX.rcv_wnd t) ;
              (* -1 for a side that offered no window scaling: *)
              "snd_wscale", V.Int (t.snd_wscale |? -1) ;
              "rcv_wscale", V.Int (if t.offered_wscale then t.rcv_wscale else -1) ;
              "established", V.Bool (Tcp.TRX.is_established t) ]) }

let icmp_upper = function
    | 0 | 8 -> Only N.Echo
    | 3 -> Only N.DestUnreachable
    | 11 -> Only N.TimeExceeded
    | _ -> Nothing

(* What is on top is what follows the checksum, and is told the type and
 * code: *)
let unpack_icmp _ bits =
    match%bitstring bits with
    | {| typ : 8 ; code : 8 ; _checksum : 16 ; payload : -1 : bitstring |} ->
        unpacked [ "type", V.Int typ ; "code", V.Int code ] ~upper:(icmp_upper typ)
                 ~up_hints:[ "type", V.Int typ ; "code", V.Int code ] ~payload bits
    | {| _ |} -> None

(* The message on top tells the type and code, and its own bits are what
 * follows them: *)
let icmp_node _ =
    manual (fun _ hints payload ->
        let int name =
            match List.assoc_opt name hints with
            | Some v -> int_value name 0 0xff v
            | None -> V.fail "ICMP needs a message on top" in
        let typ = int "type" and code = int "code" in
        let msg chk =
            let%bitstring hdr = {| typ : 8 ; code : 8 ; chk : 16 |} in
            concat [ hdr ; payload ] in
        msg (Tools.sum (msg 0)), [ "proto", V.Int (Ip.Proto.icmp :> int) ])

(* The message on top is told by the type: *)
let unpack_echo hints bits =
    match%bitstring bits with
    | {| id : 16 ; payload : -1 : bitstring |} ->
        let upper =
            match List.assoc_opt "type" hints with
            | Some (V.Int 8) -> Only N.Request
            | Some (V.Int 0) -> Only N.Reply
            | _ -> Nothing in
        unpacked [ "id", V.Int id ] ~upper ~payload bits
    | {| _ |} -> None

(* The id of the stream; the message on top tells its type: *)
let echo_node _ =
    manual (fun fields hints payload ->
        let id = int_of fields "Echo" "id" 0 0xffff in
        let%bitstring hdr = {| id : 16 |} in
        concat [ hdr ; payload ], hints)

let unpack_echo_message _ bits =
    match%bitstring bits with
    | {| seq : 16 ; payload : -1 : bitstring |} ->
        unpacked [ "seq", V.Int seq ; "payload", bytes_value payload ] bits
    | {| _ |} -> None

(* Its node lasts as long as its Echo, so the sequence numbers count from 1
 * along the stream, unless given: *)
let echo_message_node typ _ =
    let seq = ref 0 in
    manual (fun fields _ _ ->
        let seq =
            match opt_int fields "seq" 0 0xffff with
            | Some s -> s
            | None -> seq := (!seq + 1) land 0xffff ; !seq in
        let%bitstring hdr = {| seq : 16 |} in
        concat [ hdr ; bytes_of fields "payload" ],
        [ "type", V.Int typ ; "code", V.Int 0 ])

(* What is on top is the start of the packet it is about: *)
let unpack_icmp_error ~mtu hints bits =
    match%bitstring bits with
    | {| _ : 16 ; mtu_value : 16 ; payload : -1 : bitstring |} ->
        unpacked ((if mtu then [ "mtu", V.Int mtu_value ] else []) @
                  [ "code", List.assoc_opt "code" hints |? V.Int 0 ])
                 ~upper:(if bitstring_length payload > 0 then Any N.IP else Nothing)
                 ~payload bits
    | {| _ |} -> None

let icmp_error_node typ ~mtu _ =
    manual (fun fields _ payload ->
        let code = int_of ~def:0 fields "ICMP" "code" 0 0xff
        and mtu = if mtu then int_of ~def:0 fields "ICMP" "mtu" 0 0xffff else 0 in
        let%bitstring hdr = {| 0 : 16 ; mtu : 16 |} in
        concat [ hdr ; payload ],
        [ "type", V.Int typ ; "code", V.Int code ])

(* Quoted packets, which are often cut short: as much of them as there is,
 * with no stream, nor anything of the state of one. *)

(* Of the protocols on top, those that can be quoted: *)
let unpack_quoted_ip _ bits =
    match Ip.Pdu.unpack bits with
    | Error _ -> None
    | Ok ip ->
        let upper = match ip_upper ip with N.ICMP -> N.Bytes | u -> u in
        unpacked (ip_values ip) ~upper:(Only upper)
                 ~payload:(ip.payload :> bitstring) bits

(* Ids count from a random one, as nothing else tells them: *)
let quoted_ip_node _ =
    let id = ref (Random.int 0x10000) in
    let next_id () = id := (!id + 1) land 0xffff ; !id in
    manual (fun fields hints payload ->
        List.iter (fun n ->
            if fields n = None then V.fail "A quoted IP needs a %s" n) [ "src" ; "dst" ] ;
        pack_ip next_id fields hints payload)

(* Whatever the length says, the payload is what is left: *)
let unpack_quoted_udp _ bits =
    match%bitstring bits with
    | {| src : 16 ; dst : 16 ; length : 16 ; checksum : 16 ;
         rest : -1 : bitstring |} ->
        let payload =
            takebits (min (bitstring_length rest) (max 0 (length - 8) * 8)) rest in
        unpacked [ "src", V.Int src ; "dst", V.Int dst ;
                   "length", V.Int length ; "checksum", V.Int checksum ]
                 ~upper:(if bitstring_length payload > 0 then Only N.Bytes else Nothing)
                 ~payload bits
    | {| _ |} -> None

(* Only the ports and the sequence number are sure to be quoted; the other
 * fields read 0 when cut off: *)
let unpack_quoted_tcp _ bits =
    let u32 n = Int32.to_int n land 0xffff_ffff in
    match%bitstring bits with
    | {| src : 16 ; dst : 16 ; seq_num : 32 ; rest : -1 : bitstring |} ->
        let ack_num, flags, win_size, checksum, urg_ptr, payload =
            match%bitstring rest with
            | {| ack_num : 32 ; hdr_len : 4 ; _ : 6 ; flags : 6 ; win_size : 16 ;
                 checksum : 16 ; urg_ptr : 16 ; rest : -1 : bitstring |} ->
                let options = max 0 (hdr_len * 32 - 160) in
                u32 ack_num, flags, win_size, checksum, urg_ptr,
                (if bitstring_length rest > options then dropbits options rest
                 else empty_bitstring)
            | {| _ |} -> 0, 0, 0, 0, 0, empty_bitstring in
        unpacked [ "src", V.Int src ; "dst", V.Int dst ;
                   "seq_num", V.Int (u32 seq_num) ; "ack_num", V.Int ack_num ;
                   "flags", V.Int flags ; "win_size", V.Int win_size ;
                   "urg_ptr", V.Int urg_ptr ; "checksum", V.Int checksum ]
                 ~upper:(if bitstring_length payload > 0 then Only N.Bytes else Nothing)
                 ~payload bits
    | {| _ |} -> None

(* A segment as given, without a connection to take numbers from: *)
let quoted_tcp_node _ =
    manual (fun fields _ payload ->
        let int ?def name hi = int_of ?def fields "TCP" name 0 hi in
        let flags =
            int ~def:(if bitstring_length payload > 0 then 8 else 0) "flags" 0x3f in
        let bit b = flags land b <> 0
        and seq_num name = Tcp.SeqNum.o (Int32.of_int (int ~def:0 name 0xffff_ffff)) in
        Tcp.Pdu.make ~src_port:(Tcp.Port.o (int "src" 0xffff))
            ~dst_port:(Tcp.Port.o (int "dst" 0xffff))
            ~seq_num:(seq_num "seq_num") ~ack_num:(seq_num "ack_num")
            ~fin:(bit 1) ~syn:(bit 2) ~rst:(bit 4) ~psh:(bit 8) ~ack:(bit 16)
            ~urg:(bit 32) ~win_size:(int ~def:0xffff "win_size" 0xffff)
            ~urg_ptr:(int ~def:0 "urg_ptr" 0xffff)
            ?checksum:(opt_int fields "checksum" 0 0xffff) payload |>
        Tcp.Pdu.pack, [ "proto", V.Int tcp_proto ])

let unpack_bytes _ bits = unpacked [ "data", bytes_value bits ] bits

let bytes_node _ =
    manual (fun fields _ _ -> bytes_of fields "data", [])

(* The message on top is given the whole of it, as its names can point
 * anywhere in it: *)
let unpack_dns _ bits =
    match Dns.Pdu.unpack bits with
    | Error _ -> None
    | Ok m ->
        unpacked [ "id", V.Int m.id ]
                 ~upper:(Only (if m.is_query then N.Query else N.Answer))
                 ~payload:bits bits

(* The id of the stream, over that of the whole message on top; a server is
 * on port 53: *)
let dns_node _ =
    manual (fun fields _ payload ->
        let id = int_of fields "DNS" "id" 0 0xffff in
        let%bitstring hdr = {| id : 16 |} in
        concat [ hdr ; dropbits 16 payload ], [ "dst", V.Int 53 ])

(* As written, without the root label every name but the root ends with: *)
let dns_name n = if n = "." then n else String.rchop n

let dns_fqdn layer = function
    | V.String n ->
        (try Dns.Pdu.fqdn n
        with Invalid_argument _ -> V.fail "%s: %S is not a DNS name" layer n)
    | _ -> invalid_arg "Crafty_layers: a DNS name is not a string"

(* With its fields in the order of [dns_rr], those of a record: *)
let dns_rr_value (name, (typ : Dns.QType.t), cls, ttl, data) =
    V.Record [| V.Int cls ; V.bytes_of_string (Bytes.to_string data) ;
                V.String (dns_name name) ; V.Int (Tools.uint32 ttl) ;
                V.Int (typ :> int) |]

let dns_rrs_of layer (fields : fields) name =
    match fields name with
    | None -> []
    | Some (V.Array rrs) ->
        Array.to_list rrs |> List.map (function
            | V.Record [| cls ; data ; n ; ttl ; typ |] ->
                dns_fqdn layer n, Dns.QType.o (int_value "type" 0 0xffff typ),
                int_value "class" 0 0xffff cls,
                Int32.of_int (int_value "ttl" 0 0xffff_ffff ttl),
                Bytes.of_string (string_of_bitstring (V.bits_of_bytes data))
            | _ -> invalid_arg "Crafty_layers: not a DNS record")
    | Some _ -> invalid_arg ("Crafty_layers: "^ name ^" is not an array")

(* Of the questions of a message, the first: *)
let unpack_dns_message _ bits =
    match Dns.Pdu.unpack bits with
    | Error _ -> None
    | Ok m ->
        let name, typ, cls =
            match m.questions with
            | (n, t, c) :: _ -> dns_name n, (t : Dns.QType.t :> int), c
            | [] -> "", 0, 0 in
        let rrs l = V.Array (Array.of_list (List.map dns_rr_value l)) in
        unpacked [ "name", V.String name ; "type", V.Int typ ; "class", V.Int cls ;
                   "opcode", V.Int m.opcode ;
                   "authoritative", V.Bool m.is_auth ;
                   "truncated", V.Bool m.truncated ;
                   "rec_desired", V.Bool m.rec_desired ;
                   "rec_avail", V.Bool m.rec_avlb ;
                   "authentic_data", V.Bool m.authentic_data ;
                   "checking_disabled", V.Bool m.checking_disabled ;
                   "status", V.Int m.status ;
                   "answers", rrs m.answer_rrs ;
                   "authority", rrs m.authority_rrs ;
                   "additional", rrs m.additional_rrs ] bits

(* The whole message, with an id that the DNS layer below replaces: *)
let dns_message_node layer ~query _ =
    manual (fun fields _ _ ->
        let int ~def name hi = int_of ~def fields layer name 0 hi
        and bool ~def name = bool_of fields name ~def
        and rrs = dns_rrs_of layer fields in
        let name =
            match fields "name" with
            | Some n -> dns_fqdn layer n
            | None -> V.fail "%s needs a name" layer in
        Dns.Pdu.{
            id = 0 ; is_query = query ;
            opcode = int ~def:0 "opcode" 0xf ;
            is_auth = bool ~def:false "authoritative" ;
            truncated = bool ~def:false "truncated" ;
            rec_desired = bool ~def:true "rec_desired" ;
            rec_avlb = bool ~def:false "rec_avail" ;
            authentic_data = bool ~def:false "authentic_data" ;
            checking_disabled = bool ~def:false "checking_disabled" ;
            status = int ~def:0 "status" 0xf ;
            questions = [ name, Dns.QType.o (int ~def:1 "type" 0xffff),
                          int ~def:1 "class" 0xffff ] ;
            answer_rrs = rrs "answers" ;
            authority_rrs = rrs "authority" ;
            additional_rrs = rrs "additional" } |>
        Dns.Pdu.pack, [])

(** {2 Layers} *)

type layer =
    { name : N.t ;
      (* The layers it can be on top of; none for the root: *)
      above : layer list ;
      (* Of a packet quoted by an ICMP error, which goes by the name of the
       * layer it is a quote of: *)
      quoted : bool ;
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
      (* What its nodes tell of their streams beside {!stream_stats}: *)
      stats : (string * Type.t) list ;
      (* Decodes this layer of a received packet, given the hints of the
       * layer below: *)
      unpack : hints -> bitstring -> unpacked option }

let field ?(set_in=[ Manual ]) ?(read_in=[ Manual ]) ?(discriminant=false)
          ?pick ?peer ?driven_default name typ =
    { name ; typ ; set_in ; read_in ; discriminant ; pick ; peer = peer |? name ;
      driven_default }


let unsendable name _ =
    let fail _ _ _ = V.fail "%s cannot be sent" (N.to_string name) in
    { (manual fail) with send = fail }

let layer ?(above=[]) ?(quoted=false) ?(driven=false) ?(terminal=false) ?default
          ?(constants=[]) ?node ?(stats=[]) ?(unpack=fun _ _ -> None) name fields =
    let fields = Array.of_list fields in
    let default_field =
        Option.map (fun d ->
            try Array.findi (fun (f : field) -> f.name = d) fields
            with Not_found ->
                invalid_arg ("Crafty_layers: no field "^ d ^" in "^ N.to_string name)
        ) default in
    { name ; above ; quoted ; driven ; terminal ; fields ; default_field ;
      constants ; node = node |? unsendable name ; stats ; unpack }

(** As in error messages: [IP?] for a quoted IP. *)
let to_string (l : layer) = N.to_string l.name ^ if l.quoted then "?" else ""

(* Those of the fields of [l] that can be read, as a quote of it has them:
 * all readable, and none telling streams apart: *)
let quoted_fields (l : layer) =
    Array.to_list l.fields |>
    List.filter_map (fun (f : field) ->
        if f.read_in = [] then None else
        Some { f with set_in = (if f.set_in = [] then [] else [ Manual ]) ;
                      read_in = [ Manual ] ; discriminant = false ; pick = None })

let eth =
    layer N.Eth ~driven:true ~node:eth_node ~unpack:unpack_eth [
        field "src" Type.Mac ~read_in:both ;
        field "dst" Type.Mac ~read_in:both ;
        field "proto" Type.Int ~read_in:both ~discriminant:true
              ~driven_default:(V.Int 0x800) ;
        field "ts" Type.Time ~set_in:[] ~read_in:both ]

let ip =
    layer N.IP ~above:[ eth ] ~driven:true ~node:ip_node ~unpack:unpack_ip [
        field "src" Type.Ip ~set_in:both ~read_in:both ~discriminant:true
              ~pick:Local_address ~peer:"dst" ;
        field "dst" Type.Ip ~set_in:both ~read_in:both ~discriminant:true
              ~pick:Required ~peer:"src" ;
        field "proto" Type.Int ~set_in:both ~read_in:both ~discriminant:true ;
        field "tos" Type.Int ~set_in:both ~read_in:both ~driven_default:(V.Int 0) ;
        field "ttl" Type.Int ~set_in:both ~read_in:both ~driven_default:(V.Int 64) ;
        field "dont_frag" Type.Bool ~set_in:both ~read_in:both
              ~driven_default:(V.Bool false) ;
        field "id" Type.Int ~read_in:both ;
        field "more_frags" Type.Bool ;
        field "frag_offset" Type.Int ;
        field "tot_len" Type.Int ;
        field "options" Type.bytes ~set_in:both ~read_in:both
              ~driven_default:(V.Array [||]) ;
        field "is_fragment" Type.Bool ~set_in:[] ]

(** What the node of any layer tells of its stream: the packets that went
 * through it, and the bytes of their payloads at that layer. *)
let stream_stats =
    [ "packets_out", Type.Int ; "bytes_out", Type.Int ;
      "packets_in", Type.Int ; "bytes_in", Type.Int ]

let tcp =
    layer N.TCP ~above:[ ip ] ~driven:true ~node:tcp_node ~unpack:unpack_tcp
        ~stats:Type.[
            "bytes_acked", Int ; "bytes_received", Int ; "retrans", Int ;
            "dupacks", Int ; "timeouts", Int ; "ooo_in", Int ; "dup_in", Int ;
            "srtt", Interval ; "rttvar", Interval ; "rtt_samples", Int ;
            "rto", Interval ; "snd_mss", Int ; "rcv_mss", Int ; "cwnd", Int ;
            "ssthresh", Int ; "snd_wnd", Int ; "rcv_wnd", Int ;
            "snd_wscale", Int ; "rcv_wscale", Int ; "established", Bool ]
        ~constants:[ "FIN", Int 1 ; "SYN", Int 2 ; "RST", Int 4 ; "PSH", Int 8 ;
                     "ACK", Int 16 ; "URG", Int 32 ] [
        field "src" Type.Int ~set_in:both ~read_in:both ~discriminant:true
              ~pick:Local_port ~peer:"dst" ;
        field "dst" Type.Int ~set_in:both ~read_in:both ~discriminant:true
              ~pick:Required ~peer:"src" ;
        field "seq_num" Type.Int ;
        field "ack_num" Type.Int ;
        field "flags" Type.Int ;
        field "win_size" Type.Int ;
        field "urg_ptr" Type.Int ;
        field "checksum" Type.Int ;
        field "mss" Type.Int ~set_in:[ Driven ] ~read_in:[] ]

let udp =
    layer N.UDP ~above:[ ip ] ~node:udp_node ~unpack:unpack_udp [
        field "src" Type.Int ~discriminant:true ~pick:Local_port ~peer:"dst" ;
        field "dst" Type.Int ~discriminant:true ~pick:Told ~peer:"src" ;
        field "length" Type.Int ;
        field "checksum" Type.Int ]

(* The kind of message is told by the layer on top of it: *)
let icmp =
    layer N.ICMP ~above:[ ip ] ~node:icmp_node ~unpack:unpack_icmp [
        field "type" Type.Int ~set_in:[] ;
        field "code" Type.Int ~set_in:[] ]

(* The stream of the requests and replies of an id: *)
let echo =
    layer N.Echo ~above:[ icmp ] ~node:echo_node ~unpack:unpack_echo [
        field "id" Type.Int ~discriminant:true ~pick:(Random_in (0, 65535)) ]

let echo_message name typ =
    layer name ~above:[ echo ] ~terminal:true ~default:"payload"
          ~node:(echo_message_node typ) ~unpack:unpack_echo_message [
        field "seq" Type.Int ;
        field "payload" Type.bytes ]

(* On top of which is the start of the packet it is about, quoted: *)
let icmp_error name typ codes ~mtu =
    layer name ~above:[ icmp ]
          ~node:(icmp_error_node typ ~mtu) ~unpack:(unpack_icmp_error ~mtu)
        ~constants:(List.map (fun (n, c) -> n, Int c) codes) (
        field "code" Type.Int ::
        (if mtu then [ field "mtu" Type.Int ] else []))

let dest_unreachable =
    icmp_error N.DestUnreachable 3 ~mtu:true Icmp.Unreachable.[
        "NET_UNREACHABLE", network ; "HOST_UNREACHABLE", host ;
        "PROTOCOL_UNREACHABLE", protocol ; "PORT_UNREACHABLE", port ;
        "FRAG_NEEDED", fragmentation_needed ;
        "SOURCE_ROUTE_FAILED", source_route_failed ]

let time_exceeded =
    icmp_error N.TimeExceeded 11 ~mtu:false
        [ "TTL_EXCEEDED", 0 ; "REASSEMBLY_TIMEOUT", 1 ]

let quoted_ip =
    layer N.IP ~quoted:true ~above:[ dest_unreachable ; time_exceeded ]
        ~node:quoted_ip_node ~unpack:unpack_quoted_ip (quoted_fields ip)

let quoted_udp =
    layer N.UDP ~quoted:true ~above:[ quoted_ip ] ~node:udp_node
        ~unpack:unpack_quoted_udp (quoted_fields udp)

let quoted_tcp =
    layer N.TCP ~quoted:true ~above:[ quoted_ip ] ~node:quoted_tcp_node
        ~unpack:unpack_quoted_tcp (quoted_fields tcp)

(* What is carried by a layer that is not decoded any further: *)
let bytes =
    layer N.Bytes ~terminal:true
        ~above:[ eth ; ip ; tcp ; udp ; dest_unreachable ; time_exceeded ;
                 quoted_ip ; quoted_udp ; quoted_tcp ]
        ~node:bytes_node ~unpack:unpack_bytes
        ~default:"data" [ field "data" Type.bytes ]

(* The stream of the messages of an id, whose constants are those of the
 * messages on top: *)
let dns =
    layer N.DNS ~above:[ udp ] ~node:dns_node ~unpack:unpack_dns
        ~constants:(List.map (fun (n, c) -> n, Int c) [
            "TYPE_A", 1 ; "TYPE_NS", 2 ; "TYPE_CNAME", 5 ; "TYPE_SOA", 6 ;
            "TYPE_PTR", 12 ; "TYPE_MX", 15 ; "TYPE_TXT", 16 ;
            "TYPE_AAAA", 28 ; "TYPE_SRV", 33 ; "TYPE_ANY", 255 ;
            "CLASS_IN", 1 ;
            "NOERROR", 0 ; "FORMERR", 1 ; "SERVFAIL", 2 ; "NXDOMAIN", 3 ;
            "NOTIMP", 4 ; "REFUSED", 5 ]) [
        field "id" Type.Int ~discriminant:true ~pick:(Random_in (0, 65535)) ]

(* A resource record, its fields sorted as those of every record type: *)
let dns_rr =
    Type.Record [ "class", Type.Int ; "data", Type.bytes ; "name", Type.String ;
                  "ttl", Type.Int ; "type", Type.Int ]

(* A query or an answer, with one question: *)
let dns_message name ~query =
    layer name ~above:[ dns ] ~terminal:true ~default:"name"
          ~node:(dns_message_node (N.to_string name) ~query) ~unpack:unpack_dns_message [
        field "name" Type.String ;
        field "type" Type.Int ;
        field "class" Type.Int ;
        field "opcode" Type.Int ;
        field "authoritative" Type.Bool ;
        field "truncated" Type.Bool ;
        field "rec_desired" Type.Bool ;
        field "rec_avail" Type.Bool ;
        field "authentic_data" Type.Bool ;
        field "checking_disabled" Type.Bool ;
        field "status" Type.Int ;
        field "answers" (Type.Array dns_rr) ;
        field "authority" (Type.Array dns_rr) ;
        field "additional" (Type.Array dns_rr) ]

let all =
    [ eth ; ip ; tcp ; udp ; icmp ; echo ; echo_message N.Request 8 ;
      echo_message N.Reply 0 ;
      dest_unreachable ; time_exceeded ; quoted_ip ; quoted_udp ; quoted_tcp ;
      dns ; dns_message N.Query ~query:true ; dns_message N.Answer ~query:false ;
      bytes ]

let same_name a b = String.lowercase_ascii a = String.lowercase_ascii b

(** The layer of that name that can be on top of [below], or that is the
 * root if no [below]. *)
let find ?below name =
    List.find_opt (fun (l : layer) ->
        l.name = name &&
        match below with
        | None -> l.above = []
        | Some b -> List.memq b l.above) all

(** The layers that can be on top of [l]. *)
let uppers (l : layer) =
    List.filter (fun (u : layer) -> List.memq l u.above) all

let root = eth

(** The index of that field of [l]. *)
let find_field (l : layer) name =
    try Some (Array.findi (fun (f : field) -> same_name f.name name) l.fields)
    with Not_found -> None

(** All the constants, of all the layers. *)
let constants = List.concat_map (fun (l : layer) -> l.constants) all

(** The value of that constant, whose name is case sensitive. *)
let find_constant name =
    List.assoc_opt name constants

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
  Option.map_default ((==) eth) false (find N.Eth)
  find N.IP = None
  Option.map_default ((==) ip) false (find ~below:eth N.IP)
  find ~below:icmp N.Request = None
  Option.map_default ((==) bytes) false (find ~below:tcp N.Bytes)
  find ~below:bytes N.Bytes = None
  (find ~below:dns N.Query |> Option.map (fun (l : layer) -> l.name)) = Some N.Query
  find ~below:udp N.Query = None
  Option.map_default ((==) quoted_ip) false (find ~below:time_exceeded N.IP)
  Option.map_default ((==) quoted_udp) false (find ~below:quoted_ip N.UDP)
  find ~below:quoted_udp N.DNS = None
  find ~below:quoted_ip N.ICMP = None
*)
(* A message, decoded as sent, its names as written: *)
(*$T
  let fields = function \
      | "name" -> Some (Crafty_value.String "example.com") \
      | "answers" -> Some (Crafty_value.Array [| Crafty_value.Record [| \
          Crafty_value.Int 1 ; Crafty_value.bytes_of_string "\001\002\003\004" ; \
          Crafty_value.String "example.com" ; Crafty_value.Int 0xffff_ffff ; Crafty_value.Int 1 |] |]) \
      | _ -> None in \
  let eth = Eth.State.make ~parent:(Simulation.make ~realtime:false "dns").root ~name:"dns" \
              ~mac:(Eth.Addr.of_string "02:00:00:00:00:01") () in \
  let ctx = { eth ; key = (fun _ -> None) ; below_key = (fun _ -> None) ; below = None } in \
  let answer = dns_message N.Answer ~query:false in \
  let bits, _ = (answer.node ctx).pack fields [] Bitstring.empty_bitstring in \
  match unpack_dns [] bits with \
  | Some { upper = Only N.Answer ; payload ; _ } -> \
      (match answer.unpack [] payload with \
      | Some u -> \
          List.assoc "name" u.values = Crafty_value.String "example.com" && \
          List.assoc "rec_desired" u.values = Crafty_value.Bool true && \
          (match List.assoc "answers" u.values with \
           | Crafty_value.Array [| Crafty_value.Record [| _ ; _ ; Crafty_value.String "example.com" ; Crafty_value.Int 0xffff_ffff ; _ |] |] -> true \
           | _ -> false) \
      | None -> false) \
  | _ -> false
*)
(*$T find_field
  find_field bytes "DATA" = Some 0
  find_field tcp "mss" = Some 8
  find_field tcp "payload" = None
*)
(* Defaults are found by name: *)
(*$T
  bytes.default_field = Some 0
  (echo_message N.Request 8).default_field = Some 1
  tcp.default_field = None
*)
(*$T key_fields
  key_fields ip = [ 0 ; 1 ]
  key_fields icmp = []
  key_fields echo = [ 0 ]
  key_fields (echo_message N.Reply 0) = []
*)
(*$T find_constant
  find_constant "RST" = Some (Crafty_ast.Int 4)
  find_constant "PORT_UNREACHABLE" = Some (Crafty_ast.Int 3)
  find_constant "rst" = None
  find_constant "src" = None
*)
(*$= record_type & ~printer:Crafty_ast.Type.to_string
  (Crafty_ast.Type.Record [ "src", Crafty_ast.Type.Int ; "dst", Crafty_ast.Type.Int ]) (record_type tcp Driven)
  (Crafty_ast.Type.Record [ "data", Crafty_ast.Type.bytes ]) (record_type bytes Manual)
*)
(* The registry holds together: *)
(*$T
  List.for_all (fun (l : layer) -> \
      List.for_all (fun b -> List.memq b all) l.above) all
  List.for_all (fun n -> List.exists (fun (l : layer) -> l.name = n) all) N.all
  List.for_all (fun (l : layer) -> \
      l.terminal = (uppers l = [])) all
  List.length (List.filter (fun (l : layer) -> List.is_empty l.above) all) = 1
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
      l == b || l.name <> b.name || \
      List.for_all (fun a -> not (List.memq a b.above)) l.above) all) all
*)
(* Constants are names of their own, apart from any other: *)
(*$T
  let names = List.map (fun (n, _) -> String.lowercase_ascii n) constants in \
  List.length (List.unique names) = List.length names && \
  List.for_all (fun n -> \
      N.of_string n = None && \
      not (List.mem n Crafty_ast.(keywords @ functions @ \
                                  List.map String.lowercase_ascii predefined)) && \
      List.for_all (fun (l : layer) -> find_field l n = None) all) names
*)
