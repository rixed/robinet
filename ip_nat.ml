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
 * TRX that performs Network Address Translation
 *
 * Network Address Translation (N.A.T.) is the process of replacing on the fly non routable
 * addresses used within a LAN by a unique routable address, so that hosts from the LAN
 * can communicate with the outside world by sharing the only routable IP address.
 * A [Nat.t] is a two sided device, with an inside and an outside, and an affected Ip address,
 * that will translate outgoing source addresses with it's own and restore it in incoming
 * packets. To match these incoming packets with the outgoing one it must use the UDP or
 * TCP client port and an internal memory of currently forwarded connections. This memory
 * is of bounded size.
 * Note that any packet that reach it will be forwarded.
 * A Nat.t is a TRX at IP level (it expects Ip packets). *)
open Batteries

open Bitstring
open Tools

module State =
struct
    type socket = {       proto : Ip.Proto.t ;  (** the IP protocol *)
                       nat_port : int ;         (** the replacement src port *)
                    remote_addr : Ip.Addr.t ;   (** the other peer's address *)
                    remote_port : int }         (** the port used by the other peer *)

    type cnx = { orig_addr : Ip.Addr.t ;  (** the inside lan's host IP *)
                  orig_num : int ;        (** the origin port/id used by this host *)
                   nat_num : int }        (** the random port/id used by NAS in the outside *)

    (* For ICMP, the message's type, code and id are tracked and the id is
     * substituted. *)
    type icmp_sock = { msg_type : Icmp.MsgType.t ;
                             id : int }

    (* TODO: add an optional sink inside IP *)
    type t = {      addr : Ip.Addr.t ;                  (** our IP addr *)
                min_port : int ;                        (** smallest port to use for outgoing source ports *)
                  logger : Log.logger ;
               nat_pings : bool ;
                    cnxs : cnx OrdArray.t ;             (** all the cnxs we remember, either port or ICMP based *)
               in_cnxs_h : (socket, int) Hashtbl.t ;    (** the hash to retrieve cnxs of packets INcoming from the outside (the value is the index in [cnxs]) *)
              out_cnxs_h : (socket, int) Hashtbl.t ;    (** the hash to retrieve cnxs of packets OUTgoing to the outside *)
               in_icmp_h : (icmp_sock, int) Hashtbl.t ; (** the hash to retrieve original ICMP ids on INcoming packets (the value is *also* the index in [cnxs]) *)
              out_icmp_h : (icmp_sock, int) Hashtbl.t ; (** the hash to retrieve NATed ids on OUTgoing packets *)
              (* FIXME: Ideally, those functions are serializable references to
               * the TRX they are connected to: *)
            mutable emit : bitstring -> unit ;          (** the emit function (ie. carry packets to the outside *)
            mutable recv : bitstring -> unit }          (** the receive functon (ie. forward incoming packets from the outside *)

    (** Initialize the state for a NAT TRX. *)
    let make ?(min_port=1024) ?(num_max_cnxs=200) ?(nat_pings=true) ?(parent_logger=Log.default) addr =
        let logger = Log.sub parent_logger "nat" in
        Log.(log logger Debug (lazy (Printf.sprintf "Creating a NATer for IP %s, with %d cnxs max" (Ip.Addr.to_string addr) num_max_cnxs))) ;
        { addr ; min_port ; logger ; nat_pings ;
          cnxs = OrdArray.make num_max_cnxs { orig_addr = Ip.Addr.zero ;
                                              orig_num = 0 ;
                                              nat_num = 0 } ;
          in_cnxs_h = Hashtbl.create num_max_cnxs ;
          out_cnxs_h = Hashtbl.create num_max_cnxs ;
          in_icmp_h = Hashtbl.create num_max_cnxs ;
          out_icmp_h = Hashtbl.create num_max_cnxs ;
          emit = ignore_bits ~logger ;
          recv = ignore_bits ~logger }
end

module TRX =
struct
    (**
    Behavior on incoming packets:
{v
    [Nat] <----------------------------- [Outside host]
              Src: outside_addr,
              Dst: nat_addr
            Ports: outside_port:nat_port
v}
    Lookup (outside_addr, outside_port, nat_port, proto) in in_cnxs_h.
    If the cnx is found then replace the nat_addr:nat_port by cnx.orig_addr:cnx.orig_num.
    If nothing is found, just ignore the packet (or forward it to the sink host
    without changing the dest port).

    Behavior on outgoing packets:
{v
    [Inside host] -----------------------------> [Nat]
                      Src: inside_addr,
                      Dst: outside_addr,
                    Ports: inside_port:outside_port
v}
    Lookup (inside_addr, inside_port, outside_port, proto) in out_cnxs_h.
    If the cnx is found then replace the inside_addr:inside_port by nat_addr:cnx.nat_num.
    If nothing is found, create the cnx as:
    {[ { nat_num=random_port; orig_addr=inside_addr; orig_num=inside_port } ]}
    and insert it with the above key in out_cnxs_h.
    Also, insert this cnx in in_cnxs_h with key (outside_addr, outside_port, random_port, proto).

    *)

    let start_tracking (st : State.t) orig_addr orig_num nat_num in_h in_k =
        let last_idx = OrdArray.last st.cnxs in
        OrdArray.set st.cnxs last_idx { orig_addr ; orig_num ; nat_num } ;
        (* replace also entry in one of the incoming hashes: *)
        Hashtbl.replace in_h in_k last_idx ;
        last_idx

    let patch_src_port proto bits port =
        if proto = Ip.Proto.tcp then (
            let pdu = Option.get (Tcp.Pdu.unpack bits) in
            Tcp.Pdu.pack { pdu with Tcp.Pdu.src_port = Tcp.Port.o port }
        ) else if proto = Ip.Proto.udp then (
            let pdu = Option.get (Udp.Pdu.unpack bits) in
            Udp.Pdu.pack { pdu with Udp.Pdu.src_port = Udp.Port.o port }
        ) else should_not_happen ()

    let patch_dst_port proto bits port =
        if proto = Ip.Proto.tcp then (
            let pdu = Option.get (Tcp.Pdu.unpack bits) in
            Tcp.Pdu.pack { pdu with Tcp.Pdu.dst_port = Tcp.Port.o port }
        ) else if proto = Ip.Proto.udp then (
            let pdu = Option.get (Udp.Pdu.unpack bits) in
            Udp.Pdu.pack { pdu with Udp.Pdu.dst_port = Udp.Port.o port }
        ) else should_not_happen ()

    let patch_icmp_id (icmp : Icmp.Pdu.t) new_id =
        let payload =
            match icmp.payload with
            | Ids (_id, seq, pld) -> Icmp.Pdu.Ids (new_id, seq, pld)
            | p -> p in
        Icmp.Pdu.pack { icmp with payload }

    let do_port_nat (st : State.t) (ip : Ip.Pdu.t) src_port dst_port =
        (* Do we already follow this socket? *)
        let out_sock = State.{ proto = ip.proto ;
                            nat_port = dst_port ;
                         remote_addr = ip.src ;
                         remote_port = src_port } in
        let n = hash_find_or_insert st.out_cnxs_h out_sock (fun () ->
            (* FIXME: to avoid reusing a port that's already in use with
             * the same dest, use a long sequence of "random" generator
             * for that port number range *)
            let random_port = st.min_port + Random.int (65536 - st.min_port) in
            let in_sock = State.{ proto = ip.proto ;
                               nat_port = random_port ;
                            remote_addr = ip.dst ;
                            remote_port = dst_port } in
            start_tracking st ip.src src_port random_port st.in_cnxs_h in_sock) in
        OrdArray.promote st.cnxs n ;
        (* perform source NAT *)
        let new_src_port = (OrdArray.get st.cnxs n).nat_num in
        let payload = Payload.o (patch_src_port ip.proto
                                                (ip.payload :> bitstring)
                                                new_src_port) in
        let ip = { ip with src = st.addr ; payload } in
        st.emit (Ip.Pdu.pack ip)

    let do_icmp_nat (st : State.t) (ip : Ip.Pdu.t) (icmp : Icmp.Pdu.t) msg_type id =
        (* If we track this ping already, reuse the former outside id: *)
        let out_sock = State.{ msg_type ; id } in
        let n = hash_find_or_insert st.out_icmp_h out_sock (fun () ->
            (* FIXME: same as above *)
            let random_id = randi 8 in
            let in_sock = State.{ msg_type ; id = random_id } in
            start_tracking st ip.src id random_id st.in_icmp_h in_sock) in
        OrdArray.promote st.cnxs n ;
        (* Actually substitute the id: *)
        let new_id = (OrdArray.get st.cnxs n).nat_num in
        let payload = Payload.o (patch_icmp_id icmp new_id) in
        let ip = { ip with src = st.addr ; payload } in
        st.emit (Ip.Pdu.pack ip)

    let do_port_unnat (st : State.t) (ip : Ip.Pdu.t) src_port dst_port =
        let in_sock = State.{ proto = ip.proto ;
                           nat_port = dst_port ;
                        remote_addr = ip.src ;
                        remote_port = src_port } in
        match Hashtbl.find st.in_cnxs_h in_sock with
        | exception Not_found ->
            Log.(log st.logger Debug (lazy ("No recollection of that connection")))
        | n ->
            let cnx = OrdArray.get st.cnxs n in
            let payload = Payload.o (patch_dst_port ip.proto
                                                    (ip.payload :> bitstring)
                                                    cnx.orig_num) in
            let ip = { ip with dst = cnx.orig_addr ; payload } in
            st.recv (Ip.Pdu.pack ip)

    let do_icmp_unnat (st : State.t) (ip : Ip.Pdu.t) (icmp : Icmp.Pdu.t) msg_type id =
        let in_sock = State.{ msg_type ; id } in
        match Hashtbl.find st.in_icmp_h in_sock with
        | exception Not_found ->
            Log.(log st.logger Debug (lazy ("No recollection of that connection")))
        | n ->
            let cnx = OrdArray.get st.cnxs n in
            let payload = Payload.o (patch_icmp_id icmp cnx.orig_num) in
            let ip = { ip with dst = cnx.orig_addr ; payload } in
            st.recv (Ip.Pdu.pack ip)

    (** bits are flowing from LAN to outside world *)
    let tx (st : State.t) bits =
        match Ip.Pdu.unpack bits with
        | Some (ip : Ip.Pdu.t) ->
            if Ip.Addr.is_natable ip.src then (
                if ip.dst <> st.addr then (
                    if ip.proto = Ip.Proto.udp || ip.proto = Ip.Proto.tcp then (
                        match Ip.Pdu.get_ports ip with
                        | Some (src_port, dst_port) ->
                            Log.(log st.logger Debug (lazy (Printf.sprintf "Translating packet of %d bytes from %s:%d to %s:%d" (bytelength bits) (Ip.Addr.to_string ip.src) src_port (Ip.Addr.to_string ip.dst) dst_port))) ;
                            do_port_nat st ip src_port dst_port
                        | None ->
                            Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring outgoing IP packet of %d bytes since it has no ports" (bytelength bits))))
                    ) else if ip.proto = Ip.Proto.icmp then (
                        if st.nat_pings then (
                            match Icmp.Pdu.unpack (ip.payload :> bitstring) with
                            | Some (Icmp.Pdu.{ msg_type ; payload = Ids (id, _, _) } as icmp)
                              when Icmp.MsgType.is_echo_request msg_type ->
                                Log.(log st.logger Debug (lazy (Printf.sprintf "Translating PING of %d bytes from src:%s, id:%d to dst:%s" (bytelength bits) (Ip.Addr.to_string ip.src) id (Ip.Addr.to_string ip.dst)))) ;
                                do_icmp_nat st ip icmp msg_type id
                            (* We NAT only ICMP queries (for now?) *)
                            | Some _ ->
                                Log.(log st.logger Debug (lazy "Ignoring outgoing uninteresting ICMP packet"))
                            | None ->
                                Log.(log st.logger Debug (lazy "Ignoring bad outgoing ICMP packet"))
                        ) else (
                            Log.(log st.logger Debug (lazy "Not NATing outgoing ICMP"))
                        )
                    ) else (
                        Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring outgoing IP packet of %d bytes since it's neither UDP, TCP or ICMP" (bytelength bits))))
                    )
                ) else (
                    Log.(log st.logger Debug (lazy ("Ignoring outgoing packet destined for my public address")))
                )
            ) else (
                Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring outgoing IP packet from non NATable address %s" (Ip.Addr.to_string ip.src))))
            )
        | None ->
            Log.(log st.logger Debug (lazy "Ignoring bad IP packet"))

    let rx (st : State.t) bits =
        Log.(log st.logger Debug (lazy (Printf.sprintf "Received %d bytes" (bytelength bits)))) ;
        match Ip.Pdu.unpack bits with
        | Some (ip : Ip.Pdu.t) ->
            if ip.dst = st.addr then (
                if ip.proto = Ip.Proto.udp || ip.proto = Ip.Proto.tcp then (
                    match Ip.Pdu.get_ports ip with
                    | Some (src_port, dst_port) ->
                        do_port_unnat st ip src_port dst_port
                    | None ->
                        Log.(log st.logger Debug (lazy "Ignoring bad incoming UDP/TCP packet"))
                ) else if ip.proto = Ip.Proto.icmp then (
                    if st.nat_pings then (
                        match Icmp.Pdu.unpack (ip.payload :> bitstring) with
                        | Some (Icmp.Pdu.{ msg_type ; payload = Ids (id, _, _) } as icmp)
                          when Icmp.MsgType.is_echo_reply msg_type ->
                            Log.(log st.logger Debug (lazy (Printf.sprintf "Translating back PING reply of %d bytes from %s, id:%d" (bytelength bits) (Ip.Addr.to_string ip.src) id))) ;
                            do_icmp_unnat st ip icmp msg_type id
                        (* We NAT back only ICMP echo reply and some errors *)
                        | Some _ ->
                            Log.(log st.logger Debug (lazy "Ignoring uninteresting incoming ICMP packet"))
                        | None ->
                            Log.(log st.logger Debug (lazy "Ignoring bad incoming ICMP packet"))
                    ) else (
                        Log.(log st.logger Debug (lazy "Not NATing incoming ICMP"))
                    )
                ) else (
                    Log.(log st.logger Debug (lazy "Ignoring incoming uninteresting IP packet"))
                )
            ) else (
                Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring incoming IP packet for %s (I'm %s)" (Ip.Addr.to_string ip.dst) (Ip.Addr.to_string st.addr))))
            )
        | None ->
            Log.(log st.logger Debug (lazy "Ignoring incoming non-IP packet"))

    (** [make ip n] returns a {!Tools.trx} corresponding to a NAT device (tx is for transmitting from the LAN to the outside) that can track [n] sockets. *)
    let make (st : State.t) =
        { ins = { write = tx st ;
                  set_read = fun f -> st.recv <- f } ;
          out = { write = rx st ;
                  set_read = fun f -> st.emit <- f } }
end
