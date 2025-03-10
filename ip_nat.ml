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
    type socket = { proto : Ip.Proto.t ;  (** The IP protocol *)
                 src_addr : Ip.Addr.t ;   (** The tracked cnx source. *)
                 src_port : int ;
                 dst_addr : Ip.Addr.t ;   (** The tracked cnx destination. *)
                 dst_port : int }

    let socket_print oc s =
        Printf.fprintf oc "%s connection from %s:%d to %s:%d"
            (Ip.Proto.to_string s.proto)
            (Ip.Addr.to_string s.src_addr) s.src_port
            (Ip.Addr.to_string s.dst_addr) s.dst_port

    (* For ICMP, the message's type, code and id are tracked and the id is
     * substituted. *)
    type icmp_sock = { src_addr : Ip.Addr.t ;       (** The tracked cnx source. *)
                       dst_addr : Ip.Addr.t ;       (** The tracked cnx destination. *)
                       msg_type : Icmp.MsgType.t ;  (** The tracked ICMP type&code. *)
                             id : int }             (** The tracked ICMP id. *)

    let icmp_sock_print oc s =
        Printf.fprintf oc "ICMP message of type %s and id %d from %s to %s"
            (Icmp.MsgType.to_string s.msg_type) s.id
            (Ip.Addr.to_string s.src_addr)
            (Ip.Addr.to_string s.dst_addr)

    type cnx_keys =
        | None
        | SocketKeys of { inc_sock : socket ; out_sock : socket }
        | IcmpKeys of { inc_sock : icmp_sock ; out_sock : icmp_sock }

    type cnx = { orig_addr : Ip.Addr.t ;     (** The inside lan's host IP. *)
                  orig_num : int ;           (** The origin port/id used by this host. *)
                   nat_num : int ;           (** The random port/id used by NAT in the outside. *)
         mutable last_used : Clock.Time.t ;  (** Just for information *)
         (* Also store references to the two keys indexing this entry, so they
          * can be removed when this entry is overwritten (see [unkey_cnx]): *)
                      keys : cnx_keys }

    type port_forward = { proto : Ip.Proto.t ;
                       ext_port : int ;
                    internal_ip : Ip.Addr.t ;
                  internal_port : int }

    let port_forward ?(proto=Ip.Proto.tcp) ?internal_port internal_ip ext_port =
        let internal_port = internal_port |? ext_port in
        { proto ; ext_port ; internal_ip ; internal_port }

    (* TODO: add an optional sink inside IP *)
    type t = {      addr : Ip.Addr.t ;                  (** our IP addr *)
                min_port : int ;                        (** smallest port to use for outgoing source ports *)
                  logger : Log.logger ;
               nat_pings : bool ;                       (** whether to NAT outgoing PINGs or to drop them *)
               send_errs : bool ;                       (** whether to send ICMP/TCP errors on bad incoming packets *)
            answer_pings : bool ;                       (** whether to answer incoming pings in absence of port forwarding *)
           port_forwards : port_forward list ;
                    cnxs : cnx OrdArray.t ;             (** all the cnxs we remember, either port or ICMP based *)
              inc_cnxs_h : (socket, int) Hashtbl.t ;    (** the hash to retrieve cnxs of packets INComing from the outside (the value is the index in [cnxs]) *)
              out_cnxs_h : (socket, int) Hashtbl.t ;    (** the hash to retrieve cnxs of packets OUTgoing to the outside *)
              inc_icmp_h : (icmp_sock, int) Hashtbl.t ; (** the hash to retrieve original ICMP ids on INComing packets (the value is *also* the index in [cnxs]) *)
              out_icmp_h : (icmp_sock, int) Hashtbl.t ; (** the hash to retrieve NATed ids on OUTgoing packets *)
              (* FIXME: Ideally, those functions are serializable references to
               * the TRX they are connected to: *)
            mutable emit : bitstring -> unit ;          (** the emit function (ie. carry packets to the outside *)
            mutable recv : bitstring -> unit }          (** the receive functon (ie. forward incoming packets from the outside *)

    (** Initialize the state for a NAT TRX. *)
    let make ?(min_port=1024) ?(num_max_cnxs=200) ?(nat_pings=true)
             ?(send_errs=true) ?(answer_pings=true)
             ?(parent_logger=Log.default) ?(port_forwards=[])
             addr =
        let logger = Log.sub parent_logger "nat" in
        Log.(log logger Debug (lazy (Printf.sprintf "Creating a NATer for IP %s, with %d cnxs max" (Ip.Addr.to_string addr) num_max_cnxs))) ;
        { addr ; min_port ; logger ; nat_pings ; send_errs ; answer_pings ;
          port_forwards ;
          cnxs = OrdArray.make num_max_cnxs { orig_addr = Ip.Addr.zero ;
                                              orig_num = 0 ;
                                              nat_num = 0 ;
                                              keys = None ;
                                              last_used = Clock.now () } ;
          inc_cnxs_h = Hashtbl.create num_max_cnxs ;
          out_cnxs_h = Hashtbl.create num_max_cnxs ;
          inc_icmp_h = Hashtbl.create num_max_cnxs ;
          out_icmp_h = Hashtbl.create num_max_cnxs ;
          emit = ignore_bits ~logger ;
          recv = ignore_bits ~logger }

    (* Remove an overwritten tracked connection from the hashes: *)
    let unkey_cnx (t : t) = function
        | None -> ()
        | SocketKeys { inc_sock ; out_sock } ->
            Hashtbl.remove t.inc_cnxs_h inc_sock ;
            Hashtbl.remove t.out_cnxs_h out_sock
        | IcmpKeys { inc_sock ; out_sock } ->
            Hashtbl.remove t.inc_icmp_h inc_sock ;
            Hashtbl.remove t.out_icmp_h out_sock
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
    Lookup (outside_addr, outside_port, nat_port, proto) in inc_cnxs_h.
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
    Also, insert this cnx in inc_cnxs_h with key (outside_addr, outside_port, random_port, proto).

    *)

    let start_tracking (st : State.t) orig_addr orig_num nat_num in_h in_k keys =
        let last_idx = OrdArray.last st.cnxs in
        let prev = OrdArray.get st.cnxs last_idx in
        let now_ = Clock.now () in
        if prev.keys <> State.None then
            Log.(log st.logger Debug (lazy (Printf.sprintf "Recycling an old connection last used %s ago" Clock.(Interval.to_string Time.(sub now_ prev.last_used))))) ;
        State.unkey_cnx st (OrdArray.get st.cnxs last_idx).keys ;
        OrdArray.set st.cnxs last_idx
            { orig_addr ; orig_num ; nat_num ; keys ; last_used = now_ } ;
        (* replace also entry in one of the incoming hashes: *)
        Hashtbl.replace in_h in_k last_idx ;
        last_idx

    let patch_src_port proto bits port =
        if proto = Ip.Proto.tcp then (
            Tcp.Pdu.unpack bits |>
            Result.map (fun pdu ->
                Tcp.Pdu.pack { pdu with Tcp.Pdu.src_port = Tcp.Port.o port })
        ) else if proto = Ip.Proto.udp then (
            Udp.Pdu.unpack bits |>
            Result.map (fun pdu ->
                Udp.Pdu.pack { pdu with Udp.Pdu.src_port = Udp.Port.o port })
        ) else Error (lazy "Neither UDP nor TCP")

    let patch_dst_port proto bits port =
        if proto = Ip.Proto.tcp then (
            Tcp.Pdu.unpack bits |>
            Result.map (fun pdu ->
                Tcp.Pdu.pack { pdu with Tcp.Pdu.dst_port = Tcp.Port.o port })
        ) else if proto = Ip.Proto.udp then (
            Udp.Pdu.unpack bits |>
            Result.map (fun pdu ->
                Udp.Pdu.pack { pdu with Udp.Pdu.dst_port = Udp.Port.o port })
        ) else Error (lazy "Neither UDP nor TCP")

    let patch_icmp_id (icmp : Icmp.Pdu.t) new_id =
        let payload =
            match icmp.payload with
            | Ids (_id, seq, pld) -> Icmp.Pdu.Ids (new_id, seq, pld)
            | p -> p in
        Icmp.Pdu.pack { icmp with payload }

    let do_port_nat (st : State.t) (ip : Ip.Pdu.t) src_port dst_port =
        (* Do we already follow this socket? *)
        let out_sock = State.{ proto = ip.proto ;
                            src_addr = ip.src ;
                            src_port = src_port ;
                            dst_addr = ip.dst ;
                            dst_port = dst_port } in
        let n = hash_find_or_insert st.out_cnxs_h out_sock (fun () ->
            (* FIXME: to avoid reusing a port that's already in use with
             * the same dest, use a long sequence of "random" generator
             * for that port number range *)
            let random_port = st.min_port + Random.int (65536 - st.min_port) in
            let inc_sock = State.{ proto = ip.proto ;
                                src_addr = ip.dst ;
                                src_port = dst_port ;
                                dst_addr = st.addr ;
                                dst_port = random_port } in
            start_tracking st ip.src src_port random_port st.inc_cnxs_h inc_sock
                State.(SocketKeys { inc_sock ; out_sock })) in
        OrdArray.promote st.cnxs n ;
        (* perform source NAT *)
        (* FIXME: also check that (OrdArray.get st.cnxs n).orig_num correspond to
         * src_port and orig_addr to ip.src, otherwise it means we are reusing
         * an outdated hash entry!
         * Do this each time we read from OrdArray. *)
        (* FIXME: Also, clean the hash when that happen. Store the hash key in cnx? *)
        let cnx = OrdArray.get st.cnxs n in
        cnx.last_used <- Clock.now () ;
        let new_src_port = cnx.nat_num in
        patch_src_port ip.proto (ip.payload :> bitstring) new_src_port |>
        Result.iter (fun pld ->
            let payload = Payload.o pld in
            let ip = { ip with src = st.addr ; payload } in
            st.emit (Ip.Pdu.pack ip))

    let do_icmp_request_nat (st : State.t) (ip : Ip.Pdu.t) (icmp : Icmp.Pdu.t) msg_type id =
        (* If we track this ping already, reuse the former outside id: *)
        let out_sock = State.{ src_addr = ip.src ;
                               dst_addr = ip.dst ;
                               msg_type ; id } in
        let n = hash_find_or_insert st.out_icmp_h out_sock (fun () ->
            (* FIXME: same as above *)
            let random_id = randi 8 in
            let inc_sock = State.{ src_addr = ip.dst ;
                                   dst_addr = st.addr ;
                                   msg_type = Icmp.MsgType.reply_of msg_type ;
                                   id = random_id } in
            start_tracking st ip.src id random_id st.inc_icmp_h inc_sock
                State.(IcmpKeys { inc_sock ; out_sock })) in
        OrdArray.promote st.cnxs n ;
        (* Actually substitute the id: *)
        let cnx = OrdArray.get st.cnxs n in
        cnx.last_used <- Clock.now () ;
        let new_id = cnx.nat_num in
        let payload = Payload.o (patch_icmp_id icmp new_id) in
        Log.(log st.logger Debug (lazy (Printf.sprintf "NATing an ICMP packet, subst IP src %s->%s"
            (Ip.Addr.to_string ip.src)
            (Ip.Addr.to_string st.addr)))) ;
        let ip = { ip with src = st.addr ; payload } in
        st.emit (Ip.Pdu.pack ip)

    type unpacked_icmp_err_header =
        | TcpUdpCnx of { err_ip : Ip.Pdu.t ; src_port : int ; dst_port : int ;
                         rest : bitstring }
        | IcmpCnx of { err_ip : Ip.Pdu.t ; typ : int ; cod : int ;
                       checksum : int ; id : int ; rest : bitstring }

    let unpack_icmp_err_header (st : State.t) (pld : Payload.t) =
        match Ip.Pdu.unpack (pld :> bitstring) with
        | Ok err_ip ->
            (* After the complete IP header, the payload must have at least 8
             * bytes, and that's all we need for NAT, so unpack and patch
             * only that: *)
            if err_ip.proto = Ip.Proto.tcp ||
               err_ip.proto = Ip.Proto.udp then
                match%bitstring (err_ip.payload :> bitstring) with
                | {| src_port : 16 ; dst_port : 16 ; rest : -1 : bitstring |} ->
                    Some (TcpUdpCnx { err_ip ; src_port ; dst_port ; rest })
                | {| _ |} ->
                    Log.(log st.logger Warning (lazy "Cannot decode ICMP err header as UDP/TCP")) ;
                    None
            else if err_ip.proto = Ip.Proto.icmp then
                match%bitstring (err_ip.payload :> bitstring) with
                | {| typ : 8 ; cod : 8 ; checksum : 16 ; id : 16 ;
                     rest : -1 : bitstring |} ->
                     Some (IcmpCnx { err_ip ; typ ; cod ; checksum ; id ; rest })
                | {| _ |} ->
                    Log.(log st.logger Warning (lazy "Cannot decode ICMP err header as ICMP")) ;
                    None
            else (
                Log.(log st.logger Debug (lazy ("Not NATing back ICMP error for IP proto "^ Ip.Proto.to_string err_ip.proto))) ;
                None
            )
        | Error s ->
            Log.(log st.logger Warning (lazy ("Cannot decode IP header from ICMP payload: "^ Lazy.force s))) ;
            None

    let do_icmp_err_nat (st : State.t) (ip : Ip.Pdu.t) (icmp : Icmp.Pdu.t) ptr mtu pld =
        let emit_with_err_ip_pld err_ip_pld (err_ip : Ip.Pdu.t) =
            let err_ip = { err_ip with
                             dst = st.addr ; (* External version of the dest IP *)
                         payload = Payload.o err_ip_pld } in
            let pld = Payload.o (Ip.Pdu.pack err_ip) in
            let icmp = { icmp with payload = Header { ptr ; mtu ; pld } } in
            let payload = Payload.o (Icmp.Pdu.pack icmp) in
            let ip = { ip with src = st.addr ; payload } in
            st.emit (Ip.Pdu.pack ip) in
        unpack_icmp_err_header st pld |> Option.may (function
        | TcpUdpCnx { err_ip ; src_port ; dst_port ; rest } ->
            (* If this ICMP error is sent to an external dest, the original
             * packet that triggered the error was sent from this external
             * dest. Let's retrieve this tracked socket using the parameters
             * from the internal LAN, thus indexed in [out_cnxs_h]: *)
            let out_sock = State.{ proto = err_ip.proto ;
                                src_addr = err_ip.dst ;
                                dst_addr = err_ip.src ;
                                src_port = dst_port ;
                                dst_port = src_port } in
            (match Hashtbl.find st.out_cnxs_h out_sock with
            | exception Not_found ->
                Log.(log st.logger Warning (lazy (Printf.sprintf2
                    "No idea about that outgoing %a which triggered this ICMP error"
                        State.socket_print out_sock)))
                (* Do not send another ICMP error on an ICMP error. *)
            | n ->
                OrdArray.promote st.cnxs n ;
                let cnx = OrdArray.get st.cnxs n in
                cnx.last_used <- Clock.now () ;
                (* Patch the external version of the dest port: *)
                let%bitstring err_ip_pld =
                    {| src_port : 16 ; cnx.nat_num : 16 ;
                       rest : -1 : bitstring |} in
                emit_with_err_ip_pld err_ip_pld err_ip)
        (* An ICMP packet can also trigger an ICMP error: *)
        | IcmpCnx { err_ip ; typ ; cod ; checksum ; id ; rest } ->
            (* Will stay unchanged if it's already a reply: *)
            let msg_type = Icmp.MsgType.(reply_of (o (typ, cod))) in
            let out_sock = State.{ src_addr = err_ip.dst ;
                                   dst_addr = err_ip.src ;
                                   msg_type ; id } in
            (match Hashtbl.find st.out_icmp_h out_sock with
            | exception Not_found ->
                Log.(log st.logger Warning (lazy (Printf.sprintf2
                    "Cannot find the %a which was expected as a reply
                     to the ICMP packet that caused this ICMP error"
                    State.icmp_sock_print out_sock)))
            | n ->
                OrdArray.promote st.cnxs n ;
                let cnx = OrdArray.get st.cnxs n in
                cnx.last_used <- Clock.now () ;
                (* Put back the original dest IP and ICMP id in the
                 * ICMP copy of the IP header: *)
                let%bitstring err_ip_pld =
                    {| typ : 8 ; cod : 8 ; checksum : 16 ;
                       cnx.nat_num : 16 ;
                       rest : -1 : bitstring |} in
                emit_with_err_ip_pld err_ip_pld err_ip))

    let do_port_unnat (st : State.t) (ip : Ip.Pdu.t) src_port dst_port =
        let do_unnat n =
            OrdArray.promote st.cnxs n ;
            let cnx = OrdArray.get st.cnxs n in
            cnx.last_used <- Clock.now () ;
            Log.(log st.logger Debug (lazy (Printf.sprintf "Translating back from NATed port %d to original port %d" cnx.nat_num cnx.orig_num))) ;
            patch_dst_port ip.proto (ip.payload :> bitstring) cnx.orig_num |>
            Result.iter (fun pld ->
                let payload = Payload.o pld in
                let ip = { ip with dst = cnx.orig_addr ; payload } in
                st.recv (Ip.Pdu.pack ip)) in
        let inc_sock = State.{ proto = ip.proto ;
                            src_addr = ip.src ; src_port ;
                            dst_addr = ip.dst ; dst_port } in
        match Hashtbl.find st.inc_cnxs_h inc_sock with
        | exception Not_found ->
            (* Maybe it's declared in the port forwards: *)
            (match List.find (fun (pf : State.port_forward) ->
                       pf.proto = ip.proto && pf.ext_port = dst_port
                   ) st.port_forwards with
            | exception Not_found ->
                Log.(log st.logger Warning (lazy (Printf.sprintf2
                    "No idea about that incoming %a" State.socket_print inc_sock))) ;
                if st.send_errs then (
                    if ip.proto = Ip.Proto.tcp then
                        match Tcp.Pdu.unpack (ip.payload :> bitstring) with
                        | Ok tcp ->
                            Tcp.Pdu.(make_reset_of tcp |> pack) |>
                            Ip.Pdu.make ip.proto st.addr ip.src |>
                            Ip.Pdu.pack |> st.emit
                        | _ ->
                            (* Not supposed to happen here *)
                            Log.(log st.logger Error (lazy "Cannot unpack TCP?!"))
                    else if ip.proto = Ip.Proto.udp then
                        Icmp.Pdu.(make_port_unreachable ip |> pack) |>
                        Ip.Pdu.make Ip.Proto.icmp st.addr ip.src |>
                        Ip.Pdu.pack |> st.emit
                )
            | (pf : State.port_forward) ->
                (* TODO: for TCP, only on SYNs? *)
                Log.(log st.logger Info (lazy (Printf.sprintf
                    "Incoming connection forwarded to port %d" dst_port))) ;
                (* Track this: *)
                let inc_sock = State.{ proto = ip.proto ;
                                    src_addr = ip.src ;
                                    src_port = src_port ;
                                    dst_addr = st.addr ;
                                    dst_port = dst_port }
                and out_sock = State.{ proto = ip.proto ;
                                    src_addr = pf.internal_ip ;
                                    src_port = pf.internal_port ;
                                    dst_addr = ip.src ;
                                    dst_port = src_port } in
                let n = start_tracking st pf.internal_ip pf.internal_port
                                       dst_port st.inc_cnxs_h inc_sock
                                       State.(SocketKeys { inc_sock ; out_sock }) in
                Hashtbl.add st.out_cnxs_h out_sock n ;
                (* With the tracking in place, go NAT: *)
                do_unnat n)
        | n ->
            do_unnat n

    let do_icmp_reply_unnat (st : State.t) (ip : Ip.Pdu.t) (icmp : Icmp.Pdu.t)
                            msg_type id =
        let inc_sock = State.{ src_addr = ip.src ;
                               dst_addr = ip.dst ;
                               msg_type ; id } in
        match Hashtbl.find st.inc_icmp_h inc_sock with
        | exception Not_found ->
            Log.(log st.logger Warning (lazy (Printf.sprintf2
                "No idea about that incoming %a" State.icmp_sock_print inc_sock)))
            (* Do not sent out an ICMP error on an ICMP message. *)
        | n ->
            OrdArray.promote st.cnxs n ;
            let cnx = OrdArray.get st.cnxs n in
            cnx.last_used <- Clock.now () ;
            let payload = Payload.o (patch_icmp_id icmp cnx.orig_num) in
            let ip = { ip with dst = cnx.orig_addr ; payload } in
            st.recv (Ip.Pdu.pack ip)

    let do_icmp_err_unnat (st: State.t) (ip : Ip.Pdu.t) (icmp : Icmp.Pdu.t)
                          ptr mtu (pld : Payload.t) =
        (* In that case we have to look at normal UDP/TCP connections.
         * Unpack the IP header from the payload: *)
        let recv_with_err_ip_pld err_ip_pld (err_ip : Ip.Pdu.t) (cnx : State.cnx) =
            let err_ip = { err_ip with
                             src = cnx.orig_addr ;
                         payload = Payload.o err_ip_pld } in
            let pld = Payload.o (Ip.Pdu.pack err_ip) in
            let icmp = { icmp with payload = Header { ptr ; mtu ; pld } } in
            let payload = Payload.o (Icmp.Pdu.pack icmp) in
            let ip = { ip with dst = cnx.orig_addr ; payload } in
            st.recv (Ip.Pdu.pack ip) in
        unpack_icmp_err_header st pld |> Option.may (function
        | TcpUdpCnx { err_ip ; src_port ; dst_port ; rest } ->
            (* Look for the socket answer that was expected instead: *)
            let inc_sock = State.{ proto = err_ip.proto ;
                                src_addr = err_ip.dst ;
                                src_port = dst_port ;
                                dst_addr = err_ip.src ;
                                dst_port = src_port } in
            (match Hashtbl.find st.inc_cnxs_h inc_sock with
            | exception Not_found ->
                Log.(log st.logger Warning (lazy (Printf.sprintf2
                    "Cannot find the %a which was the expected answer to \
                     the packet that caused this ICMP error"
                    State.socket_print inc_sock)))
            | n ->
                OrdArray.promote st.cnxs n ;
                let cnx = OrdArray.get st.cnxs n in
                cnx.last_used <- Clock.now () ;
                (* Put back the original source IP and port in the ICMP
                 * copy of the IP header: *)
                let%bitstring err_ip_pld =
                    {| cnx.orig_num : 16 ; dst_port : 16 ;
                       rest : -1 : bitstring |} in
                recv_with_err_ip_pld err_ip_pld err_ip cnx)
        | IcmpCnx { err_ip ; typ ; cod ; checksum ; id ; rest } ->
            let msg_type = Icmp.MsgType.(reply_of (o (typ, cod))) in
            let inc_sock = State.{ src_addr = err_ip.dst ;
                                   dst_addr = err_ip.src ;
                                   msg_type ; id } in
            (match Hashtbl.find st.inc_icmp_h inc_sock with
            | exception Not_found ->
                Log.(log st.logger Warning (lazy (Printf.sprintf2
                    "Cannot find the %a which was expected as a reply
                     to the ICMP query that caused this ICMP error"
                    State.icmp_sock_print inc_sock)))
            | n ->
                OrdArray.promote st.cnxs n ;
                let cnx = OrdArray.get st.cnxs n in
                cnx.last_used <- Clock.now () ;
                (* Put back the original source IP and ICMP id in the ICMP
                 * copy of the IP header: *)
                let%bitstring err_ip_pld =
                    {| typ : 8 ; cod : 8 ; checksum : 16 ;
                       cnx.orig_num : 16 ;
                       rest : -1 : bitstring |} in
                recv_with_err_ip_pld err_ip_pld err_ip cnx))

    (** bits are flowing from LAN to outside world *)
    let tx (st : State.t) bits =
        match Ip.Pdu.unpack bits with
        | Ok (ip : Ip.Pdu.t) ->
            if Ip.Addr.is_natable ip.src then (
                if ip.dst <> st.addr then (
                    if ip.proto = Ip.Proto.udp || ip.proto = Ip.Proto.tcp then (
                        match Ip.Pdu.get_ports ip with
                        | Ok (src_port, dst_port) ->
                            Log.(log st.logger Debug (lazy (Printf.sprintf "Translating outgoing packet of %d bytes from %s:%d to %s:%d" (bytelength bits) (Ip.Addr.to_string ip.src) src_port (Ip.Addr.to_string ip.dst) dst_port))) ;
                            do_port_nat st ip src_port dst_port
                        | Error s ->
                            Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring outgoing IP packet of %d bytes since it has no ports (%s)" (bytelength bits) (Lazy.force s))))
                    ) else if ip.proto = Ip.Proto.icmp then (
                        match Icmp.Pdu.unpack (ip.payload :> bitstring) with
                        | Ok (Icmp.Pdu.{ msg_type ; payload = Ids (id, _, _) } as icmp)
                          when Icmp.MsgType.is_request msg_type ->
                            if st.nat_pings then (
                                Log.(log st.logger Debug (lazy (Printf.sprintf "Translating outgoing ICMP request of %d bytes from src:%s, id:%d to dst:%s" (bytelength bits) (Ip.Addr.to_string ip.src) id (Ip.Addr.to_string ip.dst)))) ;
                                do_icmp_request_nat st ip icmp msg_type id
                            ) else
                                Log.(log st.logger Debug (lazy "Not NATing outgoing ICMP"))
                        (* We should also NAT outgoing ICMP errors: *)
                        | Ok (Icmp.Pdu.{ payload = Header { ptr ; mtu ; pld } ; _ } as icmp) ->
                            Log.(log st.logger Debug (lazy (Printf.sprintf "Translating outgoing ICMP error of %d bytes from src:%s to dst:%s" (bytelength bits) (Ip.Addr.to_string ip.src) (Ip.Addr.to_string ip.dst)))) ;
                            do_icmp_err_nat st ip icmp ptr mtu pld
                        (* And that's all: *)
                        | Ok _ ->
                            Log.(log st.logger Debug (lazy "Ignoring outgoing uninteresting ICMP packet"))
                        | Error s ->
                            Log.(log st.logger Debug (lazy ("Ignoring bad outgoing ICMP packet: "^ Lazy.force s)))
                    ) else (
                        Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring outgoing IP packet of %d bytes since it's neither UDP, TCP or ICMP" (bytelength bits))))
                    )
                ) else (
                    Log.(log st.logger Debug (lazy "Ignoring outgoing packet destined for my public address"))
                )
            ) else (
                Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring outgoing IP packet from non NATable address %s" (Ip.Addr.to_string ip.src))))
            )
        | Error s ->
            Log.(log st.logger Debug (lazy ("Ignoring bad outgoing IP packet: "^ Lazy.force s)))

    let rx (st : State.t) bits =
        Log.(log st.logger Debug (lazy (Printf.sprintf "Received %d bytes" (bytelength bits)))) ;
        match Ip.Pdu.unpack bits with
        | Ok (ip : Ip.Pdu.t) ->
            if ip.dst = st.addr then (
                if ip.proto = Ip.Proto.udp || ip.proto = Ip.Proto.tcp then (
                    match Ip.Pdu.get_ports ip with
                    | Ok (src_port, dst_port) ->
                        do_port_unnat st ip src_port dst_port
                    | Error s ->
                        Log.(log st.logger Debug (lazy ("Ignoring bad incoming UDP/TCP packet: "^ Lazy.force s)))
                ) else if ip.proto = Ip.Proto.icmp then (
                    match Icmp.Pdu.unpack (ip.payload :> bitstring) with
                    | Ok (Icmp.Pdu.{ msg_type ; payload = Ids (id, seq, _) } as icmp) ->
                        if Icmp.MsgType.is_reply msg_type then (
                            Log.(log st.logger Debug (lazy (Printf.sprintf "Translating incoming ICMP reply of %d bytes from %s, id:%d" (bytelength bits) (Ip.Addr.to_string ip.src) id))) ;
                            do_icmp_reply_unnat st ip icmp msg_type id
                        ) else (
                            (* When a_request, look for a port_forwards for ICMP: *)
                            match List.find (fun (pf : State.port_forward) ->
                                        pf.proto = ip.proto
                                   ) st.port_forwards with
                            | exception Not_found ->
                                if Icmp.MsgType.is_echo_request msg_type && st.answer_pings then    (
                                    Icmp.Pdu.(make_echo_reply id seq |> pack) |>
                                    Ip.(Pdu.make Proto.icmp st.addr ip.src) |>
                                    Ip.Pdu.pack |> st.emit
                                ) else
                                    Log.(log st.logger Debug (lazy "Ignoring incoming ICMP request"))
                            | (_pf : State.port_forward) ->
                                (* TODO: track this ICMP request and port forward it *)
                                ()
                        )
                    | Ok (Icmp.Pdu.{ payload = Header { ptr ; mtu ; pld } ; _ } as icmp) ->
                        Log.(log st.logger Debug (lazy (Printf.sprintf "Translating an incoming ICMP error of %d bytes from %s" (bytelength bits) (Ip.Addr.to_string ip.src)))) ;
                        do_icmp_err_unnat st ip icmp ptr mtu pld
                    | Ok _ ->
                        Log.(log st.logger Debug (lazy "Ignoring uninteresting incoming ICMP packet"))
                    | Error s ->
                        Log.(log st.logger Debug (lazy ("Ignoring bad incoming ICMP packet"^ Lazy.force s)))
                ) else (
                    Log.(log st.logger Debug (lazy "Ignoring uninteresting incoming IP packet"))
                )
            ) else (
                Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring incoming IP packet for %s (I'm %s)" (Ip.Addr.to_string ip.dst) (Ip.Addr.to_string st.addr))))
            )
        | Error s ->
            Log.(log st.logger Debug (lazy ("Ignoring incoming non-IP packet: "^ Lazy.force s)))

    (** [make ip n] returns a {!Tools.trx} corresponding to a NAT device (tx is for transmitting from the LAN to the outside) that can track [n] sockets. *)
    let make (st : State.t) =
        { ins = { write = tx st ;
                  set_read = fun f -> st.recv <- f } ;
          out = { write = rx st ;
                  set_read = fun f -> st.emit <- f } }
end
