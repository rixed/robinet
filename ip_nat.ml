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

(** The lowest port number used by the address translation *)
let min_port = 1024

module State =
struct
    type socket = {       proto : Ip.Proto.t ;  (** the IP protocol *)
                       nat_port : int ;         (** the Nat ports *)
                    remote_addr : Ip.Addr.t ;   (** the other peer's address *)
                    remote_port : int }         (** the port used by the other peer *)

    type cnx = {  in_addr : Ip.Addr.t ;   (** the inside lan's host IP *)
                  in_port : int ;         (** the origin port used by this host *)
                 out_port : int }         (** the random port used by NAS in the outside *)

    (* TODO: add an optional sink inside IP *)
    type t = {      addr : Ip.Addr.t ;                  (** our IP addr *)
                    cnxs : cnx OrdArray.t ;             (** all the cnxs we remember *)
               in_cnxs_h : (socket, int) Hashtbl.t ;    (** the hash to retrieve cnxs of packets coming from the outside *)
              out_cnxs_h : (socket, int) Hashtbl.t ;    (** the hash to retrieve cnxs of packets coming from the inside *)
              (* FIXME: Ideally, those functions are serializable references to
               * the TRX they are connected to: *)
            mutable emit : bitstring -> unit ;          (** the emit function (ie. carry packets to the outside *)
            mutable recv : bitstring -> unit ;          (** the receive functon (ie. forward incoming packets from the outside *)
                  logger : Log.logger }

    (** Initialize the state for a NAT TRX. *)
    let make ~num_max_cnxs ~logger addr =
        Log.(log logger Debug (lazy (Printf.sprintf "Creating a NATer for IP %s, with %d cnxs max" (Ip.Addr.to_string addr) num_max_cnxs))) ;
        { addr ;
          cnxs = OrdArray.make num_max_cnxs { in_addr = Ip.Addr.zero ;
                                              in_port = 0 ;
                                              out_port = 0 } ;
          in_cnxs_h = Hashtbl.create num_max_cnxs ;
          out_cnxs_h = Hashtbl.create num_max_cnxs ;
          emit = ignore_bits ;
          recv = ignore_bits ;
          logger }
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
    If the cnx is found then replace the nat_addr:nat_port by cnx.in_addr:cnx.in_port.
    If nothing is found, just ignore the packet (or forward it to the sink host
    without changing the dest port).

    Behavior on outgoing packets:
{v
    [Inside host] -----------------------------> [Nat]
                      Src: inside_addr,
                      Dst: outside_addr,
                    Ports: inside_port:outside_port
v}
    Lookup (inside_addr, inside_port, nat_port, proto) in out_cnxs_h.
    If the cnx is found then replace the inside_addr:inside_port by nat_addr:cnx.out_port.
    If nothing is found, create the cnx as:
    {[ { out_port=random_port; in_addr=inside_addr; in_port=inside_port } ]}
    and insert it with the above key in out_cnxs_h.
    Also, insert this cnx in in_cnxs_h with key (outside_addr, outside_port, random_port, proto).

    *)

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

    let do_nat (st : State.t) ip src_port dst_port =
        (* Do we already follow this socket? *)
        let out_sock = State.{ proto = ip.Ip.Pdu.proto ;
                            nat_port = dst_port ;
                         remote_addr = ip.Ip.Pdu.src ;
                         remote_port = src_port } in
        let n = hash_find_or_insert st.out_cnxs_h out_sock (fun () ->
            let random_port = min_port + Random.int (65536-min_port) in
            let last_idx = OrdArray.last st.cnxs in
            OrdArray.set st.cnxs last_idx
                {  in_addr = ip.Ip.Pdu.src ;
                   in_port = src_port ;
                  out_port = random_port } ;
            (* replace also entry in in_cnxs_h *)
            let in_sock = State.{ proto = ip.Ip.Pdu.proto ;
                               nat_port = random_port ;
                            remote_addr = ip.Ip.Pdu.dst ;
                            remote_port = dst_port } in
            Hashtbl.replace st.in_cnxs_h in_sock last_idx ;
            last_idx) in
        OrdArray.promote st.cnxs n ;
        (* perform source NAT *)
        let new_src_port = (OrdArray.get st.cnxs n).out_port in
        let payload = Payload.o (patch_src_port ip.Ip.Pdu.proto
                                                (ip.Ip.Pdu.payload :> bitstring)
                                                new_src_port) in
        let ip = { ip with Ip.Pdu.src = st.addr ; payload } in
        st.emit (Ip.Pdu.pack ip)

    (** bits are flowing from LAN to outside world *)
    let tx (st : State.t) bits =
        match Ip.Pdu.unpack_with_ports bits with
        | None ->
            Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring packet of %d bytes since it's not IP" (bytelength bits))))
        | Some (ip, src_port, dst_port) ->
            if Ip.Addr.is_natable ip.Ip.Pdu.src then (
                Log.(log st.logger Debug (lazy (Printf.sprintf "Transmitting packet of %d bytes from %s:%d to %s:%d" (bytelength bits) (Ip.Addr.to_string ip.src) src_port (Ip.Addr.to_string ip.dst) dst_port))) ;
                do_nat st ip src_port dst_port
            ) else (
                Log.(log st.logger Debug (lazy (Printf.sprintf "Ignoring packet from non NATable address %s" (Ip.Addr.to_string ip.src))))
            )

    let rx (st : State.t) bits =
        Log.(log st.logger Debug (lazy (Printf.sprintf "Received %d bytes" (bytelength bits)))) ;
        Ip.Pdu.unpack_with_ports bits |>
        Option.may (fun (ip, src_port, dst_port) ->
            let in_sock = State.{ proto = ip.Ip.Pdu.proto ;
                               nat_port = dst_port ;
                            remote_addr = ip.Ip.Pdu.src ;
                            remote_port = src_port } in
            Hashtbl.find_option st.in_cnxs_h in_sock |>
            Option.may (fun n ->
                let cnx = OrdArray.get st.cnxs n in
                let payload = Payload.o (patch_dst_port ip.Ip.Pdu.proto
                                                        (ip.Ip.Pdu.payload :> bitstring)
                                                        cnx.in_port) in
                let ip = { ip with Ip.Pdu.dst = cnx.in_addr ; payload } in
                st.recv (Ip.Pdu.pack ip)))

    (** [make ip n] returns a {!Tools.trx} corresponding to a NAT device (tx is for transmitting from the LAN to the outside) that can track [n] sockets. *)
    let make (st : State.t) =
        { ins = { write = tx st ;
                  set_read = fun f -> st.recv <- f } ;
          out = { write = rx st ;
                  set_read = fun f -> st.emit <- f } }
end
