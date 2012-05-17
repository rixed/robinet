(* vim:sw=4 ts=4 sts=4 expandtab
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
(** Transmission Control Protocol (TCP) (un)packing. *)
open Batteries
open Bitstring
open Tools

let debug = false

(** {2 Private Types} *)

let show_ports_by_name = ref true
module MakePort (Serv : sig val srv : string end) =
    MakePrivate(struct
        type t = int
        let to_string p =
            if !show_ports_by_name then (
                try (Unix.getservbyport p Serv.srv).Unix.s_name
                with Not_found -> string_of_int p
            ) else string_of_int p
        let is_valid p = p < 0x10000
        let repl_tag = "port"
    end)

module Port = MakePort (struct let srv = "tcp" end)

module SeqNum = MakePrivate(struct
    type t = int32
    let to_string t = Printf.sprintf "0x%08lX" t
    let is_valid _ = true
    let repl_tag = "seqnum"
end)

(** {2 TCP segments} *)

module Pdu =
struct
    (*$< Pdu *)
    type flags = {
        urg      : bool ;
        ack      : bool ;
        psh      : bool ;
        rst      : bool ;
        syn      : bool ;
        fin      : bool }
    let string_of_flags f =
        Printf.sprintf "%s%s%s%s%s%s"
            (if f.urg then "Urg" else "")
            (if f.ack then "Ack" else "")
            (if f.psh then "Psh" else "")
            (if f.rst then "Rst" else "")
            (if f.syn then "Syn" else "")
            (if f.fin then "Fin" else "")
    let print_flags fmt f = Format.fprintf fmt "@{<flags>%s@}" (string_of_flags f)

    (** An unpacked TCP segment. Notice the absence of the checksum, which
     * will be set to 0 by {!Tcp.Pdu.pack}, and filled in by {!Ip.Pdu.pack},
     * since it's computed over some IP fields. *)
    type t = {
        src_port : Port.t ;
        dst_port : Port.t ;
        seq_num  : SeqNum.t ;
        ack_num  : SeqNum.t ;
        win_size : int ;
        flags    : flags ;
        urg_ptr  : int ;
        options  : bitstring ;
        payload  : Payload.t }

    let make ?(src_port = Port.o 1024) ?(dst_port = Port.o 80)
             ?(seq_num = SeqNum.o 0l) ?(ack_num = SeqNum.o 0l)
             ?(urg=false) ?(ack=false) ?(psh=false) ?(rst=false) ?(syn=false) ?(fin=false)
             ?(win_size=1024) ?(urg_ptr=0)
             ?(options=empty_bitstring)
             bits =
        { src_port ; dst_port ;
          seq_num  ; ack_num ;
          flags = { urg ; ack ; psh ; rst ; syn ; fin } ;
          win_size ;
          urg_ptr  ; options ;
          payload = Payload.o bits }

    let random () =
        make ~src_port:(Port.o (randi 16)) ~dst_port:(Port.o (randi 16))
             ~seq_num:(SeqNum.o (rand32 ())) ~ack_num:(SeqNum.o (rand32 ()))
             ~urg:(randb ()) ~ack:(randb ()) ~psh:(randb ()) ~rst:(randb ()) ~syn:(randb ()) ~fin:(randb ())
             ~win_size:(randi 16) ~urg_ptr:(if randb () then randi 16 else 0)
             ~options:(randbs 16)
             (randbs 64)

    let make_reset_of pdu =
        make ~src_port:pdu.dst_port ~dst_port:pdu.src_port
             ~seq_num:pdu.ack_num ~ack_num:(SeqNum.o (Int32.succ (pdu.seq_num:>int32)))
             ~ack:true ~rst:true empty_bitstring

    let pack t =
        let hdr_len = 20 + bytelength t.options in
        concat [ (BITSTRING {
            (t.src_port :> int) : 16 ; (t.dst_port :> int) : 16 ;
            (t.seq_num :> int32)  : 32 ; (t.ack_num :> int32)  : 32 ;
            hdr_len lsr 2 : 4 ; 0 : 6 ;
            t.flags.urg : 1 ; t.flags.ack : 1 ; t.flags.psh : 1 ;
            t.flags.rst : 1 ; t.flags.syn : 1 ; t.flags.fin : 1 ;
            t.win_size : 16 ; 0 : 16 ;
            t.urg_ptr  : 16 ; t.options : -1 : bitstring }) ;
            (t.payload :> bitstring) ]

    let unpack bits = bitmatch bits with
        | { src_port : 16 ; dst_port : 16 ;
            seq_num  : 32 ; ack_num  : 32 ;
            hdr_len  : 4  ; 0 : 6 ;
            urg : 1 ; ack : 1 ; psh : 1 ; rst : 1 ; syn : 1 ; fin : 1 ;
            win_size : 16 ; _checksum : 16 ; urg_ptr  : 16 ;
            options : ((hdr_len lsl 2) - 20) * 8 : bitstring ;
            payload  : -1 : bitstring } ->
        Some { src_port = Port.o src_port ; dst_port = Port.o dst_port ;
               seq_num  = SeqNum.o seq_num  ; ack_num  = SeqNum.o ack_num ;
               flags = { urg ; ack ; psh ; rst ; syn ; fin } ;
               win_size ; urg_ptr  ; options ; payload = Payload.o payload }
        | { _ } -> err "Not TCP"

    (*$Q pack
      ((random |- pack), dump) (fun t -> t = pack (Option.get (unpack t)))
     *)
    (*$>*)
end

(** {2 Transceiver} *)

(* This TRX encode a TCP socket. Create it with the local and remote ports (so
 * after you received the initial SYN if you want to simulate a listening host). *)
(* TODO: faire un truc equivalent pour UDP *)

module TRX =
struct
    type rcvd_pkt = int * Pdu.t (* offset * packet - we keep the whole packet so we also have the flags *)
    module Streambuf = Set.Make (
        struct
            type t = rcvd_pkt
            let compare (o1, _) (o2, _) = Int.compare o1 o2
        end)

    type tcp_trx =
        { trx : trx ;
          close : unit -> unit ; (* close the trx *)
          is_closed : unit -> bool }
    type t = {
        mutable src : Port.t ;
        mutable dst : Port.t ;
        mutable emit : bitstring -> unit ;
        mutable recv : bitstring -> unit ;
        mtu : int ;
        isn : SeqNum.t ; (* initial seq num *)
        mutable rcvd_isn : SeqNum.t option ;
        mutable closed : bool ; (* set whenever the user want to cloe or we received a FIN *)
        mutable sent_fin : bool ;
        mutable sent_pld : int ;    (* what was already send, with syn and fin counting as 1 *)
        mutable sent_acked : int ;  (* what was acked from what we sent (must be <= sent_pld) *)
        mutable rcvd_pld : int ;    (* what was already received (sequencialy), with same remark *)
        mutable rcvd_acked : int ;  (* what we have acked so far (must be <= rcvd_pld) *)
        mutable rcvd_pkts : Streambuf.t ; (* what we received but haven't given to application yet *)
        mutable to_send : bitstring list ; (* what we must send next *) (* FIXME: s/list/dequeue/ *)
        mutable unacked_tx : Streambuf.t ; (* previous packet we sent but that were not acked yet *)
        mutable rcvd_fin : bool ;   (* if we already passed the fin to the application *)
        mutable cnx_wakener : tcp_trx option Lwt.u option (* the Lwt_t to wake up whenever the cnx is established *) }

    (* FIXME: ideally, wait 2 minutes after the complete close *)
    let is_closed t () = t.closed

    let int_of_bool x = if x then 1 else 0
    let (+/) = Int32.add and (-/) = Int32.sub
    let next_seq_num t = SeqNum.o ((Int32.of_int t.sent_pld) +/ (t.isn :> int32))
    let next_ack_num t =
        if t.rcvd_pld > 0 then
            Some (SeqNum.o ((Int32.of_int t.rcvd_pld) +/ ((Option.get t.rcvd_isn) :> int32)))
        else None

    let emit_one t ?(psh=false) ?(rst=false) ?(syn=false) ?(fin=false) bits =
        let src_port = t.src and dst_port = t.dst
        and seq_num = next_seq_num t and ack_num = next_ack_num t in
        let ack = ack_num <> None in
        if ack || psh || rst || syn || fin || bitstring_length bits > 0 then (
            let tcp = Pdu.make ~src_port ~dst_port ~seq_num ?ack_num
                               ~ack ~psh ~rst ~syn ~fin bits in
            if debug then Printf.printf "Tcp: Emitting a packet from %s to %s, seq %s, length %d, content '%s'\n%!" (Port.to_string src_port) (Port.to_string dst_port) (SeqNum.to_string seq_num) (bytelength bits) (string_of_bitstring bits) ;
            t.emit (Pdu.pack tcp) ;
            if ack then t.rcvd_acked <- t.rcvd_pld ;
            if bitstring_length bits > 0 then
                t.unacked_tx <- Streambuf.add (t.sent_pld, tcp) t.unacked_tx ;
            t.sent_pld <- t.sent_pld + bytelength bits + int_of_bool syn + int_of_bool fin
        )

    let emit_multi t bits =
        let rec aux off bits =
            let rem_size = bytelength bits in
            let last = rem_size <= t.mtu in
            let pkt_len = min rem_size t.mtu in
            emit_one t ~psh:last (takebits (pkt_len * 8) bits) ;
            if not last then aux (off + pkt_len) (dropbits (pkt_len * 8) bits)
        in
        aux 0 bits

    let delayed_ack t =
        if debug then Printf.printf "Tcp: I acked %d / %d received bytes\n%!" t.rcvd_acked t.rcvd_pld ;
        if t.rcvd_acked < t.rcvd_pld then emit_one t empty_bitstring

    let rec trx_of t =
        { trx = { inp = { write = tx t ;
                          set_read = fun f -> t.recv <- f } ;
                  out = { write = rx t ;
                          set_read = fun f -> t.emit <- f } } ;
          close = close t ;
          is_closed = is_closed t }

    (* The cnx is established (ie its behavior is driven by the rcvd and sent streambuf
     * whenever we had the two syns, not when they are acked. *)
    and establish_cnx t ok =
        match t.cnx_wakener with
            | Some w ->
                if debug then Printf.printf "Tcp: waking up client\n%!" ;
                Lwt.wakeup w (if ok then Some (trx_of t) else None)
            | None -> if debug then Printf.printf "Tcp: no one was waiting\n%!"

    and try_really_rx t =
        if not (Streambuf.is_empty t.rcvd_pkts) then (
            let (o, tcp) as first = Streambuf.min_elt t.rcvd_pkts in
            if debug then Printf.printf "Tcp: First of incoming waiting pkts starts at offset %d (while I've received up to %d)\n%!" o t.rcvd_pld ;
            if o > t.rcvd_pld then (
                if debug then Printf.printf "Tcp:...keep it for later\n%!"
            ) else ( (* recv now *)
                let skip = t.rcvd_pld - o in
                if skip <= Payload.length tcp.Pdu.payload then (
                    if t.rcvd_pld = 0 then (
                        ensure tcp.Pdu.flags.Pdu.syn "Tcp: Should not happen: not a syn" ;
                        t.rcvd_pld <- 1 ;
                        (* inconditionnaly answer the SYN before the client starts writing *)
                        emit_one t ~syn:(t.sent_pld=0) empty_bitstring ;
                        establish_cnx t true
                    ) ;
                    let pld = dropbytes skip (tcp.Pdu.payload :> bitstring) in
                    t.rcvd_pld <- t.rcvd_pld + (bytelength pld) ;
                    if debug then Printf.printf "Tcp: I have now read %d bytes\n%!" t.rcvd_pld ;
                    if bitstring_length pld > 0 then t.recv pld ;
                    if tcp.Pdu.flags.Pdu.fin && not t.rcvd_fin then (
                        if debug then Printf.printf "Tcp: received a FIN\n%!" ;
                        t.rcvd_pld <- t.rcvd_pld + 1 ;
                        t.rcvd_fin <- true ;
                        t.closed <- true ;
                        t.recv empty_bitstring (* signal the close *) (* FIXME: which is not very easy to use when the TRX is piped into another one. An Err would suit better *)
                    ) else if tcp.Pdu.flags.Pdu.rst && not t.rcvd_fin then (
                        if debug then Printf.printf "Tcp: received a RST\n%!" ;
                        t.rcvd_fin <- true ;
                        t.closed <- true ;
                        t.recv empty_bitstring (* signal the close *)
                    )
                ) else (
                    if debug then Printf.printf "Tcp:...obsolete packet\n%!"
                ) ;
                t.rcvd_pkts <- Streambuf.remove first t.rcvd_pkts ;
                try_really_rx t
            )
        )

    and drop_unacked_tx t =
        let seqlen tcp =
            Payload.length tcp.Pdu.payload + int_of_bool tcp.Pdu.flags.Pdu.fin + int_of_bool tcp.Pdu.flags.Pdu.syn in
        if not (Streambuf.is_empty t.unacked_tx) then (
            let (offset, tcp) as first = Streambuf.min_elt t.unacked_tx in
            let next_byte = offset + seqlen tcp in
            if t.sent_acked >= next_byte then (
                t.unacked_tx <- Streambuf.remove first t.unacked_tx ;
                drop_unacked_tx t
            )
        )

    and inqueue_pkt t tcp =
        let offset = Int32.to_int ((tcp.Pdu.seq_num :> int32) -/ ((Option.get t.rcvd_isn) :> int32)) in
        if debug then Printf.printf "Tcp: Got a packet with %d bytes, %spush\n%!"
            (Payload.length tcp.Pdu.payload) (if tcp.Pdu.flags.Pdu.psh then "" else "don't ") ;
        if tcp.Pdu.flags.Pdu.ack then (
            let acked = Int32.to_int ((tcp.Pdu.ack_num :> int32) -/ (t.isn :> int32)) in
            if acked > t.sent_acked then (
                if acked > t.sent_pld then (
                    if debug then Printf.printf "Tcp: Acking %d while we only sent %d bytes\n%!" acked t.sent_pld
                    (* FIXME: raise an error? *)
                ) else (
                    if debug then Printf.printf "Tcp: Acked %d/%d\n%!" acked t.sent_pld ;
                    t.sent_acked <- acked ;
                    drop_unacked_tx t ;
                )
            ) else if acked = t.sent_acked && not (Streambuf.is_empty t.unacked_tx) then (
                if debug then Printf.printf "Tcp: Retransmiting eveything from %d\n%!" acked ;
                let retr = ref [] and retr_pld = ref 0 in
                Streambuf.iter (fun (_, tcp) ->
                    retr := (tcp.Pdu.payload :> bitstring) :: !retr ;
                    retr_pld := !retr_pld + (Payload.length tcp.Pdu.payload)) t.unacked_tx ;
                t.unacked_tx <- Streambuf.empty ;
                t.to_send <- List.rev_append !retr t.to_send ;
                t.sent_pld <- t.sent_pld - !retr_pld ;
                try_really_tx t
            )
        ) ;
        t.rcvd_pkts <- Streambuf.add (offset, tcp) t.rcvd_pkts ;
        try_really_rx t ;
        Clock.delay (Clock.Interval.msec 200.) delayed_ack t ;
        try_really_tx t (* because the advertized window may have changed, we might want to send a FIN, etc *)

    and is_established t = t.sent_pld > 0 && t.rcvd_pld > 0

    and rx t bits = (match Pdu.unpack bits with (* If rx were receiving unpacked PDUs then we could bind unpack to rx *)
        | None -> ()
        | Some tcp ->
            if debug then Printf.printf "Tcp: Received a segment!\n" ;
            (* TODO: check checksum *)
            if tcp.Pdu.flags.Pdu.syn then (
                if t.rcvd_pld > 0 then (
                    if debug then Printf.printf "Tcp: ignoring Syn while inbound cnx is established\n" ;
                    if t.rcvd_isn = Some tcp.Pdu.seq_num then (
                        (* retransmission of the syn, we may want to act on the ack (ie. retransmit something) *)
                        inqueue_pkt t tcp
                    )
                ) else (
                    t.rcvd_isn <- Some tcp.Pdu.seq_num ;
                    inqueue_pkt t tcp
                )
            ) else if not (is_established t) then (
                if debug then Printf.printf "Tcp: ignoring recvd packet while cnx is not establised\n"
            ) else inqueue_pkt t tcp)

    and try_really_tx t = match t.to_send with
        | bits :: to_send' ->
            t.to_send <- to_send' ;
            emit_multi t bits ;
            try_really_tx t
        | [] ->
            if t.closed && not t.sent_fin then (
                if debug then Printf.printf "Tcp: sending FIN\n%!" ;
                t.sent_fin <- true ;
                emit_one t ~fin:true empty_bitstring (* TODO: pack the FIN into the last payload? *)
            ) else ( (* maybe we should ack something ? *)
            )

    and close t () =
        ensure (is_established t) "Tcp: Closing a cnx that's not established" ;
        if debug then Printf.printf "Tcp: Closing cnx\n%!" ;
        t.closed <- true ;
        try_really_tx t

    and tx t bits =
        (* TODO (in try_really_tx): Nagle algorithm: keep the data to send in a buffer
         * if it's smaller than a segment and we have sent unacked data *)
        if t.closed then (
            Printf.fprintf stderr "Tcp: writing to a closed TRX!\n%!"
        ) else if not (is_established t) then (
            Printf.fprintf stderr "Tcp: writing to a non-established TRX!\n%!"
        ) else (
            t.to_send <- t.to_send @ [ bits ] ;
            try_really_tx t
        )

    let make_ ?isn ?(mtu=1300) src dst =
        { src = src ;
          dst = dst ;
          emit = ignore ; recv = ignore ;
          mtu = mtu ;
          isn = may_default isn (fun () -> SeqNum.o 0l (*Random.int32 0x7FFFFFFFl*)) ;
          rcvd_isn = None ;
          closed = false ; sent_fin = false ;
          sent_pld = 0 ; sent_acked = 0 ; rcvd_pld = 0 ; rcvd_acked = 0 ;
          rcvd_pkts = Streambuf.empty ;
          to_send = [] ;
          unacked_tx = Streambuf.empty ;
          rcvd_fin = false ;
          cnx_wakener = None }

    let accept ?isn ?mtu src dst =
        let t = make_ ?isn ?mtu src dst in
        trx_of t

    let may_timeout t = if not (is_established t) then establish_cnx t false
    let default_connect_timeout = Clock.Interval.sec 15.
    let connect ?(timeout=default_connect_timeout) ?isn ?mtu src dst =
        let t = make_ ?isn ?mtu src dst in
        let waiter, wakener = Lwt.wait () in
        t.cnx_wakener <- Some wakener ;
        Clock.delay timeout may_timeout t ;
        emit_one t ~syn:true empty_bitstring ;
        waiter

end
