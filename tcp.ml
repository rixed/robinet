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
(** Transmission Control Protocol. *)
open Batteries
open Bitstring
open Tools

(** {2 Private Types} *)

let show_ports_by_name = ref true
module MakePort (Serv : sig val srv : string end) =
struct
    include Private.Make (struct
        type t = int
        let to_string p =
            if !show_ports_by_name then (
                try (Unix.getservbyport p Serv.srv).Unix.s_name
                with Not_found -> string_of_int p
            ) else string_of_int p
        let is_valid p = p < 0x10000
        let repl_tag = "port"
    end)

    let random () = o (Random.int 0x10000)
end

module Port = MakePort (struct let srv = "tcp" end)

module SeqNum = Private.Make (struct
    type t = int32
    let to_string t = Printf.sprintf "0x%08lX" t
    let is_valid _ = true
    let repl_tag = "seqnum"
end)

(** {2 TCP segments} *)

module Pdu =
struct
    (*$< Pdu *)

    (* Size of a TCP header without options: *)
    let no_opt_hdr_len = 20

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
        let hdr_len = no_opt_hdr_len + bytelength t.options in
        let%bitstring hdr = {|
            (t.src_port :> int) : 16 ; (t.dst_port :> int) : 16 ;
            (t.seq_num :> int32)  : 32 ; (t.ack_num :> int32)  : 32 ;
            hdr_len lsr 2 : 4 ; 0 : 6 ;
            t.flags.urg : 1 ; t.flags.ack : 1 ; t.flags.psh : 1 ;
            t.flags.rst : 1 ; t.flags.syn : 1 ; t.flags.fin : 1 ;
            t.win_size : 16 ; 0 : 16 ;
            t.urg_ptr  : 16 ; t.options : -1 : bitstring |} in
        concat [ hdr ; (t.payload :> bitstring) ]

    let unpack bits = match%bitstring bits with
        | {| src_port : 16 ; dst_port : 16 ;
             seq_num  : 32 ; ack_num  : 32 ;
             hdr_len  : 4  ; 0 : 6 ;
             urg : 1 ; ack : 1 ; psh : 1 ; rst : 1 ; syn : 1 ; fin : 1 ;
             win_size : 16 ; _checksum : 16 ; urg_ptr  : 16 ;
             options : ((hdr_len lsl 2) - no_opt_hdr_len) * 8 : bitstring ;
             payload  : -1 : bitstring |} ->
        Ok { src_port = Port.o src_port ; dst_port = Port.o dst_port ;
               seq_num  = SeqNum.o seq_num  ; ack_num  = SeqNum.o ack_num ;
               flags = { urg ; ack ; psh ; rst ; syn ; fin } ;
               win_size ; urg_ptr  ; options ; payload = Payload.o payload }
        | {| _ |} -> Error (lazy "Not TCP")

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (Result.get_ok (unpack t)))
     *)

    let has_payload t =
        Payload.length t.payload = 0

    (** The six flags, as the choices of a set: which of them are raised is
     * what a segment says, and any of them may be. Numbered by their places,
     * having no numbers of their own -- each is a bit of the header, and a bit
     * is not a value. *)
    let flag_choices =
        Widget.choices [| "Urg" ; "Ack" ; "Psh" ; "Rst" ; "Syn" ; "Fin" |]

    (** What a segment holds, for the interface to show and, later, to edit.
     *
     * No checksum: it is not in [t] either, being computed over fields of the
     * IP header below (see [Ip.Pdu.pack]), so there is nothing here to show.
     * The options are bytes until somebody writes the kind that describes
     * them, which is the day the NOP option makes a variant case that carries
     * nothing. *)
    module Kinds =
    struct
        open SimTypes
        let port = IRange (0, 0xffff)
        let seq_num = IRange (0, 0xffff_ffff)
        let flags = Set flag_choices
        let win_size = IRange (0, 0xffff)
        let urg_ptr = IRange (0, 0xffff)
        let options = BRange (0, 40)
        let payload = BRange (0, 0xffff)
    end

    let kind =
        Widget.record
            [| "source port", Kinds.port ;
               "destination port", Kinds.port ;
               "sequence number", Kinds.seq_num ;
               "acknowledgment number", Kinds.seq_num ;
               "flags", Kinds.flags ;
               "window size", Kinds.win_size ;
               "urgent pointer", Kinds.urg_ptr ;
               "options", Kinds.options ;
               "payload", Kinds.payload |]

    let to_json (t : t) =
        let raised =
            [ t.flags.urg ; t.flags.ack ; t.flags.psh ;
              t.flags.rst ; t.flags.syn ; t.flags.fin ] |>
            List.filteri_map (fun i up -> if up then Some (`Int i) else None) in
        `Assoc [ "source port", `Int (t.src_port :> int) ;
                 "destination port", `Int (t.dst_port :> int) ;
                 "sequence number", `Int (uint32 (t.seq_num :> int32)) ;
                 "acknowledgment number", `Int (uint32 (t.ack_num :> int32)) ;
                 "flags", `List raised ;
                 "window size", `Int t.win_size ;
                 "urgent pointer", `Int t.urg_ptr ;
                 "options", Widget.json_of_bytes t.options ;
                 "payload", Widget.json_of_bytes (t.payload :> bitstring) ]

    (* Where each field is in [kind], which [of_synth] reads them by: *)
    module Field =
    struct
        let i = Widget.field_index kind
        let src_port = i "source port"
        let dst_port = i "destination port"
        let seq_num = i "sequence number"
        let ack_num = i "acknowledgment number"
        let flags = i "flags"
        let win_size = i "window size"
        let urg_ptr = i "urgent pointer"
        let options = i "options"
        let payload = i "payload"
    end

    (* [r] are the fields of a synth of [kind] (see [Generator.fields]): *)
    let of_synth r ?upper ?prev gen_values =
        let open Generator in
        let int i ?auto kind =
            int_of_nth r i gen_values ?auto kind identity in
        let port i prev_port =
            int_of_nth r i gen_values ?auto:(mostly_same prev_port Port.random)
                       Kinds.port Port.o in
        (* An automatic value is what a segment would plausibly carry: the
         * flags of a segment carrying data, rather than any of the 64
         * combinations of them -- half of which no stack would ever send. The
         * places are those [flag_choices] names, which [raised] reads back. *)
        let flags =
            of_nth r Field.flags gen_values ~auto:(fun () -> [ 1 (* Ack *) ])
                   Kinds.flags (Widget.to_choices flag_choices) in
        let raised i = List.mem i flags in
        let seq32 (n : SeqNum.t) = uint32 (n :> int32) in
        (* Given the previous segment: the sequence number that follows it, and
         * an acknowledgment number that moves on now and then, what goes the
         * other way being unknown. *)
        let seq_num =
            int Field.seq_num Kinds.seq_num ?auto:(Option.map (fun p () ->
                let one b = if b then 1 else 0 in
                (seq32 p.seq_num + Payload.length p.payload +
                 one p.flags.syn + one p.flags.fin) land 0xffff_ffff) prev)
        and ack_num =
            int Field.ack_num Kinds.seq_num ?auto:(Option.map (fun p () ->
                let ack = seq32 p.ack_num in
                if Random.bool () then ack
                else (ack + 1000 + Random.int 2000) land 0xffff_ffff) prev) in
        { src_port = port Field.src_port (Option.map (fun p -> p.src_port) prev) ;
          dst_port = port Field.dst_port (Option.map (fun p -> p.dst_port) prev) ;
          seq_num = SeqNum.o (Int32.of_int seq_num) ;
          ack_num = SeqNum.o (Int32.of_int ack_num) ;
          win_size = int Field.win_size Kinds.win_size ;
          flags = { urg = raised 0 ; ack = raised 1 ; psh = raised 2 ;
                    rst = raised 3 ; syn = raised 4 ; fin = raised 5 } ;
          (* Where the urgent data ends, which is nowhere unless Urg says
             so; and no options rather than 40 random bytes of them, which
             nothing can read past. *)
          urg_ptr = int Field.urg_ptr ~auto:(fun () -> 0) Kinds.urg_ptr ;
          options = bs_of_nth r Field.options gen_values
                              ~auto:(fun () -> empty_bitstring) Kinds.options ;
          payload = Payload.o (payload_of_nth ?upper r Field.payload
                                              gen_values Kinds.payload) }

    (*$Q of_synth
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_consts (fun js g -> \
            of_synth (Generator.fields_of_synth kind js) g) kind to_json)
      (Q.make ~print:(fun t -> Yojson.Basic.to_string (to_json t)) \
              (fun _ -> random ())) \
        (Generator.reads_autos (fun js g -> \
            of_synth (Generator.fields_of_synth kind js) g) kind to_json)
     *)

    (*$Q kind
      (Q.make (fun _ -> random ())) (fun t -> \
        try Widget.check_value kind (to_json t) ; true \
        with _ -> false)
     *)

    (*$>*)
end

(** {2 Transceiver} *)

(* This TRX encode a TCP socket. Create it with the local and remote ports (so
 * after you received the initial SYN if you want to simulate a listening host). *)

module TRX =
struct
    type rcvd_pkt = int * Pdu.t (* offset * packet - we keep the whole packet so we also have the flags *)
    module Streambuf = Set.Make (
        struct
            type t = rcvd_pkt
            let compare (o1, _) (o2, _) = Int.compare o1 o2
        end)

    (* Loss recovery, and the sent_pld at which it ends: *)
    type recovery =
        | Open
        | Fast of int (* after 3 dup acks *)
        | Timeout of int (* after the retransmission timer expired *)

    type tcp_trx = {
        trx : trx ;
        close : unit -> unit ; (* close the trx (only once established) *)
        is_closed : unit -> bool ;
        is_established : unit -> bool }
    type t = {
        logger : Log.t ;
        power : Simulation.power ;
        mutable tcp_trx : tcp_trx ;
        mutable src : Port.t ;
        mutable dst : Port.t ;
        mutable emit : bitstring -> unit ;
        mutable emit_busy_for : unit -> Clock.Interval.t ;
        mutable recv : bitstring -> unit ;
        mutable recv_busy_for : unit -> Clock.Interval.t ;
        mss : int ;  (* max segment size: used to segment payloads *)
        isn : SeqNum.t ; (* initial seq num *)
        mutable rcvd_isn : SeqNum.t option ;
        mutable closed : bool ;  (* set whenever the user want to close or we received a FIN *)
        mutable sent_fin : bool ;
        mutable sent_pld : int ;  (* what was already send, with syn and fin counting as 1 *)
        mutable sent_acked : int ;  (* what was acked from what we sent (must be <= sent_pld) *)
        mutable rcvd_pld : int ;  (* what was already received (sequentially), with same remark *)
        mutable rcvd_acked : int ;  (* what we have acked so far (must be <= rcvd_pld) *)
        mutable rcvd_pkts : Streambuf.t ; (* what we received but haven't given to application yet *)
        mutable to_send : bitstring list ; (* what we must send next *) (* FIXME: s/list/dequeue/ *)
        mutable to_send_len : int ; (* bytes in to_send *)
        snd_buf : int ; (* to_send makes writers wait once it has that many bytes *)
        mutable unacked_tx : Streambuf.t ; (* previous packet we sent but that were not acked yet *)
        mutable rcvd_fin : bool ; (* if we already passed the fin to the application *)
        rcv_buf : int ; (* the window we advertise and enforce (at most 0xffff for lack of window scaling) *)
        mutable snd_wnd : int ; (* the window the peer advertises: bytes allowed in flight *)
        mutable snd_wl1 : int ; (* rcvd offset of the segment that set snd_wnd... *)
        mutable snd_wl2 : int ; (* ...and its ack (RFC 793) *)
        mutable max_snd_wnd : int ; (* largest snd_wnd seen *)
        mutable persist_gen : int ; (* only the last armed persist timer is live *)
        mutable persist_armed : bool ;
        mutable probes : int ; (* window probes since we last sent data *)
        mutable unanswered_probes : int ; (* window probes since the peer last acked anything *)
        mutable cwnd : int ;  (* congestion window: bytes allowed in flight (sent_pld - sent_acked) *)
        mutable ssthresh : int ; (* slow start threshold (TODO: cached per dest in a host to avoid initial overshoot) *)
        mutable ca_acked : int ; (* bytes acked toward the next cwnd increase *)
        mutable dup_acks : int ; (* consecutive duplicate acks received *)
        mutable recovery : recovery ;
        mutable rtt : (Clock.Interval.t * Clock.Interval.t) option ; (* smoothed RTT and its variation, once measured *)
        mutable rtt_probe : (int * Clock.Time.t) option ; (* sent_pld after the timed segment, and when it was sent *)
        mutable rto : Clock.Interval.t ; (* retransmission timeout *)
        min_rto_var : Clock.Interval.t ; (* lower bound of the variation term of rto *)
        max_rto : Clock.Interval.t ;
        max_timeouts : int ; (* consecutive timeouts before giving up on the cnx *)
        mutable rto_gen : int ; (* only the last armed timer is live *)
        mutable rto_armed : bool ;
        mutable timeouts : int ; (* consecutive expirations of the retransmission timer *)
        mutable cnx_established_cont : (tcp_trx option -> unit) option (* what to do when the cnx is established *) }

    (* FIXME: ideally, wait 2 minutes after the complete close *)
    let is_closed t () = t.closed

    let int_of_bool x = if x then 1 else 0
    let (+/) = Int32.add and (-/) = Int32.sub
    let next_seq_num t = SeqNum.o ((Int32.of_int t.sent_pld) +/ (t.isn :> int32))
    let next_ack_num t =
        if t.rcvd_pld > 0 then
            Some (SeqNum.o ((Int32.of_int t.rcvd_pld) +/ ((Option.get t.rcvd_isn) :> int32)))
        else None

    let in_flight t = t.sent_pld - t.sent_acked

    let acked_of t tcp = Int32.to_int ((tcp.Pdu.ack_num :> int32) -/ (t.isn :> int32))

    let adv_wnd t = min t.rcv_buf 0xffff

    (* Re-emit the oldest unacked segment, with an up to date ack *)
    let retransmit_first t =
        match Streambuf.min_elt_opt t.unacked_tx with
        | None -> ()
        | Some (offset, tcp) ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Retransmitting from %d" offset))) ;
            t.rtt_probe <- None ; (* Karn's algorithm: the ack would be ambiguous *)
            let tcp = match next_ack_num t with
                | Some ack_num ->
                    t.rcvd_acked <- t.rcvd_pld ;
                    { tcp with ack_num ; win_size = adv_wnd t ;
                               flags = { tcp.flags with ack = true } }
                | None ->
                    tcp in
            Simulation.asap t.power t.emit (Pdu.pack tcp)

    (* Retransmission timer (RFC 6298), with a lower bound on the variation term
     * (as Linux does) so that delayed acks do not cause spurious timeouts: *)
    let update_rtt t sample =
        let open Clock in
        let srtt, rttvar =
            match t.rtt with
            | None ->
                sample, Interval.div sample 2.
            | Some (srtt, rttvar) ->
                Interval.(add (mul srtt 0.875) (mul sample 0.125)),
                Interval.(add (mul rttvar 0.75) (mul (abs (sub srtt sample)) 0.25)) in
        t.rtt <- Some (srtt, rttvar) ;
        t.rto <- min t.max_rto (Interval.add srtt (max t.min_rto_var (Interval.mul rttvar 4.))) ;
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: RTT sample %s, srtt %s, rto %s"
            (Interval.to_string sample) (Interval.to_string srtt) (Interval.to_string t.rto))))

    let stop_rto t =
        t.rto_gen <- t.rto_gen + 1 ;
        t.rto_armed <- false

    (* Give up on the cnx, as if it was reset *)
    let abort t =
        Log.(log t.logger Debug (lazy "Tcp: Aborting the cnx")) ;
        stop_rto t ;
        t.closed <- true ;
        t.sent_fin <- true ;
        t.rcvd_fin <- true ;
        t.to_send <- [] ;
        t.to_send_len <- 0 ;
        t.unacked_tx <- Streambuf.empty

    let rec arm_rto t =
        stop_rto t ;
        t.rto_armed <- true ;
        Simulation.delay t.power t.rto (on_rto t) t.rto_gen

    and on_rto t gen =
        if gen = t.rto_gen then (
            t.timeouts <- t.timeouts + 1 ;
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Retransmission timeout #%d" t.timeouts))) ;
            if t.timeouts > t.max_timeouts then (
                abort t ;
                Simulation.asap t.power t.recv empty_bitstring (* signal the close *)
            ) else (
                (* Only the first timeout tells about the window that was in flight: *)
                if t.timeouts = 1 then t.ssthresh <- max (in_flight t / 2) (2 * t.mss) ;
                t.cwnd <- t.mss ;
                t.ca_acked <- 0 ;
                t.dup_acks <- 0 ;
                t.recovery <- Timeout t.sent_pld ;
                t.rto <- min t.max_rto (Clock.Interval.mul t.rto 2.) ;
                retransmit_first t ;
                arm_rto t
            )
        )

    (* TX a single segment *)
    let emit_one t ?(psh=false) ?(rst=false) ?(syn=false) ?(fin=false) bits =
        let src_port = t.src and dst_port = t.dst
        and seq_num = next_seq_num t and ack_num = next_ack_num t in
        let ack = ack_num <> None in
        if ack || psh || rst || syn || fin || bitstring_length bits > 0 then (
            let tcp = Pdu.make ~src_port ~dst_port ~seq_num ?ack_num
                               ~win_size:(adv_wnd t) ~ack ~psh ~rst ~syn ~fin bits in
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Emitting a packet from %s to %s, seq %s, length %d, content '%s'" (Port.to_string src_port) (Port.to_string dst_port) (SeqNum.to_string seq_num) (bytelength bits) (string_of_bitstring bits)))) ;
            Simulation.asap t.power t.emit (Pdu.pack tcp) ;
            if ack then t.rcvd_acked <- t.rcvd_pld ;
            let seq_len = bytelength bits + int_of_bool syn + int_of_bool fin in
            if seq_len > 0 then (
                t.unacked_tx <- Streambuf.add (t.sent_pld, tcp) t.unacked_tx ;
                if t.rtt_probe = None then
                    t.rtt_probe <- Some (t.sent_pld + seq_len, Simulation.now t.power.sim) ;
                if not t.rto_armed then arm_rto t
            ) ;
            t.sent_pld <- t.sent_pld + seq_len
        )

    (* Byte counting (RFC 3465), with L = 2 MSS in slow start *)
    let grow_cwnd t newly_acked =
        if t.cwnd < t.ssthresh then
            t.cwnd <- t.cwnd + min newly_acked (2 * t.mss)
        else (
            t.ca_acked <- t.ca_acked + newly_acked ;
            if t.ca_acked >= t.cwnd then (
                t.ca_acked <- t.ca_acked - t.cwnd ;
                t.cwnd <- t.cwnd + t.mss
            )
        ) ;
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: cwnd is now %d" t.cwnd)))

    (* Fast retransmit and fast recovery (RFC 5681 and 6582) *)
    let fast_retransmit t =
        t.ssthresh <- max (in_flight t / 2) (2 * t.mss) ;
        t.cwnd <- t.ssthresh + 3 * t.mss ; (* the 3 dup acks are segments that left the network *)
        t.ca_acked <- 0 ;
        t.recovery <- Fast t.sent_pld ;
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Loss detected, ssthresh is now %d" t.ssthresh))) ;
        retransmit_first t

    let delayed_ack (t : t) =
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: I acked %d / %d received bytes" t.rcvd_acked t.rcvd_pld))) ;
        if t.rcvd_acked < t.rcvd_pld then emit_one t empty_bitstring

    (* The cnx is established (ie its behavior is driven by the rcvd and sent streambuf)
     * whenever we had the two syns, not when they are acked. *)
    let rec establish_cnx t ok =
        match t.cnx_established_cont with
        | Some f ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: calling continuation for serving new cnx on port %d" (t.src :> int)))) ;
            f (if ok then Some t.tcp_trx else None)
        | None -> Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: no one was waiting")))

    and try_really_rx t =
        if not (Streambuf.is_empty t.rcvd_pkts) then (
            let (o, tcp) as first = Streambuf.min_elt t.rcvd_pkts in
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: First of incoming waiting pkts starts at offset %d (while I've received up to %d)" o t.rcvd_pld))) ;
            if o > t.rcvd_pld then (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp:...keep it for later")))
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
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: I have now read %d bytes" t.rcvd_pld))) ;
                    if bitstring_length pld > 0 then Simulation.asap t.power t.recv pld ;
                    if tcp.Pdu.flags.Pdu.fin && not t.rcvd_fin then (
                        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: received a FIN"))) ;
                        t.rcvd_pld <- t.rcvd_pld + 1 ;
                        t.rcvd_fin <- true ;
                        t.closed <- true ;
                        Simulation.asap t.power t.recv empty_bitstring (* signal the close *) (* FIXME: which is not very easy to use when the TRX is piped into another one. An Err would suit better *)
                    ) else if tcp.Pdu.flags.Pdu.rst && not t.rcvd_fin then (
                        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: received a RST"))) ;
                        t.rcvd_fin <- true ;
                        t.closed <- true ;
                        Simulation.asap t.power t.recv empty_bitstring (* signal the close *)
                    )
                ) else (
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp:...obsolete packet")))
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

    and update_snd_wnd t offset acked win =
        if offset > t.snd_wl1 || offset = t.snd_wl1 && acked >= t.snd_wl2 then (
            if win <> t.snd_wnd then
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Peer window is now %d" win))) ;
            t.snd_wnd <- win ;
            t.snd_wl1 <- offset ;
            t.snd_wl2 <- acked ;
            t.max_snd_wnd <- max t.max_snd_wnd win
        )

    and inqueue_pkt t tcp =
        let offset = Int32.to_int ((tcp.Pdu.seq_num :> int32) -/ ((Option.get t.rcvd_isn) :> int32)) in
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Got a packet with %d bytes, %spush" (Payload.length tcp.Pdu.payload) (if tcp.Pdu.flags.Pdu.psh then "" else "don't ")))) ;
        let len = Payload.length tcp.Pdu.payload in
        if tcp.Pdu.flags.Pdu.ack then (
            let acked = acked_of t tcp in
            if acked > t.sent_acked then (
                if acked > t.sent_pld then (
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Acking %d while we only sent %d bytes" acked t.sent_pld)))
                    (* FIXME: raise an error? *)
                ) else (
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Acked %d/%d" acked t.sent_pld))) ;
                    let newly_acked = acked - max 1 t.sent_acked (* the SYN does not count *) in
                    t.sent_acked <- acked ;
                    t.dup_acks <- 0 ;
                    drop_unacked_tx t ;
                    (match t.rtt_probe with
                    | Some (seq, sent) when acked >= seq ->
                        t.rtt_probe <- None ;
                        update_rtt t (Clock.Time.diff (Simulation.now t.power.sim) sent)
                    | _ -> ()) ;
                    t.timeouts <- 0 ;
                    if in_flight t = 0 then stop_rto t else arm_rto t ;
                    (* Partial acks: the next hole is lost too *)
                    match t.recovery with
                    | Open ->
                        grow_cwnd t newly_acked
                    | Fast recover when acked < recover ->
                        t.cwnd <- max t.mss (t.cwnd - newly_acked + t.mss) ;
                        retransmit_first t
                    | Timeout recover when acked < recover ->
                        grow_cwnd t newly_acked ;
                        retransmit_first t
                    | Fast _ ->
                        Log.(log t.logger Debug (lazy "Tcp: Recovered")) ;
                        t.recovery <- Open ;
                        t.cwnd <- min t.ssthresh (in_flight t + t.mss)
                    | Timeout _ ->
                        Log.(log t.logger Debug (lazy "Tcp: Recovered")) ;
                        t.recovery <- Open
                )
            ) else if acked = t.sent_acked && len = 0 && tcp.Pdu.win_size = t.snd_wnd &&
                      offset >= t.rcvd_pld && (* not a window probe *)
                      not (tcp.Pdu.flags.Pdu.syn || tcp.Pdu.flags.Pdu.fin) &&
                      not (Streambuf.is_empty t.unacked_tx) then (
                t.dup_acks <- t.dup_acks + 1 ;
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Duplicate ack #%d for %d" t.dup_acks acked))) ;
                match t.recovery with
                | Open -> if t.dup_acks = 3 then fast_retransmit t
                | Fast _ -> t.cwnd <- t.cwnd + t.mss (* another segment left the network *)
                | Timeout _ -> ()
            )
        ) ;
        (* Only after the ack, which must not see a window update as a dup ack: *)
        if tcp.Pdu.flags.Pdu.ack then (
            t.unanswered_probes <- 0 ;
            let acked = acked_of t tcp in
            if acked >= t.sent_acked && acked <= t.sent_pld then
                update_snd_wnd t offset acked tcp.Pdu.win_size
        ) else if tcp.Pdu.flags.Pdu.syn then
            update_snd_wnd t offset 0 tcp.Pdu.win_size ;
        (* Out of order, filling a gap, or already received: *)
        let unexpected = offset <> t.rcvd_pld || not (Streambuf.is_empty t.rcvd_pkts) in
        let is_probe = len = 0 && offset < t.rcvd_pld in
        (* With an application that reads at once, our window is all of rcv_buf,
         * out of order data included: *)
        let beyond_wnd = len > 0 && offset >= t.rcvd_pld + adv_wnd t in
        if beyond_wnd then
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Dropping data at %d, beyond our window" offset)))
        else
            t.rcvd_pkts <- Streambuf.add (offset, tcp) t.rcvd_pkts ;
        try_really_rx t ;
        try_really_tx t ; (* because the advertized window may have changed, we might want to send a FIN, etc *)
        (* Data (or SYN/FIN) is acked at once when unexpected (so the sender sees
         * duplicate acks, or a lost ack is replaced), when more than one MSS is
         * unacked (ie. every second full segment) or on FIN, otherwise after at
         * most 200ms. A segment below what was received (a window probe) or
         * beyond our window is acked at once, for its sender to learn our window. *)
        let consumes_seq = len > 0 || tcp.Pdu.flags.Pdu.syn || tcp.Pdu.flags.Pdu.fin in
        if is_probe || beyond_wnd ||
           consumes_seq && (unexpected ||
                            t.rcvd_acked < t.rcvd_pld && tcp.Pdu.flags.Pdu.fin ||
                            t.rcvd_pld - t.rcvd_acked > t.mss) then
            emit_one t empty_bitstring
        else if t.rcvd_acked < t.rcvd_pld then
            Simulation.delay t.power (Clock.Interval.msec 200.) delayed_ack t

    and is_established t = t.sent_pld > 0 && t.rcvd_pld > 0

    and rx (t : t) bits = (match Pdu.unpack bits with (* If rx were receiving unpacked PDUs then we could bind unpack to rx *)
        | Error s ->
            Log.(log t.logger Warning s)
        | Ok tcp ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Received a segment!"))) ;
            (* TODO: check checksum *)
            if tcp.Pdu.flags.Pdu.syn then (
                if t.rcvd_pld > 0 then (
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: ignoring Syn while inbound cnx is established"))) ;
                    if t.rcvd_isn = Some tcp.Pdu.seq_num then (
                        (* retransmission of the syn, we may want to act on the ack (ie. retransmit something) *)
                        inqueue_pkt t tcp
                    )
                ) else (
                    t.rcvd_isn <- Some tcp.Pdu.seq_num ;
                    inqueue_pkt t tcp
                )
            ) else if not (is_established t) then (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: ignoring recvd packet while cnx is not established")))
            ) else inqueue_pkt t tcp)

    (* Persist timer: with nothing in flight, no ack would tell that the peer's
     * window reopened, so we ask, backing off up to max_rto. *)
    and arm_persist t =
        t.persist_armed <- true ;
        let rec backoff d n =
            if n = 0 || d >= t.max_rto then min d t.max_rto
            else backoff (Clock.Interval.mul d 2.) (n - 1) in
        Simulation.delay t.power (backoff t.rto t.probes) (on_persist t) t.persist_gen

    and stop_persist t =
        t.persist_gen <- t.persist_gen + 1 ;
        t.persist_armed <- false ;
        t.probes <- 0

    and on_persist t gen =
        if gen = t.persist_gen then (
            t.persist_armed <- false ;
            if t.to_send <> [] && in_flight t = 0 then (
                if t.snd_wnd > 0 then (
                    (* Open, but too small for SWS avoidance: send what fits *)
                    tx_queued t true
                ) else if t.unanswered_probes >= t.max_timeouts then (
                    abort t ;
                    Simulation.asap t.power t.recv empty_bitstring (* signal the close *)
                ) else (
                    send_probe t ;
                    t.probes <- t.probes + 1 ;
                    t.unanswered_probes <- t.unanswered_probes + 1 ;
                    arm_persist t
                )
            )
        )

    (* As Linux does, an empty segment one byte below what was sent, which the
     * peer must ack, rather than one byte beyond its window: *)
    and send_probe t =
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Window probe #%d" (t.probes + 1)))) ;
        let seq_num = SeqNum.o ((Int32.of_int (t.sent_pld - 1)) +/ (t.isn :> int32))
        and ack_num = next_ack_num t in
        if ack_num <> None then t.rcvd_acked <- t.rcvd_pld ;
        let tcp = Pdu.make ~src_port:t.src ~dst_port:t.dst ~seq_num ?ack_num
                           ~ack:(ack_num <> None) ~win_size:(adv_wnd t) empty_bitstring in
        Simulation.asap t.power t.emit (Pdu.pack tcp)

    and try_really_tx t = tx_queued t false

    (* Data is sent one segment at a time, only while the whole segment fits in cwnd.
     * Each ack calls back here to send what cwnd now allows.
     * Limited Transmit (RFC 3042): each of the first two dup acks allows one more
     * segment, so that small windows still get the 3 dup acks of a fast retransmit.
     * The peer's window is never exceeded, but a segment is cut down to fit it
     * if that sends at least half the largest window seen (RFC 1122 SWS avoidance),
     * or if [force]d to.
     * With nothing in flight, only the peer's window can hold data back, and
     * then the persist timer is armed. *)
    and tx_queued t force = match t.to_send with
        | bits :: to_send' ->
            let bits_len = bytelength bits in
            let rwnd_room = t.snd_wnd - in_flight t in
            let len =
                let len = min bits_len t.mss in
                if len <= rwnd_room then len
                else if rwnd_room > 0 && (force || 2 * rwnd_room >= t.max_snd_wnd) then rwnd_room
                else 0 in
            let wnd =
                if t.recovery = Open then t.cwnd + min t.dup_acks 2 * t.mss
                else t.cwnd in
            if len > 0 && in_flight t + len <= wnd then (
                let is_last = len = bits_len in
                stop_persist t ;
                emit_one t ~psh:is_last (takebytes len bits) ;
                t.to_send <- if is_last then to_send' else dropbytes len bits :: to_send' ;
                t.to_send_len <- t.to_send_len - len ;
                try_really_tx t
            ) else (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: window full (%d in flight, cwnd %d, peer window %d)" (in_flight t) wnd t.snd_wnd))) ;
                if in_flight t = 0 && not t.persist_armed then arm_persist t
            )
        | [] ->
            if t.closed && not t.sent_fin then (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: sending FIN"))) ;
                t.sent_fin <- true ;
                emit_one t ~fin:true empty_bitstring (* TODO: pack the FIN into the last payload? *)
            ) else ( (* maybe we should ack something ? *)
            )

    and close t () =
        ensure (is_established t) "Tcp: Closing a cnx that's not established" ;
        Log.(log t.logger Debug (lazy (Printf.sprintf "Tcp: Will close the cnx"))) ;
        t.closed <- true ;
        try_really_tx t

    and tx t bits =
        (* TODO (in try_really_tx): Nagle algorithm: keep the data to send in a buffer
         * if it's smaller than a segment and we have sent unacked data *)
        if t.closed then (
            Printf.fprintf stderr "Tcp: writing to a closed TRX!"
        ) else if not (is_established t) then (
            Printf.fprintf stderr "Tcp: writing to a non-established TRX!"
        ) else (
            t.to_send <- t.to_send @ [ bits ] ;
            t.to_send_len <- t.to_send_len + bytelength bits ;
            try_really_tx t
        )

    (* A full send buffer drains as acks come back, so in about an RTT; and
     * what does leave it then waits for what is below. *)
    let busy_for t () =
        let own =
            if t.to_send_len < t.snd_buf then Clock.Interval.zero
            else match t.rtt with Some (srtt, _) -> srtt | None -> t.rto in
        max own (t.emit_busy_for ())

    (* Retransmission defaults are those of Linux: *)
    let make power ?isn ?(mss=536) ?(ssthresh=max_int) ?(snd_buf=65536) ?(rcv_buf=65535)
             ?(initial_rto=Clock.Interval.sec 1.) ?(min_rto_var=Clock.Interval.msec 200.)
             ?(max_rto=Clock.Interval.sec 120.) ?(max_timeouts=15)
             src dst logger =
        let t = { logger ; power ;
                  src = src ;
                  dst = dst ;
                  emit = ignore_bits ~logger ;
                  emit_busy_for = never_busy ;
                  recv = ignore_bits ~logger ;
                  recv_busy_for = never_busy ;
                  mss ; cwnd = mss ; ssthresh ; ca_acked = 0 ; dup_acks = 0 ; recovery = Open ;
                  rtt = None ; rtt_probe = None ; rto = initial_rto ; rto_gen = 0 ;
                  min_rto_var ; max_rto ; max_timeouts ;
                  rto_armed = false ; timeouts = 0 ;
                  isn = may_default isn (fun () -> SeqNum.o 0l (*Random.int32 0x7FFFFFFFl*)) ;
                  rcvd_isn = None ;
                  closed = false ; sent_fin = false ;
                  sent_pld = 0 ; sent_acked = 0 ; rcvd_pld = 0 ; rcvd_acked = 0 ;
                  rcvd_pkts = Streambuf.empty ;
                  to_send = [] ; to_send_len = 0 ; snd_buf ;
                  unacked_tx = Streambuf.empty ;
                  rcvd_fin = false ;
                  rcv_buf ; snd_wnd = 0 ; snd_wl1 = -1 ; snd_wl2 = 0 ; max_snd_wnd = 0 ;
                  persist_gen = 0 ; persist_armed = false ; probes = 0 ; unanswered_probes = 0 ;
                  cnx_established_cont = None ;
                  tcp_trx = { trx = null_trx ~logger ;
                              close = ignore ;
                              is_closed = (fun _ -> true) ;
                              is_established = (fun _ -> false) } } in
        t.tcp_trx <- { trx =  { ins = { write = tx t ;
                                        busy_for = busy_for t ;
                                        set_read = fun f busy_for ->
                                            t.recv <- f ;
                                            t.recv_busy_for <- busy_for } ;
                                out = { write = rx t ;
                                        busy_for = (fun () -> t.recv_busy_for ()) ;
                                        set_read = fun f busy_for ->
                                            t.emit <- f ;
                                            t.emit_busy_for <- busy_for } } ;
                       close = close t ;
                       is_closed = is_closed t ;
                       is_established = (fun () -> is_established t) } ;
        t

    let may_timeout t =
        if not (is_established t) then (
            establish_cnx t false ;
            t.cnx_established_cont <- None ;
            abort t
        )
    let default_connect_timeout = Clock.Interval.sec 15.
    let connect ?(timeout=default_connect_timeout) t cont =
        t.cnx_established_cont <- Some cont ;
        Simulation.delay t.power timeout may_timeout t ;
        emit_one t ~syn:true empty_bitstring

end

(*$< TRX *)
(*$R make
    (* [a] sends [size] bytes to [b], which advertises [rcv_buf] in segments
     * that [b_to_a] may then rewrite or drop. Returns [a], the most that was
     * in flight, the bytes received, the window probes sent and how far beyond
     * what it received [b] ever held data. *)
    let transfer ?rcv_buf ?(mss=100) ?max_timeouts ?(b_to_a=fun _ p -> Some p) size =
        let sim = Simulation.make ~realtime:false "peer-window" in
        let power = sim.root.power and logger = Log.make () in
        let a = make power ~mss ?max_timeouts (Port.o 1) (Port.o 2) logger
        and b = make power ~mss ?rcv_buf (Port.o 2) (Port.o 1) logger in
        let max_in_flight = ref 0 and rcvd = ref 0 and probes = ref 0 and ahead = ref 0 in
        a.tcp_trx.trx.out --> sink (fun bits ->
            max_in_flight := max !max_in_flight (in_flight a) ;
            let p = Result.get_ok (Pdu.unpack bits) in
            if Payload.length p.Pdu.payload = 0 && not p.Pdu.flags.Pdu.syn &&
               (p.Pdu.seq_num :> int32) = Int32.pred (next_seq_num a :> int32) then
                incr probes ;
            b.tcp_trx.trx.out.write bits ;
            Streambuf.iter (fun (o, p) ->
                ahead := max !ahead (o + Payload.length p.Pdu.payload - b.rcvd_pld)
            ) b.rcvd_pkts) ;
        b.tcp_trx.trx.out --> sink (fun bits ->
            Option.may (fun p -> a.tcp_trx.trx.out.write (Pdu.pack p))
                (b_to_a (Simulation.now sim) (Result.get_ok (Pdu.unpack bits)))) ;
        b.tcp_trx.trx.ins --> sink (fun bits -> rcvd := !rcvd + bytelength bits) ;
        connect a (fun _ -> a.tcp_trx.trx.ins.write (zeroes_bitstring (8 * size))) ;
        Simulation.run sim false ;
        a, !max_in_flight, !rcvd, !probes, !ahead in
    let a, _, rcvd, _, _ = transfer 1000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 1000 rcvd ;
    assert_equal ~printer:string_of_int ~msg:"default window" 0xffff a.snd_wnd ;
    let _, m, rcvd, _, _ = transfer ~rcv_buf:250 2000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 2000 rcvd ;
    assert_bool "whole segments within the window" (m = 200) ;
    let _, m, rcvd, _, _ = transfer ~rcv_buf:60 2000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 2000 rcvd ;
    assert_bool "segments cut down to a window below the MSS" (m = 60) ;
    (* A window closed until 5s: *)
    let b_to_a now p =
        let opened = now >= Clock.Time.of_secs 5. in
        Some { p with Pdu.win_size = if opened then 0xffff else 0 } in
    let _, _, rcvd, probes, _ = transfer ~b_to_a 2000 in
    assert_equal ~printer:string_of_int ~msg:"all received once reopened" 2000 rcvd ;
    assert_bool "probed, backing off" (probes >= 3 && probes <= 6) ;
    (* A window too small for SWS avoidance to ever use: *)
    let b_to_a _ p =
        Some { p with Pdu.win_size = if p.Pdu.flags.Pdu.syn then 1000 else 100 } in
    let _, _, rcvd, _, _ = transfer ~mss:200 ~b_to_a 2000 in
    assert_equal ~printer:string_of_int ~msg:"all received in small segments" 2000 rcvd ;
    (* A closed window, and a peer that answers no probe: *)
    let b_to_a _ p =
        if p.Pdu.flags.Pdu.syn then Some { p with Pdu.win_size = 0 } else None in
    let a, _, rcvd, probes, _ = transfer ~max_timeouts:3 ~b_to_a 2000 in
    assert_equal ~printer:string_of_int ~msg:"nothing received" 0 rcvd ;
    assert_equal ~printer:string_of_int ~msg:"probes before giving up" 3 probes ;
    assert_bool "gave up" a.closed ;
    (* A sender told a larger window than [b] enforces: *)
    let b_to_a _ p = Some { p with Pdu.win_size = 0xffff } in
    let _, _, rcvd, _, ahead = transfer ~rcv_buf:300 ~b_to_a 3000 in
    assert_equal ~printer:string_of_int ~msg:"all received" 3000 rcvd ;
    assert_bool "nothing held beyond the window" (ahead <= 300)
*)
(*$>*)
