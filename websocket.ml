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
(** WebSocket protocol (RFC 6455) *)
open Batteries
open Bitstring
open Tools

type opcode =
    | Continuation
    | Text
    | Binary
    | Close
    | Ping
    | Pong

let opcode_of_int = function
    | 0 -> Some Continuation
    | 1 -> Some Text
    | 2 -> Some Binary
    | 8 -> Some Close
    | 9 -> Some Ping
    | 10 -> Some Pong
    | _ -> None

let int_of_opcode = function
    | Continuation -> 0
    | Text -> 1
    | Binary -> 2
    | Close -> 8
    | Ping -> 9
    | Pong -> 10

module Pdu =
struct
    type t =
        { fin : bool ;
          opcode : opcode ;
          length : int ;
          frame_length : int ; (* Only set by unpack *)
          mask : int32 option ;
          payload : Payload.t }

    let apply_mask mask pld =
        string_of_bitstring pld |>
        String.mapi (fun i c ->
            let d = Char.code c in
            let m =
                (Int32.shift_right mask (8 * (i mod 4)) |> Int32.to_int) land 255 in
            Char.chr (d lxor m)) |>
        bitstring_of_string

    let pack t =
        let len = Payload.length t.payload in
        let%bitstring hdr = {|
            t.fin : 1 ;
            0 : 3 ;
            int_of_opcode t.opcode : 4 ;
            t.mask <> None : 1 ;
            if len < 126 then len else if len < 65536 then 126 else 127 : 7 |} in
        let length =
            if len < 126 then empty_bitstring else
            if len < 65536 then [%bitstring {| len : 16 |}] else
            [%bitstring {| Int64.of_int len : 64 |}] in
        let mask, payload =
            match t.mask with
            | None ->
                empty_bitstring,
                (t.payload :> bitstring)
            | Some m ->
                [%bitstring {| m : 32 : littleendian |}],
                apply_mask m (t.payload :> bitstring) in
        concat [ hdr ; length ; mask ; payload ]

    (* [actual] and [expected] are byte counts of the whole frame, [TooLong]
       gives the payload length. *)
    type unpack_err =
        | TooShort of { actual : int ; expected : int }
        | TooLong of int
        | NotWebsocket

    (** Unpack the frame at the beginning of [bits], which may hold more.
        A payload longer than [max_length] is refused as soon as its header
        is known. *)
    let unpack ?(max_length=max_int) bits =
        let actual = bytelength bits in
        let too_short expected = Error (TooShort { actual ; expected }) in
        match%bitstring bits with
        | {| _ : 8 ; has_mask : 1 ; len : 7 |} ->
            let hdr_len =
                2 + (if len < 126 then 0 else if len = 126 then 2 else 8) +
                (if has_mask then 4 else 0) in
            if actual < hdr_len then too_short hdr_len else
            (match%bitstring bits with
            | {| fin : 1 ; _ : 3 ; op : 4 ; _ : 1 ; _ : 7 ;
                 ext_len :
                    if len < 126 then 0 else if len = 126 then 16 else 64 : bitstring ;
                 mask : if has_mask then 32 else 0 : bitstring ;
                 rest : -1 : bitstring |} ->
                let length =
                    match%bitstring ext_len with
                    | {| l : 64 |} -> Int64.to_int l
                    | {| l : 16 |} -> l
                    | {| _ |} -> len in
                let frame_length = hdr_len + length in
                if length < 0 then Error NotWebsocket else
                if length > max_length then Error (TooLong length) else
                if actual < frame_length then too_short frame_length else
                (match opcode_of_int op with
                | None -> Error NotWebsocket
                | Some opcode ->
                    let payload = takebytes length rest in
                    let mask, payload =
                        match%bitstring mask with
                        | {| m : 32 : littleendian |} -> Some m, Payload.o (apply_mask m payload)
                        | {| _ |} -> None, Payload.o payload in
                    Ok { fin ; opcode ; length ; frame_length ; mask ; payload })
            | {| _ |} -> Error NotWebsocket)
        | {| _ |} -> too_short 2

    let rand_mask () =
        Int32.of_int (Random.bits ())

    let make ~has_mask ?(fin=true) ?(opcode=Binary) (payload : Payload.t) =
        { fin ; opcode ;
          length = Payload.length payload ;
          frame_length = 0 ;
          mask = if has_mask then Some (rand_mask ()) else None ;
          payload }

    let close ~has_mask payload =
        make ~has_mask ~opcode:Close payload

    let ping ~has_mask payload =
        make ~has_mask ~opcode:Ping payload

    let pong ~has_mask payload =
        make ~has_mask ~opcode:Pong payload
end

(*$R
    let check pdu =
        let bits = concat [ Pdu.pack pdu ; bitstring_of_string "next" ] in
        match Pdu.unpack bits with
        | Ok p ->
            assert_equal ~printer:identity
                (Payload.to_string pdu.Pdu.payload) (Payload.to_string p.Pdu.payload) ;
            assert_equal ~printer:string_of_int
                (bytelength bits - 4) p.Pdu.frame_length ;
            (* Every strict prefix asks for more: *)
            for n = 0 to p.Pdu.frame_length - 1 do
                match Pdu.unpack (takebytes n bits) with
                | Error (Pdu.TooShort _) -> ()
                | _ -> assert_failure (Printf.sprintf "prefix of %d bytes" n)
            done
        | Error _ -> assert_failure "cannot unpack" in
    let big = Pdu.pack (Pdu.make ~has_mask:true (Payload.o (randbs 1000))) in
    assert_bool "too long" (Pdu.unpack ~max_length:999 (takebytes 8 big) = Error (Pdu.TooLong 1000)) ;
    List.iter (fun len ->
        List.iter (fun has_mask ->
            check (Pdu.make ~has_mask (Payload.o (randbs len))))
            [ false ; true ])
        [ 0 ; 5 ; 125 ; 126 ; 1000 ; 70000 ]
*)

(* Base64 with padding, which Batteries omits: *)
let base64 s =
    let b = Base64.str_encode s in
    b ^ String.make ((4 - String.length b mod 4) mod 4) '='

let accept_key client_key =
    let guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" in
    Sha1.(string (client_key ^ guid) |> to_bin) |> base64

(*$= accept_key & ~printer:identity
    "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" (accept_key "dGhlIHNhbXBsZSBub25jZQ==")
*)

let header_has name value headers =
    match Http.headers_find name headers with
    | Some v ->
        String.split_on_char ',' v |>
        List.exists (fun v -> String.icompare (String.trim v) value = 0)
    | None -> false

let is_upgrade (req : Http.Pdu.t) =
    header_has "Upgrade" "websocket" req.headers

(** {2 TRX}

    Turns a byte stream (typically a TCP connection) into a websocket: it
    upgrades the stream with the HTTP handshake, then wraps what is written
    to it into binary frames and delivers the payload of the data frames it
    receives. Pings are answered and, after [keep_alive] without traffic,
    sent.

    Writing an empty bitstring starts the closing handshake; an empty
    bitstring is delivered once the websocket is closed, after which the
    stream is closed with [close].

    [on_handshake] is called once the opening handshake is over, whether the
    websocket is then open or closed.

    The opening and closing handshakes must complete within [timeout].
    Writes are sent in frames of at most [max_frame] bytes, and a longer
    frame received closes the websocket. *)
module TRX =
struct
    type role = Client of Url.t | Server

    type state =
        | Handshake
        | Open
        | Closing (* we sent a Close frame *)
        | Closed

    type t =
        { power : Simulation.power ;
          logger : Log.t ;
          role : role ;
          keep_alive : Clock.Interval.t ;
          timeout : Clock.Interval.t ;
          max_frame : int ;
          close_stream : unit -> unit ;
          (* Added to a client's upgrade request: *)
          headers : Http.header list ;
          on_handshake : t -> unit ;
          mutable state : state ;
          (* The upgrade request, sent or received: *)
          mutable request : Http.Pdu.t option ;
          (* The response to a client's upgrade request: *)
          mutable response : Http.Pdu.t option ;
          (* Bytes received from the stream and not yet used: *)
          pending : Stdlib.Buffer.t ;
          (* No progress is possible before [pending] is that long: *)
          mutable wanted : int ;
          (* What was written during the handshake: *)
          mutable to_send : bitstring list ;
          mutable last_traffic : Clock.Time.t ;
          mutable emit : bitstring -> unit ;
          mutable emit_busy_for : unit -> Clock.Interval.t ;
          mutable recv : bitstring -> unit ;
          mutable recv_busy_for : unit -> Clock.Interval.t ;
          mutable trx : trx }

    let is_client t = match t.role with Client _ -> true | Server -> false

    let now t = Simulation.now t.power.sim

    let emit t bits =
        t.last_traffic <- now t ;
        t.emit bits

    let emit_pdu t pdu =
        if t.state <> Closed then emit t (Pdu.pack pdu)

    let frame t opcode bits =
        Pdu.make ~has_mask:(is_client t) ~opcode (Payload.o bits)

    let close_now t =
        if t.state <> Closed then (
            Log.(log t.logger Debug (lazy "Websocket: closed")) ;
            let was_handshaking = t.state = Handshake in
            t.state <- Closed ;
            Stdlib.Buffer.clear t.pending ;
            t.to_send <- [] ;
            t.close_stream () ;
            if was_handshaking then t.on_handshake t ;
            t.recv empty_bitstring)

    (* An open websocket tells its peer why with a Close [status]: *)
    let fail ?status t msg =
        Log.(log t.logger Warning (lazy (Printf.sprintf "Websocket: %s" msg))) ;
        (match status with
        | Some code when t.state = Open ->
            emit_pdu t (frame t Close [%bitstring {| code : 16 |}])
        | _ -> ()) ;
        close_now t

    (* Fail if still in [state] after the timeout: *)
    let arm_timeout t state what =
        Simulation.delay t.power t.timeout (fun () ->
            if t.state = state then fail t (what ^" timed out")) ()

    let rec keep_alive t () =
        if t.state = Open then (
            let next = Clock.Time.add t.last_traffic t.keep_alive in
            if Clock.Time.is_after (now t) next then (
                Log.(log t.logger Debug (lazy "Websocket: ping")) ;
                emit_pdu t (frame t Ping empty_bitstring) ;
                Simulation.delay ~background:true t.power t.keep_alive (keep_alive t) ()
            ) else
                Simulation.at ~background:true t.power next (keep_alive t) ())

    let tx t bits =
        match t.state with
        | Handshake ->
            if bitstring_is_empty bits then close_now t
            else t.to_send <- bits :: t.to_send
        | Open ->
            if bitstring_is_empty bits then (
                emit_pdu t (frame t Close empty_bitstring) ;
                t.state <- Closing ;
                arm_timeout t Closing "closing handshake"
            ) else
                let rec send bits =
                    if bytelength bits > t.max_frame then (
                        emit_pdu t (frame t Binary (takebytes t.max_frame bits)) ;
                        send (dropbytes t.max_frame bits)
                    ) else
                        emit_pdu t (frame t Binary bits) in
                send bits
        | Closing | Closed ->
            Log.(log t.logger Debug (lazy (Printf.sprintf
                "Websocket: dropping %d bytes written after close" (bytelength bits))))

    let opened t =
        Log.(log t.logger Debug (lazy "Websocket: open")) ;
        t.state <- Open ;
        t.last_traffic <- now t ;
        Simulation.delay ~background:true t.power t.keep_alive (keep_alive t) () ;
        let to_send = List.rev t.to_send in
        t.to_send <- [] ;
        List.iter (tx t) to_send ;
        t.on_handshake t

    let send_request t url =
        let key = base64 (string_of_bitstring (randbs 16)) in
        let req =
            Http.Pdu.make_request "GET" (Url.request_target url)
                ([ "Host", url.Url.net_loc ;
                   "Upgrade", "websocket" ;
                   "Connection", "Upgrade" ;
                   "Sec-WebSocket-Key", key ;
                   "Sec-WebSocket-Version", "13" ] @ t.headers) in
        t.request <- Some req ;
        emit t (Http.Pdu.pack req)

    (** Answer the upgrade request [req], for a server whose stream received
        it already (and nothing else since). *)
    let accept t (req : Http.Pdu.t) =
        let refuse code msg =
            emit t (Http.Pdu.pack (Http.Pdu.make_response code)) ;
            fail t msg in
        match req.cmd, Http.headers_find "Sec-WebSocket-Key" req.headers with
        | Http.Request ("GET", _), Some key when is_upgrade req ->
            t.request <- Some req ;
            emit t (Http.Pdu.pack {
                Http.Pdu.cmd = Http.Status 101 ;
                version = Http.Pdu.default_version ;
                headers = [ "Upgrade", "websocket" ;
                            "Connection", "Upgrade" ;
                            "Sec-WebSocket-Accept", accept_key key ] ;
                body = "" }) ;
            opened t
        | _ ->
            refuse 400 "not a websocket upgrade request"

    (* Check the response [resp] to our upgrade request. *)
    let accepted t (resp : Http.Pdu.t) =
        t.response <- Some resp ;
        let expected =
            Option.bind t.request (fun req ->
                Http.headers_find "Sec-WebSocket-Key" req.Http.Pdu.headers) |>
            Option.map accept_key in
        match resp.cmd with
        | Http.Status 101 when Http.headers_find "Sec-WebSocket-Accept" resp.headers = expected ->
            opened t
        | Http.Status c ->
            fail t (Printf.sprintf "upgrade refused (%d)" c)
        | Http.Request _ ->
            fail t "got a request instead of an upgrade response"

    let on_frame t (pdu : Pdu.t) =
        match pdu.opcode with
        | Continuation | Text | Binary ->
            if t.state = Open && not (Payload.is_empty pdu.payload) then
                t.recv (pdu.payload :> bitstring)
        | Ping ->
            emit_pdu t (frame t Pong (pdu.payload :> bitstring))
        | Pong ->
            ()
        | Close ->
            (* Echo the status code to complete the closing handshake: *)
            if t.state = Open then
                emit_pdu t (frame t Close (takebytes (min 2 pdu.length) (pdu.payload :> bitstring))) ;
            close_now t

    (* Use as much of [str] as possible; returns how many bytes. *)
    let rec parse t str ofs =
        let rest () = String.sub str ofs (String.length str - ofs) in
        let continue n = n + parse t str (ofs + n) in
        if ofs >= String.length str then 0 else
        match t.state with
        | Closed -> String.length str - ofs
        | Handshake ->
            (match Http.Pdu.parse (rest ()) false with
            | Http.Pdu.Parsed (msg, n) ->
                if is_client t then accepted t msg else accept t msg ;
                continue n
            | Http.Pdu.Truncated n ->
                t.wanted <- n ;
                0
            | Http.Pdu.Not_http ->
                fail t "bad HTTP handshake" ;
                String.length str - ofs)
        | Open | Closing ->
            (match Pdu.unpack ~max_length:t.max_frame (bitstring_of_string (rest ())) with
            | Ok pdu ->
                on_frame t pdu ;
                continue pdu.frame_length
            | Error (TooShort { expected ; _ }) ->
                t.wanted <- expected ;
                0
            | Error (TooLong n) ->
                fail ~status:1009 t (Printf.sprintf "frame of %d bytes is too long" n) ;
                String.length str - ofs
            | Error NotWebsocket ->
                fail ~status:1002 t "not a websocket frame" ;
                String.length str - ofs)

    let rx t bits =
        if bitstring_is_empty bits then (
            Log.(log t.logger Debug (lazy "Websocket: stream closed")) ;
            close_now t
        ) else (
            t.last_traffic <- now t ;
            Stdlib.Buffer.add_string t.pending (string_of_bitstring bits) ;
            if Stdlib.Buffer.length t.pending >= t.wanted then (
                let str = Stdlib.Buffer.contents t.pending in
                t.wanted <- 0 ;
                let n = parse t str 0 in
                Stdlib.Buffer.clear t.pending ;
                Stdlib.Buffer.add_substring t.pending str n (String.length str - n)))

    (** A websocket over the stream it will be connected to. A client sends
        its upgrade request to [url] as soon as it is connected. *)
    let make power ?(keep_alive=Clock.Interval.sec 30.) ?(timeout=Clock.Interval.sec 10.)
             ?(max_frame=1 lsl 20) ?(close=ignore) ?(headers=[]) ?(on_handshake=ignore)
             role logger =
        let t =
            { power ; logger ; role ; keep_alive ; timeout ; max_frame ; close_stream = close ;
              headers ; on_handshake ;
              state = Handshake ; request = None ; response = None ;
              pending = Stdlib.Buffer.create 4096 ; wanted = 0 ; to_send = [] ;
              last_traffic = Clock.Time.zero ;
              emit = ignore_bits ~logger ; emit_busy_for = never_busy ;
              recv = ignore_bits ~logger ; recv_busy_for = never_busy ;
              trx = null_trx ~logger } in
        t.trx <-
            { ins = { write = tx t ;
                      busy_for = (fun () -> t.emit_busy_for ()) ;
                      set_read = (fun f busy_for ->
                          t.recv <- f ; t.recv_busy_for <- busy_for) } ;
              out = { write = rx t ;
                      busy_for = (fun () -> t.recv_busy_for ()) ;
                      set_read = (fun f busy_for ->
                          t.emit <- f ; t.emit_busy_for <- busy_for ;
                          if t.state = Handshake && t.request = None then (
                              arm_timeout t Handshake "opening handshake" ;
                              match role with
                              | Client url -> send_request t url
                              | Server -> ())) } } ;
        t
end

(* For the tests: a client and a server websocket joined back to back, and
   what each receives. Bytes cross one at a time, a millisecond apart. *)
(*$inject
    let ws_pair ?keep_alive ?max_frame () =
        let sim = Simulation.make ~realtime:false "websocket" in
        let power = sim.root.power and logger = Log.make () in
        let cnx_closed = ref 0 in
        let close () = incr cnx_closed in
        let url = Url.of_string "http://example.com/ws" in
        let c = TRX.make power ?keep_alive ?max_frame ~close (TRX.Client url) logger
        and s = TRX.make power ?keep_alive ?max_frame ~close TRX.Server logger in
        let got_c = ref [] and got_s = ref [] in
        sink (fun b -> got_c := string_of_bitstring b :: !got_c) <-= c.trx |> ignore ;
        sink (fun b -> got_s := string_of_bitstring b :: !got_s) <-= s.trx |> ignore ;
        let link dst =
            let free_at = ref Clock.Time.zero in
            fun bits ->
                for i = 0 to bytelength bits - 1 do
                    free_at := Clock.Time.add (Clock.Time.max (Simulation.now sim) !free_at)
                                              (Clock.Interval.msec 1.) ;
                    Simulation.at power !free_at dst.write (takebytes 1 (dropbytes i bits))
                done in
        c.trx.out --> sink (link s.trx.out) ;
        s.trx.out --> sink (link c.trx.out) ;
        sim, c, s, got_c, got_s, cnx_closed
*)

(*$R
    let sim, c, s, got_c, got_s, cnx_closed = ws_pair () in
    (* Written before the handshake completes: *)
    tx c.trx (bitstring_of_string "hello") ;
    Simulation.run sim false ;
    assert_bool "both open" (c.TRX.state = TRX.Open && s.TRX.state = TRX.Open) ;
    tx s.trx (bitstring_of_string "world") ;
    tx c.trx (bitstring_of_string (String.make 300 'x')) ;
    Simulation.run sim false ;
    assert_equal ~printer:dump [ String.make 300 'x' ; "hello" ] !got_s ;
    assert_equal ~printer:dump [ "world" ] !got_c ;
    (* Closing handshake: *)
    tx c.trx empty_bitstring ;
    Simulation.run sim false ;
    assert_bool "both closed" (c.TRX.state = TRX.Closed && s.TRX.state = TRX.Closed) ;
    assert_equal ~printer:dump "" (List.hd !got_s) ;
    assert_equal ~printer:dump "" (List.hd !got_c) ;
    assert_equal ~printer:string_of_int 2 !cnx_closed
*)

(*$R
    (* An idle websocket pings; the ping is traffic for the other side,
       which thus stays quiet: *)
    let sim, c, s, _, _, _ = ws_pair ~keep_alive:(Clock.Interval.sec 10.) () in
    let pings = ref 0 in
    List.iter (fun (t : TRX.t) ->
        let emit = t.emit in
        t.emit <- (fun b ->
            (match Pdu.unpack b with
            | Ok { Pdu.opcode = Ping ; _ } -> incr pings
            | _ -> ()) ;
            emit b)) [ c ; s ] ;
    (* Something in the foreground to keep the run going for a minute: *)
    Simulation.delay sim.root.power (Clock.Interval.sec 65.) ignore () ;
    Simulation.run sim false ;
    assert_equal ~printer:string_of_int 6 !pings ;
    assert_bool "still open" (c.TRX.state = TRX.Open && s.TRX.state = TRX.Open)
*)

(*$R
    (* A server that never answers: *)
    let sim = Simulation.make ~realtime:false "websocket-timeout" in
    let got = ref [] in
    let c = TRX.make sim.root.power ~timeout:(Clock.Interval.sec 1.)
                     (TRX.Client (Url.of_string "http://example.com/ws")) (Log.make ()) in
    sink (fun b -> got := string_of_bitstring b :: !got) <-= c.trx |> ignore ;
    c.trx.out --> sink ignore ;
    Simulation.run sim false ;
    assert_bool "closed" (c.TRX.state = TRX.Closed) ;
    assert_equal ~printer:dump [ "" ] !got ;
    (* A peer that never answers our Close: *)
    let sim, c, _, got_c, _, cnx_closed = ws_pair () in
    Simulation.run sim false ;
    c.trx.out --> sink ignore ;
    tx c.trx empty_bitstring ;
    assert_bool "closing" (c.TRX.state = TRX.Closing) ;
    Simulation.run sim false ;
    assert_bool "closed after the timeout" (c.TRX.state = TRX.Closed) ;
    assert_equal ~printer:dump [ "" ] !got_c ;
    assert_equal ~printer:string_of_int 1 !cnx_closed
*)

(*$R
    let sim, c, s, got_c, got_s, cnx_closed = ws_pair ~max_frame:100 () in
    Simulation.run sim false ;
    (* Long writes are split: *)
    tx c.trx (bitstring_of_string (String.make 250 'x')) ;
    Simulation.run sim false ;
    assert_equal ~printer:dump [ String.make 50 'x' ; String.make 100 'x' ; String.make 100 'x' ] !got_s ;
    (* Long frames are refused, with a Close telling why: *)
    let closes = ref [] in
    let emit = s.TRX.emit in
    s.TRX.emit <- (fun b ->
        (match Pdu.unpack b with
        | Ok { Pdu.opcode = Close ; payload ; _ } ->
            closes := Payload.to_string payload :: !closes
        | _ -> ()) ;
        emit b) ;
    s.trx.out.write (Pdu.pack (Pdu.make ~has_mask:true (Payload.o (randbs 101)))) ;
    Simulation.run sim false ;
    assert_bool "both closed" (c.TRX.state = TRX.Closed && s.TRX.state = TRX.Closed) ;
    assert_equal ~printer:dump [ Payload.to_string (Payload.o [%bitstring {| 1009 : 16 |}]) ] !closes ;
    assert_equal ~printer:dump "" (List.hd !got_c) ;
    assert_equal ~printer:string_of_int 2 !cnx_closed
*)
