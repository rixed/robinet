(* vim:sw=4 ts=4 sts=4 expandtab
*)
open Batteries
open Bitstring
open Tools

let debug = false

(* Ports *)

type port = Tcp.port
let string_of_port = Tcp.string_of_port
let print_port = Tcp.print_port

(* UDP datagrams *)

module Pdu =
struct
    type t = {
        src_port : int   ; dst_port : int ;
        length   : int   ; checksum : int option ;
        payload  : bitstring }

    let make ?(src_port=1024) ?(dst_port=80)
             ?(length) ?checksum payload =
        let length = may_default length (fun () -> bytelength payload + 8) in
        { src_port ; dst_port ; length   ; checksum ; payload }

    let pack t =
        concat [ (BITSTRING {
            t.src_port : 16 ; t.dst_port : 16 ;
            t.length   : 16 ; (Option.default 0 t.checksum) : 16 }) ;
            t.payload ]

    let unpack bits = bitmatch bits with
        | { src_port : 16 ; dst_port : 16 ;
            length   : 16 ; checksum : 16 ;
            payload  : (length-8) * 8 : bitstring } when length >= 8 ->
            Some { src_port = src_port ; dst_port = dst_port ;
                   length   = length   ; checksum = Some checksum ;
                   payload  = payload }
        | { _ } -> err "Not UDP"
end

(* Transceiver *)

module TRX =
struct
    type t = {
        mutable src : port ; mutable dst : port option ;
        mutable emit : payload -> unit ;
        mutable recv : payload -> unit }

    let tx t bits =
        let src_port = t.src and dst_port = Option.get t.dst in
        let udp = Pdu.make ~src_port ~dst_port bits in
        if debug then Printf.printf "Udp: Emitting a packet from %d to %d\n%!" src_port dst_port ;
        t.emit (Pdu.pack udp)

    (* TODO: check checksum *)
    let rx t bits = (match Pdu.unpack bits with
        | None -> ()
        | Some udp ->
            if debug then Printf.printf "Udp: Received a datagram\n%!" ;
            if debug then Printf.printf "Udp: Got a datagram with %d bytes\n%!" (bytelength udp.Pdu.payload) ;
            if bitstring_length udp.Pdu.payload > 0 then t.recv udp.Pdu.payload)

    let make ?dst src =
        let t = { src = src ; dst = dst ;
                  emit = ignore ; recv = ignore } in
        { tx = tx t ;
          rx = rx t ;
          set_emit = (fun f -> t.emit <- f) ;
          set_recv = (fun f -> t.recv <- f) }

    let make_client ~src ~dst = make ~dst src

    let make_server src = make src
end
