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
(*
   A special host that access the physical network through the OS network stack.
*)
open Batteries
open Bitstring
open Tools

let logger = Log.make "Host/localhost" 50

let signal_err e =
    Printf.fprintf stderr "Localhost: %s\n%!" e

type t =
    { sock : Lwt_unix.file_descr ;
      mutable recv : bitstring -> unit ;
      mutable is_closed : bool ;
      mutable reader_running : bool }

let tx t bits =
    let str = string_of_bitstring bits in
    Log.(log logger Debug (lazy (Printf.sprintf "Sending '%s'" (abbrev ~len:100 str)))) ;
    let rec aux o =
        if o >= String.length str then Lwt.return ()
        else (
            lwt w = Lwt_unix.write t.sock str o ((String.length str)-o) in
            Log.(log logger Debug (lazy (Printf.sprintf "Just write %d bytes" w))) ;
            aux (o+w)
        ) in
    Lwt.ignore_result (aux 0)   (* FIXME: if this actually blocks, we may end up writing things in mixed order. tx should enqueue the payload and another thread should perform the actual write. *)

let close t () =
    Log.(log logger Debug (lazy (Printf.sprintf "Closing socket"))) ;
    t.is_closed <- true ;
    Lwt.ignore_result (Lwt_unix.close t.sock)

let rec reader t =
    if t.is_closed then Lwt.return () else
    let buf = String.create 1000 in
    lwt r = Lwt.catch
        (fun () ->
            let r = Lwt_unix.read t.sock buf 0 (String.length buf) in
            Clock.synch () ;
            r)
        (function
            | Unix.Unix_error (error, func_name, _) ->
                Clock.synch () ;
                Log.(log logger Info (lazy (Printf.sprintf "Unix_error: Cannot %s: %s" func_name (Unix.error_message error)))) ;
                (* Can we get EINTR? I think not, so all errors are supposed fatal here *)
                Lwt.return 0
            | _ -> error "Cannot handle this exception in Unix.read") in
    Log.(log logger Debug (lazy (Printf.sprintf "Read %d bytes" r))) ;
    if t.is_closed then Lwt.return () else (
        if r > 0 then (
            let s = String.sub buf 0 r in
            Log.(log logger Debug (lazy (Printf.sprintf "Received '%s'" s))) ;
            t.recv (bitstring_of_string s)
        ) else if r = 0 then (
            Log.(log logger Debug (lazy (Printf.sprintf "Received EOF"))) ;
            t.recv empty_bitstring ;
            t.is_closed <- true
        ) ;
        reader t
    )

let tcp_trx_of_socket sock =
    let t = {
        sock = sock ;
        recv = ignore ;
        is_closed = false ;
        reader_running = false } in
    let trx =
        { tx = tx t ;
          rx = should_not_happen ;
          set_emit = should_not_happen ;
          set_recv = (fun f ->
            (* trick: only start reading the socket when the receiver is set! *)
            Log.(log logger Debug (lazy (Printf.sprintf "Set recv function"))) ;
            t.recv <- f ;
            if not t.reader_running then (
                t.reader_running <- true ;
                Lwt.ignore_result (reader t)
            )) } in
    { Tcp.TRX.trx       = trx ;
      Tcp.TRX.close     = close t ;
      Tcp.TRX.is_closed = (fun () -> t.is_closed) }

let ip_addr_of_inet_addr i =
    Unix.string_of_inet_addr i |>
    Ip.addr_of_string

let inet_addr_print oc a =
    Printf.fprintf oc "%s" (Unix.string_of_inet_addr a)

let gethostbyname name =
    lwt h_entry = Lwt_unix.gethostbyname name in
    Log.(log logger Debug (lazy (Printf.sprintf2 "Got these IPs for '%s': %a"
        name
        (Array.print inet_addr_print)
        h_entry.Lwt_unix.h_addr_list))) ;
    Array.enum h_entry.Lwt_unix.h_addr_list /@
        ip_addr_of_inet_addr |>
        List.of_enum |>
        Lwt.return

let tcp_connect dst ?src_port (dst_port : Tcp.Port.t) =
    let connect_tcp_ inet_addr =
        Log.(log logger Debug (lazy (Printf.sprintf "Connecting to %s" (Unix.string_of_inet_addr inet_addr)))) ;
        let sock = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
        Option.may (fun (port : Tcp.Port.t) ->
            Lwt_unix.bind sock (Lwt_unix.ADDR_INET (Unix.inet_addr_any, (port :> int))))
            src_port ;
        lwt () = Lwt_unix.connect sock (Lwt_unix.ADDR_INET (inet_addr, (dst_port :> int))) in
        Lwt.return (tcp_trx_of_socket sock)
    in
    match dst with
        | Host.IPv4 dst_ip ->
            connect_tcp_ (Unix.inet_addr_of_string (Ip.Addr.to_string dst_ip))
        | Host.Name name ->
            lwt dst_ips =
                lwt h_entry = Lwt_unix.gethostbyname name in
                Log.(log logger Debug (lazy (Printf.sprintf2 "Got these IPs for '%s': %a"
                    name
                    (Array.print inet_addr_print)
                    h_entry.Lwt_unix.h_addr_list))) ;
                Lwt.return (h_entry.Lwt_unix.h_addr_list) in
            connect_tcp_ dst_ips.(0)

let tcp_server src_port server_f =
    Log.(log logger Debug (lazy (Printf.sprintf "Establishing a server on port %s" (Tcp.Port.to_string src_port)))) ;
    let sock = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
    Lwt_unix.setsockopt sock Lwt_unix.SO_REUSEADDR true ;
    Lwt_unix.bind sock (Lwt_unix.ADDR_INET (Unix.inet_addr_any, (src_port :> int))) ;
    Lwt_unix.listen sock 5 ;
    let rec sock_server () =
        lwt fd, _ = Lwt_unix.accept sock in
        let trx = tcp_trx_of_socket fd in
        server_f trx ; (* supposed to set the recv of this trx *)
        sock_server () in (* accept next connection *)
    Lwt.ignore_result (sock_server ())

let make () =
    { Host.name          = "localhost" ;
      Host.logger        = logger ;
      Host.tcp_connect   = tcp_connect ;
      Host.udp_connect   = (fun _ ?src_port _ _ -> ignore src_port ; todo "UDP connect for localhost") ;
      Host.gethostbyname = gethostbyname ;
      Host.tcp_server    = tcp_server ;
      Host.udp_server    = (fun _ _ -> todo "UDP server for localhost") ;
      Host.signal_err    = signal_err ;
      Host.set_emit      = ignore ;
      Host.rx            = ignore }

