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
  A special host that access the physical network through the OS network stack.
*)
open Batteries
open Bitstring
open Tools

let logger = Log.make "Host/localhost" 50

let signal_err e =
    Printf.fprintf stderr "Localhost: %s\n%!" e

type t =
    { sock : Unix.file_descr ;
      mutable recv : bitstring -> unit ;
      mutable is_closed : bool ;
      mutable reader : Thread.t option }

let tx t bits =
    let str = string_of_bitstring bits in
    Log.(log logger Debug (lazy (Printf.sprintf "Sending '%s'" (abbrev ~len:100 str)))) ;
    let rec aux o =
        if o < String.length str then (
            let w = Unix.write_substring t.sock str o ((String.length str)-o) in
            Log.(log logger Debug (lazy (Printf.sprintf "Just write %d bytes" w))) ;
            aux (o+w)
        ) in
    ignore (aux 0)   (* FIXME: if this actually blocks, we may end up writing things in mixed order. tx should enqueue the payload and another thread should perform the actual write. *)

let close t () =
    Log.(log logger Debug (lazy (Printf.sprintf "Closing socket"))) ;
    t.is_closed <- true ;
    Unix.close t.sock ;
    (* In case the closing of the fd is not enough: *)
    match t.reader with
    | None -> ()
    | Some _reader ->
        t.reader <- None

let rec reader t =
    if not t.is_closed then
    let buf = Bytes.create 1000 in
    let r =
        try Unix.read t.sock buf 0 (Bytes.length buf)
        with Unix.Unix_error (error, func_name, _) ->
                Log.(log logger Info (lazy (Printf.sprintf "Unix_error: Cannot %s: %s" func_name (Unix.error_message error)))) ;
                (* Can we get EINTR? I think not, so all errors are supposed fatal here *)
                0
            | _ -> 0 in
    Clock.synch () ;
    Log.(log logger Debug (lazy (Printf.sprintf "Read %d bytes" r))) ;
    if not t.is_closed then (
        if r > 0 then (
            let s = Bytes.sub buf 0 r |> Bytes.to_string in
            Log.(log logger Debug (lazy (Printf.sprintf "Received '%s'" s))) ;
            (* Use the Clock so that the recv function is called in main thread *)
            Clock.asap t.recv (bitstring_of_string s) ;
            reader t
        ) else if r = 0 then (
            Log.(log logger Debug (lazy (Printf.sprintf "Received EOF"))) ;
            Clock.asap t.recv empty_bitstring ;
            t.is_closed <- true
        )
    )

let tcp_trx_of_socket sock =
    let t = {
        sock = sock ;
        recv = ignore ;
        is_closed = false ;
        reader = None } in
    let trx =
        { ins = { write = tx t ;
                  set_read = (fun f ->
                    (* trick: only start reading the socket when the receiver is set, so that buffering is handled by the kernel *)
                    Log.(log logger Debug (lazy (Printf.sprintf "Set recv function"))) ;
                    t.recv <- f ;
                    if t.reader = None then t.reader <- Some (Thread.create reader t)) } ;
          out = { write = should_not_happen ;
                  set_read = should_not_happen } } in
    { Tcp.TRX.trx       = trx ;
      Tcp.TRX.close     = close t ;
      Tcp.TRX.is_closed = (fun () -> t.is_closed) }

(* TODO: make use of another thread for an assynchronous gethostbyname *)
let gethostbyname name cont =
    let h_entry = Unix.gethostbyname name in
    Clock.synch () ;
    Log.(log logger Debug (lazy (Printf.sprintf2 "Got these IPs for '%s': %a"
        name
        (Array.print Ip.inet_addr_print)
        h_entry.Unix.h_addr_list))) ;
    let ips = Array.enum h_entry.Unix.h_addr_list /@
        Ip.Addr.of_inet_addr |>
        List.of_enum in
    cont (Some ips)

let wait_server_delay = ref 3.

let tcp_connect ?(wait_for_server=true) dst ?src_port ?ttl ?tos
                (dst_port : Tcp.Port.t) cont =
    let connect_ inet_addr =
        Log.(log logger Debug (lazy (Printf.sprintf "Connecting to %s:%s"
            (Unix.string_of_inet_addr inet_addr)
            (Tcp.Port.to_string dst_port)))) ;
        let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
        Option.may (fun (port : Tcp.Port.t) ->
            Unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_any, (port :> int))))
            src_port ;
        Option.may (Sockopt.set_ttl sock) ttl ;
        Option.may (Sockopt.set_tos sock) tos ;
        (* Retry the connect from time to time, waiting for the server: *)
        let rec try_connect () =
            match
                Unix.connect sock (Unix.ADDR_INET (inet_addr, (dst_port :> int)))
            with
            | exception (Unix.(Unix_error (ECONNREFUSED, _, _)) as e) ->
                if wait_for_server then
                    (* More luck later: *)
                    let d = jitter 0.1 !wait_server_delay in
                    Clock.(delay (Interval.sec d)) try_connect ()
                else
                    raise e
            | () ->
                cont (Some (tcp_trx_of_socket sock)) in
        Clock.asap try_connect ()
    in
    match dst with
        | Host.IPv4 dst_ip ->
            connect_ (Ip.Addr.to_inet_addr dst_ip)
        | Host.Name name ->
            let dst_ips =
                (* FIXME: use Localhost.gethostbyname *)
                let h_entry = Unix.gethostbyname name in
                Clock.synch () ;
                Log.(log logger Debug (lazy (Printf.sprintf2 "Got these IPs for '%s': %a"
                    name
                    (Array.print Ip.inet_addr_print)
                    h_entry.Unix.h_addr_list))) ;
                h_entry.Unix.h_addr_list in
            connect_ dst_ips.(0)

let tcp_server src_port server_f =
    Log.(log logger Debug (lazy (Printf.sprintf "Establishing a server on port %s" (Tcp.Port.to_string src_port)))) ;
    let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
    Unix.setsockopt sock Unix.SO_REUSEADDR true ;
    Unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_any, (src_port :> int))) ;
    Unix.listen sock 5 ;
    let rec sock_server () =
        let fd, _ = Unix.accept sock in
        let trx = tcp_trx_of_socket fd in
        server_f trx ; (* supposed to set the recv of this trx *)
        sock_server () in (* accept next connection *)
    sock_server ()

let make () =
    { Host.name          = "localhost" ;
      Host.logger        = logger ;
      Host.tcp_connect   = tcp_connect ~wait_for_server:true ?ttl:None ?tos:None ;
      Host.udp_connect   = (fun _ ?src_port _ _ -> ignore src_port ; todo "UDP connect for localhost") ;
      Host.udp_send      = (fun _ ?src_port _ _ -> ignore src_port ; todo "UDP send for localhost") ;
      Host.ping          = (fun ?id ?seq _ -> ignore id ; ignore seq ; todo "Ping from localhost") ;
      Host.gethostbyname = gethostbyname ;
      Host.tcp_server    = tcp_server ;
      Host.udp_server    = (fun _ _ -> todo "UDP server for localhost") ;
      Host.signal_err    = signal_err ;
      Host.dev           = { write = ignore ; set_read = ignore } ;
      Host.get_mac       = (fun () -> todo "get the Eth mac addr of localhost") ;
      Host.get_ip        = (fun () -> todo "get the IP addr of localhost") ;
      Host.arp_set       = (fun _ _ -> todo "set ARP table of localhost") ;
      Host.power_on      = (fun ?on_ip () -> ignore on_ip) ;
      Host.power_off     = (fun ?timeout () -> ignore timeout) ;
      Host.add_killer    = ignore }

