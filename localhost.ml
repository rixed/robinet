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

(* Localhost is the real host, reached through the OS network stack rather than
 * simulated. It still belongs to a simulation -- the one whose clock dates what
 * it does, and whose tree its widget hangs in -- which [host] is given. *)
type ctx = { sim : Simulation.t ; widget : Widget.t }

let logger ctx = ctx.widget.Widget.logger

let signal_err e =
    Printf.fprintf stderr "Localhost: %s\n%!" e

type t =
    { ctx : ctx ;
      mutable sock : Unix.file_descr ;
      mutable recv : bitstring -> unit ;
      mutable is_closed : bool ;
      mutable reader : Thread.t option }

let tx t bits =
    let str = string_of_bitstring bits in
    Log.(log (logger t.ctx) Debug (lazy (Printf.sprintf "Sending '%s'" (abbrev ~len:100 str)))) ;
    let rec aux o =
        if o < String.length str then (
            let w = Unix.write_substring t.sock str o ((String.length str)-o) in
            Log.(log (logger t.ctx) Debug (lazy (Printf.sprintf "Just write %d bytes" w))) ;
            aux (o+w)
        ) in
    ignore (aux 0)   (* FIXME: if this actually blocks, we may end up writing things in mixed order. tx should enqueue the payload and another thread should perform the actual write. *)

let close t () =
    if not t.is_closed then (
        (* Set first, and with nothing in between: [close] is called both by the
         * reader on end of file and by whoever is handling the connection, so
         * two threads do race here, and anything between the test and the
         * assignment -- a log line will do, since it allocates -- is a chance
         * for both to get through and close the socket twice. *)
        t.is_closed <- true ;
        Log.(log (logger t.ctx) Debug (lazy (Printf.sprintf "Closing socket"))) ;
        (* Not merely [close]: the reader thread is blocked in [read] on this
         * very fd, and closing it then leaves the socket alive -- the blocked
         * syscall still holds the file description -- so no FIN is ever sent
         * and a client honouring "Connection: close" waits for end of file for
         * ever. Shutting down first both sends the FIN and wakes the reader. *)
        Unix.shutdown t.sock SHUTDOWN_ALL ;
        Unix.close t.sock ;
        t.sock <- bad_fd ;
        (* Deliberately *not* joining the reader here. [close] is called from within
         * an event handler, so this thread is holding the simulation's lock, while
         * the reader needs that same lock to finish its round through the clock:
         * waiting for it deadlocks the simulation, and with it every later
         * connection. [is_closed] above is what makes the reader go away, and it
         * needs no help from us to do it. *)
        t.reader <- None
    )

let rec reader t =
    if not t.is_closed then
    let buf = Bytes.create 4000 in
    let r =
        try Unix.read t.sock buf 0 (Bytes.length buf)
        with Unix.Unix_error (error, func_name, _) ->
                Log.(log (logger t.ctx) Info (lazy (Printf.sprintf "Unix_error: Cannot %s: %s" func_name (Unix.error_message error)))) ;
                (* Can we get EINTR? I think not, so all errors are supposed fatal here *)
                0
            | _ -> 0 in
    Simulation.synch t.ctx.sim ;
    Log.(log (logger t.ctx) Debug (lazy (Printf.sprintf "Read %d bytes" r))) ;
    if r > 0 then (
        let s = Bytes.sub buf 0 r |> Bytes.to_string in
        Log.(log (logger t.ctx) Debug (lazy (Printf.sprintf "Received '%s'" s))) ;
        (* Use the Clock so that the recv function is called in main thread *)
        Simulation.asap t.ctx.sim t.recv (bitstring_of_string s) ;
        reader t
    ) else if r = 0 then (
        Log.(log (logger t.ctx) Debug (lazy (Printf.sprintf "Received EOF"))) ;
        Simulation.asap t.ctx.sim t.recv empty_bitstring ;
        close t ()
    )

let tcp_trx_of_socket ctx sock =
    let t = {
        ctx ; sock ;
        recv = ignore_bits ~logger:(logger ctx) ;
        is_closed = false ;
        reader = None } in
    let trx =
        { ins = { write = tx t ;
                  set_read = (fun f ->
                    (* trick: only start reading the socket when the receiver is set, so that buffering is handled by the kernel *)
                    Log.(log (logger ctx) Debug (lazy (Printf.sprintf "Set recv function"))) ;
                    t.recv <- f ;
                    if t.reader = None then t.reader <- Some (Thread.create reader t)) } ;
          out = { write = should_not_happen ;
                  set_read = should_not_happen } } in
    { Tcp.TRX.trx       = trx ;
      Tcp.TRX.close     = close t ;
      Tcp.TRX.is_closed = (fun () -> t.is_closed) }

(* TODO: make use of another thread for an asynchronous gethostbyname *)
let gethostbyname ctx name cont =
    let h_entry = Unix.gethostbyname name in
    Simulation.synch ctx.sim ;
    Log.(log (logger ctx) Debug (lazy (Printf.sprintf2 "Got these IPs for '%s': %a"
        name
        (Array.print Ip.inet_addr_print)
        h_entry.Unix.h_addr_list))) ;
    let ips = Array.enum h_entry.Unix.h_addr_list /@
        Ip.Addr.of_inet_addr |>
        List.of_enum in
    cont (Some ips)

let wait_server_delay = ref 3.

let tcp_connect ctx ?(wait_for_server=true) ?ttl ?tos
                dst ?src_port (dst_port : Tcp.Port.t) cont =
    let connect_ inet_addr =
        Log.(log (logger ctx) Debug (lazy (Printf.sprintf "Connecting to %s:%s"
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
                    Simulation.delay ctx.sim (Clock.Interval.sec d) try_connect ()
                else
                    raise e
            | () ->
                cont (Some (tcp_trx_of_socket ctx sock)) in
        Simulation.asap ctx.sim try_connect ()
    in
    match dst with
        | Host.IPv4 dst_ip ->
            connect_ (Ip.Addr.to_inet_addr dst_ip)
        | Host.Name name ->
            let dst_ips =
                (* FIXME: use Localhost.gethostbyname *)
                let h_entry = Unix.gethostbyname name in
                Simulation.synch ctx.sim ;
                Log.(log (logger ctx) Debug (lazy (Printf.sprintf2 "Got these IPs for '%s': %a"
                    name
                    (Array.print Ip.inet_addr_print)
                    h_entry.Unix.h_addr_list))) ;
                h_entry.Unix.h_addr_list in
            connect_ dst_ips.(0)

let tcp_server ctx src_port server_f =
    Log.(log (logger ctx) Debug (lazy (Printf.sprintf "Establishing a server on port %s" (Tcp.Port.to_string src_port)))) ;
    let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
    Unix.setsockopt sock Unix.SO_REUSEADDR true ;
    Unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_any, (src_port :> int))) ;
    Unix.listen sock 5 ;
    let rec sock_server () =
        let fd, _ = Unix.accept sock in
        Log.(log (logger ctx) Debug (lazy (Printf.sprintf "Accepted a new connection on port %s" (Tcp.Port.to_string src_port)))) ;
        let trx = tcp_trx_of_socket ctx fd in
        server_f trx ; (* supposed to set the recv of this trx *)
        if Simulation.is_running ctx.sim then sock_server () in (* accept next connection *)
    Thread.create sock_server () |>
    ignore

(** The context Localhost's functions work against: which simulation dates what
 * it does, and the widget its logs hang under.
 *
 * It takes a location for the same reason a real interface does: this is the
 * machine running the simulation, joining it from outside, and the map has to
 * be able to show where that is. *)
let make_ctx ?location sim =
    { sim ; widget = Widget.make ~parent:sim.root ?location "localhost" }

let host ?location sim =
    let ctx = make_ctx ?location sim in
    let tcp_connect = tcp_connect ctx ~wait_for_server:true ?ttl:None ?tos:None
    and udp_connect _ ?src_port _ _ =
        ignore src_port ;
        todo "UDP connect for localhost"
    and udp_send _ ?src_port _ _ =
        ignore src_port ;
        todo "UDP send for localhost"
    and ping ?id ?seq _ =
        ignore id ; ignore seq ;
        todo "Ping from localhost"
    and udp_server _ _ =
        todo "UDP server for localhost"
    and arp_set _ _ =
        todo "set ARP table of localhost"
    and power_on ?on_ip () =
        ignore on_ip
    and power_off ?timeout () =
        ignore timeout
    and add_killer = ignore in
    { Host.widget = ctx.widget ;
      tcp_connect ; udp_connect ; udp_send ; ping ;
      gethostbyname = gethostbyname ctx ; tcp_server = tcp_server ctx ; udp_server ; signal_err ;
      dev = { write = ignore ; set_read = ignore } ;
      arp_set ; power_on ; power_off ; add_killer }
