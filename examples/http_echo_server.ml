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
   Small HTTP server for tests
*)
open Batteries

let run port =
    let host = Localhost.make () in
    (* Start server *)
    let resources =
        [ Str.regexp "/static/\\([^/]+/[^/]+\\)/\\(.*\\)$", Opache.static_file_server "./" ;
          Str.regexp ".*", Opache.it_works ] in
    Opache.serve host ~port:(Tcp.Port.o port) (Opache.multiplexer resources) ;
    Myadmin.make host (Tcp.Port.o (port+1)) ;
    (* Run everything *)
   Clock.run true

let main =
    let port = ref 80 in
    Arg.parse [ "-port",   Arg.Set_int port,      "TCP port to listen to (default: 80)" ]
              (fun _ -> raise (Arg.Bad "unknown parameter"))
              "Start a dummy http server" ;
    Random.self_init () ;
    ignore (Myadmin.report_thread 10.) ;
    run !port
