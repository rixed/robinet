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

let run sim port =
    let host = Localhost.host sim in
    (* Start server *)
    let resources =
        [ Str.regexp "/static/\\([^/]+/[^/]+\\)/\\(.*\\)$", Opache.static_file_server "./" ;
          Str.regexp ".*", Opache.it_works ] in
    Opache.serve host ~port:(Tcp.Port.o port) (Opache.multiplexer resources) ;
    Myadmin.make sim host (Tcp.Port.o (port+1)) ;
    (* Run everything *)
    Simulation.run sim true

let main =
    (* Everything this program does happens in this simulation. *)
    let sim = Simulation.make "http_echo_server" in
    let port = ref 80 in
    Arg.parse [ "-port",   Arg.Set_int port,      "TCP port to listen to (default: 80)" ]
              (fun _ -> raise (Arg.Bad "unknown parameter"))
              "Start a dummy http server" ;
    Random.self_init () ;
    (* No more report thread: metrics are read through the administration
     * interface, from the widgets that own them. *)
    run sim !port
