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
open Bitstring
open Tools

let run port root =
    let host = Localhost.make () in
    (* Start server *)
    let resources =
        [ Str.regexp "/\\(.*\\)$", Opache.static_file_server root ] in
    Opache.serve host (Tcp.Port.o port) (Opache.multiplexer resources) ;
    (* Run everything *)
    Lwt.join [ Clock.run true ]

let main =
    let port = ref 80 and root = ref "./" in
    Arg.parse [ "-port", Arg.Set_int port,    "TCP port to listen to (default: 80)" ;
                "-root", Arg.Set_string root, "Root directory (default: ./)" ]
              (fun _ -> raise (Arg.Bad "unknown parameter"))
              "Start a static file http server" ;
    Random.self_init () ;
    Lwt_main.run (
        Lwt.choose [ run !port !root ]
    )

