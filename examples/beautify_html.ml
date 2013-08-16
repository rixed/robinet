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
   Display the HTML structure of a file containing HTML.
*)
open Batteries
open Tools

let main =
    Arg.parse [] (fun f ->
        let str = file_content f in
        match Html.parse str with
        | None -> Printf.fprintf stderr "Cannot parse file '%s'\n" f
        | Some tree ->
            Printf.printf "File %s:\n%a" f (Html.print_tree ~level:0) tree)
        "Load an HTTP server by simulating browsing" ;

