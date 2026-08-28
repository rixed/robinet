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
  Serves the administration interface itself: the page, its script and its
  style sheet.

  Those live in www/ as ordinary files, and are compiled into
  myadmin_assets.ml by the Makefile, so that a robinet program is a single
  binary with nothing to install alongside it and no directory to find at run
  time. There is deliberately no serving of arbitrary files.
*)
open Batteries

let content_type name =
    if String.ends_with name ".html" then "text/html" else
    if String.ends_with name ".js" then "text/javascript" else
    if String.ends_with name ".css" then "text/css" else
    "text/plain"

let asset name _mth _matches _vars _qry_body resp =
    match List.assoc name Myadmin_assets.all with
    | exception Not_found ->
        raise (Opache.ResourceError (404, "No such asset: "^ name))
    | content ->
        String.print resp content ;
        200, [ "Content-Type", content_type name ]

let resources : (Str.regexp * Opache.resource) list =
    (* One route per asset, rather than a path taken from the URL: there is
     * nothing to escape, and nothing can be reached that we did not put
     * there. *)
    (Str.regexp "/$", asset "index.html") ::
    List.map (fun (name, _) ->
        Str.regexp ("/"^ Str.quote name ^"$"), asset name
    ) Myadmin_assets.all
