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
  An HTTP server for monitoring/editing the virtual network.

  This module now only holds the routing table; the handlers themselves live in
  the myadmin_* modules.
*)
open Batteries

(* Kept here for the benefit of the simulations that start it: *)
let report_thread = Myadmin_metrics.report_thread

let make sim host port =
    let res =
        Myadmin_api.resources sim @
        [ Str.regexp "/home.html$", Myadmin_home.home ;
          Str.regexp "/$", Myadmin_home.home ;
          Str.regexp "/metrics.html$", Myadmin_metrics.metrics ;
          Str.regexp "/logs.html$", Myadmin_logs.logs ] in
    Opache.(serve host ~port (multiplexer res))
