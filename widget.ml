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
  Any object that can be visualized and manipulated via the API
 *)
open Batteries

type t =
    { name : string ;
      (* We want to be able to navigate the logs/stats/characteristics of
       * every simulated things (aka "widgets").
       * Widgets are connected with TRX in various ways, sometime "vertically",
       * as a stack of layers to assemble composed objects (ex: a service with
       * a host with an HTTP layer with a TCP layer with an IP layer with an
       * ETH layer), and sometimes "horizontally" as connections between various
       * objects, mostly via cables.
       * From the point of view of the simulator, all these are just trxs
       * connected together.
       * Those relationships are indicated at construction time.
       *
       * Parent / children: widgets form a hierarchical tree. The full_name of a
       * widget indicates that hierarchy. *)
      parent : t option ;
      mutable children : t list ;
      (* Siblings: When widgets are connected "horizontally" to others.
       * Widget names are then unrelated. *)
      mutable peers : peer list ;
      logger : Log.t ;
      (* Setter and getter of configurable properties: *)
      mutable properties : property list }

and peer = { widget : t ;
             via : t option }

and property = { name : string ;
                descr : string ;
               getter : (unit -> string) ;
               (* If that property can be set *)
               setter : (string -> unit) option }

let property ?(descr="") ?setter ~getter name =
    { name ; descr ; getter ; setter }

let full_name_ name parent =
    let rec loop full_name = function
        | None -> full_name
        | Some p ->
            let full_name = "/"^ p.name ^ full_name in
            loop full_name p.parent in
    loop ("/"^ name) parent

let full_name t = full_name_ t.name t.parent

(* All existing widgets are inventoried here.
 * Indexed by a list of names, from indexed widget to ancestor: *)
let all = Hashtbl.create 131

let make ?parent ?use_wall_clock ?size ?(properties=[]) name =
    let full_name = full_name_ name parent in
    let size =
        match size, parent with
        | Some _, _ -> size
        | None, Some p -> Some (Array.length p.logger.queues.(0).msgs)
        | None, None -> None in
    let use_wall_clock =
        match use_wall_clock, parent with
        | Some _, _ -> use_wall_clock
        | None, Some p -> Some p.logger.use_wall_clock
        | None, None -> None in
    let logger = Log.make ?use_wall_clock ?size full_name in
    let t = {
        name ;
        parent ;
        children = [] ;
        peers = [] ;
        logger ;
        properties } in
    Option.may (fun p -> p.children <- t :: p.children) parent ;
    Hashtbl.add all full_name t ;
    t

let make_peers ?via t1 t2 =
    t1.peers <- { widget = t2 ; via } :: t1.peers ;
    t2.peers <- { widget = t1 ; via } :: t2.peers ;
    Option.may (fun via ->
        via.peers <- { widget = t1 ; via = None } ::
                     { widget = t2 ; via = None } :: via.peers
    ) via
