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
open Batteries
open Tools

let debug = false

(* A net is a graph of devices (with position on a 2d plane),
   connected with cables, with additional notes, easily serializable.

   Nets are stored on disk in a file nets/net_name, in a csv format for
   easy edition.

   Nets are also available via myadmin http server:
   - GET them from nets/net_name (for the whole file)
   - or GET some parts from nets/net_name/part_name for an easier csv
   - PUT them into nets/net_name
   (for coherency reasons it's not possible to PUT only one part) *)

type hub    = { hub_nb_ports : int }
type switch = { switch_nb_ports : int ;
                switch_nb_macs : int }
type host   = { host_gw : Eth.gw_addr ;
                host_search_sfx : string ;
                host_nameserver : Ip.Addr.t ;
                host_mac : Eth.Addr.t ;
                host_ip : Ip.Addr.t option }
                (* Also: net, tap... *)
type note   = string
type plug   = HubPort of string * int
            | SwitchPort of string * int
            | HostAdapter of string
type cable  = { plugs : plug * plug
                (* later: add a category, that will generate errors depending on the
                   throughput and length *) }

let plug_printer _paren oc = function
    | HubPort (name, p) ->
        Printf.fprintf oc "Hub %s#%d" name p
    | SwitchPort (name, p) ->
        Printf.fprintf oc "Switch %s#%d" name p
    | HostAdapter name ->
        Printf.fprintf oc "Host %s" name

(* Note that a net is not the actual graph of actual virtual devices, but
   rather a constructor for such a setup, that can be easily serialized.
   That's why you do not see some Hub.Switch.t but rather the required
   parameters to create a new Hub.Switch.t *)
type elmt = Hub of hub
          | Switch of switch
          | Host of host
          | Note of note
          (* later: Net of t *)

type node = { elmt : elmt ;
              mutable pos : float * float ;
              mutable node_name : string }

type t = { name : string ; nodes : node list ; cables : cable list }

let make name nodes cables = { name ; nodes ; cables }

let empty name = make name [] []

exception Cannot_parse of string * string

let hub_of_csv str =
    let make_hub name x y nb_ports =
        { elmt = Hub { hub_nb_ports = nb_ports } ;
          pos = x, y ;
          node_name = name } in
    try Scanf.sscanf str "%S,%f,%f,%d" make_hub
    with _ -> raise (Cannot_parse ("hub", str))

let switch_of_csv str =
    let make_switch name x y nb_ports nb_macs =
        { elmt = Switch { switch_nb_ports = nb_ports ;
                          switch_nb_macs = nb_macs } ;
          pos = x, y ;
          node_name = name } in
    try Scanf.sscanf str "%S,%f,%f,%d,%d" make_switch
    with _ -> raise (Cannot_parse ("switch", str))

let host_of_csv str =
    let make_host name x y gw search_sfx nameserver mac ip =
        { elmt = Host { host_gw = Eth.gw_addr_of_string gw ;
                        host_search_sfx = search_sfx ;
                        host_nameserver = Ip.Addr.of_string nameserver ;
                        host_mac = Eth.Addr.of_string mac ;
                        host_ip = if String.length ip > 0 then Some (Ip.Addr.of_string ip)
                                  else None } ;
          pos = x, y ;
          node_name = name } in
    try Scanf.sscanf str "%S,%f,%f,%s@,%s@,%s@,%s@,%s" make_host
    with _ -> raise (Cannot_parse ("host", str))

let note_of_csv str =
    let make_note name x y text =
        { elmt = Note text ;
          pos = x, y ;
          node_name = name } in
    try Scanf.sscanf str "%S,%f,%f,%S" make_note
    with _ -> raise (Cannot_parse ("note", str))

let node_of_csv t str =
    (if t = "switch" then switch_of_csv
    else if t = "hub" then hub_of_csv
    else if t = "host" then host_of_csv
    else if t = "note" then note_of_csv
    else invalid_arg t) str

let cable_of_csv str =
    (* when pluged to port -1, it means take next available port *)
    let make_plug typ nam =
        if typ = "hub" then HubPort (nam, -1)
        else if typ = "switch" then SwitchPort (nam, -1)
        else if typ = "host" then HostAdapter nam
        else invalid_arg typ in
    let make_cable t1 n1 t2 n2 =
        let p1 = make_plug t1 n1 and p2 = make_plug t2 n2 in
        { plugs = p1, p2 } in
    try Scanf.sscanf str "%s@,%S,%s@,%S" make_cable
    with _ -> raise (Cannot_parse ("cable", str))

let of_csv_file ic name =
    let nodes = ref [] and cables = ref [] in
    let make_thing t rest =
        if t = "cable" then (
            cables := cable_of_csv rest :: !cables
        ) else (
            nodes := node_of_csv t rest :: !nodes
        ) in
    Enum.iter
        (fun str ->
            let t, rest = String.split str "," in
            make_thing t rest)
        (BatIO.lines_of ic) ;
    make name !nodes !cables

let of_csv_string str name =
    (* FIXME: close on exception! with_input... *)
    let ic = BatIO.input_string str in
    let net = of_csv_file ic name in
    BatIO.close_in ic ;
    net

let csv_for_hosts oc t =
    Printf.fprintf oc "name,x,y,gw,search_sfx,nameserver,mac,ip\n" ;
    List.iter (function
        | { elmt = Host h ; pos = x,y ; node_name } ->
            Printf.fprintf oc "%S,%f,%f,%s,%s,%s,%s,%s\n"
                node_name x y
                (Eth.string_of_gw_addr h.host_gw)
                h.host_search_sfx
                (Ip.Addr.to_dotted_string h.host_nameserver)
                (Eth.Addr.to_string h.host_mac)
                (match h.host_ip with
                    | Some ip -> Ip.Addr.to_dotted_string ip
                    | _ -> "")
        | _ -> ())
        t.nodes

let csv_for_switches oc t =
    Printf.fprintf oc "name,x,y,nb_ports,nb_macs\n" ;
    List.iter (function
        | { elmt = Switch s ; pos = x,y ; node_name } ->
            Printf.fprintf oc "%S,%f,%f,%d,%d\n"
                node_name x y s.switch_nb_ports s.switch_nb_macs
        | _ -> ())
        t.nodes

let csv_for_hubs oc t =
    Printf.fprintf oc "name,x,y,nb_ports\n" ;
    List.iter (function
        | { elmt = Hub h ; pos = x,y ; node_name } ->
            Printf.fprintf oc "%S,%f,%f,%d\n"
                node_name x y h.hub_nb_ports
        | _ -> ())
        t.nodes

let csv_for_notes oc t =
    Printf.fprintf oc "name,x,y,text\n" ;
    List.iter (function
        | { elmt = Note text ; pos = x,y ; node_name } ->
            Printf.fprintf oc "%S,%f,%f,%S\n"
                node_name x y text
        | _ -> ())
        t.nodes

let csv_for_cables oc t =
    let print_plug oc = function
        | HubPort (n, _)    -> Printf.fprintf oc "hub,%S" n
        | SwitchPort (n, _) -> Printf.fprintf oc "switch,%S" n
        | HostAdapter n     -> Printf.fprintf oc "host,%S" n in
    Printf.fprintf oc "type1,name1,type2,name2\n" ;
    List.iter (fun { plugs = a, b } ->
        Printf.fprintf oc "%a,%a\n"
            print_plug a print_plug b)
        t.cables

let csv_for_node oc = function
    | { elmt = Host h ; pos = x,y ; node_name } ->
        Printf.fprintf oc "host,%S,%f,%f,%s,%s,%s,%s,%s\n"
            node_name x y
            (Eth.string_of_gw_addr h.host_gw)
            h.host_search_sfx
            (Ip.Addr.to_dotted_string h.host_nameserver)
            (Eth.Addr.to_string h.host_mac)
            (match h.host_ip with
                | Some ip -> Ip.Addr.to_dotted_string ip
                | _ -> "")
    | { elmt = Switch s ; pos = x,y ; node_name } ->
        Printf.fprintf oc "switch,%S,%f,%f,%d,%d\n"
            node_name x y s.switch_nb_ports s.switch_nb_macs
    | { elmt = Hub h ; pos = x,y ; node_name } ->
        Printf.fprintf oc "hub,%S,%f,%f,%d\n"
            node_name x y h.hub_nb_ports
    | { elmt = Note text ; pos = x,y ; node_name } ->
        Printf.fprintf oc "note,%S,%f,%f,%S\n"
            node_name x y text

let csv_for_cable oc { plugs = a, b } =
    let print_plug oc = function
        | HubPort (n, _)    -> Printf.fprintf oc "hub,%S" n
        | SwitchPort (n, _) -> Printf.fprintf oc "switch,%S" n
        | HostAdapter n     -> Printf.fprintf oc "host,%S" n in
    Printf.fprintf oc "cable,%a,%a\n"
        print_plug a print_plug b

let to_csv_file oc t =
    List.iter (csv_for_node oc) t.nodes ;
    List.iter (csv_for_cable oc) t.cables

let save t =
    Persist.with_output_file "nets" t.name (fun oc ->
        to_csv_file oc t)

let load name =
    Persist.with_input_file "nets" name "" (fun ic ->
        of_csv_file ic name)

(* creates all the nodes and returns an index allowing to reach any (named) node by name *)
let instanciate t =
    Printf.printf "Net: instanciate net %s\n" t.name ;
    let hubs = Hashtbl.create 11 in
    let switches = Hashtbl.create 11 in
    let hosts = Hashtbl.create 11 in
    let notes = Hashtbl.create 11 in
    let create_node { node_name = name ; elmt ; _ } = match elmt with
        | Hub h ->
            Hashtbl.add hubs name
                (Hub.Repeater.make h.hub_nb_ports)
        | Switch s ->
            Hashtbl.add switches name
                (Hub.Switch.make s.switch_nb_ports s.switch_nb_macs)
        | Host h ->
            Hashtbl.add hosts name
                (match h.host_ip with
                | None ->
                    Host.make_dhcp name
                                   ~gw:h.host_gw
                                   ~search_sfx:h.host_search_sfx
                                   ~nameserver:h.host_nameserver
                                   h.host_mac
                | Some ip ->
                    Host.make_static name
                                   ~gw:h.host_gw
                                   ~search_sfx:h.host_search_sfx
                                   ~nameserver:h.host_nameserver
                                   h.host_mac ip)
        | Note text ->
            Hashtbl.add notes name text in
    let connect_cable { plugs = a, b } =
        (* return the rx function and set_emit function of the plug *)
        (* FIXME: handle when port number = -1 *)
        let rx_of_plug = function
            | HubPort (name, p) ->
                Hashtbl.find_option hubs name |>
                    Option.map (fun hub ->
                        Hub.Repeater.rx p hub, Hub.Repeater.set_emit p hub)
            | SwitchPort (name, p) ->
                Hashtbl.find_option switches name |>
                    Option.map (fun sw ->
                        Hub.Switch.rx p sw, Hub.Switch.set_emit p sw)
            | HostAdapter name ->
                Hashtbl.find_option hosts name |>
                    Option.map (fun host ->
                        host.Host.dev.write, host.Host.dev.set_read) in
        let a_rx = rx_of_plug a and b_rx = rx_of_plug b in
        match a_rx, b_rx with
        | None, _ -> Print.printf p"Net: Cannot connect unknown node %{plug}\n%!" a
        | _, None -> Print.printf p"Net: Cannot connect unknown node %{plug}\n%!" b
        | Some (a_rx, a_set_emit), Some (b_rx, b_set_emit) ->
            (* TODO: choose latency according to cable actual length *)
            (* TODO: choose throughput according to min of both adapters throughput *)
            (* TODO: add a flag for half/full duplex *)
            let latency = Clock.Interval.msec 10. and throughput = 1_000_000_000. in
            let half_dup = Eth.limited latency throughput in
            a_set_emit (half_dup b_rx) ;
            b_set_emit (half_dup a_rx)
    in
    List.iter create_node t.nodes ;
    List.iter connect_cable t.cables ;
    hubs, switches, hosts, notes
