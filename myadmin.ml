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
*)
open Batteries
open Tools

let debug = false

let serie_size = 100 (* keep the 100 last values for each metric *)
type serie = { mutable used : int ; past : int64 array ; color : int32 }
let series = Hashtbl.create 11 (* name -> past values array or size serie_size *)
let serie_current_idx = ref 0 (* last value is there, previous one is in current-1, and so on *)

(* If you use the above, you must also run this thread. period is in seconds. *)
let rec report_thread period =
    let make_color =
        let colors = [| 0xFF0000l ; 0x00FF00l ; 0x0000FFl ;
                        0x909000l ; 0x900090l ; 0x009090l ;
                        0x909090l ; 0xC08040l ; 0xC04080l ;
                        0x80C040l ; 0x8040C0l ; 0x40C080l ;
                        0x4080C0l |]
        and idx = ref 0 in
        fun () ->
            incr idx ;
            colors.(!idx mod Array.length colors) in
    let make_serie () =
        { used = 0 ; past = Array.create serie_size 0L ; color = make_color () } in
    let update_atomic n ev =
        let serie =
            hash_find_or_insert series n make_serie in
        serie.past.(!serie_current_idx) <- ev.Metric.Atomic.count ;
        if serie.used < serie_size then serie.used <- serie.used + 1
    in
    Thread.delay period ;
    (* Save all the metrics *)
    if debug then Printf.printf "MyAdmin: updating stored metrics\n%!" ;
    serie_current_idx := if !serie_current_idx < serie_size-1 then !serie_current_idx+1 else 0 ;
    Hashtbl.iter update_atomic Metric.Atomic.all ;
    report_thread period

let basename s =
    try snd (String.rsplit s "/") with Not_found -> s

(* Must be englobed within a FORM *)
let print_tree vars oc tree =
    let rec add_ev oc n =
        Printf.fprintf oc "<label><input type='checkbox' name='%s'%s/>%s</label>"
            n
            (if Hashtbl.mem vars n then " checked='checked'" else "")
            (basename n)
    and add_tree oc n t =
        Printf.fprintf oc "%s\n<ul>%a</ul>\n"
            n (List.print ~first:"<li>" ~last:"</li>" ~sep:"</li>\n<li>" add_item) t
    and add_item oc = function
        | Metric.Atomic ev   -> add_ev oc ev.Metric.Atomic.name
        | Metric.Counter ev  -> add_ev oc ev.Metric.Counter.name
        | Metric.Timed ev    -> add_ev oc ev.Metric.Timed.name
        | Metric.Tree (n, t) -> add_tree oc n t in
    add_tree oc "" tree

let page_head ?(selected="home") resp_body =
    Printf.fprintf resp_body
        {|<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
    <title>RobiNet: Network Simulator</title>
    <link rel="stylesheet" type="text/css" media="screen" href="fonts.css" />
    <link rel="stylesheet" type="text/css" media="screen" href="colors.css" />
    <link rel="stylesheet" type="text/css" media="screen" href="layout.css" />
    <link rel="stylesheet" type="text/css" media="screen" href="svg.css" />
    <script type="text/javascript" src="d3.js"></script>
    <script type="text/javascript" src="d3.csv.js"></script>
    <script type="text/javascript" src="gge.js"></script>
    <script type="text/javascript" src="myfuncs.js"></script>
</head>
<body onload='load_menu("%s")'>
<div id="menu"></div>
<div id="page">
|}
        selected

let page_foot resp_body =
    Printf.fprintf resp_body {|</div>
<div id="foot">
    <p>footer</p>
</div>
</body>
|}

let home _mth _matches _vars _qry_body resp_body =
    page_head ~selected:"home" resp_body ;
    page_foot resp_body ;
    [ "Content-Type", "text/html" ]

let net _mth _matches _vars _qry_body resp_body =
    page_head ~selected:"net editor" resp_body ;
    Printf.fprintf resp_body {|
<div id="controls">
    <form action="javascript: false;">
        <!-- a select to choose the net to edit? -->
        <div id="dyncontrols">
            Select an item to edit.
        </div>
        <span class="buttons">
            <span class="grouped">
                <input type="button" value="Add:" onclick='javascript: new_net_item();'/>
                <select name="what">
                    <option value="">New...</option>
                    <option value="host">host (static)</option>
                    <option value="dynhost">host (dhcp)</option>
                    <option value="hub">hub</option>
                    <option value="switch">switch</option>
                    <option value="tap">tap</option>
                    <option value="note">note</option>
                    <!-- where the user can plug another net, a pcap file, a pcap dev... -->
                    <option value="anchor">anchor</option>
                </select>
                <input type="button" id="netlink" value="Link to..." onclick='javascript: new_net_link();'/>
                <input type="button" id="netunlink" value="Unlink from..." onclick='javascript: del_net_link();'/>
                <input type="button" value="Save" onclick='javascript: save_net();'/>
            </span>
            <span class="away">
                <input type="submit" value="Delete" onclick='javascript: del_net_item();'/>
            </span>
        </span>
    </form>
</div>
<div id="view">
    <svg id="net" />
</div>
<script type="text/javascript">
    load_net_editor("demonet", "net");
</script>
|};
    page_foot resp_body ;
    [ "Content-Type", "text/html" ]

let netpart_csv _mth matches _vars _qry_body resp_body =
    match matches with
    | _total :: netname :: partname :: [] ->
        let net = Net.load netname in
        if partname = "hub" then Net.csv_for_hubs resp_body net
        else if partname = "switch" then Net.csv_for_switches resp_body net
        else if partname = "host"   then Net.csv_for_hosts    resp_body net
        else if partname = "note"   then Net.csv_for_notes    resp_body net
        else if partname = "cable"  then Net.csv_for_cables   resp_body net ;
        [ "Content-Type", "text/csv" ]
    | _ -> should_not_happen ()

let net_csv mth matches _vars qry_body resp_body =
    match matches with
    | _total :: netname :: [] ->
        (match mth with
        | "GET" ->
            let net = Net.load netname in
            Net.to_csv_file resp_body net ;
            [ "Content-Type", "text/csv" ]
        | "PUT" ->
            (try
                let net = Net.of_csv_string qry_body netname in
                Net.save net ;
                Printf.fprintf resp_body "Ok" ;
                [ "content-Type", "text/plain" ]
            with Net.Cannot_parse (what, line) ->
                raise (Opache.ResourceError (406, Printf.sprintf "Cannot make a %s out of '%s'" what line)))
        | _ ->
            raise (Opache.ResourceError (405, Printf.sprintf "Unknown method '%s'" mth)))
    | _ -> should_not_happen ()

let scenarii _mth _matches _vars _qry_body resp_body =
    page_head ~selected:"scenarii" resp_body ;
    page_foot resp_body ;
    [ "Content-Type", "text/html" ]

let engine _mth _matches _vars _qry_body resp_body =
    page_head ~selected:"engine" resp_body ;
    page_foot resp_body ;
    [ "Content-Type", "text/html" ]

(* See Google chart API doc here: http://code.google.com/apis/chart/image/docs/making_charts.html *)
let metrics _mth _matches vars _qry_body resp_body =
    if debug then Printf.printf "MyAdmin: metric: vars = %a\n" Opache.print_vars vars ;
    let chds_min = ref 0L and chds_max = ref 0L in
    let serie_of_metric n =
        (* given the name of a metric, returns the serie of values we know for this metric and a color *)
        match Hashtbl.find_option series n with
        | None -> [], 0x000000l
        | Some serie ->
            let rec aux prev idx left =
                if left > 0 then (
                    let v = serie.past.(idx) in
                    if v < !chds_min then chds_min := v ;
                    if v > !chds_max then chds_max := v ;
                    aux (v::prev) (if idx>0 then idx-1 else serie_size-1) (left-1)
                ) else prev in
            let values = aux [] !serie_current_idx serie.used in
            values, serie.color
    in
    let names, values, colors = Hashtbl.fold (fun n _ ((names, values, colors) as prev) ->
        match serie_of_metric n with
        | [], _ -> prev
        | s, c -> (Url.encode n::names, s::values, c::colors)) vars ([], [], []) in
    let chd =
        let str = BatIO.output_string () in
        List.print ~first:"t:" ~last:"" ~sep:"|"
            (List.print ~first:"" ~last:"" ~sep:"," Int64.print) str values ;
        BatIO.close_out str
    and chdl =
        let str = BatIO.output_string () in
        List.print ~first:"" ~last:"" ~sep:"|" String.print str names ;
        BatIO.close_out str
    and chco =
        let str = BatIO.output_string () in
        List.print ~first:"" ~last:"" ~sep:","
            (fun out t -> Printf.fprintf out "%06lX" t)
            str colors ;
        BatIO.close_out str
    and width, height = 640, 460
    in
    page_head ~selected:"metrics" resp_body ;
    Printf.fprintf resp_body {|
<div id="controls">
    <form id='metric' method='post'>
        %a
        <input type='submit' name='redraw' value='redraw'/>
    </form>
</div>
<div id="view">
    <img width='%d' height='%d' class='chart'
     src='https://chart.googleapis.com/chart?chs=%dx%d&amp;cht=lc&amp;chd=%s&amp;chdl=%s&amp;chdlp=b&amp;chco=%s&amp;chxt=x,y&amp;chxl=0:|Past|Now&amp;chxr=1,%Ld,%Ld&amp;chds=%Ld,%Ld'
     alt='Metrics'/>
</div>
|}
        (print_tree vars) (Metric.tree ())
        width height width height
        chd chdl chco !chds_min !chds_max !chds_min !chds_max ;
    page_foot resp_body ;
    [ "Content-Type", "text/html" ]

let logs _mth _matches vars _qry_body resp_body =
    let print_queue oc q =
        Log.queue_iter (fun t str ->
                Printf.fprintf oc "<tr><td class=\"time\">%a</td><td>%s</td></tr>\n"
                Clock.printer t str)
            q in
    page_head ~selected:"logs" resp_body ;
    let logger_name = try Hashtbl.find vars "logger" with Not_found -> "Host/localhost" in
    let logger = Hashtbl.find Log.loggers logger_name in
    Printf.fprintf resp_body {|
<div id="controls">
    <form id='logger' method='post'>
        %a
        <input type='submit' name='show' value='show'/>
    </form>
</div>
<div id="view" class="logs">
    <table class="log">
    <caption>%s</caption>
    <thead>
        <tr><th>Time</th><th>Message</th></tr>
    </thead>
    <tfoot>
        <tr><th>Time</th><th>Message</th></tr>
    </tfoot>
    <tbody>
    %a
    </tbody>
    </table>
</div>
|}
        (Hashtbl.print ~first:"<select name='logger'>\n" ~last:"</select>\n" ~sep:"" ~kvsep:""
            (fun _ _ -> ())
            (fun oc v ->
                Printf.fprintf oc "<option value='%s'%s/>%s</option>\n"
                    v.Log.name
                    (if logger_name = v.Log.name then " selected='selected'" else "")
                    (basename v.Log.name))) Log.loggers
        logger.Log.name
        (Array.print ~first:"" ~last:"" ~sep:"" print_queue) logger.Log.queues ; (* add a select box for log levels *)
    page_foot resp_body ;
    [ "Content-Type", "text/html" ]

let make host port =
    let res = [ Str.regexp "/home.dyn$", home ;
                Str.regexp "/$", home ;
                Str.regexp "/net.dyn$", net ;
                Str.regexp "/nets/\\(.+\\)/\\([^/]+\\).csv$", netpart_csv ;
                Str.regexp "/nets/\\(.+\\).csv$", net_csv ;
                Str.regexp "/scenarii.dyn$", scenarii ;
                Str.regexp "/engine.dyn$", engine ;
                Str.regexp "/metrics.dyn$", metrics ;
                Str.regexp "/logs.dyn$", logs ;
                Str.regexp "/\\(.*\\)$", Opache.static_file_server "./www" ] in
    Opache.serve host port (Opache.multiplexer res)

