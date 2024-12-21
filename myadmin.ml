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
let report_thread period =
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
    let rec loop () =
        Thread.delay period ;
        (* Save all the metrics *)
        if debug then Printf.printf "MyAdmin: updating stored metrics\n%!" ;
        serie_current_idx := if !serie_current_idx < serie_size-1 then !serie_current_idx+1 else 0 ;
        Hashtbl.iter update_atomic Metric.Atomic.all ;
        if !Clock.continue then loop () in
    Thread.create loop ()

let basename s =
    try snd (String.rsplit ~by:"/" s) with Not_found -> s

(* Must be placed within a FORM *)
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

let page_head resp_body =
    Printf.fprintf resp_body
        {|<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
    <meta charset="utf-8">
    <title>RobiNet: Network Simulator</title>
</head>
<div>
    <a href="home.html">home</a>
    <a href="metrics.html">metrics</a>
    <a href="logs.html">logs</a>
</div>
|}

let home _mth _matches _vars _qry_body resp_body =
    page_head resp_body ;
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
    page_head resp_body ;
    Printf.fprintf resp_body {|
<div>
    <form>
        %a
        <input type='submit' name='redraw' value='redraw'/>
    </form>
</div>
<div>
    <img width='%d' height='%d'
     src='https://chart.googleapis.com/chart?chs=%dx%d&amp;cht=lc&amp;chd=%s&amp;chdl=%s&amp;chdlp=b&amp;chco=%s&amp;chxt=x,y&amp;chxl=0:|Past|Now&amp;chxr=1,%Ld,%Ld&amp;chds=%Ld,%Ld'
     alt='Metrics'/>
</div>
|}
        (print_tree vars) (Metric.tree ())
        width height width height
        chd chdl chco !chds_min !chds_max !chds_min !chds_max ;
    [ "Content-Type", "text/html" ]

let logs _mth _matches vars _qry_body resp_body =
    let print_queue oc q =
        Log.queue_iter (fun t str ->
                Printf.fprintf oc "<tr><td>%a</td><td>%s</td></tr>\n"
                Clock.printer t str)
            q in
    page_head resp_body ;
    let all_names =
        Hashtbl.keys Log.loggers |>
        Array.of_enum in
    Array.fast_sort String.compare all_names ;
    let logger_name =
        try
            Some (Hashtbl.find vars "logger")
        with Not_found ->
            if Array.length all_names > 0 then Some all_names.(0) else None in
    Printf.fprintf resp_body {|
<div>
    <form>
        <select name="logger" onchange="this.form.submit()">%a</select>
    </form>
</div>
|}
        (Array.print ~first:"" ~last:"" ~sep:""
            (fun oc name ->
                Printf.fprintf oc "<option value=\"%s\"%s/>%s</option>\n"
                    name
                    (if logger_name = Some name then " selected=\"selected\"" else "")
                    name)) all_names ;
    Option.may (fun logger_name ->
        let logger = Hashtbl.find_option Log.loggers logger_name in
        Option.may (fun (logger : Log.logger) ->
            let open_link_to (l : Log.logger) =
                Printf.sprintf "<a href=\"?logger=%s\">" (Url.encode l.full_name) in
            let link_to ?(full_name=false) (l : Log.logger) =
                Printf.sprintf "%s%s</a>"
                    (open_link_to l)
                    (if full_name then l.full_name else l.name) in
            let print_child oc (l : Log.logger) =
                String.print oc (link_to l) in
            let print_sibling oc (s : Log.sibling) =
                String.print oc (link_to ~full_name:true s.peer) ;
                Option.may (fun via ->
                    Printf.fprintf oc "&nbsp;(via: %s)" (link_to via)
                ) s.via in
            let open_link, close_link =
                match logger.parent with
                | None -> "<s>", "</s>"
                | Some parent -> open_link_to parent, "</a>" in
            Printf.fprintf resp_body {|
<div>
    %sparent%s
<!-- children: -->
%s%a<br/>
<!-- siblings: -->
%s%a
</div>
<div>
    <table>
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
                (* parent *)
                open_link close_link
                (* children *)
                (if logger.children <> [] then "children: " else "")
                (List.print ~first:"" ~last:"" ~sep:" | " print_child) logger.children
                (* siblings *)
                (if logger.siblings <> [] then "siblings: " else "")
                (List.print ~first:"" ~last:"" ~sep:" | " print_sibling) logger.siblings
                (Array.print ~first:"" ~last:"" ~sep:"" print_queue)
                    logger.queues (* TODO: add a select box for log levels *)
        ) logger
    ) logger_name ;
    [ "Content-Type", "text/html" ]

let make host port =
    let res = [ Str.regexp "/home.html$", home ;
                Str.regexp "/$", home ;
                Str.regexp "/metrics.html$", metrics ;
                Str.regexp "/logs.html$", logs ] in
    Opache.serve host ~port (Opache.multiplexer res)
