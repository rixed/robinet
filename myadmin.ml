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
        <input type="submit" name="redraw" value="redraw"/>
    </form>
</div>
<div>
    <img width="%d" height="%d"
     src="https://chart.googleapis.com/chart?chs=%dx%d&amp;cht=lc&amp;chd=%s&amp;chdl=%s&amp;chdlp=b&amp;chco=%s&amp;chxt=x,y&amp;chxl=0:|Past|Now&amp;chxr=1,%Ld,%Ld&amp;chds=%Ld,%Ld"
     alt="Metrics"/>
</div>
|}
        (print_tree vars) (Metric.tree ())
        width height width height
        chd chdl chco !chds_min !chds_max !chds_min !chds_max ;
    [ "Content-Type", "text/html" ]

let find_logs ?(max_level=Log.max_level) ?(vert_distance=0) ?(horiz_distance=0)
              logger =
    (* Collect all loggers within those distances: *)
    let loggers =
        let visited = ref Set.String.empty in
        let is_close max_dist logger =
            if max_dist < 0 then (
                Printf.printf "max dist %d < 0\n%!" max_dist ;
                false
            ) else if Set.String.mem logger.Log.full_name !visited then (
                Printf.printf "already visited %s\n%!" logger.full_name ;
                false
            ) else (
                Printf.printf "Visiting logger %s\n%!" logger.full_name ;
                visited := Set.String.add logger.full_name !visited ;
                true
            ) in
        let rec loop_up loggers max_horiz max_up max_down logger =
            if max_up >= 0 then (
                loop_horiz loggers max_horiz max_up max_down logger
            ) else loggers
        and loop_down loggers max_horiz max_up max_down logger =
            if max_down >= 0 then (
                loop_horiz loggers max_horiz max_up max_down logger
            ) else loggers
        and loop_horiz loggers max_horiz max_up max_down logger =
            Printf.printf "loop_horiz %d %d %d %S\n%!" max_horiz max_up max_down logger.Log.full_name ;
            if is_close max_horiz logger then (
                Printf.printf "Adding logger %s\n%!" logger.full_name ;
                let loggers = logger :: loggers in
                let loggers =
                    match logger.parent with
                    | Some p ->
                        (* Don't come back down to not end up in other branches *)
                        loop_up loggers max_horiz (max_up - 1) 0 p
                    | None -> loggers in
                let loggers =
                    List.fold_left (fun loggers child ->
                        (* There is no point coming back up: *)
                        loop_down loggers max_horiz 0 (max_down - 1) child
                    ) loggers logger.children in
                List.fold_left (fun loggers (sibling : Log.sibling) ->
                    match sibling.via with
                    | None ->
                        loop_horiz loggers (max_horiz - 1) max_up max_down
                                   sibling.peer
                    | Some via ->
                        let loggers =
                            loop_horiz loggers (max_horiz - 1) max_up max_down
                                       via in
                        loop_horiz loggers (max_horiz - 2) max_up max_down
                                   sibling.peer
                ) loggers logger.siblings
            ) else loggers in
        loop_horiz [] horiz_distance vert_distance vert_distance logger in
    Printf.printf "Got these loggers: %a\n%!" (List.print (fun oc l -> String.print oc l.Log.full_name)) loggers ;
    (* TODO: options to include N parents/children, M siblings... Aka vertical
     * and horizontal distance *)
    let collect_logger e (logger : Log.logger) =
        let rec loop lvl e =
            if lvl > max_level then e else
            let e' = Log.queue_enum logger.queues.(lvl) in
            let e' = Enum.map (fun l -> logger, lvl, l) e' in
            loop (lvl + 1) (Enum.append e e') in
        loop 0 e in
    let e = List.fold_left collect_logger (Enum.empty ()) loggers in
    let a = Array.of_enum e in
    Array.fast_sort
        (fun (_, _, (t1, _)) (_, _, (t2, _)) -> Clock.Time.compare t1 t2) a ;
    Array.enum a, loggers

let logs _mth _matches vars _qry_body resp_body =
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
    let int_of_var name def =
        Hashtbl.find_option vars name |>
        Option.map int_of_string |? def in
    let max_level = int_of_var "max_level" Log.max_level in
    let vert_distance = int_of_var "vert_distance" 0 in
    let horiz_distance = int_of_var "horiz_distance" 0 in
    let ignored_loggers =
        Hashtbl.find_all vars "ignored" |>
        List.fold_left (fun ignored_loggers name ->
            Set.String.add name ignored_loggers
        ) Set.String.empty in
    Printf.fprintf resp_body "<div><form>\n" ;
    let selected = " selected" in
    Printf.fprintf resp_body "\
        <select name=\"logger\" \
                onchange=\"this.form.submit()\">\n\
            %a\
        </select>\n"
        (Array.print ~first:"" ~last:"" ~sep:""
            (fun oc name ->
                let v = Html.cdata_encode name in
                Printf.fprintf oc "<option value=\"%s\"%s>%s</option>\n"
                    v
                    (if logger_name = Some name then selected else "")
                    v)
        ) all_names ;
    Printf.fprintf resp_body "\
        <label>Up to:\n\
          <select name=\"max_level\" \
                  onchange=\"this.form.submit()\">\n\
            %a\
          </select>\n\
        </label>\n"
        (Enum.print ~first:"" ~last:"" ~sep:""
            (fun oc lvl ->
                Printf.fprintf oc "<option value=\"%d\"%s>%s</option>\n"
                    lvl
                    (if max_level = lvl then selected else "")
                    (Log.string_of_int_level lvl))
        ) (Enum.range 0 ~until:Log.max_level) ;
    Printf.fprintf resp_body "\
        <label>Parents:\n\
          <select name=\"vert_distance\" \
                  onchange=\"this.form.submit()\">\n\
            %a\
          </select>\n\
        </label>\n"
        (List.print ~first:"" ~last:"" ~sep:""
            (fun oc (v, l) ->
                Printf.fprintf oc "<option value=\"%d\"%s>%s</option>\n"
                    v
                    (if vert_distance = v then selected else "")
                    l)
        ) [ 0, "none" ; 1, "direct" ; 2, "two levels" ; max_int, "all" ] ;
    Printf.fprintf resp_body "\
        <label>Siblings:\n\
          <select name=\"horiz_distance\" \
                  onchange=\"this.form.submit()\">%a\
          </select>\n\
        </label>\n"
        (List.print ~first:"" ~last:"" ~sep:""
            (fun oc (v, l) ->
                Printf.fprintf oc "<option value=\"%d\"%s/>%s</option>\n"
                    v
                    (if horiz_distance = v then selected else "")
                    l)
        ) [ 0, "none" ; 1, "direct" ; 2, "two levels" ; max_int, "all" ] ;
    Option.may (fun logger_name ->
        let logger = Hashtbl.find_option Log.loggers logger_name in
        Option.may (fun (logger : Log.logger) ->
            let open_link_to (l : Log.logger) =
                Printf.sprintf "<a href=\"?logger=%s&max_level=%d&vert_distance=%d&horiz_distance=%d\">"
                    (Url.encode l.full_name)
                    max_level vert_distance horiz_distance in
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
|}
                (* parent *)
                open_link close_link
                (* children *)
                (if logger.children <> [] then "children: " else "")
                (List.print ~first:"" ~last:"" ~sep:" | " print_child)
                    logger.children
                (* siblings *)
                (if logger.siblings <> [] then "siblings: " else "")
                (List.print ~first:"" ~last:"" ~sep:" | " print_sibling)
                    logger.siblings ;
            (* And now the log selection: *)
            let logs, loggers = find_logs ~max_level ~vert_distance ~horiz_distance logger in
            let loggers =
                List.fast_sort (fun l1 l2 ->
                    String.compare l1.Log.full_name l2.full_name
                ) loggers in
            if loggers <> [] then (
                let print_ignored_logger oc logger =
                    let v = Html.cdata_encode logger.Log.full_name in
                    Printf.fprintf oc "\
                        <option value=\"%s\"%s>%s</option>\n"
                        v
                        (if Set.String.mem logger.full_name ignored_loggers
                        then selected else "")
                        v in
                Printf.fprintf resp_body "\
                    <div><label>Hide:&nbsp;\n\
                        <select multiple name=\"ignored\" \
                                onchange=\"this.form.submit()\">\n\
                        %a\
                        </select>\n\
                    </label></div>\n"
                    (List.print ~first:"" ~last:"" ~sep:"" print_ignored_logger)
                        loggers
            ) ;
            let print_log oc (logger, lvl, (t, msg)) =
                Printf.fprintf oc "<tr><td>%a</td><td>%s</td><td>%s</td><td>%s</td></tr>\n"
                    Clock.printer t
                    logger.Log.full_name
                    (Log.string_of_int_level lvl)
                    (Lazy.force msg) in
            Printf.fprintf resp_body {|
<div>
    <table>
    <thead>
        <tr><th>Time</th><th>Source</th><th>Level</th><th>Message</th></tr>
    </thead>
    <tfoot>
        <tr><th>Time</th><th>Source</th><th>Level</th><th>Message</th></tr>
    </tfoot>
    <tbody>
    %a
    </tbody>
    </table>
</div>
|}
                (Enum.print ~first:"" ~last:"" ~sep:"" print_log)
                    (Enum.filter (fun (l, _, _) ->
                        not (Set.String.mem l.Log.full_name ignored_loggers)
                    ) logs)
        ) logger
    ) logger_name ;
    Printf.fprintf resp_body "</form></div>\n" ;
    [ "Content-Type", "text/html" ]

let make host port =
    let res = [ Str.regexp "/home.html$", home ;
                Str.regexp "/$", home ;
                Str.regexp "/metrics.html$", metrics ;
                Str.regexp "/logs.html$", logs ] in
    Opache.serve host ~port (Opache.multiplexer res)
