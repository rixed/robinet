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

let to_js_string s =
    "'"^ s ^"'"  (* TODDO *)

let basename s =
    try snd (String.rsplit ~by:"/" s) with Not_found -> s

let page_head_open resp =
    Printf.fprintf resp {|<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
    <meta charset="utf-8">
    <title>RobiNet: MyAdmin</title>
|}

let page_head_close resp =
    Printf.fprintf resp {|</head>
<div>
    <a href="home.html">home</a>
    <a href="metrics.html">metrics</a>
    <a href="logs.html">logs</a>
</div>
|}

let page_head resp =
    page_head_open resp ;
    page_head_close resp

let home _mth _matches _vars _qry_body resp =
    page_head resp ;
    [ "Content-Type", "text/html" ]

(*
 * Metrics
 *)

(* Only for atomic events (ie counters): (FIXME) *)

let seq_size = 100 (* keep the 100 last values for each metric *)
let seq_used = ref 0 (* That many are used in the sequences *)
let seq_next_idx = ref 0 (* next value to write *)

type seq = { name : string ;
             past : value array ;
            color : string ;
       is_instant : bool }

and value = { min : float ; current : float ; max : float }

let value ?min ?max current =
    { min = min |? 0. ; current ; max = max |? current }

let series : (string, (Metric.Params.t, seq) Hashtbl.t) Hashtbl.t =
    Hashtbl.create 11

let make_color =
    let colors = [| "#FF0000" ; "#00FF00" ; "#0000FF" ;
                    "#909000" ; "#900090" ; "#009090" ;
                    "#909090" ; "#C08040" ; "#C04080" ;
                    "#80C040" ; "#8040C0" ; "#40C080" ;
                    "#4080C0" |]
    and idx = ref 0 in
    fun () ->
        incr idx ;
        colors.(!idx mod Array.length colors)

let make_seq name is_instant =
    let past =
        Array.init seq_size (fun _ -> { min = 0. ; current = 0. ; max = 0. }) in
    { name ; past ; color = make_color () ; is_instant }

let seq_time = make_seq "time" false

(* If you use the above, you must also run this thread.
 * [period] is in seconds. *)
let report_thread period =
    let update_atomic_metric n = function
        | Metric.Atomic.T m ->
            Hashtbl.iter (fun params count ->
                let names =
                    hash_find_or_insert series n (fun () -> Hashtbl.create 10) in
                let seq =
                    hash_find_or_insert names params (fun () -> make_seq n false) in
                seq.past.(!seq_next_idx) <- value (float_of_int count)
            ) m.counts
        | Metric.Gauge.T m ->
            Hashtbl.iter (fun params (v : Metric.Gauge.value) ->
                let names =
                    hash_find_or_insert series n (fun () -> Hashtbl.create 10) in
                let seq =
                    hash_find_or_insert names params (fun () -> make_seq n true) in
                seq.past.(!seq_next_idx) <-
                    value ~min:(float_of_int v.min)
                          ~max:(float_of_int v.max)
                          (float_of_int v.current)
            ) m.values
        | Metric.Counter.T m ->
            Hashtbl.iter (fun params count ->
                let names =
                    hash_find_or_insert series n (fun () -> Hashtbl.create 10) in
                let seq =
                    hash_find_or_insert names params (fun () -> make_seq n false) in
                seq.past.(!seq_next_idx) <- value (float_of_int count)
            ) m.values
        | Metric.Timed.T m ->
            Hashtbl.iter (fun params (v : Metric.Timed.duration) ->
                let names =
                    hash_find_or_insert series n (fun () -> Hashtbl.create 10) in
                let seq =
                    hash_find_or_insert names params (fun () -> make_seq n true) in
                seq.past.(!seq_next_idx) <-
                    value ~min:(v.min :> float) ~max:(v.max :> float)
                          ((v.sum :> float) /. float_of_int v.count)
            ) m.durations
        | _ ->
            () (* TODO *) in
    let rec forever () =
        Thread.delay period ;
        (* Save all the metrics *)
        if debug then Printf.printf "MyAdmin: updating stored metrics\n%!" ;
        Hashtbl.iter update_atomic_metric Metric.all ;
        seq_time.past.(!seq_next_idx) <- value (Unix.gettimeofday ()) ;
        seq_next_idx :=
            if !seq_next_idx < seq_size-1 then !seq_next_idx+1 else 0 ;
        if !seq_used < seq_size then incr seq_used ;
        if !Clock.continue then forever () in
    Thread.create forever ()

(*
 * Tree of all metrics
 *)

let selected = " selected"

type param_filter =
    | Expr of Search.Expr.t
    | Error of string

let metrics _mth _matches vars _qry_body resp = if debug then Printf.printf "MyAdmin: metric: vars = %a\n" Opache.print_vars vars ;
    page_head_open resp ;
    let chartjs_url = "http://happyleptic.org:8080/chart.js" in (* cached locally *)
    (* let chartjs_url = "https://cdn.jsdelivr.net/npm/chart.js" in *)
    String.print resp ("<script src=\""^ chartjs_url ^"\"></script>\n") ;
    page_head_close resp ;
    let selected_metrics = Hashtbl.find_all vars "metric" in
    (* All parameters and their possible values that are present in selected
     * metrics: *)
    let parameters : (string, Metric.Param.t Set.t) Hashtbl.t = Hashtbl.create 99 in
    List.iter (fun name ->
        match Hashtbl.find series name with
        | exception Not_found ->
            (* Although unlikely, it is possible that a metric disappear: *)
            ()
        | seqs ->
            Hashtbl.keys seqs |> Enum.uniqq |>
            Enum.iter (fun params ->
                List.iter (fun (n, v) ->
                    Hashtbl.modify_opt n (function
                        | None -> Some (Set.singleton v)
                        | Some s -> Some (Set.add v s)
                    ) parameters
                ) params)
    ) selected_metrics ;
    let filter_str = Hashtbl.find_default vars "filter" "" in
    let filter =
        let s = String.trim filter_str in
        let s = if s = "" then "true" else s in
        try Expr (Search.Expr.of_string s)
        with e ->
            Error (Printexc.to_string e) in
    if debug then Printf.eprintf "filter_str=%S, expr=%s\n" filter_str (match filter with Expr e -> Search.Expr.to_string e | Error e -> "Err:"^e) ;
    let filter_vars_of_params params =
        if debug then Printf.eprintf "filter_vars_of_params: %a\n" (List.print (Tuple2.print String.print Metric.Param.print)) params ;
        (* FIXME: Maybe search should go with Metric.Param values directly for
         * immediate values? *)
        List.map (fun (pnam, pval) ->
            pnam,
            match pval with
            | Metric.Param.Bool v -> Search.Expr.BoolVal v
            | Int v -> IntVal v
            | String v -> StrVal v
        ) params in
    (* Prepare the list of all metrics: *)
    let all_metrics =
        Hashtbl.enum Metric.all //@
        (fun (k, metric) ->
            if Metric.has_data metric then Some k else None) |>
        Array.of_enum in
    Array.fast_sort String.compare all_metrics ;
    let fold_seq_values f u seq =
        let rec loop u idx left =
            if left <= 0 then u else
            let idx = if idx < seq_size then idx else 0 in
            let u = f u seq.past.(idx) in
            loop u (idx + 1) (left - 1) in
        let start_idx =
            if !seq_used < seq_size then 0 else !seq_next_idx in
        loop u start_idx !seq_used in
    let print_values to_str oc seq =
        Char.print oc '[' ;
        fold_seq_values (fun is_first v ->
            if not is_first then Char.print oc ',' ;
            String.print oc (to_str v.current) ;
            false
        ) true seq |> ignore ;
        Char.print oc ']' in
    let print_dataset oc seq =
        Printf.fprintf oc "\
        { label: %s,
          data: %a,
          fill: false,
          borderColor: %s,
          tension: 0.1 }\n"
        (to_js_string seq.name)
        (print_values string_of_float) seq
        (to_js_string seq.color) in
    let datetime_of_float f =
        to_js_string (string_of_timestamp f) in
    let all_seqs =
        match filter with
        | Error _ ->
            []
        | Expr filter_expr ->
            List.fold_left (fun seqs name ->
                match Hashtbl.find series name with
                | exception Not_found ->
                    (* Although unlikely, it is possible that a metric disappear: *)
                    seqs
                | h ->
                    (* For now just take all params: *)
                    Hashtbl.fold (fun params seq seqs ->
                        let filter_vars = filter_vars_of_params params in
                        match Search.Expr.(
                                eval ~vars:filter_vars filter_expr |>
                                to_bool) with
                        | exception e ->
                            Printf.eprintf "Cannot evaluate filter: %S\n"
                                (Printexc.to_string e) ;
                            seqs
                        | true ->
                            seq :: seqs
                        | false ->
                            seqs
                    ) h seqs
            ) [] selected_metrics in
    let print_option oc name =
        let v = Html.cdata_encode name in
        Printf.fprintf oc "<option value=\"%s\"%s>%s</option>"
            v
            (if List.mem name selected_metrics then selected else "")
            v in
    Printf.fprintf resp {|
<div>
    <form>
        <select multiple size="%d" name="metric">
%a
        </select>
|}
        (min 15 (Array.length all_metrics))
        (Array.print print_option) all_metrics ;
    if not (Hashtbl.is_empty parameters) then (
        Printf.fprintf resp "<p>Parameters:&nbsp;%a</p>\n"
            (Enum.print (fun oc pnam ->
                Printf.fprintf oc "<span>%s (%a)</span>"
                    (Html.cdata_encode pnam)
                    (Set.print ~first:"" ~last:"" ~sep:", " (fun oc v ->
                        Metric.Param.to_string v |>
                        Html.cdata_encode |>
                        String.print oc)
                    ) (Hashtbl.find_default parameters pnam Set.empty)
            )) (Hashtbl.keys parameters |> Enum.uniqq) ;
        Printf.fprintf resp
            "<input name=\"filter\" value=\"%s\" size=\"80\"/>\n"
            (Html.cdata_encode filter_str) ;
        (match filter with
        | Error str ->
            Printf.fprintf resp "<p class=\"error\">%s</p>" str
        | _ -> ())
    ) ;
    Printf.fprintf resp {|
        <input type="submit" name="redraw" value="redraw"/>
    </form>
</div>
<div>
    <canvas id="my_chart"></canvas>
</div>
<script type="text/javascript">
    const ctx = document.getElementById('my_chart');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: %a,
            datasets: %a
        }
    });
</script>
|}
        (* labels, aka timestamps: *)
        (print_values datetime_of_float) seq_time
        (* datasets: *)
        (List.print ~sep:",\n" print_dataset) all_seqs ;
    [ "Content-Type", "text/html" ]

(*
 * Logs
 *)

let find_loggers ?(vert_distance=0) ?(horiz_distance=0) logger =
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
                List.fold_left (fun loggers (peer : Log.peer) ->
                    match peer.via with
                    | None ->
                        loop_horiz loggers (max_horiz - 1) max_up max_down
                                   peer.logger
                    | Some via ->
                        let loggers =
                            loop_horiz loggers (max_horiz - 1) max_up max_down
                                       via in
                        loop_horiz loggers (max_horiz - 2) max_up max_down
                                   peer.logger
                ) loggers logger.peers
            ) else loggers in
        loop_horiz [] horiz_distance vert_distance vert_distance logger in
    Printf.printf "Got these loggers: %a\n%!" (List.print (fun oc l -> String.print oc l.Log.full_name)) loggers ;
    loggers

let get_logs ?(max_level=Log.max_level) loggers =
    (* TODO: options to include N parents/children, M peers... Aka vertical
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
    Array.enum a

let logs_menu resp selected_name also_selected ignored_loggers =
    (* The root layer is composed of all loggre without parents: *)
    let roots =
        Hashtbl.fold (fun _k l root ->
            if l.Log.parent = None then  l :: root else root
        ) Log.loggers [] in
    let rec num_descendants logger =
        List.fold_left (fun num child ->
            num + num_descendants child
        ) 0 logger.Log.children |> max 1 in
    (* Memoize those for the duration of this function call: *)
    let num_descendants = memoize num_descendants in
    let rec max_depth logger =
        List.fold_left (fun depth child ->
            max depth (1 + max_depth child)
        ) 1 logger.Log.children in
    let onmouseover (l : Log.logger) =
        let peers =
            List.fold_left (fun peers (peer : Log.peer) ->
                let peers = peer.logger :: peers in
                match peer.via with
                | None -> peers
                | Some via -> via :: peers
            ) [] l.peers in
        let ids =
            IO.to_string (List.print ~sep:"," (fun oc (l : Log.logger) ->
                String.print oc (to_js_string ("td_"^ l.full_name)))
            ) peers in
        Printf.sprintf " onmouseover=\"highlight(%s)\" \
                         onmouseout=\"unhighlight(%s)\"" ids ids in
    let onclick (l : Log.logger) =
        " onclick=\"setLogger("^ to_js_string l.full_name ^")\"" in
    let rec loop_row bw (groups : (int * Log.logger list * int) list) =
        (* [bw] is the border width for the new separations between those \
         * [groups] *)
        Printf.fprintf resp "<tr>\n" ;
        let style is_first bwl is_last bwr no_desc =
            (* [bwl] is border width at left, r for right *)
            Printf.sprintf "border-left: %s; \
                            border-right: %s; \
                            border-top: %dpx solid black; \
                            border-bottom: %s;"
                (string_of_int (if is_first then bwl else bw) ^"px solid black")
                (string_of_int (if is_last  then bwr else bw) ^"px solid black")
                bw
                (if no_desc  then "1px solid black" else "none") in
        let rec loop_groups next_row next_is_empty = function
            | [] ->
                List.rev next_row, next_is_empty
            | (_, [], _ as empty) :: groups ->  (* empty group *)
                Printf.fprintf resp "<td></td>" ;
                let next_row = empty :: next_row in
                loop_groups next_row next_is_empty groups
            | (bwl, group, bwr) :: groups ->
                let rec loop_children is_first next_row next_is_empty prev_full prev_clen =
                    function
                    | [] ->
                        next_row, next_is_empty
                    | (l : Log.logger) :: loggers ->
                        let is_last = loggers = [] in
                        let prev_full, prev_clen, disp_name =
                            let clen = common_pref_length prev_full l.name in
                            if clen > 5 && clen >= prev_clen then
                                let eff_clen =
                                    if prev_clen > 0 then
                                        prev_clen
                                    else
                                        let clen = clen - 2 in (* keep an "anchor" *)
                                        let len = String.length l.name in
                                        let rem_len = max 3 (len - clen) in
                                        len - rem_len in
                                prev_full,
                                eff_clen,
                                "…"^ String.lchop ~n:eff_clen l.name
                            else
                                l.name,
                                0,
                                l.name in
                        let sel_class =
                            if selected_name = Some l.full_name then
                                " selected" else
                            if List.exists ((==) l) also_selected then
                                " also-selected" else "" in
                        Printf.fprintf resp
                            "<td id=\"td_%s\" \
                                colspan=\"%d\" class=\"pointy%s%s\" \
                                style=\"%s\"%s%s>%s</td>"
                            (Html.cdata_encode l.full_name)
                            (num_descendants l)
                            sel_class
                            (if Set.String.mem l.full_name ignored_loggers then
                                " ignored" else "")
                            (style is_first bwl is_last bwr (l.children = []))
                            (if l.peers = [] then "" else onmouseover l)
                            (onclick l)
                            (if disp_name <> "" then disp_name
                             else "<i>unnamed</i>") ;
                        let next_row =
                            ((if is_first then bwl else bw), l.children,
                             (if is_last then bwr else bw)) :: next_row in
                        let next_is_empty =
                            if l.children = [] then next_is_empty else false in
                        loop_children false next_row next_is_empty prev_full prev_clen loggers in
                let next_row, next_is_empty =
                    loop_children true next_row next_is_empty "" 0 group in
                loop_groups next_row next_is_empty groups in
        let next_row, next_is_empty = loop_groups [] true groups in
        Printf.fprintf resp "</tr>\n" ;
        if not next_is_empty then
            loop_row (bw  - 1) next_row in
    Printf.fprintf resp "<div style=\"display: flow-root;\">\n" ;
    List.iter (fun root ->
        let max_rows = max_depth root in
        let bw = max_rows in
        Printf.fprintf resp
            "<table class=\"loggers\" \
                    style=\"background-color: #fee; float: left; margin: 5px; \
                            border-collapse: separate; border-spacing: %dpx 0; \
                            text-align: center;\">\n"
            (2 * bw) ;
        loop_row bw [ bw, [ root ], bw ] ;
        Printf.fprintf resp "</table>\n"
    ) roots ;
    Printf.fprintf resp "</div><br style=\"clear: left\"/>\n"

let logs _mth _matches vars _qry_body resp =
    page_head_open resp ;
    Printf.fprintf resp {|
    <style type="text/css">
        /* Loggers tables */
        table.loggers {
            font-size: 0.7rem;
        }
        td.pointy {
            cursor: pointer;
        }
        td.selected {
            background-color: #faa;
            font-weight: bold;
        }
        td.also-selected {
            background-color: #fcc;
        }
        td.ignored {
            text-decoration: line-through wavy red;
        }
        /* Last because higher priority: */
        td.pointy:hover {
            background-color: #ccf;
        }
        td.highlighted {
            background-color: #4ff;
        }
        .top-pretty-please {
            display: flex;
        }
        /* Log lines */
        .hidden {
            visibility: collapse;
        }
        table.logs {
            font-family: monospace;
            font-size: 0.8rem;
            text-wrap: nowrap;
        }
        table.logs th {
            text-align: left;
            position: sticky;
            top: 0em;
            box-shadow: 0 2px 2px -1px rgba(0, 0, 0, 0.4);
            background: #fff;
            height: 1.5rem;
        }
        table.logs tr.separated > td.src, table.logs td.lvl-set {
            position: sticky;
            top: 1.75rem;
            background: #fff;
        }
        table.logs label.compl {
            font-size: 0.8em;
            font-style: italic;
        }
        table.logs td, table.logs th {
            margin-right: 0.6em;
        }
        tr.dbg {
            color: #333;
        }
        tr.err, tr.fatal, tr.crit {
            background-color: #f88;
            font-weight: bold;
        }
        tr.wrn {
            background-color: #fcc;
            font-weight: bold;
        }
        tr.nfo {
            background-color: #aff;
            font-weight: bold;
        }
        tr.separated td {
            border-top: 1px solid #888;
        }
    </style>
    <script type="text/javascript">
        function highlight(ids) {
            ids.forEach((id) =>
              this.document.getElementById(id).classList.add("highlighted"));
        }
        function unhighlight(ids) {
            ids.forEach((id) =>
              this.document.getElementById(id).classList.remove("highlighted"));
        }
        function setLogger(val) {
            let sel = this.document.getElementById('logger_select');
            sel.value = val;
            sel.onchange();
        }
        function chgreltime(is_rel) {
            let to_show = this.document.getElementById(is_rel ? 'reltime-col':'abstime-col');
            let to_hide = this.document.getElementById(is_rel ? 'abstime-col':'reltime-col');
            to_hide.classList.add('hidden');
            to_show.classList.remove('hidden');
        }
    </script>
|};
    page_head_close resp ;
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
    let bool_of_var name =
        (Hashtbl.find_option vars name |? "0") = "1" in
    let max_level = int_of_var "max_level" Log.max_level in
    let reltime = bool_of_var "reltime" in
    let vert_distance = int_of_var "vert_distance" 0 in
    let horiz_distance = int_of_var "horiz_distance" 0 in
    let ignored_loggers =
        Hashtbl.find_all vars "ignored" |>
        List.fold_left (fun ignored_loggers name ->
            Set.String.add name ignored_loggers
        ) Set.String.empty in
    let selected_loggers =
        Option.bind logger_name (fun name ->
            Option.bind
                (Hashtbl.find_option Log.loggers name)
                (fun logger ->
                    Some (find_loggers ~vert_distance ~horiz_distance logger))
        ) |? [] in
    Printf.fprintf resp "<div><form>\n" ;
    logs_menu resp logger_name selected_loggers ignored_loggers ;
    Printf.fprintf resp "\
        <select id=\"logger_select\" name=\"logger\" \
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
    Printf.fprintf resp "\
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
    Printf.fprintf resp "\
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
    Printf.fprintf resp "\
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
            let print_peer oc (p : Log.peer) =
                String.print oc (link_to ~full_name:true p.logger) ;
                Option.may (fun via ->
                    Printf.fprintf oc "&nbsp;(via: %s)" (link_to via)
                ) p.via in
            let open_link, close_link =
                match logger.parent with
                | None -> "<s>", "</s>"
                | Some parent -> open_link_to parent, "</a>" in
            Printf.fprintf resp {|
<div>
    %sparent%s
<!-- children: -->
%s%a<br/>
<!-- peers: -->
%s%a
</div>
|}
                (* parent *)
                open_link close_link
                (* children *)
                (if logger.children <> [] then "children: " else "")
                (List.print ~first:"" ~last:"" ~sep:" | " print_child)
                    logger.children
                (* peers *)
                (if logger.peers <> [] then "peers: " else "")
                (List.print ~first:"" ~last:"" ~sep:" | " print_peer)
                    logger.peers ;
            (* And now the log selection: *)
            let logs = get_logs ~max_level selected_loggers in
            let loggers =
                List.fast_sort (fun l1 l2 ->
                    String.compare l1.Log.full_name l2.full_name
                ) selected_loggers in
            if loggers <> [] then (
                let print_ignored_logger oc logger =
                    let v = Html.cdata_encode logger.Log.full_name in
                    Printf.fprintf oc "\
                        <option value=\"%s\"%s>%s</option>\n"
                        v
                        (if Set.String.mem logger.full_name ignored_loggers
                        then selected else "")
                        v in
                Printf.fprintf resp "\
                    <div><label class=\"top-pretty-please\">Hide:&nbsp;\n\
                        <select multiple name=\"ignored\" \
                                onchange=\"this.form.submit()\">\n\
                        %a\
                        </select>\n\
                    </label></div>\n"
                    (List.print ~first:"" ~last:"" ~sep:"" print_ignored_logger)
                        loggers
            ) ;
            let interv_print =
                let prev_t = ref None in
                fun oc t ->
                    (match !prev_t with
                    | None ->
                        Clock.Time.printf oc t
                    | Some pt ->
                        let i = Clock.Time.sub t pt in
                        Clock.Interval.printf oc i) ;
                    prev_t := Some t in
            let print_log =
                let class_of_level =
                    [| "fatal" ; "crit" ; "err" ; "wrn" ; "nfo" ; "dbg" |] in
                let prev_src = ref "" in
                let prev_lvl = ref ~-1 in
                fun oc (logger, lvl, (t, msg)) ->
                    let src = logger.Log.full_name in
                    let with_border =
                        if !prev_src <> src then (
                            prev_src := src ;
                            true
                        ) else false in
                    let lvl_str =
                        if !prev_lvl <> lvl then (
                            prev_lvl := lvl ;
                            Log.string_of_int_level lvl
                        ) else "" in
                    Printf.fprintf oc "\
                        <tr class=\"%s%s\">\
                            <td class=\"tm tm-abs\">%a</td>\
                            <td class=\"tm tm-rel\">%a</td>\
                            <td class=\"src\">%s</td>\
                            <td class=\"lvl%s\">%s</td>\
                            <td class=\"msg\">%s</td>\
                        </tr>\n"
                        class_of_level.(lvl)
                        (if with_border then " separated" else "")
                        Clock.Time.printf t
                        interv_print t
                        (if with_border then src else "")
                        (if lvl_str <> "" then " lvl-set" else "")
                        lvl_str
                        (Lazy.force msg) in
            Printf.fprintf resp {|
<div>
    <table class="logs">
    <colgroup>
        <col id="abstime-col" class="%s"/>
        <col id="reltime-col" class="%s"/>
        <col/>
        <col/>
        <col/>
    </colgroup>
    <thead>
        <tr>
            <th colspan="2">
            Time<br/>
            <label class="compl">
                <input type="checkbox" value="1" name="reltime"%s \
                       onchange="chgreltime(this.checked)"/>relative
            </label>
            </th>
        <th>Source</th><th>Level</th><th>Message</th></tr>
    </thead>
    <tbody>
    %a
    </tbody>
    </table>
</div>
|}
                (if reltime then "hidden" else "")
                (if reltime then "" else "hidden")
                (if reltime then " checked" else "")
                (Enum.print ~first:"" ~last:"" ~sep:"" print_log)
                    (Enum.filter (fun (l, _, _) ->
                        not (Set.String.mem l.Log.full_name ignored_loggers)
                    ) logs)
        ) logger
    ) logger_name ;
    Printf.fprintf resp "</form></div>\n" ;
    [ "Content-Type", "text/html" ]

let make host port =
    let res = [ Str.regexp "/home.html$", home ;
                Str.regexp "/$", home ;
                Str.regexp "/metrics.html$", metrics ;
                Str.regexp "/logs.html$", logs ] in
    Opache.(serve host ~port (multiplexer res))
