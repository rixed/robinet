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
  MyAdmin logs page, with its table of widgets.

  Kept as a reference while the new UI is designed; meant to disappear.
*)
open Batteries
open Tools
open Myadmin_common

(*
 * Logs (from widgets)
 *)

(* These pages predate simulations and just look everywhere. *)
let find_widget id =
    (* Batteries' find_map raises rather than returning an option: *)
    try
        Simulation.all () |>
        List.find_map (fun s -> Widget.find s.Simulation.root id) |>
        Option.some
    with Not_found -> None

let find_widgets ?(vert_distance=0) ?(horiz_distance=0) widget =
    (* Collect all widgets within those distances: *)
    let widgets =
        let visited = ref Set.Int.empty in
        let is_close max_dist (widget : Widget.t) =
            if max_dist < 0 then (
                if debug then Printf.printf "max dist %d < 0\n%!" max_dist ;
                false
            ) else if Set.Int.mem widget.id !visited then (
                if debug then Printf.printf "already visited %s\n%!" (Widget.full_name widget) ;
                false
            ) else (
                if debug then Printf.printf "Visiting widget %s\n%!" (Widget.full_name widget) ;
                visited := Set.Int.add widget.id !visited ;
                true
            ) in
        let rec loop_up widgets max_horiz max_up max_down widget =
            if max_up >= 0 then (
                loop_horiz widgets max_horiz max_up max_down widget
            ) else widgets
        and loop_down widgets max_horiz max_up max_down widget =
            if max_down >= 0 then (
                loop_horiz widgets max_horiz max_up max_down widget
            ) else widgets
        and loop_horiz widgets max_horiz max_up max_down widget =
            if debug then Printf.printf "loop_horiz %d %d %d %S\n%!" max_horiz max_up max_down (Widget.full_name widget) ;
            if is_close max_horiz widget then (
                if debug then Printf.printf "Adding widget %s\n%!" (Widget.full_name widget) ;
                let widgets = widget :: widgets in
                let widgets =
                    match widget.parent with
                    | Some p ->
                        (* Don't come back down to not end up in other branches *)
                        loop_up widgets max_horiz (max_up - 1) 0 p
                    | None -> widgets in
                let widgets =
                    List.fold_left (fun widgets child ->
                        (* There is no point coming back up: *)
                        loop_down widgets max_horiz 0 (max_down - 1) child
                    ) widgets widget.children in
                List.fold_left (fun widgets (peer : Widget.peer) ->
                    match peer.via with
                    | None ->
                        loop_horiz widgets (max_horiz - 1) max_up max_down
                                   peer.widget
                    | Some via ->
                        let widgets =
                            loop_horiz widgets (max_horiz - 1) max_up max_down
                                       via in
                        loop_horiz widgets (max_horiz - 2) max_up max_down
                                   peer.widget
                ) widgets widget.peers
            ) else widgets in
        loop_horiz [] horiz_distance vert_distance vert_distance widget in
    if debug then Printf.printf "Got these widgets: %a\n%!" (List.print (fun oc w -> String.print oc (Widget.full_name w))) widgets ;
    widgets

let get_logs ?(max_level=Log.max_level) widgets =
    (* TODO: options to include N parents/children, M peers... Aka vertical
     * and horizontal distance *)
    let collect_logger e (widget : Widget.t) =
        let rec loop lvl e =
            if lvl > max_level then e else
            let e' = Log.queue_enum widget.logger.queues.(lvl) in
            let e' = Enum.map (fun l -> widget, lvl, l) e' in
            loop (lvl + 1) (Enum.append e e') in
        loop 0 e in
    let e = List.fold_left collect_logger (Enum.empty ()) widgets in
    let a = Array.of_enum e in
    Array.fast_sort
        (fun (_, _, (t1, _)) (_, _, (t2, _)) -> Clock.Time.compare t1 t2) a ;
    Array.enum a

let logs_menu resp selected_id also_selected ignored_widgets =
    (* The root layer is composed of all widgets without parents: *)
    let roots =
        Simulation.all () |> List.map (fun s -> s.Simulation.root) in
    let rec num_descendants widget =
        List.fold_left (fun num child ->
            num + num_descendants child
        ) 0 widget.Widget.children |> max 1 in
    (* Memoize those for the duration of this function call: *)
    let num_descendants = memoize num_descendants in
    let rec max_depth widget =
        List.fold_left (fun depth child ->
            max depth (1 + max_depth child)
        ) 1 widget.Widget.children in
    let onmouseover (w : Widget.t) =
        let peers =
            List.fold_left (fun peers (peer : Widget.peer) ->
                let peers = peer.widget :: peers in
                match peer.via with
                | None -> peers
                | Some via -> via :: peers
            ) [] w.peers in
        let ids =
            IO.to_string (List.print ~sep:"," (fun oc (w : Widget.t) ->
                String.print oc (to_js_string ("td_"^ string_of_int w.id)))
            ) peers in
        Printf.sprintf " onmouseover=\"highlight(%s)\" \
                         onmouseout=\"unhighlight(%s)\"" ids ids in
    let onclick (w : Widget.t) =
        " onclick=\"setLogger("^ to_js_string (string_of_int w.id) ^")\"" in
    let rec loop_row bw (groups : (int * Widget.t list * int) list) =
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
                    | (w : Widget.t) :: widgets ->
                        let is_last = widgets = [] in
                        let prev_full, prev_clen, disp_name =
                            let clen = common_pref_length prev_full w.name in
                            if clen > 5 && clen >= prev_clen then
                                let eff_clen =
                                    if prev_clen > 0 then
                                        prev_clen
                                    else
                                        let clen = clen - 2 in (* keep an "anchor" *)
                                        let len = String.length w.name in
                                        let rem_len = max 3 (len - clen) in
                                        len - rem_len in
                                prev_full,
                                eff_clen,
                                "…"^ String.lchop ~n:eff_clen w.name
                            else
                                w.name,
                                0,
                                w.name in
                        let sel_class =
                            if selected_id = Some w.id then
                                " selected" else
                            if List.exists ((==) w) also_selected then
                                " also-selected" else "" in
                        Printf.fprintf resp
                            "<td id=\"td_%s\" \
                                colspan=\"%d\" class=\"pointy%s%s\" \
                                style=\"%s\"%s%s>%s</td>"
                            (string_of_int w.id)
                            (num_descendants w)
                            sel_class
                            (if Set.Int.mem w.id ignored_widgets then
                                " ignored" else "")
                            (style is_first bwl is_last bwr (w.children = []))
                            (if w.peers = [] then "" else onmouseover w)
                            (onclick w)
                            (if disp_name <> "" then disp_name
                             else "<i>unnamed</i>") ;
                        let next_row =
                            ((if is_first then bwl else bw), w.children,
                             (if is_last then bwr else bw)) :: next_row in
                        let next_is_empty =
                            if w.children = [] then next_is_empty else false in
                        loop_children false next_row next_is_empty prev_full prev_clen widgets in
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
            "<table class=\"widgets\" \
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
        table.widgets {
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
            let sel = this.document.getElementById('widget_select');
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
    let all_widgets =
        Simulation.all () |>
        List.map (fun s -> Widget.descendants s.Simulation.root) |>
        List.concat |> Array.of_list in
    Array.fast_sort (fun (a : Widget.t) b ->
        String.compare (Widget.full_name a) (Widget.full_name b)) all_widgets ;
    let widget_id =
        match Hashtbl.find_option vars "widget" with
        | Some id -> Some (int_of_string id)
        | None ->
            if Array.length all_widgets > 0 then Some all_widgets.(0).id
            else None in
    let int_of_var name def =
        Hashtbl.find_option vars name |>
        Option.map int_of_string |? def in
    let bool_of_var name =
        (Hashtbl.find_option vars name |? "0") = "1" in
    let max_level = int_of_var "max_level" Log.max_level in
    let reltime = bool_of_var "reltime" in
    let vert_distance = int_of_var "vert_distance" 0 in
    let horiz_distance = int_of_var "horiz_distance" 0 in
    let ignored_widgets =
        Hashtbl.find_all vars "ignored" |>
        List.fold_left (fun ignored_widgets id ->
            Set.Int.add (int_of_string id) ignored_widgets
        ) Set.Int.empty in
    let selected_widgets =
        Option.bind widget_id (fun id ->
            Option.bind
                (find_widget id)
                (fun widget ->
                    Some (find_widgets ~vert_distance ~horiz_distance widget))
        ) |? [] in
    Printf.fprintf resp "<div><form>\n" ;
    logs_menu resp widget_id selected_widgets ignored_widgets ;
    Printf.fprintf resp "\
        <select id=\"widget_select\" name=\"widget\" \
                onchange=\"this.form.submit()\">\n\
            %a\
        </select>\n"
        (Array.print ~first:"" ~last:"" ~sep:""
            (fun oc (w : Widget.t) ->
                Printf.fprintf oc "<option value=\"%d\"%s>%s</option>\n"
                    w.id
                    (if widget_id = Some w.id then selected else "")
                    (Html.cdata_encode (Widget.full_name w)))
        ) all_widgets ;
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
            (fun oc (v, w) ->
                Printf.fprintf oc "<option value=\"%d\"%s>%s</option>\n"
                    v
                    (if vert_distance = v then selected else "")
                    w)
        ) [ 0, "none" ; 1, "direct" ; 2, "two levels" ; max_int, "all" ] ;
    Printf.fprintf resp "\
        <label>Siblings:\n\
          <select name=\"horiz_distance\" \
                  onchange=\"this.form.submit()\">%a\
          </select>\n\
        </label>\n"
        (List.print ~first:"" ~last:"" ~sep:""
            (fun oc (v, w) ->
                Printf.fprintf oc "<option value=\"%d\"%s/>%s</option>\n"
                    v
                    (if horiz_distance = v then selected else "")
                    w)
        ) [ 0, "none" ; 1, "direct" ; 2, "two levels" ; max_int, "all" ] ;
    Option.may (fun widget_id ->
        let widget = find_widget widget_id in
        Option.may (fun (widget : Widget.t) ->
            let open_link_to (w : Widget.t) =
                Printf.sprintf "<a href=\"?widget=%d&max_level=%d&vert_distance=%d&horiz_distance=%d\">"
                    w.id
                    max_level vert_distance horiz_distance in
            let link_to ?(full_name=false) (w : Widget.t) =
                Printf.sprintf "%s%s</a>"
                    (open_link_to w)
                    (if full_name then Widget.full_name w else w.name) in
            let print_child oc (w : Widget.t) =
                String.print oc (link_to w) in
            let print_peer oc (p : Widget.peer) =
                String.print oc (link_to ~full_name:true p.widget) ;
                Option.may (fun via ->
                    Printf.fprintf oc "&nbsp;(via: %s)" (link_to via)
                ) p.via in
            let open_link, close_link =
                match widget.parent with
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
                (if widget.children <> [] then "children: " else "")
                (List.print ~first:"" ~last:"" ~sep:" | " print_child)
                    widget.children
                (* peers *)
                (if widget.peers <> [] then "peers: " else "")
                (List.print ~first:"" ~last:"" ~sep:" | " print_peer)
                    widget.peers ;
            (* And now the log selection: *)
            let logs = get_logs ~max_level selected_widgets in
            let widgets =
                List.fast_sort (fun l1 l2 ->
                    String.compare (Widget.full_name l1) (Widget.full_name l2)
                ) selected_widgets in
            if widgets <> [] then (
                let print_ignored_widget oc (widget : Widget.t) =
                    Printf.fprintf oc "\
                        <option value=\"%d\"%s>%s</option>\n"
                        widget.id
                        (if Set.Int.mem widget.id ignored_widgets
                        then selected else "")
                        (Html.cdata_encode (Widget.full_name widget)) in
                Printf.fprintf resp "\
                    <div><label class=\"top-pretty-please\">Hide:&nbsp;\n\
                        <select multiple name=\"ignored\" \
                                onchange=\"this.form.submit()\">\n\
                        %a\
                        </select>\n\
                    </label></div>\n"
                    (List.print ~first:"" ~last:"" ~sep:"" print_ignored_widget)
                        widgets
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
                fun oc (widget, lvl, (t, msg)) ->
                    let src = Widget.full_name widget in
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
                    (Enum.filter (fun ((w : Widget.t), _, _) ->
                        not (Set.Int.mem w.id ignored_widgets)
                    ) logs)
        ) widget
    ) widget_id ;
    Printf.fprintf resp "</form></div>\n" ;
    200, [ "Content-Type", "text/html" ]
