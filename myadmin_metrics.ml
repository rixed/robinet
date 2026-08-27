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
  MyAdmin metrics page, along with the thread archiving metric values.

  Metrics are about to be reworked to hang off widgets, the same way logs
  already do, at which point this whole page goes away.
*)
open Batteries
open Tools
open Myadmin_common

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

type param_filter =
    | Expr of Search.Expr.t
    | Error of string

let metrics _mth _matches vars _qry_body resp = if debug then Printf.printf "MyAdmin: metric: vars = %a\n" Opache.print_vars vars ;
    page_head_open resp ;
    (*let chartjs_url = "http://happyleptic.org:8080/chart.js" in (* cached locally *)*)
    let chartjs_url = "https://cdn.jsdelivr.net/npm/chart.js" in
    String.print resp ("<script src=\""^ chartjs_url ^"\"></script>\n") ;
    Printf.fprintf resp {|
        <style type="text/css">
            select.metrics {
                float: left;
                margin-right: 1em;
                margin-bottom: 1em;
                font-family: monospace;
                font-size: 0.7rem;
            }
            div.filter {
                clear: left;
            }
            p.params {
                font-weight: bold;
                text-decoration: underline 1px solid #555;
            }
            ul.params {
                padding-left: 1em;
            }
            ul.params li {
                font-family: monospace;
                font-size: 0.8rem;
                list-style-position: inside;
                list-style-type: "-";
            }
            span.pvalues {
                font-size: 0.7rem;
            }
        </style>
|};
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
        <select class="metrics" multiple size="%d" name="metric">
%a
        </select>
|}
        (min 15 (Array.length all_metrics))
        (Array.print ~first:"" ~last:"" ~sep:"\n" print_option) all_metrics ;
    if not (Hashtbl.is_empty parameters) then (
        Printf.fprintf resp
            "<p class=\"params\">Parameters:</p>\n\
            <ul class=\"params\">%a</ul>\n"
            (Enum.print (fun oc pnam ->
                Printf.fprintf oc "\
                    <li>%s <span class=\"pvalues\">(%a)</span></li>"
                    (Html.cdata_encode pnam)
                    (Set.print ~first:"" ~last:"" ~sep:", " (fun oc v ->
                        Metric.Param.to_string v |>
                        Html.cdata_encode |>
                        String.print oc)
                    ) (Hashtbl.find_default parameters pnam Set.empty)
            )) (Hashtbl.keys parameters |> Enum.uniqq) ;
        Printf.fprintf resp "\
            <div class=\"filter\">\n\
            <label>Filter:&nbsp;\n\
            <input size=\"80\" name=\"filter\" value=\"%s\"/>\n\
            </label>\n\
            <input type=\"submit\" name=\"redraw\"/>\n\
            </div>\n"
            (Html.cdata_encode filter_str) ;
        (match filter with
        | Error str ->
            Printf.fprintf resp "<p class=\"error\">%s</p>" str
        | _ -> ())
    ) else (
        Printf.fprintf resp "\
            <div class=\"filter\">\n\
            <input type=\"submit\" name=\"select\"/>\n\
            </div>\n"
    ) ;
    Printf.fprintf resp {|
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
    200, [ "Content-Type", "text/html" ]
