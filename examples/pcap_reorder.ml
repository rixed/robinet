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
(*
   I often end up with pcap which packets are not stricly in chronological
   order. This small tool reorder packets within some given bounds.
*)
   
open Batteries

let input_of name =
    Pcap.enum_of_file name

let sink_to name =
    let f = Pcap.Pdu.save name in
    Enum.iter f

(* TODO: a dequeue would be faster here *)
let reorder limit inp out =
    let num_reorders = ref 0 and num_tot = ref 0 and need_more_pass = ref false in
    let insert p lst =
        let rec aux prevs = function
            | [] -> List.rev (p::prevs)
            | p1::rest as lst ->
                if p.Pcap.Pdu.ts < p1.Pcap.Pdu.ts then (
                    incr num_reorders ;
                    if prevs = [] && !num_tot > 0 then need_more_pass := true ;
                    List.rev_append prevs (p::lst)
                ) else (
                    aux (p1::prevs) rest
                ) in
        aux [] lst in
    let e = input_of inp in
    (* consume e, generating another enum sorted *)
    let loop (len, prevs) =
        (* fill prevs with next packets *)
        let len, prevs =
            if len < limit then (
                Enum.take (limit-len) e |>
                Enum.fold (fun (len,prevs) p -> succ len, insert p prevs)
                          (len, prevs)
            ) else (len, prevs) in
        (* are we done yet? *)
        if len = 0 then None else
        (* output the oldest packet *)
        let oldest = List.hd prevs in
        incr num_tot ;
        Some (oldest, (pred len, List.tl prevs))
    in
    Enum.unfold (0, []) loop |>
    sink_to out ;
    !num_tot, !num_reorders, !need_more_pass

let main =
    let limit        = ref 20
    and input        = ref ""
    and output       = ref ""
    in
    Random.self_init () ;
    Arg.parse [ "-w", Arg.Set_int limit,     "How many packets to remember before outputing one (default: 20)" ;
                "-i", Arg.Set_string input,  "Where to read packets from" ;
                "-o", Arg.Set_string output, "Where to write packets" ]
              (fun _ -> raise (Arg.Bad "unknown parameter"))
              "Reorder packets within a pcap file" ;
    if !input = "" then (
        Printf.printf "No input?\n"
    ) else if !output = "" then (
        Printf.printf "No output?\n"
    ) else (
        let num_tot, num_reorders, need_more_pass = reorder !limit !input !output in
        Printf.printf "%d/%d packets reordered%s\n" num_reorders num_tot (if need_more_pass then " (not done)" else "")
    )

