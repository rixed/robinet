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

let debug = false

let rootdir = "persist"

let mkdir_all ?(is_file=false) dir =
    let dir_exist d =
        try Unix.is_directory d
        with Unix.Unix_error _ -> false in
    let dir = if is_file then Filename.dirname dir else dir in
    let rec ensure_exist d =
        if debug then Printf.printf "Persist: Ensure dir '%s' exists\n%!" d ;
        if String.length d > 0 && not (dir_exist d) then (
            ensure_exist (Filename.dirname d) ;
            if debug then Printf.printf "Persist: Creating directory '%s'\n%!" d ;
            try Unix.mkdir d 0o755
            with Unix.Unix_error (Unix.EEXIST, "mkdir", _) ->
                (* Happen when we have "somepath//someother" (dirname should handle this IMHO *)
                ()
        ) in
    ensure_exist dir

let make_abs family fname =
    let fname = Filename.(concat (concat rootdir family) fname) in
    mkdir_all ~is_file:true fname ;
    fname

let with_input_file family fname default func =
    try File.with_file_in (make_abs family fname) func
    with Sys_error _ -> (* we suppose all sys_errors are no_such_file :-/ *)
        func (BatIO.input_string default)

let with_output_file family fname func = File.with_file_out (make_abs family fname) func

(* All names of a category must be unique *)

let genname =
    let seqfile = ".genname" in
    let seq = ref (with_input_file "system" seqfile "0\n" (fun ic ->
        Scanf.bscanf (Scanf.Scanning.from_input ic) "%d" identity)) in
    let save_seq () = with_output_file "system" seqfile (fun oc ->
        Print.fprintf oc p"%d\n" !seq) in
    at_exit save_seq ;
    fun pref ->
        incr seq ;
        pref ^ (string_of_int !seq)

