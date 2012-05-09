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
   This will open a pcap file and add duplicates (with a given delay)
*)
open Batteries
open Bitstring
open Tools
open Pcap

let handle_file delay ifile ofile =
    let apply_delay a =
        let d = Clock.Interval.usec delay in
        { a with Pdu.ts = Clock.Time.add a.Pdu.ts d } in
    merge [ enum_of_file ifile ;
            enum_of_file ifile /@ apply_delay ] |>
    file_of_enum ofile

let main =
    let delay = ref 0.
    and ifile = ref "/dev/stdin"
    and ofile = ref "/dev/stdout"
    in
    Arg.parse [ "-d", Arg.Set_float delay, "Delay (in microseconds, default: 0)" ;
                "-i", Arg.Set_string ifile, "Input file (default: stdin)" ;
                "-o", Arg.Set_string ofile, "Output file (default: stdout)" ]
              (fun _ -> raise (Arg.Bad "Unknown parameter"))
              "Add echo to a pcap file" ;
    handle_file !delay !ifile !ofile

