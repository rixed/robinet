(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(* Copyright 2026, Cedric Cellier
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
(* What qtest puts before the tests it extracts (all_tests.ml). *)
open Batteries;; open Bitstring;; open Tools;; open SimTypes;;

(* Every test deletes the simulations it made: registered, they would stay
 * alive, for the full collection that OUnit runs after each test to walk
 * through again. *)
let (>::) name f =
    OUnit.(name >:: fun () ->
        let before = List.map Simulation.id (Simulation.all ()) in
        let cleanup () =
            List.iter (fun s ->
                if not (List.mem (Simulation.id s) before) then Simulation.delete s
            ) (Simulation.all ()) in
        match f () with
        | () -> cleanup ()
        | exception e -> cleanup () ; raise e)
