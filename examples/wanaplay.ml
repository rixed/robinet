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
 'malicious' program that takes sport reservation automatically on some website
 (or one have to go online in the middle of the night to have a chance to get
 a reservation at a decent time. Many hours of sleep saved thanks to RobiNet! ;->)
*)
open Batteries
open Tools

(* At each step, we:
   - draw a title
   - pause
   - perform some action of type continuation -> 'a option
   - if we got None, display an error and stop
   - if ok, return the result of the action so we can use it for next one *)
let step title action cont =
    Printf.printf "%s: %!" title ;
    Clock.delay (Clock.Interval.sec 1.) (fun () ->
        action (function
        | None   -> error "Fail!"
        | Some x -> Printf.printf "Ok!\n%!" ;
                    cont x)) ()

let reserve date time login pwd =
    let sha1 =
        let cmd = "echo -n "^(Filename.quote pwd)^" | sha1sum | cut -d' ' -f 1" in
        IO.read_line (Unix.open_process_in cmd) in
    let host = Localhost.make ()
    and mozilla_user_agent = "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.16) Gecko/20110929 Iceweasel/3.5.16 (like Firefox/3.5.16)" in
    let browser = Browser.make ~user_agent:mozilla_user_agent host in
    step "Get homepage for the fun of it (and collect some cookies)"
         (Browser.get browser (Url.of_string "http://www.wanaplay.com/"))
         (function _ ->
    step "Post the login form with hardcoded username and password"
         (Browser.post browser (Url.of_string "http://fr.wanaplay.com/auth/doLogin")    (* here we know it's fr.wanaplay.com. Better get this from the previous base. ie. browser should save the last base so that we can provide relative URLs. *)
                [ "sha1mdp", sha1 ;
                  "login", login ;
                  "passwd", pwd ;
                  "rememberMe", "on" ;
                  "commit", "S" ])
         (function _ ->
    step "Go to EspacePontoise Planning"
         (Browser.get browser (Url.of_string "http://fr.wanaplay.com/plannings/espacesportifpontoise"))
         (function _ ->
    step (Printf.sprintf "Ask for the planning for this date (%s)" date)
         (Browser.post browser
                       ~headers: [ "X-Requested-With", "XMLHttpRequest" ;
                                   "X-Prototype-Version", "1.5.0" ]
                       (Url.of_string "http://fr.wanaplay.com/reservation/planning2")
                       [ "date", date ;
                         "type", "picto" ;
                         "_", "" ])
         (function (_h, body) ->
(* we got many cells of the form (when time is still open for reservation):
<tr>
    <td width='90px' height='35px' class='...' onmouseover="..." onmouseout="..." style='...'
        onClick='window.location.href="/reservation/takeReservationShow?idTspl=44371592"'>
        <p class='timeSlotTime'>15:00</p>
    </td>
</tr> *)
    let freeslots_re = Str.regexp ("window.location.href=\"/reservation/takeReservationShow\\?idTspl=\\([0-9]+\\)\"'><p class='timeSlotTime'>\\("^time^"\\)</p>") in
    if (try ignore (Str.search_forward freeslots_re body 0) ; true with Not_found -> false) then (
        let idTspl = Str.matched_group 1 body
        and time = Str.matched_group 2 body in
        step (Printf.sprintf "Reserving for %s" time)
             (Browser.post browser (Url.of_string "http://fr.wanaplay.com/reservation/takeReservationBase")
                [ "idTspl", idTspl ;
                  "date", date ;
                  "time", time^":00" ;
                  "resource_name", "Court 1" (* huhu, is that useful? *) ;
                  "duration", "40" ;
                  "nb_consecutive_reservations", "1" ;
                  "tab_users_id_0", "8d123ae11f94d8b3c1d566cbf32ec70d" ;
                  "tab_users_name_0", "Cellier Cedric" ;
                  "tab_users_comments_0", "" ;
                  "nb_participants", "1" ;
                  "nb_participants", "1" (* not a typo, at least not in _this_ program *) ;
                  "commit", "Confirmer" ])
             (function _ ->
                Printf.printf "Do not forget your reservation, %s at %s\n%!" date time ;
                exit 0)
    ) else (
        error "No match for this time :-(\n";
    )))))

let main =
    if Array.length Sys.argv <> 5 then (
        Printf.printf "wanaplay YYYY-MM-DD HH:MM login passwd\n(note: time is actually used in a regexp)\n" ;
    ) else (
        reserve Sys.argv.(1)    (* date *)
                Sys.argv.(2)    (* time *)
                Sys.argv.(3)    (* login *)
                Sys.argv.(4)    (* passwd *)
    ) ;
    Clock.run true
