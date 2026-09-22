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
  The command line of the robinet program, which is a list of documents to run
  and a few words about how to run them.

  An option that says how a network is to be run has to say which network, and
  naming one is awkward: a simulation is called what its document calls itself,
  disambiguated against the simulations already there, so two files that both
  call themselves "wan" become "wan" and "wan-1", neither of them anything that
  was typed. So these options are positional instead. Each applies to every
  document that follows it, until another says otherwise:

  {[
    robinet --speed=0.5 a.json b.json     # both at half speed
    robinet a.json --pause b.json         # only b.json is stopped
    robinet --pause a.json --resume b.json
  ]}

  Which is also why the parsing is here rather than in cmdliner: what an option
  applies to is where it sits, and a parser that hands back the options on one
  side and the file names on the other has thrown that away.
*)
open Batteries

(** How fast a simulation is to run. Not the same question as whether it is
 * paused, which is [paused] below: a simulation stopped at a ratio of 2 is one
 * that will run at twice the speed of the world when it is let go. *)
type speed =
    (* At [r] times the wall clock: 1. for the speed of the world, .5 for half
     * of it. *)
    | Ratio of float
    (* As fast as the machine will carry it, which is what a simulation is for
     * when the answer matters more than the picture. *)
    | Max
    (* Reading its time off the wall clock rather than pacing itself against
     * it, which is what an interface of the machine needs and what a portal
     * asks for on its own (see [Simulation.make_realtime]). One way: there is
     * no leaving it afterwards. *)
    | Real

(** What the options in force say about a document. *)
type clock =
    { (* [None] where nothing was asked for, which is not the same as asking
       * for the speed a simulation is made at. What is made of a network is
       * allowed to have a view: a portal switched on ties its simulation to
       * the wall clock, and a speed nobody asked for gives way to that,
       * whereas one that was asked for is refused out loud. *)
      speed : speed option ;
      paused : bool ;
      (* How long, in simulated seconds, to let it run before stopping it. *)
      duration : float option ;
      (* Whether to run the network's startup list once it stands, which is
       * what switches on what it is made of: every box registers its power-on
       * there as it is built (see [Simulation.run_startup]). *)
      power : bool }

(** How to make the interfaces the portals of a network name, when they are not
 * there already. One way so far; tuntap and docker are the ones asked for
 * next. *)
type portals = Veth

type t =
    { (* The port the administration interface is to be served on. *)
      admin : int option ;
      (* Whether to open a browser on it. *)
      ui : bool ;
      portals : portals option ;
      (* The documents to run, in the order they were given, each with the
       * options that were in force where it sat. *)
      documents : (string * clock) list ;
      (* Nothing to run: say what there is and stop. *)
      help : bool }

exception Error of string

let () =
    Printexc.register_printer (function
        | Error m -> Some m
        | _ -> None)

let error fmt = Printf.ksprintf (fun m -> raise (Error m)) fmt

let default_port = 8080

(* A network paced against the wall clock, running, and switched on: the
 * answers that surprise nobody. A network's delays and rates are written in
 * seconds and bits per second, and at a ratio of 1 they are the seconds and
 * the bits per second of whoever is watching. *)
let default_clock =
    { speed = None ; paused = false ; duration = None ; power = true }

let usage =
    "robinet [option|document]...\n\
     \n\
     Runs the networks of the documents named, which are the files the\n\
     administration interface saves.\n\
     \n\
     Options, wherever they appear:\n\
     \  --admin[=PORT]  serve the administration interface (default port:\n\
     \                  8080)\n\
     \  --ui            open a browser on it; implies --admin\n\
     \  --portals=veth  for every portal of every network, make a network\n\
     \                  namespace of that name and a veth pair into it\n\
     \                  (wants root: run under sudo)\n\
     \  --help          this\n\
     \n\
     Options applying to every document that follows them:\n\
     \  --speed=R       run it at R times the speed of the wall clock, 1 by\n\
     \                  default; also \"max\", as fast as it will go, and\n\
     \                  \"real\", reading the time off the wall clock\n\
     \  --duration=S    stop it after S simulated seconds, and quit once\n\
     \                  every network has stopped; by default it runs until\n\
     \                  it is interrupted\n\
     \  --pause         load it stopped, which --speed=0 also says; --resume,\n\
     \                  the default, does not\n\
     \  --off           leave what it is made of switched off; --on, the\n\
     \                  default, switches it on once the whole network\n\
     \                  stands\n\
     \n\
     With no document and no --admin there is nothing to run.\n"

(* The number an option was given, or what it was given instead. *)
let float_of what s =
    match float_of_string s with
    | exception _ -> error "%s: %S is not a number" what s
    | f when Float.is_finite f && f >= 0. -> f
    | _ -> error "%s: %S is not a positive number" what s

let int_of what s =
    match int_of_string s with
    | exception _ -> error "%s: %S is not a number" what s
    | i -> i

(** Read a command line, which is [Sys.argv] without the program's own name. *)
let parse args =
    let admin = ref None
    and ui = ref false
    and portals = ref None
    and help = ref false
    and clock = ref default_clock
    and documents = ref [] in
    let value ~flag = function
        | Some v -> v
        | None -> error "%s wants a value: %s=..." flag flag in
    let no_value ~flag = function
        | None -> ()
        | Some _ -> error "%s takes no value" flag in
    List.iter (fun arg ->
        if String.length arg = 0 || arg.[0] <> '-' then
            (* Anything that is not an option is a document, and it is opened
             * where it stands, with the options in force at that point. *)
            documents := (arg, !clock) :: !documents
        else
            let flag, v =
                match String.index arg '=' with
                | exception Not_found -> arg, None
                | i ->
                    String.sub arg 0 i,
                    Some (String.sub arg (i + 1) (String.length arg - i - 1)) in
            match flag with
            | "--admin" ->
                admin :=
                    Some (match v with
                          | None -> default_port
                          | Some v -> int_of flag v)
            | "--ui" -> no_value ~flag v ; ui := true
            | "--portals" ->
                portals :=
                    Some (match value ~flag v with
                          | "veth" -> Veth
                          | m -> error "%s: there is no way to make a portal's \
                                        interface called %S (there is: veth)"
                                     flag m)
            | "--help" | "-h" -> no_value ~flag v ; help := true
            | "--speed" ->
                (match value ~flag v with
                | "max" -> clock := { !clock with speed = Some Max }
                | "real" -> clock := { !clock with speed = Some Real }
                | s ->
                    (match float_of flag s with
                    (* Standing still is not a speed, and asking for it is the
                     * one thing a ratio of zero can mean. *)
                    | 0. -> clock := { !clock with paused = true }
                    | r -> clock := { !clock with speed = Some (Ratio r) }))
            | "--duration" ->
                let d = float_of flag (value ~flag v) in
                clock := { !clock with duration = Some d }
            | "--pause" -> no_value ~flag v ; clock := { !clock with paused = true }
            | "--resume" -> no_value ~flag v ; clock := { !clock with paused = false }
            | "--on" -> no_value ~flag v ; clock := { !clock with power = true }
            | "--off" -> no_value ~flag v ; clock := { !clock with power = false }
            | _ ->
                error "There is no %s option" flag
    ) args ;
    { admin =
        (* There is nothing else for a browser to be opened on. *)
        (if !ui && !admin = None then Some default_port else !admin) ;
      ui = !ui ;
      portals = !portals ;
      documents = List.rev !documents ;
      help = !help }

(*$inject
  let clocks args =
      List.map snd (parse args).documents
  let speeds args =
      List.map (fun c -> c.speed) (clocks args)
 *)

(* An option applies to what follows it, and to nothing before it. *)
(*$= clocks & ~printer:dump
  [ { default_clock with paused = true } ; \
    { default_clock with paused = true } ] \
    (clocks [ "--pause" ; "a" ; "b" ])
  [ default_clock ; { default_clock with paused = true } ] \
    (clocks [ "a" ; "--pause" ; "b" ])
  [ { default_clock with paused = true } ; default_clock ] \
    (clocks [ "--pause" ; "a" ; "--resume" ; "b" ])
 *)

(* The three ways of saying how fast, and the one that means stopped. *)
(*$= speeds & ~printer:dump
  [ None ] (speeds [ "a" ])
  [ Some (Ratio 0.5) ] (speeds [ "--speed=0.5" ; "a" ])
  [ Some Max ] (speeds [ "--speed=max" ; "a" ])
  [ Some Real ] (speeds [ "--speed=real" ; "a" ])
 *)

(* Which leaves the pace alone, pausing and pacing being two questions: a
 * network stopped at twice the speed of the world is one that will run at
 * twice the speed of the world. *)
(*$= clocks & ~printer:dump
  [ { default_clock with speed = Some (Ratio 2.) ; paused = true } ] \
    (clocks [ "--pause" ; "--speed=2" ; "a" ])
  [ { default_clock with speed = Some (Ratio 2.) ; paused = true } ] \
    (clocks [ "--speed=2" ; "--speed=0" ; "a" ])
 *)

(* How long to run is a number of seconds, and only a document that follows
 * it is given it. *)
(*$= clocks & ~printer:dump
  [ default_clock ; { default_clock with duration = Some 1.5 } ] \
    (clocks [ "a" ; "--duration=1.5" ; "b" ])
 *)

(*$T parse
  (try ignore (parse [ "--duration" ]) ; false with Error _ -> true)
  (try ignore (parse [ "--duration=soon" ]) ; false with Error _ -> true)
  (try ignore (parse [ "--duration=-1" ]) ; false with Error _ -> true)
 *)

(* A browser has nothing but the interface to open on. *)
(*$T parse
  (parse [ "--ui" ]).admin = Some default_port
  (parse [ "--ui" ; "--admin=9090" ]).admin = Some 9090
  (parse [ "--admin=9090" ; "--ui" ]).admin = Some 9090
  (parse []).admin = None
 *)

(* What is not an option is a document, and what looks like one and is not is
 * a mistake rather than a file of that name. *)
(*$T parse
  (parse [ "a.json" ; "b.json" ]).documents |> List.map fst = \
      [ "a.json" ; "b.json" ]
  (try ignore (parse [ "--nope" ]) ; false with Error _ -> true)
  (try ignore (parse [ "--pause=yes" ]) ; false with Error _ -> true)
  (try ignore (parse [ "--speed" ]) ; false with Error _ -> true)
  (try ignore (parse [ "--speed=fast" ]) ; false with Error _ -> true)
  (try ignore (parse [ "--portals" ]) ; false with Error _ -> true)
  (try ignore (parse [ "--portals=magic" ]) ; false with Error _ -> true)
 *)
