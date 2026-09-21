(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(** Run the networks of the documents given on the command line -- the files
 * the administration interface saves -- and, if asked to, the interface
 * itself, and whatever a portal needs of the machine to reach the outside.
 *
 * Everything here a program of ten lines could do with the library; what it
 * adds is that nobody has to write that program, or rebuild anything, in order
 * to run another network.
 *
 * Examples:
 *
 *   % robinet                 # nothing to run, and it says so
 *
 *   % robinet --admin         # the interface alone, on port 8080, to build a
 *                             # network in
 *   % robinet --ui demo.json  # that network, and a browser on the interface
 *
 *   % robinet demo1.json demo2.json --pause demo3.json
 *                             # three networks, the last one stopped: an
 *                             # option applies to the documents that follow it
 *
 *   % sudo robinet --portals=veth demo.json
 *                             # and for every portal of it, a namespace of
 *                             # that name with a veth pair into it, so that
 *                             # what runs in the namespace talks to the
 *                             # simulated network
 *
 * See [Cli.usage] for the whole of the command line.
 *)
open Batteries
open SimTypes

(* A document, as the simulation it describes, running.
 *
 * Nothing is switched on yet, whatever the options say: the interfaces the
 * portals name may not exist until every document has been read and
 * [Netns.setup] has run, and that is the whole reason powering up is a phase
 * of its own. Nor is the speed set here, for a reason of the same shape: a
 * portal switched on ties its simulation to the wall clock, so what was asked
 * for on the command line has to be asked for after that has had its say --
 * and then it is refused out loud rather than quietly lost. *)
let open_document (path, (clock : Cli.clock)) =
    let topology =
        match File.with_file_in path IO.read_all with
        | exception Sys_error m ->
            Printf.eprintf "%s\n%!" m ;
            exit 1
        | s ->
            (match Topology.of_string ~env:true s with
            | exception Widget.Bad_value m ->
                Printf.eprintf "%s: %s\n%!" path m ;
                exit 1
            | t -> t) in
    let name =
        if String.trim topology.Topology.name <> "" then
            String.trim topology.Topology.name
        else Filename.(remove_extension (basename path)) in
    match Topology.new_simulation ~topology ~paused:clock.paused name with
    | exception Widget.Bad_value m ->
        Printf.eprintf "%s: %s\n%!" path m ;
        exit 1
    | sim, refused ->
        (* The network is still the one that was asked for, which is why these
         * are said and passed rather than fatal. *)
        List.iter (Printf.eprintf "%s: %s\n%!" path) refused ;
        sim, clock

(* The interfaces the portals of these simulations name, which is their
 * widgets' names. *)
let portal_ifnames sims =
    List.concat_map (fun (sim, _) ->
        Simulation.borrow sim (fun () ->
            Widget.enum sim.root //@ (fun (w : Widget.t) ->
                Option.map (fun (p : Pcap.portal) -> p.ifname)
                           (Pcap.portal_of_widget w)) |>
            List.of_enum)
    ) sims

(* What the command line has to say about a clock, once the network has had
 * its. [Simulation.set_speed_ratio] refuses a simulation that follows the wall
 * clock, which is what a portal has made of it, and that exception is left to
 * come out: a network that reaches the outside world cannot be run at half
 * speed, the backtrace says which one and where, and the option was a mistake
 * either way. *)
let set_speed (sim, (clock : Cli.clock)) =
    match clock.speed with
    | None -> ()
    | Some Cli.Max -> Simulation.set_speed_ratio sim None
    | Some (Cli.Ratio r) -> Simulation.set_speed_ratio sim (Some r)
    | Some Cli.Real -> Simulation.make_realtime sim

(* Phase two of every load, now that all of it stands and the interfaces are
 * there: what the network is to be asked, which is what switches on every box
 * it is made of.
 *
 * Here rather than left to [Simulation.run], which would do it too, because
 * the interfaces the portals name had to be made first and that is this
 * program's doing. Asked to leave it off, it is had done with rather than left
 * pending, or running the network would switch it on after all. *)
let run_startup (sim, (clock : Cli.clock)) =
    Simulation.borrow sim (fun () ->
        if clock.Cli.power then Simulation.run_startup sim
        else Simulation.forgo_startup sim)

let main =
    Printexc.record_backtrace true ;
    let opts =
        match Cli.parse (List.tl (Array.to_list Sys.argv)) with
        | exception Cli.Error m ->
            Printf.eprintf "%s\nTry --help\n%!" m ;
            exit 1
        | opts -> opts in
    if opts.Cli.help then (
        print_string Cli.usage ;
        exit 0) ;
    if opts.Cli.documents = [] && opts.Cli.admin = None then (
        (* Nothing to run. Not an error -- it is what was asked for -- but
         * saying so beats a program that starts and does nothing. *)
        print_string "Nothing to run: name a document, or ask for --admin.\n" ;
        exit 0) ;
    let sims = List.map open_document opts.Cli.documents in
    let ifnames =
        match opts.Cli.portals with
        | None -> []
        | Some Cli.Veth ->
            let ifnames = portal_ifnames sims in
            List.iter Netns.setup ifnames ;
            ifnames in
    finally (fun () -> List.iter Netns.teardown ifnames) (fun () ->
        List.iter run_startup sims ;
        List.iter set_speed sims ;
        Simulation.with_trapped [ Sys.sigint ; Sys.sigterm ] (fun () ->
            match opts.Cli.admin with
            | None ->
                (* Nothing here but the networks, so this thread has nothing
                 * to do but wait for them. ^C reaches them all the same:
                 * [with_trapped] keeps a thread awake for its handler to run
                 * in, which is what a program parked in [Thread.join] cannot
                 * offer it. *)
                List.iter (fun (sim, _) ->
                    Option.may Thread.join sim.thread) sims
            | Some port ->
                (* In a simulation of its own, following the wall clock, so
                 * that pausing a network leaves the interface answering. *)
                let admin = Simulation.make ~realtime:true "admin" in
                Myadmin.make admin (Localhost.host admin) (Tcp.Port.o port) ;
                let url = Printf.sprintf "http://localhost:%d/" port in
                Printf.printf "Point a browser at %s\n%!" url ;
                if opts.Cli.ui then (
                    (* The interface is listening already -- [Localhost]'s
                     * server binds within [Myadmin.make] -- so there is
                     * nothing to wait for here. *)
                    let cmd = "xdg-open "^ Filename.quote url in
                    match Unix.system cmd with
                    | Unix.WEXITED 0 -> ()
                    | _ ->
                        (* The interface is up either way, and its address has
                         * been printed. *)
                        Printf.eprintf "Cannot open a browser with %S\n%!" cmd) ;
                Simulation.run_here admin)) ()
