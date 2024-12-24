(* vim:sw=4 ts=4 sts=4 expandtab
*)
(** This test simulates a network of clients (from various distance)
 * navigating a website at random, looking for some pattern and
 * tracking some performance counters. *)
open Batteries
open Tools

(*
 * Configuration for a test plan
 *
 * The configuration contains several things:
 *
 * - a description of the network;
 * - a description of the behavior of the things, à la expect: what to do
 *   and how to react.
 * - a description of when the things are doing what (ie when to start new
 *   activities in a way that allows us to start the simulation at any time
 *   (but we could also start earlier with clocks at full speed before
 *   syncing the clock with wall clock and opening the sink)
 * - we want this to be configurable with simple config file or actual
 *   dynloaded ocaml files, so actions should be functions.
 * - we then want to be able to send triggers manually as the simulation
 *   unfold, and those can have several parameters.
 * - alternatively, or in addition, if we manage to make it a lib that's
 *   very easy to configure then that would be a valid way to use the
 *   simulator while keeping it as simple as required. Which is what the
 *   sim module was all about. So, a program could just be a function
 *   taking the equipment, a state 'a, and a polymorphic variant (the event)
 *   and returning a state 'a. Aside from calling any function to make
 *   the equipment perform this or that, one could also signal other programs
 *   (p2p or broadcast) with an event.
 *   The simulator therefore need to take a program with every created
 *   equipment, and then run it.
 *   Or we could have a _single_ function dispatching on a polymorphic variant
 *   that takes whatever equipment is required. But it would improve
 *   reusability/composability to be able to split this huge event handler
 *   into pieces. We could then just submit each event into a list of
 *   registered event handlers, so we could glue together different small
 *   ones. Also, one can defer unknown events to subfunctions.
 *
 *   Examples of such programs:
 *)

(* Given we want behavior to inherit from each others we also want
 * equipment state to inherit ; the simpler is to use OCaml object
 * system for this. So here, if normal hosts had a state then
 * this one would inherit from it. *)
(* Actually, we could use the object system for everything, having
 * the event handlers implemented as methods. Would that be simpler? *)

(* OO coating for Sim equipments with methods for implementing specific
 * behavior so that it's easier to write succinct scenarii. *)

class equipment = object
    method around_time (_ : Sim.Time.t) = ()
    method at_time (_ : Sim.Time.t) = ()
end

(* Should belong to some Generators.Tcp module: *)
let tcp_write_continuously ~throughput tcp_trx =
    (* We write chunks of throughput bytes every seconds: *)
    let chunk = Bitstring.make_bitstring (int_of_float throughput) 'z' in
    let rec send_next () =
        Clock.(delay (Interval.sec 1.) (fun () ->
            tx tcp_trx.Tcp.TRX.trx chunk ;
            send_next ()) ())
    in
    send_next ()

(* This one is supposedly provided in Sim *)
class host h = object (self)
    inherit equipment

    method power_on =
        h.Host.power_on ~on_ip:(fun _ -> self#powered_on) ()
    method power_off ~timeout =
        h.Host.power_off ~timeout ()
    method powered_on = ()

    method tcp_serve ~port ~throughput () =
        h.Host.tcp_server port (fun tcp_trx ->
            (* TODO: Host should automatically close all established connections
             * at power-off. *)
            tcp_write_continuously ~throughput tcp_trx)

    method tcp_traffic ?src_port ?port ?(num_connections=1) ~throughput to_ =
        let random_traffic throughput = function
            | Some tcp_trx ->
                h.Host.add_killer (fun k ->
                    tcp_trx.Tcp.TRX.close () ; k ()) ;
                tcp_write_continuously ~throughput tcp_trx
            | None ->
                Log.(log h.Host.logger Error (lazy "Cannot traffic"))
        in
        if num_connections > 1 then
            let throughput = throughput /. (float_of_int num_connections) in
            for _ = 1 to num_connections do
                self#tcp_traffic ?src_port ?port ~num_connections:1 ~throughput to_
            done
        else
            let port = Option.default_delayed Tcp.Port.random port in
            h.Host.tcp_connect to_ ?src_port port (random_traffic throughput)

    method browse ~from ~(read_time : Distribution.t) =
        (* In order to have an implicit host [h] we could either define this
         * browse function in the host closure out of the object, where it
         * would be accessible by a mere function call, or make it a method,
         * where access require a dispatch but allows for customization from
         * child classes, which users might find useful. *)
        ignore (read_time ()) ; (* TODO *)
        Log.(log h.Host.logger Info (lazy "Starting a web browser")) ;
        let browser = Browser.make h in
        h.Host.add_killer (Browser.kill browser) ;
        Browser.user browser ~pause:5. 1000 from

    method http_serve ?port () =
        (* TODO All default parameters: any hostname, random catalog of resources
         * with some text/html with random content and mostly valid links.
         * We have to have a non optional argument though. *)
        (* TODO Uses [sql_backend] default throughput and relative qps (aka queries
         * per pages distribution). *)
        Opache.serve h ?port (fun _host http pdu logger ->
            ignore pdu ;
            ignore logger ;
            let open Http in
            Pdu.make_response 404 ~body:"yeah yeah" |>
            TRXtop.tx http)

    method pgsql_serve ?(port=Tcp.Port.o 5432) ~(response_time : unit -> float) ~(response_size : unit -> float) () =
        (* TODO *)
        ignore port ; ignore (response_time ()) ; ignore (response_size ())
end

(* DEBUG *)
class pinger h = object
    inherit host h

    method powered_on =
        let dst = Host.IPv4 (Ip.Addr.of_string "8.8.8.8") in
        Log.(log h.Host.logger Debug (lazy "Pinging!")) ;
        h.Host.ping dst
end

class web_client h = object (self)
    inherit host h
    (* where we take power_on from *)

    method powered_on =
        (*
        self#browse ~from:(Url.of_string "http://news.ycombinator.com")
                    ~read_time:(Distribution.chi_squared 2.) ;
        (* Start browsing until told otherwise. *)
        (* Note: rather than a direct variant for the distribution we prefer a
         * function as the syntax is actually better (optional arguments are
         * not possible with variant/records). Also we have more freedom to
         * return either a variant describing the distribution or a function
         * implementing it. *)
        (* This will browse the _real_ hackernews, as DNS queries of unknown
         * name will be forwarded to external specified DNS (8.8.8.8 by
         * default) *)
        *)

        self#browse ~from:(Url.of_string "http://intranet.boringjob.com")
                    ~read_time:(Distribution.binomial ~p:0.5 ~n:40)
        (* This will browse the fake intranet defined below *)

    method around_time = function
        | { hour = 9; min = 30; day_of_week } when Sim.Time.is_working_day day_of_week ->
            (* We have minutely, hourly, daily and weekly clock ticks.
             * For each equipment, the next tick is signaled with a `Time event at
             * the actual, accurate time stamp. But with each of those ticks we
             * have also an accompanying approximate tick, that's set `around` the
             * accurate one, and signaled with AroundTime. The time specification
             * of AroundTime is therefore the accurate one, but its event is
             * received around that time.
             * The only drawback is that two different AroundTime of the same time
             * on the same client will execute at the same time ; but actually as
             * the pattern will shadow each other the compiler will complain. *)
            (* As functions cannot return a matching patterns we have to find a way
             * to make it work with actual pattern matching. *)

            self#power_on
            (* There is really no possible non-optional argument for that one. *)
            (* power_on has to be inherited, and will call self#powered_on. *)

        | { hour = 17; min = 0; day_of_week } when Sim.Time.is_working_day day_of_week ->
            self#power_off ~timeout:(Clock.Interval.min 1.)
            (* will kill all running activities on that host with that timeout,
             * aka stop sending new HTTP gets but still wait and ack answers,
             * until timeout, and then poweroff the host. *)

        | _ -> ()
end

class infested_web_client h = object (self)
    inherit web_client h
    val mutable infested = false
    val mutable triggered = false

    method virus_triggered =
        (* That's a global event that will call virus_triggered in all
         * hosts so that infested ones start extra-communication all at the
         * same time *)
        if infested && not triggered then (
            triggered <- true ;
            (* We can specify several new actions in sequence: *)
            self#tcp_traffic ~port:(Tcp.Port.o 666) ~throughput:10. (Host.Name "m4l1c10u5.ru") ;
            self#tcp_traffic ~port:(Tcp.Port.o 667) ~throughput:50. ~num_connections:3 (Host.Name "m4l1c10u5.ru")
        )

    method around_time = function
        | { min = 0 ; _ } ->
            (* Every hour we get some chance to be infested. *)
            if not infested then infested <- Random.float 1. > 0.99

        | _ -> ()
end

class boringjob_intranet h = object (self)
    inherit host h

    method powered_on =
        self#http_serve (*~backends:[Backend.sql ~host:"pgsql.boringjob.com"]*) ()
        (* All default parameters: any hostname, random catalog of resources
         * with some text/html with random content and mostly valid links.
         * We have to have a non optional argument though. *)
        (* Uses back-end default throughput and relative qps (aka queries
         * per pages distribution). *)
end

class boringjob_db h = object (self)
    inherit host h

    method powered_on =
        self#pgsql_serve ~response_time:(Distribution.chi_squared 2.5) ~response_size:(Distribution.chi_squared 7.) ()
end

class malicious_web_server h = object (self)
    inherit host h

    method powered_on =
        self#tcp_serve ~port:(Tcp.Port.o 666) ~throughput:50. () ;
        (* Use default ~content that will send random data *)
        self#tcp_serve ~port:(Tcp.Port.o 667) ~throughput:10_000. ()
end

type cable_state = { seq_num : int }

class faulty_cable =
    let seq = ref 0 in
    object
        inherit equipment
        val seq_num = incr seq ; !seq
        val mutable cut = false
        (* Now we need to access the underlying sim.cable to be able to act on this... *)

        method cable_cut num =
            (* Another global event, this time with a parameter (identifier of
             * an individual cable to be cut). *)
            if num = seq_num then cut <- true

        method cable_repair num =
            if num = seq_num then cut <- false
    end

(*
 * The above defined the possible behaviors.
 * Now we have to associate one with (some of) the equipment.
 * We will use direct classes so no more PPP config file I'm afraid.
 *)

module Plan =
struct
    (* Basically, for each "herd" of hosts we want to tell the composition
     * (so many of that kind, and so on).
     * For cables, we want to replace selected cables with "behaviored" ones.
     * We then spawn the "soul" of the machines/cables that control them.
     * Note that for cables that means replacing actual TX in the cable construtor.
     * Those "souls" live independently of the Sim.Net, but control it.
     * It can be "instanciated" at a later stage. So we could have the Sim.Net
     * described in a ppp file, and then also the behavior affectations
     * (as long as classes are known by some name and the user do not want
     * to add to the corpus of predefined characters, but then what's the point
     * of making those behaviors configurable then? Much better it is to produce
     * a simulator with parameters replacable via command line switch for such
     * things as number of DC, size of LANs and shares of behaviors.
     *)

    type hosts_spec = HerdOf of int | Individual of string * Ip.Addr.t
    module LAN = struct
        type t =
            { name : string option ;
              public_ip : Ip.Addr.t ;
              hosts : (hosts_spec * (Host.host_trx -> host)) list }
    end

    module DC = struct
        type t =
            { name : string option ;
              nameserver : string option ;
              cidr : string ;
              hosts : (hosts_spec * (Host.host_trx -> host)) list ;
              (* Where to mirror traffic to: *)
              iface_name : string }
    end

    (* Instantiation will connect all DCs to "internet" via a sink mirroring
     * everything toward a pcap interface *)
    type t =
        { root_nameserver : string ;
          dcs : DC.t list ;
          lans : LAN.t list }

    let instanciate p =
        let global_directory = Hashtbl.create 9 in
        (* Endow each host with a controlling soul: *)
        let rec give_soul (make_host : ?name:string -> ?ip:Ip.Addr.t -> ?on:bool -> unit -> Host.host_trx) prevs = function
            | [] -> prevs
            | (HerdOf 0, _)::rest ->
                give_soul make_host prevs rest
            | (HerdOf n, make)::rest ->
                let h = make_host ?name:None ?ip:None ~on:false () in
                let chr = make h in
                give_soul make_host (chr :: prevs) ((HerdOf (n-1), make)::rest)
            | (Individual (name, ip), make)::rest ->
                let h = make_host ~name ~ip ~on:false () in
                Hashtbl.add global_directory name ip ;
                let chr = make h in
                give_soul make_host (chr :: prevs) rest in
        let ns_ip = Ip.Addr.of_string p.root_nameserver
        and ns_name = "root" in
        let root_nameserver = Sim.Net.make_server ~name:ns_name ns_ip in
        Hashtbl.add global_directory ns_name ns_ip ;
        let lookup = (Hashtbl.find_option global_directory) in
        let dns_state = Named.State.make lookup in
        Sim.Net.iter_equipments (function
            | Host host -> Named.serve dns_state host
            | _ -> ()) root_nameserver ;
        let inet = Sim.Net.make_internet () in
        assert_ok (Sim.Net.connect inet root_nameserver) ;
        let net = Sim.Net.union [ inet ; root_nameserver ] in
        let num_hosts =
            List.fold_left (fun s -> function
                | HerdOf n, _ -> s + n
                | Individual _, _ -> s + 1
            ) 0 in
        let characters, net =
            List.fold_lefti (fun (characters, net) i dc ->
                let open DC in
                let dc_name = dc.name |? "datacenter" ^ string_of_int i in
                let cidr = Ip.Cidr.of_string dc.cidr in
                let num_hosts = num_hosts dc.hosts in
                let g, add_host =
                    Sim.Net.make_dc ~dc_name ~nameserver:ns_ip ~cidr num_hosts in
                (* Tap DC traffic to the sink: *)
                let tap = Sim.Net.make_repeater 3 ("tap."^ dc_name) in
                let sink = Sim.Net.make_sink dc.iface_name in
                assert_ok (Sim.Net.connect tap sink) ;
                assert_ok (Sim.Net.connect tap g) ;
                assert_ok (Sim.Net.connect tap inet) ;
                let characters = give_soul add_host characters dc.hosts in
                characters, Sim.Net.union [ net ; tap ; sink ; g ]
            ) ([], net) p.dcs in
        let characters, net =
            List.fold_left (fun (characters, net) lan ->
                let open LAN in
                let num_hosts = num_hosts lan.hosts in
                let g, add_host =
                    Sim.Net.make_lan ?lan_name:lan.name ns_ip num_hosts in
                assert_ok (Sim.Net.connect inet g) ;
                let characters = give_soul add_host characters lan.hosts in
                characters, Sim.Net.union [ net ; g ]
            ) (characters, net) p.lans in
        Log.(log default Info (lazy
            (Printf.sprintf2 "Will run with this directory: %a"
                (Hashtbl.print String.print Ip.Addr.printf) global_directory))) ;
        characters, net

end

let simul plan =
    let characters, _net = Plan.instanciate plan in
    Log.(log default Info (lazy
        (Printf.sprintf "Got a net with %d characters" (List.length characters)))) ;
    (* What to do with the souls? For now we just power them all on.
     * FIXME: we should power them on when the scenario says so! ie either
     * around_time X or immediately.
     * We should also register the external events to some inventory, in such
     * a way that user can control the controlling souls? *)
    (* Power-on everything: *)
    List.iter (fun chr -> chr#power_on) characters
    (* And so on. *)

let main =
    Random.self_init () ; (* TODO: parameter for seed *)
    let plan = Plan.{
        root_nameserver = "1.1.1.1" ;
        lans = [
            { name = None ;
              public_ip = Ip.Addr.of_string "1.2.3.4" ;
              hosts = [ HerdOf 1, new web_client ] } ] ;
        dcs = [ {
            name = None ;
            nameserver = None ;
            cidr = "1.0.0.0/8" ;
            hosts = [
                Individual ("intranet.boringjob.com", Ip.Addr.of_string "1.2.3.4"), new boringjob_intranet
            ] ;
            iface_name = "bridge0" } ] } in
    Log.console_lvl := Log.Debug ;
    simul plan ;
    Clock.run true
