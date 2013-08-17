(* vim:sw=4 ts=4 sts=4 expandtab
*)
(** This test simulates a network of clients (from various distance)
 * navigating a website at random, looking for some pattern and
 * tracking some performance counters. *)
open Batteries
open Tools

let logger = Log.make "webperf" 1000

(** {1 Tools} *)

(** Creates [nb_groups] groups connected through an Internet. *)
let make_net avg_group_size nb_groups ifname nameserver =
    (* Sim.Net.make_internet returns a network with an unlimited amount of eth "plugs"
     * (functioning as a router internally). *)
    Log.(log logger Info (lazy "Create the Internet... :^O")) ;
    let inet = Sim.Net.make_internet () in
    Log.(log logger Info (lazy (Printf.sprintf "Create %d groups..." nb_groups))) ;
    let groups = List.init nb_groups (fun i ->
        (* Sim.make_simple_lan returns a network made with many hosts, a dhcp
         * server and a switch, with a free port for external connectivity. *)
        let nb_hosts = avg_group_size in
        Log.(log logger Info (lazy (Printf.sprintf "Create group %d with %d hosts" i nb_hosts))) ;
        let group = Sim.Net.make_simple_lan ~nameserver nb_hosts in
        Log.(log logger Info (lazy "Connect it...")) ;
        (* Sim.Net.connect takes two nets and connect them the obvious way *)
        assert_ok (Sim.Net.connect inet group) ;
        group) in
    Log.(log logger Info (lazy ("Connecting "^ifname))) ;
    let sink, _sniff_thread = Sim.Net.make_sink ifname in
    assert_ok (Sim.Net.connect inet sink) ;
    Sim.Net.union (inet :: sink :: groups)

(** Spawn a browser thread in all hosts of the given network, that will browse
 * at random in a human like fashion from the root url *)
(* FIXME: Would be easier if we could give to make_net a sort of 'init' function for each host *)
let random_browsing net url =
    List.iter (function
        | Sim.Net.Host host ->
            Log.(log logger Info (lazy (Printf.sprintf "Starting a new web browser on %s" host.Host.name))) ;
            let browser = Browser.make host in
            (* FIXME: better have a browser.at_init register function *)
            let rec start_browsing () =
                if host.Host.get_ip () <> None then (
                    Browser.user browser ~pause:5. 1000 url
                ) else (
                    Log.(log logger Info (lazy (Printf.sprintf "IP not initialized, wait"))) ;
                    Clock.(delay (Interval.sec 1.) start_browsing ())
                ) in
            start_browsing ();
        | _ -> ())
        net.Sim.Net.equip


(** {1 Main function} *)

(** This will creates the objects and queue the first callbacks but does not start the clock *)
let simul_webperf avg_group_size nb_groups _duration ifname nameserver url =
    Log.(log logger Info (lazy (Printf.sprintf "Starting webperf simulation with %d groups of %d users (avg) for base url %s"
        nb_groups avg_group_size (Url.to_string url)))) ;
    let net = make_net avg_group_size nb_groups ifname nameserver in
    Log.(log logger Info (lazy "Starting browser on each host...")) ;
    random_browsing net url

let main =
    let url = ref "http://google.com"
    and ifname = ref "eth0"
    and nb_groups = ref 5
    and avg_grp_size = ref 10
    and duration = ref 60
    and nameserver = ref "192.168.1.254"
    in
    Arg.parse [ "-ifname",   Arg.Set_string ifname,     "iface name (default: eth0)" ;
                "-nb-lans",  Arg.Set_int nb_groups,     "nb LANs (default: 5)" ;
                "-lan-size", Arg.Set_int avg_grp_size,  "Avg LAN size (default: 10)" ;
                "-duration", Arg.Set_int duration,      "duration of browsing (in secs) (default: 60)" ;
                "-dns",      Arg.Set_string nameserver, "external DNS to use (default: 192.168.1.254)" ;
                "-url",      Arg.Set_string url,        "URL (default: http://www.google.com)" ]
              (fun _ -> raise (Arg.Bad "unknown parameter"))
              "Browse a web site from various locations" ;
    Log.console_lvl := Log.Debug ;
    simul_webperf !avg_grp_size
                  !nb_groups
                  (Clock.Interval.sec (float_of_int !duration))
                  !ifname
                  (Ip.Addr.of_string !nameserver)
                  (Url.of_string !url) ;
    Log.(log logger Info (lazy "Running it all...")) ;
    Clock.run true

