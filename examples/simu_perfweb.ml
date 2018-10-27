(* vim:sw=4 ts=4 sts=4 expandtab
*)
(** This test simulates a network of clients (from various distance)
 * navigating a website at random, looking for some pattern and
 * tracking some performance counters. *)
open Batteries
open Tools

let logger = Log.make "webperf" 1000

(** {1 Tools} *)

(** Spawn a browser thread in all hosts of the given network, that will browse
 * at random in a human like fashion from the root url *)
let client_init url host =
    let trx = host.Host.host_trx in
    Log.(log logger Info (lazy (Printf.sprintf "Starting a new web browser on %s" trx.Host.name))) ;
    let browser = Browser.make trx in
    (* FIXME: better have a browser.at_init register function *)
    let rec start_browsing () =
        if trx.Host.get_ip () <> None then (
            Browser.user browser ~pause:5. 1000 url
        ) else (
            Log.(log logger Info (lazy (Printf.sprintf "IP not initialized, wait"))) ;
            Clock.(delay (Interval.sec 1.) start_browsing ())
        ) in
    start_browsing ()

(** Creates [num_groups] groups connected through an Internet. *)
let make_net avg_group_size num_groups ifname nameserver =
    (* Sim.Net.make_internet returns a network with an unlimited amount of eth "plugs"
     * (functioning as a router internally). *)
    Log.(log logger Info (lazy "Create the Internet... :^O")) ;
    let inet = Sim.Net.make_internet () in
    Log.(log logger Info (lazy (Printf.sprintf "Create %d groups..." num_groups))) ;
    let groups = List.init num_groups (fun i ->
        (* Sim.make_lan returns a network made with many hosts, a dhcp
         * server and a switch, with a free port for external connectivity. *)
        let num_hosts = avg_group_size in
        Log.(log logger Info (lazy (Printf.sprintf "Create group %d with %d hosts" i num_hosts))) ;
        let group, add_host = Sim.Net.make_lan nameserver num_hosts in
        for _ = 1 to num_hosts do
            add_host ?name:None ?ip:None ~on:true |> ignore
        done ;
        Log.(log logger Info (lazy "Connect it...")) ;
        (* Sim.Net.connect takes two nets and connect them the obvious way *)
        assert_ok (Sim.Net.connect inet group) ;
        group) in
    Log.(log logger Info (lazy ("Connecting "^ifname))) ;
    let sink, _sniff_thread = Sim.Net.make_real_net ifname logger in
    assert_ok (Sim.Net.connect inet sink) ;
    Sim.Net.union (inet :: sink :: groups)

(** {1 Main function} *)

(** This will creates the objects and queue the first callbacks but does not start the clock *)
let simul_webperf avg_group_size num_groups _duration ifname nameserver url =
    Log.(log logger Info (lazy (Printf.sprintf "Starting webperf simulation with %d groups of %d users (avg) for base url %s"
        num_groups avg_group_size (Url.to_string url)))) ;
    let net = make_net avg_group_size num_groups ifname nameserver in
    (* Power on everything: *)
    Log.(log logger Info (lazy "Starting browser on each host...")) ;
    Sim.Net.iter_equipments (function
        Sim.Net.Equipment.Host h -> h.Host.power_on ~on_ip:(client_init url) ()
        | _ -> ()
    ) net

let main =
    let url = ref "http://google.com"
    and ifname = ref "eth0"
    and num_groups = ref 5
    and avg_grp_size = ref 10
    and duration = ref 60
    and nameserver = ref "192.168.1.254"
    in
    Arg.parse [ "-ifname",   Arg.Set_string ifname,     "iface name (default: eth0)" ;
                "-nb-lans",  Arg.Set_int num_groups,    "nb LANs (default: 5)" ;
                "-lan-size", Arg.Set_int avg_grp_size,  "Avg LAN size (default: 10)" ;
                "-duration", Arg.Set_int duration,      "duration of browsing (in secs) (default: 60)" ;
                "-dns",      Arg.Set_string nameserver, "external DNS to use (default: 192.168.1.254)" ;
                "-url",      Arg.Set_string url,        "URL (default: http://www.google.com)" ]
              (fun _ -> raise (Arg.Bad "unknown parameter"))
              "Browse a web site from various locations" ;
    Log.console_lvl := Log.Debug ;
    simul_webperf !avg_grp_size
                  !num_groups
                  (Clock.Interval.sec (float_of_int !duration))
                  !ifname
                  (Ip.Addr.of_string !nameserver)
                  (Url.of_string !url) ;
    Log.(log logger Info (lazy "Running it all...")) ;
    Clock.run true

