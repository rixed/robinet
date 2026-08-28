(* A small network with an administration interface on top of it, to try the UI.
 *   ./examples/admin_demo.opt [port]
 * then point a browser at http://localhost:<port>/ *)
open Batteries
open Tools

let main =
    let port = if Array.length Sys.argv > 1 then int_of_string Sys.argv.(1) else 8080 in
    (* The network under study: closed, so it can be paused at will. *)
    let net = Simulation.make ~realtime:false "wan" in
    let parent = net.root in
    let netmask = Ip.Addr.of_string "255.255.255.0" in
    let switch = Hub.Switch.make ~parent 4 64 "switch" in
    let hosts =
        List.init 3 (fun i ->
            let ip = Ip.Addr.of_string (Printf.sprintf "192.168.1.%d" (i + 10)) in
            let h = Host.make_static ~parent ~netmask ip (Printf.sprintf "host%d" i) in
            let cable =
                Eth.Cable.State.make ~parent ~length:(5. *. float_of_int (i + 1))
                                     ~error_rate:0.0001
                                     ~name:(Printf.sprintf "cable%d" i) () in
            let trx = Eth.Cable.make cable in
            Hub.Switch.iface switch i -=> trx <=-> h.Host.trx.dev ;
            Widget.make_peers ~via:cable.widget
                switch.Hub.Switch.widget h.Host.trx.Host.widget ;
            h, ip) in
    (* Some traffic, so that the counters have something to count: every host
     * pings the next one, round and round. *)
    let rec tick () =
        List.iteri (fun i (h, _) ->
            let _, dst = List.at hosts ((i + 1) mod List.length hosts) in
            h.Host.trx.Host.ping (Host.IPv4 dst)) hosts ;
        Simulation.delay net (Clock.Interval.msec 100.) tick () in
    tick () ;
    ignore (Simulation.start net) ;
    (* And the interface, in a simulation of its own so that pausing the one
     * above leaves it responsive. *)
    let admin = Simulation.make ~realtime:true "admin" in
    Myadmin.make admin (Localhost.host admin) (Tcp.Port.o port) ;
    Printf.printf "Point a browser at http://localhost:%d/\n%!" port ;
    Simulation.run_here admin
