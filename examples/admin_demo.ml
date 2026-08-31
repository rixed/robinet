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
    (* Where this little network is.
     *
     * The spot itself is arbitrary; that its parts have one at all is not. A
     * widget with no place of its own is drawn in the strip under the map
     * rather than put somewhere and left to look placed, so a simulation that
     * places nothing opens on a map with nothing on it.
     *
     * The cables then take their length from the ground distance between the
     * two ends they join, the way simwan's do, so that the picture and the
     * delays it is supposed to explain are computed from the same numbers
     * rather than merely agreeing by luck. *)
    let switch_at = Widget.{ lat = 48.8566 ; lon = 2.3522 } in
    let rad d = d *. Float.pi /. 180. in
    (* Metres between two places, on a sphere. Good to a fraction of a percent,
     * which is far past what a cable's delay is sensitive to -- and rounded to
     * the metre where it is used, since the digits past that are the sphere's
     * error rather than anything about the cable. *)
    let ground_distance (a : Widget.location) (b : Widget.location) =
        let hav x = let s = sin (x /. 2.) in s *. s in
        let h = hav (rad (b.lat -. a.lat)) +.
                cos (rad a.lat) *. cos (rad b.lat) *.
                hav (rad (b.lon -. a.lon)) in
        2. *. 6_371_000. *. asin (sqrt (min 1. h)) in
    (* [dist] metres from [c], on a [bearing] in degrees clockwise from north. *)
    let offset (c : Widget.location) ~bearing ~dist =
        let m_per_deg = 111_320. in
        Widget.{ lat = c.lat +. dist *. cos (rad bearing) /. m_per_deg ;
                 lon = c.lon +. dist *. sin (rad bearing) /.
                                (m_per_deg *. cos (rad c.lat)) } in
    let switch = Hub.Switch.make ~parent 4 64 "switch" in
    Widget.place switch.Hub.Switch.widget (Some switch_at) ;
    let hosts =
        List.init 3 (fun i ->
            let ip = Ip.Addr.of_string (Printf.sprintf "192.168.1.%d" (i + 10)) in
            let h = Host.make_static ~parent ~netmask ip (Printf.sprintf "host%d" i) in
            (* Spread around the switch, each one further out than the last, so
             * that the three cables are of three different lengths. *)
            let at = offset switch_at ~bearing:(120. *. float_of_int i)
                            ~dist:(300. *. float_of_int (i + 1)) in
            Widget.place h.Host.trx.widget (Some at) ;
            let cable =
                Eth.Cable.State.make ~parent
                                     ~length:(Float.round
                                                  (ground_distance switch_at at))
                                     ~error_rate:0.0001
                                     ~name:(Printf.sprintf "cable%d" i) () in
            let trx = Eth.Cable.make cable in
            Hub.Switch.iface switch i -=> trx <=-> h.Host.trx.dev ;
            (* The cable reaches the host's adapter, and that is the end the
               graph records -- the same one the creation API would have
               recorded, so a network built by hand and one built from the
               interface read alike. The switch end is the switch: its ports are
               not widgets, one being as good as another. *)
            Widget.make_peers ~via:cable.widget
                switch.Hub.Switch.widget h.Host.eth_state.Eth.State.widget ;
            h, ip) in
    (* Some traffic, so that the counters have something to count: every host
     * pings the next one, round and round. *)
    let rec tick () =
        List.iteri (fun i (h, _) ->
            let _, dst = List.at hosts ((i + 1) mod List.length hosts) in
            h.Host.trx.Host.ping (Host.IPv4 dst)) hosts ;
        Simulation.delay net (Clock.Interval.msec 100.) tick () in
    (* A DHCP server on the first host, so that the interface has properties
     * that may have no value to show (and one metric that has not fired). *)
    let first = fst (List.hd hosts) in
    let dhcpd =
        Dhcpd.State.make ~parent:first.Host.trx.Host.widget ~netmask ~mtu:1500
            (Ip.Range.of_cidr (Ip.Cidr.of_string "192.168.1.128/25")) in
    Dhcpd.serve dhcpd first.Host.trx ;
    tick () ;
    ignore (Simulation.start net) ;
    (* And the interface, in a simulation of its own so that pausing the one
     * above leaves it responsive. *)
    let admin = Simulation.make ~realtime:true "admin" in
    Myadmin.make admin (Localhost.host admin) (Tcp.Port.o port) ;
    Printf.printf "Point a browser at http://localhost:%d/\n%!" port ;
    Simulation.run_here admin
