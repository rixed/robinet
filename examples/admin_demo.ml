(* A small network with an administration interface on top of it, to try the UI.
 *   ./examples/admin_demo.opt [port]
 * then point a browser at http://localhost:<port>/
 *
 * Built through the device catalogue rather than by calling the constructors,
 * so that it exercises the same path the interface itself takes when the
 * reader adds a switch. What comes back is a widget, and the module of the
 * kind asked for turns it back into the thing to run a program on. *)
open Batteries
open Tools

let main =
    let port = if Array.length Sys.argv > 1 then int_of_string Sys.argv.(1) else 8080 in
    (* The network under study: closed, so it can be paused at will. *)
    let net = Simulation.make ~realtime:false "wan" in
    let parent = net.root in
    (* Where this little network is.
     *
     * The spot itself is arbitrary; that its parts have one at all is not. A
     * widget with no place of its own is drawn in the strip under the map
     * rather than put somewhere and left to look placed, so a simulation that
     * places nothing opens on a map with nothing on it.
     *
     * It also decides the cables: one built with no length of its own takes
     * the ground distance between the two ends it joins, the way simwan's do,
     * so that the picture and the delays it is supposed to explain are
     * computed from the same numbers rather than merely agreeing by luck. *)
    let switch_at = Widget.{ lat = 48.8566 ; lon = 2.3522 } in
    (* [dist] metres from [c], on a [bearing] in degrees clockwise from north. *)
    let offset (c : Widget.location) ~bearing ~dist =
        let rad d = d *. Float.pi /. 180. in
        let m_per_deg = 111_320. in
        Widget.{ lat = c.lat +. dist *. cos (rad bearing) /. m_per_deg ;
                 lon = c.lon +. dist *. sin (rad bearing) /.
                                (m_per_deg *. cos (rad c.lat)) } in
    let switch =
        Device.make ~parent "switch"
            (Device.TSwitch { ports = 4 ; macs = 64 ;
                              speeds = Eth.Iface.default_speeds ;
                              full_duplex = true }) in
    Widget.place switch (Some switch_at) ;
    let hosts =
        List.init 3 (fun i ->
            let ip = Ip.Addr.of_string (Printf.sprintf "192.168.1.%d" (i + 10)) in
            let w =
                Device.make ~parent (Printf.sprintf "host%d" i)
                    (Device.THost { static_ip = Some ip ;
                                    netmask =
                                        Ip.Addr.of_string "255.255.255.0" ;
                                    gateway = None ; nameserver = None ;
                                    search_sfx = None ; mac = None }) in
            (* Spread around the switch, each one further out than the last, so
             * that the three cables are of three different lengths. Before the
             * cable, since it is from these that it takes its own. *)
            Widget.place w
                (Some (offset switch_at ~bearing:(120. *. float_of_int i)
                              ~dist:(300. *. float_of_int (i + 1)))) ;
            ignore (
                Device.make ~parent (Printf.sprintf "cable%d" i)
                    (Device.TCable { from_ = switch.Widget.id ;
                                     to_ = w.Widget.id ;
                                     from_port = None ; to_port = None ;
                                     length = None ;
                                     error_rate = 0.0001 })) ;
            (* Something to run the pings on. A host built as a host has one,
             * and this is the whole reason the demo can be written this way. *)
            Option.get (Host.of_widget w), ip) in
    (* Some traffic, so that the counters have something to count: every host
     * pings the next one, round and round. *)
    let rec tick () =
        List.iteri (fun i ((h : Host.t), _) ->
            let _, dst = List.at hosts ((i + 1) mod List.length hosts) in
            h.Host.trx.Host.ping (Host.IPv4 dst)
        ) hosts ;
        Simulation.delay net.Simulation.power (Clock.Interval.msec 100.) tick () in
    (* A DHCP server on the first host, so that the interface has properties
     * that may have no value to show (and one metric that has not fired).
     * Not a device of its own: what the catalogue builds are machines, and
     * what runs on one of them is a program. *)
    let first = fst (List.hd hosts) in
    let dhcpd =
        Dhcpd.State.make ~parent:first.Host.trx.Host.widget
            ~netmask:(Ip.Addr.of_string "255.255.255.0") ~mtu:1500
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
