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
(** This module puts together all the modules required to build
 * networks and run a simulation. *)
open Batteries
open Tools

(** A network is a set of equipments, and some optionally named "plugs"
 * where to attach another network to form a new one. We keep track of
 * the equipment because we want to be able to delete a whole network
 * at once, to iter on all hosts of a network, and so on.
 * The underlying connections are not materialized beyond the emit/recv
 * function pointers, so contrary to what one might expect a net is not a
 * graph but a mere list of equipment (and available plugs).
 * Connecting two nets make the used plugs disappear, but other than that
 * the two nets stay the same. To group two nets (either connected or not)
 * use the [union] function which will return the union of the two nets. *)
module Net =
struct
    (** A plug is a named entry/exit point to a networks.
     * The name is there to suggest an usage but is not used internally. *)
    module Plug = struct
        type t = { name : string ; (** name *)
                    dev : dev }
        let make name dev = { name ; dev }
    end

    module Equipment = struct
        type t = Host of Host.host_trx
               | Hub of Hub.Repeater.t
               | Switch of Hub.Switch.t
               | Trx of trx (* generic trx like gateways... *)

        let print oc = function
            | Host h -> Host.print oc h
            | Hub h -> Hub.Repeater.print oc h
            | Switch s -> Hub.Switch.print oc s
            | Trx _ -> Printf.fprintf oc "some TRX"
    end

    (** A net is a mere list of equipment and another one for available plugs.
     * Plugs get consumed as they are used. Also, nets can be grouped into
     * bigger ones. *)
    type simple = { mutable equip : Equipment.t list ;
                    mutable plugs : Plug.t list }
    type t = Simple of simple | Union of t list

    let rec print oc = function
        | Simple s -> List.print Equipment.print oc s.equip
        | Union u -> List.print print oc u

    (* Build a net made of all the passed ones. *)
    (* NOTE: we could also try to keep the union flat *)
    let union ts = Union ts

    let rec fold f i = function
        | Simple s -> f i s
        | Union ts ->
            List.fold_left (fun i t ->
                fold f i t
            ) i ts

    let fold_equipments f =
        fold (fun i s -> List.fold_left f i s.equip)

    let iter f = fold (fun () -> f) ()

    let iter_equipments f = fold_equipments (fun () -> f) ()

    (** remove the matching plug and return it *)
    let find_named_plug t name =
        let find_in_simple t =
            let list_extract_first f l =
                let rec aux prevs = function
                    | []    -> raise Not_found
                    | x::xs ->
                        if f x then x, List.rev_append prevs xs
                        else aux (x::prevs) xs in
                aux [] l in
            try
                let p, ps =
                    list_extract_first (fun p ->
                        name = None || name = Some p.Plug.name)
                        t.plugs in
                t.plugs <- ps ;
                Printf.printf "Consume plug %S of %a\n%!" p.name print (Simple t) ;
                Result.Ok p
            with Not_found ->
                Result.Error (`Unknown_plug name)
        in
        let rec loop = function
            | Simple t -> find_in_simple t
            | Union ts -> find_in_union ts
        and find_in_union = function
            | [] -> Result.Error (`Unknown_plug name)
            | x::rest ->
                let r = loop x in
                if Result.is_ok r then r
                else find_in_union rest in
        loop t

    (** [connect t1 ~name1:"plug1" t2 ~name2:"plug2"] will change the plugs emitting
     * and receiving functions such that t1 and t2 start exchanging messages at this point.
     * Will return [BatResult.Error (`Unknown_plug of string)] if name1 or name2 can
     * not be found.
     * If a name for the plug is not given then anyone will do.
     * Notice that the used plugs are consumed (ie. removed from the passed nets). *)
    let connect ?plug1 t1 ?plug2 t2 = Result.Monad.(
        find_named_plug t1 plug1 >>= (fun p1 ->
            find_named_plug t2 plug2 >>= (fun p2 ->
                p1.Plug.dev <--> p2.Plug.dev ;
                Ok ())))

    (** Returns a sink toward the real world via the named interface: *)
    let make_sink iface_name =
        let iface = Pcap.openif ~caplen:1800 iface_name in
        (* As we always [connect] both read and write, just silently ignore
         * calls to [set_read] instead of reporting an error: *)
        let write bits =
            Printf.printf "injecting some bits in iface %s\n%!" iface.Pcap.name ;
            Pcap.inject iface bits
        and set_read = ignore in
        let plug = Plug.make iface_name { write ; set_read } in
        Simple { equip = [] ; plugs = [ plug ] }

    (* A repeater as a Net.t *)
    let make_repeater n name =
        Printf.printf "Build repeater with %d ports\n%!" n ;
        let r = Hub.Repeater.make n name in
        let plugs = List.init n (fun i ->
            let iface_name = "port#"^ string_of_int i in
            Plug.make iface_name (Hub.Repeater.port r i)) in
        Simple { equip = [ Hub r ] ; plugs }

    (** Returns a net representing the external network via the given interface,
     * and the thread that sniffs packets. *)
    let make_real_net iface_name =
        let iface = Pcap.openif ~caplen:1800 iface_name in
        let emit = ref ignore_bits in
        let plug = Plug.make iface_name { write = Pcap.inject iface ;
                                          set_read = fun em -> emit := em } in
        Simple { equip = [] ; plugs = [ plug ] },
        Pcap.sniffer iface (fun bits -> !emit bits)

    (** Returns a net with an unlimited supply of plugs that performs as a router. *)
    let make_internet () =
        (* A big switch for now *)
        let nb_ports = 10 in
        let sw = Hub.Switch.make nb_ports 5000 "Internet" in
        let plugs = List.init nb_ports (fun i ->
            Plug.make "" (Hub.Switch.port sw i)) in
        Simple { equip = [ Switch sw ] ; plugs }

    (* Build a single server (public static IP and name) as a Net.t: *)
    let make_server ~on ?(name=Host.Name.random()) ?(mac=Eth.Addr.random ()) ?nameserver public_ip =
        let netmask = Ip.Addr.zero in (* Should this be the default? *)
        let host = Host.make_static ?nameserver ~on ~netmask name mac public_ip in
        let plug = Plug.make "itf" host.Host.dev in
        Simple { equip = [ Host host ] ; plugs = [ plug ] }

    (** Returns an _empty_ LAN with enough room for [n] hosts.
     * A LAN consists of a switch connected to a router/dhcp server/name server/nater with an "exit" plug.
     * See make_lan_host to add a host in this LAN. *)
    let make_lan ?(lan_name="homelan") ?(public_ip=Ip.Addr.random ()) nameserver n =
        let cidr = Ip.Cidr.of_string "192.168.0.0/16" in
        let gw = Router.make_gw public_ip cidr ~nameserver ~name:("gw."^lan_name) in
        let sw = Hub.Switch.make (n+1) (5*n) ("switch."^lan_name) in
        Hub.Switch.set_read sw n gw.trx.ins.write ;
        gw.trx.ins.set_read (Hub.Switch.write sw n) ;
        let plug = Plug.make lan_name gw.trx.out in
        let net =
            { equip = [ Switch sw ; Trx gw.trx ] ; plugs = [ plug ] } in
        let num_hosts = ref 0 in
        (* Here name is the local name *)
        let add_host ?name ?ip ~on =
            assert (ip = None) ;
            let name = name |? "desktop_" ^ string_of_int (!num_hosts) in
            let name = name ^"."^ lan_name in
            let gw_ip = Ip.Addr.of_string "192.168.0.1"
            and srv_ip = Ip.Addr.of_string "192.168.0.2" in
            let netmask = Ip.Addr.of_string "255.255.0.0" in
            let gw = [ Eth.Gateway.make ~addr:(Eth.Gateway.IPv4 gw_ip) () ] in
            let h = Host.make_dhcp name ~on ~gw ~nameserver:srv_ip ~netmask (Eth.Addr.random ()) in
            h.Host.dev.set_read (Hub.Switch.write sw !num_hosts) ;
            Hub.Switch.set_read sw !num_hosts h.Host.dev.write ;
            net.equip <- Equipment.Host h :: net.equip ;
            incr num_hosts ;
            h
        in
        Simple net, add_host

    (** Returns a set of many static hosts and a switch with no NAT: *)
    let make_dc ~dc_name ?nameserver ~cidr n =
        let sw = Hub.Switch.make (n+1) (5*n) ("switch."^dc_name) in
        let local_ips = Ip.Cidr.local_addrs cidr in
        let plug = Plug.make dc_name (Hub.Switch.port sw n) in
        let net =
            { equip = [ Switch sw ] ; plugs = [ plug ] } in
        let num_hosts = ref 0 in
        (* Here name is the FQ name *)
        let add_host ?name ?ip ~on =
            let name = name |? "server_" ^ string_of_int !num_hosts ^ "."^ dc_name in
            let ip =
                ip |? try Enum.get_exn local_ips
                      with Enum.No_more_elements ->
                          Printf.sprintf "Not enough IPs in %s for %d hosts"
                              (Ip.Cidr.to_string cidr) n |>
                          failwith
            in
            let mac = Eth.Addr.random () in
            let netmask = Ip.Addr.zero in
            let h = Host.make_static ~on name ?nameserver ~netmask mac ip in
            h.Host.dev.set_read (Hub.Switch.write sw !num_hosts) ;
            Hub.Switch.set_read sw !num_hosts h.Host.dev.write ;
            net.equip <- Equipment.Host h :: net.equip ;
            incr num_hosts ;
            h
        in
        Simple net, add_host

end

module Time = struct
    type t = { hour : int ; min : int ; day_of_week : int }

    let is_working_day dow =
        (* TODO: make it configurable *)
        dow <> 0 && dow <> 7
end
