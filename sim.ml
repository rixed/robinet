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
(** This module puts together all the modules required to build
 * networks and run a simulation. *)
open Batteries
open Bitstring
open Tools

(** A network is a set of equipments, and some optionaly named "plugs"
 * where to attach another network to form a new one. We keep track of
 * the equipement because we want to be able to delete a whole network
 * at once, to iter on all hosts of a network, and so on.
 * The underlying connections are not materialized beyond the emit/recv
 * function pointers, so contrary to one would expect a net is not a
 * graph but a mere list of equipment (and available plugs).
 * Connecting two nets make the used plugs disapear, but other than that
 * the two nets stay the same. To group two nets (either connected or net)
 * use the [union] function which will return the union of the two nets. *)
module Net =
struct
    (** A plug is a named entry point to a networks.
     * The name is there to suggest an usage but is not used internally. *)
    module Plug = struct
        type t = {     name : string ; (** name *)
                        dev : dev }
        let make name dev = { name ; dev }
    end

    type equipment = Host of Host.host_trx
                   | Hub of Hub.Repeater.t
                   | Switch of Hub.Switch.t
                   | Trx of trx (* generic trx like gateways... *)

    (** A net is a mere list of equipment and another one for available plugs.
     * Plugs get consumed as they are used. *)
    type t = {         equip : equipment list ;
               mutable plugs : Plug.t list }

    let make_empty () = { equip = [] ; plugs = [] }

    let rec union = function
        | []    -> make_empty ()
        | t::ts ->
            let u = union ts in
            { equip = List.rev_append u.equip t.equip ;
              plugs = List.rev_append u.plugs t.plugs }

    (** remove the matching plug and return it *)
    let find_named_plug t name =
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
            Result.Ok p
        with Not_found ->
            Result.Bad (`Unknown_plug name)

    (** [connect t1 ~name1:"plug1" t2 ~name2:"plug2"] will change the plugs emiting
     * and receiving functions such that t1 and t2 start exchanging messages at this point.
     * Will return [BatResult.Bad (`Unknown_plug of string)] if name1 or name2 can
     * not be found.
     * If a name for the plug is not given then anyone will do.
     * Notice that the used plugs are consumed (ie. removed from the passed nets). *)
    let connect ?plug1 t1 ?plug2 t2 = Result.Monad.(
        find_named_plug t1 plug1 >>= (fun p1 ->
            find_named_plug t2 plug2 >>= (fun p2 ->
                p1.Plug.dev <--> p2.Plug.dev ;
                Ok ())))

    (** Return a net representing the external network via the given interface,
     * and the thread that sniffs packets. *)
    let make_sink iface_name =
        let iface = Pcap.openif iface_name true "" 1800 in
        let emit = ref ignore in
        { equip = [] ;
          plugs = [ Plug.make iface_name { write = Pcap.inject_pdu iface ;
                                           set_read = fun em -> emit := em} ] },
        Pcap.sniffer iface (fun bits -> !emit bits)

    (** Returns a net with an unlimited supply of plugs that performs as a router. *)
    let make_internet () =
        (* A big switch for now *)
        let nb_ports = 100 in
        let sw = Hub.Switch.make nb_ports 5000 in
        let plugs = List.init nb_ports (fun i ->
            Plug.make "" (Hub.Switch.to_dev i sw)) in
        { equip = [ Switch sw ] ; plugs }

    (** Returns a lan consisting of n hosts connected to a switch connected to a
     * router/dhcp server/nater with an "exit" plug. *)
    let make_simple_lan ?nameserver ?(public_ip=Ip.Addr.random ()) n =
        let cidr = Ip.Cidr.of_string "192.168.0.0/16" in
        let gw = Router.make_gw public_ip cidr in
        let sw = Hub.Switch.make (n+1) (5*n) in
        Hub.Switch.set_read n sw gw.ins.write ;
        gw.ins.set_read (Hub.Switch.write n sw) ;
        let hosts = List.init n (fun i ->
            let h = Host.make_dhcp ("desktop_" ^ string_of_int i)
                                   ~gw:(Eth.IPv4 (Ip.Addr.of_string "192.168.0.1"))
                                   ?nameserver
                                   (Eth.Addr.random ()) in
            h.Host.dev.set_read (Hub.Switch.write i sw) ;
            Hub.Switch.set_read i sw h.Host.dev.write ;
            Host h) in
        let plug = Plug.make "" (Hub.Switch.to_dev 0 sw) in
        { equip = (Switch sw) :: (Trx gw) :: hosts ; plugs = [ plug ] }

end

let run ?timeout threads =
    (match timeout with
        | None -> ()
        | Some d -> Clock.delay d failwith "timeout") ;
    let e_threads =
        List.map (fun t ->
            Lwt.catch (fun () -> t)
                      (fun e ->
                        Printf.fprintf stderr "Simul thread failed with: %a\n%!" Printexc.print e ;
                        Lwt.return ())) threads in
    Lwt.choose [ Clock.run true ; Lwt.join e_threads ]

