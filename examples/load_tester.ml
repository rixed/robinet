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
(*
   Small tool that replay pcap files, duplicating the packets after changing
   their MAC and IP so that your tested equipment is tricked to think there
   are as large a number of simultaneous hosts are wanted.
   TODO:
   - configure number of flows instead of number of duplicates;
   - takes several pcap as input
*)

open Batteries
open Bitstring
open Tools

type pkt_source = Iface of string | File of string

let input_of = function
    | File name ->
        Pcap.enum_of_file name
    | Iface name ->
        let iface = Pcap.openif name true "" 0 in
        Enum.from (fun () ->
            let ts, pkt = Pcap.sniff iface in
            Pcap.Pdu.make name ts (bitstring_of_string pkt))

let sink_to = function
    | File name ->
        Enum.iter (Pcap.Pdu.save name)
    | Iface name ->
        let iface = Pcap.openif name false "" 0 in
        let inject_f pdu = Pcap.inject_pdu iface (pdu.Pcap.Pdu.payload :> bitstring) in
        Enum.iter inject_f

let replay offset n inps outs =
    (* TODO: use several inputs *)
    let inp = List.hd inps and out = List.hd outs in
    let open Packet in
    let alter_bits = bitstring_add in
    let alter_layer i = function
        | Pdu.Eth p ->
            let open Eth.Pdu in
            Pdu.Eth { p with src = alter_bits i (p.src :> bitstring) |> Eth.Addr.o ; dst = alter_bits i (p.dst :> bitstring) |> Eth.Addr.o }
        | Pdu.Ip p ->
            let open Ip.Pdu in
            let alter_ip i (ip : Ip.Addr.t) =
                Ip.Addr.o32 (Int32.add (Ip.Addr.to_int32 ip) (Int32.of_int i)) in
            Pdu.Ip { p with src = alter_ip i p.src ; dst = alter_ip i p.dst ; id = (p.id + i) land 0xffff }
        | Pdu.Vlan p ->
            let open Vlan.Pdu in
            Pdu.Vlan { p with id = (p.id + i) land 0xfff }
(*      | Pdu.Arp p -> change addresses ? *)
        | x -> x in
    let alter_packet i l =
        if i = 0 then l else
        List.map (alter_layer i) l in
    input_of inp /@
    (fun p ->
        let packet = Packet.Pdu.unpack p in
        Enum.init n (fun i ->
            alter_packet (offset+i) packet |>
            Packet.Pdu.pack)) |>
    Enum.flatten |>
    sink_to out

let main =
    let growth        = ref 1 (* TODO: a number of simultaneous flows *)
    and offset        = ref 0
    and input         = ref []
    and output        = ref []
    and loop          = ref false
    and add_iface l s = l := Iface s :: !l
    and add_pcap l s  = l := File s :: !l in
    Random.self_init () ;
    Arg.parse [ "-n", Arg.Set_int growth, "How many times should the input be duplicated (default: 1)" ;
                "-o", Arg.Set_int offset, "Initial offset to apply to traffic - useful when running several replay simultaneously (default: 0)" ;
                "-c", Arg.Unit (fun () -> do_compute_checksum := false), "Disable checkums" ;
                "-l", Arg.Set loop, "Loop forever" ;
                "-i", Arg.String (add_iface input),  "Where to sniff packets from" ;
                "-r", Arg.String (add_pcap input),   "Where to read packet from" ;
                "-I", Arg.String (add_iface output), "Where to inject generated traffic" ;
                "-w", Arg.String (add_pcap output),  "Where to write generated traffic" ]
              (fun _ -> raise (Arg.Bad "unknown parameter"))
              "Replay a pcap several times simultaneously" ;

    if !input = [] then (
        Printf.printf "No input?\n"
    ) else if !output = [] then (
        Printf.printf "No output?\n"
    ) else (
        let rec aux () =
            replay !offset !growth !input !output ;
            if !loop then aux () in
        aux ()
    )

