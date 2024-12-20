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
(**
  This module can attach to a created tap interface and sniff/inject traffic from
  it, like the Pcap module (which would not work with tap devices on linux for
  some reasons).
 *)
open Batteries
open Bitstring
open Tools

let debug = true

(** A counter for how many packets we failed to inject. *)
let packets_injected_err = Metric.Atomic.make "Tap/Packets/Injected/Err"

type tap_iface = { name : string ; sock : Unix.file_descr }

(* Returns the bind socket: *)
external tap_open : string -> int = "wrap_tap_open"

let openif ifname =
    { name = ifname ; sock = fd_of_int (tap_open ifname) }

let inject iface bits =
    try
        let str = string_of_bitstring bits in
        let len = String.length str in
        if debug then
            Printf.printf "Tap(%s): injecting a packet (%d bytes)...\n%!"
                iface.name len ;
        let sent = Unix.send_substring iface.sock str 0 len [ MSG_DONTROUTE ] in
        assert (sent = len)
    with e ->
        Printf.printf "Tap(%s): Cannot inject a packet: %s\n%!"
            iface.name (Printexc.to_string e) ;
        Metric.Atomic.fire packets_injected_err

external tap_read : int -> string = "wrap_tap_read"

let sniff iface =
    let bytes = tap_read (int_of_fd iface.sock) in
    let ts = Clock.Time.wall_clock () in
    Pcap.Pdu.make iface.name ts (bitstring_of_string bytes)

(** A counter for how many packets were sniffed. *)
let packets_sniffed_ok = Metric.Atomic.make "Tap/Packets/Sniffed"

(** A counter for how many bytes were sniffed. *)
let bytes_in           = Metric.Counter.make "Tap/Bytes/In" "bytes"

(* TODO: This should be provided for any sniffing module by the functor: *)
(** [sniffer iface rx] returns a thread that continuously sniff packets
 * and pass them to the [rx] function (via the Clock). *)
let sniffer iface rx =
    let rec loop () =
        match none_if_exception sniff iface with
        | None -> ()
        | Some pdu ->
            Clock.synch () ;
            Metric.Atomic.fire packets_sniffed_ok ;
            Metric.Counter.add bytes_in (Int64.of_int (Payload.length pdu.Pcap.Pdu.payload)) ;
            if debug then Printf.printf "Tap(%s): Got packet for ts %s\n%!"
                iface.name (Clock.Time.to_string pdu.ts) ;
            Clock.at pdu.ts rx (pdu.payload :> bitstring) ;
            if !Clock.continue then loop () in
    Thread.create loop ()
