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
open Batteries
open Bitstring
open Tools

(** A Repeater (or HUB) is a device that receives Eth frames and blindly mirrors them
   to several locations (but the one from which the frame came from) *)
module Repeater =
struct
    type t = {  ports : (bitstring -> unit) array ;
                 name : string ;
               logger : Log.logger }

    let print oc t =
        Printf.fprintf oc "repeater %s with %d ports" t.name (Array.length t.ports)

    let make ?logger n name =
        let logger =
            Option.default_delayed (fun () -> Log.make name) logger in
        { ports = Array.make n ignore_bits ;
          name ; logger }

    let forward_from t n pld =
        Array.iteri (fun i emit ->
            if i <> n then (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Forward to port %d/%d" i (Array.length t.ports)))) ;
                Clock.asap emit pld
            )) t.ports

    let write t n pld =
        Log.(log t.logger Debug (lazy (Printf.sprintf "Rx from port %d/%d" n (Array.length t.ports)))) ;
        forward_from t n pld

    let set_read t n f =
        Log.(log t.logger Debug (lazy (Printf.sprintf "Setting reader for port %d" n))) ;
        t.ports.(n) <- f

    (** Turns a port into a device *)
    let port t n =
        { write = write t n ; set_read = set_read t n }

    let t_printer _paren oc t =
        Printf.fprintf oc "%d" (Array.length t.ports)

    let is_connected = (!=) ignore_bits

    let first_free_port t =
        Array.findi (not % is_connected) t.ports
end

(** A Switch is a device that will forward Ethernet frames based on the observed
  location of the destination. *)
module Switch =
struct
    module R = Repeater

    type mac_entry =
        { mutable addr : Eth.Addr.t option ;
          mutable port : int }

    type t =
        { hub  : R.t ;
          macs : mac_entry OrdArray.t ;
          (* Mapping from mac to position in the OrdArray [macs] *)
          macs_h : int BitHash.t ;
          name : string ;
          logger : Log.logger }

    let print oc t =
        Printf.fprintf oc "switch %s with %d ports" t.name (Array.length t.hub.ports)

    (* [num_macs] is the maximum number of remembered MACs. *)
    let make num_ports num_macs name =
        let logger = Log.make name in
        { hub = R.make ~logger num_ports name ;
          macs = OrdArray.init num_macs (fun _ -> { addr = None ; port = 0 }) ;
          macs_h = BitHash.create (num_macs/10) ;
          name ; logger }

    let update_macs t src ins =
        match BitHash.find_option t.macs_h src with
        | None ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "New mac %s" (Eth.Addr.to_string (Eth.Addr.o src))))) ;
            let last_idx = OrdArray.last t.macs in
            let last = OrdArray.get t.macs last_idx in
            (match last.addr with None -> () | Some addr ->
                (* This MAC which has not been used for long leaves the switch
                 * memory: *)
                BitHash.remove t.macs_h (addr :> bitstring)) ;
            last.addr <- Some (Eth.Addr.o src) ;
            last.port <- ins ;
            BitHash.add t.macs_h src last_idx ;
            OrdArray.promote t.macs last_idx
        | Some n ->
            let mac = OrdArray.get t.macs n in
            if mac.port <> ins then (
                Log.(log t.logger Debug (lazy (Printf.sprintf "Host %s changed from port %d to %d" (Eth.Addr.to_string (Eth.Addr.o src)) mac.port ins))) ;
                mac.port <- ins
            ) ;
            OrdArray.promote t.macs n

    let forward_from t ins bits = match%bitstring bits with
        | {| dst : 6*8 : bitstring ;
             src : 6*8 : bitstring |} ->
            (* update mac table for source (before forwarding!) *)
            update_macs t src ins ;
            (* TODO: addresses reserved by 802.1d should not be forwarded. *)
            (* now forward *)
            let do_broadcast () =
                Log.(log t.logger Debug (lazy (Printf.sprintf "Forwarding to all ports"))) ;
                R.forward_from t.hub ins bits in
            if Eth.Addr.is_broadcast (Eth.Addr.o dst) then
                do_broadcast ()
            else (
                match BitHash.find_option t.macs_h dst with
                | None ->
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Unknown dest %s, broadcasting" (Eth.Addr.to_string (Eth.Addr.o dst))))) ;
                    do_broadcast ()
                | Some n ->
                    let mac = OrdArray.get t.macs n in
                    Log.(log t.logger Debug (lazy (Printf.sprintf "Known dest %s, will forward to port %d" (Eth.Addr.to_string (Eth.Addr.o dst)) mac.port))) ;
                    Clock.asap t.hub.Repeater.ports.(mac.port) bits ;
                    OrdArray.promote t.macs n)
        | {| _ |} ->
            Log.(log t.logger Debug (lazy (Printf.sprintf "Drop incoming frame without destination")))

    let write t n pld =
        Log.(log t.logger Debug (lazy (Printf.sprintf "Rx from port %d/%d" n (Array.length t.hub.ports)))) ;
        forward_from t n pld

    let set_read t n f =
        Log.(log t.logger Debug (lazy (Printf.sprintf "Setting emitter for port %d/%d" n (Array.length t.hub.ports)))) ;
        Repeater.set_read t.hub n f

    (** Turns a port into a device *)
    let port t n =
        { write = write t n ; set_read = set_read t n }

    let first_free_port t =
        R.first_free_port t.hub
end

(** A Tap is a 2 port repeater which mirror each packet to a user function.
  It can be used as a transparent TRX. *)
module Tap =
struct
    type t = trx

    let make mirror =
        let emit_ins = ref ignore_bits
        and emit_out = ref ignore_bits in
        { ins = { write = (fun bits -> mirror bits ; !emit_out bits) ;
                  set_read = fun f -> emit_ins := f } ;
          out = { write = (fun bits -> mirror bits ; !emit_ins bits) ;
                  set_read = fun f -> emit_out := f } }

end
