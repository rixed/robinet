(* vim:sw=4 ts=4 sts=4 expandtab
*)
open Batteries
open Tools

let debug = false

(* A HUB is a device that receives Eth frames and blindly mirrors them to several locations
   (but the one from which the frame came from) *)
module Repeater =
struct
    type port = { mutable emit : payload -> unit }
    type t = { ports : port array }

    let make n = { ports = Array.init n (fun _ -> { emit = ignore }) }

    let forward_from n t pld =
        Array.iteri (fun i port ->
            if i <> n then (
                if debug then Printf.printf "Repeater:...fwd to port %d\n%!" i ;
                port.emit pld
            )) t.ports

    let rx n t pld =
        if debug then Printf.printf "Repeater: rx from port %d\n%!" n ;
        forward_from n t pld

    let set_emit n t emit =
        if debug then Printf.printf "Repeater: setting emitter for port %d\n%!" n ;
        t.ports.(n).emit <- emit

    let t_printer _paren oc t =
        Printf.fprintf oc "%d" (Array.length t.ports)

end

module Switch =
struct
    module R = Repeater

    module OrdArray =
    struct
        type entry = { mutable prev : int ; mutable next : int }
        type t =
            { arr   : entry array ;
              mutable first : int ;
              mutable last  : int }

        let make s =
            { arr = Array.init s (fun i ->
                { prev = if i = 0 then -1 else i-1 ;
                  next = if i = s-1 then -1 else i+1 }) ;
              first = 0 ;
              last = s-1 }

        let remove t n =
            if t.arr.(n).prev <> -1 then t.arr.(t.arr.(n).prev).next <- t.arr.(n).next ;
            if t.arr.(n).next <> -1 then t.arr.(t.arr.(n).next).prev <- t.arr.(n).prev ;
            if t.first = n then t.first <- t.arr.(n).next ;
            if t.last = n then t.last <- t.arr.(n).prev
        
        (* n was already removed! *)
        let add_head t n =
            t.arr.(n).prev <- -1 ;
            t.arr.(n).next <- t.first ;
            t.arr.(t.first).prev <- n ;
            t.first <- n

        let promote t n =
            remove t n ;
            add_head t n
    end

    type mac_entry =
        { mutable addr : Eth.addr option ;
          mutable port : int }

    type t =
        { hub  : R.t ;
          macs : mac_entry array ;
          last_used : OrdArray.t ;
          macs_h : int BitHash.t }

    let make nb_ports nb_macs =
        { hub = R.make nb_ports ;
          macs = Array.init nb_macs (fun _ -> { addr = None ; port = 0 }) ;
          last_used = OrdArray.make nb_macs ;
          macs_h = BitHash.create (nb_macs/10) }

    let forward_from inp t bits = bitmatch bits with
        | { dst : 6*8 : bitstring ;
            src : 6*8 : bitstring } ->
            (* forward *)
            (match BitHash.find_option t.macs_h dst with
            | None ->
                if debug then Printf.printf "Switch: unknown dest %s broadcasting\n%!"
                    (Eth.string_of_addr dst) ;
                R.forward_from inp t.hub bits
            | Some n ->
                t.hub.Repeater.ports.(t.macs.(n).port).Repeater.emit bits ;
                (* promote in last_used *)
                OrdArray.promote t.last_used n) ;
            (* update mac table *)
            (match BitHash.find_option t.macs_h src with
            | None ->
                if debug then Printf.printf "Switch: new mac %s\n%!" (Eth.string_of_addr src) ;
                let last = t.last_used.OrdArray.last in
                (match t.macs.(last).addr with None -> () | Some addr ->
                    BitHash.remove t.macs_h addr) ;
                t.macs.(last).addr <- Some src ;
                t.macs.(last).port <- inp ;
                BitHash.add t.macs_h src last ;
                OrdArray.promote t.last_used last
            | Some n ->
                if t.macs.(n).port <> inp then (
                    if debug then Printf.printf "Switch: host %s changed from port %d to %d\n"
                        (Eth.string_of_addr src) n inp ;
                    t.macs.(n).port <- inp
                ) ;
                OrdArray.promote t.last_used n)
        | { _ } ->
            if debug then Printf.printf "Switch: drop incoming frame without destonator\n%!"

    let rx n t pld =
        if debug then Printf.printf "Switch: rx from port %d\n%!" n ;
        forward_from n t pld

    let set_emit n t emit =
        if debug then Printf.printf "Switch: setting emitter for port %d\n%!" n ;
        Repeater.set_emit n t.hub emit
end
