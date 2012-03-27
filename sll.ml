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
open Batteries
open Bitstring
open Tools

let debug = false

(* Linux Cooked Capture frames *)

module Pdu = struct
    (*$< Pdu *)
    type pkt_type = UnicastIn | BroadcastIn | MulticastIn | OutToOut | SentByUs
    let pkt_type_of_int = function
        | 0 -> UnicastIn | 1 -> BroadcastIn | 2 -> MulticastIn | 3 -> OutToOut | 4 -> SentByUs
        | _ -> error "Invalid SLL packet type"
    let int_of_pkt_type = function
        | UnicastIn -> 0 | BroadcastIn -> 1 | MulticastIn -> 2 | OutToOut -> 3 | SentByUs -> 4
    type t = { pkt_type     : pkt_type ;
               ll_addr_type : int ;
               ll_addr      : bitstring ;
               proto        : Arp.HwProto.t ;
               payload      : Payload.t }

    let make ?(ll_addr_type=1) pkt_type proto ll_addr payload =
        { pkt_type ; ll_addr_type ; ll_addr ; proto ; payload }

    let random () =
        let pkt_type = pkt_type_of_int (Random.int 5) in
        make pkt_type (Arp.HwProto.random ()) (Eth.Addr.random () :> bitstring) (Payload.random 30)

    let pack t =
        concat [ (BITSTRING {
                    int_of_pkt_type t.pkt_type : 16 ;
                    t.ll_addr_type : 16 ;
                    bytelength t.ll_addr : 16 ;
                    fixedbits 64 t.ll_addr : 64 : bitstring ;
                    (t.proto :> int) : 16 }) ;
                 (t.payload :> bitstring) ]

    let unpack bits = bitmatch bits with
        | { pkt_type : 16 ;
            ll_addr_type : 16 ;
            ll_addr_len : 16 ;
            ll_addr : min 64 (ll_addr_len*8) : bitstring ;
            _zeroes : if ll_addr_len*8 >= 64 then 0 else 64-ll_addr_len*8 : bitstring ;
            proto : 16 ;
            payload : -1 : bitstring } when pkt_type >= 0 && pkt_type <= 4 ->
            Some { pkt_type = pkt_type_of_int pkt_type ;
                   ll_addr_type ; ll_addr ;
                   proto = Arp.HwProto.o proto ;
                   payload = Payload.o payload }
        | { _ } ->
            err "Not SLL"

    (*$Q pack
      ((random |- pack), dump) (fun t -> t = pack (Option.get (unpack t)))
     *)
    (*$>*)
end

