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
  Capabilities that are automatically negotiated when connecting two ports
 *)
open Batteries

module EthSpeed =
struct
    type t =
        | Eth10Mbps
        | Eth100Mbps
        | Eth1Gbps
        | Eth2_5Gbps
        | Eth5Gbps
        | Eth10Gbps
        | Eth25Gbps
        | Eth40Gbps
        | Eth100Gbps
        [@@deriving enum]

    let t_max = max
    let t_min = min

    let max s1 s2 =
        if s1 >= s2 then s1 else s2
end

type t =
    | NoCapabilities (* For when negotiation failed (or has to fail) *)
    | Any (* For ports accepting anything equally well, such as recorder *)
    | Eth of { speeds : EthSpeed.t list ; full_duplex : bool }

let negotiate a b =
    match a, b with
    | NoCapabilities, _ | _, NoCapabilities ->
        NoCapabilities
    | Any, c | c, Any ->
        c
    | Eth a, Eth b ->
        (match List.filter (fun s -> List.mem s b.speeds) a.speeds with
        | [] -> NoCapabilities
        | l -> Eth { speeds = [ List.reduce EthSpeed.max l ] ;
                     full_duplex = a.full_duplex && b.full_duplex })

(*$inject
  open EthSpeed
  let eth ?(full_duplex=true) speeds = Eth { speeds ; full_duplex }
 *)

(* The fastest speed both ends have, and full duplex only if both are up for
 * it. The result is one speed, not a list: what a link runs at. *)
(*$= negotiate & ~printer:dump
  (eth [ Eth100Mbps ]) \
    (negotiate (eth [ Eth10Mbps ; Eth1Gbps ; Eth100Mbps ]) \
               (eth [ Eth100Mbps ; Eth10Mbps ]))
  (eth ~full_duplex:false [ Eth10Mbps ]) \
    (negotiate (eth [ Eth10Mbps ]) \
               (eth ~full_duplex:false [ Eth1Gbps ; Eth10Mbps ]))
  (* Nothing in common is no link, and so is an end that offers nothing. *) \
    NoCapabilities (negotiate (eth [ Eth10Mbps ]) (eth [ Eth1Gbps ]))
  NoCapabilities (negotiate (eth []) (eth [ Eth10Mbps ]))
  (* Whoever has no say takes what the other end offers... *) \
    (eth [ Eth10Mbps ]) (negotiate Any (eth [ Eth10Mbps ]))
  (eth [ Eth10Mbps ]) (negotiate (eth [ Eth10Mbps ]) Any)
  Any (negotiate Any Any)
  (* ...but a failure is a failure, whatever it is met with. *) \
    NoCapabilities (negotiate Any NoCapabilities)
  NoCapabilities (negotiate (eth [ Eth10Mbps ]) NoCapabilities)
 *)

(* Which end asks makes no difference. *)
(*$T negotiate
  let a = eth [ Eth10Mbps ; Eth100Mbps ] \
  and b = eth ~full_duplex:false [ Eth100Mbps ; Eth1Gbps ] in \
  negotiate a b = negotiate b a
  negotiate (eth [ Eth10Mbps ]) (eth [ Eth1Gbps ]) = \
    negotiate (eth [ Eth1Gbps ]) (eth [ Eth10Mbps ])
 *)

(* What two ends settled on, put to either of them again, settles on itself:
 * a link that is renegotiated with nothing changed stays as it is. *)
(*$T negotiate
  let a = eth [ Eth10Mbps ; Eth100Mbps ; Eth1Gbps ] \
  and b = eth ~full_duplex:false [ Eth100Mbps ; Eth10Mbps ] in \
  let c = negotiate a b in \
  negotiate c a = c && negotiate c b = c
 *)
