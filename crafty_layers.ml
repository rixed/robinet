(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(* Copyright 2026, Cedric Cellier
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
(** The protocol layers crafty knows of: what the parser, the typer, the tree
   of parsers and the packet generator all read from.

   Names of layers, fields and constants are case insensitive. Constants are
   reserved names, valid anywhere, as are the layers. *)
open Batteries
open Crafty_ast

(** A layer is either crafted packet by packet ([Manual], written with a
 * bang), or left to a robinet TRX that drives a whole stream ([Driven]). *)
type mode = Manual | Driven

let string_of_mode = function Manual -> "manual" | Driven -> "self-driven"

type field =
    { name : string ;
      typ : Type.t ;
      (* The modes in which the field can be given as an option, and those in
       * which a condition can read it. Some are read only (computed or
       * virtual, such as [is_fragment]), and some are options of a TRX that
       * are not header fields (such as TCP's [mss]): *)
      set_in : mode list ;
      read_in : mode list ;
      (* Whether it tells streams apart, which the tree of parsers keys its
       * nodes on: *)
      discriminant : bool }

type layer =
    { name : string ;
      (* The layers it can be on top of, by name; none for the root: *)
      above : string list ;
      (* Whether it has a self-driven mode distinct from the manual one; for
       * those that have not, a bang is ignored and they behave manually: *)
      driven : bool ;
      (* Whether nothing can be on top of it. Emitting a terminal layer is
       * what sends packets: *)
      terminal : bool ;
      fields : field array ;
      (* The index of the field that a lone option, or a lone condition that
       * is not a boolean, is about ([Bytes("x")]): *)
      default_field : int option ;
      (* The constants for its fields ([flags & RST]): *)
      constants : (string * literal) list }

let field ?(set_in=[ Manual ]) ?(read_in=[ Manual ]) ?(discriminant=false)
          name typ =
    { name ; typ ; set_in ; read_in ; discriminant }

let both = [ Manual ; Driven ]

let layer ?(above=[]) ?(driven=false) ?(terminal=false) ?default
          ?(constants=[]) name fields =
    let fields = Array.of_list fields in
    let default_field =
        Option.map (fun d ->
            try Array.findi (fun (f : field) -> f.name = d) fields
            with Not_found ->
                invalid_arg ("Crafty_layers: no field "^ d ^" in "^ name)
        ) default in
    { name ; above ; driven ; terminal ; fields ; default_field ; constants }

let eth =
    layer "Eth" ~driven:true [
        field "src" Type.Mac ~read_in:both ;
        field "dst" Type.Mac ~read_in:both ;
        field "proto" Type.Int ~read_in:both ~discriminant:true ]

let ip =
    layer "IP" ~above:[ "eth" ] ~driven:true [
        field "src" Type.Ip ~set_in:both ~read_in:both ~discriminant:true ;
        field "dst" Type.Ip ~set_in:both ~read_in:both ~discriminant:true ;
        field "proto" Type.Int ~read_in:both ~discriminant:true ;
        field "tos" Type.Int ~set_in:both ~read_in:both ;
        field "ttl" Type.Int ~set_in:both ~read_in:both ;
        field "dont_frag" Type.Bool ~set_in:both ~read_in:both ;
        field "id" Type.Int ;
        field "more_frags" Type.Bool ;
        field "frag_offset" Type.Int ;
        field "tot_len" Type.Int ;
        field "options" Type.bytes ;
        field "is_fragment" Type.Bool ~set_in:[] ]

let tcp =
    layer "TCP" ~above:[ "ip" ] ~driven:true
        ~constants:[ "FIN", Int 1 ; "SYN", Int 2 ; "RST", Int 4 ; "PSH", Int 8 ;
                     "ACK", Int 16 ; "URG", Int 32 ] [
        field "src" Type.Int ~set_in:both ~read_in:both ~discriminant:true ;
        field "dst" Type.Int ~set_in:both ~read_in:both ~discriminant:true ;
        field "seq_num" Type.Int ;
        field "ack_num" Type.Int ;
        field "flags" Type.Int ;
        field "win_size" Type.Int ;
        field "urg_ptr" Type.Int ;
        field "mss" Type.Int ~set_in:[ Driven ] ~read_in:[] ]

let udp =
    layer "UDP" ~above:[ "ip" ] [
        field "src" Type.Int ~discriminant:true ;
        field "dst" Type.Int ~discriminant:true ;
        field "length" Type.Int ;
        field "checksum" Type.Int ]

(* The kind of message is told by the layer on top of it: *)
let icmp =
    layer "ICMP" ~above:[ "ip" ] [
        field "type" Type.Int ~set_in:[] ;
        field "code" Type.Int ~set_in:[] ]

let echo name =
    layer name ~above:[ "icmp" ] ~terminal:true ~default:"payload" [
        field "id" Type.Int ~discriminant:true ;
        field "seq" Type.Int ;
        field "payload" Type.bytes ]

(* Whose payload is the beginning of the packet that caused it, kept as
 * bytes: *)
let icmp_error name codes ~mtu =
    layer name ~above:[ "icmp" ] ~terminal:true
        ~constants:(List.map (fun (n, c) -> n, Int c) codes) (
        field "code" Type.Int ::
        (if mtu then [ field "mtu" Type.Int ] else []) @
        [ field "payload" Type.bytes ])

let dest_unreachable =
    icmp_error "DestUnreachable" ~mtu:true Icmp.Unreachable.[
        "NET_UNREACHABLE", network ; "HOST_UNREACHABLE", host ;
        "PROTOCOL_UNREACHABLE", protocol ; "PORT_UNREACHABLE", port ;
        "FRAG_NEEDED", fragmentation_needed ;
        "SOURCE_ROUTE_FAILED", source_route_failed ]

let time_exceeded =
    icmp_error "TimeExceeded" ~mtu:false
        [ "TTL_EXCEEDED", 0 ; "REASSEMBLY_TIMEOUT", 1 ]

(* What is carried by a layer that is not decoded any further: *)
let bytes =
    layer "Bytes" ~above:[ "eth" ; "ip" ; "tcp" ; "udp" ] ~terminal:true
        ~default:"data" [ field "data" Type.bytes ]

let all =
    [ eth ; ip ; tcp ; udp ; icmp ; echo "EchoRequest" ; echo "EchoReply" ;
      dest_unreachable ; time_exceeded ; bytes ]

let same_name a b = String.lowercase_ascii a = String.lowercase_ascii b

(** All the names of layers, in lower case. *)
let names =
    List.map (fun (l : layer) -> String.lowercase_ascii l.name) all |>
    List.unique

let is_layer name = List.mem (String.lowercase_ascii name) names

(** The layer of that name that can be on top of [below], or that is the
 * root if no [below]. *)
let find ?below name =
    List.find_opt (fun (l : layer) ->
        same_name l.name name &&
        match below with
        | None -> l.above = []
        | Some (b : layer) -> List.exists (same_name b.name) l.above) all

(** The layers that can be on top of [l]. *)
let uppers (l : layer) =
    List.filter (fun (u : layer) -> List.exists (same_name l.name) u.above) all

let root = eth

(** The index of that field of [l]. *)
let find_field (l : layer) name =
    try Some (Array.findi (fun (f : field) -> same_name f.name name) l.fields)
    with Not_found -> None

(** All the constants, of all the layers. *)
let constants = List.concat_map (fun (l : layer) -> l.constants) all

(** The value of that constant. *)
let find_constant name =
    List.find_opt (fun (n, _) -> same_name n name) constants |>
    Option.map snd

(** The mode a layer runs in when written with a bang or not. *)
let mode_of (l : layer) ~bang =
    if bang || not l.driven then Manual else Driven

(** The record of the fields of [l] that can be read in [mode], as found in a
 * matched packet. *)
let record_type (l : layer) mode =
    Type.Record (Array.to_list l.fields |> List.filter_map (fun (f : field) ->
        if List.mem mode f.read_in then Some (f.name, f.typ) else None))

(*$T find
  (find "eth" |> Option.map (fun (l : layer) -> l.name)) = Some "Eth"
  find "IP" = None
  (find ~below:eth "ip" |> Option.map (fun (l : layer) -> l.name)) = Some "IP"
  (find ~below:icmp "echoREQUEST" |> Option.map (fun (l : layer) -> l.name)) = \
    Some "EchoRequest"
  find ~below:udp "EchoRequest" = None
  find ~below:tcp "Bytes" <> None
  find ~below:bytes "Bytes" = None
*)
(*$T find_field
  find_field bytes "DATA" = Some 0
  find_field tcp "mss" = Some 7
  find_field tcp "payload" = None
*)
(* Defaults are found by name: *)
(*$T
  bytes.default_field = Some 0
  (echo "EchoRequest").default_field = Some 2
  tcp.default_field = None
*)
(*$T find_constant
  find_constant "rst" = Some (Crafty_ast.Int 4)
  find_constant "port_unreachable" = Some (Crafty_ast.Int 3)
  find_constant "src" = None
*)
(*$= record_type & ~printer:Crafty_ast.Type.to_string
  (Crafty_ast.Type.Record [ "src", Crafty_ast.Type.Int ; "dst", Crafty_ast.Type.Int ]) (record_type tcp Driven)
  (Crafty_ast.Type.Record [ "data", Crafty_ast.Type.bytes ]) (record_type bytes Manual)
*)
(* The registry holds together: *)
(*$T
  List.for_all (fun (l : layer) -> \
      List.for_all (fun b -> is_layer b) l.above) all
  List.for_all (fun (l : layer) -> \
      l.terminal = (uppers l = [])) all
  List.length (List.filter (fun (l : layer) -> l.above = []) all) = 1
  List.for_all (fun (l : layer) -> \
      l.driven || List.for_all (fun (f : field) -> \
        not (List.mem Driven f.set_in) && not (List.mem Driven f.read_in)) \
        (Array.to_list l.fields)) all
  List.for_all (fun (l : layer) -> \
      let names = List.map (fun (f : field) -> String.lowercase_ascii f.name) \
                      (Array.to_list l.fields) in \
      List.length (List.unique names) = List.length names) all
  List.for_all (fun (l : layer) -> List.for_all (fun (b : layer) -> \
      l == b || not (same_name l.name b.name) || \
      List.for_all (fun a -> not (List.exists (same_name a) b.above)) l.above) all) all
*)
(* Constants are names of their own, apart from any other: *)
(*$T
  let names = List.map (fun (n, _) -> String.lowercase_ascii n) constants in \
  List.length (List.unique names) = List.length names && \
  List.for_all (fun n -> \
      not (is_layer n) && \
      not (List.mem n Crafty_ast.(keywords @ unsupported @ functions @ predefined)) && \
      List.for_all (fun (l : layer) -> find_field l n = None) all) names
*)
