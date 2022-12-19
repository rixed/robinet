(* vim:sw=2 ts=2 sts=2 expandtab spell spelllang=en
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
  Wrap traffic (aka bytes) into some form of tunnel, such as a socket, a
  protocol stack, message queue messages, whatever... Each wrapper returns a
  [Tools.trx], aka can send and receive data after a transformation.
  The objective is to make it possible to have a traffic generator on one hand
  and plug it into a wrapper, both being configured independently, and have
  the wrapper easy to specify in a serializable form.
  *)
open Batteries
open Tools

type wrapper_spec =
  | Trxs of trx_wrapper list (* lowest level protocol at the list's head *)
  | Socket of socket_wrapper
(*| Kafka
  | PgSql *)

and trx_wrapper =
  (* Optional parameters are inferred from the rest of the stack.
   * As much as we'd like to have proto and my_addresses fully automatic
   * all the time, this is not possible when the last layer is not specified ;
   * for instance in an Eth tunnel when the generator outputs IP packets. *)
  | Eth of { mutable mtu : int option ; delay : float ; loss : float ;
             src : string ; mutable proto : string option ;
             mutable my_addresses : string list option }
  | Ip of { mutable mtu : int option ; src : string ; dst : string ;
            mutable proto : string option }
  | Ip6 of { src : string ; dst : string ; mutable proto : string option }
  | Udp of { src : int option ; dst : int }
  | Tcp of { src : int option ; dst : int ; mutable isn : int option ;
             mutable mtu : int option }
  (* TODO: HTTP Posts *)

and socket_wrapper =
  { dgram : bool ; dst : string ; dst_port : int ; src_port : int option }

(* We want to be able to turn a string description of a wrapper into an actual
 * TRX.
 * All wrappers are specified with: "name(p1=v1, p2=v2,...)" *)

exception MissingParam of { cmd : string ; param : string }

let () =
  Printexc.register_printer (function
    | MissingParam { cmd ; param } ->
        Some (Printf.sprintf "Missing parameter for command %s: %s" cmd param)
    | _ ->
        None)

let get cmd params n =
  try List.assoc n params
  with Not_found -> raise (MissingParam { cmd ; param = n })

let get_opt params n =
  try Some (List.assoc n params)
  with Not_found -> None

let get_i cmd params n =
  get cmd params n |> int_of_string

let get_b cmd params n =
  get cmd params n |> bool_of_string

let get_opt_i params n =
  get_opt params n |> Option.map int_of_string

let get_opt_f params n =
  get_opt params n |> Option.map float_of_string

module Trx =
struct
  let eth_of_string params =
    let mtu = get_opt_i params "mtu"
    and delay = get_opt_f params "delay" |? 0.
    and loss = get_opt_f params "loss" |? 0.
    and src = get "eth" params "src"
    and proto = get_opt params "proto"
    and my_addresses =
      get_opt params "my_addresses" |>
      Option.map (String.split_on_char ':')
    in
    Eth { mtu ; delay ; loss ; src ; proto ; my_addresses }

  let ip_of_string params =
    let mtu = get_opt_i params "mtu"
    and src = get "ip" params "src"
    and dst = get "ip" params "dst"
    and proto = get_opt params "proto"
    in
    Ip { mtu ; src ; dst ; proto }

  let ip6_of_string params =
    let src = get "ip6" params "src"
    and dst = get "ip6" params "dst"
    and proto = get_opt params "proto"
    in
    Ip6 { src ; dst ; proto }

  let udp_of_string params =
    let src = get_opt_i params "src"
    and dst = get_i "udp" params "dst"
    in
    Udp { src ; dst }

  let tcp_of_string params =
    let mtu = get_opt_i params "mtu"
    and src = get_opt_i params "src"
    and dst = get_i "tcp" params "dst"
    and isn = get_opt_i params "isn"
    in
    Tcp { mtu ; src ; dst ; isn }

end

module Socket =
struct
  let of_string params =
    let dgram = get_b "socket" params "dgram"
    and dst = get "socket" params "dst"
    and dst_port = get_i "socket" params "dst_port"
    and src_port = get_opt_i params "src_port"
    in
    { dgram ; dst ; dst_port ; src_port }
end

let of_string s =
  let parse_layer s =
    let len = String.length s in
    if s.[len-1] = ')' then
      match String.split s ~by:"(" with
      | exception Not_found ->
          invalid_arg "of_string: cannot parse parentheses"
      | name, params ->
          let params = String.rchop params in (* get rid of the final ")" *)
          let params = String.split_on_char ',' params in
          let params =
            List.map (fun p ->
              match String.split ~by:"=" p with
              | exception Not_found ->
                  invalid_arg ("of_string: cannot parse param "^ p)
              | n, v ->
                  String.trim n, String.trim v
            ) params in
          String.lowercase_ascii name, params
    else
      s, []
  and trx_of name params =
    match name with
    | "eth" ->
        Trx.eth_of_string params
    | "ip" ->
        Trx.ip_of_string params
    | "ip6" ->
        Trx.ip6_of_string params
    | "udp" ->
        Trx.udp_of_string params
    | "tcp" ->
        Trx.tcp_of_string params
    | _ ->
        invalid_arg ("of_string: unknown name "^ name)
  and max_mtu layers =
    List.fold_left (fun mtu -> function
      | Eth eth -> max_opt mtu eth.mtu
      | Ip ip -> max_opt mtu ip.mtu
      | Tcp tcp -> max_opt mtu tcp.mtu
      | _ -> mtu
    ) None layers
  and first_proto layers =
    let rec loop = function
      | [] -> None
      | Ip _ :: _ -> Some Arp.HwProto.(to_string ip4)
      | Ip6 _ :: _ -> Some Arp.HwProto.(to_string ip6)
      | Udp _ :: _ -> Some Ip.Proto.(to_string udp)
      | Tcp _ :: _ -> Some Ip.Proto.(to_string tcp)
      | _ :: rest -> loop rest in
    loop layers
  and all_addresses layers =
    List.fold_left (fun prev -> function
      | Eth eth -> eth.src :: prev
      | Ip ip -> ip.src :: prev
      | Ip6 ip -> ip.src :: prev
      | _ -> prev
    ) [] layers in
  let stack_mtu def layers =
    Some (max_mtu layers |? def)
  in
  let s = String.trim s in
  if String.length s = 0 then
    invalid_arg "of_string: empty string" ;
  let layers = String.split_on_char '/' s in
  match layers with
  | [ single ] ->
      let name, params = parse_layer single in
      if name = "socket" || name = "sock" then
        Socket (Socket.of_string params)
      else
        Trxs [ trx_of name params ]
  | layers ->
      let lst =
        List.map (fun layer ->
          let name, params = parse_layer layer in
          trx_of name params
        ) layers in
      (* Set the various optional parameters that can be inferred from the
       * protocol stack: *)
      let rec loop = function
        | [] ->
            ()
        | Eth eth :: rest ->
            if eth.mtu = None then
              eth.mtu <- stack_mtu 1500 lst ;
            if eth.proto = None then
              eth.proto <- first_proto rest ;
            if eth.my_addresses = None then
              eth.my_addresses <- Some (all_addresses (Eth eth :: rest)) ;
            loop rest
        | Ip ip :: rest ->
            if ip.mtu = None then
              ip.mtu <- stack_mtu (1500 - 20) lst ;
            if ip.proto = None then
              ip.proto <- first_proto rest ;
            loop rest
        | Ip6 ip :: rest ->
            if ip.proto = None then
              ip.proto <- first_proto rest ;
            loop rest
        | _ :: rest ->
            loop rest in
      loop lst ;
      Trxs lst

let to_string =
  let print_trx oc cmd params =
    let params =
      List.filter_map (function
        | _, None ->
            None
        | name, Some v ->
            Some (Printf.sprintf "%s=%s" name v)
      ) params in
    Printf.fprintf oc "%s%a"
      cmd
      (List.print ~first:"(" ~last:")" ~sep:", " String.print) params
  and if_not_none v p =
    match v with
    | None -> None
    | Some v -> Some (IO.to_string p v)
  and if_not_zero v p =
    if v = 0. then None else Some (IO.to_string p v)
  and always v p = Some (IO.to_string p v)
  and my_addr_print =
    List.print ~first:"" ~last:"" ~sep:":" String.print
  in
  function
  | Trxs lst ->
      let trx_print oc = function
        | Eth eth ->
            print_trx oc "eth"
              [ "mtu", if_not_none eth.mtu Int.print ;
                "delay", if_not_zero eth.delay Float.print ;
                "loss", if_not_zero eth.loss Float.print ;
                "src", always eth.src String.print ;
                "proto", if_not_none eth.proto String.print ;
                "my_addresses", if_not_none eth.my_addresses my_addr_print ]
        | Ip ip ->
            print_trx oc "ip"
              [ "mtu", if_not_none ip.mtu Int.print ;
                "src", always ip.src String.print ;
                "dst", always ip.dst String.print ;
                "proto", if_not_none ip.proto String.print ]
        | Ip6 ip ->
            print_trx oc "ip"
              [ "src", always ip.src String.print ;
                "dst", always ip.dst String.print ;
                "proto", if_not_none ip.proto String.print ]
        | Udp udp ->
            print_trx oc "udp"
              [ "src", if_not_none udp.src Int.print ;
                "dst", always udp.dst Int.print ]
        | Tcp tcp ->
            print_trx oc "tcp"
              [ "src", if_not_none tcp.src Int.print ;
                "dst", always tcp.dst Int.print ;
                "isn", if_not_none tcp.isn Int.print ]
      in
      IO.to_string (List.print ~first:"" ~last:"" ~sep:"/" trx_print) lst
  | Socket sock ->
      IO.to_string (fun oc sock ->
        print_trx oc "socket"
          [ "dgram", always sock.dgram Bool.print ;
            "dst", always sock.dst String.print ;
            "dst_port", always sock.dst_port Int.print ;
            "src_port", if_not_none sock.src_port Int.print ]) sock

let to_trx t cont =
  let trx_of_udp_sock _sock =
    todo "trx_of_udp_sock"
  and trx_of_tcp_sock sock =
    let dst = Host.addr_of_string sock.dst
    and src_port = Option.map Tcp.Port.o sock.src_port
    and dst_port = Tcp.Port.o sock.dst_port in
    let tcp_trx =
      Localhost.tcp_connect dst ?src_port dst_port (fun tcp_trx_opt ->
        cont (Option.map (fun tcp_trx -> tcp_trx.Tcp.TRX.trx) tcp_trx_opt)) in
    ignore tcp_trx in
  let trx_of_socket sock =
    if sock.dgram then trx_of_tcp_sock sock else trx_of_udp_sock sock in
  let trx_of_trxs _trxs =
    todo "trx_of_trxs"
  in
  match t with
  | Trxs trxs ->
      trx_of_trxs trxs
  | Socket sock ->
      trx_of_socket sock
