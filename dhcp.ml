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

(* Opcodes, types, etc *)

let bootrequest = 1
let bootreply = 2
type opcode = BootRequest | BootReply

module MsgType = struct
    module Inner = struct
        type t = int
        let to_string = function
            | 1 -> "DISCOVER"
            | 2 -> "OFFER"
            | 3 -> "REQUEST"
            | 4 -> "DECLINE"
            | 5 -> "ACK"
            | 6 -> "NACK"
            | 7 -> "RELEASE"
            | 8 -> "INFORM"
            | _ -> should_not_happen ()
        let is_valid x = x >= 1 && x <= 8
        let repl_tag = "code"
    end
    include MakePrivate(Inner)

    let discover = o 1
    let offer    = o 2
    let request  = o 3
    let decline  = o 4
    let ack      = o 5
    let nack     = o 6
    let release  = o 7
    let inform   = o 8

    let rec random () =
        let p = randi 3 + 1 in
        if Inner.is_valid p then p else random ()
end

(* DHCP messages *)

module Pdu =
struct
    (*$< Pdu *)
    type t =
        { op : opcode ;
          htype : Arp.HwType.t ;
          hlen : int ; hops : int ;
          xid : int32 ;
          secs : int ; broadcast : bool ;
          ciaddr : Ip.Addr.t ; yiaddr : Ip.Addr.t ;
          siaddr : Ip.Addr.t ; giaddr : Ip.Addr.t ;
          chaddr : bitstring ;
          sname : string ;
          file : string ;
          (* Bootp options *)
          mutable msg_type : MsgType.t option ;
          mutable subnet_mask : Ip.Addr.t option ;
          mutable router : Ip.Addr.t option ;
          mutable ntp_server : Ip.Addr.t option ;
          mutable smtp_server : Ip.Addr.t option ;
          mutable pop3_server : Ip.Addr.t option ;
          mutable name_server : Ip.Addr.t option ;
          mutable client_name : string option ;
          mutable search_sfx : string option ;
          mutable lease_time : int32 option ; (* in seconds *)
          mutable server_id : Ip.Addr.t option ;
          mutable requested_ip : Ip.Addr.t option ;
          mutable message : string option ;
          mutable client_id : bitstring option ;
          mutable request_list : string option }

    let rec unpack_options t bits = bitmatch bits with
        | { 0 : 8 ;
            rest : -1 : bitstring } -> unpack_options t rest
        | { 255 : 8 } -> true
        | { 1 : 8 ; 4 : 8 ; subnet_mask : 32 ;
            rest : -1 : bitstring } ->
            t.subnet_mask <- Some (Ip.Addr.o subnet_mask) ;
            unpack_options t rest
        | { 3 : 8 ; len : 8 : check (len >= 4) ; ips : 8*len : bitstring ;
            rest : -1 : bitstring } ->
            t.router <- Some (Ip.Addr.of_bitstring (takebits 32 ips)) ;
            unpack_options t rest
        | { 42 : 8 ; len : 8 : check (len >= 4) ; ips : 8*len : bitstring ;
            rest : -1 : bitstring } ->
            t.ntp_server <- Some (Ip.Addr.of_bitstring (takebits 32 ips)) ;
            unpack_options t rest
        | { 69 : 8 ; len : 8 : check (len >= 4 && len land 3 = 0) ; ips : 8*len : bitstring ;
            rest : -1 : bitstring } ->
            t.smtp_server <- Some (Ip.Addr.of_bitstring (takebits 32 ips)) ;
            unpack_options t rest
        | { 70 : 8 ; len : 8 : check (len >= 4 && len land 3 = 0) ; ips : 8*len : bitstring ;
            rest : -1 : bitstring } ->
            t.pop3_server <- Some (Ip.Addr.of_bitstring (takebits 32 ips)) ;
            unpack_options t rest
        | { 6 : 8 ; len : 8 : check (len >= 4) ; ips : 8*len : bitstring ;
            rest : -1 : bitstring } ->
            t.name_server <- Some (Ip.Addr.of_bitstring (takebits 32 ips)) ;
            unpack_options t rest
        | { 12 : 8 ; len : 8 : check (len >= 1) ; name : 8*len : string ;
            rest : -1 : bitstring } ->
            t.client_name <- Some name ;
            unpack_options t rest
        | { 15 : 8 ; len : 8 : check (len >= 1) ; sfx : 8*len : string ;
            rest : -1 : bitstring } ->
            t.search_sfx <- Some sfx ;
            unpack_options t rest
        | { 50 : 8 ; 4 : 8 ; req_ip : 32 ;
            rest : -1 : bitstring } ->
            t.requested_ip <- Some (Ip.Addr.o req_ip) ;
            unpack_options t rest
        | { 51 : 8 ; 4 : 8 ; lease : 32 ;
            rest : -1 : bitstring } ->
            t.lease_time <- Some lease ;
            unpack_options t rest
        | { 53 : 8 ; 1 : 8 ; msg_type : 8 : check (msg_type > 0 && msg_type < 9) ;
            rest : -1 : bitstring } ->
            t.msg_type <- Some (MsgType.o msg_type) ;
            unpack_options t rest
        | { 54 : 8 ; 4 : 8 ; ip : 32 ;
            rest : -1 : bitstring } ->
            t.server_id <- Some (Ip.Addr.o ip) ;
            unpack_options t rest
        | { 55 : 8 ; len : 8 : check (len > 0) ; params : 8*len : string ;
            rest : -1 : bitstring } ->
            t.request_list <- Some params ;
            unpack_options t rest
        | { 56 : 8 ; len : 8 : check (len > 0) ; msg : 8*len : string ;
            rest : -1 : bitstring } ->
            t.message <- Some msg ;
            unpack_options t rest
        | { 61 : 8 ; len : 8 : check (len >= 2) ; id : 8*len : bitstring ;
            rest : -1 : bitstring } ->
            t.client_id <- Some id ;
            unpack_options t rest
        (* FIXME: IP Layer parameters setting could be interresting to get/set via DHCP.
           At least netmask *)
        (* FIXME: handle option overload of file/sname fields with more options *)
        | { _ : 8 ; len : 8 ; _ : 8*len ; rest : -1 : bitstring } ->
            unpack_options t rest
        | { _ } -> false

    let unpack bits = bitmatch bits with
        | { op : 8 : check (op = bootrequest || op = bootreply) ;
            htype : 8 ; hlen : 8 ; hops : 8 ;
            xid : 32 ; secs : 16 ;
            flags : 16 : check (flags land 0x7fff = 0) ;
            ciaddr : 32 : bitstring ;
            yiaddr : 32 : bitstring ;
            siaddr : 32 : bitstring ;
            giaddr : 32 : bitstring ;
            chaddr : 16*8 : bitstring ;
            sname : 64*8 : string ;
            file : 128*8 : string ;
            0x63825363l : 32 ;
            options : -1 : bitstring } ->
          let t = { op = if op = bootrequest then BootRequest else BootReply ;
                    htype = Arp.HwType.o htype ; hlen ; hops ; xid ;
                    secs ; broadcast = flags land 0x8000 = 0x8000 ;
                    ciaddr = Ip.Addr.of_bitstring ciaddr ;
                    yiaddr = Ip.Addr.of_bitstring yiaddr ;
                    siaddr = Ip.Addr.of_bitstring siaddr ;
                    giaddr = Ip.Addr.of_bitstring giaddr ;
                    chaddr = takebytes hlen chaddr ; sname ; file ;
                    subnet_mask = None ;
                    router = None ;
                    ntp_server = None ;
                    smtp_server = None ;
                    pop3_server = None ;
                    name_server = None ;
                    client_name = None ;
                    search_sfx = None ;
                    lease_time = None ;
                    msg_type = None ;
                    server_id = None ;
                    requested_ip = None ;
                    message = None ;
                    client_id = None ;
                    request_list = None } in
          if unpack_options t options then Some t
          else err "Dhcp: Cannot decode options"
        | { _ } -> err "Dhcp: Not DHCP"

    let pack_options t =
        let may_pack_msgtyp t v = Option.map (fun (v : MsgType.t) -> (BITSTRING { t : 8 ; 1 : 8 ; (v :> int) : 8 })) v
        and may_pack_int32  t v = Option.map (fun v -> (BITSTRING { t : 8 ; 4 : 8 ; v : 32 })) v
        and may_pack_ip     t v = Option.map (fun (v : Ip.Addr.t) -> (BITSTRING { t : 8 ; 4 : 8 ; (v :> int32) : 32 })) v
        and may_pack_string t v = Option.map (fun v -> (BITSTRING { t : 8 ; String.length v : 8 ; v : -1 : string })) v
        and may_pack_bits   t v = Option.map (fun v -> (BITSTRING { t : 8 ; bytelength v : 8 ; v : -1 : bitstring })) v
        in
        List.enum [ may_pack_msgtyp 53 t.msg_type ;
                    may_pack_ip 1 t.subnet_mask ; (* must apear before router *)
                    may_pack_ip 3 t.router ;
                    may_pack_ip 42 t.ntp_server ;
                    may_pack_ip 69 t.smtp_server ;
                    may_pack_ip 70 t.pop3_server ;
                    may_pack_ip 6 t.name_server ;
                    may_pack_string 12 t.client_name ;
                    may_pack_string 15 t.search_sfx ;
                    may_pack_int32 51 t.lease_time ;
                    may_pack_ip 50 t.requested_ip ;
                    may_pack_ip 54 t.server_id ;
                    may_pack_string 56 t.message ;
                    may_pack_bits 61 t.client_id ;
                    may_pack_string 55 t.request_list ;
                    Some (BITSTRING { 255 : 8 }) ] //@
            identity |>
            List.of_enum |>
            Bitstring.concat

    let pack t =
        let string_extend str len =
            let l = String.length str in
            if l >= len then String.sub str 0 len
            else str ^ (String.make (len-l) (Char.chr 0))
        in
        (BITSTRING {
            match t.op with BootRequest -> 1 | BootReply -> 2 : 8 ;
            (t.htype :> int) : 8 ; t.hlen : 8 ; t.hops : 8 ;
            t.xid : 32 ;
            t.secs : 16 ; if t.broadcast then 0x8000 else 0 : 16 ;
            Ip.Addr.to_bitstring t.ciaddr : -1 : bitstring ;
            Ip.Addr.to_bitstring t.yiaddr : -1 : bitstring ;
            Ip.Addr.to_bitstring t.siaddr : -1 : bitstring ;
            Ip.Addr.to_bitstring t.giaddr : -1 : bitstring ;
            extendbytes 16 t.chaddr : -1 : bitstring ;
            string_extend t.sname 64 : 64*8 : string ;
            string_extend t.file 128 : 128*8 : string ;
            0x63825363l : 32 ;
            pack_options t : -1 : bitstring })

    let make_base ?(mac=Eth.Addr.zero) ?xid ?name ?(yiaddr=Ip.Addr.zero) msg_type =
        let xid = may_default xid (fun () -> Random.int32 Int32.max_int) in
        { op = BootRequest ;
          htype = Arp.HwType.eth ;
          hlen = 6 ; hops = 0 ;
          xid ;
          secs = 0 ; broadcast = false ;
          ciaddr = Ip.Addr.zero ;
          yiaddr ;
          siaddr = Ip.Addr.zero ;
          giaddr = Ip.Addr.zero ;
          chaddr = extendbytes 16 (mac :> bitstring) ;
          sname = "" ; file = "" ;
          msg_type = Some msg_type ;
          subnet_mask = None ; router = None ;
          ntp_server = None ; smtp_server = None ;
          pop3_server = None ; name_server = None ;
          client_name = name ; requested_ip = None ;
          search_sfx = None ; lease_time = None ;
          server_id = None ; message = None ;
          client_id = None ; request_list = None }

    let make_discover ?(mac=Eth.Addr.zero) ?xid ?name () =
        let t = make_base ~mac ?xid ?name MsgType.discover in
        t.client_id <- Some (BITSTRING {
            (Arp.HwType.eth :> int) : 8 ;
            (mac :> bitstring) : 6*8 : bitstring }) ;
        t.request_list <- Some "\001\003\006\012\015\028\051\058\119" ;
        t

    let make_offer ?(mac=Eth.Addr.zero) ?xid yiaddr client_id =
        let t = make_base ~mac ?xid ~yiaddr MsgType.offer in
        t.client_id <- client_id ;
        t

    let make_request ?(mac=Eth.Addr.zero) ?xid ?name yiaddr server_id =
        let t = make_base ~mac ?xid ?name MsgType.request in
        t.client_id <- Some (BITSTRING {
            (Arp.HwType.eth :> int) : 8 ;
            (mac :> bitstring) : 6*8 : bitstring }) ;
        t.request_list <- Some "\001\003\006\012\015\028\051\058\119" ;
        t.requested_ip <- Some yiaddr ;
        t.server_id <- server_id ;
        t

    let make_ack ?(mac=Eth.Addr.zero) ?xid yiaddr client_id =
        let t = make_base ~mac ?xid ~yiaddr MsgType.ack in
        t.client_id <- client_id ;
        t

    let random () =
        let xid = rand32 () and name = randstr 8 in
        if randb () then
            make_discover ~xid ~name ()
        else
            make_request ~xid ~name (Ip.Addr.random ()) (if randb () then Some (Ip.Addr.random ()) else None)

    (*$Q pack
      ((random |- pack), dump) (fun t -> t = pack (Option.get (unpack t)))
     *)
    (*$>*)

end
