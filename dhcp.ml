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
(** Dynamic Host Configuration Protocol. *)
open Batteries
open Bitstring
open Tools

let debug = true

(** {2 Opcodes, types, etc} *)

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
    include Private.Make (Inner)

    let discover = o 1
    let offer    = o 2
    let request  = o 3
    let decline  = o 4
    let ack      = o 5
    let nack     = o 6
    let release  = o 7
    let inform   = o 8

    let of_bitstring bits =
        match%bitstring bits with
        | {| v : 8 |} -> o v
        | {| _ |} -> invalid_arg "Dhcp.MsgType.of_bitstring"

    let rec random () =
        let p = randi 3 + 1 in
        if Inner.is_valid p then p else random ()
end


module Option = struct
	type t =
		{ code : int ; min_len : int ; max_len : int option ; name : string }

    let make ?len ?(min_len=0) ?max_len ~name code =
        let min_len, max_len =
            match len with
            | Some l -> l, Some l
            | None -> min_len, max_len in
        { code ; min_len ; max_len ; name }

    let dummy code = make ~name:"dummy" code

	let all_options =
        [| dummy 0 ;
           make ~len:4 ~name:"subnet mask" 1 ;
           make ~len:4 ~name:"time offset" 2 ;
           make ~min_len:4 ~name:"routers" 3 ;
           make ~min_len:4 ~name:"time servers" 4 ;
           make ~min_len:4 ~name:"name servers" 5 ;
           make ~min_len:4 ~name:"domain name servers" 6 ;
           make ~min_len:4 ~name:"log servers" 7 ;
           make ~min_len:4 ~name:"cookie servers" 8 ;
           make ~min_len:4 ~name:"line printers" 9 ;
           make ~min_len:4 ~name:"impress servers" 10 ;
           make ~min_len:4 ~name:"resource location servers" 11 ;
           make ~min_len:1 ~name:"host name" 12 ;
           make ~len:2 ~name:"boot file size" 13 ;
           make ~min_len:1 ~name:"dump file" 14 ;
           make ~min_len:1 ~name:"domain name" 15 ;
           make ~len:4 ~name:"swap server" 16 ;
           make ~min_len:1 ~name:"root path" 17 ;
           make ~min_len:1 ~name:"extensions" 18 ;
           make ~len:1 ~name:"ip forwarding" 19 ;
           make ~len:1 ~name:"non-local routing" 20 ;
           make ~min_len:8 ~name:"policy filter" 21 ;
           make ~len:2 ~name:"max datagram" 22 ;
           make ~len:1 ~name:"default IP TTL" 23 ;
           make ~len:4 ~name:"Path MTU timeout" 24 ;
           make ~min_len:2 ~name:"MTU sizes" 25 ;
           make ~len:2 ~name:"interface MTU" 26 ;
           make ~len:1 ~name:"local subnets" 27 ;
           make ~len:4 ~name:"broadcast address" 28 ;
           make ~len:1 ~name:"perform mask discovery" 29 ;
           make ~len:1 ~name:"answer mask supplier" 30 ;
           make ~len:1 ~name:"perform router discovery" 31 ;
           make ~len:4 ~name:"router solicitation" 32 ;
           make ~min_len:8 ~name:"static routes" 33 ;
           make ~len:1 ~name:"negociate trailers" 34 ;
           make ~len:4 ~name:"ARP cache timeout" 35 ;
           make ~len:1 ~name:"Ethernet encapsulation" 36 ;
           make ~len:1 ~name:"default TCP TTL" 37 ;
           make ~len:4 ~name:"keepalive interval" 38 ;
           make ~len:1 ~name:"keepalive garbage" 39 ;
           make ~min_len:1 ~name:"NIS domain" 40 ;
           make ~min_len:4 ~name:"NIS servers" 41 ;
           make ~min_len:4 ~name:"NTP servers" 42 ;
           make ~min_len:1 ~name:"Vendor information" 43 ;
           make ~min_len:4 ~name:"NBNS servers" 44 ;
           make ~min_len:4 ~name:"NBDD servers" 45 ;
           make ~len:1 ~name:"netios/TCP node" 46 ;
           make ~min_len:1 ~name:"netbios/TCP scope" 47 ;
           make ~min_len:4 ~name:"X11 font servers" 48 ;
           make ~min_len:4 ~name:"X11 display managers" 49 ;
           make ~len:4 ~name:"requested IP" 50 ;
           make ~len:4 ~name:"lease time" 51 ;
           make ~len:1 ~name:"option overload" 52 ;
           make ~len:1 ~name:"message type" 53 ;
           make ~len:4 ~name:"server identifier" 54 ;
           make ~min_len:1 ~name:"request list" 55 ;
           make ~min_len:1 ~name:"message" 56 ;
           make ~len:2 ~name:"max DHCP message size" 57 ;
           make ~len:4 ~name:"renewal time" 58 ;
           make ~len:4 ~name:"rebinding time" 59 ;
           make ~len:1 ~name:"vendor class" 60 ;
           make ~min_len:2 ~name:"client identifier" 61 ;
           dummy 62 ;
           dummy 63 ;
           make ~min_len:1 ~name:"NIS+ domain" 64 ;
           make ~min_len:4 ~name:"NIS+ servers" 65 ;
           make ~min_len:1 ~name:"TFTP server" 66 ;
           make ~min_len:1 ~name:"bootfile server" 67 ;
           make ~min_len:0 ~name:"mobile IP home agents" 68 ;
           make ~min_len:4 ~name:"SMTP servers" 69 ;
           make ~min_len:4 ~name:"POP3 servers" 70 ;
           make ~min_len:4 ~name:"NNTP servers" 71 ;
           make ~min_len:4 ~name:"WWW servers" 72 ;
           make ~min_len:4 ~name:"finger servers" 73 ;
           make ~min_len:4 ~name:"IRC servers" 74 ;
           make ~min_len:4 ~name:"streettalk servers" 75 ;
           make ~min_len:4 ~name:"STDA servers" 76 |]

    let () =
        Array.iteri (fun i opt -> assert (i = opt.code)) all_options

    let subnet_mask = 1
    let routers = 3
    let time_servers = 4
    let domain_name_servers = 6
    let host_name = 12
    let interface_mtu = 26
    let broadcast_address = 28
    let requested_ip = 50
    let lease_time = 51
    let server_id = 54
    let request_list = 55
    let client_id = 61

    let default_client_id ?(htype=Arp.HwType.eth) chaddr =
        let%bitstring client_id = {|
            (htype :> int) : 8 ;
            chaddr : 6*8 : bitstring |} in
        string_of_bitstring client_id
end

(** {2 DHCP messages} *)

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
          mutable domain_name_server : Ip.Addr.t option ;
          mutable host_name : string option ;
          mutable search_sfx : string option ;
          mutable lease_time : int32 option ; (* in seconds *)
          mutable server_id : Ip.Addr.t option ;
          mutable requested_ip : Ip.Addr.t option ;
          mutable message : string option ;
          mutable max_dhcp_msg_size : int32 option ;
          mutable vendor_class_id : string option ;
          mutable client_id : string option ;
          mutable request_list : string option ;
          (* Not all options are worth decoding: *)
          mutable other_options : (int * bitstring) list}

    let set_option t code len v =
        let ip_list l = l >= 4 && l land 3 = 0 in
        match code, len with
        |  1, 4 -> t.subnet_mask <- Some (Ip.Addr.of_bitstring v)
        |  3, l when ip_list l ->
                   t.router <- Some (Ip.Addr.of_bitstring (takebits 32 v))
        |  6, l when ip_list l ->
                   t.domain_name_server <- Some (Ip.Addr.of_bitstring (takebits 32 v))
        | 12, l when l >= 1 ->
                   t.host_name <- Some (string_of_bitstring v)
        | 15, l when l >= 1 ->
                   t.search_sfx <- Some (string_of_bitstring v)
        | 42, l when ip_list l ->
                   t.ntp_server <- Some (Ip.Addr.of_bitstring (takebits 32 v))
        | 50, 4 -> t.requested_ip <- Some (Ip.Addr.of_bitstring v)
        | 51, 4 -> t.lease_time <- Some (int32_of_bitstring v)
        | 53, 1 -> t.msg_type <- Some (MsgType.of_bitstring v)
        | 54, 4 -> t.server_id <- Some (Ip.Addr.of_bitstring v)
        | 55, l when l > 0 ->
                   t.request_list <- Some (string_of_bitstring v)
        | 56, l when l > 0 ->
                   t.message <- Some (string_of_bitstring v)
        | 57, l when l > 0 ->
                   t.max_dhcp_msg_size <- Some (int32_of_bitstring v)
        | 60, l when l > 0 ->
                   t.vendor_class_id <- Some (string_of_bitstring v)
        | 61, l when l >= 2 ->
                   t.client_id <- Some (string_of_bitstring v)
        (* FIXME: IP Layer parameters setting could be interesting to get/set via DHCP.
           At least netmask *)
        (* FIXME: handle option overload of file/name fields with more options *)
        | 69, l when ip_list l ->
                   t.smtp_server <- Some (Ip.Addr.of_bitstring (takebits 32 v))
        | 70, l when ip_list l ->
                   t.pop3_server <- Some (Ip.Addr.of_bitstring (takebits 32 v))
        | _     -> t.other_options <- (code, v) :: t.other_options

    let rec unpack_options t bits = match%bitstring bits with
        | {| 0 : 8 ; rest : -1 : bitstring |} -> (* padding *)
            unpack_options t rest
        | {| 255 : 8 |} -> (* end *)
            true
        | {| code : 8 ; len : 8 ; v : 8*len : bitstring ; rest : -1 : bitstring |} ->
            set_option t code len v ;
            unpack_options t rest
        | {| _ |} -> false

    let unpack bits = match%bitstring bits with
        | {| op : 8 : check (op = bootrequest || op = bootreply) ;
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
            options : -1 : bitstring |} ->
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
                    domain_name_server = None ;
                    host_name = None ;
                    search_sfx = None ;
                    lease_time = None ;
                    msg_type = None ;
                    server_id = None ;
                    requested_ip = None ;
                    message = None ;
                    max_dhcp_msg_size = None ;
                    vendor_class_id = None ;
                    client_id = None ;
                    request_list = None ;
                    other_options = [] } in
          if unpack_options t options then Some t
          else err "Dhcp: Cannot decode options"
        | {| _ |} -> err "Dhcp: Not DHCP"

    let pack_options t =
        let may_pack_msgtyp t v = BatOption.map (fun (v : MsgType.t) -> let%bitstring b = {| t : 8 ; 1 : 8 ; (v :> int) : 8 |} in b) v
        and may_pack_int32  t v = BatOption.map (fun v -> let%bitstring b = {| t : 8 ; 4 : 8 ; v : 32 |} in b) v
        and may_pack_ip     t v = BatOption.map (fun (v : Ip.Addr.t) -> let%bitstring b = {| t : 8 ; 4 : 8 ; (Ip.Addr.to_int32 v) : 32 |} in b) v
        and may_pack_string t v = BatOption.map (fun v -> let%bitstring b = {| t : 8 ; String.length v : 8 ; v : -1 : string |} in b) v
        in
        List.filter_map identity [
            may_pack_msgtyp 53 t.msg_type ;
            may_pack_ip 1 t.subnet_mask ; (* must appear before router *)
            may_pack_ip 3 t.router ;
            may_pack_ip 42 t.ntp_server ;
            may_pack_ip 69 t.smtp_server ;
            may_pack_ip 70 t.pop3_server ;
            may_pack_ip 6 t.domain_name_server ;
            may_pack_string 12 t.host_name ;
            may_pack_string 15 t.search_sfx ;
            may_pack_int32 51 t.lease_time ;
            may_pack_ip 50 t.requested_ip ;
            may_pack_ip 54 t.server_id ;
            may_pack_string 56 t.message ;
            may_pack_int32 57 t.max_dhcp_msg_size ;
            may_pack_string 60 t.vendor_class_id ;
            may_pack_string 61 t.client_id ;
            may_pack_string 55 t.request_list
        ] @
        List.rev_map (fun (tag, v) ->
            let%bitstring tl = {| tag : 8 ; bytelength v : 8 |} in
            Bitstring.concat [ tl ; v ]
        ) t.other_options @ [
            (* END: *) bitstring_of_int8 255 ] |>
        Bitstring.concat

    let pack t =
        let string_extend str len =
            let l = String.length str in
            if l >= len then String.sub str 0 len
            else str ^ (String.make (len-l) (Char.chr 0))
        in
        let%bitstring b = {|
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
            pack_options t : -1 : bitstring |} in b

    let make_base
            ?op ?(chaddr=(Eth.Addr.zero :> bitstring)) ?xid ?(yiaddr=Ip.Addr.zero)
            ?subnet_mask ?router ?ntp_server ?smtp_server
            ?pop3_server ?domain_name_server ?host_name ?requested_ip
            ?search_sfx ?lease_time ?server_id ?message
            ?max_dhcp_msg_size ?vendor_class_id ?client_id ?request_list
            ?(options=[]) msg_type =
        let op =
            BatOption.default_delayed (fun () ->
                if msg_type = MsgType.offer ||
                   msg_type = MsgType.ack ||
                   msg_type = MsgType.nack then
                    BootReply
                else
                    BootRequest
            ) op in
        let xid = may_default xid (fun () -> Random.int32 Int32.max_int) in
        let t =
            { op ;
              htype = Arp.HwType.eth ;
              hlen = 6 ; hops = 0 ;
              xid ;
              secs = 0 ; broadcast = false ;
              ciaddr = Ip.Addr.zero ;
              yiaddr ;
              siaddr = Ip.Addr.zero ;
              giaddr = Ip.Addr.zero ;
              chaddr = extendbytes 16 chaddr ;
              sname = "" ; file = "" ;
              (* Common options: *)
              msg_type = Some msg_type ;
              subnet_mask ; router ;
              ntp_server ; smtp_server ;
              pop3_server ; domain_name_server ;
              host_name ; requested_ip ;
              search_sfx ; lease_time ;
              server_id ; message ;
              max_dhcp_msg_size ; vendor_class_id ;
              client_id ; request_list ;
              (* Other options: *)
              other_options = [] } in
        (* If some important parameters are given as options move them from the
         * anonymous option list onto the proper data structure. They take
         * precedence over parameters given explicitly though. *)
        List.iter (fun (code, v) ->
            set_option t code (bitstring_length v) v
        ) options ;
        t

    let make_discover ?(chaddr=(Eth.Addr.zero :> bitstring)) ?xid ?host_name ?request_list ?options () =
        let client_id = Option.default_client_id chaddr in
        make_base ~chaddr ?xid ?host_name ~client_id ?request_list ?options MsgType.discover

    let make_offer ?chaddr ?xid ?options ?client_id yiaddr =
        make_base ?chaddr ?xid ?client_id ?options ~yiaddr MsgType.offer

    let make_request ?(chaddr=(Eth.Addr.zero :> bitstring)) ?xid ?host_name ?server_id ?request_list ?options yiaddr =
        let client_id = Option.default_client_id chaddr in
        make_base ~chaddr ?xid ?host_name ~client_id ?server_id ?request_list ~requested_ip:yiaddr ?options MsgType.request

    let make_ack ?chaddr ?xid ?client_id ?options yiaddr =
        make_base ?chaddr ?xid ?client_id ?options ~yiaddr MsgType.ack

    let make_nak ?chaddr ?xid ?client_id ?options ?message () =
        make_base ?chaddr ?xid ?client_id ?options ?message MsgType.ack

    let random () =
        let xid = rand32 () and host_name = rand_hostname () in
        if randb () then
            make_discover ~xid ~host_name ()
        else
            let server_id = if randb () then Some (Ip.Addr.random ()) else None in
            make_request ~xid ?server_id (Ip.Addr.random ())

    (*$Q pack
      (Q.make (fun _ -> random () |> pack)) (fun t -> t = pack (BatOption.get (unpack t)))
     *)
    (*$>*)

end
