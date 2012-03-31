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
(**
 * This module holds all functions related to [libpcap], packet sniffing,
 * packet injection, and pcap file reading and writing.
 *)
open Batteries
open Bitstring
open Tools

let debug = false

(** {1 Libpcap low level wrappers} *)

(** A network device opened for sniffing or injection *)
type iface

(** [openif "eth0" true "port 80" 96] returns the iface representing eth0,
 * in promiscuous mode, filtering port 80 and capturing only the first 96 bytes
 * of each packets. Notice that if [caplen] is set to 0 then a "default" value
 * of 65535 will be chosen, which is probably not what you want. You should set
 * [caplen] = your {e MTU} size. *)
external openif : string -> bool -> string -> int -> iface = "wrap_pcap_make"

(** [inject iface packet] inject this packet into this interface *)
external inject : iface -> string -> unit = "wrap_pcap_inject"

(** [sniff iface] will return the next available packet, as well as its capture
 * timestamp *)
external sniff : iface -> (float * string) = "wrap_pcap_read"

(** {1 User functions} *)
(** {2 Packet injection} *)

(** A counter for how many packets were injected successfully. *)
let packets_injected_ok  = Metric.Atomic.make "Pcap/Packets/Injected/Ok"
(** A counter for how many packets we failed to inject. *)
let packets_injected_err = Metric.Atomic.make "Pcap/Packets/Injected/Err"
(** A counter for how many bytes were injected successfully. *)
let bytes_out            = Metric.Counter.make "Pcap/Bytes/Out" "bytes"

(** [inject_pdu iface bits] inject the packet [bits] into interface [iface]. *)
let inject_pdu iface bits =
    if debug then Printf.printf "Pcap: injecting a packet (%s)...\n%!" (string_of_bitstring bits);
    (try
        inject iface (string_of_bitstring bits) ;
        Metric.Atomic.fire packets_injected_ok ;
        Metric.Counter.increase bytes_out (Int64.of_int (bytelength bits))
    with _ ->
        if debug then Printf.printf "Pcap: Cannot inject a packet\n" ;
        Metric.Atomic.fire packets_injected_err)

(** {2 Packet sniffing} *)

(** A counter for how many packets were sniffed. *)
let packets_sniffed_ok = Metric.Atomic.make "Pcap/Packets/Sniffed"
(** A counter for how many bytes were sniffed. *)
let bytes_in           = Metric.Counter.make "Pcap/Bytes/In" "bytes"

(** [sniffer iface rx] return a Lwt thread that continuously sniff packets
 * and pass them to the [rx] function. *)
let sniffer iface rx =
    let rec loop () =
        lwt ts, pkt = Lwt_preemptive.detach sniff iface in
        Metric.Atomic.fire packets_sniffed_ok ;
        Metric.Counter.increase bytes_in (Int64.of_int (String.length pkt)) ;
        if debug then Printf.printf "Pcap: Got packet for ts %f\n%!" ts ;
        Clock.at ts rx (bitstring_of_string pkt) ;
        loop ()
    in loop ()

(** {2 Pcap files} *)

(** {e Data Link Layers} are constant values indicating what protocol and hardware technology
 * some captured packets were taken from. We support only the two most common: [Dlt.en10mb], ie
 * usual Ethernet cables, and [Dlt.linux_cooked] corresponding to a capture on the {e any}
 * network device on Linux. *)
module Dlt = struct
    include MakePrivate(struct
        type t = int32
        let to_string = function
            |   0l -> "BSD loopback encapsulation"
            |   1l -> "Ethernet (10Mb)"
            |   2l -> "Experimental Ethernet (3Mb)"
            |   3l -> "Amateur Radio AX.25"
            |   4l -> "Proteon ProNET Token Ring"
            |   5l -> "Chaos"
            |   6l -> "802.5 Token Ring"
            |   7l -> "ARCNET, with BSD-style header"
            |   8l -> "Serial Line IP"
            |   9l -> "Point-to-point Protocol"
            |  10l -> "FDDI"
            | 113l -> "Linux Cooked Capture"
            |    x -> Printf.sprintf "dlt(%ld)" x
        let is_valid _ = true
        let repl_tag = "proto"
    end)

    (** Some well know DLT values. *)

    (** BSD loopback encapsulation *)
    let null    = o 0l
    (** Ethernet (10Mb) *)
    let en10mb  = o 1l
    (** Experimental Ethernet (3Mb) *)
    let en3mb   = o 2l
    (** Amateur Radio AX.25 *)
    let ax25    = o 3l
    (** Proteon ProNET Token Ring *)
    let pronet  = o 4l
    (** Chaos *)
    let chaos   = o 5l
    (** 802.5 Token Ring *)
    let ieee802 = o 6l
    (** ARCNET, with BSD-style header *)
    let arcnet  = o 7l
    (** Serial Line IP *)
    let slip    = o 8l
    (** Point-to-point Protocol *)
    let ppp     = o 9l
    (** FDDI *)
    let fddi    = o 10l
    (** Linux SLL *)
    let linux_cooked = o 113l

    let random () = o (rand32 ())
end

(** The global header of a pcap file. *)
type global_header = { name          : string ;
                       endianness    : endian ;
                       version_major : int ;
                       version_minor : int ;
                       this_zone     : int32 ;
                       sigfigs       : int32 ;
                       snaplen       : int32 ; (** Indicate that no caplen will be smaller. We don't use this. *)
                       dlt           : Dlt.t }

(** {3 Pdu} *)

(** Packets harvested with libpcap will come with additional informations such
 * as caplen, timestamp etc.
 * This special PDU module make a pseudo-header out of those informations, so
 * that we it's kept while we edit the packets and can be reused for saving
 * afterward. *)
module Pdu =
struct
    (** These informations are present as the first layer of every packet
     * read from a pcap file. *)
    type t = { source_name : string ; caplen : int ; dlt : Dlt.t ;
               ts : float ; payload : Payload.t }

    let make source_name ?(caplen=65535) ?(dlt=Dlt.en10mb) ts payload =
        { source_name ; caplen ; dlt ; ts ; payload }

    (** Return the [bitstring] ready to be written into a pcap file (see {!Pcap.save}). *)
    let pack t =
        let sec      = Int32.of_float t.ts in
        let usec     = Int32.of_float ((t.ts -. (floor t.ts)) *. 1_000_000.) in
        let wire_len = bytelength (t.payload :> bitstring) in
        let pkt_hdr = (BITSTRING {
            sec  : 32 : littleendian ;
            usec : 32 : littleendian ;
            Int32.of_int (min t.caplen wire_len) : 32 : littleendian ;
            Int32.of_int wire_len : 32 : littleendian }) in
        concat [ pkt_hdr ; (t.payload :> bitstring) ]
end

(** [save "file.pcap"] returns a function that will save passed packets (as [bitstring]s)
 * in ["file.pcap"] file.
 * @param caplen can be used to cap saved packet to a given number of bytes
 * @param dlt can be used to change the file's DLT (you probably do not want to do that) *)
let save ?(caplen=65535) ?(dlt=Dlt.en10mb) fname =
    let out_chan = open_out_bin fname
    and file_hdr = (BITSTRING {
        0xa1b2c3d4l : 32 : littleendian ;
        2 (* version major *) : 16 : littleendian ;
        4 (* version minor *) : 16 : littleendian ;
        0l (* this TZ *) : 32 : littleendian ;
        0l : 32 : littleendian ;
        Int32.of_int caplen : 32 : littleendian ;
        (dlt :> int32) : 32 : littleendian }) in
    output_string out_chan (string_of_bitstring file_hdr) ;
    let f bits =
        let pdu = Pdu.make fname ~caplen ~dlt (Clock.now ()) bits in
        let bytes = string_of_bitstring (Pdu.pack pdu) in
        output_string out_chan bytes in
    Gc.finalise (fun _ -> close_out out_chan) f ;
    f

(** When trying to read packets from a file that doesn't look like a pcap file. *)
exception Not_a_pcap_file

(** [read_global_header filename] reads the pcap global header from the
 * fiven file, and returns both a {!Pcap.global_header} and the input channel. *)
let read_global_header fname =
    let ic = open_in_bin fname in
    let header = bitstring_of_string (IO.really_nread ic 24) ; in
    let endianness = bitmatch (takebits 32 header) with
        | { 0xa1b2c3d4l : 32 : bigendian } -> BigEndian
        | { 0xa1b2c3d4l : 32 : littleendian } -> LittleEndian
        | { _ } -> raise Not_a_pcap_file in
    bitmatch (dropbits 32 header) with
    | { version_major : 16 : endian (endianness) ; version_minor : 16 : endian (endianness) ;
        this_zone : 32 : endian (endianness) ; sigfigs : 32 : endian (endianness) ;
        snaplen : 32 : endian (endianness) ; dlt : 32 : endian (endianness) } ->
        { name = fname ; endianness ; version_major ; version_minor ;
          this_zone ; sigfigs ; snaplen ; dlt = Dlt.o dlt }, ic
   | { _ } -> raise Not_a_pcap_file

(** [read_next_pkt global_header ic] will return the next {!Pcap.Pdu.t} that's to
 * be read from the input stream [ic]. *)
let read_next_pkt global_header ic =
    let pkt_hdr = IO.really_nread ic 16 in
    bitmatch (bitstring_of_string pkt_hdr) with
    | { sec      : 32 : endian (global_header.endianness) ;
        usec     : 32 : endian (global_header.endianness) ;
        caplen   : 32 : endian (global_header.endianness) ;
        wire_len : 32 : endian (global_header.endianness) } ->
        if caplen > global_header.snaplen then (
            (* We don't really care but the user might *)
            Printf.printf "caplen > snaplen!\n%!"
        ) ;
        let pkt = IO.really_nread ic (Int32.to_int caplen) in
        let bits = bitstring_of_string pkt in
        let bits = if wire_len <= caplen then bits
                   else (
                       concat [ bits ; zeroes_bitstring (Int32.to_int (Int32.sub wire_len caplen)*8) ]
                   ) in
        let ts = Int32.to_float sec +. (Int32.to_float usec) *. 0.000001 in
        Pdu.make global_header.name
                 ~caplen:(Int32.to_int caplen)
                 ~dlt:global_header.dlt
                 ts (Payload.o bits)
    | { _ } -> should_not_happen ()

(** from a pcap file, returns an [Enum.t] of {!Pcap.Pdu.t}. *)
let enum_of fname =
    let global_header, ic = read_global_header fname in
    let rec next () =
        try read_next_pkt global_header ic
        with IO.No_more_input | IO.Input_closed ->
            raise Enum.No_more_elements in
    Enum.from next

(** {2 Tools} *)

(** Informations on a pcap file. *)
type infos = { filename : string ; data_link_type : Dlt.t ;
               num_packets : int ; data_size : int64 ;
               start_time : float ; stop_time : float }

(** Return some informations about a pcap file (require to scan the whole file,
 * so depending on the file size it may take some time). *)
let infos_of filename =
    let pkts = enum_of filename in
    let min_ts = ref Float.max_num and max_ts = ref Float.min_num
    and num_packets = ref 0 and data_size = ref 0L in
    let dlt = match Enum.peek pkts with Some p -> p.Pdu.dlt | None -> Dlt.en10mb in
    Enum.iter (fun pdu ->
        incr num_packets ;
        data_size := Int64.add !data_size (Int64.of_int (Payload.length pdu.Pdu.payload)) ;
        min_ts := min !min_ts pdu.Pdu.ts ;
        max_ts := max !max_ts pdu.Pdu.ts) pkts ;
    { filename ; data_link_type = dlt ;
      num_packets = !num_packets ; data_size = !data_size ;
      start_time = !min_ts ; stop_time = !max_ts }

(* Check that we found the same values than capinfo *)
(*$= infos_of & ~printer:BatPervasives.dump
    (infos_of "tests/someweb.pcap") ({ filename = "tests/someweb.pcap" ;\
                                       data_link_type = Dlt.en10mb ;\
                                       num_packets = 173 ; data_size = 149461L ;\
                                       start_time = 1332451938.3774271 ;\
                                       stop_time = 1332451941.92178106 })
    (infos_of "tests/someweb_cut.pcap") ({ filename = "tests/someweb_cut.pcap" ;\
                                           data_link_type = Dlt.en10mb ;\
                                           num_packets = 173 ; data_size = 149461L ;\
                                           start_time = 1332451938.3774271 ;\
                                           stop_time = 1332451941.92178106 })
 *)

(** [merge [e1 ; e2 ; e3]] will merge the three [Enumt.t] of packets in chronological
 * order. *)
let rec merge = function
    | [] -> Enum.empty ()
    | a :: rest ->
        let test_ts a b = a.Pdu.ts <= b.Pdu.ts in
        Enum.merge test_ts a (merge rest)
(*$= merge & ~printer:BatPervasives.dump
    (merge [ (enum_of "tests/someweb.pcap" // \
        let r = ref true in fun _ -> r := not !r ; !r) ; \
             (enum_of "tests/someweb.pcap" // \
        let r = ref false in fun _ -> r := not !r ; !r) ] |> List.of_enum) \
                                    (enum_of "tests/someweb.pcap" |> List.of_enum)
 *)

(** Small utility that truncate a pcap file to the last valid packet.
 * Useful for those interrupted/damaged pcap files with an incomplete packet at the end,
 * that some tools then refuse to read. *)
let repair_file fname =
    let global_header, ic = read_global_header fname in
    let ic, counter = IO.pos_in ic in
    let rec aux () =
        let ofs = counter () in
        let cont = try ignore (read_next_pkt global_header ic) ; true
                   with IO.No_more_input | IO.Input_closed -> false in
        if cont then aux () else ofs in
    Unix.truncate fname (24 (* global header *) + (aux ()))

(** [play tx "file.pcap"] will read packets from ["file.pcap"] and send them to [tx]
 * copying the pcap file frame rate. Notice that we use the internal {!Clock} for this,
 * so it's both very accurate or not accurate at all, depending on how you look at it. *)
let play tx fname =
    let packets = enum_of fname in
    (* With last_packet_timestamp (or None), schedule a function using the clock to read
       the next packet from the file. *)
    let rec read_next_pkt last_ts =
        match Enum.get packets with
            | None -> () (* pcap file is over *)
            | Some pdu ->
                let d = match last_ts with None -> 0. | Some lts -> pdu.Pdu.ts -. lts in
                Clock.delay d (fun () ->
                    tx (pdu.Pdu.payload :> bitstring) ;
                    read_next_pkt (Some pdu.Pdu.ts)) ()
    in
    Clock.delay 0. read_next_pkt None

