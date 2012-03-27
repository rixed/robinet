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

(* Libpcap wrapper *)

type iface
external openif : string -> bool -> string -> int -> iface = "wrap_pcap_make"
(* [openif "eth0" true "port 80" 96] returns the iface representing eth0,
   in promiscuous mode, filtering port 80 and capturing only the first 96 bytes
   of each packets. Notice that if caplen is set to 0 then a "default" value
   of 65535 will be chosen, which is probably not what you want. *)
external inject : iface -> string -> unit = "wrap_pcap_inject"
(* [inject iface packet] inject this packet into this interface *)
external sniff : iface -> (float * string) = "wrap_pcap_read"
(* [sniff iface] will return the next available packet, as well as
   its capture timestamp *)

let packets_injected_ok  = Metric.Atomic.make "Pcap/Packets/Injected/Ok"
let packets_injected_err = Metric.Atomic.make "Pcap/Packets/Injected/Err"
let bytes_out            = Metric.Counter.make "Pcap/Bytes/Out" "bytes"

let inject_pdu iface bits =
    if debug then Printf.printf "Pcap: injecting a packet (%s)...\n%!" (string_of_bitstring bits);
    (try
        inject iface (string_of_bitstring bits) ;
        Metric.Atomic.fire packets_injected_ok ;
        Metric.Counter.increase bytes_out (Int64.of_int (bytelength bits))
    with _ ->
        if debug then Printf.printf "Pcap: Cannot inject a packet\n" ;
        Metric.Atomic.fire packets_injected_err)

let packets_sniffed_ok = Metric.Atomic.make "Pcap/Packets/Sniffed"
let bytes_in = Metric.Counter.make "Pcap/Bytes/In" "bytes"

(* Lwt thread that continuously sniff packets *)
let sniffer iface rx =
    let rec loop () =
        lwt ts, pkt = Lwt_preemptive.detach sniff iface in
        Metric.Atomic.fire packets_sniffed_ok ;
        Metric.Counter.increase bytes_in (Int64.of_int (String.length pkt)) ;
        if debug then Printf.printf "Pcap: Got packet for ts %f\n%!" ts ;
        Clock.at ts rx (bitstring_of_string pkt) ;
        loop ()
    in loop ()

(* Pcap files *)

(* See /usr/include/pcap/bpf.h *)
let dlt_null    = 0l (* BSD loopback encapsulation *)                                             
let dlt_en10mb  = 1l (* Ethernet (10Mb) *)                                                        
let dlt_en3mb   = 2l (* Experimental Ethernet (3Mb) *)                                            
let dlt_ax25    = 3l (* Amateur Radio AX.25 *)                                                    
let dlt_pronet  = 4l (* Proteon ProNET Token Ring *)
let dlt_chaos   = 5l (* Chaos *)                                                                  
let dlt_ieee802 = 6l (* 802.5 Token Ring *)
let dlt_arcnet  = 7l (* ARCNET, with BSD-style header *)                                          
let dlt_slip    = 8l (* Serial Line IP *)                                                         
let dlt_ppp     = 9l (* Point-to-point Protocol *)                                                
let dlt_fddi    = 10l (* FDDI *)
let dlt_linux_cooked = 113l (* Linux SLL *)

let save ?(caplen=65535) ?(linktype=dlt_en10mb) fname =
    let out_chan = open_out_bin fname
    and file_hdr = (BITSTRING {
        0xa1b2c3d4l : 32 : littleendian ;
        2 (* version major *) : 16 : littleendian ;
        4 (* version minor *) : 16 : littleendian ;
        0l (* this TZ *) : 32 : littleendian ;
        0l : 32 : littleendian ;
        Int32.of_int caplen : 32 : littleendian ;
        linktype : 32 : littleendian })
    and write_pkt caplen bits =
        let ts       = Clock.now () in
        let sec      = Int32.of_float (ts) in
        let usec     = Int32.of_float ((ts -. (floor ts)) *. 1_000_000.)
        and wire_len = bytelength bits
        in
        let pkt_hdr = (BITSTRING {
            sec  : 32 : littleendian ;
            usec : 32 : littleendian ;
            Int32.of_int (min caplen wire_len) : 32 : littleendian ;
            Int32.of_int wire_len : 32 : littleendian }) in
        concat [ pkt_hdr ; bits ] in
    output_string out_chan (string_of_bitstring file_hdr) ;
    let f bits =
        let p = write_pkt caplen bits in
        output_string out_chan (string_of_bitstring p) in
    Gc.finalise (fun _ -> close_out out_chan) f ;
    f

type global_header = { endianness    : endian ;
                       version_major : int ;
                       version_minor : int ;
                       this_zone     : int32 ;
                       sigfigs       : int32 ;
                       snaplen       : int32 ;
                       dlt           : int32 }

exception Not_a_pcap_file

let read_global_header ic =
    let header = bitstring_of_string (IO.nread ic 24) ; in
    let endianness = bitmatch (takebits 32 header) with
        | { 0xa1b2c3d4l : 32 : bigendian } -> BigEndian
        | { 0xa1b2c3d4l : 32 : littleendian } -> LittleEndian
        | { _ } -> raise Not_a_pcap_file in
    bitmatch (dropbits 32 header) with
    | { version_major : 16 : endian (endianness) ; version_minor : 16 : endian (endianness) ;
        this_zone : 32 : endian (endianness) ; sigfigs : 32 : endian (endianness) ;
        snaplen : 32 : endian (endianness) ; dlt : 32 : endian (endianness) } ->
        { endianness ; version_major ; version_minor ;
          this_zone ; sigfigs ; snaplen ; dlt }
   | { _ } -> raise Not_a_pcap_file

let dlt_of fname =
    let in_chan = open_in_bin fname in
    let global_header = read_global_header in_chan in
    close_in in_chan ;
    global_header.dlt

(* from a pcap file, return an enumerator of (TS * bitstring) and the global header *)
let load fname =
    let in_chan = open_in_bin fname in
    let global_header = read_global_header in_chan in
    let rec read_next_pkt () =
        let pkt_hdr = try IO.nread in_chan 16
                      with IO.No_more_input | IO.Input_closed ->
                           raise Enum.No_more_elements in
        bitmatch (bitstring_of_string pkt_hdr) with
        | { sec      : 32 : endian (global_header.endianness) ;
            usec     : 32 : endian (global_header.endianness) ;
            caplen   : 32 : endian (global_header.endianness) ;
            wire_len : 32 : endian (global_header.endianness) } ->
            if caplen > global_header.snaplen then (
                (* We don't really care but the user might *)
                Printf.printf "caplen > snaplen!\n%!"
            ) ;
            let pkt = try IO.nread in_chan (Int32.to_int caplen)
                      with IO.No_more_input -> raise Enum.No_more_elements in
            let bits = bitstring_of_string pkt in
            let bits = if wire_len <= caplen then bits
                       else (
                           concat [ bits ; zeroes_bitstring (Int32.to_int (Int32.sub wire_len caplen)*8) ]
                       ) in
            let ts = Int32.to_float sec +. (Int32.to_float usec) *. 0.000001 in
            ts, bits
        | { _ } -> should_not_happen ()
    in
    Enum.from read_next_pkt, global_header

let enum_of fname = fst (load fname)

type infos = { filename : string ; data_link_type : int32 ;
               num_packets : int ; data_size : int64 ;
               start_time : float ; stop_time : float }
let infos_of filename =
    let pkts, global_header = load filename in
    let min_ts = ref Float.max_num and max_ts = ref Float.min_num
    and num_packets = ref 0 and data_size = ref 0L in
    Enum.iter (fun (ts, bits) ->
        incr num_packets ;
        data_size := Int64.add !data_size (Int64.of_int (bytelength bits)) ;
        min_ts := min !min_ts ts ;
        max_ts := max !max_ts ts) pkts ;
    { filename ; data_link_type = global_header.dlt ;
      num_packets = !num_packets ; data_size = !data_size ;
      start_time = !min_ts ; stop_time = !max_ts }

(* Check that we found the same values than capinfo *)
(*$= infos_of & ~printer:BatPervasives.dump
    (infos_of "tests/someweb.pcap") ({ filename = "tests/someweb.pcap" ;\
                                       data_link_type = dlt_en10mb ;\
                                       num_packets = 173 ; data_size = 149461L ;\
                                       start_time = 1332451938.3774271 ;\
                                       stop_time = 1332451941.92178106 })
    (infos_of "tests/someweb_cut.pcap") ({ filename = "tests/someweb_cut.pcap" ;\
                                           data_link_type = dlt_en10mb ;\
                                           num_packets = 173 ; data_size = 149461L ;\
                                           start_time = 1332451938.3774271 ;\
                                           stop_time = 1332451941.92178106 })
 *)

let rec merge = function
    | [] -> Enum.empty ()
    | a :: rest ->
        let test_ts (ts_a, _) (ts_b, _) = ts_a <= ts_b in
        Enum.merge test_ts a (merge rest)
(*$= merge & ~printer:BatPervasives.dump
    (merge [ (enum_of "tests/someweb.pcap" // \
        let r = ref true in fun _ -> r := not !r ; !r) ; \
             (enum_of "tests/someweb.pcap" // \
        let r = ref false in fun _ -> r := not !r ; !r) ] |> List.of_enum) \
                                    (enum_of "tests/someweb.pcap" |> List.of_enum)
 *)

let play tx fname =
    (* With last_packet_timestamp (or None), schedule a function using the clock to read
       the next packet from the file. *)
    let packets = enum_of fname in
    let rec read_next_pkt last_ts =
        match Enum.get packets with
            | None -> () (* pcap file is over *)
            | Some (ts, bits) ->
                let d = match last_ts with None -> 0. | Some lts -> ts -. lts in
                Clock.delay d (fun () ->
                    tx bits ;
                    read_next_pkt (Some ts)) ()
    in
    Clock.delay 0. read_next_pkt None

