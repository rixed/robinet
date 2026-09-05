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
   This module holds all functions related to [libpcap], packet sniffing,
   packet injection and pcap file reading and writing.

   All I want is sniffing packets:

   To grab the first packet from "em1" interface and display it:

{[

# let itf = Pcap.openif "em1";;
val itf : Pcap.iface = {Pcap.handler = <abstr>; name = "em1"; caplen = 1500}
# let pkt = Pcap.sniff itf;;
val pkt : Pcap.Pdu.t =
 {Pcap.Pdu.source_name = "em1"; caplen = 1500;
   dlt = Ethernet (10Mb); ts = 15:09:49.81;
   payload = 66 bytes (74 46 a0 a1 28 8e 00...)}
# Packet.Pdu.unpack pkt;;
- : Packet.Pdu.layer list =
 [Packet.Pdu.Pcap
   {Pcap.Pdu.source_name = "em1"; caplen = 1500;
    dlt = Ethernet (10Mb); ts = 15:09:49.81;
    payload = 66 bytes (74 46 a2 a1 28 8e 00...)};
  Packet.Pdu.Eth
   {Eth.Pdu.src = Cisco:25:ac:42;
    dst = 74:46:a2:a1:28:8e; proto = IP;
    payload = 52 bytes (45 20 00 34 86 aa 40...)};
  Packet.Pdu.Ip
   {Ip.Pdu.tos = 32; tot_len = 52; id = 34474; dont_frag = true;
    more_frags = false; frag_offset = 0; ttl = 58; proto = tcp;
    src = 172.16.255.194; dst = 172.28.11.20;
    options = ; payload = 32 bytes (02 02 bc c8 a2 6c d0...)};
  Packet.Pdu.Tcp
   {Tcp.Pdu.src_port = shell; dst_port = 48328;
    seq_num = 0xA26CD0EB; ack_num = 0x304E4FC3;
    win_size = 501; flags = Ack; urg_ptr = 0;
    options = 01 01 08 0a 28 f5 dd 89 - 57 c2 c6 25              .....��.W��%
    ;
    payload = empty}]

]}

   Following packets can be dumped easily with just {[Pcap.sniff itf |> Packet.Pdu.unpack]}
   ("|>" is like the UNIX pipe).

   All I want is editing pcap files:

   To create a small pcap file with a single packet:

{[

Tcp.Pdu.make ~dst_port:(Tcp.Port.o 5000) (bitstring_of_string "HTTP/1.2 pas glop") |>
    Tcp.Pdu.pack |>
    Ip.Pdu.make Ip.Proto.tcp (Ip.Addr.random ()) (Ip.Addr.random ()) |>
    Ip.Pdu.pack |>
    Eth.Pdu.make Arp.HwProto.ip4 (Eth.Addr.random ()) (Eth.Addr.random ()) |>
    Eth.Pdu.pack |>
    Pcap.save "/tmp/random.pcap";;
]}

   To grep a string into a pcap file and obtain another pcap file with matching
   packets only:

{[

let grep needle haystack = try String.find haystack needle ; true with Not_found -> false in
Pcap.enum_of_file "input.pcap" |>
    Enum.filter (fun pdu -> grep "needle" (string_of_bitstring (pdu.Pcap.Pdu.payload :> bitstring))) |>
    Pcap.file_of_enum "output.pcap";;
]}

 *)
open Batteries
open Bitstring
open Tools

let debug = false

(* Where the recorded files are kept: a library the reader saves into, picks
 * from and (eventually) replays. Everything in it is named by a plain file
 * name, never by a path -- see [check_fname]. *)
let pcap_dir = ref "/tmp"

let path_of_fname fname = Filename.concat !pcap_dir fname

(* A name for a file in [pcap_dir], and nothing else.
 *
 * The reader chooses it, so it is checked here rather than trusted: a '/'
 * would point at a file outside the library -- anywhere at all, given a few of
 * them -- and a NUL would make the name the system is handed shorter than the
 * one that was checked. Everything else is a matter of taste, and not ours:
 * whatever the filesystem takes, the library holds.
 *
 * The empty name is not a name either. It is how a recorder says it has no
 * file (see [recorder]), and cannot also be the way to ask for one. *)
let check_fname fname =
    if fname = "" then
        Widget.bad_value "A file name is required" ;
    if String.contains fname '/' then
        Widget.bad_value
            "A file name cannot contain '/': %S must name a file of %s, not a \
             path" fname !pcap_dir ;
    if String.contains fname '\000' then
        Widget.bad_value "A file name cannot contain a NUL character" ;
    fname

(*$T check_fname
  check_fname "foo.pcap" = "foo.pcap"
  try ignore (check_fname "") ; false with Widget.Bad_value _ -> true
  try ignore (check_fname "a/b") ; false with Widget.Bad_value _ -> true
  try ignore (check_fname "a\000b") ; false with Widget.Bad_value _ -> true
 *)

(** {2 Libpcap low level wrappers} *)

(** Libpcap network interface handler. *)
type iface_handler

(** [inject_ iface_handler packet] inject this packet into this interface *)
external inject_ : iface_handler -> string -> unit = "wrap_pcap_inject"

(** [sniff_ iface_handler] will return the next available packet as a string,
 * as well as its capture timestamp.
 * If timeout is set then the function will raise Not_found after that number of
 * seconds if no packets have been captured. It will raise End_of_file if the
 * file descriptor has been closed. *)
type sniff_ret_ =
    { sniffed_timestamp : Clock.Time.t ; sniffed_caplen : int ;
      sniffed_wirelen : int ; sniffed_bytes : string }

external sniff_ : ?timeout:float -> iface_handler -> sniff_ret_ = "wrap_pcap_read"

(** [openif_ "eth0" true "port 80" 96] returns the iface representing eth0,
 * in promiscuous mode, filtering port 80 and capturing only the first 96 bytes
 * of each packets. Notice that if [caplen] is set to 0 then a "default" value
 * of 65535 will be chosen, which is probably not what you want. You should set
 * [caplen] = your {e MTU} size. *)
external openif_ : string -> bool -> string -> int -> iface_handler = "wrap_pcap_make"

external closeif_ : iface_handler -> unit = "wrap_pcap_close"


(** {2 Pcap files} *)

(** {e Data Link Types} are constant values indicating what protocol and hardware technology
 * some captured packets were taken from. We support only the two most common: [Dlt.en10mb], ie
 * usual Ethernet cables, and [Dlt.linux_cooked] corresponding to a capture on the {e any}
 * network device on Linux. *)
module Dlt = struct
    include Private.Make (struct
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

    let to_int (t : t) = Int32.to_int (t :> int32)
end

(** The global header of a pcap file. *)
type global_header = { name          : string ; (** The file name. *)
                       endianness    : endian ; (** Endianess of the file. *)
                       version_major : int ;    (** Libpcap version. *)
                       version_minor : int ;
                       this_zone     : int32 ;  (** Time zone (should be zero, unused). *)
                       sigfigs       : int32 ;  (** unused. *)
                       snaplen       : int32 ;  (** Indicate that no caplen will be smaller. We don't use this. *)
                       dlt           : Dlt.t    (** The Data Link Type (see {!Pcap.Dlt}). *) }

(** {3 Captured packet} *)

(** Packets harvested with libpcap will come with additional informations such
 * as caplen, timestamp etc.
 * This special PDU module make a pseudo-header out of those informations, so
 * that we it's kept while we edit the packets and can be reused for saving
 * afterward. *)
module Pdu =
struct
    (** These informations are present as the first layer of every packet
     * read from a pcap file. *)
    type t = { source_name : string ; caplen : int ; wirelen : int ;
               dlt : Dlt.t ; ts : Clock.Time.t ; payload : Payload.t }

    let make source_name ?(caplen=65535) ?wirelen ?(dlt=Dlt.en10mb) ts bits =
        let wirelen = wirelen |? bytelength bits
        and payload = Payload.o bits in
        { source_name ; caplen ; wirelen ; dlt ; ts ; payload }

    (** Return the [bitstring] ready to be written into a pcap file (see {!Pcap.save}). *)
    let pack t =
        let sec, usec = Clock.Time.to_ints t.ts in
        let len = Payload.length t.payload in
        (* What is saved of the packet, which is not all of it when the caplen
         * is shorter than what is in hand. *)
        let cap_len = min t.caplen len in
        let payload =
            if cap_len < len then takebytes cap_len (t.payload :> bitstring)
            else (t.payload :> bitstring) in
        let%bitstring pkt_hdr = {|
            Int32.of_int sec  : 32 : littleendian ;
            Int32.of_int usec : 32 : littleendian ;
            Int32.of_int cap_len : 32 : littleendian ;
            (* How long the packet was on the wire, which is more than is in
             * hand whenever it was cut short -- by libpcap on the way in (see
             * [sniffed_wirelen]), or by the caplen above. *)
            Int32.of_int t.wirelen : 32 : littleendian |} in
        concat [ pkt_hdr ; payload ]

    (** [output out] returns a function that will call [out] with the file header
     * and then the binary encoding of all passed pdus. *)
    let output ?(caplen=65535) ?(dlt=Dlt.en10mb) out =
        let%bitstring file_hdr = {|
            0xa1b2c3d4l : 32 : littleendian ;
            2 (* version major *) : 16 : littleendian ;
            4 (* version minor *) : 16 : littleendian ;
            0l (* this TZ *) : 32 : littleendian ;
            0l : 32 : littleendian ;
            Int32.of_int caplen : 32 : littleendian ;
            (dlt :> int32) : 32 : littleendian |} in
        out (string_of_bitstring file_hdr) ;
        fun pdu ->
            pack pdu |>
            string_of_bitstring |>
            out

    (** [write out] returns a function that will write passed pdus into [out].
     * @param caplen can be used to cap saved packet to a given number of bytes
     * @param dlt can be used to change the file's DLT (you probably do not want to do that) *)
    let write ?caplen ?dlt out_chan =
        output ?caplen ?dlt (String.print out_chan)

    (** [save "file.pcap"] returns a function that will save passed pdus in ["file.pcap"]
     * and another one that will close this file.
     * @param caplen can be used to cap saved packet to a given number of bytes
     * @param dlt can be used to change the file's DLT (you probably do not want to do that) *)
    let save ?(flush=true) ?caplen ?dlt fname =
        let out_chan = open_out_bin fname in
        let write_pdu = write ?caplen ?dlt out_chan in
        let write_pdu =
            if flush then
                fun pdu -> write_pdu pdu ; Batteries.flush out_chan
            else write_pdu in
        let close () = close_out out_chan in
        write_pdu, close
end

let default_dlt = Dlt.en10mb

(** [save "file.pcap"] returns a function that will save passed bitstrings as
 * packets in ["file.pcap"], and another function that will close that file.
 * @param caplen can be used to cap saved packet to a given number of bytes
 * @param dlt can be used to change the file's DLT (required if you do not write Ethernet packets) *)
let save sim ?caplen ?(dlt=default_dlt) fname =
    let write_pdu, close = Pdu.save ?caplen ~dlt fname in
    let write_bits bits =
        let pdu = Pdu.make fname ?caplen ~dlt (Simulation.now sim) bits in
        write_pdu pdu in
    write_bits, close

(** Recorder: a widget to record pcap files and download them.

   A recorder records one file after another, and they are told apart by what
   they are called: the reader names the file, ejects it when it holds what
   they wanted, and names the next one. The name of the recorder says where in
   the network it is listening and has nothing to do with the names of the
   files it writes -- the point of keeping a recorder is to record several
   files from the same place. *)

type recorder =
    { (* What is being recorded, as a file of [pcap_dir], or "" when nothing
       * is: a recorder with no file name has no file open and records
       * nothing. That is how it waits, both before its first file and after
       * each one is ejected. *)
      mutable fname : string ;
      caplen : int option ;
      dlt : Dlt.t ;
      widget : Widget.t ;
      (* What the port writes into. The same function for the life of the
       * recorder, since a cable is handed it once: which file it writes into,
       * and whether it writes at all, are read at each packet. *)
      mutable write : bitstring -> unit ;
      (* The file of the moment, as what writes into it and what closes it, or
       * [None] when there is none -- which is exactly when [fname] is "". *)
      mutable file : ((bitstring -> unit) * (unit -> unit)) option ;
      mutable recording : bool ;
      packets_recvd : Metric.Counter.t }

(* Open [fname] and record into it from now on.
 *
 * Recording starts with the file: naming one is asking for its contents, and a
 * recorder that had to be started as well as named would quietly miss whatever
 * happened in between. *)
let recorder_open recorder fname =
    let fname = check_fname fname in
    let path = path_of_fname fname in
    if Sys.file_exists path then
        Log.(log recorder.widget.logger Warning (lazy (Printf.sprintf
            "Overwriting %s" path))) ;
    let sim = Simulation.of_widget recorder.widget in
    let write, close =
        (* The name was the reader's, so the refusal is theirs to read: a
           directory that is not there, or not theirs to write in, is something
           they can do something about once they are told which. *)
        try save sim ?caplen:recorder.caplen ~dlt:recorder.dlt path
        with Sys_error msg -> Widget.bad_value "Cannot record into %s" msg in
    recorder.file <- Some (write, close) ;
    recorder.fname <- fname ;
    recorder.recording <- true ;
    Log.(log recorder.widget.logger Info (lazy (
        "Recording into "^ path)))

(* Stop, and let go of the file. It stays in the library under its name, which
 * is how it is downloaded (see [Myadmin_api.get_property_file]) and, one day,
 * replayed. *)
let recorder_eject recorder =
    Option.may (fun (_write, close) ->
        close () ;
        Log.(log recorder.widget.logger Info (lazy (
            "Ejecting "^ path_of_fname recorder.fname)))
    ) recorder.file ;
    recorder.file <- None ;
    recorder.fname <- "" ;
    recorder.recording <- false

let recorder ~parent ?location ?caplen ?(dlt=default_dlt) ?fname name =
    let widget = Widget.make ~parent ?location ~device:"recorder" name in
    let recorder =
        { fname = "" ; caplen ; dlt ; widget ; write = ignore ; file = None ;
          recording = false ; packets_recvd = Metric.Counter.make () } in
    recorder.write <- (fun bits ->
        match recorder.file with
        | Some (write, _close) when recorder.recording ->
            let now = Simulation.Widget.now widget in
            write bits ;
            Metric.Counter.inc recorder.packets_recvd ~now
        | _ -> ()) ;
    Option.may (recorder_open recorder) fname ;
    widget.on_delete <- (fun () -> recorder_eject recorder) ;
    widget.ports <- Widget.{
        count = (fun () -> 1) ;
        is_connected = (fun _ -> false) ;
        dev = (function _ -> { write = recorder.write ; set_read = ignore }) ;
        owner = (fun _ -> widget) ;
        disconnect = ignore } ;
    Widget.add_properties widget Widget.[
        property "recording" ~kind:Bool
            ~descr:"Tells if the packets are currently saved in the file \
                    (rather than dropped)."
            ~getter:(fun () -> `Bool recorder.recording)
            (* Nothing to record into, nothing to start: the file comes first. *)
            ~can_set:(fun () -> recorder.file <> None)
            ~setter:(fun v ->
                let v = to_bool v in
                recorder.recording <- v ;
                Log.(log recorder.widget.logger Info (lazy (Printf.sprintf
                    "%s recording into %s"
                    (if v then "Started" else "Stopped")
                    (path_of_fname recorder.fname))))) ;
        (* Kind FileName to make it downloadable.
         * Valid until ejected, when it's going to be downloaded and cleared
         * (the filename not the file). *)
        property "file name"
            ~kind:(Optional (Hint ("capture.pcap", FileName)))
            ~descr:(Printf.sprintf
                "Name of the file being recorded, in %s." !pcap_dir)
            ~getter:(fun () ->
                if recorder.fname = "" then `Null
                else `String recorder.fname)
            ~can_set:(fun () -> recorder.file = None)
            ~setter:(fun v ->
                match to_option to_string v with
                | None | Some "" -> recorder_eject recorder
                | Some fname ->
                    if recorder.file <> None then
                        bad_value
                            "Already recording into %s: eject it first"
                            recorder.fname ;
                    recorder_open recorder fname) ;
        property "caplen" ~kind:(Optional (IRange (1, 65535))) ~units:"bytes"
            ~descr:"Capture length (or interface MTU)."
            ~getter:(fun () ->
                match recorder.caplen with None -> `Null
                | Some i -> `Int i) ;
        property "dlt" ~kind:Int
            ~descr:"DLT used for the file."
            ~getter:(fun () -> `Int (Int32.to_int (recorder.dlt :> int32))) ;
        metric_property "packets" ~descr:"Packets recorded into the files"
            (Metric.Counter.T recorder.packets_recvd) ] ;
    recorder

(** When trying to read packets from a file that doesn't look like a pcap file. *)
exception Not_a_pcap_file

let bitstring_of_global_header h =
    let%bitstring hdr = {|
        0xa1b2c3d4l : 32 : endian (h.endianness) ;
        h.version_major : 16 : endian (h.endianness) ;
        h.version_minor : 16 : endian (h.endianness) ;
        h.this_zone : 32 : endian (h.endianness) ;
        h.sigfigs : 32 : endian (h.endianness) ;
        h.snaplen : 32 : endian (h.endianness) ;
        (h.dlt :> int32) : 32 : endian (h.endianness) |} in hdr

let global_header_of_bitstring name header =
    let endianness = match%bitstring (takebits 32 header) with
        | {| 0xa1b2c3d4l : 32 : bigendian |} -> BigEndian
        | {| 0xa1b2c3d4l : 32 : littleendian |} -> LittleEndian
        | {| _ |} -> raise Not_a_pcap_file in
    match%bitstring (dropbits 32 header) with
    | {| version_major : 16 : endian (endianness) ; version_minor : 16 : endian (endianness) ;
        this_zone : 32 : endian (endianness) ; sigfigs : 32 : endian (endianness) ;
        snaplen : 32 : endian (endianness) ; dlt : 32 : endian (endianness) |} ->
        { name ; endianness ; version_major ; version_minor ;
          this_zone ; sigfigs ; snaplen ; dlt = Dlt.o dlt }
   | {| _ |} -> raise Not_a_pcap_file

(** [read_global_header filename] reads the pcap global header from the
 * given file, and returns both a {!Pcap.global_header} and the input channel. *)
let read_global_header fname =
    let ic = open_in_bin fname in
    (* A file that turns out not to be a pcap is a file we opened and are not
       going to read: whoever asked for it gets the exception, and must not
       also be left holding the descriptor. *)
    match bitstring_of_string (IO.really_nread ic 24) with
    | exception e ->
        close_in ic ;
        (* Too short to hold even the header, which is one way of not being a
           pcap file and reads better as that than as an end of input. *)
        if e = IO.No_more_input then raise Not_a_pcap_file else raise e
    | header ->
        (match global_header_of_bitstring fname header with
        | exception e -> close_in ic ; raise e
        | header -> header, ic)

(** [read_next_pkt global_header ic] will return the next {!Pcap.Pdu.t} that's to
 * be read from the input stream [ic]. *)
let read_next_pkt global_header ic =
    let pkt_hdr = IO.really_nread ic 16 in
    match%bitstring (bitstring_of_string pkt_hdr) with
    | {| sec      : 32 : endian (global_header.endianness) ;
         usec     : 32 : endian (global_header.endianness) ;
         caplen   : 32 : endian (global_header.endianness) ;
         wire_len : 32 : endian (global_header.endianness) |} ->
        let pkt = IO.really_nread ic (Int32.to_int caplen) in
        let bits = bitstring_of_string pkt in
        let bits = if wire_len <= caplen then bits
                   else (
                       concat [ bits ; zeroes_bitstring (Int32.to_int (Int32.sub wire_len caplen)*8) ]
                   ) in
        let ts = Clock.Time.o (Int32.to_float sec +. (Int32.to_float usec) *. 0.000001) in
        Pdu.make global_header.name
                 ~caplen:(Int32.to_int caplen)
                 ~dlt:global_header.dlt
                 ts bits
    | {| _ |} -> should_not_happen ()

(** From a pcap file, returns an [Enum.t] of {!Pcap.Pdu.t}. *)
let enum_of_file fname =
    let global_header, ic = read_global_header fname in
    let next () =
        try read_next_pkt global_header ic
        with IO.No_more_input ->
              close_in ic ;
              raise Enum.No_more_elements
           | IO.Input_closed ->
              raise Enum.No_more_elements in
    Enum.from next

(** [write_global_header filename] write a 'generic' pcap global header and
 * returns the output channel. *)
let write_global_header fname gh =
    let oc = open_out_bin fname
    and header = bitstring_of_global_header gh in
    IO.nwrite oc (string_of_bitstring header) ;
    oc

(** [write_next_pkt global_header ic] will return the next {!Pcap.Pdu.t} that's to
 * be read from the input stream [ic]. *)
let write_next_pkt oc pdu =
    let bytes = string_of_bitstring (Pdu.pack pdu) in
    output_string oc bytes

(** [file_of_enum filename e] will save an [Enum.t] of {!Pcap.Pdu.t} into the file named [filename]. *)
let file_of_enum ?(dlt=Dlt.en10mb) fname e =
    let header = { name = fname ;
                   endianness = LittleEndian ;
                   version_major = 2 ; version_minor = 4 ;
                   this_zone = 0l ; sigfigs = 0l ;
                   snaplen = 65535l ; dlt } in
    let oc = write_global_header fname header in
    Enum.iter (write_next_pkt oc) e ;
    close_out oc

(** {2 Tools} *)

(** Informations on a pcap file. *)
type infos = { filename : string ; data_link_type : Dlt.t ;
               num_packets : int ; data_size : int64 ;
               start_time : Clock.Time.t ; stop_time : Clock.Time.t }

(** Return some informations about a pcap file (require to scan the whole file,
 * so depending on the file size it may take some time). *)
let infos_of filename =
    let pkts = enum_of_file filename in
    let min_ts = ref Float.max_num and max_ts = ref Float.min_num
    and num_packets = ref 0 and data_size = ref 0L in
    let dlt = match Enum.peek pkts with Some p -> p.Pdu.dlt | None -> Dlt.en10mb in
    Enum.iter (fun pdu ->
        incr num_packets ;
        data_size := Int64.add !data_size (Int64.of_int (Payload.length pdu.Pdu.payload)) ;
        min_ts := min !min_ts (pdu.Pdu.ts :> float);
        max_ts := max !max_ts (pdu.Pdu.ts :> float)) pkts ;
    { filename ; data_link_type = dlt ;
      num_packets = !num_packets ; data_size = !data_size ;
      start_time = Clock.Time.o !min_ts ; stop_time = Clock.Time.o !max_ts }

(* Check that we found the same values than capinfo *)
(*$= infos_of & ~printer:BatPervasives.dump
    (infos_of "tests/someweb.pcap") ({ filename = "tests/someweb.pcap" ;\
                                       data_link_type = Dlt.en10mb ;\
                                       num_packets = 173 ; data_size = 149461L ;\
                                       start_time = Clock.Time.o 1332451938.3774271 ;\
                                       stop_time = Clock.Time.o 1332451941.92178106 })
    (infos_of "tests/someweb_cut.pcap") ({ filename = "tests/someweb_cut.pcap" ;\
                                           data_link_type = Dlt.en10mb ;\
                                           num_packets = 173 ; data_size = 149461L ;\
                                           start_time = Clock.Time.o 1332451938.3774271 ;\
                                           stop_time = Clock.Time.o 1332451941.92178106 })
 *)

(** [merge [e1 ; e2 ; e3]] will merge the three [Enumt.t] of packets in chronological
 * order. *)
let rec merge = function
    | [] -> Enum.empty ()
    | a :: rest ->
        let test_ts a b = a.Pdu.ts <= b.Pdu.ts in
        Enum.merge test_ts a (merge rest)
(*$= merge & ~printer:BatPervasives.dump
    (merge [ (enum_of_file "tests/someweb.pcap" // \
        let r = ref true in fun _ -> r := not !r ; !r) ; \
             (enum_of_file "tests/someweb.pcap" // \
        let r = ref false in fun _ -> r := not !r ; !r) ] |> List.of_enum) \
                                    (enum_of_file "tests/someweb.pcap" |> List.of_enum)
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
                   with IO.No_more_input
                      | IO.Input_closed
                      | Invalid_argument _ (*"BatIO.really_nread"*) ->
                            false in
        if cont then aux () else ofs in
    Unix.truncate fname (24 (* global header *) + (aux ()))

(** [play tx "file.pcap"] will read packets from ["file.pcap"] and send them to [tx]
 * copying the pcap file frame rate. Notice that we use the internal
 * {!module:Clock} for this, so it's both very accurate or not accurate at all,
 * depending on how you look at it. *)
let play power tx fname =
    let packets = enum_of_file fname in
    (* With last_packet_timestamp (or None), schedule a function using the clock to read
       the next packet from the file. *)
    let rec read_next_pkt last_ts =
        match Enum.get packets with
            | None -> () (* pcap file is over *)
            | Some pdu ->
                let d =
                    match last_ts with
                    | None     -> Clock.Interval.zero
                    | Some lts -> Clock.Time.diff pdu.Pdu.ts lts in
                Simulation.delay power d (fun () ->
                    tx (pdu.Pdu.payload :> bitstring) ;
                    read_next_pkt (Some pdu.Pdu.ts)) ()
    in
    Simulation.asap power read_next_pkt None

(* Replayer: a widget to replay pcap files (dual of a recorder).
 *
 * Where a recorder has a single port and writes down what reaches it, a
 * replayer has as many ports as it is given cables for and sends every packet
 * into all of them: what it plays is a recording, and a recording is addressed
 * to no one in particular.
 *
 * What it follows is the file's own timestamps, not the clock it is played
 * into: two packets go out with the gap between them that the capture recorded,
 * so a file is replayed at the speed it was recorded at. *)

type replayer =
    { (* The file being played, as a file of [pcap_dir], or "" when there is
       * none: as for a recorder, that is how a replayer says it is waiting to
       * be given one. *)
      mutable fname : string ;
      widget : Widget.t ;
      (* One entry per port that has ever had a cable, in port order: the one
       * at [n] is what port [n] emits into, or [None] since the cable that was
       * there was unplugged. Unplugging leaves the slot to be filled by the
       * next cable rather than dropping it, because the ports below it are
       * numbered and cables remember which number they were given. *)
      mutable readers : (bitstring -> unit) option ref list ;
      mutable replaying : bool ;
      mutable loop : bool ;
      mutable file : (global_header * IO.input) option ;
      (* When was the last packet played: *)
      mutable last_ts : Clock.Time.t option ;
      (* Which reading of the file the packets on their way belong to.
       *
       * A packet is read and scheduled before it is due, and between those two
       * moments the reader can have paused, changed the file or taken it out.
       * Everything that does one of those bumps this, and a packet that comes
       * due bearing a number that is no longer the current one is dropped
       * along with the chain it would have continued -- otherwise resuming
       * would leave two chains reading the same file, each moving the other's
       * position in it.
       *
       * The price is the one packet that had been read but not yet sent when
       * the reader intervened: it is gone, since there is no unreading it. *)
      mutable gen : int ;
      packets_sent : Metric.Counter.t }

(* Close the file, if one is open, and forget where in it we were.
 *
 * The name is kept: what a replayer is playing and whether it is playing are
 * two different things, and a replayer that forgot the name whenever it
 * stopped could never be started again. *)
let replayer_close replayer =
    (* We could just read all packets and the enum will close the file, but that
     * might potentially be a very large file so instead we close the input stream
     * that we have: *)
    Option.may (fun (_global_header, ic) -> close_in ic) replayer.file ;
    replayer.file <- None ;
    replayer.last_ts <- None ;
    replayer.gen <- replayer.gen + 1

(* Open the file [fname] of the library, at its first packet. Also how a file
 * already open is wound back to the beginning. *)
let replayer_open replayer fname =
    let fname = check_fname fname in
    let path = path_of_fname fname in
    replayer_close replayer ;
    let global_header, ic =
        try read_global_header path with
        | Sys_error msg ->
            Widget.bad_value "Cannot replay %s" msg
        | Not_a_pcap_file ->
            Widget.bad_value "%s is not a pcap file" path in
    (* Said and not refused: what is plugged into a replayer decides what the
       bytes mean, and only whoever wired it up knows whether that is Ethernet.
       But a file of anything else is almost certainly a mistake, and one that
       shows up as unintelligible frames rather than as an error. *)
    if global_header.dlt <> default_dlt then
        Log.(log replayer.widget.logger Warning (lazy (Printf.sprintf
            "%s holds %s, not %s"
            path (Dlt.to_string global_header.dlt)
            (Dlt.to_string default_dlt)))) ;
    replayer.file <- Some (global_header, ic) ;
    replayer.fname <- fname

(* Take the file out: nothing to play, and nothing playing. *)
let replayer_eject replayer =
    if replayer.file <> None then
        Log.(log replayer.widget.logger Info (lazy (
            "Ejecting "^ path_of_fname replayer.fname))) ;
    replayer_close replayer ;
    replayer.fname <- "" ;
    replayer.replaying <- false

(* Every cable plugged into this replayer gets every packet. *)
let replayer_tx replayer bits =
    let now = Simulation.Widget.now replayer.widget in
    Metric.Counter.inc replayer.packets_sent ~now ;
    List.iter (fun reader ->
        Option.may (fun read -> read bits) !reader
    ) replayer.readers

(* Schedule the next packet of a replayer, until the file ends or replaying
 * stops. *)
let rec replay_next replayer =
    match replayer.file with
    | Some (global_header, ic) when replayer.replaying ->
        (match read_next_pkt global_header ic with
        | exception IO.No_more_input ->
            replay_end replayer
        | (pdu : Pdu.t) ->
            let d =
                match replayer.last_ts with
                | None -> Clock.Interval.zero
                | Some lts ->
                    let d = Clock.Time.diff pdu.ts lts in
                    (* A capture whose packets are not in order would otherwise
                       ask for an event in the past, which is a moment this
                       clock has no way back to. Such a packet is played as
                       soon as the one before it. *)
                    if Clock.Interval.compare d Clock.Interval.zero < 0 then
                        Clock.Interval.zero
                    else d in
            replayer.last_ts <- Some pdu.ts ;
            let sim = Simulation.of_widget replayer.widget in
            let gen = replayer.gen in
            Simulation.delay sim.power d (fun () ->
                if gen = replayer.gen then (
                    replayer_tx replayer (pdu.payload :> bitstring) ;
                    replay_next replayer)) ())
    | _ ->
        ()

(* The file is over. Wind it back either way, so that whatever starts it next
 * -- the loop, or the reader pressing play again -- starts at the first
 * packet. *)
and replay_end replayer =
    (* Nothing was played, so there is nothing to play again: a file with no
     * packets in it would otherwise loop over its own emptiness for ever. *)
    let played = replayer.last_ts <> None in
    let fname = replayer.fname in
    replayer_open replayer fname ;
    if replayer.loop && played then
        replay_next replayer
    else (
        replayer.replaying <- false ;
        Log.(log replayer.widget.logger Info (lazy (Printf.sprintf
            (if played then "Done replaying %S"
                       else "Nothing to replay in %S") fname))))

let replayer ~parent ?location ?fname ?(loop=false) name =
    let widget = Widget.make ~parent ?location ~device:"replayer" name in
    let replayer =
        { fname = "" ; widget ; readers = [] ; replaying = false ; loop ;
          file = None ; last_ts = None ; gen = 0 ;
          packets_sent = Metric.Counter.make () } in
    (* Named at birth is named by the reader: it plays at once, as a recorder
       named at birth records at once. *)
    Option.may (fun fname ->
        replayer_open replayer fname ;
        replayer.replaying <- true ;
        replay_next replayer) fname ;
    widget.on_delete <- (fun () -> replayer_eject replayer) ;
    widget.ports <- Widget.{
        count = (fun () -> List.length replayer.readers + 1) ;
        is_connected = (fun n ->
            if n = List.length replayer.readers then false else
            match List.nth replayer.readers n with
            | exception _ -> Widget.bad_value "No such port #%d" n
            | reader -> !reader <> None) ;
        dev = (fun n ->
            { write = ignore ;
              (* Into port [n] and no other: a freed slot when that is what was
                 handed out, and a new one at the end otherwise. The port a
                 cable was given is the one it asks to be disconnected from, so
                 a reader that went in anywhere else would leave that cable
                 unable to let go -- and the port it really took reading as
                 free to the next cable. *)
              set_read = (fun f ->
                match List.nth replayer.readers n with
                | exception _ ->
                    replayer.readers <- replayer.readers @ [ ref (Some f) ]
                | reader -> reader := Some f) }) ;
        owner = (fun _ -> widget) ;
        disconnect = (fun n ->
            match List.nth replayer.readers n with
            | exception _ -> Widget.bad_value "No such port #%d" n
            | { contents = None } -> Widget.bad_value "Port #%d is not connected" n
            | { contents = Some _ } as r -> r := None) } ;
    Widget.add_properties widget Widget.[
        property "replaying" ~kind:Bool
            ~descr:"Tells if the packets are currently being replayed from \
                    the file (or if the replay is on pause)"
            ~getter:(fun () -> `Bool replayer.replaying)
            (* Nothing to play, nothing to start: the file comes first. *)
            ~can_set:(fun () -> replayer.file <> None)
            ~setter:(fun v ->
                let v = to_bool v in
                if v <> replayer.replaying then (
                    (* Whatever was already on its way belongs to the reading
                       that is being interrupted here (see [gen]). *)
                    replayer.gen <- replayer.gen + 1 ;
                    replayer.replaying <- v ;
                    if v then replay_next replayer ;
                    Log.(log replayer.widget.logger Info (lazy (Printf.sprintf
                        "%s replaying into %d readers"
                        (if v then "Started" else "Stopped")
                        List.(length (filter (function
                            | { contents = Some _ } -> true
                            | _ -> false
                        ) replayer.readers))))))) ;
        (* Named while there is no file, read while there is one, exactly as a
           recorder's is (see [recorder]): the file being played cannot be
           swapped under the replayer, and the way to be done with one is to
           take it out -- which is what setting this to nothing does. *)
        property "file name" ~kind:(Optional (Hint ("capture.pcap", FileName)))
            ~descr:(Printf.sprintf
                "Name of the file being replayed, from %s." !pcap_dir)
            ~getter:(fun () ->
                if replayer.fname = "" then `Null
                else `String replayer.fname)
            ~can_set:(fun () -> replayer.file = None)
            ~setter:(fun v ->
                match to_option to_string v with
                | None | Some "" ->
                    replayer_eject replayer
                | Some fname ->
                    if replayer.file <> None then
                        bad_value "Already replaying %s: eject it first"
                            replayer.fname ;
                    replayer_open replayer fname ;
                    replayer.replaying <- true ;
                    replay_next replayer) ;
        property "loop" ~kind:Bool
            ~descr:"Restart from the beginning when done."
            ~getter:(fun () -> `Bool replayer.loop)
            ~setter:(fun v ->
                let v = to_bool v in
                replayer.loop <- v ;
                (* A file that had been played to its end is wound back but not
                   playing: asking for it to loop is asking for it to go on. *)
                if v && not replayer.replaying && replayer.file <> None then (
                    replayer.gen <- replayer.gen + 1 ;
                    replayer.replaying <- true ;
                    replay_next replayer)) ;
        metric_property "packets" ~descr:"Packets replayed from the files"
            (Metric.Counter.T replayer.packets_sent) ] ;
    replayer


(** {2 User friendly functions for capturing/injecting packets} *)

(** A network device opened for sniffing or injection *)
type iface = { handler : iface_handler ;
                  name : string ;
                caplen : int ;
               (* Interfaces can be opened and closed, but that's still the same
                * interface. There is nothing to reset and events need not be
                * removed from the scheduler. So here the power is going to be
                * the Simulation.mains. *)
                 power : Simulation.power ;
                widget : Widget.t }

let default_caplen ifname =
    if ifname = "any" then 65535
    else mtu_of_iface ifname

(** [openif "eth0" true "port 80" 96] returns the iface representing eth0,
 * in promiscuous mode, filtering port 80 and capturing only the first 96 bytes
 * of each packets. Notice that if [caplen] is not set then {e MTU} for the
 * device will be chosen.
 *
 * Pass it a widget to log and pay for events. *)
let openif ~widget ?(promisc=true) ?(filter="") ?caplen ifname =
    let caplen =
        Option.default_delayed (fun () -> default_caplen ifname) caplen in
    let iface = {
        handler = openif_ ifname promisc filter caplen ;
        name = ifname ;
        caplen ;
        power = (Simulation.of_widget widget).Simulation.power ;
        widget } in
    (* A real interface only makes sense in a realtime simulation: *)
    Simulation.make_realtime (Simulation.of_widget widget) ;
    iface

(** Never use the handler after that! *)
let closeif iface =
    Log.(log iface.widget.logger Info (lazy (Printf.sprintf "Closing interface %s" iface.name))) ;
    closeif_ iface.handler

(** [sniff iface] will return the next available packet as a Pcap.Pdu.t.
 *
 * Dated on the simulation's clock, not on the one libpcap read: a simulation
 * that was tied to the wall clock after having run at its own speed is some
 * distance from it, and a packet still carrying the real world's timestamp
 * would be scheduled that far into its past or its future. See
 * [Simulation.of_wall_clock]. *)
let sniff ?dlt ?timeout iface =
    let sniffed = sniff_ ?timeout iface.handler in
    Log.(log iface.widget.logger Debug (lazy (Printf.sprintf "Captured %d/%d bytes" sniffed.sniffed_caplen sniffed.sniffed_wirelen))) ;
    let ts =
        Simulation.of_wall_clock (Simulation.of_widget iface.widget)
                                 sniffed.sniffed_timestamp in
    Pdu.make iface.name ?dlt
        ~caplen:sniffed.sniffed_caplen
        ~wirelen:sniffed.sniffed_wirelen
        ts
        (bitstring_of_string sniffed.sniffed_bytes)

(** {2 Packet injection} *)

(* Waiting to be attached to the widget that owns them, which will supply the
 * clock they must be dated with:

(** A counter for how many packets we failed to inject. *)
let packets_injected_err = Metric.Atomic.make "Pcap/Packets/Injected/Err"

(** A counter for how many bytes were injected successfully. *)
let bytes_out            = Metric.Counter.make "Pcap/Bytes/Out" "bytes"
*)

(** [inject iface bits] inject the packet [bits] into interface [iface]. *)
let inject (iface : iface) bits =
    (* let params = Metric.(Params.singleton "iface" Param.(String iface.name)) in *)
    try
        let str = string_of_bitstring bits in
        Log.(log iface.widget.logger Debug (lazy (Printf.sprintf "Injecting %d bytes" (String.length str)))) ;
        inject_ iface.handler str
        (* Metric.Counter.add ~params bytes_out (bytelength bits) *)
    with e ->
        Log.(log iface.widget.logger Error (lazy (Printf.sprintf "Cannot inject: %s" (Printexc.to_string e))))
        (* Metric.Atomic.fire ~params packets_injected_err *)

(** {2 Packet sniffing} *)

(* Waiting for their widget, as above:

(** A counter for how many packets were sniffed. *)
let packets_sniffed_ok = Metric.Atomic.make "Pcap/Packets/Sniffed"

(** A counter for how many bytes were sniffed. *)
let bytes_in           = Metric.Counter.make "Pcap/Bytes/In" "bytes"
*)

(** [sniffer iface rx] returns a thread that continuously sniff packets
 * and pass them to the [rx] function (via the Clock). *)
let sniffer iface ?(while_=(fun () -> true)) rx =
    let rec loop () =
        if while_ () && iface.power.on then
            (* Although we should not close the interface while this is running,
             * sniff should just fail with End_of_file in those cases. *)
            match sniff ~timeout:0.5 iface with
            | exception End_of_file ->
                Log.(log iface.widget.logger Warning (lazy (Printf.sprintf "Interface %s has been closed while in use!" iface.name)))
            | exception Not_found ->
                (* Loop to check the ending condition again *)
                if debug then
                    Log.(log iface.widget.logger Debug (lazy (Printf.sprintf "No packet to capture yet on interface %s" iface.name))) ;
                loop ()
            | exception e ->
                Log.(log iface.widget.logger Error (lazy (Printf.sprintf "Cannot capture packet on %s: %s" iface.name (Printexc.to_string e))))
            | pdu ->
                Simulation.synch (Simulation.of_widget iface.widget) ;
                (* Metric.Atomic.fire packets_sniffed_ok ;
                   Metric.Counter.add bytes_in (Payload.length pdu.Pdu.payload) ; *)
                Simulation.at iface.power pdu.Pdu.ts rx (pdu.Pdu.payload :> bitstring) ;
                loop () in
    Thread.create loop ()

(** A Pcap.portal is a widget representing a real network interface form the
 * host, that can be added to a simulation and will have a single pluggable
 * port where to attach cables, to exchange packets with a real interface. *)

type portal = {
   (* Share the widget with this iface: *)
   mutable iface : iface option ;
           (* Everything to rebuild the iface: *)
          ifname : string ; (* Could be editable if we could rename widgets *)
          widget : Widget.t ; (* Shared with the iface *)
 (* Those three properties require closing/reopening the iface
  * for a change to take effect. The handler is opened with it,
  * and libpcap has no way to change it afterwards. *)
 mutable promisc : bool ;
  mutable filter : string ;
  mutable caplen : int option ;
    mutable emit : (bitstring -> unit) option ;
  mutable reader : Thread.t option }

let set_read (portal : portal) f =
    Log.(log portal.widget.logger Debug (lazy (Printf.sprintf "Setting emitter for portal %s" portal.ifname))) ;
    portal.emit <- Some f

let is_connected portal =
    portal.emit <> None

let dev (portal : portal) =
    { write = (fun bits ->
        (* Any writer will hold the simulation lock so iface is not going to be
         * closed before we are done writing *)
        match portal.iface with
        | Some iface -> inject iface bits
        | None -> ()) ;
      set_read = set_read portal }

let disconnect portal =
    if is_connected portal then (
        Log.(log portal.widget.logger Debug (lazy (Printf.sprintf
            "Disconnecting portal %s" portal.ifname))) ;
        portal.emit <- None
    ) else
        Log.(log portal.widget.logger Debug (lazy (Printf.sprintf
            "Ignoring request to disconnect portal %s, which is not \
             connected" portal.ifname)))

let power_down portal =
    match portal.iface with
    | Some iface ->
        Log.(log iface.widget.logger Info (lazy ("Closing portal to "^ iface.name))) ;
        (* Stop the reader thread *first*, then close the iface while nobody uses
         * the handle. But do not wait with the lock: do the cleaning from another
         * thread, releasing the simulation lock right now: *)
        portal.iface <- None ;
        Option.may (fun reader_thread ->
            Thread.create (fun reader_thread ->
                Thread.join reader_thread ;
                (* Even if power_up have been called already on the same portal,
                 * the new iface will be a new pcap handle so we can still close
                 * this one safely: *)
                closeif iface
            ) reader_thread |> ignore
        ) portal.reader ;
        (* Also clear [portal.reader] while we have the lock: *)
        portal.reader <- None ;
    | None ->
        Log.(log portal.widget.logger Debug (lazy
            "Ignoring request to close closed portal."))

let power_up portal =
    Log.(log portal.widget.logger Info (lazy ("Opening portal to "^ portal.ifname))) ;
    if portal.iface <> None then power_down portal ;
    let iface =
        openif ~widget:portal.widget ~promisc:portal.promisc
               ~filter:portal.filter ?caplen:portal.caplen portal.ifname in
    portal.iface <- Some iface ;
    portal.reader <- Some (
        sniffer iface
            ~while_:(fun () ->
                (* Continue as long as we uses the same iface: *)
                match portal.iface with None -> false | Some i -> i == iface)
            (fun bits ->
                (* Use the current emit function not the one at power_up: *)
                Option.may (fun emit -> emit bits) portal.emit))

(* Create a portal.
 * [location] is where that interface is: a real one injecting real traffic is
 * a device of the simulated network like any other, and has to be somewhere on
 * the map for the traffic coming out of it to have come from anywhere. *)
let portal ~parent ?location ?(promisc=true) ?(filter="") ?caplen ifname =
    let widget = Widget.make ~parent ?location ~device:"portal" ifname in
    let portal = {
        iface = None ;
        ifname ; widget ; promisc ; filter ; caplen ;
        emit = None ;
        reader = None } in
    widget.on_delete <- (fun () -> power_down portal) ;
    widget.ports <- Widget.{
        count = (fun () -> 1) ;
        is_connected = (fun _ -> is_connected portal) ;
        dev = (fun _ -> dev portal) ;
        owner = (fun _ -> widget) ;
        disconnect = (fun _ -> disconnect portal) } ;
    Widget.add_properties widget Widget.[
        property "on" ~descr:"The interface is opened." ~kind:Bool
            ~getter:(fun () -> `Bool (portal.iface <> None))
            ~setter:(fun v ->
                let v = to_bool v in
                try
                    (if v then power_up else power_down) portal
                with e ->
                    bad_value "Cannot power %s interface %s: %s"
                        (if v then "up" else "down") portal.ifname
                        (Printexc.to_string e)) ;
        property "name" ~kind:String
            ~descr:"Interface name."
            ~getter:(fun () -> `String portal.ifname) ;
        property "promisc" ~kind:Bool
            ~descr:"Is the interface opened in promiscuous mode."
            ~getter:(fun () -> `Bool portal.promisc)
            ~setter:(fun v -> portal.promisc <- to_bool v) ;
        property "filter" ~kind:String
            ~descr:"Filter applied to capture traffic."
            ~getter:(fun () -> `String portal.filter)
            ~setter:(fun v -> portal.filter <- to_string v) ;
        property "caplen" ~kind:(Optional (IRange (1, 65535))) ~units:"bytes"
            ~descr:"Capture length (or interface MTU)."
            ~getter:(fun () ->
                match portal.caplen with None -> `Null
                | Some i -> `Int i)
            ~setter:(fun v ->
                portal.caplen <- to_option (to_int_range ~min:1 ~max:65535) v) ] ;
    portal
