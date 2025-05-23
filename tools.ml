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
  Various functions/types prevalent in the library.
  *)
open Batteries
open Bitstring

let ensure cond msg =
    if not cond then (
        flush stdout ;
        Printf.fprintf stderr "ERROR: %s\n%s\n%!"
            msg (Printexc.get_backtrace ()) ;
        assert false
    )

let error msg =
    ensure false msg ;
    assert false (* so we have no output type *)

let should_not_happen _ =
    error "Are you certain this really happened?"

let todo what =
    error ("I refuse to proceed without instructions for "^what)

(* [jitter r v] returns a random value between v-r% and v+r%, where r is
 * supposed to be a ratio from 0 to 1. *)
let jitter r v =
    v +. (Random.float 2. -. 1.) *. r *. abs_float v

(*$Q jitter
   Q.float (fun v -> let v' = jitter 0.1 v in abs_float (v'-.v) <= abs_float (v *. 0.1))
 *)

let bytelength bs = (bitstring_length bs + 7) lsr 3

let takebytes n bs = takebits (n lsl 3) bs

let extendbytes n bs =
    concat [ bs ; create_bitstring ((n lsl 3) - bitstring_length bs) ]

let bitstring_is_empty bs = bitstring_length bs = 0

let dropbytes n bs = dropbits (n lsl 3) bs

let fixedbits len bits =
    let l = bitstring_length bits in
    if l < len then concat [ bits ; zeroes_bitstring (len-l) ]
    else takebits len bits

(* err_rate is the average number of errors per bits *)
let bitstring_fuzz err_rate bits =
    if err_rate = 0. then bits else
    let noerr_len = 1. /. err_rate in (* average number of bits without errors *)
    let rec aux prevs rest =
        let len = 1 + Int.of_float (Random.float (2. *. noerr_len)) in (* incorrect but fast *)
        match%bitstring rest with
        | {| b1 : len-1 : bitstring ;
             b  : 1 ;
             b2 : -1 : bitstring |} ->
            let b = (if b then zeroes_bitstring else ones_bitstring) 1 in
            aux (b :: b1 :: prevs) b2
        | {| rest : -1 : bitstring |} ->
            concat (List.rev (rest :: prevs)) in
    aux [] bits
(*$T bitstring_fuzz
  let str = "pas glop pas glop" in \
  string_of_bitstring (bitstring_fuzz 0.1 (bitstring_of_string str)) <> str
*)

(** Shift [n]th bit (counting from higher bit!).
 * Modify the passed bitstring! *)
let bitstring_shift n bits =
    let v = if Bitstring.is_clear bits n then 1 else 0 in
    Bitstring.put bits n v

(*$= bitstring_shift & ~printer:hexstring_of_bitstring
  (bitstring_of_int8 0xE0) (let b = bitstring_of_int8 0xA0 in bitstring_shift 1 b ; b)
  (bitstring_of_int8 0xA0) (let b = bitstring_of_int8 0xE0 in bitstring_shift 1 b ; b)
*)

(* Do not modify b after that unless you also intend to modify that bitstring! *)
let bitstring_of_subbytes b ofs len =
    if len > Bytes.length b then invalid_arg "bitstring_of_bytes" ;
    b, ofs, len lsl 3

(* See above warning *)
let bitstring_of_bytes b =
    bitstring_of_subbytes b 0 (Bytes.length b)

let bytes_of_bitstring b =
    string_of_bitstring b |> Bytes.of_string

(* Only for bitstrings shorter than 64 bits *)
let bitstring_add i b =
    let len = bitstring_length b in
    if len > 31 then (
        match%bitstring b with
        | {| pref : len - 31 : bitstring ;
             n : 31 |} ->
            let%bitstring b = {|
                pref : len - 31 : bitstring ;
                n + i : 31 |} in b
    ) else (
        match%bitstring b with
        | {| n : len : int |} ->
            let%bitstring b = {| Int64.add n (Int64.of_int i) : len |} in b
    )
(*$= bitstring_add
    (bitstring_of_string "\000" |> bitstring_add 42) (bitstring_of_string "\042")
    (bitstring_of_string "\042" |> bitstring_add 42) (bitstring_of_string "\084")
 *)

let hexstring s =
    (* FIXME: make use of hexdump_bitstring *)
    let hexify c = Printf.sprintf "%02x" (Char.code c) in
    String.enum s /@ hexify |> List.of_enum |> String.join " "

let hexstring_of_bitstring =
    hexstring % string_of_bitstring

let hexstring_of_bitstring_abbrev ?(bits=64) bs =
    if bitstring_length bs <= bits then hexstring_of_bitstring bs
    else hexstring_of_bitstring (takebits (bits-8) bs) ^ "..."
(*$= hexstring_of_bitstring_abbrev & ~printer:identity
     (hexstring_of_bitstring_abbrev (bitstring_of_string "\x42")) "42"
     (hexstring_of_bitstring_abbrev (bitstring_of_string "abcdefgh"))  "61 62 63 64 65 66 67 68"
     (hexstring_of_bitstring_abbrev (bitstring_of_string "abcdefghi")) "61 62 63 64 65 66 67..."
 *)

let substring_of_bitstring bs ofs len =
    let s = string_of_bitstring bs in
    String.sub s ofs len

(* Starting comparing from high bits: *)
let bitstring_common_prefix_length bs1 bs2 =
    let rec loop n =
        try
            if Bitstring.is_set bs1 n = Bitstring.is_set bs2 n then
                loop (n + 1)
            else
                n
        with Invalid_argument _ ->
            n
    in
    loop 0

(*$= bitstring_common_prefix_length & ~printer:string_of_int
  3 (bitstring_common_prefix_length (bitstring_of_int32 0x8000_0000) \
                                    (bitstring_of_int32 0x9000_0000))
  4 (bitstring_common_prefix_length (bitstring_of_int32 0x8000_0000) \
                                    (bitstring_of_int32 0x8800_0000))
  8 (bitstring_common_prefix_length (bitstring_of_int32 0x8000_0000) \
                                    (bitstring_of_int32 0x8080_0000))
 *)

let bitstring_enum ~from ~until =
    (* [until] is inclusive: *)
    Enum.from_loop from (fun bits ->
        if Bitstring.compare bits until > 0 then raise Enum.No_more_elements ;
        let next = bitstring_add 1 bits in
        bits, next)

(*$= bitstring_enum & ~printer:(IO.to_string (List.print Int.print))
  [ 1 ; 2 ; 3 ] (bitstring_enum ~from:(bitstring_of_int8 1) ~until:(bitstring_of_int8 3) /@ int_of_bitstring |> List.of_enum)
  [ 1 ] (bitstring_enum ~from:(bitstring_of_int8 1) ~until:(bitstring_of_int8 1) /@ int_of_bitstring |> List.of_enum)
  [] (bitstring_enum ~from:(bitstring_of_int8 2) ~until:(bitstring_of_int8 1) /@ int_of_bitstring |> List.of_enum)
*)

let printable str =
    let is_printable c =
        Char.is_latin1 c || Char.is_digit c || Char.is_symbol c || c = ' ' in
    String.map (fun c -> if is_printable c then c else '.') str

let print_bitstring fmt bits =
    let rec aux bits =
        match%bitstring bits with
        | {| a : 64 : bitstring ;
             b : 64 : bitstring ;
             rest : -1 : bitstring |} ->
            Format.fprintf fmt "%s - %s  %s%s@\n"
                (hexstring_of_bitstring a) (hexstring_of_bitstring b)
                (printable (string_of_bitstring a)) (printable (string_of_bitstring b)) ;
            aux rest
        | {| a : 64 : bitstring ;
             b : -1 : bitstring |} when not (bitstring_is_empty b) ->
            Format.fprintf fmt "%s - %-23s  %s%s@\n"
                (hexstring_of_bitstring a) (hexstring_of_bitstring b)
                (printable (string_of_bitstring a)) (printable (string_of_bitstring b))
        | {| a : -1 : bitstring |} ->
            if not (bitstring_is_empty a) then
            Format.fprintf fmt "%-23s                            %s@\n"
                (hexstring_of_bitstring a) (printable (string_of_bitstring a)) in
    Format.open_vbox 0 ; (* if not 0 then the first line is less indented than the others *)
    aux bits ;
    Format.close_box ()

(* Simple conversion from bitstrings to int (when the bitstring is small enough to fit
 * in an int). Used for tests only. *)
let int_of_bitstring bs =
    let l = bitstring_length bs in
    (* bitstring fills bytes from high to low bits but we'd like out int to be the lower bits *)
    let bs = if l < 8 then Bitstring.concat [create_bitstring (8-l) ; bs] else bs in
    match%bitstring bs with
    | {| n : 8 ; _ : -1 : bitstring |} -> n

(*$= int_of_bitstring & ~printer:dump
    0 (int_of_bitstring (let%bitstring b = {| 0 : 3  : littleendian |} in b))
    1 (int_of_bitstring (let%bitstring b = {| 1 : 3  : littleendian |} in b))
    2 (int_of_bitstring (let%bitstring b = {| 2 : 3  : littleendian |} in b))
    3 (int_of_bitstring (let%bitstring b = {| 3 : 3  : littleendian |} in b))
    2 (int_of_bitstring (let%bitstring b = {| 2 : 30 : littleendian |} in b))
*)

let int32_of_bitstring bits =
    match%bitstring bits with
    | {| n : 32 ; _ : -1 : bitstring |} -> n

let bitstring_of_int8 n =
    let%bitstring s = {| n : 8 |} in
    s

let bitstring_of_int16 n =
    let%bitstring s = {| n : 16 |} in
    s

let bitstring_of_int32 n =
    let n = int32_of_int n in
    let%bitstring s = {| n : 32 |} in
    s

(* bitstring_of_int32 always returns a 32bits string, and bits are counted from
 * the highest bit: *)
(*$T
  Bitstring.is_set (bitstring_of_int32 0x80) (31 - 7)
  not (Bitstring.is_set (bitstring_of_int32 0x80) 0)
  not (Bitstring.is_set (bitstring_of_int32 0x80) 31)
*)

let bitstring_copy bs =
    string_of_bitstring bs |>
    String.copy |>
    bitstring_of_string |>
    takebits (bitstring_length bs)

(* [all bits n] returns all bitstrings of n bits (as an enum) *)
let all_bits n =
    let succ bs = (* interpreting bs as little endian *)
        let bs = bitstring_copy bs in (* we are going to modify it inplace *)
        let rec aux i =
            if i < 0 then None else
            if Bitstring.is_set bs i then (
                Bitstring.clear bs i ;
                aux (i-1)
            ) else (
                Bitstring.set bs i ;
                Some bs
            ) in
        aux (n-1) in
    let bs = ref (Some (create_bitstring n)) in
    Enum.from (fun () ->
        match !bs with
        | Some v ->
            bs := succ v ;
            v
        | None -> raise Enum.No_more_elements)
(*$= all_bits & ~printer:(IO.to_string (List.print Int.print))
  [ 0 ; 1 ; 2 ; 3 ] (all_bits 2 /@ int_of_bitstring |> List.of_enum)
  [ 2 ; 2 ; 2 ; 2 ] (all_bits 2 /@ bitstring_length |> List.of_enum)
  [ 0 ; 1 ]         (all_bits 1 /@ int_of_bitstring |> List.of_enum)
  [ 1 ; 1 ]         (all_bits 1 /@ bitstring_length |> List.of_enum)
*)

(* Check if a & mask = b & mask *)
let match_mask mask a b =
    let len = bitstring_length mask in
    bitstring_length a = len &&
    bitstring_length b = len &&
    let a = string_of_bitstring a
    and b = string_of_bitstring b
    and m = string_of_bitstring mask in
    try
        for i = 0 to String.length m - 1 do
            let c s = Char.code s.[i] in
            let a = c a and b = c b and m = c m in
            if a land m <> b land m then raise Exit
        done ;
        true
    with Exit -> false

(*$T match_mask
  match_mask (bitstring_of_int32 0xfff0) (bitstring_of_int32 0x1234) (bitstring_of_int32 0x1239)
  not (match_mask (bitstring_of_int32 0xfff0) (bitstring_of_int32 0x1234) (bitstring_of_int32 0x5234))
*)

let abbrev ?(len=25) str =
    let tot_len = String.length str in
    if len < tot_len then (String.sub str 0 (len-3)) ^ "..."
    else str

let rec string_find_first ?(from=0) f str =
    if from >= String.length str then raise Not_found ;
    if f str.[from] then from else string_find_first ~from:(from+1) f str

let int_of_hexchar c_ =
    let c = Char.code c_ in
    if c >= Char.code '0' && c <= Char.code '9' then c - Char.code '0' else
    if c >= Char.code 'a' && c <= Char.code 'f' then 10 + c - Char.code 'a' else
    if c >= Char.code 'A' && c <= Char.code 'F' then 10 + c - Char.code 'A' else (
        Printf.fprintf stderr "Tools: Char is not hex: '%c'\n" c_ ;
        invalid_arg "Bad char"
    )

let int_of_hexstring s =
    let len = String.length s in
    let rec aux v i =
        if i >= len then v else
        let d = int_of_hexchar s.[i] in
        aux (v*16 + d) (i+1) in
    try Some (aux 0 0)
    with Invalid_argument _ ->
        Printf.fprintf stderr "Tools: Bad char in hexstring '%s'\n" (abbrev s) ;
        None

(*$= int_of_hexstring & ~printer:dump
    (Some 26) (int_of_hexstring "0000001A")
    (Some 47) (int_of_hexstring "2F")
*)

let bitstring_of_hexstring str =
    let bytes = Bytes.create ((String.length str + 1)/ 2) in
    let is_digit n =
        n < String.length str &&
        let c = str.[n] in
        c >= '0' && c <= '9' ||
        c >= 'a' && c <= 'f' ||
        c >= 'A' && c <= 'A' in
    let rec loop s d =
        let rec skip s =
            if s < String.length str - 1 && not (is_digit s) then
                skip (s + 1)
            else
                s in
        let s = skip s in
        if is_digit s then (
            (* Accept up to 2 digits: *)
            let v, s = int_of_hexchar str.[s], s + 1 in
            let v, s =
                if is_digit s then
                    v lsl 4 + int_of_hexchar str.[s], s + 1
                else
                    v, s in
            Bytes.set bytes d (Char.chr v) ;
            loop s (d + 1)
        ) else d in
    let d = loop 0 0 in
    assert (d <= Bytes.length bytes) ;
    bitstring_of_subbytes bytes 0 d

(*$T bitstring_of_hexstring
  Bitstring.equals (bitstring_of_hexstring "00 00 00") (zeroes_bitstring 24)
  Bitstring.equals (bitstring_of_hexstring "0") (zeroes_bitstring 8)
  Bitstring.equals (bitstring_of_hexstring "12 34 56") \
                   (bitstring_of_hexstring " 12--34--56")
*)

let may_default v_opt f = match v_opt with Some v -> v | None -> f ()

let max_opt a b =
    match a, b with
    | None, _ -> b
    | _, None -> a
    | Some a, Some b -> Some (max a b)

(* FIXME: use enums *)
let rec remove_last_if cond = function
    | [] -> []
    | i :: [] -> if cond i then [] else i :: []
    | i :: l  -> i :: (remove_last_if cond l)

let none_if_not_found f x = try Some (f x) with Not_found -> None
let none_if_exception f x = try Some (f x) with _ -> None
let assert_ok x = if Result.is_bad x then should_not_happen ()

let str_all_matches str =
    let rec aux prevs n =
        try let m = Str.matched_group n str in
            aux (m::prevs) (n+1)
        with Not_found -> aux (""::prevs) (n+1)
           | Invalid_argument _ -> List.rev prevs in
    aux [] 0

(*$= str_all_matches & ~printer:dump
    [ "foobaaaaa" ; "oo" ; "aaaaa" ] \
        (let str = "foobaaaaar" in \
         let _ = Str.string_match (Str.regexp "f\\(o+\\)b\\(a+\\)") str 0 in \
         str_all_matches str)
*)

module HashedBits : Hashtbl.HashedType with type t = bitstring = struct
    type t = bitstring
    let equal = Bitstring.equals
    let hash t = Hashtbl.hash (string_of_bitstring t)
end

module BitHash = Hashtbl.Make (HashedBits)

let hash_find_or_insert h k f =
    try Hashtbl.find h k
    with Not_found -> (
        let v = f () in
        Hashtbl.add h k v ;
        v
    )

let hash_merge h h' =
    Hashtbl.iter (fun k v -> Hashtbl.add h k v) h'

let file_content f =
    File.with_file_in f IO.read_all

(* Get some information about a HW device (on Linux). *)
let info_of_iface ifname what =
    let fname = Printf.sprintf "/sys/class/net/%s/%s" ifname what in
    File.lines_of fname |> Enum.get_exn

(** Get the MTU of a device (on Linux). May raise all kind of exceptions. *)
let mtu_of_iface ifname =
    info_of_iface ifname "mtu" |> int_of_string

let mac_of_iface ifname =
    info_of_iface ifname "address"

let list_dir path =
  let hdl = Unix.opendir path in
  finally
    (fun () -> Unix.closedir hdl)
    (fun () ->
      let rec loop acc =
        match Unix.readdir hdl with
        | exception End_of_file ->
            List.rev acc
        | entry ->
            loop (entry :: acc) in
      loop [])
    ()

external addresses_of_iface : string -> string list = "wrap_addresses_of_iface"

let list_interfaces () =
    let sys_class_net = "/sys/class/net" in
    let dirs = list_dir sys_class_net in
    List.filter_map (fun ifname ->
        if ifname <> "." && ifname <> ".." then
            Some ifname
        else
            None
    ) dirs

(** An OrdArray is a container for an ordered set of bounded size. *)
module OrdArray =
struct
    (*$< OrdArray *)
    type entry = { mutable prev : int ;
                   mutable next : int }
    type 'a t =
        {     last_used : entry array ; (** The ordered list of indices. *)
          mutable first : int ;         (** The index of the first element. *)
           mutable last : int ;         (** and the last one. *)
                   data : 'a array }    (** User data *)

    let make_from_data data =
        let s = Array.length data in
        { last_used = Array.init s (fun i ->
            (* -1 is for invalid: *)
            { prev = if i = 0 then -1 else i-1 ;
              next = if i = s-1 then -1 else i+1 }) ;
          first = 0 ;
          last = s-1 ;
          data  }

    let make s x = make_from_data (Array.create s x)
    let init s f = make_from_data (Array.init s f)

    (** Returns the first and last indices: *)
    let first t = t.first
    let last t = t.last

    (** So that [get t (first t)] will return the first data item in the queue *)
    let get t n = t.data.(n)
    let set t n x = t.data.(n) <- x

    let unlink t n =
        if t.last_used.(n).prev <> -1 then
            t.last_used.(t.last_used.(n).prev).next <- t.last_used.(n).next ;
        if t.last_used.(n).next <> -1 then
            t.last_used.(t.last_used.(n).next).prev <- t.last_used.(n).prev ;
        if t.first = n then t.first <- t.last_used.(n).next ;
        if t.last = n then t.last <- t.last_used.(n).prev

    (* n must have already been unlinked! *)
    let link_at_head t n =
        t.last_used.(n).prev <- -1 ;
        t.last_used.(n).next <- t.first ;
        t.last_used.(t.first).prev <- n ;
        t.first <- n

    let promote t n =
        unlink t n ;
        link_at_head t n

    (*$R promote
        let oa = make_from_data [| 5;6;7 |] in
        assert_equal ~printer:string_of_int ~msg:"order should be preserved at creation"
            5 (get oa (first oa)) ;
        promote oa 1 ;
        assert_equal ~printer:string_of_int ~msg:"promoted item should come first"
            6 (get oa (first oa)) ;
        assert_equal ~printer:string_of_int ~msg:"but last one should not change"
            7 (get oa (last oa))
     *)

    (* Overwrite the last entry with [x] and make it the new first entry: *)
    let prepend t x =
        set t t.last x ;
        promote t t.last

    (*$>*)
end


(* Some random generators for tests *)
let randi bits =
    let mask = (1 lsl bits) - 1 in
    Random.bits () land mask

let rand32 () = Int32.of_int64 (Random.int64 0x100000000L)

let randb = Random.bool

let randstr ?charset len =
    let rc _i = Random.char ()
    and sc s _s = s.[Random.int (String.length s)] in
    String.init len (match charset with None -> rc | Some s -> sc s)

let randbs len (* in bytes! *)=
    randstr len |> bitstring_of_string

let rand_hostname () =
    let num_parts = 1 + randi 3 in
    let parts = List.init num_parts (fun _i ->
        randstr ~charset:"abcdefghijklmnopqrstuvwxyz-" (3 + randi 4)) in
    String.join "." parts

let do_sum bits =
    let rec aux s bits = match%bitstring bits with
        | {| w : 16 ; rest : -1 : bitstring |} -> aux (s + w) rest
        | {| b : 8 |} -> s + (b lsl 8)
        | {| _ |} -> s in
    let s = aux 0 (concat [ bits ; zeroes_bitstring 7 ]) in
    let rec wrap s =
        if s < 0x10000 then s else wrap ((s land 0xffff) + (s lsr 16)) in
    (lnot (wrap s)) land 0xffff
(*$= do_sum & ~printer:(fun d -> Printf.sprintf "%x" d)
  (do_sum (bitstring_of_string "\x45\x00\x00\xaa\x03\xa6\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x45\xd1\x55\xe3\x67")) 0xfffd
*)

(* As computing checksum was found to consume 30% of CPU (yes, the above function)
 * then here is a simple way to disable this *)
let do_compute_checksum = ref true
let sum bits =
    if !do_compute_checksum then
        do_sum bits
    else Random.int 65536

module Payload = struct
    include Private.Make (struct
        type t = bitstring
        let to_string t =
            let bytes = bytelength t in
            if bytes > 0 then (
                Printf.sprintf "%d bytes (%s)" bytes (hexstring_of_bitstring_abbrev t)
            ) else "empty"
        let is_valid _ = true
        let repl_tag = "bits"
    end)

    let empty = o empty_bitstring
    let bitlength (t : t) = bitstring_length (t :> bitstring)
    let length (t : t) = bytelength (t :> bitstring)
    let random len = o (randbs len)
    (* Since a bitstring is a slice, if we want a hash of the content we have
     * to extract the content first: *)
    let hash (t : t) =
        string_of_bitstring (t :> bitstring) |> Hashtbl.hash
    let is_empty (t : t) = bitstring_is_empty (t :> bitstring)
end

(** A device is something to which you can send packet and register a
 * receiving function.
 * In a way this is just a trick to defer initialization of a peer when
 * creating another. *)
type dev =
    { write : bitstring -> unit ; set_read : (bitstring -> unit) -> unit }

let null_logger =
    Log.make "voracious monster"

(** Obituary for ignored bits: *)
let ignore_bits ?(logger=null_logger) bits =
    Log.(log logger Debug (lazy
        (Printf.sprintf "wolfed %d bits down" (bitstring_length bits))))

(** For those cases when you want to build a [trx] from a single [dev] *)
let null_dev ~logger =
    { write = ignore_bits ~logger ; set_read = ignore }

(* Sets the reader of a device, "graphically" *)
let (-->) dev f =
    dev.set_read f

(* Connects two devices [a] and [b] in such a way that one receives what
 * the other transmit. *)
let (<-->) dev1 dev2 =
    dev1 --> dev2.write ;
    dev2 --> dev1.write

(** A transmitter is a kind of pipe with an inside and an outside device, and is
 * thus oriented (from inside to outside, inside being left operand for following
 * functions), that transforms the written payload before emitting it.
 *
 * Picture it like this:
 *
 *   receives       TRX        emits
 *  <--------  < ins | out >  ------>
 *
 *        ins.write -->  out.set_read =->
 * <-= ins.set_read <--  out.write
 *
 * Where the operator <-= sets the receiving function for (the inside side of)
 * the trx, and =-> sets the function that will receive data emitted from the
 * (outside side of) the trx.
 *
 * Two usual ways to connect two TRXs together, with the <==> and the ==>
 * operators:
 *
 *        TRX_1                TRX_2
 *    < ins | out >  <==>  < out | ins >
 *
 * and
 *
 *        TRX_1                TRX_2
 *    < ins | out >   ==>  < ins | out >
 *)
(* TODO: Ideally TRX should have their oewn logger, accessible here, so that
 * owners could reparent their logger: *)
type trx = { ins : dev ; out : dev }

let tx trx = trx.ins.write

let rx trx = trx.out.write

let inverse_trx trx = { ins = trx.out ; out = trx.ins }

let null_trx ~logger = { ins = null_dev ~logger ; out = null_dev ~logger }

(** [f <-= trx] sets f as the receive function of this [trx].
 * Previous receive function, if any, is lost.
 * {b Note:} [trx] is returned so that you can write such things as:
 * [f <-= a <==> b] or [f1 <-= a =-> f2] *)
let (<-=) f trx =
    trx.ins.set_read f ;
    trx

(** [trx =-> f] sets [f] as the emitting function of this [trx].
 * Previous emitting function, if any, is lost. *)
let (=->) trx f =
    trx.out.set_read f

(* Connect the device to the inside of the trx: *)
let (-=>) dev trx =
    dev.set_read trx.ins.write ;
    dev.write <-= trx

(* Or the other way around, connect it to the output side of the trx: *)
let (<=-) trx dev =
    dev.set_read trx.out.write ;
    trx =-> dev.write

(** [a ==> b] connects [a] to [b] such that [b] transmits what [a] emits.
 * Previous connection from [a], if any, is overridden. *)
let (==>) trx1 trx2 =
    trx1 =-> trx2.ins.write ;
    trx1.out.write <-= trx2

(** [a <==> b] connects [a] to [b] such that [b] receives from the outside
 * what [a] emits to the outside, and [a] receives from the outside what
 * [b] emits to the outside. *)
(* BEWARE that for a change, [b]'s is not oriented inside->outside but the
 * other way around. *)
let (<==>) trx1 trx2 =
    trx1 =-> trx2.out.write ;
    trx2 =-> trx1.out.write

(** [pipe trx1 trx2] is like [trx1 ==> trx2] but instead of returning trx2 it
 * returns a trx with trx1 as the inside and trx2 as the outside. *)
let pipe trx1 trx2 =
    trx1.out.set_read trx2.ins.write ;
    trx2.ins.set_read trx1.out.write ;
    { ins = trx1.ins ; out = trx2.out }

(* Sometime we connect trx to mere devices: *)
let (<=->) trx dev =
    trx.out <--> dev

let (<-=>) dev trx =
    dev <--> trx.ins

module type PDU = sig
    type t
    val pack   : t -> bitstring
    val unpack : bitstring -> t option
end

let int_of_fd (fd : Unix.file_descr) : int = Obj.magic fd

let fd_of_int : int -> Unix.file_descr = Obj.magic

(* Like Option.delayed_default, but returns still an option, so they can be
 * chainned. *)
let option_default_delayed_opt f a_opt =
    match a_opt with
    | Some _ -> a_opt
    | None -> f ()

(* Do something on an optional value but return it unchanged: *)
let option_tap f opt =
    Option.may f opt ;
    opt

let memoize ?(h_size=10) f =
    let h = Hashtbl.create h_size in
    fun x ->
        try Hashtbl.find h x
        with Not_found ->
            let v = f x in
            Hashtbl.add h x v ;
            v

let common_pref_length s1 s2 =
    let l1 = String.length s1
    and l2 = String.length s2 in
    let len = min l1 l2 in
    let rec loop i =
        if i >= len then i else
        if s1.[i] <> s2.[i] then i else
        loop (i + 1) in
    loop 0

let string_of_timestamp ts =
    let open Unix in
    let t = Unix.localtime ts in
    Printf.sprintf "%04d-%02d-%02d %02dh%02dm%02ds"
        (t.tm_year + 1900)
        (t.tm_mon + 1)
        t.tm_mday
        t.tm_hour
        t.tm_min
        t.tm_sec

let quoted s =
    "\""^ String.escaped s ^"\""

module Infix =
struct
    let (-->) = (-->)
    let (<-->) = (<-->)
    let (<-=) = (<-=)
    let (=->) = (=->)
    let (-=>) = (-=>)
    let (<=-) = (<=-)
    let (==>) = (==>)
    let (<==>) = (<==>)
    let (<=->) = (<=->)
    let (<-=>) = (<-=>)
end
