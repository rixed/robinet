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

(* TODO: maintain a hash of error counts *)
(* ou plutot, on prend un liste de string et on comptabilise dans un arbre *)
let err str = Printf.fprintf stderr "ERROR: %s\n%!" str ; None

let bytelength bs = (bitstring_length bs + 7) lsr 3

let takebytes n bs = takebits (n lsl 3) bs

let extendbytes n bs = concat [ bs ; create_bitstring ((n lsl 3) - bitstring_length bs) ]

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
        bitmatch rest with
        | { b1 : len-1 : bitstring ;
            b  : 1 ;
            b2 : -1 : bitstring } ->
            let b = (if b then zeroes_bitstring else ones_bitstring) 1 in
            aux (b :: b1 :: prevs) b2
        | { rest : -1 : bitstring } ->
            concat (List.rev (rest :: prevs)) in
    aux [] bits
(*$T bitstring_fuzz
  let str = "pas glop pas glop" in \
  string_of_bitstring (bitstring_fuzz 0.1 (bitstring_of_string str)) <> str
*)

let bitstring_add i b =
    let len = bitstring_length b in
    if len > 31 then (
        bitmatch b with
        | { pref : len - 31 : bitstring ;
            n : 31 } ->
            (BITSTRING {
                pref : len - 31 : bitstring ;
                n + i : 31 })
    ) else (
        bitmatch b with
        | { n : len : int } ->
            (BITSTRING {
                Int64.add n (Int64.of_int i) : len })
    )
(*$= bitstring_add
    (bitstring_of_string "\000" |> bitstring_add 42) (bitstring_of_string "\042")
    (bitstring_of_string "\042" |> bitstring_add 42) (bitstring_of_string "\084")
 *)

let hexstring_of_bitstring bs =
    let s = string_of_bitstring bs in
    let hexify c = Printf.sprintf "%02x" (Char.code c) in
    String.enum s /@ hexify |> List.of_enum |> String.join " "

let printable str =
    let is_printable c = Char.is_latin1 c || Char.is_digit c || Char.is_symbol c || c = ' ' in
    String.map (fun c -> if is_printable c then c else '.') str

let print_bitstring fmt bits =
    let rec aux bits =
        bitmatch bits with
        | { a : 64 : bitstring ;
            b : 64 : bitstring ;
            rest : -1 : bitstring } ->
            Format.fprintf fmt "%s - %s  %s%s@\n"
                (hexstring_of_bitstring a) (hexstring_of_bitstring b)
                (printable (string_of_bitstring a)) (printable (string_of_bitstring b)) ;
            aux rest
        | { a : 64 : bitstring ;
            b : -1 : bitstring } when not (bitstring_is_empty b) ->
            Format.fprintf fmt "%s - %-23s  %s%s@\n"
                (hexstring_of_bitstring a) (hexstring_of_bitstring b)
                (printable (string_of_bitstring a)) (printable (string_of_bitstring b))
        | { a : -1 : bitstring } ->
            if not (bitstring_is_empty a) then
            Format.fprintf fmt "%-23s                            %s@\n"
                (hexstring_of_bitstring a) (printable (string_of_bitstring a)) in
    Format.open_vbox 0 ; (* if not 0 then the first line is less indented than the others *)
    aux bits ;
    Format.close_box ()

(* Simple convertion from bitstrings to int (when the bitstring is small enough to fit
 * in an int). Used for tests only. *)
let int_of_bitstring bs =
    let l = bitstring_length bs in
    (* bitstring fills bytes from high to low bits but we'd like out int to be the lower bits *)
    let bs = if l < 8 then Bitstring.concat [create_bitstring (8-l) ; bs] else bs in
    bitmatch bs with
    | { n : 8 ;
        _ : -1 : bitstring } -> n
(*$= int_of_bitstring & ~printer:dump
    0 (int_of_bitstring (BITSTRING { 0 : 3  : littleendian }))
    1 (int_of_bitstring (BITSTRING { 1 : 3  : littleendian }))
    2 (int_of_bitstring (BITSTRING { 2 : 3  : littleendian }))
    3 (int_of_bitstring (BITSTRING { 3 : 3  : littleendian }))
    2 (int_of_bitstring (BITSTRING { 2 : 30 : littleendian }))
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

let may_default v_opt f = match v_opt with Some v -> v | None -> f ()

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

(** An OrdArray is a container for an ordered set of bounded size. *)
module OrdArray =
struct
    (*$< OrdArray *)
    type entry = { mutable prev : int ;
                   mutable next : int }
    type 'a t =
        {     last_used : entry array ; (** The ordered list of indices. *)
          mutable first : int ;         (** The indice of the first element. *)
           mutable last : int ;         (** and the last one. *)
                   data : 'a array }    (** User data *)

    let make_from_data data =
        let s = Array.length data in
        { last_used = Array.init s (fun i ->
            { prev = if i = 0 then -1 else i-1 ;
              next = if i = s-1 then -1 else i+1 }) ;
          first = 0 ;
          last = s-1 ;
          data  }

    let make s x = make_from_data (Array.create s x)
    let init s f = make_from_data (Array.init s f)

    let get t n = t.data.(n)
    let set t n x = t.data.(n) <- x
    let first t = t.first
    let last t = t.last

    let remove t n =
        if t.last_used.(n).prev <> -1 then
            t.last_used.(t.last_used.(n).prev).next <- t.last_used.(n).next ;
        if t.last_used.(n).next <> -1 then
            t.last_used.(t.last_used.(n).next).prev <- t.last_used.(n).prev ;
        if t.first = n then t.first <- t.last_used.(n).next ;
        if t.last = n then t.last <- t.last_used.(n).prev

    (* n was already removed! *)
    let add_head t n =
        t.last_used.(n).prev <- -1 ;
        t.last_used.(n).next <- t.first ;
        t.last_used.(t.first).prev <- n ;
        t.first <- n

    let promote t n =
        remove t n ;
        add_head t n

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
    let nb_parts = 1 + randi 3 in
    let parts = List.init nb_parts (fun _i ->
        randstr ~charset:"abcdefghijklmnopqrstuvwxyz-" (3 + randi 4)) in
    String.join "." parts

let do_sum bits =
    let rec aux s bits = bitmatch bits with
        | { w : 16 ; rest : -1 : bitstring } -> aux (s + w) rest
        | { b : 8 } -> s + (b lsl 8)
        | { _ } -> s in
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

(* A Module with a private int type and custom printer, used
   to constomize printing of various protocolar fields such as
   TCP ports and so on. A little convoluted but we gain:
   - the toplevel don't mix TCP ports with ETH protocol fields
     and can display them differently;
   - the programmer can't confuse the two either or will be told
     by the compiler. *)
module type PRIVATE_TYPE =
sig
    type t
    type outer_t
    val to_string : t -> string
    val print : Format.formatter -> t -> unit
    val o : outer_t -> t
end

module MakePrivate (Outer : sig
    type t
    val to_string : t -> string
    val is_valid : t -> bool
    val repl_tag : string
end) : PRIVATE_TYPE with type t = private Outer.t and type outer_t = Outer.t =
struct
    type t = Outer.t
    type outer_t = Outer.t
    let to_string = Outer.to_string
    let print fmt t = Format.fprintf fmt "@{<%s>%s@}" Outer.repl_tag (to_string t)
    let o t = assert (Outer.is_valid t) ; t
end

module Payload = struct
    include MakePrivate(struct
        type t = bitstring
        let to_string t =
            let bytes = bytelength t in
            if bytes > 0 then Printf.sprintf "%d bytes" bytes
            else "empty"
        let is_valid _ = true
        let repl_tag = "bits"
    end)

    let empty = o empty_bitstring
    let bitlength (t : t) = bitstring_length (t :> bitstring)
    let length (t : t) = bytelength (t :> bitstring) (* TODO: rename to length *)
    let random len = o (randbs len)
end

(** A device is something to which you can send packet and register a
 * receiving function *)
(* FIXME: a better name which makes apparent that a trx is actually 2 devs *)
type dev = { write : bitstring -> unit ; set_read : (bitstring -> unit) -> unit }

(** For those cases when you want to build a [trx] from a single [dev] *)
let null_dev = { write = ignore ; set_read = ignore }

(** Connects two {!dev} together *)
let (<-->) a b =
    a.set_read b.write ;
    b.set_read a.write

(** A transmiter is a kind of pipe with an inside and an outside device, is
 * thus oriented (from inside to outside, inside being left operand for following
 * functions), that transforms the writen payload before emitting it. *)
type trx = { ins : dev ; out : dev }

let tx trx = trx.ins.write
let rx trx = trx.out.write

let inverse_trx trx = { ins = trx.out ; out = trx.ins }

let null_trx = { ins = null_dev ; out = null_dev }

(** [f <-= trx] sets f as the receive function of this [trx].
 * {b Note:} [trx] is returned so that you can write such things as:
 * [f <-= a <==> b] or [f1 <-= a =-> f2] *)
let (<-=) f trx =
    trx.ins.set_read f ;
    trx

(** [trx =-> f] sets [f] as the emiting function of this [trx]. *)
let (=->) trx f =
    trx.out.set_read f

(** [a ==> b] connects [a] to [b] such that [b] transmits what [a] emits. *)
let (==>) trx1 trx2 =
    trx1 =-> trx2.ins.write ;
    trx1.out.write <-= trx2

(** [a <==> b] connects [a] to [b] such that [b] receives what [a] emits
 * and [a] receives what [b] emits. *)
let (<==>) trx1 trx2 =
    trx1 =-> trx2.out.write ;
    trx2 =-> trx1.out.write

(** [pipe trx1 trx2] connects trx1 and trx2 so that trx1 output is sent through trx2,
 * and returns a trx with trx1 as the inside and trx2 as the outside. *)
let pipe trx1 trx2 =
    trx1.out.set_read trx2.ins.write ;
    trx2.ins.set_read trx1.out.write ;
    { ins = trx1.ins ; out = trx2.out }

module type PDU = sig
    type t
    val pack   : t -> bitstring
    val unpack : bitstring -> t option
end

