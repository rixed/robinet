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

let ensure cond msg =
    if not cond then (
        flush stdout ;
        Printf.fprintf stderr "ERROR: %s\n%s\n%!"
            msg (Printexc.get_backtrace ()) ;
        exit 1 ;
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
        let len = Int.of_float (Random.float (2. *. noerr_len)) in (* incorrect but fast *)
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

let may_default v_opt f = match v_opt with Some v -> v | None -> f ()

(* FIXME: use enums *)
let rec remove_last_if cond = function
    | [] -> []
    | i :: [] -> if cond i then [] else i :: []
    | i :: l  -> i :: (remove_last_if cond l)

let none_if_not_found f x = try Some (f x) with Not_found -> None

let str_all_matches str =
    let rec aux prevs n =
        try let m = Str.matched_group n str in
            aux (m::prevs) (n+1)
        with Not_found -> aux (""::prevs) (n+1)
           | Invalid_argument _ -> List.rev prevs in
    aux [] 0

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

type trx = { tx : bitstring -> unit ; (* transmit this payload *)
             rx : bitstring -> unit ; (* receive this payload *)
             set_emit : (bitstring -> unit) -> unit ;
             set_recv : (bitstring -> unit) -> unit  }

let null_trx = { tx = ignore ;
                 rx = ignore ;
                 set_emit = ignore ;
                 set_recv = ignore }

module type PDU = sig
    type t
    val pack   : t -> bitstring
    val unpack : bitstring -> t option
end

(*(* ?? *)
module type TRANSPORT = sig
    type addr
    val addr_of_string : string -> addr
    val string_of_addr : addr -> string
end*)

let check () =
    (int_of_hexstring "0000001A" = Some 26) &&
    (int_of_hexstring "2F" = Some 47) &&
    (let str = "foobaaaaar" in
     Str.string_match (Str.regexp "f\\(o+\\)b\\(a+\\)") str 0 &&
     str_all_matches str = [ "foobaaaaa" ; "oo" ; "aaaaa" ])