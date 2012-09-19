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
   Simple Parsing Expression Grammar that allow restart.
*)
open Batteries
open Tools

let debug = false

(* Pb: Lorsqu'un parseur demande d'attendre, il consomme quand même une partie.
       Puis on lui envoie la suite, il peut alors réussir, mais son résultat peut
       être pipé dans un autre parseur qui lui échoue. Exemple :
       pipe liner headers,
       auquel on envoit ['\r'], le pipe va renvoyer Wait (mais consommer le '\r').
       Puis on lui envoit ['\n' ; du garbage] : liner va envoyer son résultat à headers,
       qui va renvoyer Fail (car une ligne vide n'est pas un header). L'appelant sait
       alors que ['\n';...] fait failer le pipe, et peut decider d'essayer cette entrée
       sur un autre parseur (cas du seq par exemple). Or le '\r' initial fait en fait
       partit du fail, mais a été consommé !
       Il faudrait donc que Wait renvoit aussi la liste de ce
       qui reste et que ce soit à l'appelant de mémoriser ce qu'il faut renvoyer à un
       parseur après un Wait. Ainsi, dans ce cas, le seq sais que le '\r' initial n'est
       toujours pas consommé (car le pipe a renvoyé initialisement Wait ['\r']).
       L'ennuis désormais, c'est que si c'est la seconde partie du pipe qui Wait,
       alors il faut qu'il renvoit un Wait avec l'input du premier parseur. Or celui-ci
       peut avoir modifié son état interne. Il faut donc que :
       0) Fail renvoit aussi la liste des inputs non consommés
       1) pipe sauve tous les inputs envoyés au premier parseur pour Failer avec ces imputs
       2) le premier parseur n'ai pas d'état interne. *)

type ('a, 'b) parzer_result = Wait | Res of 'a * 'b list | Fail
type ('a, 'b) parzer = 'b list (* tokens to add *) -> bool (* more to come *) -> ('a, 'b) parzer_result

let print_intlist oc l =
    Printf.fprintf oc "[ %s ]" (String.concat "; " (List.map string_of_int l))
let print_int oc i =
    Printf.fprintf oc "%d" i
let print_intopt oc v = Option.print Int.print oc v

let check_results name res_printer p rs bs =
    let print_res oc = function
        | Wait -> Printf.fprintf oc "Wait"
        | Fail -> Printf.fprintf oc "Fail"
        | Res (res, rem) -> Printf.fprintf oc "Res (%a, %a)" res_printer res print_intlist rem in
    let rec aux ret rs = function
        | [] -> ret
        | b::bs' ->
            let expected = List.hd rs in
            let got = p b (bs' <> []) in
            let ret = ref ret in
            if got = expected then (
                if debug then Printf.printf "Peg: %s: %a -> %a OK\n" name print_intlist b print_res got
            ) else (
                Printf.printf "Peg: %s: %a -> %a FAIL! got %a\n%!" name print_intlist b print_res expected print_res got ;
                ret := false
            ) ;
            let rem = (match got with
                | Res (_, rem) -> rem
                | _ -> []) in
            (* append rest to next sequence *)
            let bs'' = (match bs' with
                | [] -> [] (* don't parse remain when it's over *)
                | ns::ns' -> (rem@ns) :: ns') in
            aux !ret (List.tl rs) bs''
    in aux true rs bs

(* example of simple parsers *)

(* unconditionally returns something - useful to adapt result types *)
let return res bs _ = Res (res, bs)
let fail _ _ = Fail
let anything bs m = match bs with
    | [] -> if m then Wait else Fail
    | b :: bs' -> Res (b, bs')

(*$T return
    let items = [ [1] ; [2] ] \
    and results = [ Res (5, [ 1 ]); Res (5, [ 1 ; 2 ]) ] \
    in check_results "return" print_int (return 5) results items
*)

(* repeat the application of the add function on all items individualy
   until either we have no more (and this is a failure when we hit the
   end of items list) or we have a result or a failure *)
let rec foreach_item add bs m = match bs with
    | [] -> if m then Wait else Fail
    | [b] -> add b m
    | b::bs' -> (match add b true with
        | Wait -> foreach_item add bs' m
        | Fail -> Fail
        | Res (res, rem) -> Res (res, List.append rem bs'))

let rec start_match = function
    | [], _ -> true
    | _, [] -> false
    | a::a', b::b' -> a = b && start_match (a', b')

let upto delim =
    let buffer = ref [] in
    let delim = List.rev delim in
    foreach_item (fun b m ->
        buffer := b :: !buffer ;
        if start_match (delim, !buffer) then (
            let res = List.rev !buffer in
            buffer := [] ;
            Res (res, [])
        ) else (
            if m then Wait else (
                if debug then Printf.printf "Peg: upto: Failed to find delim before end of items\n" ;
                Fail
            )
        ))

(*$T upto
    let items = [ [1]; [2; 0]; [0; 5]; [0; 0]; [1] ] \
    and results = [ Wait; Wait; Res ([1; 2; 0; 0], [5]); \
                    Res ([5; 0; 0], []); \
                    Fail ] in \
    check_results "upto" print_intlist (upto [0; 0]) results items
*)

let cond c =
    foreach_item (fun b _ ->
        if c b then Res (b, [])
        else (
            if debug then Printf.printf "Peg: cond: Fail\n" ;
            Fail
        ))

let item i = cond ((=) i)

(*$T item
    let items = [ [1]; [1; 2]; [2] ] \
    and results = [ Res (1, []); Res (1, [2]); Fail ] in \
    check_results "item" print_int (item 1) results items
*)

(* like item but restricted to string values, and the first element is required to match a regex
   and the returned value is the tuple of matching substrings *)
let regex re_str =
    let re = Str.regexp re_str in
    foreach_item (fun b _ ->
        if Str.string_match re b 0 then (
            let rec aux prev i =
                try aux ((Str.matched_group i b)::prev) (i+1) with
                    | Not_found -> aux (""::prev) (i+1)
                    | Invalid_argument _ -> prev
            in Res (List.rev (aux [] 0), [])
        ) else (
            if debug then Printf.printf "Peg: regex: re '%s' failed\n" re_str ;
            Fail
        ))

let take n =
    if n < 0 then (
        Printf.fprintf stderr "Peg: take: Cannot take less than %d bytes!\n" n ;
        fun _bs _m -> Fail
    ) else if n = 0 then (
        fun bs _ -> Res ([], bs) (* we can't use foreach_item if we are interrested in 0 itemr *)
    ) else
    let rem = ref n in
    let value = ref [] in
    let got_res rest =
        if debug then Printf.printf "Peg: take: took %d bytes\n" n ;
        let res = Res (List.rev !value, rest) in
        rem := n ;
        value := [] ;
        res in
    (* FIXME: a much faster version without foreach_item *)
    foreach_item (fun b m ->
        if !rem = 0 then (
            got_res [b]
        ) else (
            value := b :: !value ;
            decr rem ;
            if !rem = 0 then got_res [] else
            if m then Wait else (
                if debug then Printf.printf "Peg: take: Failed to took %d bytes before end of items\n" n ;
                Fail
            )
        ))

(*$T take
    let items = [ [0]; [1; 2]; [3; 4; 5]; [6]; [7; 8]; [] ] \
    and results = [ Wait; Res ([0; 1], [2]); Res ([2; 3], [4; 5]); \
                    Res ([4; 5], [6]); Res ([6; 7], [8]); Fail ] in \
    check_results "take(1)" print_intlist (take 2) results items

    let items = [ [1;2] ] \
    and results = [ Res ([], [1;2]) ] in \
    check_results "take(2)" print_intlist (take 0) results items
*)

(* this is the only function which returns a result when there are no more items *)
let all () =
    let prevs = ref [] in
    let flatten_rev l = List.concat (List.rev l) in
    (fun bs m ->
        prevs := bs :: !prevs ;
        if m then Wait else Res (flatten_rev !prevs, []))

(*$T all
    let items = [ [1;2]; [3]; [4] ] \
    and results = [ Wait; Wait; Res ([1;2;3;4], []) ] in \
    check_results "all" print_intlist (all ()) results items
*)

(* Change every value returned by p through f *)
let map p f =
    fun bs m -> match p bs m with
        | Fail -> Fail
        | Wait -> Wait
        | Res (res, rem) ->
            if debug then Printf.printf "Peg: map: %d items remaining\n" (List.length rem) ;
            Res (f res, rem)

let map_filter p f =
    fun bs m -> match p bs m with
        | Fail -> Fail
        | Wait -> Wait
        | Res (res, rem) -> (match f res with
            | None -> Fail
            | Some x -> Res (x, rem))

let some p = map p (fun res -> Some res)
let none p = map p (fun _ -> None)

(* combinators *)

let seq ps =
    let ps' = ref ps and prev = ref [] in
    let rec aux bs m = match !ps' with
        | [] ->
            let res = List.rev !prev in
            ps' := ps ; prev := [] ;
            Res (res, bs)
        | p::ps'' -> (match p bs m with
            | Wait -> Wait
            | Res (res, rem) ->
                ps' := ps'' ; prev := res :: !prev ;
                aux rem m
            | Fail ->
                ps' := ps ; prev := [] ;
                Fail)
    in aux

(*$T seq
    let p = seq [ item 1 ; item 2 ; item 3 ] \
    and items = [ [1]; [2; 3; 1]; [2]; [3; 5] ] \
    and results = [ Wait; Res ([ 1; 2; 3 ], [1]); Wait; Res ([ 1; 2; 3 ], [5]) ] in \
    check_results "seq" print_intlist p results items
*)

(* Many times, some values are not interresting.
   This version of seq takes parsers thar return an optional value, and filter them *)
let seqf ps =
    map (seq ps) (List.filter_map identity)

(* alternative function that takes a list of parsers and return the first that returns a value *)
let either ps =
    let ps' = ref ps and prev_bs = ref [] in
    let rec aux bs m = match !ps' with
        | [] ->
            if debug then Printf.printf "Peg: either: fail since no parser suits\n" ;
            ps' := ps ; prev_bs := [] ;
            Fail
        | p::ps'' ->
            prev_bs := !prev_bs @ bs ;
            (match p bs m with
                | Wait ->
                    Wait
                | Res (x, y) ->
                    ps' := ps ; prev_bs := [] ;
                    Res (x, y)
                | Fail -> (* start over with another parser *)
                    let bs' = !prev_bs in
                    ps' := ps'' ; prev_bs := [] ;
                    aux bs' m)
    in aux

(*$T either
    let p = either [ item 1; item 2 ] \
    and items = [ [1]; [1]; [2]; [2; 3] ] \
    and results = [ Res (1, []); Res (1, []); Res (2, []); Res (2, [3]) ] in \
    check_results "either(1)" print_int p results items

    let p = either [ seq [ item 1; item 2; item 3 ] ; \
                     seq [ item 1; item 2; item 4 ] ] \
    and items = [ [1; 2]; [3]; [1]; [2]; [4]; [1]; [2]; [5] ] \
    and results = [ Wait; Res([1;2;3],[]); Wait; Wait; Res([1;2;4],[]); Wait; Wait; Fail ] in \
    check_results "either(2)" print_intlist p results items
*)

let repeat ?min ?max p =
    let prev = ref []
    and nb_match = ref 0 in
    let res bs =
        match min with
            | Some min when min > !nb_match ->
                if debug then Printf.printf "Peg: repeat: fail since only %d/%d matched\n" !nb_match min ;
                prev := [] ; nb_match := 0 ;
                Fail
            | _ ->
                let r = Res (List.rev !prev, bs) in
                if debug then Printf.printf "Peg: repeat: res with %d items\n" !nb_match ;
                prev := [] ; nb_match := 0 ;
                r in
    let rec aux bs m = match p bs m with
        | Wait ->
            if m then Wait else res bs
        | Res (res, rem) ->
            prev := res :: !prev ;
            incr nb_match ;
            (match max with
                | Some mx when mx = !nb_match ->
                    let r = Res (List.rev !prev, rem) in
                    if debug then Printf.printf "Peg: repeat: res with max %d items\n" !nb_match ;
                    prev := [] ; nb_match := 0 ;
                    r
                | _ -> aux rem m (* FIXME: is rem=[], then Wait/Fail depending on m? *))
        | Fail ->
            res bs
    in aux

(*$T repeat
    let items = [ [1; 1; 1]; [1; 2] ] \
    and results = [ Wait; Res([1; 1; 1; 1], [2]) ] in \
    check_results "repeat(1)" print_intlist (repeat ~min:2 ~max:4 (item 1)) results items

    let items = [ [1; 1; 1]; [1; 1; 2] ] \
    and results = [ Wait; Res ([1; 1; 1; 1], [1; 2]) ] in \
    check_results "repeat(2)" print_intlist (repeat ~min:2 ~max:4 (item 1)) results items

    let items = [ [1; 2; 1] ] \
    and results = [ Fail ] in \
    check_results "repeat(3)" print_intlist (repeat ~min:2 ~max:4 (item 1)) results items
*)

let many p = repeat p

(*$T many
    let items = [ [1; 1; 1]; [1; 2] ] \
    and results = [ Wait; Res([1; 1; 1; 1], [2]) ] in \
    check_results "many(1)" print_intlist (many (item 1)) results items

    let p = many (map (seq [ item 1; item 2 ]) (fun _ -> 12)) \
    and items = [ [1; 2; 1]; [2; 1]; [2; 3] ] \
    and results = [ Wait; Wait; Res ([12; 12; 12], [3]) ] in \
    check_results "many(2)" print_intlist p results items

    let p = many (map (seq [ item 1; item 2 ]) (fun _ -> 12)) \
    and items = [ [5] ] and results = [ Res([], [5]) ] in \
    check_results "many(3)" print_intlist p results items
*)

let several p = repeat ~min:1 p

(*$T several
    let items = [ [1; 1; 1]; [1; 2] ] \
    and results = [ Wait; Res([1; 1; 1; 1], [2]) ] in \
    check_results "several(1)" print_intlist (several (item 1)) results items

    let p = several (map (seq [ item 1; item 2 ]) (fun _ -> 12)) \
    and items = [ [1; 2; 1]; [2; 1]; [2; 3] ] \
    and results = [ Wait; Wait; Res ([12; 12; 12], [3]) ] in \
    check_results "several(2)" print_intlist p results items

    let p = several (map (seq [ item 1; item 2 ]) (fun _ -> 12)) \
    and items = [ [5] ] and results = [ Fail ] in \
    check_results "several(3)" print_intlist p results items
*)

(* returns either None or Some value *)
let optional p = map (repeat ~max:1 p) (function
    | []  -> None
    | [v] -> Some v
    | _   -> should_not_happen ())

(*$T optional
    let p = optional (item 1) \
    and items = [ [1; 1; 2] ] \
    and results = [ Res (Some 1, [1; 2]) ] in \
    check_results "optional(1)" print_intopt p results items

    let p = optional (item 2) \
    and items = [ [1; 1; 2] ] \
    and results = [ Res (None, [1; 1; 2]) ] in \
    check_results "optional(2)" print_intopt p results items
*)

let repeat_until f p =
    let prev = ref [] in
    let rec aux bs m = match p bs m with
        | Wait -> Wait
        | Fail ->
            prev := [] ;
            Fail
        | Res (res, rem) ->
            prev := res :: !prev ;
            if f res then (
                let res' = List.rev !prev in
                prev := [] ;
                Res (res', rem)
            ) else (
                if rem = [] then (
                    if m then Wait else (
                        prev := [] ; Fail
                    )
                ) else aux rem m
            ) in
    aux

(* Run parser p until a result is obtained, then give the result to f that will return a new parser.
   Once this new parser got it's result, give new items to first parser and so on *)
let bind p f =
    let p2 = ref None in
    let rec aux bs m = match !p2 with
        | None ->
            (match p bs m with
                | Wait -> Wait
                | Fail ->
                    if debug then Printf.printf "Peg: bind: Fail since first parser failed\n" ;
                    Fail
                | Res (res, rem) ->
                    if debug then Printf.printf "Peg: bind: First parser got a response\n" ;
                    p2 := Some (f res) ;
                    aux rem m)
        | Some p ->
            if debug then Printf.printf "Peg: bind: Passing %d bytes to second parser\n" (List.length bs) ;
            (match p bs m with
                | Wait ->
                    if debug then Printf.printf "Peg: bind: ...wait\n" ;
                    Wait
                | Fail ->
                    if debug then Printf.printf "Peg: bind: Fail since second parser failed\n" ;
                    Fail
                | Res _ as res ->
                    if debug then Printf.printf "Peg: bind: Second parser got a result\n" ;
                    p2 := None ;
                    res)
    in aux

(*$T bind
    let positive = cond ((<=) 0) in \
    let p = bind (positive) (fun i -> \
        assert (i >= 0) ; \
        (* match a sequence of i zeros *) \
        let rec aux l i = \
            (* we should be able to reuse the same item 0 here but I dont feel like it *) \
            if i = 0 then l else aux ((item 0)::l) (i-1) \
        in seq (aux [] i)) \
    and items = [[1]; [0; 2; 0]; [0]; [0]; [3; 0; 0]; [0; 5]] \
    and results = [ Wait; Res ([0], [2; 0]); Res ([0; 0], []); \
                    Res ([], []); Wait; Res ([0; 0; 0], [5]) ] in \
    check_results "bind" print_intlist p results items
*)

(* Use the results of the first parser as the input elements of the second.
   Return the results of p2.
   Notice that if p1 is a ('a, 'b) parzer and p2 a ('c, 'a) parzer,
   then pipe p1 p2 is a ('c, 'b) parzer, which comes handy;
   but p2 is then forced to consume everything ! *)
let pipe : 'a 'b 'c. ('a, 'b) parzer -> ('c, 'a) parzer -> ('c, 'b) parzer = fun p1 p2 ->
    let p1_rem = ref [] in
    let rec aux bs m =
        let prev_rem = !p1_rem in
        p1_rem := [] ;
        match p1 (prev_rem @ bs) m with
        | Fail ->
            if debug then Printf.printf "Peg: pipe: Fail since first end of pipe failed\n" ;
            Fail
        | Wait -> Wait
        | Res (res, rem) ->
            if debug then Printf.printf "Peg: pipe first end returned a result.\n%!" ;
            (match p2 [res] (rem <> [] || m) with
                | Res (res', rem') ->
                    if debug then Printf.printf "Peg: pipe second end returned a result.\n%!" ;
                    (* we need to return as unconsumed both p1_rem and rem' *)
                    if rem' <> [] then Printf.printf "Peg: WRN: second end of a pipe did not consume eveything !\n" ;
                    Res (res', rem)
                | Fail ->
                    if debug then Printf.printf "Peg: pipe: Fail since second end failed.\n%!" ;
                    Fail
                | Wait ->
                    p1_rem := rem ;
                    if rem <> [] then aux [] m
                    else Wait)
    in aux

(*$T pipe
    (* first build list of ints (up to 0), then check these lists are [3;2;1;0] *) \
    let p = pipe (upto [0]) (item [3;2;1;0]) in \
    let items = [ [3]; [2; 1]; [0; 3]; [2; 1; 0]; [1; 0] ] \
    and results = [ Wait; Wait; Res ([3;2;1;0], [3]); Res ([3;2;1;0], []); Fail ] in \
    check_results "pipe(1)" print_intlist p results items
*)
(*  let items = [ [1] ; [0; 3; 2; 1] ; [0; 1] ] FIXME
    and results = [ Wait; Fail; Res ([3;2;1;0], [1]) ] in
    check_results "pipe(2)" print_intlist p results items in
*)

(* Various useful parsers *)

let blank () =
    either [ item ' ' ; item '\t' ; item '\r' ; item '\n' ]

let alphabetic () =
    cond (fun c ->
        (c >= 'a' && c <= 'z') ||
        (c >= 'A' && c <= 'Z'))

let numeric () =
    cond (fun c -> c >= '0' && c <= '9')

let alphanum () = either [ alphabetic () ; numeric () ]

let iitem c = either [ item c ; item (Char.uppercase c) ]
let char_seq str =
    seq (List.map (fun c ->
        if c >= 'a' && c <= 'z' then iitem c else item c)
        (String.to_list str))

let crlf () = seq [ item '\r' ; item '\n' ]

