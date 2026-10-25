(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(* Copyright 2026, Cedric Cellier
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
(** Compiles crafty programs, and runs them on an Ethernet interface of a
   robinet simulation. What a program may send is bounded by what its
   interface is connected to, such as a {!Policer}, whose [on_limit] can stop
   the program.

   Everything happens in the callbacks of the simulation's scheduler, in
   continuation passing style: a statement is given what to do once it is
   done. A block is left in one way only, its cancellation, whether it ends,
   breaks, fails or is restarted: what it set up is undone, and so are the
   blocks within it. As events of the scheduler cannot be withdrawn, those
   of a cancelled block find it dead and do nothing.

   [repeat] runs its iterations one after the other, each starting [every]
   after the previous one started (or as soon as it ends, if later), until
   it has run [count] of them or the next one would start once [for] has
   elapsed since it started; it ends right after its last iteration. Over
   [items], as from a [foreach], it runs one iteration per item.
   [retry max=N] runs its block again up to N times (3 by default) while it
   fails, the error of the last attempt going to the enclosing block.
   [wait] goes on with the next statement after that duration.
   [catch] leaves its block on its first error, which goes no further. [if]
   runs the block of the first condition that holds, if any, and [case] that
   of its value's constructor. A block, an [if] or a [case] that is the
   value of a declaration, an assignment or a statement runs as a block of
   its own, which ends with that value; within another expression, the
   typer lets it only compute, and it is evaluated at once. An error
   reaching the program's block ends the program.

   [expect] waits for its pattern, failing after its timeout, then runs its
   block once. [first] does the same with the first of its patterns to match.
   A packet sent, by any block, is then [LAST]. [on] lets its block go on, and runs the block of the pattern of every
   match until its timeout, its [max] or a [break] out of it; a block ends
   only once its statements are done and its [on]s are over. The packet
   matched, [MATCH], is decoded to its top, and only if read. *)
open Batteries
open Crafty_value
module EthSpeed = SimTypes.EthSpeed
module A = Crafty_ast
module T = Crafty_typing
module Interval = Clock.Interval

type error = Crafty_parser.error

(** {2 Expressions} *)

(* Variables are cells, so that a block sees the changes made after it was
 * entered; a block entered again (a new iteration, another match) has cells
 * of its own. A cell is made when first used, so that a value is computed
 * only if needed: *)
module Env = Map.Int

type env =
    { vars : value ref Lazy.t Env.t ;
      (* The current protocol stack, its top first: *)
      stack : Crafty_tree.entry list ;
      (* In a condition, the packet being matched up to its layer, the top
       * first: *)
      packet : Crafty_tree.packet }

let lookup (env : env) (v : T.var) =
    try Lazy.force (Env.find v.id env.vars)
    with Not_found -> invalid_arg ("Crafty_interp: no cell for "^ v.name)

let bind env (v : T.var) value =
    { env with vars = Env.add v.id (Lazy.from_val (ref value)) env.vars }

let bind_lazy env (v : T.var) f =
    { env with vars = Env.add v.id (lazy (ref (f ()))) env.vars }

(* The position of item [i] of an array of length [len], counting from the
 * end if negative: *)
let position loc len i =
    let p = if i < 0 then i + len else i in
    if p < 0 || p >= len then
        error loc "No item %d in an array of length %d" i len ;
    p

let item loc a i = a.(position loc (Array.length a) i)

(* The offset and length of the slice [from:to_] of something of length
 * [len], negative bounds counting from the end, out of range ones clipped: *)
let slice len from to_ =
    let clip i = if i < 0 then max 0 (i + len) else min i len in
    let from = clip (Option.default 0 from) in
    from, max 0 (clip (Option.default len to_) - from)

(* The value of key [k], of type [typ], in map [m] of default [d]: *)
let find loc typ m d k =
    match Map.PMap.find k m with
    | v -> v
    | exception Not_found ->
        (match d with
        | Some v -> v
        | None -> error loc "No key %s in this map" (to_string typ k))

(* A copy of [x] with [y] at that path of indices, each with its type: *)
let rec set_item loc x path y =
    match x, path with
    | _, [] -> y
    | Array a, (_, Int i) :: path ->
        let a' = Array.copy a in
        let i = position loc (Array.length a) i in
        a'.(i) <- set_item loc a.(i) path y ;
        Array a'
    | Map (m, d), (typ, k) :: path ->
        let v = if path = [] then y else set_item loc (find loc typ m d k) path y in
        Map (Map.PMap.add k v m, d)
    | _ -> assert false

let rand loc = function
    | Int max ->
        if max <= 0 then error loc "rand needs a positive maximum, not %d" max ;
        Int (Random.int max)
    | Float max -> Float (Random.float max)
    | Bool _ -> Bool (Random.bool ())
    | _ -> assert false

let int_of loc = function
    | Bool b -> if b then 1 else 0
    | Int i | Byte i -> i
    | Float f ->
        if Float.is_finite f then int_of_float f
        else error loc "Cannot convert %s to an int" (A.string_of_float f)
    | Interval i -> int_of_float (Interval.to_secs i)
    | Time t -> int_of_float (Clock.Wall.to_secs t)
    | _ -> assert false

let float_of = function
    | Bool b -> if b then 1. else 0.
    | Int i | Byte i -> float_of_int i
    | Float f -> f
    | Interval i -> Interval.to_secs i
    | Time t -> Clock.Wall.to_secs t
    | _ -> assert false

(* The [value] of type [from] as a [typ]: *)
let rec convert loc (from : A.Type.t) (typ : A.Type.t) value =
    match from, typ, value with
    | Int, Float, Int i -> Float (float_of_int i)
    | Byte, Int, Byte b -> Int b
    | Int, Bool, Int i -> Bool (i <> 0)
    | String, Array Byte, String s -> bytes_of_string s
    | Array Byte, String, Array a -> String (string_of_bytes a)
    | Array Byte, Ip, Array a ->
        if Array.length a <> 4 then
            error loc "%d bytes are no IP address" (Array.length a) ;
        Ip (Ip.Addr.of_bytes (Bytes.of_string (string_of_bytes a)))
    | Array Byte, Mac, Array a ->
        if Array.length a <> 6 then
            error loc "%d bytes are no MAC address" (Array.length a) ;
        Mac (Eth.Addr.o (Bitstring.bitstring_of_string (string_of_bytes a)))
    | Variant cs, Variant ds, Variant (n, v) ->
        Variant (n, convert_to loc (List.assoc n cs) (List.assoc n ds) v)
    | Record fs, Record gs, Record vs ->
        Record (Array.of_list (List.mapi (fun i ((_, t), (_, t')) ->
            convert_to loc t t' vs.(i)) (List.combine fs gs)))
    | Array t, Array t', Array a -> Array (Array.map (convert_to loc t t') a)
    | Map (_, t), Map (_, t'), Map (m, d) ->
        let conv = convert_to loc t t' in
        Map (Map.PMap.map conv m, Option.map conv d)
    | _ -> invalid_arg "Crafty_interp.convert"

and convert_to loc from typ value =
    if from = typ then value else convert loc from typ value

(* The value written in that string, if [ok] accepts it: *)
let parsed loc what ok s =
    match Option.map of_literal (Crafty_parser.parse_literal (String.trim s)) with
    | Some v when ok v -> v
    | _ -> error loc "Cannot convert %S to %s" s what

(* That statistic over the values [vs], of which there is at least one: *)
let stat loc (b : T.builtin) vs args =
    let best better = Array.fold_left (fun a v -> if better v a then v else a) vs.(0) vs in
    match b, args with
    | T.Min, [] -> best (fun v a -> compare_values v a < 0)
    | T.Max, [] -> best (fun v a -> compare_values v a > 0)
    | (T.Mean | T.Stddev), [] ->
        let is_interval = match vs.(0) with Interval _ -> true | _ -> false in
        let xs = Array.map (function
            | Interval i -> Interval.to_secs i
            | v -> float_of v) vs in
        let n = float_of_int (Array.length xs) in
        let mean = Array.fold_left (+.) 0. xs /. n in
        (* Of the population: *)
        let x =
            if b = T.Mean then mean else
            sqrt (Array.fold_left (fun s x -> s +. (x -. mean) ** 2.) 0. xs /. n) in
        if is_interval then Interval (Interval.of_secs x) else Float x
    (* The nearest rank: the smallest value that [p] percent of them are not
     * above: *)
    | T.Percentile, [ p ] ->
        let p = float_of p in
        if not (p >= 0. && p <= 100.) then
            error loc "No percentile %s, which is not within 0 and 100" (A.string_of_float p) ;
        let vs = Array.copy vs in
        Array.sort compare_values vs ;
        let rank = int_of_float (ceil (p /. 100. *. float_of_int (Array.length vs))) in
        vs.(max 0 (rank - 1))
    | _ -> assert false

(* What a setuid crafty, which drops the user's environment, prefixes their
 * variables with: *)
let user_env_prefix = "CRAFTY_USER_ENV_"

(* The user's variable, renamed or not: *)
let getenv name =
    match Tools.unsafe_getenv_opt (user_env_prefix ^ name) with
    | None -> Tools.unsafe_getenv_opt name
    | v -> v

(* The system resolver's answers, asked once per name or address for the
 * whole run; [resolve] keeps only the IPv4 addresses: *)
let resolved = Hashtbl.create 10
let resolve name =
    match Hashtbl.find_option resolved name with
    | Some addrs -> addrs
    | None ->
        let addrs =
            Unix.getaddrinfo name "" Unix.[ AI_FAMILY PF_INET ] |>
            List.filter_map (function
                | Unix.{ ai_addr = ADDR_INET (a, _) ; _ } -> Some (Ip.Addr.o a)
                | _ -> None) |>
            List.unique ~eq:(fun a b -> Ip.Addr.compare a b = 0) in
        Hashtbl.add resolved name addrs ;
        addrs

let hostnames = Hashtbl.create 10
let hostname (ip : Ip.Addr.t) =
    match Hashtbl.find_option hostnames ip with
    | Some name -> name
    | None ->
        let name =
            try Some (Unix.getnameinfo (Unix.ADDR_INET ((ip :> Unix.inet_addr), 0))
                                       Unix.[ NI_NAMEREQD ]).ni_hostname
            with Not_found -> None in
        Hashtbl.add hostnames ip name ;
        name

let rec call loc (b : T.builtin) args ~print ~print_err ~now =
    let number = function Bool _ | Int _ | Float _ -> true | _ -> false in
    let reparse what ok s =
        call loc b [ parsed loc what ok s ] ~print ~print_err ~now in
    match b, args with
    | T.To_int, [ String s ] -> reparse "an int" number s
    | T.To_float, [ String s ] -> reparse "a float" number s
    | T.To_bool, [ String s ] -> reparse "a bool" number s
    | T.To_byte, [ String s ] -> reparse "a byte" number s
    | T.To_interval, [ String s ] ->
        reparse "an interval" (fun v -> number v || match v with Interval _ -> true | _ -> false) s
    | T.To_time, [ String s ] ->
        reparse "a time" (fun v -> number v || match v with Time _ -> true | _ -> false) s
    | T.To_ip, [ String s ] ->
        parsed loc "an IP address" (function Ip _ -> true | _ -> false) s
    | T.To_mac, [ String s ] ->
        parsed loc "a MAC address" (function Mac _ -> true | _ -> false) s
    | T.To_interval, [ Interval _ as i ] -> i
    | T.To_time, [ Time _ as t ] -> t
    | T.Rand, [ max ] -> rand loc max
    | T.Randbytes, [ Int len ] ->
        if len < 0 then error loc "randbytes needs a length, not %d" len ;
        Array (Array.init len (fun _ -> Byte (Random.int 256)))
    | T.Exp, [ x ] -> Float (exp (float_of x))
    | T.Ln, [ x ] -> Float (log (float_of x))
    | T.Log, [ x ] -> Float (log10 (float_of x))
    | T.Log2, [ Int x ] ->
        if x <= 0 then error loc "log2 needs a positive int, not %d" x ;
        let rec loop n x = if x <= 1 then n else loop (n + 1) (x lsr 1) in
        Int (loop 0 x)
    | T.To_int, [ x ] -> Int (int_of loc x)
    | T.To_float, [ x ] -> Float (float_of x)
    | T.To_bool, [ x ] -> Bool (float_of x <> 0.)
    | T.To_byte, [ x ] -> Byte (int_of loc x land 255)
    | T.To_interval, [ x ] ->
        (match Interval.of_secs (float_of x) with
        | i -> Interval i
        | exception Invalid_argument _ ->
            error loc "%s is not a number of seconds" (A.string_of_float (float_of x)))
    | T.To_time, [ x ] ->
        let s = float_of x in
        if not (Float.is_finite s) then
            error loc "%s is not a number of seconds" (A.string_of_float s) ;
        Time (Clock.Wall.of_secs s)
    | T.Now, [] -> Time (now ())
    | T.To_ip, [ b ] -> convert loc A.Type.bytes A.Type.Ip b
    | T.To_mac, [ b ] -> convert loc A.Type.bytes A.Type.Mac b
    | T.Getenv, String name :: default ->
        (match getenv name, default with
        | Some v, _ -> String v
        | None, [ d ] -> d
        | None, _ -> error loc "Environment variable %s is not set" name)
    | T.Resolve, [ String name ] ->
        (match resolve name with
        | [] -> error loc "%s has no IPv4 address" name
        | addrs -> Array (Array.of_list (List.map (fun a -> Ip a) addrs)))
    | T.Hostname, Ip ip :: default ->
        (match hostname ip, default with
        | Some n, _ -> String n
        | None, [ d ] -> d
        | None, _ -> error loc "%s has no name" (Ip.Addr.to_dotted_string ip))
    | T.Split, [ String s ; String by ] ->
        if by = "" then error loc "Cannot split by an empty string" ;
        Array (Array.of_list (List.map (fun p -> String p) (String.split_on_string ~by s)))
    | T.Make_array, [ init ; Int len ] ->
        if len < 0 then error loc "array needs a length, not %d" len ;
        Array (Array.make len init)
    | T.Length, [ Array a ] -> Int (Array.length a)
    | T.Concat, [ Array a ; Array b ] -> Array (Array.append a b)
    | T.Append, [ Array a ; x ] -> Array (Array.append a [| x |])
    | T.Prepend, [ x ; Array a ] -> Array (Array.append [| x |] a)
    | T.Length, [ Map (m, _) ] -> Int (Map.PMap.cardinal m)
    | T.Make_map, [ _ ; default ] -> empty_map (Some default)
    | T.Has, [ Map (m, _) ; k ] -> Bool (Map.PMap.mem k m)
    | T.Remove, [ Map (m, d) ; k ] -> Map (Map.PMap.remove k m, d)
    | (T.Min | T.Max | T.Mean | T.Stddev | T.Percentile as b), vs :: args ->
        let vs =
            match vs with
            | Array a -> a
            | Map (m, _) -> Array.of_enum (Map.PMap.values m)
            | _ -> assert false in
        if Array.length vs = 0 then
            error loc "No %s of no values"
                (match b with T.Min -> "minimum" | T.Max -> "maximum"
                            | T.Mean -> "mean" | T.Stddev -> "standard deviation"
                            | _ -> "percentile") ;
        stat loc b vs args
    | T.Sum, [ vs ; zero ] ->
        let add a b =
            match a, b with
            | Int a, (Int b | Byte b) -> Int (a + b)
            | Float a, Float b -> Float (a +. b)
            | Interval a, Interval b -> Interval (Interval.add a b)
            | _ -> assert false in
        (match vs with
        | Array a -> Array.fold_left add zero a
        | Map (m, _) -> Map.PMap.fold (fun v s -> add s v) m zero
        | _ -> assert false)
    | T.Histogram, [ vs ; bucket ] ->
        let secs = function Interval i -> Interval.to_secs i | v -> float_of v in
        let of_secs x =
            match bucket with Interval _ -> Interval (Interval.of_secs x) | _ -> Float x in
        let b = secs bucket in
        if not (b > 0.) then error loc "The bucket of a histogram must be positive" ;
        let xs =
            match vs with
            | Array a -> Array.map secs a
            | Map (m, _) -> Array.of_enum (Enum.map secs (Map.PMap.values m))
            | _ -> assert false in
        Array.sort Float.compare xs ;
        (* The fields in their order, of each bucket from the last: *)
        let record n lo hi = Record [| Int n ; of_secs hi ; of_secs lo |] in
        let buckets, last =
            Array.fold_left (fun (buckets, cur) x ->
                let k = floor (x /. b) in
                match cur with
                | Some (k', n, lo, _) when k' = k -> buckets, Some (k, n + 1, lo, x)
                | Some (_, n, lo, hi) -> record n lo hi :: buckets, Some (k, 1, x, x)
                | None -> buckets, Some (k, 1, x, x)) ([], None) xs in
        let buckets =
            match last with
            | Some (_, n, lo, hi) -> record n lo hi :: buckets
            | None -> buckets in
        Array (Array.of_list (List.rev buckets))
    | T.Sorted, [ Array a ] ->
        let a = Array.copy a in
        Array.stable_sort compare_values a ;
        Array a
    | T.Keys, [ Map (m, _) ] -> Array (Array.of_enum (Map.PMap.keys m))
    | T.Values, [ Map (m, _) ] -> Array (Array.of_enum (Map.PMap.values m))
    | T.Length, [ String s ] -> Int (String.length s)
    | T.Print, [ String s ] -> print s ; Void
    | T.Print_err, [ String s ] -> print_err s ; Void
    | T.Assert, [ cond ; String msg ] ->
        if cond = Bool false || cond = Int 0 then error loc "%s" msg ;
        Void
    | _ -> assert false

let arith loc op a b =
    match op, a, b with
    | A.Add, Int a, Int b -> Int (a + b)
    | A.Sub, Int a, Int b -> Int (a - b)
    | A.Mul, Int a, Int b -> Int (a * b)
    | (A.Div | A.Mod), Int _, Int 0 -> error loc "Division by zero"
    | A.Div, Int a, Int b -> Int (a / b)
    | A.Mod, Int a, Int b -> Int (a mod b)
    | A.Add, Float a, Float b -> Float (a +. b)
    | A.Sub, Float a, Float b -> Float (a -. b)
    | A.Mul, Float a, Float b -> Float (a *. b)
    | A.Div, Float a, Float b -> Float (a /. b)
    | A.Mod, Float a, Float b -> Float (Stdlib.Float.rem a b)
    | A.Add, Interval a, Interval b -> Interval (Interval.add a b)
    | A.Sub, Interval a, Interval b -> Interval (Interval.sub a b)
    | A.Mul, Interval a, Float b | A.Mul, Float b, Interval a ->
        Interval (Interval.mul a b)
    | A.Mul, Array a, Int n | A.Mul, Int n, Array a ->
        if n < 0 then error loc "Cannot repeat %d times" n ;
        Array (Array.concat (List.make n a))
    | A.Div, Interval _, Float 0. -> error loc "Division by zero"
    | A.Div, Interval a, Float b -> Interval (Interval.div a b)
    | A.Div, Interval a, Interval b -> Float (Interval.to_secs a /. Interval.to_secs b)
    | A.Sub, Time a, Time b ->
        let d = Clock.Wall.to_secs a -. Clock.Wall.to_secs b in
        (* As many picoseconds as an int holds: *)
        if Float.abs d *. 1e12 >= float_of_int max_int then
            error loc "%s - %s is too long an interval"
                (Clock.Wall.to_iso8601 a) (Clock.Wall.to_iso8601 b) ;
        Interval (Interval.of_secs d)
    | A.Add, Time t, Interval i | A.Add, Interval i, Time t ->
        Time (Clock.Wall.add t i)
    | A.Sub, Time t, Interval i -> Time (Clock.Wall.sub t i)
    | A.Add, Time t, Float s | A.Add, Float s, Time t ->
        Time (Clock.Wall.of_secs (Clock.Wall.to_secs t +. s))
    | A.Sub, Time t, Float s ->
        Time (Clock.Wall.of_secs (Clock.Wall.to_secs t -. s))
    | A.BitAnd, Int a, Int b -> Int (a land b)
    | A.BitOr, Int a, Int b -> Int (a lor b)
    | A.BitXor, Int a, Int b -> Int (a lxor b)
    | A.BitAnd, Byte a, Byte b -> Byte (a land b)
    | A.BitOr, Byte a, Byte b -> Byte (a lor b)
    | A.BitXor, Byte a, Byte b -> Byte (a lxor b)
    | _ -> invalid_arg "Crafty_interp.arith"

(* Where a program writes, and the date it reads: *)
type output =
    { print : string -> unit ; print_err : string -> unit ;
      now : unit -> Clock.Wall.t ;
      (* What [format()] writes: *)
      format : format }

let rec eval output (env : env) (e : T.expr) =
    let eval = eval output env in
    match e.desc with
    | T.Lit l -> of_literal l
    | T.String parts ->
        String (String.concat "" (List.map (function
            | T.Text s -> s
            | T.Interp e -> to_string e.typ (eval e)) parts))
    | T.Var v ->
        (match !(lookup env v) with
        | Void when v.id = T.last_var.id -> error e.loc "LAST is not set: no packet was sent yet"
        | x -> x)
    | T.Packet_field { layer ; field } ->
        let (l : Crafty_layers.layer), (u : Crafty_layers.unpacked) =
            List.nth env.packet (List.length env.packet - 1 - layer) in
        List.assoc l.fields.(field).name u.values
    | T.Field (r, i) ->
        (* Void only in the fields of BUDGET and PORTS that are not set, and
         * in those of a packet sent that only its capture tells: *)
        (match eval r, r.typ with
        | Record vs, A.Type.Record fs ->
            (match vs.(i), List.nth fs i with
            | Void, (n, t) when t <> A.Type.Void ->
                if r.typ = T.budget_type || r.typ = T.ports_type then
                    error e.loc "%s is not set, by the program or the command line" n ;
                let l = List.find (fun l -> T.packet_record l = r.typ) Crafty_layers.all in
                error e.loc "%s.%s is not known: %s" (T.lname l.name) n T.only_captured
            | v, _ -> v)
        | _ -> assert false)
    | T.Index (a, i) ->
        (match eval a, eval i with
        | Array a, Int i -> item e.loc a i
        | Map (m, d), k -> find e.loc i.T.typ m d k
        | _ -> assert false)
    | T.Slice (a, from, to_) ->
        let a = eval a in
        let bound = Option.map (fun i -> match eval i with Int i -> i | _ -> assert false) in
        let from, to_ = bound from, bound to_ in
        (match a with
        | Array a ->
            let o, l = slice (Array.length a) from to_ in
            Array (Array.sub a o l)
        | String s ->
            let o, l = slice (String.length s) from to_ in
            String (String.sub s o l)
        | _ -> assert false)
    | T.Select { packet ; layer ; from_start ; nth } ->
        (match eval packet with
        | Array a ->
            let layers =
                Array.to_list a |>
                List.filter_map (function
                    | Variant (n, v) when n = T.lname layer.name -> Some v
                    | _ -> None) in
            let layers = if from_start then layers else List.rev layers in
            (match List.nth_opt layers nth with
            | Some v -> v
            | None -> error e.loc "No such %s in this packet" (T.lname layer.name))
        | _ -> assert false)
    | T.Call (T.Stats, []) ->
        let stats = Crafty_tree.stats (List.hd env.stack).node in
        (match e.typ with
        | A.Type.Record fields ->
            Record (Array.of_list (List.map (fun (n, _) -> List.assoc n stats) fields))
        | _ -> assert false)
    | T.Call (T.Format, [ x ]) ->
        (match Crafty_value.format output.format x.typ (eval x) with
        | Some s -> String s
        | None ->
            error e.loc "Only a scalar, or a record, array or map of scalars, \
                         makes CSV, not %s" (A.Type.to_string x.typ))
    | T.Call (b, args) ->
        call e.loc b (List.map eval args)
             ~print:output.print ~print_err:output.print_err ~now:output.now
    | T.Unop (A.Not, a) ->
        (match eval a with Bool b -> Bool (not b) | _ -> assert false)
    | T.Unop (A.Neg, a) ->
        (match eval a with
        | Int i -> Int (~- i)
        | Float f -> Float (~-. f)
        | Interval i -> Interval (Interval.sub Interval.zero i)
        | _ -> assert false)
    | T.Binop (op, a, b) ->
        (* No short cut: both operands are evaluated, errors and all *)
        let a = eval a and b = eval b in
        (match op with
        | A.And | A.Or ->
            (match a, b with
            | Bool a, Bool b -> Bool (if op = A.And then a && b else a || b)
            | _ -> assert false)
        | A.Eq -> Bool (equal a b)
        | A.Ne -> Bool (not (equal a b))
        | A.Lt -> Bool (compare_values a b < 0)
        | A.Le -> Bool (compare_values a b <= 0)
        | A.Gt -> Bool (compare_values a b > 0)
        | A.Ge -> Bool (compare_values a b >= 0)
        | op -> arith e.loc op a b)
    | T.Record es -> Record (Array.of_list (List.map eval es))
    | T.Array es -> Array (Array.of_list (List.map eval es))
    | T.Map kvs ->
        (match empty_map None with
        | Map (m, d) ->
            Map (List.fold_left (fun m (k, v) ->
                let k = eval k in Map.PMap.add k (eval v) m) m kvs, d)
        | _ -> assert false)
    | T.Convert a -> convert e.loc a.typ e.typ (eval a)
    | T.Construct (c, a) -> Variant (c, Option.map_default eval Void a)
    | T.Block b -> eval_block output env b
    | T.If { cond ; then_ ; else_ } ->
        eval_block output env (match eval cond with Bool true -> then_ | _ -> else_)
    | T.Case { subject ; arms ; else_ } ->
        let env, b = branch env (eval subject) arms else_ in
        eval_block output env b

(* The block of a [case] for that value, and the environment to run it in: *)
and branch env v (arms : T.arm list) else_ =
    match v with
    | Variant (n, x) ->
        (match List.find_opt (fun (a : T.arm) -> a.ctor = n) arms, else_ with
        | Some a, _ -> Option.map_default (fun h -> bind env h x) env a.held, a.branch
        | None, Some b -> env, b
        (* The typer has an [else] unless every constructor has an arm: *)
        | None, None -> assert false)
    | _ -> assert false

(* That of a block within an expression, which the typer lets have only
 * declarations, assignments and expressions: *)
and eval_block output env (b : T.block) =
    List.fold_left (fun (env, _) (s : T.stmt) ->
        match s.stmt with
        | T.Declare (v, e) -> bind env v (eval output env e), Void
        | T.Assign { var ; path ; value } ->
            let is, env' = bind_path output env path in
            let x = eval output env' value in
            let cell = lookup env var in
            cell := set_item s.stmt_loc !cell is x ;
            env, Void
        | T.Expr e -> env, eval output env e
        | _ -> assert false) (env, Void) b |> snd

(* The indices of an assignment's path, and the environment with each bound
 * to its variable: *)
and bind_path output env path =
    List.fold_left (fun (is, env) (v, i) ->
        let i = eval output env i in
        ((v : T.var).typ, i) :: is, bind env v i) ([], env) path |>
    fun (is, env) -> List.rev is, env

(** {2 Blocks} *)

(* A block being run: *)
type block =
    { parent : block option ;
      mutable live : bool ;
      mutable children : block list ;
      (* What to undo when it is left: *)
      mutable cleanups : (unit -> unit) list ;
      (* Where its errors go, once it is cancelled: *)
      fail : error -> unit ;
      (* Leaving that many enclosing loops: *)
      break_ : int -> unit ;
      (* How many of its [on]s are not over: *)
      mutable busy : int ;
      (* How many of its [on]s with a duration or a linger are armed: *)
      mutable holding : int ;
      (* What to run once its statements are done: *)
      mutable stmts_done : (unit -> unit) list ;
      (* What disarms its other [on]s, once its statements are done and none
       * holds it: *)
      mutable ending : (unit -> unit) list ;
      (* What ends it, once its statements are done, when it is not busy: *)
      mutable finish : (unit -> unit) option }

(* Leaves [b], and the blocks within it; the most recent first: *)
let rec cancel b =
    if b.live then (
        b.live <- false ;
        List.iter cancel b.children ;
        List.iter (fun f -> f ()) b.cleanups ;
        b.cleanups <- [] ;
        Option.may (fun p -> p.children <- List.filter ((!=) b) p.children)
                   b.parent)

(* Ends [b] if it is done and not busy: *)
let settle b =
    if b.live && b.busy = 0 then
        Option.may (fun f -> b.finish <- None ; f ()) b.finish

(* Disarms the [on]s that end with [b], if it is done and not held: *)
let release b =
    if b.live && b.holding = 0 && b.finish <> None then (
        let ending = b.ending in
        b.ending <- [] ;
        List.iter (fun f -> f ()) ending ;
        settle b)

(* [f ()], or else its error goes to [b], which is then left. Only what is
 * run within this block is guarded, never what follows it: *)
let guard b f =
    match f () with
    | x -> Some x
    | exception Runtime_error (where, message) ->
        b.fail Crafty_parser.{ where ; message } ;
        None

type t =
    { power : Simulation.power ;
      output : output ;
      tree : Crafty_tree.node ;
      (* What was sent and is waited for on its way out, by order of
       * sending, and who waits for it: *)
      awaited : (Crafty_tree.emitted * (Crafty_tree.packet -> unit)) list ref }

(* How long a packet sent may take to be seen leaving: *)
let capture_timeout = Interval.sec 1.

(* Calls [k] with the packet that the interface emits as [e], once it is
 * captured on its way out, or else fails [b] at [loc]: *)
let await t b loc e k =
    let rec w = e, (fun p -> if b.live then (disarm () ; k p))
    and disarm () = t.awaited := List.filter ((!=) w) !(t.awaited) in
    t.awaited := !(t.awaited) @ [ w ] ;
    b.cleanups <- disarm :: b.cleanups ;
    Simulation.delay t.power capture_timeout (fun () ->
        if List.memq w !(t.awaited) && b.live then (
            disarm () ;
            ignore (guard b (fun () ->
                error loc "The packet sent was not seen leaving within %s"
                    (Interval.to_string capture_timeout))))) ()

(* Tells the first that waits for [frame], captured on its way out: *)
let emitted t frame =
    match List.find_opt (fun (e, _) -> Crafty_tree.is_emitted e frame) !(t.awaited) with
    | Some (_, k) -> k (Crafty_tree.captured t.tree frame)
    | None -> ()

(* The stack of [env] with these layers on top of its [depth] first ones,
 * their nodes held by [b] (but for the root, which stays, and for a terminal
 * layer's, which goes with its parent). The options are those of this stack,
 * not of its nodes; the first [overlay] layers also take the key and the
 * options (that they can set) of the layers of [env] they are over, unless
 * they give them. Raises [Failed]. *)
let push t b env depth overlay (layers : T.layer list) =
    let n = List.length env.stack - depth in
    let base = List.drop n env.stack
    and over = List.rev (List.take n env.stack) in
    List.fold_lefti (fun stack j (l : T.layer) ->
        let options =
            List.map (fun (i, e) -> i, eval t.output env e) l.options in
        let options =
            if j >= overlay then options else
            let (o : Crafty_tree.entry) = List.nth over j in
            let given (i, _) = List.mem_assoc i options in
            let settable (i, _) = List.mem l.mode l.layer.fields.(i).set_in in
            options @
            List.filter (not % given) o.node.key @
            List.filter (fun opt ->
                not (given opt) && not (List.mem_assoc (fst opt) o.node.key) &&
                settable opt) o.options in
        let node =
            match stack with
            | [] ->
                assert (l.layer == Crafty_layers.root) ;
                t.tree
            | (below : Crafty_tree.entry) :: _ ->
                let node =
                    Crafty_tree.child l.layer_loc below.node l.layer options in
                if not l.layer.terminal then (
                    Crafty_tree.acquire node ;
                    b.cleanups <- (fun () -> Crafty_tree.release node) :: b.cleanups) ;
                node in
        Crafty_tree.{ node ; mode = l.mode ; options } :: stack
    ) base layers

(* The value of the [timeout] parameter of that statement: *)
let timeout_of eval what = function
    | Some (e : T.expr) ->
        (match eval e with
        | Interval i ->
            if Interval.compare i Interval.zero < 0 then
                error e.loc "The timeout of %s cannot be negative" what ;
            i
        | _ -> assert false)
    | None -> Interval.min 1.

(* A packet, the bottom first: *)
let packet_value packet =
    Array (Array.of_list (List.rev_map (fun ((l : Crafty_layers.layer), (u : Crafty_layers.unpacked)) ->
        match T.packet_record l with
        | A.Type.Record fields ->
            Variant (T.lname l.name, Record (Array.of_list (List.map (fun (name, _) ->
                List.assoc name u.values) fields)))
        | _ -> assert false) packet))

(* [MATCH], from the packet that matched, decoded to its top: *)
let match_value packet = packet_value (Crafty_tree.complete packet)

(* Registers alternative [patterns] for block [b], their conditions
 * evaluated in [env] at match time; a relative pattern on the node of the
 * stack it is on top of, which is seen in the mode of the stack. Its layers
 * that are over layers of the stack match only the streams of their nodes.
 * Returns what unregisters them: *)
(* Each case is alternative patterns and what to do of a packet that matches
 * one; a packet goes to one case at most: *)
let register t b env (cases : (T.pattern list * _) list) ~failed =
    let alternative (p : T.pattern) =
        let over = List.rev (List.take (List.length env.stack - p.depth) env.stack) in
        let layers =
            List.mapi (fun j (pl : T.pattern_layer) ->
                let cond =
                    Option.map (fun c packet ->
                        match eval t.output { env with packet } c with
                        | Bool b -> b
                        | _ -> assert false) pl.cond in
                let test =
                    if j >= p.overlay then cond else
                    let (o : Crafty_tree.entry) = List.nth over j in
                    Some (fun packet ->
                        Crafty_tree.of_stream o.node (snd (List.hd packet)) &&
                        Option.map_default (fun c -> c packet) true cond) in
                Crafty_tree.{ player = pl.pl_layer ; pmode = pl.pl_mode ; test }
            ) p.pat_layers in
        if p.depth = 0 then t.tree, layers else
        let (e : Crafty_tree.entry) =
            List.nth env.stack (List.length env.stack - p.depth) in
        e.node,
        Crafty_tree.{ player = e.node.layer ; pmode = e.mode ; test = None } :: layers in
    let cases = List.map (fun (ps, matched) -> List.map alternative ps, matched) cases in
    Crafty_tree.register cases ~failed ~hold:(fun n ->
        Crafty_tree.acquire n ;
        b.cleanups <- (fun () -> Crafty_tree.release n) :: b.cleanups)

(* Runs that block within [parent], then [k], unless it fails or breaks
 * first; returns the block. Its environment is what [enter] makes of [env]
 * once the block exists, unless that fails: *)
let rec run_block ?(enter=fun _ env -> Some env) t parent env (stmts : T.block)
                  ~fail ~break_ k =
    let rec b =
        { parent = Some parent ; live = true ; children = [] ; cleanups = [] ;
          fail = (fun e -> cancel b ; fail e) ;
          break_ ; busy = 0 ; holding = 0 ; stmts_done = [] ; ending = [] ;
          finish = None } in
    parent.children <- b :: parent.children ;
    let finish v =
        b.finish <- Some (fun () -> cancel b ; k v) ;
        let stmts_done = b.stmts_done in
        b.stmts_done <- [] ;
        List.iter (fun f -> f ()) stmts_done ;
        release b in
    let rec loop env = function
        | [] -> finish Void
        | [ { T.stmt = T.Expr e ; _ } ] ->
            exec_value t b env e (fun v -> if b.live then finish v)
        | s :: rest ->
            exec t b env s (fun env -> if b.live then loop env rest) in
    Option.may (fun env -> loop env stmts) (enter b env) ;
    b

(* Computes [e] in block [b], then [k] with its value; a block, an [if] or a
 * [case] runs as a block within [b]: *)
and exec_value t b env (e : T.expr) k =
    let run env body =
        ignore (run_block t b env body ~fail:b.fail ~break_:b.break_ k) in
    let eval e = guard b (fun () -> eval t.output env e) in
    match e.desc with
    | T.Block body -> run env body
    | T.If { cond ; then_ ; else_ } ->
        Option.may (fun c -> run env (match c with Bool true -> then_ | _ -> else_))
            (eval cond)
    | T.Case { subject ; arms ; else_ } ->
        Option.may (fun v -> let env, body = branch env v arms else_ in run env body)
            (eval subject)
    | _ -> Option.may k (eval e)

(* Runs that statement in block [b], then [k] with the environment for the
 * next statements: *)
and exec t b env (s : T.stmt) k =
    let eval e = eval t.output env e in
    let guard f = guard b f in
    match s.stmt with
    | T.Declare (v, e) -> exec_value t b env e (fun x -> k (bind env v x))
    | T.Assign { var ; path ; value } ->
        Option.may (fun (is, env') ->
            exec_value t b env' value (fun x ->
                let cell = lookup env var in
                Option.may (fun y -> cell := y ; k env)
                    (guard (fun () -> set_item s.stmt_loc !cell is x))))
            (guard (fun () -> bind_path t.output env path))
    | T.Expr e -> exec_value t b env e (fun _ -> k env)
    | T.Break n -> b.break_ n
    | T.Wait dur ->
        guard (fun () ->
            match eval dur with
            | Interval i ->
                if Interval.compare i Interval.zero < 0 then
                    error dur.loc "Cannot wait %s" (Interval.to_string i) ;
                i
            | _ -> assert false) |>
        Option.may (fun i ->
            Simulation.delay t.power i (fun () -> if b.live then k env) ())
    | T.Repeat { var ; count ; items ; every ; for_ ; body } ->
        repeat t b env var count items every for_ body s.stmt_loc (fun () -> k env)
    | T.Retry { max ; body } ->
        guard (fun () ->
            match Option.map eval max with Some (Int n) -> n | _ -> 3) |>
        Option.may (fun max ->
            let rec attempt retries =
                ignore (run_block t b env body ~break_:b.break_ (fun _ -> k env)
                    ~fail:(fun e ->
                        if retries < max && b.live then attempt (retries + 1)
                        else b.fail e)) in
            attempt 0)
    | T.Catch body ->
        ignore (run_block t b env body ~break_:b.break_ (fun _ -> k env)
                    ~fail:(fun _ -> if b.live then k env))
    | T.Stack { depth ; overlay ; layers ; body } ->
        (* The block holds the nodes of its stack: *)
        let enter b env =
            match push t b env depth overlay layers with
            | stack -> Some { env with stack }
            | exception Failed message ->
                b.fail Crafty_parser.{ where = s.stmt_loc ; message } ; None
            | exception Runtime_error (where, message) ->
                b.fail Crafty_parser.{ where ; message } ; None in
        ignore (run_block ~enter t b env body ~fail:b.fail ~break_:b.break_
                    (fun _ -> k env))
    | T.Send { depth ; overlay ; layers ; capture } ->
        (* A packet, leaving the current stack as it was, once it can go on
         * without waiting (as a blocking write does). Its frames reach the
         * interface through events of their own, due now, so the stack is
         * asked a picosecond later, once they all ran; and again once it
         * said it would be ready, or a node of it says it is, whichever
         * comes first: *)
        guard (fun () ->
            try
                let stack = push t b env depth overlay layers in
                stack, Crafty_tree.send stack
            with Failed msg -> error s.stmt_loc "%s" msg) |>
        Option.may (fun (stack, (packet, emitted)) ->
            lookup env T.last_var := packet_value packet ;
            (* The first capture makes its variable, which the next ones
             * update: *)
            let set env v x =
                if Env.mem v.T.id env.vars then (lookup env v := x ; env)
                else bind env v x in
            match capture, emitted with
            | Some v, Some e ->
                await t b s.stmt_loc e (fun p -> k (set env v (packet_value p)))
            | Some _, None -> assert false (* the typer said so *)
            | None, _ ->
            let rec wait d =
                let asked = ref false in
                let ask () =
                    if not !asked then (
                        asked := true ;
                        if b.live then check ()) in
                Simulation.delay t.power d ask () ;
                Crafty_tree.on_ready stack ask
            and check () =
                let d = Crafty_tree.busy_for stack in
                if Interval.compare d Interval.zero <= 0 then k env else wait d in
            wait (Interval.psec 1))
    | T.First { form ; timeout ; cases } ->
        guard (fun () -> timeout_of eval form timeout) |>
        Option.may (fun timeout ->
            let armed = ref true and unregister = ref ignore in
            let disarm () = armed := false ; !unregister () in
            let fire f = if !armed && b.live then (disarm () ; f ()) in
            unregister :=
                register t b env
                    (List.map (fun (c : T.case) ->
                        c.patterns, fun packet -> fire (fun () ->
                            let inner =
                                bind_lazy env c.match_ (fun () -> match_value packet) in
                            ignore (run_block t b inner c.body ~fail:b.fail
                                        ~break_:b.break_ (fun _ -> k env)))) cases)
                    ~failed:(fun where message -> fire (fun () ->
                        b.fail Crafty_parser.{ where ; message })) ;
            b.cleanups <- disarm :: b.cleanups ;
            Simulation.delay t.power timeout (fun () -> fire (fun () ->
                ignore (guard (fun () ->
                    error s.stmt_loc "Nothing matched within %s"
                        (Interval.to_string timeout))))) ())
    | T.On { for_ ; linger ; timeout ; max ; cases } ->
        let duration what = Option.map (fun (e : T.expr) ->
            match eval e with
            | Interval i ->
                if Interval.compare i Interval.zero < 0 then
                    error e.loc "The %s of on cannot be negative" what ;
                i
            | _ -> assert false) in
        guard (fun () ->
            duration "duration" for_,
            duration "linger" linger |? Interval.zero,
            duration "timeout" timeout,
            Option.map (fun e -> match eval e with Int n -> n | _ -> assert false) max) |>
        Option.may (fun (for_, linger, timeout, max) ->
            (* Like [repeat count=0], [max=0] does nothing: *)
            if Option.map_default (fun m -> m > 0) true max then
                on t b env s.stmt_loc cases ~for_ ~linger ~timeout max ;
            k env)

(* Disarmed after [for_], or else [linger] after the statements of [b] (or,
 * without a linger, once [b] is no longer held), or after [max] matches;
 * fails [b] after [timeout] without a match. Over once disarmed and its
 * running blocks are done: *)
and on t b env loc cases ~for_ ~linger ~timeout max =
    let armed = ref true and over = ref false and unregister = ref ignore in
    let holds = for_ <> None || Interval.compare linger Interval.zero > 0 in
    let matches = ref 0 in
    let now () = Simulation.now t.power.sim in
    let last_match = ref (now ()) in
    (* The instances of its block that are running: *)
    let running = ref [] in
    let disarm () =
        if !armed then (
            armed := false ;
            !unregister () ;
            if holds then (
                b.holding <- b.holding - 1 ;
                release b)) in
    let check_over () =
        if not !armed && List.is_empty !running && not !over && b.live then (
            over := true ;
            b.busy <- b.busy - 1 ;
            settle b) in
    let stop () =
        disarm () ;
        let r = !running in
        running := [] ;
        List.iter cancel r ;
        check_over () in
    b.busy <- b.busy + 1 ;
    if holds then b.holding <- b.holding + 1 ;
    let matched (c : T.case) packet =
        if !armed && b.live then (
            incr matches ;
            last_match := now () ;
            if Option.map_default (fun m -> !matches >= m) false max then
                disarm () ;
            let inner = bind_lazy env c.match_ (fun () -> match_value packet) in
            let instance =
                run_block t b inner c.body ~fail:b.fail
                    ~break_:(fun n -> if n <= 1 then stop () else b.break_ (n - 1))
                    (fun _ ->
                        running := List.filter (fun i -> i.live) !running ;
                        check_over ()) in
            (* Unless it was left already, with a break: *)
            if instance.live then
                if !over then cancel instance
                else running := instance :: !running ;
            check_over ()) in
    unregister :=
        register t b env (List.map (fun (c : T.case) -> c.patterns, matched c) cases)
            ~failed:(fun where message ->
                if !armed && b.live then (
                    disarm () ;
                    b.fail Crafty_parser.{ where ; message })) ;
    b.cleanups <- disarm :: b.cleanups ;
    let end_ () = disarm () ; check_over () in
    (match for_ with
    | Some d -> Simulation.delay t.power d end_ ()
    | None when holds ->
        b.stmts_done <- (fun () -> Simulation.delay t.power linger end_ ()) ::
                        b.stmts_done
    | None -> b.ending <- end_ :: b.ending) ;
    Option.may (fun timeout ->
        let rec idle () =
            if !armed && b.live then
                let until = Clock.Time.add !last_match timeout in
                if Clock.Time.compare (now ()) until < 0 then
                    Simulation.at t.power until idle ()
                else (
                    disarm () ;
                    ignore (guard b (fun () ->
                        error loc "Nothing matched within %s"
                            (Interval.to_string timeout)))) in
        Simulation.delay t.power timeout idle ()) timeout

and repeat t b env var count items every for_ body body_loc k =
    let eval = eval t.output env in
    let interval d = function
        | Some e -> (match eval e with Interval i -> i | _ -> assert false)
        | None -> d in
    guard b (fun () ->
        let items =
            Option.map (fun e ->
                match eval e with
                | Array a -> a
                (* Records of a key then a value, as their fields sort: *)
                | Map (m, _) ->
                    Array.of_list (List.map (fun (k, v) -> Record [| k ; v |])
                                            (Map.PMap.bindings m))
                | _ -> assert false) items in
        (match items, Option.map eval count with
        | Some a, _ -> Some (Array.length a)
        | None, Some (Int n) -> Some n
        | _ -> None),
        items,
        interval Interval.zero every,
        interval (Interval.min 5.) for_) |>
    Option.may (fun (count, items, every, for_) ->
    let now () = Simulation.now t.power.sim in
    let start = now () in
    let deadline = Clock.Time.add start for_ in
    let too_late time = Clock.Time.compare time deadline >= 0 in
    (* The iteration being run, for a break to leave it: *)
    let current = ref None in
    (* Iterations that are due run in a loop rather than one from the end of
     * the other, not to pile up on the stack; one is scheduled only when it
     * is not due yet. Without a count, so many of them without the time
     * moving on are a loop that would never end: *)
    let max_at_once = 100_000 in
    let rec iterations i =
        let i = ref i and at_once = ref 0 and again = ref true in
        while !again do
            again := false ;
            if b.live then (
                if Option.map_default (fun c -> !i >= c) false count ||
                   too_late (now ()) then
                    k ()
                else if count = None && !at_once >= max_at_once then
                    ignore (guard b (fun () ->
                        error body_loc "This repeat runs %d times without the \
                                        time moving on" max_at_once))
                else (
                    let env =
                        bind env var (match items with Some a -> a.(!i) | None -> Int !i) in
                    let break_ n =
                        if n <= 1 then (Option.may cancel !current ; k ())
                        else b.break_ (n - 1) in
                    let running = ref true and ended = ref false in
                    let this = !i in
                    current := Some (
                        run_block t b env body ~fail:b.fail ~break_ (fun _ ->
                            let next =
                                Clock.Time.add start
                                    (Interval.mul every (float_of_int (this + 1))) in
                            if Option.map_default (fun c -> this + 1 >= c) false count ||
                               too_late (Clock.Time.max next (now ())) then
                                k ()
                            else if Clock.Time.compare next (now ()) > 0 then
                                Simulation.at t.power next iterations (this + 1)
                            else if !running then ended := true
                            else iterations (this + 1))) ;
                    running := false ;
                    if !ended then (
                        incr i ; incr at_once ;
                        again := true)))
        done in
    iterations 0)

(** {2 Running programs} *)

type status = Running | Done | Failed of error | Stopped

type handle =
    { stop : unit -> unit ;
      status : unit -> status ;
      (* Whether the tree has no node beside its root, streams still
       * closing included, and no frame waits for an address resolution: *)
      idle : unit -> bool ;
      (* Tells a frame the interface sent, as captured on its way out: *)
      emitted : Bitstring.bitstring -> unit ;
      (* Whether a frame, sent or received, matches a filter: *)
      matches : filter -> Bitstring.bitstring -> bool ;
      (* The streams still open: *)
      open_streams : unit -> Crafty_tree.node list }

(** Alternative absolute patterns, matched against a frame on its own: *)
and filter = T.pattern list

let idle (tree : Crafty_tree.node) () =
    Crafty_tree.size tree = 1 && Tools.BitHash.length tree.eth.Eth.State.postponed = 0

let open_streams tree () = Crafty_tree.streams tree

let output_of power ?(format=Human) ~print ~print_err () =
    let now () =
        let sim = power.SimTypes.sim in
        Simulation.date_of sim (Simulation.now sim) in
    { print ; print_err ; now ; format }

let matches output tree (ps : filter) frame =
    List.exists (fun (p : T.pattern) ->
    let layers =
        List.map (fun (pl : T.pattern_layer) ->
            Crafty_tree.{
                player = pl.pl_layer ; pmode = pl.pl_mode ;
                test = Option.map (fun c packet ->
                    match eval output { vars = Env.empty ; stack = [] ; packet } c with
                    | Bool b -> b
                    | _ -> assert false) pl.cond }) p.pat_layers in
    Crafty_tree.matches tree layers frame) ps

(* Runs [program] on [power]'s simulation, starting at once, sending and
 * receiving through [tree] (from {!Crafty_tree.make_root}), writing with
 * [print] and [print_err], and calling [on_exit] with its final status
 * (possibly before returning). *)
(* The values of BUDGET and PORTS, void where not set: *)
let self_values (l : T.limits) =
    let record typ get =
        match typ with
        | A.Type.Record fs -> Record (Array.of_list (List.map (fun (n, _) -> get n) fs))
        | _ -> assert false in
    let ranges rs =
        Array (Array.of_list (List.map (fun (lo, hi) -> Array [| Int lo ; Int hi |]) rs)) in
    record T.budget_type (fun n ->
        Option.map_default of_literal Void (List.assoc_opt n l.budget)),
    record T.ports_type (fun n ->
        match l.ports with
        | None -> Void
        | Some p -> ranges (if n = "tcp" then p.tcp else p.udp))

let run_on_tree power tree ?format ~print ~print_err ?(on_exit=ignore)
                ?(limits=T.no_limits) (program : T.block) =
    let status = ref Running in
    let t = { power ; output = output_of power ?format ~print ~print_err () ; tree ;
              awaited = ref [] } in
    let exit s =
        if !status = Running then (
            status := s ;
            on_exit s) in
    let rec root =
        { parent = None ; live = true ; children = [] ; cleanups = [] ;
          fail = (fun e -> cancel root ; exit (Failed e)) ;
          break_ = (fun _ -> assert false) ; busy = 0 ; holding = 0 ;
          stmts_done = [] ; ending = [] ; finish = None } in
    let budget, ports = self_values limits in
    let vars =
        { vars = Env.empty ; stack = [] ; packet = [] } |>
        fun env -> bind (bind (bind env T.budget_var budget) T.ports_var ports)
                        T.last_var Void in
    ignore (run_block t root vars program
                ~fail:root.fail ~break_:root.break_
                (fun _ -> cancel root ; exit Done)) ;
    { stop = (fun () -> cancel root ; exit Stopped) ;
      status = (fun () -> !status) ;
      idle = idle tree ;
      emitted = emitted t ;
      matches = matches t.output tree ;
      open_streams = open_streams tree }

(* With what it declares of itself: *)
type program = { body : Crafty_typing.block ; limits : Crafty_typing.limits }

let print_error = Crafty_parser.print_error

(** The program, or all the errors found in it, in the order of the source;
 * and in [warnings], what is likely not what was meant. *)
let compile ?warnings text : (program, error list) result =
    match Crafty_parser.parse text with
    | Error e -> Error [ e ]
    | Ok p ->
        Result.bind (Crafty_typing.check ?warnings p) (fun body ->
            Result.map (fun limits -> { body ; limits }) (Crafty_typing.limits p))

(** The filter of that text, alternative absolute patterns, or what is wrong
 * with it. *)
let compile_filter text : (filter, error) result =
    Result.bind (Crafty_parser.parse_patterns text) Crafty_typing.check_patterns

let print_status oc = function
    | Running -> String.print oc "running"
    | Done -> String.print oc "done"
    | Failed e -> Printf.fprintf oc "failed: %a" print_error e
    | Stopped -> String.print oc "stopped"

(** Runs [program] on a new Ethernet interface under [parent], of address
 * [mac] and [ip] (in [netmask]), of link [speed] (default 1Gbps), full
 * duplex unless [full_duplex] is false, and of [mtu], sending beyond its
 * subnet to [gateway], answering ARP for [ip] unless [answer_arp] is false,
 * taking the frames for other addresses too if [promisc],
 * picking the local ports it is not given from the ports of [limits] (as
 * {!Crafty_tree.make_root} does), [limits] (default: the program's) being
 * what [BUDGET] and [PORTS] are, printing with [print] and [print_err],
 * [format()] writing in [format] (default {!Crafty_value.Human}),
 * calling [on_exit] with how it ends, and [on_closed] with the node of each
 * stream that goes away. Unless [rx_wire], what is written to the device was
 * received already (captured) and is taken at once, in order. Returns the device of the interface, and a handle to stop the
 * program, ask its status or tell it what the interface sent. The program starts at the next tick of the
 * simulation, once that device can be connected. *)
let run ~parent ?(name="crafty") ~mac ~ip ?netmask ?gateway ?answer_arp
        ?(promisc=false)
        ?(speed=EthSpeed.Eth1Gbps) ?(full_duplex=true) ?mtu
        ?limits ?format ?(print=ignore) ?(print_err=ignore) ?(on_exit=ignore)
        ?(on_closed=ignore) ?(rx_wire=true) (program : program) =
    let limits = limits |? program.limits in
    let ports =
        Option.map (fun (p : T.ports) -> [ "TCP", p.tcp ; "UDP", p.udp ])
                   limits.ports in
    let gateways =
        Option.map_default (fun gw ->
            [ Eth.State.gw_selector (), Some gw ]) [] gateway in
    let eth =
        Eth.State.make ~parent ~name ~mac ~gateways ?answer_arp
            ?promisc:(if promisc then Some ignore else None)
            ~speeds:[ speed ] ~full_duplex ?mtu
            ~my_addresses:[ Eth.State.make_my_ip_address ?netmask ip ] () in
    (* No cable to negotiate with: the link is what the interface supports. *)
    eth.iface.widget.ports.set_capabilities 0 Capabilities.Any ;
    eth.iface.rx_wire <- rx_wire ;
    let power = eth.iface.widget.power in
    let tree =
        Crafty_tree.make_root ?ports eth
            ~on_removed:on_closed in
    let started = ref None and stopped = ref false in
    Simulation.asap power (fun () ->
        if not !stopped then
            started :=
                Some (run_on_tree power tree ?format ~print ~print_err ~on_exit
                                  ~limits program.body)
    ) () ;
    Eth.Iface.dev eth.iface,
    { stop = (fun () ->
        match !started with
        | Some (h : handle) -> h.stop ()
        | None ->
            if not !stopped then (
                stopped := true ;
                on_exit Stopped)) ;
      status = (fun () ->
        match !started with
        | Some h -> h.status ()
        | None -> if !stopped then Stopped else Running) ;
      idle = idle tree ;
      emitted = (fun frame -> Option.may (fun (h : handle) -> h.emitted frame) !started) ;
      matches = matches (output_of power ?format ~print ~print_err ()) tree ;
      open_streams = open_streams tree }

(* [runs ?stop_at ?trees ?frames ?sent ?inject text] is what the program in that text
 * prints, each line with the time it is printed at (and with [trees], the
 * tree of parsers then), then how it ends; or why it cannot run. With
 * [frames], the frames it emits are among those lines, as [describe] tells
 * them (without their time, which depends on the scheduler by a few ps).
 * [inject] are frames it receives, with the time they arrive at, made with
 * the help of [incoming] (from 02:00:00:00:00:02). With [sent], the frames
 * it emits are told back to it as captured on their way out. With [promisc], its
 * interface takes the frames for other addresses too. Its interface is 10.0.0.1/24, its gateway 02:00:00:00:00:fe, and it
 * knows the MAC address of 10.0.0.2. *)
(*$inject
  let gw_mac = Eth.Addr.of_string "02:00:00:00:00:fe"

  let crafty_eth ?promisc sim =
      let eth =
          Eth.State.make ~parent:sim.SimTypes.root ~name:"crafty" ?promisc
              ~mac:(Eth.Addr.of_string "02:00:00:00:00:01")
              ~gateways:[ Eth.State.gw_selector (), Some (Eth.Gateway.Mac gw_mac) ]
              ~my_addresses:[ Eth.State.make_my_ip_address
                                  ~netmask:(Ip.Addr.of_string "255.255.255.0")
                                  (Ip.Addr.of_string "10.0.0.1") ] () in
      Tools.BitHash.replace eth.Eth.State.arp_cache
          (Ip.Addr.to_bitstring (Ip.Addr.of_string "10.0.0.2"))
          (Some (Eth.Addr.of_string "02:00:00:00:00:02")) ;
      eth

  let describe frame = Packet.Pdu.Printer.for_tests (Packet.of_frame frame)

  let peer_mac = Eth.Addr.of_string "02:00:00:00:00:02"

  let incoming ?(dst_mac=Eth.Addr.of_string "02:00:00:00:00:01") ?(proto=Eth.Proto.ip4) bits =
      Eth.Pdu.(pack (make proto peer_mac dst_mac bits))

  let ip_packet ?(id=1) ?(src="10.0.0.2") proto bits =
      Ip.Pdu.make ~id proto (Ip.Addr.of_string src) (Ip.Addr.of_string "10.0.0.1") bits

  let udp_packet ?id sport dport data =
      Udp.Pdu.(pack (make ~src_port:(Udp.Port.o sport) ~dst_port:(Udp.Port.o dport)
                          (Bitstring.bitstring_of_string data))) |>
      ip_packet ?id Ip.Proto.udp

  let arp ?(reply=false) sender =
      let sender = Ip.Addr.to_bitstring (Ip.Addr.of_string sender)
      and us = Ip.Addr.to_bitstring (Ip.Addr.of_string "10.0.0.1") in
      let hw = (peer_mac :> Bitstring.bitstring) in
      (if reply then
          Arp.Pdu.make_reply Arp.HwType.eth Eth.Proto.ip4 hw sender
              (Eth.Addr.of_string "02:00:00:00:00:01" :> Bitstring.bitstring) us
      else Arp.Pdu.make_request Arp.HwType.eth Eth.Proto.ip4 hw sender us) |>
      Arp.Pdu.pack |>
      incoming ~proto:Eth.Proto.arp ~dst_mac:Eth.Addr.broadcast

  let same_random_ids s =
      let first = ref None in
      String.split_on_char '\n' s |> List.map (fun l ->
          match String.split l ~by:" id=" with
          | a, b ->
              let id, rest = String.split b ~by:" " in
              if id = "7" then l else (
                  if !first = None then first := Some id ;
                  a ^" id="^ (if !first = Some id then "?" else "other") ^" "^ rest)
          | exception Not_found -> l) |> String.concat "\n"

  let reply ?(sport=53) ?(dport=1000) data =
      incoming (Ip.Pdu.pack (udp_packet sport dport data))

  let runs ?stop_at ?(trees=false) ?(frames=false) ?(sent=false) ?(inject=[]) ?(promisc=false) ?format text =
      match Crafty_parser.parse text with
      | Error e -> IO.to_string Crafty_parser.print_error e
      | Ok p ->
          match Crafty_typing.check p with
          | Error es ->
              String.concat "\n" (List.map (IO.to_string Crafty_parser.print_error) es)
          | Ok p ->
              let sim = Simulation.make ~realtime:false "crafty" in
              sim.epoch <- Clock.Wall.of_secs 0. ;
              let eth = crafty_eth ?promisc:(if promisc then Some ignore else None) sim in
              let tree = Crafty_tree.make_root eth in
              let out = ref [] in
              let line pfx s =
                  out := Printf.sprintf "%s%s: %s%s" pfx
                      (Clock.Time.to_string (Simulation.now sim)) s
                      (if trees then " "^ Crafty_tree.to_string tree else "") :: !out in
              let emitted = ref ignore in
              if frames || sent then
                  Tools.(Eth.Iface.dev eth.Eth.State.iface -->
                      sink (fun bits ->
                          if frames then out := ("> "^ describe bits) :: !out ;
                          if sent then Simulation.asap sim.root.power !emitted bits)) ;
              List.iter (fun (t, frame) ->
                  Simulation.at sim.root.power (Clock.Time.of_secs t)
                      (fun () -> eth.Eth.State.iface.Eth.Iface.recv frame) ()) inject ;
              let h =
                  run_on_tree sim.root.power tree ?format ~print:(line "") ~print_err:(line "err ")
                      ~on_exit:(function
                          | Done -> line "" "done"
                          | Failed e ->
                              line "" ("failed: "^ IO.to_string Crafty_parser.print_error e)
                          | Stopped -> line "" "stopped"
                          | Running -> ()) p in
              emitted := h.emitted ;
              Option.may (fun t ->
                  Simulation.at sim.root.power t h.stop ()) stop_at ;
              Simulation.run sim false ;
              String.concat "\n" (List.rev !out)
*)

(*$= runs & ~printer:identity
  "0s: hello 3\nerr 0s: oops\n0s: done" \
    (runs "print(\"hello ${1 + 2}\")\nprint_err(\"oops\")")
  "0s: 0\n1s: 1\n2s: 2\n2s: after\n2s: done" \
    (runs "repeat count=3 every=1s { print(\"${I}\") }\nprint(\"after\")")
  "0s: 0\n1s: 1\n2s: 2\n2s: done" \
    (runs "repeat for=2500ms every=1s { print(\"${I}\") }")
  "0s: 0\n1s: 1\n1s: done" \
    (runs "repeat for=2s every=1s { print(\"${I}\") }")
  "0s: 0\n1s: 1\n2s: done" \
    (runs "repeat for=1500ms { print(\"${I}\")\n  repeat count=2 every=1s {} }")
  "0s: 0\n400ms: 1\n1s: 0\n1s400ms: 1\n2s: 0\n2s400ms: 1\n2s400ms: done" \
    (runs "repeat count=3 every=1s { repeat count=2 every=400ms { print(\"${I}\") } }")
  "0s: 0.0\n0s: 0.1\n0s: 1.0\n0s: 1.1\n0s: done" \
    (runs "repeat var=i count=2 { repeat var=j count=2 { print(\"${i}.${j}\") } }")
  "0s: done" \
    (runs "repeat count=0 { print(\"never\") }")
  "0s: 3\n0s: 5\n0s: 6\n0s: done" \
    (runs "foreach t [3, 5, 6] { print(\"${t}\") }")
  "0s: a\n1s: b\n1s: after\n1s: done" \
    (runs "foreach s every=1s [\"a\", \"b\"] { print(s) }\nprint(\"after\")")
  "0s: a\n1s: b\n1s: done" \
    (runs "foreach s every=1s for=1500ms [\"a\", \"b\", \"c\"] { print(s) }")
  "0s: done" \
    (runs "foreach array(init=1, len=0) { print(\"never\") }")
  "0s: 1\n0s: 2\n0s: [9]\n0s: done" \
    (runs "x = [1, 2]\nforeach v x { x := [9]\n  print(\"${v}\") }\nprint(\"${x}\")")
  "0s: 1\n0s: done" \
    (runs "foreach [1, 2, 3] { if I == 2 { break }\n  print(\"${I}\") }")
  "0s: 0\n0s: after\n0s: done" \
    (runs "repeat count=5 every=1s { print(\"${I}\")\n  break }\nprint(\"after\")")
  "0s: 0\n0s: after\n0s: done" \
    (runs "repeat var=i count=3 { repeat { print(\"${i}\")\n    break 2 } }\nprint(\"after\")")
  "0s: [0, 1, 2, 3, 4] [0, 1, 2, 5] [9, 0, 1, 2] [0, 1, 2, 0, 1, 2] [7]\n0s: done" \
    (runs "x = [1]\nx += 2\nx := 0 + x\ny = array(0, 0) + 7\nprint(\"${x + [3, 4]} ${append(x, 5)} ${prepend(9, x)} ${concat(x, x)} ${y}\")")
  "0s: [a, , b c] 2 1 [x]\n0s: done" \
    (runs "p = split(\"a,,b c\", \",\")\nprint(\"${p} ${length(split(\"a--b\", by=\"--\"))} ${length(split(\"\", \",\"))} ${split(\"x\", \"y\")}\")")
  "0s: failed: line 1, column 5: Cannot split by an empty string" \
    (runs "x = split(\"a\", \"\")")
  "0s: [a: 2, b: 1] 2 0\n0s: done" \
    (runs "n = map(key=\"\", default=0)\nforeach w [\"a\", \"b\", \"a\"] { n[w] += 1 }\nprint(\"${n} ${length(n)} ${n[\"z\"]}\")")
  "0s: 2=b\n0s: 3=c\n0s: [1: a, 2: b, 3: c] [2, 3] [b, c] false\n0s: done" \
    (runs "m = [2: \"b\", 1: \"a\"]\nm[3] := \"c\"\nn = m\nm := remove(m, 1)\nforeach m { print(\"${I.key}=${I.value}\") }\nprint(\"${n} ${keys(m)} ${values(m)} ${has(m, 1)}\")")
  "0s: [1: [5]] true false\n0s: done" \
    (runs "m = map(key=0, default=[0])\nm[1][0] += 5\nprint(\"${m} ${m == [1: [5]]} ${m == [1: [6]]}\")")
  "0s: failed: line 2, column 5: No key 3 in this map" \
    (runs "m = [1: 2]\nx = m[3]")
  "0s: failed: line 2, column 1: No key 2 in this map" \
    (runs "m = [1: [0]]\nm[2][0] := 1")
  "0s: [1: 2.0]\n0s: done" \
    (runs "m = map(key=1, default=0.5)\nm := [1: 2]\nprint(\"${m}\")")
  "0s: [tcp: 1, udp: 2], and 0 icmp\n0s: done" \
    (runs "seen = map(key=\"\", default=0)\nforeach p [\"udp\", \"tcp\", \"udp\"] { seen[p] += 1 }\nprint(\"${seen}, and ${seen[\"icmp\"]} icmp\")")
  "0s: 1 7 1.5 1s500ms 2 3 1 2\n0s: done" \
    (runs "a = [5, 1, 4, 2, 3]\nprint(\"${min([3, 1, 2])} ${max([1: 5, 2: 7])} ${mean([1, 2])} ${mean([1s, 2s])} ${percentile(a, 40)} ${percentile(a, 40.1)} ${percentile([1], 0)} ${count([1, 2])}\")")
  "0s: 64 to 1500, median 512\n0s: done" \
    (runs "sizes = [64, 512, 1500]\nprint(\"${min(sizes)} to ${max(sizes)}, median ${percentile(sizes, 50)}\")")
  "0s: 2.0 1s 0.0\n0s: done" \
    (runs "print(\"${stddev([2, 4, 4, 4, 5, 5, 7, 9])} ${stddev([1: 1s, 2: 3s])} ${stddev([3.5])}\")")
  "0s: failed: line 1, column 5: No standard deviation of no values" \
    (runs "x = stddev(array(init=1s, len=0))")
  "0s: [1, 2, 3] [3, 1, 2] [[1, 2], [3]] [b: [1, 2]]\n0s: done" \
    (runs "a = [3, 1, 2]\nb = sorted(a)\nc = [[2, 1], [3]]\nsort(c[0])\nm = [\"b\": [2, 1]]\nsort(a=m[\"b\"])\nprint(\"${b} ${a} ${c} ${m}\")\nsort(a)\nassert(a == b)")
  "0s: 2s 1s500ms 2026-10-21T00:00:00Z 2026-10-21T00:00:00.25Z true\n0s: done" \
    (runs "t = time(1792540800.25)\nprint(\"${interval(2)} ${interval(1.5)} ${time(1792540800)} ${t} ${time(float(t)) == t && interval(float(90s)) == 90s}\")")
  "0s: 6 2.5 1s500ms 300 0 0.0 0s\n0s: done" \
    (runs "e = array(init=1, len=0)\nprint(\"${sum([1, 2, 3])} ${sum([1: 1, 2: 1.5])} ${sum([1s, 500ms])} ${sum([#ff, #2d])} ${sum(e)} ${sum(array(init=0.5, len=0))} ${sum(map(key=1, default=1s))}\")")
  "0s: [{count: 2, max: 2.0, min: 1.0}, {count: 1, max: 12.0, min: 12.0}, {count: 1, max: 15.0, min: 15.0}] []\n0s: done" \
    (runs "print(\"${histogram([12, 1, 15, 2], bucket=5)} ${histogram(array(init=1.5, len=0), 1)}\")")
  "0s: 2 [{count: 2, max: 7ms, min: 5ms}, {count: 1, max: 22ms, min: 22ms}]\n0s: done" \
    (runs "h = histogram([1: 7ms, 2: 22ms, 3: 5ms], bucket=5ms)\nprint(\"${length(h)} ${h}\")")
  "0s: failed: line 1, column 5: The bucket of a histogram must be positive" \
    (runs "x = histogram([1], bucket=0)")
  "0s: 1.5 1 -2 1792540800.25 1792540800\n0s: done" \
    (runs "t = 2026-10-21T00:00:00.25Z\nprint(\"${float(1500ms)} ${int(1500ms)} ${int(-2500ms)} ${float(t)} ${int(t)}\")")
  "0s: failed: line 1, column 5: No minimum of no values" \
    (runs "x = min(array(init=1, len=0))")
  "0s: failed: line 1, column 5: No percentile 101.0, which is not within 0 and 100" \
    (runs "x = percentile([1], 101)")
  "0s: [1, 5] [9, 2]\n0s: done" \
    (runs "x = [1, 2]\ny = x\nx[1] += 3\ny[0] := 9\nprint(\"${x} ${y}\")")
  "0s: [[1], [0]]\n0s: done" \
    (runs "a = array(init=[0], len=2)\na[0][0] := 1\nprint(\"${a}\")")
  "0s: 1 [0, 5]\n0s: done" \
    (runs "n = 0\nx = [0, 0]\nx[{ n += 1 ; n }] += 5\nprint(\"${n} ${x}\")")
  "0s: failed: line 2, column 1: No item 1 in an array of length 1" \
    (runs "x = [1]\nx[1] := 2")
  "0s: 499999500000\n0s: done" \
    (runs "n = 0\nrepeat count=1000000 { n += I }\nprint(\"${n}\")")
  "0s: 0\n0s: 2\n0s: 4\n0s: done" \
    (runs "repeat count=3 { x = I * 2\n  print(\"${x}\") }")
  "0s: failed: line 1, column 1: This repeat runs 100000 times without the time moving on" \
    (runs "repeat { x = 1 }")
  "0s: try\n0s: try\n0s: try\n0s: failed: line 2, column 7: Division by zero" \
    (runs "retry max=2 { print(\"try\")\n  x = 1 / 0 }\nprint(\"not reached\")")
  "0s: try\n0s: try\n0s: try\n0s: try\n0s: failed: line 2, column 7: No item 1 in an array of length 1" \
    (runs "retry { print(\"try\")\n  x = [1][1] }")
  "0s: try\n0s: failed: line 2, column 7: Division by zero" \
    (runs "retry max=0 { print(\"try\")\n  x = 1 / 0 }")
  "0s: 0\n0s: 1\n0s: 2\n0s: after\n0s: done" \
    (runs "repeat count=3 { catch { print(\"${I}\")\n    x = 1 / 0\n    print(\"not reached\") } }\nprint(\"after\")")
  "0s: ok\n0s: failed: line 2, column 5: Division by zero" \
    (runs "catch { print(\"ok\") }\nx = 1 / 0")
  "0s: ok\n0s: failed: line 2, column 5: Division by zero" \
    (runs "retry max=2 { print(\"ok\") }\nx = 1 / 0")
  "0s: 2 {a: 1, b: [1, 2]} #414243 1.2.3.4 AA:BB:CC:DD:EE:FF\n0s: done" \
    (runs "x = {a: 1, b: [1, 2]}\nprint(\"${x.b[1]} ${x} ${#414243} ${1.2.3.4} ${aa:bb:cc:dd:ee:ff}\")")
  "0s: ABC\n0s: true 1s500ms 2s -1s 1 1.5\n0s: done" \
    (runs "print(#414243)\nprint(\"${1.2.3.4 == #01020304} ${1s + 500ms} ${2 * 1s} ${-1s} ${7 % 3} ${7.5 % 2}\")")
  "0s: 13 3.0 false #2c 1s500ms\n0s: done" \
    (runs "print(\"${int(3.7) + log2(1024)} ${float(3)} ${bool(0)} ${byte(300)} ${interval(1.5)}\")")
  "0s: 2026-10-20T22:02:46.5Z 1s500ms 2026-10-20T22:02:46.5Z true 1970-01-01T00:00:00Z 1970-01-01T00:00:11Z 2026-10-20T22:02:44Z\n0s: done" \
    (runs "t0 = 2026-10-20T22:02:45Z\nt1 = t0 + 1.5\nprint(\"${t1} ${t1 - t0} ${t0 + 2s - 500ms} ${t1 > t0} ${time(0)} ${10 + time(1)} ${t0 - 1}\")")
  "1s500ms: 1s500ms\n1s500ms: done" \
    (runs "t = now()\nwait 1500ms\nprint(\"${now() - t}\")")
  "0s: failed: line 1, column 10: 2026-10-20T00:00:00Z - 1970-01-01T00:00:00Z is too long an interval" \
    (runs "print(\"${2026-10-20T00:00Z - time(0)}\")")
  "0s: 10.0.0.1 true 01:02:03:04:05:06\n0s: done" \
    (runs "x = ip_addr(#0a000001)\nprint(\"${x} ${x == 10.0.0.1} ${mac_addr(#010203040506)}\")")
  "0s: failed: line 1, column 5: 3 bytes are no IP address" \
    (runs "x = ip_addr(#010203)")
  "0s: failed: line 1, column 5: 4 bytes are no MAC address" \
    (runs "x = mac_addr(#01020304)")
  "0s: 16 -1.5 1 true #2c 1s500ms 2026-10-20T22:02:45Z 10.0.0.1 01:02:03:04:05:06\n0s: done" \
    (runs "print(\"${int(\"0x10\")} ${float(\" -1.5 \")} ${int(\"1.9\")} ${bool(\"true\")} ${byte(\"300\")} ${interval(\"1.5s\")} ${time(\"2026-10-20T22:02:45Z\")} ${ip_addr(\"10.0.0.1\")} ${mac_addr(\"1:2:3:4:5:6\")}\")")
  "0s: failed: line 1, column 5: Cannot convert \"1.2.3.4\" to an int" \
    (runs "x = int(\"1.2.3.4\")")
  "0s: failed: line 1, column 5: Cannot convert \"10.0.0\" to an IP address" \
    (runs "x = ip_addr(\"10.0.0\")")
  ("0s: "^ Sys.getenv "HOME" ^"\n0s: done") \
    (runs "print(getenv(\"HOME\"))")
  "0s: failed: line 1, column 5: Environment variable CRAFTY_NO_SUCH_VAR is not set" \
    (runs "x = getenv(\"CRAFTY_NO_SUCH_VAR\")")
  ("0s: default "^ Sys.getenv "HOME" ^"\n0s: done") \
    (runs "print(\"${getenv(\"CRAFTY_NO_SUCH_VAR\", default=\"default\")} ${getenv(\"HOME\", default=\"\")}\")")
  "0s: [127.0.0.1] localhost\n0s: done" \
    (runs "print(\"${resolve(\"localhost\")} ${hostname(resolve(\"localhost\")[0])}\")")
  "0s: {ip: 10.0.0.2, ok: true, rtt: 1ms500µs}\n0s: done" \
    (runs "print(format({ip: 10.0.0.2, rtt: 1.5ms, ok: true}))")
  "0s: {\"data\":\"#0102\",\"ip\":\"10.0.0.2\",\"rtt\":0.0015,\"tags\":[\"a\",\"b\"]}\n0s: done" \
    (runs ~format:Json "print(format({ip: 10.0.0.2, rtt: 1.5ms, tags: [\"a\", \"b\"], data: #0102}))")
  "0s: 10.0.0.2,0.0015,\"a,b\"\n0s: 1,2,3\n0s: done" \
    (runs ~format:Csv "print(format({ip: 10.0.0.2, rtt: 1.5ms, s: \"a,b\"})) ; print(format([1, 2, 3]))")
  "0s: failed: line 1, column 7: Only a scalar, or a record, array or map of scalars, makes CSV, not {a: int[]}" \
    (runs ~format:Csv "print(format({a: [1]}))")
  "0s: [1.5, 1.5] 2 1.5 4\n0s: done" \
    (runs "x = array(init=1.5, len=2)\nprint(\"${x} ${length(x)} ${x[1]} ${length(randbytes(4))}\")")
  "0s: failed: line 3, column 1: Assertion failed: (x * 2) == 5" \
    (runs "x = 2\nassert(x * 2 == 4)\nassert(x * 2 == 5)\nprint(\"not reached\")")
  "0s: failed: line 2, column 1: x is 3" \
    (runs "x = 3\nassert(x == 4, msg=\"x is ${x}\")")
  "0s: caught\n0s: done" \
    (runs "catch { assert(0) }\nprint(\"caught\")")
  "0s: small 0\n0s: odd 1\n0s: big 2\n0s: odd 3\n0s: big 4\n0s: done" \
    (runs "repeat count=5 { if I & 1 { print(\"odd ${I}\") } elsif I > 1 { print(\"big ${I}\") }\n  else { print(\"small ${I}\") } }")
  "0s: 0\n0s: 1\n0s: after\n0s: done" \
    (runs "repeat { if I == 2 { break }\n  print(\"${I}\") }\nprint(\"after\")")
  "0s: 2.5 0.25 inf\n0s: done" \
    (runs "print(\"${5s / 2s} ${1ms / 4ms} ${1ms / 0s}\")")
  "0s: failed: line 1, column 4: Division by zero" \
    (runs "if 1 / 0 > 0 {}\nprint(\"not reached\")")
  "0s: #0101 #010201020102 [1, 2, 1, 2] 0\n0s: done" \
    (runs "x = 0\nprint(\"${#01 * 2} ${3 * #0102} ${[1, 2] * 2} ${length(#00 * x)}\")")
  "0s: failed: line 1, column 10: Cannot repeat -1 times" \
    (runs "print(\"${#01 * -1}\")")
  "0s: 1.0 6 11 small\n0s: done" \
    (runs "x = if 1 > 0 { 1 } else { 2.5 }\ny = { z = 2 ; z * 3 }\nprint(\"${x} ${y} ${1 + if y > 5 { 10 } else { 20 }} ${if y > 9 { \"big\" } else { \"small\" }}\")")
  "1s: 2\n1s: 3\n1s: done" \
    (runs "x = if true { wait 1s\n  2 } else { 3 }\nprint(\"${x}\")\nx := { y = x + 1\n  y }\nprint(\"${x}\")")
  "0s: 0\n0s: 1\n0s: 2\n0s: after\n0s: done" \
    (runs "repeat { x = if I > 2 { break } else { I }\n  print(\"${x}\") }\nprint(\"after\")")
  "0s: failed: line 1, column 23: Division by zero" \
    (runs "x = 1 + { y = 0 ; z = 1 / y ; z }\nprint(\"not reached\")")
  "1s: in\n1s: failed: line 2, column 17: Division by zero" \
    (runs "x = { wait 1s\n  print(\"in\") ; 1 / 0 }\nprint(\"not reached\")")
  "0s: failed: line 1, column 5: No item -2 in an array of length 1" \
    (runs "x = [1][-2]")
  "0s: 3 [1, 9]\n0s: done" \
    (runs "x = [1, 2, 3]\nx[-2] := 9\nprint(\"${x[-1]} ${x[:-1]}\")")
  "0s: [3, 4] [0, 1] [2, 3] [3] [] [] [0, 1, 2, 3, 4]\n0s: done" \
    (runs "a = [0, 1, 2, 3, 4]\nprint(\"${a[3:]} ${a[:2]} ${a[2:4]} ${a[-2:-1]} ${a[4:2]} ${a[9:]} ${a[-9:9]}\")")
  "0s: ell #0203 bc\n0s: done" \
    (runs "b = #01020304\nprint(\"${\"hello\"[1:-1]} ${b[1:3]} ${split(\"abc\", \"/\")[0][ 1 : ]}\")")
  "line 1, column 5: Cannot slice an int" \
    (runs "x = 1[1:]")
  "line 2, column 1: Unknown variable y" \
    (runs "x = #0102\ny := x")
  "0s: a\n1s500ms: b\n1s500ms: done" \
    (runs "print(\"a\")\nwait 1500ms\nprint(\"b\")")
  "1s: 0\n1s500ms: stopped" \
    (runs ~stop_at:(Clock.Time.of_secs 1.5) "repeat count=3 { wait 1s\n  print(\"${I}\") }")
  "0s: failed: line 1, column 6: Cannot wait -1s" \
    (runs "wait -1s")
  "0s: 0\n1s: 1\n1s500ms: stopped" \
    (runs ~stop_at:(Clock.Time.of_secs 1.5) \
          "repeat count=5 every=1s { print(\"${I}\") }")
*)
(* Stacks hold their nodes for the block they are in: *)
(*$= runs & ~printer:identity
  "0s: in Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1{UDP(src=1, dst=53)*1}}\n0s: out Eth\n0s: done Eth" \
    (runs ~trees:true "/IP(dst=1.2.3.4)/UDP(src=1, dst=53) { print(\"in\") }\nprint(\"out\")")
  "0s: a Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1}\n0s: b Eth{IP(src=10.0.0.1, dst=1.2.3.4)*2}\n3ps: c Eth{IP(src=10.0.0.1, dst=1.2.3.4)*3{ICMP*1{Echo(id=7)*1{Request}}, UDP(src=1, dst=53)*1}}\n3ps: d Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1}\n3ps: e Eth{IP(src=10.0.0.1, dst=1.2.3.5)*1}\n3ps: done Eth" \
    (runs ~trees:true "IP(dst=1.2.3.4) {\n  print(\"a\")\n  /IP(dst=1.2.3.4) {\n    print(\"b\")\n    UDP(src=1, dst=53) {\n      /IP(dst=1.2.3.4)/ICMP/Echo(id=7)/Request\n      print(\"c\") } }\n  print(\"d\") }\n/IP(dst=1.2.3.5) { print(\"e\") }")
  "0s: try Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1{UDP(src=1, dst=53)*1}}\n0s: try Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1{UDP(src=1, dst=53)*1}}\n0s: failed: line 4, column 9: Division by zero Eth" \
    (runs ~trees:true "retry max=1 {\n  /IP(dst=1.2.3.4)/UDP(src=1, dst=53) {\n    print(\"try\")\n    x = 1 / 0 } }")
  "0s: done Eth" \
    (runs ~trees:true "repeat count=3 { /IP(dst=1.2.3.4)/UDP(dst=53) {} }")
*)
(* What programs send, through the gateway or to a neighbour, self-driven or
 * manual, with the automatic fields filled in (checksums included, which
 * [describe] checks): *)
(*$= runs & ~printer:identity
  "> 02:00:00:00:00:01>02:00:00:00:00:FE IP 10.0.0.1>1.2.3.4 ttl=64 UDP 1000>53 \"hi\"\n4µs480ns2ps: done" \
    (runs ~frames:true "/IP(dst=1.2.3.4)/UDP(src=1000, dst=53)/Bytes(\"hi\")")
  "> 02:00:00:00:00:01>02:00:00:00:00:FE IP 10.0.0.1>1.2.3.4 ttl=3 df UDP 1>2 \"x\"\n4µs400ns1ps: done" \
    (runs ~frames:true "/IP!(dst=1.2.3.4, ttl=3, dont_frag=true)/UDP(src=1, dst=2)/Bytes(\"x\")")
  "> 02:00:00:00:00:01>02:00:00:00:00:FE IP 10.0.0.1>1.2.3.4 ttl=64 proto=99 \"p\"\n3µs760ns2ps: done" \
    (runs ~frames:true "/IP(dst=1.2.3.4, proto=99)/Bytes(\"p\")")
  "> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP\n4µs320ns2ps: done\n> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP\n> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP" \
    (runs ~frames:true "/IP(dst=10.0.0.3)/UDP(src=1, dst=2)/Bytes(\"who\")")
*)
(* Self-driven IP takes TTL and DF per packet (and a packet leaves the
 * stack of the block as it was); the requests of an Echo share its id (the
 * random one shown as "?"), and their sequence numbers go on: *)
(*$= runs & ~printer:identity
  "> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 UDP 1>2 \"a\"\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=3 df UDP 1>2 \"b\"\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 UDP 1>2 \"c\"\n13µs200ns6ps: done" \
    (runs ~frames:true "/IP(dst=10.0.0.2)/UDP(src=1, dst=2) { Bytes(\"a\")\n  /IP(dst=10.0.0.2, ttl=3, dont_frag=true)/UDP(src=1, dst=2)/Bytes(\"b\")\n  Bytes(\"c\") }")
  "> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 opts=[opt 94040000] UDP 1>2 \"a\"\n4µs720ns2ps: failed: line 2, column 1: The options of IP must be a multiple of 4 bytes, up to 40" \
    (runs ~frames:true "/IP(dst=10.0.0.2, options=#94040000)/UDP(src=1, dst=2)/Bytes(\"a\")\n/IP(dst=10.0.0.2, options=#940400)/UDP(src=1, dst=2)/Bytes(\"b\")")
  "> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 ICMP 8/0 id=? seq=1 \"ping\"\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 ICMP 8/0 id=? seq=2 \"ping\"\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 ICMP 8/0 id=7 seq=42 \"\"\n13µs600ns6ps: done" \
    (same_random_ids (runs ~frames:true "/IP(dst=10.0.0.2)/ICMP/Echo { repeat count=2 { Request(\"ping\") }\n  /IP(dst=10.0.0.2)/ICMP/Echo(id=7)/Request(seq=42) }"))
  "> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 ICMP 3/3 mtu=1400 \"\\001\\002\"\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 ICMP 11/0 mtu=0 \"\\003\\004\"\n8µs960ns2ps: done" \
    (runs ~frames:true "/IP!(dst=10.0.0.2)/ICMP/DestUnreachable(code=PORT_UNREACHABLE, mtu=1400)/Bytes(#0102)\n/IP!(dst=10.0.0.2)/ICMP/TimeExceeded/Bytes(#0304)")
*)
(* Manual frames, to a given MAC address or to what the interface knows: *)
(*$= runs & ~printer:identity
  "> 02:00:00:00:00:01>AA:BB:CC:DD:EE:FF proto=0x88b5 \"raw\"\n> 02:00:00:00:00:01>02:00:00:00:00:FE IP 10.0.0.1>1.2.3.4 ttl=64 UDP 1>2 \"y\"\n> 02:00:00:00:00:99>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 proto=99 \"z\"\n10µs480ns3ps: done" \
    (runs ~frames:true "/Eth!(dst=aa:bb:cc:dd:ee:ff, proto=0x88b5)/Bytes(\"raw\")\n/Eth!/IP!(dst=1.2.3.4)/UDP(src=1, dst=2)/Bytes(\"y\")\n/Eth!(src=02:00:00:00:00:99)/IP!(dst=10.0.0.2, proto=99)/Bytes(\"z\")")
*)
(* What cannot be sent: *)
(*$= runs & ~printer:identity
  "0s: failed: line 1, column 1: The MAC address of 10.0.0.3 is not known: Eth! needs a dst" \
    (runs ~frames:true "/Eth!/IP!(dst=10.0.0.3)/UDP(src=1, dst=2)/Bytes(\"x\")")
  "0s: failed: line 1, column 1: A self-driven Eth carries only IPv4: use Eth!" \
    (runs ~frames:true "/Eth/Bytes(\"x\")")
  "0s: failed: line 1, column 1: IP needs a proto" \
    (runs ~frames:true "/IP(dst=1.2.3.4)/Bytes(\"x\")")
  "0s: failed: line 1, column 1: The ttl must be between 0 and 255, not 256" \
    (runs ~frames:true "/IP!(dst=1.2.3.4, ttl=256)/ICMP/Echo/Request()")
  "0s: failed: line 1, column 1: A self-driven IP sends no empty packet: use IP!" \
    (runs ~frames:true "/IP(dst=1.2.3.4, proto=99)/Bytes()")
*)
(* Received frames go through the nodes of their streams (the sender's
 * port being the destination port of the node), fragments reassembled,
 * those for other hosts dropped: *)
(*$= runs & ~printer:identity
  "0s:  Eth{IP(src=10.0.0.1, dst=10.0.0.2)*1{UDP(src=1000, dst=53)*1}}\n1s:  Eth#6{IP(src=10.0.0.1, dst=10.0.0.2)*1#5{UDP(src=1000, dst=53)*1#2}}\n1s: done Eth#6" \
    (runs ~trees:true \
        ~inject:(List.map (fun f -> 0.5, f) \
            ([ incoming (Ip.Pdu.pack (udp_packet 53 1000 "hi")) ; \
               incoming (Ip.Pdu.pack (udp_packet 54 1000 "other port")) ; \
               incoming ~dst_mac:(Eth.Addr.of_string "02:00:00:00:00:03") \
                   (Ip.Pdu.pack (udp_packet 53 1000 "other host")) ; \
               incoming (Ip.Pdu.pack (ip_packet Ip.Proto.icmp \
                   (Icmp.Pdu.(pack (make_echo_reply 7 1))))) ] @ \
             List.map incoming \
               (Ip.Pdu.fragment 36 (udp_packet ~id:2 53 1000 "in two fragments")))) \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) { repeat count=2 every=1s { print(\"\") } }")
*)
(* The interface answers ARP, and sends what waited for an answer: *)
(*$= runs & ~printer:identity
  "> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP\n4µs320ns2ps: done\n> 02:00:00:00:00:01>02:00:00:00:00:02 ARP\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.3 ttl=64 UDP 1>2 \"who\"" \
    (runs ~frames:true ~inject:[ 0.1, arp "10.0.0.2" ; 0.2, arp ~reply:true "10.0.0.3" ] \
        "/IP(dst=10.0.0.3)/UDP(src=1, dst=2)/Bytes(\"who\")")
*)
(* Unanswered, the request is sent again every second, three times in all,
 * after which what waited is dropped: *)
(*$= runs & ~printer:identity
  "> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP\n4µs320ns2ps: done\n> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.3 ttl=64 UDP 1>2 \"who\"" \
    (runs ~frames:true ~inject:[ 1.5, arp ~reply:true "10.0.0.3" ] \
        "/IP(dst=10.0.0.3)/UDP(src=1, dst=2)/Bytes(\"who\")")
  "> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP\n4µs320ns2ps: done\n> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP\n> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP" \
    (runs ~frames:true ~inject:[ 3.5, arp ~reply:true "10.0.0.3" ] \
        "/IP(dst=10.0.0.3)/UDP(src=1, dst=2)/Bytes(\"who\")")
*)
(* A packet sent into a variable is waited for until seen leaving, and is
 * then that very frame, even among others alike: *)
(*$= runs & ~printer:identity
  "4µs640ns2ps: true true true 3ps 4µs639ns999ps\n9µs280ns2ps: pong\n9µs280ns2ps: done" \
    (runs ~sent:true \
        "/IP!(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n\
           a = Bytes(\"ping\")\n\
           ida = LAST[IP].id\n\
           b = Bytes(\"ping\")\n\
           print(\"${a[IP].id == ida} ${b[IP].id == LAST[IP].id} ${a[IP].id != b[IP].id} ${a[Eth].ts - time(0)} ${b[Eth].ts - a[Eth].ts}\")\n\
           b := Bytes(\"pong\")\n\
           print(b[Bytes].data) }")
  "3ps: 53 #78\n3ps: done" \
    (runs ~sent:true \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n\
           p = ../../IP!/UDP/Bytes(\"x\")\n\
           print(\"${p[UDP].dst} ${p[Bytes].data}\") }")
  "1s: failed: line 1, column 44: The packet sent was not seen leaving within 1s" \
    (runs "/IP!(dst=10.0.0.2)/UDP(src=1000, dst=53) { p = Bytes(\"ping\") }")
*)
(* A frame's [ts] is when it came in, which conditions can read: *)
(*$= runs & ~printer:identity
  "500ms: 500ms\n700ms: 700ms\n1s: done" \
    (runs ~inject:[ 0.2, reply "a" ; 0.5, reply "b" ; 0.7, reply "c" ] \
        "t0 = time(0)\non for=1s /Eth(ts > t0 + 300ms)/IP/UDP { print(\"${MATCH[Eth].ts - t0}\") }")
*)
(* expect waits for its pattern, on the stream of the stack, conditions
 * evaluated at match time: *)
(*$= runs & ~printer:identity
  "500ms: 10.0.0.2 53 [Eth {dst: 02:00:00:00:00:01, proto: 2048, src: 02:00:00:00:00:02, ts: 1970-01-01T00:00:00.5Z}, IP {dont_frag: false, dst: 10.0.0.1, frag_offset: 0, id: 1, is_fragment: false, more_frags: false, options: [], proto: 17, src: 10.0.0.2, tos: 0, tot_len: 32, ttl: 64}, UDP {checksum: 2272, dst: 1000, length: 12, src: 53}, Bytes {data: #706f6e67}]\n500ms: after\n500ms: done" \
    (runs ~inject:[ 0.2, reply ~sport:54 "pong" ; 0.3, reply "nope" ; 0.5, reply "pong" ; 0.6, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  expect Bytes(\"pong\") { print(\"${MATCH[IP].src} ${MATCH[UDP].src} ${MATCH}\") }\n  print(\"after\") }")
  "1s: failed: line 2, column 3: Nothing matched within 1s" \
    (runs "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  expect timeout=1s Bytes(\"pong\") { print(\"no\") } }")
  "2s400ms3ps: 2\n2s400ms3ps: done" \
    (runs ~inject:[ 0.5, reply "pong" ; 1.4, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  n = 0\n  catch { repeat count=3 { Bytes(\"ping\")\n      expect timeout=1s Bytes(\"pong\") { n += 1 } } }\n  print(\"${n}\") }")
  "500ms: failed: line 2, column 26: 5 bytes are no IP address" \
    (runs ~inject:[ 0.5, reply "pong!" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  expect Bytes(IP.dst == data) {} }")
*)
(* Frames for other addresses are seen only if promiscuous: *)
(*$= runs & ~printer:identity
  "500ms: 02:00:00:00:00:09\n500ms: done" \
    (runs ~promisc:true \
        ~inject:[ 0.5, incoming ~dst_mac:(Eth.Addr.of_string "02:00:00:00:00:09") \
                    (Ip.Pdu.pack (udp_packet 53 1000 "pong")) ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  expect timeout=1s Bytes(\"pong\") { print(\"${MATCH[Eth].dst}\") } }")
  "1s: failed: line 2, column 3: Nothing matched within 1s" \
    (runs \
        ~inject:[ 0.5, incoming ~dst_mac:(Eth.Addr.of_string "02:00:00:00:00:09") \
                    (Ip.Pdu.pack (udp_packet 53 1000 "pong")) ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  expect timeout=1s Bytes(\"pong\") { print(\"${MATCH[Eth].dst}\") } }")
*)
(* LAST is the last packet sent by any block: as packed down to the
 * self-driven layers, which only their stack tells: *)
(*$= runs & ~printer:identity
  "3ps: [Eth {dst: ?, proto: 2048, src: ?, ts: ?}, IP {dont_frag: false, dst: 10.0.0.2, frag_offset: ?, id: ?, is_fragment: ?, more_frags: ?, options: [], proto: 17, src: 10.0.0.1, tos: 0, tot_len: ?, ttl: 64}, UDP {checksum: ?, dst: 53, length: 10, src: 1000}, Bytes {data: #6869}]\n3ps: done" \
    (runs "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) { Bytes(\"hi\")\n  print(\"${LAST}\") }")
  "3ps: #61\n3ps: done" \
    (runs "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) { Bytes(\"a\") }\nprint(\"${LAST[Bytes].data}\")")
  "0s: failed: line 1, column 5: LAST is not set: no packet was sent yet" \
    (runs "x = LAST\nprint(\"not reached\")")
  "6ps: #62\n6ps: done" \
    (runs "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) { Bytes(\"a\")\n  { Bytes(\"b\") }\n  print(\"${LAST[Bytes].data}\") }")
  "6ps: 64 1\n6ps: done" \
    (runs "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) { Bytes(\"a\")\n  x = LAST[IP].ttl\n  ../../IP(ttl=1)/UDP/Bytes(\"b\")\n  print(\"${x} ${LAST[IP].ttl}\") }")
  "2ps: [Eth {dst: ?, proto: 2048, src: ?, ts: ?}, IP {dont_frag: false, dst: 10.0.0.2, frag_offset: 0, id: 7, is_fragment: false, more_frags: false, options: [], proto: 17, src: 10.0.0.1, tos: 0, tot_len: 30, ttl: 64}, UDP {checksum: 32593, dst: 53, length: 10, src: 1000}, Bytes {data: #6869}]\n2ps: done" \
    (runs "/IP!(dst=10.0.0.2, id=7)/UDP(src=1000, dst=53)/Bytes(\"hi\")\nprint(\"${LAST}\")")
  "9ps: #61 #6262 #62\n9ps: done" \
    (runs "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) { Bytes(\"a\")\n  x = LAST\n  y = x\n  { Bytes(\"bb\")\n    y := LAST }\n  Bytes(\"b\")\n  print(\"${x[Bytes].data} ${y[Bytes].data} ${LAST[Bytes].data}\") }")
  "400ms: b\n1s3ps: done" \
    (runs ~inject:[ 0.4, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) { Bytes(\"a\")\n  on for=1s Bytes(\"pong\") { print(LAST[Bytes].data) }\n  Bytes(\"b\") }")
  "2ps: 0\n4ps: 1\n4ps: done" \
    (runs "repeat count=2 { /IP!(dst=10.0.0.2, id=I)/UDP(src=1000, dst=53)/Bytes(\"x\")\n  print(\"${LAST[IP].id}\") }")
  "3ps: 4660\n3ps: done" \
    (runs "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53, checksum=0x1234) { Bytes(\"a\")\n  print(\"${LAST[UDP].checksum}\") }")
  "3ps: {ack_num: 0, checksum: ?, dst: 80, flags: 2, seq_num: 0, src: 1000, urg_ptr: 0, win_size: 65535}\n3ps: failed: line 3, column 5: TCP.checksum is not known: only a packet captured as it leaves has it (p = MESSAGE, through manual layers)" \
    (runs "/IP(dst=10.0.0.2)/TCP!(src=1000, dst=80, flags=SYN, seq_num=0)/Bytes()\nprint(\"${LAST[TCP]}\")\nx = LAST[TCP].checksum")
  "3ps: failed: line 2, column 7: UDP.checksum is not known: only a packet captured as it leaves has it (p = MESSAGE, through manual layers)" \
    (runs "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) { Bytes(\"a\")\n  x = LAST[UDP].checksum }")
  "3ps: failed: line 2, column 7: IP.id is not known: only a packet captured as it leaves has it (p = MESSAGE, through manual layers)" \
    (runs "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) { Bytes(\"a\")\n  x = LAST[IP].id }")
  "2ps: failed: line 3, column 10: Eth.ts is not known: only a packet captured as it leaves has it (p = MESSAGE, through manual layers)" \
    (runs "/IP!(dst=10.0.0.2)/UDP(src=1000, dst=53)/Bytes(\"a\")\nx = LAST\nprint(\"${x[Eth].ts}\")")
*)
(* first runs the block of the first pattern to match, and no other: *)
(*$= runs & ~printer:identity
  "500ms: b\n500ms: after\n500ms: done" \
    (runs ~inject:[ 0.3, reply "nope" ; 0.5, reply "b" ; 0.6, reply "a" ; 0.7, reply "b" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  first Bytes(\"a\") { print(\"a\") } | Bytes(\"b\") { print(MATCH[Bytes].data) }\n  print(\"after\") }")
  "1s: failed: line 2, column 3: Nothing matched within 1s" \
    (runs ~inject:[ 1.5, reply "a" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  first timeout=1s Bytes(\"a\") {} | Bytes(\"b\") {} }")
  "0s: failed: line 1, column 15: The timeout of first cannot be negative" \
    (runs "first timeout=-1s Bytes(\"x\") {} | Bytes(\"y\") {}")
  "500ms: b\n500ms: done" \
    (runs ~inject:[ 0.3, reply "nope" ; 0.5, reply "b" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  first Bytes(\"a\") | Bytes(\"b\") { print(MATCH[Bytes].data) } | Bytes(\"c\") { print(\"c\") } }")
*)
(* on runs the block of the pattern of each match, a packet matching once: *)
(*$= runs & ~printer:identity
  "300ms: a\n500ms: b\n1s3ps: done" \
    (runs ~inject:[ 0.3, reply "a" ; 0.5, reply "b" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) { Bytes(\"x\")\n  on for=1s Bytes(\"a\") { print(\"a\") } | Bytes { print(MATCH[Bytes].data) } }")
*)
(* A pattern can be alternatives, which match a packet at most once: *)
(*$= runs & ~printer:identity
  "300ms: pong\n300ms: done" \
    (runs ~inject:[ 0.3, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  expect Bytes(\"ping\")\n    | /IP/UDP(src == 53)/Bytes(\"pong\") { print(MATCH[Bytes].data) } }")
  "1s: 2\n1s: done" \
    (runs ~inject:[ 0.1, reply "pong" ; 0.2, reply "pang" ; 0.3, reply "x" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  n = 0\n  { on for=1s Bytes(\"pong\") | Bytes(\"pang\") | Bytes(\"pong\") { n += 1 } }\n  print(\"${n}\") }")
*)
(* A constructor makes a variant, which converts to a wider one, what it
 * holds converted along: *)
(*$= runs & ~printer:identity
  "0s: pending\n0s: got 2\n0s: Failed late\n0s: [Ok 1.0, Err a, Ok 2.5] true false A {b: [C]}\n0s: done" \
    (runs "assert(Pending() == Pending)\nr = Pending\nforeach [1, 2, 3] {\n  if I == 2 { r := Got(I) } elsif I == 3 { r := Failed(\"late\") }\n  print(case r Pending { \"pending\" } | Got { \"got ${r}\" } else { \"${r}\" }) }\nx = [Ok(1), Err(\"a\"), Ok(2.5)]\nprint(\"${x} ${x[0] == Ok(1.0)} ${x[1] == Ok(1)} ${A({b: [C]})}\")")
*)
(* case runs the arm of a value's constructor, in which the variable that
 * was cased is what that constructor holds: *)
(*$= runs & ~printer:identity
  "500ms: other\n500ms: ip 10.0.0.2\n500ms: udp 53\n500ms: other\n500ms: Bytes\n1s500ms: 64\n1s500ms: done" \
    (runs ~inject:[ 0.5, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  expect Bytes(\"pong\") {\n    foreach MATCH { print(case I IP { \"ip ${I.src}\" } | UDP { \"udp ${I.src}\" } | else { \"other\" }) }\n    case var=l MATCH[3] Bytes { print(\"Bytes\") }\n    case MATCH[3] IP { print(\"not reached\") }\n    ttl = case var=h MATCH[1] IP { wait 1s\n      h.ttl } | else { 0 }\n    print(\"${ttl}\") } }")
*)
(* on runs its block for every match, and its block waits for it: *)
(*$= runs & ~printer:identity
  "0s: armed\n1s: 3\n1s: done" \
    (runs ~inject:[ 0.1, reply "pong" ; 0.2, reply "pong" ; 0.3, reply "pong" ; 1.5, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  n = 0\n  { on for=1s Bytes(\"pong\") { n += 1 }\n    print(\"armed\") }\n  print(\"${n}\") }")
  "100ms: pong\n200ms: pong\n200ms: done" \
    (runs ~inject:[ 0.1, reply "pong" ; 0.2, reply "pong" ; 0.3, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on for=1s max=2 Bytes(\"pong\") { print(\"pong\") } }")
  "400ms: stop\n400ms: after\n400ms: done" \
    (runs ~inject:[ 0.4, reply "stop" ; 0.5, reply "stop" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on for=10s Bytes(\"stop\") { print(\"stop\")\n    break } }\nprint(\"after\")")
  "400ms: 0\n400ms: after\n400ms: done" \
    (runs ~inject:[ 0.4, reply "pong" ] \
        "repeat count=3 { /IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on for=1s Bytes(\"pong\") { print(\"${I}\")\n    break 2 } } }\nprint(\"after\")")
  "0s: done" \
    (runs ~inject:[ 0.4, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on max=0 Bytes(\"pong\") { print(\"no\") } }")
  "0s: failed: line 1, column 16: The timeout of expect cannot be negative" \
    (runs "expect timeout=-1s Bytes(\"x\") {}")
  "400ms: failed: line 2, column 33: Division by zero" \
    (runs ~inject:[ 0.4, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on for=1s Bytes(\"pong\") { x = 1 / 0 } }")
  "400ms: on\n400ms: expect\n400ms: done" \
    (runs ~inject:[ 0.4, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on Bytes(\"pong\") { print(\"on\") }\n  expect Bytes(\"pong\") { print(\"expect\") } }")
*)
(* Without a duration, an on ends with the statements of its block, or
 * lingers after them; the block waits for those that do, and for those with
 * a duration: *)
(*$= runs & ~printer:identity
  "250ms: 2\n250ms: done" \
    (runs ~inject:[ 0.1, reply "pong" ; 0.2, reply "pong" ; 0.3, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  n = 0\n  { on Bytes(\"pong\") { n += 1 }\n    wait 250ms }\n  print(\"${n}\") }")
  "450ms: 3\n450ms: done" \
    (runs ~inject:[ 0.1, reply "pong" ; 0.2, reply "pong" ; 0.3, reply "pong" ; 0.5, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  n = 0\n  { on linger=200ms Bytes(\"pong\") { n += 1 }\n    wait 250ms }\n  print(\"${n}\") }")
  "300ms: a\n1s: done" \
    (runs ~inject:[ 0.3, reply "a" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on Bytes(\"a\") { print(\"a\") }\n  on for=1s Bytes(\"b\") {} }")
  "0s: failed: line 2, column 13: The linger of on cannot be negative" \
    (runs "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on linger=-1s Bytes(\"a\") {} }")
*)
(* An on with a timeout fails once that long passes without a match: *)
(*$= runs & ~printer:identity
  "600ms1ps: failed: line 2, column 3: Nothing matched within 300ms" \
    (runs ~inject:[ 0.1, reply "pong" ; 0.3, reply "pong" ; 0.7, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on for=1s timeout=300ms Bytes(\"pong\") {} }")
  "1s: done" \
    (runs ~inject:[ 0.2, reply "pong" ; 0.4, reply "pong" ; 0.6, reply "pong" ; 0.8, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on for=1s timeout=300ms Bytes(\"pong\") {} }")
  "300ms: done" \
    (runs ~inject:[ 0.1, reply "pong" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on for=1s max=1 timeout=200ms Bytes(\"pong\") {}\n  wait 300ms }")
*)
(* Patterns from the root, or on top of the stack, make nodes for the
 * layers they matched, which their block holds; those over the layers of
 * the stack see only their streams: *)
(*$= runs & ~printer:identity
  "500ms: got Eth#2{IP(src=10.0.0.1, dst=10.0.0.2)*1#2{UDP(src=7, dst=53)*1#1}}\n500ms: after Eth#2{IP(src=10.0.0.1, dst=10.0.0.2)*1#2{UDP(src=7, dst=53)*1#1}}\n500ms: out Eth#2\n500ms: done Eth#2" \
    (runs ~trees:true ~inject:[ 0.2, reply ~dport:8 "a" ; 0.5, reply ~dport:7 "b" ] \
        "{ expect /IP(src == 10.0.0.2)/UDP(dst == 7) { print(\"got\") }\n  print(\"after\") }\nprint(\"out\")")
  "500ms: 54 Eth#2{IP(src=10.0.0.1, dst=10.0.0.2)*2#2{UDP(src=1000, dst=54)*1#1}}\n1s: done Eth#2" \
    (runs ~trees:true ~inject:[ 0.2, reply "a" ; 0.5, reply ~sport:54 "b" ] \
        "x = 53\n/IP(dst=10.0.0.2) {\n  on for=1s UDP(src == x, IP.src == 10.0.0.2) { print(\"${MATCH[UDP].src}\") }\n  x := 54 }")
  "500ms: a\n1s: done" \
    (runs ~inject:[ 0.2, reply ~sport:54 "b" ; 0.5, reply "a" ] \
        "/IP(dst=10.0.0.2)/UDP(src=1000, dst=53) {\n  on for=1s ../UDP { print(MATCH[Bytes].data) } }")
  "500ms: fragment 0\n500ms1ps: fragment 2\n500ms1ps: id 2\n500ms1ps: in two fragments\n1s1ps: done" \
    (runs ~inject:(List.map (fun f -> 0.5, incoming f) (Ip.Pdu.fragment 36 (udp_packet ~id:2 53 1000 "in two fragments"))) \
        "/IP(dst=10.0.0.2) {\n  on for=1s ../IP!(is_fragment) { print(\"fragment ${MATCH[IP].frag_offset}\") }\n  on for=1s ../IP/UDP { print(\"id ${MATCH[IP].id}\") ; print(MATCH[Bytes].data) } }")
*)
(* ICMP, with the code of an error: *)
(*$= runs & ~printer:identity
  "500ms: 7 {payload: [], seq: 1}\n600ms: unreachable\n600ms: done" \
    (runs ~inject:[ 0.4, incoming (Ip.Pdu.pack (ip_packet Ip.Proto.icmp (Icmp.Pdu.(pack (make_echo_reply 8 1))))) ; \
                    0.5, incoming (Ip.Pdu.pack (ip_packet Ip.Proto.icmp (Icmp.Pdu.(pack (make_echo_reply 7 1))))) ; \
                    0.6, incoming (Ip.Pdu.pack (ip_packet Ip.Proto.icmp (Icmp.Pdu.(pack { msg_type = Icmp.MsgType.o (3, 3) ; \
                              payload = DestUnreachable (0, Payload.o (Bitstring.bitstring_of_string "A")) })))) ] \
        "/IP(dst=10.0.0.2)/ICMP {\n  Echo(id=7) { Request(\"hi\")\n    expect Reply { assert(MATCH[Echo].id == 7)\n      print(\"${MATCH[Echo].id} ${MATCH[Reply]}\") } }\n  expect DestUnreachable(code == PORT_UNREACHABLE) { print(\"unreachable\") } }")
*)

(* [two ?loss ?arp ?frames a b] is what programs [a] (at 10.0.0.1)
 * and [b] (at 10.0.0.2, started first) print, each line with the name of
 * the program and the time to the millisecond, then how they end and their
 * trees then, when they are at both ends of a cable (that knows each
 * other's MAC address already with [arp]), each interface dropping that
 * ratio [loss] of the packets it sends; with [frames], the frames [a]
 * sends ("a>") and receives ("a<") too, from their IP layer.
 * [without_counts] removes the numbers of packets received from the trees.
 * [with_host] is the same with a simulated host at 10.0.0.2, set up by
 * [setup], which is given a function for the host to print lines. *)
(*$inject
  let compile text =
      match Crafty_parser.parse text with
      | Error e -> failwith (IO.to_string Crafty_parser.print_error e)
      | Ok p ->
          match Crafty_typing.check p with
          | Error es -> failwith (String.concat "\n" (List.map (IO.to_string Crafty_parser.print_error) es))
          | Ok p -> p

  let address n = Ip.Addr.of_string (Printf.sprintf "10.0.0.%d" n)
  let mac n = Eth.Addr.of_string (Printf.sprintf "02:00:00:00:00:%02x" n)
  let netmask = Ip.Addr.of_string "255.255.255.0"

  let crafty_peer sim n =
      Eth.State.make ~parent:sim.SimTypes.root ~name:(Printf.sprintf "crafty%d" n) ~mac:(mac n)
          ~my_addresses:[ Eth.State.make_my_ip_address ~netmask (address n) ] ()

  let knows (eth : Eth.State.t) n =
      Tools.BitHash.replace eth.arp_cache (Ip.Addr.to_bitstring (address n)) (Some (mac n))

  let start ?(closed=false) sim out name eth text =
      let line s =
          out := Printf.sprintf "%s %.3fs: %s" name (Clock.Time.to_secs (Simulation.now sim)) s :: !out in
      let tree =
          Crafty_tree.make_root eth ~on_removed:(fun n ->
              if closed then line ("closed "^ Crafty_tree.stats_line n)) in
      ignore (run_on_tree sim.SimTypes.root.power tree ~print:line ~print_err:(fun s -> line ("err "^ s))
          ~on_exit:(function
              | Done -> line ("done "^ Crafty_tree.to_string tree)
              | Failed e -> line ("failed: "^ IO.to_string Crafty_parser.print_error e ^" "^ Crafty_tree.to_string tree)
              | Stopped -> line "stopped"
              | Running -> ()) (compile text))

  let frame_line sim out dir bits =
      let d = describe bits in
      let d =
          match String.split d ~by:" IP " with
          | _, ip -> ip
          | exception Not_found -> if String.ends_with d " ARP" then "ARP" else d in
      out := Printf.sprintf "a%s %.3fs: %s" dir (Clock.Time.to_secs (Simulation.now sim)) d :: !out

  let plug sim ?log (a : SimTypes.widget) (b : SimTypes.widget) =
      List.iter (fun (w : SimTypes.widget) ->
          w.ports.set_capabilities 0
              (Capabilities.Eth { speeds = [ EthSpeed.Eth100Mbps ] ; full_duplex = true })
      ) [ a ; b ] ;
      let cable = Eth.Cable.State.make ~parent:sim.SimTypes.root () in
      let trx = Eth.Cable.make cable in
      let trx =
          match log with
          | None -> trx
          | Some log ->
              Tools.{ trx with ins = {
                  trx.ins with
                  write = (fun bits -> log ">" bits ; trx.ins.write bits) ;
                  set_read = (fun f busy -> trx.ins.set_read (fun bits -> log "<" bits ; f bits) busy) } } in
      ignore Tools.(a.ports.dev 0 -=> trx) ;
      Tools.(trx <=- b.ports.dev 0)

  let without_counts s =
      let b = Stdlib.Buffer.create (String.length s) and skip = ref false in
      String.iter (fun c ->
          if c = '#' then (skip := true ; Stdlib.Buffer.add_char b c)
          else if not (!skip && c >= '0' && c <= '9') then (
              skip := false ; Stdlib.Buffer.add_char b c)) s ;
      Stdlib.Buffer.contents b

  let two ?(loss=0.) ?(arp=false) ?(frames=false) ?closed a b =
      let sim = Simulation.make ~realtime:false "crafty-pair" in
      let out = ref [] in
      let ea = crafty_peer sim 1 and eb = crafty_peer sim 2 in
      ea.loss <- loss ; eb.loss <- loss ;
      if arp then (knows ea 2 ; knows eb 1) ;
      let log = if frames then Some (frame_line sim out) else None in
      plug sim ?log ea.Eth.State.iface.widget eb.Eth.State.iface.widget ;
      start ?closed sim out "b" eb b ;
      start ?closed sim out "a" ea a ;
      Simulation.run sim false ;
      String.concat "\n" (List.rev !out)

  let with_host ?(setup=fun _ _ -> ()) ?(frames=false) ?closed text =
      let sim = Simulation.make ~realtime:false "crafty-host" in
      let out = ref [] in
      let ea = crafty_peer sim 1 in
      let h = Host.make ~parent:sim.SimTypes.root ~static_ip:(address 2) ~netmask "host" in
      let log = if frames then Some (frame_line sim out) else None in
      plug sim ?log ea.Eth.State.iface.widget h.Host.trx.Host.widget ;
      Simulation.run_startup sim ;
      setup h (fun s ->
          out := Printf.sprintf "host %.3fs: %s" (Clock.Time.to_secs (Simulation.now sim)) s :: !out) ;
      start ?closed sim out "a" ea text ;
      Simulation.run sim false ;
      String.concat "\n" (List.rev !out)
*)
(* Two programs: a UDP ping retried until the other end listens (after
 * 1.5s); a response counter; a TCP checksum given, then computed; MATCH
 * ending with what was not decoded, if anything, in a Bytes; the
 * counter with losses; losses sparing ARP; ICMP echo requests answered by a
 * program: *)
(*$= & ~printer:identity
  "b 1.500s: listening\nb 2.000s: ping from 10.0.0.1:1000\na 2.000s: pong from 10.0.0.2\na 2.000s: done Eth#2\nb 2.000s: done Eth#4" \
    (two "/IP(dst=10.0.0.2)/UDP(src=1000, dst=7) {\n  retry { Bytes(\"ping\")\n    expect timeout=1s Bytes(\"pong\") { print(\"pong from ${MATCH[IP].src}\") } } }" \
         "wait 1500ms\nprint(\"listening\")\nexpect /IP/UDP(dst == 7)/Bytes(\"ping\") {\n  print(\"ping from ${MATCH[IP].src}:${MATCH[UDP].src}\")\n  /IP(dst=MATCH[IP].src)/UDP(src=7, dst=MATCH[UDP].src)/Bytes(\"pong\") }")
  "a 1.000s: 100 pongs\na 1.000s: done Eth#101\nb 2.000s: done Eth#101" \
    (two "/IP(dst=10.0.0.2)/UDP(src=1000, dst=7) {\n  n = 0\n  { on for=1s Bytes(\"pong\") { n += 1 }\n    repeat count=100 every=1ms { Bytes(\"ping\") } }\n  print(\"${n} pongs\") }" \
         "on for=2s /IP/UDP(dst == 7)/Bytes(\"ping\") {\n  /IP(dst=MATCH[IP].src)/UDP(src=7, dst=MATCH[UDP].src)/Bytes(\"pong\") }")
  "a> 0.010s: ARP\na< 0.010s: ARP\na 0.010s: done Eth\na> 0.010s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Syn \"\" bad-checksum\nb 0.010s: 4660\na> 0.010s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Syn \"\"\nb 0.010s: 35896\nb 1.000s: done Eth#3" \
    (two ~frames:true "wait 10ms\n/IP(dst=10.0.0.2)/TCP!(src=4000, dst=7, flags=SYN, seq_num=1, checksum=0x1234)/Bytes()\n/IP(dst=10.0.0.2)/TCP!(src=4000, dst=7, flags=SYN, seq_num=1)/Bytes()" \
         "on for=1s /IP/TCP!(dst == 7) { print(\"${MATCH[TCP].checksum}\") }")
  "a 0.010s: done Eth\nb 0.010s: 4 []\nb 0.010s: 4 #00000000\nb 1.000s: done Eth#3" \
    (two "wait 10ms\n/IP(dst=10.0.0.2)/TCP!(src=4000, dst=7, flags=SYN, seq_num=1)/Bytes()\n/IP!(dst=10.0.0.2, proto=1)/Bytes(#0d00f2ff00000000)" \
         "{ on for=1s /IP/TCP! { print(\"${length(MATCH)} ${MATCH[Bytes].data}\") }\n  on for=1s /IP/ICMP { print(\"${length(MATCH)} ${MATCH[Bytes].data}\") } }")
  "a 1.000s: some lost\na 1.000s: done Eth#\nb 2.000s: done Eth#" \
    (without_counts @@ two ~arp:true ~loss:0.2 "/IP(dst=10.0.0.2)/UDP(src=1000, dst=7) {\n  n = 0\n  { on for=1s Bytes(\"pong\") { n += 1 }\n    repeat count=100 every=1ms { Bytes(\"ping\") } }\n  assert(n > 30 && n < 100, msg=\"${n} pongs\")\n  print(\"some lost\") }" \
         "on for=2s /IP/UDP(dst == 7)/Bytes(\"ping\") {\n  /IP(dst=MATCH[IP].src)/UDP(src=7, dst=MATCH[UDP].src)/Bytes(\"pong\") }")
  "a> 0.000s: ARP\na< 0.000s: ARP\na 0.000s: done Eth\nb 1.000s: done Eth#1" \
    (two ~frames:true ~loss:1. "/IP(dst=10.0.0.2)/UDP(src=1000, dst=7)/Bytes(\"x\")" \
         "on for=1s /IP/UDP { print(\"got\") }")
  "a 0.000s: seq 1\na 0.100s: seq 2\na 0.200s: seq 3\na 0.200s: done Eth#4\nb 1.000s: done Eth#4" \
    (two "/IP(dst=10.0.0.2)/ICMP/Echo { repeat count=3 every=100ms { Request(\"hi\")\n    expect timeout=1s Reply { assert(MATCH[Reply].payload == \"hi\")\n      print(\"seq ${MATCH[Reply].seq}\") } } }" \
         "on for=1s /IP/ICMP/Echo/Request {\n  /IP(dst=MATCH[IP].src)/ICMP/Echo(id=MATCH[Echo].id)/Reply(seq=MATCH[Request].seq, payload=MATCH[Request].payload) }")
*)
(* A program and a host: ping, a UDP echo server, a closed port: *)
(*$= & ~printer:identity
  "a 0.000s: seq 1\na 0.100s: seq 2\na 0.200s: seq 3\na 0.200s: done Eth#4" \
    (with_host "/IP(dst=10.0.0.2)/ICMP/Echo { repeat count=3 every=100ms { Request(\"hi\")\n    expect timeout=1s Reply { assert(MATCH[Reply].payload == \"hi\")\n      print(\"seq ${MATCH[Reply].seq}\") } } }")
  "a 0.000s: echo 0\na 0.000s: echo 1\na 0.000s: done Eth#3" \
    (with_host ~setup:(fun h _ -> h.Host.trx.Host.udp_server_start (Udp.Port.o 7) (fun udp -> \
        Tools.(udp.Udp.TRX.trx.ins --> sink (fun bits -> tx udp.Udp.TRX.trx bits)))) \
        "/IP(dst=10.0.0.2)/UDP(dst=7) { repeat count=2 { Bytes(\"echo ${I}\")\n    expect timeout=1s Bytes { print(MATCH[Bytes].data) } } }")
  "a 0.000s: unreachable\na 0.000s: done Eth#2" \
    (with_host "/IP(dst=10.0.0.2)/UDP(dst=9) { Bytes(\"anyone?\")\n  first timeout=1s Bytes { print(\"answer\") } | ../ICMP/DestUnreachable(code == PORT_UNREACHABLE) { print(\"unreachable\") } }")
  "a 0.000s: unreachable\na 0.000s: done Eth#2" \
    (with_host "/IP(dst=10.0.0.2)/UDP(dst=9) { Bytes(\"anyone?\")\n  expect timeout=1s ../ICMP/DestUnreachable(code == PORT_UNREACHABLE) { print(\"unreachable\") } }")
*)
(* A key told by the layer on top: DNS tells UDP its port, at the first
 * message of the stream; told nothing, UDP fails, as it does if told the
 * key of another stream; given, the port wins: *)
(*$= & ~printer:identity
  "a 0.000s: popo. has 1 address\na 0.000s: done Eth#2" \
    (with_host ~setup:(fun h _ -> \
        Named.serve (Named.State.make ~parent:h.Host.trx.Host.widget (function \
            | "popo" -> Some (address 2) | _ -> None)) h.Host.trx) \
        "/IP(dst=10.0.0.2)/UDP {\n  DNS {\n    Query(\"popo\")\n    expect timeout=1s Answer { print(\"${MATCH[Answer].name}. has ${length(MATCH[Answer].answers)} address\") } } }")
  "a 0.000s: failed: line 1, column 25: UDP needs a dst Eth" \
    (with_host "/IP(dst=10.0.0.2)/UDP { Bytes(\"x\") }")
  "a 0.000s: failed: line 2, column 3: There is already a UDP with src=4000, dst=53 Eth" \
    (with_host "/IP(dst=10.0.0.2)/UDP(src=4000, dst=53) {\n  /IP(dst=10.0.0.2)/UDP(src=4000)/DNS/Query(\"x\") }")
  "b 0.000s: port 5353\nb 0.000s: done Eth#1\na 0.000s: done Eth" \
    (two ~arp:true "/IP(dst=10.0.0.2)/UDP(dst=5353)/DNS/Query(\"popo\")" \
         "expect timeout=1s /IP/UDP/DNS/Query { print(\"port ${MATCH[UDP].dst}\") }")
*)
(* ICMP errors and the packets they quote: a host's, and forged by a
 * program, one quoting a whole datagram, one only the first 8 bytes of a
 * segment: *)
(*$= & ~printer:identity
  "a 0.000s: port 9 of 10.0.0.2, from 10.0.0.2, length 15\na 0.000s: done Eth#2" \
    (with_host "/IP(dst=10.0.0.2)/UDP(src=4000, dst=9)/Bytes(\"anyone?\")\nexpect timeout=1s /IP/ICMP/DestUnreachable(code == PORT_UNREACHABLE)/IP/UDP(src == 4000) {\n  print(\"port ${MATCH[UDP].dst} of ${MATCH[IP].dst}, from ${MATCH[^IP].src}, length ${MATCH[UDP].length}\") }")
  "a 0.000s: udp to 33434, ttl 1, from 10.0.0.2\na 0.000s: tcp seq 7, win 0\nb 0.000s: done Eth#1\na 1.000s: done Eth#2" \
    (two ~arp:true "{ on for=1s /IP/ICMP/TimeExceeded/IP/UDP(src == 4000) {\n    print(\"udp to ${MATCH[UDP].dst}, ttl ${MATCH[IP].ttl}, from ${MATCH[^IP].src}\") }\n  on for=1s /IP/ICMP/TimeExceeded/IP/TCP(src == 4000) {\n    print(\"tcp seq ${MATCH[TCP].seq_num}, win ${MATCH[TCP].win_size}\") }\n  /IP(dst=10.0.0.2)/UDP(src=4000, dst=33434)/Bytes(\"probe\") }" \
         "expect timeout=1s /IP/UDP(dst == 33434)/Bytes {\n  /IP(dst=MATCH[IP].src)/ICMP/TimeExceeded/IP(src=MATCH[IP].src, dst=MATCH[IP].dst, ttl=1)/UDP(src=MATCH[UDP].src, dst=MATCH[UDP].dst)/Bytes(MATCH[Bytes].data)\n  /IP(dst=MATCH[IP].src)/ICMP/TimeExceeded/IP(src=MATCH[IP].src, dst=MATCH[IP].dst, proto=6, tot_len=60)/Bytes(#0fa0005000000007) }")
*)
(* DNS: a name resolved by a host's server then pinged; and between two
 * programs, the server's query also seen as bytes: *)
(*$= & ~printer:identity
  "a 0.000s: popo. has 1 address\na 0.000s: pong\na 0.000s: done Eth#3" \
    (with_host ~setup:(fun h _ -> \
        Named.serve (Named.State.make ~parent:h.Host.trx.Host.widget (function \
            | "popo" -> Some (address 2) | _ -> None)) h.Host.trx) \
        "/IP(dst=10.0.0.2)/UDP(dst=53)/DNS {\n  Query(\"popo\")\n  expect timeout=1s Answer(status == NOERROR) {\n    print(\"${MATCH[Answer].name}. has ${length(MATCH[Answer].answers)} address\")\n    /IP(dst=MATCH[Answer].answers[0].data)/ICMP/Echo {\n      Request(\"hi\")\n      expect timeout=1s Reply { print(\"pong\") } } } }")
  "b 0.000s: 29 bytes\nb 0.000s: query for example.com\na 0.000s: example.com is #0a000002\na 0.000s: done Eth#1\nb 1.000s: done Eth#1" \
    (two ~arp:true "/IP(dst=10.0.0.2)/UDP(dst=5353)/DNS {\n  Query(\"example.com\")\n  expect timeout=1s Answer(\"example.com\") {\n    print(\"${MATCH[Answer].name} is ${MATCH[Answer].answers[0].data}\") } }" \
         "{ on for=1s /IP/UDP(dst == 5353)/Bytes { print(\"${length(MATCH[Bytes].data)} bytes\") }\n  on for=1s /IP/UDP(dst == 5353)/DNS/Query(type == TYPE_A) {\n    print(\"query for ${MATCH[Query].name}\")\n    /IP(dst=MATCH[IP].src)/UDP(src=5353, dst=MATCH[UDP].src)/DNS(id=MATCH[DNS].id)/Answer(MATCH[Query].name, answers=[{name: MATCH[Query].name, type: TYPE_A, class: CLASS_IN, ttl: 60, data: #0a000002}]) } }")
*)
(* TCP, against a host's echo server that closes when its client does,
 * and as a server to a host's client, with the handshakes and the closes
 * (the nodes going away once the close is complete): *)
(*$inject
  let tcp_echo h _ =
      h.Host.trx.Host.tcp_server_start (Tcp.Port.o 7) (fun cnx ->
          Tools.(cnx.Tcp.TRX.trx.ins --> sink (fun bits ->
              if Bitstring.bitstring_length bits = 0 then cnx.close ()
              else tx cnx.trx bits)))

  let tcp_client h log =
      h.Host.trx.Host.tcp_connect (Host.IPv4 (address 1)) ~src_port:(Tcp.Port.o 5000) (Tcp.Port.o 80) (function
          | None -> log "cannot connect"
          | Some cnx ->
              Tools.(cnx.Tcp.TRX.trx.ins --> sink (fun bits ->
                  if Bitstring.bitstring_length bits = 0 then (log "closed" ; cnx.close ())
                  else log ("got "^ Bitstring.string_of_bitstring bits))) ;
              Tools.tx cnx.trx (Bitstring.bitstring_of_string "hello"))
*)
(*$= & ~printer:identity
  "a> 0.000s: ARP\na< 0.000s: ARP\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Syn opts=[mss 1460,nop,wscale 7] \"\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 7>4000 AckSyn opts=[mss 1460,nop,wscale 7] \"\"\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Ack \"\"\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 AckPsh \"hello\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 7>4000 AckPsh \"hello\"\na 0.000s: hello\na 0.000s: done Eth#3{IP(src=10.0.0.1, dst=10.0.0.2)#2{TCP(src=4000, dst=7)#2{Bytes#2}}}\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 AckFin \"\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 7>4000 AckFin \"\"\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Ack \"\"" \
    (with_host ~setup:tcp_echo ~frames:true \
        "/IP(dst=10.0.0.2)/TCP(src=4000, dst=7) {\n  Bytes(\"hello\")\n  expect timeout=1s Bytes { print(MATCH[Bytes].data) } }")
  "a< 0.000s: ARP\na> 0.000s: ARP\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 5000>80 Syn opts=[mss 1460,nop,wscale 7] \"\"\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 80>5000 AckSyn opts=[mss 1460,nop,wscale 7] \"\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 5000>80 Ack \"\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 5000>80 AckPsh \"hello\"\na 0.000s: hello\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 80>5000 AckPsh \"world\"\nhost 0.000s: got world\na< 0.040s: 10.0.0.2>10.0.0.1 ttl=64 TCP 5000>80 Ack \"\"\na 1.000s: done Eth#5{IP(src=10.0.0.1, dst=10.0.0.2)#4{TCP(src=80, dst=5000)#4{Bytes}}}\na> 1.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 80>5000 AckFin \"\"\nhost 1.000s: closed\na< 1.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 5000>80 AckFin \"\"\na> 1.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 80>5000 Ack \"\"" \
    (with_host ~setup:tcp_client ~frames:true \
        "on for=1s /IP/TCP(dst == 80)/Bytes {\n  print(MATCH[Bytes].data)\n  /IP(dst=MATCH[IP].src)/TCP(src=80, dst=MATCH[TCP].src)/Bytes(\"world\") }")
  "a 0.000s: pong\na 0.000s: pong\na 0.000s: pong\na 0.000s: done Eth#5{IP(src=10.0.0.1, dst=10.0.0.2)#4{TCP(src=5000, dst=80)#4{Bytes#6}}}\nb 1.000s: done Eth#8{IP(src=10.0.0.2, dst=10.0.0.1)#7{TCP(src=80, dst=5000)#7{Bytes#4}}}" \
    (two "/IP(dst=10.0.0.2)/TCP(src=5000, dst=80) {\n  repeat count=3 { Bytes(\"ping ${I}\")\n    expect timeout=1s Bytes { print(MATCH[Bytes].data) } } }" \
         "on for=1s /IP/TCP(dst == 80)/Bytes {\n  /IP(dst=MATCH[IP].src)/TCP(src=80, dst=MATCH[TCP].src)/Bytes(\"pong\") }")
*)
(* The stats of a TCP stream, as data is echoed, then of each stream as it
 * goes away; of a UDP one; with losses: *)
(*$= & ~printer:identity
  "a 0.000s: out 3 5, in 2 5, acked 5, received 5, retrans 0, mss 1460, established true\na 0.000s: done Eth#3{IP(src=10.0.0.1, dst=10.0.0.2)#2{TCP(src=4000, dst=7)#2{Bytes#2}}}" \
    (with_host ~setup:tcp_echo \
        "/IP(dst=10.0.0.2)/TCP(src=4000, dst=7) {\n  Bytes(\"hello\")\n  expect timeout=1s Bytes {\n    s = stats()\n    print(\"out ${s.packets_out} ${s.bytes_out}, in ${s.packets_in} ${s.bytes_in}, acked ${s.bytes_acked}, received ${s.bytes_received}, retrans ${s.retrans}, mss ${s.snd_mss}, established ${s.established}\") } }")
  "a 0.000s: 2 echoes, out 2 12, in 2 12\na 0.000s: done Eth#3" \
    (with_host ~setup:(fun h _ -> h.Host.trx.Host.udp_server_start (Udp.Port.o 7) (fun udp -> \
        Tools.(udp.Udp.TRX.trx.ins --> sink (fun bits -> tx udp.Udp.TRX.trx bits)))) \
        "/IP(dst=10.0.0.2)/UDP(src=4000, dst=7) { repeat count=2 { Bytes(\"echo ${I}\")\n    expect timeout=1s Bytes {} }\n  s = stats()\n  print(\"2 echoes, out ${s.packets_out} ${s.bytes_out}, in ${s.packets_in} ${s.bytes_in}\") }")
  "a 0.001s: fragmented 1, frags out 3, in 3, reassembled 1, timeouts 0\na 0.001s: done Eth#4" \
    (with_host ~setup:(fun h _ -> h.Host.trx.Host.udp_server_start (Udp.Port.o 7) (fun udp -> \
        Tools.(udp.Udp.TRX.trx.ins --> sink (fun bits -> tx udp.Udp.TRX.trx bits)))) \
        "/IP(dst=10.0.0.2) {\n  UDP(src=4000, dst=7) {\n    Bytes(randbytes(3000))\n    expect timeout=1s Bytes {} }\n  s = stats()\n  print(\"fragmented ${s.fragmented}, frags out ${s.frags_out}, in ${s.frags_in}, reassembled ${s.reassembled}, timeouts ${s.reasm_timeouts}\") }")
*)
(*$T
  let out = with_host ~setup:tcp_echo ~closed:true \
      "/IP(dst=10.0.0.2)/TCP(src=4000, dst=7) {\n  Bytes(\"hello\")\n  expect timeout=1s Bytes {} }" in \
  List.exists (fun l -> String.starts_with l "a 0.000s: closed /IP(src=10.0.0.1, dst=10.0.0.2)/TCP(src=4000, dst=7): packets_out=5 bytes_out=5 packets_in=3 bytes_in=5 bytes_acked=5 bytes_received=5 retrans=0 dupacks=0 timeouts=0 ooo_in=0 dup_in=0 ") (String.split_on_char '\n' out) && \
  List.mem "a 0.000s: closed /IP(src=10.0.0.1, dst=10.0.0.2): packets_out=5 bytes_out=113 packets_in=3 bytes_in=73 fragmented=0 frags_out=0 frags_in=0 reassembled=0 reasm_timeouts=0" (String.split_on_char '\n' out) || (print_endline out ; false)
*)
(*$T
  let out = two ~arp:true ~loss:0.1 \
      "/IP(dst=10.0.0.2)/TCP(src=5000, dst=80) {\n  repeat count=30 { Bytes(\"ping ${I}\")\n    expect timeout=1m Bytes {} }\n  s = stats()\n  print(\"retrans ${s.retrans > 0} ${s.retrans <= s.packets_out}, rtt ${s.srtt > 0s} ${s.rtt_samples > 0}\") }" \
      "on for=2m /IP/TCP(dst == 80)/Bytes {\n  /IP(dst=MATCH[IP].src)/TCP(src=80, dst=MATCH[TCP].src)/Bytes(\"pong\") }" in \
  String.exists out "retrans true true, rtt true true" || (print_endline out ; false)
*)
(* Writing more than the send buffer takes until the rest fits in it: *)
(*$inject
  let tcp_discard h _ =
      h.Host.trx.Host.tcp_server_start (Tcp.Port.o 9) (fun cnx ->
          Tools.(cnx.Tcp.TRX.trx.ins --> sink (fun bits ->
              if Bitstring.bitstring_length bits = 0 then cnx.close ())))
*)
(*$T
  not (String.starts_with \
    (with_host ~setup:tcp_discard \
        "/IP(dst=10.0.0.2)/TCP(src=4000, dst=9) {\n  Bytes(randbytes(100000))\n  print(\"written\") }") \
    "a 0.000s: written")
*)
(* Manual segments, inserted into a connection or not (a handshake made
 * by hand), and resets: *)
(*$= & ~printer:identity
  "a> 0.000s: ARP\na< 0.000s: ARP\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4001>22 Syn opts=[mss 1460,nop,wscale 7] \"\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 22>4001 AckRst \"\"\na 0.000s: reset\na 0.000s: done Eth#2{IP(src=10.0.0.1, dst=10.0.0.2)#1{TCP(src=4001, dst=22)#1{Bytes}}}" \
    (with_host ~frames:true \
        "/IP(dst=10.0.0.2)/TCP(src=4001, dst=22) {\n  Bytes(#1ee7)\n  expect timeout=1s ../TCP!(flags & RST) { print(\"reset\") } }")
  "a> 0.000s: ARP\na< 0.000s: ARP\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Syn \"\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 7>4000 AckSyn opts=[mss 1460] \"\"\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Ack \"\"\na 0.000s: connected!\na 0.000s: done Eth#2" \
    (with_host ~setup:tcp_echo ~frames:true \
        "/IP(dst=10.0.0.2)/TCP(src=4000, dst=7) {\n  ../TCP!(flags=SYN, seq_num=123)/Bytes()\n  expect timeout=1s ../TCP!(flags == SYN | ACK) {\n    ../TCP!(flags=ACK, seq_num=124, ack_num=MATCH[TCP].seq_num + 1)/Bytes()\n    print(\"connected!\") } }")
  "a> 0.000s: ARP\na< 0.000s: ARP\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Syn opts=[mss 1460,nop,wscale 7] \"\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 7>4000 AckSyn opts=[mss 1460,nop,wscale 7] \"\"\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Ack \"\"\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 AckPsh \"hello\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 7>4000 AckPsh \"hello\"\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 AckPsh \" world\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 7>4000 AckPsh \" world\"\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Rst \"\"\na 0.000s: failed: line 7, column 3: This TCP connection is closed Eth#4{IP(src=10.0.0.1, dst=10.0.0.2)#3{TCP(src=4000, dst=7)#3{Bytes#4}}}" \
    (with_host ~setup:tcp_echo ~frames:true \
        "/IP(dst=10.0.0.2)/TCP(src=4000, dst=7) {\n  Bytes(\"hello\")\n  expect timeout=1s Bytes(\"hello\") {}\n  ../TCP!/Bytes(\" world\")\n  expect timeout=1s Bytes(\" world\") {}\n  ../TCP!(flags=RST)/Bytes()\n  Bytes(\"too late\") }")
  "a> 0.000s: ARP\na< 0.000s: ARP\na> 0.000s: 10.0.0.1>10.0.0.2 ttl=64 TCP 4000>7 Syn \"\"\na< 0.000s: 10.0.0.2>10.0.0.1 ttl=64 TCP 7>4000 AckRst \"\"\na 0.000s: 101\na 0.000s: done Eth#2" \
    (with_host ~frames:true \
        "/IP(dst=10.0.0.2)/TCP!(src=4000, dst=7, flags=SYN, seq_num=100)/Bytes()\nexpect timeout=1s /IP/TCP!(src == 7, flags & RST) { print(\"${MATCH[TCP].ack_num}\") }")
*)
(* [policed ?limits ?stop_at ?stop text] is what the program in that text prints,
 * each line with the time to the millisecond, how it ends, then how many
 * frames went through a policer with these limits, which stops the program
 * when one is hit; or why it does not compile. It is at 10.0.0.1/24, behind
 * the gateway 02:00:00:00:00:fe. It is stopped at [stop_at] seconds, or with
 * [stop] as soon as it is run. *)
(*$inject
  let policed ?max_packets ?max_packet_rate ?max_syns ?max_syn_rate ?stop_at ?(stop=false) text =
      match Crafty_interp.compile text with
      | Error es -> String.concat "\n" (List.map (IO.to_string print_error) es)
      | Ok p ->
          let sim = Simulation.make ~realtime:false "crafty-api" in
          let out = ref [] and frames = ref 0 in
          let line s =
              out := Printf.sprintf "%.3fs: %s" (Clock.Time.to_secs (Simulation.now sim)) s :: !out in
          let dev, h =
              run ~parent:sim.SimTypes.root ~mac:(Eth.Addr.of_string "02:00:00:00:00:01")
                  ~ip:(Ip.Addr.of_string "10.0.0.1") ~netmask:(Ip.Addr.of_string "255.255.255.0")
                  ~gateway:(Eth.Gateway.Mac (Eth.Addr.of_string "02:00:00:00:00:fe"))
                  ~print:line ~print_err:line
                  ~on_exit:(fun s -> line (IO.to_string print_status s)) p in
          let policer =
              Policer.make ~parent:sim.root ?max_packets ?max_packet_rate ?max_syns ?max_syn_rate
                  ~on_limit:(fun l -> line ("hit "^ Policer.string_of_limit l) ; h.stop ()) "policer" in
          Simulation.power_up policer.widget.power ;
          Tools.(dev --> policer.widget.ports.dev 0) ;
          Tools.(policer.widget.ports.dev 1 --> sink (fun _ -> incr frames)) ;
          if stop then h.stop () ;
          Option.may (fun t -> Simulation.at sim.root.power (Clock.Time.of_secs t) h.stop ()) stop_at ;
          Simulation.run sim false ;
          String.concat "\n" (List.rev !out) ^ Printf.sprintf "\n%d frames" !frames

  let pings = "/IP(dst=1.2.3.4)/UDP(src=1000, dst=7) { repeat count=500 every=1ms { Bytes(\"ping\") } }"
*)
(*$= policed & ~printer:identity
  "line 1, column 5: Cannot apply + to a string and an int\nline 2, column 1: Unknown variable y" \
    (policed "x = \"a\" + 1\ny := 2")
  "line 1, column 5: Expected expression in statement" \
    (policed "x = ")
  "0.000s: hello\n0.000s: done\n1 frames" \
    (policed "print(\"hello\")\n/IP(dst=1.2.3.4)/UDP(src=1000, dst=7)/Bytes(\"x\")")
  "0.003s: hit max-packets\n0.003s: stopped\n3 frames" (policed ~max_packets:3 pings)
  "0.003s: hit max-packets\n0.003s: stopped\n3 frames" \
    (policed ~max_packets:3 ("catch { "^ pings ^" }\nprint(\"not caught\")"))
  "0.110s: hit max-packet-rate\n0.110s: stopped\n110 frames" (policed ~max_packet_rate:100. pings)
  "0.100s: stopped\n100 frames" (policed ~stop_at:0.1 pings)
  "0.000s: stopped\n0 frames" (policed ~stop:true pings)
  "0.000s: 3 10s [[40000, 40200]] []\n0.000s: done\n0 frames" \
    (policed "print(\"${BUDGET.max_syns} ${BUDGET.max_duration} ${PORTS.tcp} ${PORTS.udp}\")\n\
              BUDGET = {max_syns: 3, max_duration: 10s}\n\
              PORTS = {tcp: [[40000, 40100], [40050, 40200]]}")
  "0.000s: [[53, 53], [40000, 40100]]\n0.000s: done\n0 frames" \
    (policed "print(\"${PORTS.udp}\")\nPORTS = {udp: [[40000, 40100], 53]}")
  "0.000s: failed: line 1, column 10: max_bytes is not set, by the program or the command line\n0 frames" \
    (policed "print(\"${BUDGET.max_bytes}\")")
  "0.000s: failed: line 1, column 10: tcp is not set, by the program or the command line\n0 frames" \
    (policed "print(\"${PORTS.tcp}\")")
  (String.concat "\n" [ \
    "line 1, column 11: BUDGET can only be declared at the top level of the program" ; \
    "line 2, column 9: PORTS gives no port" ; \
    "line 3, column 1: PORTS is already declared" ]) \
    (policed "if true { BUDGET = {max_syns: 3} }\nPORTS = {tcp: []}\nPORTS = {udp: [[1, 2]]}")
  "line 1, column 24: BUDGET cannot be changed" (policed "BUDGET := {max_syns: 3}")
  "5.995s: done\n1000 frames" \
    (policed ~max_syns:1000 ~max_syn_rate:200. "\
      BUDGET = {max_syns: 1000, max_syns_per_secs: 200}\n\
      PORTS = {tcp: [[40000, 40000]]}\n\
      sport = PORTS.tcp[0][0]\n\
      {\n\
        on linger=1s /IP(src == 192.0.2.10)/TCP!(dst == sport, flags == SYN | ACK) {}\n\
        repeat var=i count=BUDGET.max_syns every=1s / BUDGET.max_syns_per_secs {\n\
          /IP(dst=192.0.2.10)/TCP!(src=sport, dst=i + 1, flags=SYN, seq_num=1)/Bytes()\n\
        }\n\
      }")
  "line 2, column 21: BUDGET.max_syns must be a literal int, 0 or more" \
    (policed "x = 1\nBUDGET = {max_syns: x}")
*)
(* Sharing the address of the host: the gateway found by ARP, no answer to
 * ARP for the address, the local port from those given, and no node left
 * once done: *)
(*$R run
  let sim = Simulation.make ~realtime:false "crafty-shared" in
  let ip = Ip.Addr.of_string and mac = Eth.Addr.of_string in
  let arp ?(from="02:00:00:00:00:fe") pdu =
      Eth.Pdu.(pack (make Eth.Proto.arp (mac from) (mac "02:00:00:00:00:01") (Arp.Pdu.pack pdu))) in
  let p = Result.get_ok (Crafty_interp.compile
              "PORTS = {udp: [[5000, 5000]]}\n\
               wait dur=1s\n/IP(dst=1.2.3.4)/UDP(dst=7)/Bytes(\"x\")") in
  let dev, h =
      run ~parent:sim.SimTypes.root ~mac:(mac "02:00:00:00:00:01") ~ip:(ip "10.0.0.1")
          ~netmask:(ip "255.255.255.0") ~gateway:(Eth.Gateway.IPv4 (ip "10.0.0.254"))
          ~answer_arp:false p in
  let frames = ref [] in
  Tools.(dev --> sink (fun bits ->
      let d = describe bits in
      frames := d :: !frames ;
      (* The gateway answers its ARP requests, once they are sent: *)
      if String.ends_with d " ARP" && String.starts_with d "02:00:00:00:00:01>FF" then
          Simulation.delay sim.root.power (Clock.Interval.msec 1.) dev.Tools.write (arp
              (Arp.Pdu.make_reply Arp.HwType.eth Arp.HwProto.ip4
                  (mac "02:00:00:00:00:fe" :> Bitstring.bitstring) (Ip.Addr.to_bitstring (ip "10.0.0.254"))
                  (mac "02:00:00:00:00:01" :> Bitstring.bitstring) (Ip.Addr.to_bitstring (ip "10.0.0.1"))))
  )) ;
  (* A neighbour asks for the address, which is not for the program to
   * answer: *)
  Simulation.at sim.root.power (Clock.Time.of_secs 0.5) dev.Tools.write (arp ~from:"02:00:00:00:00:02"
      (Arp.Pdu.make_request Arp.HwType.eth Arp.HwProto.ip4
          (mac "02:00:00:00:00:02" :> Bitstring.bitstring) (Ip.Addr.to_bitstring (ip "10.0.0.2"))
          (Ip.Addr.to_bitstring (ip "10.0.0.1")))) ;
  Simulation.run sim false ;
  assert_equal ~printer:(String.concat "\n")
      [ "02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP" ;
        "02:00:00:00:00:01>02:00:00:00:00:FE IP 10.0.0.1>1.2.3.4 ttl=64 UDP 5000>7 \"x\"" ]
      (List.rev !frames) ;
  assert_equal Done (h.status ()) ;
  assert_bool "idle" (h.idle ())
*)

(* [filters text frame] is whether that frame matches the filter of that
 * text, or why it is no filter: *)
(*$inject
  let filters text frame =
      match compile_filter text with
      | Error e -> IO.to_string print_error e
      | Ok f ->
          let sim = Simulation.make ~realtime:false "crafty" in
          let tree = Crafty_tree.make_root (crafty_eth sim) in
          let output = output_of sim.root.power ~print:ignore ~print_err:ignore () in
          string_of_bool (matches output tree f frame)
*)

(*$= filters & ~printer:identity
  "true" (filters "/IP/UDP" (reply "x"))
  "true" (filters " /ip(src == 10.0.0.2)/UDP(dst == 1000) " (reply "x"))
  "false" (filters "/IP/UDP(dst == 7)" (reply "x"))
  "true" (filters "/IP/UDP/Bytes(\"x\")" (reply "x"))
  "false" (filters "/IP/UDP/Bytes(\"y\")" (reply "x"))
  "false" (filters "/IP/TCP" (reply "x"))
  "false" (filters "/IP" (arp "10.0.0.2"))
  "true" (filters "/Eth" (arp "10.0.0.2"))
  "line 1, column 1: The pattern must be absolute (start with /)" \
    (filters "IP/UDP" (reply "x"))
  "line 1, column 9: Unknown variable x" (filters "/IP/UDP(x == 1)" (reply "x"))
  "line 1, column 9: Expected end of pattern" (filters "/IP/UDP {}" (reply "x"))
  "true" (filters "/IP | /Eth" (arp "10.0.0.2"))
  "false" (filters "/IP/TCP | /IP/UDP(dst == 7)" (reply "x"))
  "line 1, column 11: The pattern must be absolute (start with /)" \
    (filters "/IP/TCP | UDP" (reply "x"))
*)
