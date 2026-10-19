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
(** Runs a typed crafty program on a robinet simulation.

   Everything happens in the callbacks of the simulation's scheduler, in
   continuation passing style: a statement is given what to do once it is
   done. A block is left in one way only, its cancellation, whether it ends,
   breaks, fails or is restarted: what it set up is undone, and so are the
   blocks within it. As events of the scheduler cannot be withdrawn, those
   of a cancelled block find it dead and do nothing.

   [repeat] runs its iterations one after the other, each starting [every]
   after the previous one started (or as soon as it ends, if later), until
   it has run [count] of them or the next one would start once [for] has
   elapsed since it started; it ends right after its last iteration.
   [retry max=N] runs its block again up to N times (3 by default) while it
   fails, the error of the last attempt going to the enclosing block.
   [catch] leaves its block on its first error, which goes no further. An
   error reaching the program's block ends the program. *)
open Batteries
open Crafty_value
module A = Crafty_ast
module T = Crafty_typing
module Interval = Clock.Interval

type error = Crafty_parser.error

(** {2 Expressions} *)

(* Variables are cells, so that a block sees the changes made after it was
 * entered; a block entered again (a new iteration, another match) has cells
 * of its own: *)
module Env = Map.Int

type env =
    { vars : value ref Env.t ;
      (* The current protocol stack, its top first: *)
      stack : Crafty_tree.entry list }

let lookup (env : env) (v : T.var) =
    try Env.find v.id env.vars
    with Not_found -> invalid_arg ("Crafty_interp: no cell for "^ v.name)

let bind env (v : T.var) value =
    { env with vars = Env.add v.id (ref value) env.vars }

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
    | _ -> assert false

let float_of = function
    | Bool b -> if b then 1. else 0.
    | Int i | Byte i -> float_of_int i
    | Float f -> f
    | _ -> assert false

let call loc (b : T.builtin) args ~print ~print_err =
    match b, args with
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
    | T.Make_array, [ init ; Int len ] ->
        if len < 0 then error loc "array needs a length, not %d" len ;
        Array (Array.make len init)
    | T.Length, [ Array a ] -> Int (Array.length a)
    | T.Length, [ String s ] -> Int (String.length s)
    | T.Get, [ Array a ; Int i ] ->
        if i < 0 || i >= Array.length a then
            error loc "No item %d in an array of length %d" i (Array.length a) ;
        a.(i)
    | T.Print, [ String s ] -> print s ; Void
    | T.Print_err, [ String s ] -> print_err s ; Void
    | _ -> assert false

(* The [value] of type [from] as a [typ]: *)
let convert loc (from : A.Type.t) (typ : A.Type.t) value =
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
    | _ -> invalid_arg "Crafty_interp.convert"

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
    | A.Div, Interval _, Float 0. -> error loc "Division by zero"
    | A.Div, Interval a, Float b -> Interval (Interval.div a b)
    | A.BitAnd, Int a, Int b -> Int (a land b)
    | A.BitOr, Int a, Int b -> Int (a lor b)
    | A.BitXor, Int a, Int b -> Int (a lxor b)
    | A.BitAnd, Byte a, Byte b -> Byte (a land b)
    | A.BitOr, Byte a, Byte b -> Byte (a lor b)
    | A.BitXor, Byte a, Byte b -> Byte (a lxor b)
    | _ -> invalid_arg "Crafty_interp.arith"

(* Where a program writes: *)
type output = { print : string -> unit ; print_err : string -> unit }

let rec eval output (env : env) (e : T.expr) =
    let eval = eval output env in
    match e.desc with
    | T.Lit l -> of_literal l
    | T.String parts ->
        String (String.concat "" (List.map (function
            | T.Text s -> s
            | T.Interp e -> to_string e.typ (eval e)) parts))
    | T.Var v -> !(lookup env v)
    | T.Packet_field _ ->
        error e.loc "Packets are not supported yet"
    | T.Field (r, i) ->
        (match eval r with Record vs -> vs.(i) | _ -> assert false)
    | T.Index (a, i) ->
        (match eval a, eval i with
        | Array a, Int i ->
            if i < 0 || i >= Array.length a then
                error e.loc "No item %d in an array of length %d" i (Array.length a) ;
            a.(i)
        | _ -> assert false)
    | T.Select { packet ; layer ; from_start ; nth } ->
        (match eval packet with
        | Array a ->
            let layers =
                Array.to_list a |>
                List.filter_map (function
                    | Variant (n, v) when n = layer.name -> Some v
                    | _ -> None) in
            let layers = if from_start then layers else List.rev layers in
            (match List.nth_opt layers nth with
            | Some v -> v
            | None -> error e.loc "No such %s in this packet" layer.name)
        | _ -> assert false)
    | T.Call (b, args) ->
        call e.loc b (List.map eval args)
             ~print:output.print ~print_err:output.print_err
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
    | T.Convert a -> convert e.loc a.typ e.typ (eval a)

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
      break_ : int -> unit }

(* Leaves [b], and the blocks within it; the most recent first: *)
let rec cancel b =
    if b.live then (
        b.live <- false ;
        List.iter cancel b.children ;
        List.iter (fun f -> f ()) b.cleanups ;
        b.cleanups <- [] ;
        Option.may (fun p -> p.children <- List.filter ((!=) b) p.children)
                   b.parent)

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
      tree : Crafty_tree.node }

(* The stack of [env] with these layers on top, their nodes held by [b] (but
 * for the root, which stays, and for a terminal layer's, which goes with its
 * parent).
 * Options belong to the stack and not to the nodes, so they are scoped as
 * the stack is: a stack statement without a block, terminal or not, makes
 * its stack with its options the current one until the end of the block.
 * Another packet with other options writes its whole stack again. *)
let push t b env absolute (layers : T.layer list) =
    let base = if absolute then [] else env.stack in
    List.fold_left (fun stack (l : T.layer) ->
        let options =
            List.map (fun (i, e) -> i, eval t.output env e) l.options in
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

(* Runs that block within [parent], then [k], unless it fails or breaks
 * first; returns the block: *)
let rec run_block t parent env (stmts : T.block) ~fail ~break_ k =
    let rec b =
        { parent = Some parent ; live = true ; children = [] ; cleanups = [] ;
          fail = (fun e -> cancel b ; fail e) ;
          break_ } in
    parent.children <- b :: parent.children ;
    let rec loop env = function
        | [] ->
            cancel b ;
            k ()
        | s :: rest ->
            exec t b env s (fun env -> if b.live then loop env rest) in
    loop env stmts ;
    b

(* Runs that statement in block [b], then [k] with the environment for the
 * next statements: *)
and exec t b env (s : T.stmt) k =
    let eval e = eval t.output env e in
    let guard f = guard b f in
    match s.stmt with
    | T.Declare (v, e) -> Option.may (fun x -> k (bind env v x)) (guard (fun () -> eval e))
    | T.Assign (v, e) ->
        Option.may (fun x -> (lookup env v) := x ; k env) (guard (fun () -> eval e))
    | T.Do (f, args) ->
        guard (fun () ->
            ignore (call s.stmt_loc f (List.map eval args)
                         ~print:t.output.print ~print_err:t.output.print_err)) |>
        Option.may (fun () -> k env)
    | T.Block body ->
        ignore (run_block t b env body ~fail:b.fail ~break_:b.break_
                    (fun () -> k env))
    | T.Break n -> b.break_ n
    | T.Repeat { var ; count ; every ; for_ ; body } ->
        repeat t b env var count every for_ body s.stmt_loc (fun () -> k env)
    | T.Retry { max ; body } ->
        guard (fun () ->
            match Option.map eval max with Some (Int n) -> n | _ -> 3) |>
        Option.may (fun max ->
            let rec attempt retries =
                ignore (run_block t b env body ~break_:b.break_ (fun () -> k env)
                    ~fail:(fun e ->
                        if retries < max && b.live then attempt (retries + 1)
                        else b.fail e)) in
            attempt 0)
    | T.Catch body ->
        ignore (run_block t b env body ~break_:b.break_ (fun () -> k env)
                    ~fail:(fun _ -> if b.live then k env))
    | T.Stack { absolute ; layers ; body = Some body } ->
        (* The block after a stack is where that stack is pushed: *)
        let push = { s with stmt = T.Stack { absolute ; layers ; body = None } } in
        exec t b env { s with stmt = T.Block (push :: body) } k
    | T.Stack { absolute ; layers ; body = None } ->
        guard (fun () ->
            match push t b env absolute layers with
            | top :: rest as stack when top.node.layer.terminal ->
                (* Which sends, and does not stay: *)
                (try Crafty_tree.send stack
                 with Failed msg -> error s.stmt_loc "%s" msg) ;
                rest
            | stack -> stack) |>
        Option.may (fun stack -> k { env with stack })
    | T.Expect _ | T.On _ ->
        ignore (guard (fun () ->
            error s.stmt_loc "Patterns are not supported yet"))

and repeat t b env var count every for_ body body_loc k =
    let eval = eval t.output env in
    let interval d = function
        | Some e -> (match eval e with Interval i -> i | _ -> assert false)
        | None -> d in
    guard b (fun () ->
        (match Option.map eval count with Some (Int n) -> Some n | _ -> None),
        interval Interval.zero every,
        interval (Interval.min 5.) for_) |>
    Option.may (fun (count, every, for_) ->
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
                    let env = bind env var (Int !i) in
                    let break_ n =
                        if n <= 1 then (Option.may cancel !current ; k ())
                        else b.break_ (n - 1) in
                    let running = ref true and ended = ref false in
                    let this = !i in
                    current := Some (
                        run_block t b env body ~fail:b.fail ~break_ (fun () ->
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
      status : unit -> status }

(** Runs [program] on [power]'s simulation, starting at once, sending and
 * receiving through [tree] (from {!Crafty_tree.make_root}), writing with
 * [print] and [print_err], and calling [on_exit] with its final status
 * (possibly before returning). *)
let run power tree ~print ~print_err ?(on_exit=ignore) (program : T.block) =
    let status = ref Running in
    let t = { power ; output = { print ; print_err } ; tree } in
    let exit s =
        if !status = Running then (
            status := s ;
            on_exit s) in
    let rec root =
        { parent = None ; live = true ; children = [] ; cleanups = [] ;
          fail = (fun e -> cancel root ; exit (Failed e)) ;
          break_ = (fun _ -> assert false) } in
    ignore (run_block t root { vars = Env.empty ; stack = [] } program
                ~fail:root.fail ~break_:root.break_
                (fun () -> cancel root ; exit Done)) ;
    { stop = (fun () -> cancel root ; exit Stopped) ;
      status = (fun () -> !status) }

(* [runs ?stop_at ?trees ?frames ?inject text] is what the program in that text
 * prints, each line with the time it is printed at (and with [trees], the
 * tree of parsers then), then how it ends; or why it cannot run. With
 * [frames], the frames it emits are among those lines, as [describe] tells
 * them (without their time, which depends on the scheduler by a few ps).
 * [inject] are frames it receives, with the time they arrive at, made with
 * the help of [incoming] (from 02:00:00:00:00:02). Its interface is 10.0.0.1/24, its gateway 02:00:00:00:00:fe, and it
 * knows the MAC address of 10.0.0.2. *)
(*$inject
  let gw_mac = Eth.Addr.of_string "02:00:00:00:00:fe"

  let crafty_eth sim =
      let eth =
          Eth.State.make ~parent:sim.SimTypes.root ~name:"crafty"
              ~mac:(Eth.Addr.of_string "02:00:00:00:00:01")
              ~gateways:[ Eth.State.gw_selector (), Some (Eth.Gateway.Mac gw_mac) ]
              ~my_addresses:[ Eth.State.make_my_ip_address
                                  ~netmask:(Ip.Addr.of_string "255.255.255.0")
                                  (Ip.Addr.of_string "10.0.0.1") ] () in
      Tools.BitHash.replace eth.Eth.State.arp_cache
          (Ip.Addr.to_bitstring (Ip.Addr.of_string "10.0.0.2"))
          (Some (Eth.Addr.of_string "02:00:00:00:00:02")) ;
      eth

  let describe frame =
      let b = Stdlib.Buffer.create 80 in
      let add fmt = Printf.bprintf b fmt in
      let str bits = Bitstring.string_of_bitstring bits in
      let pld (p : Payload.t) = str (p :> Bitstring.bitstring) in
      (match Eth.Pdu.unpack frame with
      | Error _ -> add "?"
      | Ok e ->
          add "%s>%s" (Eth.Addr.to_hexstring e.Eth.Pdu.src) (Eth.Addr.to_hexstring e.dst) ;
          let bits = (e.payload :> Bitstring.bitstring) in
          if e.proto = Eth.Proto.arp then add " ARP"
          else if e.proto <> Eth.Proto.ip4 then add " proto=0x%x %S" (e.proto :> int) (str bits)
          else match Ip.Pdu.unpack bits with
          | Error _ -> add " ?"
          | Ok ip ->
              add " IP %s>%s ttl=%d" (Ip.Addr.to_dotted_string ip.Ip.Pdu.src)
                  (Ip.Addr.to_dotted_string ip.dst) ip.ttl ;
              if ip.dont_frag then add " df" ;
              if Tools.sum (Bitstring.takebits (8 * (20 + Tools.bytelength ip.options)) bits) <> 0 then
                  add " bad-checksum" ;
              let l4 = (ip.payload :> Bitstring.bitstring) in
              if ip.proto = Ip.Proto.udp then (
                  match Udp.Pdu.unpack l4 with
                  | Error _ -> add " ?"
                  | Ok u ->
                      add " UDP %d>%d %S" (u.Udp.Pdu.src_port :> int) (u.dst_port :> int) (pld u.payload) ;
                      if Tools.sum_list [ Ip.Pdu.pseudo_header ip () ; l4 ] <> 0 then
                          add " bad-checksum"
              ) else if ip.proto = Ip.Proto.icmp then (
                  match Icmp.Pdu.unpack l4 with
                  | Error _ -> add " ?"
                  | Ok i ->
                      let typ, code = (i.Icmp.Pdu.msg_type :> int * int) in
                      add " ICMP %d/%d" typ code ;
                      (match i.payload with
                      | Icmp.Pdu.Ids (id, seq, p) -> add " id=%d seq=%d %S" id seq (pld p)
                      | Icmp.Pdu.Header { mtu ; pld = p ; _ } -> add " mtu=%d %S" mtu (pld p)
                      | _ -> add " ?") ;
                      if Tools.sum l4 <> 0 then add " bad-checksum"
              ) else add " proto=%d %S" (ip.proto :> int) (str l4)) ;
      Stdlib.Buffer.contents b

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

  let runs ?stop_at ?(trees=false) ?(frames=false) ?(inject=[]) text =
      match Crafty_parser.parse text with
      | Error e -> IO.to_string Crafty_parser.print_error e
      | Ok p ->
          match Crafty_typing.check p with
          | Error es ->
              String.concat "\n" (List.map (IO.to_string Crafty_parser.print_error) es)
          | Ok p ->
              let sim = Simulation.make ~realtime:false "crafty" in
              let eth = crafty_eth sim in
              let tree = Crafty_tree.make_root eth in
              let out = ref [] in
              let line pfx s =
                  out := Printf.sprintf "%s%s: %s%s" pfx
                      (Clock.Time.to_string (Simulation.now sim)) s
                      (if trees then " "^ Crafty_tree.to_string tree else "") :: !out in
              if frames then
                  Tools.(Eth.Iface.dev eth.Eth.State.iface -->
                      sink (fun bits -> out := ("> "^ describe bits) :: !out)) ;
              List.iter (fun (t, frame) ->
                  Simulation.at sim.root.power (Clock.Time.of_secs t)
                      (fun () -> eth.Eth.State.iface.Eth.Iface.recv frame) ()) inject ;
              let h =
                  run sim.root.power tree ~print:(line "") ~print_err:(line "err ")
                      ~on_exit:(function
                          | Done -> line "" "done"
                          | Failed e ->
                              line "" ("failed: "^ IO.to_string Crafty_parser.print_error e)
                          | Stopped -> line "" "stopped"
                          | Running -> ()) p in
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
  "0s: 0\n0s: after\n0s: done" \
    (runs "repeat count=5 every=1s { print(\"${I}\")\n  break }\nprint(\"after\")")
  "0s: 0\n0s: after\n0s: done" \
    (runs "repeat var=i count=3 { repeat { print(\"${i}\")\n    break 2 } }\nprint(\"after\")")
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
  "0s: [1.5, 1.5] 2 1.5 4\n0s: done" \
    (runs "x = array(init=1.5, len=2)\nprint(\"${x} ${length(x)} ${get(a=x, index=1)} ${length(randbytes(4))}\")")
  "0s: failed: line 1, column 5: No item -1 in an array of length 1" \
    (runs "x = get(a=[1], index=-1)")
  "line 2, column 1: Unknown variable y" \
    (runs "x = #0102\ny := x")
  "0s: 0\n1s: 1\n1s500ms: stopped" \
    (runs ~stop_at:(Clock.Time.of_secs 1.5) \
          "repeat count=5 every=1s { print(\"${I}\") }")
  "0s: failed: line 1, column 32: Patterns are not supported yet" \
    (runs "/IP(dst=1.2.3.4)/UDP(dst=53) { expect Bytes(\"x\") {} }")
*)
(* Stacks hold their nodes for the block they are in: *)
(*$= runs & ~printer:identity
  "0s: in Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1{UDP(src=1, dst=53)*1}}\n0s: out Eth\n0s: done Eth" \
    (runs ~trees:true "/IP(dst=1.2.3.4)/UDP(src=1, dst=53) { print(\"in\") }\nprint(\"out\")")
  "0s: a Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1}\n0s: b Eth{IP(src=10.0.0.1, dst=1.2.3.4)*2}\n0s: c Eth{IP(src=10.0.0.1, dst=1.2.3.4)*3{ICMP*1{EchoRequest(id=7)}, UDP(src=1, dst=53)*1}}\n0s: d Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1}\n0s: e Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1, IP(src=10.0.0.1, dst=1.2.3.5)*1}\n0s: done Eth" \
    (runs ~trees:true "IP(dst=1.2.3.4)\nprint(\"a\")\n{\n  /IP(dst=1.2.3.4)\n  print(\"b\")\n  UDP(src=1, dst=53)\n  /IP(dst=1.2.3.4)/ICMP/EchoRequest(id=7)\n  print(\"c\")\n}\nprint(\"d\")\n/IP(dst=1.2.3.5)\nprint(\"e\")")
  "0s: try Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1{UDP(src=1, dst=53)*1}}\n0s: try Eth{IP(src=10.0.0.1, dst=1.2.3.4)*1{UDP(src=1, dst=53)*1}}\n0s: failed: line 4, column 7: Division by zero Eth" \
    (runs ~trees:true "retry max=1 {\n  /IP(dst=1.2.3.4)/UDP(src=1, dst=53)\n  print(\"try\")\n  x = 1 / 0 }")
  "0s: done Eth" \
    (runs ~trees:true "repeat count=3 { /IP(dst=1.2.3.4)/UDP(dst=53) }")
*)
(* What programs send, through the gateway or to a neighbour, self-driven or
 * manual, with the automatic fields filled in (checksums included, which
 * [describe] checks): *)
(*$= runs & ~printer:identity
  "0s: done\n> 02:00:00:00:00:01>02:00:00:00:00:FE IP 10.0.0.1>1.2.3.4 ttl=64 UDP 1000>53 \"hi\"" \
    (runs ~frames:true "/IP(dst=1.2.3.4)/UDP(src=1000, dst=53)/Bytes(\"hi\")")
  "0s: done\n> 02:00:00:00:00:01>02:00:00:00:00:FE IP 10.0.0.1>1.2.3.4 ttl=3 df UDP 1>2 \"x\"" \
    (runs ~frames:true "/IP!(dst=1.2.3.4, ttl=3, dont_frag=true)/UDP(src=1, dst=2)/Bytes(\"x\")")
  "0s: done\n> 02:00:00:00:00:01>02:00:00:00:00:FE IP 10.0.0.1>1.2.3.4 ttl=64 proto=99 \"p\"" \
    (runs ~frames:true "/IP(dst=1.2.3.4, proto=99)/Bytes(\"p\")")
  "0s: done\n> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP" \
    (runs ~frames:true "/IP(dst=10.0.0.3)/UDP(src=1, dst=2)/Bytes(\"who\")")
*)
(* Self-driven IP takes TTL and DF per packet (and a terminal stack leaves
 * its own as the current one); echo ids are shared (the random ones shown
 * as "?"), and their sequence numbers go on: *)
(*$= runs & ~printer:identity
  "0s: done\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 UDP 1>2 \"a\"\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=3 df UDP 1>2 \"b\"\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=3 df UDP 1>2 \"c\"" \
    (runs ~frames:true "/IP(dst=10.0.0.2)/UDP(src=1, dst=2) { Bytes(\"a\")\n  /IP(dst=10.0.0.2, ttl=3, dont_frag=true)/UDP(src=1, dst=2)/Bytes(\"b\")\n  Bytes(\"c\") }")
  "0s: done\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 ICMP 8/0 id=? seq=1 \"ping\"\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 ICMP 8/0 id=? seq=2 \"ping\"\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 ICMP 8/0 id=7 seq=42 \"\"" \
    (runs ~frames:true "/IP(dst=10.0.0.2)/ICMP { repeat count=2 { EchoRequest(\"ping\") }\n  EchoRequest(id=7, seq=42) }" |> \
     String.split_on_char '\n' |> List.map (fun l -> \
        match String.split l ~by:" id=" with \
        | a, b when not (String.starts_with b "7 ") -> \
            a ^" id=? "^ snd (String.split b ~by:" ") \
        | _ -> l \
        | exception Not_found -> l) |> String.concat "\n")
  "0s: done\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 ICMP 3/3 mtu=1400 \"\\001\\002\"\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 ICMP 11/0 mtu=0 \"\\003\\004\"" \
    (runs ~frames:true "/IP!(dst=10.0.0.2)/ICMP/DestUnreachable(code=PORT_UNREACHABLE, mtu=1400, payload=#0102)\n/IP!(dst=10.0.0.2)/ICMP/TimeExceeded(#0304)")
*)
(* Manual frames, to a given MAC address or to what the interface knows: *)
(*$= runs & ~printer:identity
  "0s: done\n> 02:00:00:00:00:01>AA:BB:CC:DD:EE:FF proto=0x88b5 \"raw\"\n> 02:00:00:00:00:01>02:00:00:00:00:FE IP 10.0.0.1>1.2.3.4 ttl=64 UDP 1>2 \"y\"\n> 02:00:00:00:00:99>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.2 ttl=64 proto=99 \"z\"" \
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
    (runs ~frames:true "/IP!(dst=1.2.3.4, ttl=256)/ICMP/EchoRequest()")
  "0s: failed: line 1, column 1: A self-driven IP sends no empty packet: use IP!" \
    (runs ~frames:true "/IP(dst=1.2.3.4, proto=99)/Bytes()")
  "0s: failed: line 1, column 1: TCP is not supported yet" \
    (runs ~frames:true "/IP(dst=1.2.3.4)/TCP(dst=80)/Bytes(\"x\")")
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
  "0s: done\n> 02:00:00:00:00:01>FF:FF:FF:FF:FF:FF ARP\n> 02:00:00:00:00:01>02:00:00:00:00:02 ARP\n> 02:00:00:00:00:01>02:00:00:00:00:02 IP 10.0.0.1>10.0.0.3 ttl=64 UDP 1>2 \"who\"" \
    (runs ~frames:true ~inject:[ 0.1, arp "10.0.0.2" ; 0.2, arp ~reply:true "10.0.0.3" ] \
        "/IP(dst=10.0.0.3)/UDP(src=1, dst=2)/Bytes(\"who\")")
*)
