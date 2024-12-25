(* Implementation of a minimalistic search language used to filter textual values *)
open Batteries

open Tools

let debug = false

module Token =
struct
  (*$< Token *)

  exception Read_error of int

  type t = Open | Close | Not | And | Or | Eq | Neq | Gt | Gte | Lt | Lte
         | In | Sep | Symbol of string | Word of string

  let to_string = function
    | Open -> "opened parentheses"
    | Close -> "closed parentheses"
    | Not -> "not unary operator"
    | And -> "and binary operator"
    | Or -> "or binary operator"
    | Eq -> "equality binary operator"
    | Neq -> "not-equal binary operator"
    | Gt -> "greater-than binary operator"
    | Gte -> "greater-than binary operator"
    | Lt -> "lesser-than binary operator"
    | Lte -> "lesser-than binary operator"
    | In -> "in binary operator"
    | Sep -> "list separator"
    | Symbol s -> "symbol "^ quoted s
    | Word s -> "literal string "^ quoted s

  let is_blank = function
    | ' ' | '\t' | '\r' | '\n' -> true
    | _ -> false

  (* Tells if a char can be part of a symbol *)
  let is_symboly c =
    c >= 'a' && c <= 'z' ||
    (*c >= 'A' && c <= 'Z' || Has been lowercased already *)
    c >= '0' && c <= '9' ||
    c = '_'

  (* Assuming all strings have been cleaned/lowercased already: *)
  let of_string = function
    | "(" -> Open
    | ")" -> Close
    | "not" -> Not
    | "and" -> And
    | "or" -> Or
    | "=" -> Eq
    | "<>" | "!=" -> Neq
    | ">" -> Gt
    | ">=" -> Gte
    | "<" -> Lt
    | "<=" -> Lte
    | "in" -> In
    | "," -> Sep
    | "" -> invalid_arg "Token.of_string"
    | s when String.for_all is_symboly s -> Symbol s
    | _ -> raise Not_found

  let quote = '"'

  let parse s =
    let rec loop toks i =
      if debug then Printf.eprintf "loop %d\n" i ;
      if i >= String.length s then toks else
      if is_blank s.[i] then loop toks (i + 1) else
      if s.[i] = quote then (
        let i' = i + 1 in
        match String.index_from s i' quote with
        | exception _ -> raise (Read_error i)
        | j -> loop ((i, Word (String.sub s i' (j - i'))) :: toks) (j + 1)
      ) else (
        let possible_toks =
          let rec loop_poss possible_toks j =
            if debug then Printf.eprintf "loop_poss (%d possibles, s=%S, i=%d, j=%d)\n" (List.length possible_toks) s i j ;
            if j >= String.length s || is_blank s.[j] then possible_toks else
            match of_string String.(lowercase_ascii (sub s i (1 + j - i))) with
            | exception Not_found ->
                (* Keep trying, s is short: *)
                loop_poss possible_toks (j + 1)
            | Symbol _ as t ->
                if j + 1 < String.length s && is_symboly s.[j + 1] then
                  loop_poss possible_toks (j + 1)
                else (
                  if debug then Printf.eprintf "loop_poss: accept %s since next char is not symboly (%c)\n" (to_string t) (try s.[j + 1] with _ -> '?') ;
                  (* Save the position of the last char of the symbol with it: *)
                  loop_poss ((t, j) :: possible_toks) (j + 1))
            | t ->
                loop_poss ((t, j) :: possible_toks) (j + 1) in
          loop_poss [] i in
        if debug then Printf.eprintf "Found those possible tokens: %a\n" (List.print (fun oc (s, _) -> String.print oc (to_string s))) possible_toks ;
        let rec loop_possibles = function
          | [] ->
              raise (Read_error i)
          | [ single, j ] ->
              (* If that's the only option then it has to work *)
              loop ((i, single) :: toks) (j + 1)
          | (t1, j) :: others ->
              (* There should be only one way to parse a string: *)
              (try loop ((i, t1) :: toks) (j + 1)
              with Read_error _ -> loop_possibles others) in
        loop_possibles possible_toks
      ) in
    loop [] 0 |>
    List.rev

  (*$= parse & ~printer:Batteries.(IO.to_string (List.print (Tuple2.print Int.print (fun oc t -> String.print oc (to_string t)))))
    []  (parse "")
    []  (parse "  ")
    [(0, Open) ; (1, Close)]  (parse "()")
    [(1, Open) ; (3, Close)]  (parse " ( )  ")
    [(0, Word "")]  (parse "\"\"")
    [(0, Word "glop")]  (parse "\"glop\"")
    [(0, Symbol "true") ; (5, And) ; (9, Symbol "true") ; \
     (14, Or) ; (17, Symbol "false")] \
        (parse "true and true or false")
  *)

  (*$>*)
end

module Expr =
struct
  (*$< Expr *)

  exception Parse_error of int * string

  type t =
    | Not of t
    | And of t * t
    | Or of t * t
    | Eq of t * t
    | Neq of t * t
    | Gt of t * t
    | Lt of t * t
    | Gte of t * t
    | Lte of t * t
    | In of t * t
    | List of t list
    | Var of string
    | IntVal of int
    | StrVal of string
    | BoolVal of bool

  let rec to_string =
    let to_string_ = function
      | List ts ->
          "("^
          (List.map (fun t -> to_string t) ts |> String.join ", ")
          ^")"
      | Var s ->
          s
      | IntVal d ->
          string_of_int d
      | StrVal s ->
          quoted s
      | BoolVal true ->
          "true"
      | BoolVal false ->
          "false"
      | t ->
          "("^ to_string t ^")" in
    function
    | Not t -> "not "^ to_string_ t
    | And (a, b) -> to_string_ a ^" and "^ to_string_ b
    | Or (a, b) -> to_string_ a ^" or "^ to_string_ b
    | Eq (a, b) -> to_string_ a ^" = "^ to_string_ b
    | Neq (a, b) -> to_string_ a ^" != "^ to_string_ b
    | Gt (a, b) -> to_string_ a ^" > "^ to_string_ b
    | Lt (a, b) -> to_string_ a ^" < "^ to_string_ b
    | Gte (a, b) -> to_string_ a ^" >= "^ to_string_ b
    | Lte (a, b) -> to_string_ a ^" <= "^ to_string_ b
    | In (a, b) -> to_string_ a ^" in "^ to_string_ b
    | t -> to_string_ t

  let binexpr a b = function
    | Token.And -> And (a, b)
    | Or -> Or (a, b)
    | Eq -> Eq (a, b)
    | Neq -> Neq (a, b)
    | Gt -> Gt (a, b)
    | Gte -> Gte (a, b)
    | Lt -> Lt (a, b)
    | Lte -> Lte (a, b)
    | In -> In (a, b)
    | _ -> invalid_arg "binexpr"

  let print_token oc (p, t) =
    Printf.fprintf oc "%s@%d" (Token.to_string t) p

  let print_expr oc e =
    String.print oc (to_string e)

  let parse_error p err =
    raise (Parse_error (p, err))

  (* Parse the next tokens until the next separator, close of currently opened
   * parentheses, or end of input; And returns a single expression and the
   * remaining tokens.
   * [waitop] is the waiting operator waiting for its right argument. *)
  let rec expr ?waitop ?(stack=[]) toks =
    if debug then Printf.eprintf "expr, stack=%a, toks=%a\n" (List.print print_expr) stack (List.print print_token) toks ;
    let expr_of_stack = function
      | [ e ] -> e
      | _ ->
          let p = match toks with [] -> -1 | (p, _) :: _ -> p in
          parse_error p "cannot parse before"
    in
    (* "2 > 1 or false and 0 < 0" *)
    let higher_prio right_op = function
      | None -> true
      (* Then the  only cases where we are going to bind an operand with its
       * right operator is when let operator is Or and right is not, or when
       * the left one is And and the right one is anything but Or and And. *)
      | Some Token.Or -> right_op <> Token.Or
      | Some And -> right_op <> Or && right_op <> And
      (* In all other cases the left operator takes the operand first. *)
      | Some _ -> false in
    match toks with
    | [] ->
        expr_of_stack stack,
        toks
    | (_, Token.Open) :: (_, Close) :: toks ->
        expr ?waitop ~stack:(List [] :: stack) toks
    | (i, Open) :: toks ->
        let rec loop_list_items lst toks =
          if debug then Printf.eprintf "loop_list_items, current list=%a, toks=%a\n" (List.print print_expr) lst (List.print print_token) toks ;
          let e, toks = expr toks in
          if debug then Printf.eprintf "next expr of the list: e=%s, toks=%a" (to_string e) (List.print print_token) toks ;
          match toks with
          | (_, Sep) :: (_, Close) :: toks
              (* Allow terminal separator: *)
          | (_, Close) :: toks ->
              (* Expression in parentheses must reduce to a single expression
               * or to a list: *)
              (if lst = [] then e else List (List.rev (e :: lst))),
              toks
          | (_, Sep) :: toks ->
              loop_list_items (e :: lst) toks
          | [] ->
              parse_error i "parentheses never closed"
          | _ ->
              parse_error i "cannot parse list" in
        let e, toks = loop_list_items [] toks in
        expr ?waitop ~stack:(e :: stack) toks
    | (_, (Close | Sep)) :: _ ->
        (* We stop there *)
        expr_of_stack stack,
        toks
    | (_, Not) :: toks ->
        let e, toks = expr ~waitop:Token.Not toks in
        expr ?waitop ~stack:(Not e :: stack) toks
    | (i, (And | Or | Eq | Neq | Gt | Gte | Lt | Lte | In as binop)) :: toks' ->
        if stack = [] then
          parse_error i ("need an expression before "^ Token.to_string binop) ;
        if higher_prio binop waitop then (
          (* Get our right operand: *)
          let e, toks = expr ~waitop:binop toks' in
          let e = binexpr (List.hd stack) e binop in
          let stack = e :: List.tl stack in
          (* Same waitop will compete with the next operator to get us :*)
          expr ?waitop ~stack toks
        ) else (
          (* Abandon our left operand: *)
          expr_of_stack stack,
          toks
        )
    | (_, Symbol s) :: toks ->
        let e =
          if s = "true" then BoolVal true else
          if s = "false" then BoolVal false else
          (* numbers are not quoted so appear as symbols for the tokenizer: *)
          try IntVal (int_of_string s)
          with _ -> Var s in
        expr ?waitop ~stack:(e :: stack) toks
    | (_, Word s) :: toks ->
        expr ?waitop ~stack:(StrVal s :: stack) toks

  (* Returns a single expression: *)
  let of_string s =
    let toks = Token.parse s in
    let e, toks = expr toks in
    if debug then Printf.eprintf "expr -> e=%s, toks=%a\n" (to_string e) (List.print print_token) toks ;
    match toks with
    | [] -> e
    | (p, _) :: _ -> parse_error p "garbage"

  (*$= of_string & ~printer:to_string
    (List []) (of_string "()")
    (And (Var "a", IntVal 42)) (of_string "A and 42")
    (In (StrVal "glop", List [ StrVal "pas" ; StrVal "glop" ])) \
        (of_string "\"glop\" in (\"pas\", \"glop\")")
    (Or (And (BoolVal true, BoolVal true), BoolVal false)) \
        (of_string "true and true or false")
   *)

  exception Eval_error of string * t

  let to_bool = function
    | BoolVal b -> b
    | IntVal i -> i <> 0
    | StrVal s -> s <> ""
    | e -> raise (Eval_error ("not a boolean", e))

  let eval ?(undef_to_empty=true) ?(vars=[]) e =
    let rec promote ?(reverse=false) orig_e a b =
      let a, b =
        match a, b with
        | BoolVal _, BoolVal _
        | IntVal _, IntVal _
        | StrVal _, StrVal _ ->
            a, b
        | BoolVal a, IntVal _ ->
            IntVal (if a then 1 else 0), b
        | BoolVal a, StrVal _ ->
            StrVal (if a then "1" else ""), b
        | IntVal d, StrVal _ ->
            StrVal (string_of_int d), b
        | List la, List lb ->
            let rec loop la lb la' lb' =
              match la', lb' with
              | [], b :: lb' ->
                  loop la (b :: lb) la' lb'
              | a :: la', [] ->
                  loop (a :: la) lb la' lb'
              | [], [] ->
                  List (List.rev la), List (List.rev lb)
              | a :: la', b :: lb' ->
                  let a, b = promote orig_e a b in
                  loop (a :: la) (b :: lb) la' lb' in
            loop [] [] la lb
        | a, b ->
            if reverse then
              raise (Eval_error ("incompatible types", orig_e))
            else
              promote ~reverse:true orig_e b a
      in
      if reverse then b, a else a, b in
    let rec eval = function
      | Not t ->
          BoolVal (not (to_bool (eval t)))
      | And (a, b) ->
          (* Force both members to be evaluated regardless of the result: *)
          let a = to_bool (eval a) and b = to_bool (eval b) in
          BoolVal (a && b)
      | Or (a, b) ->
          let a = to_bool (eval a) and b = to_bool (eval b) in
          BoolVal (a || b)
      | Eq (a, b) as e ->
          let a = eval a and b = eval b in
          (* Promote some types before generic operators: *)
          let a, b = promote e a b in
          BoolVal (a = b)
      | Neq (a, b) as e ->
          let a = eval a and b = eval b in
          let a, b = promote e a b in
          BoolVal (a <> b)
      | Gt (a, b) as e ->
          let a = eval a and b = eval b in
          let a, b = promote e a b in
          BoolVal (a > b)
      | Lt (a, b) as e ->
          let a = eval a and b = eval b in
          let a, b = promote e a b in
          BoolVal (a < b)
      | Gte (a, b) as e ->
          let a = eval a and b = eval b in
          let a, b = promote e a b in
          BoolVal (a >= b)
      | Lte (a, b) as e ->
          let a = eval a and b = eval b in
          let a, b = promote e a b in
          BoolVal (a <= b)
      | In (a, b) as e ->
          BoolVal (
            match eval a, eval b with
            | x, List lst ->
                List.exists (fun y ->
                  let x, y = promote e x y in
                  x = y
                ) lst
            | StrVal s1, StrVal s2 ->
                String.exists s2 s1
            | IntVal i, StrVal s2 ->
                String.exists s2 (string_of_int i)
            | IntVal i1, IntVal i2 ->  (* just for fun *)
                i2 mod i1 = 0
            | _ ->
                raise (Eval_error ("bad operands", e)))
      | List ts ->
          (* Simplify *)
          List (List.map eval ts)
      | Var n as e ->
          (match List.assoc n vars with
          | exception Not_found ->
              if undef_to_empty then BoolVal false else
              raise (Eval_error ("undefined variable", e))
          | e ->
              (* We should not worry about recursive references in this simple
               * language: *)
              eval e)
      | IntVal _ | StrVal _ | BoolVal _ as e ->
          e in
    eval e

  (*$= eval & ~printer:to_string
    (List []) (eval (of_string "()"))
    (BoolVal true) (eval (of_string "true and true or false"))
    (BoolVal true) (eval (of_string "\"glop\" in \"pas glop\""))
    (BoolVal false) (eval (of_string "not (\"glop\" in \"pas glop\")"))
    (BoolVal true) (eval (of_string "2 > 1"))
    (BoolVal false) (eval (of_string "not (2 > 1)"))
    (BoolVal false) (eval (of_string "false and true"))
    (BoolVal true) (eval (of_string "not false and true"))
    (BoolVal true) (eval (of_string "not (false and true)"))
    (BoolVal true) (eval (of_string "2 > 1 or false"))
    (BoolVal true) (eval (of_string "2 > 1 or false and 0 < 0"))
    (BoolVal true) (eval (of_string "2 > 1 or (false and 0 < 0)"))
    (BoolVal false) (eval (of_string "(2 > 1 or false) and 0 < 0"))
    (BoolVal true) (eval (of_string "(2 > 1) or (((false)) and (0 < 0))"))
   *)

  (*$>*)
end

let () =
  let string_of_pos p =
    if p < 0 then "at end of input" else
    if p = 0 then "at beginning of input" else
    ("at column #"^ string_of_int (p + 1))
  in
  Printexc.register_printer (function
    | Token.Read_error p ->
        Some (
          "Reading error "^ string_of_pos p)
    | Expr.Parse_error (p, err) ->
        Some (
          Printf.sprintf "Parse error %s: %s" (string_of_pos p) err)
    | Expr.Eval_error (err, expr) ->
        Some (
          Printf.sprintf "%s for %s" err (Expr.to_string expr))
    | _ ->
        None)
