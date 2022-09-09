(* A Module with a private type and custom printer, used
   to customize printing of various protocolar fields such as
   TCP ports and so on. A little convoluted but we gain:
   - the toplevel don't mix TCP ports with ETH protocol fields
     and can display them differently;
   - the programmer can't confuse the two either or will be told
     by the compiler. *)
open Batteries

module type S =
sig
    type t
    type outer_t
    val to_string : t -> string
    val print : Format.formatter -> t -> unit
    val printf : unit BatInnerIO.output -> t -> unit
    val o : outer_t -> t
end

module Make (Outer : sig
    type t
    val to_string : t -> string
    val is_valid : t -> bool
    val repl_tag : string
end) : S with type t = private Outer.t and type outer_t = Outer.t =
struct
    type t = Outer.t
    type outer_t = Outer.t
    let to_string = Outer.to_string
    let print fmt t = Format.fprintf fmt "@{<%s>%s@}" Outer.repl_tag (to_string t)
    let printf oc t = String.print oc (to_string t)

    let o t =
      if not (Outer.is_valid t) then (
        Printf.eprintf "Invalid value for type %S\n%!" Outer.repl_tag ;
        assert false
      ) ;
      t
end
