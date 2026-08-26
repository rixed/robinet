(* setsockopts missing from the stdlib: *)
open Tools

external set_ttl : Unix.file_descr -> int (* TTL *) -> unit = "wrap_set_ttl"

external set_tos : Unix.file_descr -> int (* TOS *) -> unit = "wrap_set_tos"

let tos_lowcost = 0x02
let tos_reliability = 0x04
let tos_throughput = 0x08
let tos_lowdelay = 0x10

external set_df : Unix.file_descr -> unit = "wrap_set_df"

external set_tcp_syn_count : Unix.file_descr -> int -> unit =
  "wrap_set_tcp_syn_count"

external set_recv_errs : Unix.file_descr -> bool -> unit =
  "wrap_set_recv_errs"

(* Raises Not_found if no error has been received *)
external get_last_icmp_err :
  Unix.file_descr ->
  int (* ICMP err type *) * int (* ICMP err code *) * Unix.inet_addr option (* emitter *) =
  "wrap_get_last_icmp_err"

external htons : int -> int = "wrap_htons"
external ntohs : int -> int = "wrap_ntohs"

(*$= ntohs & ~printer:string_of_int
  0x3412 (ntohs 0x1234)
*)
