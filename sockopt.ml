(* setsockopts missing from the stdlib: *)
open Tools

external set_ttl_ : int (* filedescr *) -> int (* TTL *) -> unit = "wrap_set_ttl"

let set_ttl fd ttl =
  set_ttl_ (int_of_fd fd) ttl

external set_tos_ : int (* filedescr *) -> int (* TOS *) -> unit = "wrap_set_tos"

let tos_lowcost = 0x02
let tos_reliability = 0x04
let tos_throughput = 0x08
let tos_lowdelay = 0x10

let set_tos fd tos =
  set_tos_ (int_of_fd fd) tos

external set_df_ : int (* filedescr *) -> unit = "wrap_set_df"

let set_df fd =
  set_df_ (int_of_fd fd)
