include Condition

exception Timeout

external timed_wait_noexc: t -> Mutex.t -> float -> bool = "caml_condition_timedwait"

let timed_wait t mut timeo =
  if timed_wait_noexc t mut timeo then raise Timeout
