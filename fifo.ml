(* vim:sw=4 ts=4 sts=4 expandtab
  A FIFO can have one writter thread and one reader thread,
  the reader being blocked while there is no element to read,
  and one end being destroyed when the other end is.
*)
open Batteries
open Lwt
open Tools

let debug = false

type 'a t =
    { queue : 'a Queue.t ;
      mutable closed : bool ; (* if true, then the writer closed the pipe *)
      mutex : Lwt_mutex.t ;
      condvar : unit Lwt_condition.t }

let create () =
    { queue = Queue.create () ;
      closed = false ;
      mutex = Lwt_mutex.create () ;
      condvar = Lwt_condition.create () }

let add t e =
    Lwt_mutex.with_lock t.mutex (fun () ->
        assert (not t.closed) ;
        Queue.add e t.queue ;
        Lwt_condition.signal t.condvar () ;
        return ())

let close t =
    Lwt_mutex.with_lock t.mutex (fun () ->
        assert (not t.closed) ;
        t.closed <- true ;
        Lwt_condition.signal t.condvar () ;
        return ())

let take t =
    let rec wait_not_empty () =
        if t.closed || not (Queue.is_empty t.queue) then
            return ()
        else
            lwt _ = Lwt_condition.wait ~mutex:t.mutex t.condvar in
            wait_not_empty ()
    in
    Lwt_mutex.with_lock t.mutex (fun () ->
        lwt _ = wait_not_empty () in
        return (if Queue.is_empty t.queue then None else Some (Queue.take t.queue)))

let to_stream fifo =
    BatLazyList.from (fun () ->
        lwt e = take fifo in
        match e with
        | None   -> fail BatLazyList.No_more_elements
        | Some x -> return x)

(* utility to turn a trx into a fifo *)
let of_trx trx_set_recv =
    let q = create () in
    trx_set_recv (fun bits ->
        if bitstring_is_empty bits then Lwt.ignore_result (close q)
        else Lwt.ignore_result (add q bits)) ;
    q

(* Checks *)

let check1 () =
    let res = ref true in
    let writer q =
        lwt _ = Lwt_unix.sleep 0.1 in   (* yield to the reader to check its blocked and resumed as soon as one thing is available *)
        (* First write some things, then close *)
        Printf.printf "Store 0\n%!" ;
        lwt _ = add q 0 in
        Printf.printf "Store 1\n%!" ;
        lwt _ = add q 1 in
        Printf.printf "Close queue\n%!" ;
        close q
    and reader q s =
        let check e a =
            Printf.printf "Got : %a\n%!" (Option.print Int.print) a ;
            if a <> e then res := false in
        (* Sleep a little so that our writer may even close the queue before we start *)
        lwt _ = Lwt_unix.sleep s in
        Printf.printf "Taking one...\n%!" ;
        lwt a = take q in
        check (Some 0) a ;
        lwt a = take q in
        check (Some 1) a ;
        lwt a = take q in
        check None a ;
        lwt a = take q in   (* this should not wait *)
        check None a ;
        return ()
    in
    let q1 = create () and q2 = create ()
    in
    lwt () = join [
        writer q1 ; reader q1 0. ;
        writer q2 ; reader q2 10.
    ] in
    Lwt.return !res

let check () =
    Lwt_main.run (check1 ())

