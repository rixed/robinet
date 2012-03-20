(* vim:sw=4 ts=4 sts=4 expandtab
*)

let _ =
    let ok =
        Opache.check () &&
        Ip.check () &&
        Tools.check () &&
        Http.check () &&
        Peg.check () &&
        Fifo.check () &&
        Html.check () &&
        Url.check () &&
        Browser.check () in
    exit (if ok then 0 else 1)
