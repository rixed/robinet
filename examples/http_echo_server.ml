(* vim:sw=4 ts=4 sts=4 expandtab
   Small HTTP server for tests
*)
open Batteries
open Bitstring
open Tools

let run port =
    let host = Localhost.make () in
    (* Start server *)
    let resources =
        [ Str.regexp "/static/\\([^/]+/[^/]+\\)/\\(.*\\)$", Opache.static_file_server "./" ;
          Str.regexp ".*", Opache.it_works ] in
    Opache.serve host port (Opache.multiplexer resources) ;
    Myadmin.make host (port+1) ;
    (* Run everything *)
    Lwt.join [ Clock.run () ]

let main =
    let port = ref 80 in
    Arg.parse [ "-port",   Arg.Set_int port,      "TCP port to listen to (default: 80)" ]
              (fun _ -> raise (Arg.Bad "unknown parameter"))
              "Start a dummy http server" ;
    Random.self_init () ;
    Lwt_main.run (
        Lwt.choose [
            run !port ;
            Myadmin.report_thread 10.
        ]
    )

