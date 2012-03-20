(* vim:sw=4 ts=4 sts=4 expandtab
   Small HTTP server for tests
*)
open Batteries
open Bitstring
open Tools

let run port root =
    let host = Localhost.make () in
    (* Start server *)
    let resources =
        [ Str.regexp "/\\(.*\\)$", Opache.static_file_server root ] in
    Opache.serve host port (Opache.multiplexer resources) ;
    (* Run everything *)
    Lwt.join [ Clock.run () ]

let main =
    let port = ref 80 and root = ref "./" in
    Arg.parse [ "-port", Arg.Set_int port,    "TCP port to listen to (default: 80)" ;
                "-root", Arg.Set_string root, "Root directory (default: ./)" ]
              (fun _ -> raise (Arg.Bad "unknown parameter"))
              "Start a static file http server" ;
    Random.self_init () ;
    Lwt_main.run (
        Lwt.choose [ run !port !root ]
    )

