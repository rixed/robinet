(* vim:sw=4 ts=4 sts=4 expandtab
   Display the HTML structure of a file containing HTML.
*)
open Batteries
open Bitstring
open Tools

let main =
    Arg.parse [] (fun f ->
        let str = file_content f in
        match Html.parse str with
        | None -> Printf.fprintf stderr "Cannot parse file '%s'\n" f
        | Some tree ->
            Printf.printf "File %s:\n%a" f (Html.print_tree ~level:0) tree)
        "Load an HTTP server by simulating browsing" ;

