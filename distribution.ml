type t = unit -> float

let chi_squared k =
  ignore k ;
  fun () -> 0.5

let binomial ~p ~n =
  ignore p ;
  ignore n ;
  fun () -> 0.5
