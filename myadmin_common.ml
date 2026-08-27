(* vim:sw=4 ts=4 sts=4 expandtab spell spelllang=en
*)
(* Copyright 2012, Cedric Cellier
 *
 * This file is part of RobiNet.
 *
 * RobiNet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RobiNet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with RobiNet.  If not, see <http://www.gnu.org/licenses/>.
 *)
(**
  Helpers shared by the MyAdmin page handlers.
*)
open Batteries

let debug = false

let to_js_string s =
    "'"^ s ^"'"  (* TODDO *)

let page_head_open resp =
    Printf.fprintf resp {|<?xml version="1.0"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
    <meta charset="utf-8">
    <title>RobiNet: MyAdmin</title>
|}

let page_head_close resp =
    Printf.fprintf resp {|</head>
<div>
    <a href="home.html">home</a>
    <a href="metrics.html">metrics</a>
    <a href="logs.html">logs</a>
</div>
|}

let page_head resp =
    page_head_open resp ;
    page_head_close resp

let selected = " selected"
