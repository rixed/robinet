RobiNet
=======

RobiNet is a simple but flexible network simulator.
A mix of Scapy (for the simple packet manipulation), a packet generator à la Spirent's Avalanche, aimed at whole network simulation.

Written in OCaml so that, if it's not as feature-full as Scapy it won't at least
be as slow.
Performance wise, the goal is in the hundreds of routers/hosts.

Usage
=====

1. Using the WEB UI:

Run `robinet --admin` and open the URL that will be displayed.

Exemple with the `examples/two-continents.json` example topology:

[Screenshot](screenshot.png)

2. Using the REPL:

```
# let itf = Pcap.openif "wlp59s0";;
val itf : Pcap.iface_handler =
  {Pcap.pcap = <abstr>; name = "wlp59s0"; caplen = 1500}
# let pkt = Pcap.sniff itf;;
val pkt : Pcap.Pdu.t =
  {Pcap.Pdu.source_name = "wlp59s0"; caplen = 94; wirelen = 94; dlt = 1l;
   ts = 1790069808.47518492; payload = <abstr>}
# Packet.Pdu.unpack pkt;;
- : Packet.Pdu.layer list =
[Packet.Pdu.Pcap
  {Pcap.Pdu.source_name = "wlp59s0"; caplen = 94; wirelen = 94; dlt = 1l;
   ts = 1790069808.47518492; payload = <abstr>};
 Packet.Pdu.Eth
  {Eth.Pdu.src = <abstr>; dst = <abstr>; proto = 34525; payload = <abstr>};
 Packet.Pdu.Ip6
  {Ip6.Pdu.ttl = 255; proto = 58; diff_serv = 0; ecn = 0; flow_label = 0;
   src = <abstr>; dst = <abstr>; payload = <abstr>};
 Packet.Pdu.Raw <abstr>]
```

3. Using the library:

See [examples](https://github.com/rixed/robinet/tree/master/examples).

4. Using the API:

See [the doc](https://github.com/rixed/robinet/blob/master/docs/openapi.yaml).

5. Using a file:

Description of a simulation can be written in a JSON file.
See [the doc](https://github.com/rixed/robinet/blob/master/docs/simulation.md),
and the examples such as [this one](https://github.com/rixed/robinet/blob/master/examples/transatlantic.json).
