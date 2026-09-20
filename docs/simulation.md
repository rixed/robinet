# The simulation document

A *document* is a network written down: the file the administration interface
saves, and the file `robinet` runs.

```
% robinet examples/packet-pair.json          # run that network
% robinet --ui examples/packet-pair.json     # and watch it in a browser
% robinet --admin                            # an empty one, to build in the UI
```

It holds the network and nothing of the simulation running it: no clock, no
counters, nothing that was going on. It is JSON, indented when saved, and meant
to be read and edited by hand as much as by the interface.

This describes what goes in one. The wire schema is in
[openapi.yaml](openapi.yaml) (`Topology`); the catalogue of devices is
`device.ml`, which is the one place a device type is declared, and the one
place to look when this file has gone stale.

## The whole of it

```json
{
  "version": 1,
  "name": "two-hosts",
  "devices": [ ... ],
  "startup": [ ... ]
}
```

| key | meaning |
| --- | --- |
| `version` | Currently 1. Bumped only when an older robinet would read a newer document *wrongly* rather than merely incompletely. |
| `name` | What the network is called. A label: loading renames nothing. `robinet` names the simulation after it, or after the file when it is blank. |
| `devices` | Everything the network is made of, in the order it must be built. |
| `startup` | What to ask of it once it stands. May be left out; see below. |

Loading is all or nothing for the shape of the network: a device that cannot be
built takes the whole load with it and leaves the simulation empty. A *property*
that will not take is a different matter — it is reported and skipped, and the
network still loads, because it is still the network that was asked for.

## A device

```json
{ "type": "host",
  "path": "h1",
  "at": { "lat": 48.8566, "lon": 2.3522 },
  "params": { "static-ip": "192.168.0.1" },
  "properties": { "eth": { "loss": 0.01 } } }
```

| key | meaning |
| --- | --- |
| `type` | A catalogue entry: `host`, `switch`, `hub`, `router`, `gateway`, `portal`, `recorder`, `replayer`, `synthesizer`, `cable`, `note`. |
| `path` | Where it sits, relative to the simulation's root. The last component is its own name, the rest its parent — `"h1"` at the root, `"rack/h1"` inside something already listed. |
| `at` | Where it is in the world, or `null`. Beside the parameters and not among them: a place is not something a device is configured with. |
| `params` | What it is built with (below). Anything left out takes its default. |
| `properties` | What it is configured with, once built (below). |

Only `type` and `path` are required. `at`, `params` and `properties` may be
left out entirely when there is nothing to say — written `null` means the same
— which is what the examples below do. A save from the interface writes all
five all the same: what it writes is what it read.

**Order matters.** Devices are built in the order they are listed, and each is
configured as it is built, so a cable must come after both of the things it
joins. That order is also what makes a cable negotiate against what its two
interfaces advertise: negotiation happens when a cable is plugged, and a cable
is always younger than both its ends.

## How values are written

| kind | written as | example |
| --- | --- | --- |
| optional anything | `null` for nothing | `"caplen": null` |
| address, netmask, MAC, CIDR | a string | `"192.168.0.1"`, `"02:52:01:00:00:01"`, `"192.168.0.0/24"` |
| one of a list of choices | its number | `"speed": 1` (100Mbps) |
| several of them | a list of numbers | `"speeds": [0, 1, 2, 3, 4]` |
| a duration | seconds, as a number | `"interval": 1.0` |
| a length | meters | `"length": 10.0` |
| a gateway | a MAC *or* an IP, whichever it reads as | `"via": "203.0.113.5"` |
| one end of a cable | the **path** of a device in this document | `"from": "h1"` |

A cable's ends are widget ids over the API and paths in a document: the file
describes a network and not one instance of one, and must load into a
simulation whose widgets were built afresh.

Ethernet speeds are numbered `0`–`8`: 10Mbps, 100Mbps, 1Gbps, 2.5Gbps, 5Gbps,
10Gbps, 25Gbps, 40Gbps, 100Gbps. A hub accepts the first two only.

A router's `load balancing` is numbered `0`–`3`: first matching, track flow,
random, round robin. It says which of the routes that matched a packet actually
carries it — see *Routing tables* below.

## The catalogue

What a device is *built* with is a short list — the few things one is asked for
when buying the real thing. Everything else is a property, set afterwards on the
thing itself.

### host

A machine with a single network adapter. With `static-ip` it is configured
statically; without one it goes looking for a DHCP server.

| param | kind | default | |
| --- | --- | --- | --- |
| `static-ip` | optional string | `null` | Its address, or DHCP when left out. |
| `netmask` | optional string | `"255.255.255.0"` | What it can reach without a gateway. A DHCP client is told by its lease and has this only to fall back on. |
| `gateway` | optional string | `null` | Where to send what the netmask does not cover. |
| `nameserver` | optional string | `null` | Which DNS server to ask. |
| `search suffix` | optional string | `null` | Appended to the names it resolves. |
| `MAC` | optional string | `null` | Drawn at random when left out. |

### switch

Forwards frames to the port it last saw their destination on.

| param | kind | default | |
| --- | --- | --- | --- |
| `ports` | 2…1024 | `8` | How many cables it takes. |
| `speeds` | list of speeds | `[0,1,2,3,4]` | What every port advertises. |
| `full duplex` | bool | `true` | |
| `MACs` | 1…1000000 | `1024` | How many addresses it remembers at once. |

### hub

A repeater: whatever reaches one port leaves by every other.

| param | kind | default | |
| --- | --- | --- | --- |
| `ports` | 2…1024 | `8` | |
| `speed` | `0` (10Mbps) or `1` (100Mbps) | `1` | One fixed speed, as a real repeater has. |

### router

Forwards packets between its interfaces. It arrives with an **empty routing
table** and interfaces with no address: where a packet goes is configuration,
not something the machine is built with. See *Routing tables* below.

| param | kind | default | |
| --- | --- | --- | --- |
| `ports` | 1…1024 | `4` | Interfaces, one cable each. |
| `MAC range` | string | `""` | Leading octets every interface's address shares (`"00:11:22"`), the rest drawn at random. |
| `MACs` | string | `""` | The addresses themselves instead, comma separated, one per port. |

### gateway

A router with a NAT, a DHCP server and a resolver behind it. **Port 0 is the
outside, port 1 the network it serves.**

| param | kind | default | |
| --- | --- | --- | --- |
| `public address` | string | `"192.0.2.1"` | What it is known by outside, and what it translates its LAN to. |
| `public netmask` | optional string | `null` | Left out, everything outside is directly reachable — right for a gateway plugged into a LAN of real machines, wrong for one hanging off a router. |
| `public gateway` | optional string | `null` | Where to send what that netmask does not cover, as an IP or a MAC. |
| `LAN` | string | `"192.168.0.0/24"` | The network behind it. Its **first** address is the gateway itself, the **second** the server that hands out the rest, and the pool starts at the third. |
| `max connections` | 1…1000000 | `500` | Translations its NAT holds at once. |
| `MAC` | optional string | `null` | Its address on the LAN side, which is the one the machines behind it send to. |

Only the server (`.2`) answers pings: the gateway's own LAN address lives on a
router interface, and a router interface answers for an address only when its
routing table says so.

### portal

Opens a real interface of the machine and exchanges packets with the real world.
**The portal's name is the interface's name.** Switching it on opens the
interface, so the interface must exist by then — `robinet --portals=veth` makes
a namespace and a veth pair for every portal of every document it loads. A
portal turns its simulation over to the wall clock.

| param | kind | default | |
| --- | --- | --- | --- |
| `promisc` | bool | `true` | |
| `filter` | string | `""` | pcap filter for what to capture. |
| `caplen` | optional 1…65535 | `null` | Defaults to the interface MTU. |

### recorder

Writes every packet that reaches it into a pcap file. One port. It has no power
switch: naming a file opens it and starts the recording, and emptying the name
ejects it.

| param | kind | default | |
| --- | --- | --- | --- |
| `file name` | optional string | `null` | A file in the pcap library, `/tmp` by default. Nothing is recorded until there is one. |
| `caplen` | optional 1…65535 | `null` | |
| `DLT` | optional int | `1` | 1 is EN10MB. |

### replayer

The dual of a recorder: plays a pcap file into whatever is plugged into it. No
power switch either; it is started with the `start replay` action.

| param | kind | default | |
| --- | --- | --- | --- |
| `file name` | optional string | `null` | A file in the pcap library. |
| `loop` | bool | `false` | Start again from the beginning at the end. |

### synthesizer

A traffic generator: emits a stream of packets it makes up. What it emits is
three properties — see *The packet synthesizer* below.

| param | kind | default | |
| --- | --- | --- | --- |
| `adapters` | 1…1024 | `1` | Ethernet adapters, one cable each. All are driven by the same generators. |
| `speeds` | list of speeds | `[0,1,2,3,4]` | |
| `independent` | bool | `false` | Whether every adapter draws its own values rather than emitting the very same packets. |

### cable

Joins two devices, and delays and corrupts what crosses it. The one device that
cannot exist on its own, which is why its two ends are parameters: a cable with
one end loose is not a cable that needs finishing, it is nothing at all.

| param | kind | default | |
| --- | --- | --- | --- |
| `from`, `to` | path | — | The two devices. |
| `from port`, `to port` | optional int | `null` | Which port of each; left out, the first free one. |
| `length` | optional meters | `null` | Left out, the distance between the two points on the map — and nothing at all when either end is not placed. |
| `error rate` | 0…1 | `0.0` | Faulty bits per bit transmitted. |

### note

Something written on the map: no ports, no power, nothing to simulate.

| param | kind | default | |
| --- | --- | --- | --- |
| `text` | string | `""` | |

## Properties

Parameters build a device; properties configure it. They are keyed by the path
of the widget that carries them **relative to the device**, the empty string
being the device itself:

```json
"properties": {
  "": { "routes": [ ... ] },
  "nat": { "port forwards": [ ... ] },
  "#0": { "loss": 0.01 }
}
```

The parts too, because that is where much of the configuration lives: a
router's interfaces are `#0`, `#1`…, a host's adapter is `eth`, a
synthesizer's are `eth0`, `eth1`…, and a gateway is a whole box of parts.

Only what can be set is worth writing: metrics, and answers that are worked out
rather than chosen, a save leaves out. What each holds, by the path it is
under:

| device | path | properties |
| --- | --- | --- |
| host | `""` | `static-ip`, `static-netmask`, `nameserver`, `hostname`, `search suffix` |
| | `eth` | *its adapter* |
| switch | `""` | `cut-through` |
| | `#0`… | *its ports* |
| hub | `""` | `speed` |
| router | `""` | `routes`, `errors probability`, `errors delay`, `cut-through bytes`, `load balancing`, `reroute admin` |
| | `#0`… | *its interfaces* |
| | `#0/admin@0`… | `hostname`, `search suffix` — the stack answering for the address that interface holds |
| gateway | `router`, `router/#0`, `router/#1` | *a router and its two interfaces* |
| | `nat` | `min port`, `port forwards`, `NAT pings`, `send errors`, `answer pings` |
| | `srv`, `srv/eth` | *the host it serves DHCP and DNS from* |
| | `srv/dhcpd` | `authoritative`, `lease time`, `netmask`, `broadcast`, `gateway`, `DNS`, `NTP`, `domain name`, `MTU` |
| | `srv/named` | `default TTL` |
| | `hub` | `speed` — what joins the three inside |
| recorder | `""` | `file name`, `recording` |
| replayer | `""` | `file name`, `loop` |
| synthesizer | `""` | `emitting`, `generators`, `stream`, `packet`, `independent` |
| | `eth0`… | *its adapters* |
| cable | `""` | `length`, `error rate` |
| note | `""` | `text` |

*An Ethernet adapter* is `speeds`, `full-duplex` and `inter-frame-gap`, and on
one with an IP stack above it also `gateways`, `delay` and `loss` — a loss of
0.01 drops one frame in a hundred, which is how a machine is made to misbehave
without touching the cable. Its MAC is a parameter of the device it belongs to,
not a property: an address is not something a running machine is reconfigured
with.

The current list for anything is one request away — `GET
/api/simulations/<s>/widgets/<w>/properties` gives each one's name, kind,
description and whether it can be set just now — and saving a network from the
interface writes out exactly what can be read back, which is the table above.

Properties are restored in the order they are written, which matters where one
is read against another: a synthesizer's `generators` must come before the
`stream` and `packet` that name them.

### Routing tables

A router's `routes` is a list of rows, tried **in order**, first match wins. Any
of the tests may be `null`, which is no test at all:

```json
{ "input port": 0, "src mask": null, "dst mask": "10.0.1.1/24",
  "ip proto": null, "src port": null, "dst port": null,
  "output port": null, "via": null }
```

| field | |
| --- | --- |
| `input port` | Only packets that came in there. |
| `src mask`, `dst mask` | CIDR the address must fall in. |
| `ip proto` | 0…255 (6 TCP, 17 UDP, 1 ICMP). |
| `src port`, `dst port` | `"80"`, `"1024-65535"`, `"1024-"`, `"-1023"`. |
| `output port` | Where it goes… |
| `via` | …and through which gateway, as an IP or a MAC. `null` for directly. |

Several rows may match one packet, and `load balancing` says which of them
takes it: the first (the default), the one the source and destination hash to
(so that a flow keeps its path), one at random, or each in turn. Write the same
destination several times, once per outgoing link, and that is how a router is
given more than one way there.

**`"output port": null` is not a route to nowhere: it is a route to the router
itself** — and it is where a router gets its address. The first such row that
applies to an interface gives that interface the address *and the netmask* of
its `dst mask`. So `"dst mask": "10.0.1.1/24"` with `"input port": 0` makes
interface 0 answer for 10.0.1.1 and treat 10.0.1.0/24 as directly reachable,
while `"10.0.1.1/32"` would make it answer for the same address and need a
`via` to reach anything at all. That is the shape to use between routers, where
every hop is named explicitly.

### The packet synthesizer

Three properties, which must be written in this order:

`generators` — named integer generators, so the same drawn value can be used in
several places:

```json
[ { "name": "payload size",
    "generator": { "uniform": { "from": 960, "up to (excluded)": 1000 } } } ]
```

One of `{"constant": n}`, `{"increment": {"start": n, "step": n}}`,
`{"uniform": {"from": n, "up to (excluded)": n}}`,
`{"normal": {"mean": f, "standard deviation": f}}`.

`stream` — how many and how far apart:

```json
{ "stop after": 2, "distance": null, "distance from end": true }
```

`stop after` is `null` for forever. `distance` is a number of **bits** to the
next packet, or `null` for back to back — which is also the floor, since a port
cannot start a frame before it has finished the one before it.

`packet` — a stack of layers, outermost first, each field a constant
(`{"const": v}`), a generator (`{"gen": "its name"}`), or `null` for automatic:

```json
[ { "name": "Eth",  "fields": { "source": { "const": "00:11:22:33:44:01" },
                                "destination": { "const": "00:11:22:33:44:02" },
                                "protocol": null, "payload": null } },
  { "name": "Ip",   "fields": { "source": { "const": "10.0.0.1" },
                                "destination": { "const": "10.0.0.2" },
                                "protocol": null, "time to live": null, ... } },
  { "name": "Udp",  "fields": { "source port": { "const": 40000 },
                                "destination port": { "const": 7 },
                                "length": null, "checksum": null,
                                "payload": null } },
  { "name": "Data", "fields": { "gen": "payload size" } } ]
```

An automatic value is a *plausible* one and not any the field could hold: a
protocol number says what is above it, a length counts what is below, a TTL is
64, an IP id is the previous packet's plus one. `Data` is the raw bottom layer
and its whole `fields` is one value: from a generator, it is that many random
bytes. Layer names are `Eth`, `Arp`, `Ip`, `Ip6`, `Udp`, `Tcp`, `Icmp`, `Dns`,
`Dhcp`, `Vlan`, `Sll`, `Pcap`, `Data`; a field left out of `fields` is refused,
so write them all, `null` for the ones to leave alone.

A synthesizer emits nothing until `emitting` is set. Set in a document, it
starts when the box is switched on.

## The startup list

A document says what a network is *made of*; the startup list says what is to
be *done* to it, once all of it stands and is answering.

```json
"startup": [
  { "path": "h1", "action": "power on" },
  { "path": "h1", "action": "ping",
    "params": { "target": "192.168.0.2", "count": 3 } }
]
```

`path` and `action` are required, `params` only when the action takes some.
The path is relative to the simulation's root — a path and not an id, since the
list outlives the process that wrote it. The entries run in order, at one
instant of the clock.

**Every box is born dark**, and what switches it on is its `power on` here. So:

- **An empty or absent `startup` means the power-ons the devices registered as
  they were built** — one for each, in the order they were built. That is what a
  document written before there was a startup list meant, and it is the sane
  default.
- **A list that is present replaces that entirely.** Write one, and every box
  you leave out stays off. The easiest way to get a correct one is to let
  robinet write it: load the document with `"startup": []`, then read
  `GET /api/simulations/<s>/startup`, or save the network from the interface.

What can be asked:

| action | of | params |
| --- | --- | --- |
| `power on`, `power off` | anything with a power switch of its own: hosts, switches, hubs, routers, gateways, portals, synthesizers and **cables** (but not recorders, replayers or notes) | — |
| `ping` | a host | `target` (address or name), `count` (3), `interval` secs (1), `timeout` secs (4) |
| `start replay`, `stop replay` | a replayer | — |

`GET /api/simulations/<s>/widgets/<w>/actions` lists what one widget will
answer to, and what each takes.

Two things to know before putting much in a list:

- **Routers and gateways switch themselves on when built**, so their `power on`
  runs against a box that is already on and says `cannot power on just now`.
  Harmless, and the entry is worth keeping: it is what will switch them on the
  day they stop doing it themselves.
- **The list runs at time zero**, so anything that has to wait cannot be asked
  here. A DHCP client waits a few seconds before its first request, so a `ping`
  in the list goes out before the host has an address. Give it a `count` large
  enough to outlive the wait, or ask from the interface once the network has
  settled.

## Examples

Each of these runs as it stands. Start with `robinet --ui <file>` to watch, or
`robinet --speed=max <file>` to let it go as fast as it will.

### Two hosts on a cable

```json
{
  "version": 1,
  "name": "two-hosts",
  "devices": [
    { "type": "host", "path": "h1",
      "params": { "static-ip": "192.168.0.1" } },
    { "type": "host", "path": "h2",
      "params": { "static-ip": "192.168.0.2" } },
    { "type": "cable", "path": "h1-h2",
      "params": { "from": "h1", "to": "h2" } }
  ],
  "startup": [
    { "path": "h1", "action": "power on" },
    { "path": "h2", "action": "power on" },
    { "path": "h1-h2", "action": "power on" },
    { "path": "h1", "action": "ping",
      "params": { "target": "192.168.0.2", "count": 3 } }
  ]
}
```

The ping's result — `{"sent": 3, "received": 3, ...}` — is on h1's page in the
interface, and in `GET /api/simulations/0/actions`.

### Three hosts on a switch

The cables say neither port, so each takes the first one free.

```json
{
  "version": 1,
  "name": "one-switch",
  "devices": [
    { "type": "switch", "path": "sw",
      "params": { "ports": 4 } },
    { "type": "host", "path": "h1",
      "params": { "static-ip": "192.168.0.1" } },
    { "type": "host", "path": "h2",
      "params": { "static-ip": "192.168.0.2" } },
    { "type": "host", "path": "h3",
      "params": { "static-ip": "192.168.0.3" } },
    { "type": "cable", "path": "sw-h1",
      "params": { "from": "sw", "to": "h1" } },
    { "type": "cable", "path": "sw-h2",
      "params": { "from": "sw", "to": "h2" } },
    { "type": "cable", "path": "sw-h3",
      "params": { "from": "sw", "to": "h3" } }
  ],
  "startup": [
    { "path": "sw", "action": "power on" },
    { "path": "h1", "action": "power on" },
    { "path": "h2", "action": "power on" },
    { "path": "h3", "action": "power on" },
    { "path": "sw-h1", "action": "power on" },
    { "path": "sw-h2", "action": "power on" },
    { "path": "sw-h3", "action": "power on" },
    { "path": "h1", "action": "ping",
      "params": { "target": "192.168.0.3", "count": 2 } }
  ]
}
```

### A host behind a gateway, by DHCP

No `static-ip`, so the host asks. It is leased 192.168.0.3, the third address of
the LAN, and told its gateway and its resolver. The ping is aimed at the server
inside the gateway (`.2`, not `.1`) and asks for eight, because the first few go
out before the lease: expect `{"sent": 8, "received": 4}`.

```json
{
  "version": 1,
  "name": "a-gateway",
  "devices": [
    { "type": "gateway", "path": "gw",
      "params": { "public address": "192.0.2.1", "LAN": "192.168.0.0/24" } },
    { "type": "host", "path": "h" },
    { "type": "cable", "path": "gw-h",
      "params": { "from": "gw", "to": "h", "from port": 1 } }
  ],
  "startup": [
    { "path": "gw", "action": "power on" },
    { "path": "h", "action": "power on" },
    { "path": "gw-h", "action": "power on" },
    { "path": "h", "action": "ping",
      "params": { "target": "192.168.0.2", "count": 8 } }
  ]
}
```

### A tap

A hub repeats everything to every port, so a recorder on one of them sees the
whole segment. This writes `/tmp/a-tap.pcap`: two ARP frames and four ICMP.

```json
{
  "version": 1,
  "name": "a-tap",
  "devices": [
    { "type": "hub", "path": "hub",
      "params": { "ports": 3 } },
    { "type": "host", "path": "h1",
      "params": { "static-ip": "192.168.0.1" } },
    { "type": "host", "path": "h2",
      "params": { "static-ip": "192.168.0.2" } },
    { "type": "recorder", "path": "tap",
      "params": { "file name": "a-tap.pcap" } },
    { "type": "cable", "path": "hub-h1",
      "params": { "from": "hub", "to": "h1" } },
    { "type": "cable", "path": "hub-h2",
      "params": { "from": "hub", "to": "h2" } },
    { "type": "cable", "path": "hub-tap",
      "params": { "from": "hub", "to": "tap" } }
  ],
  "startup": [
    { "path": "hub", "action": "power on" },
    { "path": "h1", "action": "power on" },
    { "path": "h2", "action": "power on" },
    { "path": "hub-h1", "action": "power on" },
    { "path": "hub-h2", "action": "power on" },
    { "path": "hub-tap", "action": "power on" },
    { "path": "h1", "action": "ping",
      "params": { "target": "192.168.0.2", "count": 2 } }
  ]
}
```

### Two routers

Two LANs, a link between them, and a host on each. Every router row of the
first two kinds gives an interface its address; the last two say where the two
networks are. The `/30` between the routers is what lets each reach the other
directly; the `/24`s are what let each reach its own host.

```json
{
  "version": 1,
  "name": "two-routers",
  "devices": [
    { "type": "router", "path": "r1",
      "params": { "ports": 2 },
      "properties": { "": { "routes": [
        { "input port": 0, "src mask": null, "dst mask": "10.0.1.1/24",
          "ip proto": null, "src port": null, "dst port": null,
          "output port": null, "via": null },
        { "input port": 1, "src mask": null, "dst mask": "10.0.0.1/30",
          "ip proto": null, "src port": null, "dst port": null,
          "output port": null, "via": null },
        { "input port": null, "src mask": null, "dst mask": "10.0.1.0/24",
          "ip proto": null, "src port": null, "dst port": null,
          "output port": 0, "via": null },
        { "input port": null, "src mask": null, "dst mask": "10.0.2.0/24",
          "ip proto": null, "src port": null, "dst port": null,
          "output port": 1, "via": "10.0.0.2" } ] } } },
    { "type": "router", "path": "r2",
      "params": { "ports": 2 },
      "properties": { "": { "routes": [
        { "input port": 0, "src mask": null, "dst mask": "10.0.0.2/30",
          "ip proto": null, "src port": null, "dst port": null,
          "output port": null, "via": null },
        { "input port": 1, "src mask": null, "dst mask": "10.0.2.1/24",
          "ip proto": null, "src port": null, "dst port": null,
          "output port": null, "via": null },
        { "input port": null, "src mask": null, "dst mask": "10.0.2.0/24",
          "ip proto": null, "src port": null, "dst port": null,
          "output port": 1, "via": null },
        { "input port": null, "src mask": null, "dst mask": "10.0.1.0/24",
          "ip proto": null, "src port": null, "dst port": null,
          "output port": 0, "via": "10.0.0.1" } ] } } },
    { "type": "host", "path": "h1",
      "params": { "static-ip": "10.0.1.2", "netmask": "255.255.255.0",
                  "gateway": "10.0.1.1" } },
    { "type": "host", "path": "h2",
      "params": { "static-ip": "10.0.2.2", "netmask": "255.255.255.0",
                  "gateway": "10.0.2.1" } },
    { "type": "cable", "path": "r1-h1",
      "params": { "from": "r1", "to": "h1", "from port": 0 } },
    { "type": "cable", "path": "r1-r2",
      "params": { "from": "r1", "to": "r2", "from port": 1, "to port": 0 } },
    { "type": "cable", "path": "r2-h2",
      "params": { "from": "r2", "to": "h2", "from port": 1 } }
  ],
  "startup": [
    { "path": "r1", "action": "power on" },
    { "path": "r2", "action": "power on" },
    { "path": "h1", "action": "power on" },
    { "path": "h2", "action": "power on" },
    { "path": "r1-h1", "action": "power on" },
    { "path": "r1-r2", "action": "power on" },
    { "path": "r2-h2", "action": "power on" },
    { "path": "h1", "action": "ping",
      "params": { "target": "10.0.2.2", "count": 3 } }
  ]
}
```

### A generator

Two UDP datagrams of a hundred-odd random bytes, back to back, from a made-up
machine to a real one, with a recorder watching. `emitting` is set in the
document, so it starts when the box is switched on.

```json
{
  "version": 1,
  "name": "a-generator",
  "devices": [
    { "type": "hub", "path": "hub",
      "params": { "ports": 3 } },
    { "type": "host", "path": "h",
      "params": { "static-ip": "10.0.0.2", "netmask": "255.255.255.0",
                  "MAC": "00:11:22:33:44:02" } },
    { "type": "synthesizer", "path": "gen",
      "params": { "adapters": 1 },
      "properties": { "": {
        "generators": [
          { "name": "payload size",
            "generator": { "uniform": { "from": 100,
                                        "up to (excluded)": 200 } } } ],
        "stream": { "stop after": 2, "distance": null,
                    "distance from end": true },
        "packet": [
          { "name": "Eth",
            "fields": { "source": { "const": "00:11:22:33:44:01" },
                        "destination": { "const": "00:11:22:33:44:02" },
                        "protocol": null, "payload": null } },
          { "name": "Ip",
            "fields": { "type of service": null, "total length": null,
                        "id": null, "don't fragment": { "const": false },
                        "more fragments": null, "fragment offset": null,
                        "time to live": null, "protocol": null,
                        "source": { "const": "10.0.0.1" },
                        "destination": { "const": "10.0.0.2" },
                        "options": null, "payload": null } },
          { "name": "Udp",
            "fields": { "source port": { "const": 40000 },
                        "destination port": { "const": 7 },
                        "length": null, "checksum": null, "payload": null } },
          { "name": "Data", "fields": { "gen": "payload size" } } ],
        "independent": false,
        "emitting": true } } },
    { "type": "recorder", "path": "tap",
      "params": { "file name": "a-generator.pcap" } },
    { "type": "cable", "path": "hub-h",
      "params": { "from": "hub", "to": "h" } },
    { "type": "cable", "path": "hub-gen",
      "params": { "from": "hub", "to": "gen" } },
    { "type": "cable", "path": "hub-tap",
      "params": { "from": "hub", "to": "tap" } }
  ],
  "startup": [
    { "path": "hub", "action": "power on" },
    { "path": "h", "action": "power on" },
    { "path": "gen", "action": "power on" },
    { "path": "hub-h", "action": "power on" },
    { "path": "hub-gen", "action": "power on" },
    { "path": "hub-tap", "action": "power on" }
  ]
}
```

### Playing a capture back

What the previous example recorded, played into another network. A replayer has
no power switch: `start replay` is what sets it going.

```json
{
  "version": 1,
  "name": "a-replay",
  "devices": [
    { "type": "hub", "path": "hub",
      "params": { "ports": 3 } },
    { "type": "replayer", "path": "play",
      "params": { "file name": "a-generator.pcap", "loop": false } },
    { "type": "recorder", "path": "tap",
      "params": { "file name": "a-replay.pcap" } },
    { "type": "cable", "path": "hub-play",
      "params": { "from": "hub", "to": "play" } },
    { "type": "cable", "path": "hub-tap",
      "params": { "from": "hub", "to": "tap" } }
  ],
  "startup": [
    { "path": "hub", "action": "power on" },
    { "path": "hub-play", "action": "power on" },
    { "path": "hub-tap", "action": "power on" },
    { "path": "play", "action": "start replay" }
  ]
}
```

### A whole one

`examples/packet-pair.json` puts most of this together: ten routers across an
ocean, two NATed LANs, a hub and a recorder on each, and a generator on one of
them sending two frames under its neighbour's address, through both NATs, to
the machine at the far end. The two captures are the same two frames seen from
either side, which is what makes the translation visible: they leave as
192.168.10.3 and arrive as 198.51.100.1.

## See also

- [openapi.yaml](openapi.yaml) — the administration API, and the schema of
  everything above.
- `device.ml` — the catalogue: the one place a device type is declared.
- `examples/` — documents to start from.
