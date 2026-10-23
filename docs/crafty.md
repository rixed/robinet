# The crafty language

Crafty sends traffic from a real interface and reacts to what comes back: to
check that a port is open, find where packets are lost, measure round trips,
or see how a TCP connection behaves. Packets are crafted to the bit, or made
by crafty's own stacks (ARP, IPv4, TCP, UDP, ICMP, DNS).

## 1. Introduction

### A first program

```
# Three datagrams to a UDP echo server: how many come back?
# "IP", "UDP" and "Bytes" are layers of a protocol stack. Every stack
# starts at the interface, with an "Eth" layer that can be left out:
# /IP(dst=192.0.2.10)/UDP(dst=7) is /Eth/IP(dst=192.0.2.10)/UDP(dst=7).
# Followed by a block, a stack is the current stack of that block:
/IP(dst=192.0.2.10)/UDP(dst=7) {
  answers = 0                     # "answers" is a variable holding integers
  # Repeats the block 3 times, "I" being the loop counter, from 0:
  repeat var=I count=3 every=100ms {
    # Bytes is a terminal layer: it sends the message made from
    # /IP(dst=192.0.2.10)/UDP(dst=7)/Bytes("ping ${I}")
    Bytes("ping ${I}")
    catch {                       # a lost answer is no error
      # expect waits for a packet that matches a pattern; here, any Bytes
      # layer on top of the current stack, coming back:
      expect timeout=1s Bytes {
        answers += 1
        print(MATCH[Bytes].data)  # MATCH is the packet that matched
      }
    }
  }
  print("${answers} answers out of 3")
}
```

```
% sudo crafty -i eth0 --udp 40000-40010 --fw intro.cfty
...
ping 0
ping 1
ping 2
3 answers out of 3
Done after 0.3s, status: OK.
```

A stack is layers and their options, separated by slashes. At its bottom is
always `Eth`, the interface. A leading slash starts a stack there, with `Eth`
or without it (`/IP` is `/Eth/IP`); without a leading slash, a stack goes on
top of the current stack.

Ending with a terminal layer (`Bytes`, `Request`, `Reply`, `Query`,
`Answer`), a stack is a complete message, sent there and then: nothing can
be stacked on top of it, and so it opens no block. Any other stack needs a
block.

The layers of a stack are streams: `UDP` picks its source port once (from
`--udp`), and every message sent and every pattern on top of it are of that
stream.

An `expect` that times out is an error. An error leaves the enclosing
blocks one after the other, until a `catch` drops it or a `retry` runs its
block again; one that reaches the top ends the program.

The language is statically typed.

### Going down the stack

```
# Is anyone listening on UDP port 7?
target = ip_addr(getenv("TARGET"))  # Read the envvar and cast to an IP, or fail
/IP(dst=target)/UDP(dst=7) {
  Bytes("hello")      # two messages on top of the same stack:
  Bytes("world")      # the same stream, from the same port
  # Waits for the first packet that matches either pattern: a datagram
  # back, or the ICMP error a closed port answers with. "../" goes back to
  # /IP(dst=target), and ICMP goes on top of that IP stream instead of
  # UDP: these are the ICMP errors that it receives.
  first timeout=1s Bytes { print(MATCH[Bytes].data) }
    | ../ICMP/DestUnreachable(code == PORT_UNREACHABLE) { print("closed") }
}
```

```
hello
```

With `dst=8`, where nothing listens, it prints `closed`.

Each leading `../` goes back one layer down the current stack: in this
block, `../` goes back to `/IP(dst=target)`, and `../../` to `/Eth`. That
is not `/IP`: an absolute pattern, as `/IP/ICMP/DestUnreachable`, matches
from the interface up, the packets of any stream, whereas `../ICMP` only sees
what comes to the IP stream of this block.

### Overlaying

```
# The same stream, but for one datagram with a TTL of 1:
/IP(dst=192.0.2.10)/UDP(dst=7) {
  Bytes("ttl 64")
  print("Sent from port ${LAST[UDP].src}")   # LAST is the last packet sent
  # ../../ goes back to /Eth, where IP and UDP land on the IP and UDP of
  # the current stack. They overlay them: the same streams, with their
  # options (dst, the ports) unless given. ttl=1 is for this message only.
  ../../IP(ttl=1)/UDP/Bytes("ttl 1")
  print("Also sent from port ${LAST[UDP].src}")
  repeat count=2 {
    expect timeout=1s Bytes { print(MATCH[Bytes].data) }
  }
}
```

```
Sent from port 40000
Also sent from port 40000
ttl 64
ttl 1
```

If we had written an absolute
`/IP(dst=192.0.2.10, ttl=1)/UDP(dst=7)/Bytes("ttl 1")` instead of the
relative `../../IP(ttl=1)/UDP/Bytes("ttl 1")`, that would have created
another UDP stream, from another port, whose answer the `expect` of this
block would not see.

Similarly, if the expect had used an absolute pattern, as in `expect
timeout=1s /IP(src == 192.0.2.10)/UDP/Bytes`, that would have matched *any*
UDP packet from that host, not only those belonging to the current stream.

The rule to remember, for stacks and patterns alike: relative ones stay on
the streams of the current stack (`../` overlaying some of its layers),
whereas absolute ones start anew from `Eth`.

Giving a key of a layer that overlays changes the stream instead: in a block
on `/IP(dst=192.0.2.53)/UDP(dst=53)/DNS`, `../DNS(id=1234)/Query("example.org")`
is a query on the DNS stream of id 1234, on the same UDP stream.

### Manual layers

So far, layers were *self-driven*: crafty resolves addresses with ARP,
connects, retransmits, fragments and reassembles. A bang makes a layer
*manual*, for packets as on the wire: `TCP!(flags=SYN)` is one segment, as
given, the fields left out filled in. On reception, `IP!` sees each fragment
and `TCP!` each segment, even without data.

```
# A SYN of our own, and the SYN-ACK that answers it:
target = 192.0.2.10
{
  # "on" runs its block for each matching packet, while the enclosing
  # block goes on; here, for one SYN-ACK at most, until 1s after the block:
  on max=1 linger=1s /IP(src == target)/TCP!(src == 7 && flags & SYN &&
                                               ack_num > 1000 && ack_num <= 2000) {
    print("SYN-ACK: seq ${MATCH[TCP].seq_num}, ack ${MATCH[TCP].ack_num}")
  }
  # Sends the segment, and waits until it is seen leaving: "seg" is the
  # packet as captured. Only fully manual messages can be captured.
  seg = /IP!(dst=target)/TCP!(src=40000, dst=7, flags=SYN, seq_num=1000)/Bytes()
  print("SYN of seq ${seg[TCP].seq_num} sent")
}
```

```
% sudo crafty -i eth0 --tcp 40000 --fw syn.cfty
SYN of seq 1000 sent
SYN-ACK: seq 1969569245, ack 1001
```

### Running crafty

```
sudo crafty -i eth0 --tcp 40000-40099 --udp 40000-40099 --fw prog.cfty
sudo crafty -i eth0 --ip 192.0.2.5 --udp 40000-40099 prog.cfty
sudo crafty -i eth0 --ip 192.0.2.5 -e '/IP(dst=192.0.2.10)/ICMP/Echo {
  Request("hi")
  expect timeout=1s Reply { print("up") } }'
```

- `-e PROG`: the program itself, rather than a file.
- `-i IFACE`: the interface to send from and capture on. Crafty needs root.
- `--tcp LO-HI`, `--udp LO-HI` (repeatable): the ports to pick source ports
  from, with the program's `PORTS` (see [Budget and ports](#budget-and-ports)).
  A program that sends TCP or UDP without a `src` needs them.
- `--fw`: crafty shares the interface's address with the host, whose kernel
  would answer what crafty receives with TCP resets and ICMP port
  unreachables. `--fw` keeps the kernel off the ports of `--tcp` and `--udp`.
- `--ip ADDR`: an address of crafty's own instead, on the interface's network,
  for which crafty answers ARP. Then `--fw` is not needed, nor allowed.
- `-p [/PATTERN]` (or `--print-packets`): prints the packets sent (`>`) and
  received (`<`), or only those that match the pattern, timed since the start:

  ```
  > 0.049097 10.77.0.1:14085 > 10.77.0.2:7 TCP [S] seq 3588057113 ack 0 win 65535 options [mss 1460,nop,wscale 7] len 0
  < 0.049326 10.77.0.2:7 > 10.77.0.1:14085 TCP [S.] seq 670698564 ack 3588057114 win 64240 options [mss 1460,nop,wscale 7] len 0
  ```

- `--stats`: prints the stats of each stream (see `stats()`) as it closes, and
  of those still open at the end:

  ```
  Closed /IP(src=10.77.0.1, dst=10.77.0.2)/TCP(src=14085, dst=7): packets_out=5 bytes_out=5 packets_in=4 bytes_in=5 bytes_acked=5 bytes_received=5 retrans=0 ... established=true
  ```

- `--format csv|json`: one record per line instead, for the prints, the
  packets of `-p` (in JSON, with all their `layers`), the stats and the
  outcome; crafty's other messages go to stderr. `ts` is in seconds since the
  start, durations in seconds. CSV has the values of the JSON, in that order,
  without the `layers`:

  ```
  {"type":"print","ts":0.000412,"text":"ping 0"}
  {"type":"done","ts":0.215302,"status":"OK","packets_out":3,"packets_in":3,...}
  ```

- `--max-duration D`, `--max-packets N`, `--max-bytes N`,
  `--max-packets-per-secs N`, `--max-bytes-per-secs N`, `--max-syns N`,
  `--max-syns-per-secs N`: budgets, with the program's `BUDGET`; exceeding
  one stops the program. SYNs are TCP SYNs without ACK, i.e. connection
  attempts.
- `--linger D`: once the program is done, how long to wait for the traffic to
  stop, so that connections close (default 2s).
- `--check`: only compiles the program.
- `--warn-error`: the warnings (on stderr) are errors.
- `--no-warning`: no warnings.
- `--cleanup`: undoes what a killed crafty left on the host (firewall rules,
  reserved ports).
- `--promisc`: receives the frames for other addresses too.
- `--mtu N`, `--speed 10Mbps|...|1Gbps|...|100Gbps`, `--duplex full|half`:
  the link's, rather than the interface's.
- `--verbose`: prints the interface's settings and the commands configuring
  it.
- `--normalize`: prints the program back, without its comments.
- `--reference`: print the reference manual.
- `--examples`: print examples of use.

Exit status: 0 when the program completes, 1 when an error ends it, 2 when it
does not compile, 3 when a budget stops it, 130 when interrupted.

## 2. Reference

### Lexical conventions

- A statement ends at the end of its line, or at a `;`. Within parentheses,
  brackets and braces, and after a binary operator, a new line is plain
  white space. A block opens on the line of the statement it belongs to.
- Comments run from a `#` to the end of the line. A `#` followed by a
  hexadecimal digit is a byte literal instead.
- Names of layers, fields, functions and keywords are case insensitive.
  Constants, `MATCH` and `LAST` are upper case. All but field names are
  reserved. Variables and constructors are case sensitive.

### Types and literals

- `bool`: `true`, `false`.
- `int`: `42`, `-1`, `0x1f`, `0o17`, `0b101`.
- `float`: `1.5`, `2e-3`.
- `byte`: `#1f`.
- bytes: `#deadbeef` (an even number of digits), or a string where bytes are
  expected. An array of bytes.
- `string`: `"text ${expr}"`.
- `interval`: `5s`, `10ms`, `1m30s`, `1.5ms`, `-2s`. Units: `d`, `h`, `m`,
  `s`, `ms`, `us` (or `µs`), `ns`, `ps`. Printed as `1s500ms`.
- `time`: `2026-10-20T22:02:45.25Z`, `2026-10-20T22:02+02:00`,
  `2026-10-20T22:02` (local time). Printed in UTC. `int(t)` and `float(t)`
  give its unix timestamp, `time(secs)` the reverse.
- `ip`: `192.0.2.1`. IPv4 only.
- `mac`: `aa:bb:cc:dd:ee:ff`.
- arrays: `[1, 2, 3]`. Items of one type.
- maps: `[192.0.2.1: "gw", 192.0.2.2: "dns"]`, a `string[ip]`, in no
  particular order. `map(key=k, default=v)` is an empty map with keys of the
  type of `k`, where missing keys have the value `v`.
- records: `{name: "gw", ip: 192.0.2.1}`. `{}` is an empty block, not a
  record.
- variants: `Ok(42)`, `Failed("timeout")`, `Pending`. A constructor starts
  with a capital letter; a bare name that is a variable is the variable. The
  layers of a packet are variants too, of constructors `IP`, `UDP`...

Literals are whole words: `1.2.3.4` is an IP address, `5s` an interval.

Strings interpolate any expression: `"ttl ${MATCH[IP].ttl - 1}"`. Escapes:
`\n`, `\r`, `\t`, `\0`, `\\`, `\"`, `\$`, `\xHH`. Interpolated bytes are
written in hexadecimal (`#68656c6c6f`); bytes passed where a string is
expected, as to `print`, are text.

**Conversions** happen where needed: an int to a float, a byte to an int, a
string to bytes and back, bytes to an IP address (4 bytes) or a MAC address
(6 bytes, checked at run time), an int to a bool (non-zero is true). Others
use the functions `int`, `float`, `bool`, `byte`, `interval`, `time`,
`ip_addr` and `mac_addr`, which also read a string as a literal:
`ip_addr(getenv("SERVER"))`, `interval("1.5s")`. Items of arrays, values of
maps and fields of records convert likewise.

**Variants** need no declaration. Where variants meet (items of an array,
branches of an `if`, values assigned to a variable...), they make one variant
with the constructors of all, which `case` tells apart:

```
result = Pending   # of type (Failed string | Got int | Pending)
first Bytes("pong") { result := Got(length(MATCH)) }
  | ../ICMP { result := Failed("unreachable") }
print(case result Got { "${result} layers" } else { "${result}" })
```

Interpolated, a variant is written `Got 4`, `Pending`.

### Variables

- `x = expr` declares `x` in the current block, with the type of `expr`.
  Declaring a name twice in one block is an error; an inner block may shadow
  it.
- `x := expr` assigns it, and `x += expr` (also `-=`, `*=`, `/=`, `%=`, `&=`,
  `|=`, `^=`) updates it.
- Blocks see the variables of the blocks around them. Conditions of patterns
  read them when a packet arrives.
- Predefined: `MATCH` (in the block of an `expect`, `first` or `on`), `LAST`
  (the last packet sent, once a block has sent one), `I`, the counter of
  a `repeat` or the item of a `foreach`, and `BUDGET` and `PORTS`.

### Budget and ports

A program may declare them, once each, at its top level, with literals only:

```
BUDGET = {max_duration: 30s, max_syns: 30, max_syns_per_secs: 5, max_bytes: 50000}
PORTS = {tcp: [[40000, 40100]], udp: [[5000, 5000]]}
```

- `BUDGET`'s fields are the budget options of crafty, named alike:
  `max_duration`, `max_packets`, `max_bytes`, `max_packets_per_secs`,
  `max_bytes_per_secs`, `max_syns`, `max_syns_per_secs`.
- `PORTS` has ranges `[first, last]` by protocol; a protocol left out gets
  no port.
- crafty runs with what both the program and the command line allow: the
  least of each budget, the ports in both (an error if there is none).
- `BUDGET` and `PORTS` are readable anywhere, and are those values:
  `src = PORTS.tcp[0][0]`. Reading a field that neither the program nor the
  command line sets is an error. They cannot be assigned.

### Expressions

Operators, from the tightest binding to the loosest:

1. `!x`, `-x`.
2. `*`, `/`, `%`: on numbers; an interval can be multiplied or divided by a
   number. An array (or a byte) times an int repeats it: `#01 * 2` is
   `#0101`, `[0] * 3` is `[0, 0, 0]`.
3. `+`, `-`: on numbers and intervals; a time minus a time is an interval, a
   time plus an interval (or a number of seconds) is a time. `+` also
   concatenates arrays (`[1] + [2, 3]`) and appends or prepends an item
   (`[1, 2] + 3`, `0 + [1, 2]`). Strings do not add up: interpolate them.
4. `&`, then `^`, then `|`: bitwise, on ints or bytes. They bind tighter than
   comparisons: `flags & RST == 0` is `(flags & RST) == 0`.
5. `==`, `!=`, `<`, `<=`, `>`, `>=`: they do not chain; ordering works on
   numbers, bytes, intervals, times and strings.
6. `&&`, then `||`.

Also: `r.field`, `a[i]` (from 0, checked at run time), `m[k]` (else the
default, else an error), `f(arg, name=arg)`, and the layer selectors of
[Patterns](#patterns). `a[i] := v` and `m[k] += 1` change an item, adding the
key to a map if need be.

**Blocks, `if` and `case` are expressions**:

```
y = if c { 1 } else { 2 }
ttl = case var=h MATCH[1] IP { h.ttl } else { 0 }
rtt = { t0 = now() ; Request("ping") ; expect Reply {} ; now() - t0 }
```

A block can wait, send, receive, loop or `break` only as the whole value of
a declaration, an assignment or a statement: `n = 1 + { wait 1s ; 1 }` is an
error.

### Protocol stacks

`/IP(dst=192.0.2.10, ttl=3)/UDP(src=4000, dst=53)`:

- A stack that starts with `/` starts from the interface, at the Ethernet
  layer, which can be left out (`/IP` is `/Eth/IP`). Other stacks go on top
  of the current stack.
- Followed by a block, a stack is the current stack of that block.
- Ending with a terminal layer (`Bytes`, `Request`, `Reply`, `Query`,
  `Answer`), a stack is a message, sent before the program goes on. The
  current stack is unchanged: `Bytes("a")` then `Bytes("b")` both send on it.
- `p = MESSAGE` sends it and waits until the interface is seen sending it
  (an error after 1s): `p` is the packet as captured, `p[Eth].ts` when it
  left. Every layer but `Eth` must be manual, so that it is one frame. See
  [When did it leave?](#when-did-it-leave).
- Options are named (`dst=...`), except a lone option of a layer that has a
  default field: `Bytes("x")` is `Bytes(data="x")`. Most can be left out:
  ports, protocols, lengths and checksums are guessed or computed.
- Options belong to the stack, not to the stream: those of a block's stack
  apply to everything sent from that block, those of a message to that
  message only.
- Each leading `../` goes one layer down the current stack. A layer that
  lands on the same layer of the current stack overlays it, keeping its
  options unless given: `../TCP!` is the same connection, sent by hand.

**Streams.** The layers of stacks are *nodes*, keyed by the IP addresses, the
TCP and UDP ports, and the echo and DNS ids. Stacks with the same keys share
their nodes, and so the state of the protocol: the TCP connection, the IP ids,
the echo sequence numbers.

A TCP connection opens when its first message is sent, and closes once no
block uses its stack any more:

```
/IP(dst=192.0.2.10)/TCP(src=40000, dst=7) {
  Bytes("hello\n")
  expect timeout=2s Bytes("hello\n") { print("echoed") }
  ../TCP!(flags=RST)/Bytes()     # a RST on that connection
}
```

A manual layer cannot carry a self-driven one: `IP/TCP!` is fine, `IP!/TCP`
is not.

### Patterns

- `/IP/UDP(dst == 7)/Bytes`: *absolute*, matched from the interface up, on
  any stream. In a block, one that shares with its stack more than `IP`, or
  all of it, with no condition on `IP`, is warned of: `/IP/UDP/DNS/Answer` in
  a block on `/IP/UDP/DNS` is likely meant as `Answer`.
- `Bytes("pong")`: *relative*, on top of the current stack, so only on its
  stream.
- `../ICMP/DestUnreachable`: relative to a layer below the top of the current
  stack. In a block on `IP/UDP`, these are the ICMP errors the IP stream
  receives. On the same layer as the stack's, a pattern sees only that
  stream: in a block on `IP/TCP`, `../TCP!` sees that connection's segments.
- `Bytes("pong") | ../ICMP`: alternatives, wherever a pattern goes (`-p`
  too), in parentheses or not. A packet that matches several matches once.

Conditions in parentheses are boolean expressions, where `,` and `=` can
stand for `&&` and `==`:

- A bare name is a field of the layer if it has one, else a variable:
  `UDP(src == port)`.
- Fields of the layers below read as `IP.src`. When there are several (a
  tunnel, the packet an ICMP error quotes), `IP^.src` is the IP layer below
  the last one, and `^IP.src` the first.
- A condition that is not a bool compares the default field:
  `Bytes("pong")` is `Bytes(data == "pong")`. An int is true when not zero:
  `TCP!(flags & RST)`.
- The fields that can be read depend on the mode (see [Layers](#layers)): a
  self-driven `TCP` shows its ports, a manual `TCP!` each segment's header.

What UDP, TCP and ICMP errors carry is decoded as whatever the patterns and
streams expect there, so a datagram can match both `UDP/DNS/Query` and
`UDP/Bytes`. A packet matches in one mode only: a fragment `IP!`, a
reassembled packet `IP`; TCP data `TCP/Bytes`, in order and once per chunk
delivered, and each segment `TCP!`.

**`MATCH`** is the packet that matched, as an array of layers, decoded past
the pattern as `Bytes` (or the `IP` that an ICMP error quotes). `MATCH[UDP]`
is its last UDP layer, `MATCH[IP^]` the last IP but one, `MATCH[^IP]` the
first; then `MATCH[IP].src`, `MATCH[Bytes].data`. `MATCH[0]` is a layer of
any kind, which `case` tells apart:

```
foreach MATCH {
  print(case I IP { "IP from ${I.src}" } | UDP { "UDP to ${I.dst}" } else { "other" })
}
```

**`LAST`**, likewise, is the last packet sent. Self-driven layers show their
options, what crafty picked (source ports) and their defaults (`ttl`), but not
what their engine computes (checksums).

### Special forms

Parameters are written `name=value`, or without the name for a form with a
single one (`break 2`, `wait 1s`).

- `{ ... }`: a block of its own; its variables and patterns end with it.
- `repeat var=v count=n every=d for=d { ... }`: runs the block `count` times,
  or while `for` (default 5m) has not elapsed. An iteration starts `every`
  after the previous one started, or when it ends if later. `v` (default `I`)
  counts from 0.
- `foreach v every=d for=d ARRAY { ... }`: a `repeat` over the items of the
  array (computed once), `v` (default `I`) being the item. The items of a map
  are `{key: k, value: v}`.
- `retry max=n { ... }`: runs the block again, up to `n` times (default 3),
  while it fails. The last error escapes.
- `catch { ... }`: leaves the block at its first error, which goes no further.
- `if c { ... } elsif c { ... } else { ... }`: `else` may start the line after
  the brace before it.
- `case var=v X C { ... } | C { ... } else { ... }`: runs the block of the
  constructor of `X`. Without `var`, a variable `X` is, in each block, what the
  constructor holds.
- `break depth=n`: leaves the `n` (default 1) innermost `repeat`, `foreach`
  or `on`.
- `wait dur=d`: pauses.
- `expect timeout=d PATTERN { ... }`: waits for one matching packet (default
  timeout 1m, which is an error), then runs the block.
- `first timeout=d PATTERN { ... } | PATTERN { ... }`: waits for the first
  packet that matches any pattern, and runs that pattern's block only. A
  timeout is an error.
- `on for=d linger=d timeout=d max=n PATTERN { ... } | PATTERN { ... }`: the
  enclosing block goes on, while for each matching packet a new block runs,
  that of its pattern. It ends after `for`, which the enclosing block waits
  for; or else with the enclosing block, which waits `linger` (default 0)
  after its statements; not both. It also ends after `max` matches, or at a
  `break` from its block. A `timeout` (default none) without a match is an
  error.

A block completes once its statements are done, its `linger`s waited, and
its `on`s with a `for` ended. Leaving a block, normally or on an error, cancels what it still had
going: patterns, timers, inner blocks, and the nodes it held, closing their
connections.

### Functions

An argument can be left unnamed when the function has a single parameter.
Otherwise, unnamed arguments take, in order, the parameters without a default
that are not named: `append(a, x)`, `histogram(rtts, bucket=5ms)`.

- `print(s)`, `print_err(s)`: to stdout, to stderr.
- `format(x)`: any value as a string, in the format of `--format`. CSV takes a
  scalar, or a record, array or map of scalars; record fields come in the
  order of their names: `print(format(stats()))`.
- `assert(cond, msg=s)`: fails if `cond` is false.
- `now()`: the current time.
- `stats()`: the stats of the stream at the top of the current stack, so far:
  `packets_out`, `packets_in`, `bytes_out`, `bytes_in` (the payloads at that
  layer). A self-driven TCP connection counts its segments, retransmissions
  included, and adds, as Linux's `tcp_info`: `bytes_acked`, `bytes_received`
  (in order), `retrans`, `dupacks`, `timeouts`, `ooo_in` (segments received
  out of order), `dup_in` (segments with only data already received: the
  peer's spurious retransmissions), `srtt`, `rttvar`, `rtt_samples`, `rto`,
  `snd_mss`, `rcv_mss`, `cwnd`, `ssthresh` (2^31-1 before any loss),
  `snd_wnd` (the peer's window), `rcv_wnd`, `snd_wscale` and `rcv_wscale`
  (the window shifts the peer and we offered, -1 if none; scaling is on only
  if both offered one) and `established`.
- `getenv(name, default=s)`: fails if unset and no default.
- `rand(max)`: an int or a float in `[0, max)` (default 1.0), or a bool if
  `max` is `true`. `randbytes(len)`: random bytes.
- `int(x)`, `float(x)`, `bool(x)`, `byte(x)` (the low 8 bits): `int` and
  `float` also take an interval, as seconds, and a time (see `time` above).
  `interval(secs)`: the reverse.
- `exp(x)`, `ln(x)`, `log(x)` (base 10). `log2(n)`: the integer base 2
  logarithm of a positive int.
- `array(init=v, len=n)`, `length(a)` (or `count(a)`, of an array, a map or a
  string), `concat(a, b)`, `append(a, x)`, `prepend(x, a)`.
- `has(m, k)`, `remove(m, k)` (a copy), `keys(m)`, `values(m)`.
- `sorted(a)`: a sorted copy. `sort(a)`, a statement, sorts the variable `a`.
- `sum(a)`, `min(a)`, `max(a)`, `mean(a)`, `stddev(a)`, `percentile(a, p)`:
  of an array, or the values of a map. Only `sum` takes none (0). `mean` and
  `stddev` take numbers (giving a float) or intervals. `percentile` is the
  smallest value that `p` percent of them do not exceed; 50 is the median.
- `histogram(a, bucket=b)`: the values counted in buckets of width `b` from
  0, as an array of `{min, count, max}`, `min` and `max` being the extreme
  values in the bucket.

### Layers

Each field has its type, and the modes in which it can be *set* as an option
and *read* in a condition or in `MATCH`: **M** manual, **S** self-driven. A
layer with a single mode is manual. *(key)* fields tell streams apart.

#### `Eth`: Ethernet (bottom of every stack)

- `src`: mac; set M; read M, S. Default: the interface's.
- `dst`: mac; set M; read M, S. Default: what the interface knows of the
  destination (ARP cache, gateway), without asking.
- `proto`: int; set M; read M, S. Default: the layer on top.
- `ts`: time; read M, S. When the frame was captured; for what is
  reassembled, the frame that completed it. Unset in `LAST`.

Self-driven, it carries only IPv4, and finds destinations with ARP. It
answers ARP for an address of its own (`--ip`); the host's kernel answers for
the interface's. `Eth!` frames go out as they are.

#### `IP`: IPv4 (on `Eth`)

- `src` (key): ip; set M, S; read M, S. Default: the interface's address.
- `dst` (key): ip; set M, S; read M, S. Required.
- `proto`: int; set M, S; read M, S. Default: the layer on top.
- `tos`: int; set M, S; read M, S.
- `ttl`: int; set M, S; read M, S. Default 64.
- `dont_frag`: bool; set M, S; read M, S. Default false.
- `id`: int; set M; read M, S. Default: the stream's counter, from a random
  value.
- `more_frags`: bool; set M; read M.
- `frag_offset`: int; set M; read M.
- `tot_len`: int; set M; read M. Default: computed.
- `options`: bytes; set M, S; read M, S.
- `is_fragment`: bool; read M.

Self-driven IP fragments to the MTU and reassembles. `tos`, `ttl`,
`dont_frag` and `options` apply to what it sends, but for the segments of a
self-driven TCP connection. `IP!` sends the header as given, but for the
checksum.

#### `TCP` (on `IP`)

- `src` (key): int; set M, S; read M, S. Default: a port of `--tcp`.
- `dst` (key): int; set M, S; read M, S. Required.
- `seq_num`: int; set M; read M.
- `ack_num`: int; set M; read M.
- `flags`: int; set M; read M. Constants `FIN`, `SYN`, `RST`, `PSH`, `ACK`,
  `URG`.
- `win_size`: int; set M; read M.
- `urg_ptr`: int; set M; read M.
- `checksum`: int; set M; read M. Default: computed, as when 0.
- `mss`: int; set S. The MSS of the connection.

Self-driven, the first message sent connects, and what follows waits for the
connection. A TCP node created by a pattern accepts the connection instead.

`TCP!` segments take the sequence and ack numbers, the window and the ACK|PSH
flags of the node's connection when not given, and the connection accounts
for them: they advance its sequence, FIN closes it, RST aborts it. They are
not retransmitted. Sending one while the connection is being established is
an error.
Without a connection, `TCP!` counts sequence numbers from a random one.

#### `UDP` (on `IP`)

- `src` (key): int; set M; read M. Default: a port of `--udp`.
- `dst` (key): int; set M; read M. Required, unless told by the layer on
  top.
- `length`: int; set M; read M. Default: computed.
- `checksum`: int; set M; read M. Default: computed, as when 0.

#### `ICMP` (on `IP`)

- `type`, `code`: int; read M. Set by the message on top.

#### `Echo` (on `ICMP`)

- `id` (key): int; set M; read M. Default: a free random id.

The stream of an echo id, for `Request` and `Reply` messages, which count
their sequence numbers per stream.

#### `Request` and `Reply` (on `Echo`, terminal)

- `seq`: int; set M; read M. Default: the stream's counter, from 1.
- `payload`: bytes; set M; read M. Default field.

#### `DestUnreachable` and `TimeExceeded` (on `ICMP`)

- `code`: int; set M; read M. Default 0. Constants: `NET_UNREACHABLE`,
  `HOST_UNREACHABLE`, `PROTOCOL_UNREACHABLE`, `PORT_UNREACHABLE`,
  `FRAG_NEEDED`, `SOURCE_ROUTE_FAILED`; `TTL_EXCEEDED`, `REASSEMBLY_TIMEOUT`.
- `mtu`: int; set M; read M. `DestUnreachable` only; default 0.

On top is the start of the packet the error is about: a quoted `IP`, or
`Bytes`.

#### Quoted `IP`, `UDP` and `TCP` (on `DestUnreachable` and `TimeExceeded`)

They have the fields of `IP`, `UDP` and `TCP` (but `is_fragment` and `mss`),
all readable and settable. They are manual, and no streams: a quoted TCP
segment is no part of a connection. Errors print them as `IP?`, `UDP?`,
`TCP?`.

```
on for=5s /IP/ICMP/TimeExceeded/IP(dst == target)/UDP(dst == 33434) {
  print("from ${MATCH[^IP].src}, ttl ${MATCH[IP].ttl}")
}
```

`MATCH[IP]` is the quoted packet, `MATCH[^IP]` the error's. A quote is often
cut 8 bytes after the IP header: of `TCP`, only the ports and `seq_num` are
then sure, the other fields reading 0. Sent, a quoted `IP` needs a `src` and
a `dst`; lengths and checksums are computed unless given.

#### `DNS` (on `UDP`)

- `id` (key): int; set M; read M. Default: a free random id.

The stream of a DNS id, for `Query` and `Answer` messages.

#### `Query` and `Answer` (on `DNS`, terminal)

- `name`: string; set M; read M. Default field; required. Without the
  trailing dot (`"example.com"`), but for the root (`"."`).
- `type`: int; set M; read M. Default `TYPE_A`. Constants `TYPE_A`,
  `TYPE_NS`, `TYPE_CNAME`, `TYPE_SOA`, `TYPE_PTR`, `TYPE_MX`, `TYPE_TXT`,
  `TYPE_AAAA`, `TYPE_SRV`, `TYPE_ANY`.
- `class`: int; set M; read M. Default `CLASS_IN`.
- `opcode`: int; set M; read M. Default 0.
- `authoritative`, `truncated`, `rec_avail`, `authentic_data`,
  `checking_disabled`: bool; set M; read M. Default false.
- `rec_desired`: bool; set M; read M. Default true.
- `status`: int; set M; read M. Default `NOERROR`. Constants `NOERROR`,
  `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED`.
- `answers`, `authority`, `additional`: records; set M; read M. Default
  none. Each is `{name: string, type: int, class: int, ttl: int, data:
  bytes}`; the data of an A record converts to an IP address.

A message has one question (`name`, `type`, `class`): the first, of a
received message with several.

#### `Bytes` (on `Eth`, `IP`, `TCP`, `UDP`, the ICMP errors and the quoted layers, terminal)

- `data`: bytes; set M; read M. Default field.

What a layer carries when not decoded further: the payload of UDP, the data
of TCP, a fragment, a quote, an unknown protocol.

## 3. Examples

These ran against a host with UDP and TCP echo servers on port 7.

### Ping

```
/IP(dst=192.0.2.10)/ICMP/Echo {
  received = 0
  repeat count=5 every=200ms {
    Request("hello")
    catch {
      expect timeout=1s Reply(payload == "hello") {
        received += 1
        print("reply from ${MATCH[IP].src}: seq=${MATCH[Reply].seq} ttl=${MATCH[IP].ttl}")
      }
    }
  }
  print("${received} replies out of 5")
}
```

```
% sudo crafty -i eth0 --ip 192.0.2.5 ping.cfty
reply from 192.0.2.10: seq=1 ttl=64
...
5 replies out of 5
```

The replies come back to the `Echo` stream of the requests, whatever its id.

### Round trip times

```
# 100 probes to a UDP echo server: how many come back, and how fast?
/IP!(dst=192.0.2.10)/UDP(dst=7) {
  rtts = array(init=0s, len=0)
  repeat count=100 every=10ms {
    p = Bytes("probe ${I}")
    catch {
      expect timeout=500ms Bytes("probe ${I}") { rtts += MATCH[Eth].ts - p[Eth].ts }
    }
  }
  print("${length(rtts)}/100 echoed, rtt min ${min(rtts)} median ${percentile(rtts, 50)} p99 ${percentile(rtts, 99)} max ${max(rtts)}")
  foreach histogram(rtts, bucket=1ms) { print("${I.min} to ${I.max}: ${I.count}") }
}
```

```
% sudo crafty -i eth0 --ip 192.0.2.5 --udp 40000-40010 rtt.cfty
100/100 echoed, rtt min 4ms343µs509ns674ps median 7ms940µs530ns777ps p99 10ms282µs516ns479ps max 10ms662µs794ns113ps
4ms343µs509ns674ps to 4ms773µs139ns954ps: 8
...
```

The times are those of the captures, of the probe going out and of its echo
coming in. Each probe expects its own echo, so that a late one is not taken
for the next.

### Resolve, then ping

```
/IP(dst=192.0.2.53)/UDP/DNS {
  Query("www.example.com")
  expect timeout=2s Answer(status == NOERROR) {
    a = MATCH[Answer].answers
    assert(length(a) > 0 && a[0].type == TYPE_A, msg="no address")
    /IP(dst=a[0].data)/ICMP/Echo {
      Request("hi")
      expect timeout=1s Reply { print("${a[0].name} is up") }
    }
  }
}
```

The first record is an address only if the name has no CNAME.

### A UDP echo server

```
on for=1h /IP/UDP(dst == 7)/Bytes {
  /IP(dst=MATCH[IP].src)/UDP(src=7, dst=MATCH[UDP].src)/Bytes(MATCH[Bytes].data)
}
```

```
% sudo crafty -i eth0 --udp 7 --fw server.cfty
```

### Losses per flow

```
# 4 flows of 25 datagrams to the UDP echo server: how many get no echo?
target = 192.0.2.10
lost = array(init=25, len=4)
{
  on linger=1s /IP(src == target)/UDP(src == 7, dst >= 40000, dst < 40004) {
    lost[MATCH[UDP].dst - 40000] -= 1
  }
  repeat count=100 every=10ms {
    /IP(dst=target)/UDP(src=40000 + I % 4, dst=7)/Bytes("ping")
  }
}
repeat var=f count=4 { print("flow ${f}: ${lost[f]} lost") }
```

```
% sudo crafty -i eth0 --udp 40000-40003 --fw losses.cfty
flow 0: 0 lost
...
```

The `on` starts listening before the datagrams go out, and goes on 1s after
the last one.

### Is a port closed?

```
/IP(dst=192.0.2.10)/TCP(src=40001, dst=22) {
  Bytes("hello")
  expect timeout=1s ../TCP!(flags & RST) { print("reset by ${MATCH[IP].src}") }
}
```

A reset carries no data, so a pattern on top of `TCP` never sees it; `../TCP!`
sees each segment of the connection.

### When did it leave?

```
/IP!(dst=192.0.2.10)/UDP(dst=7) {
  p = Bytes("ping")
  expect timeout=1s Bytes { print("rtt: ${MATCH[Eth].ts - p[Eth].ts}") }
}
```

### How is the connection doing?

```
/IP(dst=192.0.2.10)/TCP(dst=7) {
  Bytes("hello")
  expect timeout=1s Bytes {
    s = stats()
    print("srtt ${s.srtt}, mss ${s.snd_mss}, peer window ${s.snd_wnd}")
  }
}
```

### A TCP port scan

```
target = 192.0.2.10
{
  on linger=1s /IP(src == target)/TCP!(src >= 1, src <= 100, flags == SYN | ACK) {
    print("port ${MATCH[TCP].src} is open")
  }
  repeat var=i count=100 every=5ms {
    /IP(dst=target)/TCP!(src=40000, dst=i + 1, flags=SYN, seq_num=1)/Bytes()
  }
}
```

```
% sudo crafty -i eth0 --tcp 40000 --fw scan.cfty
port 7 is open
```

### A port scan within its budget

```
BUDGET = {max_syns: 1000, max_syns_per_secs: 200}
PORTS = {tcp: [[40000, 40000]]}
target = 192.0.2.10
sport = PORTS.tcp[0][0]
{
  on linger=1s /IP(src == target)/TCP!(dst == sport, flags == SYN | ACK) {
    print("port ${MATCH[TCP].src} is open")
  }
  repeat var=i count=BUDGET.max_syns every=1s / BUDGET.max_syns_per_secs {
    /IP(dst=target)/TCP!(src=sport, dst=i + 1, flags=SYN, seq_num=1)/Bytes()
  }
}
```

```
% sudo crafty -i eth0 --fw --max-syns-per-secs 50 budget-scan.cfty
port 7 is open
```

No `--tcp`: `PORTS` gives it, for `--fw` too. With `--max-syns-per-secs 50`,
`BUDGET.max_syns_per_secs` is 50 and the scan takes 20s; with
`--max-syns 100`, it scans ports 1 to 100.

### Traceroute

```
target = 192.0.2.10
repeat var=hop count=30 {
  ttl = hop + 1
  port = 33434 + hop
  {
    on max=1 linger=1s /IP/ICMP/TimeExceeded(code == TTL_EXCEEDED)/IP/UDP(dst == port) {
      print("${ttl}: ${MATCH[^IP].src}")
    }
    on max=1 linger=1s /IP/ICMP/DestUnreachable(code == PORT_UNREACHABLE)/IP/UDP(dst == port) {
      print("${ttl}: ${target}, reached")
      break 2
    }
    /IP(dst=target, ttl=ttl)/UDP(dst=port)/Bytes("probe")
  }
}
```

The patterns are absolute, as the routers have addresses of their own, and
tell the probes apart by the port of the packet the errors quote. `break 2`
leaves the `on` and the `repeat`.

### Giving up gracefully

```
/IP(dst=192.0.2.10)/UDP(dst=7) {
  catch {
    retry max=2 {
      Bytes("are you there?")
      expect timeout=500ms Bytes { print("yes") }
    }
  }
}
print("moving on")
```

### Raw frames

```
/Eth!(dst=ff:ff:ff:ff:ff:ff, proto=0x88b5)/Bytes("hello")
/IP!(dst=192.0.2.10, ttl=1, id=1234, dont_frag=true)/UDP(src=40000, dst=9)/Bytes(#deadbeef)
```

### Values

```
host = {name: "gw", ip: 192.0.2.1}
sizes = [64, 512, 1500]
total = 0
foreach s sizes { total += s }
print("${host.name} is ${host.ip}; ${total} bytes in ${length(sizes)} packets")
seen = map(key="", default=0)
foreach p ["udp", "tcp", "udp"] { seen[p] += 1 }
print("${seen}, and ${seen["icmp"]} icmp")
print("${min(sizes)} to ${max(sizes)}, median ${percentile(sizes, 50)}")
print("${interval(0.5) * 3}")
```

prints:

```
gw is 192.0.2.1; 2076 bytes in 3 packets
[tcp: 1, udp: 2], and 0 icmp
64 to 1500, median 512
1s500ms
```

### Utilities

Whole programs, which take their arguments from the environment.

#### Traceroute through load balancers

```
# Every probe goes from the same UDP port to the same port, so that routers
# that balance per flow send them all the same way: where a hop still shows
# several routers, they balance per packet.
target = ip_addr(getenv("TARGET"))
probes = int(getenv("PROBES", default="5"))      # per hop
max_hops = int(getenv("MAX_HOPS", default="30"))
port = int(getenv("PORT", default="33434"))
/IP!(dst=target)/UDP(dst=port) {
  probe = 0                       # the IP id, that tells the probes apart
  repeat var=hop count=max_hops {
    rtts = map(key=0.0.0.0, default=array(init=0s, len=0))
    reached = false
    repeat count=probes {
      probe += 1
      p = ../../IP!(ttl=hop + 1, id=probe)/UDP/Bytes("probe")
      if probe == 1 { print("to ${target} from UDP port ${p[UDP].src} to ${port}") }
      catch {
        first timeout=1s /IP/ICMP/TimeExceeded/IP(id == probe, dst == target)/UDP {
          rtts[MATCH[^IP].src] += MATCH[Eth].ts - p[Eth].ts
        } | /IP/ICMP/DestUnreachable/IP(id == probe, dst == target)/UDP {
          rtts[MATCH[^IP].src] += MATCH[Eth].ts - p[Eth].ts
          reached := true
        }
      }
    }
    head = "${hop + 1}"
    answered = 0
    foreach rtts {
      answered += length(I.value)
      ms = float(int(float(min(I.value)) * 100000.0)) / 100.0
      print("${head}\t${I.key}\t${length(I.value)}/${probes}\tmin ${ms}ms")
      head := ""
    }
    if answered < probes { print("${head}\t*\t${probes - answered}/${probes}") }
    if reached { break }
  }
}
```

```
% sudo TARGET=10.2.1.3 PROBES=8 crafty -i eth0 --udp 40000 --fw lbtrace.cfty
to 10.2.1.3 from UDP port 40000 to 33434
1	10.1.1.1	8/8	min 0.04ms
2	10.1.0.5	4/8	min 37.67ms
	10.1.0.6	4/8	min 34.92ms
3	10.2.0.1	2/8	min 89.71ms
	10.2.0.2	6/8	min 90.97ms
4	10.2.0.6	8/8	min 117.6ms
5	10.2.1.3	8/8	min 110.92ms
```

Hops 2 and 3 balance per packet. Behind routers that balance per flow, each
hop shows one router, and another `PORT` may show another path. A `*` line
counts the probes without an answer.

#### Path MTU

```
# Echo requests that must not be fragmented: a router that cannot forward one
# tells its next hop MTU, which is the next size to try; one that drops it
# silently leaves a binary search between what came back and what did not.
target = ip_addr(getenv("TARGET"))
lo = 68                                         # fits any IPv4 path
hi = int(getenv("MTU", default="1500"))         # what may fit
/IP!(dst=target, dont_frag=true)/ICMP/Echo {
  size = hi
  replies = 0
  repeat count=32 {
    told = 0                      # the next hop MTU a router said
    answered = false
    Request(seq=size, payload=#00 * (size - 28))
    catch {
      first timeout=1s Reply(seq == size) {
        print("${size}: echoed")
        answered := true
        replies += 1
        lo := size
      # Absolute, as routers have addresses of their own. "src != target" only
      # silences the warning that it is not relative, as the stack's Echo is.
      } | /IP(src != target)/ICMP/DestUnreachable(code == FRAG_NEEDED)/IP(dst == target, tot_len == size) {
        told := MATCH[DestUnreachable].mtu
        print("${size}: too big for ${MATCH[^IP].src}, next hop MTU ${told}")
        answered := true
      }
    }
    if !answered { print("${size}: no answer") }
    if told > lo && told < size {
      hi := told
      size := told
    } else {
      if !answered || told > 0 { hi := size - 1 }
      if lo >= hi { break }
      size := (lo + hi + 1) / 2
    }
  }
  print(if replies > 0 { "path MTU to ${target}: ${lo}" } else { "no echo came back" })
}
```

```
% sudo TARGET=10.2.1.3 crafty -i eth0 pmtu.cfty
1500: too big for 10.1.0.5, next hop MTU 1400
1400: no answer
734: echoed
1067: echoed
1233: echoed
1316: no answer
1274: echoed
1295: no answer
1284: no answer
1279: echoed
1281: no answer
1280: echoed
path MTU to 10.2.1.3: 1280
```

10.1.0.5 reports its MTU of 1400, but a router further on drops what
exceeds 1280 without a word.

#### Losses and round trips per hop, over time

```
# Probes every hop once per round, on one flow as the traceroute does, and
# reports each hop's losses and round trips every REPORT rounds.
target = ip_addr(getenv("TARGET"))
rounds = int(getenv("ROUNDS", default="60"))
report = int(getenv("REPORT", default="10"))   # rounds per report
pace = interval(getenv("INTERVAL", default="1s"))
max_hops = int(getenv("MAX_HOPS", default="30"))   # less than 64
port = int(getenv("PORT", default="33434"))
last = max_hops - 1               # the target's hop, from 0, once known
sent = array(init=0, len=max_hops)
rtts = array(init=array(init=0s, len=0), len=max_hops)
hosts = array(init=map(key=0.0.0.0, default=0), len=max_hops)
sent_at = map(key=0, default=now())     # by IP id: round * 64 + hop
/IP!(dst=target)/UDP(dst=port) {
  on /IP/ICMP/TimeExceeded/IP(dst == target)/UDP(dst == port) |
     /IP/ICMP/DestUnreachable(code == PORT_UNREACHABLE)/IP(dst == target)/UDP(dst == port) {
    id = MATCH[IP].id
    if has(sent_at, id) {
      hop = id % 64
      rtts[hop] += MATCH[Eth].ts - sent_at[id]
      hosts[hop][MATCH[^IP].src] += 1
      if MATCH[^IP].src == target && hop < last { last := hop }
      sent_at := remove(sent_at, id)
    }
  }
  repeat var=r count=rounds + 1 every=pace {
    if r > 0 && r % report == 0 {
      print("after ${r} rounds:")
      repeat var=hop count=last + 1 {
        s = sent[hop]
        n = length(rtts[hop])
        line = "${hop + 1}\t${keys(hosts[hop])}\tloss ${(s - n) * 100 / s}%"
        if n > 0 {
          avg = float(int(float(mean(rtts[hop])) * 100000.0)) / 100.0
          best = float(int(float(min(rtts[hop])) * 100000.0)) / 100.0
          worst = float(int(float(max(rtts[hop])) * 100000.0)) / 100.0
          line := "${line}\tavg ${avg}ms\tbest ${best}ms\tworst ${worst}ms"
        }
        print(line)
        sent[hop] := 0
        rtts[hop] := array(init=0s, len=0)
        hosts[hop] := map(key=0.0.0.0, default=0)
      }
      sent_at := map(key=0, default=now())    # too late for the next report
    }
    if r < rounds {
      repeat var=hop count=last + 1 {
        id = (r * 64 + hop) % 65536
        p = ../../IP!(ttl=hop + 1, id=id)/UDP/Bytes("probe")
        sent_at[id] := p[Eth].ts
        sent[hop] += 1
      }
    }
  }
}
```

```
% sudo TARGET=10.2.1.3 ROUNDS=40 REPORT=20 INTERVAL=200ms crafty -i eth0 --udp 40000 --fw mtr.cfty
after 20 rounds:
1	[10.1.1.1]	loss 0%	avg 0.33ms	best 0.11ms	worst 0.48ms
2	[10.1.0.5]	loss 50%	avg 37.81ms	best 37.6ms	worst 38.1ms
3	[10.2.0.2]	loss 0%	avg 90.91ms	best 90.69ms	worst 91.07ms
4	[10.2.0.6]	loss 10%	avg 114.42ms	best 114.18ms	worst 115.02ms
5	[10.2.1.3]	loss 5%	avg 114.23ms	best 114.09ms	worst 114.73ms
after 40 rounds:
1	[10.1.1.1]	loss 0%	avg 0.33ms	best 0.09ms	worst 0.6ms
2	[10.1.0.5]	loss 45%	avg 37.81ms	best 37.6ms	worst 37.97ms
3	[10.2.0.2]	loss 0%	avg 90.87ms	best 90.68ms	worst 91.3ms
4	[10.2.0.6]	loss 20%	avg 114.47ms	best 114.1ms	worst 116.44ms
5	[10.2.1.3]	loss 15%	avg 114.37ms	best 114.02ms	worst 116.14ms
```

Hop 2 only answers half of its probes: hop 3 losing none, what is lost is the
answers, not the traffic. The losses start between hops 3 and 4, and go on
to the target.
