# The crafty language

Crafty is a small language for writing network test traffic: sending
packets, crafted to the bit or produced by real protocol stacks, waiting for
the answers, and reacting to them.

## 1. Introduction

### Basic principles

**Protocol stacks** are layers, with their options, separated by slashes:
`/IP(dst=192.0.2.10)/UDP(dst=7)` is a UDP stream to `192.0.2.10:7`. The
leading slash makes it absolute, starting from the interface.

A stack followed by a block (`{...}`) is the current stack of that block,
which relative stacks (without the leading slash) go on top of. A stack that
ends with a message (`Bytes`, `Request`...) sends it, in one or several
packets depending on the protocols below.

**Self-driven or manual.** By default, layers are *self-driven*: crafty
establishes connections, resolves addresses with ARP, retransmits,
fragments and reassembles. A bang (`!`) after a layer's name makes it
*manual*: crafty only fills in the header fields not given, with plausible
values. On reception, `IP!` sees each fragment and `TCP!` each segment,
including those without data.

**Patterns.** `expect` waits for the first matching packet, `any` for the
first packet that matches one of several patterns, and `on` handles every
matching packet while the rest of the block goes on. They take
*patterns*, each of which describes a packet layer by layer, with conditions on
each layer:

  `expect /IP/TCP(dst == 7)/Bytes(data == "Ping") { ... }`

or, as `data` is the default field of `Bytes`:

  `expect /IP/TCP(dst == 7)/Bytes("Ping") { ... }`

In the block of an `expect`, `any` or `on`, `MATCH` is the packet that matched:

  `expect /IP/ICMP/Echo(id == 42)/Request { print("ping from ${MATCH[IP].src}") }`

**Errors.** An `expect` that times out is an error. An error leaves the blocks
that enclose it one after the other, until a `retry` runs its block again or a
`catch` drops the error. An error that reaches the top of the program ends it.

The language is statically typed, has variables, string interpolation, and
simple control flow. Comments start with `#`.

### A short example

```
# Send three pings to a UDP echo server, and count the answers.
/IP(dst=192.0.2.10)/UDP(dst=7) {
  answers = 0
  repeat count=3 every=100ms {
    Bytes("ping ${I}")  # 'I' is the loop counter
    catch {
      expect timeout=1s Bytes {
        answers += 1
        print(MATCH[Bytes].data)
      }
    }
  }
  print("${answers} answers out of 3")
}
```

The block's stack is IPv4 to 192.0.2.10, then UDP to port 7, from a source
port picked once: one UDP stream. Every 100ms, `Bytes(...)` sends a
datagram, and `expect` waits for one to come back on that stream. `catch`
keeps a lost answer from ending the program.

Run against a real echo server:

```
% sudo crafty -i eth0 --udp 40000-40010 --fw intro.cfty
...
ping 0
ping 1
ping 2
3 answers out of 3
Done after 0.2s, status: OK.
```

## 2. Reference

### Lexical conventions

- A statement ends at the end of its line, or at a `;`. Within parentheses,
  brackets and braces, and after a binary operator, a new line is plain
  white space. A block opens on the line of the statement it belongs to.
- Comments run from a `#` to the end of the line. A `#` followed by a
  hexadecimal digit is a byte literal instead.
- Names of layers, fields, functions, constants and keywords are case
  insensitive, and all but field names are reserved. Variables and
  constructors are case sensitive.

### Types and literals

- `bool`: `true`, `false`.
- `int`: `42`, `-1`, `0x1f`, `0o17`, `0b101`.
- `float`: `1.5`, `2e-3`.
- `byte`: `#1f`.
- bytes: `#deadbeef`, or a string where bytes are expected. An array of
  bytes; an odd number of digits is an error.
- `string`: `"text ${expr}"`. See below.
- `interval`: `5s`, `10ms`, `1m30s`, `1.5ms`, `-2s`. Units: `d`, `h`, `m`,
  `s`, `ms`, `us` (or `µs`), `ns`, `ps`.
- `time`: `2026-10-20T22:02:45Z`, `2026-10-20T22:02+02:00`,
  `2026-10-20T22:02`. ISO 8601, with the `T` and the hour and minute;
  seconds (with a fraction, as in `:45.25`) and zone are optional. Without a
  zone, in the local time of the host. Written in UTC
  (`2026-10-20T20:02:00Z`).
- `ip`: `192.0.2.1`. IPv4 only.
- `mac`: `aa:bb:cc:dd:ee:ff`.
- arrays: `[1, 2, 3]`. Items of one type.
- maps: `[192.0.2.1: "gw", 192.0.2.2: "dns"]`, a `string[ip]`. Keys of any
  one type, values of one type, in no particular order. `map(key=k,
  default=v)` is an empty map with the type of `k` as keys, and `v` as the
  value of missing keys.
- records: `{name: "gw", ip: 192.0.2.1}`. Field names are case insensitive.
  Braces with no field in them, `{}`, are an empty block, not a record.
- variants: `Ok(42)`, `Failed("timeout")`, `Pending` (or `Pending()`). A
  constructor is a name that starts with a capital letter, followed by what
  it holds in parentheses, or by nothing. A bare name is a variable rather
  than a constructor wherever a variable of that name is defined; with
  parentheses, it is always a constructor. Each layer of a packet is a
  variant too, whose constructors are the layers' names.

Literals are read as whole words: `1.2.3.4` is an IP address, `5s` an
interval.

Strings interpolate any expression with `${...}`, not only variables:
`"hop ${MATCH[UDP].dst - 33434}, ttl ${MATCH[IP].ttl}"`. They know the
escapes `\n`, `\r`, `\t`, `\0`, `\\`, `\"`, `\$` and `\xHH`. In an
interpolation, bytes are written in hexadecimal (`#68656c6c6f`). Bytes passed where a string is
expected, such as to `print`, are taken as text.

**Conversions** happen where needed: an int to a float, a byte to an int, a
string to bytes and back, bytes to an IP address (4 bytes) or a MAC address
(6 bytes, checked at run time). An int is a bool where one is expected
(non-zero is true). Other conversions use the functions `int`, `float`,
`bool`, `byte`, `interval`, `time`, `ip_addr` and `mac_addr`, which also
read a string as a literal: `ip_addr(getenv("SERVER"))`, `interval("1.5s")`.
The items of an array, the values of a map and the fields of a record
convert likewise.

**Variants** need no declaration: `Ok(42)` is of the variant `(Ok int)`,
which converts to any variant that has the constructor `Ok` holding an int
(or what an int converts to). Where variants meet, as the items of an
array, the branches of an `if` or a `case`, the operands of `==`, or the
values assigned to a variable, they make one variant with the constructors
of all:

```
result = Pending   # of type (Failed string | Got int | Pending)
any Bytes("pong") { result := Got(length(MATCH)) }
  | ../ICMP { result := Failed("unreachable") }
print(case result Got { "${result} bytes" } else { "${result}" })
```

A `case` tells the constructors apart. Interpolated, a variant is written
as its constructor followed by what it holds: `Got 4`, `Pending`.

### Variables

- `x = expr` declares `x` in the current block, and its type is that of
  `expr`. Declaring the same name twice in one block is an error.
  Redeclaring it in an inner block shadows the outer variable.
- `x := expr` assigns an existing variable, and `x += expr` (also `-=`,
  `*=`, `/=`, `%=`, `&=`, `|=`, `^=`) updates it.
- Blocks see the variables of the blocks around them. Conditions of
  patterns read their values when a packet arrives, not when the pattern
  starts waiting.
- Predefined variables: `MATCH` (the matched packet, within the block of an
  `expect`, an `any` or an `on`), `LAST` (the last packet sent, once a block
  has sent one), the counter of a `repeat` and the item of a `foreach` (`I`
  by default).

### Expressions

Operators, from the tightest binding to the loosest:

1. `!x`, `-x`: not, negation.
2. `*`, `/`, `%`: on ints and floats; an interval can be multiplied or
   divided by a number.
3. `+`, `-`: on ints and floats, and between intervals; a time minus a time
   is an interval, and a time plus or minus an interval, or a number of
   seconds, is a time. `+` also concatenates two arrays (`[1] + [2, 3]`), and
   appends or prepends an item (`[1, 2] + 3`, `0 + [1, 2]`).
4. `&`: bitwise and (ints or bytes).
5. `^`: bitwise exclusive or.
6. `|`: bitwise or.
7. `==`, `!=`, `<`, `<=`, `>`, `>=`: comparisons, which do not chain;
   ordering works on numbers, bytes, intervals, times and strings.
8. `&&`: and.
9. `||`: or.

Bitwise operators bind tighter than comparisons, so `flags & RST == 0` means
`(flags & RST) == 0`, and `flags == SYN | ACK` means `flags == (SYN | ACK)`.
Strings are not added together; use interpolation instead.

Also: `r.field` (a record's field), `a[i]` (an array's item, from 0, checked
at run time), `m[k]` (a map's value for key `k`, else its default, else an
error), `f(arg, name=arg)` (a function call), and the layer selectors
described under [Patterns](#patterns). `a[i] := v` and `m[k] += 1` change
an item, or a key's value, adding the key if need be. Two maps are equal
when their keys and values are.

**Blocks, `if` and `case` are expressions.**:

```
y = if c { 1 } else { 2 }
ttl = case var=h MATCH[1] IP { h.ttl } else { 0 }
```

A block can wait, send, receive, loop or `break` only when it gives the
value of a declaration, of an assignment or of a statement:

```
rtt = { t0 = now() ; Request("ping") ; expect Reply {} ; now() - t0 }  # fine
n = 1 + { wait 1s ; 1 } # error
```

### Protocol stacks

A stack is a list of layers, each optionally with options in parentheses:
`/IP(dst=192.0.2.10, ttl=3)/UDP(src=4000, dst=53)`.

- A stack that starts with `/` is on top of the interface: the Ethernet
  layer, always at the bottom, which can be left out (`/IP` is `/Eth/IP`).
  Without the `/`, a stack goes on top of the current stack.
- Followed by a block, a stack is the current stack of that block.
- Ending with a terminal layer (`Bytes`, `Request`, `Reply`, `Query`,
  `Answer`), a stack is a message, which is sent.
  The current stack stays as it was: `Bytes("a")` then `Bytes("b")` both
  send on it.
  The execution continue when the message has been sent.
- Options are named (`dst=...`), except that a lone option of a layer that
  has a default field is that field: `Bytes("x")` is `Bytes(data="x")`.
- Options belong to the stack, not to the stream: those of a block's stack
  apply to everything sent from that block, those of a message to that
  message only.
- Options are guessed when left out. For instance, ports or protocol fields
  can
  be guessed from upper protocols.
- Each leading `../` goes one layer down the current stack. A layer that
  then lands over the same layer of the current stack overlays it: it takes
  its keys and options, and those it gives override them. `../TCP!` is
  thus the same connection, sent by hand.


**Streams.** The layers of a stack are *nodes*, keyed by what tells streams
apart. These keys are the IP addresses, the TCP and UDP ports, and the echo
and DNS ids. Two stacks that give the same keys share their nodes, and so the state
of the protocol: the TCP connection, the IP ids, the echo sequence numbers.

A TCP connection opens when its first message is sent, and closes once no
block uses its stack any more. To insert a manual segment into it, overlay
its layer:

```
/IP(dst=192.0.2.10)/TCP(src=40000, dst=7) {
  Bytes("hello\n")
  expect timeout=2s Bytes("hello\n") { print("echoed") }
  # A RST, on that same connection:
  ../TCP!(flags=RST)/Bytes()
}
```

A manual layer cannot carry a self-driven one: `IP/TCP!` is fine, `IP!/TCP` is
not.

### Patterns

A pattern describes a received packet, layer by layer:

- `/IP/UDP(dst == 7)/Bytes`: an *absolute* pattern, matched from the
  interface up.
- `Bytes("pong")`: a *relative* pattern, matched on top of the current
  stack, so only on its stream (here: what comes back on the block's UDP
  stream).
- `../ICMP/DestUnreachable`: relative to a layer below the top of the
  current stack, each `../` going one layer down. In a block on `IP/UDP`,
  this matches the ICMP errors that the IP stream receives. A layer over the
  same layer of the stack matches only its stream: in a block on `IP/TCP`,
  `../TCP!` sees the segments of that connection only.

A layer of a pattern can carry conditions in parentheses: any boolean
expression, where `,` and `=` can replace `&&` and `==`. In conditions:

- A bare name is a field of that layer if it has one, else a variable:
  `UDP(src == port)`.
- Fields of the layers below are read as `IP.src`. In tunnels and in the
  packets that ICMP errors quote, `IP^.src` is that of the IP layer below
  the last one, and `^IP.src` of the first.
- A condition that is not a bool, on a layer with a default field, compares
  that field: `Bytes("pong")` is `Bytes(data == "pong")`. An int condition
  is true when it is not zero: `TCP!(flags & RST)`.
- Which fields can be read depends on the mode the layer is matched in (see
  [Layers](#layers)). A self-driven `TCP` shows only its ports, and a
  manual `TCP!` shows each segment's header.

A layer whose header names what it carries (the `proto` of IP, the `type` of
ICMP) is decoded only as that. What UDP, TCP and the ICMP errors carry is
decoded as each layer that a stream or a pattern expects there, so that a
datagram can match both `UDP/DNS/Query` and `UDP/Bytes`. `MATCH` is decoded
past the pattern as `Bytes` only, but for the packet an ICMP error quotes,
which is decoded as `IP` when it can be.

A packet matches a pattern in one mode at most:

- a fragment is seen by `IP!` only, and a reassembled packet by `IP` only;
- the data of a TCP connection is seen by `TCP/Bytes` in order, once per
  chunk delivered, and each segment is seen by `TCP!`.

**`MATCH`** is the packet that matched, decoded up to its top layer, as an
array of layers. `MATCH[UDP]` selects the last UDP layer, `MATCH[IP^]` the
last IP layer but one, `MATCH[^IP]` the first IP layer. Fields are then read
with a dot: `MATCH[IP].src`, `MATCH[Bytes].data`. An item of the array,
such as `MATCH[0]`, is a layer of any kind: a `case` tells which, and reads
its fields:

```
foreach MATCH {
  print(case I IP { "IP from ${I.src}" } | UDP { "UDP to ${I.dst}" } else { "other" })
}
```

**`LAST`** is the last packet sent, an array of layers like `MATCH`. Defined
after each terminal stack, shadowing the previous.  Self-driven layers do not
reveal the fields set by their internal engine: Picked source ports are
accessible, checksums are unset.

### Special forms

Their parameters are written `name=value`. A form with a single parameter
also takes it unnamed (`break 2`, `wait 1s`).

- `{ ... }`: A block of its own: its variables and patterns end with it.
  Its value is that of its last statement (see
  [Expressions](#expressions)).
- `repeat var=v count=n every=d for=d { ... }`: Runs the block `count`
  times, or as long as `for` (default 5m) has not elapsed. An iteration
  starts `every` after the previous one started, or when that one ends if it
  ends later. `v` (default `I`) counts from 0. All parameters are optional.
  `count=0` runs nothing.
- `retry max=n { ... }`: Runs the block, and again up to `n` times (default
  3) while it fails. If the last try fails too, its error escapes the retry
  block.
- `catch { ... }`: Leaves the block at its first error, which goes no
  further: the program goes on after the block.
- `if c { ... } elsif c { ... } else { ... }`: Runs the block of the first
  condition that holds, if any. An int condition holds unless it is 0 (`if
  flags & SYN`). There can be any number of `elsif`, and an `else` may start
  the line after the brace before it. Its value is that of the block it
  ran.
- `case var=v X C { ... } | C { ... } ... else { ... }`: Runs the block of
  the constructor of `X`'s value, or else the `else` block, if any.
  Without `var`, a variable `X` is itself what the constructor holds.
  A `|` may end a line or start the next one. Its value is that of the block
  it ran.
- `foreach v every=d for=d ARRAY { ... }`: A `repeat` that runs the
  block once per item of the array, in order, `v` (default `I`, also
  `var=v`) being the item. The array is computed once, before the first
  iteration. `every` and `for` are as for `repeat`, and optional. The items
  of a map are records `{key: k, value: v}`.
- `break depth=n`: Leaves the `n` (default 1, a literal) innermost enclosing
  `repeat`, `foreach` or `on` forms.
- `wait dur=d`: Pauses for `d`. A negative duration is an error.
- `expect timeout=d PATTERN { ... }`: Waits for one packet that matches
  (default timeout 1m), then runs the block with `MATCH` bound to it. A
  timeout is an error.
- `any timeout=d PATTERN { ... } | PATTERN { ... } ...`: Waits for the first
  packet that matches any of the patterns (default timeout 1m), then runs
  the block of that pattern only, with `MATCH` bound to it. A `|` may end a
  line or start the next one. A timeout is an error.
- `on timeout=d max=n PATTERN { ... }`: Lets the enclosing block go on, and
  runs a new block for each matching packet, each with its own `MATCH`. It
  ends at its timeout (default 1m, not an error), after its `max`th match,
  or at a `break` from one of its blocks.

A block completes when its statements are done and all its `on` forms have
ended, including their running blocks. Leaving a block, normally or on an
error, cancels whatever it still had going: patterns, timers, inner blocks,
and the nodes it held.

### Functions

- `print(s)`, `print_err(s)`: Writes the string to the output, or to the
  error output.
- `assert(cond, msg=s)`: Fails if `cond` is false. The default message
  quotes the condition.
- `rand(max)`: A random int in `[0, max)`, a float in `[0, max)` (default
  `max` is 1.0), or a random bool if `max` is `true`.
- `randbytes(len)`: `len` random bytes.
- `exp(x)`, `ln(x)`, `log(x)`: Floats; `log` is in base 10.
- `log2(n)`: The integer base 2 logarithm of a positive int.
- `int(x)`, `float(x)`, `bool(x)`, `byte(x)`: Conversions between bools,
  ints, floats and bytes (`byte` keeps the low 8 bits). `int` and `float`
  also take an interval, as seconds, and a time, as seconds since 1970
  (`int` truncates).
- `interval(secs)`: The interval of that many seconds.
- `time(secs)`: The time that many seconds after 1970-01-01T00:00:00Z.
- `now()`: The current time: the clock of the host when crafty runs a
  program.
- `getenv(name, default=s)`: An environment variable (fails if unset and
  no default).
- `array(init=v, len=n)`: An array of `n` items, all `v`.
- `length(a)`: The length of an array, a map or a string.
- `concat(a, b)`, `append(a, x)`, `prepend(x, a)`: as with `+`.
- `map(key=k, default=v)`: see maps above.
- `has(m, k)`, `remove(m, k)`: Whether map `m` has key `k`; `m` without it.
- `keys(m)`, `values(m)`: Arrays of the keys and the values of a map.
- `count(a)`: Same as `length`.
- `sum(a)`: Of the numbers or intervals of an array, or of the values of a
  map; 0 if there are none.
- `sorted(a)`: A sorted copy of an array of ordered values. `sort(a)`, a
  statement, sorts the array `a` (a variable, or an item of one).
- `min(a)`, `max(a)`, `mean(a)`, `stddev(a)`, `percentile(a, p)`: Over the
  items of an array, or the values of a map; an error if there are none.
  `mean` and `stddev` (of the population) take numbers (giving a float) or
  intervals, the others anything ordered.
  `percentile` is the nearest rank: the smallest value that at least `p`
  percent of them do not exceed (`percentile(a, 50)`, the median).

An argument can be left unnamed when the function has a single parameter,
when it is the only parameter without a default (`assert(x == 4)`), or when
no parameter has a default and all are given in order (`append(a, x)`).
Otherwise arguments are named.

### Layers

Each field is listed with its type, then *set* and *read* say in which modes
it can be given as an option and read in a condition or in `MATCH`: **M** for
manual, **S** for self-driven. A layer with a single mode is always manual.
Fields marked *(key)* are the keys of a stream.

#### `Eth`: Ethernet (bottom of every stack)

- `src`: mac; set M; read M, S. Default: the interface's address.
- `dst`: mac; set M; read M, S. Default: what the interface knows of the
  destination (ARP cache, gateway), without asking.
- `proto`: int; set M; read M, S. Default: what the layer on top is.

Self-driven, it carries only IPv4, and finds destinations with ARP. The
interface answers ARP for its address, unless it shares that address with
the host (without the `--ip` command line argument), whose kernel answers.
`Eth!` frames are emitted as they are.

#### `IP`: IPv4 (on `Eth`)

- `src` (key): ip; set M, S; read M, S. Default: the interface's address.
- `dst` (key): ip; set M, S; read M, S. Required.
- `proto`: int; set M, S; read M, S. Default: what the layer on top is.
- `tos`: int; set M, S; read M, S.
- `ttl`: int; set M, S; read M, S. Default 64.
- `dont_frag`: bool; set M, S; read M, S. Default false.
- `id`: int; set M; read M, S. Default: the stream's counter, from a random
  value.
- `more_frags`: bool; set M; read M.
- `frag_offset`: int; set M; read M.
- `tot_len`: int; set M; read M. Default: computed.
- `options`: bytes; set M, S; read M, S.
- `is_fragment`: bool; cannot be set; read M.

Self-driven IP fragments to the interface's MTU and reassembles: an `IP`
pattern sees a fragmented packet once complete, with the `id` its fragments
share and the `options` of the first one, and an `IP!` pattern sees each
fragment. The `tos`, `ttl`, `dont_frag` and `options` fields apply to the
packets it sends (only the options with the copied flag go into fragments
after the first), but not to the segments of a self-driven TCP connection,
which sends them on its own. `IP!` sends the header as given, but for the header
checksum, which is always computed.

#### `TCP` (on `IP`)

- `src` (key): int; set M, S; read M, S. Default: a free local port.
- `dst` (key): int; set M, S; read M, S. Required.
- `seq_num`: int; set M; read M.
- `ack_num`: int; set M; read M.
- `flags`: int; set M; read M. Constants `FIN`, `SYN`, `RST`, `PSH`, `ACK`,
  `URG`.
- `win_size`: int; set M; read M.
- `urg_ptr`: int; set M; read M.
- `checksum`: int; set M; read M. Default: computed, as it is when given 0.
- `mss`: int; set S; cannot be read. The MSS of the connection.

Self-driven, the first packet sent on a TCP node connects it, and what
follows waits for the connection. A TCP node created by a pattern accepts
the connection instead.

`TCP!` segments take the sequence and ack numbers, the window and the
ACK|PSH flags of the node's connection when not given, and the connection
accounts for them: they advance its sequence, FIN closes it, and RST aborts
it. They are not retransmitted. Sending one while the connection
is being established is an error. Without a connection, `TCP!` counts its
sequence numbers from a random one.

#### `UDP` (on `IP`)

- `src` (key): int; set M; read M. Default: a free local port.
- `dst` (key): int; set M; read M. Required, unless told by the layer on
  top.
- `length`: int; set M; read M. Default: computed.
- `checksum`: int; set M; read M. Default: computed, as it is when given 0.

#### `ICMP` (on `IP`)

- `type`: int; cannot be set; read M.
- `code`: int; cannot be set; read M.

Its type and code are set by the message on top of it.

#### `Echo` (on `ICMP`)

- `id` (key): int; set M; read M. Default: a free random id.

`Echo` has no header of its own. It is the stream of an echo id, on which
`Request` and `Reply` messages go. The sequence numbers of its messages are
counted per stream.

#### `Request` and `Reply` (on `Echo`, terminal)

- `seq`: int; set M; read M. Default: the stream's counter, from 1.
- `payload`: bytes; set M; read M. Default field.

#### `DestUnreachable` and `TimeExceeded` (on `ICMP`)

- `code`: int; set M; read M. Default 0.
- `mtu`: int; set M; read M. `DestUnreachable` only; default 0.

Constants for `code`: `NET_UNREACHABLE`, `HOST_UNREACHABLE`,
`PROTOCOL_UNREACHABLE`, `PORT_UNREACHABLE`, `FRAG_NEEDED`,
`SOURCE_ROUTE_FAILED` (for `DestUnreachable`); `TTL_EXCEEDED`,
`REASSEMBLY_TIMEOUT` (for `TimeExceeded`).

On top of them is the start of the packet the error is about: a quoted
`IP`, or `Bytes`.

#### Quoted `IP`, and `UDP` and `TCP` on top of it (on `DestUnreachable` and `TimeExceeded`)

The packet that an ICMP error quotes has the fields of `IP`, `UDP` and
`TCP`, all of which can be read and set but for `is_fragment`, and none of
`TCP`'s `mss`. Its layers are manual only, are no streams and have no
keys, so that what they hold changes nothing to the streams of the
program: a quoted TCP segment is no part of a connection. Errors print them
as `IP?`, `UDP?` and `TCP?`.

```
on /IP/ICMP/TimeExceeded/IP(dst == target)/UDP(dst == 33434) {
  print("from ${MATCH[^IP].src}, ttl ${MATCH[IP].ttl}")
}
```

`MATCH[IP]` is the quoted packet, and `MATCH[^IP]` the error's.

A quote is often cut short, at 8 bytes after the IP header: its `IP` and
`UDP` keep the lengths they announce, and the payload is what is left. Of
`TCP`, only the ports and `seq_num` are sure to be there; the other fields
read 0 when cut off. Sent, a quoted `IP` needs a `src` and a `dst`, and
its lengths are computed unless given, as are the checksums of `UDP` and
`TCP`.

#### `DNS` (on `UDP`)

- `id` (key): int; set M; read M. Default: a free random id.

`DNS` has no header of its own but the id. It is the stream of an id, on
which `Query` and `Answer` messages go, told apart by the QR bit.

#### `Query` and `Answer` (on `DNS`, terminal)

- `name`: string; set M; read M. Default field; required.
- `type`: int; set M; read M. Default `TYPE_A`.
- `class`: int; set M; read M. Default `CLASS_IN`.
- `opcode`: int; set M; read M. Default 0.
- `authoritative`: bool; set M; read M. Default false.
- `truncated`: bool; set M; read M. Default false.
- `rec_desired`: bool; set M; read M. Default true.
- `rec_avail`: bool; set M; read M. Default false.
- `authentic_data`: bool; set M; read M. Default false.
- `checking_disabled`: bool; set M; read M. Default false.
- `status`: int; set M; read M. Default `NOERROR`.
- `answers`: records; set M; read M. Default none.
- `authority`: records; set M; read M. Default none.
- `additional`: records; set M; read M. Default none.

A message has one question, of `name`, `type` and `class`; of a received
message with several, these are the first. Names are written without the
trailing dot (`"example.com"`), but for the root (`"."`). The records of
the three sections are `{name: string, type: int, class: int, ttl: int,
data: bytes}`; the data of an A record converts to an IP address.

Constants for `type`: `TYPE_A`, `TYPE_NS`, `TYPE_CNAME`, `TYPE_SOA`,
`TYPE_PTR`, `TYPE_MX`, `TYPE_TXT`, `TYPE_AAAA`, `TYPE_SRV`, `TYPE_ANY`; for
`class`: `CLASS_IN`; for `status`: `NOERROR`, `FORMERR`, `SERVFAIL`,
`NXDOMAIN`, `NOTIMP`, `REFUSED`.

#### `Bytes` (on `Eth`, `IP`, `TCP`, `UDP`, the ICMP errors and the quoted layers, terminal)

- `data`: bytes; set M; read M. Default field.

It is what a layer carries when it is not decoded any further: the payload
of UDP, the data of TCP, a fragment, a quote, or an unknown protocol.

### Not available yet

The keyword `report`, matching embedded packets with
`=~`, the HTTP
layer, IPv6, VLANs and tunnels. Using any of them is reported as
unsupported.

## 3. Examples

All these examples were run against a host with UDP and TCP echo servers on
port 7. The command lines show the `crafty` options they need.

### Ping

```
target = 192.0.2.10
/IP(dst=target)/ICMP/Echo {
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

The `Echo` stream picks an id, and its requests count their sequence
numbers. The replies come back to that stream, so `Reply` needs no
condition on the id.

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

The answer comes back on the `DNS` stream of the query's id. The first
record is the address only if the name has no CNAME, which the `assert`
checks.

### A UDP echo server

```
# Echo back, for a minute, whatever comes to UDP port 7.
on timeout=1m /IP/UDP(dst == 7)/Bytes {
  /IP(dst=MATCH[IP].src)/UDP(src=7, dst=MATCH[UDP].src)/Bytes(MATCH[Bytes].data)
}
```

```
% sudo crafty -i eth0 --udp 7 --fw server.cfty
```

The pattern is absolute, as there is no current stack. The answer's stack
names the stream the request came on, so it uses the node that the pattern
created.

### Losses per flow

```
# 4 flows of 25 datagrams to the UDP echo server: how many get no echo?
target = 192.0.2.10
lost = array(init=25, len=4)
{
  on timeout=2s /IP(src == target)/UDP(src == 7, dst >= 40000, dst < 40004) {
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

### Is a port closed?

```
/IP(dst=192.0.2.10)/TCP(src=40001, dst=22) {
  Bytes("hello")
  expect timeout=1s ../TCP!(flags & RST) { print("reset by ${MATCH[IP].src}") }
}
```

The self-driven connection sends a SYN. A reset is not data, so a pattern on
top of `TCP` would never see it, while `../TCP!` sees the segments of that
connection.

### A TCP port scan

```
# Which of the ports 1 to 100 accept TCP connections?
target = 192.0.2.10
{
  on timeout=2s /IP(src == target)/TCP!(src >= 1, src <= 100, flags == SYN | ACK) {
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

The `on` starts waiting before the SYNs go out, and the bare block lasts
until it times out, 2 seconds later. `--fw` keeps the host's kernel from
resetting connections it knows nothing of.

### Traceroute

```
# The routers on the way to a host, as traceroute finds them.
target = 192.0.2.10
repeat var=hop count=30 {
  ttl = hop + 1
  port = 33434 + hop
  {
    on max=1 timeout=1s /IP/ICMP/TimeExceeded(code == TTL_EXCEEDED)/IP/UDP(dst == port) {
      print("${ttl}: ${MATCH[^IP].src}")
    }
    on max=1 timeout=1s /IP/ICMP/DestUnreachable(code == PORT_UNREACHABLE)/IP/UDP(dst == port) {
      print("${ttl}: ${target}, reached")
      break 2
    }
    /IP(dst=target, ttl=ttl)/UDP(dst=port)/Bytes("probe")
  }
}
```

Each probe waits for whichever answer comes first: a router's that the TTL
ran out, or the target's that the port is unreachable. The patterns are
absolute, as routers have addresses of their own, and tell the answers to
each probe by the destination port of the packet they quote: `MATCH[IP]`
is the quoted probe, and `MATCH[^IP]` the error. `break 2` leaves both the
`on` and the `repeat`.

### Giving up gracefully

```
# Try three times to get an answer, then give up quietly.
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
# A broadcast frame of an experimental protocol, then an IPv4 packet with a
# hand-made header.
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
delay = interval(0.5) * 3
print("waiting ${delay}")
wait delay
x = rand(10)
assert(x >= 0 && x < 10, msg="rand gave ${x}")
```

prints:

```
gw is 192.0.2.1; 2076 bytes in 3 packets
[tcp: 1, udp: 2], and 0 icmp
64 to 1500, median 512
waiting 1s500ms
```
