(* Generated from docs/crafty.md (md5 8368601669d82c290ae2ff73125c0a1f) by the Makefile. Do not edit. *)
let introduction = {crafty_manual|### A first program

    # Three datagrams to a UDP echo server: how many come back?
    # "IP", "UDP" and "Raw" are layers of a protocol stack. Every stack
    # starts at the interface, with an "Eth" layer that can be left out:
    # /IP(dst=192.0.2.10)/UDP(dst=7) is /Eth/IP(dst=192.0.2.10)/UDP(dst=7).
    # Followed by a block, a stack is the current stack of that block:
    /IP(dst=192.0.2.10)/UDP(dst=7) {
      answers = 0                     # "answers" is a variable holding integers
      # Repeats the block 3 times, "I" being the loop counter, from 0:
      repeat var=I count=3 every=100ms {
        # Raw is a terminal layer: it sends the message made from
        # /IP(dst=192.0.2.10)/UDP(dst=7)/Raw("ping ${I}")
        # Unset options will be filled in automatically.
        Raw("ping ${I}")
        catch {                       # a lost answer is no error
          # expect waits for a packet that matches a pattern; here, any Raw
          # layer on top of the current stack, coming back:
          expect timeout=1s Raw {
            answers += 1
            print(MATCH[Raw].data)  # MATCH is the packet that matched
          }
        }
      }
      print("${answers} answers out of 3")
    }

    % sudo crafty --udp 40000-40010 --fw intro.cfty
    ...
    ping 0
    ping 1
    ping 2
    3 answers out of 3
    Done after 0.3s, status: OK.

A stack is layers and their options, separated by slashes, like file paths. An
absolute stack starts with `/IP` (with an `Eth` layer implied). A relative stack
goes on top of the current one.

Some layers are terminal (`Raw`, `Request`, `Reply`, `Query`, `Answer`): they
end the stack and send the message. An incomplete stack is followed instead by a
block of further instructions.

The layers of a stack are streams: `UDP` picks its source port once (from
`--udp`), and every message sent and every pattern on top of it belong to that
stream.

An `expect` that times out is an error. An error leaves the enclosing blocks one
after the other, until a `catch` drops it or a `retry` runs its block again; one
that reaches the top ends the program.

The language is statically typed.

### Going down the stack

    # Is anyone listening on UDP port 7?
    target = ip_addr(getenv("TARGET"))  # Read the envvar and cast to an IP, or fail
    /IP(dst=target)/UDP(dst=7) {
      Raw("hello")      # two messages on top of the same stack:
      Raw("world")      # the same stream, from the same port
      # Waits for the first packet that matches either pattern: a datagram
      # back, or the ICMP error a closed port answers with. "../" goes back to
      # /IP(dst=target), and ICMP goes on top of that IP stream instead of
      # UDP: these are the ICMP errors that it receives.
      first timeout=1s Raw { print(MATCH[Raw].data) }
        | ../ICMP/DestUnreachable(code == PORT_UNREACHABLE) { print("closed") }
    }

    hello

With `dst=8`, where nothing listens, it prints `closed`.

Each leading `../` goes one layer down the current stack: here, `../` is
`/IP(dst=target)` and `../../` is `/Eth`. Relative stacks reuse opened streams,
whereas absolute stacks create new streams: `/IP/ICMP/DestUnreachable` matches
any Dest-Unreachable packet whereas `../ICMP` matches only those from the same
`IP/UDP` stream.

### Overlaying

Like relative patterns, relative stacks can go back with `../` and modify upper
layers' options while reusing the stream:

    # The same stream, but for one datagram with a TTL of 1:
    /IP(dst=192.0.2.10)/UDP(dst=7) {
      Raw("ttl 64")
      print("Sent from port ${LAST[UDP].src}")   # LAST is the last packet sent
      # ../../ goes back to /Eth, where IP and UDP land on the IP and UDP of
      # the current stack. They overlay them: the same streams, with their
      # options (dst, the ports) unless given. ttl=1 is for this message only.
      ../../IP(ttl=1)/UDP/Raw("ttl 1")
      print("Also sent from port ${LAST[UDP].src}")
      repeat count=2 {
        # Wait for Raw in the same stream (unlike with /IP/UDP/Raw that would
        # match even outside this stream)
        expect timeout=1s Raw { print(MATCH[Raw].data) }
      }
    }

    Sent from port 40000
    Also sent from port 40000
    ttl 64
    ttl 1

The rule, for stacks and patterns alike: relative ones stay on the streams of
the current stack (`../` overlaying some of its layers); absolute ones start
anew from `Eth`. Overlaying can set a temporary value for an earlier option;
unless that's a key: `../IP(dst=another)` would create a new stream indeed.

### Manual layers

So far, streams were *self-driven*: crafty resolves addresses with ARP,
connects, retransmits, fragments and reassembles. A bang makes a layer *manual*,
for packets as on the wire: `TCP!(flags=SYN, ack_num=0)` is a SYN packet with
this sequence number regardless of the state of the TCP connection. On
reception, `IP!` sees each fragment and `TCP!` each segment, even without data.

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
      seg = /IP!(dst=target)/TCP!(src=40000, dst=7, flags=SYN, seq_num=1000)/Raw()
      print("SYN of seq ${seg[TCP].seq_num} sent")
    }

    % sudo crafty --tcp 40000 --fw syn.cfty
    SYN of seq 1000 sent
    SYN-ACK: seq 1969569245, ack 1001

### Running crafty

`crafty [options] file [arg...]` or `crafty [options] -e program [arg...]`.

What follow the file are the program's own arguments (that are returned by
`arg(n)`. With `-e`, every argument that's not an option is a program's
argument, and `--` ends the options.

Options:

-   `-e PROG`: the program itself, rather than a file.
-   `-i IFACE`: the interface to send from and capture on, rather than that of
    the default route. Crafty needs root.
-   `--tcp LO-HI`, `--udp LO-HI` (repeatable): the ranges to pick source ports
    from, with the program's `PORTS` (see [Budget and
    ports](#budget-and-ports)). A program that sends TCP or UDP without a `src`
    needs them.
-   `--fw`: crafty shares the interface's address with the host, whose kernel
    would answer what crafty receives with TCP resets and ICMP port
    unreachables. `--fw` keeps the kernel off the ports of `--tcp` and `--udp`.
-   `--ip ADDR`: an address of crafty's own instead, on the interface's network,
    for which crafty answers ARP. Then `--fw` is not needed, nor allowed.
-   `-p [/PATTERN]` (or `--print-packets`): prints the packets à la tcpdump.
-   `--format csv|json`: change the output format to csv or json (json makes -p
    print all available details of every packet).
-   `--stats`: prints the stats of each stream (see `stats()`) as it ends.
-   `--check`: only compiles the program.
-   `--max-duration`, `--max-packets`, `--max-bytes`, `--max-packets-per-secs`,
    `--max-bytes-per-secs`, `--max-syns`, `--max-syns-per-secs`: self-imposed
    budget.
-   `--reference`: prints the reference manual.
-   `--examples`: prints many examples of use.
-   `--cliref`: exhaustive list of options including seldom used ones.

Exit status: 0 when the program completes, 1 when an error ends it, 2 when it
does not compile, 3 when a budget stops it, 130 when interrupted.

### Tips

-   Use `resolve("hostname")` to resolve a hostname
-   Errors and warnings go to stderr, all else to stdout: filter stdout as you
    like, but not stderr (`crafty x.cfty | grep ...`, not `2>&1 | grep`)
-   Parameterize your programs with arguments (`crafty x.cfty 10.0.0.1 5`, read
    with `arg(0)`, `arg(1)`) or environment variables
    (`TARGET=10.0.0.1 crafty x.cfty`, read with `getenv("TARGET")`)
-   When unsure, use --max-duration
|crafty_manual}

let reference = {crafty_manual|### Lexical conventions

-   A statement ends at the end of its line or at a `;`. Within parentheses,
    brackets and braces, after a binary operator, or before an `else`, `elsif`
    or `|`, a new line is plain white space. A block opens on the line of the
    statement it belongs to.
-   Comments run from a `#` to the end of the line. A `#` followed by a
    hexadecimal digit is a byte literal instead.
-   Names of layers, fields, functions and keywords are case insensitive.
    Constants, `MATCH` and `LAST` are upper case. All but field names are
    reserved. Variables and constructors are case sensitive.

### Types and literals

-   `bool`: `true`, `false`.
-   `int`: `42`, `-1`, `0x1f`, `0o17`, `0b101`.
-   `float`: `1.5`, `2e-3`.
-   `byte`: `#1f`.
-   bytes: `#deadbeef` (an even number of digits), or a string where bytes are
    expected. An array of bytes.
-   `string`: `"text ${expr}"`.
-   `interval`: `5s`, `10ms`, `1m30s`, `1.5ms`, `-2s`. Units: `d`, `h`, `m`,
    `s`, `ms`, `us` (or `µs`), `ns`, `ps`. Printed in one unit up to `s`, to 6
    significant digits: `157.949ms`, `8.85159µs`, `3725.5s`.
-   `time`: `2026-10-20T22:02:45.25Z`, `2026-10-20T22:02+02:00`,
    `2026-10-20T22:02` (local time). Printed in UTC. `int(t)` and `float(t)`
    give its unix timestamp, `time(secs)` the reverse.
-   `ip`: `192.0.2.1`. IPv4 only.
-   `mac`: `aa:bb:cc:dd:ee:ff`.
-   arrays: `[1, 2, 3]`. Items of one type.
-   maps: `[192.0.2.1: "gw", 192.0.2.2: "dns"]`, a `string[ip]`, in no
    particular order. `map(key=k, default=v)` is an empty map with keys of the
    type of `k`, where missing keys have the value `v` (tip: `[0s] * 0` is an
    empty array with a known type!).
-   records: `{name: "gw", ip: 192.0.2.1}`. `{}` is an empty block, not a
    record.
-   variants: `Ok(42)`, `Failed("timeout")`, `Pending`. A constructor starts
    with a capital letter; a bare name that is a variable is the variable. The
    layers of a packet are variants too, of constructors `IP`, `UDP`...

Literals are whole words: `1.2.3.4` is an IP address, `5s` an interval.

Strings interpolate any expression: `"ttl ${MATCH[IP].ttl - 1}"`. Escapes: `\n`,
`\r`, `\t`, `\0`, `\\`, `\"`, `\$`, `\xHH`. Interpolated bytes are written in
hexadecimal (`#68656c6c6f`); bytes passed where a string is expected, as to
`print`, are text.

**Conversions** happen where needed: an int to a float, a byte to an int, a
string, an IP address or a MAC address to bytes and back (4 and 6 bytes), an int
to a bool. Bytes compare with the others as bytes. Others use the functions
`int`, `float`, `bool`, `byte`, `interval`, `time`, `ip_addr` and `mac_addr`,
which also read a string as a literal: `ip_addr(getenv("SERVER"))`. An IPv4
address converts to an int and back: `ip_addr(int(a) + 1)`. `bytes(x)` makes
bytes of a byte or of what converts to them, for `+`: `#0102 + bytes(10.0.0.1)`.
`checksum(b)` is the 2 bytes of the Internet checksum of `b` (RFC 1071):
`h1 + checksum(h1 + #0000 + h2) + h2`.

**Variants** need no declaration. Where variants meet (items of an array,
branches of an `if`, values assigned to a variable...), they make one variant
with the constructors of all, which `case` tells apart:

    result = Pending   # of type (Failed string | Got int | Pending)
    first Raw("pong") { result := Got(length(MATCH)) }
      | ../ICMP { result := Failed("unreachable") }
    print(case result Got { "${I} layers" } else { "${result}" })

### Variables

-   `x = expr` declares `x` in the current block, with the type of `expr`.
    Declaring a name twice in one block is an error; an inner block may shadow
    it.
-   `x := expr` assigns it, and `x += expr` (also `-=`, `*=`, etc.) updates it.
-   Predefined: `MATCH` (in the block of an `expect`, `first` or `on`), `LAST`
    (the last packet sent, once a block has sent one), `I`, the counter of a
    `repeat` or the item of a `foreach`, and `BUDGET` and `PORTS`.
-   `LAST` is the packet as given, not as it left: reading a field that only the
    wire knows (`LAST[Eth].ts`, or `IP.id`, `UDP.checksum`... under a
    self-driven `IP`) is an error. `p = MESSAGE` captures the packet as it
    leaves (see [Self-driven vs manual stacks](#self-driven-vs-manual-stacks)).

### Budget and ports

A program may declare them, once each, at its top level, with literals only:

    BUDGET = {max_duration: 30s, max_syns: 30}
    PORTS = {tcp: [[40000, 40100]], udp: [[5000, 5000]]}

-   `BUDGET`'s fields are the budget options of crafty, named alike.
-   `PORTS` has ranges `[first, last]` by protocol; a protocol left out gets no
    port.
-   crafty runs with what both the program and the command line allow.

### Expressions

Operators, from the tightest binding to the loosest:

1.  `!x`, `-x`.
2.  `*`, `/`, `%`: on numbers. An array (or a byte) times an int repeats it:
    `#01 * 2` is `#0101`, `[0] * 3` is `[0, 0, 0]`.
3.  `+`, `-`: on numbers; a time minus a time is an interval, a time plus an
    interval (or a number of seconds) is a time. `+` also concatenates arrays
    (`[1] + [2, 3]`) and appends or prepends an item (`[1, 2] + 3`,
    `0 + [1, 2]`). Strings do not add up: interpolate them.
4.  `<<`, `>>`: shift an int or a byte by an int; `>>` keeps the sign of an int,
    and a byte stays 8 bits.
5.  `&`, then `^`, then `|`: bitwise, on ints or bytes. They bind tighter than
    comparisons: `flags & RST == 0` is `(flags & RST) == 0`.
6.  `==`, `!=`, `<`, `<=`, `>`, `>=`: they do not chain; ordering works on
    numbers, bytes, intervals, times and strings.
7.  `&&`, then `||`.

Also: `r.field`, `a[i]` (`a[-1]` is the last item), `m[k]` (else the default,
else an error), `f(arg, name=arg)`, and the layer selectors of
[Patterns](#patterns). Arrays, bytes and strings slice as in Python. `a[i] := v`
and `m[k] += 1` change an item, adding the key to a map if need be.

**Blocks, `if` and `case` are expressions**:

    y = if cond 1 else 2
    ttl = case var=h MATCH[1] IP { h.ttl } else { 0 }
    rtt = { t0 = now() ; Request("ping") ; expect Reply {} ; now() - t0 }

A block can wait, send, receive, loop or `break` only as the whole value of a
declaration, an assignment or a statement: `n = 1 + { wait 1s ; 1 }` is an
error.

### Self-driven vs manual stacks

Sent messages can be assigned to a variable if they are purely manual:

`p = /IP!(dst=target)/TCP!(src=1, dst=2, flags=SYN)/Raw()`

This sends a packet and waits until that packet is recaptured on its way out.
Its timestamp `p[Eth].ts` is therefore accurate.

Self-driven and manual layers can be mixed with some restrictions: a manual
layer cannot carry a self-driven one: `IP/TCP!` is fine, `IP!/TCP` is not.

### Patterns

-   `/IP/UDP(dst == 7)/Raw`: *absolute*, matched from the interface up, on any
    stream.
-   `Raw("pong")`: *relative*, on top of the current stack, so only on its
    stream.
-   `../ICMP/DestUnreachable`: relative to a layer below the top of the current
    stack.
-   `Raw("pong") | ../ICMP`: alternatives.
-   `UDP(src == port)`: conditions in parentheses are boolean expressions. A
    bare name is a variable if there is one (`port`), else a field of the layer
    (`src`).
-   `IP.src` is the field of the last IP layer, this one included. When there
    are several (a tunnel, the packet an ICMP error quotes), `IP^.src` is the IP
    layer below the last one, and `^IP.src` the first.
-   A condition that is not a bool compares the default field: `Raw("pong")` is
    `Raw(data == "pong")`.
-   The fields that can be read depend on the mode (see [Layers](#layers)): a
    self-driven `TCP` shows its ports, a manual `TCP!` each segment's header.

A packet matches in one mode only: a fragment `IP!`, a reassembled packet `IP`;
TCP data `TCP/Raw`, in order and once per chunk delivered, and each segment
`TCP!`.

**`MATCH`** is the packet that matched, as an array of layers. `MATCH[UDP]` is
its last UDP layer, `MATCH[IP^]` the last IP but one, `MATCH[^IP]` the first;
then `MATCH[IP].src`, `MATCH[Raw].data`. `MATCH[0]` is a layer of any kind,
which `case` tells apart:

    foreach MATCH {
      print(case I IP { "IP from ${I.src}" } | UDP { "UDP to ${I.dst}" } else { "other" })
    }

**`LAST`**, likewise, is the last packet sent. Self-driven layers show their
options, what crafty picked (source ports) and their defaults (`ttl`), but not
what their engine computes (checksums).

### Special forms

-   `repeat var=v count=n every=d for=d { ... }`: runs the block `count` times,
    or while `for` (default 1m) has not elapsed. An iteration starts `every`
    after the previous one started, or when it ends if later. `v` (default `I`)
    counts from 0.
-   `foreach v every=d for=d ARRAY { ... }`: a `repeat` over the items of the
    array or map (as `{key: k, value: v}`), `v` (default `I`) being the item.
-   `retry max=n { ... }`: runs the block again, up to `n` times (default 3),
    while it fails. The last error escapes.
-   `catch { ... }`: blocks error propagation.
-   `if COND STMT [elsif COND STMT] else STMT`: conditionals.
-   `case var=v X C { ... } | C { ... } else { ... }`: runs the block of the
    constructor of `X`, where `v` (default `I`) is what that constructor holds.
-   `break n`: leaves the `n` (default 1) innermost `repeat`, `foreach` or `on`.
-   `wait d` (or `sleep d`): pauses.
-   `expect timeout=d PATTERN { ... }`: waits for one matching packet, then runs
    the block; a timeout (none by default) is an error.
-   `first timeout=d PATTERN { ... } | PATTERN { ... }`: waits for the first
    packet that matches any pattern.
-   `on for=d linger=d timeout=d max=n PATTERN { ... } | PATTERN { ... }`: the
    enclosing block goes on; each matching packet runs the block of its pattern,
    repeatedly (`max` times or unlimited) until its lifetime or that of the
    enclosing blocks are over. `linger` (default 0) instructs that enclosing
    block to wait further.
-   `{ ... }`: a block; its variables and patterns end with it. A block ends
    once its statements are done, its `linger`s waited, and its `on`s with a
    `for` ended. Leaving a block, normally or on an error, cancels what it still
    had going: patterns, timers, inner blocks, and the streams it held, closing
    their connections.

### Functions

-   `print(x)`, `print_err(x)`: to stdout, to stderr, as `"${x}"` (bytes as
    text).
-   `format(x)`: any value as a string, in the format of `--format`. CSV takes a
    scalar, or a record, array or map of scalars; record fields come in the
    order of their names: `print(format(stats()))`.
-   `assert(cond, msg=s)`: fails if `cond` is false.
-   `now()`: the current time.
-   `stats()`: the stats of the stream at the top of the current stack, so far:
    `packets_out`, `packets_in`, `bytes_out`, `bytes_in` (the payloads at that
    layer). A self-driven TCP connection counts its segments, retransmissions
    included, and adds, as Linux's `tcp_info`: `bytes_acked`, `bytes_received`
    (in order), `retrans`, `dupacks`, `timeouts`, `holes_in` (gaps opened in
    what was received), `ooo_in` (segments filling a gap within `min_rtt` of the
    one beyond it: reordered, not resent), `dup_in` (segments with only data
    already received: the peer's spurious retransmissions), `srtt`, `rttvar`,
    `min_rtt`, `rtt_samples`, `rto`, `snd_mss`, `rcv_mss`, `cwnd`, `ssthresh`
    (2\^31-1 before any loss), `snd_wnd` (the peer's window), `rcv_wnd`,
    `snd_wscale` and `rcv_wscale` (the window shifts the peer and we offered, -1
    if none; scaling is on only if both offered one) and `established`. An IP
    stream adds `fragmented` (packets sent in fragments), `frags_out`,
    `frags_in`, `reassembled` and `reasm_timeouts` (incomplete after 30s).
-   `getenv(name, default=s)`: fails if unset and no default.
-   `arg(n, default=s)`: the n-th argument after the program, from 0; fails if
    missing and no default. `nargs()`: how many there are.
-   `resolve(name)`: the IPv4 addresses of a name, as an array, from the
    system's resolver; an address resolves to itself. `hostname(ip, default=s)`:
    the name of an address. Blocking, so better resolved before sending.
-   `rand(max)`: an int or a float in `[0, max)` (default 1.0), or a bool if
    `max` is `true`. `randbytes(len)`: random bytes.
-   `int(x)`, `float(x)`, `bool(x)`, `byte(x)` (the low 8 bits): `int` and
    `float` also take an interval, as seconds, and a time (see `time` above).
    `interval(secs)`: the reverse.
-   `exp(x)`, `ln(x)`, `log(x)` (base 10). `log2(n)`: the integer base 2
    logarithm of a positive int.
-   `split(s, by)`: the parts of `s` between the occurrences of `by`.
-   `array(init=v, len=n)`, `length(a)` (or `count(a)`, of an array, a map or a
    string), `concat(a, b)`, `append(a, x)`, `prepend(x, a)`.
-   `sorted(a)`: a sorted copy. `sort(a)`, a statement, sorts an array.
-   `has(m, k)`, `remove(m, k)` (a copy), `keys(m)`, `values(m)` on map `m`.
-   `sum(a)`, `min(a)`, `max(a)`, `mean(a)`, `stddev(a)`, `percentile(a, p)`: of
    an array, or the values of a map. Only `sum` takes none (0). `mean` and
    `stddev` take numbers (giving a float) or intervals. `percentile` is the
    smallest value that `p` percent of them do not exceed; 50 is the median.
-   `histogram(a, bucket=b)`: the values counted in buckets of width `b` from 0,
    as an array of `{min, count, max}`, `min` and `max` being the extreme values
    in the bucket.

### Layers

Each field has its type, and the modes in which it can be *set* as an option and
*read* in a condition or in `MATCH`: **M** manual, **S** self-driven. A layer
with a single mode is manual. *(key)* fields tell streams apart.

#### `Eth`: Ethernet (bottom of every stack)

-   `src`: mac; set M; read M, S. Default: the interface's.
-   `dst`: mac; set M; read M, S. Default: what the interface knows of the
    destination (ARP cache, gateway), without asking.
-   `proto`: int; set M; read M, S. Default: the layer on top.
-   `ts`: time; read M, S. When the frame was captured; for what is reassembled,
    the frame that completed it. Unset in `LAST`.

Self-driven, it carries only IPv4, and finds destinations with ARP. It answers
ARP for an address of its own (`--ip`); the host's kernel answers for the
interface's. `Eth!` frames go out as they are.

#### `IP`: IPv4

-   `src` (key): ip; set M, S; read M, S. Default: the interface's address.
-   `dst` (key): ip; set M, S; read M, S. Required.
-   `proto`: int; set M, S; read M, S. Default: the layer on top.
-   `tos`: int; set M, S; read M, S.
-   `ttl`: int; set M, S; read M, S. Default 64.
-   `dont_frag`: bool; set M, S; read M, S. Default false.
-   `id`: int; set M; read M, S. Default: the stream's counter, from a random
    value.
-   `more_frags`: bool; set M; read M.
-   `frag_offset`: int; set M; read M.
-   `tot_len`: int; set M; read M. Default: computed.
-   `options`: bytes; set M, S; read M, S.
-   `is_fragment`: bool; read M.

Self-driven IP fragments to the MTU and reassembles. `tos`, `ttl`, `dont_frag`
and `options` apply to what it sends, but for the segments of a self-driven TCP
connection. `IP!` sends the header as given, but for the checksum.

#### `TCP`

-   `src` (key): int; set M, S; read M, S. Default: a port of `--tcp`.
-   `dst` (key): int; set M, S; read M, S. Required.
-   `seq_num`: int; set M; read M.
-   `ack_num`: int; set M; read M.
-   `flags`: int; set M; read M. Constants `FIN`, `SYN`, `RST`, `PSH`, `ACK`,
    `URG`.
-   `win_size`: int; set M; read M.
-   `urg_ptr`: int; set M; read M.
-   `checksum`: int; set M; read M. Default: computed, as when 0.
-   `options`: bytes; set M; read M. Default: none.
-   `mss`, `wscale`: int; set M, S; read M. The first option of each kind, or
    -1.
-   `ts_val`, `ts_ecr`: int; set M; read M. Those of the timestamps option, or
    -1.
-   `sack_ok`: bool; set M; read M. Whether SACK is permitted.

The fields of the options cannot be given with `options`. A missing `ts_val` or
`ts_ecr` is 0. Self-driven, `mss` and `wscale` are what the connection offers
(default: the MTU less 40, and what fits the receive buffer; -1 offers no window
scaling, which caps its window at 64KiB); a `TCP!` over it does not send them.

Self-driven, the first message sent connects, and what follows waits for the
connection. A TCP stream created by a pattern accepts the connection instead.

`TCP!` segments take the sequence and ack numbers, the window and the ACK|PSH
flags of the stream's connection when not given, and the connection accounts for
them: they advance its sequence, FIN closes it, RST aborts it. They are not
retransmitted.

#### `UDP`

-   `src` (key): int; set M; read M. Default: a port of `--udp`.
-   `dst` (key): int; set M; read M. Required, unless told by the layer on top.
-   `length`: int; set M; read M. Default: computed.
-   `checksum`: int; set M; read M. Default: computed, as when 0.

#### `ICMP`

-   `type`, `code`: int; read M. Set by the message on top.

#### `Echo` (on `ICMP`)

-   `id` (key): int; set M; read M. Default: a free random id.

The stream of an echo id, for `Request` and `Reply` messages, which count their
sequence numbers per stream.

#### `Request` and `Reply` (on `Echo`, terminal)

-   `seq`: int; set M; read M. Default: the stream's counter, from 1.
-   `payload`: bytes; set M; read M. Default field.

#### `DestUnreachable` and `TimeExceeded` (on `ICMP`)

-   `code`: int; set M; read M. Default 0. Constants: `NET_UNREACHABLE`,
    `HOST_UNREACHABLE`, `PROTOCOL_UNREACHABLE`, `PORT_UNREACHABLE`,
    `FRAG_NEEDED`, `SOURCE_ROUTE_FAILED`; `TTL_EXCEEDED`, `REASSEMBLY_TIMEOUT`.
-   `mtu`: int; set M; read M. `DestUnreachable` only; default 0.

On top is the start of the packet the error is about: a quoted `IP`, or `Raw`.

#### Quoted `IP`, `UDP` and `TCP` (on `DestUnreachable` and `TimeExceeded`)

They have the fields of `IP`, `UDP` and `TCP` (but `is_fragment`), all readable
and settable. They are no streams: a quoted TCP segment is no part of a
connection. Errors print them as `IP?`, `UDP?`, `TCP?`.

    on for=5s /IP/ICMP/TimeExceeded/IP(dst == target)/UDP(dst == 33434) {
      print("from ${MATCH[^IP].src}, ttl ${MATCH[IP].ttl}")
    }

`MATCH[IP]` is the quoted packet, `MATCH[^IP]` the error's. A quote is often cut
8 bytes after the IP header: of `TCP`, only the ports and `seq_num` are then
sure, the other fields reading 0. Sent, a quoted `IP` needs a `src` and a `dst`;
lengths and checksums are computed unless given.

#### `DNS`

-   `id` (key): int; set M; read M. Default: a free random id.

The stream of a DNS id, for `Query` and `Answer` messages.

#### `Query` and `Answer` (on `DNS`, terminal)

-   `name`: string; set M; read M. Default field; required. Without the trailing
    dot (`"example.com"`), but for the root (`"."`).
-   `type`: int; set M; read M. Default `TYPE_A`. Constants `TYPE_A`, `TYPE_NS`,
    `TYPE_CNAME`, `TYPE_SOA`, `TYPE_PTR`, `TYPE_MX`, `TYPE_TXT`, `TYPE_AAAA`,
    `TYPE_SRV`, `TYPE_ANY`.
-   `class`: int; set M; read M. Default `CLASS_IN`.
-   `opcode`: int; set M; read M. Default 0.
-   `authoritative`, `truncated`, `rec_avail`, `authentic_data`,
    `checking_disabled`: bool; set M; read M. Default false.
-   `rec_desired`: bool; set M; read M. Default true.
-   `status`: int; set M; read M. Default `NOERROR`. Constants `NOERROR`,
    `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED`.
-   `answers`, `authority`, `additional`: records; set M; read M. Default none.
    Each is `{name: string, type: int, class: int, ttl: int, data: bytes}`; the
    data of an A record converts to an IP address.

A message has one question (`name`, `type`, `class`): the first, of a received
message with several.

#### `Raw` (on `Eth`, `IP`, `TCP`, `UDP`, the ICMP errors and the quoted layers, terminal)

-   `data`: bytes; set M; read M. Default field.

What a layer carries when not decoded further: the payload of UDP, the data of
TCP, a fragment, a quote, an unknown protocol. Sent as given.
|crafty_manual}

let examples = {crafty_manual|These ran against a host with UDP and TCP echo servers on port 7.

### Ping

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

    % sudo crafty --ip 192.0.2.5 ping.cfty
    reply from 192.0.2.10: seq=1 ttl=64
    ...
    5 replies out of 5

The replies come back to the `Echo` stream of the requests, whatever its id.

### Round trip times

    # 100 probes to a UDP echo server: how many come back, and how fast?
    /IP!(dst=192.0.2.10)/UDP(dst=7) {
      rtts = array(init=0s, len=0)
      repeat count=100 every=10ms {
        p = Raw("probe ${I}")
        catch {
          expect timeout=500ms Raw("probe ${I}") { rtts += MATCH[Eth].ts - p[Eth].ts }
        }
      }
      print("${length(rtts)}/100 echoed, rtt min ${min(rtts)} median ${percentile(rtts, 50)} p99 ${percentile(rtts, 99)} max ${max(rtts)}")
      foreach histogram(rtts, bucket=1ms) { print("${I.min} to ${I.max}: ${I.count}") }
    }

    % sudo crafty --ip 192.0.2.5 --udp 40000-40010 rtt.cfty
    100/100 echoed, rtt min 4.34351ms median 7.94053ms p99 10.2825ms max 10.6628ms
    4.34351ms to 4.77314ms: 8
    ...

The times are those of the captures, of the probe going out and of its echo
coming in. Each probe expects its own echo, so that a late one is not taken for
the next.

### Resolve, then ping

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

The first record is an address only if the name has no CNAME.

### A UDP echo server

    on for=1h /IP/UDP(dst == 7)/Raw {
      /IP(dst=MATCH[IP].src)/UDP(src=7, dst=MATCH[UDP].src)/Raw(MATCH[Raw].data)
    }

    % sudo crafty --udp 7 --fw server.cfty

### Losses per flow

    # 4 flows of 25 datagrams to the UDP echo server: how many get no echo?
    target = 192.0.2.10
    lost = array(init=25, len=4)
    {
      on linger=1s /IP(src == target)/UDP(src == 7, dst >= 40000, dst < 40004) {
        lost[MATCH[UDP].dst - 40000] -= 1
      }
      repeat count=100 every=10ms {
        /IP(dst=target)/UDP(src=40000 + I % 4, dst=7)/Raw("ping")
      }
    }
    repeat var=f count=4 { print("flow ${f}: ${lost[f]} lost") }

    % sudo crafty --udp 40000-40003 --fw losses.cfty
    flow 0: 0 lost
    ...

The `on` starts listening before the datagrams go out, and goes on 1s after the
last one.

### Is a port closed?

    /IP(dst=192.0.2.10)/TCP(src=40001, dst=22) {
      Raw("hello")
      expect timeout=1s ../TCP!(flags & RST) { print("reset by ${MATCH[IP].src}") }
    }

A reset carries no data, so a pattern on top of `TCP` never sees it; `../TCP!`
sees each segment of the connection.

### When did it leave?

    /IP!(dst=192.0.2.10)/UDP(dst=7) {
      p = Raw("ping")
      expect timeout=1s Raw { print("rtt: ${MATCH[Eth].ts - p[Eth].ts}") }
    }

### How is the connection doing?

    /IP(dst=192.0.2.10)/TCP(dst=7) {
      Raw("hello")
      expect timeout=1s Raw {
        s = stats()
        print("srtt ${s.srtt}, mss ${s.snd_mss}, peer window ${s.snd_wnd}")
      }
    }

### Raw frames

    /Eth!(dst=ff:ff:ff:ff:ff:ff, proto=0x88b5)/Raw("hello")
    /IP!(dst=192.0.2.10, ttl=1, id=1234, dont_frag=true)/UDP(src=40000, dst=9)/Raw(#deadbeef)

### Utilities

Whole programs

#### Traceroute through load balancers

    # Every probe goes from the same UDP port to the same port, so that routers
    # that balance per flow send them all the same way: where a hop still shows
    # several routers, they balance per packet.
    # usage: lbtrace.cfty TARGET [PROBES] [MAX_HOPS] [PORT]
    target = resolve(arg(0))[0]
    probes = int(arg(1, default="5"))      # per hop
    max_hops = int(arg(2, default="30"))
    port = int(arg(3, default="33434"))
    /IP!(dst=target)/UDP(dst=port) {
      probe = 0                       # the IP id, that tells the probes apart
      repeat var=hop count=max_hops {
        rtts = map(key=0.0.0.0, default=array(init=0s, len=0))
        reached = false
        repeat count=probes {
          probe += 1
          p = ../../IP!(ttl=hop + 1, id=probe)/UDP/Raw("probe")
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

    % sudo crafty --udp 40000 --fw lbtrace.cfty 10.2.1.3 8
    to 10.2.1.3 from UDP port 40000 to 33434
    1   10.1.1.1    8/8 min 0.04ms
    2   10.1.0.5    4/8 min 37.67ms
        10.1.0.6    4/8 min 34.92ms
    3   10.2.0.1    2/8 min 89.71ms
        10.2.0.2    6/8 min 90.97ms
    4   10.2.0.6    8/8 min 117.6ms
    5   10.2.1.3    8/8 min 110.92ms

Hops 2 and 3 balance per packet. Behind routers that balance per flow, each hop
shows one router, and another port may show another path. A `*` line counts the
probes without an answer.

#### Path MTU

    # Echo requests that must not be fragmented, to find the path MTU in each direction:
    # - echoed whole: the size fits both ways;
    # - echoed in fragments: it fits the way out, and the largest fragment bounds the
    #   MTU of the way back (fragments carry multiples of 8 bytes, so within 7 bytes);
    # - Frag-Needed: a router on the way out tells its next hop MTU;
    # - nothing: dropped silently, on the way out or, if the reply had DF, on the way back.
    # usage: pmtu.cfty TARGET [MTU]
    target = resolve(arg(0))[0]
    lo = 68                                         # fits any IPv4 path
    hi = int(arg(1, default="1500"))
    frag_max = 0                                    # largest fragment of the last reply
    ret_mtu = 0                                     # the way back fragmented at this size
    {
      # Raw fragments from the target, alongside the self-driven stream that reassembles them
      on /IP!(src == target && is_fragment) {
        if MATCH[IP].tot_len > frag_max { frag_max := MATCH[IP].tot_len }
      }
      /IP(dst=target, dont_frag=true)/ICMP/Echo {
        size = hi
        repeat count=32 {
          told = 0
          answered = false
          frag_max := 0
          Request(seq=size, payload=#00 * (size - 28))
          catch {
            first timeout=1s Reply(seq == size) {
              answered := true
              lo := size
              if frag_max > 0 {
                print("${size}: echoed in fragments of up to ${frag_max} bytes")
                ret_mtu := frag_max
              } else { print("${size}: echoed whole") }
            } | /IP(src != target)/ICMP/DestUnreachable(code == FRAG_NEEDED)/IP(dst == target, tot_len == size) {
              told := MATCH[DestUnreachable].mtu
              answered := true
              print("${size}: too big for ${MATCH[^IP].src}, next hop MTU ${told}")
            }
          }
          if !answered { print("${size}: no answer (dropped one way or the other)") }
          if told > lo && told < size {
            hi := told
            size := told
          } else {
            if !answered || told > 0 { hi := size - 1 }
            if lo >= hi { break }
            size := (lo + hi + 1) / 2
          }
        }
      }
    }
    print("way out: ${lo} bytes get through")
    if ret_mtu > 0 { print("way back: fragmented, MTU about ${ret_mtu} bytes") }

    % sudo crafty pmtu.cfty 10.2.1.3
    1500: too big for 10.1.0.5, next hop MTU 1400
    1400: no answer (dropped one way or the other)
    734: echoed whole
    1067: echoed whole
    1233: echoed whole
    1316: no answer (dropped one way or the other)
    1274: echoed whole
    1295: no answer (dropped one way or the other)
    1284: no answer (dropped one way or the other)
    1279: echoed whole
    1281: no answer (dropped one way or the other)
    1280: echoed whole
    way out: 1280 bytes get through

10.1.0.5 reports its MTU of 1400, but a router further on drops what exceeds
1280 without a word.

#### Losses and round trips per hop, over time

    # Probes every hop once per round, on one flow as the traceroute does, and
    # reports each hop's losses and round trips every REPORT rounds.
    # usage: mtr.cfty TARGET [ROUNDS] [REPORT] [INTERVAL] [MAX_HOPS] [PORT]
    target = resolve(arg(0))[0]
    rounds = int(arg(1, default="60"))
    report = int(arg(2, default="10"))   # rounds per report
    pace = interval(arg(3, default="1s"))
    max_hops = int(arg(4, default="30"))   # less than 64
    port = int(arg(5, default="33434"))
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
            p = ../../IP!(ttl=hop + 1, id=id)/UDP/Raw("probe")
            sent_at[id] := p[Eth].ts
            sent[hop] += 1
          }
        }
      }
    }

    % sudo crafty --udp 40000 --fw mtr.cfty 10.2.1.3 40 20 200ms
    after 20 rounds:
    1   [10.1.1.1]  loss 0% avg 0.33ms  best 0.11ms worst 0.48ms
    2   [10.1.0.5]  loss 50%    avg 37.81ms best 37.6ms worst 38.1ms
    3   [10.2.0.2]  loss 0% avg 90.91ms best 90.69ms    worst 91.07ms
    4   [10.2.0.6]  loss 10%    avg 114.42ms    best 114.18ms   worst 115.02ms
    5   [10.2.1.3]  loss 5% avg 114.23ms    best 114.09ms   worst 114.73ms
    after 40 rounds:
    1   [10.1.1.1]  loss 0% avg 0.33ms  best 0.09ms worst 0.6ms
    2   [10.1.0.5]  loss 45%    avg 37.81ms best 37.6ms worst 37.97ms
    3   [10.2.0.2]  loss 0% avg 90.87ms best 90.68ms    worst 91.3ms
    4   [10.2.0.6]  loss 20%    avg 114.47ms    best 114.1ms    worst 116.44ms
    5   [10.2.1.3]  loss 15%    avg 114.37ms    best 114.02ms   worst 116.14ms

Hop 2 only answers half of its probes: hop 3 losing none, what is lost is the
answers, not the traffic. The losses start between hops 3 and 4, and go on to
the target.
|crafty_manual}
