#!/bin/sh
# vim:sw=4 ts=4 sts=4 expandtab
# Copyright 2026, Cedric Cellier
#
# This file is part of RobiNet, under the GNU Affero General Public License
# (see the other files for the full notice).
#
# Checks crafty.opt on a real interface: a veth pair into a network
# namespace with UDP and TCP echo servers in it. Wants root, and socat,
# tcpdump, nft and ethtool. Not part of `make check`.
#
# After each case, the host must be as it was before: no nftables table of
# crafty's, the same reserved ports, the same offloads, no state file.

set -u

CRAFTY="$(cd "$(dirname "$0")/.." && pwd)/crafty.opt"
NS=crtns
HOST_IF=crt0
NS_IF=crt1
DIR=$(mktemp -d)
FAILED=0

setup() {
    ip netns add $NS
    ip link add $HOST_IF type veth peer name $NS_IF
    ip link set $NS_IF netns $NS
    ip addr add 10.77.0.1/24 dev $HOST_IF
    ip link set $HOST_IF up
    ip netns exec $NS ip addr add 10.77.0.2/24 dev $NS_IF
    ip netns exec $NS ip link set $NS_IF up
    ip netns exec $NS ip link set lo up
    # So that the capture gets frames with their checksums:
    ip netns exec $NS ethtool -K $NS_IF tx off >/dev/null
    # Something for crafty to turn off, and back on:
    ethtool -K $HOST_IF generic-receive-offload on >/dev/null
    ip netns exec $NS socat UDP4-RECVFROM:7,fork EXEC:cat >/dev/null 2>&1 &
    ip netns exec $NS socat TCP4-LISTEN:7,fork,reuseaddr EXEC:cat >/dev/null 2>&1 &
    sleep 0.5
}

teardown() {
    ip netns pids $NS | xargs -r kill
    ip netns del $NS
    ip link del $HOST_IF 2>/dev/null
    rm -rf "$DIR"
}

state() {
    nft list tables | grep crafty_
    cat /proc/sys/net/ipv4/ip_local_reserved_ports
    ethtool -k $HOST_IF | grep -E '^(generic-receive-offload|rx-gro-list):'
    ls /run/robinet 2>/dev/null
}

# check NAME EXPECTED_EXIT EXIT [PATTERN_IN_OUTPUT]
check() {
    name=$1 expected=$2 code=$3
    ok=1
    if [ "$code" != "$expected" ]; then
        echo "  exit $code, expected $expected" ; ok=0
    fi
    if [ $# -ge 4 ] && ! grep -q -- "$4" "$DIR/out" ; then
        echo "  no \"$4\" in the output:" ; sed 's/^/    /' "$DIR/out" ; ok=0
    fi
    state > "$DIR/after"
    if ! diff -u "$DIR/before" "$DIR/after" > "$DIR/diff" ; then
        echo "  the host was not restored:" ; sed 's/^/    /' "$DIR/diff" ; ok=0
    fi
    if [ $ok = 1 ] ; then echo "ok   $name" ; else echo "FAIL $name" ; FAILED=1 ; fi
}

cat > "$DIR/udp.cfty" <<'EOF'
/IP(dst=10.77.0.2)/UDP(dst=7) {
  repeat count=3 {
    Bytes("echo ${I}")
    expect timeout=1s Bytes { print(MATCH[Bytes].data) }
  }
}
EOF
cat > "$DIR/tcp.cfty" <<'EOF'
/IP(dst=10.77.0.2)/TCP(dst=7) {
  Bytes("hello")
  expect timeout=2s Bytes { print(MATCH[Bytes].data) }
}
EOF
cat > "$DIR/flood.cfty" <<'EOF'
/IP(dst=10.77.0.2)/UDP(dst=7) {
  repeat count=1000 every=10ms { Bytes("x") }
}
EOF
# A frame comes in after its capture, by its serialization at least:
cat > "$DIR/ts.cfty" <<'EOF'
/IP(dst=10.77.0.2)/UDP(dst=7) {
  Bytes("stamp")
  expect timeout=1s Bytes {
    d = now() - MATCH[Eth].ts
    print(if d > 0s && d < 10ms { "captured ${d} before" } else { "not captured then: ${d}" })
  }
}
EOF
# A packet sent into a variable is that packet as captured on its way out:
cat > "$DIR/sent.cfty" <<'EOF'
/IP!(dst=10.77.0.2)/UDP(dst=7) {
  p = Bytes("ping")
  expect timeout=1s Bytes {
    d = MATCH[Eth].ts - p[Eth].ts
    print(if d > 0s && d < 100ms { "round trip ${d}" } else { "no round trip: ${d}" })
  }
}
EOF
# Over a lossy path, data echoed comes back out of order, but all of it:
cat > "$DIR/lossy.cfty" <<'EOF'
/IP(dst=10.77.0.2)/TCP(dst=7) {
  n = 0
  {
    on timeout=20s Bytes {
      n += length(MATCH[Bytes].data)
      if n >= 200000 { break }
    }
    Bytes(randbytes(200000))
  }
  s = stats()
  print("echoed ${n}, out of order ${s.ooo_in > 0}")
}
EOF
printf 'x = "a" + 1\n' > "$DIR/bad.cfty"

setup
trap teardown EXIT
state > "$DIR/before"

"$CRAFTY" -i $HOST_IF --ip 10.77.0.5 --udp 40000-40010 -p "$DIR/udp.cfty" > "$DIR/out" 2>&1
check "UDP with an address of its own" 0 $? "echo 2"

"$CRAFTY" -i $HOST_IF --ip 10.77.0.5 --udp 40000-40010 -p '/IP/UDP(src == 7)' "$DIR/udp.cfty" > "$DIR/out" 2>&1
check "printing the packets of a pattern" 0 $? "echo 2"
if [ "$(grep -c '^< ' "$DIR/out")" = 3 ] && ! grep -q '^> ' "$DIR/out" ; then
    echo "ok   only the echoes are printed"
else
    echo "FAIL not only the echoes are printed:" ; sed 's/^/    /' "$DIR/out" ; FAILED=1
fi

"$CRAFTY" -i $HOST_IF --ip 10.77.0.5 --udp 40000-40010 "$DIR/ts.cfty" > "$DIR/out" 2>&1
check "frames are dated by their capture" 0 $? "captured "

"$CRAFTY" -i $HOST_IF --ip 10.77.0.5 --udp 40000-40010 "$DIR/sent.cfty" > "$DIR/out" 2>&1
check "a packet sent is seen leaving" 0 $? "round trip "

ip netns exec $NS timeout 6 tcpdump -n -i $NS_IF -w "$DIR/tcp.pcap" tcp 2>/dev/null &
TCPDUMP=$!
sleep 1
"$CRAFTY" -i $HOST_IF --tcp 14000-14099 --fw "$DIR/tcp.cfty" > "$DIR/out" 2>&1
check "TCP on the host's address" 0 $? "hello"
wait $TCPDUMP
if tcpdump -n -r "$DIR/tcp.pcap" 2>/dev/null | grep -q 'Flags \[R' ; then
    echo "FAIL the kernel reset the connection" ; FAILED=1
else
    echo "ok   the kernel did not reset the connection"
fi

ip netns exec $NS tc qdisc add dev $NS_IF root netem loss 10%
"$CRAFTY" -i $HOST_IF --tcp 14000-14099 --fw "$DIR/lossy.cfty" > "$DIR/out" 2>&1
check "the stats of a lossy connection" 0 $? "echoed 200000, out of order true"
ip netns exec $NS tc qdisc del dev $NS_IF root

"$CRAFTY" -i $HOST_IF --tcp 14000-14099 --fw --stats "$DIR/tcp.cfty" > "$DIR/out" 2>&1
check "--stats with TCP" 0 $? "hello"
if grep -q '^Closed /IP(src=10.77.0.1, dst=10.77.0.2)/TCP(src=140[0-9][0-9], dst=7): packets_out=[0-9]* bytes_out=5 .* bytes_acked=5 bytes_received=5 .* established=true$' "$DIR/out" ; then
    echo "ok   the stats of a stream are printed as it closes"
else
    echo "FAIL no stats of the stream as it closes:" ; sed 's/^/    /' "$DIR/out" ; FAILED=1
fi

"$CRAFTY" -i $HOST_IF --udp 40000-40010 --fw --max-packets 3 "$DIR/flood.cfty" > "$DIR/out" 2>&1
check "a budget stops the program" 3 $? "stopped: max-packets"

"$CRAFTY" -i $HOST_IF --udp 40000-40010 --fw "$DIR/flood.cfty" > "$DIR/out" 2>&1 &
sleep 1.5
"$CRAFTY" --cleanup > /dev/null
if nft list tables | grep -q crafty_ ; then
    echo "ok   a cleanup spares a running crafty"
else
    echo "FAIL a cleanup undid what a running crafty did" ; FAILED=1
fi
pkill -INT -x crafty.opt
wait $!
check "interrupted" 130 $? "interrupted"

"$CRAFTY" -i $HOST_IF --udp 40000-40010 --fw "$DIR/flood.cfty" > /dev/null 2>&1 &
sleep 1.5
pkill -KILL -x crafty.opt
wait $!
"$CRAFTY" --cleanup > "$DIR/out" 2>&1
check "cleaned up after being killed" 0 $? "Cleaned up after crafty_"

"$CRAFTY" -i $HOST_IF --udp 40000-40010 --fw "$DIR/bad.cfty" > "$DIR/out" 2>&1
check "a broken program changes nothing" 2 $? "Cannot apply +"

exit $FAILED
