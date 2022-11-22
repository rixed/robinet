#!/bin/sh

# Assuming router_frenzy is run with -s 10 to avoid 192.168.0.0/24:
sudo ip link add type veth
sudo ifconfig veth0 192.168.10.42 up
sudo ifconfig veth1 up

for i in `seq 11 30`; do
  sudo ip route add 192.168.$i.0/24 dev veth0 via 192.168.10.1
done

# Once the target is known, assuming first router is 192.168.10.1:
#sudo ip route add $target/32 dev veth0 via 192.168.10.1
