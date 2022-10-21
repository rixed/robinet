#!/bin/sh

sudo ip link add type veth
sudo ifconfig veth0 192.168.10.42 up
sudo ifconfig veth1 up

sudo ip route add 192.168.11.0/24 dev veth0 via 192.168.10.1
sudo ip route add 192.168.12.0/24 dev veth0 via 192.168.10.1
sudo ip route add 192.168.13.0/24 dev veth0 via 192.168.10.1

# Once the target is known, assuming first router is 192.168.0.1:
#sudo ip route add $target/32 dev veth0 via 192.168.0.1
