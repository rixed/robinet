#!/bin/sh

# create veth0 and veth1:
sudo ip link add type veth
sudo ifconfig veth0 192.168.0.42 up
sudo ifconfig veth1 up

sudo ip route add 192.168.1.0/24 dev veth0 via 192.168.0.1
sudo ip route add 192.168.2.0/24 dev veth0 via 192.168.0.1
sudo ip route add 192.168.3.0/24 dev veth0 via 192.168.0.1
