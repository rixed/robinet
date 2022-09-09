#!/bin/sh

sudo modprobe dummy
sudo ip link add br0 type dummy
sudo ifconfig br0 192.168.0.0/24
sudo ifconfig br0 up
sudo ip route add 192.168.1.0/24 dev br0
sudo ip route add 192.168.2.0/24 dev br0 via 192.168.1.0
sudo ip route add 192.168.3.0/24 dev br0 via 192.168.1.0
