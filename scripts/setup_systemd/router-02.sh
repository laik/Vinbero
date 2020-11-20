#!/bin/bash

# addr configuraiton
sudo ip link set lo up
sudo ip addr add fc00:2::2/128 dev lo
sudo ip link set eth1 up
sudo ip addr add fc00:12::2/64 dev eth1
sudo ip link set eth2 up
sudo ip addr add fc00:23::2/64 dev eth2

# to route1
sudo ip -6 route add fc00:1::/64 via fc00:12::1
sudo ip -6 route add fc00:12::/64 via fc00:12::1

sudo ip -6 route add fc00:3::/64 via fc00:23::1
sudo ip -6 route add fc00:23::/64 via fc00:23::1

# seg6
sudo sysctl net.ipv4.conf.all.forwarding=1
sudo sysctl net.ipv6.conf.all.forwarding=1
sudo sysctl net.ipv4.conf.all.rp_filter=0


sudo sysctl net.ipv6.conf.all.seg6_enabled=1
sudo sysctl net.ipv6.conf.default.seg6_enabled=1
sudo sysctl net.ipv6.conf.eth1.seg6_enabled=1
sudo sysctl net.ipv6.conf.eth2.seg6_enabled=1

# sudo ip -6 route add fc00:2::1/128 encap seg6local action End dev eth1
# sudo ip -6 route add fc00:2::2/128 encap seg6local action End dev eth2

ethtool -L eth0 combined 2
ethtool -L eth1 combined 2
ethtool -L eth2 combined 2
