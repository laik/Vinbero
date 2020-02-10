#!/bin/bash

# addr configuraiton
sudo ip link set lo up
sudo ip addr add 10.0.1.1/32 dev lo
sudo ip link set eth1 up
sudo ip addr add 172.0.1.1/24 dev eth1
sudo ip route add 10.0.2.0/24 via 172.0.1.2
sudo ip route add 172.0.2.0/24 via 172.0.1.2

ethtool -L eth0 combined 2
ethtool -L eth1 combined 2
