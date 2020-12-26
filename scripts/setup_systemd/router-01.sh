#!/bin/bash
# addr configuraiton
sudo ip link set lo up
sudo ip addr add fc00:1::1/128 dev lo
sudo ip link set eth1 up
sudo ip addr add 172.0.1.2/24 dev eth1
sudo ip link set eth2 up
sudo ip addr add fc00:12::1/64 dev eth2
sudo ip -6 route add fc00:23::/64 via fc00:12::2
sudo ip -6 route add fc00:2::/64 via fc00:12::2
sudo ip -6 route add fc00:3::/64 via fc00:12::2

# seg6
sudo sysctl net.ipv4.conf.all.forwarding=1
sudo sysctl net.ipv6.conf.all.forwarding=1
sudo sysctl net.ipv4.conf.all.rp_filter=0
sudo sysctl net.ipv4.conf.eth1.rp_filter=0

sudo sysctl net.ipv6.conf.all.seg6_enabled=1
sudo sysctl net.ipv6.conf.default.seg6_enabled=1
sudo sysctl net.ipv6.conf.eth1.seg6_enabled=1
sudo sysctl net.ipv6.conf.eth2.seg6_enabled=1

# sudo ip route add 172.0.2.0/24 encap seg6 mode encap segs fc00:2::1,fc00:3::3 dev eth2
# sudo ip -6 route del local fc00:1::1
# sudo ip -6 route add local fc00:1::1/128 encap seg6local action End.DX4 nh4 172.0.1.1 dev eth2

# ↑same config
# internal:
#   # logfile: "/var/log/vinbero.log"
#   logfile: "./vinbero.log"
#   development: false
#   devices:
#     - eth1
#     - eth2
# settings:
#   functions:
#     - action: SEG6_LOCAL_ACTION_END_DX4
#       triggerAddr: fc00:1::1/128
#       nexthop: 172.0.1.1
#   transitv4:
#     - action: SEG6_IPTUN_MODE_ENCAP
#       triggerAddr: 172.0.2.0/24
#       actionSrcAddr: fc00:1::1
#       segments:
#         - fc00:3::3 # last arrive next hop
#         - fc00:2::1

ethtool -L eth0 combined 2
ethtool -L eth1 combined 2
ethtool -L eth2 combined 2
