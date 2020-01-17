#!/bin/bash
set -eu

if [[ $(id -u) -ne 0 ]] ; then
    echo "Please run with sudo"
    exit 1
fi

run () {
    echo "$@"
    "$@" || exit 1
}

create_router1 () {
    # setup namespaces
    run ip netns add host1
    run ip netns add router1

    # setup veth peer
    run ip link add veth-h1-rt1 type veth peer name veth-rt1-h1
    run ip link set veth-h1-rt1 netns host1
    run ip link set veth-rt1-h1 netns router1

    # host1 configuraiton
    run ip netns exec host1 ip link set lo up
    run ip netns exec host1 ip addr add 10.0.1.1 dev lo
    run ip netns exec host1 ip addr add 172.0.1.1 dev veth-h1-rt1
    run ip netns exec host1 ip link set veth-h1-rt1 up
    run ip netns exec host1 ip route add 10.0.1.0/24 via 172.0.1.2

    # router1 configuration
    run ip netns exec router1 ip link set lo up
    run ip netns exec router1 ip link set veth-rt1-h1 up
    run ip netns exec router1 ip addr add 172.0.1.2 dev veth-rt1-h1

    # sysctl for router1
    ip netns exec router1 sysctl net.ipv6.conf.all.forwarding=1
    ip netns exec router1 sysctl net.ipv6.conf.all.seg6_enabled=1
    ip netns exec router1 sysctl net.ipv4.conf.all.rp_filter=0
}

create_router2 () {
    # setup namespaces
    run ip netns add router2

    # router2 configuration
    run ip netns exec router2 ip link set lo up

    # sysctl for router2
    ip netns exec router2 sysctl net.ipv6.conf.all.forwarding=1
    ip netns exec router2 sysctl net.ipv6.conf.all.seg6_enabled=1
    ip netns exec router2 sysctl net.ipv4.conf.all.rp_filter=0
}

create_router3 () {
    # setup namespaces
    run ip netns add host2
    run ip netns add router3

    # setup veth peer
    run ip link add veth-h2-rt3 type veth peer name veth-rt3-h2
    run ip link set veth-h2-rt3 netns host2
    run ip link set veth-rt3-h2 netns router3

    # host2 configuraiton
    run ip netns exec host2 ip link set lo up
    run ip netns exec host2 ip link set veth-h2-rt3 up
    run ip netns exec host2 ip addr add 10.0.1.2/24 dev lo
    run ip netns exec host2 ip addr add 172.0.2.2/24 dev veth-h2-rt3

    run ip netns exec host2 ip route add 10.0.1.0/24 via 172.0.2.2

    # router3 configuration
    run ip netns exec router3 ip link set lo up
    run ip netns exec router3 ip link set veth-rt3-h2 up
    run ip netns exec router3 ip addr add 172.0.2.2 dev veth-rt3-h2

    # sysctl for router3
    ip netns exec router3 sysctl net.ipv6.conf.all.forwarding=1
    ip netns exec router3 sysctl net.ipv6.conf.all.seg6_enabled=1
    ip netns exec router3 sysctl net.ipv4.conf.all.rp_filter=0
}

connect_rt1_rt2 () {
    # create veth peer
    run ip link add veth-rt1-rt2 type veth peer name veth-rt2-rt1
    run ip link set veth-rt1-rt2 netns router1
    run ip link set veth-rt2-rt1 netns router2

    # configure router1
    run ip netns exec router1 ip link set veth-rt1-rt2 up
    run ip netns exec router1 ip addr add fc00:12::1/64 dev veth-rt1-rt2
    run ip netns exec router1 ip -6 route add fc00:23::/64 via fc00:12::2

    # configure router2
    run ip netns exec router2 ip link set veth-rt2-rt1 up
    run ip netns exec router2 ip addr add fc00:12::2/64 dev veth-rt2-rt1
    run ip netns exec router2 ip -6 route add fc00:23::/64 via fc00:12::1
}

connect_rt2_rt3 () {
    # create veth peer
    run ip link add veth-rt2-rt3 type veth peer name veth-rt3-rt2
    run ip link set veth-rt2-rt3 netns router2
    run ip link set veth-rt3-rt2 netns router3

    # configure router2
    run ip netns exec router2 ip link set veth-rt2-rt3 up
    run ip netns exec router2 ip addr add fc00:23::1/64 dev veth-rt2-rt3
    run ip netns exec router2 ip -6 route add fc00:12::/64 via fc00:23::1

    # configure router3
    run ip netns exec router3 ip link set veth-rt3-rt2 up
    run ip netns exec router3 ip addr add fc00:23::2/64 dev veth-rt3-rt2
    run ip netns exec router3 ip -6 route add fc00:12::/64 via fc00:23::2
}

destroy_network () {
    run ip netns del router1
    run ip netns del host1

    run ip netns del router2

    run ip netns del router3
    run ip netns del host2
}

stop () {
    destroy_network
}

trap stop 0 1 2 3 13 14 15

# exec functions
create_router1
create_router2
create_router3

connect_rt1_rt2
connect_rt2_rt3

status=0; $SHELL || status=$?
exit $status
