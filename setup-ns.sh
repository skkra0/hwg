#!/usr/bin/env bash
# Sets up two network namespaces (ns1, ns2) connected by a veth pair,
# simulating two hosts on the same LAN so the tunnel binary can be run
# in each one and tested end-to-end. See README.md for the full flow.
set -euo pipefail

sudo ip netns add ns1
sudo ip netns add ns2

sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 netns ns1
sudo ip link set veth1 netns ns2

sudo ip netns exec ns1 ip link set veth0 up
sudo ip netns exec ns2 ip link set veth1 up
sudo ip netns exec ns1 ip link set lo up
sudo ip netns exec ns2 ip link set lo up

sudo ip netns exec ns1 ip addr add 172.16.0.1/24 dev veth0
sudo ip netns exec ns2 ip addr add 172.16.0.2/24 dev veth1
