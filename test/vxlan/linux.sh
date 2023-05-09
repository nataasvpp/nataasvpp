#!/bin/sh

ip link add tun0 type vxlan id 0 local 192.168.10.2 remote 192.168.10.1 nolearning dev underlay-tun0 dstport 4789
ip link set tun0 up
ip addr add 192.168.1.2/24 dev tun0
ip link set tun0 arp off
ip neigh add 192.168.1.1 lladdr 36:a3:6e:77:61:90 dev tun0

