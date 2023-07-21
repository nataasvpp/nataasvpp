sudo ip link add tun0 type vxlan id 100 local 192.168.10.2 remote 192.168.10.1 nolearning dev underlay-tun0
sudo ip link set tun0 up
sudo ip addr add 192.168.1.2/24 dev tun0
 ip link set vxlan0 arp off

