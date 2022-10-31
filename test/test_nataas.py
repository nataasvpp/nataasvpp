#!/usr/bin/env python3
#
# Copyright (c) 2022 Cisco and/or its affiliates.

"""NATaaS tests"""

import unittest
from scapy.layers.inet6 import Ether, IP, UDP, TCP, IPv6
from scapy.layers.inet import ICMP
from scapy.layers.vxlan import VXLAN
from framework import VppTestCase, VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import VppIpRoute, VppRoutePath, FibPathProto
from socket import AF_INET, AF_INET6, inet_pton


"""
Tests for NATaaS.
"""

class TestNATaaS(VppTestCase):
    """NATaaS Test Case"""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        super(TestNATaaS, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)

    @classmethod
    def tearDownClass(cls):
        super(TestNATaaS, cls).tearDownClass()

    def setUp(self):
        super(TestNATaaS, self).setUp()
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

    def tearDown(self):
        super(TestNATaaS, self).tearDown()
        if not self.vpp_dead:
            for i in self.pg_interfaces:
                i.unconfig_ip4()
                i.admin_down()

    def encapsulate(self, dport, vni, pkt):
        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
            / UDP(sport=dport, dport=dport, chksum=0)
            / VXLAN(vni=vni, flags=0) / Ether()
            / pkt
        )

    def gen_packets(self, pool, dst):
        # in2out packets
        tests = [

            {
                'send': IP(src='10.10.10.10', dst=dst)/UDP(sport=123, dport=456),
                'expect': IP(src=pool, dst=dst)/UDP(sport=123, dport=456),
                'npackets': 2,

             },

            {
                'send':   IP(src='10.10.10.10', dst=dst)/TCP(),
                'expect': IP(src=pool, dst=dst)/TCP(),
                'npackets': 2,
            },
            {
                'send': IP(src='10.10.10.10', dst=dst)/ICMP(id=1234),
                'expect': IP(src=pool, dst=dst)/ICMP(id=1234),
                'npackets': 2,
             },
        ]
        dport = 4789
        vni = 123
        for t in tests:
            t['send'] = self.encapsulate(dport, vni, t['send'])
            t['expect'][IP].ttl -= 1


        self.nataas_tests = tests

    def validate(self, rx, expected):
        self.assertEqual(rx, expected.__class__(expected))

    def validate_bytes(self, rx, expected):
        self.assertEqual(rx, expected)

    def payload(self, len):
        return "x" * len

    def send_packet_through_nat(self, pool, tunnel_dport):
        "pg0 is inside nat, pg1 is outside"
        # Send a VXLAN packet and validate that is passes through the service chain and is natively forwarded
        self.gen_packets(pool, self.pg1.remote_ip4) # Move to setup

        # slowpath
        for t in self.nataas_tests:
            print('SENT PACKET:')
            t['send'].show2()
            rx = self.send_and_expect(self.pg0, t['send'] * t['npackets'], self.pg1)
            print(self.vapi.cli("show vcdp session-table"))
            for p in rx:
                print('RECEIVED PACKET:')
                p.show2()
                self.validate(p[1], t['expect'])

        # fastpath
        for t in self.nataas_tests:
            print('SENT PACKET:')
            t['send'].show2()
            rx = self.send_and_expect(self.pg0, t['send'] * t['npackets'], self.pg1)
            print(self.vapi.cli("show vcdp session-table"))
            for p in rx:
                print('RECEIVED PACKET:')
                p.show2()
                self.validate(p[1], t['expect'])


        # # Send two packets in two frames to test both slowpath and fastpath
        # rx = self.send_and_expect(self.pg0, pkt_to_send*2, self.pg1)
        # rx = self.send_and_expect(self.pg0, pkt_to_send*2, self.pg1)
        # rx[0].show2()
        # print(self.vapi.cli("show vcdp session-table"))

        # reply = rx[0][IP]
        # reply.show2()
        # tmp = reply.src
        # reply.src = reply.dst
        # reply.dst = tmp
        # tmp = reply[TCP].sport
        # reply[TCP].sport = reply[TCP].dport
        # reply[TCP].dport = tmp
        # reply.show2()

        # pkt_to_send = Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac) / reply

        # # send packet back through NAT
        # rx = self.send_and_expect(self.pg1, pkt_to_send, self.pg0)
        # print('PACKET FROM NAT')
        # rx[0].show2()
        # print(self.vapi.cli("show vcdp session-table"))

        # # Make sure we receive on the same tunnel we sent on.
        # self.assertEqual(rx[0][UDP].dport, tunnel_dport)

    def test_vxlan(self):
        """VXLAN gateway through NAT"""
        # Create tunnel
        tenant=0
        outside_tenant=1000
        dport=4789
        dport2=4790
        vrf=0
        pool = '1.1.1.1'

        self.vapi.cli(f'vcdp tenant add {tenant} context 0')
        self.vapi.cli(f'vcdp tenant add {outside_tenant} context 0 no-create')
        self.vapi.cli(f"set vcdp gateway interface {self.pg1.name} tenant {outside_tenant}")

        self.vapi.cli(f"set vcdp gateway tunnel {self.pg0.name}")
        self.vapi.cli(f"set vcdp tunnel id foobar-uuid tenant {tenant} method vxlan-dummy-l2 src {self.pg0.local_ip4} dst {self.pg0.remote_ip4} dport {dport2}")
        self.vapi.cli(f"set vcdp tunnel id foobar-uuid2 tenant {tenant} method vxlan-dummy-l2 src {self.pg0.local_ip4} dst {self.pg0.remote_ip4} dport {dport}")
        self.vapi.cli(f"set vcdp services tenant {tenant} vcdp-l4-lifecycle vcdp-nat-output forward")
        self.vapi.cli(f'set vcdp services tenant {tenant} vcdp-l4-lifecycle vcdp-tunnel-output reverse')
        self.vapi.cli("vcdp nat alloc-pool add 4243 2.2.2.2")
        self.vapi.cli(f"vcdp nat alloc-pool add 4242 {pool}")
        self.vapi.cli(f"set vcdp nat snat tenant {tenant} alloc-pool 4242")

        self.send_packet_through_nat(pool, dport)
        self.send_packet_through_nat(pool, dport2)

        # TODO: What is supposed to happen if same packet is sent on two different tunnels? Drop or return traffic back on the original one?

        # verify that packet from outside does not create session (default drop for tenant 1000)

        pkt = IP(src='10.10.10.10', dst=self.pg1.remote_ip4)/TCP(sport=666)
        pkt_to_send = self.encapsulate(666, 123, pkt)
        no_session_pkt = pkt_to_send
        no_session_pkt[TCP].dport = 666
        print('SENDING PACKET FROM OUTSIDE')
        self.send_and_assert_no_replies(self.pg1, no_session_pkt)
        print(self.vapi.cli("show vcdp session-table"))

        print(self.vapi.cli('show vcdp tenant'))

        # Send IPv6 packet
        pkt = IPv6(src='1::1', dst='2::2')/TCP(sport=dport)
        self.send_and_assert_no_replies(self.pg0, self.encapsulate(dport, 0, pkt))


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
