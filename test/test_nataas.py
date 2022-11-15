#!/usr/bin/env python3
#
# Copyright (c) 2022 Cisco and/or its affiliates.

"""NATaaS tests"""

import unittest
from socket import AF_INET, AF_INET6, inet_pton

from framework import VppTestCase, VppTestRunner
from scapy.layers.inet import ICMP
from scapy.layers.inet6 import IP, TCP, UDP, Ether, IPv6
from scapy.layers.vxlan import VXLAN
from vpp_ip import DpoProto
from vpp_ip_route import FibPathProto, VppIpRoute, VppRoutePath

"""
Tests for NATaaS.
"""

DEBUG = False
def log_packet(msg, pkt):
    if DEBUG:
        print(msg)
        pkt.show2()
def log_error_packet(msg, pkt):
    print(msg)
    pkt.show2()

class TestNATaaS(VppTestCase):
    """NATaaS Test Case"""

    maxDiff = None
    @classmethod
    def setUpClass(self):
        super(TestNATaaS, self).setUpClass()
        self.create_pg_interfaces(range(2))
        self.interfaces = list(self.pg_interfaces)
        for i in self.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        tenant=0
        outside_tenant=1000
        dport=4789
        dport2=4790
        vrf=0
        pool = '222.1.1.1'

        self.vapi.cli(f'set vcdp tenant {tenant} context 0')
        self.vapi.cli(f'set vcdp tenant {outside_tenant} context 0 no-create')
        self.vapi.cli(f"set vcdp gateway interface {self.pg1.name} tenant {outside_tenant}")
        self.vapi.cli(f"set vcdp gateway tunnel {self.pg0.name}")
        self.vapi.cli(f"set vcdp tunnel id foobar-uuid tenant {tenant} method vxlan-dummy-l2 src {self.pg0.local_ip4} dst {self.pg0.remote_ip4} dport {dport2}")
        self.vapi.cli(f"set vcdp tunnel id foobar-uuid2 tenant {tenant} method vxlan-dummy-l2 src {self.pg0.local_ip4} dst {self.pg0.remote_ip4} dport {dport}")
        self.vapi.cli(f"set vcdp services tenant {tenant} vcdp-l4-lifecycle vcdp-nat-output forward")
        self.vapi.cli(f'set vcdp services tenant {tenant} vcdp-l4-lifecycle vcdp-tunnel-output reverse')
        self.vapi.cli(f'set vcdp services tenant {outside_tenant} vcdp-bypass forward')
        self.vapi.cli("vcdp nat alloc-pool add 4243 2.2.2.2")
        self.vapi.cli(f"vcdp nat alloc-pool add 4242 {pool}")
        self.vapi.cli(f"set vcdp nat snat tenant {tenant} alloc-pool 4242")

        self.vxlan_pool = pool
        self.vxlan_dport = dport
        self.vxlan_dport2 = dport2

    @classmethod
    def tearDownClass(cls):
        super(TestNATaaS, cls).tearDownClass()
        # if not cls.vpp_dead:
        #     for i in cls.pg_interfaces:
        #         i.unconfig_ip4()
        #         i.admin_down()

    def encapsulate(self, dport, vni, pkt):
        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
            / UDP(sport=dport, dport=dport, chksum=0)
            / VXLAN(vni=vni, flags=0) / Ether()
            / pkt
        )


    def gen_packets(self, pool, dst, dport, vni):
        # in2out packets
        # TODO:Separate test table for out2in packets.
        tests = [
            {
                'name': 'Basic UDP',
                'send': IP(src='10.10.10.10', dst=dst)/UDP(sport=123, dport=456),
                'expect': IP(src=pool, dst=dst)/UDP(sport=123, dport=456),
                'npackets': 1,
                'reply': True,
            },
            {
                'name': 'Basic UDP',
                'send': IP(src='210.10.10.10', dst=dst)/UDP(sport=124, dport=456),
                'expect': IP(src=pool, dst=dst)/UDP(sport=124, dport=456),
                'npackets': 2,
            },
            {
                'name': 'Basic TCP',
                'send':   IP(src='10.10.10.10', dst=dst)/TCP(),
                'expect': IP(src=pool, dst=dst)/TCP(),
                'npackets': 2,
                'reply': True,
            },
            {
                # Test normalisation too
                'name': 'Basic ICMP',
                'send': IP(src='10.10.10.10', dst=dst)/ICMP(id=1234),
                'expect': IP(src=pool, dst=dst)/ICMP(id=1234),
                'npackets': 2,
            },
            {
                'name': 'Basic ICMP',
                'send': IP(src='210.10.10.10', dst=dst)/ICMP(id=1235),
                'expect': IP(src=pool, dst=dst)/ICMP(id=1235),
                'npackets': 2,
            },
            {
                'name': 'Send unsupported packet',
                'send': IPv6(src='1::1', dst='2::2')/TCP(sport=dport),
                'expect': None,
                'npackets': 1,
            },
            {
                'name': 'Truncated packet',
                'send': IP(src='210.10.10.10', dst=dst),
                'expect': None,
                'npackets': 1,
            },

            # {
            #     'name': 'Send non TCP/UDP/ICMP packet',
            #     'send': IP(src='210.10.10.10', dst=dst)/IP(),
            #     'expect': IP(src=pool, dst=dst)/IP(),
            #     'npackets': 1,
            # },

            # {
            #     'name': 'Verify mid-stream TCP creates session',
            #     'send':   IP(src='10.10.10.10', dst=dst)/TCP(flags='A', sport=123, dport=8080),
            #     'expect': IP(src=pool, dst=dst)/TCP(sport=123, dport=8080),
            #     'npackets': 1,
            #     'nframe': 1,
            # },
        ]

        for t in tests:
            t['send'] = self.encapsulate(dport, vni, t['send'])
            if t['expect']: # If a reply is expected
                t['expect'][IP].ttl -= 1


        return tests

    def validate(self, rx, expected, msg=None):
        self.assertEqual(rx, expected.__class__(expected), msg=msg)

    def validate_bytes(self, rx, expected):
        self.assertEqual(rx, expected)

    def payload(self, len):
        return "x" * len

    def make_reply(self, pkt):
        pkt = pkt.copy()
        pkt[Ether].src, pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src
        pkt[IP].src, pkt[IP].dst = pkt[IP].dst, pkt[IP].src
        if pkt[IP].proto == 6:
            pkt[TCP].sport, pkt[TCP].dport = pkt[TCP].dport, pkt[TCP].sport
            pkt[IP][TCP].flags = 'SA'
        elif pkt[IP].proto == 17:
            pkt[UDP].sport, pkt[UDP].dport = pkt[UDP].dport, pkt[UDP].sport
        elif pkt[IP].proto == 1:
            if pkt[IP][ICMP].type == 8: #echo-request
                pkt[IP][ICMP].type = 0 #echo-reply
        return pkt

    def validate_reply_packet(self, received, sent):
        # A little rough validation that we received the packet on same tunnel as sent on
        try:
            self.assertEqual(sent[UDP].dport, received[UDP].dport)
            self.assertEqual(sent[IP].src, received[IP].dst)
            self.assertEqual(sent[IP].dst, received[IP].src)
        except AssertionError:
            log_error_packet('Sent VXLAN encapsulated packet', sent)
            log_error_packet('Received VXLAN encapsulated packet', received)
            raise

    def run_tests(self, tests, pool, tunnel_dport, nframes):
        "pg0 is inside nat, pg1 is outside"
        # Send a VXLAN packet and validate that is passes through the service chain and is natively forwarded

        # first frame is slowpath second frame is through the fastpath
        for t in tests:
            with self.subTest(msg=f"*******************Test: {t['name']}", t=t):
                for f in range(nframes):
                    log_packet('Sent packet', t['send'])
                    if t['expect'] == None:
                        self.send_and_assert_no_replies(self.pg0, t['send'] * t['npackets'])
                        continue
                    else:
                        try:
                            rx = self.send_and_expect(self.pg0, t['send'] * t['npackets'], self.pg1)
                        except:
                            self.fail(f"No packet received for test {t['name']}")
                    print(self.vapi.cli("show vcdp session-table"))
                    for p in rx:
                        log_packet('Received packet', p)
                        self.validate(p[1], t['expect'], msg=t)

                        # if reply is set, send reply and validate inside packet (VXLAN encapsulated)
                        # Send reply back through the opened sessions
                        if t.get('reply', False):
                            reply = self.make_reply(p)
                            expected_reply = self.make_reply(t['send'])
                            log_packet('Expected packet', expected_reply)
                            log_packet('Reply to send', reply)
                            try:
                                rx = self.send_and_expect(self.pg1, reply, self.pg0)
                            except:
                                print('FAIL:', t)
                                raise
                            log_packet('Out2in packet', rx[0])
                            self.validate_reply_packet(rx[0], t['send'])
                            #self.validate(rx[0][1], expected_reply)


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

        tests = self.gen_packets(self.vxlan_pool, self.pg1.remote_ip4, self.vxlan_dport, 123) # Move to setup

       # self.run_tests([tests[7]], self.vxlan_pool, self.vxlan_dport, 1)
        self.run_tests(tests, self.vxlan_pool, self.vxlan_dport, 1)
#        self.test_runner(self.nataas_tests, self.vxlan_pool, self.vxlan_dport2, 1)
        # self.send_packet_through_nat(pool, dport2)

        # TODO: What is supposed to happen if same packet is sent on two different tunnels? Drop or return traffic back on the original one?

        # verify that packet from outside does not create session (default drop for tenant 1000)

        pkt = IP(src='10.10.10.10', dst=self.pg1.remote_ip4)/TCP(sport=666)
        pkt_to_send = self.encapsulate(666, 123, pkt)
        no_session_pkt = pkt_to_send
        no_session_pkt[TCP].dport = 666
        self.send_and_assert_no_replies(self.pg1, no_session_pkt)

        print(self.vapi.cli("show vcdp session-table"))
        print(self.vapi.cli('show vcdp tenant'))
        print(self.vapi.cli('show vcdp tcp session-table'))

        self.assertEqual(self.statistics["/vcdp/tunnels/no"], 2)

        print('Tunnel statistics:', self.statistics["/vcdp/tunnels/rx"], self.statistics["/vcdp/tunnels/tx"])
