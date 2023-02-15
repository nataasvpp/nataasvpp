#!/usr/bin/env python3
#
# Copyright (c) 2022 Cisco and/or its affiliates.

 # pylint: disable=line-too-long
 # pylint: disable=invalid-name

"""NATaaS tests"""

import unittest
from socket import AF_INET, AF_INET6, inet_pton
import uuid
from framework import VppTestCase, VppTestRunner
from scapy.layers.inet import ICMP
from scapy.layers.inet6 import IP, TCP, UDP, Ether, IPv6
from scapy.layers.vxlan import VXLAN
from vpp_ip import DpoProto
from vpp_ip_route import FibPathProto, VppIpRoute, VppRoutePath
from vpp_papi import VppEnum

"""
Tests for NATaaS.
"""

DEBUG = True
def log_packet(msg, pkt):
    '''Show scapy packet'''
    if DEBUG:
        print(msg)
        pkt.show2()
def log_error_packet(msg, pkt):
    '''Show scapy packet'''
    print(msg)
    pkt.show2()

class TestNATaaS(VppTestCase):
    """NATaaS Test Case"""

    maxDiff = None
    @classmethod
    def setUpClass(cls):
        '''Initialise tests'''
        super(TestNATaaS, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)
        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        tenant=0
        outside_tenant=1000
        dport=4789
        dport2=4790
        # vrf=0
        pool = '222.1.1.1'
        nat_id = 'nat-instance-1'
        tenant_flags = VppEnum.vl_api_vcdp_tenant_flags_t
        tunnel_flags = VppEnum.vl_api_vcdp_tunnel_method_t
        services_flags = VppEnum.vl_api_vcdp_session_direction_t

        tunnel_id1 = str(uuid.uuid4())
        tunnel_id2 = str(uuid.uuid4())

        mss = 1280

        # NATs
        cls.vapi.vcdp_nat_add(nat_id=nat_id, addr=[pool], n_addr=len([pool]))

        # Tenants
        cls.vapi.vcdp_tenant_add_del(tenant_id=tenant, context_id=0, is_add=True)
        cls.vapi.vcdp_tenant_add_del(tenant_id=outside_tenant, context_id=0, flags=tenant_flags.NO_CREATE, is_add=True)

        # Bind tenant to nat
        cls.vapi.vcdp_nat_bind_set_unset(tenant_id=tenant, nat_id=nat_id, is_set=True)

        # Tunnels
        cls.vapi.vcdp_tunnel_add(tunnel_id=tunnel_id1, tenant_id=tenant, method=tunnel_flags.VL_API_VCDP_TUNNEL_VXLAN_DUMMY_L2, src=cls.pg0.local_ip4,
                                  dst=cls.pg0.remote_ip4, dport=dport2)  # Add src_mac, dst_mac
        cls.vapi.vcdp_tunnel_add(tunnel_id=tunnel_id2, tenant_id=tenant, method=tunnel_flags.VL_API_VCDP_TUNNEL_VXLAN_DUMMY_L2, src=cls.pg0.local_ip4,
                                  dst=cls.pg0.remote_ip4, dport=dport)  # Add src_mac, dst_mac

        # Configure services
        # cls.assertEqual(services_flags.VCDP_API_REVERSE, 1)
        forward_services = [{'data': 'vcdp-l4-lifecycle'}, {'data': 'vcdp-tcp-mss'}, {'data':'vcdp-nat-output'}]
        reverse_services = [{'data': 'vcdp-l4-lifecycle'}, {'data': 'vcdp-tunnel-output'}]
        outside_services = [{'data': 'vcdp-bypass'}]
        cls.vapi.vcdp_set_services(tenant_id=tenant, dir=services_flags.VCDP_API_FORWARD,
                                    n_services=len(forward_services), services=forward_services)
        cls.vapi.vcdp_set_services(tenant_id=tenant, dir=services_flags.VCDP_API_REVERSE,
                                    n_services=len(reverse_services), services=reverse_services)
        cls.vapi.vcdp_set_services(tenant_id=outside_tenant, dir=services_flags.VCDP_API_FORWARD,
                                    n_services=len(outside_services), services=outside_services)

        # MSS clamping
        cls.vapi.vcdp_tcp_mss_enable_disable(tenant_id=tenant, ip4_mss=[mss, 0xFFFF], is_enable=True)

        # Enable interfaces
        cls.vapi.vcdp_gateway_enable_disable(sw_if_index=cls.pg1.sw_if_index, is_enable=True, tenant_id=outside_tenant)
        cls.vapi.vcdp_gateway_tunnel_enable_disable(sw_if_index=cls.pg0.sw_if_index, is_enable=True)

        cls.vxlan_pool = pool
        cls.vxlan_dport = dport
        cls.vxlan_dport2 = dport2
        cls.mss = mss
        cls.nat_id = nat_id
        cls.tenant = tenant
        cls.tunnel_id1 = tunnel_id1

    @classmethod
    def tearDownClass(cls):
        '''Clean up after tests'''
        super(TestNATaaS, cls).tearDownClass()
        # if not cls.vpp_dead:
        #     for i in cls.pg_interfaces:
        #         i.unconfig_ip4()
        #         i.admin_down()

    def encapsulate(self, dport, vni, pkt):
        '''Wrap packet in Ether/IP/UDP/VXLAN. Specific to interface pg0'''
        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
            / UDP(sport=dport, dport=dport, chksum=0)
            / VXLAN(vni=vni, flags=0) / Ether()
            / pkt
        )


    def gen_packets(self, pool, dst, dport, vni):
        '''Array of tests. Returns encapsulated test packets'''
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
                # Test TTL=1. Expect ICMP error
                'name': 'Basic ICMP TTL=1',
                'send': IP(src='10.10.10.12', dst=dst, ttl=1)/ICMP(id=1234),
                'expect': IP(src=pool, dst=dst)/ICMP(id=1234),
                'npackets': 1,
                'expect_interface': self.pg0,
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

            {
                'name': 'Send non TCP/UDP/ICMP packet',
                'send': IP(src='210.10.10.10', dst=dst)/IP(),
                'expect': IP(src=pool, dst=dst)/IP(),
                'npackets': 1,
            },

            {
                'name': 'Check TCP MSS clamp',
                'send': IP(src='210.10.10.10', dst=dst)/TCP(sport=888, flags="S", options=[("MSS", 9000), ("EOL", None)]),
                'expect': IP(src=pool, dst=dst)/TCP(sport=888, flags="S", options=[("MSS", self.mss), ("EOL", None)]),
                'npackets': 1,
            },
            # Tests for TCP state machine
            {
                'name': 'TCP state machine 3-way open #1',
                'send':   IP(src='10.10.10.10', dst=dst)/TCP(flags="S", sport=12345, dport=80),
                'expect': IP(src=pool, dst=dst)/TCP(sport=12345, dport=80),
                'npackets': 1,
                'reply': True,
            },
            {
                'name': 'TCP state machine 3-way open #2',
                'send':   IP(src='10.10.10.10', dst=dst)/TCP(flags="A", sport=12345, dport=80),
                'expect': IP(src=pool, dst=dst)/TCP(flags="A", sport=12345, dport=80),
                'npackets': 1,
                'reply': False,
            },

            # ICMP error
            # {
            #     'name': 'ICMP error for established session',
            #     'send':   IP(src='8.8.8.8', dst=pool)/ICMP(type="dest-unreach", code="fragmentation-needed", nexthopmtu=576)/IP(src='10.10.10.10', dst=dst)/TCP(flags="S", sport=1234, dport=1234),
            #     'expect': None,
            #     'npackets': 1,
            #     'reply': False,
            #     'interface': self.pg1  # out2in
            # },
            {
                'name': 'ICMP error - truncated',
                'send':   IP(src='8.8.8.8', dst=pool)/ICMP(type="dest-unreach", code="fragmentation-needed", nexthopmtu=576),
                'expect': None,
                'npackets': 1,
                'reply': False,
                'interface': self.pg1  # out2in
            },

            {
                'name': 'ICMP error for established session from the outside',
                'send':   IP(src='9.9.9.9', dst=pool)/ICMP(type="dest-unreach", code="fragmentation-needed", nexthopmtu=576)/IP(src=pool, dst=dst)/TCP(flags="S", sport=12345, dport=80),
                'expect':   self.encapsulate(dport, vni, IP(src='9.9.9.9', dst='10.10.10.10')/ICMP(type="dest-unreach", code="fragmentation-needed", nexthopmtu=576)/IP(src='10.10.10.10', dst=dst)/TCP(flags="S", sport=1234, dport=1234)),
                'npackets': 1,
                'reply': False,
                'interface': self.pg1, # out2in
                'expect_interface': self.pg0,
                'validate': False,  # TODO: validate
            },
            {
                'name': 'ICMP error for established session from the inside',
                'send':   IP(src='10.10.10.10', dst=dst)/ICMP(type="dest-unreach", code="fragmentation-needed", nexthopmtu=576)/IP(src=dst, dst='10.10.10.10')/TCP(flags="S", sport=80, dport=12345),
                'expect':   IP(src=pool, dst=dst)/ICMP(type="dest-unreach", code="fragmentation-needed", nexthopmtu=576)/IP(src='10.10.10.10', dst=dst)/TCP(flags="S", sport=1234, dport=1234),
                'npackets': 1,
                'reply': False,
                'validate': False,  # TODO: validate
            },

            # {
            #     'name': 'Verify mid-stream TCP creates session',
            #     'send':   IP(src='10.10.10.10', dst=dst)/TCP(flags='A', sport=123, dport=8080),
            #     'expect': IP(src=pool, dst=dst)/TCP(sport=123, dport=8080),
            #     'npackets': 1,
            #     'nframe': 1,
            # },
        ]

        for t in tests:
            if 'expect_interface' not in t:
                t['expect_interface'] = self.pg1
            if t.get('interface', self.pg0) == self.pg0:
                t['send'] = self.encapsulate(dport, vni, t['send'])
                t['interface'] = self.pg0
            else:
                interface = t['interface']
                t['send'] =  Ether(src=interface.remote_mac, dst=interface.local_mac) / t['send']
                
            if t['expect']: # If a reply is expected
                t['expect'][IP].ttl -= 1


        return tests

    def validate(self, rx, expected, msg=None):
        '''Validate received and expected packets'''
        self.assertEqual(rx, expected.__class__(expected), msg=msg)

    def validate_bytes(self, rx, expected):
        '''Validate received and expected packets byte for byte'''
        self.assertEqual(rx, expected)

    def payload(self, len):
        '''Create payload of the given length'''
        return "x" * len

    def make_reply(self, pkt):
        '''Given a forward packet, generate the reply'''
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
        ''' A little rough validation that we received the packet on same tunnel as sent on'''
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
                    if t['expect'] is None:
                        print('Running test: ', t['name'], ' with no reply')
                        self.send_and_assert_no_replies(t['interface'], t['send'] * t['npackets'])
                        continue
                    else:
                        try:
                            rx = self.send_and_expect(t['interface'], t['send'] * t['npackets'], t['expect_interface'])
                        except Exception:
                            self.fail(f"No packet received for test {t['name']}")
                    print(self.vapi.cli("show vcdp session-table"))
                    for p in rx:
                        log_packet('Received packet:', p[1])
                        log_packet('Expected packet:', t['expect'])
                        validate = t.get('validate', True)
                        if validate:
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

        # self.run_tests(tests, self.vxlan_pool, self.vxlan_dport, 1)
        self.run_tests([tests[0]], self.vxlan_pool, self.vxlan_dport, 1)
        # self.run_tests(tests[9:], self.vxlan_pool, self.vxlan_dport, 1)

        # verify that packet from outside does not create session (default drop for tenant 1000)

        # pkt = IP(src='10.10.10.10', dst=self.vxlan_pool)/TCP(sport=666)
        # pkt_to_send = Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac) / pkt
        # self.send_and_assert_no_replies(self.pg1, pkt_to_send)

        print(self.vapi.cli("show vcdp session-table"))
        # print(self.vapi.cli('show vcdp tcp session-table'))
        print(self.vapi.cli('show vcdp tenant'))

        self.assertEqual(self.statistics["/vcdp/tunnels/no"], 2)

        print('Tunnel statistics:', self.statistics["/vcdp/tunnels/rx"], self.statistics["/vcdp/tunnels/tx"])
        print('NAT statistics', self.statistics[f"/vcdp/nat/{self.nat_id}/forward"], self.statistics[f"/vcdp/nat/{self.nat_id}/reverse"])

        print('Tenant session statistics', self.statistics["/vcdp/tenant_session/created"], self.statistics["/vcdp/tenant_session/removed"])

        # Delete tenant prematurely
        # self.vapi.vcdp_tenant_add_del(tenant_id=self.tenant, is_add=False)
        # self.run_tests([tests[0]], self.vxlan_pool, self.vxlan_dport, 1)


        # Delete a NAT
        self.vapi.vcdp_nat_bind_set_unset(tenant_id=self.tenant, nat_id=self.nat_id, is_set=False)
        self.vapi.vcdp_nat_remove(nat_id=self.nat_id)

        # Delete a tunnel
        self.vapi.vcdp_tunnel_remove(tunnel_id=self.tunnel_id1)

        # Delete tenant
        self.vapi.vcdp_tenant_add_del(tenant_id=self.tenant, is_add=False)
