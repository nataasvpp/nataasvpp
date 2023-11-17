# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
#
# Copyright (c) 2023 Cisco and/or its affiliates.

 # pylint: disable=line-too-long
 # pylint: disable=invalid-name

"""VCDP TCP session tests"""

import unittest
from socket import AF_INET, AF_INET6, inet_pton
import uuid
from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.inet import ICMP
from scapy.layers.inet6 import IP, TCP, UDP, Ether, IPv6
from scapy.layers.vxlan import VXLAN
from vpp_ip import DpoProto
from vpp_ip_route import FibPathProto, VppIpRoute, VppRoutePath
from vpp_papi import VppEnum

"""
Tests for VCDP TCP sessions.
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

class TestVCDPSession(VppTestCase):
    """VCDP TCP session Test Case"""

    maxDiff = None
    @classmethod
    def setUpClass(cls):
        '''Initialise tests'''
        super(TestVCDPSession, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)
        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        tenant=0
        outside_tenant=1000
        pool = '222.1.1.1'
        nat_id = 'nat-instance-1'
        services_flags = VppEnum.vl_api_vcdp_service_chain_t
        mss = 1280

        # NATs
        cls.vapi.vcdp_nat_add(nat_id=nat_id, addr=[pool], n_addr=len([pool]))

        # Tenants
        cls.vapi.vcdp_tenant_add_del(tenant_id=tenant, context_id=0, is_add=True)
        cls.vapi.vcdp_tenant_add_del(tenant_id=outside_tenant, context_id=0, is_add=True)

        # Bind tenant to nat
        cls.vapi.vcdp_nat_bind_set_unset(tenant_id=tenant, nat_id=nat_id, is_set=True)

        # Configure services
        # cls.assertEqual(services_flags.VCDP_API_REVERSE, 1)
        forward_services = [{'data': 'vcdp-l4-lifecycle'}, {'data': 'vcdp-tcp-check-lite'}, {'data': 'vcdp-tcp-mss'}, {'data':'vcdp-output'}]
        reverse_services = [{'data': 'vcdp-l4-lifecycle'}, {'data': 'vcdp-tcp-check-lite'},     {'data': 'vcdp-output'}]
        outside_services = [{'data': 'vcdp-bypass'}]
        miss_services = [{'data': 'vcdp-nat-slowpath'}, {'data': 'vcdp-drop'}]
        cls.vapi.vcdp_set_services(tenant_id=tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
                                    n_services=len(forward_services), services=forward_services)
        cls.vapi.vcdp_set_services(tenant_id=tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE,
                                    n_services=len(reverse_services), services=reverse_services)
        cls.vapi.vcdp_set_services(tenant_id=tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS,
                                    n_services=len(miss_services), services=miss_services)
        cls.vapi.vcdp_set_services(tenant_id=outside_tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
                                    n_services=len(outside_services), services=outside_services)

        # MSS clamping
        cls.vapi.vcdp_tcp_mss_enable_disable(tenant_id=tenant, ip4_mss=[mss, 0xFFFF], is_enable=True)

        # Enable interfaces
        cls.vapi.vcdp_gateway_enable_disable(sw_if_index=cls.pg0.sw_if_index, is_enable=True, tenant_id=tenant)
        cls.vapi.vcdp_gateway_enable_disable(sw_if_index=cls.pg1.sw_if_index, is_enable=True, tenant_id=outside_tenant)

        cls.mss = mss
        cls.nat_id = nat_id
        cls.tenant = tenant
        cls.pool = pool

    @classmethod
    def tearDownClass(cls):
        '''Clean up after tests'''
        super(TestVCDPSession, cls).tearDownClass()
        # if not cls.vpp_dead:
        #     for i in cls.pg_interfaces:
        #         i.unconfig_ip4()
        #         i.admin_down()

    def validate(self, rx, expected, msg=None):
        '''Validate received and expected packets'''
        if rx != expected.__class__(expected):
            log_error_packet(msg, rx)
            log_error_packet(msg, expected)
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
        self.assertEqual(pkt[IP].proto, 6)
        pkt[TCP].sport, pkt[TCP].dport = pkt[TCP].dport, pkt[TCP].sport
        return pkt

    def establish_session(self, interface, expect_interface):
        '''Establish TCP session'''
        # Send SYN
        mss = 1460
        print('SYN')
        syn = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)/IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)/TCP(sport=1234, dport=80, flags='S', seq=1000, options=[("MSS", (mss)), ("EOL", None)]))
        rx = self.send_and_expect(interface, syn, expect_interface)
        rx[0].show2()
        self.assertEqual(rx[0][TCP].options[0][1], self.mss)

        print('SYN-ACK')
        synack = self.make_reply(rx[0])
        synack[TCP].flags='SA'
        rx = self.send_and_expect(expect_interface, synack, interface)
        rx[0].show2()

        # Send ACK
        print('ACK')
        ack = syn.copy()
        ack[TCP].flags='A'
        rx = self.send_and_expect(interface, ack, expect_interface)

        # Verify that session is established
        print('Verify session')
        session = self.vapi.vcdp_session_lookup(tenant_id=self.tenant, src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, sport=1234, dport=80, protocol=6)
        print('SESSION', session)
        session_state = VppEnum.vl_api_vcdp_session_state_t
        self.assertEqual(session.state, session_state.VCDP_API_SESSION_STATE_ESTABLISHED)

    def close_session(self, interface, expect_interface):
        '''Close TCP session'''
        # Send FIN
        print('FIN')
        fin = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)/IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)/TCP(sport=1234, dport=80, flags='F', seq=1000))
        rx = self.send_and_expect(interface, fin, expect_interface)

        print('FIN-ACK')
        finack = self.make_reply(rx[0])
        finack[TCP].flags='FA'

        rx = self.send_and_expect(expect_interface, finack, interface)

        # Send ACK
        print('ACK')
        ack = fin.copy()
        ack[TCP].flags='A'
        rx = self.send_and_expect(interface, ack, expect_interface)

        # Verify that session is established
        print('Verify session')
        session = self.vapi.vcdp_session_lookup(tenant_id=self.tenant, src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, sport=1234, dport=80, protocol=6)
        print('SESSION', session)
        session_state = VppEnum.vl_api_vcdp_session_state_t
        self.assertEqual(session.state, session_state.VCDP_API_SESSION_STATE_TIME_WAIT)

    def test_vcdp_session(self):
        """VCDP TCP Session through NAT"""

        # Set up TCP session
        self.establish_session(self.pg0, self.pg1)

        # Close it
        self.close_session(self.pg0, self.pg1)

        # Establish it again and verify that session goes back to established and that
        # MSS clamping works
        self.establish_session(self.pg0, self.pg1)


        # print(self.vapi.cli("show vcdp session detail"))
        print(self.vapi.cli("show vcdp summary"))
        # print(self.vapi.cli('show vcdp tcp session-table'))
        print(self.vapi.cli('show vcdp tenant'))

        # self.assertEqual(self.statistics["/vcdp/tunnels/no"], 2)

        # print('Tunnel statistics:', self.statistics["/vcdp/tunnels/rx"], self.statistics["/vcdp/tunnels/tx"])
        print('NAT statistics', self.statistics[f"/vcdp/nats/{self.nat_id}/rx-octets-and-pkts"], self.statistics[f"/vcdp/nats/{self.nat_id}/tx-octets-and-pkts"])

        print('Tenant session statistics', self.statistics["/vcdp/tenant/created-sessions"], self.statistics["/vcdp/tenant/removed-sessions"])

    @unittest.SkipTest
    def test_tcp_checksum(self):
        '''Test TCP checksum'''

        # Send 64K packets, spinning through all possible checksums
        pkts = []
        print('Generating packets...')
        for i in range(0, 0xFFFF):
            pkt = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)/IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4)/TCP(sport=i, dport=81, flags='S'))
            pkts.append(pkt)

        print('Sending and receiving replies...')
        rx = self.send_and_expect(self.pg0, pkts, self.pg1, trace=False)

        print('Validating checksums...')
        for p in rx:
            modified = p.copy()
            modified[TCP].chksum = None
            modified[IP].src = self.pool
            self.validate(p[1], modified[1])


        print('VALIDATE TCP CHECKSUM in REPLY packet')
        # print(self.vapi.cli("show vcdp session"))
        print(self.vapi.cli("show vcdp summary"))

        print('Awaiting to see if anything expires:')
        import time
        time.sleep(10)

#       0x06000000ac100102ac10020204d20050
#       0x06000000ac100202de010101005004d2