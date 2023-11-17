#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2023 Cisco and/or its affiliates.

 # pylint: disable=line-too-long
 # pylint: disable=invalid-name

"""VCDP Port forwarding tests"""

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
Tests for VCDP Port forwarding.
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

class TestVCDPPortForwarding(VppTestCase):
    """VCDP TCP session Test Case"""

    maxDiff = None
    @classmethod
    def setUpClass(cls):
        '''Initialise tests'''
        super(TestVCDPPortForwarding, cls).setUpClass()
        cls.create_pg_interfaces(range(2))
        cls.interfaces = list(cls.pg_interfaces)
        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()

        tenant=0
        outside_tenant=1000
        portforwarding_tenant=2000
        cls.pool = '222.1.1.1'
        nat_id = 'nat-instance-1'
        services_flags = VppEnum.vl_api_vcdp_service_chain_t
        mss = 1280

        # NATs
        cls.vapi.vcdp_nat_add(nat_id=nat_id, addr=[cls.pool], n_addr=len([cls.pool]))

        # Tenants
        cls.vapi.vcdp_tenant_add_del(tenant_id=tenant, context_id=0, is_add=True)
        cls.vapi.vcdp_tenant_add_del(tenant_id=outside_tenant, context_id=0, is_add=True)
        cls.vapi.vcdp_tenant_add_del(tenant_id=portforwarding_tenant, context_id=0, is_add=True)

        # Bind tenant to nat
        cls.vapi.vcdp_nat_bind_set_unset(tenant_id=tenant, nat_id=nat_id, is_set=True)

        # Configure services
        # cls.assertEqual(services_flags.VCDP_API_REVERSE, 1)
        forward_services = [{'data': 'vcdp-l4-lifecycle'}, {'data': 'vcdp-tcp-mss'},
                            {'data': "vcdp-nat-early-rewrite"}, {'data':'vcdp-output'}]
        reverse_services = [{'data': 'vcdp-l4-lifecycle'}, {'data': "vcdp-nat-late-rewrite"},
                            {'data': 'vcdp-output'}]
        # outside_services = [{'data': 'vcdp-bypass'}]
        miss_services = [{'data': 'vcdp-nat-port-forwarding'}, {'data': 'vcdp-drop'}]

        portforwarding_services = [{'data': 'vcdp-nat-early-rewrite'}, {'data': 'vcdp-output'},]
        portforwarding_reverse_services = [{'data': 'vcdp-nat-late-rewrite'}, {'data': 'vcdp-output'},]

        cls.vapi.vcdp_set_services(tenant_id=tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
                                    n_services=len(forward_services), services=forward_services)
        cls.vapi.vcdp_set_services(tenant_id=tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE,
                                    n_services=len(reverse_services), services=reverse_services)
        # cls.vapi.vcdp_set_services(tenant_id=outside_tenant, dir=services_flags.VCDP_API_FORWARD,
        #                             n_services=len(outside_services), services=outside_services)
        cls.vapi.vcdp_set_services(tenant_id=outside_tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS,
                                    n_services=len(miss_services), services=miss_services)

        # Service chain template for port-forwarding
        cls.vapi.vcdp_set_services(tenant_id=portforwarding_tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
                                    n_services=len(portforwarding_services), services=portforwarding_services)
        cls.vapi.vcdp_set_services(tenant_id=portforwarding_tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE,
                                    n_services=len(portforwarding_reverse_services), services=portforwarding_reverse_services)

        # MSS clamping
        cls.vapi.vcdp_tcp_mss_enable_disable(tenant_id=tenant, ip4_mss=[mss, 0xFFFF], is_enable=True)

        # NAT port forwarding
        match = {'addr': cls.pool, 'port': 80, 'protocol': 6}
        rewrite = {'addr': '10.10.10.10', 'port': 8080,}

        cls.vapi.vcdp_nat_portforwarding_add_del(tenant_id=portforwarding_tenant,
                                             nat_id=nat_id, match=match, rewrite=rewrite)

        # Enable interfaces
        cls.vapi.vcdp_gateway_enable_disable(sw_if_index=cls.pg1.sw_if_index, output_arc=True, is_enable=True, tenant_id=tenant)
        cls.vapi.vcdp_gateway_enable_disable(sw_if_index=cls.pg1.sw_if_index, is_enable=True, tenant_id=outside_tenant)

        cls.vapi.cli(f"ip route add 10.0.0.0/8 via {cls.pg0.remote_ip4}")

        cls.mss = mss
        cls.nat_id = nat_id
        cls.tenant = tenant

    @classmethod
    def tearDownClass(cls):
        '''Clean up after tests'''
        super(TestVCDPPortForwarding, cls).tearDownClass()
        # if not cls.vpp_dead:
        #     for i in cls.pg_interfaces:
        #         i.unconfig_ip4()
        #         i.admin_down()

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
        self.assertEqual(pkt[IP].proto, 6)
        pkt[TCP].sport, pkt[TCP].dport = pkt[TCP].dport, pkt[TCP].sport
        return pkt

    def port_forwarding(self, interface, expect_interface):
        '''Establish TCP session'''
        # Send SYN
        mss = 1460
        print('SYN')
        syn = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)/IP(src=self.pg1.remote_ip4, dst=self.pool)/TCP(sport=1234, dport=80, flags='S', seq=1000, options=[("MSS", (mss)), ("EOL", None)]))
        syn.show2()
        rx = self.send_and_expect(interface, syn, expect_interface)
        print('RX')
        rx[0].show2()
        # self.assertEqual(rx[0][TCP].options[0][1], self.mss)

        print('SYN-ACK')
        synack = self.make_reply(rx[0])
        synack[TCP].flags='SA'
        synack.show2()
        rx = self.send_and_expect(expect_interface, synack, interface)

        print('RX of SYNACK')
        rx[0].show2()

        # Send a packet that should continue down the miss-chain
        syn = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)/IP(src=self.pg1.remote_ip4, dst=self.pool)/TCP(sport=1234, dport=81, flags='S', seq=1000, options=[("MSS", (mss)), ("EOL", None)]))
        syn.show2()
        self.send_and_assert_no_replies(interface, syn)


        # # Send ACK
        # print('ACK')
        # ack = syn.copy()
        # ack[TCP].flags='A'
        # rx = self.send_and_expect(interface, ack, expect_interface)

        # # Verify that session is established
        # print('Verify session')
        # session = self.vapi.vcdp_session_lookup(tenant_id=self.tenant, src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, sport=1234, dport=80, protocol=6)
        # print('SESSION', session)
        # session_state = VppEnum.vl_api_vcdp_session_state_t
        # self.assertEqual(session.state, session_state.VCDP_API_SESSION_STATE_ESTABLISHED)


    def test_vcdp_session(self):
        """VCDP Port Forwarding TCP Session through NAT from outside"""
        print(self.vapi.cli("show vcdp session"))

        self.port_forwarding(self.pg1, self.pg0)

        # Close it
        # self.close_session(self.pg1, self.pg0)

        # # Establish it again and verify that session goes back to established and that
        # # MSS clamping works
        # self.establish_session(self.pg0, self.pg1)


        print(self.vapi.cli("show vcdp session detail"))
        print(self.vapi.cli("show vcdp summary"))
        # print(self.vapi.cli('show vcdp tcp session-table'))
        print(self.vapi.cli('show vcdp tenant'))

        # self.assertEqual(self.statistics["/vcdp/tunnels/no"], 2)

        # print('Tunnel statistics:', self.statistics["/vcdp/tunnels/rx"], self.statistics["/vcdp/tunnels/tx"])
        print('NAT statistics', self.statistics[f"/vcdp/nats/{self.nat_id}/rx-octets-and-pkts"], self.statistics[f"/vcdp/nats/{self.nat_id}/tx-octets-and-pkts"])

        print('Tenant session statistics', self.statistics["/vcdp/tenant/created-sessions"], self.statistics["/vcdp/tenant/removed-sessions"])
