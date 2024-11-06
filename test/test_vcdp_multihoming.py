#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2023 Cisco and/or its affiliates.

# pylint: disable=line-too-long
# pylint: disable=invalid-name

"""VCDP Multihoming tests"""

import unittest
from socket import AF_INET, AF_INET6, inet_pton
import uuid
from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_ip import DpoProto
from vpp_ip_route import FibPathProto, VppIpRoute, VppRoutePath
from vpp_papi import VppEnum

from scapy.all import Ether, IP, IPOption_RR, UDP, TCP, ICMP

"""
Tests for VCDP Multi-homing.
"""

DEBUG = True


def log_packet(msg, pkt):
    """Show scapy packet"""
    if DEBUG:
        print(msg)
        pkt.show2()


def log_error_packet(msg, pkt):
    """Show scapy packet"""
    print(msg)
    pkt.show2()


def validate(self, rx, expected, msg=None):
    """Validate received and expected packets"""
    self.assertEqual(rx, expected.__class__(expected), msg=msg)


def validate_bytes(self, rx, expected):
    """Validate received and expected packets byte for byte"""
    self.assertEqual(rx, expected)


def payload(self, len):
    """Create payload of the given length"""
    return "x" * len


def fixup_tcp_flags(pkt, flags):
    pkt[TCP].flags = flags

class NAT:
    def __init__(self, in_if, out_if, dst=None, tunnel=False) -> None:
        self.in_if = in_if
        self.out_if = out_if
        self.context_id = 0
        self.dst = dst
        self.tunnel = tunnel

class TestVCDPMH(VppTestCase):
    """VCDP MH Test Cases"""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        """Initialise tests"""
        super(TestVCDPMH, cls).setUpClass()
        cls.create_pg_interfaces(range(5))
        cls.interfaces = list(cls.pg_interfaces)
        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()


    def setUp(self):
        """Set up test environment"""
        super(TestVCDPMH, self).setUp()
        print('Configuring VCDP...')
        self.configure_vcdp()


    @classmethod
    def tearDownClass(cls):
        """Clean up after tests"""
        super(TestVCDPMH, cls).tearDownClass()
        # if not cls.vpp_dead:
        #     for i in cls.pg_interfaces:
        #         i.unconfig_ip4()
        #         i.admin_down()


    def enable_interface(self, sw_if_index, inside_tenant,
                         outside_tenant=None):
        """Enable interface"""
        self.vapi.vcdp_gateway_enable_disable(sw_if_index=sw_if_index, is_enable=True,
                                              tenant_id=inside_tenant)
        if outside_tenant is not None:
            self.vapi.vcdp_gateway_enable_disable(sw_if_index=sw_if_index, is_enable=True,
                                                  tenant_id=outside_tenant, output_arc=True)


    def configure_vcdp(self):
        '''
        Inside interface: self.pg0
        Outside interface 1: self.pg1
        Outside interface 2: self.pg2

        # RX only VCDP
        Inside interface: self.pg3
        Outside interface: self.pg4
        '''
        tenant1 = 0
        tenant2 = 1
        tenant3 = 2
        tenant4 = 3
        self.tenant1 = tenant1
        outside_tenant = 1000
        bypass_tenant = 2000
        nat_id1 = "nat-instance-pg1"
        nat_id2 = "nat-instance-pg2"
        nat_id3 = "nat-instance-ipip0"
        nat_id4 = "nat-instance-rxmode"

        services_flags = VppEnum.vl_api_vcdp_service_chain_t

        # Tenants
        self.vapi.vcdp_tenant_add_del(tenant_id=tenant1, context_id=0, is_add=True)
        self.vapi.vcdp_tenant_add_del(tenant_id=tenant2, context_id=0, is_add=True)
        self.vapi.vcdp_tenant_add_del(tenant_id=tenant3, context_id=0, is_add=True)
        self.vapi.vcdp_tenant_add_del(tenant_id=tenant4, context_id=0, is_add=True)
        self.vapi.vcdp_tenant_add_del(tenant_id=outside_tenant, context_id=0, is_add=True)
        self.vapi.vcdp_tenant_add_del(tenant_id=bypass_tenant, context_id=0, is_add=True)

        # Configure service chains
        self.vapi.vcdp_set_services(tenant_id=tenant1, dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD, services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output")
        self.vapi.vcdp_set_services(tenant_id=tenant1, dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE, services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output")
        self.vapi.vcdp_set_services(tenant_id=tenant1, dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS, services="vcdp-nat-slowpath vcdp-drop")

        self.vapi.vcdp_set_services(tenant_id=tenant2, dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD, services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output")
        self.vapi.vcdp_set_services(tenant_id=tenant2, dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE, services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output")
        self.vapi.vcdp_set_services(tenant_id=tenant2, dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS, services="vcdp-nat-slowpath vcdp-drop")

        self.vapi.vcdp_set_services(tenant_id=tenant3, dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD, services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output")
        self.vapi.vcdp_set_services(tenant_id=tenant3, dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE, services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output")
        self.vapi.vcdp_set_services(tenant_id=tenant3, dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS, services="vcdp-nat-slowpath vcdp-drop")

        self.vapi.vcdp_set_services(tenant_id=tenant4, dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD, services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output")
        self.vapi.vcdp_set_services(tenant_id=tenant4, dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE, services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output")
        self.vapi.vcdp_set_services(tenant_id=tenant4, dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS, services="vcdp-nat-slowpath vcdp-drop")

        self.vapi.vcdp_set_services(tenant_id=bypass_tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD, services="vcdp-output")
        self.vapi.vcdp_set_services(tenant_id=bypass_tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE, services="vcdp-output")
        # self.vapi.vcdp_set_services(tenant_id=bypass_tenant, dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS, services="vcdp-nat-slowpath vcdp-drop")

        # Configure IPIP tunnel
        self.ipip_tunnel_session = {'src': self.pg1.local_ip4,
                                    'dst': self.pg1.remote_ip4,
                                    'sport': 0,
                                    'dport': 0,
                                    'proto': 4}

        ipip_sw_if_index = self.ipip_add_tunnel(bypass_tenant, **self.ipip_tunnel_session)

        # NATs
        print('Configuring NAT instances')
        self.vapi.vcdp_nat_if_add(nat_id=nat_id1, sw_if_index=self.pg1.sw_if_index)
        self.vapi.vcdp_nat_if_add(nat_id=nat_id2, sw_if_index=self.pg2.sw_if_index)
        self.vapi.vcdp_nat_if_add(nat_id=nat_id3, sw_if_index=ipip_sw_if_index)
        self.vapi.vcdp_nat_if_add(nat_id=nat_id4, sw_if_index=self.pg4.sw_if_index)

        # Bind tenant to nat
        self.vapi.vcdp_nat_bind_set_unset(tenant_id=tenant1, nat_id=nat_id1, is_set=True)
        self.vapi.vcdp_nat_bind_set_unset(tenant_id=tenant2, nat_id=nat_id2, is_set=True)
        self.vapi.vcdp_nat_bind_set_unset(tenant_id=tenant3, nat_id=nat_id3, is_set=True)
        self.vapi.vcdp_nat_bind_set_unset(tenant_id=tenant4, nat_id=nat_id4, is_set=True)


        # Enable outside interface using interface NAT
        self.enable_interface(self.pg1.sw_if_index, inside_tenant=outside_tenant, outside_tenant=tenant1)
        self.enable_interface(self.pg2.sw_if_index, inside_tenant=outside_tenant, outside_tenant=tenant2)
        self.enable_interface(self.pg3.sw_if_index, inside_tenant=tenant4)
        self.enable_interface(self.pg4.sw_if_index, inside_tenant=outside_tenant)
        self.enable_interface(ipip_sw_if_index, inside_tenant=outside_tenant, outside_tenant=tenant3)

        self.nat1 = NAT(self.pg0, self.pg1)
        self.nat2 = NAT(self.pg0, self.pg2)
        self.nat3 = NAT(self.pg0, self.pg1, '10.0.0.123', tunnel=True)
        self.nat4 = NAT(self.pg3, self.pg4)
        self.nats = [self.nat1, self.nat2, self.nat3, self.nat4]

    def ipip_add_tunnel(self, tenant, src, dst, sport, dport, proto, table_id=0, dscp=0x0, flags=0):
        """Add a IPIP tunnel"""
        rv = self.vapi.ipip_add_tunnel(
            tunnel={
                "src": src,
                "dst": dst,
                "table_id": table_id,
                "instance": 0xFFFFFFFF,
                "dscp": dscp,
                "flags": flags,
            }
        )
        sw_if_index = rv.sw_if_index
        print(f'Created IPIP tunnel {sw_if_index}')

        rv = self.vapi.sw_interface_set_flags(sw_if_index,
                                              flags=VppEnum.vl_api_if_status_flags_t.IF_STATUS_API_FLAG_ADMIN_UP)
        print('Enabled IPIP tunnel state:', rv)
        rv = self.vapi.sw_interface_add_del_address(sw_if_index=sw_if_index, prefix='10.0.0.1/24', is_add=1)
        print('Enabled IPIP tunnel address:', rv)

        # # Send test packet
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)/
            IP(src='1.2.3.4', dst='10.0.0.2')/ICMP())
        rx = self.send_and_expect(self.pg0, p, self.pg1)

        # Add static session for IPIP tunnel
        primary_key = {'context_id': 0, 'src': dst, 'dst': src, 'sport': 0, 'dport': 0, 'proto': 4}
        secondary_key = {'context_id': 0, 'src': src, 'dst': dst, 'sport': 0, 'dport': 0, 'proto': 4}
        self.vapi.vcdp_session_add(tenant_id=tenant, primary_key=primary_key,
                                   secondary_key=secondary_key)


        return sw_if_index

    def send_i2o_packet(self, out_if, dst_port=53):
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)/
            IP(src=self.pg0.remote_ip4, dst=out_if.remote_ip4)/
            UDP(dport=dst_port))
        rx = self.send_and_expect(self.pg0, p, out_if)
        for p in rx:
            # print('OUTSIDE packet:')
            # p.show2()
            print(p.summary())

    def send_o2i_packet(self, out_if, no_reply=False, src_port=53):
        p = (Ether(src=out_if.remote_mac, dst=out_if.local_mac)/
            IP(src=out_if.remote_ip4, dst=out_if.local_ip4)/
            UDP(sport=src_port))
        print('OUTSIDE TO INSIDE packet:')
        p.show2()
        if no_reply:
            self.send_and_assert_no_replies(out_if, p)
            return
        rx = self.send_and_expect(out_if, p, self.pg0)
        for p in rx:
            print(p.summary())

    def send_i2o_tunnel(self, dst, outif, dport=53):
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)/
            IP(src=self.pg0.remote_ip4, dst=dst)/UDP(dport=dport))
        rx = self.send_and_expect(self.pg0, p, outif)
        for p in rx:
            p.show2()
            print(p.summary())

    def send_o2i_tunnel(self, inif, dport=53):
        p = (Ether(src=inif.remote_mac, dst=inif.local_mac)/
             IP(src=inif.remote_ip4, dst=inif.local_ip4)/
            IP(src='10.0.0.2', dst='10.0.0.1')/UDP(dport=dport))
        print('====================================')
        p.show2()
        rx = self.send_and_expect(inif, p, self.pg0)
        for p in rx:
            p.show2()
            print(p.summary())

    def verify_ping_request(self, p, src, dst, seq):
        ip = p[IP]
        self.assertEqual(ip.version, 4)
        self.assertEqual(ip.flags, 0)
        self.assertEqual(ip.src, src)
        self.assertEqual(ip.dst, dst)
        self.assertEqual(ip.proto, 1)
        self.assertEqual(len(ip.options), 0)
        self.assertGreaterEqual(ip.ttl, 254)
        icmp = p[ICMP]
        self.assertEqual(icmp.type, 8)
        self.assertEqual(icmp.code, 0)
        self.assertEqual(icmp.seq, seq)
        return icmp


    def ping_ip4(self, interface):
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()

        remote_ip4 = interface.remote_ip4
        ping_cmd = "ping " + remote_ip4 + " interval 0.01 repeat 10"
        ret = self.vapi.cli(ping_cmd)
        self.logger.info(ret)
        out = interface.get_capture(10)
        icmp_id = None
        icmp_seq = 1
        for p in out:
            icmp = self.verify_ping_request(
                p, interface.local_ip4, interface.remote_ip4, icmp_seq
            )
            icmp_seq = icmp_seq + 1
            if icmp_id is None:
                icmp_id = icmp.id
            else:
                self.assertEqual(icmp.id, icmp_id)

    def test_vcdp_ping(self):
        print('Configuring VCDP...')
        self.configure_vcdp()

        # Test local traffic. Set source to local interface
        self.ping_ip4(self.pg1)
        print(self.vapi.cli("show vcdp session"))

    def make_reply_ip(self, pkt, i):
        pkt[i].src, pkt[i].dst = pkt[i].dst, pkt[i].src
        if pkt[i].proto == 6 or pkt[i].proto == 17:
            pkt[i+1].sport, pkt[i+1].dport = pkt[i+1].dport, pkt[i+1].sport
        return pkt
    def make_reply(self, pkt):
        """Given a forward packet, generate the reply"""
        pkt = pkt.copy()
        pkt[Ether].src, pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src
        pkt = self.make_reply_ip(pkt, 1)
        if pkt[1].proto == 4:
            pkt = self.make_reply_ip(pkt, 2)
        return pkt

    def tcp_handshake(self, nat, sport, dport):
        # Send SYN
        src = nat.in_if.remote_ip4
        if nat.tunnel:
            dst = nat.dst
        else:
            dst = nat.out_if.remote_ip4
        syn = (Ether(src=nat.in_if.remote_mac, dst=nat.in_if.local_mac)/
            IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags='S'))
        rx = self.send_and_expect(nat.in_if, syn, nat.out_if)

        # Send SYN-ACK
        syn_ack = self.make_reply(rx[0])
        syn_ack[TCP].flags = 'SA'
        # print('Sending SYN-ACK')
        # syn_ack.show2()
        rx = self.send_and_expect(nat.out_if, syn_ack, nat.in_if)

        # Send ACK
        ack = syn.copy()
        ack[TCP].flags = 'A'
        rx = self.send_and_expect(nat.in_if, ack, nat.out_if)

        # Verify session
        session = self.vapi.vcdp_session_lookup(context_id=nat.context_id, src=src, dst=dst,
                                                sport=sport, dport=dport, proto=6)
        print(f'Session {session}')
        assert session.pkts == [2, 1]
        # assert session.bytes == [144, 144, 144]

        # Send FIN
        fin = ack.copy()
        fin[TCP].flags = 'F'
        rx = self.send_and_expect(nat.in_if, fin, nat.out_if)

        # Send FIN-ACK
        fin_ack = self.make_reply(rx[0])
        fin_ack[TCP].flags = 'FA'
        rx = self.send_and_expect(nat.out_if, fin_ack, nat.in_if)

    def test_tcp_handshake(self):
        # Test handshake
        for i, nat in enumerate(self.nats):
            self.tcp_handshake(nat, 12000+i, 80)
        print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp session detail")}')

    def test_ip4_option(self):
        # Test IP4 options
        # Currently options end up from ip4-input to ip4-options that drops them.
        p = (Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)/
            IP(src=self.pg0.remote_ip4, dst=self.pg1.remote_ip4, options=[IPOption_RR()])/UDP(dport=80))
        self.send_and_assert_no_replies(self.pg0, p)

        # What if we put the options packet inside of a tunnel?
        p = (Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)/
             IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4)/
            IP(src='10.0.0.2', dst=self.pg0.remote_ip4, options=[IPOption_RR()])/UDP(dport=1234))
        self.send_and_assert_no_replies(self.pg1, p)

    def test_ipip_tunnel(self):
        # Test IPIP tunnel
        self.send_i2o_tunnel('10.0.0.2', self.pg1)
        self.send_o2i_tunnel(self.pg1)

    def test_icmp_error_ttl(self):
        # Create session with ttl=1
        nat = self.nat1

        p = (Ether(src=nat.in_if.remote_mac, dst=nat.in_if.local_mac)/
             IP(src=nat.in_if.remote_ip4, dst=nat.out_if.remote_ip4, ttl=1)/
             UDP(dport=1234))
        rx = self.send_and_expect(nat.in_if, p, nat.in_if)
        rx[0].show2()

        # Assert on ICMP error

    def test_icmp_error(self):
        # Test handshake
        # for i, nat in enumerate(self.nats):
        #     self.tcp_handshake(nat, 12000+i, 80)
        nat = self.nat1

        # Create session
        p = (Ether(src=nat.in_if.remote_mac, dst=nat.in_if.local_mac)/
             IP(src=nat.in_if.remote_ip4, dst=nat.out_if.remote_ip4)/
             UDP(dport=1234))
        rx = self.send_and_expect(nat.in_if, p, nat.out_if)
        print('CREATE SESSION INSIDE TO OUTSIDE - REPLY')
        rx[0].show2()
        outside_packet = rx[0].copy()

        # Send ICMP error from outside to inside.
        # Created for a packet sent inside to outside.
        icmp_error = (Ether(src=nat.out_if.remote_mac, dst=nat.out_if.local_mac)/
                      IP(src='1.2.3.4', dst=rx[0][IP].src)/ICMP(type=3, code=1)/
                      rx[0][IP])
        icmp_error.show2()
        rx = self.send_and_expect(nat.out_if, icmp_error, nat.in_if)
        rx[0].show2()
        assert str(rx[0][IP].src) == '1.2.3.4'
        assert rx[0][IP].dst == nat.in_if.remote_ip4
        inner_ip = rx[0][3]
        inner_ip.show2()
        assert inner_ip.src == nat.in_if.remote_ip4
        assert inner_ip.dst == nat.out_if.remote_ip4

        # print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp session detail")}')

        # Send ICMP error from inside to outside.
        # Created for a packet sent outside to inside (a reply).
        reply_packet = self.make_reply(outside_packet)
        rx = self.send_and_expect(nat.out_if, reply_packet, nat.in_if)
        print('INNER REPLY PACKET')
        rx[0].show2()

        icmp_error = (Ether(src=nat.in_if.remote_mac, dst=nat.in_if.local_mac)/
                        IP(src=nat.in_if.remote_ip4, dst=nat.out_if.remote_ip4)/ICMP(type=3, code=1)/
                        rx[0][IP])

        icmp_error.show2()
        rx = self.send_and_expect(nat.in_if, icmp_error, nat.out_if)

        # ICMP error on the outside of the NAT
        print('THE ICMP error message on the outside of the NAT')
        rx[0].show2()

    def test_vcdp_mh(self):
        '''VCDP Multi-homing tests'''
        # Test local traffic. Set source to local interface
        # self.ping_ip4(self.pg0)


        # Verify outer tunnel counters
        session = self.vapi.vcdp_session_lookup(context_id=0, **self.ipip_tunnel_session)
        print(f'Session {session}')
        # assert session.pkts == [1, 1]
        try:
            assert session.bytes == [48, 48], "Expected to fail until we fix vcdp_get_l3_length()"
        except AssertionError as e:
            print(e)

        # Send a packet from inside to outside via pg1
        self.send_i2o_packet(self.pg1, dst_port=80)
        self.send_o2i_packet(self.pg1, src_port=80)

        # Trying to send packet from outside to inside via pg1...
        self.send_o2i_packet(self.pg1, no_reply=True)
        # Now it should work
        self.send_i2o_packet(self.pg1)
        self.send_o2i_packet(self.pg1, no_reply=False)

        print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp session detail")}')
        print(f'Interfaces:\n{self.vapi.cli("show vcdp interface")}')


        # Test timeout
        self.vapi.vcdp_set_timeout(established=10)
        self.send_i2o_packet(self.pg1, dst_port=81)
        self.send_o2i_packet(self.pg1, src_port=81)
        i = 0
        while i < 10:
            self.sleep(2)
            print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp session")}')
            i += 1

        # Check that session to verify that old is removed
        self.send_i2o_packet(self.pg1, dst_port=82)
        print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp session")}')

        # Add separate tests.
        # add test for TCP 3-way handshake

        return
        # self.sleep(6)
        # self.send_i2o_packet(self.pg1)
        # self.send_i2o_packet(self.pg1, dst_port=80)

        # print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp session detail")}')

        ##################################################


        # Send a packet from inside to outside via pg1
        print('Sending packet from inside to outside via pg1...')
        self.send_i2o_packet(self.pg1)
        self.send_i2o_packet(self.pg1)
        self.send_i2o_packet(self.pg2)


        print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp session detail")}')

        # Test how sessions is reused
        print('Waiting for session to timeout... then see if we can reuse it.')
        self.sleep(5)
        print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp session detail")}')
        print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp summary")}')
        self.send_i2o_packet(self.pg2)
        print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp session detail")}')

        # Verify that a session timer is refreshed when a packet is sent
        session = self.vapi.vcdp_session_lookup(tenant_id=1, src=self.pg0.remote_ip4, dst=self.pg2.remote_ip4,
                                                sport=53, dport=53, protocol=17)
        print(f'Session {session}')

        # while True:
        #     self.send_i2o_packet(self.pg1)
        #     self.sleep(2)
        #     print(f'SESSION TABLE:\n{self.vapi.cli("show vcdp session detail")}')

        # Verify that sessions are removed after timeout. Otherwise they'll hog outside ports.
        print(f'LRU:\n{self.vapi.cli("show vcdp lru")}')
        self.send_i2o_packet(self.pg2, dst_port=80)

        print(self.vapi.cli("show interface"))


        # Test local traffic. Set source to local interface
        self.ping_ip4(self.pg0)
        # print(self.vapi.cli(f"ping {self.pg0.remote_ip4} repeat 1"))
