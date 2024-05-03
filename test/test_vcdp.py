#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2023 Cisco and/or its affiliates.

# pylint: disable=line-too-long
# pylint: disable=invalid-name

"""VCDP tests"""

import unittest
from socket import AF_INET, AF_INET6, inet_pton
import uuid
from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.layers.inet import ICMP, GRE
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dhcp6 import (DHCP6, DHCP6_Solicit)
from scapy.layers.inet6 import (
    IP,
    TCP,
    UDP,
    Ether,
    IPv6,
    ICMPv6EchoRequest,
    ICMPv6DestUnreach,
)
from scapy.layers.vxlan import VXLAN
from vpp_ip import DpoProto
from vpp_ip_route import FibPathProto, VppIpRoute, VppRoutePath
from vpp_papi import VppEnum

"""
Tests for VCDP.
"""

# Define a set of tests. Each test:
# - packet to send.
# - expected packet to receive.
# - potential reply to send back? (and again a an expected packet to receive)... etc.

# Check NAT session state via API / CLI
# Check NAT statistics via API / CLI
# Multiple inside same source port to same destination port.
# Test effectiveness of port allocation algorithm.

# Test cases:
# - TCP session establishment
# - UDP session establishment
# - ICMP session establishment (echo request/reply)
# - ICMP error against existing session

# Tests depending on other sub-tests??

DEBUG = True

# TODO: Tests
# ===========
# - Plan IPv4 to IPv4
# - Plan IPv6 to IPv6
# - IPv6 link-local addresses
# - IPv4 link-local addresses
# - Interface address NAT
# - Directed broadcast traffic
# - Tunnels

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


class Test:
    def __init__(
        self,
        name,
        send,
        expect=None,
        npackets=1,
        expect_reply=None,
        reply=False,
        no_expect=False,
        expect_interface=None,
        send_interface=None,
        check=None,
        reply_fixup=None,
    ):
        self.name = name
        self.send = send
        self.expect = expect
        self.npackets = npackets
        self.reply = reply
        self.expect_reply = expect_reply
        self.no_expect = no_expect
        self.expect_interface = expect_interface
        self.send_interface = send_interface
        self.check = check
        self.reply_fixup = reply_fixup


class Tests(Test):
    def tcp_state_check(self, state, pkt):
        session = self.harness.vapi.vcdp_session_lookup(tenant_id=0,
                                                src=pkt[IP].dst,
                                                dst=pkt[IP].src,
                                                sport=pkt[TCP].dport,
                                                dport=pkt[TCP].sport,
                                                protocol=6)
        self.harness.assertEqual(session.state, state)

    def __init__(self, harness, inside, outside, pool):
        self.harness = harness
        self.inside = inside
        self.outside = outside
        self.pool = pool
        mss = 1240
        self.ether_in = Ether(src=inside.remote_mac, dst=inside.local_mac)
        self.ether_out = Ether(src=outside.remote_mac, dst=outside.local_mac)
        tcp = TCP(
            sport=1234,
            dport=80,
            flags="S",
            seq=1000,
            options=[("MSS", (mss)), ("EOL", None)],
        )
        tcp2 = TCP(
            sport=1234,
            dport=80,
            flags="A",
            seq=1000,
            options=[("MSS", (mss)), ("EOL", None)],
        )
        udp = UDP(sport=1234, dport=80)

        # Tests
        self.nat64_tests = [
            Test(
                name="UDP + reply",
                send=(
                    IPv6(src=inside.remote_ip6, dst="64:ff9b::" + outside.remote_ip4)
                    / udp
                ),
                expect=(IP(src=pool, dst=outside.remote_ip4, ttl=63, id=0) / udp),
                reply=True,
                npackets=2,
            ),
            Test(
                name="TCP SYN",
                send=(
                    IPv6(src=inside.remote_ip6, dst="64:ff9b::" + outside.remote_ip4)
                    / tcp
                ),
                reply=lambda pkt: fixup_tcp_flags(pkt, 'SA'),
            ),
            Test(
                name="TCP ACK",
                send=(
                    IPv6(src=inside.remote_ip6, dst="64:ff9b::" + outside.remote_ip4)
                    / tcp2
                ),
            ),
            Test(
                name="TCP SYN + reply conflicting source port",
                send=(IPv6(src="1::1", dst="64:ff9b::" + outside.remote_ip4) / tcp),
                # expect=(IP(src=pool, dst=outside.remote_ip4, ttl=63, id=0)/ tcp),
                reply=True,
            ),
            Test(
                name="ICMP echo + reply",
                send=(
                    IPv6(src=inside.remote_ip6, dst="64:ff9b::" + outside.remote_ip4)
                    / ICMPv6EchoRequest()
                ),
                expect=(IP(src=pool, dst=outside.remote_ip4, ttl=63, id=0) / ICMP()),
                reply=True,
                expect_reply=(
                    IPv6(
                        src="64:ff9b::" + outside.remote_ip4,
                        dst=inside.remote_ip6,
                        hlim=62,
                    )
                    / ICMPv6EchoRequest()
                ),
            ),
            Test(
                name="ICMP echo + reply conflicting source port",
                send=(
                    IPv6(src="1::1", dst="64:ff9b::" + outside.remote_ip4)
                    / ICMPv6EchoRequest()
                ),
                reply=True,
                expect_reply=(
                    IPv6(src="64:ff9b::" + outside.remote_ip4, dst="1::1", hlim=62)
                    / ICMPv6EchoRequest()
                ),
            ),
            Test(
                name="GRE",
                send=(
                    IPv6(src=inside.remote_ip6, dst="64:ff9b::" + outside.remote_ip4)
                    / GRE()
                ),
                npackets=4,
            ),
            Test(
                name="Truncated packet",
                send=(
                    IPv6(
                        src=inside.remote_ip6,
                        dst="64:ff9b::" + outside.remote_ip4,
                        nh=6,
                    )
                ),
                no_expect=True,
            )
            # IPv6 extension headers
            # Fragmented packets
            # Fragmented packets with shallow reassembly enabled
            # Hairpinning
        ]

        self.icmp_error_tests = [
            Test(
                name="Basic TCP TTL=1 in2out",
                send=(
                    IPv6(src="1::1", dst="64:ff9b::" + outside.remote_ip4, hlim=1) / tcp
                ),
                expect_interface=self.inside,
            ),
            Test(
                name="Basic TCP TTL=1 in2out against existing session",
                send=(
                    IPv6(src="1::1", dst="64:ff9b::" + outside.remote_ip4, hlim=1) / tcp
                ),
                expect_interface=self.inside,
            ),
            Test(
                name="ICMPv6 error against non-existing session (drop)",
                send=(
                    IPv6(src="1234::1", dst="64:ff9b::" + outside.remote_ip4)
                    / ICMPv6DestUnreach()
                    / IPv6(src=inside.remote_ip6, dst="64:ff9b::1.2.3.4")
                    / ICMPv6EchoRequest()
                ),
                no_expect=True,
            ),
            Test(
                name="ICMPv6 error against existing session (in2out)",
                send=(
                    IPv6(src="1234::1", dst="64:ff9b::" + outside.remote_ip4)
                    / ICMPv6DestUnreach()
                    / IPv6(src="1::1", dst="64:ff9b::" + outside.remote_ip4)
                    / tcp
                ),
            ),
            Test(
                name="ICMPv4 error against existing session (out2in)",
                send=(
                    IP(src="8.8.8.8", dst=self.pool)
                    / ICMP(type=3, code=1)
                    / IP(src=self.pool, dst=outside.remote_ip4)
                    / tcp
                ),
                send_interface=self.outside,
                expect_interface=self.inside,
            ),
        ]
        # First fragment
        fragment = IP(src=inside.remote_ip4, dst=outside.remote_ip4, flags="MF") / UDP(
            sport=1235, dport=80
        )
        # Second fragment
        second_fragment = IP(
            src=inside.remote_ip4, dst=outside.remote_ip4, flags="MF", frag=2
        )

        self.nat44_tests = [
            Test(
                name="UDP + reply",
                send=(IP(src=inside.remote_ip4, dst=outside.remote_ip4) / udp),
                reply=True,
                npackets=2,
            ),
            Test(
                name="TCP SYN",
                send=(IP(src=inside.remote_ip4, dst=outside.remote_ip4) / tcp),
                reply=lambda pkt: fixup_tcp_flags(pkt, 'SA'),
            ),
            Test(
                name="TCP ACK",
                send=(
                    IP(src=inside.remote_ip4, dst=outside.remote_ip4)
                    / TCP(sport=1234, dport=80, flags="A")
                ),
            ),
            Test(
                name="UDP fragment",
                send=(fragment),
                expect=(
                    IP(src=pool, dst=outside.remote_ip4, flags="MF", ttl=63, id=1)
                    / UDP(sport=1235, dport=80)
                ),
            ),
            Test(
                name="UDP fragment #2",
                send=(second_fragment),
                no_expect=True,
            ),
            Test(
                name="Basic ICMP TTL=10 in2out",
                send=(
                    IP(src=inside.remote_ip4, dst=outside.remote_ip4, ttl=10)
                    / ICMP(id=10)
                ),
                expect=(IP(src=pool, dst=outside.remote_ip4, ttl=9) / ICMP(id=10)),
            ),
            Test(
                name="Basic ICMP TTL=1 in2out",
                send=(
                    IP(src=inside.remote_ip4, dst=outside.remote_ip4, ttl=1)
                    / ICMP(id=10)
                ),
                expect_interface=self.inside,
            ),
            Test(
                name="Truncated packet",
                send=(IP(src=inside.remote_ip4, dst=outside.remote_ip4, proto=6)),
                no_expect=True,
            ),
            # Test(
            #     name="DHCP Discover",
            #     send=(IP(src='0.0.0.0', dst='255.255.255.255')/
            #           UDP(sport=68, dport=67)/
            #           BOOTP(chaddr='00:00:00:00:00:00', ciaddr='0.0.0.0', xid=0x01020304, flags=1)/
            #           DHCP(options=[("message-type", "discover"), "end"])),
            #     # expect=IP(src=pool, dst=dst)/UDP(sport=123, dport=456),
            #     no_expect=True,
            # ),
        ]

        self.port_forwarding_tests = [
            Test(
                name="TCP SYN",
                send=(IP(src=outside.remote_ip4, dst=pool) / TCP(sport=12340, dport=8000)),
                send_interface=outside,
                expect_interface=inside,
                # no_expect=True,
                # reply=fixup_tcp,
                reply=True,
            ),
            Test(
                name="Hairpinning",
                send=(IP(src=inside.remote_ip4, dst=pool) / TCP(sport=12340, dport=8000)),
                no_expect=True,
            )
        ]

        # Verify TCP establishment and teardown
        self.tcp_tests = [
            # Test(
            #     name="TCP SYN",
            #     send=(IP(src=outside.remote_ip4, dst=pool) / tcp),
            #     # reply=fixup_tcp,
            #     reply=True,
            #     check=tcp_state_check,
            # ),
            Test(
                name="TCP SYN",
                send=(IP(src=inside.remote_ip4, dst=outside.remote_ip4) / tcp),
                check=(lambda *args, state=VppEnum.vl_api_vcdp_session_state_t.VCDP_API_SESSION_STATE_FSOL: self.tcp_state_check(state, *args)),
                reply=lambda pkt: fixup_tcp_flags(pkt, 'SA'),
            ),
            Test(
                name="TCP ACK",
                send=(IP(src=inside.remote_ip4, dst=outside.remote_ip4) / tcp2),
                check=(lambda *args, state=VppEnum.vl_api_vcdp_session_state_t.VCDP_API_SESSION_STATE_ESTABLISHED: self.tcp_state_check(state, *args)),
                # reply=lambda pkt: fixup_tcp_flags(pkt, 'SA'),
            ),
            Test(
                name="TCP FIN",
                send=(IP(src=inside.remote_ip4, dst=outside.remote_ip4) / tcp2),
                check=(lambda *args, state=VppEnum.vl_api_vcdp_session_state_t.VCDP_API_SESSION_STATE_ESTABLISHED: self.tcp_state_check(state, *args)),
                reply=lambda pkt: fixup_tcp_flags(pkt, 'FA'),
            ),
            Test(
                name="TCP ACK",
                send=(IP(src=inside.remote_ip4, dst=outside.remote_ip4) / tcp2),
                check=(lambda *args, state=VppEnum.vl_api_vcdp_session_state_t.VCDP_API_SESSION_STATE_TIME_WAIT: self.tcp_state_check(state, *args)),
            ),
        ]

        # Verify that DHCP packets are bypassed and no session is created
        self.dhcp_tests = [
            Test(
                name="DHCP client to server broadcast",
                send=(IP(src='0.0.0.0', dst='255.255.255.255') / UDP(sport=68, dport=67) / BOOTP() /
                      DHCP(options=[("message-type","discover"),"end"])),
                no_expect=True,
            ),
            Test(
                name="DHCP client to server unicast",
                send=(IP(src=inside.remote_ip4, dst=inside.local_ip4) / UDP(sport=68, dport=67) / BOOTP() /
                      DHCP(options=[("message-type","discover"),"end"])),
                no_expect=True,
            )
        ]
        self.dhcp6_tests = [
            Test(
                name="DHCPv6 client to server multicast",
                send=(IPv6(src='fe80::1', dst='ff02::1:2') / UDP(sport=546, dport=547) / DHCP6_Solicit()),
                no_expect=True,
            ),
            # Test(
            #     name="DHCPv6 client to server multicast #2",
            #     send=(IPv6(src='fe80::1', dst='ff02::2') / UDP(sport=546, dport=547) / DHCP6_Solicit()),
            #     no_expect=True,
            # ),
        ]

    def make_reply(self, pkt):
        """Given a forward packet, generate the reply"""
        pkt = pkt.copy()
        pkt[Ether].src, pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src
        pkt[1].src, pkt[1].dst = pkt[1].dst, pkt[1].src
        if pkt[1].proto == 6 or pkt[1].proto == 17:
            pkt[2].sport, pkt[2].dport = pkt[2].dport, pkt[2].sport
        return pkt

    def send(self, test):
        log_packet(f"SEND: {test.name}", test.send)
        expect_interface = test.expect_interface or self.outside
        send_interface = test.send_interface or self.inside
        if test.no_expect:
            rx = self.harness.send_and_assert_no_replies(
                send_interface, [self.ether_in / test.send] * test.npackets
            )
            return
        else:
            rx = self.harness.send_and_expect(
                send_interface,
                [self.ether_in / test.send] * test.npackets,
                expect_interface,
            )
        log_packet(f"RX: {test.name}", rx[0])
        try:
            test.check(rx[0])
        except TypeError:
            pass
        if test.expect:
            log_packet(f"EXPECTED: {test.name}", test.expect)
            self.harness.assertEqual(
                rx[0][1], test.expect.__class__(test.expect), test.name
            )

        if test.reply:
            reply = self.make_reply(rx[0])
            if callable(test.reply):
                test.reply(reply)
            log_packet(f"REPLY: {test.name}", reply)
            rx = self.harness.send_and_expect(expect_interface, reply, send_interface)
            log_packet(f"REPLY RX: {test.name}", rx[0])
            if test.expect_reply:
                log_packet(f"EXPECTED REPLY: {test.name}", test.expect_reply)
                self.harness.assertEqual(
                    rx[0][1], test.expect_reply.__class__(test.expect_reply), test.name
                )


class TestVCDP(VppTestCase):
    """VCDP Test Cases"""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        """Initialise tests"""
        super(TestVCDP, cls).setUpClass()
        cls.create_pg_interfaces(range(4))
        cls.interfaces = list(cls.pg_interfaces)
        for i in cls.interfaces:
            i.admin_up()
            i.config_ip4()
            i.resolve_arp()
            i.config_ip6()
            i.resolve_ndp()

        tenant = 0
        v4tenant = 1
        iftenant = 2
        hairpinningtenant = 3
        cls.v4tenant_dpo = v4tenant_dpo = 4
        cls.v4dpo_prefix = v4dpo_prefix = '0.0.0.0/0'
        outside_tenant = 1000
        portforwarding_tenant = 2000
        bypass_tenant = 3000
        cls.pool = "222.1.1.1"
        nat_id = "nat-instance-1"
        nat_id2 = "nat-instance-2-interface"

        services_flags = VppEnum.vl_api_vcdp_service_chain_t

        # NATs
        cls.vapi.vcdp_nat_add(nat_id=nat_id, addr=[cls.pool], n_addr=len([cls.pool]))
        cls.vapi.vcdp_nat_if_add(nat_id=nat_id2, sw_if_index=cls.pg1.sw_if_index)

        # Tenants
        cls.vapi.vcdp_tenant_add_del(tenant_id=tenant, context_id=0, is_add=True)
        cls.vapi.vcdp_tenant_add_del(tenant_id=v4tenant, context_id=0, is_add=True)
        cls.vapi.vcdp_tenant_add_del(
            tenant_id=outside_tenant, context_id=0, is_add=True
        )
        cls.vapi.vcdp_tenant_add_del(
            tenant_id=portforwarding_tenant, context_id=0, is_add=True
        )
        cls.vapi.vcdp_tenant_add_del(tenant_id=iftenant, context_id=0, is_add=True)
        cls.vapi.vcdp_tenant_add_del(tenant_id=bypass_tenant, context_id=0, is_add=True)
        cls.vapi.vcdp_tenant_add_del(tenant_id=v4tenant_dpo, context_id=0, is_add=True)

        # Bind tenant to nat
        cls.vapi.vcdp_nat_bind_set_unset(tenant_id=tenant, nat_id=nat_id, is_set=True)
        cls.vapi.vcdp_nat_bind_set_unset(tenant_id=v4tenant, nat_id=nat_id, is_set=True)
        cls.vapi.vcdp_nat_bind_set_unset(tenant_id=v4tenant_dpo, nat_id=nat_id, is_set=True)
        cls.vapi.vcdp_nat_bind_set_unset(tenant_id=iftenant, nat_id=nat_id2, is_set=True)
        cls.vapi.vcdp_nat_bind_set_unset(tenant_id=portforwarding_tenant, nat_id=nat_id, is_set=True)

        # Configure services
        forward_services = "vcdp-l4-lifecycle vcdp-tcp-check-lite ip4-lookup"
        reverse_services = "vcdp-l4-lifecycle vcdp-tcp-check-lite ip6-lookup"
        miss_services = "vcdp-nat64-slowpath vcdp-drop"

        cls.vapi.vcdp_set_services(
            tenant_id=tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
            services=forward_services,
        )
        cls.vapi.vcdp_set_services(
            tenant_id=tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE,
            services=reverse_services,
        )
        cls.vapi.vcdp_set_services(
            tenant_id=tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS,
            services=miss_services,
        )

        # v4 DPO tenant service chains
        cls.vapi.vcdp_set_services(
            tenant_id=v4tenant_dpo,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
            services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output-dpo",
        )
        cls.vapi.vcdp_set_services(
            tenant_id=v4tenant_dpo,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE,
            services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output-dpo",
        )
        cls.vapi.vcdp_set_services(
            tenant_id=v4tenant_dpo,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS,
            services="vcdp-nat-slowpath vcdp-drop",
        )

        # v4 tenant service chains
        cls.vapi.vcdp_set_services(
            tenant_id=v4tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
            services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output",
        )
        cls.vapi.vcdp_set_services(
            tenant_id=v4tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE,
            services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output",
        )
        cls.vapi.vcdp_set_services(
            tenant_id=v4tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS,
            services="vcdp-lookup-ip4-1tuple vcdp-nat-slowpath vcdp-drop",
        )

        cls.vapi.vcdp_set_services(
            tenant_id=bypass_tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
            services="vcdp-bypass vcdp-drop",
        )

        # Interface NAT tenant service chains
        cls.vapi.vcdp_set_services(
            tenant_id=iftenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
            services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output",
        )
        cls.vapi.vcdp_set_services(
            tenant_id=iftenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE,
            services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output",
        )
        cls.vapi.vcdp_set_services(
            tenant_id=iftenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS,
            services="vcdp-lookup-ip4-1tuple vcdp-nat-slowpath vcdp-drop",
        )

        # Port forwarding service chains
        cls.vapi.vcdp_set_services(
            tenant_id=portforwarding_tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
            services="vcdp-nat-early-rewrite vcdp-output",
        )
        cls.vapi.vcdp_set_services(
            tenant_id=portforwarding_tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE,
            services="vcdp-nat-late-rewrite vcdp-output",
        )

        cls.vapi.vcdp_set_services(
            tenant_id=outside_tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS,
            services="vcdp-nat-port-forwarding vcdp-drop",
        )

        '''
        cls.vapi.vcdp_set_services(
            tenant_id=portforwarding_tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_FORWARD,
            services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output",
        )
        cls.vapi.vcdp_set_services(
            tenant_id=portforwarding_tenant
            dir=services_flags.VCDP_API_SERVICE_CHAIN_REVERSE,
            services="vcdp-l4-lifecycle vcdp-tcp-check-lite vcdp-output",
        )
        cls.vapi.vcdp_set_services(
            tenant_id=portforwarding_tenant,
            dir=services_flags.VCDP_API_SERVICE_CHAIN_MISS,
            services="vcdp-nat-port-forwarding vcdp-nat-slowpath vcdp-drop",
        )
        '''

        # Add static sessions for DHCP
        cls.vapi.vcdp_session_add(bypass_tenant, 0, '0.0.0.0', '255.255.255.255', 17, 68, 67)
        cls.vapi.vcdp_session_add(bypass_tenant, 0, 0, '255.255.255.255', 17, 0, 67)
        cls.vapi.vcdp_session_add(bypass_tenant, 0, 0, cls.pg0.local_ip4, 0, 0, 0)
        cls.vapi.vcdp_session_add(bypass_tenant, 0, 0, cls.pg2.local_ip4, 0, 0, 0)

        # NAT port forwarding
        match = {"addr": cls.pool, "port": 8000, "protocol": 6}
        rewrite = {
            "addr": "10.10.10.10",
            "port": 8080,
        }

        rv = cls.vapi.vcdp_nat_portforwarding_add_del(
            tenant_id=portforwarding_tenant, nat_id=nat_id, match=match, rewrite=rewrite
        )

        # Enable interfaces
        cls.vapi.vcdp_gateway_prefix_enable_disable(
            table_id=0, prefix="64:ff9b::/96", is_enable=True, is_interpose=False, tenant_id=tenant
        )
        cls.vapi.vcdp_gateway_enable_disable(
            sw_if_index=cls.pg1.sw_if_index, is_enable=True, tenant_id=outside_tenant
        )

        # Enable inside interface using interface NAT
        cls.vapi.vcdp_gateway_enable_disable(
            sw_if_index=cls.pg2.sw_if_index, is_enable=True, tenant_id=iftenant
        )

        # cls.vapi.vcdp_gateway_enable_disable(sw_if_index=cls.pg1.sw_if_index, is_enable=True, tenant_id=outside_tenant, output_arc=True)

        # Catching IPv4 traffic on IPv4 output interface
        # cls.vapi.vcdp_gateway_enable_disable(
        #     sw_if_index=cls.pg0.sw_if_index, is_enable=True, tenant_id=v4tenant
        # )

        # # # Catch inside traffic via DPO instead of as an ip4 input feature
        # # # How to follow the 'real' DPO? Store tenant in DPO index.
        # cls.vapi.vcdp_gateway_prefix_enable_disable(
        #     prefix=v4dpo_prefix, is_enable=True, tenant_id=v4tenant_dpo
        # )

        cls.vapi.cli(f"ip route add 10.0.0.0/8 via {cls.pg0.remote_ip4}")
        cls.vapi.cli(f"ip route add ::/0 via {cls.pg0.remote_ip6}")

        # Add ourselves to the All DHCPv6 servers group
        cls.vapi.ip_multicast_group_join(grp_address='FF02::1:2')

        cls.nat_id = nat_id
        cls.tenant = tenant

    @classmethod
    def tearDownClass(cls):
        """Clean up after tests"""
        super(TestVCDP, cls).tearDownClass()
        # if not cls.vpp_dead:
        #     for i in cls.pg_interfaces:
        #         i.unconfig_ip4()
        #         i.admin_down()

    def test_vcdp(self):
        """Run all the tests"""
        tests = Tests(self, self.pg0, self.pg1, self.pool)
        # test_suites = [tests.nat64_tests, tests.nat44_tests, tests.icmp_error_tests, tests.port_forwarding_tests]
        # test_suites = [tests.icmp_error_tests]
        # test_suites = [tests.nat44_tests]
        # test_suites = [tests.port_forwarding_tests]
        # test_suites = [tests.tcp_tests]
        test_suites = [tests.nat64_tests]
        # test_suites = [tests.dhcp6_tests]

        for test_suite in test_suites:
            for t in test_suite:
                print(f"Running: {t.name}")
                tests.send(t)

        print(self.vapi.cli("show vcdp session detail"))
        print(self.vapi.cli("show vcdp session"))
        print(self.vapi.cli("show vcdp tenant"))
        print(
            "NAT statistics",
            self.statistics[f"/vcdp/nats/{self.nat_id}/rx-octets-and-pkts"],
            self.statistics[f"/vcdp/nats/{self.nat_id}/tx-octets-and-pkts"],
        )
        print(
            "Tenant session statistics",
            self.statistics["/vcdp/tenant/created-sessions"],
            self.statistics["/vcdp/tenant/removed-sessions"],
        )
        print(self.vapi.cli("show errors"))
        self.vapi.cli("ip route add 0.0.0.0/0 via pg1")
        print(self.vapi.cli("show ip fib 0.0.0.0/0 detail"))

    def test_vcdp_if_nat(self):
        """Run all the tests with interface NAT"""
        tests = Tests(self, inside=self.pg2, outside=self.pg1, pool=self.pg1.local_ip4)
        test_suites = [tests.nat64_tests, tests.nat44_tests, tests.icmp_error_tests, tests.port_forwarding_tests]
        # test_suites = [tests.icmp_error_tests]
        # test_suites = [tests.nat44_tests]
        # test_suites = [tests.port_forwarding_tests]
        # test_suites = [tests.tcp_tests]
        # test_suites = [tests.nat64_tests]

        for test_suite in test_suites:
            for t in test_suite:
                print(f"Running: {t.name}")
                tests.send(t)

        print(self.vapi.cli("show vcdp session detail"))
        print(self.vapi.cli("show vcdp session"))
        print(self.vapi.cli("show vcdp tenant"))
        print(
            "NAT statistics",
            self.statistics[f"/vcdp/nats/{self.nat_id}/rx-octets-and-pkts"],
            self.statistics[f"/vcdp/nats/{self.nat_id}/tx-octets-and-pkts"],
        )
        print(
            "Tenant session statistics",
            self.statistics["/vcdp/tenant/created-sessions"],
            self.statistics["/vcdp/tenant/removed-sessions"],
        )
        print(self.vapi.cli("show errors"))

    def test_via_interpose_dpo2(self):
        '''Default route'''

        # Try installing in different order.
        # First install covering route, then our DPO
        # Second install our DPO then the covering route
        self.vapi.cli('set logging class fib level debug')
        prefix = '0.0.0.0/0'
        vcdprefix1 = '0.0.0.0/1'
        vcdprefix2 = '128.0.0.0/1'
        print(self.vapi.cli(f"show ip fib {prefix} detail"))

        self.vapi.vcdp_gateway_prefix_enable_disable(
            prefix=vcdprefix1, is_enable=True, is_interpose=True, tenant_id=self.v4tenant_dpo
        )

        self.vapi.vcdp_gateway_prefix_enable_disable(
            prefix=vcdprefix2, is_enable=True, is_interpose=True, tenant_id=self.v4tenant_dpo
        )
        self.vapi.cli(f"ip route add {prefix} via pg1 {self.pg1.remote_ip4}")
        self.vapi.cli(f"ip route del {prefix} via pg1 {self.pg1.remote_ip4}")
        self.vapi.cli(f"ip route add {prefix} via pg1 {self.pg1.remote_ip4}")

        print(self.vapi.cli(f"show ip fib {prefix} detail"))
        # print(self.vapi.cli(f"show ip fib {vcdprefix1} detail"))
        # print(self.vapi.cli(f"show ip fib {prefix} detail"))
        print(self.vapi.cli('show log'))
        # If interpose is enabled, will not install until there is a covering route


        p = (Ether(src=self.pg3.remote_mac, dst=self.pg3.local_mac) /
            IP(src=self.pg3.remote_ip4, dst='13.0.0.1') /
            UDP(sport=1234, dport=80))
        rx = self.send_and_expect(self.pg3, p, self.pg1)
        rx[0].show2()
        rx = self.send_and_expect(self.pg3, p, self.pg1)
        rx[0].show2()

        # What happens if I change the default route????
        self.vapi.cli(f"ip route del {prefix} via pg1 {self.pg1.remote_ip4}")
        p[IP].dst = '13.0.0.4'
        self.send_and_assert_no_replies(self.pg3, p)
        print(self.vapi.cli(f"show ip fib {prefix} detail"))
        # print(self.vapi.cli(f"show ip fib {vcdprefix1} detail"))

        self.vapi.cli(f"ip route add {prefix} via pg2 {self.pg2.remote_ip4}")
        p[IP].dst = '13.0.0.5'
        rx = self.send_and_expect(self.pg3, p, self.pg2)
        rx[0].show2()
        print(self.vapi.cli(f"show ip fib {prefix} detail"))


    def test_via_interpose_dpo(self):
        # Cases:
        # More specific VCDP DPO. VCDP done based on that. Forwarding done on covering DPO.
        # What if destination address is rewritten?
        #

        """Test that we can catch traffic via the interpose DPO"""
        prefix = '0.0.0.0/0'
        msrprefix = '12.0.0.0/24'
        msrprefix2 = '13.0.0.0/24'

        # Catch inside traffic via DPO instead of as an ip4 input feature
        # How to follow the 'real' DPO? Store tenant in DPO index.
        # self.vapi.vcdp_gateway_prefix_enable_disable(
        #     prefix=prefix, is_enable=True, tenant_id=self.v4tenant_dpo
        # )

        # # More specific DPO without exact match
        # self.vapi.vcdp_gateway_prefix_enable_disable(
        #     prefix=msrprefix, is_enable=True, tenant_id=self.v4tenant_dpo
        # )

        # More specific DPO with exact match
        self.vapi.vcdp_gateway_prefix_enable_disable(
            table_id=0, prefix=msrprefix2, is_enable=True, is_interpose=False, tenant_id=self.v4tenant_dpo
        )

        print(self.vapi.cli(f"show ip fib {msrprefix} detail"))
        print(self.vapi.cli(f"show ip fib {msrprefix2} detail"))

        #
        # Send via more specific2
        #
        # self.vapi.cli(f"ip route add {msrprefix2} via pg1 {self.pg1.remote_ip4}")
        msrp2 = (Ether(src=self.pg3.remote_mac, dst=self.pg3.local_mac) /
             IP(src=self.pg3.remote_ip4, dst='13.0.0.1') /
             UDP(sport=1234, dport=80))
        rx = self.send_and_expect(self.pg3, msrp2, self.pg1)
        rx[0].show2()

        # Remove route, should be forwarded via covering route
        print(f'Forwarding via covering route {msrprefix2}')
        # self.vapi.cli(f"ip route del {msrprefix2} via pg1 {self.pg1.remote_ip4}")
        print(self.vapi.cli(f"show ip fib {msrprefix2} detail"))
        rx = self.send_and_expect(self.pg3, msrp2, self.pg1)
        rx[0].show2()

        return

        # Default route via pg1
        self.vapi.cli(f"ip route add {prefix} via pg1 {self.pg1.remote_ip4}")
        p = (Ether(src=self.pg3.remote_mac, dst=self.pg3.local_mac) /
             IP(src=self.pg3.remote_ip4, dst='12.8.8.8') /
             UDP(sport=1234, dport=80))
        rx = self.send_and_expect(self.pg3, p, self.pg1)
        rx[0].show2()

        # Send via more specific
        msrp = (Ether(src=self.pg3.remote_mac, dst=self.pg3.local_mac) /
             IP(src=self.pg3.remote_ip4, dst='12.0.0.1') /
             UDP(sport=1234, dport=80))
        # rx = self.send_and_expect(self.pg3, msrp, self.pg1)
        # rx[0].show2()

        # Change nexthop to pg2
        self.vapi.cli(f"ip route del {prefix} via pg1 {self.pg1.remote_ip4}")
        self.vapi.cli(f"ip route add {prefix} via pg2 {self.pg2.remote_ip4}")
        rx = self.send_and_expect(self.pg3, p, self.pg2)
        rx[0].show2()

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
            validate(self, p[1], modified[1])

        print('VALIDATE TCP CHECKSUM in REPLY packet')
        # print(self.vapi.cli("show vcdp session"))
        print(self.vapi.cli("show vcdp summary"))

        print('Awaiting to see if anything expires:')
        import time
        time.sleep(10)


###
### DHCP tests
### Send broadcast and unicast messages to a punt service.
### Register port 67 UDP and catch that in tests?
### Add static sessions and do 3-tuple lookups
###
