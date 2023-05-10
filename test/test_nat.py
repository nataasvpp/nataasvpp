#!/usr/bin/env python3

import time
import pytest
from scapy.all import sendp, sniff
from scapy.layers.inet import IP, UDP, TCP, ICMP, GRE, IPerror
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.all import AsyncSniffer, sendp
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from pydantic import BaseModel
from typing import Callable, Union
from vpp_papi import VPPApiClient, VPPApiJSONFiles
from ipaddress import IPv4Address
import psutil
import socket
import os
import subprocess
import time

def is_ethernet_interface(iface):
    try:
        # Get the interface details
        iface_details = psutil.net_if_addrs().get(iface, [])

        # Check if the interface has AF_PACKET address family
        for addr in iface_details:
            if addr.family == socket.AF_PACKET:
                return True

        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

@pytest.fixture(scope='session')
def linux_cmdopt(request):
    return request.config.getoption("--linux")
@pytest.fixture(scope='session')
def startup_cmdopt(request):
    return request.config.getoption("--config")
@pytest.fixture(scope='session')
def vpp_cmdopt(request):
    return request.config.getoption("--vpp")

@pytest.fixture(scope='module')
def start_vpp(vpp_cmdopt, linux_cmdopt, startup_cmdopt):
    # Start VPP if asked to
    if not vpp_cmdopt:
        yield None
        return
    vpp_process = subprocess.Popen([vpp_cmdopt, '-c', startup_cmdopt])
    # Optionally, wait for VPP to start up
    # You can adjust the sleep time depending on your system
    time.sleep(5)
    if linux_cmdopt:
        rc = subprocess.call(linux_cmdopt, shell=True)
    yield vpp_process

    # Terminate VPP
    vpp_process.terminate()
    vpp_process.wait()

@pytest.fixture(scope='module')
def vpp_connection(start_vpp):
    apifiles = VPPApiJSONFiles.find_api_files('./_build/debug/plugins')
    apifiles += VPPApiJSONFiles.find_api_files('../vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/')
    vpp = VPPApiClient(apifiles=apifiles)
    vpp.connect(name='test_nat')
    vpp_clear_session(vpp)
    vpp_tcp_mss_clamp(vpp, 0, 1234)
    yield vpp

    # Disconnect from VPP
    vpp.disconnect()


# Define the IP addresses and ports of the devices involved
src_ip = IPv4Address('192.168.1.2')  # IP address of the internal device
dst_ip = '8.8.8.8'      # IP address of the external device
nat_ip = '192.168.100.1'  # IP address of the NAT device

src_port = 12345        # Port number of the internal device
dst_port = 80           # Port number of the external device

inside_iface = 'tun0'
outside_iface = 'tun1'


def send_and_receive(packet, src_iface, dst_iface, send_count=1):
    """Send a packet on src_iface and receive the corresponding packet on dst_iface."""
    count = 1
    if is_ethernet_interface(src_iface):
        packet = Ether()/packet
    s = lambda: sendp(packet, iface=src_iface, verbose=False, count=send_count)
    assert dst_iface

    if dst_iface == src_iface:
        count = 2
    received = sniff(iface=dst_iface, started_callback=s, count=count, timeout=2)
    assert received

    if count == 2:
        return received[1]
    return received

def send_and_verify_drop(packet, src_iface, dst_iface, send_count=1):
    """Send a packet on src_iface and receive the corresponding packet on dst_iface."""
    s = lambda: sendp(packet, iface=src_iface, verbose=False, count=send_count)
    received = sniff(iface=dst_iface, started_callback=s, count=send_count, timeout=1)
    assert len(received) == 0
    return

def respond_tcp_syn(packet):
    """Respond to a TCP SYN packet with a SYN ACK."""
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':
        return IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='SA')
    return None

def respond_data(packet):
    """Respond to a TCP SYN packet with a SYN ACK."""
    if packet.haslayer(TCP):
        return IP(src=packet[IP].dst, dst=packet[IP].src) / TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags='A')
    if packet.haslayer(UDP):
        return IP(src=packet[IP].dst, dst=packet[IP].src) / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
    if packet.haslayer(ICMP):
        return IP(src=packet[IP].dst, dst=packet[IP].src) / ICMP(type=0, id=packet[ICMP].id)
    
    pkt = packet.copy()
    pkt[IP].src, pkt[IP].dst = pkt[IP].dst, pkt[IP].src
    return pkt
    
def validate_vpp_session_state(vpp, packet, expected_state):
    """Validate the VPP state against the expected state."""
    if packet.haslayer(TCP):
        session = vpp.api.vcdp_session_lookup(tenant_id=0,
                                    src=packet[IP].src, dst=packet[IP].dst,
                                    protocol=packet[IP].proto,
                                    sport=packet[TCP].sport, dport=packet[TCP].dport)
        if expected_state == 1:
            assert session.remaining_time > 7400 and session.remaining_time < 7500

    elif packet.haslayer(UDP):
        session = vpp.api.vcdp_session_lookup(tenant_id=0,
                                    src=packet[IP].src, dst=packet[IP].dst,
                                    protocol=packet[IP].proto,
                                    sport=packet[UDP].sport, dport=packet[UDP].dport)
        if expected_state == 1:
            assert session.remaining_time > 230 and session.remaining_time < 250

    elif packet.haslayer(ICMP):
        session = vpp.api.vcdp_session_lookup(tenant_id=0,
                                    src=packet[IP].src, dst=packet[IP].dst,
                                    protocol=packet[IP].proto,
                                    sport=packet[ICMP].id, dport=packet[ICMP].id)
    else:
        session = vpp.api.vcdp_session_lookup(tenant_id=0,
                                    src=packet[IP].src, dst=packet[IP].dst,
                                    protocol=packet[IP].proto,
                                    sport=0, dport=0)

    assert session.state == expected_state

    if expected_state == 0 or expected_state == 2:
        assert session.remaining_time > 0 and session.remaining_time < 5

    # print('SESSION', session)

def vpp_clear_session(vpp):
    """Clear all VPP sessions."""
    vpp.api.vcdp_session_clear()

def vpp_tcp_mss_clamp(vpp, tenant, mss):
    '''Missing CLI for this one'''
    vpp.api.vcdp_tcp_mss_enable_disable(tenant_id=tenant, ip4_mss=[mss, 0xFFFF], is_enable=True)


class NATTest(BaseModel):
    '''A test case for the NAT.'''
    name: str
    send: Packet
    expect: Packet = None
    respond: Callable = None
    validate_vpp: Callable = None
    send_iface: str = inside_iface
    receive_iface: Union[str,None] = outside_iface
    expected_to_fail: str = None

    class Config:
        arbitrary_types_allowed = True

class NATTestCases(BaseModel):
    '''A list of test cases for the NAT.'''
    tests: list[NATTest]

test_cases = [
    # test0: Normal three-way TCP handshake
    {
        'name': 'TCP syn',
        'send': IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S'),
        'expect': IP(src=nat_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S'),
        'respond': respond_tcp_syn,
        'validate_vpp': lambda vpp, packet, expected_state=0: validate_vpp_session_state(vpp, packet, expected_state)

    },
    # test1: SYN ACK
    {
        'name': 'TCP syn_ack',
        'send': IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A'),
        'expect': IP(src=nat_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A'),
        'validate_vpp': lambda vpp, packet, expected_state=1: validate_vpp_session_state(vpp, packet, expected_state)
    },
    # test2: Data phase
    {
        'name': 'tcp_data',
        'send': IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A') / "Test NAT TCP data",
        'expect': IP(src=nat_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A') / "Test NAT TCP data",
        'validate_vpp': lambda vpp, packet, expected_state=1: validate_vpp_session_state(vpp, packet, expected_state)
    },
    # test3: Close
    {
        'name': 'tcp_fin',
        'send': IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='FA'),
        'expect': IP(src=nat_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='FA'),
        'validate_vpp': lambda vpp, packet, expected_state=2: validate_vpp_session_state(vpp, packet, expected_state)
    },

    # test4: Create a session mid-way. Testing TCP lite state machine.
    {
        'name': 'session created from tcp_data',
        'send': IP(src=src_ip+1, dst=dst_ip) / TCP(sport=src_port+1, dport=dst_port, flags='A') / "Test NAT TCP data",
        'expect': IP(src=nat_ip, dst=dst_ip) / TCP(sport=src_port+1, dport=dst_port, flags='A') / "Test NAT TCP data",
        'respond': respond_data,
        'validate_vpp': lambda vpp, packet, expected_state=1: validate_vpp_session_state(vpp, packet, expected_state)
    },

    # test5: Reset session
    {
        'name': 'tcp_rst',
        'send':  IP(src=src_ip+1, dst=dst_ip) / TCP(sport=src_port+1, dport=dst_port, flags='R'),
        'expect': IP(src=nat_ip, dst=dst_ip) / TCP(sport=src_port+1, dport=dst_port, flags='R'),
        'validate_vpp': lambda vpp, packet, expected_state=2: validate_vpp_session_state(vpp, packet, expected_state)
    },

    # test6: Create a UDP session.
    {
        'name': 'session created from udp_data',
        'send': IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / "Test NAT UDP data",
        'expect': IP(src=nat_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / "Test NAT UDP data",
        'validate_vpp': lambda vpp, packet, expected_state=0: validate_vpp_session_state(vpp, packet, expected_state)
    },

    # test7: Create a UDP session.
    {
        'name': 'session created from udp_data',
        'send': IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / "Test NAT UDP data",
        'expect': IP(src=nat_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / "Test NAT UDP data",
        'respond': respond_data,
        'validate_vpp': lambda vpp, packet, expected_state=1: validate_vpp_session_state(vpp, packet, expected_state)
    },

    # test8: Other IP protocol session
    {
        'name': 'session created from gre tunnel data',
        'send': IP(src=src_ip, dst=dst_ip) / GRE() / "Test NAT GRE data",
        'expect': IP(src=nat_ip, dst=dst_ip) / GRE() / "Test NAT GRE data",
        'respond': respond_data,
        'validate_vpp': lambda vpp, packet, expected_state=1: validate_vpp_session_state(vpp, packet, expected_state)
    },

    # test9: ICMP information request
    {
        'name': 'session created from icmp',
        'send': IP(src=src_ip, dst=dst_ip) / ICMP() / "Test NAT ICMP data",
        'expect': IP(src=nat_ip, dst=dst_ip) / ICMP() / "Test NAT ICMP data",
        'respond': respond_data,
        'validate_vpp': lambda vpp, packet, expected_state=1: validate_vpp_session_state(vpp, packet, expected_state)
    },

    # test10: Random ICMP error not against a session from inside
    {
        'name': 'icmp_error',
        'send': IP(src=src_ip, dst=dst_ip) / ICMP(type=3, code=1) / IP()/UDP() / "Test NAT ICMP error",
    },

    # test11: Random ICMP error not against a session from outside
    {
        'name': 'icmp_error',
        'send': IP(src=src_ip, dst=dst_ip) / ICMP(type=3, code=1) / IP()/UDP() / "Test NAT ICMP error",
        'send_iface': outside_iface,
        'receive_iface': inside_iface,
    },

    # test12: ICMP error against an existing session (from outside)
    # in2out data packet
    {
        'name': 'icmp_error against established session. Depends on previous test. Outside',
        'send': IP(src='1.1.1.1', dst=nat_ip) / ICMP(type=3, code=1) / IP(src=nat_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / "Test NAT UDP data",
        'expect': IP(src='1.1.1.1', dst=src_ip) / ICMP(type=3, code=1) / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / "Test NAT UDP data",
        'send_iface': outside_iface,
        'receive_iface': inside_iface,
    },

    # test13: ICMP error against an existing session (from inside)
    # out2in data packet
    {
        'name': 'icmp_error against established session. Depends on previous test. Inside',
        'send': IP(src=src_ip, dst=dst_ip) / ICMP(type=3, code=1) / IP(src=dst_ip, dst=src_ip) / UDP(sport=dst_port, dport=src_port) / "Test NAT UDP data",
        'expect': IP(src=nat_ip, dst=dst_ip) / ICMP(type=3, code=1) / IP(src=dst_ip, dst=nat_ip) / UDP(sport=dst_port, dport=src_port) / "Test NAT UDP data",
    },

    # test14: ICMP error generated by VCDP (triggered by inside)
    # Note the little hack that inner packet has TTL=1, we haven't decremented it yet.
    {
        'name': 'UDP with TTL=1, check ICMP error',
        'send': IP(src=src_ip, dst=dst_ip, ttl=1) / UDP(sport=src_port, dport=dst_port) / "Test NAT UDP data",
        'expect': IP(src='0.0.0.0', dst=src_ip, ttl=255, id=0) / ICMP(type='time-exceeded', code='ttl-zero-during-transit') / IP(src=src_ip, dst=dst_ip, ttl=1) / UDP(sport=src_port, dport=dst_port) / "Test NAT UDP data",
        # 'validate_vpp': lambda vpp, packet, expected_state=0: validate_vpp_session_state(vpp, packet, expected_state)
        'receive_iface': inside_iface,
    },

    # test15: ICMP error generated by VCDP (triggered by outside packet)
    {
        'name': 'UDP with TTL=1, check ICMP error',
        'send': IP(src=dst_ip, dst=nat_ip, ttl=1) / UDP(sport=dst_port, dport=src_port) / "Test NAT ICMP UDP data",
        'expect': IP(src=nat_ip, dst=dst_ip, id=0) / ICMP(type='time-exceeded', code='ttl-zero-during-transit') / IP(src=dst_ip, dst=nat_ip, ttl=0) / UDP(sport=dst_port, dport=src_port) / "Test NAT ICMP UDP data",
        'send_iface': outside_iface,
        'receive_iface': outside_iface,
    },

    # test16 ICMP error triggered by GRE packet (triggered by inside)
    # Run together with test8
    {
        'name': 'GRE TTL=1, check ICMP error',
        'send': IP(src=src_ip, dst=dst_ip, ttl=1) / GRE() / "Test NAT GRE data",
        'expect': IP(src='0.0.0.0', dst=src_ip, id=0) / ICMP(type='time-exceeded', code='ttl-zero-during-transit') / IP(src=src_ip, dst=dst_ip, ttl=0) / GRE() / "Test NAT GRE data",
        'receive_iface': inside_iface,
    },

    # test17 ICMP error triggered by GRE packet (triggered by outside)
    # Run together with test8
    {
        'name': 'GRE TTL=1, check ICMP error',
        'send': IP(src=dst_ip, dst=nat_ip, ttl=1) / GRE() / "Test NAT GRE data",
        'expect': IP(src=nat_ip, dst=dst_ip, id=0) / ICMP(type='time-exceeded', code='ttl-zero-during-transit') / IP(src=dst_ip, dst=nat_ip, ttl=0) / GRE() / "Test NAT GRE data",
        'send_iface': outside_iface,
        'receive_iface': outside_iface,
    },

    # test18 Test bypass feature
    {
        # Random outside packet to test bypass.
        'name': 'Basic outside bypass',
        'send': IP(src='9.9.9.9', dst=nat_ip, ttl=64)/ICMP(id=8888),
        'expect': IP(src=nat_ip, dst='9.9.9.9')/ICMP(type='echo-reply', id=8888),
        'send_iface': outside_iface,
        'receive_iface': outside_iface,
    },

    # test19 Test static mapping with bypass
    # DHCP only works for Ethernet interfaces?
    {
        'name': 'DHCP packet against static binding',
        'send': IP(src='0.0.0.0', dst='255.255.255.255')/UDP(sport=68, dport=67),
        'expect': IP(src=nat_ip, dst='9.9.9.9')/ICMP(type='echo-reply', id=8888),
        'send_iface': outside_iface,
        'receive_iface': outside_iface,
        'expected_to_fail': True,
    },

    # test20 TCP MSS clamping
    {
        'name': 'Check TCP MSS clamp',
        'send': IP(src='210.10.10.10', dst=dst_ip)/TCP(sport=888, flags="S", options=[("MSS", 9000), ("EOL", None)]),
        'expect': IP(src=nat_ip, dst=dst_ip)/TCP(sport=888, flags="S", options=[("MSS", 1234), ("EOL", None)]),
    },

    # test 21 Truncated packet
    {
        'name': 'Truncated packet',
        'send': IP(src='210.10.10.10', dst=dst_ip, proto=17),
        'expect': None,
    },

    # Fragments
    # Too small packets

    # Chained packets
    # Hairpinning
]

def validate_packet(received, expected):
    if received.firstlayer().haslayer('Ether'):
        received = received[0].payload

    # Ignore TTL and ID
    expected[IP].ttl = received[IP].ttl
    expected[IP].id = received[IP].id

    if expected[IP].src == '0.0.0.0':
        expected[IP].src = received[IP].src

    if received.haslayer('IPerror'):
        expected[IP][ICMP][IP].ttl = received[IP][ICMP][IPerror].ttl

    expected = expected.__class__(bytes(expected))
    if received != expected:
        print('Received packet does not match expected packet.')
        print('Expected:')
        expected.show2()
        print('Received:')
        received.show2()
    return received == expected

test_cases = NATTestCases(tests=test_cases)
@pytest.mark.parametrize("test", test_cases.tests)
def test_run_testcase(test, vpp_connection):
    # print(f'SENDING on interface {test.send_iface} ')
    # test.send.show2()
    if test.expected_to_fail:
        pytest.xfail(f"{test.expected_to_fail}")
    if test.expect:
        received_packets = send_and_receive(test.send, test.send_iface, test.receive_iface)
        # test.send.show2()
        for expected_packet, received_packet in zip(test.expect, received_packets):
            assert validate_packet(received_packet[0], expected_packet[0])
            if test.respond:
                response = test.respond(received_packet[0])
                if response:
                    # Send from the receive interface
                    send_and_receive(response, test.receive_iface, test.send_iface)
        if test.validate_vpp:
            test.validate_vpp(vpp_connection, test.send)
    else:
        send_and_verify_drop(test.send, test.send_iface, test.receive_iface)
