# SPDX-License-Identifier: Apache-2.0
#

from unittest import TestCase
from unittest.mock import Mock

# Completely mock the vpp_papi module, as we do not actually needed it for
# these unit tests and it is not readily available in a developer environment
# (such as my macbook) for testing against anyway.

import sys

sys.modules["vpp_papi"] = Mock()
sys.modules["vpp_papi.vpp_stats"] = Mock()

from vppconf import caller, parser
from vppconf.exceptions import VppConfigParsingError

##############################################################################


class TestVppConfigParser(TestCase):
    def setUp(self):
        interfaces = {"tap0": 1, "tap1": 2}
        fake_vppclient = object()
        self.caller = caller.VppNoopCaller(interfaces, vppclient=fake_vppclient)
        self.parser = parser.VppConfigParser(self.caller)

    def test_add_interface_1(self):
        running = {"interfaces": {}}
        desired = {"interfaces": {"tap0": {"tenant": 1000}}}
        self.parser.parse(desired, running)
        self.assertEqual(len(self.caller.calls), 1)

    def test_add_interface_2(self):
        # Tunnel and tenant on different interfaces
        running = {"interfaces": {}}
        desired = {
            "interfaces": {
                "tap0": {"tenant": 1000},
                "tap1": {"tunnel-headend": True},
            }
        }
        self.parser.parse(desired, running)
        self.assertEqual(len(self.caller.calls), 2)

    def test_add_interface_3(self):
        # Both tunnel and tenant on same interface
        running = {"interfaces": {}}
        desired = {"interfaces": {"tap0": {"tenant": 1000, "tunnel-headend": True}}}
        self.parser.parse(desired, running)
        self.assertEqual(len(self.caller.calls), 2)

    def test_add_nats(self):
        # add two nats
        running = {"nats": {}}
        desired = {
            "nats": {
                1: {"pool-address": ["1.1.1.1", "2.2.2.2"]},
                2: {"pool-address": ["1.1.1.1", "2.2.2.2"]},
            },
        }
        self.parser.parse(desired, running)
        self.assertEqual(len(self.caller.calls), 2)

    def test_append_nat(self):
        # one nat already exists, so only one is being added
        running = {
            "nats": {2: {"pool-address": ["1.1.1.1", "2.2.2.2"]}},
        }
        desired = {
            "nats": {
                1: {"pool-address": ["1.1.1.1", "2.2.2.2"]},
                2: {"pool-address": ["1.1.1.1", "2.2.2.2"]},
            },
        }
        self.parser.parse(desired, running)
        self.assertEqual(len(self.caller.calls), 1)

    def test_add_tenant(self):
        running = {"tenants": {}}
        desired = {
            "tenants": {
                "0": {
                    "tcp-mss": [123, 456],
                    "context": 0,
                    "flags": "no-create",
                    "forward-services": [
                        "vcdp-l4-lifecycle",
                        "vcdp-tcp-mss",
                        "vcdp-nat-output",
                    ],
                    "reverse-services": ["vcdp-l4-lifecycle", "vcdp-tunnel-output"],
                    "nat-instance": "6529f996-2854-4d78-8337-059053a2c61f",
                }
            }
        }

        self.parser.parse(desired, running)
        self.assertEqual(len(self.caller.calls), 5)

    def test_remove_interface(self):
        running = {
            "interfaces": {"tap0": {"tenant": 1000}, "tap1": {"tunnel-header": True}}
        }
        desired = {"interfaces": {}}
        self.parser.parse(desired, running)
        self.assertEqual(len(self.caller.calls), 1)

    def test_remove_nat(self):
        running = {
            "nats": {
                1: {"pool-addresses": ["1.1.1.1", "2.2.2.2"]},
                2: {"pool-addresses": ["1.1.1.1", "2.2.2.2"]},
            },
        }
        desired = {
            "nats": {2: {"pool-addresses": ["1.1.1.1", "2.2.2.2"]}},
        }

        self.parser.parse(desired, running)
        self.assertEqual(len(self.caller.calls), 1)

    def test_remove_tenant(self):
        running = {
            "tenants": {
                "0": {
                    "tcp-mss": [123, 456],
                    "context": 0,
                    "flags": "no-create",
                    "forward-services": [
                        "vcdp-l4-lifecycle",
                        "vcdp-tcp-mss",
                        "vcdp-nat-output",
                    ],
                    "reverse-services": ["vcdp-l4-lifecycle", "vcdp-tunnel-output"],
                    "nat-instance": "6529f996-2854-4d78-8337-059053a2c61f",
                }
            }
        }
        desired = {"tenants": {}}
        self.parser.parse(desired, running)
        self.assertEqual(len(self.caller.calls), 3)

    def test_modify(self):
        running = {"interfaces": {"tap0": {"tenant": 1000}}}
        desired = {"interfaces": {"tap0": {"tenant": 1001}}}
        with self.assertRaises(VppConfigParsingError):
            self.parser.parse(desired, running)

    def test_ignore_bootime_interface_list(self):
        running = {"interfaces": {}}
        desired = {
            "interfaces": {"tap0": {"tenant": 1000}},
            "interface_list": {},
            "boottime": 0,
        }
        self.parser.parse(desired, running)
        self.assertEqual(len(self.caller.calls), 1)

    def test_exception_on_unknown_fields(self):
        running = {"interfaces": {}}
        desired = {"interfaces": {"tap0": {"tenant": 1000}}, "unknown_field": {}}
        with self.assertRaises(VppConfigParsingError):
            self.parser.parse(desired, running)


##############################################################################


class TestVppCalls(TestCase):
    def setUp(self):
        interfaces = {"tap0": 1}
        fake_vppclient = object()
        self.caller = caller.VppNoopCaller(interfaces, vppclient=fake_vppclient)

    def test_vcdpinterface_headend(self):
        c = parser.VcdpInterface(self.caller)
        c.call("tap0", {"tunnel-headend": True}, 1)
        self.assertEqual(len(self.caller.calls), 1)
        call_name, call_params = self.caller.calls[0]
        self.assertEqual(call_name, "vcdp_gateway_tunnel_enable_disable")
        self.assertEqual(call_params, {"sw_if_index": 1, "is_enable": 1})

    def test_vcdpinterface_tenant(self):
        c = parser.VcdpInterface(self.caller)
        c.call("tap0", {"tenant": "xxx"}, 1)
        self.assertEqual(len(self.caller.calls), 1)
        call_name, call_params = self.caller.calls[0]
        self.assertEqual(call_name, "vcdp_gateway_enable_disable")
        self.assertEqual(
            call_params, {"tenant_id": "xxx", "sw_if_index": 1, "is_enable": 1}
        )

    def test_vcdptunnel_add(self):
        tunnel_params = {
            "tenant": "xxx",
            "method": "vxlan-dummy-l2",
            "src": "10.5.20.12",
            "dst": "169.254.29.254",
            "dport": 4789,
            "src-mac": "de:ad:be:ef:00",
            "dst-mac": "de:ad:be:ef:01",
        }
        c = parser.VcdpTunnel(self.caller)
        c.call("tunnel_id_1", tunnel_params, 1)
        self.assertEqual(len(self.caller.calls), 1)
        call_name, call_params = self.caller.calls[0]
        self.assertEqual(call_name, "vcdp_tunnel_add")
        self.assertEqual(call_params["tenant_id"], tunnel_params["tenant"])
        self.assertEqual(call_params["method"], 0)
        self.assertEqual(call_params["src"], tunnel_params["src"])
        self.assertEqual(call_params["dst"], tunnel_params["dst"])
        self.assertEqual(call_params["dport"], tunnel_params["dport"])
        self.assertEqual(call_params["src_mac"], tunnel_params["src-mac"])
        self.assertEqual(call_params["dst_mac"], tunnel_params["dst-mac"])

    def test_vcdptunnel_add_geneve(self):
        tunnel_params = {
            "tenant": "xxx",
            "method": "not-vxlan",
            "src": "10.5.20.12",
            "dst": "169.254.29.254",
            "dport": 4789,
            "src-mac": "de:ad:be:ef:00",
            "dst-mac": "de:ad:be:ef:01",
        }
        c = parser.VcdpTunnel(self.caller)
        c.call("tunnel_id_1", tunnel_params, 1)
        self.assertEqual(len(self.caller.calls), 1)
        call_name, call_params = self.caller.calls[0]
        self.assertEqual(call_name, "vcdp_tunnel_add")
        self.assertEqual(call_params["method"], 1)

    def test_vcdptunnel_remove(self):
        c = parser.VcdpTunnel(self.caller)
        c.call("tunnel_id_1", {}, 0)
        self.assertEqual(len(self.caller.calls), 1)
        call_name, call_params = self.caller.calls[0]
        self.assertEqual(call_name, "vcdp_tunnel_remove")
        self.assertEqual(call_params, {"tunnel_id": "tunnel_id_1"})

    def test_vcdpnat_add(self):
        c = parser.VcdpNat(self.caller)
        c.call("nat_1", {"pool-address": ["1.1.1.1"]}, 1)
        self.assertEqual(len(self.caller.calls), 1)
        call_name, call_params = self.caller.calls[0]
        self.assertEqual(call_name, "vcdp_nat_add")
        self.assertEqual(
            call_params, {"nat_id": "nat_1", "addr": ["1.1.1.1"], "n_addr": 1}
        )

    def test_vcdpnat_remove(self):
        c = parser.VcdpNat(self.caller)
        c.call("nat_1", {}, 0)
        self.assertEqual(len(self.caller.calls), 1)
        call_name, call_params = self.caller.calls[0]
        self.assertEqual(call_name, "vcdp_nat_remove")
        self.assertEqual(call_params, {"nat_id": "nat_1"})

    def test_vcdptenant_add(self):
        tenant_params = {
            "context": 0,
            "forward-services": [
                "vcdp-l4-lifecycle",
            ],
            "reverse-services": [
                "vcdp-l4-lifecycle",
            ],
            "nat-instance": "xxx",
            "tcp-mss": [
                1310,
                1310,
            ],
        }
        c = parser.VcdpTenant(self.caller)
        c.call(12345, tenant_params, 1)
        self.assertEqual(len(self.caller.calls), 5)

        # vcdp_tenant_add_del must be the first call
        call_name, call_params = self.caller.calls[0]
        self.assertEqual(call_name, "vcdp_tenant_add_del")
        self.assertEqual(
            call_params, {"context_id": 0, "tenant_id": 12345, "is_add": 1}
        )

        # all of the other calls needed for a tenant were also made?
        call_names = [name for name, params in self.caller.calls]
        self.assertIn("vcdp_set_services", call_names)
        self.assertIn("vcdp_nat_bind_set_unset", call_names)
        self.assertIn("vcdp_tcp_mss_enable_disable", call_names)

    def test_vcdptenant_remove(self):
        tenant_params = {
            "context": 0,
            "forward-services": [
                "vcdp-l4-lifecycle",
            ],
            "reverse-services": [
                "vcdp-l4-lifecycle",
            ],
            "nat-instance": "xxx",
            "tcp-mss": [
                1310,
                1310,
            ],
        }
        c = parser.VcdpTenant(self.caller)
        c.call(12345, tenant_params, 0)
        self.assertEqual(len(self.caller.calls), 3)

        # vcdp_tenant_add_del must be the last call
        call_name, call_params = self.caller.calls[-1]
        self.assertEqual(call_name, "vcdp_tenant_add_del")
        self.assertEqual(
            call_params, {"context_id": 0, "tenant_id": 12345, "is_add": 0}
        )

        # all of the other calls needed for a tenant were also made?
        call_names = [name for name, params in self.caller.calls]
        self.assertIn("vcdp_nat_bind_set_unset", call_names)
        self.assertIn("vcdp_tcp_mss_enable_disable", call_names)

        # vcdp_set_services was NOT called
        self.assertNotIn("vcdp_set_services", call_names)


##############################################################################
# THE END
