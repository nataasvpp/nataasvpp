# SPDX-License-Identifier: Apache-2.0
#

from unittest import TestCase
from unittest.mock import MagicMock

# Completely mock the vpp_papi module, as we do not actually needed it for
# these unit tests and it is not readily available in a developer environment
# (such as my macbook) for testing against anyway.

import sys

sys.modules["vpp_papi"] = MagicMock()
sys.modules["vpp_papi.vpp_stats"] = MagicMock()

from vppconf import caller, parser
from vppconf.exceptions import VppCallerError

##############################################################################


def make_vppclient(return_value):
    def get_function(name):
        def apicall(**kwargs):
            class apicall_result(object):
                pass

            result = apicall_result()
            result.retval = return_value
            return result

        return apicall

    vppclient = MagicMock()
    vppclient.get_function = get_function
    return vppclient


def make_async_vppclient(return_value):
    callback = None

    def register_event_callback(func):
        nonlocal callback
        callback = func

    def get_function(name):
        def apicall(**kwargs):
            class apicall_result(object):
                pass

            result = apicall_result()
            result.retval = return_value
            callback(None, result)

        return apicall

    vppclient = MagicMock()
    vppclient.register_event_callback = register_event_callback
    vppclient.get_function = get_function
    return vppclient


##############################################################################


class TestVppCaller(TestCase):
    def test_successful_caller(self):
        interfaces = {"tap0": 1}
        vppclient = make_vppclient(0)
        c = caller.VppCaller(interfaces, vppclient=vppclient)
        c.call(
            "vcdp_gateway_enable_disable",
            {"tenant_id": "xxx", "sw_if_index": "tap0", "is_enable": 1},
        )
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 1, "replies_received": 1, "replies_failed": 0},
        )

    def test_failing_caller(self):
        interfaces = {"tap0": 1}
        vppclient = make_vppclient(1)
        c = caller.VppCaller(interfaces, vppclient=vppclient)
        with self.assertRaises(VppCallerError):
            c.call(
                "vcdp_gateway_enable_disable",
                {"tenant_id": "xxx", "sw_if_index": "tap0", "is_enable": 1},
            )
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 1, "replies_received": 1, "replies_failed": 1},
        )

    def test_caller_with_missing_interface(self):
        interfaces = {"tap0": 1}
        vppclient = make_vppclient(0)
        c = caller.VppCaller(interfaces, vppclient=vppclient)
        with self.assertRaises(VppCallerError):
            c.call(
                "vcdp_gateway_enable_disable",
                {"tenant_id": "xxx", "sw_if_index": "tap1", "is_enable": 1},
            )
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 0, "replies_received": 0, "replies_failed": 0},
        )


class TestVppBatchCaller(TestCase):
    def test_successful_caller(self):
        interfaces = {"tap0": 1}
        vppclient = make_vppclient(0)
        c = caller.VppBatchCaller(interfaces, vppclient=vppclient)
        c.call(
            "vcdp_gateway_enable_disable",
            {"tenant_id": "xxx", "sw_if_index": "tap0", "is_enable": 1},
        )
        c.call(
            "vcdp_gateway_tunnel_enable_disable",
            {"sw_if_index": "tap0", "is_enable": 1},
        )
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 0, "replies_received": 0, "replies_failed": 0},
        )

        c.call_batch()
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 2, "replies_received": 2, "replies_failed": 0},
        )

    def test_failing_caller(self):
        interfaces = {"tap0": 1}
        vppclient = make_vppclient(1)
        c = caller.VppBatchCaller(interfaces, vppclient=vppclient)
        c.call(
            "vcdp_gateway_enable_disable",
            {"tenant_id": "xxx", "sw_if_index": "tap0", "is_enable": 1},
        )
        c.call(
            "vcdp_gateway_tunnel_enable_disable",
            {"sw_if_index": "tap0", "is_enable": 1},
        )
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 0, "replies_received": 0, "replies_failed": 0},
        )

        with self.assertRaises(VppCallerError):
            c.call_batch()
        # batch call aborts with an error and does not complete the remainder
        # of the calls. Two calls batched here, but only one actually made
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 1, "replies_received": 1, "replies_failed": 1},
        )

    def test_caller_with_missing_interface(self):
        # this will raise the exception on the call() method, not call_batch()
        interfaces = {"tap0": 1}
        vppclient = make_vppclient(0)
        c = caller.VppBatchCaller(interfaces, vppclient=vppclient)
        with self.assertRaises(VppCallerError):
            c.call(
                "vcdp_gateway_enable_disable",
                {"tenant_id": "xxx", "sw_if_index": "tap1", "is_enable": 1},
            )
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 0, "replies_received": 0, "replies_failed": 0},
        )


class TestVppAsyncBatchCaller(TestCase):
    def test_successful_caller(self):
        interfaces = {"tap0": 1}
        vppclient = make_async_vppclient(0)
        c = caller.VppAsyncBatchCaller(interfaces, vppclient=vppclient)
        c.call(
            "vcdp_gateway_enable_disable",
            {"tenant_id": "xxx", "sw_if_index": "tap0", "is_enable": 1},
        )
        c.call(
            "vcdp_gateway_tunnel_enable_disable",
            {"sw_if_index": "tap0", "is_enable": 1},
        )
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 0, "replies_received": 0, "replies_failed": 0},
        )

        c.call_batch()
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 2, "replies_received": 2, "replies_failed": 0},
        )

    def test_failing_caller(self):
        interfaces = {"tap0": 1}
        vppclient = make_async_vppclient(1)
        c = caller.VppAsyncBatchCaller(interfaces, vppclient=vppclient)
        c.call(
            "vcdp_gateway_enable_disable",
            {"tenant_id": "xxx", "sw_if_index": "tap0", "is_enable": 1},
        )
        c.call(
            "vcdp_gateway_tunnel_enable_disable",
            {"sw_if_index": "tap0", "is_enable": 1},
        )
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 0, "replies_received": 0, "replies_failed": 0},
        )

        with self.assertRaises(VppCallerError):
            c.call_batch()
        # unlike the normal batch caller, all calls should have been made
        # here, regardless of whether they errored or not.
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 2, "replies_received": 2, "replies_failed": 2},
        )

    def test_caller_with_missing_interface(self):
        # this will raise the exception on the call() method, not call_batch()
        interfaces = {"tap0": 1}
        vppclient = make_async_vppclient(0)
        c = caller.VppAsyncBatchCaller(interfaces, vppclient=vppclient)
        with self.assertRaises(VppCallerError):
            c.call(
                "vcdp_gateway_enable_disable",
                {"tenant_id": "xxx", "sw_if_index": "tap1", "is_enable": 1},
            )
        self.assertEqual(
            c.call_summary(),
            {"calls_made": 0, "replies_received": 0, "replies_failed": 0},
        )


##############################################################################
# THE END
