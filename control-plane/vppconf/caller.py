# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

import logging

from threading import Event

from vpp_papi import VPPApiClient  # pylint: disable=import-error
from vpp_papi.vpp_stats import VPPStats  # pylint: disable=import-error

from .exceptions import VppCallerError

logger = logging.getLogger(__name__)

##############################################################################

# A VppCaller performs the actual api calls to vpp.  The VppParser is passed
# a caller object and will use its `call()` method to make the call. Exactly
# how the caller perform this operation is implementation specific, and there
# are four different VppCaller classes here that do this operation
# differently:
#
#  1. VppCaller (the base caller) makes the vpp api call immediately when its
#     call() method is invoked. For every call, a connection to the vpp api
#     is made, the api call is executed, the return results are parsed, and
#     thect connection is torn down.
#
#  2. VppBatchCaller records the api call and params but does not actually
#     call the vpp api. Instead this object provides a `call_batch()` method
#     that can be ivoked after all of the api calls have been recorded
#     (ie., after the parser has finished parsing the state file and converted
#     all of the state into api calls).  This is more efficient and faster as
#     only one vpp connection is made before all of the api calls are executed
#     in sequence (aborting if one fails), and then the connection is closed.
#
#  3. VppAsyncBatchCaller is simular to the VppBatchCaller in that all api
#     calls are batched until the `call_batch()` method is invoked. But
#     this method is called, the vpp api calls are all made asyncronously,
#     without waiting for the previous command to complete, which is the
#     fastest why to batch call the vpp api of these options.
#
#  4. VppNopCaller does nothing. Useful in unit tests and executing the
#     parser without actually call the vpp api.


class VppCaller:
    """
    Use the vpp api to issue calls to the running vpp process.
    """

    def __init__(self, interfaces, vppclient=None, apidir=None):
        if not vppclient:
            if apidir:
                VPPApiClient.apidir = apidir
            vppclient = VPPApiClient(use_socket=True)
        self.vpp = vppclient

        if interfaces:
            self.interfaces = interfaces
        else:
            self.interfaces = {}
            self.vpp.connect(name="nataasvpp", do_async=False)
            try:
                for i in self.vpp.api.sw_interface_dump():
                    self.interfaces[i.interface_name] = i.sw_if_index
            finally:
                self.vpp.disconnect()

        stats = VPPStats()
        self.current_boottime = stats["/sys/boottime"]

        self.calls_made = 0
        self.replies_received = 0
        self.replies_failed = 0

    def _find_call_function(self, call_name, call_params):
        if "sw_if_index" in call_params and isinstance(call_params["sw_if_index"], str):
            call_params["sw_if_index"] = self.interfaces.get(call_params["sw_if_index"])
            if not call_params["sw_if_index"]:
                raise VppCallerError(
                    f"Interface: {call_params['sw_if_index']} not configured in VPP"
                )
        return call_name, call_params

    def call(self, call_name, call_params):
        name, params = self._find_call_function(call_name, call_params)
        self.vpp.connect(name="nataasvpp", do_async=False)
        try:
            logger.debug("VPP CALL: %s(%s)", name, params)
            func = self.vpp.get_function(name)
            self.calls_made += 1
            result = func(**params)
            self.replies_received += 1
            if result.retval != 0:
                self.replies_failed += 1
                raise VppCallerError(f"{call_name}({params}) failed with {result}")
        finally:
            self.vpp.disconnect()

    def call_summary(self):
        return {
            "calls_made": self.calls_made,
            "replies_received": self.replies_received,
            "replies_failed": self.replies_failed,
        }


##############################################################################


class VppBatchCaller(VppCaller):
    """
    A VppCaller that will batch up all of the calls to be executed at once.
    Use the call_batch() function to trigger all the calls after they have
    been batched.
    """

    def __init__(self, interfaces, vppclient=None, apidir=None):
        super().__init__(interfaces, vppclient=vppclient, apidir=apidir)
        self.calls = []

    def call(self, call_name, call_params):
        call_name, call_params = self._find_call_function(call_name, call_params)
        self.calls.append((call_name, call_params))

    def call_batch(self):
        self.vpp.connect(name="nataasvpp", do_async=False)
        try:
            for name, params in self.calls:
                logger.debug("VPP CALL: %s(%s)", name, params)
                func = self.vpp.get_function(name)
                self.calls_made += 1
                result = func(**params)
                self.replies_received += 1
                if result.retval != 0:
                    self.replies_failed += 1
                    raise VppCallerError(f"{name}({params}) failed with {result}")
        finally:
            self.vpp.disconnect()


##############################################################################


class VppAsyncBatchCaller(VppBatchCaller):
    """
    A VppBatchCaller that uses async api calls. call_batch() will not wait
    for a response from the an api call before moving onto the next one.
    Instead a callback function is passed with each api call, and it will
    be invoked for every call result. This callback function tracks how
    many replies have been received and logs any failed results.
    call_batch() will wait for the callback function to indicate all
    replies have been received (or a timeout has expired) before exiting.
    """

    def __init__(self, interfaces, vppclient=None, apidir=None):
        super().__init__(interfaces, vppclient=vppclient, apidir=apidir)
        self.evt = Event()

    def call_batch(self):
        self.vpp.register_event_callback(self._callback)
        self.vpp.connect(name="nataasvpp", do_async=True)
        try:
            for name, params in self.calls:
                logger.debug("VPP CALL: %s(%s)", name, params)
                func = self.vpp.get_function(name)
                self.calls_made += 1
                func(**params)

            if self.calls_made > 0:
                timeout = max(self.calls_made / 1000, 5)
                self.evt.wait(timeout=timeout)

            if self.replies_failed > 0:
                raise VppCallerError("Async calls failed.")
        finally:
            self.vpp.disconnect()

    def _callback(self, _, msg):
        retval = msg.retval
        if retval != 0:
            self.replies_failed += 1
            logger.error("FAILED: %s", msg)
        self.replies_received += 1
        if self.replies_received == self.calls_made:
            self.evt.set()


##############################################################################


class VppNoopCaller(VppBatchCaller):
    """
    A caller the does nothing. Capable of emulating a regular and a batch
    vpp caller.
    """

    def reset_calls(self):
        self.calls = []

    def call_batch(self):
        pass


##############################################################################
# THE END
