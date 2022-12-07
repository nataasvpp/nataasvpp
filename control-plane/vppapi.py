# Copyright(c) 2022 Cisco Systems, Inc.

'''
API runner: Takes a list of API calls and applies them to VPP.
'''

import struct
import threading
import logging
from vpp_papi import VPPApiClient
from vpp_papi.vpp_stats import VPPStats

# pylint: disable=line-too-long
# pylint: disable=invalid-name

def dump_interfaces(vpp):
    '''
    Get interface list for VPP. This is run only when first configuration the VPP instance. Later the
    interface list is cached in the current running state configuration file.
    '''
    interface_list = {}
    interfaces = vpp.api.sw_interface_dump()
    for i in interfaces:
        interface_list[i.interface_name] = i.sw_if_index
    return interface_list

replies_received = 0
calls_made = 0
replies_failed = 0
evt = threading.Event()

def callback(msgname, msg):
    '''Called for each response message from VPP (in async mode)'''
    global replies_received
    global replies_failed
    retval = msg.retval
    if retval != 0:
        replies_failed += 1
        logging.error(msg)
    replies_received += 1
    if calls_made == replies_received:
        evt.set()

def api_calls(vpp, interface_list, calls, binary_file):
    '''Execute blocking API calls against VPP'''
    for api_call in calls:
        (k, v), = api_call.items()
        f = vpp.get_function(k)
        if 'sw_if_index' in v and isinstance(v['sw_if_index'], str):  ## Change to check for vl_api_interface_id_t
            v['sw_if_index'] = interface_list[v['sw_if_index']]
        rv = f(**v)
        if rv.retval != 0:
            raise Exception(f'{k}({v}) failed with {rv}')

def api_calls_async(vpp, interface_list, calls, binary_file):
    '''Execute async API calls against VPP'''
    global calls_made
    for api_call in calls:
        (k, v), = api_call.items()
        f = vpp.get_function(k)
        if 'sw_if_index' in v and isinstance(v['sw_if_index'], str):  ## Change to check for vl_api_interface_id_t
            if v['sw_if_index'] not in interface_list:
                raise Exception(f'Interface: {v["sw_if_index"]} not configured in VPP')
            v['sw_if_index'] = interface_list[v['sw_if_index']]
        calls_made += 1
        f(**v)

def api_calls_pack(vpp, interface_list, calls, binary_file):
    '''Get binary representation of API calls for VPP'''
    for api_call in calls:
        (k, v), = api_call.items()
        f = vpp.get_function(k+'_pack')
        if 'sw_if_index' in v and isinstance(v['sw_if_index'], str):  ## Change to check for vl_api_interface_id_t
            v['sw_if_index'] = interface_list[v['sw_if_index']]
        b = f(**v)
        l = struct.pack('>I', len(b))
        binary_file.write(l+b)

def get_init_vpp_state(vpp, interface_list):
    '''Get interface list and boottime from VPP'''
    vpp.connect(name='nataasvpp', do_async=False)
    if not interface_list:
        interface_list = dump_interfaces(vpp)

    # Check if current VPP instance is the same as we have running state for:
    statistics = VPPStats()
    current_boottime = statistics['/sys/boottime']
    vpp.disconnect()
    return interface_list, current_boottime

def vppapirunner(apidir, added, removed, interface_list, boottime, packed_file):
    '''
    Given a list of API calls, connect to VPP and call those APIs in order.
    If a call fails, abort. The state of VPP is then considered undefined.
    '''

    f = api_calls_async
    do_async = True
    fp = None
    if packed_file:
        f = api_calls_pack
        fp = open(packed_file, "wb")

    VPPApiClient.apidir = apidir
    vpp = VPPApiClient(use_socket=True)
    vpp.register_event_callback(callback)

    interface_list, current_boottime = get_init_vpp_state(vpp, interface_list)
    if boottime and boottime != current_boottime:
        raise Exception('Connecting to different VPP instance than we have running state for')

    vpp.connect(name='nataasvpp', do_async=do_async)

    # Hard code dependencies here. An improvement would be to follow dependencies and
    # resolve them dynamically. Could be JSON pointers in the document or references
    # from a JSON schema.
    sections = ['nats', 'tenants', 'interfaces', 'tunnels']
    for subsection in reversed(sections):
        if subsection not in removed:
            continue
        f(vpp, interface_list, removed[subsection], fp)

    for subsection in sections:
        if subsection not in added:
            continue
        f(vpp, interface_list, added[subsection], fp)

    # time.sleep(1) ## Wait for responses
    if do_async and calls_made > 0:
        evt.wait(timeout=10)

    vpp.disconnect()

    if fp:
        fp.close()

    summary = {'calls_made': calls_made, 'replies_received': replies_received, 'replies_failed': replies_failed}

    return interface_list, current_boottime, summary
