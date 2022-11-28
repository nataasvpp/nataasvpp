# Copyright(c) 2022 Cisco Systems, Inc.

import sys
from vpp_papi import VPPApiClient
from vpp_papi.vpp_stats import VPPStats

# pylint: disable=line-too-long
# pylint: disable=invalid-name


# TODO: Fix this to use auto-discovery or command line parameter
# Build a python package with API JSONs included?
apifiles=[
    './build/plugins/vcdp_services/nat/nat.api.json',
    './build/plugins/vcdp_services/tcp-check/tcp_check.api.json',
    './build/plugins/vcdp/vcdp_types.api.json',
    './build/plugins/vcdp/vcdp.api.json',
    './build/plugins/gateway/gateway.api.json',
    '../vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/core/memclnt.api.json',
    '../vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/core/vpe.api.json',
    '../vpp/build-root/install-vpp_debug-native/vpp/share/vpp/api/core/interface.api.json',
]

# Generate API for interfaces
# Object to API
# TODO: Store interface table in running configuration.

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

def callback(msgname, msg):
    '''In async mode this is called for every reply message from VPP'''
    print('NAME', msgname)

def vppapirunner(api_calls, interface_list, boottime):
    '''
    Given a list of API calls, connect to VPP and call those APIs in order.
    If a call fails, abort. The state of VPP is then considered undefined.
    '''

    vpp = VPPApiClient(use_socket=True, apifiles=apifiles)
    vpp.register_event_callback(callback)

    vpp.connect(name='nataasvpp', do_async=False)

    if not interface_list:
        interface_list = dump_interfaces(vpp)

    # Check if current VPP instance is the same as we have running state for:
    statistics = VPPStats()
    current_boottime = statistics['/sys/boottime']
    if boottime and boottime != current_boottime:
        raise Exception('Connecting to different VPP instance than we have running state for')

    # Hard code dependencies here. An improvement would be to follow dependencies and
    # resolve them dynamically. Could be JSON pointers in the document or references
    # from a JSON schema.
    for subsection in ['nats', 'tenants', 'interfaces', 'tunnels']:
        for api_call in api_calls[subsection]:
            (k, v), = api_call.items()
            f = vpp.get_function(k)
            if 'sw_if_index' in v and isinstance(v['sw_if_index'], str):  ## Change to check for vl_api_interface_id_t
                v['sw_if_index'] = interface_list[v['sw_if_index']]
            rv = f(**v)
            if rv.retval != 0:
                raise Exception(f'{k}({v}) failed with {rv}')

    vpp.disconnect()

    return interface_list, current_boottime
