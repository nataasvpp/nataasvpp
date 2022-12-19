#!/usr/bin/env python3
# Copyright(c) 2022 Cisco Systems, Inc.

'''
Process desired configuration against current running configuration (may be 0).
The delta from the above should then be applied to VPP.
And the new running state is stored.

Input: desired configuration, running configuration
Output: Reprogrammed VPP, new running configuration
List of API commands to execute. Named tuple arguments.

'''

 # pylint: disable=line-too-long
 # pylint: disable=invalid-name

import sys
import pprint
import argparse
import logging
import unittest
import time
from functools import wraps
import json
import traceback  # pylint: disable=unused-import
import yaml
from yaml.loader import SafeLoader
from deepdiff import DeepDiff
import IPython # pylint: disable=unused-import
from vppapi import vppapirunner

import logging

# Create a logger
logger = logging.getLogger()
console_handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

performance = []
def timeit(func):
    '''Timeit decorator'''
    @wraps(func)
    def timeit_wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        total_time = end_time - start_time
        performance.append({'func': func.__name__, 'time': total_time})
        return result
    return timeit_wrapper


class Singleton: # pylint: disable=too-few-public-methods
    '''Meta class'''
    __instance = None
    def __new__(cls, *args, **kwargs):
        if cls.__instance is None:
            cls.__instance = super().__new__(cls)
        return cls.__instance

pp = pprint.PrettyPrinter(indent=4)

@timeit
def read_yamlfile(filename):
    '''Open the file and load the file'''
    with open(filename, 'r', encoding='utf-8') as yaml_file:
        data = yaml.load(yaml_file, Loader=SafeLoader)
    return data

@timeit
def read_jsonfile(filename):
    '''Open the file and load the file'''
    with open(filename, 'r', encoding='utf-8') as json_file:
        data = json.load(json_file)
    return data

def write_yamlfile(data, filename):
    '''Write Python datastructure to YAML file'''
    with open(filename, 'w', encoding='utf-8') as yaml_file:
        data = yaml.dump(data, yaml_file)

def write_jsonfile(data, filename):
    '''Write Python datastructure to YAML file'''
    with open(filename, 'w', encoding='utf-8') as json_file:
        json.dump(data, json_file, indent=4)

class Interfaces(Singleton):
    '''Interfaces configuration object'''
    def get_api(self, interface, obj, add):
        '''Return VPP API commands'''
        # api_calls = []
        apis = []
        # sw_if_index = interface_name2index(interface)
        is_tunnel = obj.get('tunnel-headend', False)
        if is_tunnel:
            api = {}
            f = 'vcdp_gateway_tunnel_enable_disable'
            api[f] = {}
            api[f]['sw_if_index'] = interface
            api[f]['is_enable'] = add
            apis.append(api)
        tenant = obj.get('tenant', None)
        if tenant is not None:
            api = {}
            f = 'vcdp_gateway_enable_disable'
            api[f] = {}
            api[f]['tenant_id'] = tenant
            api[f]['sw_if_index'] = interface
            api[f]['is_enable'] = add
            apis.append(api)
        return apis

class Tunnels(Singleton):
    '''Tunnel configuration objects'''
    def get_api(self, tunnelid, obj, add):
        '''Return VPP API commands'''
        api = {}
        if add:
            k = 'vcdp_tunnel_add'
            api[k] = obj.copy()
            api[k]['tunnel_id'] = tunnelid
            api[k]['tenant_id'] = api[k].pop('tenant')
            if obj['method'] == 'vxlan-dummy-l2':
                api[k]['method'] = 0
            else:
                api[k]['method'] = 1
        else:
            k = 'vcdp_tunnel_remove'
            api[k] = {}
            api[k]['tunnel_id'] = tunnelid
        return [api]


class Nats(Singleton):
    '''NAT instance configuration objects'''
    def get_api(self, natid, obj, add):
        '''Return VPP API commands'''
        api = {}
        k = 'vcdp_nat_add' if add else 'vcdp_nat_remove'
        api[k] = {}
        api[k]['nat_id'] = natid
        if add:
            api[k]['addr'] = obj['pool-address']
            api[k]['n_addr'] = len(obj['pool-address'])
        return [api]

class Tenants(Singleton):
    '''Tenant configuration objects'''
    def __init__(self):
        self.dispatch = {'tcp-mss': self.tcp_mss,
                         'nat-instance': self.nat_instance,
                         'forward-services': self.services,
                         'reverse-services': self.services}

    def tcp_mss(self, key, tenantid, mss, is_add):
        '''TCP MSS clamping configuration'''
        return [{'vcdp_tcp_mss_enable_disable': {'tenant_id': tenantid,
                                                 'dir': 0,
                                                 'ip4_mss': mss,
                                                 'is_enable': is_add}}]

    def nat_instance(self, key, tenantid, natid, is_add):
        return [{'vcdp_nat_bind_set_unset': {'tenant_id': tenantid,
                                             'nat_id':  natid,
                                             'is_set': is_add}}]

    def services(self, key, tenantid, obj, is_add):
        '''Generate vcdp_set_services API call'''
        if not is_add:
            return []

        api = {}
        k = 'vcdp_set_services'
        api[k] = {}
        api[k]['tenant_id'] = tenantid
        api[k]['dir'] = 0 if key == 'forward-services' else 1
        api[k]['services'] = []
        for s in obj:
            svc = dict(data=s)
            api[k]['services'].append(svc)
        api[k]['n_services'] = len(obj)
        return [api, ]

    def get_api(self, tenantid, obj, add):
        '''Return VPP API commands'''
        apis = []
        tenantid = int(tenantid)
        for k,v in obj.items():
            if k in self.dispatch:
                l = self.dispatch[k](k, tenantid, v, add)
                if l:
                    apis += l
        api = {}
        k = 'vcdp_tenant_add_del'
        api[k] = {}
        api[k]['tenant_id'] = tenantid
        api[k]['context_id'] = obj.get('context', 0)
        api[k]['is_add'] = add

        # Ensure the tenant itself is created first and deleted last
        if add:
            apis.insert(0, api)
        else:
            apis.append(api)
        return apis

VOM = {}

def init():
    '''Init the object dispatcher'''
    VOM['interfaces'] = Interfaces()
    VOM['tunnels'] = Tunnels()
    VOM['nats'] = Nats()
    VOM['tenants'] = Tenants()


@timeit
def toapicalls(desired):
    '''Generate API calls'''
    api_calls = {}
    for section,instances in desired.items():
        for k,v in instances.items():
            if section not in api_calls:
                api_calls[section] = []
            api_calls[section] += VOM[section].get_api(k, v, True)
    return api_calls


@timeit
def diff(running, desired):
    '''Produce delta between desired and running state'''
    # if running == desired:
    #     print('They are equal!!')

    # Hard coded dependencies for now. Improve by following references. Might need a schema or use JSON pointers.
    dd = DeepDiff(running, desired, view='tree')
    logger.debug('Changes: %s\n', dd.pretty())

    #
    # If path length is 1, then missing root key. Do we allow configuration at root level?
    # If path length is 3, then individual field element is changed. Remove and add object at level 2.
    #
    added = {}
    removed = {}
    for changes in dd:
        for a in dd[changes]:
            if changes == 'dictionary_item_added':
                node = a.t2
                add = True
                api_calls = added
            elif changes == 'dictionary_item_removed':
                node = a.t1
                add = False
                api_calls = removed
            else:
                raise NotImplementedError(f'Not implemented: {changes} {a}')
            path = a.path(output_format='list')
            if len(path) == 2 and path[0] in VOM:
                if path[0] not in api_calls:
                    api_calls[path[0]] = []
                api_calls[path[0]] += VOM[path[0]].get_api(path[1], node, add)
            else:
                raise NotImplementedError('NOT YET IMPLEMENTED', path, changes  )
    return added, removed

@timeit
def call_vpp(apidir, added, removed, interface_list, boottime, cfg):
    '''Wrapper to call or generate vpp apis'''
    return vppapirunner(apidir, added, removed, interface_list, boottime, cfg)

def main():
    '''Main function'''
    parser = argparse.ArgumentParser(description="VPP Configuration.")
    parser.add_argument("--desired-conf", dest="desired", help="Desired configuration")
    parser.add_argument("--running-conf", dest="running", help="Current Running configuration",)
    parser.add_argument("--new-running-conf", dest="new_running", help="New Running configuration",)
    parser.add_argument("--test", action='store_true', help="Run unit tests",)
    parser.add_argument("--apply", action='store_true', help="Apply changes to running VPP instance",)
    parser.add_argument("--apidir", nargs="+", default=[])
    parser.add_argument("--log", help="Specify log level")
    parser.add_argument("--packed-file", help="Apply changes via binary bulk API")

    init()

    args, unknownargs = parser.parse_known_args()
    if args.log:
        loglevel = getattr(logging, args.log.upper(), None)
        if not isinstance(loglevel, int):
            raise ValueError(f'Invalid log level: {loglevel}')
        logger.setLevel(loglevel)

    if args.test:
        a = [sys.argv[0]] + unknownargs
        unittest.main(verbosity=2, argv=a)
        sys.exit(0)
    try:
        desired = read_jsonfile(args.desired)
    except json.decoder.JSONDecodeError:
        sys.exit(f'Reading "{args.desired}" failed')
    if args.running:
        try:
            running = read_jsonfile(args.running)
        except json.decoder.JSONDecodeError:
            sys.exit(f'Reading "{args.running}" failed')
    else:
        running = {'interfaces': {}, 'tenants': {}, 'nats': {}, 'tunnels': {}}

    if args.apply and not args.new_running:
        parser.error('Missing new running configuration option (--new-running-conf=<filename>)')

    boottime = running.pop('boottime', None)
    interface_list = running.pop('interface_list', None)

    if not args.running:
        added = toapicalls(desired)
        removed = {}
    else:
        # Delta API commands
        added, removed = diff(running, desired)
    logger.debug('Added: %s', pp.pformat(added))
    logger.debug('Removed: %s', pp.pformat(removed))

    if args.apply:
        try:
            interface_list, boottime, summary = call_vpp(args.apidir, added, removed, interface_list, boottime, args.packed_file)
        except Exception as e:
            logger.error('*** Programming VPP FAILED. VPP is left in an indeterminate state. %s\n', repr(e))
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(traceback.print_exc())
            sys.exit(1)

        logger.info("API calls: %d/%d (%d failed)", summary['replies_received'], summary['calls_made'], summary['replies_failed'])
        for p in performance:
            logger.info("%s: %.4fs", p['func'], p['time'])

        if summary['replies_failed'] > 0:
            logger.error('*** Programming VPP failed.')
            sys.exit(1)

        # Dump new running configuration
        desired['boottime'] = boottime
        desired['interface_list'] = interface_list
        try:
            write_jsonfile(desired, args.new_running)
        except Exception as e:
            logger.error('Writing %s failed. %s', args.new_running, repr(e))
            sys.exit(1)
    sys.exit(0)

class TestVPPConf(unittest.TestCase):
    '''Unittests for VPPConf'''
    def test_basic_add(self):
        '''Basic add objects'''
        empty_running = {'interfaces': {} }
        desired = {'interfaces': { 'tap0': {'tenant': 1000} } }
        added, removed = diff(empty_running, desired)
        self.assertEqual(len(added), 1)

        desired['interfaces']['tap1'] = {'tunnel-headend': True }
        added, removed = diff(empty_running, desired)
        self.assertEqual(len(added['interfaces']), 2)

        pp.pprint((added, removed))

        # Both tunnel and tenant on same interface
        desired = {'interfaces': { 'tap0': {'tenant': 1000, 'tunnel-headend': True} } }
        added, removed = diff(empty_running, desired)
        self.assertEqual(len(added['interfaces']), 2)
        pp.pprint((added, removed))

        desired = {'nats': {1: {'pool-address': ['1.1.1.1', '2.2.2.2']},
                            2: {'pool-address': ['1.1.1.1', '2.2.2.2']}},}

        added, removed = diff({'nats': {}}, desired)
        pp.pprint((added, removed))

        running = {'nats': {2: {'pool-address': ['1.1.1.1', '2.2.2.2']}},}
        added, removed = diff(running, desired)

        pp.pprint((added, removed))
        # self.assertEqual(len(api_calls), 1)

    def test_basic_remove(self):
        '''Basic remove'''
        running = {'interfaces': { 'tap0': {'tenant': 1000},
                                   'tap1': {'tunnel-header': True} }
        }

        api_calls = diff(running, {'interfaces': {}})
        pp.pprint(api_calls)

    def test_nat_remove(self):
        '''Remove NAT object'''
        running = {'nats': {1: {'pool-addresses': ['1.1.1.1', '2.2.2.2']},
                            2: {'pool-addresses': ['1.1.1.1', '2.2.2.2']}},
                   }
        desired = {'nats': {2: {'pool-addresses': ['1.1.1.1', '2.2.2.2']}},}

        api_calls = diff(running, desired)
        self.assertEqual(len(api_calls), 1)
        pp.pprint(api_calls)

    def test_tenant_add(self):
        '''Add tenant'''

        desired = {'tenants': {
            '0': {'tcp-mss': [123, 456], 'context': 0, 'flags': 'no-create',
            "forward-services": ["vcdp-l4-lifecycle", "vcdp-tcp-mss", "vcdp-nat-output"],
            "reverse-services": ["vcdp-l4-lifecycle", "vcdp-tunnel-output"],
            "nat-instance": "6529f996-2854-4d78-8337-059053a2c61f",}}}

        # Add
        api_calls = diff({'tenants': {}}, desired)
        print('Added API CALLS', api_calls)

        # Remove
        api_calls = diff(desired, {'tenants': {}})
        print('Removed API CALLS', api_calls)


    @unittest.skip
    def test_basic_modify(self):
        '''Modify single field'''
        running = {'interfaces': { 'tap0': {'tenant': 1000} } }
        desired = {'interfaces': { 'tap0': {'tenant': 1001} } }
        api_calls = diff(running, desired)
        self.assertEqual(len(api_calls), 1)
        pp.pprint(api_calls)


if __name__ == "__main__":
    main()
