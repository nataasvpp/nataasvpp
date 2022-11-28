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
import unittest
import yaml
from yaml.loader import SafeLoader
from deepdiff import DeepDiff
import IPython # pylint: disable=unused-import
from vppapi import vppapirunner

class Singleton: # pylint: disable=too-few-public-methods
    '''Meta class'''
    __instance = None
    def __new__(cls, *args, **kwargs):
        if cls.__instance is None:
            cls.__instance = super().__new__(cls)
        return cls.__instance

pp = pprint.PrettyPrinter(indent=4)

def read_yamlfile(filename):
    '''Open the file and load the file'''
    with open(filename, 'r', encoding='utf-8') as yaml_file:
        data = yaml.load(yaml_file, Loader=SafeLoader)
    return data

def write_yamlfile(data, filename):
    '''Write Python datastructure to YAML file'''
    with open(filename, 'w', encoding='utf-8') as yaml_file:
        data = yaml.dump(data, yaml_file)

class Interfaces(Singleton):
    '''Interfaces configuration object'''
    def get_api(self, interface, obj, add):
        '''Return VPP API commands'''
        # api_calls = []
        api = {}
        # sw_if_index = interface_name2index(interface)
        is_tunnel = obj.get('tunnel-headend', False)
        if is_tunnel:
            f = 'vcdp_gateway_tunnel_enable_disable'
            api[f] = {}
        else:
            f = 'vcdp_gateway_enable_disable'
            tenant = obj.get('tenant', 0)
            api[f] = {}
            api[f]['tenant_id'] = tenant
        api[f]['sw_if_index'] = interface
        api[f]['is_enable'] = add
        return [api]

class Tunnels(Singleton):
    '''Tunnel configuration objects'''
    def get_api(self, tunnelid, obj, add):
        '''Return VPP API commands'''
        api = {}
        k = 'vcdp_tunnel_add' if add else 'vcdp_tunnel_remove'
        api[k] = obj.copy()
        api[k]['tunnel_id'] = tunnelid
        api[k]['tenant_id'] = api[k].pop('tenant')
        if obj['method'] == 'vxlan-dummy-l2':
            api[k]['method'] = 0
        else:
            api[k]['method'] = 1
        return [api]


class Nats(Singleton):
    '''NAT instance configuration objects'''
    def get_api(self, natid, obj, add):
        '''Return VPP API commands'''
        api = {}
        k = 'vcdp_nat_add' if add else 'vcdp_nat_remove'
        api[k] = {}
        api[k]['nat_id'] = natid
        api[k]['addr'] = obj['pool-address']
        api[k]['n_addr'] = len(obj['pool-address'])
        return [api]

class Tenants(Singleton):
    '''Tenant configuration objects'''

    def services(self, tenantid, direction, obj):
        '''Generete vcdp_set_services API call'''
        api = {}
        k = 'vcdp_set_services'
        api[k] = {}
        api[k]['tenant_id'] = tenantid
        api[k]['dir'] = 0 if direction == 'forward-services' else 1
        svc = {}
        api[k]['services'] = []
        for s in obj:
            svc['data'] = s
            api[k]['services'].append(svc)
        api[k]['n_services'] = len(obj)
        return api

    def get_api(self, tenantid, obj, add):
        '''Return VPP API commands'''
        api = {}
        apis = []
        k = 'vcdp_tenant_add_del'
        api[k] = {}
        api[k]['tenant_id'] = tenantid
        api[k]['context_id'] = obj['context']
        api[k]['is_add'] = add
        apis.append(api)

        if add:
            k = 'forward-services'
            if k in obj:
                api = self.services(tenantid, k, obj[k])
                apis.append(api)
            k = 'reverse-services'
            if k in obj:
                api = self.services(tenantid, k, obj[k])
                apis.append(api)
        else:
            pass

        return apis
VOM = {}
def init():
    '''Init the object dispatcher'''
    VOM['interfaces'] = Interfaces()
    VOM['tunnels'] = Tunnels()
    VOM['nats'] = Nats()
    VOM['tenants'] = Tenants()

def diff(running, desired, verbose=None):
    '''Produce delta between desired and running state'''
    # Hard coded dependencies for now. Improve by following references. Might need a schema or use JSON pointers.
    dd = DeepDiff(running, desired, view='tree')
    if verbose:
        print('Changes:\n', dd.pretty())

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


def main():
    '''Main function'''
    parser = argparse.ArgumentParser(description="VPP Configuration.")
    parser.add_argument(
        "--desired-conf",
        dest="desired",
        help="Desired configuration",
    )
    parser.add_argument(
        "--running-conf",
        dest="running",
        help="Current Running configuration",
    )
    parser.add_argument(
        "--new-running-conf",
        dest="new_running",
        help="New Running configuration",
    )
    parser.add_argument(
        "--test", action='store_true', help="Run unit tests",
    )
    parser.add_argument(
        "--verbose", action='store_true', help="Verbose output",
    )
    parser.add_argument(
        "--apply", action='store_true', help="Apply changes to running VPP instance",
    )
    init()

    args, unknownargs = parser.parse_known_args()
    if args.test:
        a = [sys.argv[0]] + unknownargs
        unittest.main(verbosity=2, argv=a)
        sys.exit(0)
    desired = read_yamlfile(args.desired)
    if args.running:
        running = read_yamlfile(args.running)
    else:
        running = {'interfaces': {}, 'tenants': {}, 'nats': {}, 'tunnels': {}}

    if args.apply and not args.new_running:
        parser.error('Missing new running configuration option (--new-running-conf=<filename>)')

    boottime = running.pop('boottime', None)
    interface_list = running.pop('interface_list', None)

    # Delta API commands
    added, removed = diff(running, desired, args.verbose)
    if args.verbose:
        pp.pprint(added)
        pp.pprint(removed)

    # API Runner (separate module)
    if args.apply:
        try:
            interface_list, boottime = vppapirunner(added, removed, interface_list, boottime)
        except Exception as e:
            print('*** Programming VPP FAILED. VPP is left in indeterminate state.\n', repr(e), file=sys.stderr)
            sys.exit(-1)

        # Dump new running configuration
        desired['boottime'] = boottime
        desired['interface_list'] = interface_list
        write_yamlfile(desired, args.new_running)

class TestVPPConf(unittest.TestCase):
    '''Unittests for VPPConf'''
    def test_basic_add(self):
        '''Basic add objects'''
        desired = {'interfaces': { 'tap0': {'tenant': 1000} } }
        api_calls = diff(desired, desired)
        self.assertEqual(len(api_calls), 0)

        api_calls = diff({'interfaces': {}}, desired)
        self.assertEqual(len(api_calls), 1)

        desired['interfaces']['tap1'] = {'tunnel-headend': True }
        api_calls = diff({'interfaces': {}}, desired)
        pp.pprint(api_calls)

        desired = {'nats': {1: {'pool-addresses': ['1.1.1.1', '2.2.2.2']},
                            2: {'pool-addresses': ['1.1.1.1', '2.2.2.2']}},}

        api_calls = diff({'nats': {}}, desired)
        pp.pprint(api_calls)

        running = {'nats': {2: {'pool-addresses': ['1.1.1.1', '2.2.2.2']}},}
        api_calls = diff(running, desired)
        self.assertEqual(len(api_calls), 1)

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
