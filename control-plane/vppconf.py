#!/usr/bin/env python3

'''
Process desired configuration against current running configuration (may be 0).
The delta from the above should then be applied to VPP.
And the new running state is stored.

Input: desired configuration, running configuration
Output: Reprogrammed VPP, new running configuration
List of API commands to execute. Named tuple arguments.

'''

# pylint: disable=line-too-long

import sys
import pprint
import argparse
import unittest
import yaml
from yaml.loader import SafeLoader
from deepdiff import DeepDiff
import IPython # pylint: disable=unused-import

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
    # pp.pprint(data)
    return data


# Generate API for interfaces
# Object to API
# TODO: Store interface table in running configuration.
def interface_name2index(name):
    '''Map interface name to VPP sw_if_index. Table downloaded from running VPP instance'''
    return 0

class Interfaces(Singleton):
    '''Interfaces configuration object'''
    def get_api(self, interface, obj, add):
        '''Return VPP API commands'''
        api_calls = []
        api = {}
        sw_if_index = interface_name2index(interface)
        is_tunnel = obj.get('tunnel-headend', False)
        if is_tunnel:
            f = 'vcdp_gateway_tunnel_enable_disable'
            api[f] = {}
        else:
            f = 'vcdp_gateway_enable_disable'
            tenant = obj.get('tenant', 0)
            api[f] = {}
            api[f]['tenant_id'] = tenant
        api[f]['sw_if_index'] = sw_if_index
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
            print('OJB', obj)
            if 'forward-services' in obj:
                api = {}
                k = 'vcdp_set_services'
                api[k] = {}
                api[k]['tenant_id'] = tenantid
                api[k]['dir'] = 0   # Forward
                svc = {}
                api[k]['services'] = []
                for s in obj['forward-services']:
                    svc['data'] = s
                    api[k]['services'].append(svc)

                    #                 api[k]['services'] = obj['forward-services']
                    #                 api[k]['services'] = for s in obj['forward-services']
                    # [x for x in fruits if "a" in x]
                api[k]['n_services'] = len(obj['forward-services'])
                apis.append(api)
            # if 'reverse-services' in obj:
            #     api = {}
            #     k = 'vcdp_set_services'
            #     api[k] = {}
            #     api[k]['tenant_id'] = tenantid
            #     api[k]['dir'] = 1   # Forward
            #     api[k]['services'] = obj['reverse-services']
            #     api[k]['n_services'] = len(obj['reverse-services'])
            #     apis.append(api)
            
        return apis
vom = {}
def init():
    '''Init the object dispatcher'''
    global vom
    vom['interfaces'] = Interfaces()
    vom['tunnels'] = Tunnels()
    vom['nats'] = Nats()
    vom['tenants'] = Tenants()

def diff(running, desired):
    '''Produce delta between desired and running state'''
    dd = DeepDiff(running, desired, view='tree')
    print('Changes:\n', dd.pretty())
    api_calls = []

    #
    # If path length is 1, then missing root key. Do we allow configuration at root level?
    # If path length is 3, then individual field element is changed. Remove and add object at level 2.
    #
    for changes in dd:
        for a in dd[changes]:
            if changes == 'dictionary_item_added':
                node = a.t2
                add = True
            elif changes == 'dictionary_item_removed':
                node = a.t1
                add = False
            else:
                raise NotImplementedError(f'Not implemented: {changes} {a}')
            path = a.path(output_format='list')
            if len(path) == 2 and path[0] in vom:
                api_calls += vom[path[0]].get_api(path[1], node, add)
            else:
                raise NotImplementedError('NOT YET IMPLEMENTED', path, changes  )
    return api_calls


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

    # Delta API commands
    api_calls = diff(running, desired)
    # print('API CALLS', api_calls)
    pp.pprint(api_calls)

    # API Runner (separate module)
    if args.apply:
        from vppapi import vppapirunner
        rv = vppapirunner(api_calls)

    # Dump new running configuration

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
