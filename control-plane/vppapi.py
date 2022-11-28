import time
import sys
sys.path.append('/home/otroan/src/vpp/src/vpp-api/python')
#import vpp_papi
from vpp_papi import VPPApiClient

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

def callback(msgname, msg):
    print('NAME', msgname)

def vppapirunner(api_calls):
    vpp = VPPApiClient(use_socket=True, apifiles=apifiles)
    vpp.register_event_callback(callback)

    vpp.connect(name='nataasvpp', do_async=False)
    # rv = vpp.api.show_version()
    # print('RV', rv)

    # services=[{'data': 'vcdp-nat-output'}, {'data': 'vcdp-nat-output'}]
    # rv = vpp.api.vcdp_set_services(tenant_id=0, dir=0, services=services, n_services=2)

    rv = vpp.api.vcdp_nat_add(nat_id='foobar', vrf=0, n_addr=1, addr=['1.1.1.1'])

    # rv = vpp.api.cli_inband(cmd="show version")
    # print('RV', rv)
    # rv = vpp.api.log_dump()
    # print('RV', rv)

    for api_call in api_calls:
        print('Calling', api_call)
        for k,v in api_call.items():
            f = vpp.get_function(k)
            print('Function', k, v, type(v))
            rv = f(**v)
            print('RV', rv)
            break


    vpp.disconnect()
