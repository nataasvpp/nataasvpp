#!/usr/bin/env python3

import sys
import json
from jsonschema import validate, FormatChecker

formatchecker = FormatChecker(['ipv4'])
schemaname  = 'nataasvpp-schema.json'
instancename = sys.argv[1]

def read_jsonfile(filename):
    '''Open the file and load the file'''
    with open(filename, 'r', encoding='utf-8') as json_file:
        data = json.load(json_file)
    return data

schema = read_jsonfile(schemaname)
instance = read_jsonfile(instancename)
validate(instance, schema, format_checker=FormatChecker())
formatchecker.check(instance, "ipv4")

tunnel_keys = instance['tunnels'].keys()
tenant_keys = {int(k): k for k in instance['tenants'].keys()}
nat_keys = instance['nats'].keys()

# Validate that internal references are correct
for k,v in instance['tunnels'].items():
    tenant = v.get('tenant', None)
    if tenant and tenant not in tenant_keys:
        print(f'Tenant {tenant} is not defined')
for k,v in instance['tenants'].items():
    nat_instance = v.get('nat-instance', None)
    if nat_instance and nat_instance not in nat_keys:
        print(f'NAT instance {nat_instance} is not defined')
for k,v in instance['interfaces'].items():
    tenant = v.get('tenant', None)
    if tenant and tenant not in tenant_keys:
        print(f'Tenant {tenant} is not defined')

