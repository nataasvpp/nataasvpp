#!/usr/bin/env python3

import sys
import json
from jsonschema import validate

schemaname  = 'nataasvpp-schema.json'
instancename = sys.argv[1]

def read_jsonfile(filename):
    '''Open the file and load the file'''
    with open(filename, 'r', encoding='utf-8') as json_file:
        data = json.load(json_file)
    return data

schema = read_jsonfile(schemaname)
instance = read_jsonfile(instancename)

validate(instance, schema)