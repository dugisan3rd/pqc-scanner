#!/usr/bin/python3

import json

file_cbom = 'cbom.json'

with open(file_cbom, 'r') as f:
    data = json.load(f)
    # print(json.dumps(data, indent=2))
    for i in data['results']:
        print(i['extra']['metadata']['cbom'])