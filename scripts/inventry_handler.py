#!/usr/bin/env python
# -*- coding:utf-8 -*-

import os
import subprocess
import json

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

filepath = "terraform.tfstate"

with open(os.path.join(__location__, filepath)) as f:
    hosts = json.loads(f.read())
 
inventory = {
        "cloud_servers":{"hosts":[]}, 
        "_meta": {"hostvars": {}}
    }

for host_name in hosts["outputs"]:
    ipaddrs = hosts["outputs"][host_name]['value']
    inventory["cloud_servers"]["hosts"].append(host_name)
    inventory["_meta"]["hostvars"][host_name] = {"ansible_host": ipaddrs}

print(json.dumps(inventory))
