#!/usr/bin/python
# Author: Jesus Rodriguez Fonteboa
# Grational ltd - Dec 2019

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: Create Nessus.sc asset list
short_description: Create Nessus.sc asset list from a CSV file
description:
    - Create a Nessus.sc ip or hostname asset list
    - ips or hostnames need to be listed under ip or hostname columns inside the CSV file. 
version_added: "2.4"
author: Jesus Rodriguez Fonteboa (@hiperesfera)
options:
    asset_name:
        description:
            - Nessus.sc asset name
        required: true
    asset_type:
        description:
            - Nessus.sc asset type: DNS or IP
        required: true
    targets:
        description:
            - Regex expresion
        required: false
        default: .*
    file_location:
        description:
            - Location of the CSV file
        required: true
    server:
        description:
            - Nessus.sc server name
        required: true
    username:
        description:
            - user with perms to create and launch scans in Nessus.sc server
        required: true
    password:
        description:
            - user's password
        required: true
notes:
requirements:
    - Requires the following modules to be installed: pyTenable and pandas
    - Tested with Ansible 2.8.6 version and Python 2.7.16
'''


EXAMPLES = '''
- name: Create Nessus.sc asset list
  nessus-create-assets
      asset_name: "Linux hosts"
      asset_type: "DNS"
      targets: "^lnx"
      file_location: "/path/to/host_list.csv"
      server: nessus.sc_server
      username: api_nessus
      password: *****
  register: output
'''


RETURN = '''
changed:
    description: If changed or not (true if results completed)
    type: bool
output:
    description: Nessus.sc Asset list name
    type: JSON
'''


import os
import re
from ansible.module_utils.basic import AnsibleModule
import time
import json



try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False



try:
    from tenable.sc import TenableSC
    HAS_PYTENABLE = True
except ImportError:
    HAS_PYTENABLE = False




def run_module():

    module_args = dict(
        asset_name=dict(type='str', required=True),
        asset_type=dict(type='str', required=True),
        targets=dict(type='str', required=False, default='.*'),
        file_location=dict(type='str', required=True),
        server=dict(type='str', required=True),
        nessus_username=dict(type='str', required=True),
        nessus_password=dict(type='str', required=True)
        )

    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )


    if not HAS_PYTENABLE:
        module.fail_json(msg = 'pyTenable required. pip install pytenable')

    if not HAS_PANDAS:
        module.fail_json(msg = 'Pandas required. pip install panda')


    if module.check_mode:
        module.exit_json(**result)


    asset_name = module.params['asset_name']
    asset_type = module.params['asset_type']
    targets = module.params['targets']
    file_location = module.params['file_location']
    server = module.params['server']
    nessus_username = module.params['nessus_username']
    nessus_password = module.params['nessus_password']


    try:
        sc = TenableSC(server)
        sc.login(nessus_username, nessus_password)
    except:
        module.fail_json(msg='Issues connecting to Nessus.sc. Please check connectivity and credetials')

    try:
        df = pd.read_csv(file_location,low_memory=False)
    except:
        module.fail_json(msg='Issues loading CSV file' + file_location)


    asset_list = sc.asset_lists.list()['usable']
    asset_id = [item for item in asset_list if item["name"] == asset_name]

    # overwrite existing asset list
    if asset_id:
        sc.asset_lists.delete(int(asset_id[0]['id']))


    if asset_type.lower() == 'dns':
        host_list = list(df[df['hostname'].str.contains(pat=targets)]['hostname'])

        try:
            sc.asset_lists.create(asset_name,list_type='dnsname',dns_names=host_list)
        except:
            module.fail_json(msg="Error creating Nessus asset list [" + asset_name + "]")

    elif asset_type.lower() == 'ip':
        ip_list = list(df[df['ip'].str.contains(pat=targets)]['ip'])

        try:
            sc.asset_lists.create(asset_name,list_type='static',ips=ip_list)
        except:
            module.fail_json(msg="Error creating Nessus asset list [" + asset_name + "]")



    result['changed'] = True
    result['output'] = "Nessus.sc Asset list name: [" + asset_name + "]"

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
