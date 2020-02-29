#!/usr/bin/python
# Author: Jesus Rodriguez Fonteboa
# Grational ltd - Oct 2019

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: Launch Nessus.sc scans
short_description: Launch Nessus.sc scans
description:
    - This module triggers a scan in Nessus.sc
    - The scan needs to be created beforehand
version_added: "2.4"
author: Jesus Rodriguez Fonteboa (@hiperesfera)
options:
    scan_name:
        description:
            - Nessus.sc scan name
        required: true
    server:
        description:
            - Nessus.sc server name
        required: true
    username:
        description:
            - user with perms launch scans in Nessus.sc server
        required: true
    password:
        description:
            - user's password
        required: true
notes:
requirements:
    - Requires the following module to be installed pyTenable
    - Tested with Ansible 2.8.6 version and Python 2.7.16
'''

EXAMPLES = '''
- name: Run Nessus.sc scan
  nessus-launch-results
      scan_name: "Internal Windows Workstations"
      server: nesuss.sc_server
      username: api_nessus
      password: *****
  register: output
'''

RETURN = '''
changed:
    description: If changed or not (true if results completed)
    type: bool
output:
    description: Scan name and ID in Nessus.sc
    type: JSON
'''


import os
from ansible.module_utils.basic import AnsibleModule
import time
import json


try:
    from tenable.sc import TenableSC
    HAS_PYTENABLE = True
except ImportError:
    HAS_PYTENABLE = False


def run_module():

    module_args = dict(
        scan_name=dict(type='str', required=True),
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

    if module.check_mode:
        module.exit_json(**result)


    scan_name = module.params['scan_name']
    server = module.params['server']
    nessus_username = module.params['nessus_username']
    nessus_password = module.params['nessus_password']

    nessus_credentials_list = []

    try:
        sc = TenableSC(server)
        sc.login(nessus_username, nessus_password)
    except:
        module.fail_json(msg='Issues connectin to Nessus.sc. Please check connectivity and credetials')


    # listing scans
    scan_list = sc.scans.list()['usable']
    scan_id = [item for item in scan_list if item["name"] == scan_name]
    if scan_id:
        nessus_scan_id = int(scan_id[0]['id'])
    else:
        module.fail_json(msg="Nessus scan not found: [" + scan_name + "]")

    # listing scan_instances (scan results TAB in Nessus.sc)
    scan_instances_list = sc.scan_instances.list(start_time=1)['usable']
    scan_instances_id = [item for item in scan_instances_list if item["name"] == scan_name]
    if scan_instances_id:
        module.fail_json(msg='Nessus.sc scan results already exists: [' + scan_name + ']')
    else:
        sc.scans.launch(nessus_scan_id)


    result['changed'] = True
    result['output'] = 'Nessus.sc Scan Name: [' + scan_name + ']'

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
