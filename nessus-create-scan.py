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
module: Create Nessus.sc scan
short_description: Create Nessus.sc scans
description:
    - Create a scan against a given list of targets or assets
    - The scan can be authenticated or unauthenticated
    - A scannning policy needs to be created beforehand
version_added: "2.4"
author: Jesus Rodriguez Fonteboa (@hiperesfera)
options:
    scan_name:
        description:
            - Nessus.sc scan name
        required: true
    policy_name:
        description:
            - Nessus.sc policy name
        required: true
    targets:
        description:
            - Targets/remote servers to scan
        required: true
    assets:
        description:
            - Asset list containing servers to scan
        required: true
    credentials:
        description:
            - Optional credetials for authenticated scan
        required: false
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
    - Requires the following module to be installed pyTenable
    - Tested with Ansible 2.8.6 version and Python 2.7.16
'''

EXAMPLES = '''
- name: Create Nessus.sc targeted scan
  nessus-create-scan
      scan_name: "Internal Scan Windows"
      policy_name: "Nessus Policy Windows Servers"
      credentials:
         - nessus_win_user1
         - nessus_win_user1
      targets:
         - server1.domain.local
         - server2.domain.local
      server: Nessus.sc server name
      username: api_nessus
      password: *****
  register: output

- name: Create Nessus.sc asset scan
  nessus-create-scan
      scan_name: "Weekly UAT server scan"
      policy_name: "Nessus Policy Linux Servers"
      credentials:
         - uat_nessus_user
      assets:
         - UAT_server_lists
      server: Nessus.sc server name
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
import re
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
        policy_name=dict(type='str', required=True),
        targets=dict(type='list', required=False),
        assets=dict(type='list', required=False),
        credentials=dict(type='list', required=False),
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
    policy_name = module.params['policy_name']
    hosts_list = module.params['targets']
    asset_list = module.params['assets']
    credentials = module.params['credentials']
    nessus_username = module.params['nessus_username']
    nessus_password = module.params['nessus_password']

    nessus_credentials_list = []
    nessus_scan_asset_list = []

    try:
        sc = TenableSC(server)
        sc.login(nessus_username, nessus_password)
    except:
        module.fail_json(msg='Issues connectin to Nessus.sc. Please check connectivity and credetials')


    # listing policies and getting the policy ID
    policy_list = sc.policies.list()['usable']
    policy_id = [i for i in policy_list if policy_name.lower() == (i['name']).lower()]
    if policy_id:
        nessus_policy_id = int(policy_id[0]['id'])
    else:
        module.fail_json(msg='Nessus Policy not found: [' + policy_name + ']')


    # listing assets or ips to create the target list
    nessus_asset_list = sc.asset_lists.list()['usable']
    if asset_list:
        for asset in asset_list:
            scan_asset_list = [ i for i in nessus_asset_list if asset.lower() in i['name'].lower()]
            if not scan_asset_list:
                module.fail_json(msg='Nessus.sc asset list does not exists: [' + asset + ']')
            nessus_scan_asset_list.append(int(scan_asset_list[0]['id']))


    # creating scan
    scan_list = sc.scans.list()['usable']
    scan_id = [item for item in scan_list if item["name"] == scan_name]
    if scan_id:
        nessus_scan_id = int(scan_id[0]['id'])
        module.fail_json(msg='Nessus.sc scan resutls already exists: [' + scan_name + ']')
    else:

        if credentials:
            # authenticated scan
            credentials_list =  sc.credentials.list()['usable']

            for user in credentials:
                nessus_credentials = [ i for i in credentials_list if user.lower() in i['name'].lower()]
                if not nessus_credentials:
                    module.fail_json(msg='Nessus.sc user credentials does not exists: [' + user + ']')
                nessus_credentials_list.append(int(nessus_credentials[0]['id']))
            if hosts_list:
                sc.scans.create(scan_name, 1, policy_id=nessus_policy_id, targets=hosts_list, creds=nessus_credentials_list )
                time.sleep(5)
                scan_list = sc.scans.list()['usable']
                scan_id = [item for item in scan_list if item["name"] == scan_name]
                nessus_scan_id = int(scan_id[0]['id'])
            if nessus_scan_asset_list:
                sc.scans.create(scan_name, 1, policy_id=nessus_policy_id, asset_lists=nessus_scan_asset_list, creds=nessus_credentials_list )
                time.sleep(5)
                scan_list = sc.scans.list()['usable']
                scan_id = [item for item in scan_list if item["name"] == scan_name]
                nessus_scan_id = int(scan_id[0]['id'])
        else:
            # unauthenticated scan
            if hosts_list:
                sc.scans.create(scan_name, 1, policy_id=nessus_policy_id, targets=hosts_list )
                time.sleep(5)
                scan_list = sc.scans.list()['usable']
                scan_id = [item for item in scan_list if item["name"] == scan_name]
                nessus_scan_id = int(scan_id[0]['id'])
            if nessus_scan_asset_list:
                sc.scans.create(scan_name, 1, policy_id=nessus_policy_id, asset_lists=nessus_scan_asset_list)
                time.sleep(5)
                scan_list = sc.scans.list()['usable']
                scan_id = [item for item in scan_list if item["name"] == scan_name]
                nessus_scan_id = int(scan_id[0]['id'])


    result['changed'] = True
    result['output'] = "Nessus.sc Scan Name: [" + scan_name + "]"

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
