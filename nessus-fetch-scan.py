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
module: Nessus.sc fetch scan results module
short_description: Fetch Nessus.sc scan results
description:
    - Nessus.sc scan results are in SCAP (XML) format
    - This module connects and retrieves the scan results of a given scan name
    - The resulting file will be located in the same folder where the playbook runs from
    - Scan results file name: scan_name.nessus
version_added: "2.4"
author: Jesus Fonteboa (@hiperesfera)
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
            - username with perms to fetch the scan results from the Nessus.sc server
        required: true
    password:
        description:
            - username password
        required: true
notes:
requirements:
    - Requires the following module to be installed pyTenable
    - Tested with Ansible 2.8.6 version and Python 2.7.16
'''

EXAMPLES = '''
- name: Fetch Nessus.sc scan results
  nessus-scan-results
      scan_name: "DMZ Servers"
      server: Nessus.sc server
      username: api_nessus
      password: **********
  register: output
'''

RETURN = '''
changed:
    description: If changed or not (true if results completed)
    type: bool
output:
    description: Nessus scan results location path
    type: JSON
'''


import zipfile
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
from tenable.sc import TenableSC

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
        return result


    scan_name = module.params['scan_name']
    server = module.params['server']
    nessus_username = module.params['nessus_username']
    nessus_password = module.params['nessus_password']


    try:
        sc = TenableSC(server)
        sc.login(nessus_username, nessus_password)
    except:
        module.fail_json(msg='Issues connectin to Nessus.sc. Please check connectivity and credetials')



    scan_list = sc.scan_instances.list(start_time=1)['usable']
    temp_scan_id = [item for item in scan_list if item["name"] == scan_name]

    if temp_scan_id:
        scan_id = int(temp_scan_id[-1]['id'])
    else:
        scan_id = None

    # check scan is COMPLETED and not in PARTIAL or RUNNING state
    scan_status = sc.scan_instances.details(scan_id)['status']
    if scan_status.lower() != 'completed':
      module.fail_json(msg='Nesuss scan has not been COMPLETED. Scan status: ' + str(scan_status))

    try:
      report_name =  re.sub('[\s+]','_',scan_name+'_report.zip')
      p = open(report_name,'wb')
      sc.scan_instances.export_scan(scan_id, p)
      time.sleep(2)
      p.close()

      time.sleep(2)
      with zipfile.ZipFile(report_name, 'r') as zip_ref:
          zip_ref.extract(str(scan_id) + '.nessus','./')
      time.sleep(2)
    except:
      module.fail_json(msg='Issues fetching or extracting the Nessus scan results')


    # cleaning up the temp files and renaming

    os.rename( str(scan_id) + '.nessus', scan_name + '.nessus')
    os.remove(report_name)


    result['changed'] = True
    result['output'] = scan_name + '.nessus'

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
