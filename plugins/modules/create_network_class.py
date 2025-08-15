# plugins/modules/dp_network_class.py
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.radware_cc import RadwareCC

DOCUMENTATION = r'''
---
module: dp_network_class
short_description: Create or manage DefensePro network classes
description:
  - Creates a network class and adds network groups on Radware DefensePro via Radware CC API.
options:
  provider:
    description:
      - Dictionary with connection parameters.
    type: dict
    required: true
    suboptions:
      server:
        description: CC IP address
        type: str
        required: true
      username:
        type: str
        required: true
      password:
        type: str
        required: true
  device_ip:
    type: str
    required: true
  class_name:
    type: str
    required: true
  address:
    type: str
    required: true
  mask:
    type: str
    required: true
  index:
    type: int
    default: 0
'''

EXAMPLES = r'''
- name: Create a network class
  dp_network_class:
    provider:
      server: 10.105.193.3
      username: radware
      password: mypass
    device_ip: 10.105.192.32
    class_name: my_network_class
    address: 192.168.1.0
    mask: 255.255.255.0
    index: 0
'''

RETURN = r'''
response:
  description: API response from Radware CC
  type: dict
'''

def run_module():
    module_args = dict(
        provider=dict(type='dict', required=True),
        device_ip=dict(type='str', required=True),
        class_name=dict(type='str', required=True),
        address=dict(type='str', required=True),
        mask=dict(type='str', required=True),
        index=dict(type='int', required=False, default=0)
    )

    result = dict(changed=False, response={})
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    provider = module.params['provider']

    try:
        cc = RadwareCC(provider['server'], provider['username'], provider['password'])
        if not module.check_mode:
            resp = cc.create_network_group(
                module.params['device_ip'],
                module.params['class_name'],
                module.params['address'],
                module.params['mask'],
                module.params['index']
            )
            result['response'] = resp
            result['changed'] = True
    except Exception as e:
        module.fail_json(msg=str(e), **result)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
