# plugins/modules/dp_unlock.py
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.radware_cc import RadwareCC

DOCUMENTATION = r'''
---
module: dp_unlock
short_description: Unlock a DefensePro device via Radware CC
options:
  provider:
    description: Connection details for Radware CC
    required: true
    type: dict
    suboptions:
      server:
        type: str
        required: true
      username:
        type: str
        required: true
      password:
        type: str
        required: true
      verify_ssl:
        type: bool
        required: false
        default: false
  device_ip:
    description: DefensePro device IP to unlock
    required: true
    type: str
'''

EXAMPLES = r'''
- name: Unlock device
  dp_unlock:
    provider:
      server: 10.105.193.3
      username: radware
      password: mypass
      verify_ssl: false
    device_ip: 10.105.192.32
'''

RETURN = r'''
status:
  description: API status response
  type: dict
  returned: always
changed:
  description: Whether configuration state changed
  type: bool
  returned: always
'''

def run_module():
    args_spec = dict(
        provider=dict(type='dict', required=True),
        device_ip=dict(type='str', required=True),
    )

    module = AnsibleModule(argument_spec=args_spec, supports_check_mode=False)

    provider = module.params['provider'] or {}
    device_ip = module.params['device_ip']

    server = provider.get('server')
    user = provider.get('username')
    password = provider.get('password')
    verify_ssl = provider.get('verify_ssl', False)

    if not all([server, user, password]):
        module.fail_json(msg="provider.server, provider.username and provider.password are required")

    try:
        cc = RadwareCC(server, user, password, verify_ssl=verify_ssl)
        resp = cc.unlock_device(device_ip)
        if isinstance(resp, dict) and resp.get("status") == "ok":
            module.exit_json(changed=True, status=resp)
        else:
            module.fail_json(msg=f"Unexpected unlock response: {resp}", status=resp)
    except Exception as e:
        module.fail_json(msg=str(e))

def main():
    run_module()

if __name__ == '__main__':
    main()
