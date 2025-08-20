# plugins/modules/dp_lock.py
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.radware_cc import RadwareCC

DOCUMENTATION = r'''
---
module: dp_lock
short_description: Lock a DefensePro device via Radware CC
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
  dp_ip:
    description: DefensePro device IP to lock
    required: true
    type: str
'''

EXAMPLES = r'''
- name: Lock device
  dp_lock:
    provider:
      server: 10.105.193.3
      username: radware
      password: mypass
      verify_ssl: false
    dp_ip: 10.105.192.32
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
        dp_ip=dict(type='str', required=True),
    )

    module = AnsibleModule(argument_spec=args_spec, supports_check_mode=False)

    provider = module.params['provider'] or {}
    dp_ip = module.params['dp_ip']

    server = provider.get('server')
    user = provider.get('username')
    password = provider.get('password')
    verify_ssl = provider.get('verify_ssl', False)

    if not all([server, user, password]):
        module.fail_json(msg="provider.server, provider.username and provider.password are required")

    from ansible.module_utils.logger import Logger
    log_level = provider.get('log_level', 'disabled')
    logger = Logger(verbosity=log_level)
    debug_info = {}
    try:
      cc = RadwareCC(server, user, password, verify_ssl=verify_ssl, log_level=log_level, logger=logger)
      url = f"https://{server}/mgmt/system/config/tree/device/byip/{dp_ip}/lock"
      debug_info = {
        'method': 'POST',
        'url': url,
        'body': None
      }
      logger.info(f"Locking device {dp_ip} on server {server}")
      logger.debug(f"Request: {debug_info}")
      resp = cc._post(url)
      logger.debug(f"Response status: {resp.status_code}")
      data = resp.json()
      logger.debug(f"Response JSON: {data}")
      if isinstance(data, dict) and data.get("status") == "ok":
        debug_info['response_status'] = resp.status_code
        debug_info['response_json'] = data
        module.exit_json(changed=True, status=data, debug_info=debug_info)
      else:
        logger.error(f"Unexpected lock response: {data}")
        module.fail_json(msg=f"Unexpected lock response: {data}", status=data, debug_info=debug_info)
    except Exception as e:
      logger.error(f"Exception: {str(e)}")
      module.fail_json(msg=str(e), debug_info=debug_info)

def main():
    run_module()

if __name__ == '__main__':
    main()
