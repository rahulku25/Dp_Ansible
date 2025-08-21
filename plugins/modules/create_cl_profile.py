# plugins/modules/dp_connection_limit_profile_attack.py
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.radware_cc import RadwareCC

DOCUMENTATION = r'''
---
module: dp_connection_limit_profile_attack
short_description: Attach an IDS Connection Limit Attack to a Connection Limit Profile
description:
  - Attaches an existing IDS Connection Limit Attack to a Connection Limit Profile
    on Radware DefensePro via Radware CC API.
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
  dp_ip:
    type: str
    required: true
  profile_name:
    description: Name of the Connection Limit Profile
    type: str
    required: true
  attack_name:
    description: Name of the Attack being attached
    type: str
    required: true
  attack_id:
    description: Attack ID
    type: str
    required: true
author:
  - "Your Name"
'''

EXAMPLES = r'''
- name: Attach existing CL attack to profile
  dp_connection_limit_profile_attack:
    provider:
      server: 155.1.1.6
      username: radware
      password: mypass
    dp_ip: 155.1.1.7
    profile_name: "Test"
    attack_name: "Test_1"
    attack_id: "450019"
'''

RETURN = r'''
response:
  description: API response from Radware CC
  type: dict
'''

def run_module():
    module_args = dict(
        provider=dict(type='dict', required=True),
        dp_ip=dict(type='str', required=True),
        profile_name=dict(type='str', required=True),
        attack_name=dict(type='str', required=True),
        attack_id=dict(type='str', required=True),
    )

    result = dict(changed=False, response={})
    debug_info = {}

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)
    provider = module.params['provider']
    log_level = provider.get('log_level', 'disabled')

    from ansible.module_utils.logger import Logger
    logger = Logger(verbosity=log_level)

    try:
        cc = RadwareCC(provider['server'], provider['username'], provider['password'],
                       log_level=log_level, logger=logger)

        if not module.check_mode:
            # ✅ Correct API path
            path = f"/mgmt/device/byip/{module.params['dp_ip']}/config/rsIDSConnectionLimitProfileTable/{module.params['profile_name']}/{module.params['attack_name']}"

            body = {
                "rsIDSConnectionLimitProfileName": module.params['profile_name'],
                "rsIDSConnectionLimitProfileAttackName": module.params['attack_name'],
                "rsIDSConnectionLimitProfileAttackId": module.params['attack_id'],
            }

            url = f"https://{provider['server']}{path}"
            debug_info = {
                'method': 'POST',
                'url': url,
                'body': body
            }

            logger.info(f"Attaching attack {module.params['attack_name']} (ID {module.params['attack_id']}) "
                        f"to profile {module.params['profile_name']} on device {module.params['dp_ip']}")
            logger.debug(f"Request: {debug_info}")

            resp = cc._post(url, json=body)
            logger.debug(f"Response status: {resp.status_code}")

            try:
                data = resp.json()
                logger.debug(f"Response JSON: {data}")
            except ValueError:
                logger.error(f"Invalid JSON response: {resp.text}")
                raise Exception(f"Invalid JSON response: {resp.text}")

            result['response'] = data
            result['changed'] = True
            debug_info['response_status'] = resp.status_code
            debug_info['response_json'] = data

    except Exception as e:
        logger.error(f"Exception: {str(e)}")
        module.fail_json(msg=str(e), debug_info=debug_info, **result)

    result['debug_info'] = debug_info
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
