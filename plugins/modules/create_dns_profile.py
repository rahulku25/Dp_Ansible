# plugins/modules/dp_dns_profile.py
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.radware_cc import RadwareCC

DOCUMENTATION = r'''
---
module: dp_dns_profile
short_description: Create or manage DefensePro DNS Protection profiles
description:
  - Creates a DNS Protection profile on Radware DefensePro via Radware CC API.
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
  name:
    type: str
    required: true
  params:
    description:
      - Dictionary of DNS profile attributes (user-friendly names allowed).
    type: dict
    required: true
author:
  - "Your Name"
'''

EXAMPLES = r'''
- name: Create DNS Protection profile
  dp_dns_profile:
    provider:
      server: 155.1.1.6
      username: radware
      password: mypass
    dp_ip: 155.1.1.7
    name: "DNS_Demo2"
    params:
      DNS Expected Qps: "4000"
      DNS Action: "block"
      DNS Max Allow Qps: "4500"
      DNS Manual Trigger Status: "disable"
      DNS Footprint Strictness: "medium"
      DNS Packet Report Status: "enable"
      DNS Learning Suppression Threshold: "50"
'''

RETURN = r'''
response:
  description: API response from Radware CC
  type: dict
'''

# Mapping for user-friendly → Radware API keys
FIELD_MAP = {
    "DNS Expected Qps": "rsDnsProtProfileExpectedQps",
    "DNS Action": "rsDnsProtProfileAction",
    "DNS Max Allow Qps": "rsDnsProtProfileMaxAllowQps",
    "DNS Manual Trigger Status": "rsDnsProtProfileManualTriggerStatus",
    "DNS Footprint Strictness": "rsDnsProtProfileFootprintStrictness",
    "DNS Packet Report Status": "rsDnsProtProfilePacketReportStatus",
    "DNS Learning Suppression Threshold": "rsDnsProtProfileLearningSuppressionThreshold",
}

# Numeric mapping for user-friendly values
NUMERIC_MAPPING = {
    "DNS Action": {"report": 0, "block & report": 1},
    "DNS Manual Trigger Status": {"enable": 1, "disable": 2},
    "DNS Footprint Strictness": {"low": 0, "medium": 1, "high": 2},
    "DNS Packet Report Status": {"enable": 1, "disable": 2},
}


def translate_params(params):
    """Convert user-friendly keys and values to Radware API format."""
    translated = {}
    for k, v in params.items():
        api_key = FIELD_MAP.get(k, k)
        if k in NUMERIC_MAPPING:
            # Convert friendly value to integer
            translated[api_key] = NUMERIC_MAPPING[k][str(v).lower()]
        else:
            # Use integer if numeric, else keep as-is
            translated[api_key] = int(v) if str(v).isdigit() else v
    return translated


def run_module():
    module_args = dict(
        provider=dict(type='dict', required=True),
        dp_ip=dict(type='str', required=True),
        name=dict(type='str', required=True),
        params=dict(type='dict', required=True)
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
            # Path for DNS profiles
            path = f"/mgmt/device/byip/{module.params['dp_ip']}/config/rsDnsProtProfileTable/{module.params['name']}"
            body = {"rsDnsProtProfileName": module.params['name']}
            body.update(translate_params(module.params['params']))

            url = f"https://{provider['server']}{path}"
            debug_info = {
                'method': 'POST',
                'url': url,
                'body': body
            }
            logger.info(f"Creating DNS Protection profile {module.params['name']} on device {module.params['dp_ip']}")
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
