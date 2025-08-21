# plugins/modules/dp_bdos_profile.py
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.radware_cc import RadwareCC

DOCUMENTATION = r'''
---
module: dp_bdos_profile
short_description: Create or manage DefensePro BDOS Flood profiles
description:
  - Creates a BDOS Flood profile on Radware DefensePro via Radware CC API.
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
      - Dictionary of BDOS Flood profile attributes (human-friendly names allowed).
    type: dict
    required: true
author:
  - "Your Name"
'''

EXAMPLES = r'''
- name: Create BDOS Flood profile
  dp_bdos_profile:
    provider:
      server: 155.1.1.6
      username: radware
      password: mypass
    dp_ip: 155.1.1.7
    name: "BDOS_Test"
    params:
      TCP Status: "2"
      TCP SYN Status: "2"
      UDP Status: "1"
      IGMP Status: "1"
      ICMP Status: "1"
      TCP FIN/ACK Status: "2"
      TCP RST Status: "2"
      TCP PSH/ACK Status: "2"
      TCP SYN/ACK Status: "1"
      TCP Frag Status: "1"
      Bandwidth In: "40000"
      Bandwidth Out: "40000"
      Transparent Optimization: "2"
      Action: "1"
      Burst Enabled: "2"
      Learning Suppression Threshold: "50"
      Footprint Strictness: "1"
      Rate Limit: "0"
      Packet Report Status: "1"
      Packet Trace Status: "2"
      UDP Frag Status: "2"
      UDP Frag In Quota: "25"
      UDP Frag Out Quota: "25"
'''

RETURN = r'''
response:
  description: API response from Radware CC
  type: dict
'''

# Human-readable → API keys mapping
FIELD_MAP = {
    "TCP Status": "rsNetFloodProfileTcpStatus",
    "TCP SYN Status": "rsNetFloodProfileTcpSynStatus",
    "UDP Status": "rsNetFloodProfileUdpStatus",
    "IGMP Status": "rsNetFloodProfileIgmpStatus",
    "ICMP Status": "rsNetFloodProfileIcmpStatus",
    "TCP FIN/ACK Status": "rsNetFloodProfileTcpFinAckStatus",
    "TCP RST Status": "rsNetFloodProfileTcpRstStatus",
    "TCP PSH/ACK Status": "rsNetFloodProfileTcpPshAckStatus",
    "TCP SYN/ACK Status": "rsNetFloodProfileTcpSynAckStatus",
    "TCP Frag Status": "rsNetFloodProfileTcpFragStatus",
    "Bandwidth In": "rsNetFloodProfileBandwidthIn",
    "Bandwidth Out": "rsNetFloodProfileBandwidthOut",
    "Transparent Optimization": "rsNetFloodProfileTransparentOptimization",
    "Action": "rsNetFloodProfileAction",
    "Burst Enabled": "rsNetFloodProfileBurstEnabled",
    "Learning Suppression Threshold": "rsNetFloodProfileLearningSuppressionThreshold",
    "Footprint Strictness": "rsNetFloodProfileFootprintStrictness",
    "Rate Limit": "rsNetFloodProfileRateLimit",
    "Packet Report Status": "rsNetFloodProfilePacketReportStatus",
    "Packet Trace Status": "rsNetFloodProfilePacketTraceStatus",
    "UDP Frag Status": "rsNetFloodProfileUdpFragStatus",
    "UDP Frag In Quota": "rsNetFloodProfileUdpFragInQuota",
    "UDP Frag Out Quota": "rsNetFloodProfileUdpFragOutQuota"
}

def translate_params(params):
    """Convert human-readable keys to API keys"""
    return {FIELD_MAP.get(k, k): v for k, v in params.items()}

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
            path = f"/mgmt/device/byip/{module.params['dp_ip']}/config/rsNetFloodProfileTable/{module.params['name']}/"
            body = {"rsNetFloodProfileName": module.params['name']}
            body.update(translate_params(module.params['params']))

            url = f"https://{provider['server']}{path}"
            debug_info['request'] = {"method": "POST", "url": url, "body": body}
            logger.info(f"Creating BDOS Flood profile {module.params['name']} on {module.params['dp_ip']}")

            resp = cc._post(url, json=body)
            debug_info['response_status'] = resp.status_code
            try:
                data = resp.json()
                debug_info['response_json'] = data
            except ValueError:
                raise Exception(f"Invalid JSON response: {resp.text}")

            if resp.status_code not in [200, 201]:
                raise Exception(f"Failed to create BDOS profile: {data}")

            result['changed'] = True
            result['response'] = data

    except Exception as e:
        module.fail_json(msg=str(e), debug_info=debug_info, **result)

    result['debug_info'] = debug_info
    module.exit_json(**result)

def main():
    run_module()

if __name__ == "__main__":
    main()
