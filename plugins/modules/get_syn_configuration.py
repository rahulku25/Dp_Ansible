"""
Ansible module to fetch DefensePro SYN profiles, protections, and parameters in order: profile → protections → parameters.
"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.logger import Logger
from ansible.module_utils.radware_cc import RadwareCC

def run_module():
    module_args = dict(
        provider=dict(type='dict', required=True),
        dp_ip=dict(type='str', required=True),
        filter_syn_profile_names=dict(type='list', required=False, default=[]),
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)
    provider = module.params['provider']
    dp_ip = module.params['dp_ip']
    filter_syn_profile_names = module.params['filter_syn_profile_names']

    log_level = provider.get('log_level', 'disabled')
    logger = Logger(verbosity=log_level)

    # Mappings for user-friendly values
    auth_type_map = {1: "safe_reset", 2: "transparent_proxy"}
    http_auth_status = {1: "enable", 2: "disable"}
    http_auth_method = {1: "redirect", 2: "javaScript"}
    tcp_reset_map = {1: "enable", 2: "disable"}
    ssl_mitigation_map = {1: "enable", 2: "disable"}
    action_map = {0: "report_only", 1: "block_and_report"}
    tracking_mode_map = {1: "per_destination", 2: "per_policy"}
    destination_ports_map = {1: "syn_profile", 2: "all"}
    activation_mode_map = {1: "continuous", 2: "threshold_based"}

    result = dict(changed=False, profiles=[], debug_info={})
    debug_info = {}

    try:
        logger.info("=" * 60)
        cc_ip = provider['cc_ip']
        logger.info(f"Starting SYN configuration fetch for device {dp_ip} on CC {cc_ip}")

        cc = RadwareCC(cc_ip, provider['username'], provider['password'],
                       verify_ssl=provider.get('verify_ssl', False),
                       log_level=log_level, logger=logger)

        # ---------------- Fetch SYN Protections ----------------
        prot_url = f"https://{cc_ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSYNAttackTable"
        logger.info(f"Fetching SYN protections from {dp_ip}")
        logger.debug(f"Request: {{'method': 'GET', 'url': '{prot_url}'}}")
        prot_resp = cc._get(prot_url)
        logger.debug(f"Response status: {prot_resp.status_code}")
        try:
            prot_json = prot_resp.json()
            logger.debug(f"Response JSON: {prot_json}")
        except Exception:
            logger.debug(f"Response text: {prot_resp.text[:500]}")
            prot_json = {}
        syn_protections = prot_json.get('rsIDSSYNAttackTable', [])
        prot_by_name = {p.get('rsIDSSYNAttackName'): p for p in syn_protections}
        debug_info['syn_protections_count'] = len(syn_protections)

        # ---------------- Fetch SYN Profiles ----------------
        prof_url = f"https://{cc_ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesTable"
        logger.info(f"Fetching SYN profiles from {dp_ip}")
        logger.debug(f"Request: {{'method': 'GET', 'url': '{prof_url}'}}")
        prof_resp = cc._get(prof_url)
        logger.debug(f"Response status: {prof_resp.status_code}")
        try:
            prof_json = prof_resp.json()
            logger.debug(f"Response JSON: {prof_json}")
        except Exception:
            logger.debug(f"Response text: {prof_resp.text[:500]}")
            prof_json = {}
        syn_profiles = prof_json.get('rsIDSSynProfilesTable', [])
        debug_info['syn_profiles_count'] = len(syn_profiles)

        # ---------------- Fetch SYN Profile Parameters ----------------
        params_url = f"https://{cc_ip}/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesParamsTable"
        logger.info(f"Fetching SYN profile parameters from {dp_ip}")
        logger.debug(f"Request: {{'method': 'GET', 'url': '{params_url}'}}")
        params_resp = cc._get(params_url)
        logger.debug(f"Response status: {params_resp.status_code}")
        try:
            params_json = params_resp.json()
            logger.debug(f"Response JSON: {params_json}")
        except Exception:
            logger.debug(f"Response text: {params_resp.text[:500]}")
            params_json = {}
        syn_profile_params = params_json.get('rsIDSSynProfilesParamsTable', [])
        params_by_name = {p.get('rsIDSSynProfilesParamsName'): p for p in syn_profile_params}
        debug_info['syn_profile_params_count'] = len(syn_profile_params)

        # ---------------- Build structured output ----------------
        all_profiles = []
        for profile in syn_profiles:
            profile_name = profile.get('rsIDSSynProfilesName', 'DEFAULT_PROFILE')
            protection_name = profile.get('rsIDSSynProfileServiceName')

            # Profile info
            profile_info = {'profile_name': profile_name}

            # Protections (list of dicts)
            prot_details = prot_by_name.get(protection_name, {})
            protections = [{
                'protection_name': protection_name,
                'protection_id': prot_details.get('rsIDSSYNAttackId'),
                'activation_threshold': prot_details.get('rsIDSSYNAttackActivationThreshold'),
                'termination_threshold': prot_details.get('rsIDSSYNAttackTerminationThreshold'),
                'app_port_group': prot_details.get('rsIDSSYNDestinationAppPortGroup')
            }]

            # Parameters (user-friendly)
            params_raw = params_by_name.get(profile_name, {})
            parameters = {
                'AuthType': auth_type_map.get(int(params_raw.get('rsIDSSynProfilesParamsAuthType', 1)), 'N/A'),
                'WebEnable': http_auth_status.get(int(params_raw.get('rsIDSSynProfilesParamsWebEnable', 2)), 'N/A'),
                'WebMethod': http_auth_method.get(int(params_raw.get('rsIDSSynProfilesParamsWebMethod', 1)), 'N/A'),
                'TCPResetStatus': tcp_reset_map.get(int(params_raw.get('rsIDSSynProfileTCPResetStatus', 2)), 'N/A'),
                'SSLMitigationStatus': ssl_mitigation_map.get(int(params_raw.get('rsIDSSynProfilesSSLMitigationStatus', 2)), 'N/A'),
                'Action': action_map.get(int(params_raw.get('rsIDSSynProfilesAction', 1)), 'N/A'),
                'TrackingMode': tracking_mode_map.get(int(params_raw.get('rsIDSSynProfileTrackingMode', 1)), 'N/A'),
                'ActivationThreshold': int(params_raw.get('rsIDSSynProfileActivationThreshold', 1500)),
                'DestinationPorts': destination_ports_map.get(int(params_raw.get('rsIDSSynProfileDestinationPorts', 1)), 'N/A'),
                'ActivationMode': activation_mode_map.get(int(params_raw.get('rsIDSSynProfileActivationMode', 2)), 'N/A')
            }

            profile_struct = {
                'profile': profile_info,
                'protections': protections,
                'parameters': parameters
            }
            all_profiles.append(profile_struct)

        # Apply optional filtering
        if filter_syn_profile_names:
            filtered = [p for p in all_profiles if p['profile']['profile_name'] in filter_syn_profile_names]
            result['profiles'] = filtered
            debug_info.update({
                'filter_applied': True,
                'filter_syn_profile_names': filter_syn_profile_names,
                'filtered_count': len(filtered),
                'total_count': len(all_profiles)
            })
        else:
            result['profiles'] = all_profiles
            debug_info.update({
                'filter_applied': False,
                'total_count': len(all_profiles)
            })

        result['debug_info'] = debug_info
        logger.info(f"Completed SYN configuration fetch for {dp_ip}")
        logger.info("=" * 60)
        module.exit_json(**result)

    except Exception as e:
        logger.error(f"Exception: {str(e)}")
        logger.info("=" * 60)
        module.fail_json(msg=str(e), debug_info=debug_info or {})

def main():
    run_module()

if __name__ == '__main__':
    main()
