"""
Unified Ansible module to manage DefensePro SYN protections and profiles.
"""

from ansible.module_utils.basic import AnsibleModule

def run_module():
    module_args = dict(
        provider=dict(type='dict', required=True),
        dp_ip=dict(type='str', required=True),
        syn_protections=dict(type='list', required=False, default=[]),
        syn_profiles=dict(type='list', required=False, default=[])
    )

    result = dict(changed=False, response={})
    debug_info = {"operations": []}
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    provider = module.params['provider']
    dp_ip = module.params['dp_ip']
    syn_protections = module.params['syn_protections']
    syn_profiles = module.params['syn_profiles']

    log_level = provider.get('log_level', 'disabled')
    from ansible.module_utils.logger import Logger
    logger = Logger(verbosity=log_level)

    logger.debug(f"Module input: dp_ip={dp_ip}, protections_count={len(syn_protections)}, profiles_count={len(syn_profiles)}")
    debug_info['input'] = {'dp_ip': dp_ip, 'protections_count': len(syn_protections), 'profiles_count': len(syn_profiles)}

    try:
        from ansible.module_utils.radware_cc import RadwareCC
        cc = RadwareCC(provider['cc_ip'], provider['username'],
                       provider['password'], log_level=log_level, logger=logger)

        changes_made = False
        created_protections = []
        created_profiles = []

        check_mode = module.check_mode

        # Create protections first
        for protection in syn_protections:
            protection_name = protection.get('name', 'unnamed_protection')
            body = {
                "rsIDSSYNAttackName": protection_name,
                "rsIDSSYNAttackActivationThreshold": protection.get("activation_threshold", 1000),
                "rsIDSSYNAttackTerminationThreshold": protection.get("termination_threshold", 500),
                "rsIDSSYNDestinationAppPortGroup": protection.get("app_port_group", "")
            }

            url = f"https://{provider['cc_ip']}/mgmt/device/byip/{dp_ip}/config/rsIDSSYNAttackTable/0"

            if not check_mode:
                logger.info(f"Creating SYN protection '{protection_name}' at URL: {url}")
                resp = cc._post(url, json=body)
                try:
                    data = resp.json()
                except Exception:
                    data = {"raw_text": resp.text}
                refresh_device_state(cc, dp_ip, provider, logger)
            else:
                data = {"status": "check_mode_skipped"}

            created_protections.append({
                'name': protection_name,
                'parameters': {
                    "activation_threshold": body["rsIDSSYNAttackActivationThreshold"],
                    "termination_threshold": body["rsIDSSYNAttackTerminationThreshold"],
                    "app_port_group": body["rsIDSSYNDestinationAppPortGroup"]
                },
                'request': {"method": "POST", "uri": url, "body": body},
                'response': data
            })

            debug_info['operations'].append({
                "type": "protection_create",
                "name": protection_name,
                "method": "POST",
                "uri": url,
                "request_body": body,
                "response": data
            })

            changes_made = True

        # Profile FIELD & VALUE mapping
        FIELD_MAP = {
            "profile_type": "rsIDSSynProfileType",
            "auth_type": "rsIDSSynProfilesParamsAuthType",
            "web_enable": "rsIDSSynProfilesParamsWebEnable",
            "web_method": "rsIDSSynProfilesParamsWebMethod",
            "tcp_reset_status": "rsIDSSynProfileTCPResetStatus",
            "ssl_mitigation_status": "rsIDSSynProfilesSSLMitigationStatus",
            "action": "rsIDSSynProfilesAction",
            "tracking_mode": "rsIDSSynProfileTrackingMode",
            "destination_ports": "rsIDSSynProfileDestinationPorts",
            "activation_mode": "rsIDSSynProfileActivationMode",
            "activation_threshold": "rsIDSSynProfileActivationThreshold"  # profile threshold
        }

        VALUE_MAP = {
            "profile_type": {"syn_protection": 4},
            "auth_type": {"safe_reset": 1, "transparent_proxy": 2},
            "web_enable": {"enable": 1, "disable": 2},
            "web_method": {"redirect": 1, "javascript": 2},
            "tcp_reset_status": {"enable": 1, "disable": 2},
            "ssl_mitigation_status": {"enable": 1, "disable": 2},
            "action": {"report_only": 0, "block_and_report": 1},
            "tracking_mode": {"per_destination": 1, "per_policy": 2},
            "destination_ports": {"syn_profile": 1, "all": 2},
            "activation_mode": {"continuous": 1, "threshold_based": 2}
        }

        # Create profiles
        for profile in syn_profiles:
            profile_name = profile.get('name', 'unnamed_profile')
            protections = profile.get('protections', [])
            params = profile.get('params', {})

            for protection_name in protections:
                # Create profile entry
                body_profile = {
                    "rsIDSSynProfilesName": profile_name,
                    "rsIDSSynProfileServiceName": protection_name
                }
                url_profile = f"https://{provider['cc_ip']}/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesTable/{profile_name}/{protection_name}"

                if not check_mode:
                    logger.info(f"Creating SYN profile '{profile_name}' for protection '{protection_name}' at URL: {url_profile}")
                    resp_profile = cc._post(url_profile, json=body_profile)
                    try:
                        data_profile = resp_profile.json()
                    except Exception:
                        data_profile = {"raw_text": resp_profile.text}
                    refresh_device_state(cc, dp_ip, provider, logger)
                else:
                    data_profile = {"status": "check_mode_skipped"}

                debug_info['operations'].append({
                    "type": "profile_create",
                    "profile": profile_name,
                    "protection": protection_name,
                    "method": "POST",
                    "uri": url_profile,
                    "request_body": body_profile,
                    "response": data_profile
                })

                # Build profile parameters
                body_params = {"rsIDSSynProfilesParamsName": profile_name}
                profile_output_params = {}

                tracking_mode_val = str(params.get("tracking_mode", "per_policy")).lower()
                activation_mode_val = str(params.get("activation_mode", "continuous")).lower()

                for key, val in params.items():
                    # Web method only if web_enable is "enable"
                    if key == "web_method" and str(params.get("web_enable")).lower() != "enable":
                        logger.debug(f"Skipping web_method for profile '{profile_name}' because web_enable is not enabled")
                        continue

                    # Profile activation threshold: only if threshold_based
                    if key == "activation_threshold":
                        if activation_mode_val == "threshold_based":
                            body_params[FIELD_MAP[key]] = str(val)
                            profile_output_params[key] = val
                            logger.info(f"Profile '{profile_name}': Using profile_activation_threshold={val} (threshold_based mode)")
                        else:
                            profile_output_params[key] = "skipped (continuous mode)"
                            logger.debug(f"Skipping profile_activation_threshold for profile '{profile_name}' (continuous mode)")
                        continue

                    # Auth fields only if tracking_mode is per_destination
                    if key in ["auth_type", "web_enable", "web_method"] and tracking_mode_val != "per_destination":
                        profile_output_params[key] = f"skipped (tracking_mode={tracking_mode_val})"
                        logger.debug(f"Skipping auth field '{key}' for profile '{profile_name}' (tracking_mode={tracking_mode_val})")
                        continue

                    field_name = FIELD_MAP.get(key, key)
                    mapped_val = VALUE_MAP.get(key, {}).get(str(val).lower(), str(val))
                    body_params[field_name] = mapped_val
                    profile_output_params[key] = val
                    logger.info(f"Profile '{profile_name}' param '{key}': API field='{field_name}', value='{mapped_val}'")

                url_params = f"https://{provider['cc_ip']}/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesParamsTable/{profile_name}"

                if not check_mode:
                    resp_params = cc._put(url_params, json=body_params)
                    try:
                        data_params = resp_params.json()
                    except Exception:
                        data_params = {"raw_text": resp_params.text}
                    refresh_device_state(cc, dp_ip, provider, logger)
                else:
                    data_params = {"status": "check_mode_skipped"}

                created_profiles.append({
                    'profile_name': profile_name,
                    'protection_name': protection_name,
                    'parameters': profile_output_params,
                    'request': {"method": "PUT", "uri": url_params, "body": body_params},
                    'response': data_params
                })

                debug_info['operations'].append({
                    "type": "profile_update",
                    "profile": profile_name,
                    "protection": protection_name,
                    "method": "PUT",
                    "uri": url_params,
                    "request_body": body_params,
                    "response": data_params
                })

                changes_made = True

        result['changed'] = changes_made
        result['response'] = {
            'protections': created_protections,
            'profiles': created_profiles,
            'summary': {
                'total_protections_attempted': len(created_protections),
                'total_profiles_attempted': len(created_profiles),
                'protections_created': len(created_protections),
                'profiles_created': len(created_profiles),
                'operations_completed': changes_made
            }
        }
        result['debug_info'] = debug_info
        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=str(e), debug_info=debug_info, **result)


def refresh_device_state(cc, dp_ip, provider, logger):
    """Refresh device state to avoid API caching issues."""
    try:
        url = f"https://{provider['cc_ip']}/mgmt/device/byip/{dp_ip}/config/rsIDSSYNAttackTable"
        resp = cc._get(url)
        logger.debug(f"Refreshed device state for {dp_ip} (status {resp.status_code})")
    except Exception as e:
        logger.debug(f"State refresh failed (non-critical): {str(e)}")


def main():
    run_module()


if __name__ == '__main__':
    main()
