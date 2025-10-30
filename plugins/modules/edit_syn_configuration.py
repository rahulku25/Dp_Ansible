# plugins/modules/edit_syn_configuration.py
"""
Unified Ansible module to edit DefensePro SYN protections and profiles.
"""

from ansible.module_utils.basic import AnsibleModule

def map_syn_input_to_user_friendly(prot):
    """Convert SYN protection API fields into user-friendly format"""
    return {
        "protection_name": prot.get("name"),
        "activation_threshold": prot.get("activation_threshold"),
        "termination_threshold": prot.get("termination_threshold"),
        "app_port_group": prot.get("app_port_group")
    }

def pretty_syn_protections(protections):
    if not protections:
        return "  No protections edited."
    lines = []
    for prot in protections:
        lines.append(f"  - Protection: {prot['protection_name']}")
        for k, v in prot['user_friendly'].items():
            if k != "protection_name":
                lines.append(f"    - {k.replace('_',' ').capitalize()}: {v}")
        lines.append("")
    return "\n".join(lines)

def pretty_syn_profiles(profiles):
    if not profiles:
        return "  No profiles edited."
    lines = []
    for prof in profiles:
        lines.append(f"  - Profile: {prof['profile_name']} (Protection: {prof['protection_name']})")
        for k, v in prof['parameters'].items():
            lines.append(f"    - {k.replace('_',' ').capitalize()}: {v}")
        lines.append("")
    return "\n".join(lines)

def run_module():
    module_args = dict(
        provider=dict(type='dict', required=True),
        dp_ip=dict(type='str', required=True),
        syn_protections=dict(type='list', required=False, default=[]),
        syn_profiles=dict(type='list', required=False, default=[])
    )

    result = dict(changed=False, response={}, debug_info={})
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    provider = module.params['provider']
    dp_ip = module.params['dp_ip']
    syn_protections = module.params['syn_protections']
    syn_profiles = module.params['syn_profiles']

    log_level = provider.get('log_level', 'disabled')
    from ansible.module_utils.logger import Logger
    logger = Logger(verbosity=log_level)

    try:
        from ansible.module_utils.radware_cc import RadwareCC
        cc = RadwareCC(provider['cc_ip'], provider['username'], provider['password'], log_level=log_level, logger=logger)

        changes_made = False
        edited_protections = []
        edited_profiles = []
        errors = []

        check_mode = module.check_mode

        # === Edit SYN protections ===
        for prot in syn_protections:
            protection_name = prot.get("name")
            if not protection_name:
                errors.append("SYN protection requires 'name'")
                continue

            payload = {
                "rsIDSSYNAttackName": protection_name,
                "rsIDSSYNAttackActivationThreshold": prot.get("activation_threshold", 1000),
                "rsIDSSYNAttackTerminationThreshold": prot.get("termination_threshold", 500),
                "rsIDSSYNDestinationAppPortGroup": prot.get("app_port_group", "")
            }
            url = f"https://{provider['cc_ip']}/mgmt/device/byip/{dp_ip}/config/rsIDSSYNAttackTable/0"

            if not check_mode:
                logger.info(f"Editing SYN protection '{protection_name}' at URL: {url}")
                resp = cc._put(url, json=payload)
                try:
                    data = resp.json()
                except Exception:
                    data = {"raw_text": resp.text}
            else:
                data = {"status": "check_mode_skipped"}

            edited_protections.append({
                "protection_name": protection_name,
                "user_friendly": map_syn_input_to_user_friendly(prot),
                "request": {"method": "PUT", "uri": url, "body": payload},
                "response": data
            })
            changes_made = True

        # === Edit SYN profiles ===
        FIELD_MAP = {
            "profile_type": "rsIDSSynProfileType",
            "auth_type": "rsIDSSynProfilesParamsAuthType",
            "http_enable": "rsIDSSynProfilesParamsWebEnable",
            "http_method": "rsIDSSynProfilesParamsWebMethod",
            "tcp_reset_status": "rsIDSSynProfileTCPResetStatus",
            "ssl_mitigation_status": "rsIDSSynProfilesSSLMitigationStatus",
            "action": "rsIDSSynProfilesAction",
            "tracking_mode": "rsIDSSynProfileTrackingMode",
            "destination_ports": "rsIDSSynProfileDestinationPorts",
            "activation_mode": "rsIDSSynProfileActivationMode",
            "activation_threshold": "rsIDSSynProfileActivationThreshold"
        }

        VALUE_MAP = {
            "profile_type": {"syn_protection": 4},
            "auth_type": {"safe_reset": 1, "transparent_proxy": 2},
            "http_enable": {"enable": 1, "disable": 2},
            "http_method": {"redirect": 1, "javascript": 2},
            "tcp_reset_status": {"enable": 1, "disable": 2},
            "ssl_mitigation_status": {"enable": 1, "disable": 2},
            "action": {"report_only": 0, "block_and_report": 1},
            "tracking_mode": {"per_destination": 1, "per_policy": 2},
            "destination_ports": {"syn_profile": 1, "all": 2},
            "activation_mode": {"continuous": 1, "threshold_based": 2}
        }

        for profile in syn_profiles:
            profile_name = profile.get("name")
            protections = profile.get("protections", [])
            params = profile.get("params", {})

            for protection_name in protections:
                # URL for profile parameters
                body_params = {"rsIDSSynProfilesParamsName": profile_name}
                profile_output_params = {}

                tracking_mode_val = str(params.get("tracking_mode", "per_policy")).lower()
                activation_mode_val = str(params.get("activation_mode", "continuous")).lower()

                for key, val in params.items():
                    # Skip http_method if http_enable != enable
                    if key == "http_method" and str(params.get("http_enable")).lower() != "enable":
                        profile_output_params[key] = "skipped (http_enable not enabled)"
                        continue
                    # Skip activation_threshold if activation_mode != threshold_based
                    if key == "activation_threshold" and activation_mode_val != "threshold_based":
                        profile_output_params[key] = "skipped (continuous mode)"
                        continue

                    field_name = FIELD_MAP.get(key, key)
                    mapped_val = VALUE_MAP.get(key, {}).get(str(val).lower(), str(val))
                    body_params[field_name] = mapped_val
                    profile_output_params[key] = val

                url_params = f"https://{provider['cc_ip']}/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesParamsTable/{profile_name}"

                if not check_mode:
                    logger.info(f"Editing SYN profile '{profile_name}' for protection '{protection_name}' at URL: {url_params}")
                    resp_params = cc._put(url_params, json=body_params)
                    try:
                        data_params = resp_params.json()
                    except Exception:
                        data_params = {"raw_text": resp_params.text}
                else:
                    data_params = {"status": "check_mode_skipped"}

                edited_profiles.append({
                    "profile_name": profile_name,
                    "protection_name": protection_name,
                    "parameters": profile_output_params,
                    "request": {"method": "PUT", "uri": url_params, "body": body_params},
                    "response": data_params
                })
                changes_made = True

        result.update({
            "changed": changes_made,
            "response": {
                "protections": edited_protections,
                "profiles": edited_profiles,
                "summary": {
                    "total_protections_attempted": len(edited_protections),
                    "total_profiles_attempted": len(edited_profiles),
                    "protections_edited": len(edited_protections),
                    "profiles_edited": len(edited_profiles),
                },
                "pretty_protections": pretty_syn_protections(edited_protections),
                "pretty_profiles": pretty_syn_profiles(edited_profiles)
            }
        })

        if errors:
            module.fail_json(msg=f"SYN edit completed with {len(errors)} error(s).", **result)

        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=f"SYN edit failed: {str(e)}", **result)


def main():
    run_module()


if __name__ == "__main__":
    main()
