"""
Unified Ansible module to edit DefensePro SYN protections, attach them to profiles,
and update SYN profile parameters.

- Edits existing SYN protections by ID.
- Attaches protections to profiles (POST if new, PUT if already attached).
- Updates profile parameters using verified DefensePro API structure.
"""

from ansible.module_utils.basic import AnsibleModule


def run_module():
    module_args = dict(
        provider=dict(type="dict", required=True),
        dp_ip=dict(type="str", required=True),
        syn_protections=dict(type="list", required=False, default=[]),
        syn_profiles=dict(type="list", required=False, default=[]),
    )

    result = dict(changed=False, response={})
    debug_info = {"operations": []}

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)
    provider = module.params["provider"]
    dp_ip = module.params["dp_ip"]
    syn_protections = module.params["syn_protections"]
    syn_profiles = module.params["syn_profiles"]
    check_mode = module.check_mode

    log_level = provider.get("log_level", "disabled")
    from ansible.module_utils.logger import Logger

    logger = Logger(verbosity=log_level)
    from ansible.module_utils.radware_cc import RadwareCC

    cc = RadwareCC(provider["cc_ip"], provider["username"], provider["password"], log_level=log_level, logger=logger)

    logger.debug(f"Input received: dp_ip={dp_ip}, protections={len(syn_protections)}, profiles={len(syn_profiles)}")
    debug_info["input"] = {
        "dp_ip": dp_ip,
        "protections_count": len(syn_protections),
        "profiles_count": len(syn_profiles),
    }

    try:
        changes_made = False
        edited_protections = []
        edited_profiles = []

        # ----------------------------------------------------------------------
        # Edit SYN Protections
        # ----------------------------------------------------------------------
        for protection in syn_protections:
            prot_id = protection.get("id")
            if not prot_id:
                continue

            prot_name = protection.get("name", f"id_{prot_id}")
            url = f"https://{provider['cc_ip']}/mgmt/device/byip/{dp_ip}/config/rsIDSSYNAttackTable/{prot_id}"

            body = {
                "rsIDSSYNAttackActivationThreshold": protection.get("activation_threshold"),
                "rsIDSSYNAttackTerminationThreshold": protection.get("termination_threshold"),
                "rsIDSSYNDestinationAppPortGroup": protection.get("app_port_group"),
            }

            logger.info(f"Editing SYN protection '{prot_name}' (ID {prot_id}) via PUT")

            if not check_mode:
                resp = cc._put(url, json=body)
                try:
                    data = resp.json()
                except Exception:
                    data = {"status": "ok"}
            else:
                data = {"status": "check_mode_skipped"}

            # ADDED readable protection summary
            prot_parameters = {
                "activation_threshold": protection.get("activation_threshold", "N/A"),
                "termination_threshold": protection.get("termination_threshold", "N/A"),
                "app_port_group": protection.get("app_port_group", "N/A"),
            }

            edited_protections.append(
                {
                    "id": prot_id,
                    "name": prot_name,
                    "body": body,
                    "parameters": prot_parameters,
                    "response": data,
                }
            )

            debug_info["operations"].append(
                {
                    "type": "protection_edit",
                    "id": prot_id,
                    "name": prot_name,
                    "uri": url,
                    "body": body,
                    "response": data,
                }
            )
            changes_made = True

        # ----------------------------------------------------------------------
        # Attach protections to profiles (auto PUT if exists)
        # ----------------------------------------------------------------------
        attached_map = {}  #  ADDED - track which protections were attached to which profile

        for profile in syn_profiles:
            profile_name = profile.get("name")
            protections = profile.get("protections", [])
            if not protections:
                continue

            for protection_name in protections:
                url_attach = f"https://{provider['cc_ip']}/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesTable/{profile_name}/{protection_name}"
                body_attach = {
                    "rsIDSSynProfilesName": profile_name,
                    "rsIDSSynProfileServiceName": protection_name,
                }

                if not check_mode:
                    try:
                        logger.info(f"Attaching '{protection_name}' to profile '{profile_name}'")
                        cc._post(url_attach, json=body_attach)
                    except Exception as e:
                        if "already exists" in str(e) or "M_00386" in str(e):
                            logger.debug(f"Attachment already exists, retrying with PUT for '{profile_name}'")
                            cc._put(url_attach, json=body_attach)
                        else:
                            raise
                else:
                    logger.debug(f"Check mode: skipping attach for '{profile_name}'")

                attached_map[profile_name] = protection_name  #  Track attachment

                debug_info["operations"].append(
                    {
                        "type": "profile_attach",
                        "profile": profile_name,
                        "protection": protection_name,
                        "uri": url_attach,
                        "body": body_attach,
                    }
                )
                changes_made = True

        # ----------------------------------------------------------------------
        #  Update SYN Profile Parameters
        # ----------------------------------------------------------------------
        for profile in syn_profiles:
            profile_name = profile.get("name")
            params = profile.get("params", {})

            if not params:
                logger.debug(f"No parameters to update for '{profile_name}'")
                continue

            logger.info(f"Updating SYN profile parameters for '{profile_name}'")

            param_map = {
                "action": "rsIDSSynProfilesAction",
                "tracking_mode": "rsIDSSynProfileTrackingMode",
                "activation_mode": "rsIDSSynProfileActivationMode",
                "destination_ports": "rsIDSSynProfileDestinationPorts",
                "activation_threshold": "rsIDSSynProfileActivationThreshold",
                "auth_type": "rsIDSSynProfilesParamsAuthType",
                "tcp_reset_status": "rsIDSSynProfileTCPResetStatus",
                "http_enable": "rsIDSSynProfilesParamsWebEnable",
                "http_method": "rsIDSSynProfilesParamsWebMethod",
            }

            code_map = {
                "action": {"report_only": "0", "block_and_report": "1"},
                "tracking_mode": {"per_destination": "1", "per_policy": "2"},
                "activation_mode": {"continuous": "1", "threshold_based": "2"},
                "destination_ports": {"syn_profile": "1", "all": "2"},
                "auth_type": {"safe_reset": "1", "transparent_proxy": "2"},
                "tcp_reset_status": {"enable": "1", "disable": "2"},
                "http_enable": {"enable": "1", "disable": "2"},
                "http_method": {"redirect": "1", "javascript": "2"},
            }

            skip_fields = []
            if params.get("tracking_mode") == "per_destination" or params.get("activation_mode") == "continuous":
                skip_fields.append("activation_threshold")

            body_params = {"rsIDSSynProfilesParamsName": profile_name}
            for key, val in params.items():
                if key in skip_fields:
                    logger.debug(f"Skipping '{key}' for '{profile_name}' due to mode logic")
                    continue

                field = param_map.get(key)
                if not field:
                    continue

                mapped_val = code_map.get(key, {}).get(str(val).lower(), val)
                body_params[field] = mapped_val

            url_params = (
                f"https://{provider['cc_ip']}/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesParamsTable/{profile_name}"
            )

            if not check_mode:
                resp = cc._put(url_params, json=body_params)
                try:
                    data = resp.json()
                except Exception:
                    data = {"status": "ok"}
            else:
                data = {"status": "check_mode_skipped"}

            #  ADDED — Include attached protection name
            protection_name = attached_map.get(profile_name, "N/A")

            edited_profiles.append(
                {
                    "profile_name": profile_name,
                    "protection_name": protection_name,  
                    "parameters": params,
                    "applied_body": body_params,
                    "skipped": skip_fields,
                    "response": data,
                }
            )

            debug_info["operations"].append(
                {
                    "type": "profile_edit",
                    "name": profile_name,
                    "attached_protection": protection_name,  
                    "uri": url_params,
                    "body": body_params,
                    "response": data,
                }
            )
            changes_made = True

        # ----------------------------------------------------------------------
        # Result summary
        # ----------------------------------------------------------------------
        result["changed"] = changes_made
        result["response"] = {
            "protections": edited_protections,
            "profiles": edited_profiles,
        }
        result["debug_info"] = debug_info

        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=str(e), debug_info=debug_info, **result)


def main():
    run_module()


if __name__ == "__main__":
    main()
