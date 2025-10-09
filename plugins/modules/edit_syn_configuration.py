# plugins/modules/edit_syn_protection.py
"""
Unified Ansible module to edit DefensePro SYN protections and attach protections to SYN profiles.

Features:
- Edits existing SYN protections (partial updates supported).
- Edits SYN profile parameters.
- Attaches protections to SYN profiles.
- Outputs human-readable profile parameters (no numeric codes).
- Provides structured debug info including METHOD, URI, Response Code, and response data.
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.radware_cc import RadwareCC
from ansible.module_utils.logger import Logger

def run_module():
    module_args = dict(
        provider=dict(type="dict", required=True),
        dp_ip=dict(type="str", required=True),
        edit_syn_protections=dict(type="list", required=False, default=[]),
        edit_syn_profiles=dict(type="list", required=False, default=[]),
    )

    result = dict(changed=False, results=[], debug_info={})
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    provider = module.params["provider"]
    dp_ip = module.params["dp_ip"]
    edit_syn_protections = module.params["edit_syn_protections"]
    edit_syn_profiles = module.params["edit_syn_profiles"]

    log_level = provider.get("log_level", "disabled")
    logger = Logger(verbosity=log_level)
    cc = RadwareCC(
        provider["cc_ip"],
        provider["username"],
        provider["password"],
        log_level=log_level,
        logger=logger,
    )

    # Mapping for human-readable output
    REVERSE_VALUE_MAP = {
        "auth_type": {1: "safe_reset", 2: "transparent_proxy"},
        "web_enable": {1: "enable", 2: "disable"},
        "web_method": {1: "redirect", 2: "javascript"},
        "tcp_reset_status": {1: "enable", 2: "disable"},
        "ssl_mitigation_status": {1: "enable", 2: "disable"},
        "action": {0: "report_only", 1: "block_and_report"},
        "tracking_mode": {1: "per_destination", 2: "per_policy"},
        "destination_ports": {1: "syn_profile", 2: "all"},
        "activation_mode": {1: "continuous", 2: "threshold_based"},
    }

    any_changed = False
    debug_info = {"device": dp_ip, "protections": [], "profiles": []}

    try:
        # ---------------------------
        # Step 1: Edit SYN protections
        # ---------------------------
        for prot in edit_syn_protections:
            prot_result = dict(changed=False, response={}, debug_info={}, parameters={})
            body = {}

            prot_index = prot.get("index")
            if prot_index is None:
                prot_result["debug_info"] = {"error": "Missing protection index"}
                result["results"].append(prot_result)
                continue

            if "activation_threshold" in prot:
                body["rsIDSSYNAttackActivationThreshold"] = prot["activation_threshold"]
                prot_result["parameters"]["activation_threshold"] = prot["activation_threshold"]
            if "termination_threshold" in prot:
                body["rsIDSSYNAttackTerminationThreshold"] = prot["termination_threshold"]
                prot_result["parameters"]["termination_threshold"] = prot["termination_threshold"]
            if "app_port_group" in prot:
                body["rsIDSSYNDestinationAppPortGroup"] = prot["app_port_group"]
                prot_result["parameters"]["app_port_group"] = prot["app_port_group"]

            if not body:
                prot_result["debug_info"] = {"error": "No parameters provided to update"}
                result["results"].append(prot_result)
                continue

            path = f"/mgmt/device/byip/{dp_ip}/config/rsIDSSYNAttackTable/{prot_index}"
            url = f"https://{provider['cc_ip']}{path}"
            prot_result["debug_info"].update({"method": "PUT", "uri": url, "body": body})

            logger.info(f"Editing SYN protection {prot_index} on device {dp_ip}")
            logger.debug(f"PUT URL: {url}, body: {body}")

            try:
                if not module.check_mode:
                    resp = cc._put(url, json=body)
                    prot_result["response"] = resp.json()
                    prot_result["debug_info"]["status_code"] = resp.status_code
                    prot_result["changed"] = True
                    any_changed = True
                    logger.info(f"Edited SYN protection {prot_index}")
                    logger.debug(f"Response: {prot_result['response']}")
            except Exception as e:
                prot_result["debug_info"]["error"] = str(e)
                logger.error(f"Failed to edit SYN protection {prot_index}: {str(e)}")

            result["results"].append(prot_result)
            debug_info["protections"].append(prot_result["debug_info"])

        # ----------------------------------------
        # Step 2: Edit profile parameters + attach protections
        # ----------------------------------------
        for profile in edit_syn_profiles:
            profile_name = profile.get("name")
            protections = profile.get("protections", [])
            params = profile.get("params", {})

            if not profile_name:
                result["results"].append({"debug_info": {"error": "Profile name is missing"}})
                continue

            # Edit profile parameters
            if params:
                param_result = dict(changed=False, response={}, debug_info={}, parameters={})
                body = {}
                for k, v in params.items():
                    if v is not None:
                        body[k] = v
                        # Map to human-readable for debug output
                        if k in REVERSE_VALUE_MAP:
                            param_result["parameters"][k] = str(v)  # temporarily numeric; will map after response
                        else:
                            param_result["parameters"][k] = v

                path = f"/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesParamsTable/{profile_name}"
                url = f"https://{provider['cc_ip']}{path}"
                param_result["debug_info"].update({"method": "PUT", "uri": url, "body": body})

                logger.info(f"Editing SYN profile {profile_name} parameters")
                logger.debug(f"PUT URL: {url}, body: {body}")

                try:
                    if not module.check_mode:
                        resp = cc._put(url, json=body)
                        param_result["response"] = resp.json()
                        param_result["debug_info"]["status_code"] = resp.status_code
                        param_result["changed"] = True
                        any_changed = True
                        # Map numeric to string after API call
                        for key in REVERSE_VALUE_MAP:
                            if key in param_result["parameters"]:
                                num_val = param_result["parameters"][key]
                                param_result["parameters"][key] = REVERSE_VALUE_MAP[key].get(num_val, num_val)
                        logger.info(f"Profile parameters for {profile_name} updated")
                        logger.debug(f"Response: {param_result['response']}")
                except Exception as e:
                    param_result["debug_info"]["error"] = str(e)
                    logger.error(f"Failed to edit profile parameters {profile_name}: {str(e)}")

                result["results"].append(param_result)
                debug_info["profiles"].append(param_result["debug_info"])

            # Attach protections to profile
            for protection_name in protections:
                prof_result = dict(changed=False, response={}, debug_info={}, parameters={})
                body = {"rsIDSSynProfilesName": profile_name, "rsIDSSynProfileServiceName": protection_name}
                path = f"/mgmt/device/byip/{dp_ip}/config/rsIDSSynProfilesTable/{profile_name}/{protection_name}"
                url = f"https://{provider['cc_ip']}{path}"
                prof_result["debug_info"].update({"method": "POST", "uri": url, "body": body})

                logger.info(f"Attaching protection {protection_name} to profile {profile_name}")
                logger.debug(f"POST URL: {url}, body: {body}")

                try:
                    if not module.check_mode:
                        resp = cc._post(url, json=body)
                        prof_result["response"] = resp.json()
                        prof_result["debug_info"]["status_code"] = resp.status_code
                        prof_result["changed"] = True
                        any_changed = True
                except Exception as e:
                    prof_result["debug_info"]["error"] = str(e)
                    logger.error(f"Failed to attach protection {protection_name} to profile {profile_name}: {str(e)}")

                result["results"].append(prof_result)
                debug_info["profiles"].append(prof_result["debug_info"])

        result["changed"] = any_changed
        result["debug_info"] = debug_info

    except Exception as e:
        module.fail_json(msg=str(e), debug_info=debug_info, **result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
