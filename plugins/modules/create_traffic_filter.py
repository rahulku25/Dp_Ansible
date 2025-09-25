# plugins/modules/manage_traffic_filter.py
"""
Unified Ansible module to manage DefensePro Traffic Filter protections and profiles.

Handles creation of traffic filter rules and profiles with optional DNS and TCP flags,
aligned with the API output format.
"""

from ansible.module_utils.basic import AnsibleModule

def run_module():
    module_args = dict(
        provider=dict(type='dict', required=True),
        dp_ip=dict(type='str', required=True),
        traffic_filters=dict(type='list', required=False, default=[]),
        traffic_profiles=dict(type='list', required=False, default=[])
    )
    
    result = dict(changed=False, response={})
    debug_info = {}
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)
    
    provider = module.params['provider']
    dp_ip = module.params['dp_ip']
    traffic_filters = module.params['traffic_filters']
    traffic_profiles = module.params['traffic_profiles']
    
    log_level = provider.get('log_level', 'disabled')
    
    from ansible.module_utils.logger import Logger
    logger = Logger(verbosity=log_level)
    
    debug_info['input'] = {
        'dp_ip': dp_ip,
        'filters_count': len(traffic_filters),
        'profiles_count': len(traffic_profiles)
    }
    
    try:
        from ansible.module_utils.radware_cc import RadwareCC
        cc = RadwareCC(provider['cc_ip'], provider['username'],
                      provider['password'], log_level=log_level, logger=logger)
        
        changes_made = False
        created_filters = []
        created_profiles = []
        
        if not module.check_mode:
            # Step 1: Create traffic filters
            if traffic_filters:
                logger.info(f"Creating {len(traffic_filters)} traffic filters on {dp_ip}")
                
                for i, tf in enumerate(traffic_filters):
                    filter_name = tf['name']
                    api_params = map_filter_parameters(tf)
                    
                    index = tf.get('index', 0)
                    
                    if i > 0:
                        refresh_device_state(cc, dp_ip, provider, logger)
                    
                    path = f"/mgmt/device/byip/{dp_ip}/config/rsNewTrafficFilterTable/{index}"
                    url = f"https://{provider['cc_ip']}{path}"
                    
                    logger.info(f"Creating traffic filter '{filter_name}' at index {index}")
                    resp = cc._post(url, json=api_params)
                    data = resp.json()
                    
                    created_filters.append({
                        'name': filter_name,
                        'index': index,
                        'response': data
                    })
                    changes_made = True
            
            # Step 2: Create traffic filter profiles
            if traffic_profiles:
                logger.info(f"Creating {len(traffic_profiles)} traffic profiles on {dp_ip}")
                
                for profile in traffic_profiles:
                    profile_name = profile['name']
                    filters = profile.get('filters', [])
                    
                    for filter_name in filters:
                        path = f"/mgmt/device/byip/{dp_ip}/config/rsNewTrafficFilterProfileTable/{profile_name}/{filter_name}"
                        url = f"https://{provider['cc_ip']}{path}"
                        
                        body = {
                            "rsNewTrafficFilterProfileName": profile_name,
                            "rsNewTrafficFilterName": filter_name
                        }
                        
                        logger.info(f"Creating profile '{profile_name}' with filter '{filter_name}'")
                        resp = cc._post(url, json=body)
                        data = resp.json()
                        
                        created_profiles.append({
                            'profile_name': profile_name,
                            'filter_name': filter_name,
                            'response': data
                        })
                        changes_made = True
        
        result['changed'] = changes_made
        result['response'] = {
            'created_filters': created_filters,
            'created_profiles': created_profiles
        }
        
        debug_info['summary'] = {
            'filters_created': len(created_filters),
            'profiles_created': len(created_profiles),
            'operations_completed': changes_made
        }
        
    except Exception as e:
        logger.error(f"Exception: {str(e)}")
        module.fail_json(msg=str(e), debug_info=debug_info, **result)
    
    result['debug_info'] = debug_info
    module.exit_json(**result)

def map_filter_parameters(tf):
    """Map user-friendly parameters to API format."""
    
    PROTOCOL_MAP = {'tcp': '1', 'udp': '2', 'any': '0'}
    ACTION_MAP = {'report_only': '1', 'drop': '0'}
    
    api_params = {
        "rsNewTrafficFilterProfileName": tf['profile_name'],
        "rsNewTrafficFilterName": tf['name'],
        "rsNewTrafficFilterID": tf.get('id', ''),
        "rsNewTrafficFilterState": tf.get('state', '1'),
        "rsNewTrafficFilterPriority": str(tf.get('priority', '0')),
        "rsNewTrafficFilterMatchCriteria": str(tf.get('match_criteria', '1')),
        "rsNewTrafficFilterSrcNetwork": tf.get('src_network', 'As in Policy'),
        "rsNewTrafficFilterSrcPort": tf.get('src_port', 'Any'),
        "rsNewTrafficFilterDstNetwork": tf.get('dst_network', 'As in Policy'),
        "rsNewTrafficFilterDstPort": tf.get('dst_port', 'Any'),
        "rsNewTrafficFilterProtocol": PROTOCOL_MAP.get(tf.get('protocol', 'any'), '0'),
        "rsNewTrafficFilterPacketSize": tf.get('packet_size', ''),
        # TCP Flags
        "rsNewTrafficFilterTCPFlagsSyn": tf.get('tcp_syn', '1'),
        "rsNewTrafficFilterTCPFlagsAck": tf.get('tcp_ack', '2'),
        "rsNewTrafficFilterTCPFlagsRst": tf.get('tcp_rst', '2'),
        "rsNewTrafficFilterTCPFlagsSynAck": tf.get('tcp_syn_ack', '2'),
        "rsNewTrafficFilterTCPFlagsFinAck": tf.get('tcp_fin_ack', '2'),
        "rsNewTrafficFilterTCPFlagsPshAck": tf.get('tcp_psh_ack', '2'),
        # DNS
        "rsNewTrafficFilterDnsQueryName": tf.get('dns_query_name', ''),
        "rsNewTrafficFilterDnsTypeA": tf.get('dns_type_a', '2'),
        "rsNewTrafficFilterDnsTypeAAAA": tf.get('dns_type_aaaa', '2'),
        "rsNewTrafficFilterDnsTypeMX": tf.get('dns_type_mx', '2'),
        "rsNewTrafficFilterDnsTypePTR": tf.get('dns_type_ptr', '2'),
        "rsNewTrafficFilterDnsTypeCNAME": tf.get('dns_type_cname', '2'),
        "rsNewTrafficFilterDnsTypeNS": tf.get('dns_type_ns', '2'),
        "rsNewTrafficFilterDnsTypeTXT": tf.get('dns_type_txt', '2'),
        "rsNewTrafficFilterDnsTypeANY": tf.get('dns_type_any', '2'),
        "rsNewTrafficFilterDnsTypeSOA": tf.get('dns_type_soa', '2'),
        # Thresholds
        "rsNewTrafficFilterThresholdPPS": str(tf.get('threshold_pps', '10000')),
        "rsNewTrafficFilterThresholdBPS": str(tf.get('threshold_bps', '0')),
        "rsNewTrafficFilterPacketReport": tf.get('packet_report', '1'),
        # Other optional parameters
        "rsNewTrafficFilterTTL": tf.get('ttl', ''),
        "rsNewTrafficFilterSequenceNum": tf.get('seq_num', ''),
        "rsNewTrafficFilterFragId": tf.get('frag_id', ''),
        "rsNewTrafficFilterFragOffset": tf.get('frag_offset', ''),
        "rsNewTrafficFilterAttackTrackingType": tf.get('attack_tracking', '0'),
        "rsNewTrafficFilterRegex": tf.get('regex', ''),
        "rsNewTrafficFilterTOS": tf.get('tos', ''),
        "rsNewTrafficFilterVLAN": tf.get('vlan', 'Any'),
        "rsNewTrafficFilterCustomProtocol": tf.get('custom_protocol', ''),
        "rsNewTrafficFilterSrcSubPrefixIPv4": str(tf.get('src_prefix_ipv4', '32')),
        "rsNewTrafficFilterSrcSubPrefixIPv6": str(tf.get('src_prefix_ipv6', '128')),
        "rsNewTrafficFilterDstSubPrefixIPv4": str(tf.get('dst_prefix_ipv4', '32')),
        "rsNewTrafficFilterDstSubPrefixIPv6": str(tf.get('dst_prefix_ipv6', '128'))
    }
    
    return api_params

def refresh_device_state(cc, dp_ip, provider, logger):
    """Refresh device state to avoid API caching issues."""
    try:
        path = f"/mgmt/device/byip/{dp_ip}/config/rsNewTrafficFilterTable"
        url = f"https://{provider['cc_ip']}{path}"
        cc._get(url)
        logger.debug(f"Refreshed device state for {dp_ip}")
    except Exception as e:
        logger.debug(f"State refresh failed (non-critical): {str(e)}")

def main():
    run_module()

if __name__ == '__main__':
    main()
