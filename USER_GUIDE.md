# DefensePro Configuration Builder - User Guide

**Complete workflows and configuration guide for DefensePro automation**

## 🎯 What This Guide Covers

Step-by-step workflows for automating DefensePro configuration management:
- **Network Classes**: Create, edit, delete, and query network classifications
- **Security Profiles**: Manage Connection Limit, BDoS, DNS, HTTPS, OOS, SSL Objects, Traffic Filter profiles  
- **Security Policies**: Orchestrated creation with profile binding
- **Device Operations**: Locking, configuration updates, and policy application

## 📋 Prerequisites

Complete these setup steps before following any workflows:

### 1. Required Files Setup
```bash
# Create Ansible configuration files
cp ansible_example.cfg ansible.cfg
cp inventory_example.ini inventory.ini

# Create variable templates  
cd vars/
cp cc_example.yml cc.yml                    # CyberController connection
cp create_vars.yml.example create_vars.yml  # Creation workflows
cp edit_vars.yml.example edit_vars.yml      # Editing workflows
cp delete_vars.yml.example delete_vars.yml  # Deletion workflows
cp get_vars.yml.example get_vars.yml        # Query workflows
cp update_vars_example.yml update_vars.yml  # Policy updates
```

### 2. Configure Connection Settings
```bash
# Edit CyberController connection details
nano vars/cc.yml
```
Add your CyberController IP, username, and password.

### 3. Verify Setup
```bash
# Test Ansible configuration
ansible-inventory --list
```

## 🚀 Quick Start (5 Minutes)

### Example: Create Network Classes
```bash
# 1. Configure your networks
nano vars/create_vars.yml  # Add device IPs and network definitions

# 2. Test with dry-run
ansible-playbook playbooks/create_network_class.yml --check

# 3. Execute
ansible-playbook playbooks/create_network_class.yml

# 4. Verify results
ansible-playbook playbooks/get_network_class.yml
```

## 📖 Complete Workflows

### 🌐 Network Class Workflows

#### Workflow 1: Create Network Classes
```bash
# 1. Configure your networks
nano vars/create_vars.yml

# 2. Test with dry-run
ansible-playbook playbooks/create_network_class.yml --check

# 3. Execute creation
ansible-playbook playbooks/create_network_class.yml
```

#### Workflow 2: Edit Network Classes  
```bash
# 1. View current configuration
ansible-playbook playbooks/get_network_class.yml

# 2. Define changes
nano vars/edit_vars.yml

# 3. Test changes
ansible-playbook playbooks/edit_network_class.yml --check

# 4. Apply changes
ansible-playbook playbooks/edit_network_class.yml
```

#### Workflow 3: Delete Network Classes
```bash
# 1. Identify targets for deletion
ansible-playbook playbooks/get_network_class.yml

# 2. Configure deletions
nano vars/delete_vars.yml

# 3. Test deletion plan
ansible-playbook playbooks/delete_network_class.yml --check

# 4. Execute deletions
ansible-playbook playbooks/delete_network_class.yml
```

#### Workflow 4: Query Network Classes
```bash
# Show all network classes
ansible-playbook playbooks/get_network_class.yml

# Filter specific classes (edit get_vars.yml first)
nano vars/get_vars.yml  # Set filter_class_names: ["class1", "class2"]
ansible-playbook playbooks/get_network_class.yml
```

### 🔒 Connection Limit Profile Workflows

#### Workflow 5: Create Connection Limit Profiles
```bash
# 1. Configure protections and profiles
nano vars/create_vars.yml

# 2. Test configuration
ansible-playbook playbooks/create_cl_profiles.yml --check

# 3. Create profiles
ansible-playbook playbooks/create_cl_profiles.yml
```

**Variation 5a: Create Protections Only**
```bash
# Define cl_protections section only, skip cl_profiles
nano vars/create_vars.yml
ansible-playbook playbooks/create_cl_profiles.yml
```

**Variation 5b: Create Profiles with Existing Protections**
```bash
# Skip cl_protections, define cl_profiles with existing protection names
nano vars/create_vars.yml
ansible-playbook playbooks/create_cl_profiles.yml
```

#### Workflow 6: Edit Connection Limit Protections
```bash
# 1. Configure changes (specify protection_index and parameters to change)
nano vars/edit_vars.yml

# 2. Preview changes
ansible-playbook playbooks/edit_cl_protections.yml --check

# 3. Apply changes
ansible-playbook playbooks/edit_cl_protections.yml
```

#### Workflow 7: Query Connection Limit Profiles
```bash
# Show all profiles and protections
ansible-playbook playbooks/get_cl_profiles.yml

# Filter specific profiles (edit get_vars.yml first)
nano vars/get_vars.yml  # Set filter_cl_profile_names: ["profile1"]
ansible-playbook playbooks/get_cl_profiles.yml
```

#### Workflow 8: Delete Connection Limit Profiles
```bash
# 1. Plan deletions
nano vars/delete_vars.yml

# 2. Preview deletion plan
ansible-playbook playbooks/delete_cl_profiles.yml --check

# 3. Execute deletions
ansible-playbook playbooks/delete_cl_profiles.yml
```

**Important Rules for Deletion**:
- **Profile deletions**: Remove protections from profiles (profile auto-deleted when last protection removed)
- **Protection deletions**: Delete protections entirely (protection must not be in any profile)
- **Order matters**: Profile deletions are processed before protection deletions
- **Dependencies**: Cannot delete protection if it's still associated with any profile

### 🛡️ Security Profile Workflows

#### Workflow 9: BDoS Profile Management
```bash
# Create BDoS profiles
nano vars/create_vars.yml
ansible-playbook playbooks/create_bdos_profile.yml --check
ansible-playbook playbooks/create_bdos_profile.yml

# Edit BDoS profiles
nano vars/edit_vars.yml
ansible-playbook playbooks/edit_bdos_profile.yml --check
ansible-playbook playbooks/edit_bdos_profile.yml

# Query BDoS profiles
ansible-playbook playbooks/get_bdos_profile.yml

# Delete BDoS profiles
nano vars/delete_vars.yml
ansible-playbook playbooks/delete_bdos_profile.yml --check
ansible-playbook playbooks/delete_bdos_profile.yml
```

#### Workflow 10: DNS Profile Management
```bash
# Create DNS profiles
nano vars/create_vars.yml
ansible-playbook playbooks/create_dns_profile.yml --check
ansible-playbook playbooks/create_dns_profile.yml

# Edit DNS profiles
nano vars/edit_vars.yml
ansible-playbook playbooks/edit_dns_profile.yml --check
ansible-playbook playbooks/edit_dns_profile.yml

# Query DNS profiles
ansible-playbook playbooks/get_dns_profile.yml

# Delete DNS profiles
nano vars/delete_vars.yml
ansible-playbook playbooks/delete_dns_profile.yml --check
ansible-playbook playbooks/delete_dns_profile.yml
```

#### Workflow 11: HTTPS Profile Management
```bash
# Create HTTPS profiles
nano vars/create_vars.yml
ansible-playbook playbooks/create_https_profile.yml --check
ansible-playbook playbooks/create_https_profile.yml

# Edit HTTPS profiles
nano vars/edit_vars.yml
ansible-playbook playbooks/edit_https_profile.yml --check
ansible-playbook playbooks/edit_https_profile.yml

# Query HTTPS profiles
ansible-playbook playbooks/get_https_profile.yml

# Delete HTTPS profiles
nano vars/delete_vars.yml
ansible-playbook playbooks/delete_https_profile.yml --check
ansible-playbook playbooks/delete_https_profile.yml
```

#### Workflow 12: Out-of-State (OOS) Profile Management
```bash
# Create OOS profiles
nano vars/create_vars.yml
ansible-playbook playbooks/create_oos_profile.yml --check
ansible-playbook playbooks/create_oos_profile.yml

# Edit OOS profiles
nano vars/edit_vars.yml
ansible-playbook playbooks/edit_oos_profile.yml --check
ansible-playbook playbooks/edit_oos_profile.yml

# Query OOS profiles
ansible-playbook playbooks/get_oos_profile.yml

# Delete OOS profiles
nano vars/delete_vars.yml
ansible-playbook playbooks/delete_oos_profile.yml --check
ansible-playbook playbooks/delete_oos_profile.yml
```


#### Workflow 13: Traffic Filter Management
```bash
# Create Traffic Filter profiles
nano vars/create_vars.yml
ansible-playbook playbooks/create_traffic_filter.yml --check
ansible-playbook playbooks/create_traffic_filter.yml

# Edit Traffic Filter profiles
nano vars/edit_vars.yml
ansible-playbook playbooks/edit_traffic_filter.yml --check
ansible-playbook playbooks/edit_traffic_filter.yml

# Query Traffic Filter profiles
ansible-playbook playbooks/get_traffic_filter.yml

# Delete Traffic Filter profiles
nano vars/delete_vars.yml
ansible-playbook playbooks/delete_traffic_filter.yml --check
ansible-playbook playbooks/delete_traffic_filter.yml
```

### 🔐 SSL Object Workflows

#### Workflow 14: SSL Object Management
```bash
# Create SSL objects
nano vars/create_vars.yml
ansible-playbook playbooks/create_ssl_object.yml --check
ansible-playbook playbooks/create_ssl_object.yml

# Edit SSL objects
nano vars/edit_vars.yml
ansible-playbook playbooks/edit_ssl_object.yml --check
ansible-playbook playbooks/edit_ssl_object.yml

# Query SSL objects
ansible-playbook playbooks/get_ssl_object.yml

# Delete SSL objects
nano vars/delete_vars.yml
ansible-playbook playbooks/delete_ssl_object.yml --check
ansible-playbook playbooks/delete_ssl_object.yml
```

### 🎯 Security Policy & Orchestration Workflows

#### Workflow 15: Complete Security Configuration (Orchestrated)
```bash
# 1. Configure comprehensive security setup
nano vars/create_vars.yml

# Configure orchestration flags
security_policy_config:
  create_network_classes: true
  create_cl_profiles: true
  create_bdos_profiles: true
  create_dns_profiles: true
  create_https_profiles: true
  create_oos_profiles: true
  create_traffic_filter_profiles: true
  create_ssl_objects: true
  create_security_policies: true
  apply_policies_after_creation: true

# 2. Preview full orchestration
ansible-playbook playbooks/create_full_config.yml --check

# 3. Execute complete configuration
ansible-playbook playbooks/create_full_config.yml
```

#### Workflow 16: Security Policy Management
```bash
# Edit existing security policies
nano vars/edit_vars.yml
ansible-playbook playbooks/edit_security_policy.yml --check
ansible-playbook playbooks/edit_security_policy.yml

# Query security policies and profiles
ansible-playbook playbooks/get_security_policy.yml

# Delete security policies
nano vars/delete_vars.yml
ansible-playbook playbooks/delete_security_policy.yml --check
ansible-playbook playbooks/delete_security_policy.yml
```

#### Workflow 17: Policy Updates
```bash
# Manual policy updates
nano vars/update_vars.yml  # Configure target devices
ansible-playbook playbooks/update_policies.yml

# Or specify devices directly
ansible-playbook playbooks/update_policies.yml -e "target_devices=['10.105.192.32','10.105.192.33']"
```

## ⚙️ Configuration Reference

### Device and Connection Configuration

#### Target Devices (`vars/*.yml`)
```yaml
# Define target DefensePro devices
dp_ip:
  - "10.105.192.32"
  - "10.105.192.33"
```

#### CyberController Connection (`vars/cc.yml`)
```yaml
cc_ip: "10.105.193.3"
username: "your_username"
password: "your_password"
log_level: "info"  # Options: info, debug, disabled
```

### Variable File Examples

#### Network Classes (`vars/create_vars.yml`)
```yaml
netclasses:
  - name: "web_servers"
    groups:
      - { address: "192.168.1.0", mask: "255.255.255.0" }
      - { address: "192.168.2.0", mask: "24" }  # CIDR notation also supported
```

#### Connection Limit Profiles (`vars/create_vars.yml`)
```yaml
# Protection subprofiles (optional)
cl_protections:
  - name: "web_protection"
    protocol: "tcp"
    threshold: "100"
    app_port_group: "https"
    tracking_type: "src_ip"
    action: "drop"
    packet_report: "enable"

# Profiles (optional)
cl_profiles:
  - name: "web_limits"
    protections:
      - "web_protection"
      - "existing_protection"  # Can reference existing protections
```

#### Security Policy Orchestration (`vars/create_vars.yml`)
```yaml
# OPTIONAL: Define BDoS profiles (only define if creating new ones)
bdos_profiles:
  - name: "bdos_profile_5"           # MANDATORY: Profile name
    state: "enable"                              # OPTIONAL: enable, disable (default: enable)
    params:
      action: "block_and_report"                 # OPTIONAL: report_only, block_and_report (default: block_and_report)
      syn_flood: "enable"                        # OPTIONAL: enable, disable (default: disable)
      udp_flood: "enable"                        # OPTIONAL: enable, disable (default: disable)
      igmp_flood: "enable"                       # OPTIONAL: enable, disable (default: disable)
      icmp_flood: "enable"                       # OPTIONAL: enable, disable (default: disable)
      tcp_ack_fin_flood: "enable"                # OPTIONAL: enable, disable (default: disable)
      tcp_rst_flood: "enable"                    # OPTIONAL: enable, disable (default: disable)
      tcp_syn_ack_flood: "enable"                # OPTIONAL: enable, disable (default: disable)
      tcp_frag_flood: "enable"                   # OPTIONAL: enable, disable (default: disable)
      udp_frag_flood: "enable"                   # OPTIONAL: enable, disable (default: disable)

      inbound_traffic: 1000000                   # Mandatory
      outbound_traffic: 500000                   # Mandatory
      tcp_in_quota: 80                           # OPTIONAL: 0–100 (% share)
      udp_in_quota: 50
      icmp_in_quota: 10
      igmp_in_quota: 50
      tcp_out_quota: 80
      udp_out_quota: 50
      icmp_out_quota: 10
      igmp_out_quota: 50

      transparent_optimization: "enable"         # OPTIONAL: enable, disable (default: disable)
      packet_report: "enable"                    # OPTIONAL: enable, disable (default: disable)
      burst_attack: "disable"                    # OPTIONAL: enable, disable (default: disable)
      maximum_interval_between_bursts: 60        # OPTIONAL: 1–60 minutes (default: 10)
      learning_suppression_threshold: 10         # OPTIONAL: 0–50 (default: 0)
      footprint_strictness: "medium"             # OPTIONAL: low, medium, high (default: low)
      bdos_rate_limit: "user_defined"            # OPTIONAL: disable, normal_edge, suspect_edge, user_defined (default: disable)
      user_defined_rate_limit: 500               # OPTIONAL: 0–4000 (default: 0)
      udp_ packet_rate_detection_sensitivit: low # OPTIONAL: Ignore or Disable,low, medium, high      
      user_defined_rate_limit_unit: "mbps"       # OPTIONAL: kbps, mbps, gbps (default: mbps)
      adv_udp_detection: "enable"                # OPTIONAL: enable, disable (default: disable)

  # Minimal example (only mandatory parameter)
  - name: "bdos_profile5"                         # MANDATORY
    # All other parameters use defaults



### Editing BDoS Profiles (Partial Updates) ###
```yaml
# Edit existing BDoS profiles - ONLY specify what you want to change
bdos_profiles:
  - profile_name: "bdos_comprehensive_example"   # MANDATORY: must specify which profile to edit
    params:
      action: "report_only"                      # OPTIONAL: Change action only

  - profile_name: "bdos_minimal"                 # MANDATORY
    params:
      inbound_traffic: 2000000                   # OPTIONAL: Change threshold
      outbound_traffic: 1000000                  # OPTIONAL: Change threshold

  - profile_name: "bdos_custom"                  # MANDATORY
    params:
      syn_flood: "disable"                       # OPTIONAL: Disable SYN flood detection
      udp_flood: "enable"                        # OPTIONAL: Enable UDP flood detection
      footprint_strictness: "high"               # OPTIONAL: Update detection sensitivity
    # All other parameters remain unchanged
```


#### Get BDoS Profiles  ####
```yaml
# Get all BDoS profiles from devices
# No configuration needed - just run the playbook
ansible-playbook playbooks/get_bdos_profile.yml
# Filter by specific profile names (configure in get_vars.yml)
filter_bdos_profile_names: ["BDOS_Profile_5", "BDOS_Profile_6"]  # Show only these profiles
# filter_bdos_profile_names: []                                # Show all profiles (default)

#### Delete BDoS Profiles  ####
```yaml
# Delete BDoS profiles by name
bdos_profiles:
  - "BDOS_Profile_5"
  - "BDOS_Profile_6"
```

#### Bdos profile Notes:

*** name ***: MANDATORY – Unique profile name.
*** state ***: Optional – enable or disable (default: enable).
*** action ***: Required – choose between report_only or block_and_report.
*** Flood toggles (syn_flood, udp_flood, etc.) ***: Enable/disable specific protocol flood detection.
*** Traffic limits (inbound/outbound) ***: Mandatory; define baseline traffic thresholds (1–1342177280).
*** Quota values ***: Define % share of traffic per protocol (0–100).
*** Rate limiting ***: Select predefined (normal_edge, suspect_edge) or user_defined with unit and value.
*** Advanced controls ***: Includes burst attack detection, suppression threshold, footprint strictness, and advanced UDP detection.
*** Control flags ***: create_bdos_profiles can be toggled independently to enable/disable orchestration.

### Create DNS Profiles  ####
```yaml
# Define DNS profiles to create on each device
# Configure DNS profiles in `vars/create_vars.yml`:
# OPTIONAL: DNS profiles (only define if creating new ones)
create_dns_profiles:
  - name: "dns_profile_1"               # MANDATORY: Profile name
    state: "enable"                     # OPTIONAL: enable, disable (default: enable)
    params:
      action: "block_&_report"        # OPTIONAL: report_only, block_&_report (default: block_and_report)
      expected_qps: 1000                # OPTIONAL: 0–400000000 (default: 0)
      max_allow_qps: 5000               # OPTIONAL: 0–400000000 (default: 0)
      sig_rate_lim_target: 10                 # Range: 0-100 in %

      # Manual trigger configuration
      manual_trigger: "disable"         # OPTIONAL: enable, disable (default: disable)
      manual_trigger_act_thresh: 2000   # OPTIONAL: ≥ termination threshold
      manual_trigger_term_thresh: 1000  # OPTIONAL
      manual_trigger_max_qps_target: 3000
      manual_trigger_act_period: 30     # OPTIONAL: seconds
      manual_trigger_term_period: 15
      manual_trigger_escalate_period: 60
    
      # Logging / debug
      packet_report: "enable"           # OPTIONAL: enable, disable (default: disable)

      # Advanced detection
      learning_suppression_threshold: 10 # OPTIONAL: 0–100 (default: 0)
      footprint_strictness: "medium"    # OPTIONAL: low, medium, high (default: low)

      # Record quotas
      a_quota: 100                      # OPTIONAL
      mx_quota: 50
      ptr_quota: 20
      aaaa_quota: 50
      text_quota: 10
      soa_quota: 5
      naptr_quota: 5
      srv_quota: 10
      other_quota: 5

      # Record statuses (enable/disable)
      a_status: "enable"
      mx_status: "enable"
      ptr_status: "enable"
      aaaa_status: "enable"
      text_status: "enable"
      soa_status: "enable"
      naptr_status: "disable"
      srv_status: "disable"
      other_status: "enable"

  # Note - If you enable manual trigger , you must disable all query.Also termination thresholds must be less than activation thresholds.
  # Minimal example (only mandatory parameter)
  - name: "dns_profile_1"         # MANDATORY
    # All other parameters use defaults
```
### Editing DNS Profiles (Partial Updates)
```yml

# Edit existing DNS profiles - ONLY specify what you want to change
# Note - If you are editing QPS and quota same time then you have to run the playbook twice. 
edit_dns_profiles:
  - name: "dns_profile_10"                      # MANDATORY: must specify which profile to edit
    params:
      action: "report_only"                     # OPTIONAL: report_only, block_&_report
      expected_qps: 2000                        # OPTIONAL: Update expected QPS
      max_allow_qps: 8000                       # OPTIONAL: Update max QPS
      sig_rate_lim_target: 10                   # Range: 0-100 in %
      a_status: "disable"                       # OPTIONAL: Disable A record protection
      mx_status: "enable"                       # OPTIONAL: Enable MX record protection
      footprint_strictness: "high"              # OPTIONAL: Update detection sensitivity
      packet_report: "disable"                  # OPTIONAL: Change logging/reporting
      a_in_quota: 40                            # OPTIONAL: % share for A record (0–100)
      mx_in_quota: 30                           # OPTIONAL: % share for MX record (0–100)
      cname_in_quota: 20                        # OPTIONAL: % share for CNAME record (0–100)
      other_in_quota: 10                        # OPTIONAL: % share for other records (0–100)
      a_out_quota: 35                           # OPTIONAL: % share for outbound A record (0–100)
      mx_out_quota: 25                          # OPTIONAL: % share for outbound MX record (0–100)
      cname_out_quota: 15                      # OPTIONAL: % share for outbound CNAME record (0–100)
      other_out_quota: 5                        # OPTIONAL: % share for other outbound (0–100)
```
### Get DNS Profiles
```yml
# Get all DNS profiles from devices
# No configuration needed - just run the playbook
ansible-playbook playbooks/get_dns_profile.yml

filter_dns_profile_names: ["dns_profile_1"]
```
### Delete DNS Profiles
```yml
# Delete DNS profiles by name
delete_dns_profiles:
  - "dns_profile_1"
  - "dns_profile_2"
```
### DNS Profile Notes:

*** name ***: MANDATORY – Unique profile name
*** state ***: Optional – enable or disable (default: enable)
*** action ***: REQUIRED – choose between report_only or block_and_report
*** Query-type toggles ***: Optional – enable/disable detection for specific query types (a_query, aaaa_query, mx_query, ns_query, ptr_query, soa_query, srv_query, txt_query)
*** Traffic limits ***: MANDATORY – baseline DNS query thresholds in queries per second (inbound_qps, outbound_qps)
*** Quota values ***: Optional – percentage share per query type (0–100%)
*** Rate limiting ***: Optional – select predefined (normal_edge, suspect_edge) or user_defined with unit and value
*** Advanced controls ***: Optional – includes NXDOMAIN handling, malformed query detection, response rate limiting, protocol anomaly checks, footprint strictness, learning suppression thresholds
*** Control flags ***: Use to enable/disable each creation stage independently

### Create OOS Profiles ###
# Define OOS profiles to create on each device
# Configure OOS profiles in `vars/create_vars.yml`:
# OPTIONAL: OOS profiles (only define if creating new ones)

```yaml
oos_profiles:
  - name: "oos_profile_1"            # MANDATORY: Profile name
    state: "enable"                  # OPTIONAL: enable, disable (default: enable)
    params:
      action: "block_and_report"     # OPTIONAL: report_only, block_and_report (default: block_and-report)
      syn_ack_allow: "enable"        # OPTIONAL: enable, disable (default: enable)
      packet_report: "enable"        # OPTIONAL: enable, disable (default: disable)
      risk: "medium"                 # OPTIONAL: low, medium, high (default: medium)
      act_threshold: 1000            # OPTIONAL: action threshold
      term_threshold: 500            # OPTIONAL: termination threshold
      idle_state: "enable"           # OPTIONAL: enable, disable (default: disable)
      idle_state_bandwidth_threshold: 1000  # OPTIONAL: threshold for idle state
      idle_state_timer: 30           # OPTIONAL: seconds for idle timeout
```
  # Minimal example (only mandatory parameter)
  - name: "oos_profile_2"             # MANDATORY
    # All other parameters use defaults

### Editing OOS Profiles (Partial Updates)
```yaml
# Edit existing OOS profiles - ONLY specify what you want to change
oos_profiles:
  - name: "oos_profile_1"     # MANDATORY: must specify which profile to edit
    params:
      action: "report_only"           # OPTIONAL: report_only, block_and_report
      syn_ack_allow: "disable"        # OPTIONAL: enable, disable
      packet_report: "disable"        # OPTIONAL: enable, disable
      risk: "high"                    # OPTIONAL: low, medium, high
      act_threshold: 1500             # OPTIONAL: activation threshold
      term_threshold: 800             # OPTIONAL: termination threshold
      idle_state: "disable"           # OPTIONAL: enable, disable
      idle_state_bandwidth_threshold: 1000  # OPTIONAL: threshold for idle state
      idle_state_timer: 30           # OPTIONAL: seconds for idle timeout
```

### Get OOS Profiles
# Get all OOS profiles from devices
# No configuration needed - just run the playbook
```yaml
ansible-playbook playbooks/get_oos_profile.yml

oos_profiles:
  - "oos_profile_1"
  - "oos_profile_2"                  # Show all profiles (default)
```

### Delete OOS Profiles

# Delete OOS profiles by name
```yaml
oos_profiles:
  - name: "oos_profile_1"
  - name: "oos_profile_2"
```

### Notes for OOS Profiles

*** name ***: MANDATORY – Unique profile name.
*** state ***: Optional – enable or disable (default: enable).
*** action ***: REQUIRED – choose between report_only or block_and_report.
*** syn_ack_allow ***: Optional – enable/disable SYN-ACK handling.
*** packet_report ***: Optional – enable/disable packet logging.
*** risk ***: Optional – low, medium, or high risk profile.
*** Thresholds ***
    act_threshold: activation threshold.
    term_threshold: termination threshold.
    Idle state controls:
    idle_state: enable/disable.
    idle_state_bandwidth_threshold: threshold for idle state.
    idle_state_timer: seconds for idle timeout.
    Control flags: Use to enable/disable each stage independently.

### Create SSL Object ###
# Define ssl object to create on each device
# Configure ssl object in `vars/create_vars.yml`:
```yml
create_ssl_objects:
  - ssl_object_name: "server1"         # MANDATORY: SSL object name
    ssl_object_profile: "enable"       # OPTIONAL: enable, disable (default: enable)
    ip_address: "155.1.102.7"          # MANDATORY: Device IP
    Port: 443                           # OPTIONAL: Port (default: 443)
    add_certificate: "radware"         # OPTIONAL: Certificate to add
    front_sslv3: "disable"             # OPTIONAL: enable, disable (default: disable)
    front_tls1.0: "disable"            # OPTIONAL: enable, disable (default: disable)
    front_tls1.1: "enable"             # OPTIONAL: enable, disable (default: enable)
    front_tls1.2: "enable"             # OPTIONAL: enable, disable (default: enable)
    front_tls1.3: "enable"             # OPTIONAL: enable, disable (default: enable)
    cipher_suite: "enable"             # OPTIONAL: enable, disable (default: enable)
    front_user_cipher: ""              # OPTIONAL: User-defined cipher
    bk_end_decrypt: "enable"           # OPTIONAL: enable, disable (default: enable)
    bk_end_sslv3: "disable"            # OPTIONAL: enable, disable (default: disable)
    bk_end_tls1.0: "disable"           # OPTIONAL: enable, disable (default: disable)
    bk_end_tls1.1: "enable"            # OPTIONAL: enable, disable (default: enable)
    bk_end_tls1.2: "enable"            # OPTIONAL: enable, disable (default: enable)
    bk_end_tls1.3: "enable"            # OPTIONAL: enable, disable (default: enable)
    bk_cipher: "enable"                # OPTIONAL: enable, disable (default: enable)
    bk_user_cipher: ""                 # OPTIONAL: User-defined cipher
    bk_end_port: 443                   # OPTIONAL: Backend port (default: 443)
```
### Edit SSL Object ###
# Edit existing DNS profiles - ONLY specify what you want to change
# Edit ssl object in `vars/edit_vars.yml`:
```yml
edit_ssl_objects:
  - ssl_object_name: "server1"         # MANDATORY: SSL object name
    ssl_object_profile: "enable"       # OPTIONAL: enable, disable (default: enable)
    ip_address: "155.1.102.7"          # MANDATORY: Device IP
    Port: 443                           # OPTIONAL: Port (default: 443)
    add_certificate: "radware"         # OPTIONAL: Certificate to add
    remove_certificate: ""             # OPTIONAL: Certificate to remove
    front_sslv3: "disable"             # OPTIONAL: enable, disable (default: disable)
    front_tls1.0: "disable"            # OPTIONAL: enable, disable (default: disable)
    front_tls1.1: "enable"             # OPTIONAL: enable, disable (default: enable)
    front_tls1.2: "enable"             # OPTIONAL: enable, disable (default: enable)
    front_tls1.3: "enable"             # OPTIONAL: enable, disable (default: enable)
    cipher_suite: "enable"             # OPTIONAL: enable, disable (default: enable)
    front_user_cipher: ""              # OPTIONAL: User-defined cipher
    bk_end_decrypt: "enable"           # OPTIONAL: enable, disable (default: enable)
    bk_end_sslv3: "disable"            # OPTIONAL: enable, disable (default: disable)
    bk_end_tls1.0: "disable"           # OPTIONAL: enable, disable (default: disable)
    bk_end_tls1.1: "enable"            # OPTIONAL: enable, disable (default: enable)
    bk_end_tls1.2: "enable"            # OPTIONAL: enable, disable (default: enable)
    bk_end_tls1.3: "enable"            # OPTIONAL: enable, disable (default: enable)
    bk_cipher: "enable"                # OPTIONAL: enable, disable (default: enable)
    bk_user_cipher: ""                 # OPTIONAL: User-defined cipher
    bk_end_port: 443                   # OPTIONAL: Backend port (default: 443)
  ```
# The certificate API supports only one operation per call: you can either add a certificate or remove one, but not both simultaneously.

### Get SSL Object
# Get all SSL Object from devices
# No configuration needed - just run the playbook
ansible-playbook playbooks/get_ssl_object.yml
```yaml
filter_ssl_object_names: ["server1", "server2"]

```

### Delete OOS Profiles

# Delete ssl object by name
```yaml
delete_ssl_objects:
  - name: server1
  - name: server2
```
Notes for SSL Objects

*** ssl_object_name ***: MANDATORY – Unique name for the SSL object.
*** ssl_object_profile ***: Optional – enable or disable the SSL object (default: enable).
*** IP_Address ***: MANDATORY – The IP address for the SSL object.
*** Port ***: Optional – Port number (default: 443).
*** add_certificate ***: Optional – Name of certificate to add.
*** remove_certificate ***: Optional – Name of certificate to remove.
*** Frontend Protocols ***: Optional – Enable/disable SSL/TLS versions on the frontend.
# front_sslv3
# front_tls1.0
# front_tls1.1
# front_tls1.2
# front_tls1.3
*** Cipher Controls (Frontend) ***: Optional – Enable/disable cipher support.
*** Backend Decryption ***: Optional – Enable/disable backend SSL decryption.
*** Backend Protocols ***: Optional – Enable/disable SSL/TLS versions on the backend.
# bk_end_sslv3
# bk_end_tls1.0
# bk_end_tls1.1
# bk_end_tls1.2
# bk_end_tls1.3
*** Cipher Controls (Backend) ***: Optional – Enable/disable cipher support.
# bk_cipher
# bk_user_cipher
*** bk_end_port ***: Optional – Backend port number (default: same as frontend port).

# Notes:
# Frontend and backend protocol/cipher flags can be used independently to enable/disable stages.
# Certificates must exist on the device before adding to SSL objects.
# Ensure IP address and port are correct; invalid values will result in API errors.


### Create HTTPS Profiles ###
```yaml
# Define HTTPS profiles to create on each device
# Configure HTTPS profiles in `vars/create_vars.yml`:
# OPTIONAL: HTTPS profiles (only define if creating new ones)


create_https_profiles:
  - name: "https_profile_1"
    params:
      action: "report_only"   # report_only,block_and_report
      rate_limit: "2000"      # Packets per Second per Source
      http_authentication_on_suspect_sources: "enable"  # enable, disable
      http_authentication_on_all_sources: "enable"      # enable, disable
      rate_limit_status: "enable"                       # enable, disable
      packet_report: "disable"                          # enable, disable
      full_session_decryption: "disable"                # enable, disable
      #challenge_method: "javascript"                   # javascript, redirect_302



#Minimal example (only mandatory parameter)
 create_https_profiles:
  - name: "http_profile_2"
    params:
      action: "report_only"
    # All other parameters use defaults
```
### Editing HTTPS Profiles (Partial Updates)
```yaml
# Edit existing HTTPS profiles - ONLY specify what you want to change
edit_https_profiles:
  - name: "http_profile_1"
    params:
      action: "report_only"                             # report_only,block_and_report
      rate_limit: "2000"                                # Packets per Second per Source
      http_authentication_on_suspect_sources: "enable"  # enable, disable
      http_authentication_on_all_sources: "enable"      # enable, disable
      rate_limit_status: "enable"                       # enable, disable
      packet_report: "disable"                          # enable, disable
      full_session_decryption: "disable"                # enable, disable
      #challenge_method: "javascript"                   # javascript, redirect_302, SSL Decryption and Encryption should be enabled on the DP for this to work
```

### Get HTTPS Profiles
```yaml
# Get all HTTPS profiles from devices
# No configuration needed - just run the playbook
ansible-playbook playbooks/get_https_profile.yml

filter_https_profile_names: ["http_profile_3"]

```

### Delete HTTP Profiles

```yaml
delete_https_profiles:
  - "https_profile_1"
  - "https_profile_2"                  # Show all profiles (default)
```

### Create Traffic Filter ###
```yaml
# List of Traffic Filter profiles and protections to create per device
# Each item contains tf_profiles and tf_protections lists
# tf_profiles: list of profiles to create
# tf_protections: list of protections under the profiles

create_tf_profiles:
  - profile_name: "TF_PROFILE_1"
    action: "report_only"           # report_only, block_and_report
  - profile_name: "TF_PROFILE_2"
    action: "block_and_report"

create_tf_protections:
  - profile_name: "TF_PROFILE_1"
    protection_name: "TF_PROT_1"
    status: "enable"                # enable, disable (Default: enable)
    match_criteria: "match"         # match, not-match
    protocol: "tcp"                 # any, tcp, udp, icmp
    tcp_syn: "enable"               # enable, disable
    tcp_ack: "enable"               # enable, disable
    tcp_rst: "disable"              # enable, disable
    tcp_synack: "enable"            # enable, disable
    tcp_finack: "enable"            # enable, disable
    tcp_pshack: "disable"           # enable, disable
    threshold_pps: "5000"           # packet per second threshold
    threshold_kbps: "0"              # kilo bits per second threshold
    packet_report: "enable"         # enable, disable
    threshold_unit: "pps"           # kbps, pps
    attack_tracking_type: "per_destination"    # all, per-source, per-destination, per_source_and_destination, track_returning_traffic


```
### Editing Traffic Filter (Partial Updates)
```yaml
# Minimal Traffic Filter protections for testing
edit_tf_protections:
  - profile_name: "TF_PROFILE_1"
    protection_name: "TF_PROT_1"
    status: "enable"              # enable/disable
    match_criteria: "match"       # options: match, not-match
    protocol: "tcp"               # options: any, tcp, udp, icmp, igmp, sctp, icmpv6, gre, ipinip
    tcp_syn: "enable"
    tcp_ack: "enable"
    tcp_rst: "disable"
    tcp_synack: "enable"
    tcp_finack: "disable"
    tcp_pshack: "enable"
    threshold_pps: 0
    threshold_kbps: 10000
    threshold_unit: "kbps"         # options: pps, kbps
    packet_report: "enable"       # enable/disable
    attack_tracking_type: "all"  # options: all, per_source, per_destination, per_source_and_destination, track_returning_traffic


```

### Get Traffic Filter
```yaml
# Filter by specific Traffic Filter profile names, or leave empty list for all profiles
filter_tf_profile_names: ["TF_PROFILE_1", "TF_PROFILE_2"]

# Examples:
# filter_tf_profile_names: ["TF_PROFILE_1"]           # Show only one profile
# filter_tf_profile_names: ["TF_PROFILE_1","TF_PROFILE_2"]  # Show multiple profiles
# filter_tf_profile_names: []  

```

### Delete Traffic Filter

```yaml
# Structure must match what the module expects: "profiles" and "protections"

delete_traffic_filters:
  profiles:
    - name: "TF_PROFILE_1"
    - name: "TF_PROFILE_2"

  protections:
    - profile_name: "TF_PROFILE_1"
      name: "TF_PROT_1"
    - profile_name: "TF_PROFILE_2"
      name: "TF_PROT_2"                # Show all profiles (default)

  # you can delete multiple profiles and protections in one run.
  # either you can delete just protections, or both.
```
### Notes for Traffic Filter Profiles

*** profile_name ***: MANDATORY – Unique profile name.
*** state ***: Optional – enable or disable (default: enable).
*** action ***: Optional – report_only or block_and_report (default: report_only).
*** Thresholds ***:
# threshold_pps: Packets per second limit.
# threshold_kbps: Bits per second limit.
# threshold_unit: Unit for threshold (pps/kbps).
*** attack_tracking_type ***: Optional – all, per_source, per_destination, etc.
*** TCP flags ***: Optional – enable/disable per flag (syn, ack, rst, synack, finack, pshack).
*** packet_report ***: Optional – enable/disable packet logging.




### SYN Profiles - Complete Configuration Reference

# Important: Both syn_protections and syn_profiles sections are completely optional. You can define one, another, or both, based on your needs.

# Creating SYN Protections (ALL Supported Parameters)
# OPTIONAL: Define new SYN protections (only if you want to create)
```yaml
create_syn_protections:
  - name: "syn_protection"                     # MANDATORY: Protection name
    activation_threshold: 2500                 # OPTIONAL: Activation threshold 
    termination_threshold: 1500                # OPTIONAL: Termination threshold 
    app_port_group: "http"                     # OPTIONAL: http, https, dns, ftp, smtp, imap, custom, or "" (default: "http")
    packet_report: "enable"                    # OPTIONAL: enable, disable (default: disable)
    index: 0                              # OPTIONAL: 0 or 500001+ (default: 0)

  # Minimal example (only mandatory parameter)
  - name: "syn_prot_minimal"                     # MANDATORY: Only this is required
    # All other parameters use defaults

  # Custom index example
  - name: "syn_prot_custom_index"
    activation_threshold: 4000
    termination_threshold: 3000
    app_port_group: "https"
    index: 500031

# Define SYN profiles and attach protections
create_syn_profiles:
  - name: "SYN_PROFILE_1"
    protections:
      - "SYN_PROT_1"
  - name: "SYN_PROFILE_2"
    protections:
      - "SYN_PROT_2"
```
### Editing SYN Protections (Partial Updates)
# Edit existing protections - ONLY specify what you want to change
```yaml
edit_syn_protections:
  - index: 500030                                # MANDATORY: Must specify which protection to edit
    activation_threshold: 3500                   # OPTIONAL: Change activation threshold
    termination_threshold: 2500                  # OPTIONAL: Change termination threshold

  - index: 500031
    packet_report: "disable"                     # OPTIONAL: Change packet reporting only

  - index: 500032
    app_port_group: "dns"                        # OPTIONAL: Change app port group
```

### Getting SYN Profiles and Protections
# Get all SYN profiles and protections from devices
# No configuration needed - just run the playbook
```yaml
ansible-playbook playbooks/get_syn_profiles.yml
```
# Filter by specific profile names (configure in get_vars.yml)
```yaml
filter_syn_profile_names: ["SYN_PROFILE_1", "SYN_PROFILE_2"]  # Show only these profiles
# filter_syn_profile_names: []                                # Show all profiles (default)
```
### Deleting SYN Profiles and Protections
# OPTIONAL: Remove protections from profiles (without deleting protection itself)
```yaml
syn_profile_deletions:
  - profile_name: "SYN_PROFILE_1"
    protections:
      - "SYN_PROT_1"
      - "SYN_PROT_2"

  - profile_name: "SYN_PROFILE_2"
    protections:
      - "SYN_PROT_2"

# OPTIONAL: Delete protections entirely (protection must not be in any profile)
syn_protection_deletions:
  - protections_to_delete:
      - "SYN_PROT_1"         # Delete by name (module looks up index)
      - "SYN_PROT_2"
      - 500030               # Delete by index directly
      - 500031
```

### Parameter Reference for SYN Protections:

# Parameter	Status	Options	Default	Description
# name	MANDATORY	Any string	-	Protection name (create only)
# index	MANDATORY (edit) / optional (create)	Integer	0	Protection index (used for edit/delete)
# activation_threshold	OPTIONAL	"number"	1000	Threshold to trigger protection
# termination_threshold	OPTIONAL	"number"	800	Threshold to stop protection
# app_port_group	OPTIONAL	http, https, dns, ftp, smtp, imap, custom, ""	""	App port filtering
# packet_report	OPTIONAL	enable, disable	disable	Detailed packet reporting


### Key Points for Editing:

# Partial Updates: Only specify parameters you want to change
# Unchanged Values: Unspecified parameters keep their current values
# Flexible: Change one parameter or many in a single operation

### SYN Profiles (Optional Section)
# OPTIONAL: Profiles (can reference existing or newly created protections)
```yaml
syn_profiles:
  - name: "SYN_PROFILE_1"                        # MANDATORY: Profile name
    protections:                                 # MANDATORY: List of protections
      - "SYN_PROT_1"                             # Can be newly created
      - "SYN_PROT_2"                             # Or existing on DefensePro

  - name: "SYN_PROFILE_2"
    protections:
      - "syn_prot_comprehensive_example"
      - "legacy_syn_protection"
```

### Profile Configuration Notes:

# name: MANDATORY - Unique profile name
# protections: MANDATORY - List of protection names to include
# Mixed References: Can combine newly created and existing protections
# Flexible: Create profiles with any combination of protections

## Usage Pattern Examples
# Example 1: Create new protections + profiles
```yaml
syn_protections:
  - name: "syn_web_protection"
    activation_threshold: 2500
    termination_threshold: 1500
    app_port_group: "http"
  - name: "syn_api_protection"
    activation_threshold: 4000
    termination_threshold: 3000
    app_port_group: "https"

syn_profiles:
  - name: "SYN_PROFILE_WEB"
    protections:
      - "syn_web_protection"
      - "syn_api_protection"

# Example 2: Use only existing protections (skip syn_protections)
syn_profiles:
  - name: "SYN_PROFILE_EXISTING"
    protections:
      - "SYN_PROT_1"
      - "SYN_PROT_2"

# Example 3: Mixed approach (some new, some existing)
syn_protections:
  - name: "syn_new_custom"
    activation_threshold: 5000
    termination_threshold: 3500
    app_port_group: "dns"
    index: 500032
syn_profiles:
  - name: "SYN_PROFILE_MIXED"
    protections:
      - "syn_new_custom"         # Newly created above
      - "SYN_PROT_1"             # Already exists on device
```
### All modules support check mode (`--check`) for previewing changes.

### Security Policy Configuration

**Security Policy Configuration Notes**:
- **policy_name**: MANDATORY - Unique policy name
- **src_network, dst_network**: MANDATORY - Network class names (use "any" for any network)
- **direction**: MANDATORY - Traffic direction to match
- **Profile bindings**: All optional - leave empty string for no binding
- **Control flags**: Use to enable/disable each creation stage independently

Configure security policies with profile bindings in `vars/create_vars.yml`:

```yaml
# Orchestration control flags
# Control orchestration behavior
security_policy_config:
  create_network_classes: true
  create_cl_profiles: true
  create_bdos_profiles: true
  create_dns_profiles: true
  create_https_profiles: true
  create_oos_profiles: true
  create_traffic_filter_profiles: true
  create_ssl_objects: true
  create_security_policies: true
  apply_policies_after_creation: true

# Security policies with profile bindings
create_security_policies:
  - policy_name: "comprehensive_policy"
    state: "enable"
    action: "report_only"
    priority: "700"
    src_network: "any"
    dst_network: "web_servers"
    direction: "oneway"
    
    # Profile bindings (all optional)
    connection_limit_profile: "web_limits"
    bdos_profile: "bdos_profile_1"
    dns_flood_profile: "dns_profile_1"
    https_flood_profile: "https_profile_1"
    traffic_filters_profile: "tf_profile_1"
    signature_protection_profile: "All-DoS-Shield"
```

## 🛠️ Best Practices

### Development Workflow
1. **Always test first**: Use `--check` flag for dry-run validation
2. **Start small**: Begin with single device, expand to multiple devices
3. **Use filtering**: Leverage `filter_*_names` in get operations for focused results
4. **Incremental changes**: Edit only parameters you need to change
5. **Backup configurations**: Query current state before making changes

### Error Handling
- **Check mode validation**: Preview shows exactly what will be changed
- **Dependency validation**: Profile deletions validate dependencies
- **Error collection**: Batch operations collect and report all errors
- **Device locking**: Automatic device locking prevents configuration conflicts

### Common Patterns
- **Create-then-query**: Verify results after creation operations
- **Edit-specific-parameters**: Only specify parameters you want to change
- **Conditional orchestration**: Use security_policy_config flags to control stages
- **Profile references**: Mix new and existing profiles in security policies

## 📞 Support & Troubleshooting

### Common Issues
1. **Connection errors**: Verify CyberController IP, credentials, and network connectivity
2. **Parameter validation**: Check parameter formats and valid values in examples
3. **Profile dependencies**: Ensure profiles exist before referencing in policies
4. **Device locking**: Wait for lock release if device is locked by another process

### Getting Help
- **Configuration examples**: All `*.example` files contain detailed parameter documentation
- **Technical details**: See [DEVELOPER.md](DEVELOPER.md) for API documentation and architecture
- **Error messages**: Most error messages include specific guidance for resolution