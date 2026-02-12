# OpenSCAP Triage Summary

- Generated: **2026-02-10T15:43:40**
- Target: **10.244.190.234**
- Profile: **xccdf_org.ssgproject.content_profile_stig**
- Mode: **fast**
- Model used (majority): **fallback_default**
- Min severity: **2**
- Triaged findings: **31**

## Counts

- **safe_to_remediate**: 0 (0.0%)
- **requires_human_review**: 26 (83.9%)
- **too_dangerous_to_remediate**: 5 (16.1%)

## Safe to remediate (0)


## Requires human review (26)

### openscap_001
- rule_id: `xccdf_org.ssgproject.content_rule_enable_dracut_fips_module`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_002
- rule_id: `xccdf_org.ssgproject.content_rule_enable_fips_mode`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_003
- rule_id: `xccdf_org.ssgproject.content_rule_sysctl_crypto_fips_enabled`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_004
- rule_id: `xccdf_org.ssgproject.content_rule_harden_sshd_macs_openssh_conf_crypto_policy`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_005
- rule_id: `xccdf_org.ssgproject.content_rule_harden_sshd_macs_opensshserver_conf_crypto_policy`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_006
- rule_id: `xccdf_org.ssgproject.content_rule_installed_OS_is_vendor_supported`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_012
- rule_id: `xccdf_org.ssgproject.content_rule_accounts_password_pam_dcredit`
- confidence: 0.70
- rationale: Authentication/authorization hardening can lock out SSH/automation. Requires review and staged rollout.
- risk_factors: potential lockout, access control changes
- safe_next_steps:
  - Ensure you have console access/snapshot before changes.
  - Prefer creating a dedicated automation user with controlled sudo rules.
  - Apply changes in staging VM and verify SSH access before promoting.

### openscap_013
- rule_id: `xccdf_org.ssgproject.content_rule_accounts_password_pam_lcredit`
- confidence: 0.70
- rationale: Authentication/authorization hardening can lock out SSH/automation. Requires review and staged rollout.
- risk_factors: potential lockout, access control changes
- safe_next_steps:
  - Ensure you have console access/snapshot before changes.
  - Prefer creating a dedicated automation user with controlled sudo rules.
  - Apply changes in staging VM and verify SSH access before promoting.

### openscap_014
- rule_id: `xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen`
- confidence: 0.70
- rationale: Authentication/authorization hardening can lock out SSH/automation. Requires review and staged rollout.
- risk_factors: potential lockout, access control changes
- safe_next_steps:
  - Ensure you have console access/snapshot before changes.
  - Prefer creating a dedicated automation user with controlled sudo rules.
  - Apply changes in staging VM and verify SSH access before promoting.

### openscap_015
- rule_id: `xccdf_org.ssgproject.content_rule_accounts_password_pam_ocredit`
- confidence: 0.70
- rationale: Authentication/authorization hardening can lock out SSH/automation. Requires review and staged rollout.
- risk_factors: potential lockout, access control changes
- safe_next_steps:
  - Ensure you have console access/snapshot before changes.
  - Prefer creating a dedicated automation user with controlled sudo rules.
  - Apply changes in staging VM and verify SSH access before promoting.

### openscap_016
- rule_id: `xccdf_org.ssgproject.content_rule_accounts_password_pam_ucredit`
- confidence: 0.70
- rationale: Authentication/authorization hardening can lock out SSH/automation. Requires review and staged rollout.
- risk_factors: potential lockout, access control changes
- safe_next_steps:
  - Ensure you have console access/snapshot before changes.
  - Prefer creating a dedicated automation user with controlled sudo rules.
  - Apply changes in staging VM and verify SSH access before promoting.

### openscap_017
- rule_id: `xccdf_org.ssgproject.content_rule_accounts_authorized_local_users`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_018
- rule_id: `xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_019
- rule_id: `xccdf_org.ssgproject.content_rule_grub2_admin_username`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_020
- rule_id: `xccdf_org.ssgproject.content_rule_grub2_password`
- confidence: 0.70
- rationale: Authentication/authorization hardening can lock out SSH/automation. Requires review and staged rollout.
- risk_factors: potential lockout, access control changes
- safe_next_steps:
  - Ensure you have console access/snapshot before changes.
  - Prefer creating a dedicated automation user with controlled sudo rules.
  - Apply changes in staging VM and verify SSH access before promoting.

### openscap_021
- rule_id: `xccdf_org.ssgproject.content_rule_service_firewalld_enabled`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_022
- rule_id: `xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_023
- rule_id: `xccdf_org.ssgproject.content_rule_sysctl_user_max_user_namespaces_no_remediation`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_024
- rule_id: `xccdf_org.ssgproject.content_rule_selinux_context_elevation_for_sudo`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_025
- rule_id: `xccdf_org.ssgproject.content_rule_selinux_state`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_026
- rule_id: `xccdf_org.ssgproject.content_rule_postfix_prevent_unrestricted_relay`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_027
- rule_id: `xccdf_org.ssgproject.content_rule_chronyd_server_directive`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_028
- rule_id: `xccdf_org.ssgproject.content_rule_sshd_disable_root_login`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_029
- rule_id: `xccdf_org.ssgproject.content_rule_sssd_enable_certmap`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_030
- rule_id: `xccdf_org.ssgproject.content_rule_configure_usbguard_auditbackend`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.

### openscap_031
- rule_id: `xccdf_org.ssgproject.content_rule_service_auditd_enabled`
- confidence: 0.40
- rationale: LLM triage failed; defaulting to requires_human_review. Last error: API/runtime error with model nvidia/nemotron-4-mini-instruct: OpenRouter API error 400: {"error":{"message":"nvidia/nemotron-4-mini-instruct is not a valid model ID","code":400},"user_id":"user_35GamuJcm8kTLrFPwUeBmFbmFiD"}
- risk_factors: triage automation failure
- safe_next_steps:
  - Review manually; verify rule intent in STIG/SSG guidance.


## Too dangerous to remediate (5)

### openscap_007
- rule_id: `xccdf_org.ssgproject.content_rule_partition_for_tmp`
- confidence: 0.85
- rationale: Filesystem/partition/mount-option changes can break boot or services and should not be auto-remediated.
- risk_factors: filesystems/partitioning, service disruption risk
- safe_next_steps:
  - Document required partitions/mount options and implement during rebuild (Kickstart/Anaconda).
  - Validate application compatibility with mount options in a staging VM.

### openscap_008
- rule_id: `xccdf_org.ssgproject.content_rule_partition_for_var`
- confidence: 0.85
- rationale: Filesystem/partition/mount-option changes can break boot or services and should not be auto-remediated.
- risk_factors: filesystems/partitioning, service disruption risk
- safe_next_steps:
  - Document required partitions/mount options and implement during rebuild (Kickstart/Anaconda).
  - Validate application compatibility with mount options in a staging VM.

### openscap_009
- rule_id: `xccdf_org.ssgproject.content_rule_partition_for_var_log`
- confidence: 0.85
- rationale: Filesystem/partition/mount-option changes can break boot or services and should not be auto-remediated.
- risk_factors: filesystems/partitioning, service disruption risk
- safe_next_steps:
  - Document required partitions/mount options and implement during rebuild (Kickstart/Anaconda).
  - Validate application compatibility with mount options in a staging VM.

### openscap_010
- rule_id: `xccdf_org.ssgproject.content_rule_partition_for_var_log_audit`
- confidence: 0.85
- rationale: Filesystem/partition/mount-option changes can break boot or services and should not be auto-remediated.
- risk_factors: filesystems/partitioning, service disruption risk
- safe_next_steps:
  - Document required partitions/mount options and implement during rebuild (Kickstart/Anaconda).
  - Validate application compatibility with mount options in a staging VM.

### openscap_011
- rule_id: `xccdf_org.ssgproject.content_rule_partition_for_var_tmp`
- confidence: 0.85
- rationale: Filesystem/partition/mount-option changes can break boot or services and should not be auto-remediated.
- risk_factors: filesystems/partitioning, service disruption risk
- safe_next_steps:
  - Document required partitions/mount options and implement during rebuild (Kickstart/Anaconda).
  - Validate application compatibility with mount options in a staging VM.

