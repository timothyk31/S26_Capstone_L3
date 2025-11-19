#!/usr/bin/env python3
"""
Adaptive QA Agent - Self-correcting with feedback loops

This agent:
1. Scans for vulnerabilities
2. For each vulnerability:
   - Gets LLM suggestion
   - Applies fix
   - Rescans to verify
   - IF FAILED: Feeds error back to LLM and tries different approach
   - Iterates until success or max attempts
3. Learns from failures and adapts strategy
"""
import os
import sys
import json
import time
import random
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import subprocess
import shlex
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm
from dotenv import load_dotenv

from schemas import Vulnerability, RemediationSuggestion
from openscap_cli import OpenSCAPScanner
from parse_openscap import parse_openscap
from remediation_bridge import RemediationBridge
from qa_loop import AnsibleExecutor
from pydantic_ai import Agent, NativeOutput
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider

console = Console()

load_dotenv()


class AdaptiveQAAgent:
    """Self-correcting agent with feedback loops"""
    
    def __init__(
        self,
        scanner: OpenSCAPScanner,
        ansible_inventory: str,
        work_dir: Path,
        scan_profile: str,
        scan_datastream: str,
        sudo_password: Optional[str] = None,
        max_attempts: int = 5,
        interactive: bool = True,
    ):
        self.scanner = scanner
        self.ansible_executor = AnsibleExecutor(ansible_inventory)
        self.ssh_executor = SSHExecutor(
            host=scanner.target_host,
            user=scanner.ssh_user,
            key=scanner.ssh_key,
            port=scanner.ssh_port,
            sudo_password=sudo_password
        )
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True, parents=True)
        self.scan_profile = scan_profile
        self.scan_datastream = scan_datastream
        self.sudo_password = sudo_password
        self.max_attempts = max_attempts
        self.interactive = interactive
        
        # Initialize LLM agent for adaptive remediation
        self.llm_agent = self._init_llm_agent()
        
        # Track results
        self.results = {
            'fixed_first_try': [],
            'fixed_after_retry': [],
            'failed_all_attempts': [],
            'skipped': []
        }
        
        # Learning: track what works
        self.success_patterns = []
        self.failure_patterns = []
    
    def _init_llm_agent(self):
        """Initialize adaptive LLM agent"""
        # Load environment variables
        api_key = os.getenv('OPENROUTER_API_KEY')
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY not found in .env file!")
        model_name = os.getenv('OPENROUTER_MODEL')
        if not model_name:
            raise ValueError("OPENROUTER_MODEL not found in .env file!")
        
        # Configure OpenRouter model using OpenAIProvider
        model = OpenAIChatModel(
            model_name=model_name,
            provider=OpenAIProvider(
                base_url=os.getenv('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1'),
                api_key=api_key
            )
        )
        
        agent = Agent(
            model,
            output_type=NativeOutput(RemediationSuggestion, strict=True),
            system_prompt=(
                "You are an adaptive security remediation agent. "
                "When a fix fails, you learn from the error and suggest a different approach. "
                "Analyze error messages, consider alternative methods, and try different strategies. "
                "Your goal is to successfully fix security vulnerabilities, adapting your approach based on feedback."
            )
        )
        return agent
    
    def scan_for_vulnerability(self, vuln: Vulnerability) -> bool:
        """Check if a specific vulnerability still exists.
        
        Returns True if vulnerability still exists, False if fixed.
        Verification is performed by rescanning and checking the specific
        OpenSCAP rule result for this vulnerability.
        """
        console.print(f"[cyan]🔍 Checking if {vuln.id} is fixed...[/cyan]")
        
        # Run scan
        scan_file = self.work_dir / f"verify_{vuln.id}.xml"
        parsed_file = self.work_dir / f"verify_{vuln.id}.json"
        
        success = self.scanner.run_scan(
            profile=self.scan_profile,
            output_file=f"/tmp/verify_{vuln.id}.xml",
            datastream=self.scan_datastream,
            sudo_password=self.sudo_password
        )
        
        if not success:
            console.print("[yellow]⚠ Could not verify, assuming not fixed[/yellow]")
            return True  # Assume still exists if scan fails
        
        # Download and parse
        self.scanner.download_results(f"/tmp/verify_{vuln.id}.xml", str(scan_file))
        parse_openscap(str(scan_file), str(parsed_file))
        
        # Check if vulnerability still exists
        with open(parsed_file) as f:
            current_vulns = json.load(f)
        
        # Improved matching: try multiple strategies
        still_exists = False
        for finding in current_vulns:
            # Strategy 1: Match by title (exact)
            if finding.get('title') == vuln.title:
                still_exists = finding.get('result') in ['fail', 'error']
                if still_exists:
                    break
            
            # Strategy 2: Match by rule name (from parse_openscap, rule field contains short name)
            if finding.get('rule') and vuln.title:
                # Extract rule name from vuln.title (last part after rule_)
                vuln_rule_name = vuln.title.split('rule_')[-1] if 'rule_' in vuln.title else vuln.title
                finding_rule = finding.get('rule', '')
                if vuln_rule_name in finding_rule or finding_rule in vuln_rule_name:
                    still_exists = finding.get('result') in ['fail', 'error']
                    if still_exists:
                        break
            
            # Strategy 3: Match by oval_id if available
            if finding.get('oval_id') and hasattr(vuln, 'oval_id') and vuln.oval_id:
                if finding.get('oval_id') == vuln.oval_id:
                    still_exists = finding.get('result') in ['fail', 'error']
                    if still_exists:
                        break
            
            # Strategy 4: Partial title match (for cases where title might be slightly different)
            if finding.get('title') and vuln.title:
                # Check if titles are similar (one contains the other)
                if vuln.title.lower() in finding.get('title', '').lower() or \
                   finding.get('title', '').lower() in vuln.title.lower():
                    still_exists = finding.get('result') in ['fail', 'error']
                    if still_exists:
                        break
        
        return still_exists
    
    def get_initial_remediation(self, vuln: Vulnerability) -> RemediationSuggestion:
        """Get initial remediation suggestion from LLM"""
        console.print("[cyan]🤖 Getting initial remediation from AI...[/cyan]")
        
        # Parse the OpenSCAP rule name to understand what it's checking
        rule_name = vuln.title.replace('xccdf_org.ssgproject.content_rule_', '')

        # Always use LLM for remediation (built-in remediations disabled)
        # builtin = self.get_rule_based_remediation(vuln, rule_name)
        # if builtin is not None:
        #     console.print("[green]Using built-in remediation for this rule[/green]")
        #     return builtin
        
        # Include description and recommendation if available
        description = getattr(vuln, 'description', '') or ''
        recommendation = getattr(vuln, 'recommendation', '') or ''
        
        prompt = f"""You are remediating an OpenSCAP security compliance finding on Rocky Linux 10 (RHEL-based).

VULNERABILITY DETAILS:
- Rule Name: {rule_name}
- Full Rule ID: {vuln.title}
- Severity: {vuln.severity} (0=info, 1=low, 2=medium, 3=high, 4=critical)
- Host: {vuln.host}
{f"- Description: {description[:500]}" if description else ""}
{f"- Recommendation: {recommendation[:500]}" if recommendation else ""}

SYSTEM INFORMATION:
- OS: Rocky Linux 10 (RHEL-based, uses dnf/yum, systemd)
- Package Manager: dnf (NOT apt, NOT apt-get).
- Init System: systemd
- Configuration: Files typically in /etc/

TASK:
Based on the rule name "{rule_name}", determine what OpenSCAP is checking and provide the EXACT commands needed to fix it.

IMPORTANT EXECUTION CONTEXT:
- Your commands will be executed as a SINGLE SHELL SCRIPT running as ROOT.
- You can use variables, loops, and change directories (cd) - state IS preserved within the script.
- DO NOT include 'sudo' in your commands - the entire script runs as root.
- If you need to edit files, use 'sed', 'echo', or 'cat'.

COMMON OPENSCAP RULE PATTERNS AND REMEDIATION:

1. Package Installation Rules (package_*_installed):
   - Command: dnf install -y <package-name>
   - Verify: rpm -q <package-name>
   - Example: "package_aide_installed" → dnf install -y aide

2. Service Rules (service_*_enabled, service_*_running):
   - Enable: systemctl enable <service>
   - Start: systemctl start <service>
   - Verify: systemctl is-enabled <service> && systemctl is-active <service>
   - Example: "service_auditd_enabled" → systemctl enable auditd && systemctl start auditd

3. AIDE Rules (aide_*):
   - Install: dnf install -y aide
   - Initialize: aide --init
   - Copy database: if [ -f /var/lib/aide/aide.db.new.gz ]; then cp -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz; fi
   - CRITICAL: DO NOT use 'systemctl ... aide.service' (this unit does not exist)
   - Example: "aide_build_database" → dnf install -y aide && aide --init && if [ -f /var/lib/aide/aide.db.new.gz ]; then cp -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz; fi

4. Audit Rules (auditd_*):
   - Install: dnf install -y audit
   - Configure: Edit /etc/audit/auditd.conf (use sed or echo)
   - Enable/Start: systemctl enable auditd && systemctl start auditd
   - Restart after config: systemctl restart auditd

5. Sysctl Rules (sysctl_*):
   - Set immediately: sysctl -w <key>=<value>
   - Persist: echo "<key>=<value>" >> /etc/sysctl.d/99-custom.conf
   - Load: sysctl --system
   - Verify: sysctl <key>

6. File Permission Rules (file_permissions_*, file_ownership_*):
   - Set permissions: chmod <mode> <file>
   - Set ownership: chown <user>:<group> <file>
   - Verify: stat -c %a <file> (for permissions)
   - Common modes: 0600 (owner read/write), 0644 (owner read/write, others read), 0755 (executable)

7. SSH Configuration Rules (sshd_*):
   - Edit: /etc/ssh/sshd_config
   - Use sed or echo to modify settings
   - Restart: systemctl restart sshd
   - Verify: sshd -t (test config)

8. GRUB Rules (grub2_*):
   - Edit: /etc/default/grub or /boot/grub2/grub.cfg
   - Regenerate: grub2-mkconfig -o /boot/grub2/grub.cfg
   - May require reboot

9. Firewall Rules (firewalld_*):
   - Install: dnf install -y firewalld
   - Enable/Start: systemctl enable firewalld && systemctl start firewalld
   - Configure zones/rules as needed

IMPORTANT GUIDELINES:
- Use DNF, NOT apt or apt-get
- Be SPECIFIC and COMPLETE - don't just install packages, configure them properly
- Include verification commands where appropriate
- Use idempotent commands when possible (check before modifying)
- For configuration files, use sed or echo with proper escaping
- Always restart services after configuration changes (unless service refuses restart - use alternatives like augenrules --load for auditd)
- DO NOT reference 'aide.service' systemd unit (it does not exist)
- For file redirections: use echo 'text' >> /path/to/file
- For conditionals: use if condition; then action; fi
- For audit rules: prefer augenrules --load over systemctl restart auditd (auditd may refuse restart)

Provide the EXACT commands that will make this OpenSCAP check pass. Return commands as a list, in the order they should be executed.
"""
        
        # Log the prompt
        prompt_log_file = self.work_dir / f"llm_prompt_{vuln.id}_initial.txt"
        prompt_log_file.write_text(prompt, encoding='utf-8')
        
        result = self.llm_agent.run_sync(prompt)
        
        # Log the response
        response_log_file = self.work_dir / f"llm_response_{vuln.id}_initial.json"
        
        # Handle usage stats - RunUsage doesn't have model_dump(), convert to dict manually
        usage_data = None
        try:
            if hasattr(result, 'usage') and callable(result.usage):
                usage = result.usage()
                usage_data = {
                    'requests': getattr(usage, 'requests', None),
                    'input_tokens': getattr(usage, 'input_tokens', None),
                    'output_tokens': getattr(usage, 'output_tokens', None),
                }
        except Exception:
            usage_data = None
        
        response_log_file.write_text(json.dumps({
            'vuln_id': vuln.id,
            'attempt': 1,
            'remediation': result.output.model_dump() if hasattr(result.output, 'model_dump') else str(result.output),
            'usage': usage_data
        }, indent=2), encoding='utf-8')
        
        return result.output

    def get_rule_based_remediation(self, vuln: Vulnerability, rule_name: str) -> Optional[RemediationSuggestion]:
        """Return a deterministic remediation for known OpenSCAP rules.

        This improves reliability by applying well-known fixes on RHEL/Rocky.
        Returns None if no built-in remediation is available.
        """
        rn = rule_name
        cmds: List[str] = []
        notes = ""

        # AIDE rules
        if rn == 'package_aide_installed' or 'aide_installed' in rn:
            cmds = [
                'dnf install -y aide',
            ]
            notes = 'Install AIDE using dnf on Rocky/RHEL.'
        elif rn == 'aide_build_database' or 'aide_build' in rn or 'aide_init' in rn:
            cmds = [
                'dnf install -y aide',
                'aide --init',
                'if [ -f /var/lib/aide/aide.db.new.gz ]; then cp -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz; fi'
            ]
            notes = 'Initialize AIDE database after installation.'
        elif 'aide_check_audit_tools' in rn:
            cmds = [
                'cp -n /etc/aide.conf /etc/aide.conf.bak || true',
                "grep -qE '^/sbin/audit\\* ' /etc/aide.conf || echo '/sbin/audit* p+i+n+u+g+s+m+c+sha256' >> /etc/aide.conf",
                "grep -qE '^/usr/sbin/audit\\* ' /etc/aide.conf || echo '/usr/sbin/audit* p+i+n+u+g+s+m+c+sha256' >> /etc/aide.conf",
                'aide --init',
                'if [ -f /var/lib/aide/aide.db.new.gz ]; then cp -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz; fi',
                'aide --check'
            ]
            notes = 'Ensure audit tools are monitored by AIDE and reinitialize database.'

        # Auditd rules
        elif rn.startswith('package_audit') or rn.startswith('package_auditd'):
            cmds = [
                'dnf install -y audit',
            ]
            notes = 'Install audit package.'
        elif rn.startswith('service_auditd_enabled') or 'auditd_service' in rn:
            cmds = [
                'systemctl enable auditd',
                'systemctl start auditd'
            ]
            notes = 'Ensure auditd is enabled and running.'
        elif 'auditd_data_retention_space_left_action' in rn:
            cmds = [
                "sed -ri 's/^[[:space:]]*space_left_action[[:space:]]*=.*/space_left_action = email/' /etc/audit/auditd.conf",
                "sed -ri 's/^[[:space:]]*action_mail_acct[[:space:]]*=.*/action_mail_acct = root/' /etc/audit/auditd.conf",
                'systemctl restart auditd'
            ]
            notes = 'Configure auditd retention action and restart.'

        # Firewalld rules
        elif rn == 'package_firewalld_installed' or 'firewalld_installed' in rn:
            cmds = [
                'dnf install -y firewalld',
            ]
            notes = 'Install firewalld.'
        elif rn == 'service_firewalld_enabled' or 'firewalld_enabled' in rn:
            cmds = [
                'systemctl enable firewalld',
                'systemctl start firewalld'
            ]
            notes = 'Enable and start firewalld.'

        # SSH rules examples
        elif 'sshd_disable_root_login' in rn or 'permitrootlogin' in rn:
            cmds = [
                "if grep -qi '^[[:space:]]*PermitRootLogin' /etc/ssh/sshd_config; then sed -ri 's/^[[:space:]]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config; else echo 'PermitRootLogin no' >> /etc/ssh/sshd_config; fi",
                'systemctl restart sshd'
            ]
            notes = 'Disable SSH root login and restart sshd.'

        # Sysctl generic pattern example
        elif rn.startswith('sysctl_'):
            # Attempt to infer key=value from rule name is unreliable; let LLM handle unless specified
            cmds = []

        if cmds:
            return RemediationSuggestion(id=vuln.id, proposed_commands=cmds, notes=notes)
        return None
    
    def get_adaptive_remediation(self, vuln: Vulnerability, 
                                 previous_attempts: List[Dict],
                                 error_message: str) -> RemediationSuggestion:
        """Get adaptive remediation based on previous failures"""
        console.print("[yellow]🔄 Getting adaptive remediation (learning from failure)...[/yellow]")
        
        # Build detailed context from previous attempts with error analysis
        attempt_history_parts = []
        for i, att in enumerate(previous_attempts):
            attempt_info = f"Attempt {i+1}:\n"
            attempt_info += f"Commands executed:\n"
            for j, cmd in enumerate(att.get('commands', []), 1):
                attempt_info += f"  {j}. {cmd}\n"
            
            attempt_info += f"Execution Status: {'✓ Succeeded' if att.get('apply_success') else '✗ Failed'}\n"
            attempt_info += f"OpenSCAP Verification: {'✓ FIXED' if att.get('verified', False) else '✗ STILL VULNERABLE' if att.get('verified') is not None else '⚠ Not verified'}\n"

            # Summarize error categories, if present
            categories = att.get('error_categories') or []
            if categories:
                attempt_info += f"Error Categories: {', '.join(categories)}\n"
            
            # Include detailed command results if available
            detailed_results = att.get('detailed_results', [])
            if detailed_results:
                attempt_info += f"\nCommand-by-command results:\n"
                for cmd_result in detailed_results:
                    cmd_info = f"  Command: {cmd_result.get('command', 'unknown')}\n"
                    cmd_info += f"    Exit Code: {cmd_result.get('exit_code', 'N/A')}\n"
                    cmd_info += f"    Success: {cmd_result.get('success', False)}\n"
                    if cmd_result.get('error_type'):
                        cmd_info += f"    Error Type: {cmd_result.get('error_type')}\n"
                    if cmd_result.get('stdout'):
                        stdout_preview = cmd_result.get('stdout', '')[:200]
                        cmd_info += f"    Stdout: {stdout_preview}{'...' if len(cmd_result.get('stdout', '')) > 200 else ''}\n"
                    if cmd_result.get('stderr'):
                        stderr_preview = cmd_result.get('stderr', '')[:200]
                        cmd_info += f"    Stderr: {stderr_preview}{'...' if len(cmd_result.get('stderr', '')) > 200 else ''}\n"
                    attempt_info += cmd_info + "\n"
            else:
                # Fallback to error message
                error_msg = att.get('error') or 'No error information available'
                if error_msg:
                    error_preview = error_msg[:500] if len(str(error_msg)) > 500 else str(error_msg)
                    attempt_info += f"Error Output: {error_preview}\n"
                else:
                    attempt_info += "Error Output: No error information available\n"
            
            attempt_history_parts.append(attempt_info)
        
        attempt_history = "\n\n".join(attempt_history_parts)
        
        rule_name = vuln.title.replace('xccdf_org.ssgproject.content_rule_', '')
        
        prompt = f"""PREVIOUS REMEDIATION ATTEMPT FAILED! Analyze what went wrong and try a COMPLETELY DIFFERENT approach.

SYSTEM: Rocky Linux 10 (RHEL-based, uses dnf, systemd)

VULNERABILITY:
- Rule: {rule_name}
- OpenSCAP Rule ID: {vuln.title}
- Current Status: STILL VULNERABLE after {len(previous_attempts)} attempt(s)

WHAT HAPPENED:
{attempt_history}

ANALYSIS REQUIRED:
1. WHY did the previous approach fail? Look at exit codes and error messages.
2. Was the package/service actually installed/configured? Check stdout for confirmation.
3. Did we miss a configuration step? Review what OpenSCAP is actually checking.
4. Is there a different way to achieve the same compliance?
5. Are there permission issues? Check stderr for "Permission denied" or "Access denied".
6. Are commands being executed in the right order? Some fixes require multiple steps.

COMMON OPENSCAP ISSUES AND SOLUTIONS:
- "package_*_installed" rules: 
  * Package must be installed: dnf install -y <package>
  * Some packages need configuration after installation
  * Verify with: rpm -q <package>
  
- "aide_*" rules: 
  * Install: dnf install -y aide
  * Initialize: aide --init
  * Copy database: if [ -f /var/lib/aide/aide.db.new.gz ]; then cp -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz; fi
  * DO NOT use 'systemctl ... aide.service' (no such unit exists)
  
- "auditd_*" rules: 
  * Install: dnf install -y audit
  * Edit /etc/audit/auditd.conf with correct settings
  * Enable and start: systemctl enable auditd && systemctl start auditd
  * IMPORTANT: auditd may refuse manual restart - use "augenrules --load" instead of "systemctl restart auditd"
  * Verify: systemctl status auditd
  
- "service_*" rules: 
  * Service must be BOTH enabled AND started
  * Use: systemctl enable <service> && systemctl start <service>
  * Verify: systemctl is-enabled <service> && systemctl is-active <service>
  
- "sysctl_*" rules: 
  * Set immediately: sysctl -w key=value
  * Persist: echo "key=value" >> /etc/sysctl.d/99-custom.conf
  * Load: sysctl --system
  * Verify: sysctl key
  
- "file_permissions_*" rules: 
  * Check exact permissions required (usually mode 0600 or 0644)
  * Use: chmod <mode> <file>
  * Verify: stat -c %a <file>
  
- "grub2_*" rules: 
  * Edit /etc/default/grub or /boot/grub2/grub.cfg
  * Must run: grub2-mkconfig -o /boot/grub2/grub.cfg
  * Reboot may be required

IMPORTANT EXECUTION CONTEXT:
- Your commands will be executed as a SINGLE SHELL SCRIPT running as ROOT.
- You can use variables, loops, and change directories (cd) - state IS preserved within the script.
- DO NOT include 'sudo' in your commands - the entire script runs as root.

COMMON FAILURE PATTERNS AND SOLUTIONS:
- "syntax error near unexpected token `then'": Check your if/then syntax.
- "Permission denied" on redirections: The script runs as root, so this shouldn't happen unless the file is immutable (chattr +i).
- "Operation refused" on service restart: Use alternatives (e.g., augenrules --load for auditd instead of restart)
- "Operation not permitted" on chown/chmod: May need SELinux context or different approach
- Commands succeed but OpenSCAP still fails: Check exact requirements (permissions, ownership, configuration values)
- For audit rules: If systemctl restart auditd fails, use "augenrules --load" to reload rules

YOUR TASK:
Analyze the error messages, exit codes, and command outputs above. Suggest a DIFFERENT strategy that:
1. Addresses the specific failure reason (syntax error, permission issue, missing step, wrong command, etc.)
2. Is MORE SPECIFIC and COMPLETE than the previous attempt
3. Includes verification commands where appropriate
4. Handles edge cases that might have caused the failure
"""
        
        # Log the prompt for debugging
        prompt_log_file = self.work_dir / f"llm_prompt_{vuln.id}_attempt{len(previous_attempts)+1}.txt"
        prompt_log_file.write_text(prompt, encoding='utf-8')
        
        result = self.llm_agent.run_sync(prompt)
        
        # Log the response
        response_log_file = self.work_dir / f"llm_response_{vuln.id}_attempt{len(previous_attempts)+1}.json"
        
        # Handle usage stats - RunUsage doesn't have model_dump(), convert to dict manually
        usage_data = None
        try:
            if hasattr(result, 'usage') and callable(result.usage):
                usage = result.usage()
                usage_data = {
                    'requests': getattr(usage, 'requests', None),
                    'input_tokens': getattr(usage, 'input_tokens', None),
                    'output_tokens': getattr(usage, 'output_tokens', None),
                }
        except Exception:
            usage_data = None
        
        response_log_file.write_text(json.dumps({
            'vuln_id': vuln.id,
            'attempt': len(previous_attempts) + 1,
            'remediation': result.output.model_dump() if hasattr(result.output, 'model_dump') else str(result.output),
            'usage': usage_data
        }, indent=2), encoding='utf-8')
        
        return result.output
    
    def _write_commands_file(self, vuln: Vulnerability, attempt_num: int, commands: List[str]) -> Path:
        cmds_path = self.work_dir / f"fix_{vuln.id}_attempt{attempt_num}.cmds.txt"
        lines = []
        lines.append(f"# Commands for {vuln.id} attempt {attempt_num}\n")
        for i, cmd in enumerate(commands, 1):
            lines.append(f"{i}. {cmd}\n")
        cmds_path.write_text("".join(lines), encoding='utf-8')
        return cmds_path

    def _normalize_command(self, command: str) -> str:
        """Normalize obvious LLM command issues.

        - Convert Debianisms (apt/apt-get) to dnf on Rocky/RHEL
        - Avoid legacy `service` invocations when a clear systemd unit is present
        """
        cmd = command.strip()
        lower = cmd.lower()

        # Debian package manager → dnf
        if lower.startswith("apt-get ") or lower.startswith("apt "):
            # Simple heuristic: swap apt/apt-get with dnf
            parts = cmd.split(maxsplit=1)
            if parts:
                verb_rest = parts[1] if len(parts) > 1 else ""
                cmd = f"dnf {verb_rest}".strip()
                lower = cmd.lower()

        # Very simple `service` → `systemctl` mapping for common operations
        # e.g., service sshd restart → systemctl restart sshd
        if lower.startswith("service "):
            parts = cmd.split()
            if len(parts) >= 3:
                _, svc, action = parts[0], parts[1], parts[2]
                if action in ("start", "stop", "restart", "reload"):
                    cmd = f"systemctl {action} {svc}"

        return cmd

    def apply_remediation(self, vuln: Vulnerability, 
                         remediation: RemediationSuggestion,
                         attempt_num: int) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """Apply remediation and return (success, combined_output, detailed_results)"""
        console.print(f"[cyan]🔧 Applying remediation (Attempt {attempt_num}/{self.max_attempts})...[/cyan]")
        
        # Show what we're doing
        console.print("\n[yellow]Commands to execute:[/yellow]")
        for i, cmd in enumerate(remediation.proposed_commands, 1):
            console.print(f"  {i}. {cmd}")

        # Save commands file (filter out invalid aide.service operations)
        filtered_cmds: List[str] = []
        for c in remediation.proposed_commands:
            lc = c.lower()
            if "systemctl" in lc and "aide" in lc:
                continue
            filtered_cmds.append(c)
        if not filtered_cmds:
            filtered_cmds = remediation.proposed_commands

        # Normalize commands for this environment (apt→dnf, service→systemctl, etc.)
        normalized_cmds = [self._normalize_command(c) for c in filtered_cmds]

        cmds_file = self._write_commands_file(vuln, attempt_num, normalized_cmds)
        console.print(f"\n[blue]Commands file:[/blue] {cmds_file}")

        # Execute commands directly over SSH via script
        # Note: We no longer need _format_sudo_command because the SSHExecutor wraps the whole script in sudo
        success, combined_output, detailed_results = self.ssh_executor.execute_commands(normalized_cmds)

        # Save log
        log_file = self.work_dir / f"fix_{vuln.id}_attempt{attempt_num}.ssh.log"
        log_file.write_text(combined_output, encoding='utf-8')
        
        # Save detailed results as JSON
        detailed_log_file = self.work_dir / f"fix_{vuln.id}_attempt{attempt_num}.detailed.json"
        detailed_log_file.write_text(json.dumps(detailed_results, indent=2), encoding='utf-8')

        # Show output clearly
        console.print("\n[magenta]Remote Output (Attempt {}/{}):[/magenta]".format(attempt_num, self.max_attempts))
        if combined_output:
            console.print(combined_output, markup=False)
        else:
            console.print("[dim]<no output>[/dim]")
        
        # Analyze detailed results for common issues and classify failures
        for result_detail in detailed_results:
            if not result_detail.get('success', False):
                stderr_full = result_detail.get('stderr', '') or ''
                stdout_full = result_detail.get('stdout', '') or ''
                stderr = stderr_full.lower()
                stdout = stdout_full.lower()
                cmd = result_detail.get('command', '')

                categories: List[str] = []

                # Check for service restart failures (especially auditd)
                if 'systemctl' in cmd.lower() and 'restart' in cmd.lower():
                    if 'refused' in stderr or 'operation refused' in stderr:
                        console.print(f"\n[yellow]⚠ Service restart refused for: {cmd}[/yellow]")
                        console.print("[yellow]This is common for auditd - consider using 'augenrules --load' instead[/yellow]")
                        categories.append('service_restart_refused')

                # Permission / immutable issues
                if 'permission denied' in stderr or 'operation not permitted' in stderr:
                    console.print(f"\n[yellow]⚠ Permission issue detected for: {cmd}[/yellow]")
                    categories.append('permission_denied')
                    if '/etc/cron.d' in cmd or '/etc/cron.d' in stderr_full:
                        categories.append('cron_system_file_protected')

                # Syntax errors (should be mitigated by bash -c wrapping)
                if 'syntax error' in stderr:
                    console.print(f"\n[yellow]⚠ Syntax error detected - shell syntax likely malformed[/yellow]")
                    categories.append('syntax_error')

                # Fallback generic failure category if nothing specific matched
                if not categories:
                    categories.append('command_failed')

                # Store categories on the result detail for downstream analysis
                result_detail['error_categories'] = categories

        return success, combined_output, detailed_results

    def process_vulnerability_adaptively(self, vuln: Vulnerability) -> Dict:
        """Process a vulnerability with adaptive retries
        
        Returns dict with results of all attempts
        """
        console.print("\n" + "="*70)
        console.print(f"[bold cyan]Processing: {vuln.title}[/bold cyan]")
        console.print("="*70 + "\n")
        
        # Show vulnerability details
        table = Table(show_header=False, box=None)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("ID", vuln.id)
        table.add_row("Title", vuln.title)
        table.add_row("Severity", f"[{'red' if int(vuln.severity) >= 3 else 'yellow'}]{vuln.severity}[/]")
        table.add_row("Host", vuln.host)
        console.print(table)
        
        attempts = []
        
        for attempt_num in range(1, self.max_attempts + 1):
            console.print(f"\n[bold yellow]═══ Attempt {attempt_num}/{self.max_attempts} ═══[/bold yellow]\n")

            # Heuristic: if we've already hit immutable/permission-protected system files
            # for multiple attempts (e.g., cron system files), treat as non-automatable.
            # Guard against empty attempts list on the first failing iteration.
            if attempt_num > 1 and attempts:
                recent_attempt = attempts[-1]
                cats = recent_attempt.get('error_categories') or []
                if (
                    'cron_system_file_protected' in cats
                    or cats.count('permission_denied') >= 2
                ) and attempt_num >= min(3, self.max_attempts):
                    console.print("\n[yellow]⚠ Repeated permission/immutable errors on system files detected.[/yellow]")
                    console.print("[yellow]Marking this vulnerability as requiring manual remediation.[/yellow]")
                    return {
                        'vuln_id': vuln.id,
                        'status': 'skipped',
                        'reason': 'Repeated permission/immutable errors on protected system files',
                        'attempts': attempts,
                        'fixed_on_attempt': None
                    }
            
            # Get remediation suggestion
            if attempt_num == 1:
                # First attempt: get initial suggestion
                remediation = self.get_initial_remediation(vuln)
            else:
                # Subsequent attempts: adaptive based on previous failures
                last_error = attempts[-1].get('error', 'Unknown error')
                remediation = self.get_adaptive_remediation(vuln, attempts, last_error)
            
            # Show remediation
            console.print("\n[green]💡 Remediation Plan:[/green]")
            for i, cmd in enumerate(remediation.proposed_commands, 1):
                console.print(f"  {i}. [yellow]{cmd}[/yellow]")
            if remediation.notes:
                console.print(f"\n[dim]Notes: {remediation.notes}[/dim]")
            
            # Check if AI says remediation is not feasible
            notes_lower = (remediation.notes or "").lower()
            commands_lower = " ".join(remediation.proposed_commands).lower()
            rule_name_lower = vuln.title.lower()
            
            # Check for partition-related rules (cannot be fixed on running system)
            partition_keywords = ["partition_for_", "separate partition", "separate filesystem"]
            is_partition_rule = any(keyword in rule_name_lower for keyword in partition_keywords)
            
            skip_keywords = [
                "not feasible", "cannot be automated", "manual intervention", 
                "requires manual", "not possible", "cannot fix", 
                "requires downtime", "data loss", "boot failure",
                "requires reboot", "during installation", "initial os installation",
                "repartition", "separate partition", "separate filesystem"
            ]
            
            is_not_feasible = any(keyword in notes_lower or keyword in commands_lower for keyword in skip_keywords)
            
            # Auto-skip partition rules
            if is_partition_rule:
                console.print("\n[yellow]⚠ This is a partition requirement - cannot be fixed on running system[/yellow]")
                console.print("[yellow]Skipping to next vulnerability...[/yellow]")
                return {
                    'vuln_id': vuln.id,
                    'status': 'skipped',
                    'reason': 'Partition requirement - requires repartitioning',
                    'attempts': attempts,
                    'fixed_on_attempt': None
                }
            
            if is_not_feasible and len(remediation.proposed_commands) == 0:
                # AI explicitly says it can't be fixed and provided no commands
                console.print("\n[yellow]⚠ AI indicates this vulnerability cannot be automatically remediated[/yellow]")
                console.print("[yellow]Skipping to next vulnerability...[/yellow]")
                return {
                    'vuln_id': vuln.id,
                    'status': 'skipped',
                    'reason': 'AI indicated remediation not feasible',
                    'attempts': attempts,
                    'fixed_on_attempt': None
                }
            
            # Apply remediation
            time.sleep(1)  # Brief pause for readability
            apply_success, output, detailed_results = self.apply_remediation(vuln, remediation, attempt_num)

            # Aggregate error categories from detailed results (if any)
            aggregated_categories: List[str] = []
            for d in detailed_results:
                for cat in d.get('error_categories', []):
                    if cat not in aggregated_categories:
                        aggregated_categories.append(cat)

            # Record attempt with detailed error information
            attempt_record = {
                'attempt': attempt_num,
                'commands': remediation.proposed_commands,
                'apply_success': apply_success,
                'error': output if not apply_success else None,
                'detailed_results': detailed_results,
                'error_categories': aggregated_categories,
            }

            if not apply_success:
                console.print("[red]✗ Command execution failed[/red]")
                attempts.append(attempt_record)

                # Show error and ask if should continue
                if attempt_num < self.max_attempts:
                    console.print("\n[yellow]Will retry with different approach...[/yellow]")
                    time.sleep(2)
                continue
            
            # Check if commands succeeded but some had warnings (like auditd restart refusal)
            # For auditd, if config was changed but restart was refused, that's often OK
            # because auditd reloads config automatically or on next boot
            has_auditd_restart_refusal = False
            for result_detail in detailed_results:
                cmd = result_detail.get('command', '')
                stderr = result_detail.get('stderr', '')
                if 'auditd' in cmd.lower() and 'restart' in cmd.lower():
                    if 'operation refused' in stderr.lower() or 'refused' in stderr.lower():
                        has_auditd_restart_refusal = True
                        console.print("[yellow]⚠ auditd restart was refused (this is normal - config changes may still apply)[/yellow]")
                        break
            
            # If all commands succeeded OR only auditd restart was refused, consider it successful
            if apply_success or (has_auditd_restart_refusal and all(
                r.get('success', False) or ('auditd' in r.get('command', '').lower() and 'restart' in r.get('command', '').lower())
                for r in detailed_results
            )):
                console.print("[green]✓ Commands executed successfully[/green]")
            else:
                console.print("[yellow]⚠ Some commands had issues, but continuing verification...[/yellow]")
            
            # Wait for changes to take effect
            console.print("\n[cyan]⏳ Waiting 10 seconds for changes to take effect...[/cyan]")
            time.sleep(10)
            
            # Verify the fix
            console.print("\n[cyan]🔍 Verifying fix...[/cyan]")
            still_vulnerable = self.scan_for_vulnerability(vuln)
            
            attempt_record['verified'] = not still_vulnerable
            attempts.append(attempt_record)
            
            if not still_vulnerable:
                # SUCCESS!
                console.print("\n[bold green]🎉 VULNERABILITY FIXED! 🎉[/bold green]\n")
                
                # Track success pattern
                self.success_patterns.append({
                    'vuln_type': vuln.title,
                    'commands': remediation.proposed_commands,
                    'attempt': attempt_num
                })
                
                return {
                    'vuln_id': vuln.id,
                    'status': 'fixed',
                    'attempts': attempts,
                    'fixed_on_attempt': attempt_num
                }
            else:
                # Still vulnerable
                console.print("\n[yellow]⚠ Verification shows vulnerability still exists[/yellow]")
                
                if attempt_num < self.max_attempts:
                    console.print("[yellow]Will try a different approach...[/yellow]")
                    time.sleep(2)
        
        # All attempts exhausted
        console.print("\n[red]✗ Failed to fix after all attempts[/red]\n")
        
        # Track failure pattern
        self.failure_patterns.append({
            'vuln_type': vuln.title,
            'all_attempts': attempts
        })
        
        return {
            'vuln_id': vuln.id,
            'status': 'failed',
            'attempts': attempts,
            'fixed_on_attempt': None
        }

    def run_adaptive_loop(self, max_vulns: Optional[int] = None, min_severity: int = 2, randomize: bool = False):
        """Run adaptive QA loop with feedback"""
        console.print(Panel.fit(
            "[bold cyan]Adaptive QA Agent[/bold cyan]\n"
            "Self-correcting with feedback loops",
            border_style="cyan"
        ))
        
        # Initial scan
        console.print("\n[bold cyan]Running Initial Scan...[/bold cyan]\n")
        scan_file = self.work_dir / "initial_scan.xml"
        parsed_file = self.work_dir / "initial_scan_parsed.json"
        
        success = self.scanner.run_scan(
            profile=self.scan_profile,
            output_file="/tmp/initial_scan.xml",
            datastream=self.scan_datastream,
            sudo_password=self.sudo_password
        )
        
        if not success:
            console.print("[red]Initial scan failed![/red]")
            sys.exit(1)
        
        self.scanner.download_results("/tmp/initial_scan.xml", str(scan_file))
        parse_openscap(str(scan_file), str(parsed_file))
        
        # Load vulnerabilities
        with open(parsed_file) as f:
            vulns_data = json.load(f)
        
        vulns = [Vulnerability(**v) for v in vulns_data]
        
        # Filter
        filtered = [v for v in vulns if int(v.severity) >= min_severity]
        console.print(f"\n[yellow]Found {len(filtered)} vulnerabilities (severity >= {min_severity})[/yellow]")
        
        # Randomize order if requested
        if randomize:
            random.shuffle(filtered)
            console.print(f"[cyan]Randomized vulnerability processing order[/cyan]")
        
        if max_vulns and len(filtered) > max_vulns:
            filtered = filtered[:max_vulns]
            console.print(f"[yellow]Limiting to first {max_vulns} vulnerabilities[/yellow]\n")
        
        # Process each vulnerability
        all_results = []
        vuln_map = {}  # Map vuln_id to original vulnerability for final playbook
        
        for i, vuln in enumerate(filtered, 1):
            console.print(f"\n[bold cyan]╔═══ Vulnerability {i}/{len(filtered)} ═══╗[/bold cyan]")
            
            # Store original vulnerability info
            vuln_map[vuln.id] = vuln
            
            result = self.process_vulnerability_adaptively(vuln)
            all_results.append(result)
            
            # Update tracking
            if result['status'] == 'fixed':
                if result['fixed_on_attempt'] == 1:
                    self.results['fixed_first_try'].append(result['vuln_id'])
                else:
                    self.results['fixed_after_retry'].append(result['vuln_id'])
            else:
                self.results['failed_all_attempts'].append(result['vuln_id'])
            
            # Save intermediate results
            self._save_results(all_results)
            
            # Show progress
            self._show_progress()
            
            # Continue?
            if i < len(filtered):
                if self.interactive:
                    if not Confirm.ask("\n[bold]Continue to next vulnerability?[/bold]", default=True):
                        break
        
        # Final summary
        self._show_final_summary(all_results)
        
        # Generate final Ansible playbook with proven working commands
        try:
            # Pass vulnerability map for better playbook generation
            self.generate_final_playbook(all_results, vuln_map)
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to generate final playbook: {e}[/yellow]")
        
        # Write text report (always)
        try:
            self._write_text_report(all_results)
            console.print(f"\n[green]Text report saved: {self.work_dir}/adaptive_report.txt[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to write text report: {e}[/yellow]")
        # Write PDF report (optional)
        try:
            self._write_pdf_report(all_results)
            console.print(f"\n[green]PDF report saved: {self.work_dir}/adaptive_report.pdf[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to write PDF report: {e}[/yellow]")

    def generate_final_playbook(self, all_results: List[Dict], vuln_map: Optional[Dict[str, Vulnerability]] = None):
        """Generate final Ansible playbook with only proven working commands"""
        console.print("\n[bold cyan]Generating Final Ansible Playbook...[/bold cyan]\n")
        
        # Collect successful remediations
        successful_remediations = []
        successful_vulns = []
        
        if vuln_map is None:
            vuln_map = {}
        
        for result in all_results:
            if result.get('status') == 'fixed':
                vuln_id = result.get('vuln_id')
                attempts = result.get('attempts', [])
                fixed_on_attempt = result.get('fixed_on_attempt')
                
                # Get the successful attempt
                if fixed_on_attempt and fixed_on_attempt <= len(attempts):
                    successful_attempt = attempts[fixed_on_attempt - 1]
                    commands = successful_attempt.get('commands', [])
                    
                    if commands:
                        # Create RemediationSuggestion for successful commands
                        remediation = RemediationSuggestion(
                            id=vuln_id,
                            proposed_commands=commands,
                            notes=f"Successfully fixed on attempt {fixed_on_attempt}"
                        )
                        successful_remediations.append(remediation)
                        
                        # Use original vulnerability if available, otherwise create minimal one
                        if vuln_id in vuln_map:
                            vuln = vuln_map[vuln_id]
                        else:
                            vuln = Vulnerability(
                                id=vuln_id,
                                title=result.get('vuln_id', vuln_id),
                                severity="2",
                                host=self.scanner.target_host
                            )
                        successful_vulns.append(vuln)
        
        if not successful_remediations:
            console.print("[yellow]No successful remediations to include in playbook[/yellow]")
            return
        
        console.print(f"[green]Found {len(successful_remediations)} successful remediations[/green]")
        
        # Generate playbook using RemediationBridge
        from remediation_bridge import RemediationBridge
        bridge = RemediationBridge()
        
        playbook = bridge.create_playbook(
            suggestions=successful_remediations,
            vulns=successful_vulns,
            playbook_name=f"Proven Remediations - {datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        # Write playbook
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        playbook_file = self.work_dir / f"final_remediation_playbook_{timestamp}.yml"
        playbook_file.write_text(playbook.to_yaml(), encoding='utf-8')
        
        console.print(f"[bold green]✓ Final playbook saved: {playbook_file}[/bold green]")
        console.print(f"[dim]Contains {len(playbook.tasks)} tasks from {len(successful_remediations)} fixed vulnerabilities[/dim]")
        
        # Also save a summary of what's in the playbook
        summary_file = self.work_dir / f"final_playbook_summary_{timestamp}.txt"
        summary_lines = [
            f"Final Remediation Playbook Summary\n",
            f"Generated: {datetime.now().isoformat()}\n",
            f"Target Host: {self.scanner.target_host}\n",
            f"Total Fixed Vulnerabilities: {len(successful_remediations)}\n",
            f"Total Tasks: {len(playbook.tasks)}\n",
            f"\nVulnerabilities Fixed:\n",
            f"{'='*80}\n"
        ]
        
        for i, (remediation, vuln) in enumerate(zip(successful_remediations, successful_vulns), 1):
            summary_lines.append(f"\n{i}. {vuln.id}\n")
            summary_lines.append(f"   Commands ({len(remediation.proposed_commands)}):\n")
            for cmd in remediation.proposed_commands:
                summary_lines.append(f"     - {cmd}\n")
        
        summary_file.write_text("".join(summary_lines), encoding='utf-8')
        console.print(f"[dim]Summary saved: {summary_file}[/dim]")
    
    def _show_progress(self):
        """Show current progress"""
        total = (len(self.results['fixed_first_try']) + 
                len(self.results['fixed_after_retry']) + 
                len(self.results['failed_all_attempts']) +
                len(self.results['skipped']))
        
        console.print(f"\n[dim]Progress: {total} processed[/dim]")
        console.print(f"[dim]  ✓ Fixed (1st try): {len(self.results['fixed_first_try'])}[/dim]")
        console.print(f"[dim]  ✓ Fixed (retry): {len(self.results['fixed_after_retry'])}[/dim]")
        console.print(f"[dim]  ⏭ Skipped: {len(self.results['skipped'])}[/dim]")
        console.print(f"[dim]  ✗ Failed: {len(self.results['failed_all_attempts'])}[/dim]")
    
    def _save_results(self, all_results: List[Dict]):
        """Save intermediate results"""
        results_file = self.work_dir / "adaptive_results.json"
        results_file.write_text(json.dumps({
            'timestamp': datetime.now().isoformat(),
            'summary': self.results,
            'detailed_results': all_results,
            'success_patterns': self.success_patterns,
            'failure_patterns': self.failure_patterns
        }, indent=2), encoding='utf-8')
    
    def _show_final_summary(self, all_results: List[Dict]):
        """Show final summary"""
        console.print("\n" + "="*70)
        console.print("[bold cyan]Adaptive QA Agent - Final Summary[/bold cyan]")
        console.print("="*70 + "\n")
        
        table = Table(title="Results")
        table.add_column("Outcome", style="cyan")
        table.add_column("Count", justify="right", style="magenta")
        table.add_column("Details", style="dim")
        
        table.add_row(
            "✓ Fixed (First Try)",
            str(len(self.results['fixed_first_try'])),
            "No retries needed",
            style="green"
        )
        table.add_row(
            "✓ Fixed (After Retry)",
            str(len(self.results['fixed_after_retry'])),
            "Agent adapted strategy",
            style="green"
        )
        table.add_row(
            "⏭ Skipped",
            str(len(self.results['skipped'])),
            "AI indicated not feasible",
            style="yellow"
        )
        table.add_row(
            "✗ Failed",
            str(len(self.results['failed_all_attempts'])),
            f"All {self.max_attempts} attempts failed",
            style="red"
        )
        
        console.print(table)
        
        # Show learning insights
        if self.success_patterns:
            console.print("\n[bold green]🎓 Learning: Successful Patterns[/bold green]")
            for pattern in self.success_patterns[:3]:
                console.print(f"  • {pattern['vuln_type']}: Fixed on attempt {pattern['attempt']}")
        
        # Show detailed results
        console.print("\n[bold]Detailed Results:[/bold]\n")
        for result in all_results:
            status_icon = "✓" if result['status'] == 'fixed' else "✗"
            status_color = "green" if result['status'] == 'fixed' else "red"
            
            console.print(f"[{status_color}]{status_icon} {result['vuln_id']}[/{status_color}]")
            console.print(f"   Attempts: {len(result['attempts'])}")
            if result['status'] == 'fixed':
                console.print(f"   Fixed on: Attempt {result['fixed_on_attempt']}")
        
        console.print(f"\n[green]Results saved: {self.work_dir}/adaptive_results.json[/green]")

    def _write_text_report(self, all_results: List[Dict]):
        """Generate a plain-text report summarizing attempts, playbooks, and outputs."""
        report_path = self.work_dir / "adaptive_report.txt"
        lines: List[str] = []
        lines.append("Adaptive QA Agent Report\n")
        lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}\n")
        try:
            host = getattr(self.scanner, 'target_host', 'unknown-host')
        except Exception:
            host = 'unknown-host'
        lines.append(f"Target Host: {host}\n")
        lines.append("="*80 + "\n\n")

        for result in all_results:
            vuln_id = result.get('vuln_id', 'unknown')
            status = result.get('status', 'unknown')
            fixed_on = result.get('fixed_on_attempt')
            attempts = result.get('attempts', [])

            lines.append(f"Vulnerability: {vuln_id}\n")
            lines.append(f"Status: {status} | Fixed on attempt: {fixed_on if fixed_on else '-'}\n")
            lines.append("-"*80 + "\n")

            for att in attempts:
                attempt_num = att.get('attempt')
                cmds = att.get('commands', [])
                apply_success = att.get('apply_success')
                verified = att.get('verified')

                lines.append(f"Attempt {attempt_num}\n")
                lines.append("Commands:\n")
                for cmd in cmds:
                    lines.append(f"  - {cmd}\n")

                # Include commands file (or playbook if present for legacy runs)
                cmds_path = self.work_dir / f"fix_{vuln_id}_attempt{attempt_num}.cmds.txt"
                playbook_path = self.work_dir / f"fix_{vuln_id}_attempt{attempt_num}.yml"
                if cmds_path.exists():
                    lines.append(f"Commands File: {cmds_path.name}\n")
                    try:
                        cmds_text = cmds_path.read_text()
                    except Exception:
                        cmds_text = "<unable to read>"
                    lines.append("Commands Content:\n")
                    lines.append(cmds_text + ("\n" if not cmds_text.endswith("\n") else ""))
                elif playbook_path.exists():
                    lines.append(f"Playbook: {playbook_path.name}\n")
                    try:
                        playbook_text = playbook_path.read_text()
                    except Exception:
                        playbook_text = "<unable to read>"
                    lines.append("Playbook Content:\n")
                    lines.append(playbook_text + ("\n" if not playbook_text.endswith("\n") else ""))

                # Include ansible/ssh output
                log_path = self.work_dir / f"fix_{vuln_id}_attempt{attempt_num}.ssh.log"
                if not log_path.exists():
                    # Fallback to ansible log if this run used Ansible
                    log_path = self.work_dir / f"fix_{vuln_id}_attempt{attempt_num}.log"
                lines.append(f"Output (Apply: {'SUCCESS' if apply_success else 'FAILED'} | Verify: {'FIXED' if verified else 'PERSISTING' if verified is not None else 'N/A'}):\n")
                try:
                    log_text = log_path.read_text() if log_path.exists() else "<missing>"
                except Exception:
                    log_text = "<unable to read>"
                lines.append(log_text + ("\n" if not log_text.endswith("\n") else ""))

                lines.append("-"*80 + "\n")
            lines.append("\n")

        # Write the file
        report_path.write_text("".join(lines), encoding='utf-8')

    def _write_pdf_report(self, all_results: List[Dict]):
        """Generate a PDF report summarizing attempts, playbooks, and outputs."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib.utils import simpleSplit
        except Exception as e:
            # Surface a clear error to the caller; caller prints a warning and continues
            raise RuntimeError("reportlab is not installed. Install with 'pip install reportlab' or 'pip install -r requirements.txt'") from e

        pdf_path = self.work_dir / "adaptive_report.pdf"
        c = canvas.Canvas(str(pdf_path), pagesize=letter)
        width, height = letter

        def draw_wrapped(text: str, x: int, y: int, max_width: int, line_height: int = 14):
            lines = simpleSplit(text or "", "Helvetica", 10, max_width)
            cur_y = y
            for line in lines:
                if cur_y < 50:
                    c.showPage()
                    c.setFont("Helvetica", 10)
                    cur_y = height - 50
                c.drawString(x, cur_y, line)
                cur_y -= line_height
            return cur_y

        # Title
        c.setTitle("Adaptive QA Agent Report")
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "Adaptive QA Agent Report")
        c.setFont("Helvetica", 10)
        c.drawString(50, height - 70, f"Generated: {datetime.now().isoformat(timespec='seconds')}")
        # Host
        try:
            host = getattr(self.scanner, 'target_host', 'unknown-host')
        except Exception:
            host = 'unknown-host'
        c.drawString(50, height - 85, f"Target Host: {host}")
        c.showPage()

        for result in all_results:
            vuln_id = result.get('vuln_id', 'unknown')
            status = result.get('status', 'unknown')
            fixed_on = result.get('fixed_on_attempt')
            attempts = result.get('attempts', [])

            # Page header for vulnerability
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, height - 50, f"Vulnerability: {vuln_id}")
            c.setFont("Helvetica", 10)
            c.drawString(50, height - 68, f"Status: {status}  |  Fixed on attempt: {fixed_on if fixed_on else '-'}")
            y = height - 90

            for att in attempts:
                attempt_num = att.get('attempt')
                cmds = att.get('commands', [])
                apply_success = att.get('apply_success')
                verified = att.get('verified')

                # Attempt header
                c.setFont("Helvetica-Bold", 12)
                c.drawString(50, y, f"Attempt {attempt_num}")
                y -= 18

                # Commands
                c.setFont("Helvetica-Bold", 10)
                c.drawString(50, y, "Commands:")
                y -= 14
                c.setFont("Helvetica", 10)
                y = draw_wrapped("\n".join(f"- {cmd}" for cmd in cmds), 60, y, width - 90)
                y -= 6

                # Playbook content
                playbook_path = self.work_dir / f"fix_{vuln_id}_attempt{attempt_num}.yml"
                playbook_text = ""
                if playbook_path.exists():
                    try:
                        playbook_text = playbook_path.read_text()
                    except Exception:
                        playbook_text = "<unable to read playbook>"
                c.setFont("Helvetica-Bold", 10)
                c.drawString(50, y, f"Playbook: {playbook_path.name}")
                y -= 14
                c.setFont("Helvetica", 10)
                y = draw_wrapped(playbook_text[:4000], 60, y, width - 90)
                y -= 6

                # Ansible output
                log_path = self.work_dir / f"fix_{vuln_id}_attempt{attempt_num}.log"
                log_text = ""
                if log_path.exists():
                    try:
                        log_text = log_path.read_text()
                    except Exception:
                        log_text = "<unable to read log>"
                c.setFont("Helvetica-Bold", 10)
                status_str = f"Apply: {'SUCCESS' if apply_success else 'FAILED'}  |  Verify: {'FIXED' if verified else 'PERSISTING' if verified is not None else 'N/A'}"
                c.drawString(50, y, f"Output ({status_str}):")
                y -= 14
                c.setFont("Helvetica", 10)
                y = draw_wrapped(log_text[:8000], 60, y, width - 90)
                y -= 12

                if y < 120:
                    c.showPage()
                    y = height - 50

            c.showPage()

        c.save()


class SSHExecutor:
    """Execute commands remotely over SSH and capture stdout/stderr."""
    def __init__(self, host: str, user: str, key: Optional[str], port: int, sudo_password: Optional[str]):
        self.host = host
        self.user = user
        self.key = key
        self.port = port
        self.sudo_password = sudo_password

    def _build_ssh_cmd(self) -> List[str]:
        cmd = ["ssh"]
        if self.key:
            cmd.extend(["-i", self.key])
        cmd.extend([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", str(self.port),
            f"{self.user}@{self.host}",
        ])
        return cmd

    def _build_scp_cmd(self) -> List[str]:
        cmd = ["scp"]
        if self.key:
            cmd.extend(["-i", self.key])
        cmd.extend([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-P", str(self.port),
        ])
        return cmd

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload a file to the remote host."""
        cmd = self._build_scp_cmd() + [local_path, f"{self.user}@{self.host}:{remote_path}"]
        try:
            subprocess.run(cmd, check=True, capture_output=True, timeout=60)
            return True
        except subprocess.CalledProcessError as e:
            console.print(f"[red]SCP failed: {e.stderr.decode()}[/red]")
            return False
        except Exception as e:
            console.print(f"[red]SCP error: {e}[/red]")
            return False

    def execute_commands(self, commands: List[str]) -> Tuple[bool, str, List[Dict[str, Any]]]:
        """
        Execute commands by creating a script, uploading it, and running it.
        
        Returns:
            Tuple of (all_successful, combined_output, detailed_results)
        """
        # Create a temporary script file locally
        timestamp = int(time.time())
        script_name = f"remediation_{timestamp}.sh"
        remote_script_path = f"/tmp/{script_name}"
        
        # Generate script content
        # We use set -x for verbose output (echoing commands)
        # We use set -e to stop on error (optional, but good for strictness. 
        # However, for this agent we might want to continue to see all errors? 
        # Let's stick to sequential execution without set -e for now to match previous behavior 
        # where we tried to run everything, but now we have state.)
        # Actually, let's use a helper function in the script to run commands and capture status.
        
        script_content = ["#!/bin/bash", "export LANG=C"]
        
        # If we have a sudo password, we can use it.
        # But we are running the *entire script* with sudo.
        
        for cmd in commands:
            script_content.append(f"echo 'Running: {cmd}'")
            script_content.append(cmd)
            script_content.append("if [ $? -ne 0 ]; then echo 'COMMAND_FAILED'; fi")
            script_content.append("echo '---'")

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sh', newline='\n') as tmp:
            tmp.write("\n".join(script_content))
            tmp_path = tmp.name

        try:
            # Upload script
            if not self.upload_file(tmp_path, remote_script_path):
                return False, "Failed to upload remediation script", []

            # Execute script
            # We wrap the execution in sudo if password is provided
            if self.sudo_password:
                # echo password | sudo -S bash script
                # We need to be careful with quoting.
                # The command to run on remote is: echo 'PASS' | sudo -S bash /tmp/script
                remote_cmd = f"echo {shlex.quote(self.sudo_password)} | sudo -S bash {remote_script_path}"
            else:
                # Just bash script (assuming user is root or doesn't need sudo, which is unlikely for fixes)
                # But if user is root, sudo -S might complain or just work.
                # If no sudo password, maybe we just try running it?
                remote_cmd = f"bash {remote_script_path}"

            ssh_cmd = self._build_ssh_cmd() + [remote_cmd]
            
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=600)
            
            # Cleanup remote script (best effort)
            cleanup_cmd = self._build_ssh_cmd() + [f"rm -f {remote_script_path}"]
            subprocess.run(cleanup_cmd, capture_output=True, timeout=10)

            output = result.stdout + result.stderr
            
            # Parse output to reconstruct detailed results
            # This is a bit loose because we are parsing stdout.
            # But it's better than nothing.
            detailed_results = []
            
            # Simple parsing logic could be improved, but for now let's just return the whole blob
            # and mark success based on return code of the script.
            # Since we didn't use set -e, the script return code might be 0 even if commands failed.
            # We need to check for COMMAND_FAILED in output.
            
            success = (result.returncode == 0) and ("COMMAND_FAILED" not in output)
            
            # Create a single "detailed result" for the whole script for now, 
            # or try to split it if we really want to match the old interface.
            # The old interface expects a list of results.
            
            detailed_results.append({
                'command': 'full_remediation_script',
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'success': success
            })

            return success, output, detailed_results

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


def main():
    """Main entry point"""
    import argparse
    
    # Verify .env is loaded
    if not os.getenv('OPENROUTER_API_KEY'):
        console.print("[red]Error: OPENROUTER_API_KEY not found in .env file![/red]")
        console.print("[yellow]Please create .env from env.template and add your API key[/yellow]")
        sys.exit(1)
    
    parser = argparse.ArgumentParser(description="Adaptive QA Agent with feedback loops")
    parser.add_argument('--host', required=True)
    parser.add_argument('--user', default='root')
    parser.add_argument('--key', help='SSH key path')
    parser.add_argument('--sudo-password', help='Sudo password')
    parser.add_argument('--inventory', required=True)
    parser.add_argument('--profile', default='xccdf_org.ssgproject.content_profile_cis')
    parser.add_argument('--datastream', default='/usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml')
    parser.add_argument('--work-dir', default='adaptive_qa_work')
    parser.add_argument('--max-vulns', type=int, help='Max vulnerabilities to process')
    parser.add_argument('--min-severity', type=int, default=2, choices=[0,1,2,3,4])
    parser.add_argument('--max-attempts', type=int, default=5, help='Max retry attempts per vulnerability')
    parser.add_argument('--randomize', action='store_true', help='Randomize the order of vulnerability processing')
    parser.add_argument('--non-interactive', action='store_true',
                        help='Run through all vulnerabilities without prompting between each one')
    
    args = parser.parse_args()
    
    # Create scanner
    scanner = OpenSCAPScanner(
        target_host=args.host,
        ssh_user=args.user,
        ssh_key=args.key,
        ssh_port=22
    )
    
    # Create adaptive agent
    agent = AdaptiveQAAgent(
        scanner=scanner,
        ansible_inventory=args.inventory,
        work_dir=Path(args.work_dir),
        scan_profile=args.profile,
        scan_datastream=args.datastream,
        sudo_password=args.sudo_password,
        max_attempts=args.max_attempts,
        interactive=not args.non_interactive
    )
    
    try:
        # Call via class to avoid any instance attribute shadowing issues
        AdaptiveQAAgent.run_adaptive_loop(
            agent,
            max_vulns=args.max_vulns,
            min_severity=args.min_severity,
            randomize=args.randomize
        )
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

