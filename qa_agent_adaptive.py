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
from typing import Callable, List, Dict, Any, Optional, Tuple
from datetime import datetime
import subprocess
import shlex
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm
from dotenv import load_dotenv

from schemas import Vulnerability, RemediationSuggestion, RunCommandResult, ToolVerdict
from openscap_cli import OpenSCAPScanner
from parse_openscap import parse_openscap
from remediation_bridge import RemediationBridge
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
        shell_timeout = int(os.getenv('QA_AGENT_COMMAND_TIMEOUT', '120'))
        self.shell_executor = ShellCommandExecutor(
            host=scanner.target_host,
            user=scanner.ssh_user or 'root',
            key=scanner.ssh_key,
            port=int(getattr(scanner, 'ssh_port', 22) or 22),
            sudo_password=sudo_password,
            command_timeout=shell_timeout,
            max_output_chars=int(os.getenv('QA_AGENT_MAX_OUTPUT_CHARS', '8000'))
        )
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True, parents=True)
        self.scan_profile = scan_profile
        self.scan_datastream = scan_datastream
        self.sudo_password = sudo_password
        self.initial_fail_count: Optional[int] = None
        self.current_fail_count: Optional[int] = None
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
        """Initialize adaptive LLM agent that can call local shell tools."""
        api_key = os.getenv('OPENROUTER_API_KEY')
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY not found in .env file!")

        model_name = os.getenv('OPENROUTER_MODEL')
        if not model_name:
            raise ValueError("OPENROUTER_MODEL not found in .env file!")

        base_url = os.getenv('OPENROUTER_BASE_URL', 'https://openrouter.ai/api/v1').rstrip('/')
        max_tool_iterations = int(os.getenv('QA_AGENT_MAX_TOOL_CALLS', '24'))
        request_timeout = int(os.getenv('QA_AGENT_LLM_TIMEOUT', '90'))

        system_prompt = (
            "You are an adaptive security remediation agent working on Rocky Linux 10. "
            "You operate strictly through the provided tools:\n"
            "1. Use `run_command` to execute EXACTLY ONE shell command at a time. "
            "   - Do NOT chain commands with &&, ;, or multiline scripts.\n"
            "   - All commands run as root. Never prefix with sudo.\n"
            "   - If a command fails, inspect stdout/stderr and try a different approach.\n"
            "2. When you finish (either resolved or blocked), call `verdict` with a clear message and resolved=true/false.\n"
            "You must reason step-by-step, calling `run_command` between thoughts. "
            "Focus on one vulnerability at a time, be precise, prefer idempotent fixes, "
            "and always include verification commands where possible."
        )

        return ToolCallingLLM(
            model_name=model_name,
            base_url=base_url,
            api_key=api_key,
            system_prompt=system_prompt,
            shell_executor=self.shell_executor,
            command_normalizer=self._normalize_command,
            max_tool_iterations=max_tool_iterations,
            request_timeout=request_timeout
        )
    
    def scan_for_vulnerability(self, vuln: Vulnerability) -> Tuple[bool, Optional[int]]:
        """Check if a specific vulnerability still exists.
        
        Returns:
            (still_exists, current_fail_count)
            
        - still_exists: True if vulnerability still exists, False if fixed.
        - current_fail_count: total number of failing/error OpenSCAP rules
          in this verification scan (None if unavailable).
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
            # Preserve last known fail count if we have one
            return True, self.current_fail_count
        
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
        
        current_fail_count = len(current_vulns)
        return still_exists, current_fail_count
    
    def _build_agent_prompt(self, vuln: Vulnerability, previous_attempts: List[Dict[str, Any]]) -> str:
        """Construct the user-facing prompt for the agentic remediation loop."""
        rule_name = vuln.title.replace('xccdf_org.ssgproject.content_rule_', '')
        description = (getattr(vuln, 'description', '') or '').strip()
        recommendation = (getattr(vuln, 'recommendation', '') or '').strip()

        lines = [
            "You are remediating ONE OpenSCAP finding on Rocky Linux 10.",
            "",
            "VULNERABILITY:",
            f"- Rule Name: {rule_name}",
            f"- Rule ID: {vuln.title}",
            f"- Severity: {vuln.severity} (0=info, 4=critical)",
            f"- Host: {vuln.host}",
        ]

        if description:
            lines.append(f"- Description: {description[:600]}")
        if recommendation:
            lines.append(f"- Recommendation: {recommendation[:600]}")

        lines.extend([
            "",
            "ENVIRONMENT FACTS:",
            "- OS: Rocky Linux 10 (dnf, systemd)",
            "- Commands run remotely on this host via SSH; NEVER add sudo (already root).",
            "- Use dnf for packages, systemctl for services, sed/echo/cat for configs.",
            "- Prefer idempotent commands and include verification steps.",
        ])

        if previous_attempts:
            lines.append("")
            lines.append(f"PREVIOUS ATTEMPTS ({len(previous_attempts)} total, showing last {min(3, len(previous_attempts))}):")
            for att in previous_attempts[-3:]:
                lines.append(f"* Attempt {att.get('attempt')}:")
                cmds = att.get('commands') or []
                if cmds:
                    lines.append("  Commands:")
                    for cmd in cmds[-4:]:
                        lines.append(f"    - {cmd}")
                categories = att.get('error_categories') or []
                if categories:
                    lines.append(f"  Error categories: {', '.join(categories)}")
                error_text = att.get('error')
                if error_text:
                    preview = str(error_text).strip().replace("\r", "")
                    lines.append(f"  Output/Error: {preview[:400]}")
                verified = att.get('verified')
                if verified is True:
                    lines.append("  Result: Verified fixed (unexpected regression).")
                elif verified is False:
                    lines.append("  Result: Scan shows still failing.")
                else:
                    lines.append("  Result: Verification skipped.")

        lines.extend([
            "",
            "GUIDANCE:",
            "- Call `run_command` for each discrete step (install, configure, verify).",
            "- Do NOT chain commands with && or ; .",
            "- Review stdout/stderr after every command and adjust strategy as needed.",
            "- Common patterns: package_* → dnf install -y pkg; service_* → systemctl enable/start svc; "
            "sysctl_* → sysctl -w + persist in /etc/sysctl.d; aide_* → install/init/copy database; "
            "auditd_* → edit /etc/audit/auditd.conf then augenrules --load; sshd_* → edit /etc/ssh/sshd_config + systemctl restart sshd.",
            "- Finish by calling `verdict` with resolved=true when confident, or resolved=false if automation is not possible.",
        ])

        return "\n".join(lines)
    
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

    def _annotate_error_categories(self, detailed_results: List[Dict[str, Any]]) -> None:
        """Tag each command result with heuristic error categories."""
        for result_detail in detailed_results:
            if result_detail.get('success', False):
                continue

            stderr_full = (result_detail.get('stderr') or '').lower()
            stdout_full = (result_detail.get('stdout') or '').lower()
            cmd = (result_detail.get('command') or '')

            categories: List[str] = []

            if 'systemctl' in cmd.lower() and 'restart' in cmd.lower():
                if 'refused' in stderr_full or 'operation refused' in stderr_full:
                    console.print(f"\n[yellow]⚠ Service restart refused for: {cmd}[/yellow]")
                    console.print("[yellow]Consider alternatives like 'augenrules --load' for auditd[/yellow]")
                    categories.append('service_restart_refused')

            if 'permission denied' in stderr_full or 'operation not permitted' in stderr_full:
                console.print(f"\n[yellow]⚠ Permission issue detected for: {cmd}[/yellow]")
                categories.append('permission_denied')
                if '/etc/cron.d' in cmd.lower() or '/etc/cron.d' in stderr_full:
                    categories.append('cron_system_file_protected')

            if 'syntax error' in stderr_full:
                console.print(f"\n[yellow]⚠ Syntax error detected in command: {cmd}[/yellow]")
                categories.append('syntax_error')

            if not categories:
                categories.append('command_failed')

            result_detail['error_categories'] = categories

    def apply_remediation(
        self,
        vuln: Vulnerability,
        attempt_num: int,
        previous_attempts: List[Dict[str, Any]]
    ) -> Tuple[bool, str, List[Dict[str, Any]], List[str], Optional[ToolVerdict]]:
        """Run an agentic remediation attempt via tool-calling shell interface."""
        console.print(f"[cyan]🔧 Agentic remediation (Attempt {attempt_num}/{self.max_attempts})[/cyan]")

        prompt = self._build_agent_prompt(vuln, previous_attempts)
        session_label = f"{vuln.id}_attempt{attempt_num}"

        prompt_file = self.work_dir / f"llm_prompt_{session_label}.txt"
        prompt_file.write_text(prompt, encoding='utf-8')

        try:
            session_result = self.llm_agent.run_session(
                user_prompt=prompt,
                session_label=session_label
            )
        except Exception as exc:
            combined_output = f"LLM/tool execution failed: {exc}"
            console.print(f"[red]Tool call failed:[/red] {exc}")
            return False, combined_output, [], [], None

        transcript_file = self.work_dir / f"llm_transcript_{session_label}.json"
        transcript_file.write_text(json.dumps(session_result.get('transcript', []), indent=2), encoding='utf-8')

        commands = session_result.get('commands', [])
        detailed_results = session_result.get('detailed_results', [])
        combined_output = session_result.get('combined_output') or ''
        verdict_data = session_result.get('verdict')
        verdict = None
        if verdict_data:
            verdict = ToolVerdict(**verdict_data)
            console.print(f"\n[green]Verdict:[/green] {verdict.message} (resolved={verdict.resolved})")

        if commands:
            cmds_file = self._write_commands_file(vuln, attempt_num, commands)
            console.print(f"\n[blue]Commands executed:[/blue] {cmds_file}")
        else:
            console.print("\n[yellow]No commands executed during this attempt[/yellow]")

        log_file = self.work_dir / f"fix_{vuln.id}_attempt{attempt_num}.shell.log"
        log_file.write_text(combined_output or "<no command output>", encoding='utf-8')

        detailed_log_file = self.work_dir / f"fix_{vuln.id}_attempt{attempt_num}.detailed.json"
        detailed_log_file.write_text(json.dumps(detailed_results, indent=2), encoding='utf-8')

        console.print(f"\n[magenta]Agent Output (Attempt {attempt_num}/{self.max_attempts}):[/magenta]")
        if combined_output:
            console.print(combined_output, markup=False)
        else:
            console.print("[dim]<no output>[/dim]")

        apply_success = session_result.get('apply_success', False)

        return apply_success, combined_output, detailed_results, commands, verdict

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

            # Auto skip partition-style requirements that cannot be automated safely
            rule_name_lower = vuln.title.lower()
            partition_keywords = ["partition_for_", "separate partition", "separate filesystem"]
            if attempt_num == 1 and any(keyword in rule_name_lower for keyword in partition_keywords):
                console.print("\n[yellow]⚠ This rule requires partitioning/reinstallation - cannot remediate live[/yellow]")
                console.print("[yellow]Skipping to next vulnerability...[/yellow]")
                return {
                    'vuln_id': vuln.id,
                    'status': 'skipped',
                    'reason': 'Partition requirement - requires manual rebuild',
                    'attempts': attempts,
                    'fixed_on_attempt': None
                }

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
            
            # Apply remediation
            time.sleep(1)  # Brief pause for readability
            apply_success, output, detailed_results, executed_commands, verdict = self.apply_remediation(
                vuln,
                attempt_num,
                attempts
            )

            self._annotate_error_categories(detailed_results)

            # Aggregate error categories from detailed results (if any)
            aggregated_categories: List[str] = []
            for d in detailed_results:
                for cat in d.get('error_categories', []):
                    if cat not in aggregated_categories:
                        aggregated_categories.append(cat)

            # Record attempt with detailed error information
            attempt_record = {
                'attempt': attempt_num,
                'commands': executed_commands,
                'apply_success': apply_success,
                'error': output if not apply_success else None,
                'detailed_results': detailed_results,
                'error_categories': aggregated_categories,
                'verdict': verdict.model_dump() if verdict else None,
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
            
            # Verify the fix and update global failing-rule counts
            console.print("\n[cyan]🔍 Verifying fix...[/cyan]")
            prev_fail_count = self.current_fail_count if self.current_fail_count is not None else self.initial_fail_count
            still_vulnerable, fail_count = self.scan_for_vulnerability(vuln)
            self.current_fail_count = fail_count

            # Show global failing rule count change (can drop by more than one)
            if self.initial_fail_count is not None and fail_count is not None:
                total_fixed = self.initial_fail_count - fail_count
                if prev_fail_count is not None:
                    delta = prev_fail_count - fail_count
                    if delta != 0:
                        console.print(
                            f"[cyan]OpenSCAP failing rules: {prev_fail_count} → {fail_count} "
                            f"({'-' if delta > 0 else '+'}{abs(delta)})[/cyan]"
                        )
                attempt_record['remaining_failures'] = fail_count
                attempt_record['total_fixed_so_far'] = total_fixed
            
            attempt_record['verified'] = not still_vulnerable
            attempts.append(attempt_record)
            
            if not still_vulnerable:
                # SUCCESS!
                console.print("\n[bold green]🎉 VULNERABILITY FIXED! 🎉[/bold green]\n")
                
                # Track success pattern
                self.success_patterns.append({
                    'vuln_type': vuln.title,
                    'commands': executed_commands,
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
        
        # Load vulnerabilities (all failed/error OpenSCAP rules)
        with open(parsed_file) as f:
            vulns_data = json.load(f)
        
        vulns = [Vulnerability(**v) for v in vulns_data]
        # Track global failing rule count across the run
        self.initial_fail_count = len(vulns_data)
        self.current_fail_count = self.initial_fail_count
        console.print(f"[cyan]Initial failing OpenSCAP rules: {self.initial_fail_count}[/cyan]")
        
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
        if self.initial_fail_count is not None and self.current_fail_count is not None:
            reduced = self.initial_fail_count - self.current_fail_count
            console.print(
                f"[dim]  OpenSCAP failing rules: {self.current_fail_count}/{self.initial_fail_count} "
                f"(reduced by {reduced})[/dim]"
            )
    
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
        
        # Show global failing rule count change if available
        if self.initial_fail_count is not None:
            final_count = self.current_fail_count if self.current_fail_count is not None else self.initial_fail_count
            reduction = self.initial_fail_count - final_count
            console.print(
                f"\n[cyan]OpenSCAP failing rules: {self.initial_fail_count} → {final_count} "
                f"(net change {reduction:+d})[/cyan]"
            )
        
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
                log_path = self.work_dir / f"fix_{vuln_id}_attempt{attempt_num}.shell.log"
                if not log_path.exists():
                    log_path = self.work_dir / f"fix_{vuln_id}_attempt{attempt_num}.ssh.log"
                if not log_path.exists():
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


class ShellCommandExecutor:
    """Runs individual shell commands on the remote target over SSH."""

    def __init__(
        self,
        host: str,
        user: str,
        key: Optional[str],
        port: int = 22,
        sudo_password: Optional[str] = None,
        command_timeout: int = 120,
        max_output_chars: int = 8000,
    ) -> None:
        self.host = host
        self.user = user or "root"
        self.key = key
        self.port = port or 22
        self.sudo_password = sudo_password
        self.command_timeout = command_timeout
        self.max_output_chars = max_output_chars

    def _truncate(self, text: str) -> Tuple[str, bool]:
        if text and len(text) > self.max_output_chars:
            return text[: self.max_output_chars] + "\n...[truncated]...", True
        return text or "", False

    def _build_ssh_cmd(self) -> List[str]:
        cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-p",
            str(self.port),
        ]
        if self.key:
            cmd.extend(["-i", self.key])
        cmd.append(f"{self.user}@{self.host}")
        return cmd

    def _remote_shell_command(self, command: str) -> str:
        """Wrap the requested command so it runs as root on the remote host."""
        base = f"bash -lc {shlex.quote(command)}"
        if self.user == "root":
            return base
        if self.sudo_password:
            quoted_pw = shlex.quote(self.sudo_password)
            return f"echo {quoted_pw} | sudo -S {base}"
        return f"sudo -n {base}"

    def run_command(self, command: str) -> RunCommandResult:
        if not command:
            return RunCommandResult(
                command="",
                stdout="",
                stderr="No command provided",
                exit_code=None,
                success=False,
                duration=0.0,
                timed_out=False,
            )

        remote_command = self._remote_shell_command(command)
        ssh_cmd = self._build_ssh_cmd() + [remote_command]

        start = time.time()
        stdout = ""
        stderr = ""
        exit_code: Optional[int] = None
        success = False
        timed_out = False

        try:
            completed = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=self.command_timeout,
            )
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            exit_code = completed.returncode
            success = exit_code == 0
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = (exc.stderr or "") + f"\nCommand timed out after {self.command_timeout} seconds."
            timed_out = True
        except FileNotFoundError as exc:
            stderr = f"SSH binary not found: {exc}"
        finally:
            duration = time.time() - start

        stdout, stdout_truncated = self._truncate(stdout)
        stderr, stderr_truncated = self._truncate(stderr)

        return RunCommandResult(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            success=success,
            duration=duration,
            timed_out=timed_out,
            truncated_stdout=stdout_truncated,
            truncated_stderr=stderr_truncated,
        )


class ToolCallingLLM:
    """LLM wrapper that drives tool-calling remediation sessions."""

    def __init__(
        self,
        model_name: str,
        base_url: str,
        api_key: str,
        system_prompt: str,
        shell_executor: ShellCommandExecutor,
        command_normalizer: Optional[Callable[[str], str]] = None,
        max_tool_iterations: int = 24,
        request_timeout: int = 90,
    ):
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.system_prompt = system_prompt
        self.shell_executor = shell_executor
        self.command_normalizer = command_normalizer or (lambda cmd: cmd)
        self.max_tool_iterations = max_tool_iterations
        self.request_timeout = request_timeout
        self.endpoint = f"{self.base_url}/chat/completions"
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        self.tools = [
            {
                "type": "function",
                "function": {
                    "name": "run_command",
                    "description": (
                        "Execute a single shell command as root on the Rocky Linux target. "
                        "Never include sudo and do not chain multiple commands."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Single shell command to execute. No && or multiple commands.",
                            }
                        },
                        "required": ["command"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "verdict",
                    "description": "Signal that remediation is complete along with a short summary.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "message": {"type": "string"},
                            "resolved": {"type": "boolean"},
                        },
                        "required": ["message", "resolved"],
                        "additionalProperties": False,
                    },
                },
            },
        ]

    def run_session(
        self,
        user_prompt: str,
        session_label: str,
    ) -> Dict[str, Any]:
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        transcript: List[Dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        executed_commands: List[str] = []
        detailed_results: List[Dict[str, Any]] = []
        combined_output_parts: List[str] = []
        usage_records: List[Dict[str, Any]] = []
        verdict: Optional[Dict[str, Any]] = None

        command_calls = 0
        reasoning_turns = 0

        while command_calls < self.max_tool_iterations:
            response = self._chat(messages)
            usage = response.get("usage")
            if usage:
                usage_records.append(usage)

            message = response["choices"][0]["message"]
            assistant_entry: Dict[str, Any] = {
                "role": "assistant",
                "content": message.get("content"),
            }
            if message.get("tool_calls"):
                assistant_entry["tool_calls"] = message["tool_calls"]
            transcript.append(assistant_entry)
            messages.append(message)

            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                reasoning_turns += 1
                if reasoning_turns > 6:
                    break
                continue

            for tool_call in tool_calls:
                name = tool_call["function"]["name"]
                raw_args = tool_call["function"].get("arguments") or "{}"
                try:
                    args = json.loads(raw_args)
                except Exception:
                    args = {}

                payload: Dict[str, Any]
                if name == "run_command":
                    command = (args.get("command") or "").strip()
                    if not command:
                        payload = {"error": "No command provided"}
                    else:
                        normalized = self.command_normalizer(command)
                        run_result = self.shell_executor.run_command(normalized)
                        payload = run_result.model_dump()
                        if normalized != command:
                            payload["normalized_from"] = command

                        executed_commands.append(payload.get("command", command))
                        detailed_entry = {
                            "command": payload.get("command", command),
                            "exit_code": payload.get("exit_code"),
                            "stdout": payload.get("stdout", ""),
                            "stderr": payload.get("stderr", ""),
                            "success": payload.get("success", False),
                            "timed_out": payload.get("timed_out", False),
                            "duration": payload.get("duration"),
                            "normalized_from": payload.get("normalized_from"),
                        }
                        detailed_results.append(detailed_entry)
                        combined_output_parts.append(self._format_command_result(detailed_entry))

                    command_calls += 1
                    if command_calls >= self.max_tool_iterations:
                        pass
                elif name == "verdict":
                    verdict = {
                        "message": args.get("message", ""),
                        "resolved": bool(args.get("resolved")),
                    }
                    payload = {"acknowledged": True}
                else:
                    payload = {"error": f"Unknown tool {name}"}

                tool_entry = {
                    "role": "tool",
                    "tool_call_id": tool_call["id"],
                    "content": json.dumps(payload),
                }
                transcript.append(tool_entry)
                messages.append(tool_entry)

                if name == "verdict" or command_calls >= self.max_tool_iterations:
                    break

            if verdict or command_calls >= self.max_tool_iterations:
                break

        apply_success = any(result.get("success") for result in detailed_results)

        return {
            "commands": executed_commands,
            "detailed_results": detailed_results,
            "combined_output": "\n\n".join(combined_output_parts),
            "verdict": verdict,
            "apply_success": apply_success,
            "transcript": transcript,
            "usage": usage_records,
            "session_label": session_label,
        }

    def _chat(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        payload = {
            "model": self.model_name,
            "messages": messages,
            "tools": self.tools,
            "tool_choice": "auto",
        }
        response = requests.post(
            self.endpoint,
            headers=self.headers,
            json=payload,
            timeout=self.request_timeout,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"LLM API error {response.status_code}: {response.text}")
        return response.json()

    def _format_command_result(self, detail: Dict[str, Any]) -> str:
        stdout = detail.get("stdout") or ""
        stderr = detail.get("stderr") or ""
        return "\n".join([
            f"$ {detail.get('command', '<unknown>')} (exit={detail.get('exit_code')})",
            "STDOUT:",
            stdout if stdout.strip() else "<empty>",
            "STDERR:",
            stderr if stderr.strip() else "<empty>",
            "",
        ])


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

