#!/usr/bin/env python3
"""
Demo script for PipelineV2 — simulates the full agent pipeline without
requiring a live system, real LLM calls, or OpenSCAP scans.

All agents are replaced with mock implementations that produce realistic
data and print agent-to-agent communication so you can observe the flow:

  Triage → Remedy (generates fix → Review+QA approval → scan) → Result

Usage:
    python demo_scripts/demo_pipeline_v2.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from schemas import (
    PreApprovalResult,
    QAInput,
    QAResult,
    RemedyInput,
    RemediationAttempt,
    ReviewInput,
    ReviewVerdict,
    RunCommandResult,
    ToolVerdict,
    TriageDecision,
    TriageInput,
    V2FindingResult,
    Vulnerability,
)
from workflow.pipeline_v2 import PipelineV2

console = Console()

# ============================================================================
# Sample vulnerabilities for the demo
# ============================================================================

DEMO_VULNS = [
    Vulnerability(
        id="openscap_001",
        title="Ensure password minimum length is configured",
        severity="medium",
        cvss=5.3,
        host="rocky-vm-01",
        description=(
            "The system does not enforce a minimum password length of 12 characters. "
            "This weakens password security and may allow brute-force attacks."
        ),
        recommendation="Set minlen = 12 in /etc/security/pwquality.conf",
        rule="accounts_password_minlen_login_defs",
        oval_id="xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs",
        scan_class="compliance",
        os="Rocky Linux 10",
    ),
    Vulnerability(
        id="openscap_002",
        title="Ensure SSH root login is disabled",
        severity="high",
        cvss=7.5,
        host="rocky-vm-01",
        description="Root login over SSH is permitted, allowing direct brute-force attacks on the root account.",
        recommendation="Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd.",
        rule="sshd_disable_root_login",
        oval_id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
        scan_class="compliance",
        os="Rocky Linux 10",
    ),
    Vulnerability(
        id="openscap_003",
        title="Ensure auditd is enabled and running",
        severity="low",
        cvss=3.1,
        host="rocky-vm-01",
        description="The auditd service is not enabled, which means system events are not being logged for security auditing.",
        recommendation="Run systemctl enable --now auditd",
        rule="service_auditd_enabled",
        oval_id="xccdf_org.ssgproject.content_rule_service_auditd_enabled",
        scan_class="compliance",
        os="Rocky Linux 10",
    ),
]


# ============================================================================
# Mock agents — simulate LLM responses and tool execution
# ============================================================================

class MockTriageAgent:
    """Simulates the Triage agent's LLM decision."""

    def process(self, input_data: TriageInput) -> TriageDecision:
        vuln = input_data.vulnerability
        time.sleep(0.3)  # simulate latency

        console.print(
            f"  [dim]Triage LLM thinking about {vuln.id} ({vuln.severity})...[/dim]"
        )

        return TriageDecision(
            finding_id=vuln.id,
            should_remediate=True,
            risk_level=vuln.severity,
            reason=(
                f"Automated fix is safe. {vuln.title} is a standard "
                f"compliance hardening item with low risk of side effects."
            ),
            requires_human_review=False,
            estimated_impact="config change only",
        )


class MockRemedyAgent:
    """Simulates the Remedy agent's tool-calling LLM session."""

    # Pre-canned fix details per vulnerability
    FIX_DATA = {
        "openscap_001": {
            "commands": [
                "cat /etc/security/pwquality.conf",
                "sed -i 's/^# minlen.*$/minlen = 12/' /etc/security/pwquality.conf",
                "grep minlen /etc/security/pwquality.conf",
            ],
            "files_read": ["/etc/security/pwquality.conf"],
            "files_modified": ["/etc/security/pwquality.conf"],
        },
        "openscap_002": {
            "commands": [
                "cat /etc/ssh/sshd_config",
                "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                "grep PermitRootLogin /etc/ssh/sshd_config",
                "systemctl restart sshd",
            ],
            "files_read": ["/etc/ssh/sshd_config"],
            "files_modified": ["/etc/ssh/sshd_config"],
        },
        "openscap_003": {
            "commands": [
                "systemctl status auditd",
                "systemctl enable --now auditd",
                "systemctl is-active auditd",
            ],
            "files_read": [],
            "files_modified": [],
        },
    }

    def process(self, input_data: RemedyInput) -> RemediationAttempt:
        vuln = input_data.vulnerability
        fix = self.FIX_DATA.get(vuln.id, {"commands": ["echo 'no fix mapped'"], "files_read": [], "files_modified": []})
        time.sleep(0.4)

        console.print(f"  [dim]Remedy LLM generating fix for {vuln.id}...[/dim]")
        for cmd in fix["commands"]:
            console.print(f"    [dim]> tool_call: run_cmd(\"{cmd}\")[/dim]")
            time.sleep(0.15)

        execution_details = [
            RunCommandResult(
                command=cmd,
                stdout="OK",
                stderr="",
                exit_code=0,
                success=True,
                duration=0.2,
                timed_out=False,
            )
            for cmd in fix["commands"]
        ]

        return RemediationAttempt(
            finding_id=vuln.id,
            attempt_number=input_data.attempt_number,
            commands_executed=fix["commands"],
            files_modified=fix["files_modified"],
            files_read=fix["files_read"],
            execution_details=execution_details,
            scan_passed=False,  # set later by RemedyAgentV2
            success=False,
            llm_verdict=ToolVerdict(
                message=f"Applied fix for {vuln.title}. Awaiting scan verification.",
                resolved=False,
            ),
        )

    def _tool_scan(self, vuln: Vulnerability) -> dict:
        """Mock verification scan — always passes for demo."""
        time.sleep(0.3)
        console.print(f"  [dim]Mock scan for {vuln.id}: PASS[/dim]")
        return {"pass": True, "summary": f"Rule {vuln.rule} now passes."}


class MockReviewAgent:
    """Simulates the Review agent's LLM evaluation."""

    def process(self, review_input: ReviewInput) -> ReviewVerdict:
        vuln = review_input.vulnerability
        attempt = review_input.remediation_attempt
        time.sleep(0.3)

        console.print(
            f"  [dim]Review LLM evaluating fix quality for {vuln.id}...[/dim]"
        )
        console.print(
            f"    [dim]Commands reviewed: {attempt.commands_executed}[/dim]"
        )

        return ReviewVerdict(
            finding_id=vuln.id,
            is_optimal=True,
            approve=True,
            feedback="Fix uses correct in-place sed modification. No duplicate lines introduced.",
            concerns=[],
            suggested_improvements=[],
            security_score=8,
            best_practices_followed=True,
        )


class MockQAAgentV2:
    """Simulates the QA Agent V2 expert-opinion LLM call."""

    def process(self, input_data: QAInput) -> QAResult:
        vuln = input_data.vulnerability
        time.sleep(0.3)

        console.print(
            f"  [dim]QA LLM evaluating system safety for {vuln.id}...[/dim]"
        )

        return QAResult(
            finding_id=vuln.id,
            safe=True,
            verdict_reason=(
                f"Remediation for '{vuln.title}' follows best practices. "
                "No critical services will be disrupted."
            ),
            side_effects=[],
            services_affected=["sshd"] if "ssh" in (vuln.rule or "").lower() else [],
            recommendation="Approve",
            validation_duration=0.3,
        )


# ============================================================================
# Wire up the mock agents into the real V2 wrappers
# ============================================================================

def build_mock_pipeline() -> PipelineV2:
    """Construct a PipelineV2 with all agents mocked."""
    from agents.review_agent_v2 import ReviewAgentV2
    from agents.remedy_agent_v2 import RemedyAgentV2

    # Create mock base agents
    mock_triage = MockTriageAgent()
    mock_remedy = MockRemedyAgent()
    mock_review = MockReviewAgent()
    mock_qa = MockQAAgentV2()

    # Wire V2 wrappers with mock base agents
    review_v2 = ReviewAgentV2(review_agent=mock_review, qa_agent=mock_qa)
    remedy_v2 = RemedyAgentV2(remedy_agent=mock_remedy, review_agent_v2=review_v2)

    return PipelineV2(
        triage_agent=mock_triage,
        remedy_agent_v2=remedy_v2,
        max_remedy_attempts=3,
    )


# ============================================================================
# Main demo
# ============================================================================

def main():
    console.print(Panel.fit(
        "[bold green]Pipeline V2 Demo[/bold green]\n"
        "Simulates Triage → Remedy → Review → QA → Scan for each finding.\n"
        "All LLM calls and system commands are mocked.",
        title="S26 Capstone L3",
    ))

    pipeline = build_mock_pipeline()
    results: list[V2FindingResult] = []

    for i, vuln in enumerate(DEMO_VULNS, 1):
        console.rule(f"[bold]Finding {i}/{len(DEMO_VULNS)}: {vuln.id} — {vuln.title}[/bold]")
        result = pipeline.run(vuln)
        results.append(result)
        console.print()

    # ── Summary table ──────────────────────────────────────────────────
    console.rule("[bold]Demo Results Summary[/bold]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Finding ID")
    table.add_column("Title")
    table.add_column("Severity")
    table.add_column("Triage")
    table.add_column("Approval")
    table.add_column("Scan")
    table.add_column("Final Status")
    table.add_column("Duration")

    for r in results:
        triage_str = "Remediate" if r.triage.should_remediate else "Skip"
        approval_str = "—"
        scan_str = "—"
        if r.pre_approval is not None:
            approval_str = "[green]Approved[/green]" if r.pre_approval.approved else "[red]Rejected[/red]"
        if r.remediation is not None:
            scan_str = "[green]PASS[/green]" if r.remediation.scan_passed else "[red]FAIL[/red]"

        status_color = "green" if r.final_status == "success" else "red"
        table.add_row(
            r.vulnerability.id,
            r.vulnerability.title[:40],
            r.vulnerability.severity,
            triage_str,
            approval_str,
            scan_str,
            f"[{status_color}]{r.final_status.upper()}[/{status_color}]",
            f"{r.total_duration:.1f}s",
        )

    console.print(table)
    console.print(
        f"\n[bold]Total: {len(results)} findings processed, "
        f"{sum(1 for r in results if r.final_status == 'success')} succeeded[/bold]"
    )


if __name__ == "__main__":
    main()
