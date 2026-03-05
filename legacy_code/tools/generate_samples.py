#!/usr/bin/env python3
"""Generate sample PDF reports for each agent using mock data."""

from pathlib import Path
from schemas import (
    FindingResult,
    QAResult,
    RemediationAttempt,
    ReviewVerdict,
    RunCommandResult,
    ToolVerdict,
    TriageDecision,
    Vulnerability,
)

SAMPLE_DIR = Path("sample")
SAMPLE_DIR.mkdir(parents=True, exist_ok=True)
TARGET_HOST = "10.244.72.95"

# ── Mock Vulnerabilities ────────────────────────────────────────────────────

vulns = [
    Vulnerability(
        id="openscap_001",
        title="xccdf_org.ssgproject.content_rule_package_aide_installed",
        severity="3",
        host=TARGET_HOST,
        description="The AIDE package must be installed to detect unauthorized changes to files.",
        recommendation="Install the aide package using dnf install aide.",
        result="fail",
        rule="package_aide_installed",
        os="Rocky Linux 10",
    ),
    Vulnerability(
        id="openscap_015",
        title="xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs",
        severity="3",
        host=TARGET_HOST,
        description="The password minimum length must be set to 15 characters in /etc/login.defs.",
        recommendation="Set PASS_MIN_LEN to 15 in /etc/login.defs.",
        result="fail",
        rule="accounts_password_minlen_login_defs",
        os="Rocky Linux 10",
    ),
    Vulnerability(
        id="openscap_027",
        title="xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_redirects",
        severity="2",
        host=TARGET_HOST,
        description="The system must not accept ICMP redirects on all IPv4 interfaces.",
        recommendation="Set net.ipv4.conf.all.accept_redirects = 0 in sysctl configuration.",
        result="fail",
        rule="sysctl_net_ipv4_conf_all_accept_redirects",
        os="Rocky Linux 10",
    ),
    Vulnerability(
        id="openscap_048",
        title="xccdf_org.ssgproject.content_rule_partition_for_var_log",
        severity="2",
        host=TARGET_HOST,
        description="/var/log must be on a separate partition.",
        recommendation="Create a separate partition for /var/log during installation.",
        result="fail",
        rule="partition_for_var_log",
        os="Rocky Linux 10",
    ),
    Vulnerability(
        id="openscap_104",
        title="xccdf_org.ssgproject.content_rule_service_auditd_enabled",
        severity="3",
        host=TARGET_HOST,
        description="The auditd service must be running.",
        recommendation="Enable and start the auditd service.",
        result="fail",
        rule="service_auditd_enabled",
        os="Rocky Linux 10",
    ),
]

# ── Mock Triage Decisions ───────────────────────────────────────────────────

triage_decisions = [
    TriageDecision(
        finding_id="openscap_001",
        should_remediate=True,
        risk_level="low",
        reason="Installing aide is a safe, non-disruptive operation with no service impact.",
        requires_human_review=False,
        estimated_impact="Package installation; no reboot required",
    ),
    TriageDecision(
        finding_id="openscap_015",
        should_remediate=True,
        risk_level="low",
        reason="Password minimum length policy change is safe to apply automatically.",
        requires_human_review=False,
        estimated_impact="Password policy update; affects new passwords only",
    ),
    TriageDecision(
        finding_id="openscap_027",
        should_remediate=True,
        risk_level="low",
        reason="Sysctl network hardening is low-risk and standard practice.",
        requires_human_review=False,
        estimated_impact="Network parameter change; no service restart needed",
    ),
    TriageDecision(
        finding_id="openscap_048",
        should_remediate=False,
        risk_level="critical",
        reason="Filesystem/partition changes can break boot or services and should not be auto-remediated.",
        requires_human_review=False,
        estimated_impact="reboot required; filesystems/partitioning; service disruption risk",
    ),
    TriageDecision(
        finding_id="openscap_104",
        should_remediate=True,
        risk_level="low",
        reason="Enabling auditd is a standard hardening step with minimal risk.",
        requires_human_review=False,
        estimated_impact="Service enablement; no reboot required",
    ),
]

# ── Mock Remediation Attempts ───────────────────────────────────────────────

remediations = {
    "openscap_001": RemediationAttempt(
        finding_id="openscap_001",
        attempt_number=1,
        commands_executed=["dnf install -y aide", "aide --init", "cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"],
        files_modified=["/var/lib/aide/aide.db.gz"],
        files_read=["/etc/aide.conf"],
        execution_details=[
            RunCommandResult(command="dnf install -y aide", stdout="Complete!", stderr="", exit_code=0, success=True, duration=12.3),
            RunCommandResult(command="aide --init", stdout="AIDE initialized database", stderr="", exit_code=0, success=True, duration=45.1),
        ],
        scan_passed=True,
        scan_output="PASS: package_aide_installed",
        duration=62.5,
        success=True,
        llm_verdict=ToolVerdict(message="aide installed and database initialized successfully", resolved=True),
    ),
    "openscap_015": RemediationAttempt(
        finding_id="openscap_015",
        attempt_number=1,
        commands_executed=["sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    15/' /etc/login.defs"],
        files_modified=["/etc/login.defs"],
        files_read=["/etc/login.defs"],
        execution_details=[
            RunCommandResult(command="sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    15/' /etc/login.defs", stdout="", stderr="", exit_code=0, success=True, duration=0.2),
        ],
        scan_passed=True,
        scan_output="PASS: accounts_password_minlen_login_defs",
        duration=8.7,
        success=True,
        llm_verdict=ToolVerdict(message="PASS_MIN_LEN set to 15 in login.defs", resolved=True),
    ),
    "openscap_027": RemediationAttempt(
        finding_id="openscap_027",
        attempt_number=2,
        commands_executed=[
            "sysctl -w net.ipv4.conf.all.accept_redirects=0",
            "echo 'net.ipv4.conf.all.accept_redirects = 0' > /etc/sysctl.d/99-accept-redirects.conf",
            "sysctl -p /etc/sysctl.d/99-accept-redirects.conf",
        ],
        files_modified=["/etc/sysctl.d/99-accept-redirects.conf"],
        files_read=[],
        execution_details=[
            RunCommandResult(command="sysctl -w net.ipv4.conf.all.accept_redirects=0", stdout="net.ipv4.conf.all.accept_redirects = 0", stderr="", exit_code=0, success=True, duration=0.1),
        ],
        scan_passed=True,
        scan_output="PASS: sysctl_net_ipv4_conf_all_accept_redirects",
        duration=15.2,
        success=True,
        error_summary="Attempt 1 failed: forgot persistence file",
        llm_verdict=ToolVerdict(message="sysctl setting applied and persisted", resolved=True),
    ),
    "openscap_104": RemediationAttempt(
        finding_id="openscap_104",
        attempt_number=1,
        commands_executed=["systemctl enable auditd", "systemctl start auditd"],
        files_modified=[],
        files_read=[],
        execution_details=[
            RunCommandResult(command="systemctl enable auditd", stdout="", stderr="", exit_code=0, success=True, duration=0.5),
            RunCommandResult(command="systemctl start auditd", stdout="", stderr="", exit_code=0, success=True, duration=1.2),
        ],
        scan_passed=True,
        scan_output="PASS: service_auditd_enabled",
        duration=5.8,
        success=True,
        llm_verdict=ToolVerdict(message="auditd enabled and started", resolved=True),
    ),
}

# ── Mock Review Verdicts ────────────────────────────────────────────────────

reviews = {
    "openscap_001": ReviewVerdict(
        finding_id="openscap_001",
        is_optimal=True,
        approve=True,
        feedback="Clean remediation. aide installed and database initialized correctly.",
        concerns=[],
        suggested_improvements=[],
        security_score=9,
        best_practices_followed=True,
    ),
    "openscap_015": ReviewVerdict(
        finding_id="openscap_015",
        is_optimal=True,
        approve=True,
        feedback="Correct sed command to update PASS_MIN_LEN. Minimal and targeted change.",
        concerns=[],
        suggested_improvements=["Consider also updating pwquality.conf for consistency"],
        security_score=8,
        best_practices_followed=True,
    ),
    "openscap_027": ReviewVerdict(
        finding_id="openscap_027",
        is_optimal=False,
        approve=True,
        feedback="Fix works but took 2 attempts. Second attempt correctly persisted to sysctl.d.",
        concerns=["First attempt did not persist the setting"],
        suggested_improvements=["Always persist sysctl changes on first attempt"],
        security_score=7,
        best_practices_followed=True,
    ),
    "openscap_104": ReviewVerdict(
        finding_id="openscap_104",
        is_optimal=True,
        approve=True,
        feedback="Simple and correct service enablement.",
        concerns=[],
        suggested_improvements=[],
        security_score=10,
        best_practices_followed=True,
    ),
}

# ── Mock QA Results ─────────────────────────────────────────────────────────

qa_results = {
    "openscap_001": QAResult(
        finding_id="openscap_001",
        safe=True,
        side_effects=[],
        services_affected=["sshd", "auditd"],
        system_checks=[
            RunCommandResult(command="systemctl status sshd", stdout="active (running)", stderr="", exit_code=0, success=True, duration=0.3),
            RunCommandResult(command="systemctl status auditd", stdout="active (running)", stderr="", exit_code=0, success=True, duration=0.2),
        ],
        regression_detected=False,
        recommendation="Approve",
        validation_duration=8.4,
    ),
    "openscap_015": QAResult(
        finding_id="openscap_015",
        safe=True,
        side_effects=[],
        services_affected=["sshd"],
        system_checks=[
            RunCommandResult(command="systemctl status sshd", stdout="active (running)", stderr="", exit_code=0, success=True, duration=0.2),
        ],
        regression_detected=False,
        recommendation="Approve",
        validation_duration=5.1,
    ),
    "openscap_027": QAResult(
        finding_id="openscap_027",
        safe=True,
        side_effects=["Network redirects now disabled on all interfaces"],
        services_affected=["sshd", "firewalld"],
        system_checks=[
            RunCommandResult(command="systemctl status sshd", stdout="active (running)", stderr="", exit_code=0, success=True, duration=0.2),
            RunCommandResult(command="systemctl status firewalld", stdout="active (running)", stderr="", exit_code=0, success=True, duration=0.3),
        ],
        regression_detected=False,
        recommendation="Approve",
        validation_duration=7.2,
    ),
    "openscap_104": QAResult(
        finding_id="openscap_104",
        safe=True,
        side_effects=[],
        services_affected=["auditd", "sshd"],
        system_checks=[
            RunCommandResult(command="systemctl status auditd", stdout="active (running)", stderr="", exit_code=0, success=True, duration=0.2),
        ],
        regression_detected=False,
        recommendation="Approve",
        validation_duration=4.6,
    ),
}

# ── Build FindingResults ────────────────────────────────────────────────────

results = []
for v, td in zip(vulns, triage_decisions):
    fr = FindingResult(
        vulnerability=v,
        triage=td,
        remediation=remediations.get(v.id),
        review=reviews.get(v.id),
        qa=qa_results.get(v.id),
        final_status="success" if v.id in qa_results else ("discarded" if not td.should_remediate else "failed"),
        total_duration=remediations[v.id].duration if v.id in remediations else 0.0,
        timestamp="2026-02-17T14:30:00",
    )
    results.append(fr)

# ── Generate PDFs ───────────────────────────────────────────────────────────

# 1. Triage PDF — uses a stub TriageAgent (no API key needed for PDF only)
from agents.triage_agent import TriageAgent

class _StubTriageAgent(TriageAgent):
    """Bypass __init__ API key requirement just for PDF generation."""
    def __init__(self):
        self.agent_name = "TriageAgent"

triage = _StubTriageAgent()
triage.write_results_pdf(
    triage_decisions,
    output_path=SAMPLE_DIR / "triage_report.pdf",
    target_host=TARGET_HOST,
    title="OpenSCAP Triage Report (Sample)",
    total_rules_scanned=247,
    rules_passed=195,
    rules_failed=52,
    vulnerabilities=vulns,
)
print(f"  [OK] {SAMPLE_DIR / 'triage_report.pdf'}")

# 2. Remedy PDF
from agents.remedy_agent import RemedyAgent

class _StubRemedyAgent(RemedyAgent):
    def __init__(self):
        pass

remedy = _StubRemedyAgent()
remedy.write_results_pdf(
    results,
    output_path=SAMPLE_DIR / "remedy_report.pdf",
    target_host=TARGET_HOST,
    title="Remedy Agent Report (Sample)",
)
print(f"  [OK] {SAMPLE_DIR / 'remedy_report.pdf'}")

# 3. Review PDF
from agents.review_agent import ReviewAgent

class _StubReviewAgent(ReviewAgent):
    def __init__(self):
        pass

review = _StubReviewAgent()
review.write_results_pdf(
    results,
    output_path=SAMPLE_DIR / "review_report.pdf",
    target_host=TARGET_HOST,
    title="Review Agent Report (Sample)",
)
print(f"  [OK] {SAMPLE_DIR / 'review_report.pdf'}")

# 4. QA PDF
from agents.qa_agent import QAAgent

class _StubQAAgent(QAAgent):
    def __init__(self):
        pass

qa = _StubQAAgent()
qa.write_results_pdf(
    results,
    output_path=SAMPLE_DIR / "qa_report.pdf",
    target_host=TARGET_HOST,
    title="QA Agent Report (Sample)",
)
print(f"  [OK] {SAMPLE_DIR / 'qa_report.pdf'}")

print(f"\nAll sample PDFs saved to ./{SAMPLE_DIR}/")
