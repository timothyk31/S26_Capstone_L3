"""Test data factories for generating consistent test objects."""

import factory
from typing import List
from schemas import (
    Vulnerability,
    TriageDecision,
    RemediationAttempt,
    ReviewVerdict,
    QAResult,
    RunCommandResult,
    PreApprovalResult,
    V2FindingResult
)


class VulnerabilityFactory:
    """Factory for creating test vulnerabilities."""
    
    @staticmethod
    def create_ssh_timeout() -> Vulnerability:
        """Create SSH timeout vulnerability for testing."""
        return Vulnerability(
            id="openscap_ssh_001",
            title="Set SSH Idle Timeout Interval",
            severity="2",
            host="10.0.0.1",
            description="ClientAliveInterval should be set to 600 seconds",
            recommendation="Set ClientAliveInterval 600 in /etc/ssh/sshd_config",
            result="fail",
            rule="ssh_client_alive_interval",
            oval_id="xccdf_org.ssgproject.content_rule_ssh_client_alive_interval",
            scan_class="compliance"
        )
    
    @staticmethod
    def create_critical() -> Vulnerability:
        """Create critical severity vulnerability."""
        return Vulnerability(
            id="openscap_crit_001",
            title="Critical Security Configuration",
            severity="4",
            host="10.0.0.1",
            description="Critical security misconfiguration detected",
            recommendation="Fix immediately",
            result="fail",
            rule="critical_security_rule",
            oval_id="xccdf_org.ssgproject.content_rule_critical",
            scan_class="compliance"
        )
    
    @staticmethod
    def create_low_risk() -> Vulnerability:
        """Create low-risk vulnerability."""
        return Vulnerability(
            id="openscap_low_001",
            title="Low Risk Configuration",
            severity="1",
            host="10.0.0.1",
            description="Minor configuration issue",
            recommendation="Optional fix",
            result="fail",
            rule="low_risk_rule",
            oval_id="xccdf_org.ssgproject.content_rule_low_risk",
            scan_class="compliance"
        )
    
    @staticmethod
    def create_filesystem() -> Vulnerability:
        """Create filesystem-related vulnerability."""
        return Vulnerability(
            id="openscap_fs_001",
            title="Filesystem Mount Options",
            severity="3",
            host="10.0.0.1",
            description="Mount filesystem with noexec option",
            recommendation="Add noexec to /etc/fstab mount options",
            result="fail",
            rule="mount_option_noexec",
            oval_id="xccdf_org.ssgproject.content_rule_mount_noexec",
            scan_class="compliance"
        )


class TriageDecisionFactory:
    """Factory for creating test triage decisions."""
    
    @staticmethod
    def create_approve() -> TriageDecision:
        """Create approval triage decision."""
        return TriageDecision(
            finding_id="openscap_ssh_001",
            should_remediate=True,
            risk_level="low",
            reason="Safe SSH configuration change. Low impact on system.",
            requires_human_review=False,
            estimated_impact="SSH service restart required"
        )
    
    @staticmethod
    def create_reject() -> TriageDecision:
        """Create rejection triage decision."""
        return TriageDecision(
            finding_id="openscap_crit_001",
            should_remediate=False,
            risk_level="critical",
            reason="High-risk change affecting core system functionality.",
            requires_human_review=False,
            estimated_impact="System instability possible"
        )
    
    @staticmethod
    def create_human_review() -> TriageDecision:
        """Create human review triage decision."""
        return TriageDecision(
            finding_id="openscap_fs_001",
            should_remediate=False,
            risk_level="medium",
            reason="Filesystem changes require careful evaluation.",
            requires_human_review=True,
            estimated_impact="Application compatibility issues possible"
        )


class RemediationAttemptFactory:
    """Factory for creating test remediation attempts."""
    
    @staticmethod
    def create_successful(finding_id: str = "openscap_ssh_001", attempt_number: int = 1) -> RemediationAttempt:
        """Create successful remediation attempt."""
        return RemediationAttempt(
            finding_id=finding_id,
            attempt_number=attempt_number,
            commands_executed=[
                "sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config",
                "systemctl restart sshd"
            ],
            files_modified=["/etc/ssh/sshd_config"],
            execution_details=[
                RunCommandResult(
                    command="sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config",
                    stdout="",
                    stderr="",
                    exit_code=0,
                    success=True,
                    duration=0.1
                )
            ],
            scan_passed=True,
            scan_output="Rule: ssh_client_alive_interval - PASS",
            duration=5.2,
            success=True
        )
    
    @staticmethod
    def create_failed(finding_id: str = "openscap_ssh_001", attempt_number: int = 1) -> RemediationAttempt:
        """Create failed remediation attempt."""
        return RemediationAttempt(
            finding_id=finding_id,
            attempt_number=attempt_number,
            commands_executed=[
                "invalid_command --wrong-flag"
            ],
            execution_details=[
                RunCommandResult(
                    command="invalid_command --wrong-flag",
                    stdout="",
                    stderr="Command not found",
                    exit_code=127,
                    success=False,
                    duration=0.1
                )
            ],
            scan_passed=False,
            scan_output="Rule: ssh_client_alive_interval - FAIL",
            duration=2.1,
            success=False,
            error_summary="Command execution failed with exit code 127"
        )


class ReviewVerdictFactory:
    """Factory for creating test review verdicts."""
    
    @staticmethod
    def create_approved(finding_id: str = "openscap_ssh_001") -> ReviewVerdict:
        """Create approved review verdict."""
        return ReviewVerdict(
            finding_id=finding_id,
            is_optimal=True,
            approve=True,
            feedback="Commands are safe and follow best practices.",
            concerns=[],
            suggested_improvements=[],
            security_score=9,
            best_practices_followed=True
        )
    
    @staticmethod
    def create_rejected(finding_id: str = "openscap_ssh_001") -> ReviewVerdict:
        """Create rejected review verdict."""
        return ReviewVerdict(
            finding_id=finding_id,
            is_optimal=False,
            approve=False,
            feedback="Commands are unsafe and may cause system instability.",
            concerns=["Direct file modification without backup", "No validation of existing config"],
            suggested_improvements=["Create config backup", "Validate syntax before restart"],
            security_score=3,
            best_practices_followed=False
        )


class QAResultFactory:
    """Factory for creating test QA results."""
    
    @staticmethod
    def create_safe(finding_id: str = "openscap_ssh_001") -> QAResult:
        """Create safe QA result."""
        return QAResult(
            finding_id=finding_id,
            safe=True,
            verdict_reason="System validation passed. No critical services affected.",
            side_effects=["SSH service restarted"],
            services_affected=["sshd"],
            system_checks=[
                RunCommandResult(
                    command="systemctl is-active sshd",
                    stdout="active",
                    stderr="",
                    exit_code=0,
                    success=True,
                    duration=0.1
                )
            ],
            regression_detected=False,
            other_findings_affected=[],
            recommendation="Approve",
            validation_duration=3.5
        )
    
    @staticmethod
    def create_unsafe(finding_id: str = "openscap_ssh_001") -> QAResult:
        """Create unsafe QA result."""
        return QAResult(
            finding_id=finding_id,
            safe=False,
            verdict_reason="Critical service failure detected after remediation.",
            side_effects=["SSH service failed to start"],
            services_affected=["sshd"],
            system_checks=[
                RunCommandResult(
                    command="systemctl is-active sshd",
                    stdout="failed",
                    stderr="Job for sshd.service failed",
                    exit_code=3,
                    success=False,
                    duration=0.1
                )
            ],
            regression_detected=True,
            other_findings_affected=["openscap_ssh_002"],
            recommendation="Rollback",
            validation_duration=2.8
        )


class MockDataFactory:
    """Factory for creating mock external API responses."""
    
    @staticmethod
    def create_llm_response_success():
        """Create successful LLM API response."""
        return {
            "choices": [
                {
                    "message": {
                        "content": "I'll help you remediate this SSH configuration issue.",
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "run_command",
                                    "arguments": '{"command": "sed -i \'s/^#ClientAliveInterval.*/ClientAliveInterval 600/\' /etc/ssh/sshd_config"}'
                                }
                            }
                        ]
                    }
                }
            ]
        }
    
    @staticmethod
    def create_llm_response_error():
        """Create error LLM API response."""
        return {
            "error": {
                "message": "API rate limit exceeded",
                "type": "rate_limit_exceeded",
                "code": "rate_limit_exceeded"
            }
        }
    
    @staticmethod
    def create_openscap_xml_output():
        """Create mock OpenSCAP XML output."""
        return """<?xml version="1.0" encoding="UTF-8"?>
<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" 
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <rule-result idref="xccdf_org.ssgproject.content_rule_ssh_client_alive_interval">
        <result>pass</result>
        <ident system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
            oval:ssg-ssh_client_alive_interval:def:1
        </ident>
        <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
            <check-content-ref href="ssg-rhel8-oval.xml" 
                               name="oval:ssg-ssh_client_alive_interval:def:1"/>
        </check>
    </rule-result>
</TestResult>"""