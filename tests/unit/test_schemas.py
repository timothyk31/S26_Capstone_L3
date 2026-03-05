"""Unit tests for Pydantic schemas and data models."""

import pytest
from pydantic import ValidationError
from datetime import datetime

from schemas import (
    Vulnerability,
    TriageDecision,
    TriageInput,
    RemediationAttempt,
    ReviewVerdict,
    QAResult,
    RunCommandResult,
    PreApprovalResult,
    V2FindingResult,
    V2AggregatedReport
)
from tests.fixtures.test_data_factory import (
    VulnerabilityFactory,
    TriageDecisionFactory,
    RemediationAttemptFactory,
    ReviewVerdictFactory,
    QAResultFactory
)


@pytest.mark.unit
class TestVulnerabilitySchema:
    """Test Vulnerability model validation and behavior."""

    def test_vulnerability_creation_minimal(self):
        """Test creating vulnerability with minimal required fields."""
        vuln = Vulnerability(
            id="test_001",
            title="Test Vulnerability",
            severity="2",
            host="10.0.0.1"
        )
        
        assert vuln.id == "test_001"
        assert vuln.title == "Test Vulnerability"
        assert vuln.severity == "2"
        assert vuln.host == "10.0.0.1"
        assert vuln.cvss is None
        assert vuln.description is None

    def test_vulnerability_creation_full(self):
        """Test creating vulnerability with all fields."""
        vuln = Vulnerability(
            id="test_002",
            title="Full Test Vulnerability",
            severity="4",
            cvss=7.5,
            host="192.168.1.100",
            port="22",
            protocol="tcp",
            description="Detailed description",
            recommendation="Fix recommendation",
            result="fail",
            rule="ssh_config",
            oval_id="xccdf_org.ssgproject.content_rule_ssh",
            scan_class="compliance",
            os="Rocky Linux 9"
        )
        
        assert vuln.cvss == 7.5
        assert vuln.port == "22"
        assert vuln.protocol == "tcp"
        assert vuln.result == "fail"
        assert vuln.rule == "ssh_config"

    def test_vulnerability_validation_errors(self):
        """Test validation errors for invalid vulnerability data."""
        # Missing required fields
        with pytest.raises(ValidationError) as exc_info:
            Vulnerability()
        
        error_dict = exc_info.value.error_dict()
        assert "id" in error_dict
        assert "title" in error_dict
        assert "severity" in error_dict
        assert "host" in error_dict

    def test_vulnerability_factory_methods(self):
        """Test vulnerability factory methods produce valid objects."""
        ssh_vuln = VulnerabilityFactory.create_ssh_timeout()
        assert ssh_vuln.id == "openscap_ssh_001"
        assert ssh_vuln.severity == "2"
        
        critical_vuln = VulnerabilityFactory.create_critical()
        assert critical_vuln.severity == "4"
        
        low_risk_vuln = VulnerabilityFactory.create_low_risk()
        assert low_risk_vuln.severity == "1"


@pytest.mark.unit
class TestTriageDecisionSchema:
    """Test TriageDecision model validation and behavior."""

    def test_triage_decision_creation(self):
        """Test creating triage decision with all fields."""
        decision = TriageDecision(
            finding_id="test_001",
            should_remediate=True,
            risk_level="low",
            reason="Safe configuration change",
            requires_human_review=False,
            estimated_impact="Service restart required"
        )
        
        assert decision.finding_id == "test_001"
        assert decision.should_remediate is True
        assert decision.risk_level == "low"
        assert decision.requires_human_review is False

    def test_triage_decision_validation_errors(self):
        """Test validation errors for triage decision."""
        with pytest.raises(ValidationError):
            TriageDecision()  # Missing required fields

    def test_triage_decision_factory_methods(self):
        """Test triage decision factory methods."""
        approve_decision = TriageDecisionFactory.create_approve()
        assert approve_decision.should_remediate is True
        assert approve_decision.risk_level == "low"
        
        reject_decision = TriageDecisionFactory.create_reject()
        assert reject_decision.should_remediate is False
        assert reject_decision.risk_level == "critical"
        
        human_review = TriageDecisionFactory.create_human_review()
        assert human_review.requires_human_review is True


@pytest.mark.unit
class TestRemediationAttemptSchema:
    """Test RemediationAttempt model validation and behavior."""

    def test_remediation_attempt_creation(self):
        """Test creating remediation attempt."""
        attempt = RemediationAttempt(
            finding_id="test_001",
            attempt_number=1,
            commands_executed=["echo 'test'"],
            scan_passed=True,
            success=True
        )
        
        assert attempt.finding_id == "test_001"
        assert attempt.attempt_number == 1
        assert len(attempt.commands_executed) == 1
        assert attempt.scan_passed is True
        assert attempt.success is True

    def test_remediation_attempt_defaults(self):
        """Test default values for remediation attempt."""
        attempt = RemediationAttempt(
            finding_id="test_002",
            scan_passed=False,
            success=False
        )
        
        assert attempt.attempt_number == 1
        assert len(attempt.commands_executed) == 0
        assert len(attempt.files_modified) == 0
        assert len(attempt.execution_details) == 0
        assert attempt.duration == 0.0

    def test_remediation_attempt_factory_methods(self):
        """Test remediation attempt factory methods."""
        successful = RemediationAttemptFactory.create_successful()
        assert successful.success is True
        assert successful.scan_passed is True
        assert len(successful.commands_executed) > 0
        
        failed = RemediationAttemptFactory.create_failed()
        assert failed.success is False
        assert failed.scan_passed is False
        assert failed.error_summary is not None


@pytest.mark.unit
class TestRunCommandResultSchema:
    """Test RunCommandResult model validation and behavior."""

    def test_run_command_result_creation(self):
        """Test creating run command result."""
        result = RunCommandResult(
            command="echo 'hello'",
            stdout="hello",
            stderr="",
            exit_code=0,
            success=True,
            duration=0.1
        )
        
        assert result.command == "echo 'hello'"
        assert result.stdout == "hello"
        assert result.exit_code == 0
        assert result.success is True
        assert result.duration == 0.1

    def test_run_command_result_defaults(self):
        """Test default values for run command result."""
        result = RunCommandResult(
            command="test",
            stdout="",
            stderr="",
            success=True,
            duration=0.1
        )
        
        assert result.exit_code is None
        assert result.timed_out is False
        assert result.truncated_stdout is False


@pytest.mark.unit
class TestReviewVerdictSchema:
    """Test ReviewVerdict model validation and behavior."""

    def test_review_verdict_creation(self):
        """Test creating review verdict."""
        verdict = ReviewVerdict(
            finding_id="test_001",
            is_optimal=True,
            approve=True,
            security_score=8,
            best_practices_followed=True
        )
        
        assert verdict.finding_id == "test_001"
        assert verdict.is_optimal is True
        assert verdict.approve is True
        assert verdict.security_score == 8

    def test_review_verdict_defaults(self):
        """Test default values for review verdict."""
        verdict = ReviewVerdict(
            finding_id="test_002",
            is_optimal=False,
            approve=False
        )
        
        assert verdict.feedback is None
        assert len(verdict.concerns) == 0
        assert len(verdict.suggested_improvements) == 0
        assert verdict.best_practices_followed is True

    def test_review_verdict_factory_methods(self):
        """Test review verdict factory methods."""
        approved = ReviewVerdictFactory.create_approved()
        assert approved.approve is True
        assert approved.is_optimal is True
        
        rejected = ReviewVerdictFactory.create_rejected()
        assert rejected.approve is False
        assert rejected.is_optimal is False
        assert len(rejected.concerns) > 0


@pytest.mark.unit
class TestQAResultSchema:
    """Test QAResult model validation and behavior."""

    def test_qa_result_creation(self):
        """Test creating QA result."""
        qa_result = QAResult(
            finding_id="test_001",
            safe=True,
            verdict_reason="All checks passed",
            recommendation="Approve"
        )
        
        assert qa_result.finding_id == "test_001"
        assert qa_result.safe is True
        assert qa_result.verdict_reason == "All checks passed"
        assert qa_result.recommendation == "Approve"

    def test_qa_result_defaults(self):
        """Test default values for QA result."""
        qa_result = QAResult(
            finding_id="test_002",
            safe=False
        )
        
        assert qa_result.verdict_reason == ""
        assert len(qa_result.side_effects) == 0
        assert qa_result.regression_detected is False
        assert qa_result.recommendation == "Investigate"

    def test_qa_result_factory_methods(self):
        """Test QA result factory methods."""
        safe_result = QAResultFactory.create_safe()
        assert safe_result.safe is True
        assert safe_result.recommendation == "Approve"
        
        unsafe_result = QAResultFactory.create_unsafe()
        assert unsafe_result.safe is False
        assert unsafe_result.recommendation == "Rollback"


@pytest.mark.unit
class TestPreApprovalResultSchema:
    """Test PreApprovalResult model validation and behavior."""

    def test_pre_approval_result_creation(self):
        """Test creating pre-approval result."""
        review_verdict = ReviewVerdictFactory.create_approved()
        qa_result = QAResultFactory.create_safe()
        
        pre_approval = PreApprovalResult(
            review_verdict=review_verdict,
            qa_result=qa_result,
            approved=True
        )
        
        assert pre_approval.approved is True
        assert pre_approval.rejection_reason is None
        assert pre_approval.review_verdict.approve is True

    def test_pre_approval_result_rejection(self):
        """Test pre-approval result with rejection."""
        review_verdict = ReviewVerdictFactory.create_rejected()
        
        pre_approval = PreApprovalResult(
            review_verdict=review_verdict,
            qa_result=None,
            approved=False,
            rejection_reason="Review rejected the approach"
        )
        
        assert pre_approval.approved is False
        assert pre_approval.rejection_reason is not None
        assert pre_approval.qa_result is None


@pytest.mark.unit
class TestV2FindingResultSchema:
    """Test V2FindingResult model validation and behavior."""

    def test_v2_finding_result_creation(self):
        """Test creating V2 finding result."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        triage = TriageDecisionFactory.create_approve()
        remediation = RemediationAttemptFactory.create_successful()
        
        finding_result = V2FindingResult(
            vulnerability=vulnerability,
            triage=triage,
            remediation=remediation,
            final_status="success",
            total_duration=10.5,
            timestamp="2024-01-01T12:00:00Z"
        )
        
        assert finding_result.final_status == "success"
        assert finding_result.total_duration == 10.5
        assert finding_result.vulnerability.id == vulnerability.id
        assert finding_result.remediation is not None

    def test_v2_finding_result_defaults(self):
        """Test default values for V2 finding result."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        triage = TriageDecisionFactory.create_reject()
        
        finding_result = V2FindingResult(
            vulnerability=vulnerability,
            triage=triage,
            final_status="discarded",
            total_duration=0.0,
            timestamp=""
        )
        
        assert len(finding_result.all_attempts) == 0
        assert finding_result.remediation is None
        assert finding_result.pre_approval is None
        assert len(finding_result.llm_metrics) == 0


@pytest.mark.unit
class TestV2AggregatedReportSchema:
    """Test V2AggregatedReport model validation and behavior."""

    def test_v2_aggregated_report_creation(self):
        """Test creating V2 aggregated report."""
        report = V2AggregatedReport(
            findings_processed=10,
            findings_remediated=7,
            findings_failed=2,
            findings_discarded=1,
            success_rate=0.7,
            total_duration=120.5,
            scan_profile="cis",
            target_host="10.0.0.1",
            timestamp="2024-01-01T12:00:00Z"
        )
        
        assert report.findings_processed == 10
        assert report.success_rate == 0.7
        assert report.scan_profile == "cis"
        assert len(report.results) == 0

    def test_v2_aggregated_report_defaults(self):
        """Test default values for V2 aggregated report."""
        report = V2AggregatedReport(
            findings_processed=0,
            findings_remediated=0,
            findings_failed=0,
            findings_discarded=0,
            success_rate=0.0,
            scan_profile="",
            target_host="",
            timestamp=""
        )
        
        assert len(report.results) == 0
        assert len(report.stage_statistics) == 0
        assert report.ansible_playbook_path is None