"""Unit tests for v2 pipeline schemas."""

import pytest
from schemas import (
    PreApprovalResult,
    QAResult,
    RemediationAttempt,
    ReviewVerdict,
    TriageDecision,
    V2AggregatedReport,
    V2FindingResult,
    Vulnerability,
)


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def sample_vulnerability():
    return Vulnerability(
        id="openscap_001",
        title="Ensure SSH MaxAuthTries is set to 4 or less",
        severity="2",
        host="10.0.0.1",
        description="MaxAuthTries should be 4 or less.",
        recommendation="Set MaxAuthTries to 4 in sshd_config.",
    )


@pytest.fixture
def sample_triage_decision():
    return TriageDecision(
        finding_id="openscap_001",
        should_remediate=True,
        risk_level="low",
        reason="Safe SSH configuration change.",
    )


@pytest.fixture
def sample_remediation_attempt():
    return RemediationAttempt(
        finding_id="openscap_001",
        attempt_number=1,
        commands_executed=["sed -i 's/^#MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config"],
        scan_passed=True,
        success=True,
    )


@pytest.fixture
def sample_review_verdict():
    return ReviewVerdict(
        finding_id="openscap_001",
        is_optimal=True,
        approve=True,
        feedback="Fix looks correct.",
        security_score=8,
    )


@pytest.fixture
def sample_qa_result():
    return QAResult(
        finding_id="openscap_001",
        safe=True,
        verdict_reason="System is healthy after remediation.",
        recommendation="Approve",
    )


# ── PreApprovalResult ────────────────────────────────────────────────────

class TestPreApprovalResult:
    def test_approved_with_review_and_qa(self, sample_review_verdict, sample_qa_result):
        result = PreApprovalResult(
            review_verdict=sample_review_verdict,
            qa_result=sample_qa_result,
            approved=True,
        )
        assert result.approved is True
        assert result.qa_result is not None
        assert result.qa_result.safe is True
        assert result.rejection_reason is None

    def test_rejected_by_review(self, sample_review_verdict):
        verdict = sample_review_verdict.model_copy(update={"approve": False})
        result = PreApprovalResult(
            review_verdict=verdict,
            qa_result=None,
            approved=False,
            rejection_reason="Fix introduces security risk.",
        )
        assert result.approved is False
        assert result.qa_result is None
        assert result.rejection_reason == "Fix introduces security risk."

    def test_rejected_by_qa(self, sample_review_verdict, sample_qa_result):
        qa = sample_qa_result.model_copy(update={"safe": False, "verdict_reason": "sshd is down"})
        result = PreApprovalResult(
            review_verdict=sample_review_verdict,
            qa_result=qa,
            approved=False,
            rejection_reason="sshd is down",
        )
        assert result.approved is False
        assert result.qa_result is not None
        assert result.qa_result.safe is False


# ── V2FindingResult ──────────────────────────────────────────────────────

class TestV2FindingResult:
    def test_success_finding(
        self,
        sample_vulnerability,
        sample_triage_decision,
        sample_remediation_attempt,
        sample_review_verdict,
        sample_qa_result,
    ):
        approval = PreApprovalResult(
            review_verdict=sample_review_verdict,
            qa_result=sample_qa_result,
            approved=True,
        )
        result = V2FindingResult(
            vulnerability=sample_vulnerability,
            triage=sample_triage_decision,
            remediation=sample_remediation_attempt,
            pre_approval=approval,
            final_status="success",
            total_duration=42.5,
            timestamp="2026-02-21T12:00:00",
        )
        assert result.final_status == "success"
        assert result.remediation is not None
        assert result.pre_approval is not None
        assert result.pre_approval.approved is True

    def test_discarded_finding(self, sample_vulnerability):
        triage = TriageDecision(
            finding_id="openscap_001",
            should_remediate=False,
            risk_level="critical",
            reason="Filesystem change too dangerous.",
        )
        result = V2FindingResult(
            vulnerability=sample_vulnerability,
            triage=triage,
            final_status="discarded",
        )
        assert result.final_status == "discarded"
        assert result.remediation is None
        assert result.pre_approval is None

    def test_failed_finding(
        self,
        sample_vulnerability,
        sample_triage_decision,
    ):
        attempt = RemediationAttempt(
            finding_id="openscap_001",
            attempt_number=3,
            scan_passed=False,
            success=False,
        )
        result = V2FindingResult(
            vulnerability=sample_vulnerability,
            triage=sample_triage_decision,
            remediation=attempt,
            final_status="failed",
        )
        assert result.final_status == "failed"


# ── V2AggregatedReport ──────────────────────────────────────────────────

class TestV2AggregatedReport:
    def test_empty_report(self):
        report = V2AggregatedReport(
            findings_processed=0,
            findings_remediated=0,
            findings_failed=0,
            findings_discarded=0,
            success_rate=0.0,
        )
        assert report.findings_processed == 0
        assert len(report.results) == 0

    def test_report_with_results(
        self,
        sample_vulnerability,
        sample_triage_decision,
        sample_remediation_attempt,
        sample_review_verdict,
        sample_qa_result,
    ):
        approval = PreApprovalResult(
            review_verdict=sample_review_verdict,
            qa_result=sample_qa_result,
            approved=True,
        )
        finding = V2FindingResult(
            vulnerability=sample_vulnerability,
            triage=sample_triage_decision,
            remediation=sample_remediation_attempt,
            pre_approval=approval,
            final_status="success",
        )
        report = V2AggregatedReport(
            findings_processed=1,
            findings_remediated=1,
            findings_failed=0,
            findings_discarded=0,
            results=[finding],
            success_rate=1.0,
        )
        assert report.findings_processed == 1
        assert report.success_rate == 1.0
        assert len(report.results) == 1
