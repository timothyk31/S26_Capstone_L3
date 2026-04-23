"""Unit tests for ReviewAgentV2 (Review → QA chain)."""

import pytest
from unittest.mock import MagicMock, patch

from agents.review_agent_v2 import ReviewAgentV2
from schemas import (
    PreApprovalResult,
    QAInput,
    QAResult,
    RemediationAttempt,
    ReviewInput,
    ReviewVerdict,
    TriageDecision,
    Vulnerability,
)


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def vulnerability():
    return Vulnerability(
        id="openscap_010",
        title="Set Password Minimum Length",
        severity="2",
        host="10.0.0.1",
    )


@pytest.fixture
def triage_decision():
    return TriageDecision(
        finding_id="openscap_010",
        should_remediate=True,
        risk_level="low",
        reason="Password policy change is safe.",
    )


@pytest.fixture
def remediation_attempt():
    return RemediationAttempt(
        finding_id="openscap_010",
        attempt_number=1,
        commands_executed=["sed -i 's/^# minlen.*/minlen = 15/' /etc/security/pwquality.conf"],
        scan_passed=True,
        success=True,
    )


@pytest.fixture
def review_input(vulnerability, remediation_attempt, triage_decision):
    return ReviewInput(
        vulnerability=vulnerability,
        remediation_attempt=remediation_attempt,
        triage_decision=triage_decision,
    )


@pytest.fixture
def mock_review_agent():
    return MagicMock()


@pytest.fixture
def mock_qa_agent():
    return MagicMock()


@pytest.fixture
def agent(mock_review_agent, mock_qa_agent):
    return ReviewAgentV2(
        review_agent=mock_review_agent,
        qa_agent=mock_qa_agent,
    )


# ── Tests ─────────────────────────────────────────────────────────────────

class TestReviewAgentV2:
    def test_both_approve(self, agent, mock_review_agent, mock_qa_agent, review_input):
        """Review approves → QA runs and approves → approved=True."""
        mock_review_agent.process.return_value = ReviewVerdict(
            finding_id="openscap_010",
            is_optimal=True,
            approve=True,
            feedback="Looks good.",
            security_score=9,
        )
        mock_qa_agent.process.return_value = QAResult(
            finding_id="openscap_010",
            safe=True,
            verdict_reason="System healthy.",
            recommendation="Approve",
        )

        result = agent.process(review_input)

        assert isinstance(result, PreApprovalResult)
        assert result.approved is True
        assert result.review_verdict.approve is True
        assert result.qa_result is not None
        assert result.qa_result.safe is True
        assert result.rejection_reason is None
        mock_review_agent.process.assert_called_once()
        mock_qa_agent.process.assert_called_once()

    def test_review_rejects_qa_not_called(
        self, agent, mock_review_agent, mock_qa_agent, review_input
    ):
        """Review rejects → QA should NOT be called → approved=False."""
        mock_review_agent.process.return_value = ReviewVerdict(
            finding_id="openscap_010",
            is_optimal=False,
            approve=False,
            feedback="Fix introduces a duplicate config line.",
            security_score=3,
        )

        result = agent.process(review_input)

        assert result.approved is False
        assert result.qa_result is None
        assert "duplicate" in result.rejection_reason
        mock_qa_agent.process.assert_not_called()

    def test_review_approves_qa_rejects(
        self, agent, mock_review_agent, mock_qa_agent, review_input
    ):
        """Review approves → QA rejects → approved=False."""
        mock_review_agent.process.return_value = ReviewVerdict(
            finding_id="openscap_010",
            is_optimal=True,
            approve=True,
            security_score=8,
        )
        mock_qa_agent.process.return_value = QAResult(
            finding_id="openscap_010",
            safe=False,
            verdict_reason="sshd service is not running.",
            recommendation="Rollback",
        )

        result = agent.process(review_input)

        assert result.approved is False
        assert result.qa_result is not None
        assert result.qa_result.safe is False
        assert "sshd" in result.rejection_reason

    def test_review_error_auto_approves_then_qa_runs(
        self, agent, mock_review_agent, mock_qa_agent, review_input
    ):
        """Review raises exception → auto-approved → QA still runs."""
        mock_review_agent.process.side_effect = RuntimeError("LLM API timeout")
        mock_qa_agent.process.return_value = QAResult(
            finding_id="openscap_010",
            safe=True,
            verdict_reason="All services up.",
            recommendation="Approve",
        )

        result = agent.process(review_input)

        assert result.approved is True
        assert "auto-approving" in result.review_verdict.feedback
        mock_qa_agent.process.assert_called_once()

    def test_qa_error_returns_not_approved(
        self, agent, mock_review_agent, mock_qa_agent, review_input
    ):
        """Review approves → QA raises exception → approved=False."""
        mock_review_agent.process.return_value = ReviewVerdict(
            finding_id="openscap_010",
            is_optimal=True,
            approve=True,
            security_score=8,
        )
        mock_qa_agent.process.side_effect = RuntimeError("SSH connection lost")

        result = agent.process(review_input)

        assert result.approved is False
        assert result.qa_result is None
        assert "QA validation error" in result.rejection_reason

    def test_qa_receives_correct_input(
        self, agent, mock_review_agent, mock_qa_agent, review_input
    ):
        """Verify the QA agent receives properly constructed QAInput."""
        review_verdict = ReviewVerdict(
            finding_id="openscap_010",
            is_optimal=True,
            approve=True,
            security_score=9,
        )
        mock_review_agent.process.return_value = review_verdict
        mock_qa_agent.process.return_value = QAResult(
            finding_id="openscap_010",
            safe=True,
            verdict_reason="OK",
            recommendation="Approve",
        )

        agent.process(review_input)

        qa_call_args = mock_qa_agent.process.call_args[0][0]
        assert isinstance(qa_call_args, QAInput)
        assert qa_call_args.vulnerability.id == "openscap_010"
        assert qa_call_args.remediation_attempt.finding_id == "openscap_010"
        assert qa_call_args.review_verdict.approve is True
