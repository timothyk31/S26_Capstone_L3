"""Unit tests for PipelineV2 (single-pass: Triage → Remedy+Approval → pending_scan)."""

import pytest
from unittest.mock import MagicMock, patch

from workflow.pipeline_v2 import PipelineV2
from schemas import (
    PreApprovalResult,
    QAResult,
    RemediationAttempt,
    ReviewVerdict,
    TriageDecision,
    V2FindingResult,
    Vulnerability,
)


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def vulnerability():
    return Vulnerability(
        id="sshd_set_idle_timeout",
        title="Set SSH Idle Timeout Interval",
        severity="2",
        host="10.0.0.1",
        description="Set ClientAliveInterval to 600.",
    )


@pytest.fixture
def mock_triage_agent():
    agent = MagicMock()
    agent.process.return_value = TriageDecision(
        finding_id="sshd_set_idle_timeout",
        should_remediate=True,
        risk_level="low",
        reason="Safe SSH config change.",
    )
    return agent


@pytest.fixture
def mock_remedy_v2():
    return MagicMock()


@pytest.fixture
def pipeline(mock_triage_agent, mock_remedy_v2):
    return PipelineV2(
        triage_agent=mock_triage_agent,
        remedy_agent_v2=mock_remedy_v2,
    )


def _make_approval(approved=True, safe=True):
    """Helper to build a PreApprovalResult."""
    return PreApprovalResult(
        review_verdict=ReviewVerdict(
            finding_id="sshd_set_idle_timeout",
            is_optimal=True,
            approve=approved,
            security_score=8,
        ),
        qa_result=QAResult(
            finding_id="sshd_set_idle_timeout",
            safe=safe,
            verdict_reason="OK" if safe else "Critical service down",
            recommendation="Approve" if safe else "Rollback",
        ) if approved else None,
        approved=approved and safe,
        rejection_reason=None if (approved and safe) else "Rejected",
    )


def _make_attempt(attempt_number=1):
    """Helper to build a RemediationAttempt (no scan — batch-then-verify)."""
    return RemediationAttempt(
        finding_id="sshd_set_idle_timeout",
        attempt_number=attempt_number,
        commands_executed=["sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config"],
        scan_passed=False,
        success=False,
    )


# ── Tests ─────────────────────────────────────────────────────────────────

class TestPipelineV2:

    def test_single_attempt_returns_pending_scan(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Triage approves → Remedy runs → returns pending_scan (no scan in pipeline)."""
        mock_remedy_v2.process.return_value = (
            _make_attempt(),
            _make_approval(approved=True, safe=True),
        )

        result = pipeline.run(vulnerability)

        assert isinstance(result, V2FindingResult)
        assert result.final_status == "pending_scan"
        assert result.remediation is not None
        assert result.remediation.scan_passed is False  # scan not run yet
        assert result.pre_approval is not None
        assert result.pre_approval.approved is True
        mock_triage_agent.process.assert_called_once()
        mock_remedy_v2.process.assert_called_once()

    def test_triage_discards(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Triage rejects (too dangerous) → no remedy → discarded."""
        mock_triage_agent.process.return_value = TriageDecision(
            finding_id="sshd_set_idle_timeout",
            should_remediate=False,
            risk_level="critical",
            reason="Filesystem partitioning change.",
        )

        result = pipeline.run(vulnerability)

        assert result.final_status == "discarded"
        assert result.remediation is None
        assert result.pre_approval is None
        mock_remedy_v2.process.assert_not_called()

    def test_triage_human_review(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Triage flags for human review → no remedy → requires_human_review."""
        mock_triage_agent.process.return_value = TriageDecision(
            finding_id="sshd_set_idle_timeout",
            should_remediate=False,
            risk_level="medium",
            reason="Needs human review.",
            requires_human_review=True,
        )

        result = pipeline.run(vulnerability)

        assert result.final_status == "requires_human_review"
        mock_remedy_v2.process.assert_not_called()

    def test_triage_error_fallback(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Triage raises exception → defaults to human review."""
        mock_triage_agent.process.side_effect = RuntimeError("API down")

        result = pipeline.run(vulnerability)

        assert result.final_status == "requires_human_review"
        mock_remedy_v2.process.assert_not_called()

    def test_result_has_timestamp(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Verify result includes a timestamp."""
        mock_remedy_v2.process.return_value = (
            _make_attempt(),
            _make_approval(approved=True, safe=True),
        )

        result = pipeline.run(vulnerability)

        assert result.timestamp != ""
        assert result.total_duration > 0

    def test_run_with_triage_decision_skips_triage(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """When triage_decision is provided, triage agent is NOT called."""
        pre_triage = TriageDecision(
            finding_id="sshd_set_idle_timeout",
            should_remediate=True,
            risk_level="low",
            reason="Already triaged.",
        )
        mock_remedy_v2.process.return_value = (
            _make_attempt(),
            _make_approval(approved=True, safe=True),
        )

        result = pipeline.run(vulnerability, triage_decision=pre_triage)

        assert result.final_status == "pending_scan"
        mock_triage_agent.process.assert_not_called()
        mock_remedy_v2.process.assert_called_once()

    def test_run_accepts_retry_context(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Retry params (previous_attempts, review_feedback, etc.) are forwarded."""
        pre_triage = TriageDecision(
            finding_id="sshd_set_idle_timeout",
            should_remediate=True,
            risk_level="low",
            reason="Already triaged.",
        )
        prev_attempt = RemediationAttempt(
            finding_id="sshd_set_idle_timeout",
            attempt_number=1,
            commands_executed=["echo test"],
        )
        prev_verdict = ReviewVerdict(
            finding_id="sshd_set_idle_timeout",
            is_optimal=False,
            approve=False,
            feedback="Try a different approach.",
        )
        mock_remedy_v2.process.return_value = (
            _make_attempt(attempt_number=2),
            _make_approval(approved=True, safe=True),
        )

        result = pipeline.run(
            vulnerability,
            triage_decision=pre_triage,
            attempt_number=2,
            previous_attempts=[prev_attempt],
            review_feedback="Scan failed, try again.",
            previous_review_verdicts=[prev_verdict],
        )

        assert result.final_status == "pending_scan"
        # Verify the RemedyInput was constructed with retry context
        call_args = mock_remedy_v2.process.call_args[0][0]
        assert call_args.attempt_number == 2
        assert len(call_args.previous_attempts) == 1
        assert call_args.review_feedback == "Scan failed, try again."
        assert len(call_args.previous_review_verdicts) == 1

    def test_remedy_error_returns_pending_scan(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """RemedyAgentV2 returns error attempt → still returns pending_scan."""
        error_attempt = RemediationAttempt(
            finding_id="sshd_set_idle_timeout",
            attempt_number=1,
            error_summary="LLM crashed",
            scan_passed=False,
            success=False,
        )
        mock_remedy_v2.process.return_value = (error_attempt, None)

        result = pipeline.run(vulnerability)

        assert result.final_status == "pending_scan"
        assert result.remediation.error_summary == "LLM crashed"
        mock_remedy_v2.process.assert_called_once()
