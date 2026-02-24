"""Unit tests for PipelineV2 (Triage → Remedy+Approval loop → Aggregation)."""

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
        id="openscap_030",
        title="Set SSH Idle Timeout Interval",
        severity="2",
        host="10.0.0.1",
        description="Set ClientAliveInterval to 600.",
    )


@pytest.fixture
def mock_triage_agent():
    agent = MagicMock()
    agent.process.return_value = TriageDecision(
        finding_id="openscap_030",
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
        max_remedy_attempts=3,
    )


def _make_approval(approved=True, safe=True):
    """Helper to build a PreApprovalResult."""
    return PreApprovalResult(
        review_verdict=ReviewVerdict(
            finding_id="openscap_030",
            is_optimal=True,
            approve=approved,
            security_score=8,
        ),
        qa_result=QAResult(
            finding_id="openscap_030",
            safe=safe,
            verdict_reason="OK" if safe else "Critical service down",
            recommendation="Approve" if safe else "Rollback",
        ) if approved else None,
        approved=approved and safe,
        rejection_reason=None if (approved and safe) else "Rejected",
    )


def _make_attempt(scan_passed=True, attempt_number=1):
    """Helper to build a RemediationAttempt."""
    return RemediationAttempt(
        finding_id="openscap_030",
        attempt_number=attempt_number,
        commands_executed=["sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config"],
        scan_passed=scan_passed,
        success=scan_passed,
    )


# ── Tests ─────────────────────────────────────────────────────────────────

class TestPipelineV2:

    def test_full_success_first_attempt(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Triage approves → Remedy+Approval succeeds on first try → success."""
        mock_remedy_v2.process.return_value = (
            _make_attempt(scan_passed=True),
            _make_approval(approved=True, safe=True),
        )

        result = pipeline.run(vulnerability)

        assert isinstance(result, V2FindingResult)
        assert result.final_status == "success"
        assert result.remediation is not None
        assert result.remediation.scan_passed is True
        assert result.pre_approval is not None
        assert result.pre_approval.approved is True
        mock_triage_agent.process.assert_called_once()
        mock_remedy_v2.process.assert_called_once()

    def test_triage_discards(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Triage rejects (too dangerous) → no remedy → discarded."""
        mock_triage_agent.process.return_value = TriageDecision(
            finding_id="openscap_030",
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
            finding_id="openscap_030",
            should_remediate=False,
            risk_level="medium",
            reason="Needs human review.",
            requires_human_review=True,
        )

        result = pipeline.run(vulnerability)

        assert result.final_status == "requires_human_review"
        mock_remedy_v2.process.assert_not_called()

    def test_retry_on_scan_failure(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Scan fails on attempt 1, succeeds on attempt 2."""
        mock_remedy_v2.process.side_effect = [
            # Attempt 1: approved but scan fails
            (
                _make_attempt(scan_passed=False, attempt_number=1),
                _make_approval(approved=True, safe=True),
            ),
            # Attempt 2: approved and scan passes
            (
                _make_attempt(scan_passed=True, attempt_number=2),
                _make_approval(approved=True, safe=True),
            ),
        ]

        result = pipeline.run(vulnerability)

        assert result.final_status == "success"
        assert mock_remedy_v2.process.call_count == 2

    def test_retry_on_approval_rejection(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Review rejects attempt 1, approves attempt 2."""
        mock_remedy_v2.process.side_effect = [
            # Attempt 1: rejected
            (
                _make_attempt(scan_passed=False, attempt_number=1),
                _make_approval(approved=False),
            ),
            # Attempt 2: approved + scan passes
            (
                _make_attempt(scan_passed=True, attempt_number=2),
                _make_approval(approved=True, safe=True),
            ),
        ]

        result = pipeline.run(vulnerability)

        assert result.final_status == "success"
        assert mock_remedy_v2.process.call_count == 2

    def test_all_attempts_exhausted(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """All 3 attempts fail → final_status = failed."""
        mock_remedy_v2.process.return_value = (
            _make_attempt(scan_passed=False),
            _make_approval(approved=True, safe=True),
        )

        result = pipeline.run(vulnerability)

        assert result.final_status == "failed"
        assert mock_remedy_v2.process.call_count == 3

    def test_triage_error_fallback(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Triage raises exception → defaults to human review."""
        mock_triage_agent.process.side_effect = RuntimeError("API down")

        result = pipeline.run(vulnerability)

        assert result.final_status == "requires_human_review"
        mock_remedy_v2.process.assert_not_called()

    def test_remedy_error_on_generation(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """RemedyAgentV2 returns error attempt (no approval) on all tries."""
        error_attempt = RemediationAttempt(
            finding_id="openscap_030",
            attempt_number=1,
            error_summary="LLM crashed",
            scan_passed=False,
            success=False,
        )
        mock_remedy_v2.process.return_value = (error_attempt, None)

        result = pipeline.run(vulnerability)

        assert result.final_status == "failed"
        assert mock_remedy_v2.process.call_count == 3

    def test_previous_attempts_passed_to_retry(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Verify previous_attempts list grows on each retry."""
        call_count = 0

        def track_calls(input_data):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return (
                    _make_attempt(scan_passed=False, attempt_number=call_count),
                    _make_approval(approved=True, safe=True),
                )
            return (
                _make_attempt(scan_passed=True, attempt_number=call_count),
                _make_approval(approved=True, safe=True),
            )

        mock_remedy_v2.process.side_effect = track_calls

        result = pipeline.run(vulnerability)

        assert result.final_status == "success"
        # Check that the third call had 2 previous attempts
        third_call_input = mock_remedy_v2.process.call_args_list[2][0][0]
        assert len(third_call_input.previous_attempts) == 2
        assert third_call_input.attempt_number == 3

    def test_review_feedback_passed_on_rejection(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """When approval is rejected, feedback is passed to next attempt."""
        mock_remedy_v2.process.side_effect = [
            (
                _make_attempt(scan_passed=False, attempt_number=1),
                PreApprovalResult(
                    review_verdict=ReviewVerdict(
                        finding_id="openscap_030",
                        is_optimal=False,
                        approve=False,
                        feedback="Use sed instead of echo.",
                        suggested_improvements=["Use in-place sed editing"],
                    ),
                    approved=False,
                    rejection_reason="Use sed instead of echo.",
                ),
            ),
            (
                _make_attempt(scan_passed=True, attempt_number=2),
                _make_approval(approved=True, safe=True),
            ),
        ]

        result = pipeline.run(vulnerability)

        assert result.final_status == "success"
        second_call_input = mock_remedy_v2.process.call_args_list[1][0][0]
        assert "sed" in second_call_input.review_feedback

    def test_result_has_timestamp(
        self, pipeline, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Verify result includes a timestamp."""
        mock_remedy_v2.process.return_value = (
            _make_attempt(scan_passed=True),
            _make_approval(approved=True, safe=True),
        )

        result = pipeline.run(vulnerability)

        assert result.timestamp != ""
        assert result.total_duration > 0

    def test_max_remedy_attempts_respected(
        self, mock_triage_agent, mock_remedy_v2, vulnerability
    ):
        """Pipeline with max_remedy_attempts=1 only tries once."""
        p = PipelineV2(
            triage_agent=mock_triage_agent,
            remedy_agent_v2=mock_remedy_v2,
            max_remedy_attempts=1,
        )
        mock_remedy_v2.process.return_value = (
            _make_attempt(scan_passed=False),
            _make_approval(approved=True, safe=True),
        )

        result = p.run(vulnerability)

        assert result.final_status == "failed"
        assert mock_remedy_v2.process.call_count == 1
