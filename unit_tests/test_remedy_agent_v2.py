"""Unit tests for RemedyAgentV2 (Plan → Review+QA → Apply)."""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from agents.remedy_agent_v2 import RemedyAgentV2
from schemas import (
    PreApprovalResult,
    QAResult,
    RemedyInput,
    RemediationAttempt,
    ReviewVerdict,
    TriageDecision,
    ToolVerdict,
    Vulnerability,
)


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def vulnerability():
    return Vulnerability(
        id="auditd_audispd_syslog_plugin_activated",
        title="Ensure auditd is enabled",
        severity="3",
        host="10.0.0.1",
    )


@pytest.fixture
def triage_decision():
    return TriageDecision(
        finding_id="auditd_audispd_syslog_plugin_activated",
        should_remediate=True,
        risk_level="low",
        reason="Service enablement is safe.",
    )


@pytest.fixture
def remedy_input(vulnerability, triage_decision):
    return RemedyInput(
        vulnerability=vulnerability,
        triage_decision=triage_decision,
        attempt_number=1,
    )


@pytest.fixture
def mock_remedy_agent():
    agent = MagicMock()
    agent.plan_fix.return_value = "Enable and start auditd service via systemctl."
    # process() no longer runs scan — always returns scan_passed=False
    agent.process.return_value = RemediationAttempt(
        finding_id="auditd_audispd_syslog_plugin_activated",
        attempt_number=1,
        commands_executed=["systemctl enable auditd", "systemctl start auditd"],
        scan_passed=False,
        success=False,
    )
    return agent


@pytest.fixture
def mock_review_v2():
    return MagicMock()


@pytest.fixture
def agent(mock_remedy_agent, mock_review_v2):
    return RemedyAgentV2(
        remedy_agent=mock_remedy_agent,
        review_agent_v2=mock_review_v2,
    )


# ── Tests ─────────────────────────────────────────────────────────────────

class TestRemedyAgentV2:
    def test_full_success_path(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Plan → approved → process succeeds (no scan in process)."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="auditd_audispd_syslog_plugin_activated",
                is_optimal=True,
                approve=True,
                security_score=9,
            ),
            qa_result=QAResult(
                finding_id="auditd_audispd_syslog_plugin_activated",
                safe=True,
                verdict_reason="OK",
                recommendation="Approve",
            ),
            approved=True,
        )

        attempt, approval = agent.process(remedy_input)

        assert approval is not None
        assert approval.approved is True
        # scan_passed is always False now (batch-then-verify sets it later)
        assert attempt.scan_passed is False
        assert attempt.success is False
        mock_remedy_agent.plan_fix.assert_called_once()
        mock_remedy_agent.process.assert_called_once()
        mock_review_v2.process.assert_called_once()
        # Verify plan_text was passed through to process
        call_args = mock_remedy_agent.process.call_args[0][0]
        assert call_args.plan_text == "Enable and start auditd service via systemctl."

    def test_approval_rejected_injects_feedback(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Plan → rejected → feedback injected into process call."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="auditd_audispd_syslog_plugin_activated",
                is_optimal=False,
                approve=False,
                feedback="Fix is harmful.",
            ),
            approved=False,
            rejection_reason="Fix is harmful.",
        )

        attempt, approval = agent.process(remedy_input)

        assert approval is not None
        assert approval.approved is False
        # process() still runs even when rejected (with feedback injected)
        mock_remedy_agent.process.assert_called_once()
        call_args = mock_remedy_agent.process.call_args[0][0]
        assert call_args.review_feedback is not None
        assert "REJECTED" in call_args.review_feedback
        assert call_args.plan_text is not None

    def test_plan_generation_error(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """plan_fix crashes → return error attempt, no approval."""
        mock_remedy_agent.plan_fix.side_effect = RuntimeError("LLM connection error")

        attempt, approval = agent.process(remedy_input)

        assert approval is None
        assert attempt.error_summary == "LLM connection error"
        assert attempt.success is False
        mock_review_v2.process.assert_not_called()
        mock_remedy_agent.process.assert_not_called()

    def test_remedy_execution_error(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Plan + approval succeed but process() crashes → error attempt."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="auditd_audispd_syslog_plugin_activated",
                is_optimal=True,
                approve=True,
                security_score=9,
            ),
            approved=True,
        )
        mock_remedy_agent.process.side_effect = RuntimeError("SSH timeout")

        attempt, approval = agent.process(remedy_input)

        assert approval is not None
        assert attempt.error_summary == "SSH timeout"
        assert attempt.success is False

    def test_review_input_constructed_correctly(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Verify ReviewInput is built with correct vulnerability and plan."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="auditd_audispd_syslog_plugin_activated",
                is_optimal=True,
                approve=True,
                security_score=9,
            ),
            approved=True,
        )

        agent.process(remedy_input)

        review_call_args = mock_review_v2.process.call_args[0][0]
        assert review_call_args.vulnerability.id == "auditd_audispd_syslog_plugin_activated"
        assert review_call_args.remediation_attempt.finding_id == "auditd_audispd_syslog_plugin_activated"
        assert review_call_args.triage_decision.finding_id == "auditd_audispd_syslog_plugin_activated"
        # Plan text should be in the stub attempt's llm_verdict
        assert "auditd" in review_call_args.remediation_attempt.llm_verdict.message

    def test_duration_is_recorded(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Verify duration is set on the returned attempt."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="auditd_audispd_syslog_plugin_activated",
                is_optimal=True,
                approve=True,
                security_score=9,
            ),
            approved=True,
        )

        attempt, _ = agent.process(remedy_input)

        assert attempt.attempt_duration > 0

    def test_step_durations_recorded(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Verify per-step durations are recorded in llm_metrics."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="auditd_audispd_syslog_plugin_activated",
                is_optimal=True,
                approve=True,
                security_score=9,
            ),
            approved=True,
        )

        attempt, _ = agent.process(remedy_input)

        assert attempt.llm_metrics is not None
        assert "step_durations" in attempt.llm_metrics
        steps = attempt.llm_metrics["step_durations"]
        assert "plan_fix_seconds" in steps
        assert "review_qa_seconds" in steps
        assert "apply_fix_seconds" in steps
        assert all(isinstance(v, float) for v in steps.values())

    def test_step_durations_on_plan_error(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """plan_fix crashes → step_durations still has plan_fix_seconds."""
        mock_remedy_agent.plan_fix.side_effect = RuntimeError("LLM down")

        attempt, approval = agent.process(remedy_input)

        assert approval is None
        assert attempt.llm_metrics is not None
        assert "plan_fix_seconds" in attempt.llm_metrics["step_durations"]
