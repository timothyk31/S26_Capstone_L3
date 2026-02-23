"""Unit tests for RemedyAgentV2 (Remedy → Review+QA → scan)."""

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
        id="openscap_020",
        title="Ensure auditd is enabled",
        severity="3",
        host="10.0.0.1",
    )


@pytest.fixture
def triage_decision():
    return TriageDecision(
        finding_id="openscap_020",
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
def successful_attempt():
    return RemediationAttempt(
        finding_id="openscap_020",
        attempt_number=1,
        commands_executed=["systemctl enable auditd", "systemctl start auditd"],
        scan_passed=False,  # Scan not run yet at this point
        success=False,
    )


@pytest.fixture
def mock_remedy_agent(successful_attempt):
    agent = MagicMock()
    agent.process.return_value = successful_attempt
    agent._tool_scan.return_value = {"pass": True, "summary": "Rule passed"}
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
        """Fix generated → approved → scan passes → success."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="openscap_020",
                is_optimal=True,
                approve=True,
                security_score=9,
            ),
            qa_result=QAResult(
                finding_id="openscap_020",
                safe=True,
                verdict_reason="OK",
                recommendation="Approve",
            ),
            approved=True,
        )
        mock_remedy_agent._tool_scan.return_value = {
            "pass": True,
            "summary": "openscap_020: pass",
        }

        attempt, approval = agent.process(remedy_input)

        assert approval is not None
        assert approval.approved is True
        assert attempt.scan_passed is True
        assert attempt.success is True
        mock_remedy_agent.process.assert_called_once()
        mock_review_v2.process.assert_called_once()
        mock_remedy_agent._tool_scan.assert_called_once()

    def test_approval_rejected_no_scan(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Fix generated → rejected → NO scan should run."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="openscap_020",
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
        assert attempt.scan_passed is False
        assert attempt.success is False
        mock_remedy_agent._tool_scan.assert_not_called()

    def test_approved_but_scan_fails(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Fix generated → approved → scan FAILS → success=False."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="openscap_020",
                is_optimal=True,
                approve=True,
                security_score=8,
            ),
            qa_result=QAResult(
                finding_id="openscap_020",
                safe=True,
                verdict_reason="OK",
                recommendation="Approve",
            ),
            approved=True,
        )
        mock_remedy_agent._tool_scan.return_value = {
            "pass": False,
            "summary": "openscap_020: fail",
        }

        attempt, approval = agent.process(remedy_input)

        assert approval.approved is True
        assert attempt.scan_passed is False
        assert attempt.success is False

    def test_remedy_generation_error(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Remedy agent crashes → return error attempt, no approval."""
        mock_remedy_agent.process.side_effect = RuntimeError("LLM connection error")

        attempt, approval = agent.process(remedy_input)

        assert approval is None
        assert attempt.error_summary == "LLM connection error"
        assert attempt.success is False
        mock_review_v2.process.assert_not_called()
        mock_remedy_agent._tool_scan.assert_not_called()

    def test_review_input_constructed_correctly(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Verify ReviewInput is built with correct vulnerability and attempt."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="openscap_020",
                is_optimal=True,
                approve=True,
                security_score=9,
            ),
            approved=True,
        )
        mock_remedy_agent._tool_scan.return_value = {"pass": True, "summary": "pass"}

        agent.process(remedy_input)

        review_call_args = mock_review_v2.process.call_args[0][0]
        assert review_call_args.vulnerability.id == "openscap_020"
        assert review_call_args.remediation_attempt.finding_id == "openscap_020"
        assert review_call_args.triage_decision.finding_id == "openscap_020"

    def test_duration_is_recorded(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Verify duration is set on the returned attempt."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="openscap_020",
                is_optimal=True,
                approve=True,
                security_score=9,
            ),
            approved=True,
        )
        mock_remedy_agent._tool_scan.return_value = {"pass": True, "summary": "pass"}

        attempt, _ = agent.process(remedy_input)

        assert attempt.duration > 0
