"""Unit tests for RemedyAgentV2 (single-session Plan → Review+QA → Apply)."""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

from agents.remedy_agent_v2 import RemedyAgentV2
from schemas import (
    PreApprovalResult,
    QAResult,
    RemedyInput,
    RemediationAttempt,
    ReviewVerdict,
    RunCommandResult,
    TriageDecision,
    ToolVerdict,
    Vulnerability,
)


# ── Helpers ──────────────────────────────────────────────────────────────


def _make_chat_response(content=None, tool_calls=None):
    """Build a mock OpenAI-style chat response dict."""
    msg = {"content": content, "tool_calls": tool_calls}
    return {
        "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        "choices": [{"message": msg}],
    }


def _make_tool_call(call_id, name, arguments):
    return {
        "id": call_id,
        "function": {
            "name": name,
            "arguments": json.dumps(arguments),
        },
    }


def _text_padding(n=5, text=""):
    """Return n text-only responses to satisfy the loop exit guard."""
    return [_make_chat_response(content=text) for _ in range(n)]


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
def mock_remedy_agent(tmp_path):
    agent = MagicMock()
    agent.max_tool_iterations = 20
    agent.work_dir = tmp_path
    agent._build_agent_prompt.return_value = "Fix the auditd finding."
    agent._tools_spec.return_value = [
        {
            "type": "function",
            "function": {
                "name": "run_cmd",
                "description": "Run a command",
                "parameters": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
            },
        },
    ]
    # Default _tool_run_cmd returns a real RunCommandResult
    cmd_result = RunCommandResult(
        command="systemctl enable auditd",
        stdout="",
        stderr="",
        exit_code=0,
        success=True,
        duration=0.5,
    )
    agent._tool_run_cmd.return_value = cmd_result
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
        """Plan text → review_plan approved → run_cmd → final message."""
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

        mock_remedy_agent._chat.side_effect = [
            _make_chat_response(
                content="I will enable auditd.",
                tool_calls=[
                    _make_tool_call("c1", "review_plan", {
                        "plan_description": "Enable auditd via systemctl"
                    })
                ],
            ),
            _make_chat_response(
                tool_calls=[
                    _make_tool_call("c2", "run_cmd", {
                        "command": "systemctl enable auditd"
                    })
                ],
            ),
        ] + _text_padding(5, "Remediation complete.")

        attempt, approval = agent.process(remedy_input)

        assert approval is not None
        assert approval.approved is True
        assert attempt.scan_passed is False
        assert "systemctl enable auditd" in attempt.commands_executed
        assert attempt.llm_verdict.message == "Remediation complete."

    def test_approval_rejected(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """review_plan rejected → LLM ends without executing."""
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

        mock_remedy_agent._chat.side_effect = [
            _make_chat_response(
                tool_calls=[
                    _make_tool_call("c1", "review_plan", {
                        "plan_description": "Bad plan"
                    })
                ],
            ),
        ] + _text_padding(5, "Understood, stopping.")

        attempt, approval = agent.process(remedy_input)

        assert approval is not None
        assert approval.approved is False
        assert attempt.commands_executed == []

    def test_session_error_returns_error_attempt(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """_chat raises → error attempt returned, no approval."""
        mock_remedy_agent._chat.side_effect = RuntimeError("LLM connection error")

        attempt, approval = agent.process(remedy_input)

        assert approval is None
        assert "LLM connection error" in attempt.error_summary
        assert attempt.success is False

    def test_duration_is_recorded(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Verify attempt_duration is set."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="auditd_audispd_syslog_plugin_activated",
                is_optimal=True,
                approve=True,
                security_score=9,
            ),
            approved=True,
        )
        mock_remedy_agent._chat.side_effect = [
            _make_chat_response(
                tool_calls=[
                    _make_tool_call("c1", "review_plan", {
                        "plan_description": "Enable auditd"
                    })
                ],
            ),
        ] + _text_padding(5, "Done.")

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
        mock_remedy_agent._chat.side_effect = [
            _make_chat_response(
                tool_calls=[
                    _make_tool_call("c1", "review_plan", {
                        "plan_description": "Enable auditd"
                    })
                ],
            ),
            _make_chat_response(
                tool_calls=[
                    _make_tool_call("c2", "run_cmd", {
                        "command": "systemctl enable auditd"
                    })
                ],
            ),
        ] + _text_padding(5, "Done.")

        attempt, _ = agent.process(remedy_input)

        assert attempt.llm_metrics is not None
        assert "step_durations" in attempt.llm_metrics
        steps = attempt.llm_metrics["step_durations"]
        assert "plan_fix_seconds" in steps
        assert "review_qa_seconds" in steps
        assert "apply_fix_seconds" in steps
        assert all(isinstance(v, float) for v in steps.values())

    def test_step_durations_no_review(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """No review_plan called → all time in plan_fix, review/apply = 0."""
        mock_remedy_agent._chat.side_effect = _text_padding(5, "Nothing to do.")

        attempt, _ = agent.process(remedy_input)

        assert attempt.llm_metrics is not None
        steps = attempt.llm_metrics["step_durations"]
        assert steps["plan_fix_seconds"] >= 0
        assert steps["review_qa_seconds"] == 0.0
        assert steps["apply_fix_seconds"] == 0.0

    def test_step_durations_on_session_error(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Session error → no llm_metrics (error path)."""
        mock_remedy_agent._chat.side_effect = RuntimeError("LLM down")

        attempt, approval = agent.process(remedy_input)

        assert approval is None
        assert attempt.error_summary is not None

    def test_review_input_constructed_correctly(
        self, agent, mock_remedy_agent, mock_review_v2, remedy_input
    ):
        """Verify ReviewInput passed to review_v2 has correct fields."""
        mock_review_v2.process.return_value = PreApprovalResult(
            review_verdict=ReviewVerdict(
                finding_id="auditd_audispd_syslog_plugin_activated",
                is_optimal=True,
                approve=True,
                security_score=9,
            ),
            approved=True,
        )
        mock_remedy_agent._chat.side_effect = [
            _make_chat_response(
                tool_calls=[
                    _make_tool_call("c1", "review_plan", {
                        "plan_description": "Enable auditd via systemctl"
                    })
                ],
            ),
        ] + _text_padding(5, "Done.")

        agent.process(remedy_input)

        review_call_args = mock_review_v2.process.call_args[0][0]
        assert review_call_args.vulnerability.id == "auditd_audispd_syslog_plugin_activated"
        assert "auditd" in review_call_args.remediation_attempt.llm_verdict.message
