"""Unit tests for QAAgentV2 (LLM-only expert opinion, no tools)."""

import json
import pytest
from unittest.mock import MagicMock, patch

from agents.qa_agent_v2 import QAAgentV2, _build_qa_prompt, _parse_qa_result
from schemas import (
    QAInput,
    QAResult,
    RemediationAttempt,
    ReviewVerdict,
    RunCommandResult,
    ToolVerdict,
    Vulnerability,
)


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def vulnerability():
    return Vulnerability(
        id="openscap_040",
        title="Ensure firewalld is enabled",
        severity="2",
        host="10.0.0.1",
        description="The firewalld service must be enabled.",
        recommendation="Run systemctl enable firewalld.",
    )


@pytest.fixture
def remediation_attempt():
    return RemediationAttempt(
        finding_id="openscap_040",
        attempt_number=1,
        commands_executed=["systemctl enable firewalld", "systemctl start firewalld"],
        files_modified=[],
        files_read=[],
        execution_details=[
            RunCommandResult(
                command="systemctl enable firewalld",
                stdout="Created symlink...",
                stderr="",
                exit_code=0,
                success=True,
                duration=0.5,
            ),
        ],
        scan_passed=False,
        success=False,
    )


@pytest.fixture
def review_verdict():
    return ReviewVerdict(
        finding_id="openscap_040",
        is_optimal=True,
        approve=True,
        feedback="Correct approach.",
        security_score=9,
    )


@pytest.fixture
def qa_input(vulnerability, remediation_attempt, review_verdict):
    return QAInput(
        vulnerability=vulnerability,
        remediation_attempt=remediation_attempt,
        review_verdict=review_verdict,
    )


# ── _parse_qa_result ─────────────────────────────────────────────────────

class TestParseQAResult:
    def test_valid_json(self):
        raw = json.dumps({
            "finding_id": "openscap_040",
            "safe": True,
            "verdict_reason": "Fix is correct and safe.",
            "side_effects": [],
            "services_affected": ["firewalld"],
            "recommendation": "Approve",
        })
        result = _parse_qa_result(raw, "openscap_040")
        assert result.safe is True
        assert result.recommendation == "Approve"
        assert result.services_affected == ["firewalld"]

    def test_json_wrapped_in_markdown(self):
        raw = '```json\n{"finding_id": "x", "safe": true, "verdict_reason": "ok", "side_effects": [], "services_affected": [], "recommendation": "Approve"}\n```'
        result = _parse_qa_result(raw, "x")
        assert result.safe is True

    def test_invalid_json_returns_unsafe(self):
        raw = "This is not JSON at all"
        result = _parse_qa_result(raw, "test_id")
        assert result.safe is False
        assert "not valid JSON" in result.verdict_reason

    def test_missing_fields_use_defaults(self):
        raw = json.dumps({"safe": True})
        result = _parse_qa_result(raw, "fallback_id")
        assert result.safe is True
        assert result.finding_id == "fallback_id"
        assert result.side_effects == []

    def test_non_list_side_effects_ignored(self):
        raw = json.dumps({
            "finding_id": "x",
            "safe": True,
            "verdict_reason": "ok",
            "side_effects": "not a list",
            "services_affected": [],
            "recommendation": "Approve",
        })
        result = _parse_qa_result(raw, "x")
        assert result.side_effects == []


# ── _build_qa_prompt ─────────────────────────────────────────────────────

class TestBuildQAPrompt:
    def test_contains_vulnerability_info(self, qa_input):
        prompt = _build_qa_prompt(qa_input)
        assert "openscap_040" in prompt
        assert "firewalld" in prompt
        assert "Ensure firewalld is enabled" in prompt

    def test_contains_remediation_commands(self, qa_input):
        prompt = _build_qa_prompt(qa_input)
        assert "systemctl enable firewalld" in prompt

    def test_contains_review_info(self, qa_input):
        prompt = _build_qa_prompt(qa_input)
        assert "Approved: True" in prompt
        assert "Correct approach" in prompt

    def test_contains_execution_details(self, qa_input):
        prompt = _build_qa_prompt(qa_input)
        assert "exit_code=0" in prompt

    def test_includes_error_summary_when_present(self, vulnerability, review_verdict):
        attempt = RemediationAttempt(
            finding_id="openscap_040",
            attempt_number=1,
            commands_executed=["systemctl enable firewalld"],
            error_summary="Permission denied on config write",
        )
        qa_input = QAInput(
            vulnerability=vulnerability,
            remediation_attempt=attempt,
            review_verdict=review_verdict,
        )
        prompt = _build_qa_prompt(qa_input)
        assert "Permission denied" in prompt

    def test_includes_llm_verdict_when_present(self, vulnerability, review_verdict):
        attempt = RemediationAttempt(
            finding_id="openscap_040",
            attempt_number=1,
            commands_executed=["systemctl enable firewalld"],
            llm_verdict=ToolVerdict(message="Fix applied successfully", resolved=True),
        )
        qa_input = QAInput(
            vulnerability=vulnerability,
            remediation_attempt=attempt,
            review_verdict=review_verdict,
        )
        prompt = _build_qa_prompt(qa_input)
        assert "Fix applied successfully" in prompt


# ── QAAgentV2.process ────────────────────────────────────────────────────

class TestQAAgentV2Process:
    @patch("agents.qa_agent_v2._call_llm")
    def test_process_returns_qa_result(self, mock_llm, qa_input):
        mock_llm.return_value = json.dumps({
            "finding_id": "openscap_040",
            "safe": True,
            "verdict_reason": "Service enablement is safe.",
            "side_effects": [],
            "services_affected": ["firewalld"],
            "recommendation": "Approve",
        })
        agent = QAAgentV2(api_key="test", base_url="http://fake", model="test-model")
        result = agent.process(qa_input)

        assert isinstance(result, QAResult)
        assert result.safe is True
        assert result.validation_duration > 0
        mock_llm.assert_called_once()

    @patch("agents.qa_agent_v2._call_llm")
    def test_process_unsafe_verdict(self, mock_llm, qa_input):
        mock_llm.return_value = json.dumps({
            "finding_id": "openscap_040",
            "safe": False,
            "verdict_reason": "This could disable network access.",
            "side_effects": ["network disruption"],
            "services_affected": ["firewalld", "NetworkManager"],
            "recommendation": "Rollback",
        })
        agent = QAAgentV2(api_key="test", base_url="http://fake", model="test-model")
        result = agent.process(qa_input)

        assert result.safe is False
        assert "network" in result.verdict_reason.lower()
        assert result.recommendation == "Rollback"

    @patch("agents.qa_agent_v2._call_llm")
    def test_process_llm_returns_garbage(self, mock_llm, qa_input):
        mock_llm.return_value = "I don't understand the question."
        agent = QAAgentV2(api_key="test", base_url="http://fake", model="test-model")
        result = agent.process(qa_input)

        assert result.safe is False
        assert "not valid JSON" in result.verdict_reason
