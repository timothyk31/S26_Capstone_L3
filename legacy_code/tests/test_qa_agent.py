"""
Unit tests for QA Agent.
Tests QA Agent in isolation using mocked dependencies.

Run: python -m pytest unit_tests/test_qa_agent.py -v
"""

import os
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from agents.qa_agent import QAAgent
from helpers.command_executor import ShellCommandExecutor
from schemas import (
    QAInput,
    QAResult,
    RemediationAttempt,
    ReviewVerdict,
    RunCommandResult,
    TriageDecision,
    ToolVerdict,
    Vulnerability,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_executor():
    """Mock ShellCommandExecutor."""
    executor = Mock(spec=ShellCommandExecutor)

    # Mock successful command execution
    def mock_run_command(cmd):
        return RunCommandResult(
            command=cmd,
            stdout="Service is running",
            stderr="",
            exit_code=0,
            success=True,
            duration=0.1,
            timed_out=False,
            truncated_stdout=False,
            truncated_stderr=False,
        )

    executor.run_command = Mock(side_effect=mock_run_command)
    return executor


@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability for testing."""
    return Vulnerability(
        id="xccdf_org.ssgproject.content_rule_test_001",
        title="Ensure Test Service is Configured",
        severity="medium",
        host="192.168.1.10",
        description="Test vulnerability for QA agent",
        recommendation="Configure test service properly",
    )


@pytest.fixture
def sample_remediation_attempt():
    """Sample remediation attempt."""
    return RemediationAttempt(
        finding_id="xccdf_org.ssgproject.content_rule_test_001",
        attempt_number=1,
        commands_executed=["systemctl enable test-service", "systemctl start test-service"],
        files_modified=[],
        files_read=[],
        execution_details=[
            RunCommandResult(
                command="systemctl enable test-service",
                stdout="Created symlink...",
                stderr="",
                exit_code=0,
                success=True,
                duration=0.2,
            ),
            RunCommandResult(
                command="systemctl start test-service",
                stdout="",
                stderr="",
                exit_code=0,
                success=True,
                duration=0.3,
            ),
        ],
        scan_passed=True,
        success=True,
        duration=1.5,
        llm_verdict=ToolVerdict(message="Service configured successfully", resolved=True),
    )


@pytest.fixture
def sample_review_verdict():
    """Sample review verdict."""
    return ReviewVerdict(
        finding_id="xccdf_org.ssgproject.content_rule_test_001",
        is_optimal=True,
        approve=True,
        feedback=None,
        concerns=[],
        suggested_improvements=[],
        security_score=8,
        best_practices_followed=True,
    )


@pytest.fixture
def sample_triage_decision():
    """Sample triage decision."""
    return TriageDecision(
        finding_id="xccdf_org.ssgproject.content_rule_test_001",
        should_remediate=True,
        risk_level="medium",
        reason="Service configuration is safe to automate",
    )


@pytest.fixture
def sample_qa_input(sample_vulnerability, sample_remediation_attempt, sample_review_verdict, sample_triage_decision):
    """Sample QA input."""
    return QAInput(
        vulnerability=sample_vulnerability,
        remediation_attempt=sample_remediation_attempt,
        review_verdict=sample_review_verdict,
    )


# ============================================================================
# Tests
# ============================================================================


class TestQAAgentInitialization:
    """Test QA Agent initialization."""

    def test_init_with_env_vars(self, mock_executor):
        """Test initialization with environment variables."""
        with patch.dict(
            os.environ,
            {
                "OPENROUTER_API_KEY": "test-key",
                "OPENROUTER_BASE_URL": "https://test.api.com",
                "OPENROUTER_MODEL": "test-model",
            },
        ):
            agent = QAAgent(executor=mock_executor)

            assert agent.api_key == "test-key"
            assert agent.base_url == "https://test.api.com"
            assert agent.model == "test-model"
            assert agent.executor == mock_executor

    def test_init_with_parameters(self, mock_executor):
        """Test initialization with explicit parameters."""
        agent = QAAgent(
            executor=mock_executor,
            api_key="param-key",
            base_url="https://param.api.com",
            model="param-model",
        )

        assert agent.api_key == "param-key"
        assert agent.base_url == "https://param.api.com"
        assert agent.model == "param-model"

    def test_init_missing_api_key(self, mock_executor):
        """Test initialization fails without API key."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="OPENROUTER_API_KEY not found"):
                QAAgent(executor=mock_executor)


class TestQAAgentTools:
    """Test QA Agent tool definitions."""

    def test_define_tools(self, mock_executor):
        """Test that QA agent defines exactly 2 tools: run_cmd, verdict."""
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
            agent = QAAgent(executor=mock_executor)
            tools = agent._define_tools()

            assert len(tools) == 2

            tool_names = [tool["function"]["name"] for tool in tools]
            assert "run_cmd" in tool_names
            assert "verdict" in tool_names

    def test_execute_tool_run_cmd(self, mock_executor):
        """Test executing run_cmd tool."""
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
            agent = QAAgent(executor=mock_executor)

            result = agent._execute_tool("run_cmd", {"command": "systemctl status sshd"})

            assert result["success"] is True
            assert result["command"] == "systemctl status sshd"
            assert mock_executor.run_command.called

    def test_execute_tool_verdict(self, mock_executor):
        """Test executing verdict tool."""
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
            agent = QAAgent(executor=mock_executor)

            result = agent._execute_tool("verdict", {"message": "System is safe", "safe": True})

            assert result["acknowledged"] is True

    def test_execute_tool_unknown(self, mock_executor):
        """Test executing unknown tool returns error."""
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
            agent = QAAgent(executor=mock_executor)

            result = agent._execute_tool("unknown_tool", {})

            assert "error" in result
            assert "Unknown tool" in result["error"]


class TestQAAgentProcess:
    """Test QA Agent process method."""

    @patch("agents.qa_agent.ToolCallingLLM")
    def test_process_safe_system(
        self, mock_llm_class, mock_executor, sample_qa_input
    ):
        """Test QA process when system is safe."""
        # Mock LLM session result
        mock_llm_instance = Mock()
        mock_llm_instance.run_session.return_value = {
            "commands": ["systemctl status sshd", "systemctl status auditd"],
            "detailed_results": [
                {
                    "command": "systemctl status sshd",
                    "stdout": "active (running)",
                    "stderr": "",
                    "exit_code": 0,
                    "success": True,
                    "duration": 0.1,
                },
                {
                    "command": "systemctl status auditd",
                    "stdout": "active (running)",
                    "stderr": "",
                    "exit_code": 0,
                    "success": True,
                    "duration": 0.1,
                },
            ],
            "verdict": {"message": "All services healthy, system is safe", "safe": True},
            "combined_output": "...",
            "apply_success": True,
            "transcript": [],
            "usage": [],
            "session_label": "qa_test",
        }
        mock_llm_class.return_value = mock_llm_instance

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
            agent = QAAgent(executor=mock_executor)
            result = agent.process(sample_qa_input)

        assert isinstance(result, QAResult)
        assert result.safe is True
        assert result.recommendation == "Approve"
        assert len(result.system_checks) == 2
        assert "sshd" in result.services_affected
        assert "auditd" in result.services_affected

    @patch("agents.qa_agent.ToolCallingLLM")
    def test_process_unsafe_system(
        self, mock_llm_class, mock_executor, sample_qa_input
    ):
        """Test QA process when system has issues."""
        # Mock LLM session result with safety issue
        mock_llm_instance = Mock()
        mock_llm_instance.run_session.return_value = {
            "commands": ["systemctl status sshd"],
            "detailed_results": [
                {
                    "command": "systemctl status sshd",
                    "stdout": "",
                    "stderr": "Failed to get status",
                    "exit_code": 3,
                    "success": False,
                    "duration": 0.1,
                }
            ],
            "verdict": {"message": "SSH service is down, system is unsafe", "safe": False},
            "combined_output": "...",
            "apply_success": False,
            "transcript": [],
            "usage": [],
            "session_label": "qa_test",
        }
        mock_llm_class.return_value = mock_llm_instance

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
            agent = QAAgent(executor=mock_executor)
            result = agent.process(sample_qa_input)

        assert isinstance(result, QAResult)
        assert result.safe is False
        assert result.recommendation == "Rollback"
        assert len(result.system_checks) == 1


class TestQAAgentPromptBuilding:
    """Test QA Agent prompt building."""

    def test_build_qa_prompt(self, mock_executor, sample_qa_input):
        """Test QA prompt contains all necessary information."""
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
            agent = QAAgent(executor=mock_executor)
            prompt = agent._build_qa_prompt(sample_qa_input)

            # Check key elements are in prompt
            assert sample_qa_input.vulnerability.id in prompt
            assert sample_qa_input.vulnerability.title in prompt
            assert str(sample_qa_input.remediation_attempt.commands_executed) in prompt
            assert str(sample_qa_input.review_verdict.approve) in prompt
            assert "QA VALIDATION TASK" in prompt
            assert "systemctl status sshd" in prompt or "Check critical services" in prompt


class TestQAAgentServiceExtraction:
    """Test service extraction from commands."""

    def test_extract_services(self, mock_executor):
        """Test extracting service names from systemctl commands."""
        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
            agent = QAAgent(executor=mock_executor)

            commands = [
                "systemctl status sshd",
                "systemctl status auditd",
                "systemctl status firewalld",
                "echo test",  # Should be ignored
            ]

            services = agent._extract_services(commands)

            assert "sshd" in services
            assert "auditd" in services
            assert "firewalld" in services
            assert len(services) == 3


# ============================================================================
# Integration-style test (with real executor but mocked SSH)
# ============================================================================


class TestQAAgentIntegration:
    """Integration tests for QA Agent."""

    @patch("subprocess.run")
    @patch("agents.qa_agent.ToolCallingLLM")
    def test_qa_agent_full_workflow(
        self, mock_llm_class, mock_subprocess, sample_qa_input
    ):
        """Test full QA workflow with mocked subprocess."""
        # Mock subprocess to simulate SSH command execution
        mock_process = Mock()
        mock_process.stdout = "active (running)"
        mock_process.stderr = ""
        mock_process.returncode = 0
        mock_subprocess.return_value = mock_process

        # Mock LLM to call run_cmd and verdict
        mock_llm_instance = Mock()
        mock_llm_instance.run_session.return_value = {
            "commands": ["systemctl status sshd"],
            "detailed_results": [
                {
                    "command": "systemctl status sshd",
                    "stdout": "active (running)",
                    "stderr": "",
                    "exit_code": 0,
                    "success": True,
                    "duration": 0.5,
                }
            ],
            "verdict": {"message": "System validated successfully", "safe": True},
            "combined_output": "SSH is running",
            "apply_success": True,
            "transcript": [],
            "usage": [],
            "session_label": "qa_test",
        }
        mock_llm_class.return_value = mock_llm_instance

        # Create real executor (but SSH will be mocked via subprocess)
        executor = ShellCommandExecutor(
            host="test-host", user="test-user", key=None, sudo_password=None
        )

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}):
            agent = QAAgent(executor=executor)
            result = agent.process(sample_qa_input)

        assert result.safe is True
        assert result.recommendation == "Approve"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
