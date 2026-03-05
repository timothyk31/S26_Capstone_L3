"""Global pytest configuration and fixtures."""

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
import tempfile
import shutil
from typing import Generator

from schemas import (
    Vulnerability, 
    TriageDecision, 
    RemediationAttempt, 
    ReviewVerdict, 
    QAResult,
    RunCommandResult
)
from tests.fixtures.test_data_factory import VulnerabilityFactory, TriageDecisionFactory


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    temp_path = Path(tempfile.mkdtemp())
    try:
        yield temp_path
    finally:
        shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """Standard test vulnerability."""
    return VulnerabilityFactory.create_ssh_timeout()


@pytest.fixture
def critical_vulnerability() -> Vulnerability:
    """High-severity test vulnerability."""
    return VulnerabilityFactory.create_critical()


@pytest.fixture
def low_risk_vulnerability() -> Vulnerability:
    """Low-risk test vulnerability."""
    return VulnerabilityFactory.create_low_risk()


@pytest.fixture
def sample_triage_decision() -> TriageDecision:
    """Standard triage decision for testing."""
    return TriageDecisionFactory.create_approve()


@pytest.fixture
def reject_triage_decision() -> TriageDecision:
    """Rejection triage decision for testing."""
    return TriageDecisionFactory.create_reject()


@pytest.fixture
def mock_llm_client():
    """Mock LLM client for testing."""
    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = MagicMock(
        choices=[
            MagicMock(
                message=MagicMock(
                    content="Mock LLM response",
                    tool_calls=None
                )
            )
        ]
    )
    return mock_client


@pytest.fixture
def mock_command_executor():
    """Mock command executor for testing."""
    mock_executor = MagicMock()
    mock_executor.run_command.return_value = RunCommandResult(
        command="echo 'test'",
        stdout="test",
        stderr="",
        exit_code=0,
        success=True,
        duration=0.1
    )
    return mock_executor


@pytest.fixture
def mock_ssh_connection():
    """Mock SSH connection for testing."""
    with patch('paramiko.SSHClient') as mock_ssh:
        mock_client = MagicMock()
        mock_ssh.return_value = mock_client
        
        # Mock successful command execution
        mock_stdin = MagicMock()
        mock_stdout = MagicMock()
        mock_stderr = MagicMock()
        
        mock_stdout.read.return_value = b"command output"
        mock_stderr.read.return_value = b""
        mock_stdout.channel.recv_exit_status.return_value = 0
        
        mock_client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)
        
        yield mock_client


@pytest.fixture
def mock_openscap_output():
    """Mock OpenSCAP XML output for testing."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">
    <rule-result idref="xccdf_org.ssgproject.content_rule_ssh_client_alive_interval">
        <result>fail</result>
        <ident system="http://oval.mitre.org/XMLSchema/oval-definitions-5">oval:ssg-ssh_client_alive_interval:def:1</ident>
    </rule-result>
</TestResult>"""


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Set up common test environment variables."""
    with patch.dict('os.environ', {
        'OPENROUTER_API_KEY': 'test-key',
        'OPENROUTER_MODEL': 'test-model',
        'OPENROUTER_BASE_URL': 'https://test-api.com/v1'
    }):
        yield