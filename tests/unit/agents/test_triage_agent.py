"""Unit tests for TriageAgent."""

import pytest
from unittest.mock import MagicMock, patch, Mock
import json

from agents.triage_agent import TriageAgent
from schemas import TriageInput, TriageDecision, Vulnerability
from tests.fixtures.test_data_factory import VulnerabilityFactory


@pytest.mark.unit
class TestTriageAgent:
    """Test suite for TriageAgent."""

    def setup_method(self):
        """Set up test environment for each test."""
        self.agent = TriageAgent()

    def test_init_default_mode(self):
        """Test agent initialization with default mode."""
        agent = TriageAgent()
        assert agent.mode == "smart"
        assert agent.agent_name == "TriageAgent"

    def test_init_custom_mode(self):
        """Test agent initialization with custom mode."""
        agent = TriageAgent(mode="fast")
        assert agent.mode == "fast"

    def test_local_classification_dangerous_partition(self):
        """Test local classification identifies dangerous partition rules."""
        vuln = Vulnerability(
            id="test_001",
            title="Partition /var/log",
            severity="3",
            host="10.0.0.1",
            description="Create separate partition for /var/log",
            rule="partition_for_var_log"
        )
        
        input_data = TriageInput(vulnerability=vuln)
        result = self.agent.process(input_data)
        
        assert isinstance(result, TriageDecision)
        assert result.should_remediate is False
        assert result.risk_level == "critical"
        assert "partition" in result.reason.lower()

    def test_local_classification_dangerous_auth(self):
        """Test local classification identifies dangerous auth rules."""
        vuln = Vulnerability(
            id="test_002",
            title="PAM Configuration",
            severity="3",
            host="10.0.0.1",
            description="Configure PAM authentication",
            rule="accounts_password_pam_retry"
        )
        
        input_data = TriageInput(vulnerability=vuln)
        result = self.agent.process(input_data)
        
        assert isinstance(result, TriageDecision)
        assert result.should_remediate is False
        assert result.risk_level == "critical"
        assert "authentication" in result.reason.lower()

    def test_local_classification_safe_ssh_config(self):
        """Test local classification identifies safe SSH configs."""
        vuln = VulnerabilityFactory.create_ssh_timeout()
        input_data = TriageInput(vulnerability=vuln)
        
        result = self.agent.process(input_data)
        
        assert isinstance(result, TriageDecision)
        assert result.should_remediate is True
        assert result.risk_level == "low"
        assert "ssh" in result.reason.lower()

    @patch('agents.triage_agent._OpenRouterClient.call_llm')
    def test_llm_classification_success(self, mock_llm_call):
        """Test successful LLM classification for non-local rules."""
        mock_llm_response = {
            "finding_id": "test_003",
            "rule_id": "unknown_rule",
            "category": "safe_to_remediate",
            "confidence": 0.85,
            "rationale": "Safe configuration change",
            "risk_factors": [],
            "safe_next_steps": ["Apply change", "Restart service"],
            "requires_reboot": False,
            "touches_authn_authz": False,
            "touches_networking": False,
            "touches_filesystems": False
        }
        mock_llm_call.return_value = mock_llm_response
        
        vuln = Vulnerability(
            id="test_003",
            title="Unknown Configuration",
            severity="2",
            host="10.0.0.1",
            description="Some unknown configuration",
            rule="unknown_rule"
        )
        
        input_data = TriageInput(vulnerability=vuln)
        result = self.agent.process(input_data)
        
        assert isinstance(result, TriageDecision)
        assert result.should_remediate is True
        assert result.risk_level == "low"
        assert "safe configuration change" in result.reason.lower()
        mock_llm_call.assert_called_once()

    @patch('agents.triage_agent._OpenRouterClient.call_llm')
    def test_llm_classification_human_review(self, mock_llm_call):
        """Test LLM classification requesting human review."""
        mock_llm_response = {
            "finding_id": "test_004",
            "rule_id": "complex_rule",
            "category": "requires_human_review",
            "confidence": 0.6,
            "rationale": "Complex change requiring human evaluation",
            "risk_factors": ["Affects multiple services", "Complex dependencies"],
            "safe_next_steps": [],
            "requires_reboot": True,
            "touches_authn_authz": True,
            "touches_networking": False,
            "touches_filesystems": True
        }
        mock_llm_call.return_value = mock_llm_response
        
        vuln = Vulnerability(
            id="test_004",
            title="Complex Configuration",
            severity="3",
            host="10.0.0.1",
            description="Complex system configuration",
            rule="complex_rule"
        )
        
        input_data = TriageInput(vulnerability=vuln)
        result = self.agent.process(input_data)
        
        assert isinstance(result, TriageDecision)
        assert result.should_remediate is False
        assert result.requires_human_review is True
        assert result.risk_level == "medium"
        assert "human evaluation" in result.reason.lower()

    @patch('agents.triage_agent._OpenRouterClient.call_llm')
    def test_llm_classification_too_dangerous(self, mock_llm_call):
        """Test LLM classification marking as too dangerous."""
        mock_llm_response = {
            "finding_id": "test_005",
            "rule_id": "dangerous_rule",
            "category": "too_dangerous_to_remediate",
            "confidence": 0.95,
            "rationale": "High risk of system instability",
            "risk_factors": ["System crash possible", "Data loss risk"],
            "safe_next_steps": [],
            "requires_reboot": True,
            "touches_authn_authz": True,
            "touches_networking": True,
            "touches_filesystems": True
        }
        mock_llm_call.return_value = mock_llm_response
        
        vuln = Vulnerability(
            id="test_005",
            title="Dangerous Configuration",
            severity="4",
            host="10.0.0.1",
            description="High-risk system configuration",
            rule="dangerous_rule"
        )
        
        input_data = TriageInput(vulnerability=vuln)
        result = self.agent.process(input_data)
        
        assert isinstance(result, TriageDecision)
        assert result.should_remediate is False
        assert result.requires_human_review is False
        assert result.risk_level == "critical"
        assert "system instability" in result.reason.lower()

    @patch('agents.triage_agent._OpenRouterClient.call_llm')
    def test_llm_failure_fallback(self, mock_llm_call):
        """Test fallback behavior when LLM call fails."""
        mock_llm_call.side_effect = Exception("LLM API failure")
        
        vuln = Vulnerability(
            id="test_006",
            title="Unknown Configuration",
            severity="2",
            host="10.0.0.1",
            description="Some unknown configuration",
            rule="unknown_rule"
        )
        
        input_data = TriageInput(vulnerability=vuln)
        result = self.agent.process(input_data)
        
        # Should fallback to conservative human review
        assert isinstance(result, TriageDecision)
        assert result.should_remediate is False
        assert result.requires_human_review is True
        assert result.risk_level == "medium"
        assert "llm failure" in result.reason.lower()

    def test_severity_based_fallback(self):
        """Test fallback behavior for different severity levels."""
        # High severity should be more conservative
        high_severity_vuln = Vulnerability(
            id="test_007",
            title="High Severity Rule",
            severity="4",
            host="10.0.0.1",
            description="High severity configuration",
            rule="unknown_high_severity_rule"
        )
        
        with patch('agents.triage_agent._OpenRouterClient.call_llm') as mock_llm:
            mock_llm.side_effect = Exception("LLM failure")
            
            input_data = TriageInput(vulnerability=high_severity_vuln)
            result = self.agent.process(input_data)
            
            assert result.risk_level == "high"
            
        # Low severity should be less conservative
        low_severity_vuln = Vulnerability(
            id="test_008",
            title="Low Severity Rule",
            severity="1",
            host="10.0.0.1",
            description="Low severity configuration",
            rule="unknown_low_severity_rule"
        )
        
        with patch('agents.triage_agent._OpenRouterClient.call_llm') as mock_llm:
            mock_llm.side_effect = Exception("LLM failure")
            
            input_data = TriageInput(vulnerability=low_severity_vuln)
            result = self.agent.process(input_data)
            
            assert result.risk_level == "low"

    def test_system_context_handling(self):
        """Test processing with system context."""
        vuln = VulnerabilityFactory.create_ssh_timeout()
        system_context = {
            "environment": "production",
            "criticality": "high",
            "maintenance_window": "sunday_3am"
        }
        
        input_data = TriageInput(
            vulnerability=vuln,
            system_context=system_context
        )
        result = self.agent.process(input_data)
        
        # Should still process successfully
        assert isinstance(result, TriageDecision)
        assert result.finding_id == vuln.id

    def test_invalid_input_handling(self):
        """Test handling of invalid input data."""
        with pytest.raises((TypeError, AttributeError)):
            self.agent.process(None)
        
        with pytest.raises((TypeError, AttributeError)):
            self.agent.process("invalid_input")

    @patch('agents.triage_agent._OpenRouterClient.call_llm')
    def test_llm_response_validation_error(self, mock_llm_call):
        """Test handling of invalid LLM response format."""
        # Invalid response missing required fields
        mock_llm_call.return_value = {
            "finding_id": "test_009",
            "invalid_field": "invalid_value"
        }
        
        vuln = Vulnerability(
            id="test_009",
            title="Unknown Configuration",
            severity="2",
            host="10.0.0.1",
            description="Some unknown configuration",
            rule="unknown_rule"
        )
        
        input_data = TriageInput(vulnerability=vuln)
        result = self.agent.process(input_data)
        
        # Should fallback to human review
        assert isinstance(result, TriageDecision)
        assert result.requires_human_review is True
        assert "validation error" in result.reason.lower() or "llm failure" in result.reason.lower()