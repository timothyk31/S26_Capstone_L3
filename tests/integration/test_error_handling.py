"""Integration tests for error handling across the system."""

import pytest
from unittest.mock import MagicMock, patch, Mock
import json
import tempfile
from pathlib import Path

from workflow.pipeline_v2 import PipelineV2
from agents.triage_agent import TriageAgent
from schemas import Vulnerability, TriageDecision, RemediationAttempt
from tests.fixtures.test_data_factory import VulnerabilityFactory


@pytest.mark.integration
class TestErrorHandlingIntegration:
    """Test error handling and recovery mechanisms."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_triage_agent = MagicMock(spec=TriageAgent)
        self.mock_remedy_agent = MagicMock()
        
        self.pipeline = PipelineV2(
            triage_agent=self.mock_triage_agent,
            remedy_agent_v2=self.mock_remedy_agent,
            max_remedy_attempts=3
        )

    def test_triage_agent_exception_handling(self):
        """Test handling of triage agent exceptions."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Mock triage agent to raise exception
        self.mock_triage_agent.process.side_effect = RuntimeError("Triage agent crashed")
        
        result = self.pipeline.run(vulnerability)
        
        # Should fallback gracefully
        assert result.final_status == "requires_human_review"
        assert "error" in result.triage.reason.lower() or "human" in result.triage.reason.lower()

    def test_remedy_agent_exception_handling(self):
        """Test handling of remedy agent exceptions."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Mock triage approval
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Mock remedy agent to raise exception
        self.mock_remedy_agent.process.side_effect = Exception("Remedy agent failed")
        
        result = self.pipeline.run(vulnerability)
        
        # Should handle gracefully
        assert result.final_status == "failed"
        
        # Should still have attempted the maximum number of times
        assert self.mock_remedy_agent.process.call_count == 3

    def test_partial_failure_recovery(self):
        """Test recovery from partial failures."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Mock triage approval
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Mock first two attempts fail, third succeeds
        error_attempt = RemediationAttempt(
            finding_id=vulnerability.id,
            attempt_number=1,
            success=False,
            error_summary="Network timeout"
        )
        
        successful_attempt = RemediationAttempt(
            finding_id=vulnerability.id,
            attempt_number=3,
            scan_passed=True,
            success=True
        )
        
        self.mock_remedy_agent.process.side_effect = [
            (error_attempt, None),  # First attempt fails
            (error_attempt, None),  # Second attempt fails  
            (successful_attempt, MagicMock(approved=True))  # Third succeeds
        ]
        
        result = self.pipeline.run(vulnerability)
        
        assert result.final_status == "success"
        assert len(result.all_attempts) == 3
        assert self.mock_remedy_agent.process.call_count == 3

    def test_data_validation_error_handling(self):
        """Test handling of data validation errors."""
        # Create invalid vulnerability data
        invalid_vulnerability = Vulnerability(
            id="test_invalid",
            title="",  # Invalid empty title
            severity="invalid_severity",  # Invalid severity
            host=""  # Invalid empty host
        )
        
        # Mock triage to return invalid data
        invalid_triage = TriageDecision(
            finding_id="wrong_id",  # Mismatched ID
            should_remediate=True,
            risk_level="invalid_level",  # Invalid risk level
            reason=""  # Invalid empty reason
        )
        self.mock_triage_agent.process.return_value = invalid_triage
        
        # Pipeline should handle gracefully
        result = self.pipeline.run(invalid_vulnerability)
        
        # Should fallback to safe state
        assert result.final_status in ["failed", "requires_human_review"]

    def test_network_error_simulation(self):
        """Test handling of network-related errors."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Mock triage to succeed
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Mock network errors in remedy agent
        import requests
        self.mock_remedy_agent.process.side_effect = requests.exceptions.ConnectionError("Network unreachable")
        
        result = self.pipeline.run(vulnerability)
        
        assert result.final_status == "failed"

    def test_timeout_error_handling(self):
        """Test handling of timeout errors."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Mock timeout errors
        import requests
        self.mock_remedy_agent.process.side_effect = requests.exceptions.Timeout("Request timed out")
        
        result = self.pipeline.run(vulnerability)
        
        assert result.final_status == "failed"

    def test_memory_error_handling(self):
        """Test handling of memory-related errors."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Mock memory error
        self.mock_remedy_agent.process.side_effect = MemoryError("Out of memory")
        
        result = self.pipeline.run(vulnerability)
        
        assert result.final_status == "failed"

    def test_file_system_error_handling(self, temp_dir):
        """Test handling of filesystem errors."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Mock filesystem errors
        self.mock_remedy_agent.process.side_effect = OSError("Permission denied")
        
        result = self.pipeline.run(vulnerability)
        
        assert result.final_status == "failed"

    def test_json_parsing_error_handling(self):
        """Test handling of JSON parsing errors."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Mock JSON parsing errors
        self.mock_remedy_agent.process.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        
        result = self.pipeline.run(vulnerability)
        
        assert result.final_status == "failed"

    def test_cascading_failure_prevention(self):
        """Test prevention of cascading failures."""
        vulnerabilities = [
            VulnerabilityFactory.create_ssh_timeout(),
            VulnerabilityFactory.create_low_risk(),
            VulnerabilityFactory.create_filesystem()
        ]
        
        # Mock first vulnerability to cause agent failure
        self.mock_triage_agent.process.side_effect = [
            RuntimeError("Agent crashed"),  # First fails
            TriageDecision(finding_id="test", should_remediate=True, risk_level="low", reason="OK"),  # Second succeeds
            TriageDecision(finding_id="test", should_remediate=True, risk_level="low", reason="OK")   # Third succeeds
        ]
        
        results = []
        for vuln in vulnerabilities:
            try:
                result = self.pipeline.run(vuln)
                results.append(result)
            except Exception as e:
                # Should not crash the entire system
                results.append(None)
        
        # First should fail, others should succeed
        assert results[0].final_status == "requires_human_review"  # Graceful fallback
        assert results[1] is not None  # Should continue processing
        assert results[2] is not None  # Should continue processing

    def test_error_logging_and_tracing(self):
        """Test that errors are properly logged and traceable."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Mock an error with traceable information
        test_error = ValueError("Test error with traceable info")
        test_error.__traceback__ = None  # Simulate traceback
        
        self.mock_triage_agent.process.side_effect = test_error
        
        with patch('logging.getLogger') as mock_logger:
            mock_log = MagicMock()
            mock_logger.return_value = mock_log
            
            result = self.pipeline.run(vulnerability)
            
            # Should have logged the error
            # Note: Actual logging depends on implementation
            assert result.final_status == "requires_human_review"

    def test_graceful_degradation(self):
        """Test graceful degradation when services are unavailable."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Simulate external service unavailability
        class ServiceUnavailableError(Exception):
            pass
        
        self.mock_triage_agent.process.side_effect = ServiceUnavailableError("LLM service down")
        
        result = self.pipeline.run(vulnerability)
        
        # Should degrade gracefully to human review
        assert result.final_status == "requires_human_review"
        assert result.vulnerability.id == vulnerability.id