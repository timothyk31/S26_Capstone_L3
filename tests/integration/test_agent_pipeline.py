"""Integration tests for multi-agent pipeline workflows."""

import pytest
from unittest.mock import MagicMock, patch, Mock
import tempfile
import json
from pathlib import Path

from workflow.pipeline_v2 import PipelineV2
from agents.triage_agent import TriageAgent
from agents.remedy_agent_v2 import RemedyAgentV2
from schemas import (
    Vulnerability, 
    TriageDecision, 
    RemediationAttempt, 
    PreApprovalResult,
    ReviewVerdict,
    QAResult
)
from tests.fixtures.test_data_factory import (
    VulnerabilityFactory,
    RemediationAttemptFactory,
    ReviewVerdictFactory,
    QAResultFactory
)


@pytest.mark.integration
class TestAgentPipelineIntegration:
    """Test integration between pipeline components."""

    def setup_method(self):
        """Set up test environment."""
        self.mock_triage_agent = MagicMock(spec=TriageAgent)
        self.mock_remedy_agent = MagicMock(spec=RemedyAgentV2)
        
        self.pipeline = PipelineV2(
            triage_agent=self.mock_triage_agent,
            remedy_agent_v2=self.mock_remedy_agent,
            max_remedy_attempts=3
        )

    def test_end_to_end_success_flow(self):
        """Test complete successful remediation flow."""
        # Setup test data
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Mock triage approval
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe SSH configuration change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Mock successful remediation
        successful_attempt = RemediationAttemptFactory.create_successful(
            finding_id=vulnerability.id
        )
        approval_result = PreApprovalResult(
            review_verdict=ReviewVerdictFactory.create_approved(vulnerability.id),
            qa_result=QAResultFactory.create_safe(vulnerability.id),
            approved=True
        )
        self.mock_remedy_agent.process.return_value = (successful_attempt, approval_result)
        
        # Execute pipeline
        result = self.pipeline.run(vulnerability)
        
        # Verify results
        assert result.final_status == "success"
        assert result.vulnerability.id == vulnerability.id
        assert result.triage.should_remediate is True
        assert result.remediation.success is True
        assert result.pre_approval.approved is True
        
        # Verify agent interactions
        self.mock_triage_agent.process.assert_called_once()
        self.mock_remedy_agent.process.assert_called_once()

    def test_end_to_end_triage_rejection(self):
        """Test pipeline with triage rejection."""
        vulnerability = VulnerabilityFactory.create_critical()
        
        # Mock triage rejection
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=False,
            risk_level="critical",
            reason="Too dangerous for automated remediation"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        result = self.pipeline.run(vulnerability)
        
        assert result.final_status == "discarded"
        assert result.remediation is None
        assert result.pre_approval is None
        
        # Verify remedy agent was not called
        self.mock_remedy_agent.process.assert_not_called()

    def test_end_to_end_human_review_required(self):
        """Test pipeline requiring human review."""
        vulnerability = VulnerabilityFactory.create_filesystem()
        
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=False,
            risk_level="medium",
            reason="Filesystem changes require human evaluation",
            requires_human_review=True
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        result = self.pipeline.run(vulnerability)
        
        assert result.final_status == "requires_human_review"
        assert result.triage.requires_human_review is True

    def test_remediation_retry_logic(self):
        """Test remediation retry mechanism."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Mock triage approval
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Mock first attempt fails, second succeeds
        failed_attempt = RemediationAttemptFactory.create_failed(
            finding_id=vulnerability.id,
            attempt_number=1
        )
        failed_approval = PreApprovalResult(
            review_verdict=ReviewVerdictFactory.create_approved(vulnerability.id),
            qa_result=QAResultFactory.create_safe(vulnerability.id),
            approved=True
        )
        
        successful_attempt = RemediationAttemptFactory.create_successful(
            finding_id=vulnerability.id,
            attempt_number=2
        )
        successful_approval = PreApprovalResult(
            review_verdict=ReviewVerdictFactory.create_approved(vulnerability.id),
            qa_result=QAResultFactory.create_safe(vulnerability.id),
            approved=True
        )
        
        self.mock_remedy_agent.process.side_effect = [
            (failed_attempt, failed_approval),
            (successful_attempt, successful_approval)
        ]
        
        result = self.pipeline.run(vulnerability)
        
        assert result.final_status == "success"
        assert len(result.all_attempts) == 2
        assert result.remediation.attempt_number == 2
        assert self.mock_remedy_agent.process.call_count == 2

    def test_error_handling_in_pipeline(self):
        """Test error handling throughout the pipeline."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Mock triage agent error
        self.mock_triage_agent.process.side_effect = Exception("Triage agent failed")
        
        result = self.pipeline.run(vulnerability)
        
        # Should fallback to human review
        assert result.final_status == "requires_human_review"
        assert "triage error" in result.triage.reason.lower() or "human review" in result.triage.reason.lower()

    def test_data_flow_consistency(self):
        """Test that data flows correctly between agents."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change",
            estimated_impact="SSH restart required"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Create a detailed successful attempt
        attempt = RemediationAttempt(
            finding_id=vulnerability.id,
            attempt_number=1,
            commands_executed=["sed -i 's/ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config"],
            scan_passed=True,
            success=True,
            duration=5.0
        )
        approval = PreApprovalResult(
            review_verdict=ReviewVerdictFactory.create_approved(vulnerability.id),
            qa_result=QAResultFactory.create_safe(vulnerability.id),
            approved=True
        )
        self.mock_remedy_agent.process.return_value = (attempt, approval)
        
        result = self.pipeline.run(vulnerability)
        
        # Verify data consistency
        assert result.vulnerability.id == vulnerability.id
        assert result.triage.finding_id == vulnerability.id
        assert result.remediation.finding_id == vulnerability.id
        assert result.pre_approval.review_verdict.finding_id == vulnerability.id
        assert result.pre_approval.qa_result.finding_id == vulnerability.id

    def test_timing_and_metrics_collection(self):
        """Test that timing and metrics are properly collected."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Mock successful flow
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        attempt = RemediationAttemptFactory.create_successful(vulnerability.id)
        approval = PreApprovalResult(
            review_verdict=ReviewVerdictFactory.create_approved(vulnerability.id),
            qa_result=QAResultFactory.create_safe(vulnerability.id),
            approved=True
        )
        self.mock_remedy_agent.process.return_value = (attempt, approval)
        
        result = self.pipeline.run(vulnerability)
        
        # Verify timing data is collected
        assert result.total_duration > 0
        assert result.timestamp != ""
        assert isinstance(result.llm_metrics, dict)

    @pytest.mark.slow
    def test_pipeline_with_real_file_operations(self, temp_dir):
        """Test pipeline with actual file operations (no SSH)."""
        vulnerability = VulnerabilityFactory.create_ssh_timeout()
        
        # Create a real config file to modify
        config_file = temp_dir / "test_sshd_config"
        config_file.write_text("""
# SSH Configuration
#ClientAliveInterval 0
Port 22
""")
        
        # Mock triage approval
        triage_decision = TriageDecision(
            finding_id=vulnerability.id,
            should_remediate=True,
            risk_level="low",
            reason="Safe change"
        )
        self.mock_triage_agent.process.return_value = triage_decision
        
        # Mock remedy with actual file operation
        def mock_remedy_process(input_data):
            # Simulate file modification
            config_content = config_file.read_text()
            modified_content = config_content.replace(
                "#ClientAliveInterval 0",
                "ClientAliveInterval 600"
            )
            config_file.write_text(modified_content)
            
            attempt = RemediationAttempt(
                finding_id=vulnerability.id,
                attempt_number=1,
                commands_executed=[f"sed -i 's/#ClientAliveInterval.*/ClientAliveInterval 600/' {config_file}"],
                files_modified=[str(config_file)],
                scan_passed=True,
                success=True
            )
            approval = PreApprovalResult(
                review_verdict=ReviewVerdictFactory.create_approved(vulnerability.id),
                qa_result=QAResultFactory.create_safe(vulnerability.id),
                approved=True
            )
            return attempt, approval
        
        self.mock_remedy_agent.process.side_effect = mock_remedy_process
        
        result = self.pipeline.run(vulnerability)
        
        # Verify file was actually modified
        assert result.final_status == "success"
        modified_content = config_file.read_text()
        assert "ClientAliveInterval 600" in modified_content
        assert "#ClientAliveInterval 0" not in modified_content