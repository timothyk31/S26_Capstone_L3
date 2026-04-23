"""Integration tests for PipelineV2.

These exercise the real PipelineV2 wiring with mocked agent `process()` methods,
testing end-to-end flow including:
  - AgentReportWriter persisting I/O to disk
  - Multi-finding sequential runs (matching how main_multiagent drives the pipeline)
  - Retry-with-feedback handoff across attempts
  - LLM metrics tracker propagation to nested agents
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from workflow.pipeline_v2 import PipelineV2
from schemas import (
    PreApprovalResult,
    QAResult,
    RemediationAttempt,
    RemedyInput,
    ReviewVerdict,
    TriageDecision,
    Vulnerability,
)


# ── Helpers ──────────────────────────────────────────────────────────────

def _vuln(vid: str = "openscap_001", host: str = "10.0.0.1") -> Vulnerability:
    return Vulnerability(
        id=vid,
        title=f"Finding {vid}",
        severity="2",
        host=host,
        description="test vuln",
    )


def _triage_approve(vid: str) -> TriageDecision:
    return TriageDecision(
        finding_id=vid,
        should_remediate=True,
        risk_level="low",
        reason="safe",
    )


def _triage_discard(vid: str) -> TriageDecision:
    return TriageDecision(
        finding_id=vid,
        should_remediate=False,
        risk_level="critical",
        reason="too dangerous",
    )


def _triage_human(vid: str) -> TriageDecision:
    return TriageDecision(
        finding_id=vid,
        should_remediate=False,
        risk_level="medium",
        reason="needs human",
        requires_human_review=True,
    )


def _attempt(vid: str, n: int = 1, scan_passed: bool = False) -> RemediationAttempt:
    return RemediationAttempt(
        finding_id=vid,
        attempt_number=n,
        commands_executed=["echo fix"],
        scan_passed=scan_passed,
        success=scan_passed,
    )


def _approval(vid: str, approved: bool = True) -> PreApprovalResult:
    return PreApprovalResult(
        review_verdict=ReviewVerdict(
            finding_id=vid, is_optimal=approved, approve=approved, security_score=8,
        ),
        qa_result=QAResult(
            finding_id=vid, safe=True, verdict_reason="ok", recommendation="Approve",
        ) if approved else None,
        approved=approved,
        rejection_reason=None if approved else "rejected by review",
    )


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def agents():
    triage = MagicMock()
    remedy = MagicMock()
    return triage, remedy


@pytest.fixture
def pipeline_with_reports(agents, tmp_path):
    triage, remedy = agents
    return PipelineV2(
        triage_agent=triage,
        remedy_agent_v2=remedy,
        report_dir=tmp_path,
        run_id="run-test",
    ), tmp_path


# ── Tests ────────────────────────────────────────────────────────────────

@pytest.mark.integration
class TestPipelineEndToEnd:
    def test_success_path_persists_reports(self, pipeline_with_reports, agents):
        pipeline, report_dir = pipeline_with_reports
        triage, remedy = agents
        vuln = _vuln("openscap_001")
        triage.process.return_value = _triage_approve("openscap_001")
        remedy.process.return_value = (_attempt("openscap_001"), _approval("openscap_001"))

        result = pipeline.run(vuln)

        assert result.final_status == "pending_scan"
        assert result.remediation is not None
        assert result.pre_approval.approved is True
        assert result.all_attempts == [result.remediation]
        triage.process.assert_called_once()
        remedy.process.assert_called_once()

        # AgentReportWriter should have persisted triage + remedy outputs
        triage_out = report_dir / "triage" / "run-test" / "openscap_001" / "output.json"
        remedy_out = report_dir / "remedy_v2" / "run-test" / "openscap_001" / "attempt_1_output.json"
        assert triage_out.exists()
        assert remedy_out.exists()

        triage_data = json.loads(triage_out.read_text())
        assert triage_data["should_remediate"] is True

    def test_discarded_finding_skips_remedy(self, pipeline_with_reports, agents):
        pipeline, _ = pipeline_with_reports
        triage, remedy = agents
        triage.process.return_value = _triage_discard("openscap_002")

        result = pipeline.run(_vuln("openscap_002"))

        assert result.final_status == "discarded"
        assert result.remediation is None
        assert result.pre_approval is None
        remedy.process.assert_not_called()

    def test_human_review_finding_skips_remedy(self, pipeline_with_reports, agents):
        pipeline, _ = pipeline_with_reports
        triage, remedy = agents
        triage.process.return_value = _triage_human("openscap_003")

        result = pipeline.run(_vuln("openscap_003"))

        assert result.final_status == "requires_human_review"
        remedy.process.assert_not_called()

    def test_triage_exception_falls_back_to_human_review(
        self, pipeline_with_reports, agents
    ):
        pipeline, report_dir = pipeline_with_reports
        triage, remedy = agents
        triage.process.side_effect = RuntimeError("LLM down")

        result = pipeline.run(_vuln("openscap_004"))

        assert result.final_status == "requires_human_review"
        assert result.triage.requires_human_review is True
        assert "LLM down" in result.triage.reason
        remedy.process.assert_not_called()

        err_file = report_dir / "triage" / "run-test" / "openscap_004" / "error.json"
        assert err_file.exists()

    def test_preset_triage_decision_skips_triage_agent(
        self, pipeline_with_reports, agents
    ):
        pipeline, _ = pipeline_with_reports
        triage, remedy = agents
        decision = _triage_approve("openscap_005")
        remedy.process.return_value = (_attempt("openscap_005"), _approval("openscap_005"))

        result = pipeline.run(_vuln("openscap_005"), triage_decision=decision)

        triage.process.assert_not_called()
        assert result.final_status == "pending_scan"


@pytest.mark.integration
class TestRetryWithFeedback:
    def test_previous_attempts_forwarded_to_remedy(self, pipeline_with_reports, agents):
        pipeline, _ = pipeline_with_reports
        triage, remedy = agents
        triage.process.return_value = _triage_approve("openscap_010")

        prev_attempt = _attempt("openscap_010", n=1)
        prev_verdict = ReviewVerdict(
            finding_id="openscap_010", is_optimal=False, approve=False,
            feedback="backup first", concerns=["no backup"],
        )
        remedy.process.return_value = (_attempt("openscap_010", n=2), _approval("openscap_010"))

        result = pipeline.run(
            _vuln("openscap_010"),
            attempt_number=2,
            previous_attempts=[prev_attempt],
            review_feedback="backup first",
            previous_review_verdicts=[prev_verdict],
        )

        call_kwargs = remedy.process.call_args.args[0]
        assert isinstance(call_kwargs, RemedyInput)
        assert call_kwargs.attempt_number == 2
        assert call_kwargs.previous_attempts == [prev_attempt]
        assert call_kwargs.review_feedback == "backup first"
        assert call_kwargs.previous_review_verdicts == [prev_verdict]
        assert len(result.all_attempts) == 2


@pytest.mark.integration
class TestMultiFindingRun:
    def test_sequential_findings_mixed_outcomes(self, pipeline_with_reports, agents):
        pipeline, report_dir = pipeline_with_reports
        triage, remedy = agents

        triage.process.side_effect = [
            _triage_approve("f1"),
            _triage_discard("f2"),
            _triage_approve("f3"),
        ]
        remedy.process.side_effect = [
            (_attempt("f1"), _approval("f1", approved=True)),
            (_attempt("f3"), _approval("f3", approved=False)),
        ]

        results = [pipeline.run(_vuln(vid)) for vid in ("f1", "f2", "f3")]

        assert [r.final_status for r in results] == [
            "pending_scan", "discarded", "pending_scan",
        ]
        assert results[0].pre_approval.approved is True
        assert results[2].pre_approval.approved is False
        assert remedy.process.call_count == 2

        # Reports exist only for findings that reached each stage
        assert (report_dir / "triage" / "run-test" / "f1" / "output.json").exists()
        assert (report_dir / "triage" / "run-test" / "f2" / "output.json").exists()
        assert (report_dir / "remedy_v2" / "run-test" / "f1" / "attempt_1_output.json").exists()
        assert not (report_dir / "remedy_v2" / "run-test" / "f2").exists()
        assert (report_dir / "remedy_v2" / "run-test" / "f3" / "attempt_1_output.json").exists()


@pytest.mark.integration
class TestMetricsPropagation:
    def test_fresh_metrics_tracker_injected_per_finding(self, agents):
        triage, remedy = agents
        # Give the nested structure the attributes the pipeline looks for
        triage._client = MagicMock()
        remedy.remedy_agent = MagicMock()
        remedy.review_v2 = MagicMock()
        remedy.review_v2.review_agent = MagicMock()
        remedy.review_v2.qa_agent = MagicMock()

        triage.process.return_value = _triage_approve("m1")
        remedy.process.return_value = (_attempt("m1"), _approval("m1"))

        pipeline = PipelineV2(triage_agent=triage, remedy_agent_v2=remedy)
        pipeline.run(_vuln("m1"))
        first_tracker = triage.metrics_tracker

        pipeline.run(_vuln("m2"))
        second_tracker = triage.metrics_tracker

        assert first_tracker is not None
        assert second_tracker is not None
        assert first_tracker is not second_tracker
        # All nested agents share the same tracker within a single run
        assert remedy.remedy_agent.metrics_tracker is second_tracker
        assert remedy.review_v2.review_agent.metrics_tracker is second_tracker
        assert remedy.review_v2.qa_agent.metrics_tracker is second_tracker
        assert triage._client.metrics_tracker is second_tracker
