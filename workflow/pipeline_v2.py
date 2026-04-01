"""
Pipeline V2 — Single-finding workflow manager (batch-then-verify flow).

Orchestrates ONE vulnerability through a single attempt:
  Triage → Remedy (plan → Review+QA approval → apply fix)

Scanning is NOT done here — the caller (main_multiagent) runs a full-profile
scan after all findings in a round are remediated, then matches results back.

Retry logic also lives in the caller, not here.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

from rich.console import Console

from agents.triage_agent import TriageAgent
from agents.remedy_agent_v2 import RemedyAgentV2
from helpers.agent_report_writer import AgentReportWriter
from helpers.llm_metrics import LLMMetricsTracker
from schemas import (
    PreApprovalResult,
    RemedyInput,
    RemediationAttempt,
    ReviewVerdict,
    TriageDecision,
    TriageInput,
    V2FindingResult,
    Vulnerability,
)

console = Console()


class PipelineV2:
    """
    Run a single vulnerability through one attempt of the v2 pipeline.

    Stages:
        1. Triage   – decide whether to remediate (skipped if triage_decision provided)
        2. Remedy   – plan fix → Review+QA → apply (single attempt, no scan)
    """

    def __init__(
        self,
        triage_agent: TriageAgent,
        remedy_agent_v2: RemedyAgentV2,
        *,
        report_dir: Optional[Union[str, Path]] = None,
        run_id: Optional[str] = None,
    ):
        self.triage = triage_agent
        self.remedy_v2 = remedy_agent_v2
        self.run_id = run_id
        self._writer: Optional[AgentReportWriter] = (
            AgentReportWriter(report_dir, run_id=run_id) if report_dir else None
        )

    def _set_metrics_tracker(self, tracker: LLMMetricsTracker) -> None:
        """Propagate a metrics tracker to all nested agents."""
        # Triage
        self.triage.metrics_tracker = tracker
        if hasattr(self.triage, "_client"):
            self.triage._client.metrics_tracker = tracker
        # Remedy (the inner RemedyAgent)
        if hasattr(self.remedy_v2, "remedy_agent"):
            self.remedy_v2.remedy_agent.metrics_tracker = tracker
        # Review + QA (inside ReviewAgentV2 inside RemedyAgentV2)
        if hasattr(self.remedy_v2, "review_v2"):
            rv2 = self.remedy_v2.review_v2
            if hasattr(rv2, "review_agent"):
                rv2.review_agent.metrics_tracker = tracker
            if hasattr(rv2, "qa_agent"):
                rv2.qa_agent.metrics_tracker = tracker

    def run(
        self,
        vulnerability: Vulnerability,
        *,
        triage_decision: Optional[TriageDecision] = None,
        attempt_number: int = 1,
        previous_attempts: Optional[List[RemediationAttempt]] = None,
        review_feedback: Optional[str] = None,
        previous_review_verdicts: Optional[List[ReviewVerdict]] = None,
        group_label: Optional[str] = None,
    ) -> V2FindingResult:
        """Run a single vulnerability through the v2 pipeline."""
        t0 = time.time()
        vid = vulnerability.id
        tag = f"[dim]\\[{group_label}][/dim] " if group_label else ""

        normalized_previous_attempts = list(previous_attempts or [])
        normalized_previous_review_verdicts = list(previous_review_verdicts or [])

        # Create a fresh metrics tracker for this finding
        tracker = LLMMetricsTracker()
        self._set_metrics_tracker(tracker)

        # ── Stage 1: Triage ───────────────────────────────────────────
        if triage_decision is None:
            console.print(f"{tag}[bold cyan]  [{vid}] Stage 1/2: Triage[/bold cyan]")
            triage_input = TriageInput(vulnerability=vulnerability)
            try:
                triage_decision = self.triage.process(triage_input)
                if self._writer:
                    self._writer.write("triage", vid, triage_input, triage_decision)
            except Exception as exc:
                console.print(f"{tag}[red]  [{vid}] Triage error: {exc}[/red]")
                triage_decision = TriageDecision(
                    finding_id=vid,
                    should_remediate=False,
                    risk_level="medium",
                    reason=f"Triage error: {exc}",
                    requires_human_review=True,
                )
                if self._writer:
                    self._writer.write_error("triage", vid, triage_input, exc)

        if not triage_decision.should_remediate:
            status = (
                "requires_human_review"
                if triage_decision.requires_human_review
                else "discarded"
            )
            console.print(f"{tag}[yellow]  [{vid}] Triage → {status}[/yellow]")
            return V2FindingResult(
                vulnerability=vulnerability,
                triage=triage_decision,
                final_status=status,
                total_duration=time.time() - t0,
                timestamp=datetime.now().isoformat(timespec="seconds"),
                llm_metrics=tracker.summary(),
            )

        # ── Stage 2: Single remedy attempt (no scan) ─────────────────
        console.print(
            f"{tag}[bold cyan]  [{vid}] Stage 2/2: Remedy+Approval "
            f"(attempt {attempt_number})[/bold cyan]"
        )

        remedy_input = RemedyInput(
            vulnerability=vulnerability,
            triage_decision=triage_decision,
            attempt_number=attempt_number,
            previous_attempts=normalized_previous_attempts,
            review_feedback=review_feedback,
            previous_review_verdicts=normalized_previous_review_verdicts,
        )

        remediation, approval = self.remedy_v2.process(remedy_input)

        if self._writer:
            try:
                # Exclude scan fields — they're populated later by the batch scan
                dump = remediation.model_dump(mode="json", exclude={"scan_passed", "scan_output", "scan_duration"}) if remediation else remediation
                self._writer.write(
                    "remedy_v2", vid, remedy_input, dump, attempt=attempt_number,
                )
            except Exception as exc:
                console.print(f"{tag}[red]  [{vid}] Report write error: {exc}[/red]")

        elapsed = time.time() - t0
        console.print(
            f"{tag}[bold]  [{vid}] V2 Pipeline attempt {attempt_number} complete "
            f"({elapsed:.1f}s)[/bold]"
        )

        # Build the complete list of all attempts (previous failures + final)
        all_attempts = list(normalized_previous_attempts)
        if remediation is not None and remediation not in normalized_previous_attempts:
            all_attempts.append(remediation)

        return V2FindingResult(
            vulnerability=vulnerability,
            triage=triage_decision,
            remediation=remediation,
            all_attempts=all_attempts,
            pre_approval=approval,
            final_status="pending_scan",
            total_duration=elapsed,
            timestamp=datetime.now().isoformat(timespec="seconds"),
            llm_metrics=tracker.summary(),
        )
