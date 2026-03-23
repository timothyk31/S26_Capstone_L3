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
    ):
        self.triage = triage_agent
        self.remedy_v2 = remedy_agent_v2
        self._writer: Optional[AgentReportWriter] = (
            AgentReportWriter(report_dir) if report_dir else None
        )

    def run(
        self,
        vulnerability: Vulnerability,
        *,
        triage_decision: Optional[TriageDecision] = None,
        attempt_number: int = 1,
        previous_attempts: Optional[List[RemediationAttempt]] = None,
        review_feedback: Optional[str] = None,
        previous_review_verdicts: Optional[List[ReviewVerdict]] = None,
    ) -> V2FindingResult:
        """
        Run a single vulnerability through one pipeline attempt.

        Args:
            vulnerability: The finding to remediate.
            triage_decision: If provided, skip triage (used for retries).
            attempt_number: Current attempt number (1-based).
            previous_attempts: Prior RemediationAttempts for context.
            review_feedback: Feedback string from prior rejection/failure.
            previous_review_verdicts: Structured review verdicts from prior attempts.
        """
        t0 = time.time()
        vid = vulnerability.id

        # ── Stage 1: Triage (skip if pre-computed) ────────────────────
        if triage_decision is None:
            console.print(f"[bold cyan]  [{vid}] Stage 1/2: Triage[/bold cyan]")
            triage_input = TriageInput(vulnerability=vulnerability)
            try:
                triage_decision = self.triage.process(triage_input)
                if self._writer:
                    self._writer.write("triage", vid, triage_input, triage_decision)
            except Exception as exc:
                console.print(f"[red]  [{vid}] Triage error: {exc}[/red]")
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
                console.print(f"[yellow]  [{vid}] Triage → {status}[/yellow]")
                return V2FindingResult(
                    vulnerability=vulnerability,
                    triage=triage_decision,
                    final_status=status,
                    total_duration=time.time() - t0,
                    timestamp=datetime.now().isoformat(timespec="seconds"),
                )

            console.print(
                f"[green]  [{vid}] Triage → safe to remediate "
                f"(risk={triage_decision.risk_level})[/green]"
            )

        # ── Stage 2: Single remedy attempt (no scan) ─────────────────
        console.print(
            f"[bold cyan]  [{vid}] Stage 2/2: Remedy+Approval "
            f"(attempt {attempt_number})[/bold cyan]"
        )

        remedy_input = RemedyInput(
            vulnerability=vulnerability,
            triage_decision=triage_decision,
            attempt_number=attempt_number,
            previous_attempts=previous_attempts or [],
            review_feedback=review_feedback,
            previous_review_verdicts=previous_review_verdicts or [],
        )

        remediation, approval = self.remedy_v2.process(remedy_input)

        if self._writer:
            try:
                self._writer.write(
                    "remedy_v2", vid, remedy_input, remediation, attempt=attempt_number,
                )
            except Exception:
                pass

        elapsed = time.time() - t0
        console.print(
            f"[bold]  [{vid}] V2 Pipeline attempt {attempt_number} complete "
            f"({elapsed:.1f}s)[/bold]"
        )

        return V2FindingResult(
            vulnerability=vulnerability,
            triage=triage_decision,
            remediation=remediation,
            pre_approval=approval,
            final_status="pending_scan",
            total_duration=elapsed,
            timestamp=datetime.now().isoformat(timespec="seconds"),
        )
