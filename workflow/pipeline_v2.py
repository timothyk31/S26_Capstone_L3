"""
Pipeline V2 — Single-finding workflow manager (revised flow).

Orchestrates ONE vulnerability through the v2 pipeline:
  Triage → Remedy (generates fix → Review+QA approval → scan) → Aggregation

Key difference from v1:
  - The Remedy agent calls Review, which calls QA, *before* the verification
    scan is run.
  - If both Review and QA approve AND the scan passes, the finding goes
    straight to aggregation with status "success".
  - If the scan fails or approval is denied, the remedy is retried.
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
    TriageDecision,
    TriageInput,
    V2FindingResult,
    Vulnerability,
)

console = Console()


class PipelineV2:
    """
    Run a single vulnerability through the v2 pipeline.

    Stages:
        1. Triage   – decide whether to remediate
        2. Remedy   – LLM fix → Review+QA approval → scan (retry loop)
    """

    def __init__(
        self,
        triage_agent: TriageAgent,
        remedy_agent_v2: RemedyAgentV2,
        *,
        max_remedy_attempts: int = 3,
        report_dir: Optional[Union[str, Path]] = None,
    ):
        self.triage = triage_agent
        self.remedy_v2 = remedy_agent_v2
        self.max_remedy_attempts = max_remedy_attempts
        self._writer: Optional[AgentReportWriter] = (
            AgentReportWriter(report_dir) if report_dir else None
        )

    def run(self, vulnerability: Vulnerability) -> V2FindingResult:
        """Run a single vulnerability through the v2 pipeline."""
        t0 = time.time()
        vid = vulnerability.id

        # ── Stage 1: Triage ───────────────────────────────────────────
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

        # ── Stage 2: Remedy loop (fix → Review+QA → scan) ───────────
        remediation: Optional[RemediationAttempt] = None
        approval: Optional[PreApprovalResult] = None
        attempt = 1
        previous_attempts: List[RemediationAttempt] = []
        review_feedback: Optional[str] = None

        while attempt <= self.max_remedy_attempts:
            console.print(
                f"[bold cyan]  [{vid}] Stage 2/2: Remedy+Approval "
                f"(attempt {attempt}/{self.max_remedy_attempts})[/bold cyan]"
            )

            remedy_input = RemedyInput(
                vulnerability=vulnerability,
                triage_decision=triage_decision,
                attempt_number=attempt,
                previous_attempts=previous_attempts,
                review_feedback=review_feedback,
            )

            remediation, approval = self.remedy_v2.process(remedy_input)

            if self._writer:
                try:
                    self._writer.write(
                        "remedy_v2", vid, remedy_input, remediation, attempt=attempt,
                    )
                except Exception:
                    pass

            # ── Success: both approved AND scan passed ───────────────
            if (
                approval is not None
                and approval.approved
                and remediation.scan_passed
            ):
                console.print(
                    f"[green]  [{vid}] V2 Pipeline → SUCCESS "
                    f"(attempt {attempt})[/green]"
                )
                break

            # ── Failure: prepare for retry ───────────────────────────
            previous_attempts.append(remediation)

            # Build feedback for the next attempt
            if approval is not None and not approval.approved:
                review_feedback = approval.rejection_reason or "Fix rejected by Review/QA."
                rv = approval.review_verdict
                if rv and rv.suggested_improvements:
                    review_feedback += " Suggestions: " + "; ".join(
                        rv.suggested_improvements
                    )
            elif not remediation.scan_passed:
                review_feedback = (
                    "Review+QA approved but the verification scan failed. "
                    "Try a different approach."
                )

            attempt += 1

        # ── Final status ──────────────────────────────────────────────
        if (
            remediation is not None
            and remediation.scan_passed
            and approval is not None
            and approval.approved
        ):
            final_status = "success"
        else:
            final_status = "failed"

        elapsed = time.time() - t0
        console.print(
            f"[bold]  [{vid}] V2 Pipeline complete → {final_status.upper()} "
            f"({elapsed:.1f}s)[/bold]"
        )

        return V2FindingResult(
            vulnerability=vulnerability,
            triage=triage_decision,
            remediation=remediation,
            pre_approval=approval,
            final_status=final_status,
            total_duration=elapsed,
            timestamp=datetime.now().isoformat(timespec="seconds"),
        )
