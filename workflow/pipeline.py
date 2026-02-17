"""
Pipeline — Single-finding workflow manager.

Orchestrates ONE vulnerability through the complete pipeline:
  Triage → Remedy (self-loop) → Review (→ Remedy retry) → QA → FindingResult
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

from rich.console import Console

from agents.triage_agent import TriageAgent
from agents.remedy_agent import RemedyAgent
from agents.review_agent import ReviewAgent
from agents.qa_agent import QAAgent
from helpers.agent_report_writer import AgentReportWriter
from schemas import (
    FindingResult,
    QAInput,
    RemedyInput,
    RemediationAttempt,
    ReviewInput,
    ReviewVerdict,
    TriageDecision,
    TriageInput,
    Vulnerability,
)

console = Console()


class Pipeline:
    """
    Run a single vulnerability through all pipeline stages.

    Stages:
        1. Triage  – decide whether to remediate
        2. Remedy  – LLM tool-calling loop (self-loop on scan failure)
        3. Review  – validate solution quality; can reject → re-remedy
        4. QA      – system-wide safety validation
    """

    def __init__(
        self,
        triage_agent: TriageAgent,
        remedy_agent: RemedyAgent,
        review_agent: ReviewAgent,
        qa_agent: QAAgent,
        *,
        max_remedy_attempts: int = 3,
        max_review_retries: int = 1,
        report_dir: Optional[Union[str, Path]] = None,
    ):
        self.triage = triage_agent
        self.remedy = remedy_agent
        self.review = review_agent
        self.qa = qa_agent
        self.max_remedy_attempts = max_remedy_attempts
        self.max_review_retries = max_review_retries
        self._writer: Optional[AgentReportWriter] = (
            AgentReportWriter(report_dir) if report_dir else None
        )

    def run(self, vulnerability: Vulnerability) -> FindingResult:
        """Run a single vulnerability through the complete pipeline."""
        t0 = time.time()
        vid = vulnerability.id

        # ── Stage 1: Triage ───────────────────────────────────────────
        console.print(f"[bold cyan]  [{vid}] Stage 1/4: Triage[/bold cyan]")
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
            return FindingResult(
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

        # ── Stage 2 + 3: Remedy / Review loop ────────────────────────
        remediation: Optional[RemediationAttempt] = None
        review_verdict: Optional[ReviewVerdict] = None
        attempt = 1
        previous_attempts: List[RemediationAttempt] = []
        review_feedback: Optional[str] = None
        review_retries = 0

        while attempt <= self.max_remedy_attempts:
            # ── Remedy attempt ────────────────────────────────────────
            console.print(
                f"[bold cyan]  [{vid}] Stage 2/4: Remedy "
                f"(attempt {attempt}/{self.max_remedy_attempts})[/bold cyan]"
            )
            try:
                remedy_input = RemedyInput(
                    vulnerability=vulnerability,
                    triage_decision=triage_decision,
                    attempt_number=attempt,
                    previous_attempts=previous_attempts,
                    review_feedback=review_feedback,
                )
                remediation = self.remedy.process(remedy_input)
                if self._writer:
                    self._writer.write("remedy", vid, remedy_input, remediation, attempt=attempt)
            except Exception as exc:
                console.print(f"[red]  [{vid}] Remedy error: {exc}[/red]")
                remediation = RemediationAttempt(
                    finding_id=vid,
                    attempt_number=attempt,
                    error_summary=str(exc),
                )
                if self._writer:
                    self._writer.write_error("remedy", vid, remedy_input, exc, attempt=attempt)
                previous_attempts.append(remediation)
                attempt += 1
                continue

            if remediation.scan_passed:
                console.print(f"[green]  [{vid}] Remedy scan PASSED[/green]")
            else:
                console.print(f"[yellow]  [{vid}] Remedy scan FAILED[/yellow]")
                previous_attempts.append(remediation)
                attempt += 1
                continue

            # ── Review ────────────────────────────────────────────────
            console.print(f"[bold cyan]  [{vid}] Stage 3/4: Review[/bold cyan]")
            review_input = ReviewInput(
                vulnerability=vulnerability,
                remediation_attempt=remediation,
                triage_decision=triage_decision,
            )
            try:
                review_verdict = self.review.process(review_input)
                if self._writer:
                    self._writer.write(
                        "review", vid, review_input, review_verdict,
                        attempt=review_retries if review_retries > 0 else None,
                    )
            except Exception as exc:
                console.print(f"[red]  [{vid}] Review error: {exc}[/red]")
                review_verdict = ReviewVerdict(
                    finding_id=vid,
                    is_optimal=False,
                    approve=True,
                    feedback=f"Review error, auto-approving: {exc}",
                    security_score=5,
                )
                if self._writer:
                    self._writer.write_error("review", vid, review_input, exc)

            if review_verdict.approve:
                console.print(
                    f"[green]  [{vid}] Review → APPROVED "
                    f"(score={review_verdict.security_score})[/green]"
                )
                break
            else:
                console.print(
                    f"[yellow]  [{vid}] Review → REJECTED: "
                    f"{review_verdict.feedback or 'no feedback'}[/yellow]"
                )
                if review_retries < self.max_review_retries and attempt < self.max_remedy_attempts:
                    review_feedback = review_verdict.feedback or "Review rejected, try alternative."
                    if review_verdict.suggested_improvements:
                        review_feedback += " Suggestions: " + "; ".join(
                            review_verdict.suggested_improvements
                        )
                    previous_attempts.append(remediation)
                    attempt += 1
                    review_retries += 1
                    continue
                else:
                    break

        # ── Stage 4: QA ───────────────────────────────────────────────
        qa_result = None
        if remediation is not None and remediation.scan_passed and review_verdict is not None:
            console.print(f"[bold cyan]  [{vid}] Stage 4/4: QA Validation[/bold cyan]")
            qa_input = QAInput(
                vulnerability=vulnerability,
                remediation_attempt=remediation,
                review_verdict=review_verdict,
            )
            try:
                qa_result = self.qa.process(qa_input)
                if self._writer:
                    self._writer.write("qa", vid, qa_input, qa_result)
                safe_str = "SAFE" if qa_result.safe else "UNSAFE"
                color = "green" if qa_result.safe else "red"
                console.print(
                    f"[{color}]  [{vid}] QA → {safe_str} "
                    f"(recommendation={qa_result.recommendation})[/{color}]"
                )
            except Exception as exc:
                console.print(f"[red]  [{vid}] QA error: {exc}[/red]")
                if self._writer:
                    self._writer.write_error("qa", vid, qa_input, exc)

        # ── Final status ──────────────────────────────────────────────
        if qa_result is not None and qa_result.safe:
            final_status = "success"
        elif remediation is not None and remediation.scan_passed:
            final_status = "failed"
        else:
            final_status = "failed"

        elapsed = time.time() - t0
        console.print(
            f"[bold]  [{vid}] Pipeline complete → {final_status.upper()} "
            f"({elapsed:.1f}s)[/bold]"
        )

        return FindingResult(
            vulnerability=vulnerability,
            triage=triage_decision,
            remediation=remediation,
            review=review_verdict,
            qa=qa_result,
            final_status=final_status,
            total_duration=elapsed,
            timestamp=datetime.now().isoformat(timespec="seconds"),
        )