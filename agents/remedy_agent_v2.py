"""
Remedy Agent V2: Generates and applies a fix, then calls ReviewAgentV2
(which chains to QA) for pre-scan approval.

V2 flow for a single attempt:
  1. Execute the LLM tool-calling session (same as v1 — commands run on host).
  2. Call ReviewAgentV2.process() which runs Review → QA.
  3. If BOTH approve  → run verification scan.
     - Scan passes  → return success (pipeline goes straight to aggregation).
     - Scan fails   → return failure  (pipeline retries with a new fix).
  4. If either rejects → return failure with feedback (pipeline retries).

This file does NOT modify the original RemedyAgent — it wraps/composes it.
"""

from __future__ import annotations

import time
from typing import List, Optional

from rich.console import Console

from agents.remedy_agent import RemedyAgent
from agents.review_agent_v2 import ReviewAgentV2
from schemas import (
    PreApprovalResult,
    RemedyInput,
    RemediationAttempt,
    ReviewInput,
    Vulnerability,
)

console = Console()


class RemedyAgentV2:
    """
    V2 Remedy agent: fix → Review+QA approval → scan.

    Wraps the existing RemedyAgent for fix generation and adds a
    ReviewAgentV2 call before running the verification scan.
    """

    def __init__(
        self,
        remedy_agent: RemedyAgent,
        review_agent_v2: ReviewAgentV2,
    ):
        self.remedy_agent = remedy_agent
        self.review_v2 = review_agent_v2

    def process(
        self,
        input_data: RemedyInput,
    ) -> tuple[RemediationAttempt, Optional[PreApprovalResult]]:
        """
        Generate a fix, get approval, then scan.

        Returns:
            (remediation_attempt, pre_approval_result)
            - pre_approval_result is None only when the fix generation itself
              errors out before reaching the review stage.
        """
        vuln = input_data.vulnerability
        vid = vuln.id
        start = time.time()

        # ── Step 1: Generate & apply the fix (tool-calling LLM) ──────
        console.print(
            f"[bold cyan]  [{vid}] V2 Remedy: generating fix "
            f"(attempt {input_data.attempt_number})[/bold cyan]"
        )
        try:
            attempt = self.remedy_agent.process(input_data)
        except Exception as exc:
            console.print(f"[red]  [{vid}] Remedy generation error: {exc}[/red]")
            return (
                RemediationAttempt(
                    finding_id=vid,
                    attempt_number=input_data.attempt_number,
                    error_summary=str(exc),
                ),
                None,
            )

        # ── Step 2: Call Review → QA for pre-scan approval ───────────
        console.print(
            f"[bold cyan]  [{vid}] V2 Remedy: requesting Review+QA approval[/bold cyan]"
        )
        review_input = ReviewInput(
            vulnerability=vuln,
            remediation_attempt=attempt,
            triage_decision=input_data.triage_decision,
        )
        approval = self.review_v2.process(review_input)

        if not approval.approved:
            console.print(
                f"[yellow]  [{vid}] V2 Remedy: pre-approval REJECTED — "
                f"{approval.rejection_reason or 'no reason'}[/yellow]"
            )
            attempt.scan_passed = False
            attempt.success = False
            attempt.duration = time.time() - start
            return attempt, approval

        # ── Step 3: Verification scan ────────────────────────────────
        console.print(f"[bold cyan]  [{vid}] V2 Remedy: running verification scan[/bold cyan]")
        scan_result = self.remedy_agent._tool_scan(vuln)
        attempt.scan_passed = bool(scan_result.get("pass"))
        attempt.scan_output = scan_result.get("summary") or scan_result.get("raw")
        attempt.success = attempt.scan_passed

        if attempt.scan_passed:
            console.print(f"[green]  [{vid}] V2 Remedy: scan PASSED[/green]")
        else:
            console.print(f"[yellow]  [{vid}] V2 Remedy: scan FAILED[/yellow]")

        attempt.duration = time.time() - start
        return attempt, approval
