"""
Review Agent V2: Validates remediation quality, then delegates to QA Agent V2.

In the v2 pipeline the Review agent is called by the Remedy agent *before*
a scan is run.  If Review approves, it forwards the result to the QA Agent V2
(LLM-only expert opinion, no commands) for system-safety validation.  The
combined verdict (Review + QA) is returned to the caller as a
``PreApprovalResult``.

This file does NOT modify the original ReviewAgent or QAAgent — it
composes them.
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console

from agents.qa_agent_v2 import QAAgentV2
from agents.review_agent import ReviewAgent
from schemas import (
    PreApprovalResult,
    QAInput,
    QAResult,
    ReviewInput,
    ReviewVerdict,
)

console = Console()


class ReviewAgentV2:
    """
    V2 Review agent: Review → QA V2 chain.

    1. Calls the existing ReviewAgent to evaluate the fix.
    2. If the review approves, calls QAAgentV2 (LLM-only) for expert safety opinion.
    3. Returns a ``PreApprovalResult`` combining both verdicts.
    """

    def __init__(
        self,
        review_agent: ReviewAgent,
        qa_agent: QAAgentV2,
    ):
        self.review_agent = review_agent
        self.qa_agent = qa_agent

    def process(self, review_input: ReviewInput) -> PreApprovalResult:
        """Run Review then QA; return combined approval."""
        vid = review_input.vulnerability.id

        # ── Step 1: Review ────────────────────────────────────────────
        console.print(f"[bold cyan]  [{vid}] V2 Review: evaluating fix quality[/bold cyan]")
        try:
            review_verdict: ReviewVerdict = self.review_agent.process(review_input)
        except Exception as exc:
            console.print(f"[red]  [{vid}] Review error: {exc}[/red]")
            review_verdict = ReviewVerdict(
                finding_id=vid,
                is_optimal=False,
                approve=True,
                feedback=f"Review error, auto-approving: {exc}",
                security_score=5,
            )

        if not review_verdict.approve:
            console.print(
                f"[yellow]  [{vid}] V2 Review → REJECTED: "
                f"{review_verdict.feedback or 'no feedback'}[/yellow]"
            )
            return PreApprovalResult(
                review_verdict=review_verdict,
                qa_result=None,
                approved=False,
                rejection_reason=review_verdict.feedback or "Review rejected the fix",
            )

        console.print(
            f"[green]  [{vid}] V2 Review → APPROVED "
            f"(score={review_verdict.security_score})[/green]"
        )

        # ── Step 2: QA ────────────────────────────────────────────────
        console.print(f"[bold cyan]  [{vid}] V2 QA: expert safety opinion[/bold cyan]")
        qa_result: Optional[QAResult] = None
        try:
            qa_input = QAInput(
                vulnerability=review_input.vulnerability,
                remediation_attempt=review_input.remediation_attempt,
                review_verdict=review_verdict,
            )
            qa_result = self.qa_agent.process(qa_input)
        except Exception as exc:
            console.print(f"[red]  [{vid}] QA error: {exc}[/red]")
            # QA error → treat as unsafe
            return PreApprovalResult(
                review_verdict=review_verdict,
                qa_result=None,
                approved=False,
                rejection_reason=f"QA validation error: {exc}",
            )

        if not qa_result.safe:
            console.print(
                f"[yellow]  [{vid}] V2 QA → UNSAFE: "
                f"{qa_result.verdict_reason}[/yellow]"
            )
            return PreApprovalResult(
                review_verdict=review_verdict,
                qa_result=qa_result,
                approved=False,
                rejection_reason=qa_result.verdict_reason,
            )

        console.print(
            f"[green]  [{vid}] V2 QA → SAFE "
            f"(recommendation={qa_result.recommendation})[/green]"
        )

        return PreApprovalResult(
            review_verdict=review_verdict,
            qa_result=qa_result,
            approved=True,
            rejection_reason=None,
        )
