"""
Remedy Agent V2: Plan → Consult → Apply workflow.

V2 flow for a single attempt:
  1. Ask remedy LLM to describe its proposed fix (no execution).
  2. Pass the plan to ReviewAgentV2 (Review → QA) for advisory feedback.
  3. Inject the advisory feedback into the RemedyInput and execute the fix
     via the standard RemedyAgent tool-calling session (which also scans).

This file does NOT modify the original RemedyAgent — it wraps/composes it.
"""

from __future__ import annotations

import time
from typing import Optional

from rich.console import Console

from agents.remedy_agent import RemedyAgent
from agents.review_agent_v2 import ReviewAgentV2
from schemas import (
    PreApprovalResult,
    RemedyInput,
    RemediationAttempt,
    ReviewInput,
    ToolVerdict,
    Vulnerability,
)

console = Console()


class RemedyAgentV2:
    """
    V2 Remedy agent: plan → consult Review+QA → apply fix → scan.

    Wraps the existing RemedyAgent for fix planning and execution,
    and ReviewAgentV2 for pre-apply consultation.
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
        Plan a fix, consult Review+QA, then apply with feedback.

        Returns:
            (remediation_attempt, pre_approval_result)
            - pre_approval_result is None only when plan generation errors out.
        """
        vuln = input_data.vulnerability
        vid = vuln.id
        start = time.time()

        # ── Step 1: Generate fix plan (no execution) ──────────────
        console.print(
            f"[bold cyan]  [{vid}] V2 Remedy: planning fix "
            f"(attempt {input_data.attempt_number})[/bold cyan]"
        )
        try:
            plan_text = self.remedy_agent.plan_fix(input_data)
        except Exception as exc:
            console.print(f"[red]  [{vid}] Plan generation error: {exc}[/red]")
            return (
                RemediationAttempt(
                    finding_id=vid,
                    attempt_number=input_data.attempt_number,
                    error_summary=str(exc),
                ),
                None,
            )

        # ── Step 2: Consult Review+QA on the plan ─────────────────
        console.print(
            f"[bold cyan]  [{vid}] V2 Remedy: consulting Review+QA on plan[/bold cyan]"
        )
        stub_attempt = RemediationAttempt(
            finding_id=vid,
            attempt_number=input_data.attempt_number,
            llm_verdict=ToolVerdict(message=plan_text, resolved=False),
        )
        review_input = ReviewInput(
            vulnerability=vuln,
            remediation_attempt=stub_attempt,
            triage_decision=input_data.triage_decision,
            previous_verdicts=input_data.previous_review_verdicts,
        )
        advisory = self.review_v2.process(
            review_input, attempt=input_data.attempt_number
        )

        # ── Step 3: Only inject feedback if advisory FAILED ───────
        if not advisory.approved:
            console.print(
                f"[yellow]  [{vid}] V2 Remedy: advisory rejected — "
                f"injecting feedback[/yellow]"
            )
            # Prior feedback is already carried in previous_review_verdicts —
            # only include current-round rejection details to avoid duplication.
            feedback_parts = [f"YOUR PROPOSED PLAN WAS REJECTED: {plan_text[:400]}"]

            rv = advisory.review_verdict
            if rv.feedback:
                feedback_parts.append(f"Review: {rv.feedback}")
            if rv.suggested_improvements:
                feedback_parts.append(
                    "Required: " + "; ".join(rv.suggested_improvements)
                )
            if rv.concerns:
                feedback_parts.append(
                    "Concerns: " + "; ".join(rv.concerns)
                )
            if advisory.qa_result and advisory.qa_result.verdict_reason:
                feedback_parts.append(
                    f"QA: {advisory.qa_result.verdict_reason}"
                )

            enriched_input = input_data.model_copy(
                update={
                    "review_feedback": "\n".join(feedback_parts),
                    "plan_text": plan_text,
                }
            )
        else:
            enriched_input = input_data.model_copy(
                update={"plan_text": plan_text}
            )

        # ── Step 4: Apply the fix with feedback (tool-calling + scan) ──
        console.print(
            f"[bold cyan]  [{vid}] V2 Remedy: applying fix[/bold cyan]"
        )
        try:
            attempt = self.remedy_agent.process(enriched_input)
        except Exception as exc:
            console.print(f"[red]  [{vid}] Remedy execution error: {exc}[/red]")
            return (
                RemediationAttempt(
                    finding_id=vid,
                    attempt_number=input_data.attempt_number,
                    error_summary=str(exc),
                ),
                advisory,
            )

        attempt.duration = time.time() - start
        return attempt, advisory
