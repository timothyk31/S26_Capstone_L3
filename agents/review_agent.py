"""
Review Agent: validates remediation quality and optimality using an LLM only (no tools).
Uses OpenRouter (default: Nvidia Nemotron 3 Nano); configurable via env.

Env: OPENROUTER_API_KEY (required), OPENROUTER_BASE_URL, REVIEW_AGENT_MODEL.
Default model: nvidia/nemotron-3-nano-30b-a3b:free (use nvidia/nemotron-3-nano-30b-a3b for paid).
"""

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from schemas import (
    FindingResult,
    RemediationAttempt,
    ReviewInput,
    ReviewVerdict,
    TriageDecision,
    Vulnerability,
)


# ---------------------------------------------------------------------------
# Configuration (env)
# ---------------------------------------------------------------------------
# Required: OPENROUTER_API_KEY
# Optional: OPENROUTER_BASE_URL (default https://openrouter.ai/api/v1)
# Optional: REVIEW_AGENT_MODEL (default Nvidia Nemotron 3 Nano on OpenRouter)
DEFAULT_OPENROUTER_BASE = "https://openrouter.ai/api/v1"
# Client recommended Nemotron; free variant for dev, paid for production
DEFAULT_REVIEW_MODEL = "nvidia/nemotron-3-nano-30b-a3b:free"


def _get_config() -> Tuple[str, str, str]:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError(
            "OPENROUTER_API_KEY is required. Add it to .env (get a key from https://openrouter.ai/keys)."
        )
    base_url = (os.getenv("OPENROUTER_BASE_URL") or DEFAULT_OPENROUTER_BASE).rstrip("/")
    model = os.getenv("OPENROUTER_MODEL") or os.getenv("REVIEW_AGENT_MODEL") or DEFAULT_REVIEW_MODEL
    return api_key, base_url, model


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------
def _build_review_prompt(input_data: ReviewInput) -> str:
    """Turn ReviewInput into a single text prompt for the LLM."""
    v = input_data.vulnerability
    attempt = input_data.remediation_attempt
    triage = input_data.triage_decision

    lines = [
        "You are a security remediation reviewer. Evaluate the following proposed remediation plan for quality and correctness.",
        "",
        "## Vulnerability",
        f"- ID: {v.id}",
        f"- Title: {v.title}",
        f"- Severity: {v.severity}",
        f"- Description: {v.description or '(none)'}",
        f"- Recommendation: {v.recommendation or '(none)'}",
        "",
        "## Triage",
        f"- Risk level: {triage.risk_level}",
        f"- Reason: {triage.reason}",
        "",
        "## Proposed Remediation Plan",
        "(NOTE: This plan has NOT been executed yet. Evaluate whether it WOULD resolve the vulnerability if executed correctly.)",
        "",
    ]
    if attempt.llm_verdict:
        lines.append(attempt.llm_verdict.message)
    # Previous review verdicts (if this is a retry)
    if input_data.previous_verdicts:
        lines.extend(["", "## Previous Review History"])
        for i, pv in enumerate(input_data.previous_verdicts, 1):
            lines.append(f"- Review #{i}: approve={pv.approve}, score={pv.security_score}")
            if pv.concerns:
                lines.append(f"  Concerns raised: {'; '.join(pv.concerns[:5])}")
            if pv.suggested_improvements:
                lines.append(f"  Improvements requested: {'; '.join(pv.suggested_improvements[:5])}")
            if pv.feedback:
                lines.append(f"  Feedback: {pv.feedback[:200]}")
        lines.append("")
        lines.append("Check whether the current fix addresses the issues raised in previous reviews.")

    lines.extend([
        "",
        "Respond with a single JSON object (no markdown, no extra text) with these exact keys:",
        "finding_id (string), is_optimal (bool), approve (bool), feedback (string or null),",
        "concerns (list of strings), suggested_improvements (list of strings),",
        "security_score (integer 1-10 or null), best_practices_followed (bool).",
        "",
        "IMPORTANT: Set approve=true if the proposed plan would functionally resolve the vulnerability",
        "when executed. Only set approve=false if the plan is actively harmful, introduces new security",
        "risks, or would fail to address the vulnerability. Do NOT reject because commands have not been",
        "run yet — this is a plan review before execution.",
        "Use is_optimal, concerns, and suggested_improvements to note areas for improvement",
        "without blocking the fix from proceeding.",
    ])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LLM call (single completion, no tools)
# ---------------------------------------------------------------------------
def _call_llm(
    user_prompt: str,
    system_prompt: str,
    *,
    model: str,
    base_url: str,
    api_key: str,
    timeout: int = 90,
    metrics_tracker=None,
) -> tuple[str, Dict[str, Any], Optional[Dict[str, Any]], float]:
    endpoint = f"{base_url.rstrip('/')}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    start_time = None
    if metrics_tracker is not None:
        start_time = metrics_tracker.start_call()
    try:
        _t0 = time.time()
        resp = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
        _api_duration = time.time() - _t0
        if resp.status_code >= 400:
            if metrics_tracker is not None:
                metrics_tracker.record_call(None, agent="review", model=model, start_time=start_time, error=True, error_message=f"HTTP {resp.status_code}")
            raise RuntimeError(f"OpenRouter API error {resp.status_code}: {resp.text}")
        data = resp.json()
        if metrics_tracker is not None:
            metrics_tracker.record_call(data, agent="review", model=model, start_time=start_time)
    except Exception:
        if metrics_tracker is not None and start_time is not None:
            metrics_tracker.record_call(None, agent="review", model=model, start_time=start_time, error=True, error_message="request exception")
        raise
    choice = data.get("choices", [{}])[0]
    message = choice.get("message", {})
    content = message.get("content") or ""
    usage = data.get("usage")
    return content.strip(), message, usage, _api_duration


def _parse_verdict(raw: str, finding_id: str) -> ReviewVerdict:
    """Parse LLM response into ReviewVerdict; fallback on failure."""
    # Try to extract JSON (sometimes model wraps in markdown)
    text = raw.strip()
    json_match = re.search(r"\{[\s\S]*\}", text)
    if json_match:
        text = json_match.group(0)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return ReviewVerdict(
            finding_id=finding_id,
            is_optimal=False,
            approve=False,
            feedback=f"Review output was not valid JSON. Raw: {raw[:200]}...",
            concerns=["Could not parse LLM response"],
            suggested_improvements=[],
            security_score=None,
            best_practices_followed=False,
        )
    # Normalize types
    concerns = obj.get("concerns")
    if not isinstance(concerns, list):
        concerns = [str(c) for c in (concerns or [])] if concerns else []
    improvements = obj.get("suggested_improvements")
    if not isinstance(improvements, list):
        improvements = [str(i) for i in (improvements or [])] if improvements else []
    security_score = obj.get("security_score")
    if security_score is not None and not isinstance(security_score, int):
        try:
            security_score = int(security_score)
        except (TypeError, ValueError):
            security_score = None
    return ReviewVerdict(
        finding_id=str(obj.get("finding_id", finding_id)),
        is_optimal=bool(obj.get("is_optimal", False)),
        approve=bool(obj.get("approve", False)),
        feedback=obj.get("feedback") if obj.get("feedback") else None,
        concerns=concerns,
        suggested_improvements=improvements,
        security_score=security_score,
        best_practices_followed=bool(obj.get("best_practices_followed", True)),
    )


# ---------------------------------------------------------------------------
# Review Agent
# ---------------------------------------------------------------------------
class ReviewAgent:
    """
    Review agent: input -> LLM (read-only) -> ReviewVerdict.
    No tools; uses OpenRouter (default Nvidia Nemotron 3 Nano).
    """

    SYSTEM_PROMPT = (
        "You are a pragmatic security remediation reviewer for Linux systems. "
        "You are reviewing a PROPOSED PLAN before execution. Evaluate whether the plan "
        "would resolve the vulnerability if executed correctly. Do NOT reject because "
        "commands have not been run yet — they will be executed after your approval.\n\n"
        "APPROVAL GUIDELINES:\n"
        "- APPROVE if the proposed plan would resolve the vulnerability, even if the approach is not perfectly optimal.\n"
        "- APPROVE if the plan describes correct commands and configuration changes for the target vulnerability.\n"
        "- REJECT only if the plan is actively harmful, introduces serious security risks, or clearly would not address the vulnerability.\n"
        "- Imperfect but workable plans should be APPROVED with suggestions for improvement noted in feedback.\n\n"
        "You respond only with a JSON object with the requested keys; no markdown code fences or extra text."
    )

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        request_timeout: int = 90,
        metrics_tracker=None,
        transcript_dir: Optional[str | Path] = None,
    ):
        if api_key is None and base_url is None and model is None:
            api_key, base_url, model = _get_config()
        self.api_key = api_key or _get_config()[0]
        self.base_url = (base_url or os.getenv("OPENROUTER_BASE_URL") or DEFAULT_OPENROUTER_BASE).rstrip("/")
        self.model = model or os.getenv("OPENROUTER_MODEL") or os.getenv("REVIEW_AGENT_MODEL") or DEFAULT_REVIEW_MODEL
        self.request_timeout = request_timeout
        self.metrics_tracker = metrics_tracker
        self._transcript_dir: Optional[Path] = Path(transcript_dir) if transcript_dir else None
        if self._transcript_dir:
            self._transcript_dir.mkdir(parents=True, exist_ok=True)

    def process(self, input_data: ReviewInput, *, attempt: int = 1) -> ReviewVerdict:
        """Run review on one finding: LLM analyzes input and returns a verdict."""
        user_prompt = _build_review_prompt(input_data)
        raw, full_message, usage, api_duration = _call_llm(
            user_prompt,
            self.SYSTEM_PROMPT,
            model=self.model,
            base_url=self.base_url,
            api_key=self.api_key,
            timeout=self.request_timeout,
            metrics_tracker=self.metrics_tracker,
        )

        # Save transcript if transcript_dir is set
        if self._transcript_dir:
            vid = input_data.vulnerability.id
            # Capture reasoning/thinking tokens if present
            reasoning = (
                full_message.get("reasoning_content")
                or full_message.get("reasoning")
                or full_message.get("thinking")
            )

            transcript_data = {
                "finding_id": vid,
                "model": self.model,
                "attempt": attempt,
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "assistant_message": {
                    "content": raw,
                    **(({"reasoning": reasoning}) if reasoning else {}),
                },
                "_raw_message": dict(full_message),
                "usage": usage,
                "timing": {
                    "api_call_seconds": round(api_duration, 3),
                },
            }
            tp = self._transcript_dir / f"review_transcript_{vid}_attempt{attempt}.json"
            tp.write_text(json.dumps(transcript_data, indent=2, default=str), encoding="utf-8")

        return _parse_verdict(raw, input_data.vulnerability.id)

    # ------------------------------------------------------------------
    # Output: PDF report
    # ------------------------------------------------------------------
    def write_results_pdf(
        self,
        results: List[FindingResult],
        output_path: str | Path = "reports/review_report.pdf",
        *,
        target_host: str = "unknown",
        title: str = "Review Agent Report",
    ) -> Path:
        """
        Generate a PDF report summarising all Review Agent outputs.

        Only includes findings that reached the Review stage.
        """
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        page_size = landscape(letter)
        doc = SimpleDocTemplate(
            str(out),
            pagesize=page_size,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            rightMargin=0.5 * inch,
        )

        styles = getSampleStyleSheet()
        elements: list = []

        title_style = ParagraphStyle("RvTitle", parent=styles["Title"], fontSize=20, spaceAfter=6)
        subtitle_style = ParagraphStyle("RvSub", parent=styles["Normal"], fontSize=10, textColor=colors.grey, spaceAfter=14)
        section_style = ParagraphStyle("RvSec", parent=styles["Heading2"], fontSize=14, spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#1a1a2e"))
        cell_style = ParagraphStyle("RvCell", parent=styles["Normal"], fontSize=8, leading=10)
        body_style = ParagraphStyle("RvBody", parent=styles["Normal"], fontSize=9, leading=12)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elements.append(Paragraph(title, title_style))
        elements.append(Paragraph(f"Target: {target_host} &nbsp;|&nbsp; Generated: {now}", subtitle_style))

        reviewed = [r for r in results if r.review is not None]
        approved = sum(1 for r in reviewed if r.review and r.review.approve)
        rejected = len(reviewed) - approved
        scores = [r.review.security_score for r in reviewed if r.review and r.review.security_score is not None]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0

        elements.append(Paragraph("Review Summary", section_style))
        summary_data = [
            ["Total Reviewed", str(len(reviewed))],
            ["Approved", str(approved)],
            ["Rejected", str(rejected)],
            ["Avg Security Score", str(avg_score)],
        ]
        summary_table = Table(summary_data, colWidths=[3 * inch, 1.5 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fff3e0")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 14))

        if not reviewed:
            elements.append(Paragraph("No findings reached the Review stage.", body_style))
        else:
            elements.append(Paragraph("Per-Finding Review Details", section_style))
            table_data = [
                [
                    Paragraph("<b>ID</b>", cell_style),
                    Paragraph("<b>Title</b>", cell_style),
                    Paragraph("<b>Approve</b>", cell_style),
                    Paragraph("<b>Optimal</b>", cell_style),
                    Paragraph("<b>Score</b>", cell_style),
                    Paragraph("<b>Feedback</b>", cell_style),
                    Paragraph("<b>Concerns</b>", cell_style),
                    Paragraph("<b>Improvements</b>", cell_style),
                ],
            ]
            for r in reviewed:
                rv = r.review
                assert rv is not None
                approve_text = '<font color="#27ae60">YES</font>' if rv.approve else '<font color="#e74c3c">NO</font>'
                optimal_text = "Yes" if rv.is_optimal else "No"
                score_text = str(rv.security_score) if rv.security_score is not None else "\u2014"
                concerns_text = "<br/>".join(rv.concerns) or "\u2014"
                improvements_text = "<br/>".join(rv.suggested_improvements) or "\u2014"
                table_data.append([
                    Paragraph(r.vulnerability.id, cell_style),
                    Paragraph(r.vulnerability.title or "\u2014", cell_style),
                    Paragraph(approve_text, cell_style),
                    Paragraph(optimal_text, cell_style),
                    Paragraph(score_text, cell_style),
                    Paragraph(rv.feedback or "\u2014", cell_style),
                    Paragraph(concerns_text, cell_style),
                    Paragraph(improvements_text, cell_style),
                ])

            col_widths = [0.7 * inch, 1.4 * inch, 0.55 * inch, 0.55 * inch, 0.45 * inch, 2.5 * inch, 1.8 * inch, 2.05 * inch]
            t = Table(table_data, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(t)

        doc.build(elements)
        return out