#!/usr/bin/env python3
"""
pipeline_pdf_writer.py — Generate a comprehensive PDF report from V2 pipeline results.

Produces a landscape-oriented report with:
  1. Executive summary (total findings, outcomes, LLM usage)
  2. Per-finding tables grouped by final_status
  3. Agent-level detail for each finding (triage, remedy, review, QA)
  4. LLM metrics breakdown

The visual style matches the existing triage_report.pdf.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from schemas import V2FindingResult


# ── Helpers ─────────────────────────────────────────────────────────────────

_SEV_LABEL = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}


def _sev(severity: str) -> str:
    return _SEV_LABEL.get(severity, severity)


def _status_color(status: str):
    from reportlab.lib import colors

    return {
        "success": colors.HexColor("#27ae60"),
        "failed": colors.HexColor("#e74c3c"),
        "requires_human_review": colors.HexColor("#f39c12"),
        "discarded": colors.HexColor("#95a5a6"),
    }.get(status, colors.black)


def _risk_color(level: str):
    from reportlab.lib import colors

    return {
        "low": colors.HexColor("#27ae60"),
        "medium": colors.HexColor("#f39c12"),
        "high": colors.HexColor("#e67e22"),
        "critical": colors.HexColor("#e74c3c"),
    }.get(level.lower(), colors.black)


def _trunc(text: str, max_len: int = 120) -> str:
    """Truncate long text for table cells."""
    if not text:
        return "\u2014"
    return (text[:max_len] + "\u2026") if len(text) > max_len else text


def _safe_str(val: Any, default: str = "\u2014") -> str:
    if val is None or val == "":
        return default
    return str(val)


def _bool_icon(val: Optional[bool]) -> str:
    if val is True:
        return "\u2713"  # checkmark
    if val is False:
        return "\u2717"  # cross
    return "\u2014"


# ── Core ────────────────────────────────────────────────────────────────────

def write_pipeline_pdf(
    results: List["V2FindingResult"],
    output_path: str | Path = "reports/pipeline_report.pdf",
    *,
    target_host: str = "unknown",
    title: str = "OpenSCAP Multi-Agent Pipeline Report",
    model_metadata: Optional[Dict[str, str]] = None,
) -> Path:
    """
    Generate a comprehensive PDF from the full V2 pipeline results.

    Parameters
    ----------
    results : list[V2FindingResult]
        Complete pipeline results (same objects logged to Braintrust).
    output_path : str | Path
        Where to write the PDF.
    target_host : str
        The scanned host name.
    title : str
        Report title.
    model_metadata : dict | None
        Agent name → model string mapping.

    Returns
    -------
    Path  – resolved output path.
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        PageBreak,
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

    # ── Custom styles (matching triage_report) ────────────────────────
    title_style = ParagraphStyle(
        "PipelineTitle", parent=styles["Title"], fontSize=20, spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "PipelineSubtitle", parent=styles["Normal"], fontSize=10,
        textColor=colors.grey, spaceAfter=14,
    )
    section_style = ParagraphStyle(
        "PipelineSectionHeader", parent=styles["Heading2"], fontSize=14,
        spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#1a1a2e"),
    )
    subsection_style = ParagraphStyle(
        "PipelineSubSection", parent=styles["Heading3"], fontSize=11,
        spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#2c3e50"),
    )
    body_style = ParagraphStyle(
        "PipelineBody", parent=styles["Normal"], fontSize=9, leading=12,
    )
    cell_style = ParagraphStyle(
        "PipelineCell", parent=styles["Normal"], fontSize=8, leading=10,
    )
    small_cell = ParagraphStyle(
        "PipelineSmallCell", parent=styles["Normal"], fontSize=7, leading=9,
    )

    # ── Shared table-styling helper ───────────────────────────────────
    def _kv_table(data, col_widths=None):
        """Two-column key/value table with standard styling."""
        widths = col_widths or [3 * inch, 2 * inch]
        t = Table(data, colWidths=widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f5")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        return t

    def _data_table(data, col_widths, repeat_header=True):
        """Multi-column data table with header styling."""
        t = Table(data, colWidths=col_widths, repeatRows=1 if repeat_header else 0)
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
        return t

    # ── Title block ───────────────────────────────────────────────────
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph(title, title_style))
    elements.append(Paragraph(
        f"Target: {target_host} &nbsp;|&nbsp; Generated: {now}",
        subtitle_style,
    ))

    # ── Models used ───────────────────────────────────────────────────
    if model_metadata:
        elements.append(Paragraph("Models Used", section_style))
        model_rows = [[k.capitalize(), v or "\u2014"] for k, v in model_metadata.items()]
        elements.append(_kv_table(model_rows))
        elements.append(Spacer(1, 14))

    # ── Executive summary ─────────────────────────────────────────────
    total = len(results)
    successes = sum(1 for r in results if r.final_status == "success")
    failures = sum(1 for r in results if r.final_status == "failed")
    human_rev = sum(1 for r in results if r.final_status == "requires_human_review")
    discarded = sum(1 for r in results if r.final_status == "discarded")
    total_dur = sum(r.total_duration for r in results)
    success_rate = (successes / total * 100) if total else 0

    elements.append(Paragraph("Pipeline Summary", section_style))
    summary_data = [
        ["Total Findings Processed", str(total)],
        ["Remediated Successfully", str(successes)],
        ["Failed Remediation", str(failures)],
        ["Requires Human Review", str(human_rev)],
        ["Discarded / Blocked", str(discarded)],
        ["Success Rate", f"{success_rate:.1f}%"],
        ["Total Duration", f"{total_dur:.1f}s"],
    ]
    elements.append(_kv_table(summary_data))
    elements.append(Spacer(1, 14))

    # ── Aggregate LLM metrics ─────────────────────────────────────────
    agg_calls = sum((r.llm_metrics or {}).get("llm_calls", 0) for r in results)
    agg_errors = sum((r.llm_metrics or {}).get("llm_errors", 0) for r in results)
    agg_dur = sum((r.llm_metrics or {}).get("llm_duration_s", 0.0) for r in results)
    agg_prompt = sum((r.llm_metrics or {}).get("prompt_tokens", 0) for r in results)
    agg_compl = sum((r.llm_metrics or {}).get("completion_tokens", 0) for r in results)
    agg_total_tok = sum((r.llm_metrics or {}).get("total_tokens", 0) for r in results)
    agg_cost = sum((r.llm_metrics or {}).get("estimated_cost_usd", 0.0) for r in results)

    elements.append(Paragraph("LLM Usage (Aggregate)", section_style))
    llm_data = [
        ["Total LLM Calls", str(agg_calls)],
        ["Total Errors", str(agg_errors)],
        ["Total LLM Duration", f"{agg_dur:.1f}s"],
        ["Prompt Tokens", f"{agg_prompt:,}"],
        ["Completion Tokens", f"{agg_compl:,}"],
        ["Total Tokens", f"{agg_total_tok:,}"],
        ["Estimated Cost (USD)", f"${agg_cost:.4f}"],
    ]
    elements.append(_kv_table(llm_data))
    elements.append(Spacer(1, 8))

    # Per-agent LLM breakdown
    agent_totals: Dict[str, Dict[str, float]] = {}
    for r in results:
        pa = (r.llm_metrics or {}).get("per_agent", {})
        for agent_name, stats in pa.items():
            if agent_name not in agent_totals:
                agent_totals[agent_name] = {
                    "llm_calls": 0, "wall_time_s": 0.0,
                    "prompt_tokens": 0, "completion_tokens": 0,
                    "total_tokens": 0, "estimated_cost_usd": 0.0, "errors": 0,
                }
            for k in agent_totals[agent_name]:
                agent_totals[agent_name][k] += stats.get(k, 0)

    if agent_totals:
        elements.append(Paragraph("LLM Usage by Agent", subsection_style))
        agent_header = [
            Paragraph("<b>Agent</b>", cell_style),
            Paragraph("<b>Calls</b>", cell_style),
            Paragraph("<b>Errors</b>", cell_style),
            Paragraph("<b>Duration (s)</b>", cell_style),
            Paragraph("<b>Prompt Tok</b>", cell_style),
            Paragraph("<b>Compl Tok</b>", cell_style),
            Paragraph("<b>Total Tok</b>", cell_style),
            Paragraph("<b>Cost (USD)</b>", cell_style),
        ]
        agent_rows = [agent_header]
        for agent_name in ["triage", "remedy", "review", "qa"]:
            s = agent_totals.get(agent_name)
            if s is None:
                continue
            agent_rows.append([
                Paragraph(agent_name.capitalize(), cell_style),
                Paragraph(str(int(s["llm_calls"])), cell_style),
                Paragraph(str(int(s["errors"])), cell_style),
                Paragraph(f"{s['wall_time_s']:.1f}", cell_style),
                Paragraph(f"{int(s['prompt_tokens']):,}", cell_style),
                Paragraph(f"{int(s['completion_tokens']):,}", cell_style),
                Paragraph(f"{int(s['total_tokens']):,}", cell_style),
                Paragraph(f"${s['estimated_cost_usd']:.4f}", cell_style),
            ])
        agent_widths = [1.2*inch, 0.6*inch, 0.6*inch, 1.0*inch, 1.0*inch, 1.0*inch, 1.0*inch, 1.0*inch]
        elements.append(_data_table(agent_rows, agent_widths))
        elements.append(Spacer(1, 14))

    # ── Findings by status ────────────────────────────────────────────
    _STATUS_ORDER = [
        ("Remediated Successfully", "success"),
        ("Failed Remediation", "failed"),
        ("Requires Human Review", "requires_human_review"),
        ("Discarded / Blocked", "discarded"),
    ]

    for section_header, status_key in _STATUS_ORDER:
        items = [r for r in results if r.final_status == status_key]
        elements.append(Paragraph(f"{section_header} ({len(items)})", section_style))

        if not items:
            elements.append(Paragraph("None.", body_style))
            elements.append(Spacer(1, 8))
            continue

        # Overview table for this status group
        header_row = [
            Paragraph("<b>ID</b>", cell_style),
            Paragraph("<b>Title</b>", cell_style),
            Paragraph("<b>Severity</b>", cell_style),
            Paragraph("<b>Triage</b>", cell_style),
            Paragraph("<b>Risk</b>", cell_style),
            Paragraph("<b>Attempts</b>", cell_style),
            Paragraph("<b>Remedy</b>", cell_style),
            Paragraph("<b>Review</b>", cell_style),
            Paragraph("<b>QA Safe</b>", cell_style),
            Paragraph("<b>Duration</b>", cell_style),
            Paragraph("<b>LLM Calls</b>", cell_style),
        ]
        table_rows = [header_row]

        for r in items:
            v = r.vulnerability
            t = r.triage

            # Triage summary
            if t.should_remediate:
                triage_text = "Remediate"
            elif t.requires_human_review:
                triage_text = "Human Review"
            else:
                triage_text = "Blocked"

            risk_col = f'<font color="{_risk_color(t.risk_level).hexval()}">{t.risk_level.upper()}</font>'

            # Remedy
            attempts = len(r.all_attempts) if r.all_attempts else 0
            rm = r.remediation
            if rm is not None:
                remedy_text = f'<font color="{_status_color("success" if rm.success else "failed").hexval()}">' \
                              f'{"Pass" if rm.success else "Fail"}</font>'
            else:
                remedy_text = "\u2014"

            # Review + QA
            pa = r.pre_approval
            if pa and pa.review_verdict:
                rv = pa.review_verdict
                review_text = f'<font color="{_status_color("success" if rv.approve else "failed").hexval()}">' \
                              f'{"Approved" if rv.approve else "Rejected"} ({rv.security_score}/10)</font>'
            else:
                review_text = "\u2014"

            if pa and pa.qa_result:
                qa_safe = _bool_icon(pa.qa_result.safe)
            else:
                qa_safe = "\u2014"

            llm_calls = (r.llm_metrics or {}).get("llm_calls", 0)

            table_rows.append([
                Paragraph(v.id, cell_style),
                Paragraph(_trunc(v.title, 50), cell_style),
                Paragraph(_sev(v.severity), cell_style),
                Paragraph(triage_text, cell_style),
                Paragraph(risk_col, cell_style),
                Paragraph(str(attempts), cell_style),
                Paragraph(remedy_text, cell_style),
                Paragraph(review_text, cell_style),
                Paragraph(qa_safe, cell_style),
                Paragraph(f"{r.total_duration:.1f}s", cell_style),
                Paragraph(str(llm_calls), cell_style),
            ])

        widths = [
            0.85 * inch,  # ID
            1.6 * inch,   # Title
            0.55 * inch,  # Severity
            0.7 * inch,   # Triage
            0.55 * inch,  # Risk
            0.55 * inch,  # Attempts
            0.55 * inch,  # Remedy
            1.3 * inch,   # Review
            0.5 * inch,   # QA Safe
            0.6 * inch,   # Duration
            0.6 * inch,   # LLM Calls
        ]
        elements.append(_data_table(table_rows, widths))
        elements.append(Spacer(1, 10))

    # ── Detailed per-finding pages ────────────────────────────────────
    elements.append(PageBreak())
    elements.append(Paragraph("Detailed Finding Reports", section_style))

    for r in results:
        v = r.vulnerability
        t = r.triage
        rm = r.remediation
        pa = r.pre_approval
        llm = r.llm_metrics or {}

        status_col = _status_color(r.final_status)
        status_text = f'<font color="{status_col.hexval()}">{r.final_status.upper()}</font>'

        elements.append(Paragraph(
            f"{v.id}: {_trunc(v.title, 80)} &nbsp;&mdash;&nbsp; {status_text}",
            subsection_style,
        ))

        # Vulnerability info
        vuln_rows = [
            ["Rule", _safe_str(v.rule)],
            ["Severity", _sev(v.severity)],
            ["Description", _trunc(v.description or "", 200)],
            ["Recommendation", _trunc(v.recommendation or "", 200)],
            ["Host / OS", f"{_safe_str(v.host)} / {_safe_str(v.os)}"],
        ]
        elements.append(_kv_table(vuln_rows, [2 * inch, 6.5 * inch]))
        elements.append(Spacer(1, 4))

        # Triage
        triage_rows = [
            ["Should Remediate", _bool_icon(t.should_remediate)],
            ["Human Review", _bool_icon(t.requires_human_review)],
            ["Risk Level", t.risk_level.upper()],
            ["Reason", _trunc(t.reason, 250)],
            ["Estimated Impact", _safe_str(t.estimated_impact)],
        ]
        elements.append(Paragraph("Triage Decision", ParagraphStyle(
            "DetailLabel", parent=body_style, fontSize=9, textColor=colors.HexColor("#1a1a2e"),
            fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=2,
        )))
        elements.append(_kv_table(triage_rows, [2 * inch, 6.5 * inch]))
        elements.append(Spacer(1, 4))

        # Remediation attempts
        attempts = r.all_attempts or []
        if attempts:
            elements.append(Paragraph(f"Remediation ({len(attempts)} attempt(s))", ParagraphStyle(
                "DetailLabel2", parent=body_style, fontSize=9, textColor=colors.HexColor("#1a1a2e"),
                fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=2,
            )))
            for att in attempts:
                att_rows = [
                    ["Attempt #", str(att.attempt_number)],
                    ["Commands", ", ".join(att.commands_executed[:5]) if att.commands_executed else "\u2014"],
                    ["Scan Passed", _bool_icon(att.scan_passed)],
                    ["Success", _bool_icon(att.success)],
                    ["Duration", f"{att.duration:.1f}s" if att.duration else "\u2014"],
                    ["Error", _safe_str(att.error_summary)],
                ]
                elements.append(_kv_table(att_rows, [2 * inch, 6.5 * inch]))
                elements.append(Spacer(1, 3))

        # Review + QA
        if pa:
            if pa.review_verdict:
                rv = pa.review_verdict
                rev_rows = [
                    ["Approved", _bool_icon(rv.approve)],
                    ["Optimal", _bool_icon(rv.is_optimal)],
                    ["Security Score", f"{rv.security_score}/10"],
                    ["Feedback", _trunc(rv.feedback or "", 250)],
                    ["Concerns", "; ".join(rv.concerns[:3]) if rv.concerns else "\u2014"],
                ]
                elements.append(Paragraph("Review Verdict", ParagraphStyle(
                    "DetailLabel3", parent=body_style, fontSize=9, textColor=colors.HexColor("#1a1a2e"),
                    fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=2,
                )))
                elements.append(_kv_table(rev_rows, [2 * inch, 6.5 * inch]))
                elements.append(Spacer(1, 3))

            if pa.qa_result:
                qa = pa.qa_result
                qa_rows = [
                    ["Safe", _bool_icon(qa.safe)],
                    ["Verdict", _trunc(qa.verdict_reason or "", 250)],
                    ["Side Effects", "; ".join(qa.side_effects[:3]) if qa.side_effects else "\u2014"],
                    ["Regression", _bool_icon(qa.regression_detected)],
                    ["Recommendation", _safe_str(qa.recommendation)],
                ]
                elements.append(Paragraph("QA Result", ParagraphStyle(
                    "DetailLabel4", parent=body_style, fontSize=9, textColor=colors.HexColor("#1a1a2e"),
                    fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=2,
                )))
                elements.append(_kv_table(qa_rows, [2 * inch, 6.5 * inch]))
                elements.append(Spacer(1, 3))

        # LLM metrics for this finding
        if llm.get("llm_calls", 0) > 0:
            per_ag = llm.get("per_agent", {})
            agents_used = ", ".join(
                f"{a.capitalize()}({int(s.get('llm_calls', 0))})"
                for a, s in per_ag.items()
            )
            llm_rows = [
                ["LLM Calls", str(llm.get("llm_calls", 0))],
                ["Duration", f"{llm.get('llm_duration_s', 0):.1f}s"],
                ["Total Tokens", f"{llm.get('total_tokens', 0):,}"],
                ["Cost", f"${llm.get('estimated_cost_usd', 0):.4f}"],
                ["Agents", agents_used or "\u2014"],
            ]
            elements.append(Paragraph("LLM Metrics", ParagraphStyle(
                "DetailLabel5", parent=body_style, fontSize=9, textColor=colors.HexColor("#1a1a2e"),
                fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=2,
            )))
            elements.append(_kv_table(llm_rows, [2 * inch, 6.5 * inch]))

        elements.append(Spacer(1, 12))

    # ── Build PDF ─────────────────────────────────────────────────────
    doc.build(elements)
    print(f"Pipeline PDF report saved to {out}")
    return out


# ── Standalone usage ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    from schemas import V2FindingResult

    json_path = Path("reports/v2_aggregated_results.json")
    if not json_path.exists():
        raise FileNotFoundError(f"{json_path} not found.")

    raw = json.loads(json_path.read_text(encoding="utf-8"))
    results = [V2FindingResult(**entry) for entry in raw]

    model_metadata = {
        "triage": os.getenv("TRIAGE_MODEL", "unknown"),
        "remedy": os.getenv("REMEDY_MODEL", "unknown"),
        "review": os.getenv("REVIEW_MODEL", "unknown"),
        "qa": os.getenv("QA_MODEL", "unknown"),
    }

    write_pipeline_pdf(
        results,
        output_path="reports/pipeline_report.pdf",
        model_metadata=model_metadata,
    )
