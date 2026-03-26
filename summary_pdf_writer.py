#!/usr/bin/env python3
"""
summary_pdf_writer.py — Generate a polished executive-summary PDF from
pipeline V2 results.

Produces:  reports/v2_pipeline_report.pdf

Sections:
  1. Title + metadata (host, profile, timestamp, model)
  2. Dashboard summary table (counts & percentages)
  3. Per-finding detail rows (triage → remedy → review → QA → final)
"""

from __future__ import annotations

import textwrap
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from schemas import V2FindingResult


def write_summary_pdf(
    results: List[V2FindingResult],
    output_path: str | Path,
    *,
    target_host: str = "unknown",
    scan_profile: str = "",
    elapsed_seconds: float = 0.0,
) -> Path:
    """Build and write the summary PDF.  Returns the output path."""

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
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

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    elements: list = []

    # ── Custom styles ─────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "SumTitle", parent=styles["Title"], fontSize=22, spaceAfter=4,
        textColor=colors.HexColor("#0d47a1"),
    )
    subtitle_style = ParagraphStyle(
        "SumSub", parent=styles["Normal"], fontSize=10,
        textColor=colors.grey, spaceAfter=14,
    )
    section_style = ParagraphStyle(
        "SumSec", parent=styles["Heading2"], fontSize=14,
        spaceBefore=18, spaceAfter=8,
        textColor=colors.HexColor("#1a1a2e"),
    )
    normal_style = ParagraphStyle(
        "SumNorm", parent=styles["Normal"], fontSize=9, leading=12,
    )
    small_style = ParagraphStyle(
        "SumSmall", parent=styles["Normal"], fontSize=8, leading=10,
        textColor=colors.HexColor("#444444"),
    )

    # ── Title block ───────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph("Multi-Agent Pipeline V2 — Summary Report", title_style))
    meta_parts = [f"Generated: {ts}"]
    if target_host:
        meta_parts.append(f"Target Host: {target_host}")
    if scan_profile:
        meta_parts.append(f"Profile: {scan_profile}")
    if elapsed_seconds > 0:
        meta_parts.append(f"Total Runtime: {elapsed_seconds:.1f}s")
    elements.append(Paragraph(" &nbsp;|&nbsp; ".join(meta_parts), subtitle_style))
    elements.append(Spacer(1, 12))

    # ── Dashboard summary ─────────────────────────────────────────────
    total = len(results) or 1
    success   = sum(1 for r in results if r.final_status == "success")
    failed    = sum(1 for r in results if r.final_status == "failed")
    discarded = sum(1 for r in results if r.final_status == "discarded")
    human     = sum(1 for r in results if r.final_status == "requires_human_review")
    rate = success / total * 100

    elements.append(Paragraph("Overview", section_style))

    dash_data = [
        ["Category", "Count", "%"],
        ["Remediated (success)", str(success), f"{success/total*100:.0f}%"],
        ["Failed", str(failed), f"{failed/total*100:.0f}%"],
        ["Discarded (triage)", str(discarded), f"{discarded/total*100:.0f}%"],
        ["Requires Human Review", str(human), f"{human/total*100:.0f}%"],
        ["Total", str(len(results)), "100%"],
    ]

    # Colour mapping for status rows
    row_colors = {
        1: colors.HexColor("#e8f5e9"),  # success  — green tint
        2: colors.HexColor("#ffebee"),  # failed   — red tint
        3: colors.HexColor("#f5f5f5"),  # discarded — grey
        4: colors.HexColor("#fff8e1"),  # human    — amber
        5: colors.HexColor("#e3f2fd"),  # total    — blue
    }

    dash_table = Table(dash_data, colWidths=[3.5 * inch, 1 * inch, 0.8 * inch])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d47a1")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#bbbbbb")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for row_idx, bg in row_colors.items():
        style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), bg))
    # Bold the total row
    style_cmds.append(("FONTNAME", (0, 5), (-1, 5), "Helvetica-Bold"))

    dash_table.setStyle(TableStyle(style_cmds))
    elements.append(dash_table)
    elements.append(Spacer(1, 8))
    elements.append(
        Paragraph(f"<b>Success Rate: {rate:.1f}%</b>", normal_style),
    )
    elements.append(Spacer(1, 16))

    # ── Per-finding detail ────────────────────────────────────────────
    elements.append(Paragraph("Finding Details", section_style))

    STATUS_ICONS = {
        "success": "OK",
        "failed": "FAIL",
        "discarded": "SKIP",
        "requires_human_review": "REVIEW",
    }
    STATUS_COLORS = {
        "success": colors.HexColor("#2e7d32"),
        "failed": colors.HexColor("#c62828"),
        "discarded": colors.HexColor("#757575"),
        "requires_human_review": colors.HexColor("#f57f17"),
    }
    STATUS_BG = {
        "success": colors.HexColor("#e8f5e9"),
        "failed": colors.HexColor("#ffebee"),
        "discarded": colors.HexColor("#fafafa"),
        "requires_human_review": colors.HexColor("#fff8e1"),
    }

    for idx, r in enumerate(results, 1):
        v = r.vulnerability
        icon = STATUS_ICONS.get(r.final_status, "?")
        clr = STATUS_COLORS.get(r.final_status, colors.black)

        # Finding header
        hdr_style = ParagraphStyle(
            f"FH{idx}", parent=styles["Heading3"], fontSize=11,
            spaceBefore=10, spaceAfter=2, textColor=clr,
        )
        elements.append(
            Paragraph(f"[{icon}] {v.id} — {_esc(v.title)}", hdr_style),
        )

        # Detail rows as a mini-table
        detail_rows = [
            ["Severity", str(v.severity)],
            ["Triage",
             f"risk={r.triage.risk_level}, remediate={r.triage.should_remediate}"],
        ]

        if r.triage.reason:
            detail_rows.append(
                ["Triage Reason", _wrap(_esc(r.triage.reason), 90)],
            )

        if r.all_attempts:
            total_att = len(r.all_attempts)
            passed_att = next(
                (a for a in r.all_attempts if a.scan_passed), None
            )
            if passed_att:
                detail_rows.append([
                    "Scan Result",
                    f"Passed on attempt {passed_att.attempt_number} of {total_att}",
                ])
            else:
                detail_rows.append([
                    "Scan Result",
                    f"Did NOT pass ({total_att} attempt(s))",
                ])
            for att in r.all_attempts:
                cmds_str = "; ".join(att.commands_executed[:5])
                if len(att.commands_executed) > 5:
                    cmds_str += f" … (+{len(att.commands_executed)-5} more)"
                detail_rows.append([
                    f"Attempt #{att.attempt_number}",
                    f"scan_passed={att.scan_passed}, "
                    f"cmds={len(att.commands_executed)}, {att.attempt_duration:.1f}s",
                ])
                if cmds_str:
                    detail_rows.append(["  Commands", _wrap(_esc(cmds_str), 90)])
                if att.error_summary:
                    detail_rows.append(["  Error", _wrap(_esc(att.error_summary), 90)])
        elif r.remediation:
            rm = r.remediation
            cmds_str = "; ".join(rm.commands_executed[:5])
            if len(rm.commands_executed) > 5:
                cmds_str += f" … (+{len(rm.commands_executed)-5} more)"
            detail_rows.append([
                "Remedy",
                f"attempt #{rm.attempt_number}, scan_passed={rm.scan_passed}, "
                f"cmds={len(rm.commands_executed)}, {rm.attempt_duration:.1f}s",
            ])
            if cmds_str:
                detail_rows.append(["Commands", _wrap(_esc(cmds_str), 90)])
            if rm.error_summary:
                detail_rows.append(["Error", _wrap(_esc(rm.error_summary), 90)])

        if r.pre_approval:
            pa = r.pre_approval
            rv = pa.review_verdict
            detail_rows.append([
                "Review",
                f"approve={rv.approve}, optimal={rv.is_optimal}, "
                f"score={rv.security_score}",
            ])
            if rv.feedback:
                detail_rows.append(["Feedback", _wrap(_esc(rv.feedback), 90)])
            if pa.qa_result:
                qa = pa.qa_result
                detail_rows.append([
                    "QA",
                    f"safe={qa.safe}, recommendation={qa.recommendation}",
                ])
                if qa.verdict_reason:
                    detail_rows.append(
                        ["QA Reason", _wrap(_esc(qa.verdict_reason), 90)],
                    )
            if not pa.approved and pa.rejection_reason:
                detail_rows.append(
                    ["Rejection", _wrap(_esc(pa.rejection_reason), 90)],
                )

        detail_rows.append(["Final", f"{r.final_status}  |  {r.total_duration:.1f}s"])

        # Convert plain strings to Paragraphs so text wraps inside cells
        for ri, row in enumerate(detail_rows):
            detail_rows[ri] = [
                Paragraph(f"<b>{row[0]}</b>", small_style),
                Paragraph(row[1], small_style),
            ]

        det_table = Table(
            detail_rows,
            colWidths=[1.2 * inch, 5.3 * inch],
        )
        bg = STATUS_BG.get(r.final_status, colors.white)
        det_style = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
            ("BACKGROUND", (0, 0), (0, -1), bg),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]
        det_table.setStyle(TableStyle(det_style))
        elements.append(det_table)
        elements.append(Spacer(1, 6))

    # ── Build PDF ─────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )
    doc.build(elements)
    return output_path


# ── helpers ───────────────────────────────────────────────────────────────

def _esc(text: str) -> str:
    """Escape XML/HTML special chars for ReportLab Paragraphs."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _wrap(text: str, width: int = 90) -> str:
    """Soft-wrap long text for table cells."""
    return "<br/>".join(textwrap.wrap(text, width))
