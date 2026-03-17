#!/usr/bin/env python3
"""
attempt_pdf_writer.py — Generate a per-finding PDF that shows every
remediation attempt with Review, QA, and verification-scan verdicts.

Produces one PDF per finding under:
    <output_dir>/attempt_reports/<finding_id>_attempts.pdf

Each attempt gets its own section showing:
  - Commands executed
  - Review verdict (approve, score, concerns, feedback)
  - QA verdict (safe, recommendation, side-effects)
  - Verification-scan result (pass/fail)
  - Duration
"""

from __future__ import annotations

import textwrap
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from schemas import PreApprovalResult, V2FindingResult


# ── Public API ────────────────────────────────────────────────────────────

def write_attempt_pdf(
    result: V2FindingResult,
    output_dir: str | Path,
    *,
    target_host: str = "unknown",
) -> Optional[Path]:
    """Build a per-finding attempt-level PDF.  Returns the output path, or
    None if there are no attempts to report."""

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

    attempts = result.all_attempts
    if not attempts:
        return None

    approvals: List[Optional[PreApprovalResult]] = list(result.all_approvals or [])
    # Pad so indices always line up with attempts
    while len(approvals) < len(attempts):
        approvals.append(None)

    v = result.vulnerability
    out_dir = Path(output_dir) / "attempt_reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / f"{v.id}_attempts.pdf"

    styles = getSampleStyleSheet()

    # ── Custom styles ─────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "AtTitle", parent=styles["Title"], fontSize=20, spaceAfter=4,
        textColor=colors.HexColor("#0d47a1"),
    )
    subtitle_style = ParagraphStyle(
        "AtSub", parent=styles["Normal"], fontSize=10,
        textColor=colors.grey, spaceAfter=14,
    )
    section_style = ParagraphStyle(
        "AtSec", parent=styles["Heading2"], fontSize=14,
        spaceBefore=16, spaceAfter=6,
        textColor=colors.HexColor("#1a1a2e"),
    )
    subsection_style = ParagraphStyle(
        "AtSubSec", parent=styles["Heading3"], fontSize=12,
        spaceBefore=10, spaceAfter=4,
    )
    normal_style = ParagraphStyle(
        "AtNorm", parent=styles["Normal"], fontSize=9, leading=12,
    )
    small_style = ParagraphStyle(
        "AtSmall", parent=styles["Normal"], fontSize=8, leading=10,
        textColor=colors.HexColor("#444444"),
    )

    PASS_BG = colors.HexColor("#e8f5e9")
    FAIL_BG = colors.HexColor("#ffebee")
    NEUTRAL_BG = colors.HexColor("#f5f5f5")
    PASS_CLR = colors.HexColor("#2e7d32")
    FAIL_CLR = colors.HexColor("#c62828")

    elements: list = []

    # ── Title block ───────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph(f"Attempt Report — {_esc(v.id)}", title_style))
    meta = f"Generated: {ts} &nbsp;|&nbsp; Host: {_esc(target_host)} &nbsp;|&nbsp; Severity: {_esc(v.severity)}"
    elements.append(Paragraph(meta, subtitle_style))
    elements.append(Paragraph(f"<b>{_esc(v.title)}</b>", normal_style))
    elements.append(Spacer(1, 6))

    # ── Triage summary ────────────────────────────────────────────────
    elements.append(Paragraph("Triage Decision", section_style))
    triage_rows = [
        ["Risk Level", result.triage.risk_level],
        ["Should Remediate", str(result.triage.should_remediate)],
        ["Reason", _wrap(_esc(result.triage.reason or ""), 95)],
    ]
    if result.triage.requires_human_review:
        triage_rows.append(["Human Review", "Required"])
    elements.append(_make_detail_table(triage_rows, small_style, NEUTRAL_BG))
    elements.append(Spacer(1, 10))

    # ── Final outcome banner ──────────────────────────────────────────
    final_ok = result.final_status == "success"
    banner_bg = PASS_BG if final_ok else FAIL_BG
    banner_clr = PASS_CLR if final_ok else FAIL_CLR
    banner_text = f"FINAL STATUS: {result.final_status.upper()}  |  {len(attempts)} attempt(s)  |  {result.total_duration:.1f}s total"
    banner_style = ParagraphStyle(
        "Banner", parent=styles["Normal"], fontSize=12,
        textColor=banner_clr, alignment=1,  # center
    )
    banner_data = [[Paragraph(f"<b>{_esc(banner_text)}</b>", banner_style)]]
    banner_tbl = Table(banner_data, colWidths=[6.8 * inch])
    banner_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), banner_bg),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BOX", (0, 0), (-1, -1), 1, banner_clr),
    ]))
    elements.append(banner_tbl)
    elements.append(Spacer(1, 14))

    # ── Per-attempt sections ──────────────────────────────────────────
    for i, att in enumerate(attempts):
        appr = approvals[i] if i < len(approvals) else None

        attempt_ok = att.scan_passed and att.success
        att_clr = PASS_CLR if attempt_ok else FAIL_CLR
        att_bg = PASS_BG if attempt_ok else FAIL_BG

        hdr_style = ParagraphStyle(
            f"AH{i}", parent=styles["Heading2"], fontSize=13,
            spaceBefore=14, spaceAfter=4, textColor=att_clr,
        )
        status_label = "PASSED" if attempt_ok else "FAILED"
        elements.append(
            Paragraph(f"Attempt #{att.attempt_number} — {status_label}", hdr_style),
        )

        # ── Commands ──────────────────────────────────────────────────
        cmd_rows = [
            ["Duration", f"{att.duration:.1f}s"],
            ["Commands", str(len(att.commands_executed))],
        ]
        for ci, cmd in enumerate(att.commands_executed):
            label = f"  cmd {ci+1}" if ci < 20 else "  …"
            cmd_rows.append([label, _wrap(_esc(cmd), 90)])
            if ci >= 19:
                cmd_rows.append(["", f"… +{len(att.commands_executed) - 20} more"])
                break
        if att.error_summary:
            cmd_rows.append(["Error", _wrap(_esc(att.error_summary), 90)])

        elements.append(Paragraph("Remediation", subsection_style))
        elements.append(_make_detail_table(cmd_rows, small_style, att_bg))
        elements.append(Spacer(1, 6))

        # ── Review verdict ────────────────────────────────────────────
        if appr is not None:
            rv = appr.review_verdict
            rv_ok = rv.approve
            rv_bg = PASS_BG if rv_ok else FAIL_BG

            review_rows = [
                ["Approve", str(rv.approve)],
                ["Is Optimal", str(rv.is_optimal)],
                ["Security Score", str(rv.security_score or "—")],
            ]
            if rv.feedback:
                review_rows.append(["Feedback", _wrap(_esc(rv.feedback), 90)])
            if rv.concerns:
                for ci, c in enumerate(rv.concerns[:6]):
                    review_rows.append([f"  Concern {ci+1}", _wrap(_esc(c), 90)])
            if rv.suggested_improvements:
                for si, s in enumerate(rv.suggested_improvements[:6]):
                    review_rows.append([f"  Suggestion {si+1}", _wrap(_esc(s), 90)])

            elements.append(Paragraph("Review Verdict", subsection_style))
            elements.append(_make_detail_table(review_rows, small_style, rv_bg))
            elements.append(Spacer(1, 6))

            # ── QA verdict ────────────────────────────────────────────
            qa = appr.qa_result
            if qa is not None:
                qa_ok = qa.safe
                qa_bg = PASS_BG if qa_ok else FAIL_BG

                qa_rows = [
                    ["Safe", str(qa.safe)],
                    ["Recommendation", qa.recommendation or "—"],
                    ["Regression Detected", str(qa.regression_detected)],
                ]
                if qa.verdict_reason:
                    qa_rows.append(["Reason", _wrap(_esc(qa.verdict_reason), 90)])
                if qa.side_effects:
                    for ei, e in enumerate(qa.side_effects[:6]):
                        qa_rows.append([f"  Side-effect {ei+1}", _wrap(_esc(e), 90)])

                elements.append(Paragraph("QA Verdict", subsection_style))
                elements.append(_make_detail_table(qa_rows, small_style, qa_bg))
                elements.append(Spacer(1, 6))

            # ── Overall approval ──────────────────────────────────────
            appr_ok = appr.approved
            appr_bg = PASS_BG if appr_ok else FAIL_BG
            appr_rows = [["Approved", str(appr.approved)]]
            if appr.rejection_reason:
                appr_rows.append(["Rejection Reason", _wrap(_esc(appr.rejection_reason), 90)])
            elements.append(Paragraph("Pre-Scan Approval", subsection_style))
            elements.append(_make_detail_table(appr_rows, small_style, appr_bg))
            elements.append(Spacer(1, 6))
        else:
            elements.append(
                Paragraph("<i>Review/QA not reached (remedy errored)</i>", small_style),
            )
            elements.append(Spacer(1, 6))

        # ── Verification scan ─────────────────────────────────────────
        scan_rows = [["Scan Passed", str(att.scan_passed)]]
        if att.scan_output:
            scan_rows.append(["Scan Output", _wrap(_esc(str(att.scan_output)[:500]), 90)])
        scan_bg = PASS_BG if att.scan_passed else FAIL_BG
        elements.append(Paragraph("Verification Scan", subsection_style))
        elements.append(_make_detail_table(scan_rows, small_style, scan_bg))
        elements.append(Spacer(1, 10))

        # Page break between attempts (except the last)
        if i < len(attempts) - 1:
            elements.append(PageBreak())

    # ── Build PDF ─────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )
    doc.build(elements)
    return pdf_path


def write_all_attempt_pdfs(
    results: List[V2FindingResult],
    output_dir: str | Path,
    *,
    target_host: str = "unknown",
) -> List[Path]:
    """Generate attempt PDFs for every finding that had remediation attempts.
    Returns paths to all generated PDFs."""
    paths: List[Path] = []
    for r in results:
        try:
            p = write_attempt_pdf(r, output_dir, target_host=target_host)
            if p is not None:
                paths.append(p)
        except Exception:
            pass  # Don't let one finding's PDF failure block the rest
    return paths


# ── Helpers ───────────────────────────────────────────────────────────────

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


def _make_detail_table(rows, small_style, bg_color):
    """Convert a list of [label, value] rows into a styled ReportLab Table."""
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, Table, TableStyle

    table_rows = []
    for row in rows:
        table_rows.append([
            Paragraph(f"<b>{row[0]}</b>", small_style),
            Paragraph(row[1], small_style),
        ])

    tbl = Table(table_rows, colWidths=[1.3 * inch, 5.2 * inch])
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
        ("BACKGROUND", (0, 0), (0, -1), bg_color),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return tbl
