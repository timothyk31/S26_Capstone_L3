#!/usr/bin/env python3
"""
context_pdf_writer.py — Generate one PDF **per agent** showing the full LLM
messages/transcript context for every finding that agent processed.

Produces up to four files:
  - triage_context.pdf
  - remedy_context.pdf
  - review_context.pdf
  - qa_context.pdf

Reads transcript JSON files saved by each agent and renders them into
readable, colour-coded PDFs.
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from schemas import V2FindingResult


# ── SSH-login filter keywords (used externally too) ─────────────────────────

SSH_LOGIN_SKIP_KEYWORDS = [
    "sshd_disable_root_login",
    "disable ssh root login",
    "disallow direct root login",
    # Broader SSH config changes that can break the active connection
    "configure ssh",
    "ssh server",
    "ssh client",
    "sshd_config",
    "opensshserver",
    "openssh.config",
    "ssh client alive",
    "ssh access via empty",
    "ssh root login",
    "ssh warning banner",
    "x11 forwarding",
    "permissions on ssh",
    "fips 140-2 validated macs",
]


def _is_ssh_login_finding(title: str, rule: Optional[str], oval_id: Optional[str]) -> bool:
    """Return True if the finding is about disabling/disallowing SSH root login."""
    haystack = " ".join(
        s.lower() for s in [title or "", rule or "", oval_id or ""] if s
    )
    return any(kw.lower() in haystack for kw in SSH_LOGIN_SKIP_KEYWORDS)


def _load_transcript_file(path: Path) -> Optional[List[Dict]]:
    """Load a transcript JSON file, returning None on failure."""
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


# ── Per-agent transcript loaders ────────────────────────────────────────────

def _load_triage_transcripts(
    work_dir: Path, finding_id: str, _max_attempts: int,
) -> List[Tuple[int, List[Dict]]]:
    """Triage: single call per finding, no attempt suffix."""
    candidates = [
        work_dir / "transcripts" / "triage" / f"triage_transcript_{finding_id}.json",
    ]
    for p in candidates:
        t = _load_transcript_file(p)
        if t:
            return [(1, t)]
    return []


def _load_remedy_transcripts(
    work_dir: Path, finding_id: str, max_attempts: int,
) -> List[Tuple[int, List[Dict]]]:
    """Remedy: one transcript per attempt."""
    found: List[Tuple[int, List[Dict]]] = []
    for att in range(1, max_attempts + 1):
        label = f"{finding_id}_attempt{att}"
        candidates = [
            work_dir / "remedy" / f"remedy_transcript_{label}.json",
            work_dir / f"remedy_transcript_{label}.json",
        ]
        for p in candidates:
            t = _load_transcript_file(p)
            if t:
                found.append((att, t))
                break
    return found


def _load_review_transcripts(
    work_dir: Path, finding_id: str, max_attempts: int,
) -> List[Tuple[int, List[Dict]]]:
    """Review: one transcript per attempt."""
    found: List[Tuple[int, List[Dict]]] = []
    for att in range(1, max_attempts + 1):
        p = work_dir / "transcripts" / "review" / f"review_transcript_{finding_id}_attempt{att}.json"
        t = _load_transcript_file(p)
        if t:
            found.append((att, t))
    return found


def _load_qa_transcripts(
    work_dir: Path, finding_id: str, max_attempts: int,
) -> List[Tuple[int, List[Dict]]]:
    """QA: one transcript per attempt."""
    found: List[Tuple[int, List[Dict]]] = []
    for att in range(1, max_attempts + 1):
        p = work_dir / "transcripts" / "qa" / f"qa_transcript_{finding_id}_attempt{att}.json"
        t = _load_transcript_file(p)
        if t:
            found.append((att, t))
    return found


# Map used by the public API
_AGENT_REGISTRY: Dict[str, dict] = {
    "triage": {
        "label": "Triage Agent",
        "loader": _load_triage_transcripts,
        "filename": "triage_context.pdf",
        "color": "#e8eaf6",
        "header_color": "#283593",
    },
    "remedy": {
        "label": "Remedy Agent",
        "loader": _load_remedy_transcripts,
        "filename": "remedy_context.pdf",
        "color": "#e0f2f1",
        "header_color": "#00695c",
    },
    "review": {
        "label": "Review Agent",
        "loader": _load_review_transcripts,
        "filename": "review_context.pdf",
        "color": "#fff3e0",
        "header_color": "#e65100",
    },
    "qa": {
        "label": "QA Agent",
        "loader": _load_qa_transcripts,
        "filename": "qa_context.pdf",
        "color": "#fce4ec",
        "header_color": "#880e4f",
    },
}


# ── Helpers ─────────────────────────────────────────────────────────────────

def _safe_xml(text: str) -> str:
    """Escape text for reportlab Paragraph XML."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _truncate(text: str, max_len: int = 2000) -> str:
    """Truncate long text to keep PDF manageable."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n... [truncated, {len(text)} chars total]"


# ── Single-agent PDF writer ────────────────────────────────────────────────

def _write_single_agent_pdf(
    agent_key: str,
    results: List[V2FindingResult],
    work_dir: Path,
    output_path: Path,
    *,
    target_host: str = "unknown",
) -> Optional[Path]:
    """
    Build one PDF containing every transcript for *one* agent across all findings.

    Returns the output path, or None if the agent had zero transcripts.
    """
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

    info = _AGENT_REGISTRY[agent_key]
    agent_label: str = info["label"]
    loader = info["loader"]
    agent_bg = colors.HexColor(info["color"])
    agent_hdr_color = colors.HexColor(info["header_color"])

    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    elements: list = []

    # ── Custom styles ─────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "CtxTitle", parent=styles["Title"], fontSize=20, spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "CtxSub", parent=styles["Normal"], fontSize=10,
        textColor=colors.grey, spaceAfter=14,
    )
    section_style = ParagraphStyle(
        "CtxSec", parent=styles["Heading2"], fontSize=13,
        spaceBefore=16, spaceAfter=6,
        textColor=colors.HexColor("#1a1a2e"),
    )
    finding_header_style = ParagraphStyle(
        "CtxFinding", parent=styles["Heading3"], fontSize=12,
        spaceBefore=12, spaceAfter=4,
        textColor=agent_hdr_color,
    )
    role_style = ParagraphStyle(
        "CtxRole", parent=styles["Normal"], fontSize=9,
        leading=11, textColor=colors.HexColor("#333333"),
    )
    msg_system_style = ParagraphStyle(
        "MsgSys", parent=styles["Normal"], fontSize=8, leading=10,
        textColor=colors.HexColor("#6a1b9a"), leftIndent=12,
    )
    msg_user_style = ParagraphStyle(
        "MsgUser", parent=styles["Normal"], fontSize=8, leading=10,
        textColor=colors.HexColor("#1565c0"), leftIndent=12,
    )
    msg_assistant_style = ParagraphStyle(
        "MsgAsst", parent=styles["Normal"], fontSize=8, leading=10,
        textColor=colors.HexColor("#2e7d32"), leftIndent=12,
    )
    msg_tool_style = ParagraphStyle(
        "MsgTool", parent=styles["Normal"], fontSize=8, leading=10,
        textColor=colors.HexColor("#bf360c"), leftIndent=12,
    )
    mono_style = ParagraphStyle(
        "Mono", parent=styles["Code"], fontSize=7, leading=9,
        leftIndent=20, textColor=colors.HexColor("#37474f"),
    )

    ROLE_STYLES = {
        "system": msg_system_style,
        "user": msg_user_style,
        "assistant": msg_assistant_style,
        "tool": msg_tool_style,
    }
    ROLE_COLORS = {
        "system": colors.HexColor("#f3e5f5"),
        "user": colors.HexColor("#e3f2fd"),
        "assistant": colors.HexColor("#e8f5e9"),
        "tool": colors.HexColor("#fbe9e7"),
    }
    ROLE_LABELS = {
        "system": "SYSTEM",
        "user": "USER (Prompt)",
        "assistant": "ASSISTANT (LLM)",
        "tool": "TOOL RESULT",
    }

    def _render_transcript(transcript: List[Dict]) -> None:
        """Render a single transcript (list of messages) into PDF elements."""
        for msg in transcript:
            role = msg.get("role", "unknown")
            content = msg.get("content") or ""
            tool_calls = msg.get("tool_calls") or []

            label = ROLE_LABELS.get(role, role.upper())
            style = ROLE_STYLES.get(role, role_style)
            bg = ROLE_COLORS.get(role, colors.HexColor("#f5f5f5"))

            # Role label row
            label_data = [[Paragraph(f"<b>{_safe_xml(label)}</b>", style)]]
            label_table = Table(label_data, colWidths=[7 * inch])
            label_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]))
            elements.append(label_table)

            # Message content
            if content:
                safe_content = _safe_xml(_truncate(content, 3000))
                content_para = Paragraph(
                    safe_content.replace("\n", "<br/>"),
                    style,
                )
                elements.append(content_para)

            # Tool calls (from assistant messages — mainly Remedy agent)
            if tool_calls:
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    fn_name = fn.get("name", "?")
                    fn_args = fn.get("arguments", "")
                    if isinstance(fn_args, dict):
                        fn_args = json.dumps(fn_args, indent=2)
                    elif isinstance(fn_args, str):
                        try:
                            fn_args = json.dumps(json.loads(fn_args), indent=2)
                        except Exception:
                            pass
                    fn_args = _truncate(fn_args, 1500)
                    elements.append(Paragraph(
                        f"<b>Tool Call:</b> {_safe_xml(fn_name)}",
                        msg_tool_style,
                    ))
                    elements.append(Paragraph(
                        _safe_xml(fn_args).replace("\n", "<br/>"),
                        mono_style,
                    ))

            elements.append(Spacer(1, 4))

    # ── Title page ────────────────────────────────────────────────────
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph(f"{agent_label} — Messages / Context", title_style))
    elements.append(Paragraph(
        f"Target: {_safe_xml(target_host)} &nbsp;|&nbsp; Generated: {now}",
        subtitle_style,
    ))
    elements.append(Paragraph(
        f"This report shows the full LLM message context (system prompt, user "
        f"prompt, assistant responses, tool calls and results) for the "
        f"<b>{_safe_xml(agent_label)}</b> across every finding it processed.",
        role_style,
    ))
    elements.append(Spacer(1, 14))

    # ── Per-finding transcripts ───────────────────────────────────────
    findings_written = 0

    for result in results:
        vuln = result.vulnerability

        # Skip SSH root login findings
        if _is_ssh_login_finding(vuln.title, vuln.rule, vuln.oval_id):
            continue

        max_attempts = result.remediation.attempt_number if result.remediation else 1
        transcripts = loader(work_dir, vuln.id, max_attempts)

        if not transcripts:
            continue

        findings_written += 1

        # Finding header
        elements.append(PageBreak())
        status_label = result.final_status.upper()
        elements.append(Paragraph(
            f"Finding: {_safe_xml(vuln.id)} — {_safe_xml(vuln.title)}",
            finding_header_style,
        ))
        elements.append(Paragraph(
            f"Severity: {vuln.severity} &nbsp;|&nbsp; Status: {status_label} "
            f"&nbsp;|&nbsp; Transcripts: {len(transcripts)}",
            role_style,
        ))
        elements.append(Spacer(1, 8))

        for att_no, transcript in transcripts:
            if len(transcripts) > 1:
                elements.append(Paragraph(
                    f"Attempt {att_no}", section_style,
                ))
            _render_transcript(transcript)
            elements.append(Spacer(1, 8))

    # ── Empty guard ───────────────────────────────────────────────────
    if findings_written == 0:
        return None          # nothing to write — caller can skip

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
    )
    doc.build(elements)
    return output_path


# ── Public API ──────────────────────────────────────────────────────────────

def write_all_context_pdfs(
    results: List[V2FindingResult],
    work_dir: str | Path,
    output_dir: str | Path = "reports",
    *,
    target_host: str = "unknown",
) -> Dict[str, Path]:
    """
    Generate one PDF per agent (triage, remedy, review, qa).

    Returns a dict  agent_key -> Path  for every PDF that was written.
    Agents with zero transcripts are silently skipped.
    """
    work_dir = Path(work_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    written: Dict[str, Path] = {}
    for key, info in _AGENT_REGISTRY.items():
        out_path = output_dir / info["filename"]
        result = _write_single_agent_pdf(
            agent_key=key,
            results=results,
            work_dir=work_dir,
            output_path=out_path,
            target_host=target_host,
        )
        if result is not None:
            written[key] = result

    return written
