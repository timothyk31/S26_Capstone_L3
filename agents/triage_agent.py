"""
Triage Agent — First stage of the multi-agent remediation pipeline.

Decides whether a vulnerability should be auto-remediated, sent for human
review, or left alone.

Input:  TriageInput   (Vulnerability + optional system_context)
Output: TriageDecision (should_remediate, risk_level, reason, …)

Classification strategy:
  1. Local heuristics for high-confidence patterns (partition, auth/pam, …)
  2. OpenRouter LLM call for everything else
  3. Conservative fallback when the LLM fails
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Literal, Optional

import requests
from dotenv import find_dotenv, load_dotenv
from pydantic import BaseModel, Field, ValidationError

from agents.base_agent import BaseAgent
from schemas import TriageDecision, TriageInput, Vulnerability

load_dotenv(find_dotenv(), override=False)

# ---------------------------------------------------------------------------
# Internal LLM response model (richer than TriageDecision, collapsed later)
# ---------------------------------------------------------------------------

TriageCategory = Literal[
    "safe_to_remediate",
    "requires_human_review",
    "too_dangerous_to_remediate",
]


class _LLMVerdict(BaseModel):
    """Schema the LLM is told to return — mapped to TriageDecision after."""
    finding_id: str
    rule_id: str
    category: TriageCategory
    confidence: float = Field(..., ge=0.0, le=1.0)
    rationale: str = Field(..., min_length=1)
    risk_factors: List[str] = Field(default_factory=list)
    safe_next_steps: List[str] = Field(default_factory=list)
    requires_reboot: bool = False
    touches_authn_authz: bool = False
    touches_networking: bool = False
    touches_filesystems: bool = False


# ---------------------------------------------------------------------------
# OpenRouter lightweight client
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ModelSpec:
    name: str
    temperature: float = 0.0
    max_tokens: int = 600


MODELS_BY_MODE: Dict[str, ModelSpec] = {
    "fast":          ModelSpec(name="meta-llama/llama-3.1-8b-instruct",  temperature=0.0, max_tokens=450),
    "balanced":      ModelSpec(name="anthropic/claude-3.5-sonnet",       temperature=0.0, max_tokens=650),
    "smart":         ModelSpec(name="openai/gpt-4o",                     temperature=0.0, max_tokens=750),
    "nemotron_free": ModelSpec(name="nvidia/nemotron-4-mini-instruct",   temperature=0.1, max_tokens=500),
}


class _OpenRouterClient:
    """Thin wrapper around OpenRouter chat-completions for JSON classification."""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "https://openrouter.ai/api/v1",
        timeout: int = 60,
        temperature: float = 0.0,
        max_tokens: int = 600,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.endpoint = f"{self.base_url}/chat/completions"
        self.headers: Dict[str, str] = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        referer = os.getenv("OPENROUTER_HTTP_REFERER")
        title = os.getenv("OPENROUTER_APP_TITLE")
        if referer:
            self.headers["HTTP-Referer"] = referer
        if title:
            self.headers["X-Title"] = title

    def classify(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "provider": {"allow_fallbacks": True},
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security triage assistant for Rocky/RHEL 9 OpenSCAP STIG findings.\n"
                        "Return ONLY a single JSON object that matches the schema exactly.\n"
                        "No prose. No markdown. No code fences. No extra keys.\n"
                        "Be conservative: if uncertain, choose requires_human_review.\n"
                    ),
                },
                {"role": "user", "content": prompt},
            ],
        }

        last_err: Optional[str] = None
        for attempt in range(1, 4):
            try:
                r = requests.post(
                    self.endpoint,
                    headers=self.headers,
                    json=payload,
                    timeout=self.timeout,
                )
                if r.status_code in (429, 500, 502, 503, 504):
                    last_err = f"Transient OpenRouter error {r.status_code}: {r.text}"
                    time.sleep(0.5 * attempt)
                    continue
                if r.status_code >= 400:
                    raise RuntimeError(f"OpenRouter API error {r.status_code}: {r.text}")

                data = r.json()
                content = (
                    data.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                    or ""
                ).strip()
                if not content:
                    raise RuntimeError("OpenRouter returned empty content.")
                return content

            except requests.RequestException as e:
                last_err = f"RequestException: {e}"
                time.sleep(0.5 * attempt)

        raise RuntimeError(f"OpenRouter classify failed after retries. Last error: {last_err}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_json(text: str) -> str:
    """Best-effort extraction of JSON from LLM output."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    if text.startswith("{") and text.endswith("}"):
        return text
    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    return m.group(0).strip() if m else text


def _vuln_text_blob(v: Vulnerability) -> str:
    """Combine all text fields for keyword matching."""
    return " ".join(
        filter(None, [v.title, v.description or "", v.recommendation or ""])
    ).lower()


def _build_prompt(v: Vulnerability) -> str:
    return (
        "Classify this OpenSCAP finding into exactly one category:\n"
        "safe_to_remediate, requires_human_review, too_dangerous_to_remediate.\n\n"
        "Return ONLY JSON for this schema:\n"
        "{\n"
        '  "finding_id": string,\n'
        '  "rule_id": string,\n'
        '  "category": "safe_to_remediate"|"requires_human_review"|"too_dangerous_to_remediate",\n'
        '  "confidence": number between 0 and 1,\n'
        '  "rationale": string,\n'
        '  "risk_factors": [string,...],\n'
        '  "safe_next_steps": [string,...],\n'
        '  "requires_reboot": boolean,\n'
        '  "touches_authn_authz": boolean,\n'
        '  "touches_networking": boolean,\n'
        '  "touches_filesystems": boolean\n'
        "}\n\n"
        "Finding:\n"
        f"- finding_id: {v.id}\n"
        f"- rule_id: {v.title}\n"
        f"- severity: {v.severity}\n"
        f"- title: {v.title}\n"
        f"- description: {(v.description or '')[:900]}\n"
        f"- recommendation: {(v.recommendation or '')[:900]}\n\n"
        "Policy:\n"
        "- Be conservative. If unclear, choose requires_human_review.\n"
        "- Mark too_dangerous_to_remediate for partitioning/filesystem/bootloader/FIPS changes.\n"
        "- Mark requires_human_review for auth/ssh/sudo/pam/password changes.\n"
        "- Mark safe_to_remediate for low-risk package installs, service enablement, "
        "sysctl persistence that is unlikely to lock out access.\n"
    )


def _verdict_to_decision(v: _LLMVerdict) -> TriageDecision:
    """Map the richer internal _LLMVerdict to the pipeline TriageDecision."""
    category = v.category

    if category == "safe_to_remediate":
        should_remediate = True
        requires_human_review = False
        risk_level = "low"
    elif category == "requires_human_review":
        should_remediate = False
        requires_human_review = True
        risk_level = "medium"
    else:  # too_dangerous_to_remediate
        should_remediate = False
        requires_human_review = False
        risk_level = "critical"

    # Build estimated_impact from risk flags
    impact_parts: List[str] = []
    if v.requires_reboot:
        impact_parts.append("reboot required")
    if v.touches_authn_authz:
        impact_parts.append("authentication/authorization affected")
    if v.touches_networking:
        impact_parts.append("networking affected")
    if v.touches_filesystems:
        impact_parts.append("filesystems affected")
    if v.risk_factors:
        impact_parts.extend(v.risk_factors)

    return TriageDecision(
        finding_id=v.finding_id,
        should_remediate=should_remediate,
        risk_level=risk_level,
        reason=v.rationale,
        requires_human_review=requires_human_review,
        estimated_impact="; ".join(impact_parts) if impact_parts else None,
    )


# ---------------------------------------------------------------------------
# Heuristic pre-triage (fast, no LLM)
# ---------------------------------------------------------------------------

def _heuristic_triage(v: Vulnerability) -> Optional[_LLMVerdict]:
    """Return a verdict for high-confidence patterns, or None to defer to LLM."""
    blob = _vuln_text_blob(v)

    # Partition / filesystem / mount-option → too dangerous
    if any(
        kw in blob
        for kw in [
            "separate partition", "separate filesystem"
        ]
        #"mount option", "partitioning", "filesystem", "fstab", "grub", "bootloader", "fips",
    ):
        return _LLMVerdict(
            finding_id=v.id,
            rule_id=v.title,
            category="too_dangerous_to_remediate",
            confidence=0.85,
            rationale=(
                "Filesystem/partition/mount-option changes can break boot or "
                "services and should not be auto-remediated."
            ),
            risk_factors=["filesystems/partitioning", "service disruption risk"],
            safe_next_steps=[
                "Document required partitions/mount options and implement during rebuild.",
                "Validate application compatibility with mount options in a staging VM.",
            ],
            requires_reboot=True,
            touches_filesystems=True,
        )

    # Auth / password / PAM / SSH → human review
    """
    if any(
        kw in blob
        for kw in [
            "pam", "pwquality", "password", "chage", "lockout",
            "sudoers", "sshd_config", "permitrootlogin", "passwordauthentication",
        ]
    ):
    
        return _LLMVerdict(
            finding_id=v.id,
            rule_id=v.title,
            category="requires_human_review",
            confidence=0.70,
            rationale=(
                "Authentication/authorization hardening can lock out SSH/automation. "
                "Requires review and staged rollout."
            ),
            risk_factors=["potential lockout", "access control changes"],
            safe_next_steps=[
                "Ensure you have console access/snapshot before changes.",
                "Prefer creating a dedicated automation user with controlled sudo rules.",
                "Apply changes in staging VM and verify SSH access before promoting.",
            ],
            requires_reboot=False,
            touches_authn_authz=True,
            touches_networking=True,
        )
        """

    return None


# ---------------------------------------------------------------------------
# TriageAgent
# ---------------------------------------------------------------------------

class TriageAgent(BaseAgent):
    """
    First stage of the pipeline.

    Input:  TriageInput  (schemas.Vulnerability + optional system_context)
    Output: TriageDecision  (should_remediate, risk_level, reason, …)
    """

    agent_name = "TriageAgent"

    def __init__(
        self,
        *,
        mode: str = "balanced",
        model_override: Optional[str] = None,
        fallback_models: Optional[List[str]] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 60,
    ):
        api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not set. "
                "Provide it as an argument or set it in .env / environment."
            )

        spec = MODELS_BY_MODE.get(mode, MODELS_BY_MODE["balanced"])
        chosen_model = model_override or os.getenv("OPENROUTER_MODEL") or spec.name

        self._client = _OpenRouterClient(
            api_key=api_key,
            model=chosen_model,
            base_url=base_url or os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            timeout=timeout,
            temperature=spec.temperature,
            max_tokens=spec.max_tokens,
        )
        self._fallback_models: List[str] = fallback_models or []

    # ------------------------------------------------------------------
    # BaseAgent contract
    # ------------------------------------------------------------------
    def process(self, input_data: TriageInput) -> TriageDecision:
        """
        Triage a single vulnerability.

        Args:
            input_data: TriageInput containing the Vulnerability to classify.

        Returns:
            TriageDecision with should_remediate, risk_level, reason, etc.
        """
        vuln = input_data.vulnerability
        self.log_info(f"Triaging {vuln.id}: {vuln.title}")

        # 1) Try fast heuristic
        hv = _heuristic_triage(vuln)
        if hv is not None:
            self.log_info(f"  → heuristic: {hv.category}")
            return _verdict_to_decision(hv)

        # 2) LLM classification (with fallback chain)
        verdict = self._classify_with_llm(vuln)
        self.log_info(f"  → LLM: {verdict.category}")
        return _verdict_to_decision(verdict)

    # ------------------------------------------------------------------
    # Convenience: triage a batch of Vulnerabilities
    # ------------------------------------------------------------------
    def triage_batch(
        self,
        vulnerabilities: List[Vulnerability],
        *,
        min_severity: int = 0,
        sleep_s: float = 0.0,
    ) -> List[TriageDecision]:
        """
        Triage a list of Vulnerabilities, returning one TriageDecision each.

        Filters out items below *min_severity* (parsed as int from the
        severity string, defaulting to 0).
        """
        results: List[TriageDecision] = []
        for vuln in vulnerabilities:
            try:
                sev = int(vuln.severity)
            except (ValueError, TypeError):
                sev = 0

            if sev < min_severity:
                continue

            decision = self.process(TriageInput(vulnerability=vuln))
            results.append(decision)

            if sleep_s > 0:
                time.sleep(sleep_s)

        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _classify_with_llm(self, vuln: Vulnerability) -> _LLMVerdict:
        """Call OpenRouter (with fallback models) and parse the response."""
        prompt = _build_prompt(vuln)
        candidates = [self._client.model] + [
            m for m in self._fallback_models if m != self._client.model
        ]

        last_err: Optional[str] = None
        orig_model = self._client.model

        for model_name in candidates:
            try:
                self._client.model = model_name
                raw = self._client.classify(prompt)
                js = _extract_json(raw)
                return _LLMVerdict.model_validate_json(js)

            except (ValidationError, json.JSONDecodeError) as exc:
                last_err = f"Validation/JSON error with {model_name}: {exc}"
            except Exception as exc:
                last_err = f"API/runtime error with {model_name}: {exc}"
            finally:
                self._client.model = orig_model

        # Conservative fallback when all models fail
        self.log_warning(f"LLM triage failed for {vuln.id}; defaulting to human review. ({last_err})")
        return _LLMVerdict(
            finding_id=vuln.id,
            rule_id=vuln.title,
            category="requires_human_review",
            confidence=0.40,
            rationale=f"LLM triage failed; defaulting to requires_human_review. Last error: {last_err}",
            risk_factors=["triage automation failure"],
            safe_next_steps=["Review manually; verify rule intent in STIG/SSG guidance."],
        )

    # ------------------------------------------------------------------
    # Output: JSON results file
    # ------------------------------------------------------------------
    def write_results_json(
        self,
        decisions: List[TriageDecision],
        output_path: str | Path = "triage_results.json",
        *,
        target_host: str = "unknown",
        total_rules_scanned: int = 0,
        rules_passed: int = 0,
        rules_failed: int = 0,
    ) -> Path:
        """
        Write a machine-readable JSON report of triage decisions.

        Returns the resolved output path.
        """
        out = Path(output_path)

        counts = {"safe": 0, "human_review": 0, "no_action": 0}
        for d in decisions:
            if d.should_remediate:
                counts["safe"] += 1
            elif d.requires_human_review:
                counts["human_review"] += 1
            else:
                counts["no_action"] += 1

        report = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "target_host": target_host,
            "scan_statistics": {
                "total_rules_scanned": total_rules_scanned,
                "rules_passed": rules_passed,
                "rules_failed": rules_failed,
            },
            "total_triaged": len(decisions),
            "counts": counts,
            "decisions": [d.model_dump() for d in decisions],
        }

        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        self.log_info(f"JSON results saved to {out}")
        return out

    # ------------------------------------------------------------------
    # Output: PDF report
    # ------------------------------------------------------------------
    def write_results_pdf(
        self,
        decisions: List[TriageDecision],
        output_path: str | Path = "triage_report.pdf",
        *,
        target_host: str = "unknown",
        title: str = "OpenSCAP Triage Report",
        total_rules_scanned: int = 0,
        rules_passed: int = 0,
        rules_failed: int = 0,
        vulnerabilities: Optional[List[Vulnerability]] = None,
    ) -> Path:
        """
        Generate a neatly formatted PDF report of triage decisions.

        Uses reportlab (already in requirements.txt).
        Returns the resolved output path.
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
        page_size = landscape(letter)  # landscape to fit all scan columns
        doc = SimpleDocTemplate(
            str(out),
            pagesize=page_size,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            rightMargin=0.5 * inch,
        )

        # Build a lookup from finding_id → Vulnerability for scan columns
        vuln_map: Dict[str, Vulnerability] = {}
        if vulnerabilities:
            for v in vulnerabilities:
                vuln_map[v.id] = v

        styles = getSampleStyleSheet()
        elements: list = []

        # -- Custom styles --
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontSize=20,
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.grey,
            spaceAfter=14,
        )
        section_style = ParagraphStyle(
            "SectionHeader",
            parent=styles["Heading2"],
            fontSize=14,
            spaceBefore=18,
            spaceAfter=8,
            textColor=colors.HexColor("#1a1a2e"),
        )
        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
        )
        cell_style = ParagraphStyle(
            "Cell",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
        )

        # -- Title block --
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elements.append(Paragraph(title, title_style))
        elements.append(Paragraph(f"Target: {target_host} &nbsp;|&nbsp; Generated: {now}", subtitle_style))

        # -- Summary counts --
        safe = sum(1 for d in decisions if d.should_remediate)
        review = sum(1 for d in decisions if d.requires_human_review)
        blocked = len(decisions) - safe - review

        elements.append(Paragraph("Scan Statistics", section_style))
        scan_data = [
            ["Total Rules Scanned", str(total_rules_scanned)],
            ["Rules Passed", str(rules_passed)],
            ["Rules Failed / Errors", str(rules_failed)],
        ]
        scan_table = Table(scan_data, colWidths=[3 * inch, 1.5 * inch])
        scan_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8f5e9")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        elements.append(scan_table)
        elements.append(Spacer(1, 14))

        elements.append(Paragraph("Triage Summary", section_style))
        summary_data = [
            ["Total Findings Triaged", str(len(decisions))],
            ["Safe to Remediate", str(safe)],
            ["Requires Human Review", str(review)],
            ["Too Dangerous / Blocked", str(blocked)],
        ]
        summary_table = Table(summary_data, colWidths=[3 * inch, 1.5 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f5")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 14))

        # -- Colour helper --
        def _risk_color(level: str) -> colors.Color:
            return {
                "low": colors.HexColor("#27ae60"),
                "medium": colors.HexColor("#f39c12"),
                "high": colors.HexColor("#e67e22"),
                "critical": colors.HexColor("#e74c3c"),
            }.get(level.lower(), colors.black)

        # -- Per-category sections --
        _SECTIONS = [
            ("Safe to Remediate", lambda d: d.should_remediate),
            ("Requires Human Review", lambda d: d.requires_human_review and not d.should_remediate),
            ("Too Dangerous to Remediate", lambda d: not d.should_remediate and not d.requires_human_review),
        ]

        for header, predicate in _SECTIONS:
            items = [d for d in decisions if predicate(d)]
            elements.append(Paragraph(f"{header} ({len(items)})", section_style))

            if not items:
                elements.append(Paragraph("None.", body_style))
                elements.append(Spacer(1, 8))
                continue

            table_data = [
                [
                    Paragraph("<b>ID</b>", cell_style),
                    Paragraph("<b>Rule</b>", cell_style),
                    Paragraph("<b>Title</b>", cell_style),
                    Paragraph("<b>Severity</b>", cell_style),
                    Paragraph("<b>Result</b>", cell_style),
                    Paragraph("<b>Host</b>", cell_style),
                    Paragraph("<b>OS</b>", cell_style),
                    Paragraph("<b>Risk</b>", cell_style),
                    Paragraph("<b>Reason</b>", cell_style),
                    Paragraph("<b>Impact</b>", cell_style),
                ],
            ]
            for d in items:
                v = vuln_map.get(d.finding_id)
                risk_text = f'<font color="{_risk_color(d.risk_level).hexval()}">{d.risk_level.upper()}</font>'
                sev_label = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}.get(
                    v.severity if v else "", v.severity if v else "\u2014"
                )
                table_data.append([
                    Paragraph(d.finding_id, cell_style),
                    Paragraph((v.rule or "\u2014") if v else "\u2014", cell_style),
                    Paragraph((v.title or "\u2014")[:80] if v else "\u2014", cell_style),
                    Paragraph(str(sev_label), cell_style),
                    Paragraph((v.result or "\u2014").upper() if v else "\u2014", cell_style),
                    Paragraph((v.host or "\u2014") if v else "\u2014", cell_style),
                    Paragraph((v.os or "\u2014") if v else "\u2014", cell_style),
                    Paragraph(risk_text, cell_style),
                    Paragraph(d.reason[:150], cell_style),
                    Paragraph(d.estimated_impact or "\u2014", cell_style),
                ])

            col_widths = [
                0.7 * inch,   # ID
                1.2 * inch,   # Rule
                1.5 * inch,   # Title
                0.55 * inch,  # Severity
                0.5 * inch,   # Result
                0.9 * inch,   # Host
                0.7 * inch,   # OS
                0.5 * inch,   # Risk
                2.2 * inch,   # Reason
                1.25 * inch,  # Impact
            ]
            t = Table(table_data, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                # Header row
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                # Body rows
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
                # Grid
                ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 10))

        # -- Build PDF --
        doc.build(elements)
        self.log_info(f"PDF report saved to {out}")
        return out