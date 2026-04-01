"""
QA Agent V2: Expert-opinion-only system safety validation (no tools).

In the v2 pipeline the QA agent is called by the Review agent BEFORE the
fix is scanned.  Since the fix has already been applied but not yet verified,
the QA agent acts as a preventative check — providing an expert opinion on
whether the applied remediation is likely safe, without running any commands.

This is an LLM-only agent (like the Review agent).  It uses a single
OpenRouter completion call to evaluate the remediation and return a
QAResult with its safety verdict.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from schemas import (
    QAInput,
    QAResult,
    RunCommandResult,
)

DEFAULT_OPENROUTER_BASE = "https://openrouter.ai/api/v1"
DEFAULT_QA_V2_MODEL = "nvidia/nemotron-3-nano-30b-a3b:free"


def _get_config() -> Tuple[str, str, str]:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is required.")
    base_url = (os.getenv("OPENROUTER_BASE_URL") or DEFAULT_OPENROUTER_BASE).rstrip("/")
    model = os.getenv("OPENROUTER_MODEL") or os.getenv("QA_AGENT_V2_MODEL") or DEFAULT_QA_V2_MODEL
    return api_key, base_url, model


def _build_qa_prompt(input_data: QAInput) -> str:
    """Build a prompt for the LLM to evaluate system safety."""
    vuln = input_data.vulnerability
    attempt = input_data.remediation_attempt
    review = input_data.review_verdict

    lines = [
        "You are a system safety expert for Linux (Rocky Linux / RHEL).",
        "Evaluate whether the following proposed remediation plan would be safe for the system.",
        "You are providing a PREVENTATIVE expert opinion — the plan has NOT been executed yet.",
        "",
        "## Vulnerability",
        f"- ID: {vuln.id}",
        f"- Title: {vuln.title}",
        f"- Severity: {vuln.severity}",
        f"- Description: {vuln.description or '(none)'}",
        f"- Recommendation: {vuln.recommendation or '(none)'}",
        "",
        "## Proposed Remediation Plan",
        "(NOTE: This plan has NOT been executed yet. Evaluate whether it WOULD be safe if executed.)",
        "",
    ]

    if attempt.llm_verdict:
        lines.append(attempt.llm_verdict.message)

    lines.extend([
        "",
        "## Review Verdict",
        f"- Approved: {review.approve}",
        f"- Optimal: {review.is_optimal}",
        f"- Security score: {review.security_score}",
    ])
    if review.feedback:
        lines.append(f"- Feedback: {review.feedback}")
    if review.concerns:
        lines.append(f"- Concerns: {', '.join(review.concerns)}")

    lines.extend([
        "",
        "## Your Task",
        "Evaluate whether this remediation is likely safe. Consider:",
        "- Could it break critical services (sshd, auditd, firewalld, networking)?",
        "- Could it lock out SSH access or break authentication?",
        "- Does the approach seem correct for this type of vulnerability?",
        "- Are there potential side effects or regressions?",
        "",
        "Respond with a single JSON object (no markdown, no extra text) with these keys:",
        "finding_id (string), safe (bool), verdict_reason (string),",
        "side_effects (list of strings), services_affected (list of strings),",
        "recommendation (string: 'Approve' | 'Rollback' | 'Investigate').",
        "",
        "GUIDELINES:",
        "- Mark safe=true if the remediation looks correct and unlikely to break the system.",
        "- Mark safe=false ONLY if the fix is likely to cause real damage (service outages,",
        "  lockouts, data loss, or security degradation).",
        "- Configuration changes for security hardening are EXPECTED — they are not side effects.",
        "- Be pragmatic: a working fix that addresses the vulnerability should be approved.",
    ])
    return "\n".join(lines)


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
        "response_format": {"type": "json_object"},
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
                metrics_tracker.record_call(None, agent="qa", model=model, start_time=start_time, error=True, error_message=f"HTTP {resp.status_code}")
            raise RuntimeError(f"OpenRouter API error {resp.status_code}: {resp.text}")
        data = resp.json()
        if metrics_tracker is not None:
            metrics_tracker.record_call(data, agent="qa", model=model, start_time=start_time)
    except Exception:
        if metrics_tracker is not None and start_time is not None:
            metrics_tracker.record_call(None, agent="qa", model=model, start_time=start_time, error=True, error_message="request exception")
        raise
    choice = data.get("choices", [{}])[0]
    message = choice.get("message", {})
    content = message.get("content") or ""
    usage = data.get("usage")
    return content.strip(), message, usage, _api_duration


def _parse_qa_result(raw: str, finding_id: str) -> QAResult:
    """Parse LLM response into QAResult; fallback on failure."""
    text = raw.strip()
    json_match = re.search(r"\{[\s\S]*\}", text)
    if json_match:
        text = json_match.group(0)
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return QAResult(
            finding_id=finding_id,
            safe=False,
            verdict_reason=f"QA output was not valid JSON. Raw: {raw[:200]}...",
            recommendation="Investigate",
        )

    side_effects = obj.get("side_effects", [])
    if not isinstance(side_effects, list):
        side_effects = []
    services = obj.get("services_affected", [])
    if not isinstance(services, list):
        services = []

    return QAResult(
        finding_id=str(obj.get("finding_id", finding_id)),
        safe=bool(obj.get("safe", False)),
        verdict_reason=obj.get("verdict_reason", ""),
        side_effects=[str(s) for s in side_effects],
        services_affected=[str(s) for s in services],
        recommendation=obj.get("recommendation", "Investigate"),
    )


class QAAgentV2:
    """
    QA Agent V2: LLM-only expert opinion (no tools, no commands).

    Provides a preventative safety assessment of the remediation.
    """

    SYSTEM_PROMPT = (
        "You are a pragmatic system safety expert for Linux security remediation. "
        "You are evaluating a PROPOSED PLAN before execution. Given a vulnerability "
        "and the proposed remediation plan, evaluate whether the plan would be safe "
        "for the system if executed.\n\n"
        "SAFETY GUIDELINES:\n"
        "- Mark safe=true if the proposed plan is correct and unlikely to break "
        "critical services or lock out access when executed.\n"
        "- Mark safe=false ONLY if the plan would likely cause service outages, lockouts, "
        "data loss, or other serious issues.\n"
        "- Security configuration changes are EXPECTED and are NOT side effects.\n"
        "- Be pragmatic: if the plan addresses the vulnerability correctly, approve it.\n"
        "- Do NOT mark unsafe because commands have not been run yet — they will be "
        "executed after your approval.\n\n"
        "You respond only with a JSON object with the requested keys; no markdown code "
        "fences or extra text."
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
        self.model = model or os.getenv("OPENROUTER_MODEL") or os.getenv("QA_AGENT_V2_MODEL") or DEFAULT_QA_V2_MODEL
        self.request_timeout = request_timeout
        self.metrics_tracker = metrics_tracker
        self._transcript_dir: Optional[Path] = Path(transcript_dir) if transcript_dir else None
        if self._transcript_dir:
            self._transcript_dir.mkdir(parents=True, exist_ok=True)

    def process(self, input_data: QAInput, *, attempt: int = 1) -> QAResult:
        """Run QA validation: LLM expert opinion only, no commands."""
        start = time.time()
        user_prompt = _build_qa_prompt(input_data)
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
            tp = self._transcript_dir / f"qa_transcript_{vid}_attempt{attempt}.json"
            tp.write_text(json.dumps(transcript_data, indent=2, default=str), encoding="utf-8")

        result = _parse_qa_result(raw, input_data.vulnerability.id)
        result.validation_duration = time.time() - start
        return result
