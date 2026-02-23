#!/usr/bin/env python3
"""
Triage Agent for OpenSCAP DISA STIG (rl9/Rocky9) findings.

Pipeline:
1) Run OpenSCAP scan over SSH
2) Download XML + optional HTML report
3) Parse findings JSON (via parse_openscap)
4) For each finding (severity >= min), classify into:
   - safe_to_remediate
   - requires_human_review
   - too_dangerous_to_remediate
   using:
     (a) local heuristic pre-triage
     (b) OpenRouter LLM JSON output validated with Pydantic

Outputs:
- triage_results.json (machine-readable)
- triage_summary.md (human-readable)

Requires:
- requests
- pydantic (v2)
- python-dotenv
- your existing: openscap_cli.py, parse_openscap.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple

import requests
from dotenv import find_dotenv, load_dotenv
from pydantic import BaseModel, Field, ValidationError

from openscap_cli import OpenSCAPScanner
from parse_openscap import parse_openscap

# --- Load .env automatically (fixes OPENROUTER_API_KEY not found) ---
load_dotenv(find_dotenv(), override=False)

DEFAULT_PROFILE = "xccdf_org.ssgproject.content_profile_stig"
DEFAULT_DATASTREAM = "/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml"
DEFAULT_REMOTE_XML = "/tmp/oscap_stig_rl9.xml"
DEFAULT_LOCAL_XML = "oscap_stig_rl9.xml"
DEFAULT_PARSED_JSON = "oscap_stig_rl9_parsed.json"
DEFAULT_REMOTE_REPORT = "/tmp/oscap_report.html"
DEFAULT_LOCAL_REPORT = "oscap_stig_rl9_report.html"

DEFAULT_TRIAGE_JSON = "triage_results.json"
DEFAULT_TRIAGE_MD = "triage_summary.md"

# -----------------------------
# Pydantic models (outputs)
# -----------------------------

TriageCategory = Literal[
    "safe_to_remediate",
    "requires_human_review",
    "too_dangerous_to_remediate",
]


class Finding(BaseModel):
    # This matches typical parse_openscap outputs you've been using.
    id: str
    title: str
    severity: str = "0"
    host: str = ""
    result: str = ""
    rule: Optional[str] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    oval_id: Optional[str] = None

    def severity_int(self) -> int:
        try:
            return int(str(self.severity))
        except Exception:
            return 0


class TriageVerdict(BaseModel):
    finding_id: str = Field(..., description="Finding id from the scan (e.g., openscap_002)")
    rule_id: str = Field(..., description="XCCDF rule id (often in title or rule field)")
    category: TriageCategory
    confidence: float = Field(..., ge=0.0, le=1.0)
    rationale: str = Field(..., min_length=1)
    risk_factors: List[str] = Field(default_factory=list)
    safe_next_steps: List[str] = Field(default_factory=list)
    requires_reboot: bool = False
    touches_authn_authz: bool = False
    touches_networking: bool = False
    touches_filesystems: bool = False


class TriageRun(BaseModel):
    generated_at: str
    target_host: str
    profile: str
    model_used: str
    mode: str
    min_severity: int
    total_findings: int
    triaged_findings: int
    counts: Dict[TriageCategory, int]
    results: List[TriageVerdict]


# -----------------------------
# OpenRouter client
# -----------------------------

@dataclass(frozen=True)
class ModelSpec:
    name: str
    temperature: float = 0.0
    max_tokens: int = 600


MODELS_BY_MODE: Dict[str, ModelSpec] = {
    # quick switch presets
    "fast": ModelSpec(name="meta-llama/llama-3.1-8b-instruct", temperature=0.0, max_tokens=450),
    "balanced": ModelSpec(name="anthropic/claude-3.5-sonnet", temperature=0.0, max_tokens=650),
    "smart": ModelSpec(name="openai/gpt-4o", temperature=0.0, max_tokens=750),
    # Optional convenience preset for OpenRouter free nemotron usage:
    "nemotron_free": ModelSpec(name="nvidia/nemotron-4-mini-instruct", temperature=0.1, max_tokens=500),
}


class OpenRouterClient:
    def __init__(self, api_key: str, model: str, base_url: str, timeout: int, temperature: float, max_tokens: int):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.endpoint = f"{self.base_url}/chat/completions"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # Optional headers recommended by OpenRouter:
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
            # Helps routing / free-tier stability
            "provider": {"allow_fallbacks": True},
            # Best-effort JSON enforcement (some models honor this)
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
                r = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=self.timeout)
                if r.status_code in (429, 500, 502, 503, 504):
                    last_err = f"Transient OpenRouter error {r.status_code}: {r.text}"
                    time.sleep(0.5 * attempt)
                    continue
                if r.status_code >= 400:
                    raise RuntimeError(f"OpenRouter API error {r.status_code}: {r.text}")

                data = r.json()
                content = (data.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
                if not content:
                    raise RuntimeError("OpenRouter returned empty content.")
                return content

            except requests.RequestException as e:
                last_err = f"RequestException: {e}"
                time.sleep(0.5 * attempt)
                continue

        raise RuntimeError(f"OpenRouter classify failed after retries. Last error: {last_err}")


# -----------------------------
# Heuristic pre-triage
# -----------------------------

def heuristic_category(f: Finding) -> Optional[TriageVerdict]:
    """
    If we can confidently decide locally, return a verdict.
    Otherwise return None and let the LLM decide.
    """
    rule_blob = " ".join(filter(None, [f.title, f.rule or "", f.description or "", f.recommendation or ""])).lower()

    # Partition / filesystem rules: generally too dangerous to do automatically.
    if any(k in rule_blob for k in ["separate partition", "separate filesystem", "partition_for_", "mount option", "noexec", "nodev", "nosuid"]):
        return TriageVerdict(
            finding_id=f.id,
            rule_id=f.rule or f.title,
            category="too_dangerous_to_remediate",
            confidence=0.85,
            rationale="Filesystem/partition/mount-option changes can break boot or services and should not be auto-remediated.",
            risk_factors=["filesystems/partitioning", "service disruption risk"],
            safe_next_steps=[
                "Document required partitions/mount options and implement during rebuild (Kickstart/Anaconda).",
                "Validate application compatibility with mount options in a staging VM.",
            ],
            requires_reboot=True,
            touches_filesystems=True,
        )

    # Account/password/auth changes: usually human review (can lock out automation).
    if any(k in rule_blob for k in ["pam", "pwquality", "password", "chage", "lockout", "sudoers", "sshd_config", "permitrootlogin", "passwordauthentication"]):
        return TriageVerdict(
            finding_id=f.id,
            rule_id=f.rule or f.title,
            category="requires_human_review",
            confidence=0.70,
            rationale="Authentication/authorization hardening can lock out SSH/automation. Requires review and staged rollout.",
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

    return None


# -----------------------------
# Prompting + triage logic
# -----------------------------

def build_prompt(f: Finding) -> str:
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
        f"- finding_id: {f.id}\n"
        f"- rule_id: {f.rule or f.title}\n"
        f"- severity: {f.severity} (0=info,4=critical)\n"
        f"- result: {f.result}\n"
        f"- title: {f.title}\n"
        f"- description: {(f.description or '')[:900]}\n"
        f"- recommendation: {(f.recommendation or '')[:900]}\n\n"
        "Policy:\n"
        "- Be conservative. If unclear, choose requires_human_review.\n"
        "- Mark too_dangerous_to_remediate for partitioning/filesystem/bootloader/FIPS changes.\n"
        "- Mark requires_human_review for auth/ssh/sudo/pam/password changes.\n"
        "- Mark safe_to_remediate for low-risk package installs, service enablement, sysctl persistence that is unlikely to lock out access.\n"
    )


def extract_json(text: str) -> str:
    """
    Best-effort extraction if the model wraps JSON in extra text.
    Handles code fences and extra prose; Pydantic still enforces correctness.
    """
    text = text.strip()
    # Strip ```json ... ``` or ``` ... ```
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)

    if text.startswith("{") and text.endswith("}"):
        return text

    m = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if m:
        return m.group(0).strip()

    return text


def triage_findings(
    findings: List[Finding],
    client: OpenRouterClient,
    min_sev: int,
    fallback_models: List[str],
    sleep_s: float = 0.0,
) -> Tuple[List[TriageVerdict], str]:
    """
    Returns (triage_results, model_used_for_majority)
    """
    triaged: List[TriageVerdict] = []
    model_used_counter: Dict[str, int] = {}

    for f in findings:
        if f.result not in ("fail", "error"):
            continue
        if f.severity_int() < min_sev:
            continue

        # 1) heuristics first
        hv = heuristic_category(f)
        if hv is not None:
            triaged.append(hv)
            model_used_counter["heuristic"] = model_used_counter.get("heuristic", 0) + 1
            continue

        # 2) LLM classification (with fallback)
        prompt = build_prompt(f)
        candidates = [client.model] + [m for m in fallback_models if m and m != client.model]

        last_err: Optional[str] = None
        verdict: Optional[TriageVerdict] = None

        orig_model = client.model
        for mname in candidates:
            try:
                client.model = mname
                raw = client.classify(prompt)
                js = extract_json(raw)
                verdict = TriageVerdict.model_validate_json(js)

                model_used_counter[mname] = model_used_counter.get(mname, 0) + 1
                break

            except (ValidationError, json.JSONDecodeError) as e:
                last_err = f"Validation/JSON error with model {mname}: {e}"
                continue
            except Exception as e:
                last_err = f"API/runtime error with model {mname}: {e}"
                continue
            finally:
                client.model = orig_model  # always restore

        if verdict is None:
            verdict = TriageVerdict(
                finding_id=f.id,
                rule_id=f.rule or f.title,
                category="requires_human_review",
                confidence=0.40,
                rationale=f"LLM triage failed; defaulting to requires_human_review. Last error: {last_err}",
                risk_factors=["triage automation failure"],
                safe_next_steps=["Review manually; verify rule intent in STIG/SSG guidance."],
                requires_reboot=False,
                touches_authn_authz=False,
                touches_networking=False,
                touches_filesystems=False,
            )
            model_used_counter["fallback_default"] = model_used_counter.get("fallback_default", 0) + 1

        triaged.append(verdict)

        if sleep_s > 0:
            time.sleep(sleep_s)

    majority_model = max(model_used_counter.items(), key=lambda kv: kv[1])[0] if model_used_counter else client.model
    return triaged, majority_model


def write_summary_md(path: Path, run: TriageRun) -> None:
    def pct(n: int) -> str:
        return f"{(n / max(1, run.triaged_findings)) * 100:.1f}%"

    lines: List[str] = []
    lines.append("# OpenSCAP Triage Summary\n\n")
    lines.append(f"- Generated: **{run.generated_at}**\n")
    lines.append(f"- Target: **{run.target_host}**\n")
    lines.append(f"- Profile: **{run.profile}**\n")
    lines.append(f"- Mode: **{run.mode}**\n")
    lines.append(f"- Model used (majority): **{run.model_used}**\n")
    lines.append(f"- Min severity: **{run.min_severity}**\n")
    lines.append(f"- Triaged findings: **{run.triaged_findings}**\n\n")

    lines.append("## Counts\n\n")
    for cat in ["safe_to_remediate", "requires_human_review", "too_dangerous_to_remediate"]:
        c = run.counts.get(cat, 0)
        lines.append(f"- **{cat}**: {c} ({pct(c)})\n")

    def section(cat: TriageCategory, header: str) -> None:
        items = [r for r in run.results if r.category == cat]
        lines.append(f"\n## {header} ({len(items)})\n\n")
        for r in items[:60]:  # cap for readability
            lines.append(f"### {r.finding_id}\n")
            lines.append(f"- rule_id: `{r.rule_id}`\n")
            lines.append(f"- confidence: {r.confidence:.2f}\n")
            lines.append(f"- rationale: {r.rationale}\n")
            if r.risk_factors:
                lines.append(f"- risk_factors: {', '.join(r.risk_factors)}\n")
            if r.safe_next_steps:
                lines.append("- safe_next_steps:\n")
                for s in r.safe_next_steps[:6]:
                    lines.append(f"  - {s}\n")
            lines.append("\n")

    section("safe_to_remediate", "Safe to remediate")
    section("requires_human_review", "Requires human review")
    section("too_dangerous_to_remediate", "Too dangerous to remediate")

    path.write_text("".join(lines), encoding="utf-8")


# -----------------------------
# CLI + main
# -----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OpenSCAP STIG rl9 triage agent (OpenRouter + Pydantic)")
    p.add_argument("--host", required=True)
    p.add_argument("--user", default="root")
    p.add_argument("--key", help="SSH private key path")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--sudo-password", help="Sudo password on target (if needed)")
    p.add_argument("--profile", default=DEFAULT_PROFILE)
    p.add_argument("--datastream", default=DEFAULT_DATASTREAM)

    p.add_argument("--remote-output", default=DEFAULT_REMOTE_XML)
    p.add_argument("--local-output", default=DEFAULT_LOCAL_XML)
    p.add_argument("--parsed-output", default=DEFAULT_PARSED_JSON)
    p.add_argument("--report", default=DEFAULT_REMOTE_REPORT)
    p.add_argument("--local-report", default=DEFAULT_LOCAL_REPORT)

    p.add_argument("--min-severity", type=int, default=2, choices=[0, 1, 2, 3, 4])

    # OpenRouter config
    p.add_argument("--mode", choices=list(MODELS_BY_MODE.keys()), default="balanced", help="Quick model switch preset")
    p.add_argument("--model", default=None, help="Override model name (takes precedence over --mode)")
    p.add_argument("--fallback-model", action="append", default=[], help="Optional fallback models. You can pass multiple times.")
    p.add_argument("--openrouter-base-url", default=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"))
    p.add_argument("--openrouter-timeout", type=int, default=int(os.getenv("OPENROUTER_TIMEOUT", "60")))

    # Output
    p.add_argument("--triage-json", default=DEFAULT_TRIAGE_JSON)
    p.add_argument("--triage-md", default=DEFAULT_TRIAGE_MD)

    # Rate limiting
    p.add_argument("--sleep", type=float, default=0.0, help="Seconds to sleep between LLM calls")

    return p.parse_args()


def main() -> int:
    args = parse_args()

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise SystemExit(
            "ERROR: OPENROUTER_API_KEY is not set.\n"
            "Fix: ensure .env is in the same directory (or parent), and contains:\n"
            "OPENROUTER_API_KEY=sk-or-v1-...\n"
            "Or export it: export OPENROUTER_API_KEY=...\n"
        )

    spec = MODELS_BY_MODE[args.mode]
    chosen_model = args.model or os.getenv("OPENROUTER_MODEL") or spec.name

    client = OpenRouterClient(
        api_key=api_key,
        model=chosen_model,
        base_url=args.openrouter_base_url,
        timeout=args.openrouter_timeout,
        temperature=spec.temperature,
        max_tokens=spec.max_tokens,
    )

    scanner = OpenSCAPScanner(
        target_host=args.host,
        ssh_user=args.user,
        ssh_key=args.key,
        ssh_port=args.port,
    )

    print(f"Running OpenSCAP scan on {args.host}...")
    ok = scanner.run_scan(
        profile=args.profile,
        output_file=args.remote_output,
        datastream=args.datastream,
        report_file=args.report,
        sudo_password=args.sudo_password,
    )
    if not ok:
        return 1

    local_xml = Path(args.local_output)
    if not scanner.download_results(args.remote_output, str(local_xml)):
        return 1

    # parse findings
    parsed_path = Path(args.parsed_output)
    parse_openscap(str(local_xml), str(parsed_path))
    try:
        raw_findings = json.loads(parsed_path.read_text(encoding="utf-8"))
    except Exception:
        raw_findings = []

    findings: List[Finding] = []
    for d in raw_findings:
        try:
            findings.append(Finding(**d))
        except ValidationError:
            continue

    triaged, majority = triage_findings(
        findings=findings,
        client=client,
        min_sev=args.min_severity,
        fallback_models=args.fallback_model,
        sleep_s=args.sleep,
    )

    counts: Dict[TriageCategory, int] = {
        "safe_to_remediate": 0,
        "requires_human_review": 0,
        "too_dangerous_to_remediate": 0,
    }
    for v in triaged:
        counts[v.category] += 1

    run = TriageRun(
        generated_at=datetime.now().isoformat(timespec="seconds"),
        target_host=args.host,
        profile=args.profile,
        model_used=majority,
        mode=args.mode,
        min_severity=args.min_severity,
        total_findings=len(findings),
        triaged_findings=len(triaged),
        counts=counts,
        results=triaged,
    )

    out_json = Path(args.triage_json)
    out_json.write_text(run.model_dump_json(indent=2), encoding="utf-8")
    print(f"Triage JSON saved to: {out_json}")

    out_md = Path(args.triage_md)
    write_summary_md(out_md, run)
    print(f"Triage summary saved to: {out_md}")

    print("Counts:", counts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
