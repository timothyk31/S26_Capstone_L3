#!/usr/bin/env python3
"""
braintrust_eval_writer.py — Log V2 pipeline results to Braintrust.

Each pipeline run becomes an *experiment* inside a single Braintrust *project*.
Experiment names include model info so you can compare runs side-by-side.

Scoring:
  - remediated  →  score = 1
  - anything else  →  score = 0

Columns (one per agent):
  triage_output, remedy_output, review_output, qa_output

Requires:
  pip install braintrust
  Set BRAINTRUST_API_KEY in .env or environment.

Usage:
  # From main_multiagent.py — results + model_metadata are passed directly.
  # Standalone — loads from v2_aggregated_results.json on disk.
  python braintrust_eval_writer.py
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from dotenv import find_dotenv, load_dotenv

if TYPE_CHECKING:
    from schemas import V2FindingResult

DEFAULT_PROJECT = "OpenSCAP-Remediation-Pipeline"


# ── Extract structured output per agent ─────────────────────────────────────

def _extract_triage(r) -> Dict[str, Any]:
    t = getattr(r, "triage", None)
    if t is None:
        return {}
    return {
        "finding_id": t.finding_id,
        "should_remediate": t.should_remediate,
        "risk_level": t.risk_level,
        "reason": t.reason,
        "requires_human_review": t.requires_human_review,
    }


def _extract_remedy(r) -> Dict[str, Any]:
    """Extract the *final* remedy attempt."""
    rm = getattr(r, "remediation", None)
    if rm is None:
        return {}
    return {
        "attempt_number": rm.attempt_number,
        "commands_executed": rm.commands_executed,
        "scan_passed": rm.scan_passed,
        "success": rm.success,
        "error_summary": rm.error_summary,
        "duration": rm.duration,
    }


def _extract_all_attempts(r) -> List[Dict[str, Any]]:
    """Extract every remediation attempt (ordered by attempt number)."""
    attempts = getattr(r, "all_attempts", None) or []
    out = []
    for rm in attempts:
        out.append({
            "attempt_number": rm.attempt_number,
            "commands_executed": rm.commands_executed,
            "scan_passed": rm.scan_passed,
            "success": rm.success,
            "error_summary": rm.error_summary,
            "duration": rm.duration,
        })
    return out


def _extract_review(r) -> Dict[str, Any]:
    pa = getattr(r, "pre_approval", None)
    if pa is None:
        return {}
    rv = getattr(pa, "review_verdict", None)
    if rv is None:
        return {}
    return {
        "finding_id": rv.finding_id,
        "approve": rv.approve,
        "is_optimal": rv.is_optimal,
        "security_score": rv.security_score,
        "feedback": rv.feedback,
        "concerns": rv.concerns,
    }


def _extract_qa(r) -> Dict[str, Any]:
    pa = getattr(r, "pre_approval", None)
    if pa is None:
        return {}
    qa = getattr(pa, "qa_result", None)
    if qa is None:
        return {}
    return {
        "finding_id": qa.finding_id,
        "safe": qa.safe,
        "recommendation": qa.recommendation,
        "verdict_reason": qa.verdict_reason,
        "side_effects": qa.side_effects,
        "regression_detected": qa.regression_detected,
    }


# ── Core ────────────────────────────────────────────────────────────────────

def write_braintrust_eval(
    report_dir: str = "./reports",
    results: Optional[List["V2FindingResult"]] = None,
    experiment_name: Optional[str] = None,
    project_name: str = DEFAULT_PROJECT,
    model_metadata: Optional[Dict[str, str]] = None,
) -> None:
    """Log pipeline results to Braintrust as an experiment.

    Parameters
    ----------
    report_dir : str
        Directory to find / write fallback JSON.
    results : list[V2FindingResult] | None
        Pipeline results.  If *None*, loads from
        ``<report_dir>/v2_aggregated_results.json``.
    experiment_name : str | None
        Name shown in the Braintrust UI.  Defaults to a timestamped name
        that includes model info (if provided).
    project_name : str
        Braintrust project to log into (created automatically if needed).
    model_metadata : dict | None
        Mapping of agent name → model string, e.g.
        {"triage": "gpt-4o", "remedy": "claude-3.5-sonnet", ...}.
        Stored as experiment metadata so you can filter/compare.
    """
    import braintrust

    report_path = Path(report_dir)

    # Fall back to loading from JSON on disk
    if results is None:
        json_path = report_path / "v2_aggregated_results.json"
        if not json_path.exists():
            raise FileNotFoundError(
                f"No results provided and {json_path} not found."
            )
        from schemas import V2FindingResult
        raw = json.loads(json_path.read_text(encoding="utf-8"))
        results = [V2FindingResult(**entry) for entry in raw]

    # Build experiment name from models if not given
    if experiment_name is None:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        if model_metadata:
            model_tag = "_".join(
                m.rsplit("/", 1)[-1][:20] for m in model_metadata.values() if m
            )
            experiment_name = f"{model_tag}_{ts}"
        else:
            experiment_name = f"run_{ts}"

    metadata = model_metadata or {}

    # Open (or create) the Braintrust experiment
    experiment = braintrust.init(
        project=project_name,
        experiment=experiment_name,
    )

    for r in results:
        score = 1 if r.final_status == "success" else 0

        triage = _extract_triage(r)
        remedy = _extract_remedy(r)
        review = _extract_review(r)
        qa = _extract_qa(r)
        all_attempts = _extract_all_attempts(r)
        attempts_count = len(all_attempts)

        experiment.log(
            input=r.vulnerability.id,
            output={
                "triage_detail": triage,
                "remedy_detail": remedy,
                "review_detail": review,
                "qa_detail": qa,
                "all_remedy_attempts": all_attempts,
                "final_status": r.final_status,
            },
            scores={
                "remediated": score,
                "triage_should_remediate": 1 if triage.get("should_remediate") else 0,
                "triage_needs_human_review": 1 if triage.get("requires_human_review") else 0,
                "remedy_success": 1 if remedy.get("success") else 0,
                "remedy_scan_passed": 1 if remedy.get("scan_passed") else 0,
                "review_approved": 1 if review.get("approve") else 0,
                "review_security_score": min(float(review.get("security_score", 0) or 0) / 10.0, 1.0),
                "qa_safe": 1 if qa.get("safe") else 0,
                "qa_regression_detected": 1 if qa.get("regression_detected") else 0,
            },
            metadata={
                "total_duration": r.total_duration,
                "attempts_count": attempts_count,
                "title": r.vulnerability.title,
                "severity": r.vulnerability.severity,
                "rule": r.vulnerability.rule or "",
                **metadata,
            },
        )

    summary = experiment.summarize()
    print(f"Braintrust experiment '{experiment_name}' logged to project '{project_name}'.")
    print(f"  URL: {summary.experiment_url}")
    print(f"  Rows: {len(results)}")


if __name__ == "__main__":
    load_dotenv(find_dotenv(), override=False)

    model_metadata = {
        "triage": os.getenv("TRIAGE_MODEL"),
        "remedy": os.getenv("REMEDY_MODEL"),
        "review": os.getenv("REVIEW_MODEL"),
        "qa": os.getenv("QA_MODEL"),
    }
    write_braintrust_eval(model_metadata=model_metadata)
