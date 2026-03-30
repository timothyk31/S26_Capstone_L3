#!/usr/bin/env python3
"""
csv_export.py — Export pipeline results to CSV for Braintrust upload and analytics.

Produces two CSV files:
  - findings_detail.csv   : one row per finding with all agent outputs, timing, and LLM metrics
  - pipeline_summary.csv  : aggregate stats in section/metric/value/category format (graph-ready)

Usage from main_multiagent.py:
    from csv_export import write_csv_report
    detail_csv, summary_csv = write_csv_report(results=results, ...)

Standalone (loads from v2_aggregated_results.json):
    python csv_export.py
"""
from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from schemas import V2FindingResult


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sanitize(text: Optional[str]) -> str:
    """Strip newlines from text so CSV cells stay single-line."""
    if not text:
        return ""
    return " ".join(text.split())


def _join(items: Optional[List[str]]) -> str:
    """Join a list into a semicolon-separated string."""
    if not items:
        return ""
    return "; ".join(str(i) for i in items)


def _build_round_lookup(
    fixed_at_round: Optional[Dict[int, List[str]]],
) -> Dict[str, int]:
    """Invert {round: [finding_ids]} → {finding_id: round}."""
    if not fixed_at_round:
        return {}
    lookup: Dict[str, int] = {}
    for rnd, ids in fixed_at_round.items():
        for fid in ids:
            lookup[fid] = rnd
    return lookup


# ── Detail CSV columns ────────────────────────────────────────────────────────

DETAIL_COLUMNS = [
    # Identification
    "finding_id", "title", "severity", "host", "rule", "oval_id", "scan_class", "os",
    # Triage
    "triage_should_remediate", "triage_risk_level", "triage_reason",
    "triage_requires_human_review", "triage_estimated_impact", "triage_estimated_complexity",
    # Result
    "final_status", "remediated_at_round", "total_attempts",
    # Remedy (final attempt)
    "remedy_commands_executed", "remedy_scan_passed", "remedy_success",
    "remedy_error_summary", "remedy_attempt_duration_s", "remedy_scan_duration_s",
    # Review
    "review_approve", "review_is_optimal", "review_security_score",
    "review_feedback", "review_concerns",
    # QA
    "qa_safe", "qa_verdict_reason", "qa_side_effects",
    "qa_regression_detected", "qa_recommendation", "qa_validation_duration_s",
    # Timing
    "total_duration_s",
    # LLM totals
    "llm_calls", "llm_errors", "llm_duration_s",
    "prompt_tokens", "completion_tokens", "total_tokens", "estimated_cost_usd",
    # LLM per-agent
    "triage_llm_calls", "triage_tokens", "triage_cost_usd", "triage_duration_s",
    "remedy_llm_calls", "remedy_tokens", "remedy_cost_usd", "remedy_duration_s",
    "review_llm_calls", "review_tokens", "review_cost_usd", "review_duration_s",
    "qa_llm_calls", "qa_tokens", "qa_cost_usd", "qa_duration_s",
    # Models
    "triage_model", "remedy_model", "review_model", "qa_model",
]


def _build_finding_row(
    r: "V2FindingResult",
    round_lookup: Dict[str, int],
    model_metadata: Optional[Dict[str, str]],
) -> Dict[str, Any]:
    """Flatten a single V2FindingResult into a dict matching DETAIL_COLUMNS."""
    v = r.vulnerability
    t = r.triage
    rm = r.remediation
    pa = r.pre_approval
    rv = pa.review_verdict if pa else None
    qa = pa.qa_result if pa else None
    llm = r.llm_metrics or {}
    per_agent = llm.get("per_agent", {})
    meta = model_metadata or {}

    row: Dict[str, Any] = {
        # Identification
        "finding_id": v.id,
        "title": _sanitize(v.title),
        "severity": v.severity,
        "host": v.host,
        "rule": v.rule or "",
        "oval_id": v.oval_id or "",
        "scan_class": v.scan_class or "",
        "os": v.os or "",
        # Triage
        "triage_should_remediate": t.should_remediate,
        "triage_risk_level": t.risk_level,
        "triage_reason": _sanitize(t.reason),
        "triage_requires_human_review": t.requires_human_review,
        "triage_estimated_impact": _sanitize(getattr(t, "estimated_impact", None)),
        "triage_estimated_complexity": getattr(t, "estimated_complexity", None) or "",
        # Result
        "final_status": r.final_status,
        "remediated_at_round": round_lookup.get(v.id, ""),
        "total_attempts": len(r.all_attempts),
        # Remedy (final)
        "remedy_commands_executed": _join(rm.commands_executed) if rm else "",
        "remedy_scan_passed": rm.scan_passed if rm else "",
        "remedy_success": rm.success if rm else "",
        "remedy_error_summary": _sanitize(rm.error_summary) if rm else "",
        "remedy_attempt_duration_s": rm.attempt_duration if rm else "",
        "remedy_scan_duration_s": rm.scan_duration if rm else "",
        # Review
        "review_approve": rv.approve if rv else "",
        "review_is_optimal": rv.is_optimal if rv else "",
        "review_security_score": rv.security_score if rv else "",
        "review_feedback": _sanitize(rv.feedback) if rv else "",
        "review_concerns": _join(rv.concerns) if rv else "",
        # QA
        "qa_safe": qa.safe if qa else "",
        "qa_verdict_reason": _sanitize(qa.verdict_reason) if qa else "",
        "qa_side_effects": _join(qa.side_effects) if qa else "",
        "qa_regression_detected": qa.regression_detected if qa else "",
        "qa_recommendation": qa.recommendation if qa else "",
        "qa_validation_duration_s": qa.validation_duration if qa else "",
        # Timing
        "total_duration_s": r.total_duration,
        # LLM totals
        "llm_calls": llm.get("llm_calls", 0),
        "llm_errors": llm.get("llm_errors", 0),
        "llm_duration_s": llm.get("llm_duration_s", 0.0),
        "prompt_tokens": llm.get("prompt_tokens", 0),
        "completion_tokens": llm.get("completion_tokens", 0),
        "total_tokens": llm.get("total_tokens", 0),
        "estimated_cost_usd": llm.get("estimated_cost_usd", 0.0),
        # LLM per-agent
        "triage_llm_calls": per_agent.get("triage", {}).get("llm_calls", 0),
        "triage_tokens": per_agent.get("triage", {}).get("total_tokens", 0),
        "triage_cost_usd": per_agent.get("triage", {}).get("estimated_cost_usd", 0.0),
        "triage_duration_s": per_agent.get("triage", {}).get("wall_time_s", 0.0),
        "remedy_llm_calls": per_agent.get("remedy", {}).get("llm_calls", 0),
        "remedy_tokens": per_agent.get("remedy", {}).get("total_tokens", 0),
        "remedy_cost_usd": per_agent.get("remedy", {}).get("estimated_cost_usd", 0.0),
        "remedy_duration_s": per_agent.get("remedy", {}).get("wall_time_s", 0.0),
        "review_llm_calls": per_agent.get("review", {}).get("llm_calls", 0),
        "review_tokens": per_agent.get("review", {}).get("total_tokens", 0),
        "review_cost_usd": per_agent.get("review", {}).get("estimated_cost_usd", 0.0),
        "review_duration_s": per_agent.get("review", {}).get("wall_time_s", 0.0),
        "qa_llm_calls": per_agent.get("qa", {}).get("llm_calls", 0),
        "qa_tokens": per_agent.get("qa", {}).get("total_tokens", 0),
        "qa_cost_usd": per_agent.get("qa", {}).get("estimated_cost_usd", 0.0),
        "qa_duration_s": per_agent.get("qa", {}).get("wall_time_s", 0.0),
        # Models
        "triage_model": meta.get("triage", ""),
        "remedy_model": meta.get("remedy", ""),
        "review_model": meta.get("review", ""),
        "qa_model": meta.get("qa", ""),
    }
    return row


# ── Summary CSV ───────────────────────────────────────────────────────────────

SUMMARY_COLUMNS = ["section", "metric", "value", "category"]


def _build_summary_rows(
    results: List["V2FindingResult"],
    fixed_at_round: Optional[Dict[int, List[str]]],
    elapsed: float,
    model_metadata: Optional[Dict[str, str]],
    max_rounds: int,
) -> List[Dict[str, Any]]:
    """Build summary rows in section/metric/value/category format."""
    rows: List[Dict[str, Any]] = []

    def add(section: str, metric: str, value: Any, category: str = ""):
        rows.append({"section": section, "metric": metric, "value": value, "category": category})

    total = len(results)
    success = [r for r in results if r.final_status == "success"]
    failed = [r for r in results if r.final_status == "failed"]
    discarded = [r for r in results if r.final_status == "discarded"]
    human_review = [r for r in results if r.final_status == "requires_human_review"]

    # ── Overview ──
    add("overview", "total_findings", total)
    add("overview", "total_remediated", len(success))
    add("overview", "total_failed", len(failed))
    add("overview", "total_discarded", len(discarded))
    add("overview", "total_requires_human_review", len(human_review))
    add("overview", "success_rate_pct", round(len(success) / max(total, 1) * 100, 1))

    # ── Per-round breakdown ──
    fixed = fixed_at_round or {}
    for rnd in range(1, max_rounds + 1):
        count = len(fixed.get(rnd, []))
        add("per_round", "fixed_count", count, f"round_{rnd}")

    # ── Per-severity breakdown ──
    severity_buckets: Dict[str, Dict[str, int]] = {}
    for r in results:
        sev = r.vulnerability.severity
        if sev not in severity_buckets:
            severity_buckets[sev] = {"total": 0, "remediated": 0, "failed": 0}
        severity_buckets[sev]["total"] += 1
        if r.final_status == "success":
            severity_buckets[sev]["remediated"] += 1
        elif r.final_status == "failed":
            severity_buckets[sev]["failed"] += 1
    for sev in sorted(severity_buckets.keys()):
        for metric_name, val in severity_buckets[sev].items():
            add("per_severity", metric_name, val, f"severity_{sev}")

    # ── Timing ──
    durations = [r.total_duration for r in results if r.total_duration > 0]
    add("timing", "total_elapsed_s", round(elapsed, 2))
    add("timing", "avg_duration_per_finding_s", round(sum(durations) / max(len(durations), 1), 2))
    add("timing", "min_duration_s", round(min(durations), 2) if durations else 0)
    add("timing", "max_duration_s", round(max(durations), 2) if durations else 0)

    # Per-agent average durations (from LLM metrics)
    for agent in ("triage", "remedy", "review", "qa"):
        agent_times = []
        for r in results:
            pa = (r.llm_metrics or {}).get("per_agent", {}).get(agent, {})
            wt = pa.get("wall_time_s", 0.0)
            if wt > 0:
                agent_times.append(wt)
        avg = round(sum(agent_times) / max(len(agent_times), 1), 2) if agent_times else 0
        add("timing", f"avg_{agent}_duration_s", avg)

    # ── Cost ──
    total_cost = sum((r.llm_metrics or {}).get("estimated_cost_usd", 0.0) for r in results)
    total_tokens = sum((r.llm_metrics or {}).get("total_tokens", 0) for r in results)
    add("cost", "total_cost_usd", round(total_cost, 4))
    add("cost", "total_tokens", total_tokens)
    add("cost", "avg_cost_per_finding_usd", round(total_cost / max(total, 1), 4))
    add("cost", "avg_tokens_per_finding", round(total_tokens / max(total, 1)))

    # ── Models ──
    meta = model_metadata or {}
    for agent_name in ("triage", "remedy", "review", "qa"):
        add("models", "model_name", meta.get(agent_name, "unknown"), agent_name)

    # ── Stage statistics ──
    # Triage
    triage_remediate = sum(1 for r in results if r.triage.should_remediate)
    triage_discard = sum(1 for r in results if not r.triage.should_remediate)
    triage_human = sum(1 for r in results if r.triage.requires_human_review)
    add("stage_stats", "triage_total", total)
    add("stage_stats", "triage_remediate", triage_remediate)
    add("stage_stats", "triage_discard", triage_discard)
    add("stage_stats", "triage_human_review", triage_human)

    # Remedy
    with_attempts = [r for r in results if r.all_attempts]
    remedy_passed = sum(1 for r in with_attempts if r.remediation and r.remediation.scan_passed)
    remedy_failed = sum(1 for r in with_attempts if r.remediation and not r.remediation.scan_passed)
    avg_attempts = round(
        sum(len(r.all_attempts) for r in with_attempts) / max(len(with_attempts), 1), 2
    )
    add("stage_stats", "remedy_total", len(with_attempts))
    add("stage_stats", "remedy_passed_scan", remedy_passed)
    add("stage_stats", "remedy_failed_scan", remedy_failed)
    add("stage_stats", "remedy_avg_attempts", avg_attempts)

    # Review
    reviewed = [r for r in results if r.pre_approval and r.pre_approval.review_verdict]
    review_approved = sum(1 for r in reviewed if r.pre_approval.review_verdict.approve)
    review_rejected = len(reviewed) - review_approved
    sec_scores = [
        r.pre_approval.review_verdict.security_score
        for r in reviewed
        if r.pre_approval.review_verdict.security_score is not None
    ]
    avg_sec = round(sum(sec_scores) / max(len(sec_scores), 1), 2) if sec_scores else 0
    add("stage_stats", "review_total", len(reviewed))
    add("stage_stats", "review_approved", review_approved)
    add("stage_stats", "review_rejected", review_rejected)
    add("stage_stats", "review_avg_security_score", avg_sec)

    # QA
    qa_results = [r for r in results if r.pre_approval and r.pre_approval.qa_result]
    qa_safe = sum(1 for r in qa_results if r.pre_approval.qa_result.safe)
    qa_unsafe = len(qa_results) - qa_safe
    qa_regressions = sum(1 for r in qa_results if r.pre_approval.qa_result.regression_detected)
    add("stage_stats", "qa_total", len(qa_results))
    add("stage_stats", "qa_safe", qa_safe)
    add("stage_stats", "qa_unsafe", qa_unsafe)
    add("stage_stats", "qa_regressions", qa_regressions)

    return rows


# ── Public API ────────────────────────────────────────────────────────────────

def write_csv_report(
    results: List["V2FindingResult"],
    report_dir: str = "./reports",
    fixed_at_round: Optional[Dict[int, List[str]]] = None,
    elapsed: float = 0.0,
    model_metadata: Optional[Dict[str, str]] = None,
    max_rounds: int = 3,
) -> Tuple[str, str]:
    """Write per-finding detail CSV and pipeline summary CSV.

    Returns (detail_path, summary_path).
    """
    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    detail_path = out / f"findings_detail_{ts}.csv"
    summary_path = out / f"pipeline_summary_{ts}.csv"

    round_lookup = _build_round_lookup(fixed_at_round)

    # ── Detail CSV ──
    detail_rows = [_build_finding_row(r, round_lookup, model_metadata) for r in results]
    with open(detail_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=DETAIL_COLUMNS)
        writer.writeheader()
        writer.writerows(detail_rows)

    # ── Summary CSV ──
    summary_rows = _build_summary_rows(results, fixed_at_round, elapsed, model_metadata, max_rounds)
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_COLUMNS)
        writer.writeheader()
        writer.writerows(summary_rows)

    return str(detail_path), str(summary_path)


# ── Standalone usage ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    from dotenv import find_dotenv, load_dotenv
    load_dotenv(find_dotenv(), override=False)

    from schemas import V2FindingResult

    report_dir = "./reports"
    json_path = Path(report_dir) / "v2_aggregated_results.json"
    if not json_path.exists():
        print(f"No results found at {json_path}")
        raise SystemExit(1)

    raw = json.loads(json_path.read_text(encoding="utf-8"))
    results = [V2FindingResult(**entry) for entry in raw]

    model_metadata = {
        "triage": os.getenv("TRIAGE_MODEL", ""),
        "remedy": os.getenv("REMEDY_MODEL", ""),
        "review": os.getenv("REVIEW_MODEL", ""),
        "qa": os.getenv("QA_MODEL", ""),
    }

    detail, summary = write_csv_report(
        results=results,
        report_dir=report_dir,
        model_metadata=model_metadata,
    )
    print(f"Detail CSV:  {detail}")
    print(f"Summary CSV: {summary}")
