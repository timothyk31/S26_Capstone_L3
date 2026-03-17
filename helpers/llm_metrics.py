"""
helpers/llm_metrics.py — Gather per-agent LLM metrics from transcript files.

Each agent (triage, remedy, review, QA) writes transcript JSON files with
usage data during the pipeline run.  This module reads those files and
aggregates token counts, call counts, durations, and estimated costs into
a single ``llm_metrics`` dict that gets attached to V2FindingResult.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Rough default cost per 1K total tokens (ballpark mid-tier OpenRouter rate).
# Override via `cost_per_1k` parameter if needed.
_DEFAULT_COST_PER_1K = 0.0003


# ── Helpers ────────────────────────────────────────────────────────────────

def _safe_load_json(path: Path) -> Optional[Dict[str, Any]]:
    """Load a JSON file, return None on any failure or if it's not a dict."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        # Only return dicts — some older transcript files are bare lists
        # of messages with no usage info.
        if isinstance(data, dict):
            return data
        return None
    except Exception:
        return None


def _estimate_cost(total_tokens: int, cost_per_1k: float = _DEFAULT_COST_PER_1K) -> float:
    return round(total_tokens * cost_per_1k / 1000.0, 6)


def _extract_single_call(data: Dict[str, Any], cost_per_1k: float) -> Dict[str, Any]:
    """Extract usage from a single-call transcript (triage / review / QA)."""
    usage = data.get("usage") or {}
    timing = data.get("timing") or {}

    prompt = int(usage.get("prompt_tokens", 0) or 0)
    completion = int(usage.get("completion_tokens", 0) or 0)
    total = int(usage.get("total_tokens", 0) or 0) or (prompt + completion)
    wall = float(timing.get("api_call_seconds", 0.0) or 0.0)

    return {
        "llm_calls": 1,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
        "wall_time_s": round(wall, 3),
        "estimated_cost_usd": _estimate_cost(total, cost_per_1k),
    }


def _extract_remedy_session(data: Dict[str, Any], cost_per_1k: float) -> Dict[str, Any]:
    """Extract usage from a remedy transcript (multi-turn tool-calling session)."""
    usage = data.get("usage") or {}

    if isinstance(usage, dict) and "per_turn" in usage:
        per_turn = usage.get("per_turn", [])
        prompt = int(usage.get("prompt_tokens", 0) or 0)
        completion = int(usage.get("completion_tokens", 0) or 0)
        total = int(usage.get("total_tokens", 0) or 0) or (prompt + completion)
        wall = float(usage.get("total_api_seconds", 0.0) or 0.0)
        llm_calls = len(per_turn)
    else:
        prompt = completion = total = llm_calls = 0
        wall = 0.0

    return {
        "llm_calls": llm_calls,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
        "wall_time_s": round(wall, 3),
        "estimated_cost_usd": _estimate_cost(total, cost_per_1k),
    }


def _empty_agent() -> Dict[str, Any]:
    """Return a zero-valued agent metrics dict."""
    return {
        "llm_calls": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "wall_time_s": 0.0,
        "estimated_cost_usd": 0.0,
    }


def _add_agent_metrics(acc: Dict[str, Any], new: Dict[str, Any]) -> None:
    """Accumulate *new* into *acc* in-place."""
    for key in ("llm_calls", "prompt_tokens", "completion_tokens", "total_tokens"):
        acc[key] += new.get(key, 0)
    acc["wall_time_s"] += new.get("wall_time_s", 0.0)
    acc["estimated_cost_usd"] += new.get("estimated_cost_usd", 0.0)


def _round_agent(m: Dict[str, Any]) -> Dict[str, Any]:
    m["wall_time_s"] = round(m["wall_time_s"], 3)
    m["estimated_cost_usd"] = round(m["estimated_cost_usd"], 6)
    return m


# ── Public API ──────────────────────────────────────────────────────────────

def gather_llm_metrics(
    finding_id: str,
    work_dir: Union[str, Path],
    max_attempts: int = 10,
    cost_per_1k: float = _DEFAULT_COST_PER_1K,
) -> Dict[str, Any]:
    """
    Read transcript files for *finding_id* and compile LLM metrics.

    Parameters
    ----------
    finding_id : str
        e.g. ``"openscap_015"``
    work_dir : str | Path
        Pipeline working directory (the one that contains ``transcripts/``
        and ``remedy/`` subdirectories).
    max_attempts : int
        Upper bound of remedy attempts to scan for transcripts.
    cost_per_1k : float
        Estimated cost per 1 000 total tokens.

    Returns
    -------
    dict
        Aggregate + per-agent breakdown, e.g.::

            {
                "llm_calls": 21,
                "llm_errors": 0,
                "llm_duration_s": 52.863,
                "prompt_tokens": 50291,
                "completion_tokens": 2326,
                "total_tokens": 52617,
                "estimated_cost_usd": 0.019392,
                "per_agent": {
                    "triage": { ... },
                    "remedy": { ... },
                    "review": { ... },
                    "qa":     { ... },
                }
            }
    """
    work = Path(work_dir)

    # ── Triage (single call per finding) ──────────────────────────────
    triage = _empty_agent()
    triage_path = work / "transcripts" / "triage" / f"triage_transcript_{finding_id}.json"
    data = _safe_load_json(triage_path)
    if data:
        triage = _extract_single_call(data, cost_per_1k)

    # ── Remedy (one multi-turn session per attempt) ───────────────────
    remedy = _empty_agent()
    for att in range(1, max_attempts + 1):
        # Check transcripts/remedy/ first, fall back to legacy remedy/ path
        path = work / "transcripts" / "remedy" / f"remedy_transcript_{finding_id}_attempt{att}.json"
        data = _safe_load_json(path)
        if data is None:
            path = work / "remedy" / f"remedy_transcript_{finding_id}_attempt{att}.json"
            data = _safe_load_json(path)
        if data:
            _add_agent_metrics(remedy, _extract_remedy_session(data, cost_per_1k))
    _round_agent(remedy)

    # ── Review (single call per attempt) ──────────────────────────────
    review = _empty_agent()
    for att in range(1, max_attempts + 1):
        path = work / "transcripts" / "review" / f"review_transcript_{finding_id}_attempt{att}.json"
        data = _safe_load_json(path)
        if data:
            _add_agent_metrics(review, _extract_single_call(data, cost_per_1k))
    _round_agent(review)

    # ── QA (single call per attempt) ──────────────────────────────────
    qa = _empty_agent()
    for att in range(1, max_attempts + 1):
        path = work / "transcripts" / "qa" / f"qa_transcript_{finding_id}_attempt{att}.json"
        data = _safe_load_json(path)
        if data:
            _add_agent_metrics(qa, _extract_single_call(data, cost_per_1k))
    _round_agent(qa)

    # ── Aggregate ─────────────────────────────────────────────────────
    total_calls = triage["llm_calls"] + remedy["llm_calls"] + review["llm_calls"] + qa["llm_calls"]
    total_prompt = triage["prompt_tokens"] + remedy["prompt_tokens"] + review["prompt_tokens"] + qa["prompt_tokens"]
    total_comp = triage["completion_tokens"] + remedy["completion_tokens"] + review["completion_tokens"] + qa["completion_tokens"]
    total_tok = triage["total_tokens"] + remedy["total_tokens"] + review["total_tokens"] + qa["total_tokens"]
    total_dur = triage["wall_time_s"] + remedy["wall_time_s"] + review["wall_time_s"] + qa["wall_time_s"]
    total_cost = triage["estimated_cost_usd"] + remedy["estimated_cost_usd"] + review["estimated_cost_usd"] + qa["estimated_cost_usd"]

    return {
        "llm_calls": total_calls,
        "llm_errors": 0,
        "llm_duration_s": round(total_dur, 3),
        "prompt_tokens": total_prompt,
        "completion_tokens": total_comp,
        "total_tokens": total_tok,
        "estimated_cost_usd": round(total_cost, 6),
        "per_agent": {
            "triage": triage,
            "remedy": remedy,
            "review": review,
            "qa": qa,
        },
    }
