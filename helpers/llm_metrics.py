"""
LLM Metrics Tracker — captures timing, tokens, cost and call counts
for every OpenRouter / OpenAI-compatible API call in the pipeline.

Usage:
    tracker = LLMMetricsTracker()

    # Around each LLM call:
    tracker.start_call()
    resp = requests.post(...)
    data = resp.json()
    tracker.record_call(data, agent="triage")

    # After the pipeline finishes for a finding:
    summary = tracker.summary()
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Per-call record ─────────────────────────────────────────────────────────

@dataclass
class LLMCallRecord:
    """One API call to an LLM."""
    agent: str = ""
    model: str = ""
    wall_time_s: float = 0.0               # end-to-end wallclock for the HTTP call
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0        # from OpenRouter's usage.cost field
    error: bool = False
    error_message: str = ""
    timestamp: float = 0.0                  # time.time() when call started

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent": self.agent,
            "model": self.model,
            "wall_time_s": round(self.wall_time_s, 3),
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost_usd": self.estimated_cost_usd,
            "error": self.error,
            "error_message": self.error_message,
        }


# ── Tracker ─────────────────────────────────────────────────────────────────

class LLMMetricsTracker:
    """Thread-safe accumulator for LLM call metrics."""

    def __init__(self) -> None:
        self._calls: List[LLMCallRecord] = []
        self._lock = threading.Lock()
        self._pending_start: Optional[float] = None

    # -- Recording API -------------------------------------------------------

    def start_call(self) -> float:
        """Mark the beginning of an LLM API call. Returns the start time."""
        t = time.time()
        self._pending_start = t
        return t

    def record_call(
        self,
        response_data: Optional[Dict[str, Any]],
        *,
        agent: str = "",
        model: str = "",
        start_time: Optional[float] = None,
        error: bool = False,
        error_message: str = "",
    ) -> None:
        """Record one completed LLM call.

        Parameters
        ----------
        response_data : dict | None
            The parsed JSON from the API response.  May contain
            ``usage.prompt_tokens``, ``usage.completion_tokens``,
            ``usage.total_tokens`` and (OpenRouter-specific) ``usage.cost``.
        agent : str
            Which agent made the call (triage / remedy / review / qa).
        model : str
            Model identifier string.
        start_time : float | None
            ``time.time()`` from before the HTTP request. If *None* uses the
            value from the last ``start_call()``.
        error : bool
            Whether the call errored.
        error_message : str
            Error description if applicable.
        """
        t_start = start_time or self._pending_start or time.time()
        elapsed = time.time() - t_start

        usage = {}
        if response_data and isinstance(response_data, dict):
            usage = response_data.get("usage") or {}
            if not model:
                model = response_data.get("model", "")

        rec = LLMCallRecord(
            agent=agent,
            model=model,
            wall_time_s=elapsed,
            prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
            completion_tokens=int(usage.get("completion_tokens", 0) or 0),
            total_tokens=int(usage.get("total_tokens", 0) or 0),
            estimated_cost_usd=float(usage.get("cost", 0) or 0),
            error=error,
            error_message=error_message,
            timestamp=t_start,
        )
        with self._lock:
            self._calls.append(rec)
        self._pending_start = None

    # -- Summaries -----------------------------------------------------------

    @property
    def calls(self) -> List[LLMCallRecord]:
        with self._lock:
            return list(self._calls)

    def summary(self) -> Dict[str, Any]:
        """Return an aggregate summary dict (safe to JSON-serialize)."""
        with self._lock:
            recs = list(self._calls)

        total_calls = len(recs)
        total_errors = sum(1 for r in recs if r.error)
        total_wall_time = sum(r.wall_time_s for r in recs)
        total_prompt_tokens = sum(r.prompt_tokens for r in recs)
        total_completion_tokens = sum(r.completion_tokens for r in recs)
        total_tokens = sum(r.total_tokens for r in recs)
        total_cost = sum(r.estimated_cost_usd for r in recs)

        # Per-agent breakdown
        agents: Dict[str, Dict[str, Any]] = {}
        for rec in recs:
            key = rec.agent or "unknown"
            if key not in agents:
                agents[key] = {
                    "llm_calls": 0,
                    "wall_time_s": 0.0,
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                    "estimated_cost_usd": 0.0,
                    "errors": 0,
                }
            a = agents[key]
            a["llm_calls"] += 1
            a["wall_time_s"] = round(a["wall_time_s"] + rec.wall_time_s, 3)
            a["prompt_tokens"] += rec.prompt_tokens
            a["completion_tokens"] += rec.completion_tokens
            a["total_tokens"] += rec.total_tokens
            a["estimated_cost_usd"] = round(a["estimated_cost_usd"] + rec.estimated_cost_usd, 6)
            if rec.error:
                a["errors"] += 1

        return {
            "llm_calls": total_calls,
            "llm_errors": total_errors,
            "llm_duration_s": round(total_wall_time, 3),
            "prompt_tokens": total_prompt_tokens,
            "completion_tokens": total_completion_tokens,
            "total_tokens": total_tokens,
            "estimated_cost_usd": round(total_cost, 6),
            "per_agent": agents,
            "call_log": [r.to_dict() for r in recs],
        }

    def reset(self) -> None:
        """Clear all recorded calls."""
        with self._lock:
            self._calls.clear()
        self._pending_start = None
