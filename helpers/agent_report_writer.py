"""
AgentReportWriter — Persist each agent's input/output to per-agent folders.

Creates a directory tree under a configurable root so every agent call
can be reviewed after the pipeline finishes:

    <report_root>/
        triage/
            <finding_id>/
                input.json
                output.json
        remedy/
            <finding_id>/
                attempt_1_input.json
                attempt_1_output.json
                attempt_2_input.json
                attempt_2_output.json
        review/
            <finding_id>/
                input.json
                output.json
                (or attempt_N_input/output when review triggers retry)
        qa/
            <finding_id>/
                input.json
                output.json

All files are JSON-serialised Pydantic models (via .model_dump()).
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from pydantic import BaseModel


def _safe_dirname(finding_id: str) -> str:
    """Sanitise a finding id for use as a directory name."""
    return re.sub(r"[^\w\-.]", "_", finding_id)


def _dump(obj: Union[BaseModel, dict, None]) -> dict:
    """Convert a Pydantic model or dict to a plain dict for serialisation."""
    if obj is None:
        return {"_note": "No data (agent was skipped or errored)"}
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    return obj


class AgentReportWriter:
    """
    Thread-safe writer that persists agent I/O to disk.

    Usage in Pipeline.run():
        writer = AgentReportWriter(root="./pipeline_work/agent_reports")
        writer.write("triage", finding_id, input_data, output_data)
        writer.write("remedy", finding_id, input_data, output_data, attempt=1)
    """

    def __init__(self, report_root: Union[str, Path]):
        self.root = Path(report_root)
        self.root.mkdir(parents=True, exist_ok=True)

    def write(
        self,
        agent_name: str,
        finding_id: str,
        input_data: Union[BaseModel, dict, None],
        output_data: Union[BaseModel, dict, None],
        *,
        attempt: Optional[int] = None,
    ) -> Path:
        """
        Write one agent's input + output for a single finding.

        Args:
            agent_name:  "triage" | "remedy" | "review" | "qa"
            finding_id:  Vulnerability id (used as subfolder name).
            input_data:  The Pydantic model passed *into* the agent.
            output_data: The Pydantic model returned *from* the agent.
            attempt:     Optional attempt number (for remedy / review retries).

        Returns:
            Path to the finding subfolder that was written.
        """
        agent_dir = self.root / agent_name / _safe_dirname(finding_id)
        agent_dir.mkdir(parents=True, exist_ok=True)

        prefix = f"attempt_{attempt}_" if attempt is not None else ""

        input_path = agent_dir / f"{prefix}input.json"
        output_path = agent_dir / f"{prefix}output.json"

        input_path.write_text(
            json.dumps(_dump(input_data), indent=2, default=str),
            encoding="utf-8",
        )
        output_path.write_text(
            json.dumps(_dump(output_data), indent=2, default=str),
            encoding="utf-8",
        )

        return agent_dir

    def write_error(
        self,
        agent_name: str,
        finding_id: str,
        input_data: Union[BaseModel, dict, None],
        error: Exception,
        *,
        attempt: Optional[int] = None,
    ) -> Path:
        """Write input + error details when an agent raises."""
        agent_dir = self.root / agent_name / _safe_dirname(finding_id)
        agent_dir.mkdir(parents=True, exist_ok=True)

        prefix = f"attempt_{attempt}_" if attempt is not None else ""

        input_path = agent_dir / f"{prefix}input.json"
        error_path = agent_dir / f"{prefix}error.json"

        input_path.write_text(
            json.dumps(_dump(input_data), indent=2, default=str),
            encoding="utf-8",
        )
        error_path.write_text(
            json.dumps(
                {
                    "error_type": type(error).__name__,
                    "error_message": str(error),
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return agent_dir
