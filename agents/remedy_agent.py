# TODO: Implement Remedy Agent (MOST COMPLEX - Highest code reuse)
#
# Purpose: Execute remediation using LLM with tool-calling interface
# Position in pipeline: SECOND stage (after Triage approval)
# Tools: run_cmd, write_file, read_file, scan (exactly 4 per spec)
# Has self-loop: Retries on scan failure with feedback
#
# Input: RemedyInput (vulnerability, triage_decision, attempt_number, previous_attempts, review_feedback)
# Output: RemediationAttempt (commands_executed, files_modified, scan_passed, success, llm_verdict)
#
# Key responsibilities:
# 1. Build context-rich prompt with vulnerability details + previous attempts
# 2. LLM generates remediation commands via tool calling
# 3. Execute commands via run_cmd tool (uses ShellCommandExecutor)
# 4. Write/read files as needed
# 5. Call scan tool to verify fix
# 6. Self-loop up to max attempts if scan fails
# 7. Track all execution details
#
# Code reuse from qa_agent_adaptive.py:
# - apply_remediation() method (lines ~340-390) - CORE LOGIC
# - _build_agent_prompt() method - Context building
# - process_vulnerability_adaptively() - Retry loop pattern
# - Tool execution pattern from ToolCallingLLM
# - Command normalization (via utils.normalize_command)
#
# Example:
# class RemedyAgent:
#     def __init__(self, llm: ToolCallingLLM, executor: ShellCommandExecutor, scanner: Scanner):
#         self.llm = llm  # Composition - configured with 4 tools
#         self.executor = executor
#         self.scanner = scanner
#
#     def _define_tools(self) -> List[dict]:
#         return [
#             {"type": "function", "function": {"name": "run_cmd", ...}},
#             {"type": "function", "function": {"name": "write_file", ...}},
#             {"type": "function", "function": {"name": "read_file", ...}},
#             {"type": "function", "function": {"name": "scan", ...}}
#         ]
#
#     def process(self, input_data: RemedyInput) -> RemediationAttempt:
#         # Build prompt with vulnerability + previous attempts
#         # Run LLM session with tools
#         # Parse results
#         # Return RemediationAttempt

# agents/remedy_agent.py
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from schemas import Vulnerability, RemedyInput, RemediationAttempt, FindingResult, ToolVerdict, RunCommandResult
from helpers.command_executor import ShellCommandExecutor
from helpers.utils import normalize_command

DEFAULT_OPENROUTER_BASE = "https://openrouter.ai/api/v1"
DEFAULT_REMEDY_MODEL = os.getenv("REMEDY_AGENT_MODEL") or os.getenv("OPENROUTER_MODEL")  # fallback

def _get_config():
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY is required.")
    base_url = (os.getenv("OPENROUTER_BASE_URL") or DEFAULT_OPENROUTER_BASE).rstrip("/")
    model = os.getenv("REMEDY_AGENT_MODEL") or os.getenv("OPENROUTER_MODEL")
    if not model:
        raise ValueError("REMEDY_AGENT_MODEL or OPENROUTER_MODEL is required.")
    return api_key, base_url, model


class RemedyAgent:
    """
    Remedy Agent (Stage 2)
    Tools (exactly 4): run_cmd, read_file, write_file, scan
    Self-loop behavior is typically orchestrated by workflow, but this class can support max attempts too.
    """

    def __init__(
        self,
        *,
        executor: ShellCommandExecutor,
        scanner: Any,  # OpenSCAPScanner-like wrapper that can verify one vuln
        work_dir: Path,
        max_tool_iterations: int = 15,
        request_timeout: int = 120,
    ):
        self.executor = executor
        self.scanner = scanner
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)

        api_key, base_url, model = _get_config()
        self.api_key = api_key
        self.base_url = base_url
        self.model_name = model
        self.endpoint = f"{self.base_url}/chat/completions"

        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        self.max_tool_iterations = max_tool_iterations
        self.request_timeout = request_timeout

    # -------------------------
    # Public API
    # -------------------------

    def process(self, input_data: RemedyInput) -> RemediationAttempt:
        vuln = input_data.vulnerability
        start = time.time()

        attempt = RemediationAttempt(
            finding_id=vuln.id,
            attempt_number=input_data.attempt_number,
            commands_executed=[],
            files_modified=[],
            files_read=[],
            execution_details=[],
            scan_passed=False,
            scan_output=None,
            duration=0.0,
            success=False,
            error_summary=None,
            llm_verdict=None,
        )

        user_prompt = self._build_agent_prompt(
            vuln=vuln,
            triage_reason=input_data.triage_decision.reason,
            previous_attempts=input_data.previous_attempts,
            review_feedback=input_data.review_feedback,
        )

        session_label = f"{vuln.id}_attempt{input_data.attempt_number}"
        (self.work_dir / f"remedy_prompt_{session_label}.txt").write_text(user_prompt, encoding="utf-8")

        session_result = self._run_tool_session(user_prompt=user_prompt, session_label=session_label, vuln=vuln)

        # Pull tool traces into attempt
        attempt.commands_executed = session_result["commands_executed"]
        attempt.files_modified = session_result["files_modified"]
        attempt.files_read = session_result["files_read"]
        attempt.execution_details = session_result["execution_details"]
        attempt.llm_verdict = ToolVerdict(message=session_result.get("final_message", ""), resolved=False)

        # Reuse the LLM's scan result if it called scan during the session;
        # otherwise run a single-rule verification scan now.
        scan_result = session_result.get("last_scan_result") or self._tool_scan(vuln)
        attempt.scan_passed = bool(scan_result.get("pass"))
        attempt.scan_output = scan_result.get("summary") or scan_result.get("raw")

        attempt.success = attempt.scan_passed
        attempt.llm_verdict.resolved = attempt.success

        attempt.duration = time.time() - start

        # Save transcript/log
        (self.work_dir / f"remedy_transcript_{session_label}.json").write_text(
            json.dumps(session_result["transcript"], indent=2), encoding="utf-8"
        )

        return attempt

    # -------------------------
    # Prompt + tool definitions
    # -------------------------

    def _build_agent_prompt(
        self,
        *,
        vuln: Vulnerability,
        triage_reason: str,
        previous_attempts: List[RemediationAttempt],
        review_feedback: Optional[str],
    ) -> str:
        rule_id = vuln.oval_id or vuln.rule or vuln.title
        rule_name = rule_id.replace("xccdf_org.ssgproject.content_rule_", "")
        description = (vuln.description or "").strip()
        recommendation = (vuln.recommendation or "").strip()

        lines = [
            "You are the Remedy agent remediating ONE OpenSCAP finding on Rocky Linux 10.",
            "You MUST use ONLY the provided tools: run_cmd, read_file, write_file, scan.",
            "Rules:",
            "- Use run_cmd for EXACTLY ONE shell command at a time. Do NOT chain with && ; or multiline scripts.",
            "- Commands run as root. Do not prefix with sudo.",
            "- ALWAYS use read_file to inspect the target config file BEFORE modifying it.",
            "- Do NOT append duplicate lines. Use sed -i to modify existing values in-place.",
            "- If a line is commented (e.g. '# minlen = 8'), uncomment it and set the value.",
            "- Prefer minimal, reversible changes and verify with scan at the end.",
            "",
            "FINDING:",
            f"- Title: {vuln.title}",
            f"- Rule Name: {rule_name}",
            f"- Rule ID: {rule_id}",
            f"- Finding ID: {vuln.id}",
            f"- Severity: {vuln.severity}",
            f"- Host: {vuln.host}",
            "",
            "TRIAGE CONTEXT:",
            f"- Approved for remediation because: {triage_reason}",
        ]

        if description:
            lines.append(f"- Description: {description[:600]}")
        if recommendation:
            lines.append(f"- Recommendation: {recommendation[:600]}")

        if review_feedback:
            lines.extend(["", "REVIEW FEEDBACK (apply improvements):", review_feedback.strip()[:600]])

        if previous_attempts:
            lines.append("")
            lines.append(f"PREVIOUS ATTEMPTS ({len(previous_attempts)}):")
            for att in previous_attempts[-3:]:
                lines.append(f"* Attempt {att.attempt_number}: success={att.success} scan_passed={att.scan_passed}")
                if att.commands_executed:
                    lines.append("  Commands:")
                    for cmd in att.commands_executed[-4:]:
                        lines.append(f"    - {cmd}")
                if att.error_summary:
                    lines.append(f"  Error: {att.error_summary[:300]}")
                if att.scan_output:
                    lines.append(f"  Scan output: {str(att.scan_output)[:300]}")

        lines.extend([
            "",
            "Return tool calls as needed. End by calling scan.",
        ])
        return "\n".join(lines)

    def _tools_spec(self) -> List[Dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "run_cmd",
                    "description": "Execute a single shell command as root on the target. Do not chain commands.",
                    "parameters": {
                        "type": "object",
                        "properties": {"command": {"type": "string"}},
                        "required": ["command"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a single file from the target host.",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "write_file",
                    "description": "Write content to a single file on the target host.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"},
                            "mode": {"type": "string"},
                        },
                        "required": ["path", "content"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "scan",
                    "description": "Run a focused scan for this finding and return pass/fail.",
                    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
                },
            },
        ]

    # -------------------------
    # Tool-calling loop
    # -------------------------

    def _run_tool_session(self, *, user_prompt: str, session_label: str, vuln: Vulnerability) -> Dict[str, Any]:
        system_prompt = (
            "You are an adaptive remediation agent on Rocky Linux / RHEL. "
            "Use tools to inspect and remediate the finding.\n"
            "STRATEGY:\n"
            "1. ALWAYS read the relevant config file FIRST with read_file before making changes.\n"
            "2. Identify the exact key/value that needs changing.\n"
            "3. Use write_file for config changes (avoids shell quoting issues) or run_cmd for sed/systemctl.\n"
            "4. Verify with run_cmd (e.g. grep) that the change took effect.\n"
            "5. Call scan to confirm the fix.\n"
            "RULES:\n"
            "- One command at a time. Do NOT chain with && or ;\n"
            "- This is Rocky Linux/RHEL. Use dnf (not apt). Use systemctl (not service).\n"
            "- Do NOT duplicate config lines. If a key already exists, modify it in-place with sed.\n"
            "- If a key is commented out (# minlen = 8), uncomment and set the correct value.\n"
            "- stderr may contain SSH banners — ignore them. Check exit_code and stdout for results."
        )

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        transcript: List[Dict[str, Any]] = list(messages)

        commands_executed: List[str] = []
        files_read: List[str] = []
        files_modified: List[str] = []
        execution_details: List[RunCommandResult] = []
        final_message: str = ""
        last_scan_result: Optional[Dict[str, Any]] = None  # Track LLM-initiated scans

        tool_calls_used = 0
        total_turns = 0  # Counts ALL LLM round-trips (tool + reasoning)

        while tool_calls_used < self.max_tool_iterations and total_turns < self.max_tool_iterations + 6:
            total_turns += 1
            resp = self._chat(messages)
            msg = resp["choices"][0]["message"]

            transcript.append({"role": "assistant", "content": msg.get("content"), "tool_calls": msg.get("tool_calls")})
            messages.append(msg)

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                # Assistant is reasoning; allow a few turns then stop
                final_message = msg.get("content") or final_message
                if total_turns > tool_calls_used + 4:
                    break
                continue

            for tc in tool_calls:
                name = tc["function"]["name"]
                raw_args = tc["function"].get("arguments")

                # Normalize tool arguments (models may return str, dict, or list)
                if isinstance(raw_args, str):
                    try:
                        args = json.loads(raw_args)
                    except Exception:
                        args = {}
                elif isinstance(raw_args, dict):
                    args = raw_args
                elif isinstance(raw_args, list):
                    args = raw_args[0] if raw_args and isinstance(raw_args[0], dict) else {}
                else:
                    args = {}


                if name == "run_cmd":
                    command = (args.get("command") or "").strip()
                    result = self._tool_run_cmd(command)
                    commands_executed.append(result.command)
                    execution_details.append(result)
                    payload = result.model_dump()

                elif name == "read_file":
                    path = (args.get("path") or "").strip()
                    result = self.executor.read_file(path)
                    files_read.append(path)
                    execution_details.append(result)
                    payload = result.model_dump()

                elif name == "write_file":
                    path = (args.get("path") or "").strip()
                    content = args.get("content") or ""
                    mode = args.get("mode")
                    result = self.executor.write_file(path, content, mode=mode)
                    files_modified.append(path)
                    execution_details.append(result)
                    payload = result.model_dump()

                elif name == "scan":
                    scan_payload = self._tool_scan(vuln)
                    last_scan_result = scan_payload  # Cache so process() can reuse
                    payload = scan_payload
                else:
                    payload = {"error": f"Unknown tool {name}"}

                tool_entry = {
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": json.dumps(payload),
                }
                transcript.append(tool_entry)
                messages.append(tool_entry)

                tool_calls_used += 1
                if tool_calls_used >= self.max_tool_iterations:
                    break

            if tool_calls_used >= self.max_tool_iterations:
                break

        return {
            "transcript": transcript,
            "commands_executed": commands_executed,
            "files_read": files_read,
            "files_modified": files_modified,
            "execution_details": execution_details,
            "final_message": final_message,
            "last_scan_result": last_scan_result,
        }

    def _chat(self, messages: List[Dict[str, Any]], _retries: int = 3) -> Dict[str, Any]:
        payload = {
            "model": self.model_name,
            "messages": messages,
            "tools": self._tools_spec(),
            "tool_choice": "auto",
        }
        last_exc: Optional[Exception] = None
        for attempt in range(_retries):
            try:
                r = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=self.request_timeout)
                if r.status_code >= 500:
                    last_exc = RuntimeError(f"LLM API error {r.status_code}: {r.text}")
                    time.sleep(2 ** attempt)
                    continue
                if r.status_code >= 400:
                    raise RuntimeError(f"LLM API error {r.status_code}: {r.text}")
                return r.json()
            except requests.exceptions.Timeout as exc:
                last_exc = exc
                time.sleep(2 ** attempt)
            except requests.exceptions.ConnectionError as exc:
                last_exc = exc
                time.sleep(2 ** attempt)
        raise RuntimeError(f"LLM API failed after {_retries} retries: {last_exc}")

    # -------------------------
    # Tool implementations
    # -------------------------

    def _tool_run_cmd(self, command: str) -> RunCommandResult:
        command = normalize_command(command)
        return self.executor.run_command(command)

    def _tool_scan(self, vuln: Vulnerability) -> Dict[str, Any]:
        """
        Use single-rule scan for fast verification (~10-30s instead of ~5-10min).
        Falls back to full scan if single-rule is unavailable.
        """
        is_fixed, output = self.scanner.scan_single_rule(vuln)
        return {
            "pass": bool(is_fixed),
            "summary": output,
            "raw": None,
        }

    # ------------------------------------------------------------------
    # Output: PDF report
    # ------------------------------------------------------------------
    def write_results_pdf(
        self,
        results: List[FindingResult],
        output_path: str | Path = "reports/remedy_report.pdf",
        *,
        target_host: str = "unknown",
        title: str = "Remedy Agent Report",
    ) -> Path:
        """
        Generate a PDF report summarising all Remedy Agent outputs.

        Only includes findings that reached the Remedy stage (have a
        RemediationAttempt).
        """
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        page_size = landscape(letter)
        doc = SimpleDocTemplate(
            str(out),
            pagesize=page_size,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            rightMargin=0.5 * inch,
        )

        styles = getSampleStyleSheet()
        elements: list = []

        title_style = ParagraphStyle("RTitle", parent=styles["Title"], fontSize=20, spaceAfter=6)
        subtitle_style = ParagraphStyle("RSub", parent=styles["Normal"], fontSize=10, textColor=colors.grey, spaceAfter=14)
        section_style = ParagraphStyle("RSec", parent=styles["Heading2"], fontSize=14, spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#1a1a2e"))
        cell_style = ParagraphStyle("RCell", parent=styles["Normal"], fontSize=8, leading=10)
        body_style = ParagraphStyle("RBody", parent=styles["Normal"], fontSize=9, leading=12)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elements.append(Paragraph(title, title_style))
        elements.append(Paragraph(f"Target: {target_host} &nbsp;|&nbsp; Generated: {now}", subtitle_style))

        # Filter to findings that have a remediation attempt
        remedied = [r for r in results if r.remediation is not None]

        passed = sum(1 for r in remedied if r.remediation and r.remediation.scan_passed)
        failed = len(remedied) - passed
        avg_attempts = (
            round(sum(r.remediation.attempt_number for r in remedied if r.remediation) / len(remedied), 2)
            if remedied else 0.0
        )

        elements.append(Paragraph("Remedy Summary", section_style))
        summary_data = [
            ["Total Remediation Attempts", str(len(remedied))],
            ["Scan Passed", str(passed)],
            ["Scan Failed", str(failed)],
            ["Avg Attempt #", str(avg_attempts)],
        ]
        summary_table = Table(summary_data, colWidths=[3 * inch, 1.5 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e3f2fd")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 14))

        if not remedied:
            elements.append(Paragraph("No findings reached the Remedy stage.", body_style))
        else:
            elements.append(Paragraph("Per-Finding Remedy Details", section_style))
            table_data = [
                [
                    Paragraph("<b>ID</b>", cell_style),
                    Paragraph("<b>Title</b>", cell_style),
                    Paragraph("<b>Attempt</b>", cell_style),
                    Paragraph("<b>Scan</b>", cell_style),
                    Paragraph("<b>Duration</b>", cell_style),
                    Paragraph("<b>Commands</b>", cell_style),
                    Paragraph("<b>Files Modified</b>", cell_style),
                    Paragraph("<b>Error</b>", cell_style),
                ],
            ]
            for r in remedied:
                rm = r.remediation
                assert rm is not None
                scan_text = '<font color="#27ae60">PASS</font>' if rm.scan_passed else '<font color="#e74c3c">FAIL</font>'
                cmds_text = "<br/>".join(rm.commands_executed[:5]) or "\u2014"
                if len(rm.commands_executed) > 5:
                    cmds_text += f"<br/>... +{len(rm.commands_executed) - 5} more"
                files_text = "<br/>".join(rm.files_modified[:3]) or "\u2014"
                table_data.append([
                    Paragraph(r.vulnerability.id, cell_style),
                    Paragraph((r.vulnerability.title or "\u2014")[:60], cell_style),
                    Paragraph(str(rm.attempt_number), cell_style),
                    Paragraph(scan_text, cell_style),
                    Paragraph(f"{rm.duration:.1f}s", cell_style),
                    Paragraph(cmds_text, cell_style),
                    Paragraph(files_text, cell_style),
                    Paragraph((rm.error_summary or "\u2014")[:100], cell_style),
                ])

            col_widths = [0.7 * inch, 1.4 * inch, 0.5 * inch, 0.5 * inch, 0.55 * inch, 3.0 * inch, 1.5 * inch, 1.85 * inch]
            t = Table(table_data, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafafa")]),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elements.append(t)

        doc.build(elements)
        return out

