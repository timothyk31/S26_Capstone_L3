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
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from schemas import Vulnerability, RemedyInput, RemediationAttempt, ToolVerdict, RunCommandResult
from helpers.command_executor import ShellCommandExecutor

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
        max_tool_iterations: int = 5,
        request_timeout: int = 30,
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

        # Always scan at end (spec requires scan tool, but enforce here too)
        scan_result = self._tool_scan(vuln)
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
        rule_name = vuln.title.replace("xccdf_org.ssgproject.content_rule_", "")
        description = (vuln.description or "").strip()
        recommendation = (vuln.recommendation or "").strip()

        lines = [
            "You are the Remedy agent remediating ONE OpenSCAP finding on Rocky Linux 10.",
            "You MUST use ONLY the provided tools: run_cmd, read_file, write_file, scan.",
            "Rules:",
            "- Use run_cmd for EXACTLY ONE shell command at a time. Do NOT chain with && ; or multiline scripts.",
            "- Commands run as root. Do not prefix with sudo.",
            "- Prefer minimal, reversible changes and verify with scan at the end.",
            "",
            "FINDING:",
            f"- Rule Name: {rule_name}",
            f"- Rule ID: {vuln.title}",
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
            "You are an adaptive remediation agent. Use tools to inspect and remediate the finding. "
            "One command at a time. End with scan."
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

        tool_calls_used = 0

        while tool_calls_used < self.max_tool_iterations:
            resp = self._chat(messages)
            msg = resp["choices"][0]["message"]

            transcript.append({"role": "assistant", "content": msg.get("content"), "tool_calls": msg.get("tool_calls")})
            messages.append(msg)

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                # Assistant might be reasoning; let it continue a few turns
                final_message = msg.get("content") or final_message
                if tool_calls_used > 6:
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
                    # Let LLM call scan during the attempt, but we'll scan again at end anyway.
                    payload = self._tool_scan(vuln)
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
        }

    def _chat(self, messages: List[Dict[str, Any]]) -> Dict[str, Any]:
        payload = {
            "model": self.model_name,
            "messages": messages,
            "tools": self._tools_spec(),
            "tool_choice": "auto",
        }
        r = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=self.request_timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"LLM API error {r.status_code}: {r.text}")
        return r.json()

    # -------------------------
    # Tool implementations
    # -------------------------

    def _tool_run_cmd(self, command: str) -> RunCommandResult:
        # You can re-add normalization later if you want (copy from qa_agent_adaptive._normalize_command)
        return self.executor.run_command(command)

    def _tool_scan(self, vuln: Vulnerability) -> Dict[str, Any]:
        """
        scanner.scan_for_vulnerability returns (is_fixed, scan_output)
        """
        is_fixed, output = self.scanner.scan_for_vulnerability(vuln)
        return {
            "pass": bool(is_fixed),
            "summary": output,
            "raw": None,
        }

