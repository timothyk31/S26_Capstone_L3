"""
QA Agent: System-wide validation after remediation.
Position: FOURTH stage in pipeline (after Review approval).
Tools: run_cmd, scan (2 tools for validation checks).
"""

import os
import time
from typing import Any, Dict, List, Optional

from helpers.command_executor import ShellCommandExecutor
from helpers.llm_base import ToolCallingLLM
from helpers.scanner import Scanner
from helpers.utils import annotate_error_categories, normalize_command
from schemas import QAInput, QAResult, RunCommandResult


class QAAgent:
    """
    QA Agent validates that remediation didn't break the system.
    Uses LLM with run_cmd and scan tools for comprehensive validation.
    """

    SYSTEM_PROMPT = (
        "You are a QA validation agent for Linux security remediation. "
        "Your role is to verify that a remediation did NOT introduce harm to the system.\n\n"
        "You have access to 2 tools:\n"
        "1. `run_cmd`: Run system health checks (systemctl status, service checks, log analysis)\n"
        "2. `scan`: Re-run security scan to check for regressions\n\n"
        "Your validation checklist:\n"
        "- Verify critical services are still running (sshd, auditd, firewalld, etc.)\n"
        "- Check for errors in system logs (/var/log/messages, journalctl)\n"
        "- Confirm system is still accessible (SSH works)\n"
        "- Run security scan to ensure no new failures\n"
        "- Detect any side effects or unintended changes\n\n"
        "When done, call `verdict` with:\n"
        "- safe=true if system is healthy\n"
        "- safe=false if you detect issues\n"
        "- Include detailed message explaining findings"
    )

    def __init__(
        self,
        executor: ShellCommandExecutor,
        scanner: Scanner,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        max_tool_iterations: int = 24,
        request_timeout: int = 90,
    ):
        """
        Initialize QA Agent.

        Args:
            executor: ShellCommandExecutor for running system checks
            scanner: Scanner for vulnerability scanning
            api_key: LLM API key (defaults to OPENROUTER_API_KEY env)
            base_url: LLM API base URL (defaults to OPENROUTER_BASE_URL env)
            model: LLM model name (defaults to OPENROUTER_MODEL env)
            max_tool_iterations: Max LLM tool calls
            request_timeout: HTTP timeout
        """
        self.executor = executor
        self.scanner = scanner

        # Get LLM config from env if not provided
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY not found. Set it in .env or pass as parameter.")
        self.base_url = base_url or os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        self.model = model or os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b")

        # Initialize LLM with QA-specific tools
        self.llm = ToolCallingLLM(
            model_name=self.model,
            base_url=self.base_url,
            api_key=self.api_key,
            system_prompt=self.SYSTEM_PROMPT,
            tools=self._define_tools(),
            tool_executor=self._execute_tool,
            max_tool_iterations=max_tool_iterations,
            request_timeout=request_timeout,
        )

    def _define_tools(self) -> List[dict]:
        """Define QA Agent's 2 tools: run_cmd and scan."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "run_cmd",
                    "description": (
                        "Run a system health check command (systemctl status, journalctl, etc.). "
                        "Use this to verify services are running and check logs for errors."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "Single shell command for validation (e.g., systemctl status sshd)",
                            }
                        },
                        "required": ["command"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "scan",
                    "description": (
                        "Re-run security scan to check if the specific vulnerability is fixed "
                        "and verify no new failures were introduced (regression detection)."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "vulnerability_id": {
                                "type": "string",
                                "description": "ID of vulnerability to check",
                            }
                        },
                        "required": ["vulnerability_id"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "verdict",
                    "description": "Signal QA validation is complete with safety verdict.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "message": {"type": "string"},
                            "safe": {"type": "boolean"},
                        },
                        "required": ["message", "safe"],
                        "additionalProperties": False,
                    },
                },
            },
        ]

    def _execute_tool(self, tool_name: str, args: dict) -> dict:
        """Execute QA tools: run_cmd, scan, or verdict."""
        if tool_name == "run_cmd":
            command = args.get("command", "").strip()
            if not command:
                return {"error": "No command provided"}

            # Normalize command (Debian → RHEL)
            normalized = normalize_command(command)

            # Execute via executor
            result = self.executor.run_command(normalized)
            payload = result.model_dump()

            # Track normalization
            if normalized != command:
                payload["normalized_from"] = command

            return payload

        elif tool_name == "scan":
            vuln_id = args.get("vulnerability_id", "")
            if hasattr(self, "_current_vulnerability"):
                is_fixed, scan_output = self.scanner.scan_for_vulnerability(
                    self._current_vulnerability
                )
                return {
                    "command": f"scan({vuln_id})",
                    "success": True,
                    "is_fixed": is_fixed,
                    "stdout": scan_output or "",
                    "stderr": "",
                    "exit_code": 0,
                    "duration": 0.1,
                }
            return {
                "command": f"scan({vuln_id})",
                "success": False,
                "stdout": "",
                "stderr": "No vulnerability context available for scanning",
                "exit_code": 1,
                "duration": 0.0,
            }

        elif tool_name == "verdict":
            # Verdict is handled by ToolCallingLLM, just acknowledge
            return {"acknowledged": True}

        else:
            return {"error": f"Unknown tool: {tool_name}"}

    def process(self, input_data: QAInput) -> QAResult:
        """
        Run QA validation on a remediation.

        Args:
            input_data: QAInput with vulnerability, remediation, and review

        Returns:
            QAResult with safety verdict and validation details
        """
        start_time = time.time()

        # Store vulnerability so scan tool can access it
        self._current_vulnerability = input_data.vulnerability

        # Build validation prompt
        user_prompt = self._build_qa_prompt(input_data)

        # Run LLM validation session
        session_result = self.llm.run_session(
            user_prompt=user_prompt, session_label=f"qa_{input_data.vulnerability.id}"
        )

        # Extract verdict
        verdict_data = session_result.get("verdict")
        safe = False
        message = "QA validation incomplete"

        if verdict_data:
            safe = verdict_data.get("safe", False)
            message = verdict_data.get("message", "No verdict message")

        # Parse system checks from detailed results
        system_checks = []
        regression_detected = False
        for detail in session_result.get("detailed_results", []):
            system_checks.append(
                RunCommandResult(
                    command=detail.get("command", ""),
                    stdout=detail.get("stdout", ""),
                    stderr=detail.get("stderr", ""),
                    exit_code=detail.get("exit_code"),
                    success=detail.get("success", False),
                    duration=detail.get("duration", 0.0),
                    timed_out=detail.get("timed_out", False),
                )
            )
            # Check scan results for regression (is_fixed=False means vulnerability still present)
            if detail.get("command", "").startswith("scan(") and detail.get("is_fixed") is False:
                regression_detected = True

        # Determine recommendation
        if safe:
            recommendation = "Approve"
        else:
            recommendation = "Rollback"

        # Extract services from commands
        services_affected = self._extract_services(session_result.get("commands", []))

        duration = time.time() - start_time

        return QAResult(
            finding_id=input_data.vulnerability.id,
            safe=safe,
            side_effects=[],
            services_affected=services_affected,
            system_checks=system_checks,
            regression_detected=regression_detected,
            other_findings_affected=[],
            recommendation=recommendation,
            validation_duration=duration,
        )

    def _build_qa_prompt(self, input_data: QAInput) -> str:
        """Build QA validation prompt for LLM."""
        vuln = input_data.vulnerability
        attempt = input_data.remediation_attempt
        review = input_data.review_verdict

        lines = [
            "# QA VALIDATION TASK",
            "",
            f"Vulnerability ID: {vuln.id}",
            f"Title: {vuln.title}",
            f"Severity: {vuln.severity}",
            "",
            "## Remediation Applied",
            f"Commands executed: {attempt.commands_executed}",
            f"Scan passed: {attempt.scan_passed}",
            f"Success: {attempt.success}",
            "",
            "## Review Verdict",
            f"Approved: {review.approve}",
            f"Optimal: {review.is_optimal}",
            f"Security score: {review.security_score}",
        ]

        if review.feedback:
            lines.append(f"Feedback: {review.feedback}")

        if review.concerns:
            lines.append(f"Concerns: {', '.join(review.concerns)}")

        lines.extend(
            [
                "",
                "## Your Task",
                "Run comprehensive validation to ensure the remediation is safe:",
                "1. Check critical services (sshd, auditd, firewalld) are running",
                "2. Review system logs for errors introduced since remediation",
                "3. Confirm system accessibility (SSH still works)",
                "4. Run scan to verify fix and check for regressions",
                "",
                "When validation is complete, call `verdict` with your safety assessment.",
            ]
        )

        return "\n".join(lines)

    def _extract_services(self, commands: List[str]) -> List[str]:
        """Extract service names from systemctl commands."""
        services = []
        for cmd in commands:
            if "systemctl" in cmd.lower() and "status" in cmd.lower():
                parts = cmd.split()
                if len(parts) >= 3:
                    service = parts[2]  # systemctl status <service>
                    if service not in services:
                        services.append(service)
        return services