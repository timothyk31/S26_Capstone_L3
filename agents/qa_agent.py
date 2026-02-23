"""
QA Agent: System-wide validation after remediation.
Position: FOURTH stage in pipeline (after Review approval).
Tools: run_cmd (1 tool for validation checks).
"""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from helpers.command_executor import ShellCommandExecutor
from helpers.llm_base import ToolCallingLLM
from helpers.utils import annotate_error_categories, normalize_command
from schemas import FindingResult, QAInput, QAResult, RunCommandResult


class QAAgent:
    """
    QA Agent validates that remediation didn't break the system.
    Uses LLM with run_cmd tool for comprehensive validation.
    """

    SYSTEM_PROMPT = (
        "You are a pragmatic QA validation agent for Linux security remediation. "
        "Your role is to verify that a remediation did NOT introduce serious harm to the system.\n\n"
        "You have access to 1 tool:\n"
        "1. `run_cmd`: Run system health checks (systemctl status, service checks, log analysis)\n\n"
        "Your validation checklist:\n"
        "- Verify critical services are still running (sshd, auditd, firewalld, etc.)\n"
        "- Confirm system is still accessible (SSH works)\n"
        "- Detect any major side effects or unintended changes\n\n"
        "SAFETY GUIDELINES:\n"
        "- Mark safe=true if the system is still functional and critical services are running.\n"
        "- Minor warnings in logs, non-critical service restarts, or cosmetic issues should NOT cause a failure.\n"
        "- Mark safe=false ONLY if critical services are down, the system is unreachable, "
        "or the remediation clearly broke something important.\n"
        "- Security remediations are expected to change configurations — that alone is not a side effect.\n\n"
        "When done, call `verdict` with:\n"
        "- safe=true if the system is functional and healthy\n"
        "- safe=false only if serious issues are detected\n"
        "- Include detailed message explaining findings"
    )

    def __init__(
        self,
        executor: ShellCommandExecutor,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        max_tool_iterations: int = 24,
        request_timeout: int = 120,
    ):
        """
        Initialize QA Agent.

        Args:
            executor: ShellCommandExecutor for running system checks
            api_key: LLM API key (defaults to OPENROUTER_API_KEY env)
            base_url: LLM API base URL (defaults to OPENROUTER_BASE_URL env)
            model: LLM model name (defaults to OPENROUTER_MODEL env)
            max_tool_iterations: Max LLM tool calls
            request_timeout: HTTP timeout
        """
        self.executor = executor

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
        """Define QA Agent's tools: run_cmd and verdict."""
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
        """Execute QA tools: run_cmd or verdict."""
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
            verdict_reason=message,
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
                "Run validation to ensure the remediation did not break the system:",
                "1. Check critical services (sshd, auditd, firewalld) are running",
                "2. Confirm system accessibility (SSH still works)",
                "",
                "Mark safe=true if the system is still functional. Minor log warnings or expected",
                "configuration changes from the remediation are NOT reasons to mark unsafe.",
                "Only mark safe=false if critical services are down or the system is broken.",
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

    # ------------------------------------------------------------------
    # Output: PDF report
    # ------------------------------------------------------------------
    def write_results_pdf(
        self,
        results: List[FindingResult],
        output_path: str | Path = "reports/qa_report.pdf",
        *,
        target_host: str = "unknown",
        title: str = "QA Agent Report",
    ) -> Path:
        """
        Generate a PDF report summarising all QA Agent outputs.

        Only includes findings that reached the QA stage.
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

        title_style = ParagraphStyle("QTitle", parent=styles["Title"], fontSize=20, spaceAfter=6)
        subtitle_style = ParagraphStyle("QSub", parent=styles["Normal"], fontSize=10, textColor=colors.grey, spaceAfter=14)
        section_style = ParagraphStyle("QSec", parent=styles["Heading2"], fontSize=14, spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#1a1a2e"))
        cell_style = ParagraphStyle("QCell", parent=styles["Normal"], fontSize=8, leading=10)
        body_style = ParagraphStyle("QBody", parent=styles["Normal"], fontSize=9, leading=12)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elements.append(Paragraph(title, title_style))
        elements.append(Paragraph(f"Target: {target_host} &nbsp;|&nbsp; Generated: {now}", subtitle_style))

        qa_items = [r for r in results if r.qa is not None]
        safe_count = sum(1 for r in qa_items if r.qa and r.qa.safe)
        unsafe_count = len(qa_items) - safe_count
        regressions = sum(1 for r in qa_items if r.qa and r.qa.regression_detected)

        elements.append(Paragraph("QA Validation Summary", section_style))
        summary_data = [
            ["Total QA Validated", str(len(qa_items))],
            ["Safe", str(safe_count)],
            ["Unsafe", str(unsafe_count)],
            ["Regressions Detected", str(regressions)],
        ]
        summary_table = Table(summary_data, colWidths=[3 * inch, 1.5 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8f5e9")),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 14))

        if not qa_items:
            elements.append(Paragraph("No findings reached the QA stage.", body_style))
        else:
            elements.append(Paragraph("Per-Finding QA Details", section_style))
            table_data = [
                [
                    Paragraph("<b>ID</b>", cell_style),
                    Paragraph("<b>Title</b>", cell_style),
                    Paragraph("<b>Safe</b>", cell_style),
                    Paragraph("<b>Reason</b>", cell_style),
                    Paragraph("<b>Regression</b>", cell_style),
                    Paragraph("<b>Recommendation</b>", cell_style),
                    Paragraph("<b>Side Effects</b>", cell_style),
                    Paragraph("<b>Services Affected</b>", cell_style),
                    Paragraph("<b>Duration</b>", cell_style),
                ],
            ]
            for r in qa_items:
                qa = r.qa
                assert qa is not None
                safe_text = '<font color="#27ae60">SAFE</font>' if qa.safe else '<font color="#e74c3c">UNSAFE</font>'
                reason_text = qa.verdict_reason or "\u2014"
                reg_text = '<font color="#e74c3c">YES</font>' if qa.regression_detected else "No"
                side_text = "<br/>".join(qa.side_effects) or "\u2014"
                svc_text = "<br/>".join(qa.services_affected) or "\u2014"
                table_data.append([
                    Paragraph(r.vulnerability.id, cell_style),
                    Paragraph(r.vulnerability.title or "\u2014", cell_style),
                    Paragraph(safe_text, cell_style),
                    Paragraph(reason_text, cell_style),
                    Paragraph(reg_text, cell_style),
                    Paragraph(qa.recommendation, cell_style),
                    Paragraph(side_text, cell_style),
                    Paragraph(svc_text, cell_style),
                    Paragraph(f"{qa.validation_duration:.1f}s", cell_style),
                ])

            col_widths = [0.7 * inch, 1.3 * inch, 0.5 * inch, 2.0 * inch, 0.6 * inch, 0.8 * inch, 1.5 * inch, 1.4 * inch, 0.6 * inch]
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