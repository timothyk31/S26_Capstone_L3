"""
Remedy Agent V2: Single-session Plan → Review → Apply workflow.

V2 flow for a single attempt (one continuous LLM session):
  1. LLM describes its proposed fix in text (planning turn).
  2. LLM calls the review_plan tool → ReviewAgentV2 evaluates (Review + QA).
  3. If approved, LLM proceeds with run_cmd/read_file/write_file to apply.
  4. If rejected, feedback is visible in conversation history; LLM can revise
     and call review_plan again.

All steps share one session — no context re-serialisation between phases,
no separate API sessions for planning, review, QA, and application.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from worker_display import worker_print
from agents.remedy_agent import RemedyAgent
from agents.review_agent_v2 import ReviewAgentV2
from schemas import (
    PreApprovalResult,
    RemedyInput,
    RemediationAttempt,
    ReviewInput,
    ToolVerdict,
    Vulnerability,
)

console = Console()


class RemedyAgentV2:
    """
    V2 Remedy agent: single-session plan → review → apply.

    All stages run in one continuous tool-calling conversation.
    review_plan is exposed as a tool so the LLM can request Review+QA
    validation without leaving the session.
    """

    _MAX_REVIEW_REJECTIONS = 1

    def __init__(
        self,
        remedy_agent: RemedyAgent,
        review_agent_v2: ReviewAgentV2,
        transcript_dir: Optional[str | Path] = None,
    ):
        self.remedy_agent = remedy_agent
        self.review_v2 = review_agent_v2
        self._transcript_dir: Optional[Path] = Path(transcript_dir) if transcript_dir else None
        if self._transcript_dir:
            self._transcript_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def process(
        self,
        input_data: RemedyInput,
    ) -> tuple[RemediationAttempt, Optional[PreApprovalResult]]:
        """
        Run plan → review → apply in one retained LLM session.

        Returns:
            (remediation_attempt, pre_approval_result)
            pre_approval_result is None only if the session errors before
            any review_plan call is made.
        """
        vuln = input_data.vulnerability
        vid = vuln.id
        start = time.time()

        worker_print(
            f"[bold cyan]  Remedy session[/bold cyan]  {vid}  "
            f"[dim]attempt {input_data.attempt_number}[/dim]"
        )

        # Build the initial user prompt — same helper as remedy_agent, which
        # already embeds previous attempts, review verdicts, and plan text.
        user_prompt = self.remedy_agent._build_agent_prompt(
            vuln=vuln,
            triage_reason=input_data.triage_decision.reason,
            previous_attempts=input_data.previous_attempts,
            review_feedback=input_data.review_feedback,
            previous_review_verdicts=input_data.previous_review_verdicts,
            attempt_number=input_data.attempt_number,
            plan_text=input_data.plan_text,
        )

        session_label = f"{vid}_attempt{input_data.attempt_number}"
        (self.remedy_agent.work_dir / f"remedy_prompt_{session_label}.txt").write_text(
            user_prompt, encoding="utf-8"
        )

        # Stub ReviewInput used as base for review_plan tool calls.
        stub_review_input = ReviewInput(
            vulnerability=vuln,
            remediation_attempt=RemediationAttempt(
                finding_id=vid,
                attempt_number=input_data.attempt_number,
                llm_verdict=ToolVerdict(message="", resolved=False),
            ),
            triage_decision=input_data.triage_decision,
            previous_verdicts=input_data.previous_review_verdicts,
        )

        try:
            with self.remedy_agent.executor.hold_files():
                session_result = self._run_v2_session(
                    user_prompt=user_prompt,
                    session_label=session_label,
                    vuln=vuln,
                    stub_review_input=stub_review_input,
                    attempt_number=input_data.attempt_number,
                )
        except Exception as exc:
            worker_print(f"[red]  x Session error:[/red] {exc}")
            return (
                RemediationAttempt(
                    finding_id=vid,
                    attempt_number=input_data.attempt_number,
                    error_summary=str(exc),
                ),
                None,
            )

        attempt = RemediationAttempt(
            finding_id=vid,
            attempt_number=input_data.attempt_number,
            commands_executed=session_result["commands_executed"],
            files_modified=session_result["files_modified"],
            files_read=session_result["files_read"],
            execution_details=session_result["execution_details"],
            llm_verdict=ToolVerdict(
                message=session_result.get("final_message", ""), resolved=False
            ),
            scan_passed=False,
            scan_output=None,
            success=False,
        )
        attempt.llm_metrics = session_result.get("llm_metrics")
        attempt.reasoning_messages = session_result.get("reasoning_messages", [])
        attempt.attempt_duration = time.time() - start

        # Save combined transcript (plan + review + apply — all in one file)
        usage_records = session_result.get("usage", [])
        total_api_seconds = round(
            sum(u.get("_api_call_seconds", 0) for u in usage_records), 3
        )
        usage_total: Dict[str, Any] = {}
        if usage_records:
            usage_total = {
                "prompt_tokens": sum(u.get("prompt_tokens", 0) for u in usage_records),
                "completion_tokens": sum(u.get("completion_tokens", 0) for u in usage_records),
                "total_tokens": sum(u.get("total_tokens", 0) for u in usage_records),
                "total_api_seconds": total_api_seconds,
                "per_turn": usage_records,
            }
        transcript_base = self._transcript_dir or self.remedy_agent.work_dir
        transcript_path = transcript_base / f"remedy_transcript_v2_{session_label}.json"
        transcript_path.write_text(
            json.dumps(
                {"messages": session_result["transcript"], "usage": usage_total or None},
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

        return attempt, session_result.get("pre_approval_result")

    # ------------------------------------------------------------------ #
    #  Tool spec                                                           #
    # ------------------------------------------------------------------ #

    def _v2_tools_spec(self) -> List[Dict[str, Any]]:
        """4-tool spec: review_plan + the 3 remedy execution tools."""
        review_tool: Dict[str, Any] = {
            "type": "function",
            "function": {
                "name": "review_plan",
                "description": (
                    "Submit your proposed fix plan for security review and safety "
                    "validation BEFORE executing any commands. Describe the full plan "
                    "including which files to modify and which commands to run. Returns "
                    "an approval verdict with detailed feedback."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "plan_description": {
                            "type": "string",
                            "description": (
                                "Full description of your proposed remediation: "
                                "files to modify, commands to run, and rationale."
                            ),
                        }
                    },
                    "required": ["plan_description"],
                    "additionalProperties": False,
                },
            },
        }
        return [review_tool] + self.remedy_agent._tools_spec()

    # ------------------------------------------------------------------ #
    #  review_plan tool handler                                            #
    # ------------------------------------------------------------------ #

    def _handle_review_plan(
        self,
        plan_description: str,
        stub_review_input: ReviewInput,
        attempt_number: int,
    ) -> tuple[PreApprovalResult, Dict[str, Any]]:
        """
        Call ReviewAgentV2 with the LLM's plan text.
        Returns (PreApprovalResult, payload_for_llm).
        """
        updated_attempt = stub_review_input.remediation_attempt.model_copy(
            update={"llm_verdict": ToolVerdict(message=plan_description, resolved=False)}
        )
        review_input = stub_review_input.model_copy(
            update={"remediation_attempt": updated_attempt}
        )
        advisory: PreApprovalResult = self.review_v2.process(
            review_input, attempt=attempt_number
        )

        rv = advisory.review_verdict
        payload: Dict[str, Any] = {
            "approved": advisory.approved,
            "review_approved": rv.approve,
            "review_feedback": rv.feedback,
            "review_concerns": rv.concerns,
            "review_suggested_improvements": rv.suggested_improvements,
            "review_security_score": rv.security_score,
        }
        if advisory.qa_result:
            payload.update({
                "qa_safe": advisory.qa_result.safe,
                "qa_verdict_reason": advisory.qa_result.verdict_reason,
                "qa_side_effects": advisory.qa_result.side_effects,
                "qa_recommendation": advisory.qa_result.recommendation,
            })
        if not advisory.approved:
            payload["rejection_reason"] = advisory.rejection_reason
            payload["instruction"] = (
                "Your plan was NOT approved. Read the feedback carefully, revise "
                "your approach, and call review_plan again with an improved plan "
                "before using any execution tools."
            )
        else:
            payload["instruction"] = (
                "Plan approved. Proceed with run_cmd / read_file / write_file to apply the fix."
            )

        return advisory, payload

    # ------------------------------------------------------------------ #
    #  Single retained session loop                                        #
    # ------------------------------------------------------------------ #

    def _run_v2_session(
        self,
        *,
        user_prompt: str,
        session_label: str,
        vuln: Vulnerability,
        stub_review_input: ReviewInput,
        attempt_number: int,
    ) -> Dict[str, Any]:
        """
        One continuous tool-calling session covering plan → review → apply.

        The LLM naturally describes its plan, calls review_plan, then
        continues with execution tools — all in the same conversation.
        """
        system_prompt = (
            "You are an adaptive remediation agent on Rocky Linux / RHEL. "
            "Follow this workflow STRICTLY:\n"
            "  1. PLAN: In your first response, describe your proposed fix "
            "(which files, which values, which commands).\n"
            "  2. REVIEW: Call review_plan with your full plan description "
            "BEFORE executing any commands.\n"
            "  3. APPLY: Only after review_plan returns approved=true, use "
            "run_cmd / read_file / write_file to apply the fix.\n"
            "  4. If review_plan returns approved=false, read the feedback, "
            "revise your approach, and call review_plan again. You have a "
            "maximum of 3 review attempts — if all are rejected, proceed "
            "with your best plan using the execution tools.\n\n"
            "EXECUTION RULES:\n"
            "- One command at a time. Do NOT chain with && or ;\n"
            "- Always use read_file before modifying a config file.\n"
            "- This is Rocky Linux/RHEL — use dnf (not apt), systemctl (not service).\n"
            "- Do NOT duplicate config lines. Modify existing values in-place with sed.\n"
            "- Do NOT modify sshd_config or firewall rules in ways that block SSH.\n"
            "- stderr may contain SSH banners — check exit_code and stdout instead.\n"
            "- A verification scan runs automatically after your session ends."
        )

        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        transcript: List[Dict[str, Any]] = list(messages)

        commands_executed: List[str] = []
        files_read: List[str] = []
        files_modified: List[str] = []
        execution_details: List[Any] = []
        final_message: str = ""
        usage_records: List[Dict[str, Any]] = []
        turn_records: List[Dict[str, Any]] = []
        reasoning_messages: List[Dict[str, Any]] = []

        pre_approval_result: Optional[PreApprovalResult] = None

        # Phase timing for step_durations
        _session_start = time.time()
        _review_total_seconds = 0.0
        _last_review_end_time: Optional[float] = None

        # Review cap tracking
        consecutive_review_rejections = 0
        review_plan_capped = False

        tool_calls_used = 0
        max_tool_calls = self.remedy_agent.max_tool_iterations
        total_turns = 0
        v2_tools = self._v2_tools_spec()

        while tool_calls_used < max_tool_calls and total_turns < max_tool_calls + 6:
            total_turns += 1
            _t0 = time.time()
            resp = self.remedy_agent._chat(messages, tools=v2_tools)
            _turn_duration = time.time() - _t0

            turn_usage = resp.get("usage")
            if turn_usage:
                turn_usage["_api_call_seconds"] = round(_turn_duration, 3)
                usage_records.append(turn_usage)
            else:
                usage_records.append({"_api_call_seconds": round(_turn_duration, 3)})

            msg = resp["choices"][0]["message"]
            assistant_entry: Dict[str, Any] = {
                "role": "assistant",
                "content": msg.get("content"),
                "tool_calls": msg.get("tool_calls"),
            }
            reasoning = (
                msg.get("reasoning_content")
                or msg.get("reasoning")
                or msg.get("thinking")
            )
            if reasoning:
                assistant_entry["reasoning"] = reasoning
                reasoning_messages.append({
                    "turn": total_turns,
                    "reasoning": reasoning,
                    "content": msg.get("content"),
                })
            assistant_entry["_raw_message"] = dict(msg)
            transcript.append(assistant_entry)
            messages.append(msg)

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                final_message = msg.get("content") or final_message
                if total_turns > tool_calls_used + 4:
                    break
                continue

            for tc in tool_calls:
                name = tc["function"]["name"]
                raw_args = tc["function"].get("arguments")

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
                if not isinstance(args, dict):
                    args = {}

                _cmd_t0 = time.time()

                if name == "review_plan":
                    plan_description = (args.get("plan_description") or "").strip()
                    worker_print(
                        f"[bold cyan]  review_plan[/bold cyan]  {vuln.id}  "
                        f"[dim]invoking Review+QA[/dim]"
                    )
                    advisory, payload = self._handle_review_plan(
                        plan_description=plan_description,
                        stub_review_input=stub_review_input,
                        attempt_number=attempt_number,
                    )
                    pre_approval_result = advisory

                    if advisory.approved:
                        consecutive_review_rejections = 0
                    else:
                        consecutive_review_rejections += 1
                        if consecutive_review_rejections >= self._MAX_REVIEW_REJECTIONS:
                            review_plan_capped = True
                            worker_print(
                                f"[yellow]  x Review cap reached[/yellow]  "
                                f"[dim]{consecutive_review_rejections} rejections "
                                f"- ending attempt[/dim]"
                            )
                            # End the session — don't force the LLM to apply a rejected plan
                            result_content = json.dumps(payload)
                            cmd_label = "review_plan"
                            cmd_duration = time.time() - _cmd_t0
                            _review_total_seconds += cmd_duration
                            _last_review_end_time = time.time()
                            break

                    result_content = json.dumps(payload)
                    cmd_label = "review_plan"
                    cmd_duration = time.time() - _cmd_t0
                    _review_total_seconds += cmd_duration
                    _last_review_end_time = time.time()

                elif name == "run_cmd":
                    command = (args.get("command") or "").strip()
                    result = self.remedy_agent._tool_run_cmd(command)
                    commands_executed.append(result.command)
                    execution_details.append(result)
                    result_content = json.dumps(result.model_dump())
                    cmd_label = command
                    cmd_duration = getattr(result, "duration", time.time() - _cmd_t0)

                elif name == "read_file":
                    path = (args.get("path") or "").strip()
                    result = self.remedy_agent.executor.read_file(path)
                    files_read.append(path)
                    execution_details.append(result)
                    result_content = json.dumps(result.model_dump())
                    cmd_label = path
                    cmd_duration = getattr(result, "duration", time.time() - _cmd_t0)

                elif name == "write_file":
                    path = (args.get("path") or "").strip()
                    content = args.get("content") or ""
                    mode = args.get("mode")
                    result = self.remedy_agent.executor.write_file(path, content, mode=mode)
                    files_modified.append(path)
                    execution_details.append(result)
                    result_content = json.dumps(result.model_dump())
                    cmd_label = path
                    cmd_duration = getattr(result, "duration", time.time() - _cmd_t0)

                else:
                    result_content = json.dumps({"error": f"Unknown tool {name}"})
                    cmd_label = name
                    cmd_duration = 0.0

                turn_records.append({
                    "turn": total_turns,
                    "api_seconds": round(_turn_duration, 3),
                    "cmd_seconds": round(cmd_duration, 3),
                    "total": round(_turn_duration + cmd_duration, 3),
                    "tool": name,
                    "command": cmd_label,
                })

                tool_entry = {
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result_content,
                }
                transcript.append(tool_entry)
                messages.append(tool_entry)

                tool_calls_used += 1
                if tool_calls_used >= max_tool_calls:
                    break

            if tool_calls_used >= max_tool_calls or review_plan_capped:
                break

        # Compute step_durations from wall-clock phase boundaries
        _session_end = time.time()
        if _last_review_end_time is not None:
            apply_fix_seconds = _session_end - _last_review_end_time
            plan_fix_seconds = (
                (_session_end - _session_start)
                - _review_total_seconds
                - apply_fix_seconds
            )
        else:
            plan_fix_seconds = _session_end - _session_start
            apply_fix_seconds = 0.0

        step_durations = {
            "plan_fix_seconds": round(plan_fix_seconds, 3),
            "review_qa_seconds": round(_review_total_seconds, 3),
            "apply_fix_seconds": round(apply_fix_seconds, 3),
        }

        return {
            "transcript": transcript,
            "commands_executed": commands_executed,
            "files_read": files_read,
            "files_modified": files_modified,
            "execution_details": execution_details,
            "final_message": final_message,
            "usage": usage_records,
            "pre_approval_result": pre_approval_result,
            "reasoning_messages": reasoning_messages,
            "llm_metrics": {
                "total_llm_api_seconds": round(
                    sum(r["api_seconds"] for r in turn_records), 3
                ),
                "total_command_execution_seconds": round(
                    sum(r["cmd_seconds"] for r in turn_records), 3
                ),
                "llm_calls": len(usage_records),
                "per_turn": turn_records,
                "step_durations": step_durations,
                "review_rejections": consecutive_review_rejections,
                "review_plan_capped": review_plan_capped,
            },
        }
