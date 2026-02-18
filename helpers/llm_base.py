"""
ToolCallingLLM: Flexible LLM wrapper for tool-calling agents.
Extracted from qa_agent_adaptive.py and made configurable for multi-agent system.
"""

import json
from typing import Any, Callable, Dict, List, Optional

import requests


class ToolCallingLLM:
    """
    LLM wrapper that drives tool-calling sessions.
    Flexible and reusable across different agents (Remedy, QA, etc.).
    """

    def __init__(
        self,
        model_name: str,
        base_url: str,
        api_key: str,
        system_prompt: str,
        tools: List[dict],  # OpenAI function calling format
        tool_executor: Callable[[str, dict], dict],  # Handles actual tool execution
        max_tool_iterations: int = 24,
        request_timeout: int = 90,
    ):
        """
        Initialize ToolCallingLLM.

        Args:
            model_name: LLM model identifier
            base_url: API base URL (e.g., https://openrouter.ai/api/v1)
            api_key: API authentication key
            system_prompt: System prompt for the agent
            tools: List of tool definitions in OpenAI format
            tool_executor: Callback function (tool_name, args) -> result_dict
            max_tool_iterations: Max number of tool calls before stopping
            request_timeout: HTTP request timeout in seconds
        """
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.system_prompt = system_prompt
        self.tools = tools
        self.tool_executor = tool_executor
        self.max_tool_iterations = max_tool_iterations
        self.request_timeout = request_timeout
        self.endpoint = f"{self.base_url}/chat/completions"
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

    def run_session(
        self,
        user_prompt: str,
        session_label: str = "session",
    ) -> Dict[str, Any]:
        """
        Run a tool-calling session with the LLM.

        Args:
            user_prompt: User-facing prompt describing the task
            session_label: Label for logging/debugging

        Returns:
            Dictionary with:
                - commands: List of executed commands
                - detailed_results: List of execution details
                - combined_output: Formatted output string
                - verdict: Final verdict from LLM (if provided)
                - apply_success: Whether any command succeeded
                - transcript: Full conversation history
                - usage: Token usage records
                - session_label: Session identifier
        """
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        transcript: List[Dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        executed_commands: List[str] = []
        detailed_results: List[Dict[str, Any]] = []
        combined_output_parts: List[str] = []
        usage_records: List[Dict[str, Any]] = []
        verdict: Optional[Dict[str, Any]] = None

        command_calls = 0
        reasoning_turns = 0

        while command_calls < self.max_tool_iterations:
            response = self._chat(messages)
            usage = response.get("usage")
            if usage:
                usage_records.append(usage)

            message = response["choices"][0]["message"]
            assistant_entry: Dict[str, Any] = {
                "role": "assistant",
                "content": message.get("content"),
            }
            if message.get("tool_calls"):
                assistant_entry["tool_calls"] = message["tool_calls"]
            transcript.append(assistant_entry)
            messages.append(message)

            tool_calls = message.get("tool_calls") or []
            if not tool_calls:
                reasoning_turns += 1
                if reasoning_turns > 6:
                    break
                continue

            for tool_call in tool_calls:
                name = tool_call["function"]["name"]
                raw_args = tool_call["function"].get("arguments") or "{}"
                try:
                    args = json.loads(raw_args)
                except Exception:
                    args = {}

                # Execute tool via callback
                payload = self.tool_executor(name, args)

                # Track execution details for reporting
                if "command" in payload:
                    executed_commands.append(payload["command"])
                    detailed_entry = {
                        "command": payload.get("command", ""),
                        "exit_code": payload.get("exit_code"),
                        "stdout": payload.get("stdout", ""),
                        "stderr": payload.get("stderr", ""),
                        "success": payload.get("success", False),
                        "timed_out": payload.get("timed_out", False),
                        "duration": payload.get("duration"),
                        "normalized_from": payload.get("normalized_from"),
                    }
                    detailed_results.append(detailed_entry)
                    combined_output_parts.append(self._format_command_result(detailed_entry))
                    command_calls += 1

                # Check for verdict
                if name == "verdict":
                    verdict = {
                        "message": args.get("message", ""),
                        "resolved": bool(args.get("resolved")),
                    }

                tool_entry = {
                    "role": "tool",
                    "tool_call_id": tool_call["id"],
                    "content": json.dumps(payload),
                }
                transcript.append(tool_entry)
                messages.append(tool_entry)

                if name == "verdict" or command_calls >= self.max_tool_iterations:
                    break

            if verdict or command_calls >= self.max_tool_iterations:
                break

        apply_success = any(result.get("success") for result in detailed_results)

        return {
            "commands": executed_commands,
            "detailed_results": detailed_results,
            "combined_output": "\n\n".join(combined_output_parts),
            "verdict": verdict,
            "apply_success": apply_success,
            "transcript": transcript,
            "usage": usage_records,
            "session_label": session_label,
        }

    def _chat(self, messages: List[Dict[str, Any]], _retries: int = 3) -> Dict[str, Any]:
        """Send chat completion request to LLM API with retry on transient errors."""
        import time as _time
        payload = {
            "model": self.model_name,
            "messages": messages,
            "tools": self.tools,
            "tool_choice": "auto",
        }
        last_exc = None
        for attempt in range(_retries):
            try:
                response = requests.post(
                    self.endpoint,
                    headers=self.headers,
                    json=payload,
                    timeout=self.request_timeout,
                )
                if response.status_code >= 500:
                    last_exc = RuntimeError(f"LLM API error {response.status_code}: {response.text}")
                    _time.sleep(2 ** attempt)
                    continue
                if response.status_code >= 400:
                    raise RuntimeError(f"LLM API error {response.status_code}: {response.text}")
                return response.json()
            except requests.exceptions.Timeout as exc:
                last_exc = exc
                _time.sleep(2 ** attempt)
            except requests.exceptions.ConnectionError as exc:
                last_exc = exc
                _time.sleep(2 ** attempt)
        raise RuntimeError(f"LLM API failed after {_retries} retries: {last_exc}")

    def _format_command_result(self, detail: Dict[str, Any]) -> str:
        """Format command execution result for readability."""
        stdout = detail.get("stdout") or ""
        stderr = detail.get("stderr") or ""
        return "\n".join(
            [
                f"$ {detail.get('command', '<unknown>')} (exit={detail.get('exit_code')})",
                "STDOUT:",
                stdout if stdout.strip() else "<empty>",
                "STDERR:",
                stderr if stderr.strip() else "<empty>",
                "",
            ]
        )