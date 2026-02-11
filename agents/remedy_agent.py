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