# TODO: Extract ToolCallingLLM as reusable base class
#
# This module should provide:
# 1. Extract ToolCallingLLM class (lines 1172-1386 from qa_agent_adaptive.py)
# 2. Make tools configurable (passed in __init__)
# 3. Make system prompt configurable per agent
# 4. Keep tool-calling loop logic (max_tool_iterations)
# 5. Keep tool execution dispatch pattern
#
# Usage pattern (Composition):
# - Each agent (Remedy, QA, Triage, Review) creates its own ToolCallingLLM instance
# - Each agent defines its own tools and system prompt
# - Remedy Agent: tools=[run_cmd, write_file, read_file, scan]
# - QA Agent: tools=[run_cmd, scan]
# - Triage Agent: tools=[] (might not need tools)
# - Review Agent: tools=[] (might not need tools)
#
# Example interface:
# class ToolCallingLLM:
#     def __init__(
#         self,
#         model_name: str,
#         base_url: str,
#         api_key: str,
#         system_prompt: str,
#         tools: List[dict],  # OpenAI function calling format
#         tool_executor: Callable,  # Handles actual tool execution
#         max_tool_iterations: int = 24,
#         ...
#     ):
#         pass
#
#     def run_session(self, user_prompt: str) -> Dict[str, Any]:
#         """Run tool-calling session with LLM"""
#         pass