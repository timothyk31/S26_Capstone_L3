# TODO: Implement Triage Agent
#
# Purpose: Decide if a vulnerability should be remediated or discarded
# Position in pipeline: FIRST stage (receives raw vulnerabilities)
# Tools: None (or minimal - just decision making)
#
# Input: TriageInput (vulnerability, system_context)
# Output: TriageDecision (should_remediate, risk_level, reason, requires_human_review)
#
# Key responsibilities:
# 1. Assess risk level of vulnerability
# 2. Determine if fix is safe to automate
# 3. Flag vulnerabilities requiring human review
# 4. Consider system context (production vs dev, criticality)
# 5. Discard vulnerabilities that are too risky to auto-remediate
#
# Implementation approach:
# - Option 1: Rule-based logic (no LLM needed)
# - Option 2: Simple LLM call without tools (composition with ToolCallingLLM)
# - Use severity, CVSS score, vulnerability type to make decisions
#
# Example:
# class TriageAgent:
#     def __init__(self, llm: Optional[ToolCallingLLM] = None):
#         self.llm = llm  # Composition (optional if rule-based)
#
#     def process(self, input_data: TriageInput) -> TriageDecision:
#         vuln = input_data.vulnerability
#         # Decision logic here
#         return TriageDecision(
#             finding_id=vuln.id,
#             should_remediate=True,
#             risk_level="medium",
#             reason="Safe to automate audit rule addition"
#         )