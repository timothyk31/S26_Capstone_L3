# TODO: Implement Review Agent (NEW LOGIC - Not in current codebase)
#
# Purpose: Validate solution quality and optimality
# Position in pipeline: THIRD stage (after Remedy scan success)
# Tools: None or read-only (analyze Remedy output)
# Can send back: Review → Remedy loop if not optimal
#
# Input: ReviewInput (vulnerability, remediation_attempt, triage_decision)
# Output: ReviewVerdict (is_optimal, approve, feedback, concerns, suggested_improvements)
#
# Key responsibilities:
# 1. Evaluate if remediation is the BEST solution (not just working)
# 2. Check for security best practices
# 3. Identify potential issues (breaking changes, side effects)
# 4. Provide feedback for improvement
# 5. Decide: approve → QA OR send back → Remedy with feedback
#
# Review criteria:
# - Does solution follow security best practices?
# - Is it the minimal change needed?
# - Are there better alternatives?
# - Will it cause service disruptions?
# - Is it maintainable/reversible?
#
# Example:
# class ReviewAgent:
#     def __init__(self, llm: ToolCallingLLM):
#         self.llm = llm  # Composition - no tools or read-only
#
#     def process(self, input_data: ReviewInput) -> ReviewVerdict:
#         vuln = input_data.vulnerability
#         attempt = input_data.remediation_attempt
#
#         # Analyze commands executed
#         # Check best practices
#         # Identify concerns
#
#         return ReviewVerdict(
#             finding_id=vuln.id,
#             is_optimal=True,
#             approve=True,
#             security_score=9
#         )