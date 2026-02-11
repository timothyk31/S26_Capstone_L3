# TODO: Extract utility functions from qa_agent_adaptive.py
#
# This module should provide:
# 1. Extract _normalize_command() method - Debian→RHEL command translation
#    - apt-get → dnf
#    - apt → dnf
#    - Package name translations
# 2. Extract _annotate_error_categories() method - Error classification
#    - Permission denied, command not found, service failures, etc.
# 3. Extract prompt building helpers if needed
# 4. Any other shared utility functions
#
# Example interface:
# def normalize_command(command: str) -> str:
#     """Convert Debian/Ubuntu commands to RHEL/Rocky equivalents"""
#     pass
#
# def annotate_error_categories(stderr: str, exit_code: int) -> List[str]:
#     """Classify error types from command output"""
#     pass
#
# def build_vulnerability_context(vuln: Vulnerability, previous_attempts: List) -> str:
#     """Build context-rich prompt for LLM"""
#     pass