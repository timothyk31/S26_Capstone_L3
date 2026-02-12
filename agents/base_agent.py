# TODO: Implement Base Agent (Abstract interface for all pipeline agents)
#
# Purpose: Define common interface that all agents must implement
# Pattern: Abstract base class using ABC (Abstract Base Class)
#
# Key responsibilities:
# 1. Define process() method that all agents must implement
# 2. Enforce consistent interface across all agents
# 3. Enable polymorphism (Pipeline can work with any agent)
# 4. Optional: Common logging, error handling, metrics
#
# All agents extend this base:
# - TriageAgent extends BaseAgent
# - RemedyAgent extends BaseAgent
# - ReviewAgent extends BaseAgent
# - QAAgent extends BaseAgent
#
# Example implementation:
# ```python
# from abc import ABC, abstractmethod
# from typing import Any
#
# class BaseAgent(ABC):
#     """Abstract base class for all pipeline agents"""
#
#     @abstractmethod
#     def process(self, input_data: Any) -> Any:
#         """
#         Process input and return output.
#         Each agent implements its own logic.
#
#         Args:
#             input_data: Agent-specific input (TriageInput, RemedyInput, etc.)
#
#         Returns:
#             Agent-specific output (TriageDecision, RemediationAttempt, etc.)
#         """
#         pass
#
#     # Optional: Common utility methods
#     def log(self, message: str):
#         """Common logging"""
#         pass
#
#     def handle_error(self, error: Exception):
#         """Common error handling"""
#         pass
# ```
#
# Usage in Pipeline:
# ```python
# class Pipeline:
#     def __init__(
#         self,
#         triage: BaseAgent,  # Polymorphism - any BaseAgent
#         remedy: BaseAgent,
#         review: BaseAgent,
#         qa: BaseAgent
#     ):
#         self.triage = triage
#         self.remedy = remedy
#         # ...
# ```
