"""
Base Agent — Abstract interface for all pipeline agents.

Every agent in the pipeline (Triage, Remedy, Review, QA) inherits from
BaseAgent and implements ``process()``.  This guarantees polymorphism: the
Pipeline can call ``agent.process(input_data)`` without knowing the concrete
agent type.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

log = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all pipeline agents."""

    # Subclasses may set a friendly name for logging / reports.
    agent_name: str = "BaseAgent"

    # ------------------------------------------------------------------
    # Core contract
    # ------------------------------------------------------------------
    @abstractmethod
    def process(self, input_data: Any) -> Any:
        """
        Process agent-specific input and return agent-specific output.

        Args:
            input_data: Agent-specific Pydantic model
                        (TriageInput, RemedyInput, ReviewInput, QAInput).

        Returns:
            Agent-specific Pydantic model
            (TriageDecision, RemediationAttempt, ReviewVerdict, QAResult).
        """
        ...

    # ------------------------------------------------------------------
    # Optional shared utilities
    # ------------------------------------------------------------------
    def log_info(self, message: str) -> None:
        """Convenience logger at INFO level."""
        log.info("[%s] %s", self.agent_name, message)

    def log_warning(self, message: str) -> None:
        """Convenience logger at WARNING level."""
        log.warning("[%s] %s", self.agent_name, message)

    def log_error(self, message: str) -> None:
        """Convenience logger at ERROR level."""
        log.error("[%s] %s", self.agent_name, message)

    def handle_error(self, error: Exception) -> None:
        """
        Default error handler — logs and re-raises.
        Subclasses can override to add recovery / fallback logic.
        """
        self.log_error(f"{type(error).__name__}: {error}")
        raise error
