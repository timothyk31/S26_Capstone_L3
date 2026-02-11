from typing import List, Optional
from pydantic import BaseModel, Field

class Vulnerability(BaseModel):
    id: str
    title: str
    severity: str
    cvss: Optional[float] = None
    host: str
    port: Optional[str] = None
    protocol: Optional[str] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None

class RemediationSuggestion(BaseModel):
    id: str
    proposed_commands: List[str] = Field(description="List of specific remediation commands for this vulnerability")
    notes: str = Field(description="Additional context or warnings about the remediation")


class RunCommandResult(BaseModel):
    command: str = Field(description="Command that was executed (after normalization)")
    stdout: str = Field(description="Captured standard output from the command")
    stderr: str = Field(description="Captured standard error from the command")
    exit_code: Optional[int] = Field(default=None, description="Process exit code, if available")
    success: bool = Field(description="True when the command exited with code 0")
    duration: float = Field(description="Execution time in seconds")
    timed_out: bool = Field(default=False, description="True if the command exceeded the timeout")
    truncated_stdout: bool = Field(default=False, description="True if stdout was truncated for logging")
    truncated_stderr: bool = Field(default=False, description="True if stderr was truncated for logging")
    normalized_from: Optional[str] = Field(default=None, description="Original command text before normalization")


class ToolVerdict(BaseModel):
    message: str = Field(description="Summary of the remediation attempt outcome")
    resolved: bool = Field(description="Whether the vulnerability is believed to be resolved")


class BatchResult(BaseModel):
    suggestions: List[RemediationSuggestion] = Field(description="List of remediation suggestions for the vulnerabilities")


# ============================================================================
# Multi-Agent Pipeline Schemas (Review Agent dependencies + Review)
# ============================================================================

# Triage (needed for ReviewInput)
class TriageDecision(BaseModel):
    finding_id: str
    should_remediate: bool
    risk_level: str = "medium"  # "low" | "medium" | "high" | "critical"
    reason: str = ""
    requires_human_review: bool = False
    estimated_impact: Optional[str] = None


# Remedy (needed for ReviewInput)
class RemediationAttempt(BaseModel):
    finding_id: str
    attempt_number: int = 1
    commands_executed: List[str] = Field(default_factory=list)
    files_modified: List[str] = Field(default_factory=list)
    files_read: List[str] = Field(default_factory=list)
    execution_details: List[RunCommandResult] = Field(default_factory=list)
    scan_passed: bool = False
    scan_output: Optional[str] = None
    duration: float = 0.0
    success: bool = False
    error_summary: Optional[str] = None
    llm_verdict: Optional[ToolVerdict] = None


# Review Agent
class ReviewInput(BaseModel):
    vulnerability: Vulnerability
    remediation_attempt: RemediationAttempt
    triage_decision: TriageDecision


class ReviewVerdict(BaseModel):
    finding_id: str
    is_optimal: bool
    approve: bool
    feedback: Optional[str] = None
    concerns: List[str] = Field(default_factory=list)
    suggested_improvements: List[str] = Field(default_factory=list)
    security_score: Optional[int] = None  # 1-10
    best_practices_followed: bool = True

# TODO: QA Agent Schemas
# class QAInput(BaseModel):
#     vulnerability: Vulnerability
#     remediation_attempt: RemediationAttempt
#     review_verdict: ReviewVerdict
#
# class QAResult(BaseModel):
#     finding_id: str
#     safe: bool
#     side_effects: List[str] = []
#     services_affected: List[str] = []
#     system_checks: List[RunCommandResult] = []  # Reuse existing!
#     regression_detected: bool = False
#     other_findings_affected: List[str] = []
#     recommendation: str  # "Approve", "Rollback", "Investigate"
#     validation_duration: float

# TODO: Aggregation Schemas
# class FindingResult(BaseModel):
#     """Complete pipeline result for a single finding"""
#     vulnerability: Vulnerability
#     triage: TriageDecision
#     remediation: Optional[RemediationAttempt] = None
#     review: Optional[ReviewVerdict] = None
#     qa: Optional[QAResult] = None
#     final_status: str  # "success" | "failed" | "discarded" | "requires_human_review"
#     total_duration: float
#     timestamp: str
#
# class AggregatedReport(BaseModel):
#     """Final output from entire workflow"""
#     findings_processed: int
#     findings_remediated: int
#     findings_failed: int
#     findings_discarded: int
#     results: List[FindingResult]
#     success_rate: float
#     total_duration: float
#     stage_statistics: Dict[str, Any]
#     ansible_playbook_path: Optional[str] = None
#     text_report_path: Optional[str] = None
#     pdf_report_path: Optional[str] = None
#     scan_profile: str
#     target_host: str
#     timestamp: str
