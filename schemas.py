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
    # OpenSCAP scan fields
    result: Optional[str] = Field(default=None, description="Scan result status (e.g., fail, error, notchecked)")
    rule: Optional[str] = Field(default=None, description="Short rule name extracted from XCCDF rule ID")
    oval_id: Optional[str] = Field(default=None, description="Full XCCDF rule ID / OVAL reference")
    scan_class: Optional[str] = Field(default=None, description="Finding class (e.g., compliance)")
    os: Optional[str] = Field(default=None, description="Target OS detected during scan")

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
# Multi-Agent Pipeline Schemas
# ============================================================================

# --- Triage Agent Schemas ---

class TriageInput(BaseModel):
    vulnerability: Vulnerability
    system_context: Optional[dict] = Field(
        default=None,
        description="Optional context about the target system (e.g., environment, criticality)",
    )


class TriageDecision(BaseModel):
    finding_id: str = Field(..., description="Vulnerability id from the scan (e.g., openscap_002)")
    should_remediate: bool = Field(..., description="True if safe for automated remediation")
    risk_level: str = Field(
        ...,
        description="Risk assessment: low | medium | high | critical",
    )
    reason: str = Field(..., description="Rationale for the triage decision")
    requires_human_review: bool = Field(
        default=False,
        description="True if a human should review before any action",
    )
    estimated_impact: Optional[str] = Field(
        default=None,
        description="Expected impact of remediation (e.g., 'service restart', 'reboot required')",
    )

# TODO: Remedy Agent Schemas
# class RemedyInput(BaseModel):
#     vulnerability: Vulnerability
#     triage_decision: TriageDecision
#     attempt_number: int = 1
#     previous_attempts: List['RemediationAttempt'] = []
#     review_feedback: Optional[str] = None
#
# class RemediationAttempt(BaseModel):
#     finding_id: str
#     attempt_number: int
#     commands_executed: List[str]
#     files_modified: List[str]
#     files_read: List[str]
#     execution_details: List[RunCommandResult]  # Reuse existing!
#     scan_passed: bool
#     scan_output: Optional[str] = None
#     duration: float
#     success: bool
#     error_summary: Optional[str] = None
#     llm_verdict: Optional[ToolVerdict] = None  # Reuse existing!

# TODO: Review Agent Schemas
# class ReviewInput(BaseModel):
#     vulnerability: Vulnerability
#     remediation_attempt: RemediationAttempt
#     triage_decision: TriageDecision
#
# class ReviewVerdict(BaseModel):
#     finding_id: str
#     is_optimal: bool
#     approve: bool
#     feedback: Optional[str] = None
#     concerns: List[str] = []
#     suggested_improvements: List[str] = []
#     security_score: Optional[int] = None
#     best_practices_followed: bool = True

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
