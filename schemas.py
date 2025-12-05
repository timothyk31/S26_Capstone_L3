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
