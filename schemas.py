from typing import List, Optional
from pydantic import BaseModel

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
    proposed_commands: List[str]
    notes: str
