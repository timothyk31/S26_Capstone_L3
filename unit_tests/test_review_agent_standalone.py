"""
Standalone test for the Review Agent using mock input (no Triage/Remedy agents).
Run: python test_review_agent_standalone.py
Requires: .env with OPENROUTER_API_KEY (and optionally OPENROUTER_BASE_URL, REVIEW_AGENT_MODEL).
"""

import os
import sys

# Ensure project root is on path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from dotenv import load_dotenv

load_dotenv()

from schemas import (
    RemediationAttempt,
    ReviewInput,
    RunCommandResult,
    TriageDecision,
    ToolVerdict,
    Vulnerability,
)
from agents.review_agent import ReviewAgent


def make_mock_review_input() -> ReviewInput:
    """Build a minimal ReviewInput so we can test the Review Agent without other agents."""
    vuln = Vulnerability(
        id="xccdf_org.open-scap_rule_openscap_001",
        title="Ensure SSH MaxAuthTries is set correctly",
        severity="medium",
        host="192.168.1.10",
        description="SSH MaxAuthTries should be 4 or less to limit brute force.",
        recommendation="Set MaxAuthTries 4 in /etc/ssh/sshd_config and restart sshd.",
    )
    triage = TriageDecision(
        finding_id=vuln.id,
        should_remediate=True,
        risk_level="medium",
        reason="SSH hardening is recommended for exposed hosts.",
    )
    attempt = RemediationAttempt(
        finding_id=vuln.id,
        attempt_number=1,
        commands_executed=[
            "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config",
            "systemctl restart sshd",
        ],
        execution_details=[
            RunCommandResult(
                command="sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config",
                stdout="",
                stderr="",
                exit_code=0,
                success=True,
                duration=0.1,
            ),
            RunCommandResult(
                command="systemctl restart sshd",
                stdout="",
                stderr="",
                exit_code=0,
                success=True,
                duration=0.5,
            ),
        ],
        scan_passed=True,
        success=True,
        duration=2.0,
        llm_verdict=ToolVerdict(message="MaxAuthTries set and sshd restarted.", resolved=True),
    )
    return ReviewInput(vulnerability=vuln, remediation_attempt=attempt, triage_decision=triage)


def main() -> None:
    if not os.getenv("OPENROUTER_API_KEY"):
        print("ERROR: OPENROUTER_API_KEY not set. Add it to .env and try again.")
        sys.exit(1)
    print("Building mock ReviewInput (no other agents)...")
    input_data = make_mock_review_input()
    print("Running ReviewAgent.process()...")
    agent = ReviewAgent()
    verdict = agent.process(input_data)
    print("ReviewVerdict:")
    print(f"  finding_id: {verdict.finding_id}")
    print(f"  approve: {verdict.approve}")
    print(f"  is_optimal: {verdict.is_optimal}")
    print(f"  best_practices_followed: {verdict.best_practices_followed}")
    print(f"  security_score: {verdict.security_score}")
    print(f"  feedback: {verdict.feedback}")
    print(f"  concerns: {verdict.concerns}")
    print(f"  suggested_improvements: {verdict.suggested_improvements}")
    print("Done.")


if __name__ == "__main__":
    main()
