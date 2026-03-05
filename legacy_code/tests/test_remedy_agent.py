#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from dotenv import load_dotenv

from openscap_cli import OpenSCAPScanner
from helpers.scanner import Scanner
from helpers.command_executor import ShellCommandExecutor
from agents.remedy_agent import RemedyAgent

from schemas import Vulnerability, RemedyInput, TriageDecision

# --- Fix forward refs (Pydantic v2) ---
try:
    RemedyInput.model_rebuild()
except Exception:
    # Pydantic v1 fallback
    try:
        RemedyInput.update_forward_refs()
    except Exception:
        pass


def pretty(obj) -> str:
    if hasattr(obj, "model_dump"):
        obj = obj.model_dump()
    return json.dumps(obj, indent=2, default=str)


def main():
    load_dotenv()

    p = argparse.ArgumentParser(description="Standalone RemedyAgent demo (single attempt)")
    p.add_argument("--host", required=True)
    p.add_argument("--user", default="root")
    p.add_argument("--key", help="SSH private key path")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--sudo-password", help="Sudo password if needed (non-root user)")
    p.add_argument("--profile", required=True)
    p.add_argument("--datastream", required=True)
    p.add_argument("--work-dir", default="work_remedy_demo")
    p.add_argument("--attempt", type=int, default=1)

    # Demo vuln fields (simple manual input)
    p.add_argument("--finding-id", default="openscap_demo_001")
    p.add_argument("--title", default="xccdf_org.ssgproject.content_rule_sshd_disable_root_login")
    p.add_argument("--severity", default="3")
    p.add_argument("--description", default="Disable direct root login over SSH.")
    p.add_argument("--recommendation", default="Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd.")

    args = p.parse_args()

    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    # --- Build scanning stack ---
    openscap = OpenSCAPScanner(
        target_host=args.host,
        ssh_user=args.user,
        ssh_key=args.key,
        ssh_port=args.port,
    )

    scanner = Scanner(
        openscap_scanner=openscap,
        profile=args.profile,
        datastream=args.datastream,
        sudo_password=args.sudo_password,
        work_dir=str(work_dir / "scans"),
    )

    # --- Build executor ---
    executor = ShellCommandExecutor(
        host=args.host,
        user=args.user,
        key=args.key,
        port=args.port,
        sudo_password=args.sudo_password,
        command_timeout=120,
        max_output_chars=8000,
    )

    # --- Build agent ---
    agent = RemedyAgent(
        executor=executor,
        scanner=scanner,
        work_dir=work_dir / "remedy_logs",
        max_tool_iterations=24,
        request_timeout=90,
    )

    # --- Create RemedyInput ---
    vuln = Vulnerability(
        id=args.finding_id,
        title=args.title,
        severity=args.severity,
        host=args.host,
        description=args.description,
        recommendation=args.recommendation,
    )

    triage = TriageDecision(
        finding_id=vuln.id,
        should_remediate=True,
        risk_level="low",
        reason="Standalone RemedyAgent demo",
        requires_human_review=False,
        estimated_impact=None,
    )

    remedy_input = RemedyInput(
        vulnerability=vuln,
        triage_decision=triage,
        attempt_number=args.attempt,
        previous_attempts=[],
        review_feedback=None,
    )

    print("\n==================== RemedyInput ====================")
    print(pretty(remedy_input))

    print("\n==================== Running RemedyAgent ====================")
    attempt = agent.process(remedy_input)

    print("\n==================== RemediationAttempt ====================")
    print(pretty(attempt))

    print("\nArtifacts:")
    print(f"- prompts/transcripts: {work_dir}/remedy_logs/")
    print(f"- scans:              {work_dir}/scans/")


if __name__ == "__main__":
    main()
