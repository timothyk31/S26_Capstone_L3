#!/usr/bin/env python3
"""
main_multiagent.py — Full multi-agent remediation pipeline (V2, per-finding verification).

Scans a target VM with OpenSCAP, then runs every finding through:
  Triage → Remedy (plan → Review+QA → apply fix) → Single-rule scan

Each finding is verified immediately via single-rule scan after remediation.
Failed findings are retried up to --max-remedy-attempts times before moving on.

All findings are processed sequentially (no parallelism) to avoid race
conditions from concurrent SSH sessions modifying the same system.

Produces:
  - Aggregated JSON results
  - Text report

Usage examples:

  # Full pipeline from inventory file (scan + remediate)
  python main_multiagent.py --inventory inventory.yml

  # Explicit host, smart LLM
  python main_multiagent.py --host 10.244.72.95 --user root \\
         --key ~/.ssh/id_rsa --sudo-password SECRET \\
         --triage-mode smart

  # Skip scan, use existing parsed JSON
  python main_multiagent.py --skip-scan --parsed-json oscap_stig_rl9_parsed.json \\
         --host 10.244.72.95 --user root --key ~/.ssh/id_rsa

  # Limit to first 5 findings, severity >= 3
  python main_multiagent.py --inventory inventory.yml \\
         --max-vulns 5 --min-severity 3
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from dotenv import find_dotenv, load_dotenv
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from agents.qa_agent_v2 import QAAgentV2
from agents.remedy_agent import RemedyAgent
from agents.remedy_agent_v2 import RemedyAgentV2
from agents.review_agent import ReviewAgent
from agents.review_agent_v2 import ReviewAgentV2
from agents.triage_agent import TriageAgent
from helpers.agent_report_writer import _safe_dirname
from helpers.command_executor import ShellCommandExecutor
from helpers.scanner import Scanner
from openscap_cli import OpenSCAPScanner
from parse_openscap import parse_openscap
from braintrust_eval_writer import write_braintrust_eval
from context_pdf_writer import write_all_context_pdfs, _is_ssh_login_finding
from schemas import (
    RemediationAttempt,
    ReviewVerdict,
    TriageDecision,
    V2FindingResult,
    Vulnerability,
)
from worker_display import worker_display, worker_print
from workflow.pipeline_v2 import PipelineV2

load_dotenv(find_dotenv(), override=False)

console = Console()

# ── Defaults ────────────────────────────────────────────────────────────────
DEFAULT_PROFILE = "xccdf_org.ssgproject.content_profile_stig"
DEFAULT_DATASTREAM = "/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml"
DEFAULT_REMOTE_XML = "/tmp/oscap_stig_rl9.xml"
DEFAULT_LOCAL_XML = "oscap_stig_rl9.xml"
DEFAULT_PARSED_JSON = "oscap_stig_rl9_parsed.json"
DEFAULT_REMOTE_REPORT = "/tmp/oscap_report.html"
DEFAULT_LOCAL_REPORT = "oscap_stig_rl9_report.html"
DEFAULT_WORK_DIR = "./pipeline_work"
DEFAULT_REPORT_DIR = "./reports"


# ── Dependency grouping ───────────────────────────────────────────────────

def classify_finding_group(vuln: Vulnerability) -> str:
    """Map a vulnerability to a dependency group.

    Uses the XCCDF benchmark group from the scan report when available
    (e.g. "Verify Integrity with AIDE", "Federal Information Processing
    Standard (FIPS)").  These groups come from the XML and match the
    categories shown in the HTML report — findings in the same category
    typically touch the same subsystem and should run serially.

    Falls back to rule-name heuristics when the group field is missing
    (e.g. when using an older parsed JSON without group info).
    """
    # ── Prefer the XCCDF group from the scan report ──────────────
    if vuln.group:
        return vuln.group

    # ── Fallback: rule-name heuristics ───────────────────────────
    rule = vuln.rule or vuln.oval_id or vuln.id or ""
    rule = rule.replace("xccdf_org.ssgproject.content_rule_", "")

    if rule.startswith((
        "accounts_password_pam_", "accounts_passwords_pam_faillock_",
        "account_password_pam_", "no_empty_passwords",
    )):
        return "pam"
    if rule.startswith("sysctl_"):
        return "sysctl"
    if rule.startswith("mount_option_"):
        return "mount"
    if rule.startswith(("audit_rules_", "auditd_")):
        return "audit"
    if rule.startswith("selinux_"):
        return "selinux"
    if rule.startswith(("grub2_", "bootloader_")):
        return "grub"
    # Each unrecognized finding gets its own group
    return f"independent__{rule}"


def build_dependency_groups(
    vulns: List[Vulnerability],
) -> OrderedDict[str, List[Vulnerability]]:
    """Group vulnerabilities by shared resource.  Preserves original order."""
    groups: OrderedDict[str, List[Vulnerability]] = OrderedDict()
    for v in vulns:
        g = classify_finding_group(v)
        groups.setdefault(g, []).append(v)
    return groups



# ── Inventory loader ───────────────────────────────────────────────────────

def load_inventory(path: str) -> Dict:
    """Pull the first host from an Ansible-style inventory.yml."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    hosts = raw.get("all", {}).get("hosts", {})
    if not hosts:
        raise SystemExit(f"No hosts found in {path}")
    name, cfg = next(iter(hosts.items()))
    console.print(f"[cyan]Loaded host [bold]{name}[/bold] from {path}[/cyan]")
    return {
        "host": cfg.get("ansible_host", name),
        "user": cfg.get("ansible_user", "root"),
        "key": cfg.get("ansible_ssh_private_key_file"),
        "port": cfg.get("ansible_port", 22),
        "sudo_password": cfg.get("ansible_become_password"),
    }


# ── Scanning ───────────────────────────────────────────────────────────────

def run_scan(
    host: str,
    user: str,
    key: Optional[str],
    port: int,
    sudo_password: Optional[str],
    profile: str,
    datastream: str,
    remote_xml: str,
    local_xml: str,
    remote_report: str,
    local_report: str,
) -> bool:
    """Run OpenSCAP on the target VM and download the XML results."""
    scanner = OpenSCAPScanner(
        target_host=host,
        ssh_user=user,
        ssh_key=key,
        ssh_port=port,
    )
    console.print(f"\n[bold cyan]── OpenSCAP scan on {host} ──[/bold cyan]")
    ok = scanner.run_scan(
        profile=profile,
        output_file=remote_xml,
        datastream=datastream,
        report_file=remote_report,
        sudo_password=sudo_password,
    )
    if not ok:
        console.print("[red]Scan failed.[/red]")
        return False

    if not scanner.download_results(remote_xml, local_xml):
        return False

    scanner.download_results(remote_report, local_report)
    return True


# ── Parsing ────────────────────────────────────────────────────────────────

def load_vulnerabilities(
    xml_path: str,
    parsed_json_path: str,
    host_fallback: str = "unknown",
) -> List[Vulnerability]:
    """Parse the XML into JSON, then load as Vulnerability models."""
    parse_openscap(xml_path, parsed_json_path)

    try:
        raw = json.loads(Path(parsed_json_path).read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[red]Failed to read parsed JSON: {exc}[/red]")
        return []

    vulns: List[Vulnerability] = []
    for entry in raw:
        try:
            vulns.append(
                Vulnerability(
                    id=entry["id"],
                    title=entry["title"],
                    severity=entry.get("severity", "0"),
                    host=entry.get("host", host_fallback),
                    description=entry.get("description"),
                    recommendation=entry.get("recommendation"),
                    result=entry.get("result"),
                    rule=entry.get("rule"),
                    oval_id=entry.get("oval_id"),
                    scan_class=entry.get("class"),
                    os=entry.get("os"),
                    group=entry.get("group"),
                )
            )
        except (ValidationError, KeyError) as exc:
            console.print(f"[yellow]Skipping malformed finding: {exc}[/yellow]")
    return vulns


# ── Report writing ─────────────────────────────────────────────────────────


def build_report_dir(base_dir: Path, model_name: str) -> Path:
    """Create and return a timestamped report subdirectory: <base>/<model>_<YYYYMMDD_HHMMSS>/."""
    safe_name = re.sub(r'[/\\:*?"<>|]', "_", model_name)
    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = base_dir / f"{safe_name}_{run_ts}"
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


def write_results_and_text_report(
    *,
    report_dir: Path,
    results: List[V2FindingResult],
    fixed_at_round: Dict[int, List[str]],
    max_rounds: int,
    host: str,
    profile: str,
) -> Path:
    """Write v2_aggregated_results.json and v2_pipeline_report.txt into report_dir.

    Returns the path to the text report.
    """
    # ── JSON ──
    json_path = report_dir / "v2_aggregated_results.json"
    json_path.write_text(
        json.dumps(
            [r.model_dump(mode="json") for r in results],
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    console.print(f"\n[green]Results JSON: {json_path}[/green]")

    # ── Text report ──
    text_lines: List[str] = []
    ts = datetime.now().isoformat(timespec="seconds")
    text_lines.append("Multi-Agent Pipeline V2 Report")
    text_lines.append(f"Generated: {ts}")
    text_lines.append(f"Target Host: {host}")
    text_lines.append(f"Scan Profile: {profile}")
    text_lines.append("=" * 80)
    text_lines.append("")

    success_count = sum(1 for r in results if r.final_status == "success")
    attempted_failed_count = sum(1 for r in results if r.final_status in ("failed", "pending_scan"))
    discarded_count = sum(1 for r in results if r.final_status == "discarded")
    human_count = sum(1 for r in results if r.final_status == "requires_human_review")
    total_failed = attempted_failed_count + discarded_count + human_count
    attempted_count = success_count + attempted_failed_count
    overall_rate = (success_count / len(results) * 100) if results else 0.0
    attempted_rate = (success_count / attempted_count * 100) if attempted_count else 0.0

    text_lines.append(f"Findings processed:              {len(results)}")
    text_lines.append(f"Successful:                      {success_count}")
    text_lines.append(f"Total failed:                    {total_failed}")
    text_lines.append(f"  Attempted but failed:          {attempted_failed_count}")
    text_lines.append(f"  Failed due to discard:         {discarded_count}")
    text_lines.append(f"  Failed due to human review:    {human_count}")
    text_lines.append(f"Success rate (overall):          {overall_rate:.1f}%")
    text_lines.append(f"Success rate (attempted only):   {attempted_rate:.1f}%")
    text_lines.append("")
    for rnd in range(1, max_rounds + 1):
        count = len(fixed_at_round.get(rnd, []))
        text_lines.append(f"Fixed at attempt {rnd}:            {count}")
    text_lines.append("")
    text_lines.append("=" * 80)

    for i, r in enumerate(results, 1):
        v = r.vulnerability
        status_icon = {
            "success": "[OK]", "failed": "[FAIL]",
            "discarded": "[SKIP]", "requires_human_review": "[REVIEW]",
        }.get(r.final_status, "[?]")
        text_lines.append("")
        text_lines.append(f"{i}. {status_icon} {v.id} - {v.title}")
        text_lines.append(f"   Severity: {v.severity}  |  Host: {v.host}")
        text_lines.append(f"   Triage: risk={r.triage.risk_level}, remediate={r.triage.should_remediate}")

        if r.remediation:
            rm = r.remediation
            text_lines.append(
                f"   Remedy: attempt #{rm.attempt_number}, scan_passed={rm.scan_passed}, "
                f"cmds={len(rm.commands_executed)}, duration={rm.attempt_duration:.1f}s"
            )
            for cmd in rm.commands_executed:
                text_lines.append(f"     - {cmd}")
            if rm.error_summary:
                text_lines.append(f"   Error: {rm.error_summary}")

        if r.pre_approval:
            pa = r.pre_approval
            rv = pa.review_verdict
            text_lines.append(
                f"   Review: approve={rv.approve}, optimal={rv.is_optimal}, "
                f"score={rv.security_score}"
            )
            if rv.feedback:
                text_lines.append(f"   Feedback: {rv.feedback}")
            if pa.qa_result:
                qa = pa.qa_result
                text_lines.append(
                    f"   QA: safe={qa.safe}, recommendation={qa.recommendation}"
                )
            if not pa.approved and pa.rejection_reason:
                text_lines.append(f"   Rejection: {pa.rejection_reason}")

        text_lines.append(f"   Final: {r.final_status}  |  Duration: {r.total_duration:.1f}s")
        text_lines.append("-" * 80)

    text_report_path = report_dir / "v2_pipeline_report.txt"
    text_report_path.write_text("\n".join(text_lines), encoding="utf-8")
    console.print(f"[green]Text report: {text_report_path}[/green]")
    return text_report_path


# ── Summary table ──────────────────────────────────────────────────────────

def print_summary(
    results: List[V2FindingResult],
    elapsed: float,
    fixed_at_round: Optional[Dict[int, List[str]]] = None,
    max_rounds: int = 3,
) -> None:
    """Print a Rich summary table of pipeline results."""
    success = [r for r in results if r.final_status == "success"]
    attempted_failed = [r for r in results if r.final_status in ("failed", "pending_scan")]
    discarded = [r for r in results if r.final_status == "discarded"]
    review = [r for r in results if r.final_status == "requires_human_review"]
    total_failed = len(attempted_failed) + len(discarded) + len(review)
    attempted = len(success) + len(attempted_failed)

    table = Table(title="Pipeline V2 Results", show_lines=True)
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("%", justify="right")

    total = max(len(results), 1)
    table.add_row("Successful", str(len(success)),
                  f"{len(success)/total*100:.0f}%", style="green")
    table.add_row("Total failed", str(total_failed),
                  f"{total_failed/total*100:.0f}%", style="red")
    table.add_row("  Attempted but failed", str(len(attempted_failed)),
                  f"{len(attempted_failed)/total*100:.0f}%", style="red")
    table.add_row("  Failed due to discard", str(len(discarded)),
                  f"{len(discarded)/total*100:.0f}%", style="dim")
    table.add_row("  Failed due to human review", str(len(review)),
                  f"{len(review)/total*100:.0f}%", style="yellow")
    table.add_row("Total", str(len(results)), "100%", style="bold")

    # Success rates
    table.add_section()
    attempted_total = max(attempted, 1)
    table.add_row("Success rate (overall)", "",
                  f"{len(success)/total*100:.1f}%", style="bold")
    table.add_row("Success rate (attempted)", "",
                  f"{len(success)/attempted_total*100:.1f}%", style="bold")

    # Per-attempt breakdown
    table.add_section()
    for rnd in range(1, max_rounds + 1):
        count = len(fixed_at_round.get(rnd, []))
        table.add_row(
            f"Fixed at attempt {rnd}", str(count),
            f"{count/total*100:.0f}%", style="green" if count else "dim",
        )

    console.print()
    console.print(table)
    console.print(f"\n[dim]Completed in {elapsed:.1f}s[/dim]")


# ── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Multi-agent OpenSCAP remediation pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main_multiagent.py --inventory inventory.yml\n"
            "  python main_multiagent.py --host 10.244.72.95 --user root --key ~/.ssh/id_rsa\n"
            "  python main_multiagent.py --skip-scan --parsed-json oscap_stig_rl9_parsed.json --host myvm --user root --key ~/.ssh/id_rsa\n"
        ),
    )

    # ── Target ───
    target = p.add_argument_group("Target host (or use --inventory)")
    target.add_argument("--host", help="Target host IP / hostname")
    target.add_argument("--user", default="root", help="SSH user (default: root)")
    target.add_argument("--key", help="SSH private key path")
    target.add_argument("--port", type=int, default=22)
    target.add_argument("--sudo-password", help="Sudo password on target")
    target.add_argument("--inventory", help="Ansible inventory.yml (reads first host)")

    # ── Scan ───
    scan_g = p.add_argument_group("Scan options")
    scan_g.add_argument("--profile", default=DEFAULT_PROFILE)
    scan_g.add_argument("--datastream", default=DEFAULT_DATASTREAM)
    scan_g.add_argument("--remote-xml", default=DEFAULT_REMOTE_XML)
    scan_g.add_argument("--local-xml", default=DEFAULT_LOCAL_XML)
    scan_g.add_argument("--parsed-json", default=DEFAULT_PARSED_JSON)
    scan_g.add_argument("--remote-report", default=DEFAULT_REMOTE_REPORT)
    scan_g.add_argument("--local-report", default=DEFAULT_LOCAL_REPORT)
    scan_g.add_argument("--skip-scan", action="store_true",
                        help="Skip the SSH scan; use --local-xml or --parsed-json.")

    # ── Pipeline ───
    pipe_g = p.add_argument_group("Pipeline options")
    pipe_g.add_argument("--min-severity", type=int, default=2, choices=range(5), metavar="0-4",
                        help="Minimum severity to process (default: 2)")
    pipe_g.add_argument("--max-vulns", type=int, default=None,
                        help="Cap the number of vulnerabilities to process")
    pipe_g.add_argument("--max-remedy-attempts", type=int, default=3,
                        help="Max remedy retries per finding (default: 3)")

    # ── Agents ───
    agent_g = p.add_argument_group("Agent options")
    agent_g.add_argument("--triage-mode", choices=["fast", "balanced", "smart"],
                         default="balanced", help="Triage LLM quality tier")
    agent_g.add_argument("--review-model", default=None,
                         help="Override the Review agent LLM model (default: env REVIEW_AGENT_MODEL)")
    agent_g.add_argument("--lenient-triage", action="store_true", default=False,
                         help="Use lenient triage: prefer safe_to_remediate over "
                              "requires_human_review when uncertain (useful for benchmarking)")
    agent_g.add_argument("--max-complexity", choices=["low", "medium", "high"],
                         default="medium",
                         help="Max remediation complexity to attempt automatically. "
                              "Findings above this threshold are sent to human review. "
                              "(default: high — no extra filtering)")

    # ── Parallelism ───
    pipe_g.add_argument("--max-parallel-groups", type=int, default=4,
                        help="Max dependency groups to remediate in parallel (default: 4). "
                             "Controls concurrent SSH load on the target host.")

    # ── Output ───
    out = p.add_argument_group("Output")
    out.add_argument("--work-dir", default=DEFAULT_WORK_DIR,
                     help="Working directory for intermediate artifacts")
    out.add_argument("--report-dir", default=DEFAULT_REPORT_DIR,
                     help="Output directory for reports and playbook")

    # ── Braintrust ───
    bt = p.add_argument_group("Braintrust")
    bt.add_argument("--experiment-name", default=None,
                    help="Braintrust experiment name (default: auto-generated from model names + timestamp)")

    return p.parse_args()


# ── Parallel helpers ────────────────────────────────────────────────────────


def _create_pipeline_instance(
    executor: ShellCommandExecutor,
    scanner: Scanner,
    args: argparse.Namespace,
    work_dir: Path,
    transcript_dir: Path,
    agent_report_dir: Path,
    run_id: str,
) -> PipelineV2:
    """Create an independent PipelineV2 with its own agent instances (thread-safe)."""
    ta = TriageAgent(
        mode=args.triage_mode, lenient=args.lenient_triage,
        transcript_dir=transcript_dir / "triage",
        max_complexity=args.max_complexity,
    )
    ra = RemedyAgent(
        executor=executor, scanner=scanner,
        work_dir=work_dir / "remedy",
    )
    rev = ReviewAgent(model=args.review_model, transcript_dir=transcript_dir / "review")
    qa = QAAgentV2(transcript_dir=transcript_dir / "qa")
    rev_v2 = ReviewAgentV2(review_agent=rev, qa_agent=qa)
    rem_v2 = RemedyAgentV2(remedy_agent=ra, review_agent_v2=rev_v2)
    return PipelineV2(
        triage_agent=ta, remedy_agent_v2=rem_v2,
        report_dir=agent_report_dir, run_id=run_id,
    )


# ── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()
    t0 = time.time()
    run_id = datetime.now().strftime("run_%Y%m%d_%H%M%S")

    console.print(Panel.fit(
        "[bold cyan]Multi-Agent Remediation Pipeline V2[/bold cyan]\n"
        "Triage → Remedy (fix → Review+QA approval → scan)",
        border_style="cyan",
    ))

    # ── Resolve host config ───────────────────────────────────────────
    if args.inventory:
        inv = load_inventory(args.inventory)
        host = inv["host"]
        user = inv["user"]
        key = inv["key"]
        port = inv["port"]
        sudo_password = inv["sudo_password"]
    else:
        host = args.host
        user = args.user
        key = args.key
        port = args.port
        sudo_password = args.sudo_password

    if not host and not args.skip_scan:
        console.print("[red]ERROR: --host or --inventory required (unless --skip-scan).[/red]")
        return 1

    # ── Scan ──────────────────────────────────────────────────────────
    if not args.skip_scan:
        initial_scan_t0 = time.time()
        if not run_scan(
            host=host, user=user, key=key, port=port,
            sudo_password=sudo_password,
            profile=args.profile, datastream=args.datastream,
            remote_xml=args.remote_xml, local_xml=args.local_xml,
            remote_report=args.remote_report, local_report=args.local_report,
        ):
            return 1
        console.print(f"[cyan]Initial scan completed in {time.time() - initial_scan_t0:.1f}s[/cyan]")

    # ── Parse findings ────────────────────────────────────────────────
    parsed_json = args.parsed_json

    if args.skip_scan and Path(parsed_json).exists():
        console.print(f"[cyan]Using existing parsed JSON: {parsed_json}[/cyan]")
        raw = json.loads(Path(parsed_json).read_text(encoding="utf-8"))
        vulns: List[Vulnerability] = []
        for entry in raw:
            try:
                vulns.append(Vulnerability(
                    id=entry["id"], title=entry["title"],
                    severity=entry.get("severity", "0"),
                    host=entry.get("host", host or "unknown"),
                    description=entry.get("description"),
                    recommendation=entry.get("recommendation"),
                    result=entry.get("result"), rule=entry.get("rule"),
                    oval_id=entry.get("oval_id"),
                    scan_class=entry.get("class"), os=entry.get("os"),
                    group=entry.get("group"),
                ))
            except (ValidationError, KeyError):
                continue
    elif args.skip_scan and Path(args.local_xml).exists():
        console.print(f"[cyan]Parsing existing XML: {args.local_xml}[/cyan]")
        vulns = load_vulnerabilities(args.local_xml, parsed_json, host or "unknown")
    elif args.skip_scan:
        console.print("[red]--skip-scan set but no parsed JSON or local XML found.[/red]")
        return 1
    else:
        vulns = load_vulnerabilities(args.local_xml, parsed_json, host)

    if not vulns:
        console.print("[yellow]No findings to process.[/yellow]")
        return 0

    # ── Filter ────────────────────────────────────────────────────────
    # Rule-name based skip set (stable across scans, unlike positional IDs)
    SKIP_RULE_IDS = {
        "accounts_passwords_pam_faillock_audit",
        # SSH-related findings — remediation can break the active SSH session
        "sshd_use_approved_macs_ordered_stig",     # Configure SSH Server to Use FIPS 140-2 Validated MACs
        "sshd_approved_macs",                       # Configure SSH Client to Use FIPS 140-2 Validated MACs
        "file_permissions_sshd_config",             # Verify Permissions on SSH Server Config File
        "sshd_set_keepalive",                       # Set SSH Client Alive Count Max
        "sshd_set_idle_timeout",                    # Set SSH Client Alive Interval
        "sshd_disable_empty_passwords",             # Disable SSH Access via Empty Passwords
        "sshd_disable_root_login",                  # Disable SSH Root Login
        "sshd_disable_x11_forwarding",              # Disable X11 Forwarding
        "sshd_enable_warning_banner",               # Enable SSH Warning Banner
        # Sudo/sudoers-related findings - remediation can break privileged access
        "selinux_context_elevation_for_sudo",       # Writes sudoers.d SELinux context rules
        "sudoers_validate_passwd",                  # Tightens sudoers Defaults policy
        "sudo_require_reauthentication",            # Changes sudo session/authentication behavior
    }
    filtered: List[Vulnerability] = []
    ssh_skipped = 0
    manual_skipped = 0
    for v in vulns:
        # Skip SSH root login findings (would lock us out of the VM)
        if _is_ssh_login_finding(v.title, v.rule, v.oval_id):
            ssh_skipped += 1
            continue
        if v.id in SKIP_RULE_IDS:
            manual_skipped += 1
            continue
        try:
            sev = int(v.severity)
        except (ValueError, TypeError):
            sev = 0
        if sev >= args.min_severity:
            filtered.append(v)

    if ssh_skipped:
        console.print(
            f"[yellow]Skipped {ssh_skipped} SSH root-login finding(s) "
            f"(would lock out remote access).[/yellow]"
        )
    if manual_skipped:
        console.print(
            f"[yellow]Skipped {manual_skipped} manually excluded finding(s): "
            f"{', '.join(sorted(SKIP_RULE_IDS))}[/yellow]"
        )

    if not filtered:
        console.print("[yellow]No findings meet the minimum severity threshold.[/yellow]")
        return 0

    if args.max_vulns and len(filtered) > args.max_vulns:
        filtered = filtered[: args.max_vulns]
        console.print(f"[yellow]Limiting to first {args.max_vulns} findings.[/yellow]")

    console.print(
        f"[green]Loaded {len(vulns)} findings, processing {len(filtered)} "
        f"(severity >= {args.min_severity}).[/green]"
    )

    # ── Initialize shared services ────────────────────────────────────
    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    executor = ShellCommandExecutor(
        host=host or "localhost",
        user=user,
        key=key,
        port=port,
        sudo_password=sudo_password,
    )

    openscap_scanner = OpenSCAPScanner(
        target_host=host or "localhost",
        ssh_user=user,
        ssh_key=key,
        ssh_port=port,
    )

    scanner = Scanner(
        openscap_scanner=openscap_scanner,
        profile=args.profile,
        datastream=args.datastream,
        sudo_password=sudo_password,
        work_dir=str(work_dir / "scans"),
    )

    # ── Initialize shared dirs ─────────────────────────────────────
    transcript_dir = work_dir / "transcripts"
    transcript_dir.mkdir(parents=True, exist_ok=True)
    agent_report_dir = Path(args.work_dir) / "agent_reports"

    # Keep one "reference" agent set for model-label extraction in reports
    triage_agent = TriageAgent(
        mode=args.triage_mode, lenient=args.lenient_triage,
        transcript_dir=transcript_dir / "triage",
        max_complexity=args.max_complexity,
    )
    remedy_agent = RemedyAgent(
        executor=executor, scanner=scanner,
        work_dir=work_dir / "remedy",
    )
    review_agent = ReviewAgent(
        model=args.review_model, transcript_dir=transcript_dir / "review",
    )
    qa_agent_v2 = QAAgentV2(transcript_dir=transcript_dir / "qa")

    # ── Per-finding scan + retry loop helpers ────────────────────
    total = len(filtered)
    max_rounds = args.max_remedy_attempts

    def _scan_and_update(
        scanner_: "Scanner",
        vuln_: Vulnerability,
        result_: V2FindingResult,
    ) -> tuple:
        """Run single-rule scan and update the result with scan fields."""
        scan_t0_ = time.time()
        is_fixed_, scan_output_ = scanner_.scan_single_rule(vuln_)
        scan_dur_ = round(time.time() - scan_t0_, 3)
        result_.remediation.scan_passed = is_fixed_
        result_.remediation.scan_output = scan_output_
        result_.remediation.scan_duration = scan_dur_
        result_.remediation.success = is_fixed_
        updated_ = result_.model_copy(
            update={"final_status": "success" if is_fixed_ else "failed"}
        )
        return updated_, is_fixed_, scan_dur_

    # ────────────────────────────────────────────────────────────────
    # Phase A: Build dependency groups
    # ────────────────────────────────────────────────────────────────
    groups = build_dependency_groups(filtered)
    console.print(
        f"\n[bold cyan]── Phase 1: Dependency groups "
        f"({len(groups)} groups from {total} findings) ──[/bold cyan]"
    )
    for gname, gvulns in groups.items():
        console.print(f"  {gname}: {len(gvulns)} finding(s)")

    # ────────────────────────────────────────────────────────────────
    # Phase B: Parallel group execution (triage runs inline per-finding)
    # ────────────────────────────────────────────────────────────────
    console.print(
        f"\n[bold cyan]── Phase 2: Triage + Remediate "
        f"(max {args.max_parallel_groups} groups in parallel, "
        f"up to {max_rounds} attempts each) ──[/bold cyan]\n"
    )

    # Thread-safe result collection
    results_lock = threading.Lock()
    all_group_results: List[V2FindingResult] = []
    fixed_at_round: Dict[int, List[str]] = {}

    def _process_group(
        group_name: str,
        group_vulns: List[Vulnerability],
        pip: PipelineV2,
    ) -> None:
        """Process all findings in one dependency group serially."""
        worker_display.assign_worker(group_name, num_findings=len(group_vulns))
        tag = f"[dim]\\[{group_name}][/dim] "
        for vuln in group_vulns:
            attempts: List[RemediationAttempt] = []
            triage_decision: TriageDecision | None = None
            review_feedback: str | None = None
            review_verdicts: List[ReviewVerdict] = []
            result: V2FindingResult | None = None

            for attempt_num in range(1, max_rounds + 1):
                try:
                    result = pip.run(
                        vuln,
                        triage_decision=triage_decision if attempt_num > 1 else None,
                        attempt_number=attempt_num,
                        previous_attempts=attempts,
                        review_feedback=review_feedback,
                        previous_review_verdicts=review_verdicts,
                        group_label=group_name,
                    )
                except Exception as exc:
                    worker_print(f"{tag}[red]  x Pipeline error:[/red] {vuln.id} — {exc}")
                    result = V2FindingResult(
                        vulnerability=vuln,
                        triage=triage_decision or TriageDecision(
                            finding_id=vuln.id,
                            should_remediate=False,
                            risk_level="medium",
                            reason=f"Pipeline error: {exc}",
                            requires_human_review=True,
                        ),
                        final_status="failed",
                        total_duration=0.0,
                        timestamp=datetime.now().isoformat(timespec="seconds"),
                    )
                    break

                # Save triage for reuse in retries
                triage_decision = result.triage

                if result.final_status in ("discarded", "requires_human_review"):
                    break

                if result.remediation is not None and result.final_status == "pending_scan":
                    if result.pre_approval:
                        review_verdicts.append(result.pre_approval.review_verdict)
                        if not result.pre_approval.approved:
                            review_feedback = result.pre_approval.rejection_reason
                        else:
                            review_feedback = None

                    if result.pre_approval and not result.pre_approval.approved:
                        result = result.model_copy(update={"final_status": "failed"})
                        attempts.append(result.remediation)
                        reason = result.pre_approval.rejection_reason or "review/QA rejected"
                        worker_print(
                            f"{tag}[yellow]  x Rejected[/yellow]  {vuln.id}  "
                            f"[dim]attempt {attempt_num} | {reason}[/dim]"
                        )
                        out_dir = agent_report_dir / "remedy_v2" / run_id / _safe_dirname(vuln.id)
                        out_path = out_dir / f"attempt_{attempt_num}_output.json"
                        if out_dir.exists():
                            out_path.write_text(
                                json.dumps(result.remediation.model_dump(mode="json"),
                                           indent=2, default=str),
                                encoding="utf-8",
                            )
                        continue

                    result, is_fixed, scan_dur = _scan_and_update(scanner, vuln, result)
                    attempts.append(result.remediation)

                    if is_fixed:
                        worker_print(
                            f"{tag}[bold green]  + PASS[/bold green]  {vuln.id}  "
                            f"[dim]attempt {attempt_num} | scan {scan_dur:.1f}s[/dim]"
                        )
                    else:
                        worker_print(
                            f"{tag}[red]  - FAIL[/red]  {vuln.id}  "
                            f"[dim]attempt {attempt_num} | scan {scan_dur:.1f}s[/dim]"
                        )

                    out_dir = agent_report_dir / "remedy_v2" / run_id / _safe_dirname(vuln.id)
                    out_path = out_dir / f"attempt_{attempt_num}_output.json"
                    if out_dir.exists():
                        out_path.write_text(
                            json.dumps(result.remediation.model_dump(mode="json"),
                                       indent=2, default=str),
                            encoding="utf-8",
                        )

                    if is_fixed:
                        with results_lock:
                            fixed_at_round.setdefault(attempt_num, []).append(vuln.id)
                        break
                else:
                    break

            with results_lock:
                all_group_results.append(result)
            worker_display.advance()

    # Launch groups in parallel — ThreadPoolExecutor naturally balances work
    max_workers = min(len(groups), args.max_parallel_groups)
    worker_display.start(num_workers=max_workers, total_findings=total)
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {}
            for gname, gvulns in groups.items():
                pip = _create_pipeline_instance(
                    executor, scanner, args, work_dir,
                    transcript_dir, agent_report_dir, run_id,
                )
                fut = pool.submit(
                    _process_group, gname, gvulns, pip,
                )
                futures[fut] = gname

            for fut in as_completed(futures):
                gname = futures[fut]
                try:
                    fut.result()
                except Exception as exc:
                    worker_print(f"[red]  x Group failed:[/red] {gname} — {exc}")
    finally:
        worker_display.stop()

    # Combine and re-sort results to original finding order
    results: List[V2FindingResult] = list(all_group_results)
    vuln_order = {v.id: i for i, v in enumerate(filtered)}
    results.sort(key=lambda r: vuln_order.get(r.vulnerability.id, float("inf")))

    # ── Save results JSON + text report ──────────────────────────────
    model_label = getattr(remedy_agent, "model_name", "unknown")
    report_dir = build_report_dir(Path(args.report_dir), model_label)
    write_results_and_text_report(
        report_dir=report_dir,
        results=results,
        fixed_at_round=fixed_at_round,
        max_rounds=max_rounds,
        host=host or "unknown",
        profile=args.profile,
    )

    # ── Triage PDF ────────────────────────────────────────────────────
    try:
        triage_decisions = [r.triage for r in results]
        triage_vulns = [r.vulnerability for r in results]
        triage_agent.write_results_pdf(
            triage_decisions,
            output_path=report_dir / "triage_report.pdf",
            target_host=host or "unknown",
            vulnerabilities=triage_vulns,
        )
        console.print(f"[green]Triage PDF: {report_dir / 'triage_report.pdf'}[/green]")
    except Exception as exc:
        console.print(f"[yellow]Triage PDF skipped: {exc}[/yellow]")

    # ── Pipeline PDF (full summary) ───────────────────────────────────
    try:
        from pipeline_pdf_writer import write_pipeline_pdf

        pipeline_model_meta = {
            "triage": getattr(triage_agent, "model", "unknown"),
            "remedy": getattr(remedy_agent, "model_name", "unknown"),
            "review": getattr(review_agent, "model", "unknown"),
            "qa":     getattr(qa_agent_v2, "model", "unknown"),
        }

        write_pipeline_pdf(
            results,
            output_path=report_dir / "pipeline_report.pdf",
            target_host=host or "unknown",
            model_metadata=pipeline_model_meta,
        )
        console.print(f"[green]Pipeline PDF: {report_dir / 'pipeline_report.pdf'}[/green]")
    except Exception as exc:
        console.print(f"[yellow]Pipeline PDF skipped: {exc}[/yellow]")

    # ── Summary ───────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print_summary(results, elapsed, fixed_at_round=fixed_at_round, max_rounds=max_rounds)

    # ── Collect model metadata (shared by Braintrust + CSV) ────────────
    model_metadata = {
        "triage": getattr(triage_agent, "model", "unknown"),
        "remedy": getattr(remedy_agent, "model_name", "unknown"),
        "review": getattr(review_agent, "model", "unknown"),
        "qa":     getattr(qa_agent_v2, "model", "unknown"),
    }

    # ── Braintrust experiment ─────────────────────────────────────────
    try:
        from braintrust_eval_writer import write_braintrust_eval

        write_braintrust_eval(
            report_dir=str(report_dir),
            results=results,
            experiment_name=args.experiment_name,
            model_metadata=model_metadata,
        )
    except Exception as exc:
        console.print(f"[yellow]Braintrust eval skipped: {exc}[/yellow]")

    # ── CSV export ───────────────────────────────────────────────────────
    try:
        from csv_export import write_csv_report

        detail_csv, summary_csv = write_csv_report(
            results=results,
            report_dir=str(report_dir),
            fixed_at_round=fixed_at_round,
            elapsed=elapsed,
            model_metadata=model_metadata,
            max_rounds=max_rounds,
        )
        console.print(f"[green]Detail CSV:  {detail_csv}[/green]")
        console.print(f"[green]Summary CSV: {summary_csv}[/green]")
    except Exception as exc:
        console.print(f"[yellow]CSV export skipped: {exc}[/yellow]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
