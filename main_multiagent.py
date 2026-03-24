#!/usr/bin/env python3
"""
main_multiagent.py — Full multi-agent remediation pipeline (V2, batch-then-verify).

Scans a target VM with OpenSCAP, then runs every finding through:
  Triage → Remedy (plan → Review+QA → apply fix)

After each round of fixes, ONE full-profile scan verifies all findings.
Failures are retried up to --max-remedy-attempts rounds.

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
import sys
import time
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
from schemas import TriageDecision, V2FindingResult, Vulnerability
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
                )
            )
        except (ValidationError, KeyError) as exc:
            console.print(f"[yellow]Skipping malformed finding: {exc}[/yellow]")
    return vulns


# ── Summary table ──────────────────────────────────────────────────────────

def print_summary(
    results: List[V2FindingResult],
    elapsed: float,
    fixed_at_round: Optional[Dict[int, List[str]]] = None,
    max_rounds: int = 3,
) -> None:
    """Print a Rich summary table of pipeline results."""
    success = [r for r in results if r.final_status == "success"]
    failed = [r for r in results if r.final_status in ("failed", "pending_scan")]
    discarded = [r for r in results if r.final_status == "discarded"]
    review = [r for r in results if r.final_status == "requires_human_review"]

    table = Table(title="Pipeline V2 Results", show_lines=True)
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("%", justify="right")

    total = max(len(results), 1)
    table.add_row("Remediated (success)", str(len(success)),
                  f"{len(success)/total*100:.0f}%", style="green")
    table.add_row("Failed", str(len(failed)),
                  f"{len(failed)/total*100:.0f}%", style="red")
    table.add_row("Discarded (triage)", str(len(discarded)),
                  f"{len(discarded)/total*100:.0f}%", style="dim")
    table.add_row("Requires Human Review", str(len(review)),
                  f"{len(review)/total*100:.0f}%", style="yellow")
    table.add_row("Total", str(len(results)), "100%", style="bold")

    # Per-round breakdown
    if fixed_at_round:
        table.add_section()
        for rnd in range(1, max_rounds + 1):
            count = len(fixed_at_round.get(rnd, []))
            if count or rnd <= max(fixed_at_round.keys(), default=0):
                table.add_row(
                    f"Fixed at round {rnd}", str(count),
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

    # (Concurrency removed — sequential execution to avoid race conditions)

    # ── Output ───
    out = p.add_argument_group("Output")
    out.add_argument("--work-dir", default=DEFAULT_WORK_DIR,
                     help="Working directory for intermediate artifacts")
    out.add_argument("--report-dir", default=DEFAULT_REPORT_DIR,
                     help="Output directory for reports and playbook")

    # ── Braintrust ───
    bt = p.add_argument_group("Braintrust logging")
    bt.add_argument("--braintrust-name", default=None, metavar="NAME",
                    help="Log results to Braintrust under this experiment name. "
                         "Omit to skip Braintrust logging.")
    bt.add_argument("--braintrust-project", default="OpenSCAP-Remediation-Pipeline",
                    help="Braintrust project name (default: OpenSCAP-Remediation-Pipeline)")

    return p.parse_args()


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

    # ── Initialize agents (V2) ───────────────────────────────────────
    transcript_dir = work_dir / "transcripts"
    transcript_dir.mkdir(parents=True, exist_ok=True)

    triage_agent = TriageAgent(
        mode=args.triage_mode, lenient=args.lenient_triage,
        transcript_dir=transcript_dir / "triage",
        max_complexity=args.max_complexity,
    )

    remedy_agent = RemedyAgent(
        executor=executor,
        scanner=scanner,
        work_dir=work_dir / "remedy",
    )

    review_agent = ReviewAgent(
        model=args.review_model,
        transcript_dir=transcript_dir / "review",
    )

    qa_agent_v2 = QAAgentV2(
        transcript_dir=transcript_dir / "qa",
    )

    # V2 wrappers: Review wraps QA, Remedy wraps Review
    review_agent_v2 = ReviewAgentV2(
        review_agent=review_agent,
        qa_agent=qa_agent_v2,
    )

    remedy_agent_v2 = RemedyAgentV2(
        remedy_agent=remedy_agent,
        review_agent_v2=review_agent_v2,
    )

    # ── Pipeline ─────────────────────────────────────────────────────
    agent_report_dir = Path(args.work_dir) / "agent_reports"

    pipeline = PipelineV2(
        triage_agent=triage_agent,
        remedy_agent_v2=remedy_agent_v2,
        report_dir=agent_report_dir,
        run_id=run_id,
    )

    # ── Batch-then-verify loop ────────────────────────────────────
    results: List[V2FindingResult] = []
    total = len(filtered)
    max_rounds = args.max_remedy_attempts

    console.print(
        f"\n[bold cyan]── Running V2 pipeline for {total} finding(s) "
        f"(sequential, up to {max_rounds} rounds) ──[/bold cyan]\n"
    )

    # State tracker per finding
    state: Dict[str, dict] = {}
    fixed_at_round: Dict[int, List[str]] = {}  # round_num → [vid, ...]

    def _make_progress() -> Progress:
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        )

    # ── Round 1: Triage + first attempt (sequential, no scan) ─────
    console.print("[bold cyan]\n── Round 1: Triage + Remedy ──[/bold cyan]")
    with _make_progress() as progress:
        task = progress.add_task("Round 1: Triage + Remedy", total=total)
        for vuln in filtered:
            try:
                result = pipeline.run(vuln)
            except Exception as exc:
                console.print(f"[red]Pipeline error for {vuln.id}: {exc}[/red]")
                result = V2FindingResult(
                    vulnerability=vuln,
                    triage=TriageDecision(
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
            results.append(result)

            # Track state for findings that were actually remediated
            if result.remediation is not None and result.final_status == "pending_scan":
                state[vuln.id] = {
                    "vulnerability": vuln,
                    "triage": result.triage,
                    "attempts": [result.remediation],
                    "review_verdicts": (
                        [result.pre_approval.review_verdict]
                        if result.pre_approval else []
                    ),
                    "review_feedback": (
                        result.pre_approval.rejection_reason
                        if result.pre_approval and not result.pre_approval.approved
                        else None
                    ),
                    "approval": result.pre_approval,
                    "passed": False,
                    "result_index": len(results) - 1,
                }

            progress.advance(task)

    # ── Full scan after round 1 ──────────────────────────────────
    if state:
        console.print(
            f"\n[bold cyan]── Full-profile scan "
            f"({len(state)} findings remediated) ──[/bold cyan]"
        )
        try:
            scan_t0 = time.time()
            scan_findings = scanner.scan_full_profile()
            scan_duration = round(time.time() - scan_t0, 3)
            console.print(f"  Scan completed in {scan_duration:.1f}s")
            for vid, s in state.items():
                passed = Scanner.match_finding(s["vulnerability"], scan_findings)
                if passed and not s["passed"]:
                    fixed_at_round.setdefault(1, []).append(vid)
                s["passed"] = passed
                s["attempts"][-1].scan_passed = passed
                s["attempts"][-1].success = passed
                s["attempts"][-1].scan_duration = scan_duration
                # Update the result
                idx = s["result_index"]
                results[idx] = results[idx].model_copy(
                    update={
                        "final_status": "success" if passed else "failed",
                        "remediation": s["attempts"][-1],
                    }
                )
                status = "PASS" if passed else "FAIL"
                rule = s["vulnerability"].rule or vid
                console.print(f"  [{vid}] ({rule}) scan → {status}")
            # Re-write attempt JSONs with scan results
            for vid, s in state.items():
                attempt = s["attempts"][-1]
                out_dir = agent_report_dir / "remedy_v2" / run_id / _safe_dirname(vid)
                out_path = out_dir / f"attempt_{attempt.attempt_number}_output.json"
                if out_dir.exists():
                    out_path.write_text(
                        json.dumps(attempt.model_dump(mode="json"), indent=2, default=str),
                        encoding="utf-8",
                    )
        except Exception as exc:
            console.print(f"[red]Full-profile scan failed: {exc}[/red]")
            for vid, s in state.items():
                idx = s["result_index"]
                results[idx] = results[idx].model_copy(
                    update={"final_status": "failed"}
                )

    # ── Rounds 2..max: retry failures sequentially ───────────────
    for round_num in range(2, max_rounds + 1):
        pending = {vid: s for vid, s in state.items() if not s["passed"]}
        if not pending:
            console.print("[green]All findings passed — no retries needed.[/green]")
            break

        console.print(
            f"\n[bold cyan]── Round {round_num}: Retrying {len(pending)} "
            f"failed finding(s) ──[/bold cyan]"
        )

        with _make_progress() as progress:
            task = progress.add_task(
                f"Round {round_num}: Retrying failures", total=len(pending),
            )
            for vid, s in pending.items():
                try:
                    result = pipeline.run(
                        s["vulnerability"],
                        triage_decision=s["triage"],
                        attempt_number=round_num,
                        previous_attempts=s["attempts"],
                        review_feedback=s["review_feedback"],
                        previous_review_verdicts=s["review_verdicts"],
                    )
                except Exception as exc:
                    console.print(f"[red]Retry error for {vid}: {exc}[/red]")
                    progress.advance(task)
                    continue

                if result.remediation is not None:
                    s["attempts"].append(result.remediation)
                if result.pre_approval:
                    s["review_verdicts"].append(result.pre_approval.review_verdict)
                    if not result.pre_approval.approved:
                        s["review_feedback"] = result.pre_approval.rejection_reason
                    else:
                        s["review_feedback"] = None
                s["approval"] = result.pre_approval

                # Update stored result
                idx = s["result_index"]
                results[idx] = result

                progress.advance(task)

        # Full scan after this round
        console.print(
            f"\n[bold cyan]── Full-profile scan (round {round_num}) ──[/bold cyan]"
        )
        try:
            scan_t0 = time.time()
            scan_findings = scanner.scan_full_profile()
            scan_duration = round(time.time() - scan_t0, 3)
            console.print(f"  Scan completed in {scan_duration:.1f}s")
            for vid, s in pending.items():
                passed = Scanner.match_finding(s["vulnerability"], scan_findings)
                if passed and not s["passed"]:
                    fixed_at_round.setdefault(round_num, []).append(vid)
                s["passed"] = passed
                if s["attempts"]:
                    s["attempts"][-1].scan_passed = passed
                    s["attempts"][-1].success = passed
                    s["attempts"][-1].scan_duration = scan_duration
                idx = s["result_index"]
                results[idx] = results[idx].model_copy(
                    update={
                        "final_status": "success" if passed else "failed",
                        "remediation": s["attempts"][-1] if s["attempts"] else None,
                    }
                )
                status = "PASS" if passed else "FAIL"
                rule = s["vulnerability"].rule or vid
                console.print(f"  [{vid}] ({rule}) scan → {status}")
            # Re-write attempt JSONs with scan results
            for vid, s in pending.items():
                if s["attempts"]:
                    attempt = s["attempts"][-1]
                    out_dir = agent_report_dir / "remedy_v2" / run_id / _safe_dirname(vid)
                    out_path = out_dir / f"attempt_{attempt.attempt_number}_output.json"
                    if out_dir.exists():
                        out_path.write_text(
                            json.dumps(attempt.model_dump(mode="json"), indent=2, default=str),
                            encoding="utf-8",
                        )
        except Exception as exc:
            console.print(f"[red]Full-profile scan failed: {exc}[/red]")

    # ── Save results JSON ─────────────────────────────────────────────
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

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

    # ── Text report ───────────────────────────────────────────────────
    text_lines: List[str] = []
    ts = datetime.now().isoformat(timespec="seconds")
    text_lines.append("Multi-Agent Pipeline V2 Report")
    text_lines.append(f"Generated: {ts}")
    text_lines.append(f"Target Host: {host or 'unknown'}")
    text_lines.append(f"Scan Profile: {args.profile}")
    text_lines.append("=" * 80)
    text_lines.append("")

    remediated_count = sum(1 for r in results if r.final_status == "success")
    failed_count = sum(1 for r in results if r.final_status in ("failed", "pending_scan"))
    discarded_count = sum(1 for r in results if r.final_status == "discarded")
    human_count = sum(1 for r in results if r.final_status == "requires_human_review")
    rate = (remediated_count / len(results) * 100) if results else 0.0

    text_lines.append(f"Findings processed:    {len(results)}")
    text_lines.append(f"Remediated:            {remediated_count}")
    text_lines.append(f"Failed:                {failed_count}")
    text_lines.append(f"Discarded:             {discarded_count}")
    text_lines.append(f"Requires human review: {human_count}")
    text_lines.append(f"Success rate:          {rate:.1f}%")
    if fixed_at_round:
        text_lines.append("")
        for rnd in range(1, max_rounds + 1):
            count = len(fixed_at_round.get(rnd, []))
            if count or rnd <= max(fixed_at_round.keys(), default=0):
                text_lines.append(f"Fixed at round {rnd}:    {count}")
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

    # ── Context / Messages PDFs (one per agent) ──────────────────────
    try:
        ctx_pdfs = write_all_context_pdfs(
            results=results,
            work_dir=args.work_dir,
            output_dir=report_dir,
            target_host=host or "unknown",
        )
        for agent_key, pdf_path in ctx_pdfs.items():
            console.print(f"[green]Context PDF ({agent_key}): {pdf_path}[/green]")
        if not ctx_pdfs:
            console.print("[yellow]No agent transcripts found — context PDFs skipped[/yellow]")
    except Exception as exc:
        console.print(f"[yellow]Context PDFs skipped: {exc}[/yellow]")

    # ── Braintrust logging ────────────────────────────────────────────
    if args.braintrust_name:
        try:
            shared_model = os.getenv("OPENROUTER_MODEL", "")
            model_metadata = {
                "triage": shared_model or os.getenv("TRIAGE_MODEL", args.triage_mode),
                "remedy": os.getenv("REMEDY_MODEL", ""),
                "review": args.review_model or shared_model or os.getenv("REVIEW_AGENT_MODEL", ""),
                "qa": shared_model or os.getenv("QA_AGENT_V2_MODEL", ""),
            }
            write_braintrust_eval(
                report_dir=str(report_dir),
                results=results,
                experiment_name=args.braintrust_name,
                project_name=args.braintrust_project,
                model_metadata=model_metadata,
            )
            console.print(f"[green]Braintrust experiment logged: {args.braintrust_name}[/green]")
        except Exception as exc:
            console.print(f"[yellow]Braintrust logging failed: {exc}[/yellow]")

    # ── Summary ───────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print_summary(results, elapsed, fixed_at_round=fixed_at_round, max_rounds=max_rounds)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())