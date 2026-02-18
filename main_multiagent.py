#!/usr/bin/env python3
"""
main_multiagent.py — Full multi-agent remediation pipeline.

Scans a target VM with OpenSCAP, then runs every finding through:
  Triage → Remedy → Review → QA

Produces:
  - Aggregated JSON results
  - Text report
  - PDF report
  - Consolidated Ansible playbook (successful fixes only)

Usage examples:

  # Full pipeline from inventory file (scan + remediate)
  python main_multiagent.py --inventory inventory.yml

  # Explicit host, 4 concurrent workers, smart LLM
  python main_multiagent.py --host 10.244.72.95 --user root \\
         --key ~/.ssh/id_rsa --sudo-password SECRET \\
         --workers 4 --triage-mode smart

  # Skip scan, use existing parsed JSON
  python main_multiagent.py --skip-scan --parsed-json oscap_stig_rl9_parsed.json \\
         --host 10.244.72.95 --user root --key ~/.ssh/id_rsa

  # Limit to first 5 findings, severity >= 3
  python main_multiagent.py --inventory inventory.yml \\
         --max-vulns 5 --min-severity 3

  # Sequential mode (1 worker, easier to debug)
  python main_multiagent.py --inventory inventory.yml --workers 1
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
from rich.table import Table

from agents.qa_agent import QAAgent
from agents.remedy_agent import RemedyAgent
from agents.review_agent import ReviewAgent
from agents.triage_agent import TriageAgent
from aggregation.result_aggregator import ResultAggregator
from helpers.command_executor import ShellCommandExecutor
from helpers.scanner import Scanner
from openscap_cli import OpenSCAPScanner
from parse_openscap import parse_openscap
from schemas import FindingResult, Vulnerability
from workflow.concurrent_manager import ConcurrentManager
from workflow.pipeline import Pipeline

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

def print_summary(results: List[FindingResult], elapsed: float) -> None:
    """Print a Rich summary table of pipeline results."""
    success = [r for r in results if r.final_status == "success"]
    failed = [r for r in results if r.final_status == "failed"]
    discarded = [r for r in results if r.final_status == "discarded"]
    review = [r for r in results if r.final_status == "requires_human_review"]

    table = Table(title="Pipeline Results", show_lines=True)
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
    pipe_g.add_argument("--max-review-retries", type=int, default=1,
                        help="Max review→remedy loops per finding (default: 1)")

    # ── Agents ───
    agent_g = p.add_argument_group("Agent options")
    agent_g.add_argument("--triage-mode", choices=["fast", "balanced", "smart"],
                         default="balanced", help="Triage LLM quality tier")
    agent_g.add_argument("--review-model", default=None,
                         help="Override the Review agent LLM model (default: env REVIEW_AGENT_MODEL)")

    # ── Concurrency ───
    conc = p.add_argument_group("Concurrency")
    conc.add_argument("--workers", type=int, default=1,
                      help="Number of concurrent pipeline workers (default: 1)")

    # ── Output ───
    out = p.add_argument_group("Output")
    out.add_argument("--work-dir", default=DEFAULT_WORK_DIR,
                     help="Working directory for intermediate artifacts")
    out.add_argument("--report-dir", default=DEFAULT_REPORT_DIR,
                     help="Output directory for reports and playbook")

    return p.parse_args()


# ── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()
    t0 = time.time()

    console.print(Panel.fit(
        "[bold cyan]Multi-Agent Remediation Pipeline[/bold cyan]\n"
        "Triage → Remedy → Review → QA",
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
        if not run_scan(
            host=host, user=user, key=key, port=port,
            sudo_password=sudo_password,
            profile=args.profile, datastream=args.datastream,
            remote_xml=args.remote_xml, local_xml=args.local_xml,
            remote_report=args.remote_report, local_report=args.local_report,
        ):
            return 1

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
    filtered: List[Vulnerability] = []
    for v in vulns:
        try:
            sev = int(v.severity)
        except (ValueError, TypeError):
            sev = 0
        if sev >= args.min_severity:
            filtered.append(v)

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

    # ── Initialize agents ─────────────────────────────────────────────
    triage_agent = TriageAgent(mode=args.triage_mode)

    remedy_agent = RemedyAgent(
        executor=executor,
        scanner=scanner,
        work_dir=work_dir / "remedy",
    )

    review_agent = ReviewAgent(
        model=args.review_model,
    )

    qa_agent = QAAgent(executor=executor)

    # ── Pipeline factory ──────────────────────────────────────────────
    agent_report_dir = Path(args.work_dir) / "agent_reports"

    def make_pipeline() -> Pipeline:
        return Pipeline(
            triage_agent=triage_agent,
            remedy_agent=remedy_agent,
            review_agent=review_agent,
            qa_agent=qa_agent,
            max_remedy_attempts=args.max_remedy_attempts,
            max_review_retries=args.max_review_retries,
            report_dir=agent_report_dir,
        )

    # ── Run ───────────────────────────────────────────────────────────
    manager = ConcurrentManager(
        pipeline_factory=make_pipeline,
        max_concurrent=args.workers,
    )
    results = manager.run_all(filtered)

    # ── Aggregate & report ────────────────────────────────────────────
    aggregator = ResultAggregator(
        output_dir=args.report_dir,
        scan_profile=args.profile,
        target_host=host or "unknown",
    )
    report = aggregator.aggregate(results)

    # ── Per-agent PDF reports ─────────────────────────────────────────
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)

    # Triage PDF
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

    # Remedy PDF
    try:
        remedy_agent.write_results_pdf(
            results,
            output_path=report_dir / "remedy_report.pdf",
            target_host=host or "unknown",
        )
        console.print(f"[green]Remedy PDF: {report_dir / 'remedy_report.pdf'}[/green]")
    except Exception as exc:
        console.print(f"[yellow]Remedy PDF skipped: {exc}[/yellow]")

    # Review PDF
    try:
        review_agent.write_results_pdf(
            results,
            output_path=report_dir / "review_report.pdf",
            target_host=host or "unknown",
        )
        console.print(f"[green]Review PDF: {report_dir / 'review_report.pdf'}[/green]")
    except Exception as exc:
        console.print(f"[yellow]Review PDF skipped: {exc}[/yellow]")

    # QA PDF
    try:
        qa_agent.write_results_pdf(
            results,
            output_path=report_dir / "qa_report.pdf",
            target_host=host or "unknown",
        )
        console.print(f"[green]QA PDF: {report_dir / 'qa_report.pdf'}[/green]")
    except Exception as exc:
        console.print(f"[yellow]QA PDF skipped: {exc}[/yellow]")

    console.print(f"\n[green]Reports saved to: {args.report_dir}/[/green]")
    if report.ansible_playbook_path:
        console.print(f"[green]Ansible playbook: {report.ansible_playbook_path}[/green]")
    if report.text_report_path:
        console.print(f"[green]Text report: {report.text_report_path}[/green]")
    if report.pdf_report_path:
        console.print(f"[green]PDF report: {report.pdf_report_path}[/green]")

    # ── Summary ───────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print_summary(results, elapsed)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())