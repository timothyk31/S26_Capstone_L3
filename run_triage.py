#!/usr/bin/env python3
"""
run_triage.py — Standalone runner that scans a VM with OpenSCAP, feeds the
parsed findings to the pipeline-style TriageAgent, and writes both a JSON
results file and a formatted PDF report.

Supports concurrent triage: spin up N TriageAgent workers so findings are
classified in parallel (useful for large scan results + paid API tiers).

Usage examples:

  # Basic — scan, triage (1 worker), write outputs
  python run_triage.py --host 192.168.1.147 --user lawrencewong \\
         --key ~/.ssh/id_rsa --sudo-password kenwong94

  # 4 concurrent triage agents, smart model, severity >= 2
  python run_triage.py --host 192.168.1.147 --user lawrencewong \\
         --key ~/.ssh/id_rsa --sudo-password kenwong94 \\
         --workers 4 --mode smart --min-severity 2

  # Skip scan, use an existing parsed JSON
  python run_triage.py --skip-scan --parsed-json oscap_stig_rl9_parsed.json \\
         --host 192.168.1.147

  # Read host config from inventory.yml
  python run_triage.py --inventory inventory.yml
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from dotenv import find_dotenv, load_dotenv
from pydantic import ValidationError
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from agents.triage_agent import TriageAgent
from openscap_cli import OpenSCAPScanner
from parse_openscap import parse_openscap
from schemas import TriageDecision, Vulnerability

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
DEFAULT_TRIAGE_JSON = "triage_results.json"
DEFAULT_TRIAGE_PDF = "triage_report.pdf"


# ── Inventory loader ───────────────────────────────────────────────────────

def load_inventory(path: str) -> Dict:
    """
    Pull the *first* host from an Ansible-style inventory.yml and return a dict
    with keys:  host, user, key, port, sudo_password
    """
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

    # Also try to grab the HTML report (non-fatal if it fails)
    scanner.download_results(remote_report, local_report)
    return True


# ── Parsing ────────────────────────────────────────────────────────────────

def load_vulnerabilities(
    xml_path: str, parsed_json_path: str
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
                    host=entry.get("host", ""),
                    description=entry.get("description"),
                    recommendation=entry.get("recommendation"),
                )
            )
        except (ValidationError, KeyError) as exc:
            console.print(f"[yellow]Skipping malformed finding: {exc}[/yellow]")
    return vulns


# ── Concurrent triage ──────────────────────────────────────────────────────

def _make_agent(mode: str, model: Optional[str], fallbacks: List[str]) -> TriageAgent:
    """Factory: create one TriageAgent instance (each gets its own HTTP session)."""
    return TriageAgent(
        mode=mode,
        model_override=model,
        fallback_models=fallbacks,
    )


def triage_concurrent(
    vulns: List[Vulnerability],
    *,
    workers: int = 1,
    mode: str = "balanced",
    model: Optional[str] = None,
    fallbacks: Optional[List[str]] = None,
    min_severity: int = 0,
    sleep_s: float = 0.0,
) -> List[TriageDecision]:
    """
    Triage a list of Vulnerabilities, optionally across multiple workers.

    Each worker gets its own TriageAgent (and therefore its own HTTP session)
    so there are no shared-state issues.
    """
    fallbacks = fallbacks or []

    # Filter by severity up front
    filtered: List[Vulnerability] = []
    for v in vulns:
        try:
            sev = int(v.severity)
        except (ValueError, TypeError):
            sev = 0
        if sev >= min_severity:
            filtered.append(v)

    if not filtered:
        console.print("[yellow]No findings meet the minimum severity threshold.[/yellow]")
        return []

    console.print(
        f"\n[bold cyan]── Triaging {len(filtered)} findings "
        f"({workers} worker{'s' if workers > 1 else ''}, mode={mode}) ──[/bold cyan]"
    )

    results: List[TriageDecision] = []

    # ── Single worker: simple sequential loop ─────────────────────────
    if workers <= 1:
        agent = _make_agent(mode, model, fallbacks)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Triaging...", total=len(filtered))
            for vuln in filtered:
                from schemas import TriageInput

                decision = agent.process(TriageInput(vulnerability=vuln))
                results.append(decision)
                progress.advance(task)
                if sleep_s > 0:
                    time.sleep(sleep_s)
        return results

    # ── Multiple workers: ThreadPoolExecutor ──────────────────────────
    from schemas import TriageInput

    # Pre-create one agent per worker so they don't share state
    agents = [_make_agent(mode, model, fallbacks) for _ in range(workers)]
    agent_idx = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Triaging...", total=len(filtered))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {}
            for vuln in filtered:
                # Round-robin assign agents so each future uses its own instance
                ag = agents[agent_idx % workers]
                agent_idx += 1
                fut = pool.submit(ag.process, TriageInput(vulnerability=vuln))
                future_map[fut] = vuln

            for fut in as_completed(future_map):
                vuln = future_map[fut]
                try:
                    decision = fut.result()
                    results.append(decision)
                except Exception as exc:
                    console.print(
                        f"[red]Triage failed for {vuln.id}: {exc}[/red]"
                    )
                    # Conservative fallback
                    results.append(
                        TriageDecision(
                            finding_id=vuln.id,
                            should_remediate=False,
                            risk_level="medium",
                            reason=f"Triage worker error: {exc}",
                            requires_human_review=True,
                        )
                    )
                progress.advance(task)

    # Sort by original finding order
    order = {v.id: i for i, v in enumerate(filtered)}
    results.sort(key=lambda d: order.get(d.finding_id, 999))
    return results


# ── Rich summary table ─────────────────────────────────────────────────────

def print_summary(decisions: List[TriageDecision]) -> None:
    safe = [d for d in decisions if d.should_remediate]
    review = [d for d in decisions if d.requires_human_review and not d.should_remediate]
    blocked = [d for d in decisions if not d.should_remediate and not d.requires_human_review]

    table = Table(title="Triage Summary", show_lines=True)
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("%", justify="right")

    total = max(len(decisions), 1)
    table.add_row("Safe to Remediate", str(len(safe)), f"{len(safe)/total*100:.0f}%", style="green")
    table.add_row("Requires Human Review", str(len(review)), f"{len(review)/total*100:.0f}%", style="yellow")
    table.add_row("Too Dangerous", str(len(blocked)), f"{len(blocked)/total*100:.0f}%", style="red")
    table.add_row("Total", str(len(decisions)), "100%", style="bold")

    console.print()
    console.print(table)


# ── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan a VM with OpenSCAP, triage findings (concurrently), output JSON + PDF.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python run_triage.py --host 192.168.1.147 --user root --key ~/.ssh/id_rsa\n"
            "  python run_triage.py --inventory inventory.yml --workers 4 --mode smart\n"
            "  python run_triage.py --skip-scan --parsed-json oscap_stig_rl9_parsed.json --host myvm\n"
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
    scan_g.add_argument(
        "--skip-scan",
        action="store_true",
        help="Skip the SSH scan; use --local-xml or --parsed-json directly.",
    )

    # ── Triage ───
    triage = p.add_argument_group("Triage options")
    triage.add_argument("--min-severity", type=int, default=2, choices=range(5), metavar="0-4")
    triage.add_argument("--mode", choices=["fast", "balanced", "smart", "nemotron_free"], default="balanced")
    triage.add_argument("--model", default=None, help="Override LLM model name")
    triage.add_argument("--fallback-model", action="append", default=[], dest="fallbacks")
    triage.add_argument("--sleep", type=float, default=0.0, help="Seconds between LLM calls (rate-limit)")

    # ── Concurrency ───
    conc = p.add_argument_group("Concurrency")
    conc.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of concurrent TriageAgent workers (default: 1). "
             "Each worker gets its own agent + HTTP session.",
    )

    # ── Output ───
    out = p.add_argument_group("Output")
    out.add_argument("--triage-json", default=DEFAULT_TRIAGE_JSON)
    out.add_argument("--triage-pdf", default=DEFAULT_TRIAGE_PDF)
    out.add_argument("--no-pdf", action="store_true", help="Skip PDF generation")

    return p.parse_args()


# ── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()
    t0 = time.time()

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
        console.print("[red]ERROR: --host or --inventory is required (unless --skip-scan).[/red]")
        return 1

    # ── Scan ──────────────────────────────────────────────────────────
    if not args.skip_scan:
        if not run_scan(
            host=host,
            user=user,
            key=key,
            port=port,
            sudo_password=sudo_password,
            profile=args.profile,
            datastream=args.datastream,
            remote_xml=args.remote_xml,
            local_xml=args.local_xml,
            remote_report=args.remote_report,
            local_report=args.local_report,
        ):
            return 1

    # ── Parse ─────────────────────────────────────────────────────────
    parsed_json = args.parsed_json

    if args.skip_scan and Path(parsed_json).exists():
        console.print(f"[cyan]Using existing parsed JSON: {parsed_json}[/cyan]")
        raw = json.loads(Path(parsed_json).read_text(encoding="utf-8"))
        vulns: List[Vulnerability] = []
        for entry in raw:
            try:
                vulns.append(
                    Vulnerability(
                        id=entry["id"],
                        title=entry["title"],
                        severity=entry.get("severity", "0"),
                        host=entry.get("host", host or "unknown"),
                        description=entry.get("description"),
                        recommendation=entry.get("recommendation"),
                    )
                )
            except (ValidationError, KeyError):
                continue
    elif args.skip_scan and Path(args.local_xml).exists():
        console.print(f"[cyan]Parsing existing XML: {args.local_xml}[/cyan]")
        vulns = load_vulnerabilities(args.local_xml, parsed_json)
    elif args.skip_scan:
        console.print("[red]--skip-scan set but neither parsed JSON nor local XML found.[/red]")
        return 1
    else:
        vulns = load_vulnerabilities(args.local_xml, parsed_json)

    if not vulns:
        console.print("[yellow]No findings to triage.[/yellow]")
        return 0

    console.print(f"[green]Loaded {len(vulns)} findings from scan.[/green]")

    # ── Triage ────────────────────────────────────────────────────────
    decisions = triage_concurrent(
        vulns,
        workers=args.workers,
        mode=args.mode,
        model=args.model,
        fallbacks=args.fallbacks,
        min_severity=args.min_severity,
        sleep_s=args.sleep,
    )

    if not decisions:
        console.print("[yellow]No findings met the severity threshold.[/yellow]")
        return 0

    # ── Output ────────────────────────────────────────────────────────
    # Use any agent to write (they all share the same output methods)
    writer = _make_agent(args.mode, args.model, args.fallbacks)

    json_path = writer.write_results_json(
        decisions, args.triage_json, target_host=host or "unknown"
    )
    console.print(f"[green]✓ JSON saved: {json_path}[/green]")

    if not args.no_pdf:
        pdf_path = writer.write_results_pdf(
            decisions, args.triage_pdf, target_host=host or "unknown"
        )
        console.print(f"[green]✓ PDF  saved: {pdf_path}[/green]")

    # ── Summary ───────────────────────────────────────────────────────
    print_summary(decisions)
    elapsed = time.time() - t0
    console.print(f"\n[dim]Completed in {elapsed:.1f}s[/dim]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
