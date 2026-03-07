#!/usr/bin/env python3
"""
run_initial_scan.py — Standalone initial OpenSCAP scan runner.

Connects to the target VM, runs a full OpenSCAP STIG scan, downloads the
XML + HTML report, parses findings into JSON, and writes a summary with
raw vulnerability counts.

Outputs (all paths configurable via CLI flags):
  - oscap_stig_rl9.xml          Raw XCCDF XML results
  - oscap_stig_rl9_report.html  HTML report for human review
  - oscap_stig_rl9_parsed.json  Parsed findings (failed/error only)
  - initial_scan_summary.json   Scan metadata + raw counts

Usage:
  # From inventory file
  python run_initial_scan.py --inventory inventory.yml

  # Explicit host
  python run_initial_scan.py --host 10.245.124.77 --user root --key ~/.ssh/id_rsa

  # Custom output paths and datastream
  python run_initial_scan.py --inventory inventory.yml \
         --local-xml my_scan.xml --parsed-json my_scan.json

  # Rocky Linux 9 STIG (default)
  python run_initial_scan.py --inventory inventory.yml \
         --profile xccdf_org.ssgproject.content_profile_stig \
         --datastream /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import yaml
from dotenv import find_dotenv, load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from openscap_cli import OpenSCAPScanner
from parse_openscap import parse_openscap

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
DEFAULT_SUMMARY_JSON = "initial_scan_summary.json"


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


# ── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run an initial OpenSCAP scan and write all results to disk.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target = p.add_argument_group("Target host (or use --inventory)")
    target.add_argument("--host", help="Target host IP / hostname")
    target.add_argument("--user", default="root", help="SSH user (default: root)")
    target.add_argument("--key", help="SSH private key path")
    target.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    target.add_argument("--sudo-password", help="Sudo password on target")
    target.add_argument("--inventory", help="Ansible inventory.yml (reads first host)")

    scan = p.add_argument_group("Scan options")
    scan.add_argument("--profile", default=DEFAULT_PROFILE,
                      help=f"XCCDF profile (default: {DEFAULT_PROFILE})")
    scan.add_argument("--datastream", default=DEFAULT_DATASTREAM,
                      help=f"Datastream path on target (default: {DEFAULT_DATASTREAM})")
    scan.add_argument("--remote-xml", default=DEFAULT_REMOTE_XML,
                      help="Remote path for XML results")
    scan.add_argument("--remote-report", default=DEFAULT_REMOTE_REPORT,
                      help="Remote path for HTML report")

    output = p.add_argument_group("Output")
    output.add_argument("--local-xml", default=DEFAULT_LOCAL_XML,
                        help=f"Local XML results path (default: {DEFAULT_LOCAL_XML})")
    output.add_argument("--local-report", default=DEFAULT_LOCAL_REPORT,
                        help=f"Local HTML report path (default: {DEFAULT_LOCAL_REPORT})")
    output.add_argument("--parsed-json", default=DEFAULT_PARSED_JSON,
                        help=f"Parsed findings JSON path (default: {DEFAULT_PARSED_JSON})")
    output.add_argument("--summary-json", default=DEFAULT_SUMMARY_JSON,
                        help=f"Scan summary JSON path (default: {DEFAULT_SUMMARY_JSON})")

    return p.parse_args()


# ── Main ────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()
    t0 = time.time()

    console.print(Panel.fit(
        "[bold cyan]OpenSCAP Initial Scan[/bold cyan]\n"
        "Scan → Download → Parse → Write Summary",
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

    if not host:
        console.print("[red]ERROR: --host or --inventory is required.[/red]")
        return 1

    # ── Run scan ──────────────────────────────────────────────────────
    scanner = OpenSCAPScanner(
        target_host=host,
        ssh_user=user,
        ssh_key=key,
        ssh_port=port,
    )

    console.print(f"\n[bold cyan]── Running OpenSCAP scan on {host} ──[/bold cyan]")
    console.print(f"[dim]Profile:    {args.profile}[/dim]")
    console.print(f"[dim]Datastream: {args.datastream}[/dim]")

    ok = scanner.run_scan(
        profile=args.profile,
        output_file=args.remote_xml,
        datastream=args.datastream,
        report_file=args.remote_report,
        sudo_password=sudo_password,
    )
    if not ok:
        console.print("[red]Scan failed — aborting.[/red]")
        return 1

    # ── Download results ──────────────────────────────────────────────
    console.print("\n[cyan]Downloading results…[/cyan]")

    if not scanner.download_results(args.remote_xml, args.local_xml):
        console.print("[red]Failed to download XML results.[/red]")
        return 1

    scanner.download_results(args.remote_report, args.local_report)

    # ── Parse findings ────────────────────────────────────────────────
    console.print(f"\n[cyan]Parsing XML → {args.parsed_json}[/cyan]")
    parse_result = parse_openscap(args.local_xml, args.parsed_json)

    # parse_openscap returns either a list (old) or a dict with stats (new)
    if isinstance(parse_result, dict):
        findings = parse_result.get("findings", [])
        total_rules = parse_result.get("total_rules_scanned", 0)
        rules_passed = parse_result.get("rules_passed", 0)
        rules_failed = parse_result.get("rules_failed", 0)
    else:
        # Fallback: re-read the written JSON
        findings = json.loads(Path(args.parsed_json).read_text(encoding="utf-8"))
        total_rules = 0
        rules_passed = 0
        rules_failed = len(findings)

    # ── Severity breakdown ────────────────────────────────────────────
    severity_counts = {"0": 0, "1": 0, "2": 0, "3": 0, "4": 0}
    for f in findings:
        sev = str(f.get("severity", "0"))
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # ── Write scan summary JSON ───────────────────────────────────────
    elapsed = time.time() - t0
    summary = {
        "scan_timestamp": datetime.now().isoformat(timespec="seconds"),
        "target_host": host,
        "ssh_user": user,
        "profile": args.profile,
        "datastream": args.datastream,
        "duration_seconds": round(elapsed, 1),
        "output_files": {
            "xml_results": args.local_xml,
            "html_report": args.local_report,
            "parsed_json": args.parsed_json,
        },
        "raw_counts": {
            "total_rules_evaluated": total_rules,
            "rules_passed": rules_passed,
            "rules_failed_or_error": rules_failed,
        },
        "severity_breakdown": {
            "info_0": severity_counts.get("0", 0),
            "low_1": severity_counts.get("1", 0),
            "medium_2": severity_counts.get("2", 0),
            "high_3": severity_counts.get("3", 0),
            "critical_4": severity_counts.get("4", 0),
        },
        "findings": findings,
    }

    summary_path = Path(args.summary_json)
    summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    console.print(f"\n[green]Scan summary written → {summary_path}[/green]")

    # ── Pretty-print results ──────────────────────────────────────────
    severity_labels = {
        "0": ("Info", "dim"),
        "1": ("Low", "blue"),
        "2": ("Medium", "yellow"),
        "3": ("High", "red"),
        "4": ("Critical", "bold red"),
    }

    table = Table(title="Initial Scan Results", show_lines=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    table.add_row("Target Host", host)
    table.add_row("Profile", args.profile.split("_profile_")[-1])
    table.add_row("", "")
    table.add_row("Total Rules Evaluated", str(total_rules), style="cyan")
    table.add_row("Passed", str(rules_passed), style="green")
    table.add_row("Failed / Error", str(rules_failed), style="red")
    table.add_row("", "")

    for sev_key, (label, style) in severity_labels.items():
        count = severity_counts.get(sev_key, 0)
        if count > 0:
            table.add_row(f"  {label} (sev {sev_key})", str(count), style=style)

    table.add_row("", "")
    table.add_row("Duration", f"{elapsed:.1f}s", style="dim")

    console.print()
    console.print(table)

    console.print(f"\n[green]XML results:   {args.local_xml}[/green]")
    console.print(f"[green]HTML report:   {args.local_report}[/green]")
    console.print(f"[green]Parsed JSON:   {args.parsed_json}[/green]")
    console.print(f"[green]Scan summary:  {args.summary_json}[/green]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
