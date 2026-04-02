#!/usr/bin/env python3
"""
recover_report.py — Reconstruct a pipeline report from saved agent report JSONs.

Use this when a pipeline run completed all agent work but crashed before
generating the final report (e.g., WinError 267 from invalid directory name).

Usage:
    python recover_report.py --run-id run_20260331_171127
    python recover_report.py --run-id run_20260331_171127 --triage-run-id run_20260331_171127
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Ensure repo root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from schemas import (
    RemediationAttempt,
    TriageDecision,
    V2FindingResult,
    Vulnerability,
)
from main_multiagent import write_results_and_text_report


def _safe_dirname(finding_id: str) -> str:
    """Match the sanitisation used by AgentReportWriter."""
    return re.sub(r"[^\w\-.]", "_", finding_id)


def load_triage_data(
    triage_dir: Path,
) -> Dict[str, Tuple[Vulnerability, TriageDecision]]:
    """Load all triage input/output pairs from a run directory.

    Returns {finding_id: (Vulnerability, TriageDecision)}.
    """
    data: Dict[str, Tuple[Vulnerability, TriageDecision]] = {}
    if not triage_dir.is_dir():
        print(f"[WARN] Triage directory not found: {triage_dir}")
        return data

    for finding_dir in sorted(triage_dir.iterdir()):
        if not finding_dir.is_dir():
            continue
        input_path = finding_dir / "input.json"
        output_path = finding_dir / "output.json"
        error_path = finding_dir / "error.json"

        if not input_path.exists():
            print(f"[WARN] Missing triage input: {finding_dir.name}")
            continue

        try:
            input_data = json.loads(input_path.read_text(encoding="utf-8"))
            vuln = Vulnerability(**input_data["vulnerability"])
        except Exception as exc:
            print(f"[WARN] Failed to parse triage input for {finding_dir.name}: {exc}")
            continue

        if output_path.exists():
            try:
                output_data = json.loads(output_path.read_text(encoding="utf-8"))
                triage = TriageDecision(**output_data)
            except Exception as exc:
                print(f"[WARN] Failed to parse triage output for {finding_dir.name}: {exc}")
                triage = TriageDecision(
                    finding_id=vuln.id,
                    should_remediate=False,
                    risk_level="medium",
                    reason=f"Recovery: could not parse triage output: {exc}",
                    requires_human_review=True,
                )
        elif error_path.exists():
            triage = TriageDecision(
                finding_id=vuln.id,
                should_remediate=False,
                risk_level="medium",
                reason="Recovery: triage errored during pipeline run",
                requires_human_review=True,
            )
        else:
            print(f"[WARN] No triage output or error for {finding_dir.name}")
            continue

        data[vuln.id] = (vuln, triage)

    return data


def load_remedy_data(
    remedy_dir: Path,
) -> Dict[str, List[RemediationAttempt]]:
    """Load all remedy attempt outputs from a run directory.

    Returns {finding_id: [RemediationAttempt, ...]}, sorted by attempt_number.
    """
    data: Dict[str, List[RemediationAttempt]] = {}
    if not remedy_dir.is_dir():
        print(f"[WARN] Remedy directory not found: {remedy_dir}")
        return data

    for finding_dir in sorted(remedy_dir.iterdir()):
        if not finding_dir.is_dir():
            continue

        attempts: List[RemediationAttempt] = []
        for output_file in sorted(finding_dir.glob("attempt_*_output.json")):
            try:
                raw = json.loads(output_file.read_text(encoding="utf-8"))
                attempt = RemediationAttempt(**raw)
                attempts.append(attempt)
            except Exception as exc:
                print(f"[WARN] Failed to parse {output_file}: {exc}")

        if attempts:
            attempts.sort(key=lambda a: a.attempt_number)
            finding_id = attempts[0].finding_id
            data[finding_id] = attempts

    return data


def build_results(
    triage_data: Dict[str, Tuple[Vulnerability, TriageDecision]],
    remedy_data: Dict[str, List[RemediationAttempt]],
) -> Tuple[List[V2FindingResult], Dict[int, List[str]], int]:
    """Reconstruct V2FindingResult objects and fixed_at_round.

    Returns (results, fixed_at_round, max_rounds).
    """
    results: List[V2FindingResult] = []
    fixed_at_round: Dict[int, List[str]] = {}
    max_attempt = 0

    # Process all triaged findings
    for finding_id, (vuln, triage) in triage_data.items():
        attempts = remedy_data.get(finding_id, [])

        if attempts:
            max_attempt = max(max_attempt, max(a.attempt_number for a in attempts))

        # Determine final_status
        if not triage.should_remediate:
            if triage.requires_human_review:
                status = "requires_human_review"
            else:
                status = "discarded"
        elif any(a.scan_passed for a in attempts):
            status = "success"
            # Record which round fixed it
            for a in attempts:
                if a.scan_passed:
                    fixed_at_round.setdefault(a.attempt_number, []).append(finding_id)
                    break
        elif attempts:
            status = "failed"
        else:
            # Triage said remediate but no remedy data found
            status = "failed"

        last_attempt = attempts[-1] if attempts else None
        total_duration = sum(a.attempt_duration for a in attempts)

        result = V2FindingResult(
            vulnerability=vuln,
            triage=triage,
            remediation=last_attempt,
            all_attempts=attempts,
            pre_approval=None,
            final_status=status,
            total_duration=total_duration,
            timestamp=datetime.now().isoformat(timespec="seconds"),
            llm_metrics=last_attempt.llm_metrics if last_attempt and last_attempt.llm_metrics else {},
        )
        results.append(result)

    # Also pick up any remedy findings not in triage (shouldn't happen, but be safe)
    for finding_id, attempts in remedy_data.items():
        if finding_id not in triage_data:
            print(f"[WARN] Finding {finding_id} has remedy data but no triage — "
                  "reading vulnerability from remedy input")
            # Try to get vulnerability from the remedy input
            finding_dir = None
            for d in attempts[0:1]:
                # We'd need the remedy input file; use what's in the attempt
                pass

            # Create a minimal triage decision
            triage = TriageDecision(
                finding_id=finding_id,
                should_remediate=True,
                risk_level="medium",
                reason="Recovery: triage data missing, remedy data exists",
            )

            last_attempt = attempts[-1]
            status = "success" if any(a.scan_passed for a in attempts) else "failed"
            if status == "success":
                for a in attempts:
                    if a.scan_passed:
                        fixed_at_round.setdefault(a.attempt_number, []).append(finding_id)
                        break

            # Create a minimal vulnerability (we don't have the full data)
            vuln = Vulnerability(
                id=finding_id,
                title=finding_id,
                severity="unknown",
                host="unknown",
                result="fail",
            )

            result = V2FindingResult(
                vulnerability=vuln,
                triage=triage,
                remediation=last_attempt,
                all_attempts=attempts,
                pre_approval=None,
                final_status=status,
                total_duration=sum(a.attempt_duration for a in attempts),
                timestamp=datetime.now().isoformat(timespec="seconds"),
                llm_metrics=last_attempt.llm_metrics if last_attempt.llm_metrics else {},
            )
            results.append(result)

    return results, fixed_at_round, max(max_attempt, 1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recover a pipeline report from saved agent report JSONs."
    )
    parser.add_argument(
        "--run-id", required=True,
        help="Run ID directory name (e.g., run_20260331_171127)",
    )
    parser.add_argument(
        "--triage-run-id", default=None,
        help="Triage run ID if different from --run-id (default: same as --run-id)",
    )
    parser.add_argument(
        "--agent-reports", default="./pipeline_work/agent_reports",
        help="Path to agent_reports root (default: ./pipeline_work/agent_reports)",
    )
    parser.add_argument(
        "--output-dir", default=None,
        help="Output directory (default: ./reports/recovered_<run-id>/)",
    )
    parser.add_argument(
        "--max-rounds", type=int, default=None,
        help="Max remedy rounds (default: auto-detected from data)",
    )
    parser.add_argument(
        "--profile", default="xccdf_org.ssgproject.content_profile_stig",
        help="Scan profile name for report header",
    )
    parser.add_argument(
        "--model", default="unknown",
        help="Model name for PDF/CSV metadata (default: unknown)",
    )
    args = parser.parse_args()

    agent_reports = Path(args.agent_reports)
    triage_run_id = args.triage_run_id or args.run_id

    triage_dir = agent_reports / "triage" / triage_run_id
    remedy_dir = agent_reports / "remedy_v2" / args.run_id

    print(f"Loading triage data from: {triage_dir}")
    triage_data = load_triage_data(triage_dir)
    print(f"  Loaded {len(triage_data)} triage decisions")

    print(f"Loading remedy data from: {remedy_dir}")
    remedy_data = load_remedy_data(remedy_dir)
    print(f"  Loaded {len(remedy_data)} remediated findings")

    results, fixed_at_round, detected_max_rounds = build_results(triage_data, remedy_data)
    max_rounds = args.max_rounds or detected_max_rounds

    # Extract host from first vulnerability
    host = "unknown"
    if results:
        host = results[0].vulnerability.host or "unknown"

    # Summary
    success = sum(1 for r in results if r.final_status == "success")
    failed = sum(1 for r in results if r.final_status == "failed")
    discarded = sum(1 for r in results if r.final_status == "discarded")
    human = sum(1 for r in results if r.final_status == "requires_human_review")
    print(f"\nRecovered {len(results)} findings:")
    print(f"  Success:              {success}")
    print(f"  Failed:               {failed}")
    print(f"  Discarded:            {discarded}")
    print(f"  Requires human review:{human}")

    # Generate report
    output_dir = Path(args.output_dir) if args.output_dir else Path(f"reports/recovered_{args.run_id}")
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = write_results_and_text_report(
        report_dir=output_dir,
        results=results,
        fixed_at_round=fixed_at_round,
        max_rounds=max_rounds,
        host=host,
        profile=args.profile,
    )
    print(f"\nText report: {report_path}")

    # ── Triage PDF ────────────────────────────────────────────────────
    try:
        from agents.triage_agent import TriageAgent

        dummy_triage = TriageAgent(api_key="dummy", model_override=args.model)
        dummy_triage.write_results_pdf(
            [r.triage for r in results],
            output_path=output_dir / "triage_report.pdf",
            target_host=host,
            vulnerabilities=[r.vulnerability for r in results],
        )
        print(f"Triage PDF:  {output_dir / 'triage_report.pdf'}")
    except Exception as exc:
        print(f"[WARN] Triage PDF skipped: {exc}")

    # ── Pipeline PDF ──────────────────────────────────────────────────
    try:
        from pipeline_pdf_writer import write_pipeline_pdf

        model_metadata = {
            "triage": args.model,
            "remedy": args.model,
            "review": args.model,
            "qa": args.model,
        }
        write_pipeline_pdf(
            results,
            output_path=output_dir / "pipeline_report.pdf",
            target_host=host,
            model_metadata=model_metadata,
        )
        print(f"Pipeline PDF: {output_dir / 'pipeline_report.pdf'}")
    except Exception as exc:
        print(f"[WARN] Pipeline PDF skipped: {exc}")

    # ── CSV export ────────────────────────────────────────────────────
    try:
        from csv_export import write_csv_report

        model_metadata = {
            "triage": args.model,
            "remedy": args.model,
            "review": args.model,
            "qa": args.model,
        }
        elapsed = sum(r.total_duration for r in results)
        detail_csv, summary_csv = write_csv_report(
            results=results,
            report_dir=str(output_dir),
            fixed_at_round=fixed_at_round,
            elapsed=elapsed,
            model_metadata=model_metadata,
            max_rounds=max_rounds,
        )
        print(f"Detail CSV:  {detail_csv}")
        print(f"Summary CSV: {summary_csv}")
    except Exception as exc:
        print(f"[WARN] CSV export skipped: {exc}")


if __name__ == "__main__":
    main()
