"""
ResultAggregator: Collect FindingResults from all pipelines, compute statistics,
and generate text report, PDF report, and consolidated Ansible playbook.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from schemas import (
    AggregatedReport,
    FindingResult,
    RemediationSuggestion,
    Vulnerability,
)


class ResultAggregator:
    """Aggregate pipeline results into reports and a playbook."""

    def __init__(
        self,
        output_dir: str = "./reports",
        scan_profile: str = "",
        target_host: str = "",
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.scan_profile = scan_profile
        self.target_host = target_host

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def aggregate(self, results: List[FindingResult]) -> AggregatedReport:
        """Aggregate all finding results into a single report with artifacts."""
        total = len(results)
        remediated = sum(1 for r in results if r.final_status == "success")
        failed = sum(1 for r in results if r.final_status == "failed")
        discarded = sum(1 for r in results if r.final_status == "discarded")
        human_review = sum(1 for r in results if r.final_status == "requires_human_review")

        total_duration = sum(r.total_duration for r in results)
        success_rate = remediated / total if total > 0 else 0.0

        stage_stats = self._compute_stage_statistics(results)

        # Generate artifacts
        playbook_path = self._generate_playbook(results)
        text_path = self._generate_text_report(results)
        pdf_path = self._generate_pdf_report(results)

        # Persist machine-readable JSON
        json_path = self.output_dir / "aggregated_results.json"
        json_path.write_text(
            json.dumps(
                [r.model_dump(mode="json") for r in results],
                indent=2,
                default=str,
            ),
            encoding="utf-8",
        )

        timestamp = datetime.now().isoformat(timespec="seconds")

        return AggregatedReport(
            findings_processed=total,
            findings_remediated=remediated,
            findings_failed=failed,
            findings_discarded=discarded,
            results=results,
            success_rate=success_rate,
            total_duration=total_duration,
            stage_statistics=stage_stats,
            ansible_playbook_path=playbook_path,
            text_report_path=text_path,
            pdf_report_path=pdf_path,
            scan_profile=self.scan_profile,
            target_host=self.target_host,
            timestamp=timestamp,
        )

    # ------------------------------------------------------------------
    # Stage statistics
    # ------------------------------------------------------------------

    def _compute_stage_statistics(self, results: List[FindingResult]) -> Dict[str, Any]:
        """Compute per-stage success/failure counts and timing."""
        stats: Dict[str, Any] = {
            "triage": {"total": 0, "remediate": 0, "discard": 0, "human_review": 0},
            "remedy": {"total": 0, "passed_scan": 0, "failed_scan": 0, "avg_attempts": 0.0},
            "review": {"total": 0, "approved": 0, "rejected": 0, "avg_security_score": 0.0},
            "qa": {"total": 0, "safe": 0, "unsafe": 0, "regressions": 0},
        }

        review_scores: List[int] = []
        remedy_attempts: List[int] = []

        for r in results:
            # Triage
            stats["triage"]["total"] += 1
            if r.triage.should_remediate:
                stats["triage"]["remediate"] += 1
            else:
                stats["triage"]["discard"] += 1
            if r.triage.requires_human_review:
                stats["triage"]["human_review"] += 1

            # Remedy
            if r.remediation is not None:
                stats["remedy"]["total"] += 1
                remedy_attempts.append(r.remediation.attempt_number)
                if r.remediation.scan_passed:
                    stats["remedy"]["passed_scan"] += 1
                else:
                    stats["remedy"]["failed_scan"] += 1

            # Review
            if r.review is not None:
                stats["review"]["total"] += 1
                if r.review.approve:
                    stats["review"]["approved"] += 1
                else:
                    stats["review"]["rejected"] += 1
                if r.review.security_score is not None:
                    review_scores.append(r.review.security_score)

            # QA
            if r.qa is not None:
                stats["qa"]["total"] += 1
                if r.qa.safe:
                    stats["qa"]["safe"] += 1
                else:
                    stats["qa"]["unsafe"] += 1
                if r.qa.regression_detected:
                    stats["qa"]["regressions"] += 1

        if remedy_attempts:
            stats["remedy"]["avg_attempts"] = round(
                sum(remedy_attempts) / len(remedy_attempts), 2
            )
        if review_scores:
            stats["review"]["avg_security_score"] = round(
                sum(review_scores) / len(review_scores), 2
            )

        return stats

    # ------------------------------------------------------------------
    # Ansible playbook
    # ------------------------------------------------------------------

    def _generate_playbook(self, results: List[FindingResult]) -> Optional[str]:
        """Build a consolidated Ansible playbook from successfully remediated findings."""
        from remediation_bridge import RemediationBridge

        successful = [r for r in results if r.final_status == "success" and r.remediation]
        if not successful:
            return None

        suggestions: List[RemediationSuggestion] = []
        vulns: List[Vulnerability] = []

        for r in successful:
            assert r.remediation is not None  # guarded above
            suggestions.append(
                RemediationSuggestion(
                    id=r.vulnerability.id,
                    proposed_commands=r.remediation.commands_executed,
                    notes=f"Successfully remediated (attempt {r.remediation.attempt_number})",
                )
            )
            vulns.append(r.vulnerability)

        bridge = RemediationBridge()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        playbook = bridge.create_playbook(
            suggestions=suggestions,
            vulns=vulns,
            playbook_name=f"Proven Remediations - {ts}",
        )

        playbook_file = self.output_dir / f"final_remediation_playbook_{ts}.yml"
        playbook_file.write_text(playbook.to_yaml(), encoding="utf-8")
        return str(playbook_file)

    # ------------------------------------------------------------------
    # Text report
    # ------------------------------------------------------------------

    def _generate_text_report(self, results: List[FindingResult]) -> str:
        """Generate a human-readable text report."""
        ts = datetime.now().isoformat(timespec="seconds")
        lines: List[str] = []
        lines.append("Multi-Agent Pipeline Report")
        lines.append(f"Generated: {ts}")
        lines.append(f"Target Host: {self.target_host}")
        lines.append(f"Scan Profile: {self.scan_profile}")
        lines.append("=" * 80)
        lines.append("")

        # Summary table
        total = len(results)
        remediated = sum(1 for r in results if r.final_status == "success")
        failed = sum(1 for r in results if r.final_status == "failed")
        discarded = sum(1 for r in results if r.final_status == "discarded")
        human = sum(1 for r in results if r.final_status == "requires_human_review")
        rate = (remediated / total * 100) if total else 0.0

        lines.append(f"Findings processed:   {total}")
        lines.append(f"Remediated:           {remediated}")
        lines.append(f"Failed:               {failed}")
        lines.append(f"Discarded:            {discarded}")
        lines.append(f"Requires human review:{human}")
        lines.append(f"Success rate:         {rate:.1f}%")
        lines.append("")
        lines.append("=" * 80)

        # Per-finding detail
        for i, r in enumerate(results, 1):
            v = r.vulnerability
            lines.append("")
            status_icon = {
                "success": "[OK]",
                "failed": "[FAIL]",
                "discarded": "[SKIP]",
                "requires_human_review": "[REVIEW]",
            }.get(r.final_status, "[?]")
            lines.append(f"{i}. {status_icon} {v.id} - {v.title}")
            lines.append(f"   Severity: {v.severity}  |  Host: {v.host}")
            lines.append(f"   Triage: risk={r.triage.risk_level}, remediate={r.triage.should_remediate}")

            if r.remediation:
                rm = r.remediation
                lines.append(
                    f"   Remedy: attempt #{rm.attempt_number}, scan_passed={rm.scan_passed}, "
                    f"cmds={len(rm.commands_executed)}, duration={rm.duration:.1f}s"
                )
                for cmd in rm.commands_executed:
                    lines.append(f"     - {cmd}")
                if rm.error_summary:
                    lines.append(f"   Error: {rm.error_summary}")

            if r.review:
                rv = r.review
                lines.append(
                    f"   Review: approve={rv.approve}, optimal={rv.is_optimal}, "
                    f"score={rv.security_score}"
                )
                if rv.feedback:
                    lines.append(f"   Feedback: {rv.feedback}")
                if rv.concerns:
                    lines.append(f"   Concerns: {', '.join(rv.concerns)}")

            if r.qa:
                qa = r.qa
                lines.append(
                    f"   QA: safe={qa.safe}, regression={qa.regression_detected}, "
                    f"recommendation={qa.recommendation}"
                )
                if qa.side_effects:
                    lines.append(f"   Side effects: {', '.join(qa.side_effects)}")

            lines.append(f"   Final: {r.final_status}  |  Duration: {r.total_duration:.1f}s")
            lines.append("-" * 80)

        report_path = self.output_dir / "pipeline_report.txt"
        report_path.write_text("\n".join(lines), encoding="utf-8")
        return str(report_path)

    # ------------------------------------------------------------------
    # PDF report
    # ------------------------------------------------------------------

    def _generate_pdf_report(self, results: List[FindingResult]) -> Optional[str]:
        """Generate a PDF report. Returns None if reportlab is not installed."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.utils import simpleSplit
            from reportlab.pdfgen import canvas
        except ImportError:
            return None

        pdf_path = self.output_dir / "pipeline_report.pdf"
        c = canvas.Canvas(str(pdf_path), pagesize=letter)
        width, height = letter
        margin = 50

        def _new_page() -> float:
            c.showPage()
            c.setFont("Helvetica", 10)
            return height - margin

        def _draw(text: str, x: float, y: float, max_w: float, lh: int = 14) -> float:
            for line in simpleSplit(text or "", "Helvetica", 10, max_w):
                if y < margin:
                    y = _new_page()
                c.drawString(x, y, line)
                y -= lh
            return y

        # Title page
        c.setTitle("Multi-Agent Pipeline Report")
        c.setFont("Helvetica-Bold", 18)
        c.drawString(margin, height - margin, "Multi-Agent Pipeline Report")
        c.setFont("Helvetica", 11)
        ts = datetime.now().isoformat(timespec="seconds")
        c.drawString(margin, height - margin - 24, f"Generated: {ts}")
        c.drawString(margin, height - margin - 40, f"Target: {self.target_host}")
        c.drawString(margin, height - margin - 56, f"Profile: {self.scan_profile}")

        total = len(results)
        remediated = sum(1 for r in results if r.final_status == "success")
        failed = sum(1 for r in results if r.final_status == "failed")
        rate = (remediated / total * 100) if total else 0.0

        y = height - margin - 90
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, "Summary")
        y -= 18
        c.setFont("Helvetica", 10)
        for label, val in [
            ("Processed", total),
            ("Remediated", remediated),
            ("Failed", failed),
            ("Success rate", f"{rate:.1f}%"),
        ]:
            c.drawString(margin + 10, y, f"{label}: {val}")
            y -= 16

        y = _new_page()

        # Per-finding pages
        for r in results:
            v = r.vulnerability
            c.setFont("Helvetica-Bold", 13)
            c.drawString(margin, y, f"{v.id} - {v.title}")
            y -= 18
            c.setFont("Helvetica", 10)
            y = _draw(f"Severity: {v.severity}  |  Status: {r.final_status}", margin, y, width - 2 * margin)

            if r.remediation:
                y -= 6
                c.setFont("Helvetica-Bold", 10)
                c.drawString(margin, y, "Remediation commands:")
                y -= 14
                c.setFont("Helvetica", 10)
                for cmd in r.remediation.commands_executed:
                    y = _draw(f"  - {cmd}", margin, y, width - 2 * margin)

            if r.review and r.review.feedback:
                y -= 6
                y = _draw(f"Review: {r.review.feedback}", margin, y, width - 2 * margin)

            if r.qa:
                y -= 6
                y = _draw(
                    f"QA: safe={r.qa.safe}, recommendation={r.qa.recommendation}",
                    margin, y, width - 2 * margin,
                )

            y -= 20
            if y < 120:
                y = _new_page()

        c.save()
        return str(pdf_path)
