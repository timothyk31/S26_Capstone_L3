"""
ConcurrentManager — Run multiple Pipeline instances concurrently.

Default: 4 concurrent workflows sharing the same VM resource.
Uses ThreadPoolExecutor for simplicity (SSH connections are thread-safe).
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from schemas import FindingResult, Vulnerability
from workflow.pipeline import Pipeline

console = Console()


class ConcurrentManager:
    """
    Manage concurrent Pipeline executions.

    Each vulnerability is submitted to a thread pool.  Results are
    collected as they complete, and a progress bar keeps the user
    informed.
    """

    def __init__(
        self,
        pipeline_factory: Callable[[], Pipeline],
        *,
        max_concurrent: int = 4,
    ):
        """
        Args:
            pipeline_factory: Callable that creates a fresh Pipeline instance.
                              Each thread gets its own Pipeline to avoid
                              shared-state issues.
            max_concurrent: Maximum number of pipelines running in parallel.
        """
        self.pipeline_factory = pipeline_factory
        self.max_concurrent = max_concurrent

    def run_all(self, vulnerabilities: List[Vulnerability]) -> List[FindingResult]:
        """
        Run all vulnerabilities through the pipeline with concurrency.

        Returns results sorted in original vulnerability order.
        """
        if not vulnerabilities:
            console.print("[yellow]No vulnerabilities to process.[/yellow]")
            return []

        total = len(vulnerabilities)
        console.print(
            f"\n[bold cyan]── Running pipeline for {total} finding(s) "
            f"({self.max_concurrent} concurrent) ──[/bold cyan]\n"
        )

        results: List[FindingResult] = []
        t0 = time.time()

        # ── Sequential path (single worker) ───────────────────────────
        if self.max_concurrent <= 1:
            pipeline = self.pipeline_factory()
            with self._progress_bar(total) as (progress, task):
                for vuln in vulnerabilities:
                    result = self._safe_run(pipeline, vuln)
                    results.append(result)
                    progress.advance(task)
            return results

        # ── Concurrent path ───────────────────────────────────────────
        # Build an order map so we can sort results back to input order
        order = {v.id: i for i, v in enumerate(vulnerabilities)}

        with self._progress_bar(total) as (progress, task):
            with ThreadPoolExecutor(max_workers=self.max_concurrent) as pool:
                future_map = {}
                for vuln in vulnerabilities:
                    fut = pool.submit(self._run_in_thread, vuln)
                    future_map[fut] = vuln

                for fut in as_completed(future_map):
                    vuln = future_map[fut]
                    try:
                        result = fut.result()
                    except Exception as exc:
                        console.print(
                            f"[red]Pipeline crashed for {vuln.id}: {exc}[/red]"
                        )
                        from datetime import datetime
                        from schemas import TriageDecision

                        result = FindingResult(
                            vulnerability=vuln,
                            triage=TriageDecision(
                                finding_id=vuln.id,
                                should_remediate=False,
                                risk_level="medium",
                                reason=f"Pipeline crash: {exc}",
                                requires_human_review=True,
                            ),
                            final_status="failed",
                            total_duration=0.0,
                            timestamp=datetime.now().isoformat(timespec="seconds"),
                        )
                    results.append(result)
                    progress.advance(task)

        # Sort back to original order
        results.sort(key=lambda r: order.get(r.vulnerability.id, 999))

        elapsed = time.time() - t0
        console.print(
            f"\n[bold green]── All {total} finding(s) processed in {elapsed:.1f}s ──[/bold green]\n"
        )
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_in_thread(self, vuln: Vulnerability) -> FindingResult:
        """Create a dedicated Pipeline per thread and run."""
        pipeline = self.pipeline_factory()
        return self._safe_run(pipeline, vuln)

    @staticmethod
    def _safe_run(pipeline: Pipeline, vuln: Vulnerability) -> FindingResult:
        """Run pipeline with top-level exception safety."""
        try:
            return pipeline.run(vuln)
        except Exception as exc:
            from datetime import datetime
            from schemas import TriageDecision

            console.print(f"[red]Pipeline error for {vuln.id}: {exc}[/red]")
            return FindingResult(
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

    def _progress_bar(self, total: int):
        """Return a Rich progress bar context manager."""
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        )
        task = progress.add_task("Processing findings...", total=total)
        return _ProgressContext(progress, task)


class _ProgressContext:
    """Thin wrapper so we can use `with mgr._progress_bar(n) as (p, t)`."""

    def __init__(self, progress, task):
        self.progress = progress
        self.task = task

    def __enter__(self):
        self.progress.__enter__()
        return self.progress, self.task

    def __exit__(self, *args):
        return self.progress.__exit__(*args)