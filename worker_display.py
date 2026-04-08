"""
WorkerDisplay — Split-terminal view for concurrent pipeline workers.

Uses Rich's Live + Layout to show one panel per worker thread, each with
its own scrolling log.  A bottom panel shows overall progress.

Usage:
    from worker_display import worker_display, worker_print

    # At the start of main, before launching workers:
    worker_display.start(num_workers=4, total_findings=59)

    # Inside each worker thread (called automatically via assign_worker):
    wid = worker_display.assign_worker("pam")   # gets "Worker 1", etc.
    worker_print("[green]doing stuff[/green]")   # routes to that panel

    # When done:
    worker_display.stop()
"""

from __future__ import annotations

import io
import re
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Deque, Dict, List, Optional

from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.text import Text


_thread_local = threading.local()

# Max log lines to keep per worker panel
_MAX_LINES = 200

# Module-level fallback console for non-worker contexts
_fallback_console = Console()


class WorkerDisplay:
    """Manage a split-terminal Live display with per-worker-thread panels."""

    def __init__(self) -> None:
        self._num_workers: int = 0
        self._worker_ids: List[str] = []          # ["Worker 1", "Worker 2", ...]
        self._logs: Dict[str, Deque[str]] = {}
        self._group_labels: Dict[str, str] = {}   # worker_id -> current group name
        self._progress_text: str = ""
        self._lock = threading.Lock()
        self._live: Optional[Live] = None
        self._layout: Optional[Layout] = None
        self._active = False
        self._total_completed: int = 0
        self._total_findings: int = 0
        # Per-worker progress
        self._worker_completed: Dict[str, int] = {}
        self._worker_total: Dict[str, int] = {}
        # Thread-to-worker assignment
        self._next_worker_idx: int = 0
        self._thread_worker_map: Dict[int, str] = {}   # thread_id -> worker_id
        # Log file
        self._log_file: Optional[io.TextIOWrapper] = None
        self._log_path: Optional[Path] = None

    # ── Public API ───────────────────────────────────────────────────

    def start(
        self,
        num_workers: int,
        total_findings: int = 0,
        log_dir: str = "pipeline_work",
    ) -> None:
        """Start the live display with N worker panels in a single row."""
        self._num_workers = num_workers
        self._worker_ids = [f"Worker {i + 1}" for i in range(num_workers)]
        self._logs = {wid: deque(maxlen=_MAX_LINES) for wid in self._worker_ids}
        self._group_labels = {wid: "" for wid in self._worker_ids}
        self._total_completed = 0
        self._total_findings = total_findings
        self._worker_completed = {wid: 0 for wid in self._worker_ids}
        self._worker_total = {wid: 0 for wid in self._worker_ids}
        self._next_worker_idx = 0
        self._thread_worker_map = {}
        self._active = True

        # Open a log file so all worker output is preserved after the run
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._log_path = log_path / f"worker_log_{ts}.txt"
        self._log_file = open(self._log_path, "w", encoding="utf-8")

        self._layout = self._build_layout()
        self._console = Console()
        self._live = Live(
            self._layout,
            console=self._console,
            refresh_per_second=4,
            screen=True,
        )
        self._live.start()

    def stop(self) -> None:
        """Stop the live display and close the log file."""
        if self._live:
            self._live.stop()
        self._active = False
        if self._log_file:
            self._log_file.close()
            self._log_file = None
        if self._log_path:
            _fallback_console.print(f"[green]Worker log: {self._log_path}[/green]")

    def assign_worker(self, group_name: str, num_findings: int = 0) -> str:
        """Assign the current thread to a worker slot and set its group label.

        Called at the start of _process_group.  The same thread keeps the
        same worker slot even if it processes multiple groups sequentially.
        *num_findings* is added to that worker's total for progress tracking.
        Returns the worker ID (e.g. "Worker 1").
        """
        tid = threading.get_ident()
        with self._lock:
            if tid not in self._thread_worker_map:
                wid = self._worker_ids[self._next_worker_idx % self._num_workers]
                self._next_worker_idx += 1
                self._thread_worker_map[tid] = wid
            else:
                wid = self._thread_worker_map[tid]
            self._group_labels[wid] = group_name
            self._worker_total[wid] += num_findings
            self._refresh()
        _thread_local.worker_id = wid
        return wid

    def update_group(self, group_name: str) -> None:
        """Update the current worker's group label (when it moves to a new group)."""
        wid = getattr(_thread_local, "worker_id", None)
        if wid:
            with self._lock:
                self._group_labels[wid] = group_name
                self._refresh()

    def get_worker(self) -> Optional[str]:
        """Get the current thread's worker ID."""
        return getattr(_thread_local, "worker_id", None)

    def log(self, message: str, worker: Optional[str] = None) -> None:
        """Append a message to a worker's log panel.

        If *worker* is None, uses the current thread's worker context.
        Falls back to regular console.print if display not active.
        """
        if not self._active:
            _fallback_console.print(message)
            return

        wid = worker or self.get_worker()
        if wid is None or wid not in self._logs:
            _fallback_console.print(message)
            return

        # Strip the group tag prefix since the panel header already shows it
        clean = self._strip_group_tag(message)

        with self._lock:
            self._logs[wid].append(clean)
            # Write to log file with timestamp and worker ID (plain text, no markup)
            if self._log_file:
                ts = datetime.now().strftime("%H:%M:%S")
                plain = re.sub(r'\[/?[^\]]*\]', '', clean)
                self._log_file.write(f"[{ts}] {wid} | {plain}\n")
                self._log_file.flush()
            self._refresh()

    def advance(self) -> None:
        """Mark one more finding as completed for the current worker and overall."""
        wid = self.get_worker()
        with self._lock:
            self._total_completed += 1
            if wid and wid in self._worker_completed:
                self._worker_completed[wid] += 1
            self._refresh()

    def set_progress_text(self, text: str) -> None:
        """Update the bottom progress text."""
        with self._lock:
            self._progress_text = text
            self._refresh()

    # ── Internal ─────────────────────────────────────────────────────

    def _strip_group_tag(self, msg: str) -> str:
        """Remove the [dim]\\[group_name][/dim] prefix — panel title shows the group."""
        return re.sub(r'\[dim\]\\?\[[^\]]*\]\[/dim\]\s*', '', msg)

    def _build_layout(self) -> Layout:
        """Build a layout with worker panels in a single row (N columns x 1 row)."""
        layout = Layout()

        if self._num_workers == 0:
            return layout

        # All workers side-by-side in one row
        worker_layout = Layout()
        worker_layout.split_row(
            *[Layout(name=wid) for wid in self._worker_ids]
        )

        # Add a small progress footer
        layout.split_column(
            worker_layout,
            Layout(name="progress", size=3),
        )

        # Initial render
        self._render_panels()
        return layout

    def _render_panels(self) -> None:
        """Re-render all panels with current log content."""
        if not self._layout:
            return

        for wid in self._worker_ids:
            lines = list(self._logs.get(wid, []))
            group = self._group_labels.get(wid, "")
            completed = self._worker_completed.get(wid, 0)
            total = self._worker_total.get(wid, 0)

            # Per-worker progress bar
            parts: list = []
            if total > 0:
                bar_width = 20
                filled = int(bar_width * completed / total) if total else 0
                bar = "━" * filled + "╺" + "─" * (bar_width - filled - 1) if filled < bar_width else "━" * bar_width
                parts.append(Text.from_markup(
                    f"[green]{bar}[/green]  {completed}/{total}  "
                ))

            # Log lines — only show the most recent lines that fit the panel
            if lines:
                try:
                    import shutil
                    term_h = shutil.get_terminal_size().lines
                except Exception:
                    term_h = 40
                # Reserve lines for: panel border (2), progress bar (1), progress footer (3)
                max_visible = max(term_h - 6, 5)
                visible_lines = lines[-max_visible:]
                parts.append(Text.from_markup("\n".join(visible_lines)))
            elif not total:
                parts.append(Text("Waiting...", style="dim"))

            content = Group(*parts) if len(parts) > 1 else (parts[0] if parts else Text("Waiting...", style="dim"))

            subtitle = f"[dim]{group}[/dim]" if group else ""
            panel = Panel(
                content,
                title=f"[bold]{wid}[/bold]",
                subtitle=subtitle,
                border_style="cyan",
                height=None,
            )

            try:
                self._layout[wid].update(panel)
            except KeyError:
                pass

        # Progress footer
        progress_msg = (
            self._progress_text
            or f"Overall: {self._total_completed}/{self._total_findings} findings processed"
        )
        try:
            self._layout["progress"].update(
                Panel(Text(progress_msg), border_style="green", title="Progress")
            )
        except KeyError:
            pass

    def _refresh(self) -> None:
        """Refresh the live display."""
        self._render_panels()
        if self._live:
            self._live.refresh()


# ── Module-level singleton and convenience function ──────────────────

worker_display = WorkerDisplay()


def worker_print(message: str) -> None:
    """Print to the current worker's panel, or fallback to console."""
    worker_display.log(message)
