"""
WorkerDisplay — Split-terminal view for concurrent pipeline workers.

Uses Rich's Live + Layout to show one panel per worker, each with its
own scrolling log.  A bottom panel shows overall progress.

Usage:
    from worker_display import worker_display, worker_print

    # At the start of main, before launching workers:
    worker_display.start(worker_names=["pam", "sysctl", "mount", "misc"])

    # Inside each worker thread:
    worker_display.set_worker("pam")
    worker_print("[green]doing stuff[/green]")  # routes to the "pam" panel

    # When done:
    worker_display.stop()
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Deque, Dict, List, Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text


_thread_local = threading.local()

# Max log lines to keep per worker panel
_MAX_LINES = 50

# Module-level fallback console for non-worker contexts
_fallback_console = Console()


class WorkerDisplay:
    """Manage a split-terminal Live display with per-worker panels."""

    def __init__(self) -> None:
        self._worker_names: List[str] = []
        self._logs: Dict[str, Deque[str]] = {}
        self._progress_text: str = ""
        self._lock = threading.Lock()
        self._live: Optional[Live] = None
        self._layout: Optional[Layout] = None
        self._active = False
        self._completed: Dict[str, int] = {}
        self._totals: Dict[str, int] = {}

    # ── Public API ───────────────────────────────────────────────────

    def start(self, worker_names: List[str], totals: Optional[Dict[str, int]] = None) -> None:
        """Start the live display with panels for each worker."""
        self._worker_names = list(worker_names)
        self._logs = {name: deque(maxlen=_MAX_LINES) for name in worker_names}
        self._completed = {name: 0 for name in worker_names}
        self._totals = totals or {name: 0 for name in worker_names}
        self._active = True

        self._layout = self._build_layout()
        self._live = Live(
            self._layout,
            console=_fallback_console,
            refresh_per_second=4,
            screen=False,
        )
        self._live.start()

    def stop(self) -> None:
        """Stop the live display."""
        if self._live:
            self._live.stop()
        self._active = False

    def set_worker(self, name: str) -> None:
        """Set the current thread's worker identity."""
        _thread_local.worker_name = name

    def get_worker(self) -> Optional[str]:
        """Get the current thread's worker name."""
        return getattr(_thread_local, "worker_name", None)

    def log(self, message: str, worker: Optional[str] = None) -> None:
        """Append a message to a worker's log panel.

        If *worker* is None, uses the current thread's worker context.
        Falls back to regular console.print if display not active.
        """
        if not self._active:
            _fallback_console.print(message)
            return

        wname = worker or self.get_worker()
        if wname is None or wname not in self._logs:
            _fallback_console.print(message)
            return

        # Strip the group tag prefix since the panel header already identifies the worker
        clean = self._strip_group_tag(message, wname)

        with self._lock:
            self._logs[wname].append(clean)
            self._refresh()

    def advance(self, worker: Optional[str] = None) -> None:
        """Mark one more finding as completed for a worker."""
        wname = worker or self.get_worker()
        if wname and wname in self._completed:
            with self._lock:
                self._completed[wname] += 1
                self._refresh()

    def set_progress_text(self, text: str) -> None:
        """Update the bottom progress text."""
        with self._lock:
            self._progress_text = text
            self._refresh()

    # ── Internal ─────────────────────────────────────────────────────

    def _strip_group_tag(self, msg: str, worker_name: str) -> str:
        """Remove the [group_name] dim tag prefix since panels already show worker name."""
        # The tag looks like: [dim]\[group_name][/dim]
        import re
        pattern = r'\[dim\]\\?\[' + re.escape(worker_name) + r'\]\[/dim\]\s*'
        return re.sub(pattern, '', msg)

    def _build_layout(self) -> Layout:
        """Build a layout with worker panels arranged in a grid."""
        layout = Layout()

        n = len(self._worker_names)
        if n == 0:
            return layout

        # Create worker panels
        # Arrange in rows of 2 for 2+ workers
        if n == 1:
            worker_layout = Layout(name=self._worker_names[0])
        elif n == 2:
            worker_layout = Layout()
            worker_layout.split_row(
                Layout(name=self._worker_names[0]),
                Layout(name=self._worker_names[1]),
            )
        elif n <= 4:
            worker_layout = Layout()
            top_row = Layout()
            top_names = self._worker_names[:2]
            top_row.split_row(*[Layout(name=w) for w in top_names])

            bot_names = self._worker_names[2:]
            if len(bot_names) == 1:
                bot_row = Layout(name=bot_names[0])
            else:
                bot_row = Layout()
                bot_row.split_row(*[Layout(name=w) for w in bot_names])

            worker_layout.split_column(top_row, bot_row)
        else:
            # More than 4: stack rows of 2
            rows = []
            for i in range(0, n, 2):
                chunk = self._worker_names[i:i + 2]
                if len(chunk) == 1:
                    rows.append(Layout(name=chunk[0]))
                else:
                    row = Layout()
                    row.split_row(*[Layout(name=w) for w in chunk])
                    rows.append(row)
            worker_layout = Layout()
            worker_layout.split_column(*rows)

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

        for wname in self._worker_names:
            lines = list(self._logs.get(wname, []))
            completed = self._completed.get(wname, 0)
            total = self._totals.get(wname, 0)

            # Build panel content from log lines
            if lines:
                # Show last lines that fit
                display_lines = lines[-20:]
                content = Text.from_markup("\n".join(display_lines))
            else:
                content = Text("Waiting...", style="dim")

            progress_str = f" [{completed}/{total}]" if total > 0 else ""
            panel = Panel(
                content,
                title=f"[bold]{wname}{progress_str}[/bold]",
                border_style="cyan",
                height=None,
            )

            try:
                self._layout[wname].update(panel)
            except KeyError:
                pass

        # Progress footer
        total_done = sum(self._completed.values())
        total_all = sum(self._totals.values())
        progress_msg = self._progress_text or f"Overall: {total_done}/{total_all} findings processed"
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
