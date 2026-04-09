"""
ShellCommandExecutor: Execute commands remotely via SSH.
Extracted from qa_agent_adaptive.py with added file operations for multi-agent system.
"""

import base64
import re
import shlex
import subprocess
import threading
import time
from typing import List, Optional, Tuple

from schemas import RunCommandResult


# ── Per-file lock manager ──────────────────────────────────────────────────

class FileLockManager:
    """Session-based per-path locking for concurrent workers.

    Each thread can open a *session* via ``session()``.  While the session
    is active, every call to ``acquire_paths()`` from that thread grabs
    locks for the given paths **and holds them** until the session ends.
    This protects read-modify-write sequences that span multiple SSH calls.

    Locks are always acquired in sorted path order to prevent deadlocks.

    Usage (inside ShellCommandExecutor):
        with self._file_locks.session():
            # These locks are held until the ``with`` block exits:
            self.read_file("/etc/login.defs")   # acquires lock
            # ... LLM thinks ...
            self.write_file("/etc/login.defs")  # lock already held, no-op
        # all locks released here
    """

    def __init__(self) -> None:
        self._master_lock = threading.Lock()          # protects _path_locks
        self._path_locks: dict[str, threading.Lock] = {}
        self._thread_held: threading.local = threading.local()  # per-thread state

    def _get_lock(self, path: str) -> threading.Lock:
        """Get or create the lock for *path* (thread-safe)."""
        with self._master_lock:
            if path not in self._path_locks:
                self._path_locks[path] = threading.Lock()
            return self._path_locks[path]

    # ── Session API ──────────────────────────────────────────────────

    def session(self) -> "_Session":
        """Return a context manager that starts a lock-holding session
        for the current thread."""
        return self._Session(self)

    def acquire_paths(self, paths: List[str]) -> None:
        """Acquire locks for *paths* within the current session.

        - Paths already held by this thread are skipped (no double-acquire).
        - New paths are acquired in sorted order to prevent deadlocks.
        - If there is no active session, this is a no-op so that commands
          outside a session still work (just without file locking).
        - If a lock is contended, a waiting message is shown in the worker
          display panel and a resume message is shown once acquired.
        """
        held: set[str] | None = getattr(self._thread_held, "paths", None)
        if held is None:
            # No active session — nothing to do
            return

        new_paths = sorted(set(p for p in paths if p and p not in held))
        if not new_paths:
            return

        from worker_display import worker_print

        for p in new_paths:
            lk = self._get_lock(p)
            # Try non-blocking first to avoid the log message on uncontended locks
            if lk.acquire(blocking=False):
                held.add(p)
                continue
            short = p.rsplit("/", 1)[-1]
            try:
                worker_print(
                    f"[bold yellow]  >> waiting on lock: {short}[/bold yellow]"
                )
            except Exception:
                pass
            t0 = time.time()
            acquired = lk.acquire(timeout=300)
            if acquired:
                held.add(p)
                try:
                    wait = time.time() - t0
                    worker_print(
                        f"[green]  >> lock acquired: {short} "
                        f"(waited {wait:.1f}s)[/green]"
                    )
                except Exception:
                    pass
            else:
                try:
                    worker_print(
                        f"[bold red]  >> lock timeout: {short} "
                        f"(300s) — proceeding unprotected[/bold red]"
                    )
                except Exception:
                    pass

    def _release_all(self) -> None:
        """Release every lock held by the current thread's session."""
        held: set[str] | None = getattr(self._thread_held, "paths", None)
        if not held:
            return
        # Release in sorted order (consistent with acquire order)
        for p in sorted(held):
            self._path_locks[p].release()
        held.clear()

    class _Session:
        """Context manager returned by ``FileLockManager.session()``."""

        def __init__(self, manager: "FileLockManager") -> None:
            self._mgr = manager

        def __enter__(self) -> "FileLockManager._Session":
            # Initialize the per-thread held-paths set
            self._mgr._thread_held.paths = set()
            return self

        def __exit__(self, *args: object) -> None:
            self._mgr._release_all()
            self._mgr._thread_held.paths = None


# ── Helpers to extract file paths from shell commands ──────────────────────

# Patterns that indicate a command writes to a file.
_WRITE_CMD_PATTERNS: List[re.Pattern[str]] = [
    # sed -i (with optional backup suffix like -i.bak)
    re.compile(r"\bsed\s+(?:.*\s)?-i(?:\S*)?\s+.*\s(/\S+)"),
    # echo/printf ... > /path  or  >> /path
    re.compile(r">{1,2}\s*(/\S+)"),
    # tee /path
    re.compile(r"\btee\s+(?:-a\s+)?(/\S+)"),
    # cp ... /path  (last arg)
    re.compile(r"\bcp\s+.*\s(/\S+)\s*$"),
    # mv ... /path  (last arg)
    re.compile(r"\bmv\s+.*\s(/\S+)\s*$"),
    # chmod / chown (modifies metadata)
    re.compile(r"\b(?:chmod|chown)\s+\S+\s+(/\S+)"),
    # install -m ... /path (last arg)
    re.compile(r"\binstall\s+.*\s(/\S+)\s*$"),
]

# Read-only patterns (we still want to lock reads to prevent reading mid-write).
_READ_CMD_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"\bcat\s+(/\S+)"),
    re.compile(r"\bgrep\s+.*\s(/\S+)\s*$"),
    re.compile(r"\bhead\s+.*(/\S+)"),
    re.compile(r"\btail\s+.*(/\S+)"),
]


def extract_file_paths(command: str) -> List[str]:
    """Best-effort extraction of file paths a shell command will touch."""
    paths: List[str] = []
    for pat in _WRITE_CMD_PATTERNS + _READ_CMD_PATTERNS:
        for m in pat.finditer(command):
            p = m.group(1)
            # Only keep absolute paths to avoid false positives on flags
            if p.startswith("/") and not p.startswith("/dev/"):
                paths.append(p)
    return paths


class ShellCommandExecutor:
    """Runs individual shell commands on the remote target over SSH."""

    def __init__(
        self,
        host: str,
        user: str,
        key: Optional[str],
        port: int = 22,
        sudo_password: Optional[str] = None,
        command_timeout: int = 120,
        max_output_chars: int = 8000,
    ) -> None:
        self.host = host
        self.user = user or "root"
        self.key = key
        self.port = port or 22
        self.sudo_password = sudo_password
        self.command_timeout = command_timeout
        self.max_output_chars = max_output_chars
        self._file_locks = FileLockManager()

    def hold_files(self) -> FileLockManager._Session:
        """Start a file-locking session for the current thread.

        While inside the returned context manager, every ``run_command``,
        ``read_file``, and ``write_file`` call automatically acquires
        per-path locks that are held until the context exits.  This
        protects read-modify-write sequences that span multiple SSH calls.

        Usage:
            with executor.hold_files():
                executor.read_file("/etc/login.defs")   # lock acquired
                # ... LLM decides what to change ...
                executor.write_file("/etc/login.defs", new)  # same lock held
            # all file locks released here
        """
        return self._file_locks.session()

    def _truncate(self, text: str) -> Tuple[str, bool]:
        if text and len(text) > self.max_output_chars:
            return text[: self.max_output_chars] + "\n...[truncated]...", True
        return text or "", False

    @staticmethod
    def _strip_ssh_banner(text: str) -> str:
        """Remove SSH login banners / MOTD noise from stderr so the LLM sees clean output."""
        if not text:
            return ""
        import re
        # Strip common SSH warnings
        text = re.sub(r"Warning: Permanently added .+ to the list of known hosts\.\n?", "", text)
        # Strip /etc/issue banner (login shell prints it to stderr)
        text = re.sub(r"\\S\nKernel \\r on an \\m \(\\l\)\n?", "", text)
        # Strip USG / DoD login banners (multi-line block starting with "You are accessing")
        text = re.sub(
            r"You are accessing a U\.S\. Government.*?(?=\n\n|\Z)",
            "",
            text,
            flags=re.DOTALL,
        )
        return text.strip()

    def _build_ssh_cmd(self) -> list:
        cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ServerAliveInterval=30",
            "-o",
            "ServerAliveCountMax=5",
            "-p",
            str(self.port),
        ]
        if self.key:
            cmd.extend(["-i", self.key])
        cmd.append(f"{self.user}@{self.host}")
        return cmd

    def _remote_shell_command(self, command: str) -> str:
        """Wrap the requested command so it runs as root on the remote host."""
        base = f"bash -lc {shlex.quote(command)}"
        if self.user == "root":
            return base
        if self.sudo_password:
            quoted_pw = shlex.quote(self.sudo_password)
            return f"echo {quoted_pw} | sudo -S {base}"
        return f"sudo -n {base}"

    def run_command(self, command: str) -> RunCommandResult:
        """Execute a single shell command remotely via SSH.

        If called inside a ``hold_files()`` context, file paths are
        automatically added to the session lock set.  Otherwise the command
        runs without file-level locking.
        """
        if not command:
            return RunCommandResult(
                command="",
                stdout="",
                stderr="No command provided",
                exit_code=None,
                success=False,
                duration=0.0,
                timed_out=False,
            )

        # If inside a session, extend the session's held locks
        paths = extract_file_paths(command)
        self._file_locks.acquire_paths(paths)

        return self._run_command_unlocked(command)

    def _run_command_unlocked(self, command: str) -> RunCommandResult:
        """Execute a single shell command remotely."""
        remote_command = self._remote_shell_command(command)
        ssh_cmd = self._build_ssh_cmd() + [remote_command]

        start = time.time()
        stdout = ""
        stderr = ""
        exit_code: Optional[int] = None
        success = False
        timed_out = False

        try:
            completed = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=self.command_timeout,
                encoding="utf-8",
                errors="replace",
            )
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            exit_code = completed.returncode
            success = exit_code == 0
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = (exc.stderr or "") + f"\nCommand timed out after {self.command_timeout} seconds."
            timed_out = True
        except FileNotFoundError as exc:
            stderr = f"SSH binary not found: {exc}"
        finally:
            duration = time.time() - start

        stdout, stdout_truncated = self._truncate(stdout)
        stderr = self._strip_ssh_banner(stderr)
        stderr, stderr_truncated = self._truncate(stderr)

        return RunCommandResult(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            success=success,
            duration=duration,
            timed_out=timed_out,
            truncated_stdout=stdout_truncated,
            truncated_stderr=stderr_truncated,
        )

    def write_file(self, file_path: str, content: str, mode: Optional[str] = None) -> RunCommandResult:
        """
        Write content to a remote file using base64 encoding to avoid shell escaping issues.
        Uses temp-file + mv for atomic write. Optionally chmod.
        """
        self._file_locks.acquire_paths([file_path])

        content_b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        target = shlex.quote(file_path)
        tmp = shlex.quote(f"{file_path}.tmp")

        # one remote command (still a single bash -lc string)
        cmd_parts = [
            f"echo {shlex.quote(content_b64)} | base64 -d > {tmp}",
        ]
        if mode:
            cmd_parts.append(f"chmod {shlex.quote(mode)} {tmp}")
        cmd_parts.append(f"mv {tmp} {target}")

        command = " && ".join(cmd_parts)
        # NOTE: your existing system prompt forbids chaining with && for LLM-issued commands,
        # but this is an internal helper tool. It’s okay as a tool implementation.
        result = self._run_command_unlocked(command)
        return result

    def read_file(self, file_path: str) -> RunCommandResult:
        """Read a remote file. Returns a clear error if file is missing."""
        self._file_locks.acquire_paths([file_path])
        path = shlex.quote(file_path)
        command = f"test -f {path} && cat {path} || (echo FILE_NOT_FOUND >&2; exit 2)"
        return self._run_command_unlocked(command)