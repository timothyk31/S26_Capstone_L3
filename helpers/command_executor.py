"""
ShellCommandExecutor: Execute commands remotely via SSH.
Extracted from qa_agent_adaptive.py with added file operations for multi-agent system.
"""

import base64
import shlex
import subprocess
import time
from typing import Optional, Tuple

from schemas import RunCommandResult


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
        # Strip USG / DoD login banners (multi-line block starting with "You are accessing")
        text = re.sub(
            r"You are accessing a U\.S\. Government.*?See User\s*\nAgreement for details\.\n?",
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
        """Execute a single shell command remotely via SSH."""
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
        result = self.run_command(command)
        return result

    def read_file(self, file_path: str) -> RunCommandResult:
        """Read a remote file. Returns a clear error if file is missing."""
        path = shlex.quote(file_path)
        command = f"test -f {path} && cat {path} || (echo FILE_NOT_FOUND >&2; exit 2)"
        return self.run_command(command)