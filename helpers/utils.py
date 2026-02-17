"""
Utility functions for multi-agent system.
Extracted from qa_agent_adaptive.py.
"""

from typing import Any, Dict, List


def normalize_command(command: str) -> str:
    """
    Normalize obvious LLM command issues.

    - Convert Debianisms (apt/apt-get) to dnf on Rocky/RHEL
    - Avoid legacy `service` invocations when a clear systemd unit is present

    Args:
        command: Raw command from LLM

    Returns:
        Normalized command suitable for Rocky Linux/RHEL
    """
    cmd = command.strip()
    lower = cmd.lower()

    # Debian package manager → dnf
    if lower.startswith("apt-get ") or lower.startswith("apt "):
        # Simple heuristic: swap apt/apt-get with dnf
        parts = cmd.split(maxsplit=1)
        if parts:
            verb_rest = parts[1] if len(parts) > 1 else ""
            cmd = f"dnf {verb_rest}".strip()
            lower = cmd.lower()

    # Very simple `service` → `systemctl` mapping for common operations
    # e.g., service sshd restart → systemctl restart sshd
    if lower.startswith("service "):
        parts = cmd.split()
        if len(parts) >= 3:
            _, svc, action = parts[0], parts[1], parts[2]
            if action in ("start", "stop", "restart", "reload"):
                cmd = f"systemctl {action} {svc}"

    return cmd


def annotate_error_categories(
    command: str, stdout: str, stderr: str, exit_code: int, success: bool
) -> List[str]:
    """
    Tag command result with heuristic error categories.

    Args:
        command: Command that was executed
        stdout: Standard output
        stderr: Standard error
        exit_code: Process exit code
        success: Whether command succeeded

    Returns:
        List of error category strings (empty if success)
    """
    if success:
        return []

    stderr_lower = (stderr or "").lower()
    stdout_lower = (stdout or "").lower()
    cmd_lower = command.lower()

    categories: List[str] = []

    # Service restart refused (common with auditd)
    if "systemctl" in cmd_lower and "restart" in cmd_lower:
        if "refused" in stderr_lower or "operation refused" in stderr_lower:
            categories.append("service_restart_refused")

    # Permission denied
    if "permission denied" in stderr_lower or "operation not permitted" in stderr_lower:
        categories.append("permission_denied")
        if "/etc/cron.d" in cmd_lower or "/etc/cron.d" in stderr_lower:
            categories.append("cron_system_file_protected")

    # Syntax error
    if "syntax error" in stderr_lower:
        categories.append("syntax_error")

    # Command not found
    if "command not found" in stderr_lower or "not found" in stderr_lower:
        categories.append("command_not_found")

    # Package not found
    if "no match for argument" in stderr_lower or "no package" in stderr_lower:
        categories.append("package_not_found")

    # Service not found
    if "unit" in stderr_lower and ("not found" in stderr_lower or "could not be found" in stderr_lower):
        categories.append("service_not_found")

    # Default if no specific category
    if not categories:
        categories.append("command_failed")

    return categories