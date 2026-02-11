# TODO: Extract ShellCommandExecutor from qa_agent_adaptive.py and add file operations
#
# This module should provide:
# 1. Extract ShellCommandExecutor class (lines 1063-1170 from qa_agent_adaptive.py)
# 2. Add write_file() method for Remedy Agent's "write_file" tool
# 3. Add read_file() method for Remedy Agent's "read_file" tool
# 4. Keep existing run_command() method for "run_cmd" tool
# 5. Reusable by all agents (Remedy, QA)
#
# Example interface:
# class ShellCommandExecutor:
#     def __init__(self, host: str, username: str, password: Optional[str] = None, ...):
#         # SSH connection setup
#
#     def run_command(self, command: str) -> RunCommandResult:
#         """Execute a shell command remotely via SSH"""
#         pass
#
#     def write_file(self, file_path: str, content: str) -> RunCommandResult:
#         """Write content to a remote file (cat > file or echo > file)"""
#         pass
#
#     def read_file(self, file_path: str) -> RunCommandResult:
#         """Read a remote file (cat file)"""
#         pass