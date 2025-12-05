from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import re

from schemas import RemediationSuggestion, Vulnerability
from qa_framework import AnsibleTask, RemediationPlaybook, VulnerabilityRemediation

class RemediationBridge:
    """Bridge between LLM remediation suggestions and Ansible automation"""
    
    def __init__(self):
        self.command_patterns = {
            # Package management
            r"apt(-get)?\s+install\s+(.+)": lambda m: AnsibleTask(
                name=f"Install package {m.group(2)}",
                module="apt",
                params={"name": m.group(2), "state": "present"}
            ),
            r"apt(-get)?\s+update\s+(.+)": lambda m: AnsibleTask(
                name=f"Update package {m.group(2)}",
                module="apt",
                params={"name": m.group(2), "state": "latest"}
            ),
            
            # Service management
            r"systemctl\s+(start|stop|restart)\s+(.+)": lambda m: AnsibleTask(
                name=f"{m.group(1).capitalize()} service {m.group(2)}",
                module="systemd",
                params={"name": m.group(2), "state": m.group(1)}
            ),
            
            # File operations
            r"chmod\s+([0-9]+)\s+(.+)": lambda m: AnsibleTask(
                name=f"Set permissions on {m.group(2)}",
                module="file",
                params={"path": m.group(2), "mode": m.group(1)}
            ),
            
            # Configuration files
            r"echo\s+['\"](.*?)['\"].*?>>\s+(.+)": lambda m: AnsibleTask(
                name=f"Add configuration to {m.group(2)}",
                module="lineinfile",
                params={
                    "path": m.group(2),
                    "line": m.group(1),
                    "create": True
                }
            ),
        }

    def parse_command(self, command: str) -> Optional[AnsibleTask]:
        """Convert a shell command to an Ansible task"""
        for pattern, task_generator in self.command_patterns.items():
            match = re.match(pattern, command.strip())
            if match:
                return task_generator(match)
        return None

    def convert_to_ansible_tasks(self, suggestion: RemediationSuggestion) -> List[AnsibleTask]:
        """Convert remediation suggestions to Ansible tasks"""
        tasks: List[AnsibleTask] = []
        
        for command in suggestion.proposed_commands:
            # Skip comments
            if command.strip().startswith('#'):
                continue
                
            task = self.parse_command(command)
            if task:
                # Add vulnerability ID as a tag
                task.tags = [f"vuln_{suggestion.id}"]
                tasks.append(task)
            else:
                # Fallback: use command module
                # Note: Adding notes to task name for visibility
                task_name = f"Execute remediation for {suggestion.id}"
                if suggestion.notes:
                    task_name += f" - {suggestion.notes[:50]}"
                tasks.append(AnsibleTask(
                    name=task_name,
                    module="shell",
                    params={"cmd": command, "executable": "/bin/bash"},
                    tags=[f"vuln_{suggestion.id}"]
                ))
        
        return tasks

    def create_playbook(self, 
                       suggestions: List[RemediationSuggestion],
                       vulns: List[Vulnerability],
                       playbook_name: str = "Security Remediation") -> RemediationPlaybook:
        """Create an Ansible playbook from remediation suggestions"""
        all_tasks: List[AnsibleTask] = []
        
        # Group suggestions by host
        host_suggestions: Dict[str, List[RemediationSuggestion]] = {}
        for sugg, vuln in zip(suggestions, vulns):
            if vuln.host not in host_suggestions:
                host_suggestions[vuln.host] = []
            host_suggestions[vuln.host].append(sugg)
        
        # Create tasks for each host
        for host, host_suggs in host_suggestions.items():
            for sugg in host_suggs:
                tasks = self.convert_to_ansible_tasks(sugg)
                for task in tasks:
                    task.when = f"inventory_hostname == '{host}'"
                all_tasks.extend(tasks)
        
        return RemediationPlaybook(
            name=playbook_name,
            hosts="all",  # Use inventory to control host selection
            tasks=all_tasks,
            vars={
                "ansible_python_interpreter": "/usr/bin/python3",
                "ansible_become": True
            }
        )

def main():
    """Example usage"""
    # Load LLM remediation suggestions
    with open("remediations.json") as f:
        suggestions = [RemediationSuggestion(**s) for s in json.load(f)]
    
    # Load original vulnerabilities
    with open("parsed_vulns.json") as f:
        vulns = [Vulnerability(**v) for v in json.load(f)]
    
    # Create bridge and generate playbook
    bridge = RemediationBridge()
    playbook = bridge.create_playbook(suggestions, vulns)
    
    # Write playbook
    output_file = Path("remediation_playbook.yml")
    output_file.write_text(playbook.to_yaml())
    print(f"Generated Ansible playbook: {output_file}")

if __name__ == "__main__":
    main()



