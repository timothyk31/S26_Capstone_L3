from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import yaml
from pydantic import BaseModel

class AnsibleTask(BaseModel):
    """Represents a single Ansible task"""
    name: str
    module: str
    params: Dict[str, Any]
    when: Optional[str] = None
    become: bool = True
    tags: List[str] = []

class RemediationPlaybook(BaseModel):
    """Represents an Ansible playbook for remediation"""
    name: str
    hosts: str = "all"
    become: bool = True
    tasks: List[AnsibleTask]
    vars: Dict[str, Any] = {}
    
    def to_yaml(self) -> str:
        """Convert playbook to YAML format"""
        playbook_dict = [{
            "name": self.name,
            "hosts": self.hosts,
            "become": self.become,
            "vars": self.vars,
            "tasks": [
                {
                    "name": task.name,
                    "become": task.become,
                    **{task.module: task.params},
                    **({"when": task.when} if task.when else {}),
                    **({"tags": task.tags} if task.tags else {})
                }
                for task in self.tasks
            ]
        }]
        return yaml.dump(playbook_dict, sort_keys=False)

class VulnerabilityRemediation:
    """Maps vulnerabilities to Ansible remediation tasks"""
    
    def __init__(self, vuln_data_path: Path):
        self.vuln_data_path = vuln_data_path
        self.remediation_templates = {
            # Package vulnerabilities
            "outdated_package": lambda pkg: AnsibleTask(
                name=f"Update {pkg} to latest version",
                module="package",
                params={"name": pkg, "state": "latest"}
            ),
            # Service configuration
            "service_config": lambda svc, cfg: AnsibleTask(
                name=f"Configure {svc} service",
                module="template",
                params={"src": cfg["template"], "dest": cfg["path"]}
            ),
            # Firewall rules
            "firewall_rule": lambda rule: AnsibleTask(
                name=f"Configure firewall rule: {rule['description']}",
                module="iptables",
                params=rule
            ),
            # File permissions
            "file_permission": lambda path, mode: AnsibleTask(
                name=f"Set correct permissions for {path}",
                module="file",
                params={"path": path, "mode": mode}
            )
        }

    def load_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Load vulnerability data from file"""
        return json.loads(self.vuln_data_path.read_text())

    def create_remediation_task(self, vuln: Dict[str, Any]) -> Optional[AnsibleTask]:
        """Create an Ansible task for a specific vulnerability"""
        # Example vulnerability classification logic
        if "package" in vuln.get("title", "").lower():
            pkg_name = self._extract_package_name(vuln)
            if pkg_name:
                return self.remediation_templates["outdated_package"](pkg_name)
        
        if "configuration" in vuln.get("title", "").lower():
            service = self._extract_service_name(vuln)
            if service:
                config = self._get_service_config(service)
                if config:
                    return self.remediation_templates["service_config"](service, config)
        
        return None

    def generate_playbook(self, vulns: List[Dict[str, Any]], playbook_name: str) -> RemediationPlaybook:
        """Generate an Ansible playbook for a list of vulnerabilities"""
        tasks: List[AnsibleTask] = []
        
        for vuln in vulns:
            task = self.create_remediation_task(vuln)
            if task:
                # Add vulnerability info as tags
                task.tags.extend([
                    f"vuln_id_{vuln.get('id', 'unknown')}",
                    f"severity_{vuln.get('severity', 'unknown')}"
                ])
                tasks.append(task)
        
        return RemediationPlaybook(
            name=playbook_name,
            tasks=tasks,
            vars={
                "ansible_python_interpreter": "/usr/bin/python3"
            }
        )

    def _extract_package_name(self, vuln: Dict[str, Any]) -> Optional[str]:
        """Extract package name from vulnerability data"""
        title = vuln.get("title", "").lower()
        if "package" in title:
            # Example: "outdated apache2 package"
            words = title.split()
            idx = words.index("package")
            if idx > 0:
                return words[idx - 1]
        return None

    def _extract_service_name(self, vuln: Dict[str, Any]) -> Optional[str]:
        """Extract service name from vulnerability data"""
        title = vuln.get("title", "").lower()
        common_services = ["ssh", "apache", "nginx", "mysql", "postgresql"]
        for service in common_services:
            if service in title:
                return service
        return None

    def _get_service_config(self, service: str) -> Optional[Dict[str, str]]:
        """Get service configuration template details"""
        configs = {
            "ssh": {
                "template": "templates/ssh/sshd_config.j2",
                "path": "/etc/ssh/sshd_config"
            },
            "apache": {
                "template": "templates/apache/apache2.conf.j2",
                "path": "/etc/apache2/apache2.conf"
            }
        }
        return configs.get(service)

def main():
    """Main function for testing"""
    # Example usage
    vuln_file = Path("parsed_vulns.json")
    if not vuln_file.exists():
        print(f"Vulnerability file not found: {vuln_file}")
        return

    qa = VulnerabilityRemediation(vuln_file)
    vulns = qa.load_vulnerabilities()
    playbook = qa.generate_playbook(vulns, "Vulnerability Remediation")
    
    # Write playbook to file
    output_file = Path("remediation_playbook.yml")
    output_file.write_text(playbook.to_yaml())
    print(f"Generated Ansible playbook: {output_file}")

if __name__ == "__main__":
    main()
