import pytest
from pathlib import Path
import json
import yaml
from qa_framework import VulnerabilityRemediation, AnsibleTask, RemediationPlaybook

@pytest.fixture
def sample_vulnerabilities():
    return [
        {
            "id": "test-001",
            "title": "Outdated apache2 package",
            "severity": "high",
            "description": "The installed version of apache2 is outdated and contains known vulnerabilities.",
            "recommendation": "Update apache2 to the latest version"
        },
        {
            "id": "test-002",
            "title": "SSH Configuration Issue",
            "severity": "medium",
            "description": "SSH service is configured to allow weak ciphers",
            "recommendation": "Update SSH configuration to use strong ciphers only"
        }
    ]

@pytest.fixture
def vuln_file(tmp_path, sample_vulnerabilities):
    """Create a temporary vulnerability file"""
    vuln_file = tmp_path / "test_vulns.json"
    vuln_file.write_text(json.dumps(sample_vulnerabilities))
    return vuln_file

@pytest.fixture
def qa_framework(vuln_file):
    """Create QA framework instance"""
    return VulnerabilityRemediation(vuln_file)

def test_load_vulnerabilities(qa_framework, sample_vulnerabilities):
    """Test loading vulnerabilities from file"""
    loaded_vulns = qa_framework.load_vulnerabilities()
    assert loaded_vulns == sample_vulnerabilities

def test_package_remediation(qa_framework):
    """Test package vulnerability remediation"""
    vuln = {
        "id": "test-001",
        "title": "Outdated apache2 package",
        "severity": "high"
    }
    
    task = qa_framework.create_remediation_task(vuln)
    assert task is not None
    assert task.module == "package"
    assert task.params["name"] == "apache2"
    assert task.params["state"] == "latest"

def test_service_config_remediation(qa_framework):
    """Test service configuration remediation"""
    vuln = {
        "id": "test-002",
        "title": "SSH Configuration Issue",
        "severity": "medium"
    }
    
    task = qa_framework.create_remediation_task(vuln)
    assert task is not None
    assert task.module == "template"
    assert "sshd_config" in task.params["dest"]

def test_playbook_generation(qa_framework, sample_vulnerabilities):
    """Test generating complete playbook"""
    playbook = qa_framework.generate_playbook(sample_vulnerabilities, "Test Remediation")
    
    assert isinstance(playbook, RemediationPlaybook)
    assert len(playbook.tasks) > 0
    
    # Convert to YAML and verify structure
    yaml_content = playbook.to_yaml()
    playbook_dict = yaml.safe_load(yaml_content)
    
    assert isinstance(playbook_dict, list)
    assert len(playbook_dict) == 1
    assert playbook_dict[0]["name"] == "Test Remediation"
    assert "tasks" in playbook_dict[0]

def test_task_tags(qa_framework, sample_vulnerabilities):
    """Test that tasks have appropriate vulnerability tags"""
    playbook = qa_framework.generate_playbook(sample_vulnerabilities, "Test Remediation")
    
    for task in playbook.tasks:
        assert any(tag.startswith("vuln_id_") for tag in task.tags)
        assert any(tag.startswith("severity_") for tag in task.tags)

def test_invalid_vulnerability(qa_framework):
    """Test handling of invalid vulnerability data"""
    vuln = {
        "id": "test-003",
        "title": "Unknown Issue",
        "severity": "low"
    }
    
    task = qa_framework.create_remediation_task(vuln)
    assert task is None  # Should return None for unrecognized vulnerability types
