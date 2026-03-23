"""Unit tests verifying parse_openscap uses rule-based IDs, not positional counters."""

import json
import pytest
from pathlib import Path

from parse_openscap import parse_openscap


# Minimal XCCDF XML with two failing rules
SAMPLE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="test_benchmark">
  <TestResult id="test_result_1">
    <target>10.0.0.1</target>
    <rule-result idref="xccdf_org.ssgproject.content_rule_auditd_audispd_syslog_plugin_activated">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_set_idle_timeout">
      <result>fail</result>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject.content_rule_accounts_password_minlen">
      <result>pass</result>
    </rule-result>
  </TestResult>
  <Rule id="xccdf_org.ssgproject.content_rule_auditd_audispd_syslog_plugin_activated" severity="medium">
    <title>Ensure auditd is enabled</title>
    <description>The auditd service must be running.</description>
  </Rule>
  <Rule id="xccdf_org.ssgproject.content_rule_sshd_set_idle_timeout" severity="medium">
    <title>Set SSH Idle Timeout Interval</title>
    <description>Set ClientAliveInterval to 600.</description>
  </Rule>
  <Rule id="xccdf_org.ssgproject.content_rule_accounts_password_minlen" severity="low">
    <title>Set Password Minimum Length</title>
    <description>Password must be at least 12 chars.</description>
  </Rule>
</Benchmark>
"""


@pytest.fixture
def xml_file(tmp_path):
    path = tmp_path / "test_scan.xml"
    path.write_text(SAMPLE_XML, encoding="utf-8")
    return path


@pytest.fixture
def json_file(tmp_path):
    return tmp_path / "test_scan.json"


class TestParseOpenscapIds:

    def test_ids_are_rule_based(self, xml_file, json_file):
        """Parsed findings use rule names as IDs, not positional counters."""
        result = parse_openscap(str(xml_file), str(json_file))

        findings = result["findings"]
        # Only failed rules appear (pass is excluded)
        assert len(findings) == 2

        ids = {f["id"] for f in findings}
        # Should be rule names, not openscap_001/openscap_002
        assert "auditd_audispd_syslog_plugin_activated" in ids
        assert "sshd_set_idle_timeout" in ids
        assert not any(f["id"].startswith("openscap_") for f in findings)

    def test_rule_and_oval_id_preserved(self, xml_file, json_file):
        """rule and oval_id fields are still populated."""
        result = parse_openscap(str(xml_file), str(json_file))
        findings = result["findings"]

        for f in findings:
            assert f["rule"] == f["id"]  # rule name == id now
            assert f["oval_id"].startswith("xccdf_org.ssgproject.content_rule_")

    def test_json_output_matches(self, xml_file, json_file):
        """The written JSON file matches the returned findings."""
        result = parse_openscap(str(xml_file), str(json_file))

        written = json.loads(json_file.read_text(encoding="utf-8"))
        assert len(written) == len(result["findings"])
        assert written[0]["id"] == result["findings"][0]["id"]

    def test_pass_results_excluded(self, xml_file, json_file):
        """Passing rules are excluded from output."""
        result = parse_openscap(str(xml_file), str(json_file))
        findings = result["findings"]

        ids = {f["id"] for f in findings}
        assert "accounts_password_minlen" not in ids
