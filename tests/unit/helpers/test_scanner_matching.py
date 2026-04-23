"""Unit tests for Scanner.match_finding() and scan_full_profile()."""

import json
import pytest
from unittest.mock import MagicMock, patch, mock_open

from helpers.scanner import Scanner
from schemas import Vulnerability


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def vuln_auditd():
    return Vulnerability(
        id="auditd_audispd_syslog_plugin_activated",
        title="Ensure auditd is enabled",
        severity="3",
        host="10.0.0.1",
        rule="auditd_audispd_syslog_plugin_activated",
        oval_id="xccdf_org.ssgproject.content_rule_auditd_audispd_syslog_plugin_activated",
    )


@pytest.fixture
def vuln_sshd():
    return Vulnerability(
        id="sshd_set_idle_timeout",
        title="Set SSH Idle Timeout Interval",
        severity="2",
        host="10.0.0.1",
        rule="sshd_set_idle_timeout",
        oval_id="xccdf_org.ssgproject.content_rule_sshd_set_idle_timeout",
    )


@pytest.fixture
def failed_findings():
    """Simulated list of FAILED findings from a full-profile scan."""
    return [
        {
            "id": "auditd_audispd_syslog_plugin_activated",
            "title": "Ensure auditd is enabled",
            "rule": "auditd_audispd_syslog_plugin_activated",
            "oval_id": "xccdf_org.ssgproject.content_rule_auditd_audispd_syslog_plugin_activated",
            "result": "fail",
        },
        {
            "id": "accounts_password_pam_minlen",
            "title": "Set Password Minimum Length",
            "rule": "accounts_password_pam_minlen",
            "oval_id": "xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen",
            "result": "fail",
        },
    ]


# ── match_finding tests ──────────────────────────────────────────────────

class TestMatchFinding:

    def test_match_finding_fail(self, vuln_auditd, failed_findings):
        """Vulnerability found in failed findings → returns False (still failing)."""
        result = Scanner.match_finding(vuln_auditd, failed_findings)
        assert result is False

    def test_match_finding_pass(self, vuln_sshd, failed_findings):
        """Vulnerability NOT in failed findings → returns True (passed)."""
        result = Scanner.match_finding(vuln_sshd, failed_findings)
        assert result is True

    def test_match_finding_empty_scan(self, vuln_auditd):
        """No failed findings → everything passed."""
        result = Scanner.match_finding(vuln_auditd, [])
        assert result is True

    def test_match_finding_by_oval_id(self, failed_findings):
        """Match via oval_id when id doesn't match directly."""
        vuln = Vulnerability(
            id="some_other_id",
            title="Ensure auditd is enabled",
            severity="3",
            host="10.0.0.1",
            oval_id="xccdf_org.ssgproject.content_rule_auditd_audispd_syslog_plugin_activated",
        )
        result = Scanner.match_finding(vuln, failed_findings)
        assert result is False

    def test_match_finding_by_rule(self, failed_findings):
        """Match via rule field when id doesn't match."""
        vuln = Vulnerability(
            id="different_id",
            title="Ensure auditd is enabled",
            severity="3",
            host="10.0.0.1",
            rule="auditd_audispd_syslog_plugin_activated",
        )
        result = Scanner.match_finding(vuln, failed_findings)
        assert result is False


# ── scan_full_profile tests ──────────────────────────────────────────────

class TestScanFullProfile:

    def test_scan_full_profile_success(self, tmp_path):
        """Full scan runs successfully and returns parsed findings."""
        mock_oscap = MagicMock()
        mock_oscap.run_scan.return_value = True
        mock_oscap.download_results.return_value = True

        scanner = Scanner(
            openscap_scanner=mock_oscap,
            profile="test_profile",
            datastream="/test/ds.xml",
            work_dir=str(tmp_path / "scans"),
        )

        fake_findings = [
            {"id": "rule_a", "title": "Rule A", "result": "fail"},
        ]
        fake_parse_result = {
            "findings": fake_findings,
            "total_rules_scanned": 100,
            "rules_passed": 99,
            "rules_failed": 1,
        }

        with patch("helpers.scanner.parse_openscap", return_value=fake_parse_result):
            result = scanner.scan_full_profile()

        assert result == fake_findings
        mock_oscap.run_scan.assert_called_once()
        mock_oscap.download_results.assert_called_once()

    def test_scan_full_profile_failure_raises(self, tmp_path):
        """Full scan execution failure raises RuntimeError."""
        mock_oscap = MagicMock()
        mock_oscap.run_scan.return_value = False

        scanner = Scanner(
            openscap_scanner=mock_oscap,
            profile="test_profile",
            datastream="/test/ds.xml",
            work_dir=str(tmp_path / "scans"),
        )

        with pytest.raises(RuntimeError, match="Full-profile scan execution failed"):
            scanner.scan_full_profile()
