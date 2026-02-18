"""
Scanner: Wrapper around OpenSCAP scanner for vulnerability verification.
Extracted from qa_agent_adaptive.py scan_for_vulnerability method.
"""

import json
from pathlib import Path
from typing import Optional, Tuple

from openscap_cli import OpenSCAPScanner
from parse_openscap import parse_openscap
from schemas import Vulnerability


class Scanner:
    """
    Wraps OpenSCAPScanner to provide vulnerability-specific scanning.
    Used by Remedy Agent and QA Agent for verification.
    """

    def __init__(
        self,
        openscap_scanner: OpenSCAPScanner,
        profile: str,
        datastream: str,
        sudo_password: Optional[str] = None,
        work_dir: str = "./scans",
    ):
        self.scanner = openscap_scanner
        self.profile = profile
        self.datastream = datastream
        self.sudo_password = sudo_password
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True, parents=True)

    def scan_for_vulnerability(self, vuln: Vulnerability) -> Tuple[bool, Optional[str]]:
        """
        Check if a specific vulnerability still exists.

        Args:
            vuln: Vulnerability to check

        Returns:
            (is_fixed, scan_output):
                - is_fixed: True if vulnerability is fixed (no longer failing)
                - scan_output: Summary text of scan result

        Logic:
            - Runs OpenSCAP scan
            - Parses results
            - Matches vulnerability by multiple strategies (title, rule ID, etc.)
            - Returns True if result is NOT fail/error (i.e., pass or fixed)
        """
        # Run scan
        scan_file = self.work_dir / f"verify_{vuln.id}.xml"
        parsed_file = self.work_dir / f"verify_{vuln.id}.json"

        success = self.scanner.run_scan(
            profile=self.profile,
            output_file=f"/tmp/verify_{vuln.id}.xml",
            datastream=self.datastream,
            sudo_password=self.sudo_password,
        )

        if not success:
            return False, "Scan execution failed, assuming not fixed"

        # Download and parse
        self.scanner.download_results(f"/tmp/verify_{vuln.id}.xml", str(scan_file))
        parse_openscap(str(scan_file), str(parsed_file))

        # Check if vulnerability still exists
        with open(parsed_file) as f:
            current_vulns = json.load(f)

        # Improved matching: try multiple strategies
        still_exists = False
        matched_result = None

        for finding in current_vulns:
            # Strategy 1: Match by title (exact)
            if finding.get("title") == vuln.title:
                result = finding.get("result")
                still_exists = result in ["fail", "error"]
                matched_result = result
                break

            # Strategy 2: Match by rule / oval_id
            vuln_rule_id = getattr(vuln, 'oval_id', None) or getattr(vuln, 'rule', None) or ""
            finding_rule = finding.get("rule", "") or finding.get("oval_id", "")
            if vuln_rule_id and finding_rule:
                vuln_rule_name = vuln_rule_id.split("rule_")[-1] if "rule_" in vuln_rule_id else vuln_rule_id
                if vuln_rule_name in finding_rule or finding_rule in vuln_rule_name:
                    result = finding.get("result")
                    still_exists = result in ["fail", "error"]
                    matched_result = result
                    break

            # Strategy 3: Match by ID
            if finding.get("id") == vuln.id:
                result = finding.get("result")
                still_exists = result in ["fail", "error"]
                matched_result = result
                break

            # Strategy 4: Partial title match
            if finding.get("title") and vuln.title:
                if (
                    vuln.title.lower() in finding.get("title", "").lower()
                    or finding.get("title", "").lower() in vuln.title.lower()
                ):
                    result = finding.get("result")
                    still_exists = result in ["fail", "error"]
                    matched_result = result
                    break

        if matched_result:
            output = f"Vulnerability {vuln.id}: result={matched_result}"
        else:
            output = f"Vulnerability {vuln.id} not found in scan results (possibly fixed or removed)"
            # If not found, assume it's fixed
            still_exists = False

        is_fixed = not still_exists
        return is_fixed, output

    def scan_single_rule(self, vuln: Vulnerability) -> Tuple[bool, Optional[str]]:
        """
        Check a SINGLE rule via ``oscap --rule``.  Much faster than a full
        profile scan (~10-30s vs ~5-10min).

        Falls back to full scan if the rule ID cannot be determined or the
        single-rule scan fails.
        """
        rule_id = vuln.oval_id or vuln.rule or ""  # Full XCCDF rule ID
        if not rule_id or "xccdf_org.ssgproject.content_rule_" not in rule_id:
            # Cannot determine rule ID — fall back to full scan
            return self.scan_for_vulnerability(vuln)

        scan_file = self.work_dir / f"verify_rule_{vuln.id}.xml"
        parsed_file = self.work_dir / f"verify_rule_{vuln.id}.json"
        remote_xml = f"/tmp/verify_rule_{vuln.id}.xml"

        success = self.scanner.run_scan_rule(
            profile=self.profile,
            rule_id=rule_id,
            output_file=remote_xml,
            datastream=self.datastream,
            sudo_password=self.sudo_password,
        )

        if not success:
            # Don't fall back to full scan (5-10 min); report failure instead
            return False, f"Single-rule scan failed for {vuln.id} (rule={rule_id}). Could not verify."

        self.scanner.download_results(remote_xml, str(scan_file))
        parse_openscap(str(scan_file), str(parsed_file))

        with open(parsed_file) as f:
            results = json.load(f)

        # With single-rule scan the results list is very short (often 1 entry)
        for finding in results:
            result = finding.get("result", "")
            if result in ["fail", "error"]:
                return False, f"Vulnerability {vuln.id}: result={result}"
            if result in ["pass", "fixed", "notapplicable"]:
                return True, f"Vulnerability {vuln.id}: result={result}"

        # Rule not in results — assume fixed
        return True, f"Vulnerability {vuln.id} not found in single-rule scan (possibly fixed)"