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

            # Strategy 2: Match by rule name (from parse_openscap)
            if finding.get("rule") and vuln.title:
                vuln_rule_name = vuln.title.split("rule_")[-1] if "rule_" in vuln.title else vuln.title
                finding_rule = finding.get("rule", "")
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