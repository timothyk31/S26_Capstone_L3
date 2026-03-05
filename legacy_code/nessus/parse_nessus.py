import xml.etree.ElementTree as ET
import json
from pathlib import Path


def parse_nessus(file_path: str, output_json: str = "parsed_vulns.json"):
    tree = ET.parse(file_path)
    root = tree.getroot()

    findings = []
    for report_host in root.findall(".//ReportHost"):
        host = report_host.get("name")
        for item in report_host.findall("ReportItem"):
            severity = item.get("severity")
            vuln = {
                "id": item.get("pluginID"),
                "title": item.get("pluginName"),
                "severity": severity,  # 0=Info,1=Low,2=Med,3=High,4=Critical
                "cvss": item.findtext("cvss_base_score"),
                "host": host,
                "port": item.get("port"),
                "protocol": item.get("protocol"),
                "description": item.findtext("description"),
                "recommendation": item.findtext("solution"),
            }
            findings.append(vuln)

    Path(output_json).write_text(json.dumps(findings, indent=2))
    print(f"Parsed {len(findings)} findings : {output_json}")


if __name__ == "__main__":
    # Example usage
    parse_nessus("scan_results.nessus")


