#!/usr/bin/env python3
"""
Parse OpenSCAP XML results (ARF format) into structured JSON
"""
import xml.etree.ElementTree as ET
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
import sys


# XML namespaces used in OpenSCAP results
NAMESPACES = {
    'xccdf': 'http://checklists.nist.gov/xccdf/1.2',
    'arf': 'http://scap.nist.gov/schema/asset-reporting-format/1.1',
    'core': 'http://scap.nist.gov/schema/reporting-core/1.1'
}


def extract_severity(rule_elem: ET.Element) -> str:
    """
    Convert XCCDF severity to numeric scale (0-4)
    unknown/info -> 0, low -> 1, medium -> 2, high -> 3, critical -> 4
    """
    severity = rule_elem.get('severity', 'unknown').lower()
    severity_map = {
        'unknown': '0',
        'info': '0',
        'low': '1',
        'medium': '2',
        'high': '3',
        'critical': '4'
    }
    return severity_map.get(severity, '0')


def extract_text(elem: Optional[ET.Element]) -> str:
    """Extract text content from element, handling None and nested HTML"""
    if elem is None:
        return ""
    
    # Get all text content recursively
    text = ''.join(elem.itertext()).strip()
    # Clean up excessive whitespace
    text = ' '.join(text.split())
    return text


def parse_openscap(file_path: str, output_json: str = "parsed_openscap_vulns.json") -> List[Dict[str, Any]]:
    """
    Parse OpenSCAP XML results to JSON format compatible with vulnerability schemas
    
    Args:
        file_path: Path to OpenSCAP XML results file
        output_json: Output JSON file path
    
    Returns:
        List of vulnerability dictionaries
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit(1)
    
    findings = []
    
    # Try to find TestResult element (contains scan results)
    test_result = None
    
    # Check if this is an ARF format (Asset Reporting Format)
    arf_reports = root.findall('.//arf:reports/arf:report', NAMESPACES)
    if arf_reports:
        # ARF format - extract TestResult from report
        for report in arf_reports:
            test_result = report.find('.//xccdf:TestResult', NAMESPACES)
            if test_result is not None:
                break
    else:
        # Direct XCCDF format
        test_result = root.find('.//xccdf:TestResult', NAMESPACES)
    
    if test_result is None:
        print("Warning: No TestResult found in XML. File may be incomplete.")
        # Try to parse as a plain results file
        test_result = root
    
    # Extract target information
    target_elem = test_result.find('.//xccdf:target', NAMESPACES)
    host = target_elem.text if target_elem is not None else "localhost"
    
    target_facts = test_result.find('.//xccdf:target-facts', NAMESPACES)
    os_name = "Unknown"
    if target_facts is not None:
        for fact in target_facts.findall('.//xccdf:fact', NAMESPACES):
            if 'cpe' in fact.get('name', '').lower() or 'os' in fact.get('name', '').lower():
                os_name = fact.text
                break
    
    # Find all rule-results
    rule_results = test_result.findall('.//xccdf:rule-result', NAMESPACES)
    
    if not rule_results:
        print("Warning: No rule results found in scan output")
        return []
    
    # Build a map of rule definitions for additional context
    benchmark = root.find('.//xccdf:Benchmark', NAMESPACES)
    
    # If the root element IS the Benchmark (non-ARF XCCDF format), use root directly
    if benchmark is None:
        root_tag = root.tag.split('}')[-1] if '}' in root.tag else root.tag
        if root_tag == 'Benchmark':
            benchmark = root
    
    rule_definitions = {}
    
    if benchmark is not None:
        for rule in benchmark.findall('.//xccdf:Rule', NAMESPACES):
            rule_id = rule.get('id', '')
            title_elem = rule.find('xccdf:title', NAMESPACES)
            desc_elem = rule.find('xccdf:description', NAMESPACES)
            
            # Extract fix script and fixtext from Rule definition
            fix_elem = rule.find('xccdf:fix', NAMESPACES)
            fixtext_elem = rule.find('xccdf:fixtext', NAMESPACES)
            fix_text = extract_text(fix_elem) if fix_elem is not None else ""
            fixtext_text = extract_text(fixtext_elem) if fixtext_elem is not None else ""
            
            rule_definitions[rule_id] = {
                'title': extract_text(title_elem) if title_elem is not None else rule_id,
                'description': extract_text(desc_elem) if desc_elem is not None else "",
                'severity': extract_severity(rule),
                'fix': fix_text,
                'fixtext': fixtext_text,
            }
    
    # Process each rule result
    counter = 1
    for rule_result in rule_results:
        rule_id = rule_result.get('idref', '')
        result = rule_result.find('xccdf:result', NAMESPACES)
        result_text = result.text if result is not None else 'unknown'
        
        # Only include failed/error rules (skip pass, notapplicable, notchecked)
        if result_text.lower() in ['pass', 'notapplicable', 'notchecked', 'notselected']:
            continue
        
        # Get rule definition info
        rule_info = rule_definitions.get(rule_id, {})
        
        # Extract rule name from ID (last part after colon)
        rule_name = rule_id.split(':')[-1] if ':' in rule_id else rule_id
        
        title = rule_info.get('title', rule_name)
        description = rule_info.get('description', title)
        severity = rule_info.get('severity', '2')  # Default to medium
        
        # Build recommendation
        recommendation = f"Review and remediate: {title}"
        
        # Check for fix text in rule-result first
        fix = rule_result.find('xccdf:fix', NAMESPACES)
        if fix is not None:
            fix_text = extract_text(fix)
            if fix_text:
                recommendation = f"Remediation: {fix_text}"
        else:
            # Fall back to fix/fixtext from the Rule definition
            def_fixtext = rule_info.get('fixtext', '')
            def_fix = rule_info.get('fix', '')
            if def_fixtext:
                recommendation = f"Remediation: {def_fixtext}"
            elif def_fix:
                # Truncate long bash scripts to the most useful portion
                recommendation = f"Remediation script: {def_fix[:800]}"
        
        vuln = {
            "id": f"openscap_{counter:03d}",
            "title": title,
            "description": description,
            "severity": severity,
            "result": result_text.lower(),
            "oval_id": rule_id,
            "rule": rule_name,
            "class": "compliance",
            "host": host,
            "os": os_name,
            "recommendation": recommendation
        }
        
        findings.append(vuln)
        counter += 1
    
    # Write output
    output_path = Path(output_json)
    output_path.write_text(json.dumps(findings, indent=2))
    print(f"Parsed {len(findings)} failed/error findings → {output_json}")
    print(f"Total rules checked: {len(rule_results)}")
    
    # Return findings along with scan statistics
    return {
        "findings": findings,
        "total_rules_scanned": len(rule_results),
        "rules_passed": len(rule_results) - len(findings),
        "rules_failed": len(findings),
    }


def main():
    """Command-line interface"""
    if len(sys.argv) < 2:
        print("Usage: python parse_openscap.py <input.xml> [output.json]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "parsed_openscap_vulns.json"
    
    parse_openscap(input_file, output_file)


if __name__ == "__main__":
    main()

