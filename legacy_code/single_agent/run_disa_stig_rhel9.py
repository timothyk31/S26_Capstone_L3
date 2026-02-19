#!/usr/bin/env python3
"""
Run an OpenSCAP DISA STIG scan for RHEL9 over SSH and download results.
"""
from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from openscap_cli import OpenSCAPScanner
from parse_openscap import parse_openscap

DEFAULT_PROFILE = "xccdf_org.ssgproject.content_profile_stig"
DEFAULT_DATASTREAM = "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
DEFAULT_REMOTE_XML = "/tmp/oscap_stig_rhel9.xml"
DEFAULT_LOCAL_XML = "oscap_stig_rhel9.xml"
DEFAULT_PARSED_JSON = "oscap_stig_rhel9_parsed.json"
DEFAULT_REMOTE_REPORT = "/tmp/oscap_report.html"
DEFAULT_LOCAL_REPORT = "oscap_stig_rhel9_report.html"
DEFAULT_FAILED_JSON = "oscap_stig_rhel9_failed.json"
DEFAULT_VULNS_JSON = "oscap_stig_rhel9_vulnerabilities.json"
DEFAULT_FAILED_PDF = "oscap_stig_rhel9_failed.pdf"
DEFAULT_VULNS_PDF = "oscap_stig_rhel9_vulnerabilities.pdf"

NAMESPACES = {
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "arf": "http://scap.nist.gov/schema/asset-reporting-format/1.1",
}


def count_rules_checked(xml_path: Path) -> int:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except (ET.ParseError, FileNotFoundError):
        return 0

    rule_results = root.findall(".//xccdf:rule-result", NAMESPACES)
    return len(rule_results)


def ensure_pdf_suffix(path: Path) -> Path:
    if path.suffix.lower() == ".pdf":
        return path
    return path.with_suffix(".pdf")


def write_findings_pdf(
    findings: list[dict],
    pdf_path: Path,
    target_host: str,
    profile: str,
    title: str,
    total_label: str,
) -> Path:
    """Generate a clean, paginated PDF listing findings (ReportLab Platypus)."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            PageBreak,
            Table,
            TableStyle,
        )
    except Exception as e:
        raise RuntimeError(
            "reportlab is not installed. Install with 'pip install reportlab' or "
            "'pip install -r requirements.txt'"
        ) from e

    pdf_path = ensure_pdf_suffix(pdf_path)

    # Sort most severe first
    def sev_score(item: dict) -> int:
        try:
            return int(str(item.get("severity", "0")))
        except Exception:
            return 0

    findings_sorted = sorted(findings, key=sev_score, reverse=True)

    severity_map = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title=title,
        author="OpenSCAP",
    )

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    h_style = styles["Heading2"]
    body = styles["BodyText"]
    body.spaceAfter = 6

    mono = ParagraphStyle(
        "mono",
        parent=styles["BodyText"],
        fontName="Courier",
        fontSize=9,
        leading=11,
        spaceAfter=6,
    )

    # Header/footer
    def on_page(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 9)
        canvas.drawString(doc_.leftMargin, letter[1] - 0.5 * inch, title)
        canvas.drawRightString(letter[0] - doc_.rightMargin, 0.5 * inch, f"Page {doc_.page}")
        canvas.restoreState()

    story = []

    # Cover / Summary
    story.append(Paragraph(title, title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body))
    story.append(Paragraph(f"<b>Target Host:</b> {target_host}", body))
    story.append(Paragraph(f"<b>Profile:</b> {profile}", body))
    story.append(Paragraph(f"<b>{total_label}:</b> {len(findings_sorted)}", body))
    story.append(Spacer(1, 12))

    # Optional: quick severity breakdown
    counts = {k: 0 for k in severity_map}
    for v in findings_sorted:
        k = str(v.get("severity", "0"))
        counts[k] = counts.get(k, 0) + 1

    summary_rows = [["Severity", "Count"]]
    for k in ["4", "3", "2", "1", "0"]:
        summary_rows.append([severity_map.get(k, k), str(counts.get(k, 0))])

    t = Table(summary_rows, colWidths=[2.0 * inch, 1.0 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("ALIGN", (1, 1), (1, -1), "RIGHT"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(Paragraph("<b>Severity breakdown</b>", body))
    story.append(t)
    story.append(PageBreak())

    # Details
    for idx, v in enumerate(findings_sorted, 1):
        vid = v.get("id", "")
        title = v.get("title", "")
        sev = str(v.get("severity", "0"))
        sev_text = severity_map.get(sev, sev)
        host = v.get("host", target_host)

        desc = v.get("description", "") or ""
        rec = v.get("recommendation", "") or ""
        res = v.get("result", "") or ""

        story.append(Paragraph(f"Finding {idx} of {len(findings_sorted)}", h_style))

        story.append(Paragraph(f"<b>ID:</b> {vid}", body))
        story.append(Paragraph(f"<b>Severity:</b> {sev_text} ({sev})", body))
        story.append(Paragraph(f"<b>Host:</b> {host}", body))
        if res:
            story.append(Paragraph(f"<b>Result:</b> {res}", body))
        story.append(Spacer(1, 6))

        if title:
            story.append(Paragraph("<b>Title</b>", body))
            story.append(Paragraph(str(title), body))

        if desc.strip():
            story.append(Paragraph("<b>Description</b>", body))
            story.append(Paragraph(str(desc), body))

        if rec.strip():
            story.append(Paragraph("<b>Recommendation</b>", body))
            story.append(Paragraph(str(rec), body))

        # If you want to preserve raw text formatting for certain fields, use mono:
        # story.append(Paragraph(f"<b>Raw:</b><br/>{escape(raw)}", mono))

        if idx != len(findings_sorted):
            story.append(PageBreak())

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return pdf_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run OpenSCAP DISA STIG (RHEL9) scan over SSH"
    )
    parser.add_argument("--host", required=True, help="Target host (IP or hostname)")
    parser.add_argument("--user", default="root", help="SSH username")
    parser.add_argument("--key", help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--sudo-password", help="Sudo password on target (if needed)")
    parser.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        help="OpenSCAP profile ID (default: DISA STIG)",
    )
    parser.add_argument(
        "--datastream",
        default=DEFAULT_DATASTREAM,
        help="SCAP datastream path on target",
    )
    parser.add_argument(
        "--remote-output",
        default=DEFAULT_REMOTE_XML,
        help="Remote XML output path on target",
    )
    parser.add_argument(
        "--local-output",
        default=DEFAULT_LOCAL_XML,
        help="Local XML output path",
    )
    parser.add_argument(
        "--parsed-output",
        default=DEFAULT_PARSED_JSON,
        help="Local JSON output path for parsed findings",
    )
    parser.add_argument(
        "--report",
        default=DEFAULT_REMOTE_REPORT,
        help="Remote HTML report path on target",
    )
    parser.add_argument(
        "--local-report",
        default=DEFAULT_LOCAL_REPORT,
        help="Local HTML report path",
    )
    parser.add_argument(
        "--failed-output",
        default=DEFAULT_FAILED_JSON,
        help="Local JSON output path for failed only",
    )
    parser.add_argument(
        "--failed-pdf-output",
        default=DEFAULT_FAILED_PDF,
        help="Local PDF output path for failed only",
    )
    parser.add_argument(
        "--vulns-output",
        default=DEFAULT_VULNS_JSON,
        help="Local JSON output path for vulnerabilities only",
    )
    parser.add_argument(
        "--vulns-pdf-output",
        default=DEFAULT_VULNS_PDF,
        help="Local PDF output path for vulnerabilities only",
    )
    return parser.parse_args()


def _run_remote(scanner: OpenSCAPScanner, cmd: str) -> tuple[bool, str]:
    """
    Try common method names to run an arbitrary remote command.
    Returns (ok, combined_output_or_error).
    """
    for name in ("run_command", "exec", "execute", "ssh_exec", "run", "command"):
        fn = getattr(scanner, name, None)
        if callable(fn):
            try:
                out = fn(cmd)  # could be str or (rc, out, err) depending on impl
                return True, str(out)
            except Exception as e:
                return False, f"{name} failed: {e}"
    return False, (
        "OpenSCAPScanner has no method to run an arbitrary remote command. "
        "Add one (e.g., scanner.exec(cmd)) or paste openscap_cli.py so I can patch it."
    )


def _sudo_fix_perms(
    scanner: OpenSCAPScanner,
    ssh_user: str,
    sudo_password: str | None,
    remote_paths: list[str],
) -> bool:
    """
    Make remote output files readable by ssh_user so scp can download them.
    Uses sudo if password provided; if user has NOPASSWD sudo, password can be None.
    """
    for p in remote_paths:
        if not p:
            continue

        # Build a safe, single-quoted command.
        chown_chmod = f"chown {ssh_user}:{ssh_user} '{p}' && chmod 600 '{p}'"

        if sudo_password:
            cmd = f"bash -lc \"echo '{sudo_password}' | sudo -S {chown_chmod}\""
        else:
            cmd = f"bash -lc \"sudo {chown_chmod}\""

        ok, out = _run_remote(scanner, cmd)
        if not ok:
            print(f"WARNING: Could not fix permissions for {p}: {out}")
            return False
    return True


def main() -> int:
    args = parse_args()

    scanner = OpenSCAPScanner(
        target_host=args.host,
        ssh_user=args.user,
        ssh_key=args.key,
        ssh_port=args.port,
    )

    success = scanner.run_scan(
        profile=args.profile,
        output_file=args.remote_output,
        datastream=args.datastream,
        report_file=args.report,
        sudo_password=args.sudo_password,
    )
    if not success:
        return 1

    # IMPORTANT: Make sure the results/report are readable by the SSH user before scp
    if args.user != "root":
        _sudo_fix_perms(
            scanner=scanner,
            ssh_user=args.user,
            sudo_password=args.sudo_password,
            remote_paths=[args.remote_output, args.report],
        )

    local_path = Path(args.local_output)
    if not scanner.download_results(args.remote_output, str(local_path)):
        return 1

    report_path = None
    if args.report:
        report_path = Path(args.local_report)
        if not scanner.download_results(args.report, str(report_path)):
            report_path = None

    parsed_path = Path(args.parsed_output)
    parse_openscap(str(local_path), str(parsed_path))
    try:
        findings = json.loads(parsed_path.read_text())
    except json.JSONDecodeError:
        findings = []

    failed_only = [f for f in findings if f.get("result") == "fail"]
    failed_path = Path(args.failed_output)
    failed_path.write_text(json.dumps(failed_only, indent=2))

    def severity_score(item: dict) -> int:
        try:
            return int(item.get("severity", "0"))
        except (TypeError, ValueError):
            return 0

    vulnerabilities_only = [
        f for f in findings if severity_score(f) >= 2
    ]
    vulns_path = Path(args.vulns_output)
    vulns_path.write_text(json.dumps(vulnerabilities_only, indent=2))

    failed_pdf_path = Path(args.failed_pdf_output)
    try:
        pdf_path = write_findings_pdf(
            failed_only,
            failed_pdf_path,
            args.host,
            args.profile,
            "Failed Findings Report",
            "Total Failed Findings",
        )
        print(f"Failed findings PDF saved to: {pdf_path}")
    except RuntimeError as exc:
        print(f"Warning: Failed to write failed findings PDF: {exc}")

    vulns_pdf_path = Path(args.vulns_pdf_output)
    try:
        pdf_path = write_findings_pdf(
            vulnerabilities_only,
            vulns_pdf_path,
            args.host,
            args.profile,
            "Vulnerability Scan Report",
            "Total Vulnerabilities (severity >= Medium)",
        )
        print(f"Vulnerabilities PDF saved to: {pdf_path}")
    except RuntimeError as exc:
        print(f"Warning: Failed to write vulnerabilities PDF: {exc}")

    total_rules = count_rules_checked(local_path)
    print(f"Saved results to: {local_path}")
    print(f"Parsed findings: {len(findings)} failed/error rules")
    print(f"Failed only: {len(failed_only)} saved to {failed_path}")
    print(f"Vulnerabilities only: {len(vulnerabilities_only)} saved to {vulns_path}")
    if total_rules:
        print(f"Total rules checked: {total_rules}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
