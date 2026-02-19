#!/usr/bin/env python3
"""
QA Loop - Iterative vulnerability scanning, remediation, and verification
"""
import os
import sys
import json
import time
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from schemas import Vulnerability, RemediationSuggestion
from openscap_cli import OpenSCAPScanner
from parse_openscap import parse_openscap
from legacy_files import agent as agent_module
from remediation_bridge import RemediationBridge

console = Console()


class AnsibleExecutor:
    """Execute Ansible playbooks on remote hosts"""

    def __init__(self, inventory_path: str):
        self.inventory_path = inventory_path

    def execute_playbook(self, playbook_path: str, check_mode: bool = False) -> Tuple[bool, str]:
        """
        Execute an Ansible playbook

        Args:
            playbook_path: Path to the playbook YAML file
            check_mode: Run in check mode (dry-run) if True

        Returns:
            Tuple of (success, output_message)
        """
        cmd = [
            "ansible-playbook",
            "-i",
            self.inventory_path,
            playbook_path,
            "-vvv",
        ]

        if check_mode:
            cmd.append("--check")

        console.print(f"[cyan]Executing playbook: {playbook_path}[/cyan]")
        console.print(f"[dim]CMD: {' '.join(cmd)}[/dim]")
        if check_mode:
            console.print("[yellow](Check mode - no changes will be made)[/yellow]")

        try:
            
            env = {**os.environ, "ANSIBLE_STDOUT_CALLBACK": "debug", "ANSIBLE_FORCE_COLOR": "false"}
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout
                env=env,
            )

            if result.returncode == 0:
                console.print("[green]✓ Playbook executed successfully[/green]")
                # Show stdout so user can see VM output
                if result.stdout:
                    console.print(result.stdout, markup=False)
                return True, result.stdout or ""
            else:
                console.print(f"[red]✗ Playbook execution failed[/red]")
                # Show both stdout and stderr for troubleshooting
                if result.stdout:
                    console.print(result.stdout, style="yellow", markup=False)
                if result.stderr:
                    console.print(result.stderr, style="red", markup=False)
                return False, (result.stderr or result.stdout or "Unknown error")

        except subprocess.TimeoutExpired:
            error_msg = "Playbook execution timed out (>10 minutes)"
            console.print(f"[red]{error_msg}[/red]")
            return False, error_msg
        except FileNotFoundError:
            error_msg = "ansible-playbook command not found. Is Ansible installed?"
            console.print(f"[red]{error_msg}[/red]")
            return False, error_msg
        except Exception as e:
            error_msg = f"Error executing playbook: {e}"
            console.print(f"[red]{error_msg}[/red]")
            return False, error_msg


class VulnerabilityComparator:
    """Compare vulnerability scan results"""

    @staticmethod
    def compare_scans(
        before: List[Vulnerability],
        after: List[Vulnerability],
    ) -> Dict[str, List[Vulnerability]]:
        """
        Compare two scan results to identify fixed and persisting vulnerabilities

        Args:
            before: Vulnerabilities from initial scan
            after: Vulnerabilities from rescan

        Returns:
            Dictionary with 'fixed', 'persisted', and 'new' vulnerability lists
        """
        # Create sets of vulnerability identifiers
 
        before_set = {(v.title, v.host) for v in before}
        after_set = {(v.title, v.host) for v in after}

        # Create maps for easy lookup
        before_map = {(v.title, v.host): v for v in before}
        after_map = {(v.title, v.host): v for v in after}

        # Calculate differences
        fixed_keys = before_set - after_set
        persisted_keys = before_set & after_set
        new_keys = after_set - before_set

        return {
            "fixed": [before_map[key] for key in fixed_keys],
            "persisted": [after_map[key] for key in persisted_keys],
            "new": [after_map[key] for key in new_keys],
        }

    @staticmethod
    def print_comparison_report(comparison: Dict[str, List[Vulnerability]]):
        """Print a formatted comparison report"""
        table = Table(title="Vulnerability Scan Comparison")
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="right", style="magenta")

        fixed_count = len(comparison["fixed"])
        persisted_count = len(comparison["persisted"])
        new_count = len(comparison["new"])

        table.add_row("✓ Fixed", str(fixed_count), style="green")
        table.add_row("~ Persisted", str(persisted_count), style="yellow")
        table.add_row("⚠ New", str(new_count), style="red")

        console.print(table)

        # Print details for fixed vulnerabilities
        if comparison["fixed"]:
            console.print("\n[bold green]Fixed Vulnerabilities:[/bold green]")
            for vuln in comparison["fixed"][:10]:  # Show first 10
                console.print(f"  • {vuln.title} on {vuln.host}")
            if len(comparison["fixed"]) > 10:
                console.print(f"  ... and {len(comparison['fixed']) - 10} more")

        # Print details for persisted vulnerabilities
        if comparison["persisted"]:
            console.print("\n[bold yellow]Persisted Vulnerabilities:[/bold yellow]")
            for vuln in comparison["persisted"][:5]:  # Show first 5
                console.print(f"  • {vuln.title} on {vuln.host}")
            if len(comparison["persisted"]) > 5:
                console.print(f"  ... and {len(comparison['persisted']) - 5} more")


class QALoop:
    """Main QA Loop orchestrator"""

    def __init__(
        self,
        scanner: OpenSCAPScanner,
        ansible_inventory: str,
        work_dir: Path,
        scan_profile: str,
        scan_datastream: str,
        min_severity: int = 2,
        max_fixes: int = 0,
    ):
        self.scanner = scanner
        self.ansible_executor = AnsibleExecutor(ansible_inventory)
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(exist_ok=True, parents=True)
        self.scan_profile = scan_profile
        self.scan_datastream = scan_datastream
        self.min_severity = min_severity
        self.max_fixes = max_fixes

        # Configure environment for agent
        load_dotenv()
        self.model_name = os.getenv("OPENROUTER_MODEL")
        self.base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
        self.api_key = os.getenv("OPENROUTER_API_KEY")
        self.batch_size = int(os.getenv("BATCH_SIZE", "1"))
        if not self.model_name:
            raise ValueError(
                "OPENROUTER_MODEL not found in environment. Set it in .env or before running QA loop."
            )

    def run_scan(self, iteration: int) -> Path:
        """Run OpenSCAP scan and return path to parsed results"""
        console.print(f"\n[bold cyan]{'=' * 60}[/bold cyan]")
        console.print(f"[bold cyan]Iteration {iteration}: Running Security Scan[/bold cyan]")
        console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")

        # Define output paths
        raw_xml = self.work_dir / f"scan_iter{iteration}_raw.xml"
        parsed_json = self.work_dir / f"scan_iter{iteration}_vulns.json"

        # Run scan
        success = self.scanner.run_scan(
            profile=self.scan_profile,
            output_file=f"/tmp/oscap_iter{iteration}.xml",
            datastream=self.scan_datastream,
            sudo_password=self.scanner.sudo_password,
        )

        if not success:
            raise RuntimeError(f"Scan failed on iteration {iteration}")

        # Download results
        if not self.scanner.download_results(f"/tmp/oscap_iter{iteration}.xml", str(raw_xml)):
            raise RuntimeError(f"Failed to download scan results from iteration {iteration}")

        # Parse results
        parse_openscap(str(raw_xml), str(parsed_json))

        return parsed_json

    def generate_remediations(self, vulns_file: Path, iteration: int) -> Path:
        """Generate LLM-based remediation suggestions"""
        console.print(f"\n[bold cyan]Iteration {iteration}: Generating Remediations[/bold cyan]\n")

        remediations_file = self.work_dir / f"remediations_iter{iteration}.json"

        # Configure agent environment
        os.environ["VULN_INPUT"] = str(vulns_file)
        os.environ["REMEDIATIONS_OUTPUT"] = str(remediations_file)
        os.environ["OPENROUTER_MODEL"] = self.model_name
        os.environ["OPENROUTER_BASE_URL"] = self.base_url
        os.environ["BATCH_SIZE"] = str(self.batch_size)
        os.environ["MIN_SEVERITY"] = str(self.min_severity)
        if self.max_fixes > 0:
            os.environ["MAX_FIXES"] = str(self.max_fixes)

        # Run agent
        agent_module.main()

        return remediations_file

    def create_ansible_playbook(
        self,
        remediations_file: Path,
        vulns_file: Path,
        iteration: int,
    ) -> Path:
        """Convert remediation suggestions to Ansible playbook"""
        console.print(f"\n[bold cyan]Iteration {iteration}: Creating Ansible Playbook[/bold cyan]\n")

        # Load data
        with open(remediations_file) as f:
            suggestions = [RemediationSuggestion(**s) for s in json.load(f)]

        with open(vulns_file) as f:
            vulns = [Vulnerability(**v) for v in json.load(f)]

        # Create playbook
        bridge = RemediationBridge()
        playbook = bridge.create_playbook(
            suggestions=suggestions,
            vulns=vulns,
            playbook_name=f"Security Remediation - Iteration {iteration}",
        )

        # Write playbook
        playbook_file = self.work_dir / f"remediation_iter{iteration}.yml"
        playbook_file.write_text(playbook.to_yaml())

        console.print(f"[green]✓ Playbook created: {playbook_file}[/green]")
        console.print(f"[dim]Tasks: {len(playbook.tasks)}[/dim]")

        return playbook_file

    def apply_remediations(self, playbook_file: Path, dry_run: bool = False) -> bool:
        """Apply remediation playbook"""
        console.print(f"\n[bold cyan]Applying Remediations[/bold cyan]\n")

        success, output = self.ansible_executor.execute_playbook(
            str(playbook_file),
            check_mode=dry_run,
        )

        # Log output
        log_file = playbook_file.with_suffix(".log")
        log_file.write_text(output)
        console.print(f"[dim]Execution log saved to: {log_file}[/dim]")

        return success

    def run_loop(self, max_iterations: int = 3, dry_run: bool = False) -> Dict[str, Any]:
        """
        Run the complete QA loop

        Args:
            max_iterations: Maximum number of scan-remediate-rescan cycles
            dry_run: If True, run playbooks in check mode only

        Returns:
            Summary dictionary with results
        """
        console.print("[bold green]Starting QA Loop[/bold green]\n")

        results = {
            "iterations": [],
            "start_time": datetime.now().isoformat(),
            "max_iterations": max_iterations,
        }

        previous_vulns = None

        for iteration in range(1, max_iterations + 1):
            iteration_start = time.time()
            iteration_data = {"iteration": iteration}

            try:
                # Step 1: Scan
                vulns_file = self.run_scan(iteration)

                # Load vulnerabilities
                with open(vulns_file) as f:
                    vulns_data = json.load(f)
                    vulns = [Vulnerability(**v) for v in vulns_data]

                iteration_data["vulnerabilities_found"] = len(vulns)
                console.print(f"[yellow]Found {len(vulns)} vulnerabilities[/yellow]")

                # Compare with previous scan if available
                if previous_vulns:
                    console.print(f"\n[bold cyan]Comparing with Previous Scan[/bold cyan]\n")
                    comparison = VulnerabilityComparator.compare_scans(previous_vulns, vulns)
                    VulnerabilityComparator.print_comparison_report(comparison)
                    iteration_data["comparison"] = {
                        "fixed": len(comparison["fixed"]),
                        "persisted": len(comparison["persisted"]),
                        "new": len(comparison["new"]),
                    }

                    # Check if we're done (no vulnerabilities left)
                    if len(vulns) == 0:
                        console.print("\n[bold green]🎉 All vulnerabilities resolved![/bold green]")
                        break

                # Filter by severity
                high_severity_vulns = [v for v in vulns if int(v.severity) >= self.min_severity]

                if not high_severity_vulns:
                    console.print(
                        f"\n[green]No vulnerabilities above severity threshold ({self.min_severity})[/green]"
                    )
                    break

                console.print(
                    f"[yellow]Processing {len(high_severity_vulns)} vulnerabilities (severity >= {self.min_severity})[/yellow]"
                )

                # Step 2: Generate remediations
                remediations_file = self.generate_remediations(vulns_file, iteration)

                # Step 3: Create Ansible playbook
                playbook_file = self.create_ansible_playbook(
                    remediations_file,
                    vulns_file,
                    iteration,
                )

                # Step 4: Apply remediations
                if self.apply_remediations(playbook_file, dry_run=dry_run):
                    iteration_data["remediation_applied"] = True

                    # Wait for changes to take effect
                    if not dry_run:
                        console.print(
                            "\n[cyan]Waiting 30 seconds for changes to take effect...[/cyan]"
                        )
                        time.sleep(30)
                else:
                    iteration_data["remediation_applied"] = False
                    console.print("[yellow]Remediation had errors, but continuing...[/yellow]")

                # Store current vulnerabilities for next comparison
                previous_vulns = vulns

                iteration_data["duration_seconds"] = time.time() - iteration_start
                results["iterations"].append(iteration_data)

                # If this is not the last iteration, we'll rescan
                if iteration < max_iterations:
                    console.print(f"\n[cyan]Moving to iteration {iteration + 1}...[/cyan]")

            except Exception as e:
                console.print(f"\n[red]Error in iteration {iteration}: {e}[/red]")
                iteration_data["error"] = str(e)
                results["iterations"].append(iteration_data)
                break

        # Final summary
        results["end_time"] = datetime.now().isoformat()
        results["total_iterations_run"] = len(results["iterations"])

        # Save results
        results_file = self.work_dir / "qa_loop_results.json"
        results_file.write_text(json.dumps(results, indent=2))

        console.print(f"\n[bold green]{'=' * 60}[/bold green]")
        console.print(f"[bold green]QA Loop Complete[/bold green]")
        console.print(f"[bold green]{'=' * 60}[/bold green]\n")
        console.print(f"Results saved to: {results_file}")

        return results


def main():
    """Command-line interface"""
    import argparse

    parser = argparse.ArgumentParser(description="QA Loop - Iterative vulnerability remediation")
    parser.add_argument("--host", required=True, help="Target host to scan and remediate")
    parser.add_argument("--user", default="root", help="SSH username")
    parser.add_argument("--key", help="SSH private key path")
    parser.add_argument("--sudo-password", help="Sudo password on target (if needed)")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--inventory", required=True, help="Ansible inventory file")
    parser.add_argument(
        "--profile",
        default="xccdf_org.ssgproject.content_profile_cis",
        help="OpenSCAP security profile",
    )
    parser.add_argument(
        "--datastream",
        default="/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml",
        help="SCAP datastream path on target",
    )
    parser.add_argument(
        "--work-dir",
        default="qa_loop_work",
        help="Working directory for intermediate files",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum number of scan-remediate cycles",
    )
    parser.add_argument(
        "--min-severity",
        type=int,
        default=2,
        choices=[0, 1, 2, 3, 4],
        help="Minimum severity to process (0=Info, 4=Critical)",
    )
    parser.add_argument(
        "--max-fixes",
        type=int,
        default=0,
        help="Max vulnerabilities to fix per iteration (0=all)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in check mode (no actual changes)",
    )

    args = parser.parse_args()

    # Create scanner
    scanner = OpenSCAPScanner(
        target_host=args.host,
        ssh_user=args.user,
        ssh_key=args.key,
        ssh_port=args.port,
        sudo_password=args.sudo_password,
    )

    # Create and run QA loop
    qa_loop = QALoop(
        scanner=scanner,
        ansible_inventory=args.inventory,
        work_dir=Path(args.work_dir),
        scan_profile=args.profile,
        scan_datastream=args.datastream,
        min_severity=args.min_severity,
        max_fixes=args.max_fixes,
    )

    try:
        qa_loop.run_loop(max_iterations=args.max_iterations, dry_run=args.dry_run)
    except KeyboardInterrupt:
        console.print("\n[yellow]QA Loop interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]QA Loop failed: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()


