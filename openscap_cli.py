#!/usr/bin/env python3
"""
OpenSCAP CLI - Run security compliance scans using OpenSCAP
"""
import os
import sys
import subprocess
import time
from pathlib import Path
from typing import Optional, Dict, Any, List
import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from dotenv import load_dotenv

console = Console()


class OpenSCAPScanner:
    """Wrapper for running OpenSCAP scans via SSH"""
    
    def __init__(self, target_host: str, ssh_user: str, ssh_key: Optional[str] = None, 
                 ssh_password: Optional[str] = None, ssh_port: int = 22):
        self.target_host = target_host
        self.ssh_user = ssh_user
        self.ssh_key = ssh_key
        self.ssh_password = ssh_password
        self.ssh_port = ssh_port
        
    def _build_ssh_command(self, remote_command: str) -> List[str]:
        """Build SSH command with proper authentication"""
        ssh_cmd = ["ssh"]
        
        if self.ssh_key:
            ssh_cmd.extend(["-i", self.ssh_key])
        
        ssh_cmd.extend([
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-p", str(self.ssh_port),
            f"{self.ssh_user}@{self.target_host}",
            remote_command
        ])
        
        return ssh_cmd
    
    def check_oscap_installed(self) -> bool:
        """Check if OpenSCAP is installed on target"""
        try:
            cmd = self._build_ssh_command("which oscap")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception as e:
            console.print(f"[red]Error checking OpenSCAP installation: {e}[/red]")
            return False
    
    def list_available_profiles(self, profile_file: str = "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml") -> Dict[str, str]:
        """List available security profiles on target"""
        try:
            cmd = self._build_ssh_command(f"oscap info {profile_file}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                console.print(f"[yellow]Warning: Could not list profiles: {result.stderr}[/yellow]")
                return {}
            
            # Parse profile list from output
            profiles = {}
            in_profiles = False
            for line in result.stdout.split('\n'):
                if 'Profiles:' in line:
                    in_profiles = True
                    continue
                if in_profiles and ':' in line and 'Id:' in line:
                    # Extract profile ID
                    parts = line.split('Id:')
                    if len(parts) > 1:
                        profile_id = parts[1].strip()
                        # Get next line for title
                        profiles[profile_id] = profile_id
            
            return profiles
        except Exception as e:
            console.print(f"[yellow]Warning: Could not list profiles: {e}[/yellow]")
            return {}
    
    def run_scan(self, 
                 profile: str,
                 output_file: str = "/tmp/oscap_results.xml",
                 datastream: str = "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml",
                 report_file: Optional[str] = None,
                 sudo_password: Optional[str] = None) -> bool:
        """
        Run OpenSCAP scan on target host
        
        Args:
            profile: Security profile to scan (e.g., 'xccdf_org.ssgproject.content_profile_cis')
            output_file: Remote path to save XML results
            datastream: Path to SCAP datastream file on target
            report_file: Optional HTML report path on remote host
            sudo_password: Password for sudo (if required)
        
        Returns:
            bool: True if scan completed (even with findings), False on error
        """
        # Build oscap command - use sudo -S to read password from stdin if provided
        if sudo_password:
            oscap_cmd = f"echo '{sudo_password}' | sudo -S oscap xccdf eval --profile {profile}"
        else:
            oscap_cmd = f"sudo oscap xccdf eval --profile {profile}"
        
        oscap_cmd += f" --results {output_file}"
        
        if report_file:
            oscap_cmd += f" --report {report_file}"
        
        oscap_cmd += f" {datastream}"
        
        console.print(f"[cyan]Running OpenSCAP scan on {self.target_host}...[/cyan]")
        console.print(f"[dim]Profile: {profile}[/dim]")
        console.print(f"[dim]Command: {oscap_cmd}[/dim]")
        
        try:
            cmd = self._build_ssh_command(oscap_cmd)
            
            # Note: OpenSCAP returns non-zero exit codes when findings exist
            # Exit codes: 0=pass, 1=error, 2=findings
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=600  # 10 minute timeout for scan
            )
            
            # Check if scan completed (exit code 2 means findings, which is OK)
            if result.returncode in [0, 2]:
                console.print(f"[green]Scan completed successfully[/green]")
                if result.stdout:
                    console.print(f"[dim]{result.stdout[-500:]}[/dim]")  # Last 500 chars
                return True
            else:
                console.print(f"[red]Scan failed with exit code {result.returncode}[/red]")
                console.print("[red]Error:[/red]")
                console.print(result.stderr, style="red", markup=False)
                return False
                
        except subprocess.TimeoutExpired:
            console.print("[red]Scan timed out (>10 minutes)[/red]")
            return False
        except Exception as e:
            console.print("[red]Error running scan:[/red]")
            console.print(str(e), style="red", markup=False)
            return False
    
    def download_results(self, remote_path: str, local_path: str) -> bool:
        """Download scan results from remote host using scp"""
        try:
            scp_cmd = ["scp"]
            
            if self.ssh_key:
                scp_cmd.extend(["-i", self.ssh_key])
            
            scp_cmd.extend([
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-P", str(self.ssh_port),
                f"{self.ssh_user}@{self.target_host}:{remote_path}",
                local_path
            ])
            
            result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                console.print(f"[green]Results downloaded to {local_path}[/green]")
                return True
            else:
                console.print(f"[red]Failed to download results:[/red]")
                console.print(result.stderr, style="red", markup=False)
                return False
                
        except Exception as e:
            console.print(f"[red]Error downloading results:[/red]")
            console.print(str(e), style="red", markup=False)
            return False


@click.group()
def cli():
    """OpenSCAP CLI - Run security compliance scans"""
    pass


@cli.command()
@click.option('--host', required=True, help='Target host to scan (IP or hostname)')
@click.option('--user', default='root', help='SSH username')
@click.option('--key', help='SSH private key path')
@click.option('--password', help='SSH password (use key authentication when possible)')
@click.option('--sudo-password', help='Sudo password on target (if needed)')
@click.option('--port', default=22, help='SSH port')
@click.option('--profile', default='xccdf_org.ssgproject.content_profile_cis', 
              help='Security profile to scan')
@click.option('--datastream', 
              default='/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml',
              help='Path to SCAP datastream on target')
@click.option('--output', default='oscap_results.xml', help='Local output file path')
@click.option('--report', help='Generate HTML report (remote path)')
def scan(host: str, user: str, key: Optional[str], password: Optional[str], 
         sudo_password: Optional[str], port: int, profile: str, datastream: str, 
         output: str, report: Optional[str]):
    """Run an OpenSCAP scan on a remote host"""
    
    scanner = OpenSCAPScanner(
        target_host=host,
        ssh_user=user,
        ssh_key=key,
        ssh_password=password,
        ssh_port=port
    )
    
    # Check if OpenSCAP is installed
    console.print("[cyan]Checking OpenSCAP installation...[/cyan]")
    if not scanner.check_oscap_installed():
        console.print("[red]OpenSCAP is not installed on target host![/red]")
        console.print("[yellow]Install with: sudo dnf install openscap-scanner scap-security-guide[/yellow]")
        sys.exit(1)
    
    # Run scan
    remote_output = "/tmp/oscap_results.xml"
    remote_report = "/tmp/oscap_report.html" if report else None
    
    success = scanner.run_scan(
        profile=profile,
        output_file=remote_output,
        datastream=datastream,
        report_file=remote_report,
        sudo_password=sudo_password
    )
    
    if not success:
        console.print("[red]Scan failed[/red]")
        sys.exit(1)
    
    # Download results
    console.print("[cyan]Downloading results...[/cyan]")
    if scanner.download_results(remote_output, output):
        # Parse results
        console.print("[cyan]Parsing results...[/cyan]")
        from parse_openscap import parse_openscap
        parsed_output = output.replace('.xml', '_parsed.json')
        parse_openscap(output, output_json=parsed_output)
        console.print(f"[green]✓ Scan complete! Results: {parsed_output}[/green]")
    else:
        sys.exit(1)


@cli.command()
@click.option('--host', required=True, help='Target host')
@click.option('--user', default='root', help='SSH username')
@click.option('--key', help='SSH private key path')
@click.option('--port', default=22, help='SSH port')
@click.option('--datastream', 
              default='/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml',
              help='Path to SCAP datastream on target')
def list_profiles(host: str, user: str, key: Optional[str], port: int, datastream: str):
    """List available security profiles on target host"""
    
    scanner = OpenSCAPScanner(
        target_host=host,
        ssh_user=user,
        ssh_key=key,
        ssh_port=port
    )
    
    console.print(f"[cyan]Fetching profiles from {host}...[/cyan]")
    profiles = scanner.list_available_profiles(datastream)
    
    if profiles:
        console.print("\n[bold]Available Security Profiles:[/bold]")
        for profile_id in profiles:
            console.print(f"  • {profile_id}")
    else:
        console.print("[yellow]No profiles found or unable to query[/yellow]")


if __name__ == '__main__':
    cli()

