#!/usr/bin/env python3
"""
End-to-end test of the complete QA workflow:
1. OpenSCAP scan on mertcis
2. Parse results to JSON
3. LLM remediation generation
4. Ansible playbook creation
5. Apply playbook
6. Rescan to verify
"""
import os
import sys
import subprocess
import json
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

# Configuration
HOST = "192.168.135.128"
USER = "skanda"
INVENTORY = "inventory.yml"
WORK_DIR = Path("e2e_test_work")
DATASTREAM = "/usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml"  # Rocky Linux 10

def print_step(step_num: int, title: str):
    """Print a step header"""
    console.print()
    console.print(f"[bold cyan]{'='*70}[/bold cyan]")
    console.print(f"[bold cyan]STEP {step_num}: {title}[/bold cyan]")
    console.print(f"[bold cyan]{'='*70}[/bold cyan]")
    console.print()

def run_command(cmd: list, description: str, capture=True):
    """Run a command and show output"""
    console.print(f"[yellow]▶ {description}[/yellow]")
    console.print(f"[dim]Command: {' '.join(cmd)}[/dim]")
    console.print()
    
    try:
        if capture:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                console.print(f"[green]✓ Success![/green]")
                if result.stdout:
                    # Show last 500 chars of output
                    output = result.stdout.strip()
                    if len(output) > 500:
                        console.print(f"[dim]...{output[-500:]}[/dim]", markup=False)
                    else:
                        console.print(f"[dim]{output}[/dim]", markup=False)
                return True, result.stdout
            else:
                console.print(f"[red]✗ Failed![/red]")
                # Use markup=False to avoid parsing square brackets in error messages
                console.print(result.stderr, style="red", markup=False)
                return False, result.stderr
        else:
            result = subprocess.run(cmd, timeout=600)
            if result.returncode == 0:
                console.print(f"[green]✓ Success![/green]")
                return True, ""
            else:
                console.print(f"[red]✗ Failed with exit code {result.returncode}[/red]")
                return False, ""
    except subprocess.TimeoutExpired:
        console.print("[red]✗ Command timed out![/red]")
        return False, "Timeout"
    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/red]")
        return False, str(e)

def check_prerequisites():
    """Check if all prerequisites are met"""
    print_step(0, "Prerequisites Check")
    
    checks = []
    
    # Check Python packages
    console.print("[cyan]Checking Python packages...[/cyan]")
    try:
        import pydantic_ai
        import ansible
        import click
        import rich
        checks.append(("Python packages", True))
        console.print("[green]✓ All required packages installed[/green]")
    except ImportError as e:
        checks.append(("Python packages", False))
        console.print(f"[red]✗ Missing package: {e}[/red]")
        console.print("[yellow]Run: pip install -r requirements.txt[/yellow]")
    
    # Check .env file
    console.print("\n[cyan]Checking API configuration...[/cyan]")
    if Path(".env").exists():
        from dotenv import load_dotenv
        load_dotenv()
        api_key = os.getenv("OPENROUTER_API_KEY")
        if api_key:
            checks.append(("API Key", True))
            console.print(f"[green]✓ API key configured: {api_key[:10]}...[/green]")
        else:
            checks.append(("API Key", False))
            console.print("[red]✗ OPENROUTER_API_KEY not set in .env[/red]")
    else:
        checks.append((".env file", False))
        console.print("[red]✗ .env file not found[/red]")
    
    # Check inventory
    console.print("\n[cyan]Checking inventory file...[/cyan]")
    if Path(INVENTORY).exists():
        checks.append(("Inventory", True))
        console.print(f"[green]✓ Inventory file exists: {INVENTORY}[/green]")
    else:
        checks.append(("Inventory", False))
        console.print(f"[red]✗ Inventory file not found: {INVENTORY}[/red]")
    
    # Test SSH connection
    console.print("\n[cyan]Testing SSH connection...[/cyan]")
    ssh_cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no"]
    
    # Check if we have an SSH key configured
    import yaml
    if Path(INVENTORY).exists():
        with open(INVENTORY) as f:
            inv = yaml.safe_load(f)
            ssh_key = inv.get('all', {}).get('hosts', {}).get('mertcis', {}).get('ansible_ssh_private_key_file')
            if ssh_key:
                ssh_key = os.path.expanduser(ssh_key)
                if Path(ssh_key).exists():
                    ssh_cmd.extend(["-i", ssh_key])
                    console.print(f"[dim]Using SSH key: {ssh_key}[/dim]")
    
    ssh_cmd.extend([f"{USER}@{HOST}", "echo 'SSH OK'"])
    result = subprocess.run(
        ssh_cmd,
        capture_output=True,
        text=True,
        timeout=10
    )
    if result.returncode == 0:
        checks.append(("SSH Connection", True))
        console.print(f"[green]✓ SSH connection to {HOST} successful[/green]")
    else:
        checks.append(("SSH Connection", False))
        console.print(f"[red]✗ SSH connection failed: {result.stderr}[/red]")
    
    # Test Ansible
    console.print("\n[cyan]Testing Ansible...[/cyan]")
    result = subprocess.run(
        ["ansible", "-i", INVENTORY, "all", "-m", "ping"],
        capture_output=True,
        text=True,
        timeout=30
    )
    if "SUCCESS" in result.stdout:
        checks.append(("Ansible", True))
        console.print("[green]✓ Ansible can connect to mertcis[/green]")
    else:
        checks.append(("Ansible", False))
        console.print(f"[red]✗ Ansible connection failed[/red]")
        console.print(f"[dim]{result.stdout}[/dim]")
    
    # Check OpenSCAP on target
    console.print("\n[cyan]Checking OpenSCAP on target...[/cyan]")
    oscap_cmd = ["ssh", "-o", "StrictHostKeyChecking=no"]
    
    # Use SSH key if available
    if Path(INVENTORY).exists():
        with open(INVENTORY) as f:
            inv = yaml.safe_load(f)
            ssh_key = inv.get('all', {}).get('hosts', {}).get('mertcis', {}).get('ansible_ssh_private_key_file')
            if ssh_key:
                ssh_key = os.path.expanduser(ssh_key)
                if Path(ssh_key).exists():
                    oscap_cmd.extend(["-i", ssh_key])
    
    oscap_cmd.extend([f"{USER}@{HOST}", "which oscap"])
    result = subprocess.run(
        oscap_cmd,
        capture_output=True,
        text=True,
        timeout=10
    )
    if result.returncode == 0:
        checks.append(("OpenSCAP on target", True))
        console.print(f"[green]✓ OpenSCAP installed: {result.stdout.strip()}[/green]")
    else:
        checks.append(("OpenSCAP on target", False))
        console.print("[red]✗ OpenSCAP not found on target[/red]")
        console.print("[yellow]Install with: sudo dnf install openscap-scanner scap-security-guide[/yellow]")
    
    # Summary
    console.print("\n[bold]Prerequisites Summary:[/bold]")
    table = Table()
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="magenta")
    
    for name, passed in checks:
        status = "[green]✓ PASS[/green]" if passed else "[red]✗ FAIL[/red]"
        table.add_row(name, status)
    
    console.print(table)
    
    all_passed = all(status for _, status in checks)
    if not all_passed:
        console.print("\n[red]Some prerequisites failed. Please fix them before continuing.[/red]")
        return False
    
    console.print("\n[green]✓ All prerequisites met![/green]")
    return True

def step1_scan():
    """Step 1: Run OpenSCAP scan"""
    print_step(1, "Run OpenSCAP Scan")
    
    scan_output = WORK_DIR / "scan_initial.xml"
    parsed_output = WORK_DIR / "scan_initial_parsed.json"
    
    # Build scan command
    cmd = [
        "python", "openscap_cli.py", "scan",
        "--host", HOST,
        "--user", USER,
        "--output", str(scan_output),
        "--profile", "xccdf_org.ssgproject.content_profile_cis",
        "--datastream", DATASTREAM
    ]
    
    # Add SSH key and sudo password if configured
    import yaml
    if Path(INVENTORY).exists():
        with open(INVENTORY) as f:
            inv = yaml.safe_load(f)
            host_config = inv.get('all', {}).get('hosts', {}).get('mertcis', {})
            
            ssh_key = host_config.get('ansible_ssh_private_key_file')
            if ssh_key:
                ssh_key = os.path.expanduser(ssh_key)
                if Path(ssh_key).exists():
                    cmd.extend(["--key", ssh_key])
            
            sudo_password = host_config.get('ansible_become_password')
            if sudo_password:
                cmd.extend(["--sudo-password", sudo_password])
    
    success, output = run_command(cmd, "Running OpenSCAP scan on mertcis")
    
    if not success:
        console.print(f"\n[red]Scan command failed. Error output:[/red]")
        console.print(output, style="red", markup=False)
        return False, None
    
    # Check if files were created
    if scan_output.exists():
        console.print(f"\n[green]✓ Scan results saved: {scan_output}[/green]")
        size = scan_output.stat().st_size
        console.print(f"[dim]File size: {size:,} bytes[/dim]")
    else:
        console.print(f"[red]✗ Scan output not found: {scan_output}[/red]")
        return False, None
    
    if parsed_output.exists():
        console.print(f"[green]✓ Parsed results: {parsed_output}[/green]")
        
        # Show summary
        with open(parsed_output) as f:
            vulns = json.load(f)
            console.print(f"[yellow]Found {len(vulns)} vulnerabilities[/yellow]")
            
            # Show first 3
            if vulns:
                console.print("\n[cyan]Sample vulnerabilities:[/cyan]")
                for i, vuln in enumerate(vulns[:3], 1):
                    console.print(f"  {i}. {vuln['title']} (Severity: {vuln['severity']})")
                if len(vulns) > 3:
                    console.print(f"  ... and {len(vulns) - 3} more")
        
        return True, parsed_output
    else:
        console.print(f"[red]✗ Parsed output not found: {parsed_output}[/red]")
        return False, None

def step2_llm_remediation(vulns_file: Path):
    """Step 2: Generate LLM remediations"""
    print_step(2, "Generate LLM Remediations")
    
    remediations_output = WORK_DIR / "remediations.json"
    
    # Set environment variables
    os.environ["VULN_INPUT"] = str(vulns_file)
    os.environ["REMEDIATIONS_OUTPUT"] = str(remediations_output)
    os.environ["MIN_SEVERITY"] = "2"  # Medium and above
    os.environ["MAX_FIXES"] = "5"  # Limit to 5 for testing
    
    console.print(f"[cyan]Processing vulnerabilities with LLM...[/cyan]")
    console.print(f"[dim]Input: {vulns_file}[/dim]")
    console.print(f"[dim]Output: {remediations_output}[/dim]")
    console.print(f"[dim]Limiting to 5 vulnerabilities for testing[/dim]")
    console.print()
    
    # Run agent
    cmd = ["python", "agent.py"]
    success, output = run_command(cmd, "Running LLM agent", capture=False)
    
    if not success:
        return False, None
    
    # Check output
    if remediations_output.exists():
        with open(remediations_output) as f:
            remediations = json.load(f)
            console.print(f"\n[green]✓ Generated {len(remediations)} remediations[/green]")
            
            # Show samples
            if remediations:
                console.print("\n[cyan]Sample remediations:[/cyan]")
                for i, rem in enumerate(remediations[:2], 1):
                    console.print(f"\n  {i}. ID: {rem['id']}")
                    console.print(f"     Commands: {len(rem['proposed_commands'])}")
                    for cmd in rem['proposed_commands'][:2]:
                        console.print(f"       - {cmd}")
                    if rem.get('notes'):
                        console.print(f"     Notes: {rem['notes'][:100]}...")
        
        return True, remediations_output
    else:
        console.print(f"[red]✗ Remediations file not created[/red]")
        return False, None

def step3_create_playbook(remediations_file: Path, vulns_file: Path):
    """Step 3: Create Ansible playbook"""
    print_step(3, "Create Ansible Playbook")
    
    playbook_output = WORK_DIR / "remediation_playbook.yml"
    
    console.print("[cyan]Converting remediations to Ansible playbook...[/cyan]")
    
    # Load data
    with open(remediations_file) as f:
        remediations_data = json.load(f)
    
    with open(vulns_file) as f:
        vulns_data = json.load(f)
    
    # Create playbook using remediation_bridge
    from schemas import RemediationSuggestion, Vulnerability
    from remediation_bridge import RemediationBridge
    
    suggestions = [RemediationSuggestion(**s) for s in remediations_data]
    vulns = [Vulnerability(**v) for v in vulns_data]
    
    # Match vulnerabilities to suggestions
    vuln_map = {v.id: v for v in vulns}
    matched_vulns = [vuln_map.get(s.id) for s in suggestions if s.id in vuln_map]
    
    bridge = RemediationBridge()
    playbook = bridge.create_playbook(
        suggestions=suggestions,
        vulns=[v for v in matched_vulns if v is not None],
        playbook_name="E2E Test Remediation"
    )
    
    # Write playbook
    playbook_output.write_text(playbook.to_yaml())
    
    console.print(f"\n[green]✓ Playbook created: {playbook_output}[/green]")
    console.print(f"[dim]Tasks: {len(playbook.tasks)}[/dim]")
    
    # Show playbook snippet
    console.print("\n[cyan]Playbook preview:[/cyan]")
    yaml_content = playbook.to_yaml()
    lines = yaml_content.split('\n')[:20]
    for line in lines:
        console.print(f"[dim]{line}[/dim]")
    if len(yaml_content.split('\n')) > 20:
        console.print("[dim]... (truncated)[/dim]")
    
    return True, playbook_output

def step4_apply_playbook(playbook_file: Path, dry_run: bool = True):
    """Step 4: Apply Ansible playbook"""
    mode = "DRY-RUN" if dry_run else "LIVE"
    print_step(4, f"Apply Ansible Playbook ({mode})")
    
    if dry_run:
        console.print("[yellow]⚠ Running in DRY-RUN mode (no actual changes)[/yellow]")
    else:
        console.print("[red]⚠ Running in LIVE mode (will make actual changes!)[/red]")
    
    console.print()
    
    # Build command
    cmd = [
        "ansible-playbook",
        "-i", INVENTORY,
        str(playbook_file)
    ]
    
    if dry_run:
        cmd.append("--check")
    
    success, output = run_command(
        cmd,
        f"Executing playbook ({mode})",
        capture=False
    )
    
    if success:
        console.print(f"\n[green]✓ Playbook executed successfully ({mode})[/green]")
        return True
    else:
        console.print(f"\n[red]✗ Playbook execution failed[/red]")
        return False

def step5_rescan():
    """Step 5: Rescan to verify changes"""
    print_step(5, "Rescan to Verify Changes")
    
    scan_output = WORK_DIR / "scan_after.xml"
    parsed_output = WORK_DIR / "scan_after_parsed.json"
    
    cmd = [
        "python", "openscap_cli.py", "scan",
        "--host", HOST,
        "--user", USER,
        "--output", str(scan_output),
        "--profile", "xccdf_org.ssgproject.content_profile_cis",
        "--datastream", DATASTREAM
    ]
    
    # Add SSH key and sudo password if configured
    import yaml
    if Path(INVENTORY).exists():
        with open(INVENTORY) as f:
            inv = yaml.safe_load(f)
            host_config = inv.get('all', {}).get('hosts', {}).get('mertcis', {})
            
            ssh_key = host_config.get('ansible_ssh_private_key_file')
            if ssh_key:
                ssh_key = os.path.expanduser(ssh_key)
                if Path(ssh_key).exists():
                    cmd.extend(["--key", ssh_key])
            
            sudo_password = host_config.get('ansible_become_password')
            if sudo_password:
                cmd.extend(["--sudo-password", sudo_password])
    
    success, output = run_command(cmd, "Running post-remediation scan")
    
    if not success:
        return False, None
    
    if parsed_output.exists():
        with open(parsed_output) as f:
            vulns = json.load(f)
            console.print(f"\n[green]✓ Found {len(vulns)} vulnerabilities after remediation[/green]")
            return True, parsed_output
    else:
        return False, None

def step6_compare(before_file: Path, after_file: Path):
    """Step 6: Compare results"""
    print_step(6, "Compare Before/After Results")
    
    # Load data
    with open(before_file) as f:
        before_vulns = json.load(f)
    
    with open(after_file) as f:
        after_vulns = json.load(f)
    
    # Simple comparison by title
    before_titles = {v['title'] for v in before_vulns}
    after_titles = {v['title'] for v in after_vulns}
    
    fixed = before_titles - after_titles
    persisted = before_titles & after_titles
    new = after_titles - before_titles
    
    # Display results
    table = Table(title="Scan Comparison Results")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right", style="magenta")
    table.add_column("Change", justify="right", style="yellow")
    
    total_before = len(before_vulns)
    total_after = len(after_vulns)
    change = total_after - total_before
    change_str = f"{change:+d}" if change != 0 else "0"
    
    table.add_row("Before", str(total_before), "")
    table.add_row("After", str(total_after), change_str)
    table.add_row("Fixed", str(len(fixed)), "[green]↓[/green]")
    table.add_row("Persisted", str(len(persisted)), "[yellow]→[/yellow]")
    table.add_row("New", str(len(new)), "[red]↑[/red]" if len(new) > 0 else "")
    
    console.print(table)
    
    # Show details
    if fixed:
        console.print("\n[bold green]Fixed Vulnerabilities:[/bold green]")
        for i, title in enumerate(list(fixed)[:5], 1):
            console.print(f"  {i}. {title}")
        if len(fixed) > 5:
            console.print(f"  ... and {len(fixed) - 5} more")
    
    if new:
        console.print("\n[bold red]New Vulnerabilities:[/bold red]")
        for i, title in enumerate(list(new)[:5], 1):
            console.print(f"  {i}. {title}")
        if len(new) > 5:
            console.print(f"  ... and {len(new) - 5} more")
    
    return True

def main():
    """Main test workflow"""
    console.print(Panel.fit(
        "[bold cyan]End-to-End QA Loop Test[/bold cyan]\n"
        f"Target: {USER}@{HOST}\n"
        f"Work Directory: {WORK_DIR}",
        border_style="cyan"
    ))
    
    # Create work directory
    WORK_DIR.mkdir(exist_ok=True)
    console.print(f"\n[dim]Created work directory: {WORK_DIR}[/dim]")
    
    # Check prerequisites
    if not check_prerequisites():
        console.print("\n[red]Prerequisites check failed. Exiting.[/red]")
        sys.exit(1)
    
    input("\n[yellow]Press Enter to continue with Step 1 (Scan)...[/yellow]")
    
    # Step 1: Initial scan
    success, vulns_file = step1_scan()
    if not success:
        console.print("\n[red]Step 1 failed. Exiting.[/red]")
        sys.exit(1)
    
    input("\n[yellow]Press Enter to continue with Step 2 (LLM)...[/yellow]")
    
    # Step 2: LLM remediation
    success, remediations_file = step2_llm_remediation(vulns_file)
    if not success:
        console.print("\n[red]Step 2 failed. Exiting.[/red]")
        sys.exit(1)
    
    input("\n[yellow]Press Enter to continue with Step 3 (Create Playbook)...[/yellow]")
    
    # Step 3: Create playbook
    success, playbook_file = step3_create_playbook(remediations_file, vulns_file)
    if not success:
        console.print("\n[red]Step 3 failed. Exiting.[/red]")
        sys.exit(1)
    
    input("\n[yellow]Press Enter to continue with Step 4 (DRY-RUN Playbook)...[/yellow]")
    
    # Step 4a: Dry-run
    success = step4_apply_playbook(playbook_file, dry_run=True)
    if not success:
        console.print("\n[yellow]Dry-run had issues, but continuing...[/yellow]")
    
    # Ask if they want to run for real
    response = input("\n[bold yellow]Do you want to apply changes for REAL? (yes/no): [/bold yellow]")
    if response.lower() == 'yes':
        # Step 4b: Real run
        success = step4_apply_playbook(playbook_file, dry_run=False)
        if not success:
            console.print("\n[red]Playbook execution failed. Skipping rescan.[/red]")
        else:
            input("\n[yellow]Press Enter to continue with Step 5 (Rescan)...[/yellow]")
            
            # Step 5: Rescan
            success, after_vulns_file = step5_rescan()
            if success:
                input("\n[yellow]Press Enter to continue with Step 6 (Compare)...[/yellow]")
                
                # Step 6: Compare
                step6_compare(vulns_file, after_vulns_file)
    else:
        console.print("\n[yellow]Skipping real execution and rescan.[/yellow]")
    
    # Final summary
    console.print("\n" + "="*70)
    console.print("[bold green]End-to-End Test Complete![/bold green]")
    console.print("="*70)
    console.print(f"\n[cyan]All files saved in: {WORK_DIR}/[/cyan]")
    console.print("\n[cyan]Review the files:[/cyan]")
    console.print(f"  - {WORK_DIR}/scan_initial_parsed.json")
    console.print(f"  - {WORK_DIR}/remediations.json")
    console.print(f"  - {WORK_DIR}/remediation_playbook.yml")
    if (WORK_DIR / "scan_after_parsed.json").exists():
        console.print(f"  - {WORK_DIR}/scan_after_parsed.json")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Test interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Unexpected error:[/red]")
        console.print(str(e), style="red", markup=False)
        import traceback
        traceback.print_exc()
        sys.exit(1)

