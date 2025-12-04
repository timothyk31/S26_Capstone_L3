#!/usr/bin/env python3
"""
Quick runner for Adaptive QA Agent

This is a convenience script to run the adaptive agent with secure password input.
"""
import subprocess
import sys
import yaml
from getpass import getpass
from pathlib import Path
from rich.console import Console

console = Console()


def main():
    """Run adaptive agent with secure password input"""

    # Check inventory file
    inventory = Path("inventory.yml")
    if not inventory.exists():
        console.print("[red]Error: inventory.yml not found![/red]")
        console.print("Please create inventory.yml from inventory.yml.template")
        sys.exit(1)

    # Load inventory
    with open(inventory) as f:
        inv_data = yaml.safe_load(f)

    host_config = inv_data["all"]["hosts"]["mertcis"]
    host = host_config["ansible_host"]
    user = host_config["ansible_user"]

    # Get SSH key if specified
    ssh_key = host_config.get("ansible_ssh_private_key_file")

    # Get sudo password
    console.print("\n[cyan]Adaptive QA Agent - Self-Correcting with Feedback Loops[/cyan]\n")
    console.print("This agent will:")
    console.print("  1. Try to fix each vulnerability")
    console.print("  2. [yellow]Verify if fix worked (rescan)[/yellow]")
    console.print("  3. [yellow]If failed: Analyze error and try different approach[/yellow]")
    console.print("  4. [yellow]Iterate up to 5 times per vulnerability[/yellow]")
    console.print("  5. [green]Learn what works and adapt strategy[/green]\n")

    sudo_password = getpass(f"Enter sudo password for {user}@{host}: ")

    # Build command
    cmd = [
        sys.executable,
        "qa_agent_adaptive.py",
        "--host",
        host,
        "--user",
        user,
        "--sudo-password",
        sudo_password,
        "--inventory",
        "inventory.yml",
        "--profile",
        "xccdf_org.ssgproject.content_profile_cis",
        "--datastream",
        "/usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml",
        "--work-dir",
        "adaptive_qa_work",
        "--max-vulns",
        "5",  # Limit to 5 for testing
        "--min-severity",
        "2",
        "--max-attempts",
        "5",
    ]

    if ssh_key:
        cmd.extend(["--key", ssh_key])

    console.print(f"[dim]Starting adaptive agent for {host}...[/dim]\n")

    # Run
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()


