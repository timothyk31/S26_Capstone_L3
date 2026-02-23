## Multi-Agent OpenSCAP Security Compliance System

This repository implements a multi-agent architecture for automated security compliance scanning and remediation on Rocky Linux systems using OpenSCAP and LLM-driven agents.

The main entry point is:

- `main_multiagent.py` — Multi-agent pipeline orchestrator (Triage → Remedy → Review → QA)

Legacy single-agent implementations are preserved in `legacy_code/` for reference.

## What the multi-agent system does

- **Scan**: Uses `openscap_cli.OpenSCAPScanner` to run an OpenSCAP XCCDF evaluation on the remote host.
- **Parse**: Converts the resulting XML/ARF into a normalized JSON list of failed/error rules via `parse_openscap.py`.
- **Multi-agent pipeline**: For each vulnerability:
  1. **Triage Agent**: Decides if the vulnerability should be remediated and assesses risk
  2. **Remedy Agent**: Proposes and executes remediation commands using LLM guidance
  3. **Review Agent**: Validates the quality and safety of the remediation approach
  4. **QA Agent**: Performs system-wide safety validation and regression testing
- **Report & playbook**: Writes detailed reports and generates a final Ansible playbook containing only _proven-working_ remediation commands.

All working files go under the `reports/` directory and pipeline work is stored in `pipeline_work/`.

## Prerequisites

- **Python**: 3.10+ recommended
- **Dependencies**:

```bash
pip install -r requirements.txt
```

- **OpenAI-compatible API** (e.g. OpenRouter):

  - Environment variables (typically defined in `.env`):
    - `OPENROUTER_API_KEY` — API key
    - `OPENROUTER_MODEL` — model name (e.g. `meta-llama/llama-3.1-70b-instruct`)
    - `OPENROUTER_BASE_URL` — base URL, default `https://openrouter.ai/api/v1`

- **Target host**:
  - Rocky Linux (10 in current defaults) with OpenSCAP content installed (`oscap` and SCAP content such as `ssg-rl10-ds.xml`).
  - SSH access with either passwordless sudo or a known sudo password.

## Quick start

1. **Clone and install dependencies**

   ```bash
   git clone <this-repo-url>
   cd F25_Capstone_L3

   # (Optional) create and activate a virtualenv
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate

   pip install -r requirements.txt
   ```

2. **Configure your LLM endpoint**

   Create a `.env` file in the repo root (based on `env.template` if present):

   ```bash
   OPENROUTER_API_KEY=your_api_key_here
   OPENROUTER_MODEL=meta-llama/llama-3.1-70b-instruct
   OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
   ```

3. **Create `inventory.yml` for your Rocky host**

   Either copy from `inventory.yml.template` (if present) or start from this example and adjust IP, user, key path, and sudo password:

   ```yaml
   all:
     hosts:
       mertcis:
         ansible_host: 192.168.124.129 # or your VM IP / hostname
         ansible_port: 22
         ansible_user: llmagent1 # SSH user
         ansible_ssh_private_key_file: /path/to/id_ed25519
         ansible_ssh_common_args: "-o StrictHostKeyChecking=no"
         ansible_become: true
         ansible_become_method: sudo
         ansible_become_password: YOUR_SUDO_PASSWORD
   ```

4. **Run the multi-agent pipeline against your host**

   From the repo root (adjust flags as needed):

   ```bash
   python main_multiagent.py \
     --inventory inventory.yml \
     --host 192.168.124.130 \
     --user llmagent1 \
     --sudo-password "<sudo_password>" \
     --key /path/to/your/ssh/key \
     --profile xccdf_org.ssgproject.content_profile_cis \
     --datastream /usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml \
     --max-vulns 25 \
     --min-severity 2 \
     --workers 4
   ```

5. **Review results and playbooks**

   After the run completes, inspect `reports/` and `pipeline_work/` for the aggregated results, reports, and generated Ansible playbooks (see "Outputs" below).

## Inventory and SSH configuration

The agent relies on an Ansible-style inventory to describe how to reach the target host. A sample `inventory.yml` is provided and currently points to a host named `mertcis`:

- Host, user, SSH key, and sudo settings are defined under `all.hosts.mertcis`.
- `qa_agent_adaptive.py` itself only needs the `--host`, `--user`, `--key` and `--sudo-password` flags; the `--inventory` flag is used mainly for consistency with other tooling and for future Ansible or legacy-flow integration.

A minimal `inventory.yml` for a single Rocky host looks like:

```yaml
all:
  hosts:
    mertcis:
      ansible_host: 192.168.124.129 # or your VM IP / hostname
      ansible_port: 22
      ansible_user: llmagent1 # SSH user
      ansible_ssh_private_key_file: /path/to/id_ed25519
      ansible_ssh_common_args: "-o StrictHostKeyChecking=no"
      ansible_become: true
      ansible_become_method: sudo
      ansible_become_password: YOUR_SUDO_PASSWORD
```

Recommended workflow is to keep a generic `inventory.yml.template` (no real passwords) in git and create a local `inventory.yml` by copying and filling in environment-specific values. Adapt `inventory.yml` to your environment (IP/hostname, SSH key path, and sudo behaviour), and avoid committing real passwords to version control.

## Running the multi-agent pipeline

From the repository root, a typical run looks like:

```bash
python main_multiagent.py \
  --inventory inventory.yml \
  --host 192.168.124.130 \
  --user llmagent1 \
  --sudo-password "<sudo_password>" \
  --key /path/to/ssh/key \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --datastream /usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml \
  --max-vulns 25 \
  --min-severity 2 \
  --workers 4
```

Key flags:

- **`--inventory`**: Ansible inventory file describing target hosts.
- **`--host` / `--user` / `--key` / `--sudo-password`**: SSH connectivity to the Rocky host.
- **`--profile` / `--datastream`**: Which OpenSCAP content/profile to run (CIS Rocky 10 by default).
- **`--max-vulns` / `--min-severity`**: Control which and how many findings are processed.
- **`--workers`**: Number of concurrent workers for parallel processing (default: 2).
- **`--triage-mode`**: Triage mode - "auto" (skip low-risk) or "smart" (LLM-based decision).
- **`--skip-scan`**: Skip initial scan and use existing parsed results.

## Outputs

In `reports/` and `pipeline_work/`, you will typically see:

**Main Reports:**
- `reports/aggregated_results.json` — Complete pipeline results for all findings
- `reports/pipeline_report.txt` and `reports/pipeline_report.pdf` — Executive summary
- `reports/final_remediation_playbook_*.yml` — Ansible playbook with validated remediation commands
- Agent-specific reports: `triage_report.pdf`, `remedy_report.pdf`, `review_report.pdf`, `qa_report.pdf`

**Working Files:**
- `pipeline_work/agent_reports/` — Individual agent outputs and decisions
- `pipeline_work/scans/` — OpenSCAP scan results and verification data
- `pipeline_work/remedy/` — LLM conversation transcripts and command logs

These files are considered **generated artifacts** and are ignored by git.

## Repository layout (main files)

**Core Multi-Agent System:**
- **`main_multiagent.py`**: Primary entrypoint; orchestrates the full multi-agent pipeline for security compliance remediation.
- **`agents/`**: Multi-agent components - `triage_agent.py`, `remedy_agent.py`, `review_agent.py`, `qa_agent.py`, and `base_agent.py`.
- **`workflow/`**: Pipeline orchestration - `pipeline.py` (single-finding workflow) and `concurrent_manager.py` (parallel processing).
- **`aggregation/`**: Results processing - `result_aggregator.py` combines outputs from all agents into final reports.

**Core Infrastructure:**
- **`openscap_cli.py`**: SSH-based wrapper around the `oscap` CLI for running security scans.
- **`parse_openscap.py`**: Parser that converts OpenSCAP XML/ARF results into JSON format.
- **`schemas.py`**: Pydantic data models for all agent inputs/outputs and pipeline communication.
- **`helpers/`**: Shared utilities - LLM interface, command execution, scanning, and report generation.

**Configuration & Output:**
- **`inventory.yml`**: Ansible inventory describing target hosts (IP, SSH credentials, sudo settings).
- **`requirements.txt`**: Python dependencies for the multi-agent system.
- **`reports/`**: Generated reports, playbooks, and aggregated results (ignored by git).
- **`pipeline_work/`**: Working files from pipeline execution (ignored by git).

**Legacy Code:**
- **`legacy_code/`**: Older implementations including single-agent systems, tools, tests, and Nessus-based workflows.

## Legacy code

Older implementations are preserved under `legacy_code/`:

- **`single_agent/`**: Original adaptive single-agent implementations including `qa_agent_adaptive.py`, standalone triage runners, and DISA STIG tools.
- **`nessus/`**: Original Nessus-based vulnerability scanning system (`agent.py`, `parse_nessus.py`, `run_pipeline.py`) — see `legacy_code/nessus/README_nessus.md`.
- **`tools/`**: Utility scripts and sample data generation.
- **`tests/`**: Unit tests for legacy components.
- **`samples/`**: Example reports from older system runs.

These implementations are **not** required to run the current multi-agent system, but are kept for reference and potential future integration.
