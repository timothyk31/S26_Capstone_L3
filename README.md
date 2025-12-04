## Adaptive OpenSCAP QA Agent

This repository’s primary entrypoint is an adaptive OpenSCAP-based QA agent that connects to a Rocky Linux target over SSH, runs compliance scans, and uses an LLM (via an OpenAI-compatible API such as OpenRouter) to iteratively remediate and verify vulnerabilities.

The main script is:

- `qa_agent_adaptive.py` — adaptive, per-vulnerability remediation loop

Older Nessus-based and QA-loop flows are preserved in `legacy_files/` for reference.

## What the adaptive agent does

- **Scan**: Uses `openscap_cli.OpenSCAPScanner` to run an OpenSCAP XCCDF evaluation on the remote host.
- **Parse**: Converts the resulting XML/ARF into a normalized JSON list of failed/error rules via `parse_openscap.py`.
- **Adapt & remediate**: For each vulnerability:
  - Builds a rich prompt with rule details and prior attempts.
  - Lets an LLM propose concrete shell commands (executed via SSH, one at a time).
  - Verifies the effect by re-running a focused OpenSCAP scan.
  - Retries with feedback up to `--max-attempts` times.
- **Report & playbook**: Writes a detailed text/PDF report plus a final Ansible playbook containing only _proven-working_ remediation commands.

All working files for the adaptive runs go under the directory passed via `--work-dir` (default `adaptive_qa_work/`).

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

4. **Run the adaptive agent against your host**

   From the repo root (adjust flags as needed):

   ```bash
   python -B qa_agent_adaptive.py \
     --host 192.168.124.130 \
     --user llmagent1 \
     --sudo-password "<sudo_password>" \
     --inventory inventory.yml \
     --profile xccdf_org.ssgproject.content_profile_cis \
     --datastream /usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml \
     --work-dir adaptive_qa_work \
     --max-vulns 25 \
     --min-severity 2 \
     --max-attempts 3 \
     --key C:\Users\coope\.ssh\rocky_vm \
     --randomize \
     --non-interactive
   ```

5. **Review results and playbooks**

   After the run completes, inspect `adaptive_qa_work/` for the reports and generated Ansible playbook (see “Outputs” below).

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

## Running the adaptive agent

From the repository root, a typical non-interactive run looks like:

```bash
python -B qa_agent_adaptive.py \
  --host 192.168.124.130 \
  --user llmagent1 \
  --sudo-password "<sudo_password>" \
  --inventory inventory.yml \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --datastream /usr/share/xml/scap/ssg/content/ssg-rl10-ds.xml \
  --work-dir adaptive_qa_work \
  --max-vulns 25 \
  --min-severity 2 \
  --max-attempts 3 \
  --key C:\Users\coope\.ssh\rocky_vm \
  --randomize \
  --non-interactive
```

Key flags:

- **`--host` / `--user` / `--key` / `--sudo-password`**: SSH connectivity to the Rocky host.
- **`--profile` / `--datastream`**: Which OpenSCAP content/profile to run (CIS Rocky 10 by default).
- **`--work-dir`**: Where all XML/JSON logs, per-vulnerability attempts, transcripts, and final reports/playbooks are written.
- **`--max-vulns` / `--min-severity`**: Control which and how many findings are processed.
- **`--max-attempts`**: Max remediation attempts per vulnerability.
- **`--randomize`**: Shuffle vulnerability order.
- **`--non-interactive`**: Process all selected vulnerabilities without prompting between them.

## Outputs

In `adaptive_qa_work/` (or your chosen `--work-dir`), you will typically see:

- `adaptive_results.json` — machine-readable summary of all attempts and outcomes.
- `adaptive_report.txt` and `adaptive_report.pdf` — human-readable reports.
- `final_remediation_playbook_*.yml` — Ansible playbook with only successful remediation commands.
- `final_playbook_summary_*.txt` — summary listing vulnerabilities and commands included in the playbook.
- Per-vulnerability artifacts (e.g. `fix_openscap_001_attempt1.*`, `verify_<rule>.xml/json`, LLM transcripts).

These files are considered **generated artifacts** and are ignored by git.

## Repository layout (main files)

- **`qa_agent_adaptive.py`**: Primary entrypoint; orchestrates OpenSCAP scans, parses results, drives the LLM remediation loop, verifies fixes, and writes reports/playbooks under `--work-dir`.
- **`openscap_cli.py`**: SSH-based wrapper around the `oscap` CLI; provides the `OpenSCAPScanner` used by the adaptive agent (and some legacy tools) to run scans and download XML results.
- **`parse_openscap.py`**: Parser that converts OpenSCAP XML/ARF results into a JSON list of failed/error rules compatible with the `Vulnerability` schema.
- **`schemas.py`**: Pydantic models shared across the project, including `Vulnerability`, `RemediationSuggestion`, `RunCommandResult`, `ToolVerdict`, and `BatchResult`.
- **`qa_framework.py`**: Ansible playbook abstraction layer (`AnsibleTask`, `RemediationPlaybook`, plus a legacy `VulnerabilityRemediation` helper) used by `remediation_bridge.py` and indirectly by the adaptive agent when generating final playbooks.
- **`remediation_bridge.py`**: Translates `RemediationSuggestion` objects into concrete Ansible tasks and composes them into a `RemediationPlaybook`; called by the adaptive agent to build the final “proven remediation” playbook.
- **`mitm_proxy.py`**: Optional HTTP proxy for OpenAI-compatible APIs that logs prompts and model responses into `adaptive_qa_work/llm_mitm.txt` for auditing or debugging.
- **`inventory.yml`**: Environment-specific Ansible inventory describing how to reach your Rocky host (IP, SSH user/key, sudo settings). Treat this as a local config file and avoid committing real secrets.
- **`requirements.txt`**: Python dependencies for the adaptive agent and its supporting tooling.
- **`setup.py`**: Basic packaging metadata that allows the project to be installed as a package (e.g. via `pip install -e .`).
- **`test_qa_framework.py`**: Unit tests for the `qa_framework.py` abstractions (mainly relevant when extending or refactoring the playbook-generation logic).
- **`verify_commit.sh`**: Developer helper script to check for common security and hygiene issues before committing (e.g. `.env` tracked in git, SSH keys, work directories, missing key files).
- **`adaptive_qa_work/`**: Default working directory for `qa_agent_adaptive.py` where scan results, logs, reports, and generated playbooks are written (ignored by git).

## Legacy code

Older, Nessus-based and QA-loop oriented workflows are preserved under `legacy_files/`:

- Nessus parsing and remediation pipeline (`agent.py`, `parse_nessus.py`, `run_pipeline.py`) — see `legacy_files/README_nessus.md`.
- QA loop and interactive end-to-end scripts that combine OpenSCAP, the Nessus-style agent, and Ansible.
- Example SSH setup and runner scripts under `legacy_files/tools/`.

They are **not** required to run the adaptive OpenSCAP QA agent, but are kept for future reference and experimentation.
