# Multi-Agent OpenSCAP Security Compliance System

An automated security compliance scanning and remediation pipeline for Rocky Linux systems, powered by OpenSCAP and LLM-driven agents.

The system scans a target VM with OpenSCAP, then processes every failed finding through a multi-agent workflow — Triage, Remedy, Review, and QA — to automatically remediate security vulnerabilities with built-in safety checks. Dependency-grouped findings are remediated in parallel for throughput, while each finding is verified immediately via single-rule scan after remediation.

## Table of Contents
- [Requirements](#requirements)
- [External Dependencies](#external-dependencies)
- [Environmental Variables](#environmental-variables)
- [Installation and Setup](#installation-and-setup)
- [Usage](#usage)
- [Features](#features)
- [Documentation](#documentation)
- [Credits and Acknowledgments](#credits-and-acknowledgments)
- [License](#license)
- [Contact Information](#contact-information)

## Requirements

This code has been run and tested using the following internal and external components.

### Environment
- Rocky Linux 9/10 (target VM)
- Python 3.10+
- SSH access to target host (key-based authentication)
- OpenSCAP installed on target (`oscap` CLI and SCAP content such as `ssg-rl9-ds.xml` or `ssg-rl10-ds.xml`)

### Program
- pydantic >= 2
- pydantic-ai[openai] >= 0.0.15
- requests >= 2.31.0
- python-dotenv >= 1.0.1
- rich >= 13.0.0
- pyyaml >= 6.0.0
- ansible-core >= 2.15.0
- reportlab >= 4.0.0
- braintrust >= 0.0.160
- pytest >= 7.0.0
- click >= 8.0.0
- responses >= 0.23.0

### Tools
- [GitHub](https://github.com/timothyk31/482) - Main repository
- Git for version control
- OpenRouter API (or any OpenAI-compatible LLM endpoint)

## External Dependencies
- Python 3.10+ - Download latest version at https://www.python.org/downloads/
- Git - Download latest version at https://git-scm.com/book/en/v2/Getting-Started-Installing-Git
- OpenSCAP - Must be installed on the target Rocky Linux VM (`sudo dnf install openscap-scanner scap-security-guide`)

## Environmental Variables

The system uses environment variables for LLM API configuration, typically defined in a `.env` file in the project root.

**Required:**
| Variable | Description |
|---|---|
| `OPENROUTER_API_KEY` | API key for the LLM provider |
| `OPENROUTER_MODEL` | Default LLM model name (e.g. `meta-llama/llama-3.1-70b-instruct`) |

**Optional:**
| Variable | Description | Default |
|---|---|---|
| `OPENROUTER_BASE_URL` | Base URL for the API | `https://openrouter.ai/api/v1` |
| `OPENROUTER_HTTP_REFERER` | HTTP referer header for API requests | — |
| `OPENROUTER_APP_TITLE` | Application title for API headers | — |
| `REMEDY_AGENT_MODEL` | Override model for the Remedy agent | Uses `OPENROUTER_MODEL` |
| `REVIEW_AGENT_MODEL` | Override model for the Review agent | Uses `OPENROUTER_MODEL` |
| `QA_AGENT_V2_MODEL` | Override model for the QA agent | Uses `OPENROUTER_MODEL` |
| `TRIAGE_MODEL` | Override model for the Triage agent | Uses `OPENROUTER_MODEL` |

## Installation and Setup

Download this code repository using git:

```bash
git clone https://github.com/timothyk31/482.git
```

Navigate to the project directory:

```bash
cd 482/S26_Capstone_L3
```

(Optional) Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file in the project root with your LLM API credentials:

```bash
OPENROUTER_API_KEY=your_api_key_here
OPENROUTER_MODEL=meta-llama/llama-3.1-70b-instruct
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
```

Create an `inventory.yml` for your target Rocky Linux host:

```yaml
all:
  hosts:
    myhost:
      ansible_host: 192.168.124.129  # Your VM IP or hostname
      ansible_port: 22
      ansible_user: llmagent1        # SSH user
      ansible_ssh_private_key_file: /path/to/id_ed25519
      ansible_ssh_common_args: "-o StrictHostKeyChecking=no"
      ansible_become: true
      ansible_become_method: sudo
      ansible_become_password: YOUR_SUDO_PASSWORD
```

Ensure your target VM has OpenSCAP installed:

```bash
sudo dnf install openscap-scanner scap-security-guide
```

## Usage

Run the multi-agent pipeline against your target host:

```bash
python main_multiagent.py \
  --inventory inventory.yml \
  --host 192.168.124.130 \
  --user llmagent1 \
  --sudo-password "<sudo_password>" \
  --key /path/to/your/ssh/key \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --datastream /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml \
  --max-vulns 25 \
  --min-severity 2
```

### Key CLI Flags

**Target Host:**
| Flag | Description | Default |
|---|---|---|
| `--inventory` | Ansible inventory file describing target hosts | — |
| `--host` | Target host IP or hostname | — |
| `--user` | SSH user | `root` |
| `--key` | SSH private key path | — |
| `--port` | SSH port | `22` |
| `--sudo-password` | Sudo password on target | — |

**Pipeline Options:**
| Flag | Description | Default |
|---|---|---|
| `--min-severity` | Minimum severity to process (0-4) | `2` |
| `--max-vulns` | Cap the number of vulnerabilities to process | All |
| `--max-remedy-attempts` | Max remedy retries per finding | `3` |
| `--max-parallel-groups` | Max dependency groups to remediate in parallel | `4` |
| `--skip-scan` | Skip initial scan; use existing parsed JSON | — |

**Agent Options:**
| Flag | Description | Default |
|---|---|---|
| `--triage-mode` | Triage LLM quality tier (`fast`, `balanced`, `smart`) | `balanced` |
| `--review-model` | Override the Review agent LLM model | env variable |
| `--lenient-triage` | Prefer safe_to_remediate over requires_human_review | `false` |
| `--max-complexity` | Max remediation complexity (`low`, `medium`, `high`) | `medium` |

### Example: Skip scan and use existing results

```bash
python main_multiagent.py \
  --skip-scan --parsed-json oscap_stig_rl9_parsed.json \
  --host 10.244.72.95 --user root --key ~/.ssh/id_rsa
```

### Example: Limit scope for testing

```bash
python main_multiagent.py \
  --inventory inventory.yml \
  --max-vulns 5 --min-severity 3
```

### Output Artifacts

After the run completes, inspect `reports/` and `pipeline_work/`:

**Main Reports:**
- `reports/<model>_<timestamp>/v2_aggregated_results.json` — Complete pipeline results for all findings
- `reports/<model>_<timestamp>/v2_pipeline_report.txt` — Text summary report
- `reports/<model>_<timestamp>/triage_report.pdf` — Triage decisions PDF
- Agent-specific reports for remedy, review, and QA

**Working Files:**
- `pipeline_work/agent_reports/` — Individual agent outputs and decisions
- `pipeline_work/scans/` — OpenSCAP scan results and verification data
- `pipeline_work/transcripts/` — LLM conversation transcripts per agent

These files are generated artifacts and are ignored by git.

## Features

- **Multi-Agent Architecture**: Four specialized LLM-driven agents (Triage, Remedy, Review, QA) work together with distinct responsibilities and safety checks
- **Automated Triage**: LLM-based risk assessment decides whether each finding should be remediated, sent for human review, or skipped
- **Parallel Remediation**: Findings are grouped by shared system resources (PAM, sysctl, mounts, etc.) and groups are remediated in parallel via dependency-aware worker pools
- **Review + QA Approval Gate**: Every remediation plan is validated by a Review agent for correctness and a QA agent for system safety before commands are executed
- **Per-Finding Verification**: Each remediated finding is immediately verified with a targeted single-rule OpenSCAP scan
- **Automatic Retries**: Failed remediations are retried with feedback from previous attempts (up to configurable max)
- **Comprehensive Reporting**: JSON results, text reports, and PDF summaries are generated for every run
- **SSH-Based Execution**: All commands run over SSH on the target VM — no agent software required on the target
- **Configurable LLM Models**: Each agent can use a different LLM model via environment variable overrides

## Documentation

### Repository Layout

**Core Multi-Agent System:**
- `main_multiagent.py` — Primary entrypoint; orchestrates the full pipeline
- `agents/` — Agent implementations: `triage_agent.py`, `remedy_agent.py`, `review_agent.py`, `qa_agent_v2.py`, and V2 wrappers
- `workflow/` — Pipeline orchestration: `pipeline_v2.py` (single-finding workflow)
- `schemas.py` — Pydantic data models for all agent inputs/outputs

**Core Infrastructure:**
- `openscap_cli.py` — SSH-based wrapper around the `oscap` CLI
- `parse_openscap.py` — Parser converting OpenSCAP XML/ARF to JSON
- `helpers/` — Shared utilities: LLM interface (`llm_interface.py`), command execution (`command_executor.py`), scanning (`scanner.py`), and report generation

**Configuration:**
- `inventory.yml` — Ansible inventory describing target hosts
- `requirements.txt` — Python dependencies
- `.env` — LLM API credentials (not committed)

**Legacy Code:**
- `legacy_code/` — Older implementations including single-agent systems, Nessus-based workflows, and utility scripts (not required for current system)

### Troubleshooting

- **SSH connection failures**: Verify your SSH key, host IP, and that the target VM is reachable. Ensure `StrictHostKeyChecking=no` is set if using a new host.
- **OpenSCAP not found**: Install OpenSCAP on the target VM with `sudo dnf install openscap-scanner scap-security-guide`.
- **LLM API errors**: Check that `OPENROUTER_API_KEY` is valid and `OPENROUTER_BASE_URL` is correct in your `.env` file.
- **Findings skipped as SSH-related**: The pipeline automatically skips SSH configuration findings that could break the active SSH session.

## Credits and Acknowledgments

### Contributors
- [Timothy Kurniawan](https://github.com/timothyk31)
- [Vishal Suresh](https://github.com/vishalsuresh06)
- [Nicholas Turoci](https://github.com/n2rowc)
- [Lawrence Wong](https://github.com/laroldz)
- [Sophie L](https://github.com/sophiel19)

### Third-Party Libraries
This project uses the following third-party libraries:
- [Pydantic](https://docs.pydantic.dev/) (MIT License) — Data validation and settings management
- [Rich](https://github.com/Textualize/rich) (MIT License) — Terminal formatting and progress bars
- [ReportLab](https://www.reportlab.com/) (BSD License) — PDF report generation
- [PyYAML](https://pyyaml.org/) (MIT License) — YAML inventory parsing
- [python-dotenv](https://github.com/theskumar/python-dotenv) (BSD License) — Environment variable loading
- [Braintrust](https://www.braintrust.dev/) (MIT License) — LLM evaluation framework
- [Ansible Core](https://github.com/ansible/ansible) (GPL-3.0 License) — Infrastructure automation

### Acknowledgments
- OpenSCAP project for the security compliance scanning framework
- SCAP Security Guide for the STIG/CIS benchmark content
- OpenRouter for LLM API access
- L3Harris for mentorship

## License

This project is developed as part of the Texas A&M University CSCE 482 Capstone course (Spring 2026).

## Contact Information

For any questions or issues, please contact the team through the GitHub repository or reach out to the contributors listed above.
