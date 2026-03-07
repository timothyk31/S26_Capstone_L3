## Multi-Agent OpenSCAP Security Compliance System

This repository implements a **multi-agent V2 architecture** for automated security compliance scanning and remediation on Rocky Linux 9 systems using OpenSCAP STIG profiles and LLM-driven agents communicating via OpenRouter.

The main entry point is:

- **`main_multiagent.py`** — V2 pipeline orchestrator: **Triage → Remedy (fix → Review+QA approval → scan)**

Legacy single-agent implementations are preserved in `legacy_code/` for reference.

---

## Architecture Overview

### V2 Pipeline Flow

The V2 pipeline processes each vulnerability through a coordinated agent chain with a **pre-scan approval gate**: the Review and QA agents evaluate the fix *before* the verification scan runs.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        main_multiagent.py                           │
│                     (CLI + orchestration layer)                     │
└──────────┬──────────────────────────────────────────────────────────┘
           │
           │  For each vulnerability (concurrent via ThreadPoolExecutor)
           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        PipelineV2                                   │
│                  (workflow/pipeline_v2.py)                           │
│                                                                     │
│  Stage 1: Triage ──────────────────────────────────────────────►    │
│     │  TriageAgent classifies finding:                              │
│     │    • safe_to_remediate  → continue                            │
│     │    • requires_human_review → stop                             │
│     │    • too_dangerous → discard                                  │
│     │                                                               │
│  Stage 2: Remedy Loop (up to max_remedy_attempts) ──────────►      │
│     │                                                               │
│     │  ┌─────────────────────────────────────────────────────┐      │
│     │  │ RemedyAgentV2 (wraps RemedyAgent + ReviewAgentV2)   │      │
│     │  │                                                     │      │
│     │  │  Step 1: RemedyAgent generates & applies fix        │      │
│     │  │          (LLM tool-calling: run_cmd, write_file,    │      │
│     │  │           read_file, scan)                          │      │
│     │  │                                                     │      │
│     │  │  Step 2: ReviewAgentV2 evaluates fix quality        │      │
│     │  │    ├─ ReviewAgent (LLM-only) → approve/reject       │      │
│     │  │    └─ If approved → QAAgentV2 (LLM-only expert      │      │
│     │  │       safety opinion) → approve/reject              │      │
│     │  │                                                     │      │
│     │  │  Step 3: If BOTH approve → verification scan        │      │
│     │  │    ├─ Scan passes  → SUCCESS                        │      │
│     │  │    └─ Scan fails   → retry with feedback            │      │
│     │  │                                                     │      │
│     │  │  If either rejects → retry with feedback            │      │
│     │  └─────────────────────────────────────────────────────┘      │
│                                                                     │
│  Aggregation → V2FindingResult                                      │
└─────────────────────────────────────────────────────────────────────┘
           │
           ▼
    Reports + Ansible Playbook + Braintrust Evaluation
```

### Agent Architecture

All agents inherit from `BaseAgent` (abstract base class with `process()` contract). V2 agents compose V1 agents rather than replacing them.

| Agent | Type | LLM Model (default) | Role |
|---|---|---|---|
| **TriageAgent** | Heuristic + LLM classification | `anthropic/claude-3.5-sonnet` (balanced mode) | Classifies findings into safe/review/dangerous categories |
| **RemedyAgent** | LLM tool-calling (4 tools) | Configurable via env | Generates and executes remediation commands on target host |
| **ReviewAgent** | LLM-only (no tools) | `nvidia/nemotron-3-nano-30b-a3b:free` | Evaluates remediation quality, security score, best practices |
| **QAAgentV2** | LLM-only (no tools) | `nvidia/nemotron-3-nano-30b-a3b:free` | Expert safety opinion on applied remediation |
| **RemedyAgentV2** | Composition wrapper | — | Wraps RemedyAgent + ReviewAgentV2 for the V2 approval flow |
| **ReviewAgentV2** | Composition wrapper | — | Chains ReviewAgent → QAAgentV2, returns `PreApprovalResult` |

### Data Flow (Pydantic Schemas)

```
Vulnerability
    │
    ▼
TriageInput ──► TriageAgent ──► TriageDecision
    │                               │
    │  (if should_remediate=True)   │
    ▼                               ▼
RemedyInput ──► RemedyAgent ──► RemediationAttempt
    │                               │
    ▼                               ▼
ReviewInput ──► ReviewAgent ──► ReviewVerdict
    │                               │
    ▼                               ▼
QAInput ────► QAAgentV2 ────► QAResult
    │
    ▼
PreApprovalResult (combined Review + QA verdict)
    │
    ▼
V2FindingResult (complete pipeline result per finding)
    │
    ▼
V2AggregatedReport (final output for entire run)
```

### Helper Infrastructure

| Module | Purpose |
|---|---|
| `helpers/llm_base.py` | `ToolCallingLLM` — reusable LLM wrapper for tool-calling agent sessions |
| `helpers/command_executor.py` | `ShellCommandExecutor` — executes commands on remote host via SSH |
| `helpers/scanner.py` | `Scanner` — wraps OpenSCAPScanner for per-vulnerability verification scans |
| `helpers/llm_metrics.py` | `LLMMetricsTracker` — thread-safe tracker for API call timing, tokens, and cost |
| `helpers/agent_report_writer.py` | `AgentReportWriter` — persists each agent's I/O to disk for auditability |
| `helpers/utils.py` | Command normalization (apt→dnf), error categorization |

### Supporting Modules

| Module | Purpose |
|---|---|
| `openscap_cli.py` | `OpenSCAPScanner` — SSH-based wrapper around the `oscap` CLI |
| `parse_openscap.py` | Parses OpenSCAP XML/ARF results into normalized JSON |
| `schemas.py` | All Pydantic data models (V1 + V2 schemas) |
| `pipeline_pdf_writer.py` | Generates comprehensive PDF reports from V2 pipeline results |
| `braintrust_eval_writer.py` | Logs pipeline results to Braintrust for experiment comparison |
| `qa_framework.py` | Ansible task/playbook models (`AnsibleTask`, `RemediationPlaybook`) |
| `remediation_bridge.py` | Converts shell commands to Ansible tasks via pattern matching |
| `mitm_proxy.py` | HTTP proxy for logging/debugging LLM API calls |

---

## What the System Does

1. **Scan**: Runs an OpenSCAP XCCDF/STIG evaluation on the remote host via SSH (`openscap_cli.OpenSCAPScanner`).
2. **Parse**: Converts the resulting XML/ARF into a normalized JSON list of failed/error rules (`parse_openscap.py`).
3. **Multi-agent V2 pipeline**: For each vulnerability:
   1. **Triage Agent** — Classifies the finding using heuristics (partition/filesystem patterns) and LLM classification (with fallback chain). Outputs risk level and remediation decision.
   2. **Remedy Agent** — Generates and executes remediation commands on the target host via an LLM tool-calling session with 4 tools: `run_cmd`, `write_file`, `read_file`, `scan`.
   3. **Review Agent** — LLM-only evaluation of fix quality, security score (1-10), best practices adherence, and concerns.
   4. **QA Agent V2** — LLM-only expert safety opinion: checks for side effects, service disruption, regression risk.
   5. **Verification Scan** — Re-runs OpenSCAP for the specific rule to confirm the fix worked.
4. **Report & Playbook**: Generates JSON results, text/PDF reports, triage PDF, full pipeline PDF, and a consolidated Ansible playbook containing only verified-working remediation commands.
5. **Evaluation**: Optionally logs results to Braintrust for cross-run experiment comparison.

---

## Prerequisites

- **Python**: 3.10+
- **Dependencies**:

```bash
pip install -r requirements.txt
```

- **OpenRouter API** (LLM provider):
  - Environment variables (typically defined in `.env`):
    - `OPENROUTER_API_KEY` — API key (required)
    - `OPENROUTER_MODEL` — default model name (e.g. `meta-llama/llama-3.1-70b-instruct`)
    - `OPENROUTER_BASE_URL` — base URL (default: `https://openrouter.ai/api/v1`)
    - `REVIEW_AGENT_MODEL` — override model for Review agent
    - `QA_AGENT_V2_MODEL` — override model for QA V2 agent
    - `BRAINTRUST_API_KEY` — (optional) for experiment logging

- **Target host**:
  - Rocky Linux 9 with OpenSCAP content installed (`oscap` + SCAP content e.g. `ssg-rl9-ds.xml`).
  - SSH access with either passwordless sudo or a known sudo password.

## Quick Start

1. **Clone and install dependencies**

   ```bash
   git clone <this-repo-url>
   cd S26_Capstone_L3

   # (Optional) create and activate a virtualenv
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate

   pip install -r requirements.txt
   ```

2. **Configure your LLM endpoint**

   Create a `.env` file in the repo root:

   ```bash
   OPENROUTER_API_KEY=your_api_key_here
   OPENROUTER_MODEL=meta-llama/llama-3.1-70b-instruct
   OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
   # Optional agent-specific model overrides:
   # REVIEW_AGENT_MODEL=nvidia/nemotron-3-nano-30b-a3b:free
   # QA_AGENT_V2_MODEL=nvidia/nemotron-3-nano-30b-a3b:free
   # BRAINTRUST_API_KEY=your_braintrust_key
   ```

3. **Create `inventory.yml` for your Rocky host**

   ```yaml
   all:
     hosts:
       myhost:
         ansible_host: 192.168.124.129  # VM IP / hostname
         ansible_port: 22
         ansible_user: llmagent1
         ansible_ssh_private_key_file: /path/to/id_ed25519
         ansible_ssh_common_args: "-o StrictHostKeyChecking=no"
         ansible_become: true
         ansible_become_method: sudo
         ansible_become_password: YOUR_SUDO_PASSWORD
   ```

4. **Run the V2 pipeline**

   ```bash
   python main_multiagent.py \
     --inventory inventory.yml \
     --profile xccdf_org.ssgproject.content_profile_stig \
     --datastream /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml \
     --max-vulns 25 \
     --min-severity 2 \
     --workers 4
   ```

5. **Review results**

   Inspect `reports/` and `pipeline_work/` for aggregated results, reports, and Ansible playbooks (see "Outputs" below).

## Inventory and SSH Configuration

The pipeline relies on an Ansible-style inventory to describe remote host connectivity. You can either supply `--inventory inventory.yml` or pass connectivity flags directly (`--host`, `--user`, `--key`, `--sudo-password`).

A minimal `inventory.yml`:

```yaml
all:
  hosts:
    myhost:
      ansible_host: 192.168.124.129
      ansible_port: 22
      ansible_user: llmagent1
      ansible_ssh_private_key_file: /path/to/id_ed25519
      ansible_ssh_common_args: "-o StrictHostKeyChecking=no"
      ansible_become: true
      ansible_become_method: sudo
      ansible_become_password: YOUR_SUDO_PASSWORD
```

Avoid committing real passwords to version control.

## Running the Pipeline

```bash
python main_multiagent.py \
  --inventory inventory.yml \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --datastream /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml \
  --max-vulns 25 \
  --min-severity 2 \
  --workers 4
```

### CLI Flags

| Flag | Description | Default |
|---|---|---|
| `--inventory` | Ansible inventory file (reads first host) | — |
| `--host` / `--user` / `--key` / `--sudo-password` | Direct SSH connectivity | — |
| `--port` | SSH port | `22` |
| `--profile` | OpenSCAP XCCDF profile | `xccdf_org.ssgproject.content_profile_stig` |
| `--datastream` | SCAP datastream path on target | `/usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml` |
| `--skip-scan` | Skip initial scan; use existing XML/JSON | `false` |
| `--parsed-json` | Path to pre-parsed JSON findings | `oscap_stig_rl9_parsed.json` |
| `--min-severity` | Minimum severity to process (0–4) | `2` |
| `--max-vulns` | Cap number of findings to process | unlimited |
| `--max-remedy-attempts` | Max remedy retries per finding | `3` |
| `--triage-mode` | Triage LLM tier: `fast`, `balanced`, `smart` | `balanced` |
| `--review-model` | Override Review agent LLM model | env `REVIEW_AGENT_MODEL` |
| `--workers` | Concurrent pipeline workers | `1` |
| `--work-dir` | Working directory for intermediate artifacts | `./pipeline_work` |
| `--report-dir` | Output directory for reports | `./reports` |
| `--experiment-name` | Braintrust experiment name | auto-generated |

## Outputs

### Main Reports (`reports/`)

- `v2_aggregated_results.json` — Complete pipeline results for all findings
- `v2_pipeline_report.txt` — Text summary of all findings and agent decisions
- `pipeline_report.pdf` — Full PDF report with executive summary, per-finding detail, and LLM metrics
- `triage_report.pdf` — Triage-specific PDF with scan statistics and categorized findings

### Working Files (`pipeline_work/`)

- `agent_reports/` — Per-agent I/O for every finding (triage, remedy, review, QA subdirectories)
- `scans/` — OpenSCAP verification scan XML and parsed JSON per finding
- `remedy/` — LLM conversation transcripts and command execution logs

These are **generated artifacts** and should be ignored by git.

---

## Repository Layout

```
S26_Capstone_L3/
├── main_multiagent.py          # Primary entrypoint — V2 pipeline orchestrator
├── schemas.py                  # All Pydantic data models (V1 + V2)
├── openscap_cli.py             # SSH-based OpenSCAP CLI wrapper
├── parse_openscap.py           # OpenSCAP XML/ARF → JSON parser
├── pipeline_pdf_writer.py      # Full pipeline PDF report generator
├── braintrust_eval_writer.py   # Braintrust experiment logger
├── qa_framework.py             # Ansible task/playbook models
├── remediation_bridge.py       # Shell command → Ansible task converter
├── mitm_proxy.py               # HTTP proxy for LLM API debugging
├── requirements.txt            # Python dependencies
├── setup.py                    # Package setup
├── inventory.yml               # Ansible inventory (local, not committed)
│
├── agents/                     # Multi-agent components
│   ├── base_agent.py           #   Abstract base class (process() contract)
│   ├── triage_agent.py         #   Heuristic + LLM vulnerability classifier
│   ├── remedy_agent.py         #   LLM tool-calling remediation executor
│   ├── remedy_agent_v2.py      #   V2 wrapper: fix → approval → scan
│   ├── review_agent.py         #   LLM-only remediation quality reviewer
│   ├── review_agent_v2.py      #   V2 wrapper: Review → QA chain
│   ├── qa_agent.py             #   Tool-calling system validation (V1)
│   └── qa_agent_v2.py          #   LLM-only expert safety opinion (V2)
│
├── workflow/                   # Pipeline orchestration
│   ├── pipeline.py             #   V1 single-finding workflow
│   ├── pipeline_v2.py          #   V2 single-finding workflow (active)
│   └── concurrent_manager.py   #   Parallel processing manager
│
├── helpers/                    # Shared infrastructure
│   ├── llm_base.py             #   ToolCallingLLM — reusable LLM wrapper
│   ├── command_executor.py     #   ShellCommandExecutor — remote SSH execution
│   ├── scanner.py              #   Scanner — per-vulnerability verification
│   ├── llm_metrics.py          #   LLMMetricsTracker — API call metrics
│   ├── agent_report_writer.py  #   AgentReportWriter — agent I/O persistence
│   └── utils.py                #   Command normalization, error categorization
│
├── aggregation/                # Results processing
│   └── result_aggregator.py    #   Combines agent outputs into final reports
│
├── unit_tests/                 # Test suite
│   ├── test_pipeline_v2.py     #   V2 pipeline integration tests
│   ├── test_remedy_agent_v2.py #   RemedyAgentV2 unit tests
│   ├── test_review_agent_v2.py #   ReviewAgentV2 unit tests
│   ├── test_qa_agent_v2.py     #   QAAgentV2 unit tests
│   └── test_schemas_v2.py      #   V2 schema validation tests
│
├── demo_scripts/               # Demonstration
│   └── demo_pipeline_v2.py     #   Mock pipeline demo (no live system needed)
│
├── reports/                    # Generated reports (git-ignored)
├── pipeline_work/              # Working artifacts (git-ignored)
├── adaptive_qa_work/           # Adaptive QA session artifacts
│
└── legacy_code/                # Archived implementations
    ├── single_agent/           #   Original single-agent system
    ├── nessus/                 #   Nessus-based workflows
    ├── tools/                  #   Legacy tooling
    ├── tests/                  #   Legacy tests
    └── samples/                #   Sample data
```

---

## Testing

Run the V2 test suite:

```bash
pytest unit_tests/ -v
```

Run the mock demo (no live system or LLM needed):

```bash
python demo_scripts/demo_pipeline_v2.py
```

## Legacy code

Older implementations are preserved under `legacy_code/`:

- **`single_agent/`**: Original adaptive single-agent implementations including `qa_agent_adaptive.py`, standalone triage runners, and DISA STIG tools.
- **`nessus/`**: Original Nessus-based vulnerability scanning system (`agent.py`, `parse_nessus.py`, `run_pipeline.py`) — see `legacy_code/nessus/README_nessus.md`.
- **`tools/`**: Utility scripts and sample data generation.
- **`tests/`**: Unit tests for legacy components.
- **`samples/`**: Example reports from older system runs.

These implementations are **not** required to run the current multi-agent system, but are kept for reference and potential future integration.
