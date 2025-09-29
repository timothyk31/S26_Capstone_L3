## Nessus Remediation Assistant

Generate concise remediation commands from Nessus scan results. This project parses a `.nessus` XML report into structured JSON and then uses a local LLM (via Ollama, OpenAI-compatible API) to propose remediation commands per finding.

### What it does

- **Parse**: Convert `.nessus` XML to a normalized `parsed_vulns.json` list of findings.
- **Propose remediations**: Send findings in batches to an LLM and write `remediations.json` with proposed commands.
- **Orchestrate**: `run_pipeline.py` ties both steps together in one command.

## Repository layout

- `parse_nessus.py`: Parses `scan_results.nessus` into `parsed_vulns.json`.
- `agent.py`: Loads vulnerabilities and queries the model to produce `remediations.json`.
- `run_pipeline.py`: Orchestrates parsing and agent run in one step.
- `schemas.py`: Pydantic models for input and output structures.
- `requirements.txt`: Python dependencies.
- `scan_results.nessus`: Example Nessus report (replace with your file).
- `parsed_vulns.json`: Parser output (generated).
- `remediations.json`: Agent output (generated).

## Prerequisites

- **Python**: 3.10+ recommended
- **Pip**: Install dependencies

```bash
pip install -r requirements.txt
```

- **Ollama** (or compatible endpoint): Running locally with OpenAI-compatible API exposed, default `http://localhost:11434/v1`.
  - Example models: `llama3.2:3b` (default), but configurable.

## Quick start

If you have a `.nessus` file (default: `scan_results.nessus`) and Ollama running locally:

```bash
python run_pipeline.py
```

This will:

- Parse `scan_results.nessus` → `parsed_vulns.json`
- Run the agent with your model → `remediations.json`

## Orchestrated usage (`run_pipeline.py`)

Run the whole pipeline with flags to customize inputs and model settings:

```bash
python run_pipeline.py \
  --nessus scan_results.nessus \
  --parsed parsed_vulns.json \
  --remediations remediations.json \
  --model llama3.2:3b \
  --base-url http://localhost:11434/v1 \
  --batch-size 1 \
  --min-severity 3 \
  --max-fixes 0
```

### Flags

- **--nessus**: Path to the input `.nessus` XML.
- **--parsed**: Output path for parsed vulnerabilities JSON.
- **--remediations**: Output path for agent suggestions.
- **--model**: Ollama model name.
- **--base-url**: OpenAI-compatible base URL for the model server.
- **--batch-size**: Number of findings per agent request.
- **--min-severity**: Minimum severity to include (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical).
- **--max-fixes**: Optional cap on number of vulnerabilities processed (0=all).

## Individual steps

### Parse only

```bash
python parse_nessus.py
```

Defaults to reading `scan_results.nessus` and writing `parsed_vulns.json`.

### Agent only

`agent.py` reads configuration from environment variables:

- `VULN_INPUT` (default `parsed_vulns.json`)
- `REMEDIATIONS_OUTPUT` (default `remediations.json`)
- `OLLAMA_MODEL` (default `llama3.2:3b`)
- `OLLAMA_BASE_URL` (default `http://localhost:11434/v1`)
- `BATCH_SIZE` (default `1`)
- `MIN_SEVERITY` (default `3`)
- `MAX_FIXES` (default `0`, meaning unlimited)

Example:

```bash
set VULN_INPUT=parsed_vulns.json
set REMEDIATIONS_OUTPUT=remediations.json
set OLLAMA_MODEL=llama3.2:3b
set OLLAMA_BASE_URL=http://localhost:11434/v1
set BATCH_SIZE=1
set MIN_SEVERITY=3
set MAX_FIXES=0
python agent.py
```

On non-Windows shells, replace the `set` statements with `export`.

## Outputs

### `parsed_vulns.json`

Array of objects with fields like: `id`, `title`, `severity`, `cvss`, `host`, `port`, `protocol`, `description`, `recommendation`.

### `remediations.json`

Array of objects: `id`, `proposed_commands` (array of strings), `notes`.
The agent attempts to extract commands either from structured JSON or from free-form text heuristics.

## Notes and tips

- If the agent fails due to the model server, the code falls back to a direct OpenAI-compatible call to the same endpoint.
- Use a higher `--min-severity` to focus on higher priority fixes first.
- Use `--max-fixes` for quick trial runs.
- Batch size of `1` is safest; higher values reduce requests but can increase prompt size.

## Troubleshooting

- "Input file not found": Ensure your `.nessus` path is correct or provide `--nessus`.
- Connection errors: Verify your Ollama server is running and `--base-url` is correct.
- Empty outputs: Check that the `.nessus` file contains findings and that `--min-severity` isn’t too high.
