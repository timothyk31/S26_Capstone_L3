# Plan: Reduce Token Count on Remedy Retry Attempts

## Context

The remedy agent's retry attempts consume significant tokens, but we want to keep retries — just reduce how many tokens each retry consumes. The two root causes:

1. **Within-session message accumulation** (primary, biggest impact): Every LLM turn sends the full conversation history. Tool outputs (file reads, command output) accumulate across all prior turns. By turn 15, the prompt contains every curl/cat response from turns 2-14, often including 8,018-char HTML pages returned from failed curl downloads. This causes prompt size to grow from ~1,200 tokens at turn 1 to ~13,400 tokens by turn 15 — an 11x blow-up within a single attempt (128k total tokens for one 15-turn attempt).

2. **Cross-attempt prompt growth** (secondary, smaller impact): Each retry injects prior_attempts history (commands, scan output, review verdicts) into the new attempt's initial prompt. This grows the initial prompt by ~300–400 tokens per retry round.

## Root Cause Data (most recent run: `run_20260324_011524`)

Input JSON file sizes (bytes) and LLM call counts across attempts:

| Finding | Att1 input | Att2 input | Att3 input | Att1 calls | Att2 calls | Att3 calls |
|---|---|---|---|---|---|---|
| accounts_password_pam_minlen | 2,393 | 16,847 | 26,385 | 9 | 10 | 10 |
| accounts_umask_etc_profile | 2,322 | 33,564 | 35,417 | 15 | N/A | 18 |
| ensure_redhat_gpgkey_installed | 2,929 | 8,447 | 32,370 | 9 | 15 | 14 |
| service_auditd_enabled | 1,768 | 8,477 | 28,695 | 9 | 18 | 15 |

The input JSON grows because `RemediationAttempt.execution_details` (full stdout/stderr of all tool calls) accumulates across retries: e.g., attempt 2's execution_details = 17,156 chars; attempt 1's = 21,306 chars. This field is serialized in `previous_attempts` but **not used by `_build_agent_prompt()`** (only `commands_executed`, `error_summary`, `scan_output` are used in the prompt).

The actual within-session prompt growth is the primary driver: tool outputs from `read_file`/`run_cmd` within a single session accumulate in the messages list. Large outputs (curl returning 8,018-char HTML pages, file reads returning thousands of chars) persist across all subsequent turns. By turn 15, the prompt can carry 10x more tokens than turn 1.

**Note on input file size vs LLM tokens**: The large input JSON files are due to `RemediationAttempt.execution_details` being serialized into `previous_attempts`. However, `_build_agent_prompt()` does NOT include `execution_details` in the LLM prompt — it only uses `commands_executed`, `error_summary`, and `scan_output`. The input file size growth does NOT directly equal LLM token growth. The token growth is within-session from the `messages` list in `_run_tool_session()`.

## Critical Files

- `agents/remedy_agent.py` — `_run_tool_session()`, `_build_agent_prompt()`, `plan_fix()`
- `schemas.py` — `RemediationAttempt`, `RemedyInput`

## Implementation Plan

### Change 1: Instruct the agent to use targeted output commands (primary fix)

The root cause is the agent using `curl`, `cat`, or `read_file` on whole files/URLs that return thousands of chars. Instead of silently truncating the result (which hides information), we add prompt instructions that guide the agent to produce targeted, small outputs in the first place.

**Added to the system prompt in `_run_tool_session()`:**

```
OUTPUT SIZE RULES (preserve context window):
- Never dump entire files. Use grep/head/tail to extract only the relevant lines.
  Good: run_cmd 'grep -n "minlen" /etc/security/pwquality.conf'
  Bad:  read_file '/etc/security/pwquality.conf'
- For curl/wget downloads, verify with 'file <path>' or 'head -c 100 <path>' — if output looks like HTML, abort and use a different source.
- Avoid commands that produce large output (rpm -qa, find /, ls -laR). Use targeted queries instead.
```

**Added to the rules list in `_build_agent_prompt()`:**

```
- ALWAYS inspect the target config file BEFORE modifying it — use grep, NOT read_file.
  Example: run_cmd 'grep -n "minlen" /etc/security/pwquality.conf'
- OUTPUT SIZE: Use grep/head/tail instead of read_file or cat on whole files.
- For curl/wget: verify downloads with 'file <path>' or 'head -c 100 <path>'. If HTML is returned, stop and use a local/package source instead.
```

These address the two biggest output sources observed:
- `curl` hitting web pages (8,018-char HTML responses) — agent now stops and tries a different approach
- `read_file`/`cat` on config files (2,000–20,000 chars) — agent now greps for the specific line it needs

### Change 2: Hard cap on tool output size as a safety net

Even with better instructions, some commands may still produce large output (e.g., `rpm -qi` returning 2,261 chars, `ls -la` on large directories). Added `_cap_tool_output()` in `_run_tool_session()` before appending to `messages`:

```python
_MAX_TOOL_OUTPUT_CHARS = 2000

def _cap_tool_output(self, payload: dict) -> dict:
    """Cap large tool output fields before they enter the rolling message context.

    The full payload is still saved to transcript for auditing; only what
    gets sent back to the LLM is capped here.
    """
    capped = dict(payload)
    for field in ("stdout", "stderr", "content"):
        val = capped.get(field)
        if isinstance(val, str) and len(val) > self._MAX_TOOL_OUTPUT_CHARS:
            capped[field] = (
                val[:self._MAX_TOOL_OUTPUT_CHARS]
                + f"\n[output capped at {self._MAX_TOOL_OUTPUT_CHARS} chars — use grep/head for targeted output]"
            )
    return capped
```

Full payload still goes to `transcript` for auditing — only the `messages` list (sent to LLM) is capped.

### Change 3: Tighter cross-attempt prompt sections (secondary)

**In `_build_agent_prompt()`:**

| Field | Before | After |
|---|---|---|
| `att.commands_executed` per attempt | `[-4:]` | `[-2:]` |
| `att.error_summary` cap | `[:300]` | `[:200]` |
| `att.scan_output` cap | `[:900]` | `[:300]` |
| AVOID commands list | `[-8:]` | `[-5:]` |

These save ~200–300 tokens per retry but preserve the key retry signal (what was tried, why it failed).

## What Does NOT Change

- The `transcript` saved to disk (`remedy_transcript_*.json`) retains full untruncated content for auditing — only `messages` (sent to LLM) is capped.
- Retry logic, `max_rounds`, `max_tool_iterations` — unchanged.
- `plan_fix()` / review / QA flow — unchanged.
- The `previous_review_verdicts` injection — unchanged (already limited to last 3).
- The agent can still read files and run commands freely; it's guided to produce targeted output, not blocked.

## Expected Impact

For a 15-turn session with large tool outputs:
- **Current**: prompt grows from ~1.2k to ~13.4k tokens per turn (11x blow-up); 128k total tokens per attempt
- **After Change 1** (grep/head instructions): agent greps for the specific config key instead of reading full file → tool outputs drop from 2,000–8,000 chars to ~100–300 chars per turn
- **After Change 2** (hard cap at 2000 chars): residual large outputs get capped as safety net
- **Estimated**: prompt at turn 15 drops from ~13.4k to ~2–3k tokens (~75–80% reduction per turn)
- **Per-attempt token total**: ~128k → ~25–40k (~70% reduction)
- **For 3 attempts on one finding**: ~350k → ~75–120k tokens total

The agent retains exactly the information it needs (the grep match for the relevant config line) while discarding irrelevant surrounding content.

## Verification

1. Run one failing finding through the full retry pipeline (3 attempts):
   ```bash
   python3 main_multiagent.py --max-remedy-attempts 3 ...
   ```
2. Check `pipeline_work/remedy/remedy_transcript_<finding>_attempt*.json`:
   - Look at `usage.per_turn[*].prompt_tokens` — should grow slowly (not 11x by turn 15)
   - Confirm `transcript` still has full stdout/stderr in tool messages for auditing
3. Confirm `usage.total_tokens` is significantly lower than the current ~128k baseline
