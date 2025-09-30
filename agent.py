import json
import os
import sys
from typing import Iterable, List, Optional
from pathlib import Path

from pydantic import BaseModel, ValidationError
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from dotenv import load_dotenv
import requests

from schemas import Vulnerability, RemediationSuggestion


SEVERITY_ORDER = {
    "4": 4,  # Critical
    "3": 3,  # High
    "2": 2,  # Medium
    "1": 1,  # Low
    "0": 0,  # Info
}


class BatchResult(BaseModel):
    suggestions: List[RemediationSuggestion]


def load_vulnerabilities(path: Path) -> List[Vulnerability]:
    data = json.loads(path.read_text())
    vulns: List[Vulnerability] = []
    for idx, item in enumerate(data):
        try:
            # Coerce cvss to float when present
            if item.get("cvss") is not None:
                try:
                    item["cvss"] = float(item["cvss"])
                except Exception:
                    item["cvss"] = None
            vulns.append(Vulnerability(**item))
        except ValidationError as e:
            print(f"Skipping invalid vulnerability at index {idx}: {e}")
    return vulns


def severity_rank(sev: Optional[str]) -> int:
    if sev is None:
        return -1
    return SEVERITY_ORDER.get(str(sev), -1)


def sort_and_filter(vulns: List[Vulnerability], min_severity: int) -> List[Vulnerability]:
    filtered = [v for v in vulns if severity_rank(v.severity) >= min_severity]
    # Sort: severity desc, cvss desc (None last), host asc, id asc
    filtered.sort(
        key=lambda v: (
            -severity_rank(v.severity),
            -(v.cvss or -1.0),
            v.host or "",
            v.id or "",
        )
    )
    return filtered


def batched(items: List[Vulnerability], batch_size: int) -> Iterable[List[Vulnerability]]:
    for i in range(0, len(items), batch_size):
        yield items[i : i + batch_size]


def build_agent(model_name: str, base_url: str, api_key: Optional[str]) -> Agent:
    openrouter_model = OpenAIChatModel(
        model_name=model_name,
        provider=OpenAIProvider(base_url=base_url, api_key=api_key),
    )
    # No output_type, accept free-form text
    agent = Agent(
        openrouter_model,
        system_prompt=(
            "You are a systems hardening assistant. For each batch of Nessus findings, propose concise remediation commands.\n"
            "- Prefer safe, idempotent commands.\n"
            "- If you know the platform (Linux/Windows), use appropriate tools.\n"
            "- It's OK to reply in plain text or JSON.\n"
            "- Keep it brief."
            "- Keep the remedations specific to each vulnerability, such as only updating a specific package instead of updating all packages at once."
        ),
    )
    return agent


def render_batch_prompt(vulns: List[Vulnerability]) -> str:
    lines: List[str] = []
    lines.append("Propose remediation commands for these Nessus findings. Keep it brief. If you include JSON, use a 'suggestions' array.")
    for v in vulns:
        lines.append("---")
        lines.append(f"id: {v.id}")
        lines.append(f"title: {v.title}")
        lines.append(f"severity: {v.severity}")
        if v.cvss is not None:
            lines.append(f"cvss: {v.cvss}")
        lines.append(f"host: {v.host}")
        if v.port:
            lines.append(f"port: {v.port}")
        if v.protocol:
            lines.append(f"protocol: {v.protocol}")
        if v.description:
            lines.append(f"description: {v.description[:400]}")
        if v.recommendation:
            lines.append(f"recommendation: {v.recommendation[:400]}")
    return "\n".join(lines)


def call_openai_compatible_json(base_url: str, model_name: str, system: str, user: str, api_key: Optional[str] = None) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model_name,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    # Optional OpenRouter headers (improves routing/analytics if provided)
    site_url = os.getenv("OPENROUTER_SITE_URL")
    app_name = os.getenv("OPENROUTER_APP_NAME")
    if site_url:
        headers["HTTP-Referer"] = site_url
    if app_name:
        headers["X-Title"] = app_name
    resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=120)
    resp.raise_for_status()
    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    return content


def extract_first_json_object(text: str) -> Optional[dict]:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except Exception:
                    return None
    return None


def extract_commands_from_text(text: str) -> List[str]:
    lines = text.splitlines()
    commands: List[str] = []
    in_code = False
    for raw in lines:
        s = raw.strip()
        if s.startswith("```"):
            in_code = not in_code
            continue
        if not s:
            continue
        if in_code:
            commands.append(s)
            continue
        for prefix in ("- ", "* ", "• ", "1. ", "2. ", "3. "):
            if s.startswith(prefix):
                s = s[len(prefix):].strip()
                break
        starters = (
            "sudo ", "apt ", "apt-get ", "dnf ", "yum ", "zypper ", "systemctl ",
            "service ", "choco ", "winget ", "powershell ", "pwsh ", "netsh ",
            "reg ", "sc ", "Set-", "Get-", "New-", "Remove-", "Install-", "Update-",
        )
        if s.startswith(starters) or ";" in s or "&&" in s:
            commands.append(s)
    seen = set()
    deduped: List[str] = []
    for c in commands:
        if c not in seen:
            seen.add(c)
            deduped.append(c)
    return deduped


def main():
    load_dotenv()

    input_json = Path(os.getenv("VULN_INPUT", "parsed_vulns.json"))
    output_json = Path(os.getenv("REMEDIATIONS_OUTPUT", "remediations.json"))
    model_name = os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-20b:free")
    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    api_key = os.getenv("OPENROUTER_API_KEY")
    try:
        batch_size = int(os.getenv("BATCH_SIZE", "1"))
    except Exception:
        batch_size = 1
    try:
        min_sev_env = os.getenv("MIN_SEVERITY", "4")
        min_severity = int(min_sev_env)
    except Exception:
        min_severity = 4
    lenient = True

    # Optional cap on number of vulnerabilities to process
    try:
        max_fixes = int(os.getenv("MAX_FIXES", "0"))
    except Exception:
        max_fixes = 0

    if not input_json.exists():
        print(f"Input file not found: {input_json}")
        sys.exit(1)

    vulns = load_vulnerabilities(input_json)
    if not vulns:
        print("No valid vulnerabilities to process.")
        sys.exit(0)

    prioritized = sort_and_filter(vulns, min_severity=min_severity)
    if max_fixes > 0:
        prioritized = prioritized[:max_fixes]
    if not prioritized:
        print("No vulnerabilities meet the severity threshold.")
        sys.exit(0)

    agent = build_agent(model_name=model_name, base_url=base_url, api_key=api_key)

    all_suggestions: List[RemediationSuggestion] = []
    total = len(prioritized)
    processed = 0

    print(f"Processing {total} vulnerabilities in batches of {batch_size} using {model_name} @ {base_url}...")

    system_prompt_for_direct = getattr(agent, "_system_prompt", "")

    for chunk in batched(prioritized, batch_size):
        prompt = render_batch_prompt(chunk)
        try:
            result = agent.run_sync(prompt)
            if lenient:
                text = str(result.output)
                obj = extract_first_json_object(text)
                if obj and isinstance(obj, dict) and "suggestions" in obj:
                    try:
                        batch_model = BatchResult.model_validate(obj)
                        all_suggestions.extend(batch_model.suggestions)
                    except Exception:
                        # JSON didn't match; fallback to heuristic
                        cmds = extract_commands_from_text(text)
                        if not cmds:
                            cmds = [text[:500]]
                        for v in chunk:
                            all_suggestions.append(
                                RemediationSuggestion(id=v.id, proposed_commands=cmds, notes="Lenient heuristic extraction from free-form output.")
                            )
                else:
                    cmds = extract_commands_from_text(text)
                    if not cmds:
                        cmds = [text[:500]]
                    for v in chunk:
                        all_suggestions.append(
                            RemediationSuggestion(id=v.id, proposed_commands=cmds, notes="Lenient heuristic extraction from free-form output.")
                        )
            else:
                batch_out = result.output
                all_suggestions.extend(batch_out.suggestions)
            processed += len(chunk)
            if hasattr(result, "usage"):
                try:
                    usage = result.usage()
                    print(
                        f"Processed {processed}/{total} (requests={usage.requests}, tokens_in={usage.input_tokens}, tokens_out={usage.output_tokens})"
                    )
                except Exception:
                    print(f"Processed {processed}/{total}")
            else:
                print(f"Processed {processed}/{total}")
        except Exception as e:
            print(f"Error running agent on batch starting with id {chunk[0].id}: {e}")
            # Single simple fallback: direct call and lenient parse
            try:
                raw_text = call_openai_compatible_json(
                    base_url=base_url,
                    model_name=model_name,
                    system=system_prompt_for_direct or "",
                    user=prompt,
                    api_key=api_key,
                )
                obj = extract_first_json_object(raw_text)
                if obj and isinstance(obj, dict) and "suggestions" in obj:
                    try:
                        batch_model = BatchResult.model_validate(obj)
                        all_suggestions.extend(batch_model.suggestions)
                    except Exception:
                        cmds = extract_commands_from_text(raw_text)
                        if not cmds:
                            cmds = [raw_text[:500]]
                        for v in chunk:
                            all_suggestions.append(
                                RemediationSuggestion(id=v.id, proposed_commands=cmds, notes="Lenient extraction from direct call.")
                            )
                else:
                    cmds = extract_commands_from_text(raw_text)
                    if not cmds:
                        cmds = [raw_text[:500]]
                    for v in chunk:
                        all_suggestions.append(
                            RemediationSuggestion(id=v.id, proposed_commands=cmds, notes="Lenient extraction from direct call.")
                        )
                processed += len(chunk)
                print(f"Recovered via simple direct call. Progress: {processed}/{total}")
                continue
            except Exception as e4:
                print(f"Direct call failed: {e4}")
                print("Continuing with next batch...")
            continue

    # De-duplicate by id, keep last
    dedup: dict[str, RemediationSuggestion] = {}
    for s in all_suggestions:
        dedup[s.id] = s

    output_payload = [s.model_dump() for s in dedup.values()]
    output_json.write_text(json.dumps(output_payload, indent=2))
    print(f"Wrote {len(output_payload)} remediation suggestions → {output_json}")


if __name__ == "__main__":
    main()
