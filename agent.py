import json
import os
import sys
from typing import Iterable, List, Optional
from pathlib import Path

from pydantic import BaseModel, ValidationError
from pydantic_ai import Agent, NativeOutput
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from dotenv import load_dotenv

from schemas import Vulnerability, RemediationSuggestion, BatchResult


SEVERITY_ORDER = {
    "4": 4,  # Critical
    "3": 3,  # High
    "2": 2,  # Medium
    "1": 1,  # Low
    "0": 0,  # Info
}




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
    # Use structured output with strict validation
    agent = Agent(
        openrouter_model,
        output_type=NativeOutput(BatchResult, strict=True),
        system_prompt=(
            "You are a systems hardening assistant. For each batch of Nessus findings, propose concise remediation commands.\n"
            "- Prefer safe, idempotent commands.\n"
            "- You are a Linux systems hardening assistant, so use Linux-specific commands.\n"
            "- Keep remediations specific to each vulnerability (e.g., update specific package, not all packages).\n"
            "- Prefer not to sudo apt update all packages at once, prefer to update specific packages.\n"
            "- Provide clear, actionable commands that can be executed directly.\n"
            "- Include relevant notes about potential risks or considerations.\n"
            "- Return structured output with suggestions array containing id, proposed_commands, and notes for each vulnerability."
        ),
    )
    return agent


def render_batch_prompt(vulns: List[Vulnerability]) -> str:
    lines: List[str] = []
    lines.append("Propose remediation commands for these Nessus findings. Return structured output with a suggestions array.")
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




def main():
    load_dotenv()

    input_json = Path(os.getenv("VULN_INPUT", "parsed_vulns.json"))
    output_json = Path(os.getenv("REMEDIATIONS_OUTPUT", "remediations.json"))
    model_name = os.getenv("OPENROUTER_MODEL")
    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not model_name:
        print("Error: OPENROUTER_MODEL not set. Please configure it in your environment (e.g., .env).")
        sys.exit(1)
    try:
        batch_size = int(os.getenv("BATCH_SIZE", "1"))
    except Exception:
        batch_size = 1
    try:
        min_sev_env = os.getenv("MIN_SEVERITY", "4")
        min_severity = int(min_sev_env)
    except Exception:
        min_severity = 4

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

    for chunk in batched(prioritized, batch_size):
        prompt = render_batch_prompt(chunk)
        try:
            result = agent.run_sync(prompt)
            # With structured output, result.output is already a BatchResult instance
            batch_result: BatchResult = result.output
            all_suggestions.extend(batch_result.suggestions)
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
            # Fallback: create basic suggestions for failed batch
            for v in chunk:
                all_suggestions.append(
                    RemediationSuggestion(
                        id=v.id, 
                        proposed_commands=[f"# Manual review required for {v.title}"], 
                        notes=f"Failed to generate remediation: {str(e)}"
                    )
                )
            processed += len(chunk)
            print(f"Added fallback suggestions for failed batch. Progress: {processed}/{total}")
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
