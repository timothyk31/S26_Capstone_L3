import os
import sys
import argparse
from pathlib import Path

from parse_nessus import parse_nessus
import agent as agent_module


def run_pipeline(
    nessus_path: Path,
    parsed_output: Path,
    remediations_output: Path,
    model_name: str,
    base_url: str,
    batch_size: int,
    min_severity: int,
    max_fixes: int,
):
    # Parse Nessus XML to JSON
    parse_nessus(str(nessus_path), output_json=str(parsed_output))

    # Configure env vars for agent and run it
    os.environ["VULN_INPUT"] = str(parsed_output)
    os.environ["REMEDIATIONS_OUTPUT"] = str(remediations_output)
    os.environ["OPENROUTER_MODEL"] = model_name
    os.environ["OPENROUTER_BASE_URL"] = base_url
    os.environ["BATCH_SIZE"] = str(batch_size)
    os.environ["MIN_SEVERITY"] = str(min_severity)
    if max_fixes > 0:
        os.environ["MAX_FIXES"] = str(max_fixes)

    agent_module.main()


def main():
    parser = argparse.ArgumentParser(description="Parse Nessus then run agent for remediations")
    parser.add_argument(
        "--nessus",
        type=Path,
        default=Path("scan_results.nessus"),
        help="Path to input .nessus file",
    )
    parser.add_argument(
        "--parsed",
        type=Path,
        default=Path("parsed_vulns.json"),
        help="Path for parsed vulnerabilities JSON output",
    )
    parser.add_argument(
        "--remediations",
        type=Path,
        default=Path("remediations.json"),
        help="Path for remediations JSON output",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-20b:free"),
        help="OpenRouter model name",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        help="OpenRouter OpenAI-compatible base URL",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=int(os.getenv("BATCH_SIZE", "1")),
        help="Batch size for agent processing",
    )
    parser.add_argument(
        "--min-severity",
        type=int,
        default=int(os.getenv("MIN_SEVERITY", "3")),
        choices=[0, 1, 2, 3, 4],
        help="Minimum severity to include (0=Info..4=Critical)",
    )
    parser.add_argument(
        "--max-fixes",
        type=int,
        default=int(os.getenv("MAX_FIXES", "0")),
        help="Optional cap on number of vulnerabilities to process (0=all)",
    )

    args = parser.parse_args()

    if not args.nessus.exists():
        print(f"Nessus file not found: {args.nessus}")
        sys.exit(1)

    run_pipeline(
        nessus_path=args.nessus,
        parsed_output=args.parsed,
        remediations_output=args.remediations,
        model_name=args.model,
        base_url=args.base_url,
        batch_size=args.batch_size,
        min_severity=args.min_severity,
        max_fixes=args.max_fixes,
    )


if __name__ == "__main__":
    main()


