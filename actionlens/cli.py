"""CLI entry point for ActionLens."""

import argparse
import sys
from pathlib import Path

from actionlens.sast.orchestrator import SASTOrchestrator


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="actionlens",
        description="ActionLens: Security analyzer for GitHub Actions workflows.",
    )
    parser.add_argument(
        "file",
        help="Path to workflow YAML file or AST JSON file to analyze.",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["cli", "json"],
        default="cli",
        help="Output format: 'cli' (human-readable table) or 'json' (Step 4 schema). Default: cli.",
    )

    args = parser.parse_args()
    target_path = Path(args.file)

    if not target_path.exists():
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    orchestrator = SASTOrchestrator()
    findings = orchestrator.scan_workflow(target_path)

    if args.format == "json":
        print(orchestrator.scan_and_report_json(target_path))
    else:
        print(orchestrator.scan_and_report_cli(target_path))

    # Exit code: 1 if any HIGH or CRITICAL findings, else 0
    has_high = any(f.severity.value in {"HIGH", "CRITICAL"} for f in findings)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()
