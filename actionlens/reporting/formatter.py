"""Result formatters and report generators for ActionLens findings."""

import json
from typing import Sequence

from rich.console import Console
from rich.table import Table

from actionlens.models import Finding

SECURE_MESSAGE = "No findings detected. All checks passed!"


def format_findings_json(findings: Sequence[Finding], indent: int = 2) -> str:
    """Format findings as JSON matching Step 4 of docs/development.md."""
    if not findings:
        return json.dumps({"message": SECURE_MESSAGE}, indent=indent)

    data = [finding.model_dump() for finding in findings]
    return json.dumps(data, indent=indent)

def format_cli_table(findings: Sequence[Finding]) -> str:
    """Format findings as a human-readable CLI report."""
    if not findings:
        return SECURE_MESSAGE

    console = Console(record=True, color_system="auto", width=100)
    table = Table(title="ActionLens SAST Findings Report", show_lines=True)
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Severity", style="bold")
    table.add_column("OWASP CI/CD", style="magenta")
    table.add_column("Message", style="white", overflow="fold")
    table.add_column("Remediation", style="green")

    sev_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }

    for f in findings:
        sev_style = sev_colors.get(f.severity.value, "white")
        table.add_row(
            f.rule_id,
            f"[{sev_style}]{f.severity.value}[/{sev_style}]",
            f.owasp_cicd or "-",
            f.message,
            f.remediation,
        )

    with console.capture() as capture:
        console.print(table)
        console.print("\n[bold cyan]For CWE IDs and full details, use --format json.[/bold cyan]")

    return capture.get()
