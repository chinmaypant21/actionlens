"""Result formatters and report generators for ActionLens findings."""

import json
from typing import Sequence
from actionlens.models import Finding


def format_findings_json(findings: Sequence[Finding], indent: int = 2) -> str:
    """Format findings as JSON matching Step 4 of docs/development.md."""
    data = [finding.model_dump() for finding in findings]
    return json.dumps(data, indent=indent)


# Took help from Gemini 3.8 Flash to generatae CLI formatter 

def format_cli_table(findings: Sequence[Finding]) -> str:
    """Format findings as a human-readable CLI report."""
    try:
        from rich.console import Console
        from rich.table import Table
        import io

        console = Console(record=True, color_system="auto", width=100)
        table = Table(title="ActionLens SAST Findings Report", show_lines=True)
        table.add_column("Rule ID", style="cyan", no_wrap=True)
        table.add_column("Severity", style="bold")
        table.add_column("Location", style="yellow")
        table.add_column("Message", style="white")
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
                f"{f.file_path}:{f.line}",
                f.message,
                f.remediation,
            )

        with console.capture() as capture:
            console.print(table)
        return capture.get()

    except ImportError:
        # Fallback if rich is not installed
        lines = [
            "=" * 80,
            "ACTIONLENS SAST FINDINGS REPORT",
            "=" * 80,
        ]
        if not findings:
            lines.append("No findings detected. All checks passed!")
        for f in findings:
            lines.extend([
                f"[{f.severity.value}] {f.rule_id} at {f.file_path}:{f.line}",
                f"  Message:     {f.message}",
                f"  Remediation: {f.remediation}",
                "-" * 80,
            ])
        return "\n".join(lines)
