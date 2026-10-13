"""SAST Orchestrator: Coordinates rules, aggregates findings, and interfaces with reporting."""

from pathlib import Path
from typing import Union

from actionlens.models import Finding, Rule, WorkflowAST
from actionlens.parser import load_ast_json, parse_workflow_file
from actionlens.reporting.formatter import format_cli_table, format_findings_json
from actionlens.sast.rules.lint.untrusted_namespace import UntrustedNamespaceRule


class SASTOrchestrator:
    """Central engine orchestrator that executes registered SAST rules against workflow ASTs."""

    def __init__(self):
        """Initialize orchestrator with all active detection rules."""
        self.rules: list[Rule] = [
            UntrustedNamespaceRule(),
            # Add future rules here
        ]

    def scan_workflow(self, target: Union[WorkflowAST, str, Path]) -> list[Finding]:
        """Run all registered rules against a target workflow (WorkflowAST, YAML file, or AST JSON).

        Args:
            target: A parsed WorkflowAST, a path to a YAML file, or a path to AST JSON.

        Returns:
            Aggregated list of Finding objects.
        """
        if isinstance(target, WorkflowAST):
            ast = target
        else:
            path = Path(target)
            if path.suffix.lower() in {".yaml", ".yml"}:
                ast = parse_workflow_file(path)
            elif path.suffix.lower() == ".json":
                ast = load_ast_json(path)
            else:
                # Default: attempt parsing via Go binary
                ast = parse_workflow_file(path)

        findings: list[Finding] = []
        for rule in self.rules:
            rule_findings = rule.check(ast)
            findings.extend(rule_findings)

        # Sort findings by line number for deterministic reporting
        findings.sort(key=lambda f: (f.file_path, f.line))
        return findings

    def scan_and_report_json(self, target: Union[WorkflowAST, str, Path], indent: int = 2) -> str:
        """Scan a workflow and return the JSON findings matching Step 4 of development.md."""
        findings = self.scan_workflow(target)
        return format_findings_json(findings, indent=indent)

    def scan_and_report_cli(self, target: Union[WorkflowAST, str, Path]) -> str:
        """Scan a workflow and return a human-readable CLI report."""
        findings = self.scan_workflow(target)
        return format_cli_table(findings)
