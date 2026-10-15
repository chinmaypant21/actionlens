"""AL-LINT-003: Missing or Over-scoped Permissions Block."""

from actionlens.models import Finding, Rule, RuleCategory, Severity, WorkflowAST

class PermissionsBlockRule(Rule):
    """AL-LINT-003: Flags missing top-level permissions or broad 'write-all' token access."""

    rule_id: str = "AL-LINT-003"
    name: str = "Missing or Over-scoped Permissions Block"
    severity: Severity = Severity.LOW #default val
    category: RuleCategory = RuleCategory.LINT
    description: str = "The workflow lacks a top-level permissions: block (defaulting GITHUB_TOKEN to broad repository permissions), or explicitly grants broad 'write-all' access."
    cwe: str = "CWE-276"  # Incorrect Default Permissions
    remediation: str = "Specify a restrictive top-level 'permissions: {}' block and grant only minimal scoped permissions to individual jobs as needed."

    def check(self, ast: WorkflowAST) -> list[Finding]:
        findings: list[Finding] = []

        # Check 1: Top-level permissions block is missing
        if ast.permissions is None:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    file_path=ast.file_path,
                    line=1,
                    message=(
                        "Workflow is missing a top-level 'permissions:' block. "
                        "The GITHUB_TOKEN will default to broad repository permissions."
                    ),
                    remediation=self.remediation,
                )
            )
        elif ast.permissions.all == "write-all":
            line_num = ast.permissions.pos.line if ast.permissions.pos and ast.permissions.pos.line > 0 else 1
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.MEDIUM,
                    file_path=ast.file_path,
                    line=line_num,
                    message="Workflow specifies broad 'write-all' permissions at the top level.",
                    remediation=self.remediation,
                )
            )

        # Check 2: Inspect individual jobs for 'write-all'
        for job in ast.jobs:
            if job.permissions and job.permissions.all == "write-all":
                
                if job.permissions.pos and job.permissions.pos.line > 0:
                    line_num = job.permissions.pos.line
                elif job.pos.line > 0:
                    line_num = job.pos.line
                else:
                    line_num = 1

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file_path=ast.file_path,
                        line=line_num,
                        message=f"Job '{job.id}' grants broad 'write-all' permissions.",
                        remediation="Scope permissions to minimal specific permissions (e.g. 'contents: read').",
                    )
                )

        return findings
