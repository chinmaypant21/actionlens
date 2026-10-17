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
        
        # checking individual or nested permissions at top level
        elif "write-all" in (ast.permissions.all, *ast.permissions.scopes.values()):
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
            if not job.permissions:
                continue

            has_write_all = job.permissions.all == "write-all"
            
            write_all_scopes = [
                scope for scope, perm in job.permissions.scopes.items() if perm == "write-all"
            ]

            if has_write_all or write_all_scopes:
                if job.permissions.pos and job.permissions.pos.line > 0:
                    line_num = job.permissions.pos.line
                elif job.pos.line > 0:
                    line_num = job.pos.line
                else:
                    line_num = 1

                if has_write_all:
                    message = f"Job '{job.id}' grants broad 'write-all' permissions."
                else:
                    scopes_str = ", ".join(f"'{s}'" for s in write_all_scopes)
                    message = f"Job '{job.id}' grants broad 'write-all' permissions on scope(s): {scopes_str}."

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        file_path=ast.file_path,
                        line=line_num,
                        message=message,
                        remediation="Scope permissions to minimal specific permissions (e.g. 'contents: read').",
                    )
                )

        return findings
