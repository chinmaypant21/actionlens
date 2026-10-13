"""AL-LINT-001: Unpinned Third-Party Action.

Detects actions that reference mutable branches or tags like @v4 or @main
instead of an immutable 40-character commit SHA.
"""

from actionlens.models import Finding, Rule, RuleCategory, Severity, WorkflowAST


class UnpinnedActionRule(Rule):
    """AL-LINT-001: Flags third-party actions not pinned to a commit SHA."""

    rule_id: str = "AL-LINT-001"
    name: str = "Unpinned Third-Party Action"
    severity: Severity = Severity.MEDIUM
    category: RuleCategory = RuleCategory.LINT
    description: str = "A 'uses:' statement references a mutable branch or tag rather than a full, 40-character commit SHA."
    cwe: str = "CWE-1357"  # Reliance on Insufficiently Trustworthy Component
    remediation: str = "Pin the action to a full 40-character commit SHA."

    def check(self, ast: WorkflowAST) -> list[Finding]:
        findings: list[Finding] = []

        for job in ast.jobs:
            for step in job.steps:
                if not step.uses:
                    continue

                raw_ref = step.uses.raw

                # Ignore local actions
                if raw_ref.startswith("./"):
                    continue

                # Flag if not pinned to a 40-character SHA
                if not step.uses.is_sha:
                    line_num = step.pos.line if step.pos.line > 0 else (job.pos.line if job.pos.line > 0 else 1)
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            file_path=ast.file_path,
                            line=line_num,
                            message=(
                                f"Action '{raw_ref}' is unpinned "
                                f"(uses mutable tag or branch '@{step.uses.ref}' instead of commit SHA)."
                                if step.uses.ref
                                else f"Action '{raw_ref}' is unpinned (missing commit SHA)."
                            ),
                            remediation=self.remediation,
                        )
                    )

        return findings
