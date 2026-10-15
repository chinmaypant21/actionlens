"""AL-LINT-001: Unpinned Third-Party Action."""

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

                # contains value like actions/checkout@v4
                action_reference = step.uses.raw

                # Ignore local actions
                if action_reference.startswith("./"):
                    continue

                # Flag if not pinned to a 40-character SHA
                if not step.uses.is_sha:
                    if step.pos.line > 0:
                        line_num = step.pos.line
                    elif job.pos.line > 0:
                        line_num = job.pos.line
                    else:
                        line_num = 1

                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            file_path=ast.file_path,
                            line=line_num,
                            message=(
                                f"Action '{action_reference}' is unpinned "
                                f"(uses mutable tag or branch '@{step.uses.ref}' instead of commit SHA)."
                                if step.uses.ref
                                else f"Action '{action_reference}' is unpinned (missing commit SHA)."
                            ),
                            remediation=self.remediation,
                        )
                    )

        return findings
