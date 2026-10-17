"""AL-LINT-001: Unpinned Third-Party Action."""

from actionlens.models import Finding, Rule, WorkflowAST
from actionlens.sast.rules.catalog import RULE_CATALOG


class UnpinnedActionRule(Rule):
    """AL-LINT-001: Flags third-party actions not pinned to a commit SHA."""

    metadata = RULE_CATALOG["AL-LINT-001"]

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
                            cwe=self.cwe,
                            owasp_cicd=self.owasp_cicd,
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
