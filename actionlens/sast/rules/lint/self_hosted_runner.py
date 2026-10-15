"""AL-LINT-004: Unsafe Self-Hosted Runner Usage."""

from actionlens.models import Finding, Rule, RuleCategory, Severity, WorkflowAST

# Trigger events that can be activated by external/untrusted actors
UNTRUSTED_TRIGGERS: set[str] = {
    "pull_request",
    "pull_request_target",
    "issue_comment",
    "issues",
    "discussion",
    "workflow_run",
}


class SelfHostedRunnerRule(Rule):
    """AL-LINT-004: Flags jobs configured to execute on self-hosted runners."""

    rule_id: str = "AL-LINT-004"
    name: str = "Unsafe Self-Hosted Runner Usage"
    severity: Severity = Severity.HIGH #default val
    category: RuleCategory = RuleCategory.LINT
    description: str = (
        "A job specifies a self-hosted runner rather than GitHub-hosted infrastructure, "
        "risking unauthorized code execution and network compromise."
    )
    cwe: str = "CWE-829"  # Inclusion of Functionality from Untrusted Control Sphere
    remediation: str = (
        "Use GitHub-hosted runners (e.g. 'ubuntu-latest') for public repositories or untrusted PR triggers. "
        "If self-hosted runners are necessary, ensure they are ephemeral and strictly network-isolated."
    )

    def check(self, ast: WorkflowAST) -> list[Finding]:
        findings: list[Finding] = []

        # Determine if the workflow can be triggered by external/untrusted events
        has_external_trigger = False
        for trigger in ast.triggers:
            if trigger.event.lower() in UNTRUSTED_TRIGGERS:
                has_external_trigger = True
                break

        for job in ast.jobs:
            if not job.runs_on:
                continue

            # checking if any label specifies 'self-hosted' (case-insensitive)
            is_self_hosted = any(
                label.strip().lower() == "self-hosted"
                for label in job.runs_on.labels
            )

            if is_self_hosted:
                if job.runs_on.pos and job.runs_on.pos.line > 0:
                    line_num = job.runs_on.pos.line
                elif job.pos.line > 0:
                    line_num = job.pos.line
                else:
                    line_num = 1

                if has_external_trigger:
                    matched_triggers = []
                    for trigger in ast.triggers:
                        if trigger.event.lower() in UNTRUSTED_TRIGGERS:
                            matched_triggers.append(trigger.event)

                    trigger_str = ", ".join(matched_triggers)
                    message = (
                        f"Job '{job.id}' executes on a self-hosted runner and is triggered by external event(s) ({trigger_str}). "
                        f"Untrusted pull requests can compromise the host machine and internal network."
                    )
                    severity = Severity.HIGH
                else:
                    message = (
                        f"Job '{job.id}' executes on a self-hosted runner. "
                        f"Ensure the runner is ephemeral, isolated, and does not persist state across runs."
                    )
                    severity = Severity.MEDIUM

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=severity,
                        file_path=ast.file_path,
                        line=line_num,
                        message=message,
                        remediation=self.remediation,
                    )
                )

        return findings
