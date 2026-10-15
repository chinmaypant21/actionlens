"""AL-LINT-002: Compromised / Untrusted Action Namespace."""

from typing import Optional, Set
from actionlens.models import Finding, Rule, RuleCategory, Severity, WorkflowAST
from actionlens.utils import levenshtein_distance

# Standard verified official namespaces
DEFAULT_TRUSTED_NAMESPACES: set[str] = {
    "actions",
    "github",
}

# Popular official action repositories frequently targeted by typo-squatters
POPULAR_OFFICIAL_ACTIONS: set[str] = {
    "checkout",
    "setup-node",
    "setup-python",
    "setup-go",
    "setup-java",
    "cache",
    "upload-artifact",
    "download-artifact",
    "github-script",
}

class UntrustedNamespaceRule(Rule):
    """AL-LINT-002: Flag actions referencing typo-squatted or unverified namespaces."""

    rule_id: str = "AL-LINT-002"
    name: str = "Compromised / Untrusted Action Namespace"
    severity: Severity = Severity.HIGH #default val
    category: RuleCategory = RuleCategory.LINT
    description: str = (
        "A 'uses:' statement references a suspicious, unverified, or potentially "
        "typo-squatted action namespace (e.g. 'actons/checkout' instead of 'actions/checkout')."
    )
    cwe: str = "CWE-829"  # Inclusion of Functionality from Untrusted Control Sphere
    remediation: str = (
        "Verify the authenticity of the action author and pin the action to a trusted or "
        "allowlisted namespace."
    )

    def __init__(
        self,
        trusted_namespaces: Optional[Set[str]] = None,
        flag_all_untrusted: bool = False,
    ):
        """Initialize the rule.

        Args:
            trusted_namespaces: Set of allowed owner namespaces (defaults to official 'actions', 'github').
            flag_all_untrusted: If True, flag any namespace not in the trusted set as MEDIUM severity.
                                If False, only flag typo-squats and suspicious impersonations as HIGH severity.
        """
        self.trusted_namespaces = (
            set(trusted_namespaces) if trusted_namespaces is not None else DEFAULT_TRUSTED_NAMESPACES
        )
        self.flag_all_untrusted = flag_all_untrusted

    def check(self, ast: WorkflowAST) -> list[Finding]:
        findings: list[Finding] = []

        for job in ast.jobs:
            for step in job.steps:
                if not step.uses:
                    continue

                uses = step.uses

                # can contain values like actios/checkout@v4
                action_reference = uses.raw
                

                # Ignore local actions (./.github/actions/...) and docker images (docker://...)
                if action_reference.startswith("./") or action_reference.startswith("docker://"):
                    continue

                # GitHub account or organization that owns the repo. Example - "evil-owner" in "evil-owner/checkout@v4")
                owner = (uses.owner or "").lower()

                # Name of the repository containing the action. Example "checkout" in "actions/checkout@v4")
                repo = (uses.repo or "").lower()

                if not owner:
                    continue

                if step.pos.line > 0:
                    line_num = step.pos.line
                elif job.pos.line > 0:
                    line_num = job.pos.line
                else:
                    line_num = 1

                # Check 1: Typo-squatting detection against trusted namespaces
                is_typosquat = False
                for trusted in self.trusted_namespaces:
                    dist = levenshtein_distance(owner, trusted)
                    # Owner is distinct from trusted, but very close (e.g., dist 1 or 2 like 'actons' vs 'actions')
                    if 0 < dist <= 2:
                        is_typosquat = True
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                severity=Severity.HIGH,
                                file_path=ast.file_path,
                                line=line_num,
                                message=(
                                    f"Action '{action_reference}' references suspicious namespace '{owner}', "
                                    f"which appears to typo-squat official '{trusted}' namespace "
                                    f"(edit distance {dist})."
                                ),
                                remediation=(
                                    f"Verify the publisher identity and update namespace to '{trusted}/{repo}' "
                                    f"if this was an unintentional typo."
                                ),
                            )
                        )
                        break

                if is_typosquat:
                    continue

                # Check 2: Known official repository cloned under an untrusted owner
                # Example - 'evil/checkout' mimicking official 'actions/checkout'
                if repo in POPULAR_OFFICIAL_ACTIONS and owner not in self.trusted_namespaces:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            file_path=ast.file_path,
                            line=line_num,
                            message=(
                                f"Action '{action_reference}' references official repository name '{repo}' "
                                f"under third-party namespace '{owner}' rather than official 'actions'."
                            ),
                            remediation=(
                                f"Switch to the official action 'actions/{repo}' unless '{owner}/{repo}' "
                                f"is an intentional, audited fork."
                            ),
                        )
                    )
                    continue

                # Check 3: Optional strict namespace allowlist check
                # Example: "actions/checkout@v4" passes, but "evil-actor/setup-python@v1" is flagged because "evil-actor" is not in DEFAULT_TRUSTED_NAMESPACES.
                if self.flag_all_untrusted and owner not in self.trusted_namespaces:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.MEDIUM,
                            file_path=ast.file_path,
                            line=line_num,
                            message=(
                                f"Action '{action_reference}' uses third-party namespace '{owner}' "
                                f"outside the approved trusted namespaces list."
                            ),
                            remediation=(
                                f"Add '{owner}' to your organization's trusted namespace allowlist "
                                f"or vendor the action locally."
                            ),
                        )
                    )

        return findings
