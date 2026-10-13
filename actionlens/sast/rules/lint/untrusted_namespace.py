"""AL-LINT-002: Compromised / Untrusted Action Namespace.

Detects actions using suspicious, typo-squatted, or untrusted namespaces
(e.g., 'actons/checkout' mimicking 'actions/checkout').
"""

from typing import Optional, Set
from actionlens.models import Finding, Rule, RuleCategory, Severity, WorkflowAST

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


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


class UntrustedNamespaceRule(Rule):
    """AL-LINT-002: Flag actions referencing typo-squatted or unverified namespaces."""

    rule_id: str = "AL-LINT-002"
    name: str = "Compromised / Untrusted Action Namespace"
    severity: Severity = Severity.HIGH
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
                raw_ref = uses.raw

                # Ignore local actions (./.github/actions/...) and docker images (docker://...)
                if raw_ref.startswith("./") or raw_ref.startswith("docker://"):
                    continue

                owner = (uses.owner or "").lower()
                repo = (uses.repo or "").lower()

                if not owner:
                    continue

                line_num = step.pos.line if step.pos.line > 0 else (job.pos.line if job.pos.line > 0 else 1)

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
                                    f"Action '{raw_ref}' references suspicious namespace '{owner}', "
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
                # e.g., 'evil-corp/checkout' mimicking official 'actions/checkout'
                if repo in POPULAR_OFFICIAL_ACTIONS and owner not in self.trusted_namespaces:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.HIGH,
                            file_path=ast.file_path,
                            line=line_num,
                            message=(
                                f"Action '{raw_ref}' references official repository name '{repo}' "
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
                if self.flag_all_untrusted and owner not in self.trusted_namespaces:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=Severity.MEDIUM,
                            file_path=ast.file_path,
                            line=line_num,
                            message=(
                                f"Action '{raw_ref}' uses third-party namespace '{owner}' "
                                f"outside the approved trusted namespaces list."
                            ),
                            remediation=(
                                f"Add '{owner}' to your organization's trusted namespace allowlist "
                                f"or vendor the action locally."
                            ),
                        )
                    )

        return findings
