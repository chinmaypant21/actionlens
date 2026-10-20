"""Source of truth for ActionLens rule metadata.

Rule classes hold detection logic only and look up their metadata here by ID.
To add a rule, register its metadata in RULE_CATALOG and set
``metadata = RULE_CATALOG["<rule-id>"]`` on the rule class.
"""

from actionlens.models import RuleCategory, RuleMetadata, Severity


_CATALOG = {
    # ---------- Lint rules ----------
    "AL-LINT-001": {
        "name": "Unpinned Third-Party Action",
        "severity": Severity.MEDIUM,
        "category": RuleCategory.LINT,
        "description": "A 'uses:' statement references a mutable branch or tag rather than a full, 40-character commit SHA.",
        "cwe": "CWE-494",  # Download of Code Without Integrity Check
        "owasp_cicd": "CICD-SEC-3: Dependency Chain Abuse",
        "remediation": "Pin the action to a full 40-character commit SHA.",
    },
    "AL-LINT-002": {
        "name": "Compromised / Untrusted Action Namespace",
        "severity": Severity.HIGH,
        "category": RuleCategory.LINT,
        "description": (
            "A 'uses:' statement references a suspicious, unverified, or potentially "
            "typo-squatted action namespace (e.g. 'actons/checkout' instead of 'actions/checkout')."
        ),
        "cwe": "CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
        "owasp_cicd": "CICD-SEC-3: Dependency Chain Abuse",
        "remediation": (
            "Verify the authenticity of the action author and pin the action to a trusted or "
            "allowlisted namespace."
        ),
    },
    "AL-LINT-003": {
        "name": "Missing or Over-scoped Permissions Block",
        "severity": Severity.LOW,
        "category": RuleCategory.LINT,
        "description": (
            "The workflow lacks a top-level permissions: block (defaulting GITHUB_TOKEN to broad "
            "repository permissions), or explicitly grants broad 'write-all' access."
        ),
        "cwe": "CWE-250",  # Execution with Unnecessary Privileges
        "owasp_cicd": "CICD-SEC-5: Insufficient Pipeline-Based Access Controls (PBAC)",
        "remediation": (
            "Specify a restrictive top-level 'permissions: {}' block and grant only minimal scoped "
            "permissions to individual jobs as needed."
        ),
    },
    "AL-LINT-004": {
        "name": "Unsafe Self-Hosted Runner Usage",
        "severity": Severity.HIGH,
        "category": RuleCategory.LINT,
        "description": (
            "A job specifies a self-hosted runner rather than GitHub-hosted infrastructure, "
            "risking unauthorized code execution and network compromise."
        ),
        "cwe": "CWE-668",  # Exposure of Resource to Wrong Sphere
        "owasp_cicd": "CICD-SEC-7: Insecure System Configuration",
        "remediation": (
            "Use GitHub-hosted runners (e.g. 'ubuntu-latest') for public repositories or untrusted PR triggers. "
            "If self-hosted runners are necessary, ensure they are ephemeral and strictly network-isolated."
        ),
    },
    # ---------- Code / taint analysis rules ----------
    "AL-CODE-001": {
        "name": "Script Injection (RCE)",
        "severity": Severity.HIGH,
        "category": RuleCategory.CODE_ANALYSIS,
        "description": (
            "Untrusted user input is being passed to a script execution context "
            "(e.g., shell commands, Python scripts) without proper sanitization or validation."
        ),
        "cwe": "CWE-94",  # Improper Control of Generation of Code (Code Injection)
        "owasp_cicd": "CICD-SEC-4: Poisoned Pipeline Execution (PPE)",
        "remediation": (
            "Validate and sanitize all user input before executing scripts. "
            "Use intermediate environment variables to avoid direct shell execution."
        ),
    },
    "AL-CODE-002": {
        "name": "Untrusted Checkout on Privileged Trigger",
        "severity": Severity.HIGH,
        "category": RuleCategory.CODE_ANALYSIS,
        "description": (
            "An untrusted pull request ref is checked out in a privileged "
            "pull_request_target workflow."
        ),
        "cwe": "CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
        "owasp_cicd": "CICD-SEC-4: Poisoned Pipeline Execution (PPE)",
        "remediation": (
            "Do not check out pull request head refs in pull_request_target workflows. "
            "Use the trusted base revision or run untrusted code in an isolated workflow."
        ),
    },
}

# Validate each entry (missing/misspelled fields fail at import time)
RULE_CATALOG: dict[str, RuleMetadata] = {
    rule_id: RuleMetadata(rule_id=rule_id, **fields) for rule_id, fields in _CATALOG.items()
}
