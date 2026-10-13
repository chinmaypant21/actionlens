"""Tests for AL-LINT-003: Missing or Over-scoped Permissions Block."""

from pathlib import Path
from actionlens.parser import parse_workflow_file
from actionlens.sast.rules.lint.permissions_block import PermissionsBlockRule
from actionlens.models import Severity

TESTDATA_DIR = Path(__file__).resolve().parent.parent / "testdata"


def test_permissions_block_vulnerable():
    vuln_path = TESTDATA_DIR / "vulnerable" / "excessive_permissions.yml"
    ast = parse_workflow_file(vuln_path)

    rule = PermissionsBlockRule()
    findings = rule.check(ast)

    assert len(findings) == 2

    # Finding 1: missing top-level permissions
    f1 = findings[0]
    assert f1.rule_id == "AL-LINT-003"
    assert f1.severity == Severity.LOW
    assert "missing a top-level 'permissions:' block" in f1.message

    # Finding 2: job grants write-all
    f2 = findings[1]
    assert f2.rule_id == "AL-LINT-003"
    assert f2.severity == Severity.MEDIUM
    assert "write-all" in f2.message
    assert f2.line == 12


def test_permissions_block_secure():
    secure_path = TESTDATA_DIR / "secure" / "least_privilege_permissions.yml"
    ast = parse_workflow_file(secure_path)

    rule = PermissionsBlockRule()
    findings = rule.check(ast)

    assert len(findings) == 0
