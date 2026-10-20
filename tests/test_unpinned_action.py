# Created with Opus 5.5 and Gemini 3.8 Flash

"""Tests for AL-LINT-001: Unpinned Third-Party Action."""

from pathlib import Path
from actionlens.parser import parse_workflow_file
from actionlens.sast.rules.lint.unpinned_action import UnpinnedActionRule
from actionlens.models import Severity

TESTDATA_DIR = Path(__file__).resolve().parent.parent / "testdata"


def test_unpinned_action_vulnerable():
    vuln_path = TESTDATA_DIR / "vulnerable" / "unpinned_action.yml"
    ast = parse_workflow_file(vuln_path)

    rule = UnpinnedActionRule()
    findings = rule.check(ast)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.rule_id == "AL-LINT-001"
    assert f1.severity == Severity.MEDIUM
    assert "actions/checkout@v4" in f1.message
    assert f1.line == 13

    f2 = findings[1]
    assert f2.rule_id == "AL-LINT-001"
    assert f2.severity == Severity.MEDIUM
    assert "actions/setup-node@main" in f2.message
    assert f2.line == 14


def test_unpinned_action_secure():
    secure_path = TESTDATA_DIR / "secure" / "unpinned_action_pinned.yml"
    ast = parse_workflow_file(secure_path)

    rule = UnpinnedActionRule()
    findings = rule.check(ast)

    assert len(findings) == 0
