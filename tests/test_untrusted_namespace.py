"""Tests for AL-LINT-002: Compromised/Untrusted Action Namespace."""

from pathlib import Path
import json

from actionlens.parser import parse_workflow_file
from actionlens.sast.rules.lint.untrusted_namespace import UntrustedNamespaceRule
from actionlens.sast.orchestrator import SASTOrchestrator
from actionlens.models import Severity

TESTDATA_DIR = Path(__file__).resolve().parent.parent / "testdata"


def test_untrusted_namespace_vulnerable():
    vuln_path = TESTDATA_DIR / "vulnerable" / "untrusted_namespace.yml"
    ast = parse_workflow_file(vuln_path)

    rule = UntrustedNamespaceRule()
    findings = rule.check(ast)

    assert len(findings) == 2

    # First finding: typo-squat 'actons' vs 'actions'
    f1 = findings[0]
    assert f1.rule_id == "AL-LINT-002"
    assert f1.severity == Severity.HIGH
    assert "actons" in f1.message
    assert "typo-squat" in f1.message
    assert f1.line == 12

    # Second finding: official repo 'setup-python' under untrusted owner 'evil-actor'
    f2 = findings[1]
    assert f2.rule_id == "AL-LINT-002"
    assert f2.severity == Severity.HIGH
    assert "evil-actor" in f2.message
    assert "setup-python" in f2.message
    assert f2.line == 14


def test_untrusted_namespace_secure():
    secure_path = TESTDATA_DIR / "secure" / "untrusted_namespace.yml"
    ast = parse_workflow_file(secure_path)

    rule = UntrustedNamespaceRule()
    findings = rule.check(ast)

    assert len(findings) == 0


def test_orchestrator_end_to_end_report():
    vuln_path = TESTDATA_DIR / "vulnerable" / "untrusted_namespace.yml"
    orchestrator = SASTOrchestrator()

    # Get JSON output matching step 4 of development.md
    json_report = orchestrator.scan_and_report_json(vuln_path)
    data = json.loads(json_report)

    assert isinstance(data, list)
    assert len(data) == 4

    rule_ids = {item["rule_id"] for item in data}
    assert rule_ids == {"AL-LINT-001", "AL-LINT-002"}

    for item in data:
        assert item["rule_id"] in {"AL-LINT-001", "AL-LINT-002"}
        assert item["severity"] in {"HIGH", "MEDIUM"}
        assert "file_path" in item
        assert "line" in item
        assert "message" in item
        assert "remediation" in item
