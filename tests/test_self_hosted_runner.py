"""Tests for AL-LINT-004: Unsafe Self-Hosted Runner Usage."""

from pathlib import Path

from actionlens.models import Severity
from actionlens.parser import parse_workflow_file
from actionlens.sast.orchestrator import SASTOrchestrator
from actionlens.sast.rules.lint.self_hosted_runner import SelfHostedRunnerRule

TESTDATA_DIR = Path(__file__).resolve().parent.parent / "testdata"


def test_self_hosted_runner_vulnerable():
    vuln_path = TESTDATA_DIR / "vulnerable" / "self_hosted_runner.yml"
    ast = parse_workflow_file(vuln_path)

    rule = SelfHostedRunnerRule()
    findings = rule.check(ast)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "AL-LINT-004"
    assert f.severity == Severity.HIGH
    assert "build" in f.message
    assert "pull_request" in f.message
    assert f.line == 15


def test_self_hosted_runner_secure():
    secure_path = TESTDATA_DIR / "secure" / "self_hosted_runner.yml"
    ast = parse_workflow_file(secure_path)

    rule = SelfHostedRunnerRule()
    findings = rule.check(ast)

    assert len(findings) == 0


def test_orchestrator_detects_self_hosted_runner():
    vuln_path = TESTDATA_DIR / "vulnerable" / "self_hosted_runner.yml"
    orchestrator = SASTOrchestrator()
    findings = orchestrator.scan_workflow(vuln_path)

    rule_ids = [f.rule_id for f in findings]
    assert "AL-LINT-004" in rule_ids
