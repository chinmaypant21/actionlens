# Created with Opus 5.5 and Gemini 3.8 Flash

"""Tests for AL-CODE-002: Untrusted checkout on a privileged trigger."""

from pathlib import Path

from actionlens.models import Severity
from actionlens.parser import parse_workflow_file
from actionlens.sast.rules.taint_analysis.untrusted_checkout import UntrustedCheckoutRule


TESTDATA_DIR = Path(__file__).resolve().parent.parent / "testdata"
CREATE_TAINT_GRAPH = False  # Set to True to generate taint-flow graph visualizations for test cases


def test_untrusted_checkout_vulnerable():
    path = TESTDATA_DIR / "vulnerable" / "pull_request_target_checkout.yml"
    ast = parse_workflow_file(path)

    if CREATE_TAINT_GRAPH:
        rule = UntrustedCheckoutRule(visualize_path="untrusted_checkout_vulnerable.html")
    else:
        rule = UntrustedCheckoutRule()
    findings = rule.check(ast)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "AL-CODE-002"
    assert finding.severity == Severity.HIGH
    assert finding.line == 23
    assert "github.event.pull_request.head.sha" in finding.message
    assert "Run build script.run" in finding.message


def test_untrusted_checkout_secure():
    path = TESTDATA_DIR / "secure" / "pull_request_target_checkout_secure.yml"
    ast = parse_workflow_file(path)

    if CREATE_TAINT_GRAPH:
        rule = UntrustedCheckoutRule(visualize_path="untrusted_checkout_secure.html")
    else:
        rule = UntrustedCheckoutRule()
    findings = rule.check(ast)

    assert findings == []


def test_untrusted_checkout_without_execution_is_secure():
    path = TESTDATA_DIR / "vulnerable" / "pull_request_target_checkout.yml"
    ast = parse_workflow_file(path)
    ast.jobs[0].steps.pop()

    if CREATE_TAINT_GRAPH:
        rule = UntrustedCheckoutRule(visualize_path="untrusted_checkout_no_execution.html")
    else:
        rule = UntrustedCheckoutRule()
    findings = rule.check(ast)

    assert findings == []