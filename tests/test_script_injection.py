"""Tests for AL-CODE-001: Script Injection Vulnerability."""

from pathlib import Path
from actionlens.parser import parse_workflow_file
from actionlens.sast.rules.taint_analysis.script_injection import ScriptInjectionRule
from actionlens.models import Severity

TESTDATA_DIR = Path(__file__).resolve().parent.parent / "testdata"
CREATE_TAINT_GRAPH = False  # Set to True to generate taint-flow graph visualizations for test cases

# ---- Test VULNERABLE workflows ----
def test_expression_injection_vulnerable():
    vuln_path = TESTDATA_DIR / "vulnerable" / "script_injections" / "expression_injection.yml"
    ast = parse_workflow_file(vuln_path)

    if CREATE_TAINT_GRAPH:
        rule = ScriptInjectionRule(visualize_path="expression_injection_vulnerable.html")
    else:
        rule = ScriptInjectionRule()

    findings = rule.check(ast)

    assert len(findings) == 1

    f1 = findings[0]
    assert f1.rule_id == "AL-CODE-001"
    assert f1.severity == Severity.HIGH
    assert f1.line == 15 # NOTE 17 would be nicer, but the parser is not giving that


def test_inject_via_githuboutput():
    vuln_path = TESTDATA_DIR / "vulnerable" / "script_injections" / "inject_via_githuboutput.yml"
    ast = parse_workflow_file(vuln_path)

    if CREATE_TAINT_GRAPH:
        rule = ScriptInjectionRule(visualize_path="inject_via_githuboutput.html")
    else:
        rule = ScriptInjectionRule()
    findings = rule.check(ast)

    assert len(findings) == 1

    f1 = findings[0]
    assert f1.rule_id == "AL-CODE-001"
    assert f1.severity == Severity.HIGH
    assert f1.line == 11


def test_script_injection_with():
    vuln_path = TESTDATA_DIR / "vulnerable" / "script_injections" / "script_injection_with.yml"
    ast = parse_workflow_file(vuln_path)

    if CREATE_TAINT_GRAPH:
        rule = ScriptInjectionRule(visualize_path="script_injection_with.html")
    else:
        rule = ScriptInjectionRule()
    findings = rule.check(ast)

    assert len(findings) == 1

    f1 = findings[0]
    assert f1.rule_id == "AL-CODE-001"
    assert f1.severity == Severity.HIGH
    assert f1.line == 18 # NOTE 22 would be nicer, but the parser is not giving that


# ---- Test SECURE workflows ----
def test_clean_direct_githuboutput():
    safe_path = TESTDATA_DIR / "secure" / "script_injections" / "clean_direct_githuboutput.yml"
    ast = parse_workflow_file(safe_path)

    if CREATE_TAINT_GRAPH:
        rule = ScriptInjectionRule(visualize_path="clean_direct_githuboutput.html")
    else:
        rule = ScriptInjectionRule()
    findings = rule.check(ast)

    assert len(findings) == 0


def test_clean_envvar_githuboutput():
    safe_path = TESTDATA_DIR / "secure" / "script_injections" / "clean_envvar_githuboutput.yml"
    ast = parse_workflow_file(safe_path)

    if CREATE_TAINT_GRAPH:
        rule = ScriptInjectionRule(visualize_path="clean_envvar_githuboutput.html")
    else:
        rule = ScriptInjectionRule()
    findings = rule.check(ast)

    assert len(findings) == 0


def test_expression_injection_secure():
    safe_path = TESTDATA_DIR / "secure" / "script_injections" / "expression_injection_remediated.yml"
    ast = parse_workflow_file(safe_path)

    if CREATE_TAINT_GRAPH:
        rule = ScriptInjectionRule(visualize_path="expression_injection_secure.html")
    else:
        rule = ScriptInjectionRule()
    findings = rule.check(ast)

    assert len(findings) == 0


def test_script_injection_with_secure():
    safe_path = TESTDATA_DIR / "secure" / "script_injections" / "script_injection_with_secure.yml"
    ast = parse_workflow_file(safe_path)

    if CREATE_TAINT_GRAPH:
        rule = ScriptInjectionRule(visualize_path="script_injection_with_secure.html")
    else:
        rule = ScriptInjectionRule()
    findings = rule.check(ast)

    assert len(findings) == 0


def test_tainted_remediated_githuboutput():
    safe_path = TESTDATA_DIR / "secure" / "script_injections" / "tainted_remediated_githuboutput.yml"
    ast = parse_workflow_file(safe_path)

    if CREATE_TAINT_GRAPH:
        rule = ScriptInjectionRule(visualize_path="tainted_remediated_githuboutput.html")
    else:
        rule = ScriptInjectionRule()
    findings = rule.check(ast)

    assert len(findings) == 0