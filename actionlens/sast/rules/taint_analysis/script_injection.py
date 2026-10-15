"""AL-CODE-001 Script Injection (RCE)

Detects untrusted user input being passed to a script execution context 
(e.g., shell commands, Python scripts, etc.) without proper sanitization or validation.
"""

from typing import Optional, Set, Any
from actionlens.models import Finding, Rule, RuleCategory, Severity, WorkflowAST
import re
import networkx as nx

try:
    from .taint_graph import TaintGraph, NodeType
    from .visualization import visualize_graph
except ImportError:
    from actionlens.sast.rules.taint_analysis.taint_graph import TaintGraph, NodeType
    from actionlens.sast.rules.taint_analysis.visualization import visualize_graph

# User manipulated contexts that may be used to inject malicious scripts or commands into a workflow
UNTRUSTED_CONTEXTS: set[str] = {
    "github.event.issue.body",
    "github.event.issue.title",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.head_ref",
    "github.event.comment.body",
    "github.event.review.body",
}
def is_source(expr: str) -> bool:
    """Return True if the expression contains an untrusted context."""
    _alt = "|".join(re.escape(c) for c in sorted(UNTRUSTED_CONTEXTS, key=len, reverse=True))
    source_re = re.compile(rf"(?<![\w.])(?P<ctx>{_alt})(?![\w-])", re.IGNORECASE)
    return bool(source_re.search(expr))


# In the parsed json the expressions.location always notes the sinks for this step. Based on this sink type the eg "run" statement needs to be identified
# Possible tainted execution environments
SINKS = { 
    "run",
    "with.script",
    "with.ref",
}

def find_source(expr: str) -> list[str] | None:
    """Return a list of untrusted contexts found in the expression."""
    # Build a regex pattern that matches any of the untrusted contexts
    # Longest first so a longer name is never shadowed by a shorter prefix
    _alt = "|".join(re.escape(c) for c in sorted(UNTRUSTED_CONTEXTS, key=len, reverse=True))
    # Whole ${{ ... }} expression that contains an untrusted context anywhere inside
    expr_re = re.compile(
        rf"\$\{{\{{(?:(?!\}}\}}).)*?(?<![\w.])(?P<ctx>{_alt})(?![\w-])(?:(?!\}}\}}).)*\}}\}}",
        re.IGNORECASE | re.DOTALL,
    )
    m = expr_re.search(expr)
    if not m:
        return None
    return [m.group("ctx")]

def extract_write_to_githuboutput(line: str) -> tuple[str, list[str]] | None:
    """ Extracts the output name and referenced variables from a line that writes to GITHUB_OUTPUT.
    Returns a tuple (output_name, [referenced_variables]) or None if the line does not match the expected pattern.
    """
    github_output_regex = re.compile(r'''
    echo \s+ (?:-[neE]+\s+)?                 # echo-Flags
    (?P<q>["']?)                             # opening quote
    (?P<name>[A-Za-z_][\w-]*)                # output name
    =
    (?P<value>.*?)                           # output value
    (?P=q) \s*                               # closing quote
    >> \s* ["']? \$\{? GITHUB_OUTPUT \}? ["']?
    ''', re.VERBOSE)
    extract_variables_referenced_regex = re.compile(r'\$(?:\{(?P<braced>[A-Za-z_]\w*)[^}]*\}|(?P<plain>[A-Za-z_]\w*))')

    m = github_output_regex.search(line)
    if not m:
        return None
    vars_ = [g.group('braced') or g.group('plain') for g in extract_variables_referenced_regex.finditer(m.group('value'))]
    return m.group('name'), vars_

class ScriptInjectionRule(Rule):
    """AL-CODE-001: Detect untrusted user input being passed to script execution contexts."""

    rule_id: str = "AL-CODE-001"
    name: str = "Script Injection (RCE)"
    severity: Severity = Severity.HIGH
    category: RuleCategory = RuleCategory.CODE_ANALYSIS
    description: str = (
        "Untrusted user input is being passed to a script execution context "
        "(e.g., shell commands, Python scripts) without proper sanitization or validation."
    )
    cwe: str = "CWE-78"  # Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    remediation: str = (
        "Validate and sanitize all user input before executing scripts. "
        "Use intermediate environment variables to avoid direct shell execution."
    )

    def __init__(
            self, visualize_path: str | None = None
    ):
        """
        Initialize the rule.
        If visualize_path is True, a taint-flow graph will be generated the specified path.
        """
        self.visualize_path = visualize_path

    def check(self, ast: WorkflowAST) -> list[Finding]:
        findings: list[Finding] = []
        taint_graph, sink_lines = build_taint_graph(ast)
        # Perform taint analysis on the built graph
        for path in find_direct_injection_paths(taint_graph):
            sink_node = path[0]
            unstrusted_input_node = path[1]
            line_number = sink_lines.get(sink_node.value, -1)
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                file_path=ast.file_path,
                line=line_number,
                message=f"Untrusted user input '{unstrusted_input_node.value}' is being passed to a script execution context.",
                remediation=self.remediation
            ))
        if self.visualize_path:
            visualize_graph(taint_graph, output_path=self.visualize_path)
        return findings

def build_taint_graph(ast: WorkflowAST) -> tuple[TaintGraph, dict[str, int]]:
    """Build a taint graph from normalized WorkflowAST JSON.
    Note that the paths are pointing from the sink to the source for analysis reasons. 

    The graph is based on normalized ``expressions`` entries rather than
    reparsing GitHub Actions expression syntax in Python.
    """
    graph = TaintGraph()
    sink_lines: dict[str, int] = {} # Holds sink lines for later reference: "node_id": line_number

    for job in ast.jobs:
        job_id = job.id

        for step_index, step in enumerate(job.steps):
            step_name = step.id or step.name or f"step-{step_index}"

            # ---- (1): Find references to variables in execution script ----
            # Supported exec types are "run" and "action" (with.script, with.ref)
            exec_type = step.exec_type
            # According to exec_type, extract variable usage from execution environment
            match exec_type:
                case "run":
                    execution = step.run or ""
                    execution_label = f"{step_name}.run"

                case "action":
                    if step.with_.get("script", ""):
                        execution = step.with_.get("script", "")
                        execution_label = f"{step_name}.with.script"
                    elif step.with_.get("ref", ""):
                        execution = step.with_.get("ref", "")
                        execution_label = f"{step_name}.with.ref"
                    else:
                        execution = ""
                        execution_label = f"{step_name}.with.unknown_exec_type"
                        # TODO error

                case _:
                    execution = ""
                    execution_label = f"{step_name}.unknown_exec_type"
                    # TODO error

            # Create nodes for usage of untrusted contexts in the execution environment
            untrusted_context_variables = find_source(execution) or []
            for ucv in untrusted_context_variables:
                graph.add_flow(NodeType.SINK, execution_label,
                               NodeType.SOURCE, ucv)
            used_env_variables = [
                f"env.{name.lower()}"
                for name in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", execution)
                if name != "GITHUB_OUTPUT"
            ]
            for uev in used_env_variables:
                graph.add_flow(NodeType.SINK, execution_label,
                               NodeType.SANITIZER, uev)
            write_to_githuboutput = extract_write_to_githuboutput(execution)
            if write_to_githuboutput:
                output_name = write_to_githuboutput[0]
                referenced_vars = write_to_githuboutput[1]
                for env_var in referenced_vars:
                    graph.add_flow(NodeType.PROPAGATOR, f"steps.{step_name}.outputs.{output_name}", 
                                    NodeType.SANITIZER, f"env.{env_var.lower()}")

            # ---- (2): Trace values of environment variables through the "env field ----
            for variable, value in step.env.items():
                env_var_re = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")
                env_variables = [
                    f"env.{name.lower()}" for name in env_var_re.findall(value)
                    if name != "GITHUB_OUTPUT"
                ]
                github_ctx_variables = find_source(value) or []

                for v in env_variables:
                    graph.add_flow(NodeType.SANITIZER, f"env.{variable}", NodeType.PROPAGATOR, v)
                for v in github_ctx_variables:
                    graph.add_flow(NodeType.SANITIZER, f"env.{variable}", NodeType.SOURCE, v)

            # ---- (3): Analyse the expressions ----
            for expression in step.expressions:
                context = expression.context
                location = expression.location or "<no location>"
                context_label = NodeType.SOURCE if is_source(context) else NodeType.PROPAGATOR
                location_label = NodeType.SINK if location in SINKS else NodeType.SANITIZER # when propagator?
                location = f"{step_name}.{location}" if location in SINKS else location
                if location_label is NodeType.SINK:
                    pos = step.pos
                    line = pos.line or -1
                    sink_lines[location] = line

                graph.add_flow(location_label, location, context_label, context)

    return graph, sink_lines

def find_direct_injection_paths(graph: TaintGraph) -> list[list[Any]]:
    """Return sink-to-source paths that do not pass through a sanitizer."""
    paths: list[list[Any]] = []
    for sink in graph:
        if sink.type is not NodeType.SINK:
            continue
        for source in graph:
            if source.type is not NodeType.SOURCE:
                continue
            if not nx.has_path(graph, sink, source):
                continue
            for path in nx.all_simple_paths(graph, sink, source):
                # test, if there is a sanitizer right before the sink, if so, skip this path
                if len(path) > 1 and path[1].type is NodeType.SANITIZER:
                    continue

                paths.append(path)
                # NOTE future work: it may be worth it to diffrentiate between different types of propagators,
                # namely those that are simply propagating and those that are actually DEsanitizing the input.
                # Or, depending on the identified sink, assign sanitizers and propagators differently.
    return paths