"""Load the normalized workflow AST and build a taint-flow graph."""

import json
import re
from pathlib import Path
from typing import Any

import networkx as nx

try:
    from .taint_graph import NodeType, TaintGraph
    from .visualization import visualize_graph
except ImportError:
    from taint_graph import NodeType, TaintGraph
    from visualization import visualize_graph

GITHUB_CTX = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")
ENV_VAR = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)")

PROPAGATORS = (
    "env.",
)
SANITIZERS = (
    "shell-variable",
)
# something needs to happen when encountering a "steps.capture.outputs.pr_title" where the propagator is correctly linked to the sink or next propagator. 
# TODO: not all propagators are recognized correctly, e.g. "steps.capture.outputs.pr_title" is more of a propagator than a source, but it fits the current regex for sources. 
# TODO: steps.<step_id>.outputs.<out_var> should trigger a flow from the execution of the mentioned step to this context.
# TODO: questionable whether environment variables are propagators or sanitizers. Does it depend on their final usage? Further research needed!
# TODO: instead of a "run" command some workflows use "uses", "with" or "script" to call an action. These are completely overlooked as of now. 

# ------
# USAGE: Simply modify the path to the AST JSON file below and run this script. It will generate a taint-flow graph visualization and print direct injection paths.
# ------
AST_PATH = "example.json"

def load_ast(path: str | Path) -> dict[str, Any]:
    """Load a normalized AST JSON file produced by the Go parser."""
    with Path(path).open(encoding="utf-8") as ast_file:
        return json.load(ast_file)


def build_taint_graph(ast: dict[str, Any]) -> TaintGraph:
    """Build a taint graph from normalized WorkflowAST JSON.

    The graph is based on normalized ``expressions`` entries rather than
    reparsing GitHub Actions expression syntax in Python.
    """
    graph = TaintGraph()

    for job in ast.get("jobs", []):
        job_id = job.get("id", "unknown-job")
        for step_index, step in enumerate(job.get("steps", [])):
            step_name = step.get("id") or step.get("name") or f"step-{step_index}"
            step_label = f"{job_id}/{step_name}"

            for variable, value in step.get("env", {}).items():
                env_variables = [
                    f"env.{name.lower()}" for name in ENV_VAR.findall(value)
                ]
                github_ctx_variables = GITHUB_CTX.findall(value)

                for v in env_variables:
                    graph.add_flow(NodeType.PROPAGATOR, v, NodeType.PROPAGATOR, f"env.{variable}")
                for v in github_ctx_variables:
                    graph.add_flow(NodeType.SOURCE, v, NodeType.PROPAGATOR, f"env.{variable}")


            for expression in step.get("expressions", []):
                context = expression.get("context", "")
                location = expression.get("location", "")
                # context_label = NodeType.SOURCE if context.startswith(SOURCES) else NodeType.PROPAGATOR
                context_label = NodeType.SOURCE
                location_label = NodeType.SINK if location=="run" else NodeType.PROPAGATOR # when sanitizer?

                graph.add_flow(context_label, context, location_label, location)


            execution = step.get("run", "")
            env_variables = [
                f"env.{name.lower()}" for name in ENV_VAR.findall(execution)
            ]
            github_ctx_variables = GITHUB_CTX.findall(execution)
            for v in env_variables:
                graph.add_flow(NodeType.PROPAGATOR, v, NodeType.SINK, "run")
            for v in github_ctx_variables:
                graph.add_flow(NodeType.SOURCE, v, NodeType.SINK, "run")


    return graph


def find_direct_injection_paths(graph: TaintGraph) -> list[list[Any]]:
    """Return source-to-sink paths that do not pass through a sanitizer."""
    paths: list[list[Any]] = []
    for source in graph:
        if source.type is not NodeType.SOURCE:
            continue
        for sink in graph:
            if sink.type is not NodeType.SINK:
                continue
            if not nx.has_path(graph, source, sink):
                continue
            for path in nx.all_simple_paths(graph, source, sink):
                if not any(node.type is NodeType.SANITIZER for node in path):
                    paths.append(path)
    return paths


if __name__ == "__main__":
    ast = load_ast(Path(__file__).with_name(AST_PATH))
    taint_graph = build_taint_graph(ast)
    visualize_graph(taint_graph, output_path="taint_graph.html")
    for path in find_direct_injection_paths(taint_graph):
        print(" -> ".join(node.value for node in path))


