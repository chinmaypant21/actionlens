"""AL-CODE-002: Untrusted checkout in a privileged pull request workflow."""

from typing import Any

import networkx as nx

from actionlens.models import Finding, Rule, WorkflowAST
from actionlens.sast.rules.catalog import RULE_CATALOG

try:
	from .taint_graph import NodeType, TaintGraph
	from .visualization import visualize_graph
except ImportError:
	from actionlens.sast.rules.taint_analysis.taint_graph import NodeType, TaintGraph
	from actionlens.sast.rules.taint_analysis.visualization import visualize_graph


UNTRUSTED_CHECKOUT_CONTEXTS = {
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.sha",
	"github.head_ref",
}


class UntrustedCheckoutRule(Rule):
	"""Detect an untrusted PR ref checked out under ``pull_request_target``."""

	metadata = RULE_CATALOG["AL-CODE-002"]

	def __init__(self, visualize_path: str | None = None):
		self.visualize_path = visualize_path

	def check(self, ast: WorkflowAST) -> list[Finding]:
		graph, sink_lines = build_taint_graph(ast)
		findings: list[Finding] = []

		for path in find_untrusted_checkout_paths(graph):
			sink_node = path[0]
			source_node = path[-1]
			findings.append(Finding(
				rule_id=self.rule_id,
				cwe=self.cwe,
				owasp_cicd=self.owasp_cicd,
				severity=self.severity,
				file_path=ast.file_path,
				line=sink_lines.get(sink_node.value, -1),
				message=(
					f"Untrusted pull request ref '{source_node.value}' is checked out "
					"under the privileged pull_request_target trigger."
				),
				remediation=self.remediation,
			))

		if self.visualize_path:
			visualize_graph(graph, output_path=self.visualize_path)

		return findings


def build_taint_graph(ast: WorkflowAST) -> tuple[TaintGraph, dict[str, int]]:
	"""Build sink-to-source flows for privileged checkout operations."""
	graph = TaintGraph()
	sink_lines: dict[str, int] = {}
	privileged = any(trigger.event == "pull_request_target" for trigger in ast.triggers)
	if not privileged:
		return graph, sink_lines

	for job in ast.jobs:
		for step_index, step in enumerate(job.steps):
			if not step.uses or step.uses.owner != "actions" or step.uses.repo != "checkout":
				continue

			ref_expression = step.with_.get("ref")
			if not isinstance(ref_expression, str):
				continue

			sink = f"{step.id or step.name or f'step-{step_index}'}.with.ref"
			for expression in step.expressions:
				if expression.location != "with.ref":
					continue
				if expression.context not in UNTRUSTED_CHECKOUT_CONTEXTS:
					continue

				graph.add_flow(NodeType.SINK, sink, NodeType.SOURCE, expression.context)
				sink_lines[sink] = step.pos.line or -1

	return graph, sink_lines


def find_untrusted_checkout_paths(graph: TaintGraph) -> list[list[Any]]:
	"""Return checkout sink-to-source paths without sanitizers."""
	paths: list[list[Any]] = []
	for sink in graph:
		if sink.type is not NodeType.SINK:
			continue
		for source in graph:
			if source.type is not NodeType.SOURCE or not nx.has_path(graph, sink, source):
				continue
			for path in nx.all_simple_paths(graph, sink, source):
				if not any(node.type is NodeType.SANITIZER for node in path[1:-1]):
					paths.append(path)
	return paths
