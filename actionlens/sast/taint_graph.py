"""Directed taint-flow graph for GitHub Actions workflows."""
"""Translated from Go to Python using AI."""

from dataclasses import dataclass
from enum import Enum

import networkx as nx


class NodeType(str, Enum):
    """Categories used to classify taint-flow graph nodes."""

    SOURCE = "SOURCE"
    PROPAGATOR = "PROPAGATOR"
    SANITIZER = "SANITIZER"
    SINK = "SINK"


@dataclass(frozen=True)
class TaintNode:
    """A vertex in the taint-flow graph."""

    id: int
    type: NodeType
    value: str


class TaintGraph(nx.DiGraph):
    """NetworkX directed graph that deduplicates nodes by type and value."""

    def __init__(self) -> None:
        super().__init__()
        self._node_counter = 0
        self._nodes: dict[tuple[NodeType, str], TaintNode] = {}

    def get_node(self, node_type: NodeType, value: str) -> TaintNode:
        """Return an existing node or create one for ``(node_type, value)``."""
        key = (node_type, value)
        if key in self._nodes:
            return self._nodes[key]

        self._node_counter += 1
        node = TaintNode(id=self._node_counter, type=node_type, value=value)
        self._nodes[key] = node
        self.add_node(node)
        return node

    def add_flow(
        self,
        from_type: NodeType,
        from_value: str,
        to_type: NodeType,
        to_value: str,
    ) -> None:
        """Add a directed taint-flow edge between two nodes."""
        from_node = self.get_node(from_type, from_value)
        to_node = self.get_node(to_type, to_value)
        self.add_edge(from_node, to_node)