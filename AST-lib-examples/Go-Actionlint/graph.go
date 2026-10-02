// Wrapper around gonum graph to represent taint flow in GitHub Actions workflows
// Creates a directed graph where nodes have a type (Source, Propagator, Sanitizer, Sink) 
// and a value (e.g., github.event.issue.body, env: USER_INPUT, run: echo $USER_INPUT)

// Needs to be built by going through the AST of actionlint and identifying sources,
// propagators, sanitizers, and sinks.

// Can then be used to look for paths between every source and sink.
package main

import (
	"fmt"
	"gonum.org/v1/gonum/graph/simple"
)

type NodeType string

const (
	Source     NodeType = "SOURCE"     // e.g., github.event.issue.body
	Propagator NodeType = "PROPAGATOR" // e.g., env: USER_INPUT
	Sanitizer  NodeType = "SANITIZER"  // e.g., ???
	Sink       NodeType = "SINK"       // e.g., run: echo $USER_INPUT
)

// TaintNode represents a graph vertex in Gonum
type TaintNode struct {
	id    int64
	Type  NodeType
	Value string
}

// Implement the gonum graph.Node interface
func (n *TaintNode) ID() int64 { return n.id }

type TaintGraph struct {
	*simple.DirectedGraph
	nodeCounter int64					// used to generate unique IDs for nodes
	nodes       map[string]*TaintNode	// map to prevent duplicate nodes for the same target (Type:Value)
}

func NewTaintGraph() *TaintGraph {
	return &TaintGraph{
		DirectedGraph: simple.NewDirectedGraph(),
		nodes:         make(map[string]*TaintNode),
	}
}

// GetNode prevents duplicate nodes for the same target
// If e.g. github.event.issue.body occurs twice in the workflow, it should be concidered as the same source
func (tg *TaintGraph) GetNode(nType NodeType, value string) *TaintNode {
	key := fmt.Sprintf("%s:%s", nType, value)
	if node, exists := tg.nodes[key]; exists {
		return node
	}

	tg.nodeCounter++
	node := &TaintNode{
		id:    tg.nodeCounter,
		Type:  nType,				// e.g. Source, Propagator, Sanitizer, Sink
		Value: value,				// e.g. github.event.issue.body, env: USER_INPUT, run:...
	}
	tg.nodes[key] = node
	tg.AddNode(node)
	return node
}

func (tg *TaintGraph) AddFlow(fromType NodeType, fromVal string, toType NodeType, toVal string) {
	fromNode := tg.GetNode(fromType, fromVal)
	toNode := tg.GetNode(toType, toVal)
	tg.SetEdge(tg.NewEdge(fromNode, toNode))
}