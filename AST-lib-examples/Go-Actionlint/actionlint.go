package main

import (
	"fmt"
	"github.com/rhysd/actionlint"
)

func main() {
	workflowYaml := []byte(`
name: Test
on: issue_comment
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.body }}"
`)

	// 1. Parse workflow into typed AST
	w, errs := actionlint.Parse(workflowYaml)
	if len(errs) > 0 {
		panic(errs[0])
	}

	// 2. Build Taint Flow Graph
	g := NewTaintGraph()
	println(g)

	// Here, we need to parse the AST of the workflow and identify sources, propagators, sanitizers, and sinks.
	// Add edges between them to build the taint flow graph. 
	// What does the AST look like tho? And how do we identify edges?
	// -> https://pkg.go.dev/github.com/rhysd/actionlint@v1.7.12#Workflow
	for _, job := range w.Jobs {
		for _, step := range job.Steps {

			// Inspect 'run:' script steps (Sinks)
			if exec, ok := step.Exec.(*actionlint.ExecRun); ok {
				fmt.Printf("Analyzing Step Sink: %s\n", exec.Run.Value)

				// actionlint provides helper ast.ContainsExpression
				if exec.Run.ContainsExpression() {
					// Extract expressions (e.g., github.event.issue.body -> Source)
					fmt.Println("  Found dynamic ${{ }} expression injection inside shell sink!")
				}
			}
		}
	}
}