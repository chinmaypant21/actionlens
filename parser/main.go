package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

// main is the CLI entrypoint for the parser frontend.
// It reads a GitHub Actions workflow YAML file and outputs a normalized AST JSON.
func main() {
	filePath := flag.String("file", "", "Path to the GitHub Actions workflow YAML file (optional if passed as positional arg)")
	pretty := flag.Bool("pretty", true, "Pretty print output JSON")
	flag.Parse()

	// Allow file path to be passed either via -file flag or as first positional argument
	targetFile := *filePath
	if targetFile == "" && flag.NArg() > 0 {
		targetFile = flag.Arg(0)
	}

	var content []byte
	var err error
	var sourceName string

	// Read from stdin if no file is provided or '-' is specified; otherwise read from disk
	if targetFile == "" || targetFile == "-" {
		sourceName = "stdin"
		content, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
	} else {
		sourceName = targetFile
		content, err = os.ReadFile(targetFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %v\n", targetFile, err)
			os.Exit(1)
		}
	}

	// Parse YAML into normalized WorkflowAST using actionlint
	ast, err := ParseWorkflow(sourceName, content)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing workflow: %v\n", err)
		os.Exit(1)
	}

	// Serialize AST to JSON
	var out []byte
	if *pretty {
		out, err = json.MarshalIndent(ast, "", "  ")
	} else {
		out, err = json.Marshal(ast)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error serializing AST to JSON: %v\n", err)
		os.Exit(1)
	}

	// Emit result to stdout for downstream Python ingestion
	fmt.Println(string(out))
}
