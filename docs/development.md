# ActionLens Development & Contribution Guide

This guide details the architectural philosophy, technology stack, project structure, and workflow for contributing to **ActionLens**.

---

## 1. Architectural Approach: Go Workflow Parser $\to$ Python Engine

ActionLens uses a **hybrid "Parser $\to$ Analysis Engine" architecture**:

```text
┌────────────────────────────────┐
│  GitHub Actions Workflow YAML  │
└───────────────┬────────────────┘
                │
                ▼
┌────────────────────────────────┐
│      Go Parser                 │  <-- Single-purpose binary
│      (rhysd/actionlint)        │  <-- Parses YAML & ${{ ... }} expression trees
└───────────────┬────────────────┘
                │  Normalized AST JSON
                ▼
┌────────────────────────────────┐
│  Python Engine & Core ("Brain")│
│  ├── SAST Orchestrator         │  <-- Runs every registered rule, sorts findings
│  ├── Security Linter           │  <-- AST configuration & hygiene rules
│  ├── Taint Analysis (networkx) │  <-- Graph dataflow & injection path tracking
│  └── Reporting & CLI           │  <-- JSON and rich terminal output
└────────────────────────────────┘
```

Dynamic verification (DAST) was part of the original plan but has been moved to future scope, so it is not part of this pipeline.

---

## 2. Why We Chose This Approach

This design is a practical compromise based on existing open-source tooling and team workflow:

### 1. Go for AST & Expression Parsing
* **Why Go here:** Python has no dedicated parser library for GitHub Actions syntax and `${{ ... }}` expression grammar. In contrast, [`github.com/rhysd/actionlint`](https://pkg.go.dev/github.com/rhysd/actionlint) in Go provides a well-tested parser that handles both workflow schema validation and expression AST construction.
* **Scope of Go:** Kept minimal. A small Go CLI (`actionlens-parser`) parses workflow files and emits a normalized JSON AST. Once this schema is defined, Go code rarely needs changes.

### 2. Python for the Analysis Engine
* **Team familiarity:** The team is more comfortable researching and writing code in Python.
* **Graph modeling:** [`networkx`](https://networkx.org/) offers straightforward directed graph data structures and path algorithms for taint tracking (finding paths from untrusted sources to execution sinks).
* **Rule authoring:** Rules can be added, tested, and modified in Python without recompiling binaries.
* **Room for future DAST work:** DAST is not part of the current project. If it is built later, triggering workflows through the GitHub API and searching runner logs for canary tokens would be straightforward to script in Python (e.g. with `PyGithub` / `httpx`).

### 3. Trade-offs of This Approach
* **Two runtime environments:** Contributors need both Go (to build the parser) and Python (to run the scanner and tests).
* **Schema synchronization:** Any workflow property needed by a Python rule must be explicitly included in the Go parser's JSON output schema.

---

## 3. Technology Stack & Core Libraries

### A. Parser (Go)
| Library / Tool                                                                  | Purpose                                                                                  |
| :------------------------------------------------------------------------------ | :--------------------------------------------------------------------------------------- |
| **Go** (version per `parser/go.mod`, currently 1.27.1)                          | Compiles the standalone parser binary (`actionlens-parser`).                             |
| [`github.com/rhysd/actionlint`](https://pkg.go.dev/github.com/rhysd/actionlint) | Complete parsing of GitHub Actions workflows, jobs, steps, and `${{ }}` expression ASTs. |
| `encoding/json`                                                                 | Standard library serialization to emit normalized AST JSON.                              |

### B. Core Engine & Rules (Python 3.10+)
| Library / Tool | Purpose |
| :--- | :--- |
| [`networkx`](https://networkx.org/) | Directed graphs for taint analysis (Source $\to$ Propagator $\to$ Sink reachability). |
| [`pydantic`](https://docs.pydantic.dev/) | Strongly-typed data models for normalized AST schemas, findings, and rule metadata. |
| [`argparse`](https://docs.python.org/3/library/argparse.html) (standard library) | CLI entry point: `actionlens <file> [--format cli\|json]`. |
| [`rich`](https://rich.readthedocs.io/) | Colorized, human-readable terminal output and finding summaries. |
| [`pyvis`](https://pyvis.readthedocs.io/) | Optional interactive HTML visualization of taint graphs (`visualize_path=` on a taint rule). |
| [`pytest`](https://docs.pytest.org/) | Offline unit and integration test runner for rule fixtures. |

No GitHub API client is used. Dynamic verification (DAST), which would need one, is future scope.

---

## 4. End-to-End Walkthrough (Example)

Here is a concrete walkthrough showing how a small workflow with two deliberate vulnerabilities is parsed, analyzed, and reported. The workflow also has no `permissions:` block, so `AL-LINT-003` reports it as well.

### Step 1: Input Workflow (`.github/workflows/ci.yml`)

```yaml
name: Example Workflow
on: [issue_comment]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      # Vuln 1: AL-LINT-001 (Unpinned third-party action)
      - name: Checkout Code
        uses: actions/checkout@v4

      # Vuln 2: AL-CODE-001 (Script / Expression injection)
      - name: Echo Comment
        run: echo "${{ github.event.comment.body }}"
```

---

### Step 2: Go Parser Output (`actionlens-parser` JSON)

The Go parser reads the YAML, parses the `${{ }}` expression AST using `actionlint`, and emits normalized JSON:

```json
{
  "file_path": ".github/workflows/ci.yml",
  "name": "Example Workflow",
  "triggers": [
    {
      "event": "issue_comment"
    }
  ],
  "jobs": [
    {
      "id": "process",
      "runs_on": {
        "labels": [
          "ubuntu-latest"
        ],
        "pos": {..}
      },
      "steps": [
        {
          "name": "Checkout Code",
          "exec_type": "action",
          "uses": {
            "raw": "actions/checkout@v4",
            "owner": "actions",
            "repo": "checkout",
            "ref": "v4",
            "is_sha": false
          },
          "pos": {..}
        },
        {
          "name": "Echo Comment",
          "exec_type": "run",
          "run": "echo \"${{ github.event.comment.body }}\"",
          "expressions": [
            {
              "context": "github.event.comment.body",
              "location": "run"
            }
          ],
		  "pos": {..}
        }
      ],
	  "pos": {..}
    }
  ],
  "pos": {..}
}
```

---

### Step 3: Python Analyzer Step

Python validates the JSON into a `WorkflowAST`, and the `SASTOrchestrator` runs every registered rule on it:

1. **Lint Check (`AL-LINT-003`):** Inspects the top-level `permissions`. Detects that the block is missing.
2. **Lint Check (`AL-LINT-001`):** Inspects `step.uses`. Detects that `@v4` is not a 40-character commit SHA.
3. **Taint Check (`AL-CODE-001`):** Builds a taint graph from the step's `run` script and expressions, and finds a path from the `run` sink to the untrusted source `github.event.comment.body` with no sanitizer on it. The value is interpolated directly into the script rather than passed through `env:`.

The other rules find nothing: `actions` is a trusted namespace, the job uses a GitHub-hosted runner, and the trigger is not `pull_request_target`. Findings are sorted by line.

---

### Step 4: Final Output (Findings)

Output of `actionlens .github/workflows/ci.yml --format json`. Line numbers point to the start of the step (or line 1 for workflow-level findings).

```json
[
  {
    "rule_id": "AL-LINT-003",
    "severity": "LOW",
    "file_path": ".github/workflows/ci.yml",
    "line": 1,
    "message": "Workflow is missing a top-level 'permissions:' block. The GITHUB_TOKEN will default to broad repository permissions.",
    "remediation": "Specify a restrictive top-level 'permissions: {}' block and grant only minimal scoped permissions to individual jobs as needed.",
    "cwe": "CWE-250",
    "owasp_cicd": "CICD-SEC-5: Insufficient Pipeline-Based Access Controls (PBAC)"
  },
  {
    "rule_id": "AL-LINT-001",
    "severity": "MEDIUM",
    "file_path": ".github/workflows/ci.yml",
    "line": 9,
    "message": "Action 'actions/checkout@v4' is unpinned (uses mutable tag or branch '@v4' instead of commit SHA).",
    "remediation": "Pin the action to a full 40-character commit SHA.",
    "cwe": "CWE-494",
    "owasp_cicd": "CICD-SEC-3: Dependency Chain Abuse"
  },
  {
    "rule_id": "AL-CODE-001",
    "severity": "HIGH",
    "file_path": ".github/workflows/ci.yml",
    "line": 13,
    "message": "Untrusted user input 'github.event.comment.body' is being passed to a script execution context.",
    "remediation": "Validate and sanitize all user input before executing scripts. Use intermediate environment variables to avoid direct shell execution.",
    "cwe": "CWE-94",
    "owasp_cicd": "CICD-SEC-4: Poisoned Pipeline Execution (PPE)"
  }
]
```

Because there is a HIGH finding, the CLI exits with code `1`.

---

## 5. Repository Layout

```text
actionlens/
├── README.md                  # Project overview and architecture diagram
├── AGENTS.md                  # Contributor & agent guide
├── docs/                      # Architectural specifications and documentation
│   ├── architecture.md        # Technical architecture
│   ├── vulnerability-matrix.md# Catalog of targeted vulnerabilities
│   ├── development.md         # This development guide
│   └── rules/                 # Per-rule specifications
├── research/                  # Research notes (e.g. taint sources and sinks)
├── parser/                    # Go Workflow Parser
│   ├── main.go                # CLI entry point; reads YAML (file or stdin), emits JSON
│   ├── models.go              # Normalized AST structs (WorkflowAST, StepAST, etc.)
│   ├── parser.go              # actionlint AST converter with deterministic ordering
│   ├── expression.go          # Expression context extraction & action reference parser
│   ├── parser_test.go         # Test suite running against testdata/
│   ├── go.mod
│   └── go.sum
├── actionlens/                # Python Core Engine ("Brain")
│   ├── __init__.py
│   ├── __main__.py            # Enables `python -m actionlens`
│   ├── cli.py                 # CLI entry point (scan a workflow, cli or json output)
│   ├── parser.py              # Invokes parser binary and loads AST JSON
│   ├── models.py              # Pydantic schemas (AST, Rule, Finding, RuleMetadata)
│   ├── sast/
│   │   ├── orchestrator.py    # SASTOrchestrator: runs all registered rules
│   │   └── rules/
│   │       ├── catalog.py     # Rule metadata (single source of truth)
│   │       ├── lint/          # AL-LINT-* rules (AST-only checks)
│   │       └── taint_analysis/# AL-CODE-* rules, TaintGraph, and pyvis visualizer
│   ├── reporting/
│   │   └── formatter.py       # Rich CLI table and JSON formatters
│   └── utils/                 # Helpers (Levenshtein distance)
├── testdata/                  # Test workflows
│   ├── vulnerable/            # Vulnerable workflow samples for regression tests
│   ├── secure/                # Remediated & safe workflow samples
│   └── others/                # Larger exploratory workflows (not used by tests)
├── tests/                     # Pytest test suite
├── pyproject.toml             # Python packaging & dependencies
└── requirements.txt
```

---

## 6. Local Setup & Testing

### 1. Build and Test the Go Parser
```bash
cd parser
go test -v ./...
go build -o actionlens-parser .
cd ..
```

### 2. Set Up Python Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```