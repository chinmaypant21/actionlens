# ActionLens Development & Contribution Guide

This guide details the architectural philosophy, technology stack, project structure, and workflow for contributing to **ActionLens**.

---

## 1. Architectural Approach: Frontend Parser $\to$ Python Engine

ActionLens uses a **hybrid "Parser Frontend $\to$ Analysis Engine" architecture**:

```text
┌────────────────────────────────┐
│  GitHub Actions Workflow YAML  │
└───────────────┬────────────────┘
                │
                ▼
┌────────────────────────────────┐
│  Go Parser Frontend            │  <-- Single-purpose binary
│  (rhysd/actionlint)            │  <-- Parses YAML & ${{ ... }} expression trees
└───────────────┬────────────────┘
                │  Normalized AST JSON
                ▼
┌────────────────────────────────┐
│  Python Engine & Core ("Brain")│
│  ├── Security Linter           │  <-- AST configuration & hygiene rules
│  ├── Taint Engine (networkx)   │  <-- Graph dataflow & injection path tracking
│  ├── DAST Orchestrator         │  <-- GitHub API dispatch & canary verification
│  └── Reporting & CLI           │  <-- SARIF v2.1.0, JSON, and rich terminal output
└────────────────────────────────┘
```

---

## 2. Why We Chose This Approach

This design is a practical compromise based on existing open-source tooling and team workflow:

### 1. Go for AST & Expression Parsing
* **Why Go here:** Python has no dedicated parser library for GitHub Actions syntax and `${{ ... }}` expression grammar. In contrast, [`github.com/rhysd/actionlint`](https://pkg.go.dev/github.com/rhysd/actionlint) in Go provides a well-tested parser that handles both workflow schema validation and expression AST construction.
* **Scope of Go:** Kept minimal. A small Go CLI (`actionlens-parser`) parses workflow files and emits a normalized JSON AST. Once this schema is defined, Go code rarely needs changes.

### 2. Python for the Analysis Engine & DAST
* **Team familiarity:** The team is more comfortable researching and writing code in Python.
* **Graph modeling:** [`networkx`](https://networkx.org/) offers straightforward directed graph data structures and path algorithms for taint tracking (finding paths from untrusted sources to execution sinks).
* **Rule authoring:** Rules can be added, tested, and modified in Python without recompiling binaries.
* **DAST scripting:** Triggering GitHub API workflows and searching raw runner logs for canary tokens is straightforward to script in Python using `PyGithub` / `httpx` and regular expressions.

### 3. Trade-offs of This Approach
* **Two runtime environments:** Contributors need both Go (to build the parser) and Python (to run the scanner and tests).
* **Schema synchronization:** Any workflow property needed by a Python rule must be explicitly included in the Go parser's JSON output schema.

---

## 3. Technology Stack & Core Libraries

### A. Parser Frontend (Go)
| Library / Tool                                                                  | Purpose                                                                                  |
| :------------------------------------------------------------------------------ | :--------------------------------------------------------------------------------------- |
| **Go 1.21+**                                                                    | Compiles the standalone parser binary (`actionlens-parser`).                             |
| [`github.com/rhysd/actionlint`](https://pkg.go.dev/github.com/rhysd/actionlint) | Complete parsing of GitHub Actions workflows, jobs, steps, and `${{ }}` expression ASTs. |
| `encoding/json`                                                                 | Standard library serialization to emit normalized AST JSON.                              |

### B. Core Engine & Rules (Python 3.10+)
| Library / Tool | Purpose |
| :--- | :--- |
| [`networkx`](https://networkx.org/) | Directed graphs for taint analysis (Source $\to$ Propagator $\to$ Sink reachability). |
| [`pydantic`](https://docs.pydantic.dev/) | Strongly-typed data models for normalized AST schemas, findings, and rule metadata. |
| [`typer`](https://typer.tiangolo.com/) or [`click`](https://click.palletsprojects.com/) | CLI interface commands (`actionlens scan`, `actionlens verify`, `actionlens lint`). |
| [`rich`](https://rich.readthedocs.io/) | Colorized, human-readable terminal output and finding summaries. |
| [`PyGithub`](https://pygithub.readthedocs.io/) / [`httpx`](https://www.python-httpx.org/) | GitHub API client for triggering DAST test runs and querying runner execution logs. |
| [`pytest`](https://docs.pytest.org/) | Offline unit and integration test runner for rule fixtures. |

---

## 4. End-to-End Walkthrough (Example)

Here is a concrete walkthrough showing how the two in-scope MVP vulnerabilities are parsed, analyzed, and reported.

### Step 1: Input Workflow (`.github/workflows/ci.yml`)

```yaml
name: Ecample Workflow
on: issue_comment

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
  "workflow_name": "Triage Workflow",
  "triggers": ["issue_comment"],
  "jobs": [
    {
      "id": "process",
      "steps": [
        {
          "line": 9,
          "uses": "actions/checkout@v4",
          "run": null,
          "env": {},
          "expressions": []
        },
        {
          "line": 13,
          "uses": null,
          "run": "echo \"${{ github.event.comment.body }}\"",
          "env": {},
          "expressions": [
            {
              "raw": "${{ github.event.comment.body }}",
              "context": "github.event.comment.body"
            }
          ]
        }
      ]
    }
  ]
}
```

---

### Step 3: Python Analyzer Step

Python loads the JSON and runs registered rules:

1. **Lint Check (`AL-LINT-001`):** Inspects `step.uses`. Detects that `@v4` is not a 40-character commit SHA.
2. **Taint Check (`AL-CODE-001`):** Inspects `step.run` and finds untrusted source `github.event.comment.body`. Uses NetworkX to confirm the value was interpolated directly into the script rather than passed through `step.env`.

---

### Step 4: Final Output (Findings)

```json
[
  {
    "rule_id": "AL-LINT-001",
    "severity": "MEDIUM",
    "file_path": ".github/workflows/ci.yml",
    "line": 9,
    "message": "Action 'actions/checkout@v4' is unpinned (uses mutable tag instead of commit SHA).",
    "remediation": "Pin the action to a full 40-character commit SHA."
  },
  {
    "rule_id": "AL-CODE-001",
    "severity": "HIGH",
    "file_path": ".github/workflows/ci.yml",
    "line": 13,
    "message": "Untrusted expression 'github.event.comment.body' interpolated directly into shell script sink.",
    "remediation": "Pass the context value via an environment variable ('env:') and reference '$VAR' in the script."
  }
]
```

---

## 5. Repository Layout

```text
actionlens/
├── README.md                  # Project overview and architecture diagram
├── docs/                      # Architectural specifications and research documentation
│   ├── architecture.md        # Technical architecture (SAST & DAST layers)
│   ├── vulnerability-matrix.md# Catalog of targeted vulnerabilities & statuses
│   └── development.md         # This development guide
├── parser/                    # Go Parser Frontend
│   ├── main.go                # actionlint wrapper; outputs normalized AST JSON
│   ├── go.mod
│   └── go.sum
├── actionlens/                # Python Core Engine ("Brain")
│   ├── __init__.py
│   ├── cli.py                 # CLI entry point (scan, verify, lint)
│   ├── parser.py              # Invokes parser binary and loads AST JSON
│   ├── models.py              # Pydantic schemas (AST, Rule, Finding)
│   ├── sast/
│   │   ├── linter.py          # Structural & configuration checks
│   │   ├── taint.py           # NetworkX taint graph builder & path solver
│   │   └── rules/             # Rule implementations
│   │       ├── lint/          # AL-LINT-* rules
│   │       └── codeanalysis/  # AL-CODE-* rules
│   ├── dast/
│   │   ├── orchestrator.py    # GitHub API test trigger & canary dispatcher
│   │   └── verifier.py        # Log downloader & canary execution verifier
│   └── reporting/             # Formatters: Rich CLI tables, SARIF, and JSON
├── testdata/                  # Test workflows (benign & vulnerable samples)
│   ├── vulnerable/            # Vulnerable workflow samples for regression tests
│   └── secure/                # Remediated & safe workflow samples
├── tests/                     # Pytest test suite
├── pyproject.toml             # Python packaging & dependencies
└── requirements.txt
```

---

## 6. Local Setup & Testing

### 1. Build the Go Parser Frontend
```bash
cd parser
go build -o ../bin/actionlens-parser main.go
cd ..
```

### 2. Set Up Python Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 3. Run Tests
```bash
pytest -v tests/
```
Tests load YAML samples from [`testdata/`](file:///Users/chinz/projects/KTH/actionlens/testdata/) to verify positive detection on vulnerable files and zero false positives on secure files.
