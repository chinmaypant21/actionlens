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

## 4. Normalized AST JSON Contract

The Go parser emits a structured JSON object containing all contextual information needed by Python:

```json
{
  "workflow_name": "CI",
  "file_path": ".github/workflows/ci.yml",
  "triggers": ["issue_comment", "pull_request"],
  "permissions": {
    "contents": "read",
    "issues": "write"
  },
  "jobs": [
    {
      "id": "triage",
      "runs_on": ["ubuntu-latest"],
      "permissions": null,
      "steps": [
        {
          "id": "run_script",
          "name": "Process Comment",
          "uses": "",
          "run": "echo \"${{ github.event.comment.body }}\"",
          "env": {},
          "line_number": 16,
          "expressions": [
            {
              "raw": "${{ github.event.comment.body }}",
              "context_path": "github.event.comment.body",
              "is_untrusted": true
            }
          ]
        }
      ]
    }
  ]
}
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

## 6. How to Implement a New Detection Rule in Python

All rules inherit from the base `Rule` class and register under `actionlens/sast/rules/`:

### Example: Security Lint Rule (`AL-LINT-001`)

```python
from actionlens.models import Rule, Finding, Severity, WorkflowAST

class UnpinnedActionRule(Rule):
    id = "AL-LINT-001"
    name = "Unpinned Third-Party Action"
    severity = Severity.MEDIUM
    description = "Third-party actions should be pinned to full 40-character commit SHAs."

    def check(self, ast: WorkflowAST) -> list[Finding]:
        findings = []
        for job in ast.jobs:
            for step in job.steps:
                if step.uses and not step.uses.startswith("./"):
                    # Check if reference is pinned to a 40-character SHA
                    ref = step.uses.split("@")[-1] if "@" in step.uses else ""
                    if len(ref) != 40 or not all(c in "0123456789abcdefABCDEF" for c in ref):
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                file_path=ast.file_path,
                                line_number=step.line_number,
                                message=f"Action '{step.uses}' is pinned to mutable tag/branch instead of full commit SHA.",
                                remediation="Pin the action to a full 40-character commit SHA with version comment."
                            )
                        )
        return findings
```

---

## 7. Local Setup & Testing

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
