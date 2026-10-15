# ActionLens 👾

**ActionLens** is a static and dynamic analysis tool (SAST + DAST) designed to audit GitHub Actions CI/CD workflows for security vulnerabilities, unsafe data flows, and configuration weaknesses.

---

## Objectives & Scope

Modern CI/CD pipelines hold privileged access to source code, cloud credentials, production environments, and release artifacts. ActionLens targets security risks in workflow definitions across two coordinated layers:

### 1. Static Analysis (SAST)
- **Semantic Code & Taint Analysis:**
  - Evaluates untrusted data flows from external triggers (e.g., `pull_request_target`, `issue_comment`, `workflow_run`) to dangerous execution sinks (e.g., inline shell scripts via `${{ github.event... }}`).
  - Analyzes privilege over-scoping (default permissions vs. explicit least-privilege tokens).
- **Security Linting:**
  - AST-based pattern matching for supply-chain risks (e.g., unpinned third-party actions using mutable tags like `@v1` or `@main` instead of immutable commit SHAs).
  - Dangerous configuration patterns (e.g., insecure checkouts, missing environment isolation).

### 2. Dynamic Verification (DAST / Exploit Harness - Research Layer)
- **API Orchestrator & Log Verifier:**
  - In controlled environments (test repositories / ephemeral runners), triggers and orchestrates targeted execution of flagged workflows.
  - Verifies whether an identified candidate vulnerability is genuinely exploitable by inspecting execution traces and runner logs.

---

## 🗿 Architecture Overview

```mermaid
flowchart TD
    %% Input
    Input["📄 GitHub Actions Workflow<br/><code>.github/workflows/*.yml</code>"] --> Parser["⚙️ Workflow Parser<br/><i>(Parses YAML structure & expressions)</i>"]

    %% Stage 1: SAST
    subgraph SAST["1. Static Analysis (SAST)"]
        direction TB
        Parser --> Lint["🔍 Security Linter<br/><b>Pattern & Config Checks</b><br/>• Unpinned 3rd-party actions<br/>• Missing default permissions"]
        Parser --> Dataflow["🌊 Dataflow & Taint Analysis<br/><b>Code & Injection Checks</b><br/>• Untrusted inputs <i>(issue body, PR title)</i><br/>• Unsafe execution in <code>run:</code> scripts<br/>• Excessive token permissions"]
    end

    %% Findings (Bridge between SAST and DAST)
    Lint --> Findings["📋 Potential Vulnerabilities Found"]
    Dataflow --> Findings

    Findings --> StaticReport["📊 Static Security Report"]

    %% Stage 2: DAST
    subgraph DAST["2. Dynamic Verification (DAST)"]
        direction TB
        Trigger["Test Orchestrator<br/>Triggers test workflow via GitHub API<br/>with a safe payload"]
        Trigger --> Logs["📜 Log & Trace Verifier<br/>Inspects workflow runner execution logs<br/>to confirm if canary executed"]
    end
	Findings -. "Future Scope" .-> Trigger
    Logs --> Verified["📝 Verified Exploit Report"]
```

For detailed specifications, see:
- [Architecture Guide](file:///Users/chinz/projects/KTH/actionlens/docs/architecture.md)
- [Vulnerability Matrix](file:///Users/chinz/projects/KTH/actionlens/docs/vulnerability-matrix.md)
- [Agent Guide (`AGENTS.md`)](file:///Users/chinz/projects/KTH/actionlens/AGENTS.md)
- [Development & Contribution Guide](file:///Users/chinz/projects/KTH/actionlens/docs/development.md)

---

## Usage

### 1. Prerequisites
- **Go 1.21+** (for building the AST parser)
- **Python 3.10+** (for the security analysis engine)

### 2. Build the Go Parser
The Python engine invokes a standalone Go binary to parse workflow YAML and expression ASTs:
```bash
cd parser
go build -o actionlens-parser .
cd ..
```

**Note:** go parser can also be used independently for generating AST: 
```bash
./parser/actionlens-parser <filename>
```

### 3. Set Up Python Environment
Create and activate a virtual environment, then install dependencies and the package:
```bash
python3.10 -m venv .venv # or python -m ... if using Python 3.10 or newer
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 4. Run the Security Scanner
With the virtual environment activated:

```bash
# Scan a workflow file with human-readable table output
actionlens testdata/vulnerable/excessive_permissions.yml

# Or run via Python module syntax
python3 -m actionlens testdata/vulnerable/excessive_permissions.yml

# JSON Format
actionlens testdata/vulnerable/excessive_permissions.yml --format json
```

### 5. Run the Test Suite
```bash
pytest -v tests/
```

---

## 📁 Repository Layout

```text
actionlens/
├── README.md                  # Project overview and roadmap
├── docs/                      # Architectural specifications & documentation
│   ├── architecture.md        # Technical architecture
│   ├── vulnerability-matrix.md# Catalog of targeted vulnerabilitie
│   ├── development.md         # Development guideline and LLD
│   └── rules/                 # Detection rule specifications
├── parser/                    # Go-based AST parser (actionlint wrapper)
│   ├── main.go                # Emits normalized AST JSON
│   ├── parser.go              # Workflow and expression parser
│   ├── models.go              # Normalized AST Go structs
│   ├── go.mod
│   └── go.sum
├── actionlens/                # Core Python package (SAST, Taint, CLI)
│   ├── cli.py                 # CLI entry point (scan and format)
│   ├── parser.py              # Invokes parser binary and loads AST JSON
│   ├── models.py              # Pydantic schemas (AST, Rules, Findings)
│   ├── sast/                  # SAST orchestrator, lint rules & taint engine
│   ├── utils/                 # Helper utilities
│   └── reporting/             # Console and JSON formatters
├── testdata/                  # Test workflows (benign & vulnerable samples)
│   ├── vulnerable/            # Vulnerable workflow samples for regression tests
│   └── secure/                # Remediated & safe workflow samples
├── tests/                     # Pytest test suite
├── pyproject.toml             # Python package configuration & CLI entrypoint
└── requirements.txt           # Python dependencies
```



**Note:** Detailed breakdown of vulnerabilities can be found in [`docs/vulnerability-matrix.md`](file:///Users/chinz/projects/KTH/actionlens/docs/vulnerability-matrix.md).

---

## 📜 License

[MIT](file:///Users/chinz/projects/KTH/actionlens/LICENSE)
