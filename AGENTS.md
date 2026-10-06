# AGENTS.md — Contributor & Autonomous Agent Guide

This document provides essential instructions, context, and development guidelines for AI agents and human contributors working on the **ActionLens** codebase.

---

## 1. Project Mission & Identity

- **What ActionLens Is:** A specialized static analyzer (SAST) and dynamic exploit verifier (DAST) for GitHub Actions CI/CD workflows.
- **Goal:** Detect high-risk security anti-patterns and unsafe dataflows (such as script injections, token over-scoping, and supply chain vulnerabilities) with high precision and low false positives, plus optional sandbox exploit verification.
- **Stage:** Research-driven Proof of Concept (PoC). Focus on clean modularity, precision on key vulnerabilities, and room to add/remove detection rules based on ongoing research.

---

## 2. Core Architectural Principles

When implementing features or rules, follow these architectural boundaries:

1. **Strict Separation of Concerns:**
   - **Parser Frontend (`parser/` - Go):** Standalone Go binary using `actionlint` that reads workflow YAML and expressions, emitting a normalized AST JSON.
   - **Security Linting (`actionlens/sast/rules/lint/` - Python):** Fast, AST-only pattern and structural checks (e.g., checking if a `uses:` line has a commit SHA or a mutable tag, or checking whether top-level permissions are specified). Must NOT require complex data-flow tracking.
   - **Code Analysis / Taint Engine (`actionlens/sast/taint.py`, `actionlens/sast/rules/codeanalysis/` - Python):** Multi-step semantic analysis using `networkx`. Tracks how untrusted input (sources like `github.event.issue.body`) flows through variables/environments (propagators) to execution contexts (sinks like bash `run:` scripts).
   - **DAST / Dynamic Layer (`actionlens/dast/` - Python):** Operates *after* SAST. Given an identified candidate vulnerability, uses the GitHub API (`PyGithub` / `httpx`) to trigger an orchestrated run with a safe canary payload in a test harness and inspects run logs to verify true exploitability.

2. **Extensibility & Research-Friendly:**
   - Detectors must inherit from the common `Rule` base class in `actionlens.models`.
   - Every rule must have a unique identifier (e.g., `AL-LINT-001`, `AL-CODE-001`), severity, description, remediation guidance, and CWE mapping.
   - Rules must be easily enabled, disabled, or tested in isolation.

3. **Deterministic & Safe Testing:**
   - Never run DAST verification against production, external, or unauthorized repositories.
   - SAST unit and integration tests must run offline via `pytest` using YAML fixtures in [`testdata/`](file:///Users/chinz/projects/KTH/actionlens/testdata/).

---

## 3. Technology Stack & Dependencies

- **Frontend Parser (Go):** [`github.com/rhysd/actionlint`](https://pkg.go.dev/github.com/rhysd/actionlint) for typed GitHub Actions AST parsing.
- **Core Engine (Python 3.10+):**
  - **Graph & Dataflow:** [`networkx`](https://networkx.org/) for directed taint flow graph representation and reachability path analysis.
  - **Data Modeling:** [`pydantic`](https://docs.pydantic.dev/) for AST schemas and finding models.
  - **Reporting:** SARIF (Static Analysis Results Interchange Format) v2.1.0 and human-readable terminal output via [`rich`](https://rich.readthedocs.io/).
  - **DAST Client:** [`PyGithub`](https://pygithub.readthedocs.io/) and [`httpx`](https://www.python-httpx.org/).
  - **Test Framework:** [`pytest`](https://docs.pytest.org/).

---

## 4. Rule Taxonomy & Conventions

Each rule should belong to one of two categories:

### A. SAST: Security Linting (`AL-LINT-XXX`)
Checks the structure, configuration, and syntax of workflow files without tracking variable flow:
- `AL-LINT-001`: Unpinned Third-Party Action (e.g. `uses: actions/checkout@v3` instead of commit SHA).
- `AL-LINT-002`: Missing Default Permissions Block (top-level workflow permissions omitted).
- `AL-LINT-003`: Dangerous Runner Selection (e.g. untrusted self-hosted runners on public repos).

### B. SAST: Code & Taint Analysis (`AL-CODE-XXX`)
Tracks sources, propagators, and sinks across workflow jobs and steps:
- `AL-CODE-001`: Expression / Script Injection (untrusted GitHub context directly interpolated into `run:` scripts).
- `AL-CODE-002`: Excessive Token Permissions (jobs executing risky operations with broad default write permissions).
- `AL-CODE-003`: Untrusted Checkout via `pull_request_target` (checking out head branch of a PR in privileged context).

---

## 5. Development Workflow for New Rules

When creating a new detection rule:
1. **Document First:** Add or update the rule entry in [`docs/vulnerability-matrix.md`](file:///Users/chinz/projects/KTH/actionlens/docs/vulnerability-matrix.md) with threat model, sources, and sinks.
2. **Add Test Fixtures:**
   - Create a minimal vulnerable sample in `testdata/vulnerable/<rule-id>.yml`.
   - Create a remediated / benign counterpart in `testdata/secure/<rule-id>.yml`.
3. **Implement Rule:**
   - For lint rules: implement under `actionlens/sast/rules/lint/`.
   - For dataflow rules: implement under `actionlens/sast/rules/codeanalysis/` using the taint engine in `actionlens/sast/taint.py`.
4. **Write Tests:** Add Python `pytest` tests verifying both positive and negative cases.

---

## 6. Guidelines for AI Agents

- **Model & AST Schemas:** When writing Python rules, inspect `actionlens.models.WorkflowAST` schemas. When working in `parser/`, verify Go types against `actionlint` AST types (`*actionlint.Workflow`, `*actionlint.Job`, `*actionlint.Step`, `*actionlint.ExecRun`).
- **Maintain Test Suite Quality:** Ensure `pytest tests/` passes after adding or editing rule or engine code. If modifying the Go parser frontend, ensure `go test ./...` passes inside `parser/`.
- **Keep Documentation Updated:** Whenever adding new detectors or modifying graph algorithms, update [`docs/architecture.md`](file:///Users/chinz/projects/KTH/actionlens/docs/architecture.md) and [`docs/vulnerability-matrix.md`](file:///Users/chinz/projects/KTH/actionlens/docs/vulnerability-matrix.md).
- **Safe Canary Payloads Only:** In any DAST or verification code, never generate malicious, exfiltrating, or destructive payloads. Use innocuous verification markers (e.g. unique UUID or hash echoed into runner logs).
