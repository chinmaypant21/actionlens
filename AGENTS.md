# AGENTS.md — Contributor & Agent Guide

Instructions and context for AI agents and human contributors working on **ActionLens**. This file describes the code **as it currently is**. Where the other docs describe planned features, this file says so.

---

## 1. What ActionLens Is

- A static analyzer (SAST) for GitHub Actions workflow files. It detects supply-chain, permission, runner, and injection risks.
- A research Proof of Concept. Priorities are clean modularity, few false positives on the rules that exist, and making it easy to add, remove, or change rules as the research evolves.
- **Implemented:** the Go parser, 4 lint rules, 2 taint-analysis rules, the CLI, and a terminal and JSON report.
- **Not implemented (future scope):** DAST exploit verification, SARIF output, and a shared taint engine module. Do not assume these exist, and do not import them.

---

## 2. Pipeline

```
workflow.yml ──► parser/actionlens-parser (Go) ──► AST JSON on stdout
             ──► actionlens/parser.py           ──► WorkflowAST (pydantic)
             ──► SASTOrchestrator               ──► runs every registered Rule.check(ast)
             ──► reporting/formatter.py         ──► rich table (cli) or JSON
```

| Path | Role |
| :--- | :--- |
| `parser/` | Go CLI wrapping [`rhysd/actionlint`](https://pkg.go.dev/github.com/rhysd/actionlint). `parser.go` converts actionlint's AST into the normalized schema. `expression.go` extracts `${{ }}` contexts and parses `uses:` refs. `models.go` holds the JSON schema. `main.go` takes a file path, `-file`, or stdin. |
| `actionlens/parser.py` | Locates the binary (`parser/actionlens-parser`, then the repo root, then `PATH`), runs it, and validates the output into `WorkflowAST`. `load_ast_json()` loads a pre-generated AST JSON instead. |
| `actionlens/models.py` | Pydantic AST models (`WorkflowAST`, `JobAST`, `StepAST`, …), plus `Finding`, `RuleMetadata`, `Severity`, `RuleCategory`, and the abstract `Rule` base class. |
| `actionlens/sast/rules/catalog.py` | **Single source of truth for rule metadata** (`RULE_CATALOG`). |
| `actionlens/sast/rules/lint/` | AST-only structural rules (`AL-LINT-*`). |
| `actionlens/sast/rules/taint_analysis/` | Data-flow rules (`AL-CODE-*`), the `TaintGraph` (`networkx.DiGraph` subclass), and an optional pyvis visualizer. |
| `actionlens/sast/orchestrator.py` | `SASTOrchestrator`. It holds the list of active rules, accepts YAML, AST JSON, or a `WorkflowAST`, and sorts findings by `(file_path, line)`. |
| `actionlens/reporting/formatter.py` | `format_cli_table` (rich table) and `format_findings_json`. |
| `actionlens/cli.py` | `actionlens <file> [--format cli\|json]`. Exits with `1` if any finding is HIGH or CRITICAL, otherwise `0`. |
| `actionlens/utils/` | Helpers (currently `levenshtein_distance`). |
| `docs/` | `architecture.md`, `vulnerability-matrix.md`, `development.md`, and per-rule specs in `docs/rules/`. |
| `research/` | Research notes (e.g. `sources_and_sinks.md`). This is input for the rule design, not the specification of the code. |

---

## 3. Rule Catalog (current)

| ID | Class | File | Default severity | Detects |
| :--- | :--- | :--- | :--- | :--- |
| `AL-LINT-001` | `UnpinnedActionRule` | `lint/unpinned_action.py` | MEDIUM | `uses:` not pinned to a 40-char SHA. Skips local `./` actions. |
| `AL-LINT-002` | `UntrustedNamespaceRule` | `lint/untrusted_namespace.py` | HIGH | Typo-squatted owners (Levenshtein ≤ 2 from a trusted namespace), and popular official repo names under a foreign owner. Optional `flag_all_untrusted` (MEDIUM). Takes a configurable `trusted_namespaces` (default `actions`, `github`). |
| `AL-LINT-003` | `PermissionsBlockRule` | `lint/permissions_block.py` | LOW | Missing top-level `permissions:` (LOW). `write-all` at the top level or in a job, including per-scope values (MEDIUM). |
| `AL-LINT-004` | `SelfHostedRunnerRule` | `lint/self_hosted_runner.py` | HIGH | `self-hosted` runner label. HIGH with untrusted triggers, MEDIUM otherwise. |
| `AL-CODE-001` | `ScriptInjectionRule` | `taint_analysis/script_injection.py` | HIGH | An untrusted context reaches a sink (`run`, `with.script`, `with.args`, `with.ref`, …) without a sanitizer. This includes flows through `env.*` and `$GITHUB_OUTPUT` step outputs. |
| `AL-CODE-002` | `UntrustedCheckoutRule` | `taint_analysis/untrusted_checkout.py` | HIGH | `actions/checkout` with `with.ref` set to a PR head ref or SHA under `pull_request_target`, followed by a later step in the same job that runs a sink. |

All findings carry `rule_id`, `severity`, `file_path`, `line`, `message`, `remediation`, `cwe`, and `owasp_cicd` (an OWASP Top 10 CI/CD Security Risks category). Rules may override the default severity on individual findings.

> Rule IDs are permanent. Never renumber or reuse an ID. Add the next free number in the matching prefix.

---

## 4. Taint Analysis: How It Actually Works

There is no shared `taint.py`. Each `AL-CODE-*` rule has its own `build_taint_graph(ast)` and path finder, both built on `TaintGraph` from `taint_graph.py`.

- **Node types** (`NodeType`): `SOURCE`, `PROPAGATOR`, `SANITIZER`, `SINK`. `TaintGraph.get_node` deduplicates nodes by `(type, value)`.
- **Edge direction is sink → source.** Path search runs `nx.all_simple_paths(graph, sink, source)`.
- **Sources:** the hard-coded `UNTRUSTED_CONTEXTS` set in `script_injection.py`, matched by regex (longest match first, case-insensitive). AL-CODE-002 has its own smaller `UNTRUSTED_CHECKOUT_CONTEXTS`.
- **Sinks:** the `SINKS` set. A sink is identified by the expression's `location` string emitted by the Go parser (`run`, `with.<input>`, `env.<NAME>`, `if`).
- **Sanitizer rule (AL-CODE-001):** a path is ignored when the node right after the sink is a `SANITIZER`, for example an untrusted value bound to `env:` and read as `$VAR` in the script.
- **Line numbers** are the **step's** start line (`step.pos.line`), not the line of the expression inside `run:`. Tests assert this.
- **Visualization:** pass `visualize_path="out.html"` to a taint rule to write a pyvis graph. Test files have a `CREATE_TAINT_GRAPH` toggle for this. Do not commit the generated HTML.

**Known gaps** (worth knowing before you "fix" a test or add a rule):
- Workflow-level and job-level `env:`, job `outputs:`, `needs.*`, reusable workflows, and matrix/strategy are parsed partially or not at all, and are not used in taint flows.
- `find_source` returns only the first untrusted context in an expression.
- `github.event.inputs.*` and wildcard sources are not modeled.

---

## 5. Parser ↔ Python Schema Contract

The JSON emitted by `parser/models.go` must match `actionlens/models.py`. When a rule needs a workflow property that is not in the AST yet:

1. Add the field to the Go structs in `parser/models.go` and populate it in `parser/parser.go`.
2. Add the matching field to the pydantic model. Use `Field(alias=...)` for reserved names, as in `if_`/`if` and `with_`/`with`.
3. Rebuild the binary. Python tests run against the built binary, not the Go source.
4. Add or adjust a Go test in `parser/parser_test.go`.

Expressions are extracted per step from `if`, `env.<KEY>`, `run`, and `with.<input>`. The `context` field is the dotted context path resolved through actionlint's expression parser. If parsing fails, it falls back to the raw expression text.

---

## 6. Adding or Changing a Rule

1. **Document it.** Add a row to `docs/vulnerability-matrix.md`. For non-trivial rules, also add a spec in `docs/rules/<rule_name>.md`.
2. **Register the metadata** in `_CATALOG` in `actionlens/sast/rules/catalog.py`: `name`, `severity`, `category`, `description`, `cwe`, `owasp_cicd`, `remediation`. Missing or misspelled fields fail at import time.
3. **Implement the rule:**
   - Lint: `actionlens/sast/rules/lint/<rule_name>.py`, also exported from `lint/__init__.py`.
   - Data-flow: `actionlens/sast/rules/taint_analysis/<rule_name>.py`, reusing `TaintGraph` and `NodeType`.
   - Subclass `Rule`, set `metadata = RULE_CATALOG["AL-XXX-NNN"]`, implement `check(self, ast) -> list[Finding]`, and read metadata through the base-class properties (`self.rule_id`, `self.cwe`, …). Do not hard-code metadata in the class.
   - For line numbers, fall back from the element's `pos` to the job's `pos` to `1`, as the existing rules do.
4. **Activate it** by adding an instance to `self.rules` in `SASTOrchestrator.__init__`. There is no automatic discovery.
5. **Add fixtures:**
   - `testdata/vulnerable/<rule_name>.yml` and `testdata/secure/<rule_name>.yml`.
   - Name files by topic (e.g. `unpinned_action.yml`), not by rule ID.
   - Group several fixtures for one rule in a subfolder (e.g. `script_injections/`).
   - `testdata/others/` holds larger exploratory workflows that no test uses.
   - Pin actions in fixtures to SHAs unless the fixture is meant to trigger AL-LINT-001.
6. **Write tests** in `tests/test_<rule_name>.py` covering the vulnerable case (count, `rule_id`, severity, line, message content) and the secure case (`findings == []`). An orchestrator end-to-end check is a welcome addition.
7. **Update the docs.** Update `docs/architecture.md` if the rule changes the pipeline or the rule list. Keep `README.md` as a short entry point: only touch it if a document is added, renamed, or removed from its documentation index.

---

## 7. Setup, Build & Test

Requirements: Go (version per `parser/go.mod`, currently `go 1.27.1`) and Python ≥ 3.10.

```bash
# Go parser: must be built before any Python test or scan
cd parser && go test ./... && go build -o actionlens-parser . && cd ..

# Python
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e .

pytest tests/                                    # all Python tests (need the built binary)
actionlens testdata/vulnerable/unpinned_action.yml            # table output
actionlens testdata/vulnerable/unpinned_action.yml -f json    # JSON output
python -m actionlens <file>                                   # same, without installing
```

- The binary `parser/actionlens-parser` is git-ignored. Rebuild it after any change in `parser/`, or the Python tests will run against stale output.
- Runtime dependencies: `pydantic`, `networkx`, `rich`, `pyvis`. Dev dependency: `pytest`. Keep `pyproject.toml` and `requirements.txt` in sync.
- There is no CI yet. Run both test suites locally before declaring work done.

---

## 8. Rules for Agents

- **Verify against the code, not the docs.** The docs were brought in line with the code, but they can drift again. DAST and SARIF are future scope and the docs mark them that way. If your change makes a doc statement true or more wrong, update the doc.
- **Keep lint rules AST-only.** Anything that needs to follow values across env vars, outputs, or steps belongs in `taint_analysis/`.
- **Prefer precision over recall.** A new heuristic that adds false positives on `testdata/secure/` is a regression.
- **Keep tests offline and deterministic.** No network calls, and no GitHub API calls in tests.
- **Leave existing provenance comments alone.** Some files note which AI tool helped write them (e.g. `# Generated by …`). Do not remove them.
- **DAST (when it is built):**
  - Only run it against isolated sandbox repositories you are authorized to use. Never run it against production or third-party repos.
  - Use only innocuous canary payloads, such as a unique UUID echoed to the runner log. Never use exfiltrating or destructive payloads.
