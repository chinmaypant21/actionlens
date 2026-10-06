# Research: Taint Sources, Propagators, and Sinks in GitHub Actions

This research document inventories untrusted sources, propagation paths, and execution sinks in GitHub Actions workflows to inform the ActionLens static analysis engine.

---

## 1. Untrusted Sources

GitHub context objects populated by external contributors or untrusted triggers:

| Source Context Expression | Trigger Event | Attacker Control Level |
| :--- | :--- | :--- |
| `github.event.issue.title` | `issues`, `issue_comment` | Full text control |
| `github.event.issue.body` | `issues`, `issue_comment` | Full multiline markdown / text control |
| `github.event.comment.body` | `issue_comment`, `pull_request_review_comment` | Full multiline markdown / text control |
| `github.event.pull_request.title` | `pull_request`, `pull_request_target` | Full text control |
| `github.event.pull_request.body` | `pull_request`, `pull_request_target` | Full multiline markdown / text control |
| `github.event.pull_request.head.ref` | `pull_request`, `pull_request_target` | Attacker branch name (can contain shell metacharacters like `"; rm -rf ..."` on forks) |
| `github.head_ref` | `pull_request`, `pull_request_target` | Attacker branch name |
| `github.event.inputs.*` | `workflow_dispatch` | User input parameter (can be untrusted if triggered via public webhook) |

---

## 2. Propagators

Intermediate constructs that carry tainted data without directly executing it:

1. **Environment Variables (`env:` block):**
   ```yaml
   env:
     MY_VAR: ${{ github.event.issue.body }}
   ```
   *Note:* While assigning to `env:` is a propagator, referencing it as `$MY_VAR` in bash is the **recommended sanitizer** because bash does not interpret shell metacharacters inside quoted environment variables the way GitHub Actions pre-processes `${{ ... }}` into the script text before shell invocation.

2. **Step Outputs:**
   ```yaml
   id: extract
   run: echo "body=${{ github.event.issue.body }}" >> "$GITHUB_OUTPUT"
   ```
   Follow-up reference: `${{ steps.extract.outputs.body }}`.

3. **Job Outputs & Reusable Workflow Inputs:**
   Passing outputs from one job to the `needs.<job>.outputs` of downstream jobs.

---

## 3. Sinks (Execution Points)

Locations where tainted strings result in code execution or unauthorized privilege escalation:

| Sink Location | Execution Mechanism | Exploit Example |
| :--- | :--- | :--- |
| `steps[*].run` | Shell script (Bash, Sh, PowerShell, Python) | `${{ github.event.issue.title }}` injected into `run: echo "${{ ... }}"` |
| `actions/github-script` `script:` | Node.js JavaScript VM | Script injection into JS eval or template strings |
| `actions/checkout` `ref:` | Git ref checkout | Untrusted branch checkout under privileged token (`pull_request_target`) |
| `gh` CLI commands in `run:` | GitHub API client | Malicious flags injected into CLI arguments |

---

## 4. Sanitizers and Safe Coding Patterns

1. **Environment Variable Decoupling:**
   ```yaml
   # Vulnerable: Pre-processed string concatenation into bash script file
   run: echo "Hello ${{ github.event.issue.title }}"

   # Safe: Environment variable evaluated by shell at runtime
   env:
     TITLE: ${{ github.event.issue.title }}
   run: echo "Hello $TITLE"
   ```

2. **Format/Validation Step:**
   Explicit regex validation or hashing before use in command arguments.
