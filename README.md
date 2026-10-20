# ActionLens 👾

**ActionLens** is a static analysis tool (SAST) designed to audit GitHub Actions CI/CD workflows for security vulnerabilities, unsafe data flows, and configuration weaknesses.

---

## 📚 Documentation

| Document                                             | What you will find there                                                                                                                      |
| :--------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------- |
| [Architecture](docs/architecture.md)                 | System overview diagram, how the parser, orchestrator, lint rules, and taint analysis fit together, output formats, and DAST as future scope. |
| [Vulnerability Matrix](docs/vulnerability-matrix.md) | The six vulnerabilities ActionLens detects, with exploit scenarios and CWE and OWASP CI/CD mappings.                                          |
| [Development Guide](docs/development.md)             | Setup and usage (building the parser, running the scanner and tests), tech stack, an end-to-end example, and the repository layout.           |
| [Contributor Guide](AGENTS.md)                       | How to add or change a rule, project conventions, and known gaps.                                                                             |


### AI Use
Where AI tools helped in documentation/formatting, this is noted in a comment in the relevant file

<!-- Academic report content goes here. -->

---

## 📜 License

[MIT](LICENSE)
