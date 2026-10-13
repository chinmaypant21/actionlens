sequenceDiagram
    autonumber
    actor User
    participant Main as actionlens/__main__.py
    participant CLI as actionlens/cli.py
    participant Orch as sast/orchestrator.py
    participant Bridge as actionlens/parser.py
    participant Go as parser/actionlens-parser (Go binary)
    participant Rules as sast/rules/lint/...
    participant Rep as reporting/formatter.py

    User->>Main: Run CLI command
    Main->>CLI: main()
    CLI->>Orch: SASTOrchestrator()
    CLI->>Orch: scan_workflow(file_path)
    
    rect rgb(235, 245, 255)
    Note over Orch,Go: Stage 1: AST Parsing
    Orch->>Bridge: parse_workflow_file(path)
    Bridge->>Go: subprocess.run([actionlens-parser, path])
    Go-->>Bridge: Normalized AST JSON (stdout)
    Bridge-->>Orch: WorkflowAST (Pydantic model)
    end

    rect rgb(255, 245, 235)
    Note over Orch,Rules: Stage 2: Security Checks
    loop For each registered rule
        Orch->>Rules: rule.check(ast)
        Rules-->>Orch: list[Finding]
    end
    Note over Orch: Aggregate & sort findings by line number
    end

    rect rgb(240, 255, 240)
    Note over Orch,Rep: Stage 3: Reporting & Exit
    CLI->>Rep: format_findings_json(findings) or format_cli_table()
    Rep-->>CLI: Formatted output string
    end

    CLI->>User: Print report to stdout & exit (0 if clean, 1 if HIGH/CRITICAL)
