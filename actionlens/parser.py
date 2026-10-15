"""Bridge to invoke the Go parser and deserialize normalized AST JSON."""

import json
import os
import subprocess
from pathlib import Path
from typing import Union

from actionlens.models import WorkflowAST

PARSER_BIN_NAME = "actionlens-parser"


def find_parser_binary() -> Path:
    """Locate the Go parser binary in project directories or system PATH."""
    project_root = Path(__file__).resolve().parent.parent
    candidate_paths = [
        project_root / "parser" / PARSER_BIN_NAME,
        project_root / PARSER_BIN_NAME,
    ]

    for p in candidate_paths:
        if p.is_file() and os.access(p, os.X_OK):
            return p

    # Fallback to system PATH
    import shutil
    system_bin = shutil.which(PARSER_BIN_NAME)
    if system_bin:
        return Path(system_bin)

    raise FileNotFoundError(
        f"Go parser binary '{PARSER_BIN_NAME}' not found. "
        f"Please run 'go build -o {PARSER_BIN_NAME} .' inside the 'parser/' directory."
    )


def parse_workflow_file(workflow_path: Union[str, Path]) -> WorkflowAST:
    """Execute the Go parser on a workflow YAML file and return a WorkflowAST model."""
    path = Path(workflow_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Workflow file not found: {path}")

    parser_bin = find_parser_binary()
    result = subprocess.run(
        [str(parser_bin), str(path)],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(f"Parser failed with code {result.returncode}:\n{result.stderr}")

    raw_json = json.loads(result.stdout)
    # Ensure file_path is populated if omitted by parser
    if not raw_json.get("file_path"):
        raw_json["file_path"] = str(workflow_path)

    return WorkflowAST.model_validate(raw_json)


def load_ast_json(json_path_or_str: Union[str, Path]) -> WorkflowAST:
    """Load a WorkflowAST directly from a normalized JSON file or string."""
    if isinstance(json_path_or_str, Path) or (isinstance(json_path_or_str, str) and os.path.isfile(json_path_or_str)):
        with open(json_path_or_str, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    else:
        raw_data = json.loads(json_path_or_str)

    return WorkflowAST.model_validate(raw_data)
