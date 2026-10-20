"""Enable running actionlens via `python3 -m actionlens` or `python3 actionlens`."""

# Took help from Gemini 3.8 Flash for generating this

import sys
from pathlib import Path

# Ensure project root is in sys.path when executed as a directory (e.g. python3 actionlens ...)
project_root = str(Path(__file__).resolve().parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from actionlens.cli import main

if __name__ == "__main__":
    main()