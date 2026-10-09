"""Records the test-suite result (run at release time, not in CI).

Write to a temporary file, not straight to eval/results/tests.json (a half-written file there breaks the drift tests):

    python eval/record_tests.py > /tmp/tests.json && mv /tmp/tests.json eval/results/tests.json

pyproject.toml already adds -q, so this script must not.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
r = subprocess.run(
    [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "tests"], capture_output=True, text=True, cwd=ROOT
)
tail = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
passed = int(m.group(1)) if (m := re.search(r"(\d+) passed", tail)) else 0
failed = int(m.group(1)) if (m := re.search(r"(\d+) failed", tail)) else 0
json.dump(
    {
        "passed": passed,
        "failed": failed,
        "summary": tail,
        "python": platform.python_version(),
        "date": time.strftime("%Y-%m-%d"),
    },
    sys.stdout,
    indent=1,
)
print()
sys.exit(0 if r.returncode == 0 else 1)
