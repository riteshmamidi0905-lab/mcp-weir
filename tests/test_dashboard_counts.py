"""The test counts quoted in the README and in docs/dashboard.md are what ``pytest`` collects.

342 is the count recorded at release time (eval/results/tests.json, written by eval/record_tests.py). It is a record, not
something CI recomputes. This file ties it to the repository: the tests that are not Control Center tests still number
exactly that, and the totals in docs/dashboard.md match the collection.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# tests/test_interop_sdk.py starts with ``pytest.importorskip("mcp")``: without the official SDK (the ``interop`` extra)
# the whole module collects 0 tests, so a checkout installed with only ``.[test]`` sees 4 fewer tests than the 342 that
# were recorded (which ran with the SDK) and 414 instead of 418 in total. That is an environment difference, not a
# change in the suite, so this check needs the extra and says so instead of reporting a false drift.
INTEROP_TESTS = 4


def test_the_documented_test_counts_are_what_pytest_collects():
    pytest.importorskip(
        "mcp",
        reason="needs the 'interop' extra (pip install -e '.[test,interop]'): without the official MCP SDK "
        f"tests/test_interop_sdk.py collects 0 tests, {INTEROP_TESTS} fewer than the recorded count",
    )
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-qq", "-o", "addopts=", "-p", "no:cacheprovider", "tests"],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )
    per_file = {m.group(1): int(m.group(2)) for m in re.finditer(r"^(tests/\S+\.py): (\d+)$", r.stdout, re.M)}
    total = sum(per_file.values())
    dashboard = sum(n for f, n in per_file.items() if Path(f).name.startswith("test_dashboard_"))
    historical = total - dashboard
    recorded = json.loads((ROOT / "eval" / "results" / "tests.json").read_text())
    assert per_file.get("tests/test_interop_sdk.py") == INTEROP_TESTS, per_file.get("tests/test_interop_sdk.py")
    assert historical == recorded["passed"], (
        "tests outside tests/test_dashboard_*.py no longer number what was recorded at release"
    )
    doc = (ROOT / "docs" / "dashboard.md").read_text()
    assert f"collects {total} tests. {historical} of them" in doc and f"the other {dashboard} are files named" in doc, (
        total,
        historical,
        dashboard,
    )
    assert f"runs {total - 1} of them" in doc
    readme = (ROOT / "README.md").read_text()
    assert (
        f"<!-- gen-inline:testcount -->{historical}<!-- /gen-inline:testcount --> tests recorded at release time (eval/results/tests.json)"
        in readme
    )
    assert "the optional Control Center adds its own (docs/dashboard.md)" in readme
    from test_dashboard_ui import EXPECTED_BROWSER_TESTS

    assert f"{EXPECTED_BROWSER_TESTS} browser tests" in doc and f"exactly {EXPECTED_BROWSER_TESTS} pass" in doc
