"""Drive the Control Center in headless Chromium (Playwright for Node).

Where Node and Playwright are not available the test is skipped, unless WEIR_REQUIRE_BROWSER=1, which turns a missing
prerequisite into a failure (the CI browser job sets it, so it cannot pass by skipping).

Playwright comes from WEIR_PLAYWRIGHT_DIR (a directory whose node_modules has it, with a Chromium installed) or, by
default, from tests/ui after ``npm ci --prefix tests/ui`` (the lockfile pins the version). Node is WEIR_NODE or the one
on PATH. The servers and databases are real: the gateway wrote them, and the suite makes a call through the gateway
while a page is open to check live updates.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from dashboard_helpers import running, seed
from helpers import FIXTURE, POLICY_FILE, make_gateway

from mcp_weir.policy import load_policy
from mcp_weir.store import Store
from weir_testbed.world import World

HERE = Path(__file__).resolve().parent
NODE = os.environ.get("WEIR_NODE") or shutil.which("node")
PW = os.environ.get("WEIR_PLAYWRIGHT_DIR") or str(HERE / "ui")
EXPECTED_BROWSER_TESTS = (
    26  # docs/dashboard.md quotes this number; tests/test_dashboard_claims.py checks that it agrees
)


def add_second_pending(db: Path) -> None:
    async def go() -> None:
        st = Store(str(db))
        gw = make_gateway(load_policy(POLICY_FILE), st, World.from_fixture(FIXTURE))
        await gw.start()
        s = gw.open_session("live-4")
        await gw.call_tool_detailed(s, "mail__read_message", {"id": "m1"})
        await gw.call_tool_detailed(s, "files__read_file", {"path": "/secrets/payroll.txt"})
        st.close()

    asyncio.run(go())


def test_the_interface_in_a_real_browser(tmp_path):
    if not NODE or not (Path(PW) / "node_modules" / "playwright").exists():
        if os.environ.get("WEIR_REQUIRE_BROWSER") == "1":
            pytest.fail("WEIR_REQUIRE_BROWSER=1 but Node or Playwright is missing: run npm ci --prefix tests/ui")
        pytest.skip("needs Node and Playwright (npm ci --prefix tests/ui, or WEIR_NODE and WEIR_PLAYWRIGHT_DIR)")
    db = tmp_path / "weir.db"
    seed(db)
    add_second_pending(db)
    bad = tmp_path / "tampered.db"
    seed(bad)
    c = sqlite3.connect(bad)
    c.execute("UPDATE events SET payload = REPLACE(payload, 'workspace', 'edited') WHERE seq = 1")
    c.commit()
    c.close()
    import json

    lock = tmp_path / "tools.lock.json"
    lock.write_text(json.dumps({"version": 1, "tools": {t.name: "ab" * 32 for t in load_policy(POLICY_FILE).tools}}))
    with running(db, policy=str(POLICY_FILE), lock=str(lock)) as app, running(bad, policy=str(POLICY_FILE)) as app2:
        env = {
            **os.environ,
            "WEIR_UI_URL": app.base,
            "WEIR_UI_TAMPERED_URL": app2.base,
            "WEIR_UI_DB": str(db),
            "WEIR_PLAYWRIGHT_DIR": str(PW),
            "WEIR_PYTHON": sys.executable,
            "WEIR_MORE_CALLS": str(HERE / "ui" / "more_calls.py"),
        }
        r = subprocess.run(
            [str(NODE), "--test", "--test-reporter=spec", str(HERE / "ui" / "dashboard.test.mjs")],
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
        )
    if os.environ.get("WEIR_UI_LOG"):
        Path(os.environ["WEIR_UI_LOG"]).write_text(r.stdout + r.stderr)
    summary = "\n".join(line for line in r.stdout.splitlines() if line.lstrip().startswith(("✔", "✖")))
    assert r.returncode == 0, summary + "\n\n" + r.stdout[-5000:] + r.stderr[-2000:]
    counts = {k: int(v) for k, v in re.findall(r"^ℹ (tests|pass|fail|skipped|cancelled) (\d+)$", r.stdout, re.M)}
    assert counts == {
        "tests": EXPECTED_BROWSER_TESTS,
        "pass": EXPECTED_BROWSER_TESTS,
        "fail": 0,
        "skipped": 0,
        "cancelled": 0,
    }, counts
