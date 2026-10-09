"""Freeze and verify the evaluation: hash every file that determines the results, and the generated scenario sets.

``python -m weir_eval.freeze write``   record the hashes in eval/FREEZE.json (done once, before any held-out run)
``python -m weir_eval.freeze verify``  recompute and compare (the held-out runner refuses to start if this fails)

A held-out (test) run also writes a lock file; a second run needs ``--rerun`` and its report says it is not held out.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from .scenarios import suite_digest

ROOT = Path(__file__).resolve().parents[2]
FREEZE = ROOT / "eval" / "FREEZE.json"
PATTERNS = [
    "src/mcp_weir/*.py",
    "src/weir_testbed/*.py",
    "src/weir_eval/scenarios.py",
    "src/weir_eval/oracles.py",
    "src/weir_eval/transforms.py",
    "src/weir_eval/runner.py",
    "src/weir_eval/agents.py",
    "src/weir_eval/analysis.py",
    "src/weir_eval/bench.py",
    "src/weir_eval/equivalence.py",
    "src/weir_eval/run.py",
    "src/weir_eval/freeze.py",
    "eval/run_realmodel.py",
    "examples/policies/workspace.toml",
    "eval/PROTOCOL.md",
]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compute() -> dict[str, Any]:
    files = {str(p.relative_to(ROOT)): sha(p) for pat in PATTERNS for p in sorted(ROOT.glob(pat))}
    root = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    try:
        sdk = metadata.version("mcp")
    except metadata.PackageNotFoundError:
        sdk = None
    return {
        "root_sha256": root,
        "files": files,
        "suites": {name: suite_digest(name) for name in ("dev", "test")},
        "environment": {"python": platform.python_version(), "platform": platform.platform(), "mcp_sdk": sdk},
    }


def verify() -> tuple[bool, list[str]]:
    if not FREEZE.exists():
        return False, ["eval/FREEZE.json does not exist"]
    rec, now = json.loads(FREEZE.read_text()), compute()
    changed = [f for f in sorted(set(rec["files"]) | set(now["files"])) if rec["files"].get(f) != now["files"].get(f)]
    changed += [f"suite:{k}" for k in now["suites"] if rec["suites"].get(k) != now["suites"][k]]
    return not changed, changed


def lock_path(agent: str) -> Path:
    return ROOT / "eval" / f"TEST-RUN.{agent}.lock"


def main(argv: list[str] | None = None) -> int:
    cmd = (argv if argv is not None else sys.argv[1:])[:1]
    if cmd == ["write"]:
        data = compute()
        FREEZE.parent.mkdir(exist_ok=True)
        FREEZE.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        print(f"froze {len(data['files'])} files, root {data['root_sha256']}")
        return 0
    if cmd == ["verify"]:
        ok, changed = verify()
        print("freeze intact" if ok else "FREEZE BROKEN: " + ", ".join(changed))
        return 0 if ok else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
