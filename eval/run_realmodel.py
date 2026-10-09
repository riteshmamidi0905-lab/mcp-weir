"""Held-out real-model run: the protocol's explicit list of (arm, human) cells, in one process, resumable.

    python eval/run_realmodel.py --out eval/results/test-realmodel     # needs llama-server on :8080

Checks the freeze, takes the held-out lock for agent "llama" (a second run needs --rerun), then runs each cell with the
frozen runner (`weir_eval.runner.run_one`), writing one JSON record per run and flushing after each, so an interrupted run
can be resumed with --resume (it skips (scenario, arm, mode) combinations already recorded).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from weir_eval import analysis, freeze
from weir_eval.agents import LlamaAgent
from weir_eval.run import select
from weir_eval.runner import run_one
from weir_eval.scenarios import suite

ATTACK_WHERE = "kind=attack,family=F1|F2|F3|F4|F5|F6|F7,variant=value|plain"
ATTACK_SEEDS = {100, 101}
BENIGN_SEEDS = {100, 101, 102}
ATTACK_CELLS = [
    ("A0", "none"),
    ("A3", "strict"),
    ("A3", "careless"),
    ("A1", "strict"),
    ("A2", "strict"),
    ("A3d", "careless"),
]
BENIGN_CELLS = [("A0", "none"), ("A3", "none"), ("A3", "careless")]


async def main_async(a: argparse.Namespace) -> int:
    ok, changed = freeze.verify()
    if not ok:
        print("refusing: the freeze is not intact:", ", ".join(changed), file=sys.stderr)
        return 3
    lock = freeze.lock_path("llama")
    if lock.exists() and not (a.resume or a.rerun):
        print(
            f"refusing: {lock.name} exists; use --resume to continue an interrupted run or --rerun to repeat it (not held out)",
            file=sys.stderr,
        )
        return 3
    if not lock.exists():
        lock.write_text(
            json.dumps(
                {
                    "freeze_root": json.loads(freeze.FREEZE.read_text())["root_sha256"],
                    "argv": sys.argv[1:],
                    "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                },
                indent=2,
            )
            + "\n"
        )
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    scns = suite("test")
    attacks = [s for s in select(scns, ATTACK_WHERE) if s.seed in ATTACK_SEEDS]
    benigns = [s for s in select(scns, "kind=benign") if s.seed in BENIGN_SEEDS]
    agent = LlamaAgent(a.base_url)
    path = out / "runs.jsonl"
    done = set()
    if path.exists() and (a.resume or a.rerun is False):
        done = {
            (r["id"], r["arm"], r["mode"])
            for r in map(json.loads, path.read_text().splitlines() if path.exists() else [])
        }
    records = [json.loads(x) for x in path.read_text().splitlines()] if path.exists() and a.resume else []
    total = len(attacks) * len(ATTACK_CELLS) + len(benigns) * len(BENIGN_CELLS)
    t0 = time.time()
    with path.open("a" if a.resume else "w") as f:
        for cells, scn_list in ((ATTACK_CELLS, attacks), (BENIGN_CELLS, benigns)):
            for arm, mode in cells:
                for scn in scn_list:
                    if (scn.id, arm, mode) in done:
                        continue
                    rec = await run_one(scn, arm, mode, agent=agent, keep_trace=True)
                    f.write(json.dumps(rec, sort_keys=True) + "\n")
                    f.flush()
                    records.append(rec)
                    print(
                        f"[{len(records)}/{total}] {scn.id} {arm}/{mode} {rec['seconds']}s "
                        f"{'GOAL' if rec.get('attack_success') else ''} ({time.time() - t0:.0f}s)",
                        flush=True,
                    )
    (out / "REPORT.md").write_text(analysis.report(records) + "\n")
    print("done")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--rerun", action="store_true")
    return asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
