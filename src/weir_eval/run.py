"""Command line for the evaluation: ``python -m weir_eval.run --suite dev --out eval/results/dev``."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from . import analysis, freeze
from .agents import LlamaAgent
from .runner import ARM_RULES, MODES, run_many
from .scenarios import SPLIT_SEEDS, Scenario, suite


def select(scns: list[Scenario], where: str) -> list[Scenario]:
    if not where:
        return scns
    conds = dict(x.split("=", 1) for x in where.split(","))

    def ok(s: Scenario) -> bool:
        a = s.attack
        vals = {
            "kind": s.kind,
            "family": s.family,
            "seed": str(s.seed),
            "id": s.id,
            "variant": a.variant if a else "",
            "order": a.order if a else "",
            "delivery": a.delivery if a else "",
        }
        return all(
            any(vals[k] == v or (k == "id" and vals[k].startswith(v)) for v in val.split("|"))
            for k, val in conds.items()
        )

    return [s for s in scns if ok(s)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="weir_eval.run")
    ap.add_argument("--suite", choices=sorted(SPLIT_SEEDS), required=True)
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--arms", default=",".join(ARM_RULES))
    ap.add_argument("--modes", default=",".join(MODES))
    ap.add_argument("--where", default="", help="filter, e.g. family=F1|F2,variant=value,delivery=mail")
    ap.add_argument("--agent", choices=["scripted", "llama"], default="scripted")
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--seeds", default="", help="override the suite's seeds, e.g. 0,1,2")
    ap.add_argument("--rugpull", action="store_true", help="also run the tool-definition-change scenario once per seed")
    ap.add_argument("--trace", action="store_true", help="keep full transcripts in the records")
    ap.add_argument(
        "--rerun", action="store_true", help="allow a second held-out run; the report will say it is not held out"
    )
    a = ap.parse_args(argv)
    note = ""
    if a.suite == "test":
        ok, changed = freeze.verify()
        if not ok:
            print("refusing to run the held-out suite: the freeze is not intact:", ", ".join(changed), file=sys.stderr)
            return 3
        lock = freeze.lock_path(a.agent)
        if lock.exists() and not a.rerun:
            print(
                f"refusing: the held-out suite was already run with agent {a.agent} ({lock.name}); pass --rerun to run it again",
                file=sys.stderr,
            )
            return 3
        if lock.exists():
            note = "> **Not held out:** this is a re-run of the test suite after an earlier run; see eval/PROTOCOL.md (amendments).\n\n"
        else:
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
    scns = select(suite(a.suite), a.where)
    if a.seeds:
        keep = {int(x) for x in a.seeds.split(",")}
        scns = [s for s in scns if s.seed in keep]
    seeds = sorted({s.seed for s in scns})
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    agent = LlamaAgent(a.base_url) if a.agent == "llama" else None
    print(f"{len(scns)} scenarios x arms {a.arms} x modes {a.modes} -> {out}", flush=True)
    recs = asyncio.run(
        run_many(
            scns,
            a.arms.split(","),
            a.modes.split(","),
            out / "runs.jsonl",
            rugpull_seeds=seeds if a.rugpull else (),
            split=a.suite,
            agent=agent,
            keep_trace=a.trace,
        )
    )
    md = analysis.report(recs)
    (out / "REPORT.md").write_text(note + md + "\n")
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
