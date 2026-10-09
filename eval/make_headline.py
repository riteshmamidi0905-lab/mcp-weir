"""Machine-readable headline numbers (for the README drift test and the portfolio's vendored evidence).

    python eval/make_headline.py > eval/results/headline.json

Only counts and denominators computed from the frozen run records; nothing is rounded here.
"""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
R = ROOT / "eval" / "results"


def read(path: Path) -> list[dict[str, Any]]:
    op = gzip.open if path.suffix == ".gz" else open
    with op(path, "rt") as f:  # type: ignore[operator]
        return [json.loads(x) for x in f if x.strip()]


def first(*names: str) -> Path | None:
    return next((p for n in names if (p := R / n).exists()), None)


def cells(recs: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    atk = [r for r in recs if r["kind"] == "attack" and r["family"] != "F8"]
    ben = [r for r in recs if r["kind"] == "benign"]
    for arm in sorted({r["arm"] for r in recs}):
        for mode in sorted({r["mode"] for r in recs if r["arm"] == arm and r["mode"] != "n/a"}):
            a = [r for r in atk if r["arm"] == arm and r["mode"] == mode]
            b = [r for r in ben if r["arm"] == arm and r["mode"] == mode]
            out[f"{arm}/{mode}"] = {
                "attacks": len(a),
                "attacks_reached_goal": sum(bool(r["attack_success"]) for r in a),
                "benign": len(b),
                "benign_completed": sum(bool(r["benign_ok"]) for r in b),
                "approvals_per_benign_task": round(sum(r["approvals"] for r in b) / len(b), 4) if b else None,
                "benign_tasks_needing_approval": sum(r["approvals"] > 0 for r in b),
            }
    return out


def main() -> None:
    out: dict[str, Any] = {"freeze": {}, "scripted": {}, "realmodel": {}}
    fr = json.loads((ROOT / "eval" / "FREEZE.json").read_text())
    out["freeze"] = {"current_root_sha256": fr["root_sha256"], "suites": fr["suites"], "environment": fr["environment"]}
    s = first("test-scripted/runs.jsonl.gz", "test-scripted/runs.jsonl")
    if s:
        recs = read(s)
        out["scripted"] = {
            "runs": len(recs),
            "cells": cells(recs),
            "rug_pull": {
                a: [
                    sum(r["attack_success"] for r in recs if r["family"] == "F8" and r["arm"] == a),
                    sum(1 for r in recs if r["family"] == "F8" and r["arm"] == a),
                ]
                for a in sorted({r["arm"] for r in recs})
            },
        }
        arms = sorted({r["arm"] for r in recs})
        out["scripted"]["f4_secret_first"] = {}
        for arm in arms:
            for mode in sorted({r["mode"] for r in recs if r["arm"] == arm and r["mode"] != "n/a"}):
                sel = [
                    r
                    for r in recs
                    if r["arm"] == arm
                    and r["mode"] == mode
                    and r["family"] == "F4"
                    and r.get("order") == "secret_first"
                ]
                out["scripted"]["f4_secret_first"][f"{arm}/{mode}"] = [
                    sum(bool(r["attack_success"]) for r in sel),
                    len(sel),
                ]
        # which rule stopped the first attack call (A3, careful human); "none" = nothing was stopped (the answer channel)
        a3 = [
            r
            for r in recs
            if r["kind"] == "attack" and r["family"] != "F8" and r["arm"] == "A3" and r["mode"] == "strict"
        ]
        counts: dict[str, int] = {}
        for r in a3:
            key = (r.get("stopped_by") or ["none"])[0]
            counts[key] = counts.get(key, 0) + 1
        # every rule code that fired on that first stopped attack call (co-firing rules are all counted), and how the call was stopped:
        # "oracle_declined" = a held call the careful oracle declined (R-APPROVAL-DENIED present); "hard_denied" = stopped by deny rules alone
        fired: dict[str, int] = {}
        for r in a3:
            for code in set(r.get("stopped_by") or []):
                fired[code] = fired.get(code, 0) + 1
        stopped = [r for r in a3 if r.get("stopped_by")]
        out["scripted"]["first_stop"] = {
            "cell": "A3/strict",
            "n": len(a3),
            "counts": dict(sorted(counts.items())),
            "fired": dict(sorted(fired.items())),
            "oracle_declined": sum("R-APPROVAL-DENIED" in r["stopped_by"] for r in stopped),
            "hard_denied": sum("R-APPROVAL-DENIED" not in r["stopped_by"] for r in stopped),
        }
        # e-mail exfiltration by how the value was transformed: value tier alone / defaults with a careful human
        out["scripted"]["f1_variants"] = {}
        for variant in sorted({r["variant"] for r in recs if r["kind"] == "attack" and r["family"] == "F1"}):
            out["scripted"]["f1_variants"][variant] = {}
            for arm, mode in (("A2", "careless"), ("A3", "strict")):
                sel = [
                    r
                    for r in recs
                    if r["kind"] == "attack"
                    and r["family"] == "F1"
                    and r["variant"] == variant
                    and r["arm"] == arm
                    and r["mode"] == mode
                ]
                out["scripted"]["f1_variants"][variant][f"{arm}/{mode}"] = [
                    sum(bool(r["attack_success"]) for r in sel),
                    len(sel),
                ]
    m = first("test-realmodel/runs.jsonl.gz", "test-realmodel/runs.jsonl")
    if m:
        recs = read(m)
        out["realmodel"] = {"runs": len(recs), "cells": cells(recs)}
    for name, key in (("bench.json", "overhead"), ("equivalence-test.json", "equivalence")):
        if (R / name).exists():
            d = json.loads((R / name).read_text())
            out[key] = {k: v for k, v in d.items() if k != "rows"}
    if (R / "tests.json").exists():
        out["tests"] = json.loads((R / "tests.json").read_text())
    if (R / "adaptive" / "results.json").exists():
        out["adaptive"] = json.loads((R / "adaptive" / "results.json").read_text())
    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
