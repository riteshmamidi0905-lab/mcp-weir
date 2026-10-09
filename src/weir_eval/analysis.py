"""Aggregate run records into tables. Counts with denominators and Wilson 95% intervals; nothing is rounded up."""

from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .runner import ARM_NAMES, MODE_NAMES


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def fmt(k: int, n: int) -> str:
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {100 * k / n:.1f}% [{100 * lo:.1f}, {100 * hi:.1f}]"


def load(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def _cells(recs: list[dict[str, Any]], kind: str, key: str) -> dict[tuple[str, str], list[dict[str, Any]]]:
    out: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in recs:
        if r["kind"] == kind and r.get(key) is not None and r["family"] != "F8":
            out[(r["arm"], r["mode"])].append(r)
    return out


ARM_ORDER = ["A0", "A1", "A2", "A3s", "A3", "A3d"]
MODE_ORDER = ["none", "strict", "careless"]


def _order(cells: dict[tuple[str, str], Any]) -> list[tuple[str, str]]:
    return sorted(
        cells,
        key=lambda c: (
            ARM_ORDER.index(c[0]) if c[0] in ARM_ORDER else 9,
            MODE_ORDER.index(c[1]) if c[1] in MODE_ORDER else 9,
        ),
    )


def attack_table(recs: list[dict[str, Any]]) -> str:
    cells = _cells(recs, "attack", "attack_success")
    rows = ["| Arm | Human | Attacks that reached their goal |", "|---|---|---|"]
    for c in _order(cells):
        rs = cells[c]
        rows.append(
            f"| {c[0]} {ARM_NAMES.get(c[0], '')} | {c[1]} ({MODE_NAMES.get(c[1], '')}) | {fmt(sum(r['attack_success'] for r in rs), len(rs))} |"
        )
    return "\n".join(rows)


def utility_table(recs: list[dict[str, Any]]) -> str:
    cells = _cells(recs, "benign", "benign_ok")
    rows = [
        "| Arm | Human | Benign tasks completed | Approvals per task (mean) | Tasks needing ≥1 approval |",
        "|---|---|---|---|---|",
    ]
    for c in _order(cells):
        rs = cells[c]
        rows.append(
            f"| {c[0]} {ARM_NAMES.get(c[0], '')} | {c[1]} | {fmt(sum(r['benign_ok'] for r in rs), len(rs))} | "
            f"{sum(r['approvals'] for r in rs) / len(rs):.2f} | {sum(r['approvals'] > 0 for r in rs)}/{len(rs)} |"
        )
    return "\n".join(rows)


def breakdown(recs: list[dict[str, Any]], arm: str, mode: str, by: str) -> str:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in recs:
        if (
            r["kind"] == "attack"
            and r["arm"] == arm
            and r["mode"] == mode
            and r["family"] != "F8"
            and r.get(by) is not None
        ):
            groups[str(r[by]) if by != "family" else r["family"]].append(r)
    rows = [f"| {by} | attacks reaching their goal ({arm}, {mode}) |", "|---|---|"]
    for k in sorted(groups):
        rows.append(f"| {k} | {fmt(sum(r['attack_success'] for r in groups[k]), len(groups[k]))} |")
    return "\n".join(rows)


def stopped_by(recs: list[dict[str, Any]], arm: str, mode: str) -> str:
    c: Counter[str] = Counter()
    n = 0
    for r in recs:
        if r["kind"] == "attack" and r["arm"] == arm and r["mode"] == mode and r["family"] != "F8":
            n += 1
            c[
                "+".join(r["stopped_by"])
                if r.get("stopped_by")
                else ("(not stopped)" if r["attack_success"] else "(failed for other reasons)")
            ] += 1
    return "\n".join(
        [
            f"| first rule to stop the attack ({arm}, {mode}) | runs |",
            "|---|---|",
            *[f"| {k} | {v}/{n} |" for k, v in c.most_common()],
        ]
    )


def false_blocks(recs: list[dict[str, Any]], arm: str) -> str:
    """Which benign tasks were held or blocked, and by which rule (mode `none` shows every flag)."""
    c: dict[str, Counter[str]] = defaultdict(Counter)
    n: Counter[str] = Counter()
    for r in recs:
        if r["kind"] == "benign" and r["arm"] == arm and r["mode"] == "none":
            t = r["id"].split("-")[1]
            n[t] += 1
            for code in r["codes"]:
                c[t][code] += 1
    rows = [f"| task | runs flagged ({arm}) | rules |", "|---|---|---|"]
    for t in sorted(n):
        if c[t]:
            rows.append(f"| {t} | {max(c[t].values())}/{n[t]} | {', '.join(sorted(c[t]))} |")
    return "\n".join(rows)


def overhead(recs: list[dict[str, Any]]) -> str:
    vals: list[float] = sorted(
        float(r["overhead_us"]) / max(1, r["n_calls"])
        for r in recs
        if r["arm"] != "A0" and r["n_calls"] and r["agent"] == "scripted"
    )
    if not vals:
        return "(no data)"

    def q(p: float) -> float:
        return vals[min(len(vals) - 1, int(p * len(vals)))]

    return f"gateway overhead per call, in-process (n={len(vals)} runs): p50 {q(0.5):.0f} µs, p95 {q(0.95):.0f} µs, p99 {q(0.99):.0f} µs, max {vals[-1]:.0f} µs"


def report(recs: list[dict[str, Any]]) -> str:
    parts = ["### Attacks\n", attack_table(recs), "\n### Benign tasks\n", utility_table(recs)]
    for arm, mode in (("A3", "strict"), ("A3", "careless"), ("A2", "careless")):
        if any(r["arm"] == arm and r["mode"] == mode for r in recs):
            parts += [
                f"\n### {arm} / {mode}: by family\n",
                breakdown(recs, arm, mode, "family"),
                f"\n### {arm} / {mode}: by variant\n",
                breakdown(recs, arm, mode, "variant"),
            ]
    parts += [
        "\n### What stopped the attacks (A3, none)\n",
        stopped_by(recs, "A3", "none"),
        "\n### Benign tasks flagged (A3)\n",
        false_blocks(recs, "A3"),
        "\n### Overhead\n",
        overhead(recs),
    ]
    rug = [r for r in recs if r["family"] == "F8"]
    if rug:
        parts += ["\n### Tool-definition change (rug pull)\n", "| Arm | attack reached its goal |", "|---|---|"]
        for arm in ARM_ORDER:
            rs = [r for r in rug if r["arm"] == arm]
            if rs:
                parts.append(f"| {arm} | {fmt(sum(r['attack_success'] for r in rs), len(rs))} |")
    return "\n".join(parts)
