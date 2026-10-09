"""Documentation drift: what the README and the generated documents say must match what was recorded.

If one of these fails, a number in prose no longer matches a result, or a frozen file changed after the held-out runs.
"""

import gzip
import json
import subprocess
import sys
from pathlib import Path

import pytest

from weir_eval import freeze

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "eval" / "results"
README = (ROOT / "README.md").read_text()


def half_even(x: float, d: int) -> str:
    return f"{x:.{d}f}"  # Python formats exact ties to even, like the repository's own tables


def headline():
    return json.loads((R / "headline.json").read_text())


def records(rel: str):
    p = R / rel
    if not p.exists():
        p = R / (rel + ".gz")
    if p.suffix == ".gz":
        with gzip.open(p, "rt") as f:
            text = f.read()
    else:
        text = p.read_text()
    return [json.loads(x) for x in text.splitlines() if x.strip()]


def test_the_frozen_files_are_intact():
    ok, changed = freeze.verify()
    assert ok, f"frozen files changed after the freeze: {changed}"


def test_generated_documents_are_up_to_date():
    r = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "build_docs.py"), "--check"], capture_output=True, text=True, cwd=ROOT
    )
    assert r.returncode == 0, (
        "docs/evaluation.md, docs/claims.md or the generated README blocks are stale: run `python eval/build_docs.py`"
    )


def test_headline_json_is_what_the_records_produce():
    r = subprocess.run(
        [sys.executable, str(ROOT / "eval" / "make_headline.py")], capture_output=True, text=True, cwd=ROOT, check=True
    )
    assert json.loads(r.stdout) == headline()


def test_readme_numbers_come_from_the_recorded_results():
    h = headline()
    c = h["scripted"]["cells"]
    a3, a1, a3d = c["A3/strict"], c["A1/strict"], c["A3d/careless"]
    assert f"{a3['attacks']:,} scripted attacks and {a3['benign']} benign tasks per cell" in README
    assert (
        half_even(a1["approvals_per_benign_task"], 2) in README
        and half_even(a3["approvals_per_benign_task"], 2) in README
    )
    assert f"{100 * a3['attacks_reached_goal'] / a3['attacks']:.1f}%" in README
    assert f"{100 * a3d['attacks_reached_goal'] / a3d['attacks']:.1f}%" in README
    assert (
        c["A1/careless"]["attacks_reached_goal"] == c["A1/careless"]["attacks"]
        and "A1: 100% of attacks succeed" in README
    )
    assert h["scripted"]["f4_secret_first"]["A3/strict"] == [120, 120] and "100% of its runs under every arm" in README
    # "first thing to stop the attack in 47% of runs"
    recs = records("test-scripted/runs.jsonl")
    sel = [
        r for r in recs if r["arm"] == "A3" and r["mode"] == "strict" and r["kind"] == "attack" and r["family"] != "F8"
    ]
    first = sum(1 for r in sel if (r.get("stopped_by") or [""])[0] == "R-UNTRUSTED-READ")
    assert f"{100 * first / len(sel):.0f}% of runs" in README
    p99 = h["overhead"]["in_process"][2]["p99_us"] / 1000
    assert (
        f"{p99:.2f} ms" in README and "741 ms" in README
    )  # the 741 ms is the pre-fix figure, recorded in docs/red-team.md
    assert "741 ms" in (ROOT / "docs" / "red-team.md").read_text()
    assert (
        f"{h['equivalence']['agree']} held-out runs" in README
        and h["equivalence"]["agree"] == h["equivalence"]["total"]
    )


def test_readme_realmodel_prose_numbers_come_from_the_records():
    """The sentence under the real-model table quotes 62%, 86%, 14%, 27% and 23%: check each against the records."""
    recs = records("test-realmodel/runs.jsonl")
    atk = [r for r in recs if r["kind"] == "attack"]

    def rate(arm, mode, **kw):
        sel = [r for r in atk if r["arm"] == arm and r["mode"] == mode and all(r.get(k) == v for k, v in kw.items())]
        return round(100 * sum(bool(r["attack_success"]) for r in sel) / len(sel))

    assert rate("A0", "none") == 62
    assert rate("A0", "none", delivery="web") == 86 and rate("A0", "none", delivery="file") == 86
    assert rate("A0", "none", delivery="mail") == 14
    assert rate("A3", "careless") == 27
    assert rate("A1", "strict") == rate("A2", "strict") == rate("A3", "strict") == 9, (
        "README says the three arms are indistinguishable"
    )
    assert all(r["family"] == "F4" for r in atk if r["arm"] == "A3" and r["mode"] == "strict" and r["attack_success"])
    ben = [r for r in recs if r["kind"] == "benign" and r["arm"] == "A0" and r["mode"] == "none"]
    assert round(100 * sum(not r["benign_ok"] for r in ben) / len(ben)) == 23
    for frag in ("62%", "86% each", "14%", "27%", "23%", "indistinguishable"):
        assert frag in README, frag


def test_the_spec_criterion_that_was_missed_is_reported_as_missed():
    ev = (ROOT / "docs" / "evaluation.md").read_text()
    assert "**Missed, as predicted.**" in ev and "was **missed: 7.3%**" in ev


def test_no_forbidden_words_in_public_prose():
    banned = [
        "production-ready",
        "production ready",
        "enterprise-grade",
        "enterprise grade",
        "unbreakable",
        "bulletproof",
    ]
    for f in [
        "README.md",
        "docs/evaluation.md",
        "docs/limitations.md",
        "docs/claims.md",
        "docs/red-team.md",
        "docs/architecture.md",
    ]:
        text = (ROOT / f).read_text().lower()
        for w in banned:
            # allowed only where the sentence is a prohibition ("does not use")
            for line in text.splitlines():
                if w in line:
                    assert "not use" in line or "unless" in line, f"{f}: {line.strip()[:120]}"


@pytest.mark.parametrize("path", ["README.md", "docs/limitations.md", "docs/claims.md"])
def test_limitations_are_not_buried(path):
    text = (ROOT / path).read_text().lower()
    assert "synthetic" in text and (
        "same-author" in text
        or "same author" in text
        or "one ai-assisted author" in text
        or "same hand" in text
        or "one author" in text
    )
