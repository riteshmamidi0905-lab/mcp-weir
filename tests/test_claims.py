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
        and "A1 with an approve-everything oracle: 100% of attacks succeed" in README
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
        f"{h['equivalence']['agree']} sampled held-out runs" in README
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
    for frag in ("62%", "86% each", "14%", "27%", "23%", "cannot be distinguished by this run"):
        assert frag in README, frag


def test_first_stop_and_transformation_claims_are_recomputed_from_the_raw_records():
    """README, evaluation.md and claims.md quote first-stop shares and per-variant counts; derive them here from the run files, not from headline.json."""
    recs = records("test-scripted/runs.jsonl")
    a3 = [
        r for r in recs if r["kind"] == "attack" and r["family"] != "F8" and r["arm"] == "A3" and r["mode"] == "strict"
    ]
    n = len(a3)
    share = {}
    for r in a3:
        k = (r.get("stopped_by") or ["none"])[0]
        share[k] = share.get(k, 0) + 1
    pct = {k: 100 * v / n for k, v in share.items()}
    assert n == 1650
    assert (
        round(pct["R-UNTRUSTED-READ"]) == 47
        and round(pct["R-DEST-UNTRUSTED"]) == 29
        and round(pct["R-FLOW-CONF"]) == 14
    )
    for frag in ("47% of runs", "the destination rule 29%", "`R-FLOW-CONF` 14%"):
        assert frag in README, frag
    ev = (ROOT / "docs" / "evaluation.md").read_text()
    for k, d in (("R-UNTRUSTED-READ", 1), ("R-DEST-UNTRUSTED", 1), ("R-FLOW-CONF", 1), ("R-TRIFECTA", 1), ("none", 1)):
        assert f"{pct[k]:.{d}f}%" in ev, k
    assert f"{pct['R-DEST-UNTRUSTED'] + pct['R-FLOW-CONF']:.1f}%" in ev  # "the whole value tier together"
    assert pct["R-UNTRUSTED-READ"] > pct["R-DEST-UNTRUSTED"] + pct["R-FLOW-CONF"]
    assert pct["R-UNTRUSTED-READ"] > 3 * pct["R-FLOW-CONF"]

    # the caveat: with an approve-everything human the session tier alone stops nothing and the tracker still does
    def rate(arm, mode):
        sel = [
            r for r in recs if r["kind"] == "attack" and r["family"] != "F8" and r["arm"] == arm and r["mode"] == mode
        ]
        return 100 * sum(bool(r["attack_success"]) for r in sel) / len(sel)

    assert rate("A3s", "careless") == 100.0 and round(rate("A2", "careless"), 1) == 44.7
    assert rate("A3s", "strict") < rate("A2", "strict")  # with a careful human the session tier alone leaves less
    assert "A3s leaves 100.0%, A2 44.7%" in README

    # S7: the tracker alone, approve-everything human, e-mail exfiltration by transformation
    def f1(variant):
        sel = [
            r
            for r in recs
            if r["kind"] == "attack"
            and r["family"] == "F1"
            and r["arm"] == "A2"
            and r["mode"] == "careless"
            and r["variant"] == variant
        ]
        return sum(bool(r["attack_success"]) for r in sel), len(sel)

    for v in ("value", "b64", "hex", "lookalike_suffix", "lookalike_hyphen"):
        assert f1(v) == (0, 60), v
    for v in ("rot13", "rev", "chunk5"):
        assert f1(v) == (60, 60), v
    f1_a3 = [
        r for r in recs if r["kind"] == "attack" and r["family"] == "F1" and r["arm"] == "A3" and r["mode"] == "strict"
    ]
    assert not any(
        r["attack_success"] for r in f1_a3
    )  # "the same attacks were all held by the session rules with a careful human"


def test_first_stop_accounting_is_disclosed_and_recomputed_from_the_raw_records():
    """The co-firing rules, the oracle-declined share and the hard denials are quoted in README, evaluation, claims and limitations."""
    recs = records("test-scripted/runs.jsonl")
    a3 = [
        r for r in recs if r["kind"] == "attack" and r["family"] != "F8" and r["arm"] == "A3" and r["mode"] == "strict"
    ]
    n = len(a3)
    stopped = [r for r in a3 if r.get("stopped_by")]
    fired = {}
    for r in stopped:
        for c in set(r["stopped_by"]):
            fired[c] = fired.get(c, 0) + 1
    declined = sum("R-APPROVAL-DENIED" in r["stopped_by"] for r in stopped)
    hard = len(stopped) - declined
    assert (n, fired["R-FLOW-CONF"], fired["R-TRIFECTA"], declined, hard) == (1650, 464, 660, 1086, 444)
    ev = (ROOT / "docs" / "evaluation.md").read_text()
    cl = (ROOT / "docs" / "claims.md").read_text()
    lim = (ROOT / "docs" / "limitations.md").read_text()
    for doc, frags in (
        (
            README,
            (
                "28.1%",
                "40.0%",
                "65.8% (1,086 of 1,650)",
                "26.9% (444)",
                "not a causal attribution",
                "predicted that the tracker would lose to transformations (E4)",
            ),
        ),
        (
            ev,
            (
                "28.1% (464)",
                "40.0% (660)",
                "65.8% (1,086 of 1,650)",
                "26.9% (444)",
                "not a causal attribution",
                "did not predict how much of the stopping",
            ),
        ),
        (
            cl,
            (
                "28.1%",
                "40.0%",
                "65.8% (1086 of 1650)".replace("1086 of 1650", "1,086 of 1,650"),
                "26.9% (444)",
                "not a causal attribution",
            ),
        ),
        (lim, ("28.1%", "40.0%", "65.8%", "26.9%", "not a causal attribution")),
    ):
        for frag in frags:
            assert frag in doc, frag


def test_the_answer_channel_is_stated_as_by_construction_and_without_universal_claims():
    for name in ("README.md", "docs/limitations.md", "docs/claims.md", "docs/evaluation.md"):
        text = (ROOT / name).read_text()
        assert "by construction" in text, name
    for name in ("README.md", "docs/limitations.md", "docs/claims.md", "docs/evaluation.md", "docs/architecture.md"):
        text = (ROOT / name).read_text().lower()
        for banned in (
            "no gateway at this boundary can",
            "no gateway can",
            "what no gateway",
            "tracker alone",
            "i expected the tracker",
            "the surprise",
        ):
            assert banned not in text, (name, banned)


def test_mt02_is_described_with_the_right_denominators():
    assert "all seven runtime controls held in all 240 agent-mode task runs" in README
    assert (
        "which ran six times" in README
        and "in all six runs the model called that read tool and printed the secret in its answer" in README
    )
    assert "not a Weir result" in README


def test_summary_only_microbenchmark_claims_are_classified_as_such():
    cl = (ROOT / "docs" / "claims.md").read_text()
    assert "except** the microbenchmark summaries" in cl and "SUMMARY-ONLY" in cl and "741 ms" in cl
    assert "every headline number" not in cl.lower()


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
