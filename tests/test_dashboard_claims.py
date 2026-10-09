"""Claim guards for the Control Center: the wording that keeps it honest must not drift, and the page must stay legible.

If one of these fails after an edit, the edit changed what the interface says about Weir (or what a reader can see), not
only how it looks.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from dashboard_helpers import get_json, request, running, seed

from weir_dashboard import ANSWER_CHANNEL_NOTE, SYNTHETIC_NOTE, demo, rules, sources

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "src" / "weir_dashboard" / "static"
DOC = ROOT / "docs" / "dashboard.md"

BANNED = [
    r"production[- ]ready",
    r"enterprise[- ]grade",
    r"unbreakable",
    r"bulletproof",
    r"tampering detected",
    r"tamper[- ]proof",
    r"\bimmutable\b",
    r"prevents? prompt[- ]injection",
    r"protects? against prompt[- ]injection",
    r"blocks? (all )?prompt[- ]injection",
    r"\bsecure\b",
    r"\bsafe\b",
    r"\brobust\b",
    r"\bsolved\b",
    r"formally verified",
    r"guarantee[sd]?\b",
    r"improves? (the )?attack",
    r"security review",
]


def texts() -> dict[str, str]:
    out = {f.name: f.read_text() for f in STATIC.iterdir() if f.suffix in (".js", ".html", ".css")}
    out["server.py"] = (ROOT / "src" / "weir_dashboard" / "server.py").read_text()
    out["model.py"] = (ROOT / "src" / "weir_dashboard" / "model.py").read_text()
    out["rules.py"] = (ROOT / "src" / "weir_dashboard" / "rules.py").read_text()
    out["docs/dashboard.md"] = DOC.read_text()
    return out


def test_banned_phrases_appear_nowhere_in_the_interface_or_its_documentation():
    """A banned phrase is allowed only inside a sentence that negates it just before it ("does not make Weir secure")."""
    for name, text in texts().items():
        text = text.replace("safe-area-inset", "inset")  # the CSS environment variable, not a claim
        for pat in BANNED:
            for m in re.finditer(pat, text, re.I):
                before = re.split(r"[.;:!?\n]", text[max(0, m.start() - 90) : m.start()])[-1]
                assert re.search(r"\b(not|no|never|cannot|nothing|without)\b|n't", before, re.I), (
                    name,
                    pat,
                    text[max(0, m.start() - 90) : m.end() + 30],
                )


def test_the_answer_channel_limit_is_in_the_page_the_server_serves_and_in_the_docs():
    assert (
        ANSWER_CHANNEL_NOTE == "Weir mediates MCP tool calls and results. It does not inspect the model's final answer."
    )
    with running(Path("/nonexistent/x.db")) as app:
        html = request(app, "/")[2].decode()
        cfg = get_json(app, "/api/config")[1]
        demo_info = get_json(app, "/api/demo")[1]
    assert f'<span id="boundary-text">{ANSWER_CHANNEL_NOTE}</span>' in html
    assert cfg["answer_channel_note"] == ANSWER_CHANNEL_NOTE == demo_info["answer_channel_note"]
    assert ANSWER_CHANNEL_NOTE in DOC.read_text()
    js = (STATIC / "app.js").read_text()
    assert (
        "does not see the user" in js and "final answer" in js and "quiet dashboard does not mean nothing leaked" in js
    )
    assert 'id="boundary-more"' in html and 'id="info"' in html, "reachable from every view"


def test_the_synthetic_label_and_the_word_simulated_stay():
    assert "SYNTHETIC DEMONSTRATION" in SYNTHETIC_NOTE
    v = (STATIC / "v-demo.js").read_text()
    assert (
        "SYNTHETIC DEMONSTRATION" in v
        and "simulated approver" in v
        and "LOAD SYNTHETIC DEMO" in v
        and "LOAD RECORDED REAL-MODEL REPLAY" in v
    )
    assert "DEMO" in v
    titles = [a[1] for a in demo.ARMS]
    assert titles == ["NO GATEWAY", "WEIR + CAREFUL SIMULATED APPROVER", "WEIR + APPROVE-EVERYTHING SIMULATED APPROVER"]
    assert all("simulated" in (a[4] or "simulated") for a in demo.ARMS)
    doc = DOC.read_text()
    assert (
        "simulated approver" in doc
        and "SYNTHETIC DEMO" in doc
        and "RECORDED REAL-MODEL REPLAY" in doc
        and "LIVE LOCAL SESSION" in doc
    )


def test_source_labels_are_the_documented_ones_and_recorded_can_never_be_live():
    assert sources.LABELS == {
        "live-local": "LIVE LOCAL SESSION",
        "recorded-replay": "RECORDED REAL-MODEL REPLAY",
        "synthetic-demo": "SYNTHETIC DEMO",
        "unknown": "SOURCE UNKNOWN",
    }
    for kind in (sources.RECORDED, sources.SYNTHETIC, sources.UNKNOWN):
        for recent in (0.0, 1e12):
            info = sources.classify({"format": 1, "source": kind}, "s", last_activity=1e12, now=1e12 + recent)
            assert not info.live and info.kind != sources.LIVE and "LIVE" not in info.label


def test_hold_and_deny_stay_different_things():
    assert (
        rules.verdict_ui("APPROVE") == "HOLD"
        and rules.verdict_ui("DENY") == "DENY"
        and rules.verdict_ui("APPROVE") != rules.verdict_ui("DENY")
    )
    assert rules.UI_ACTION == {"approve": "HOLD", "deny": "DENY", "off": "OFF"}
    import tempfile

    p = Path(tempfile.mkdtemp()) / "w.db"
    seed(p)
    with running(p) as app:
        d = get_json(app, "/api/d/live/sessions/live-2")[1]
        ap = get_json(app, "/api/d/live/approvals")[1]
    blocked = [c for c in d["calls"] if c["verdict"] == "DENY"]
    held = [c for c in d["calls"] if c["verdict"] == "HOLD"]
    assert blocked and held
    assert all(c["approval"] is None and "cannot be approved" in c["explain"] for c in blocked), (
        "a deny offers no approval"
    )
    assert all(c["approval"] is not None for c in held), "a hold has one"
    deny_ids = {c["call_hash"] for c in blocked}
    assert not [a for a in ap["approvals"] if a["call_hash"] in {h[:12] for h in deny_ids}]
    flow = (STATIC / "v-flow.js").read_text()
    assert "Blocked. No approval can override this." in flow and "Approval required: review and decide" in flow
    assert "A deny cannot be approved." in (ROOT / "src" / "weir_dashboard" / "model.py").read_text()


def test_failure_wording_for_the_audit_chain_is_the_specified_one():
    m = (ROOT / "src" / "weir_dashboard" / "model.py").read_text()
    a = (STATIC / "v-audit.js").read_text()
    assert '"Hash-chain verification failed."' in m and "Hash-chain verification failed." in a
    assert "cannot show that events were not removed" in m


def test_the_doc_does_not_restate_evaluation_numbers_or_claim_an_effect_on_attacks():
    t = DOC.read_text()
    assert "%" not in t, "no rates: this interface has no evaluation result of its own"
    assert not re.search(r"\b(1,?650|2,?400|120/120|7\.3|741)\b", t)
    for must in (
        "not part of",
        "frozen",
        "Known limitations",
        "127.0.0.1",
        "Answer channel",
        "What it can change",
        "Approval",
        "Redaction",
        "weir-dashboard",
    ):
        assert must in t, must
    assert "does not change" in t and "benchmark" in t


def test_readme_points_to_the_dashboard_doc_without_claims():
    r = (ROOT / "README.md").read_text()
    assert "docs/dashboard.md" in r
    seg = r[r.index("Control Center") - 200 : r.index("Control Center") + 800]
    assert "local" in seg and "not part of the gateway" in seg


# ------------------------------------------------------------------ legibility: WCAG contrast of the colour tokens
def hexrgb(h: str) -> tuple[float, float, float]:
    h = h.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return tuple(int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]


def lum(c: tuple[float, float, float]) -> float:
    f = lambda v: v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4  # noqa: E731
    r, g, b = (f(v) for v in c)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    la, lb = lum(hexrgb(a)), lum(hexrgb(b))
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def tokens() -> dict[str, dict[str, str]]:
    css = (STATIC / "app.css").read_text()
    blocks = {
        "light": re.search(r":root \{(.*?)\n\}", css, re.S).group(1),
        "dark": re.search(r':root\[data-theme="dark"\] \{(.*?)\n\}', css, re.S).group(1),
    }
    auto = re.search(
        r"prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme=\"light\"\]\) \{(.*?)\n  \}", css, re.S
    ).group(1)
    out = {k: dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{3,6})", v)) for k, v in blocks.items()}
    out["auto-dark"] = dict(re.findall(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{3,6})", auto))
    return out


@pytest.mark.parametrize("theme", ["light", "dark", "auto-dark"])
def test_text_colour_pairs_meet_aa_contrast_in_every_theme(theme):
    t = tokens()
    t = {**t["light"], **t[theme]} if theme != "light" else t["light"]
    pairs = [
        ("text", "bg"),
        ("text", "surface"),
        ("text-2", "bg"),
        ("text-2", "surface"),
        ("text-2", "surface-2"),
        ("text-3", "bg"),
        ("text-3", "surface"),
        ("text-3", "surface-2"),
        ("accent", "bg"),
        ("accent", "surface"),
        ("accent", "accent-bg"),
        ("allow", "allow-bg"),
        ("hold", "hold-bg"),
        ("deny", "deny-bg"),
        ("demo", "demo-bg"),
        ("rec", "rec-bg"),
        ("allow", "surface"),
        ("hold", "surface"),
        ("deny", "surface"),
        ("text", "surface-3"),
        ("text-2", "surface-3"),
        ("bg", "text"),  # the primary button: page background colour on the text colour
    ]
    bad = [(a, b, round(contrast(t[a], t[b]), 2)) for a, b in pairs if contrast(t[a], t[b]) < 4.5]
    assert not bad, bad


def test_solid_buttons_and_the_deny_badge_meet_contrast():
    t = tokens()
    assert contrast("#ffffff", t["light"]["deny"]) >= 4.5 and contrast("#ffffff", t["light"]["allow"]) >= 4.5
    assert contrast("#1a0605", t["dark"]["deny"]) >= 4.5 and contrast("#04170d", t["dark"]["allow"]) >= 4.5
