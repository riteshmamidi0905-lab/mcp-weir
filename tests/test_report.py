from mcp_weir.report import build_records, render_html, render_text, status

EVIL = '"><script>alert(1)</script><img src=x onerror=alert(2)>'


def ev(seq, kind, **payload):
    return {"seq": seq, "ts": 0.0, "session": "s1", "kind": kind, "payload": payload}


def events():
    return [
        ev(1, "session.start", policy="p" * 64, policy_name=EVIL),
        ev(
            2,
            "call.decision",
            call="c1",
            tool="mail__read_message",
            verdict="ALLOW",
            rules=[],
            args={"id": "m1"},
            result_label="internal/untrusted",
            ctx_before="public/trusted",
            external=False,
            approval=None,
        ),
        ev(
            3,
            "call.result",
            call="c1",
            tool="mail__read_message",
            ctx_after="internal/untrusted",
            is_error=False,
            uncertain=False,
        ),
        ev(4, "approval.request", approval="ap_1", call="c2", tool="x", rules=["R-FLOW-CONF"]),
        ev(
            5,
            "call.decision",
            call="c2",
            tool=EVIL,
            verdict="DENY",
            rules=[
                {
                    "code": "R-FLOW-CONF",
                    "verdict": "DENY",
                    "message": EVIL,
                    "sources": [
                        {"call": "c1", "tool": EVIL, "label": EVIL, "kind": "gram", "via": "direct", "hits": 3}
                    ],
                }
            ],
            args={"to": EVIL, "body": {"len": 5, "sha256": EVIL}},
            result_label="",
            ctx_before="internal/untrusted",
            external=True,
            approval="ap_1",
        ),
    ]


def test_records_status_and_ordering_independent_approval_events():
    recs = build_records(events())
    assert [r.call for r in recs] == ["c1", "c2"] and status(recs[0]) == "ALLOWED" and status(recs[1]) == "BLOCKED"
    assert recs[1].approval_events == ["request ap_1"]  # attached although the approval event came first in the log


def test_html_escapes_every_attacker_controlled_string_and_has_no_script():
    recs = build_records(events())
    page = render_html("s1", EVIL, "d" * 64, recs, (True, None, 5))
    assert "<script" not in page.lower().replace("&lt;script", "") and "onerror=alert(2)>" not in page
    assert "&lt;script&gt;" in page and "<img" not in page
    txt = render_text(recs)
    assert "R-FLOW-CONF" in txt and "from c1" in txt


def test_html_for_an_empty_session():
    page = render_html("s", "p", "d" * 64, [], (False, 3, 2))
    assert "BROKEN at #3" in page and "<svg" not in page
