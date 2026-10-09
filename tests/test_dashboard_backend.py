"""Backend tests for the Weir Control Center: read-only access, data model, rule table, audit, approvals, redaction, server defences."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from itertools import pairwise
from pathlib import Path

import pytest
from dashboard_helpers import SENDMAIL, get_json, post_json, request, running, seed
from helpers import FIXTURE, POLICY_FILE, SECRET, make_gateway

from mcp_weir import report
from mcp_weir.policy import load_policy
from mcp_weir.store import Store, event_hash
from weir_dashboard import actions, rules, sources
from weir_dashboard.readonly import ApprovalWriter, DashboardDBError, ReadOnlyError, ReadOnlyStore
from weir_testbed.world import World

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def db(tmp_path):
    p = tmp_path / "weir.db"
    ids = seed(p)
    return p, ids


def dump(path: Path) -> list[str]:
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return list(c.iterdump())
    finally:
        c.close()


# ------------------------------------------------------------------ read-only access
def test_the_read_connection_cannot_write(db):
    p, _ = db
    st = ReadOnlyStore(str(p))
    for call in (
        lambda: st.append_event("x", "k", {}),
        lambda: st.resolve_approval("ap_00000000", True),
        lambda: st.consume_approval("s", "h"),
        lambda: st.create_approval("s", "h", "t", [], {}, 1.0),
        lambda: st.hmac_key(),
        lambda: st.save_session(None),  # type: ignore[arg-type]
    ):
        with pytest.raises(ReadOnlyError):
            call()
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        st._db.execute("INSERT INTO meta(key, value) VALUES('x','y')")
    st.close()


def test_reading_everything_leaves_the_database_exactly_as_it_was(db):
    p, _ = db
    before = dump(p)
    with running(p, policy=str(POLICY_FILE)) as app:
        for path in (
            "overview",
            "pulse",
            "rules",
            "policy",
            "d/live/sessions",
            "d/live/approvals",
            "d/live/audit",
            "d/live/sessions/live-2",
            "demo",
            "config",
        ):
            status, _ = get_json(app, f"/api/{path}")
            assert status == 200, path
    assert dump(p) == before


def test_a_missing_database_is_not_created_and_is_reported(tmp_path):
    p = tmp_path / "nope.db"
    with pytest.raises(DashboardDBError) as e:
        ReadOnlyStore(str(p))
    assert e.value.state == "missing" and not p.exists()
    with running(p) as app:
        status, body = get_json(app, "/api/overview")
        assert status == 503 and body["error"]["state"] == "missing"
        assert get_json(app, "/api/pulse")[1]["live"] == {"state": "missing"}
    assert not p.exists()


def test_a_file_that_is_not_a_weir_database_is_reported_not_crashed_on(tmp_path):
    p = tmp_path / "junk.db"
    p.write_bytes(b"this is not sqlite" * 100)
    with running(p) as app:
        status, body = get_json(app, "/api/overview")
        assert status == 503 and body["error"]["state"] == "corrupt"
    q = tmp_path / "other.db"
    c = sqlite3.connect(q)
    c.execute("CREATE TABLE unrelated(x)")
    c.commit()
    c.close()
    with running(q) as app:
        assert get_json(app, "/api/overview")[1]["error"]["state"] == "empty"
    r = tmp_path / "v9.db"
    Store(str(r)).close()
    c = sqlite3.connect(r)
    c.execute("UPDATE meta SET value='9' WHERE key='schema_version'")
    c.commit()
    c.close()
    with running(r) as app:
        assert get_json(app, "/api/overview")[1]["error"]["state"] == "schema"


def test_a_malformed_event_is_counted_and_skipped_not_fatal(tmp_path):
    p = tmp_path / "m.db"
    st = Store(str(p))
    st.append_event("s", "session.start", {"policy": "a" * 64, "policy_name": "workspace"})
    prev = st._db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()[0]
    bad = "{not json"
    st._db.execute(
        "INSERT INTO events(ts, session_id, kind, payload, prev_hash, hash) VALUES(?,?,?,?,?,?)",
        (1.0, "s", "call.decision", bad, prev, event_hash(prev, 1.0, "s", "call.decision", bad)),
    )
    st.close()
    with running(p) as app:
        status, body = get_json(app, "/api/overview")
        assert status == 200 and body["database"]["malformed_events"] == 1 and body["audit"]["ok"] is True
        status, d = get_json(app, "/api/d/live/sessions/s")
        assert status == 200 and d["summary"]["malformed_events"] == 1 and d["calls"] == []


# ------------------------------------------------------------------ data model
def test_session_detail_reports_what_the_gateway_recorded(db):
    p, ids = db
    with running(p, policy=str(POLICY_FILE)) as app:
        _, d = get_json(app, "/api/d/live/sessions/live-2")
    calls = {c["call"]: c for c in d["calls"]}
    assert [c["verdict"] for c in d["calls"]] == ["ALLOW", "ALLOW", "HOLD", "HOLD", "DENY"]
    assert calls["c3"]["raw_verdict"] == "APPROVE" and calls["c3"]["status"] == "HELD"
    assert calls["c4"]["status"] == "EXECUTED_AFTER_APPROVAL" and calls["c4"]["forwarded"]
    assert calls["c4"]["approval"]["id"] == ids["used"] and calls["c4"]["approval"]["state"] == "consumed"
    assert calls["c4"]["approval"]["resolved_by"] == "cli-user (command line)"
    c5 = calls["c5"]
    assert c5["status"] == "BLOCKED" and not c5["forwarded"] and c5["approval"] is None
    assert [h["code"] for h in c5["rules"]] == ids["deny_codes"] == ["R-DEST-UNTRUSTED", "R-FLOW-CONF", "R-TRIFECTA"]
    assert [h["verdict"] for h in c5["rules"]] == ["HOLD", "DENY", "HOLD"]
    assert "cannot be approved" in c5["explain"]
    assert d["summary"]["ctx"]["text"] == "secret/untrusted"
    assert d["summary"]["counts"] == {
        "calls": 5,
        "allow": 2,
        "hold": 2,
        "deny": 1,
        "held_now": 0,
        "executed_after_approval": 1,
    }


def test_provenance_lists_only_recorded_sources(db):
    p, _ = db
    with running(p) as app:
        _, d = get_json(app, "/api/d/live/sessions/live-2")
        _, none = get_json(app, "/api/d/live/sessions/live-1")
    edges = d["provenance"]
    assert {(e["from"], e["to"], e["rule"]) for e in edges} == {
        ("c2", "c5", "R-DEST-UNTRUSTED"),
        ("c4", "c5", "R-FLOW-CONF"),
    }
    assert none["provenance"] == []
    # every edge is a source object copied from a call.decision event
    st = ReadOnlyStore(str(p))
    recorded = [
        (s["call"], e["payload"]["call"])
        for e in st.events("live-2")
        if e["kind"] == "call.decision"
        for h in e["payload"]["rules"]
        for s in h["sources"]
    ]
    assert sorted((e["from"], e["to"]) for e in edges) == sorted(recorded)


def test_context_steps_come_from_the_label_model(db):
    p, _ = db
    with running(p) as app:
        _, d = get_json(app, "/api/d/live/sessions/live-2")
    assert d["lattice"] == {
        "conf": ["public", "internal", "secret"],
        "integ": ["trusted", "untrusted"],
        "bottom": "public/trusted",
    }
    path = [(s["call"], s["after"]["text"]) for s in d["ctx_steps"] if s["grew"]]
    assert path == [("c1", "public/untrusted"), ("c2", "internal/untrusted"), ("c4", "secret/untrusted")]
    ranks = [s["after"]["rank"] for s in d["ctx_steps"]]
    assert all(a[0] <= b[0] and a[1] <= b[1] for a, b in pairwise(ranks)), "the context only grows"


def test_call_records_match_the_gateways_own_report_reader(db):
    p, _ = db
    st = ReadOnlyStore(str(p))
    recs = report.build_records(list(st.events("live-2")))
    with running(p) as app:
        _, d = get_json(app, "/api/d/live/sessions/live-2")
    assert [(r.call, r.tool, r.verdict) for r in recs] == [(c["call"], c["tool"], c["raw_verdict"]) for c in d["calls"]]


def test_sessions_list_counts_and_pending(db):
    p, _ = db
    with running(p) as app:
        _, body = get_json(app, "/api/d/live/sessions")
    by = {s["id"]: s for s in body["sessions"]}
    assert set(by) == {"live-1", "live-2", "live-3"}
    assert by["live-1"]["pending_approvals"] == 1 and by["live-2"]["pending_approvals"] == 0
    assert by["live-3"]["counts"]["deny"] == 1 and by["live-3"]["counts"]["hold"] == 1
    assert all(s["source"]["kind"] == "live-local" for s in by.values())
    assert all(s["audit"]["chain_ok"] for s in by.values())


def test_overview_makes_no_claim_about_the_gateway_process(db):
    p, _ = db
    with running(p) as app:
        _, o = get_json(app, "/api/overview")
    assert set(o["activity"]) == {"last_event", "age_s", "recent", "note"}, (
        "only what the log can show: the last event and how long ago"
    )
    assert not re.search(r"uptime|RUNNING|STOPPED", json.dumps(o))
    assert "cannot see whether a gateway process is running" in o["activity"]["note"]
    assert o["approvals"]["pending"] == 1 and o["decisions"]["deny"] == 2


# ------------------------------------------------------------------ rule table
def test_the_rule_table_covers_every_rule_code_in_the_gateway_source():
    found = set()
    for f in (ROOT / "src" / "mcp_weir").glob("*.py"):
        found |= set(re.findall(r'"(R-[A-Z-]+)"', f.read_text()))
    assert found and found == set(rules.CATALOGUE), found ^ set(rules.CATALOGUE)


def test_rule_actions_come_from_the_policy_and_map_to_hold_and_deny():
    pol = load_policy(POLICY_FILE)
    d = {r["code"]: r for r in (rules.describe(c, pol) for c in rules.CATALOGUE)}
    assert [(c["key"], c["action"]) for c in d["R-FLOW-CONF"]["configured"]] == [
        ("flow_conf_secret", "DENY"),
        ("flow_conf_internal", "HOLD"),
    ]
    assert d["R-UNTRUSTED-READ"]["configured"][0]["action"] == "HOLD"
    assert d["R-GATE"]["configured"][0]["action"] == "OFF"
    assert (
        d["R-PIN"]["configured"][0]["action"] == "DENY" and d["R-APPROVAL-DENIED"]["configured"][0]["action"] == "DENY"
    )
    assert {(o["tool"], o["key"]) for o in d["R-DEST-UNTRUSTED"]["overrides"]} == {("web__fetch_url", "dest_untrusted")}
    assert rules.describe("R-FLOW-CONF", None)["configured_from"].startswith("gateway defaults")
    assert (
        rules.verdict_ui("APPROVE") == "HOLD"
        and rules.verdict_ui("DENY") == "DENY"
        and rules.verdict_ui("ALLOW") == "ALLOW"
    )


def test_the_rules_endpoint_counts_what_was_recorded(db):
    p, _ = db
    with running(p, policy=str(POLICY_FILE)) as app:
        _, r = get_json(app, "/api/rules")
    by = {x["code"]: x for x in r["rules"]}
    assert by["R-FLOW-CONF"]["fired"] == {"DENY": 1} and by["R-UNTRUSTED-READ"]["fired_total"] == 5
    assert by["R-PIN"]["fired_total"] == 0


# ------------------------------------------------------------------ audit
def test_chain_verification_uses_the_stores_own_check_and_wording(db):
    p, _ = db
    ok, _, n = ReadOnlyStore(str(p)).verify_chain()
    with running(p) as app:
        _, a = get_json(app, "/api/d/live/audit?verify=1")
    assert a["chain"]["ok"] is ok is True and a["chain"]["events"] == n == a["total_events"]
    assert a["chain"]["message"] == "Hash chain verified."
    assert "not proof" in a["chain"]["scope"] and "removed" in a["chain"]["scope"]


def test_a_broken_chain_says_so_without_overclaiming(db):
    p, _ = db
    c = sqlite3.connect(p)
    c.execute("UPDATE events SET payload = REPLACE(payload, 'workspace', 'edited') WHERE seq = 1")
    c.commit()
    c.close()
    with running(p) as app:
        _, a = get_json(app, "/api/d/live/audit?verify=1")
        _, o = get_json(app, "/api/overview")
        _, s = get_json(app, "/api/d/live/sessions")
    assert a["chain"]["ok"] is False and a["chain"]["first_bad_seq"] == 1 and a["chain"]["events"] == 0
    assert a["chain"]["message"] == "Hash-chain verification failed."
    assert o["audit"]["ok"] is False and all(not x["audit"]["chain_ok"] for x in s["sessions"])
    text = json.dumps([a, o, s]).lower()
    assert "tamper" not in text and "immutable" not in text
    assert any(e["broken"] for e in a["latest"])


# ------------------------------------------------------------------ approvals: audit of the existing mechanism, and the dashboard's use of it
def pending(app):
    _, body = get_json(app, "/api/d/live/approvals")
    return body["approvals"]


def test_approvals_list_has_only_holds_and_never_a_deny(db):
    p, ids = db
    with running(p) as app:
        items = pending(app)
    assert {a["id"] for a in items} == {ids["pending"], ids["used"], ids["denied"]}
    assert all(r["code"] != "R-FLOW-CONF" for a in items for r in a["rules"]), (
        "the blocked send has no approval to give"
    )
    by = {a["id"]: a for a in items}
    assert by[ids["pending"]]["state"] == "pending" and by[ids["pending"]]["can_resolve"]
    assert (
        by[ids["used"]]["state"] == "consumed"
        and by[ids["used"]]["used_by_call"] == "c4"
        and not by[ids["used"]]["can_resolve"]
    )
    assert by[ids["denied"]]["state"] == "denied"


def test_approve_through_the_dashboard_then_the_gateway_consumes_it_once(db):
    p, ids = db
    with running(p, policy=str(POLICY_FILE)) as app:
        a = next(x for x in pending(app) if x["id"] == ids["pending"])
        status, out = post_json(
            app, f"/api/approvals/{a['id']}", {"decision": "approve", "fingerprint": a["fingerprint"]}
        )
        assert status == 200 and out["ok"] and out["state"] == "approved"
        assert "must now repeat" in out["message"]
        st = Store(str(p))
        assert st.get_approval(a["id"]).state == "approved" and st.get_approval(a["id"]).resolved_by == "dashboard"
        # the gateway side: the identical call consumes it exactly once
        import asyncio

        async def repeat() -> list:
            gw = make_gateway(load_policy(POLICY_FILE), st, World.from_fixture(FIXTURE))
            await gw.start()
            s = gw.open_session("live-1")
            first = await gw.call_tool_detailed(s, "files__read_file", {"path": "/secrets/payroll.txt"})
            second = await gw.call_tool_detailed(s, "files__read_file", {"path": "/secrets/payroll.txt"})
            return [first, second]

        first, second = asyncio.run(repeat())
        assert first.forwarded and first.approval_id == a["id"]
        assert not second.forwarded and second.approval_id and second.approval_id != a["id"], (
            "single use: the repeat needs a new approval"
        )
        assert st.get_approval(a["id"]).state == "consumed"
        kinds = [e["kind"] for e in st.events("live-1")]
        assert kinds.count("approval.consumed") == 1
        # the human decision itself is in the approvals table, not a chain event (documented limitation)
        assert not [e for e in st.events("live-1") if e["kind"] == "approval.resolve"]
        st.close()


def test_deny_through_the_dashboard_blocks_the_identical_call(db):
    p, ids = db
    import asyncio

    with running(p) as app:
        a = next(x for x in pending(app) if x["id"] == ids["pending"])
        status, out = post_json(app, f"/api/approvals/{a['id']}", {"decision": "deny", "fingerprint": a["fingerprint"]})
        assert status == 200 and out["state"] == "denied" and "R-APPROVAL-DENIED" in out["message"]
    st = Store(str(p))

    async def repeat():
        gw = make_gateway(load_policy(POLICY_FILE), st, World.from_fixture(FIXTURE))
        await gw.start()
        return await gw.call_tool_detailed(
            gw.open_session("live-1"), "files__read_file", {"path": "/secrets/payroll.txt"}
        )

    o = asyncio.run(repeat())
    assert not o.forwarded and "R-APPROVAL-DENIED" in o.codes
    st.close()


def test_stale_double_and_conflicting_decisions_change_nothing(db):
    p, ids = db
    with running(p) as app:
        a = next(x for x in pending(app) if x["id"] == ids["pending"])
        url = f"/api/approvals/{a['id']}"
        # a page that showed something else (stale fingerprint) cannot decide
        status, out = post_json(app, url, {"decision": "approve", "fingerprint": "0" * 16})
        assert status == 409 and out["code"] == "changed"
        assert ReadOnlyStore(str(p)).get_approval(a["id"]).state == "pending"
        assert post_json(app, url, {"decision": "approve", "fingerprint": a["fingerprint"]})[0] == 200
        status, out = post_json(app, url, {"decision": "deny", "fingerprint": a["fingerprint"]})
        assert status == 409 and out["code"] == "approved", "an approved approval cannot be turned into a denial"
        assert post_json(app, url, {"decision": "approve", "fingerprint": a["fingerprint"]})[1]["code"] == "approved"
        # consumed and denied approvals cannot be resolved
        used = next(x for x in pending(app) if x["id"] == ids["used"])
        assert (
            post_json(app, f"/api/approvals/{used['id']}", {"decision": "approve", "fingerprint": used["fingerprint"]})[
                1
            ]["code"]
            == "consumed"
        )
        den = next(x for x in pending(app) if x["id"] == ids["denied"])
        assert (
            post_json(app, f"/api/approvals/{den['id']}", {"decision": "approve", "fingerprint": den["fingerprint"]})[
                1
            ]["code"]
            == "denied"
        )
        assert post_json(app, "/api/approvals/ap_00000000", {"decision": "approve", "fingerprint": "x"})[0] == 404
        assert post_json(app, url, {"decision": "maybe", "fingerprint": a["fingerprint"]})[0] == 400
        assert post_json(app, "/api/approvals/not-an-id", {"decision": "approve"})[0] == 404


def test_an_expired_approval_cannot_be_approved(db):
    p, ids = db
    c = sqlite3.connect(p)
    c.execute("UPDATE approvals SET expires = 1.0 WHERE id = ?", (ids["pending"],))
    c.commit()
    c.close()
    with running(p) as app:
        a = next(x for x in pending(app) if x["id"] == ids["pending"])
        assert a["state"] == "expired" and not a["can_resolve"]
        status, out = post_json(
            app, f"/api/approvals/{a['id']}", {"decision": "approve", "fingerprint": a["fingerprint"]}
        )
        assert status == 409 and out["code"] == "expired"
    assert ReadOnlyStore(str(p)).get_approval(ids["pending"]).state == "pending"


def test_concurrent_decisions_have_exactly_one_winner(db):
    p, ids = db
    with running(p) as app:
        a = next(x for x in pending(app) if x["id"] == ids["pending"])
        results: list[tuple[int, str]] = []
        lock = threading.Lock()

        def go(decision: str) -> None:
            status, _ = post_json(
                app, f"/api/approvals/{a['id']}", {"decision": decision, "fingerprint": a["fingerprint"]}
            )
            with lock:
                results.append((status, decision))

        ts = [threading.Thread(target=go, args=("approve" if i % 2 else "deny",)) for i in range(10)]
        [t.start() for t in ts]
        [t.join() for t in ts]
    winners = [d for s, d in results if s == 200]
    assert len(winners) == 1 and sorted(s for s, _ in results) == [200] + [409] * 9
    assert (
        ReadOnlyStore(str(p)).get_approval(ids["pending"]).state
        == {"approve": "approved", "deny": "denied"}[winners[0]]
    )


def test_an_approval_is_bound_to_the_exact_call_and_the_session(db):
    p, ids = db
    import asyncio

    st = Store(str(p))
    st.resolve_approval(ids["pending"], True, by="cli-user")

    async def go():
        gw = make_gateway(load_policy(POLICY_FILE), st, World.from_fixture(FIXTURE))
        await gw.start()
        s1 = gw.open_session("live-1")
        other_args = await gw.call_tool_detailed(
            s1, "files__read_file", {"path": "/secrets/payroll.txt "}
        )  # not the identical call
        other_session = await gw.call_tool_detailed(
            gw.open_session("live-3"), "files__read_file", {"path": "/secrets/payroll.txt"}
        )
        return other_args, other_session

    a, b = asyncio.run(go())
    assert not a.forwarded and not b.forwarded
    assert st.get_approval(ids["pending"]).state == "approved", "still unused: nothing else could take it"
    st.close()


def test_characterisation_an_approval_does_not_pin_the_rule_set(tmp_path):
    """Documented in docs/dashboard.md. The approval is bound to (session, tool + arguments), not to the rules that fired
    or to the session state. A call approved when only R-DEST-UNTRUSTED fired is consumed on repeat even though R-TRIFECTA now
    fires as well, as long as no deny rule applies."""
    import asyncio

    p = tmp_path / "c.db"
    mail = {"to": "verify@evil.example", "subject": "hello", "body": "see you at five"}

    async def go():
        st = Store(str(p))
        gw = make_gateway(load_policy(POLICY_FILE), st, World.from_fixture(FIXTURE))
        await gw.start()
        s = gw.open_session("c")
        await gw.call_tool_detailed(s, "mail__read_message", {"id": "m1"})
        held = await gw.call_tool_detailed(s, "mail__send_message", mail)
        assert held.codes == ["R-DEST-UNTRUSTED"]
        st.resolve_approval(held.approval_id, True, by="cli-user")
        r = await gw.call_tool_detailed(s, "files__read_file", {"path": "/secrets/payroll.txt"})
        st.resolve_approval(r.approval_id, True, by="cli-user")
        await gw.call_tool_detailed(s, "files__read_file", {"path": "/secrets/payroll.txt"})
        again = await gw.call_tool_detailed(s, "mail__send_message", mail)
        st.close()
        return held, again

    held, again = asyncio.run(go())
    assert again.forwarded and again.approval_id == held.approval_id
    assert "R-TRIFECTA" in again.codes and "R-TRIFECTA" not in held.codes


def test_resolving_is_refused_for_anything_that_is_not_the_live_database(db, tmp_path):
    p, ids = db
    sources.write_manifest(p, sources.SYNTHETIC, scenario="x")
    with running(p) as app:
        a = next(x for x in pending(app) if x["id"] == ids["pending"])
        status, out = post_json(
            app, f"/api/approvals/{a['id']}", {"decision": "approve", "fingerprint": a["fingerprint"]}
        )
        assert status == 403 and out["code"] == "not_live"
    assert ReadOnlyStore(str(p)).get_approval(ids["pending"]).state == "pending"


def test_the_only_write_is_the_gateway_stores_own_resolve_approval(db):
    p, _ = db
    assert ApprovalWriter.resolve_approval is Store.resolve_approval
    w = ApprovalWriter(str(p))
    for call in (
        lambda: w.append_event("s", "k", {}),
        lambda: w.create_approval("s", "h", "t", [], {}, 1.0),
        lambda: w.consume_approval("s", "h"),
        lambda: w.hmac_key(),
    ):
        with pytest.raises(ReadOnlyError):
            call()
    w.close()
    assert actions.BY == "dashboard"
    with pytest.raises(DashboardDBError):
        ApprovalWriter(str(p) + ".missing")


# ------------------------------------------------------------------ redaction
def test_masking_hides_clear_values_and_keeps_digests(db):
    p, _ = db
    with running(p) as app:
        _, plain = get_json(app, "/api/d/live/sessions/live-2?mask=0")
        _, masked = get_json(app, "/api/d/live/sessions/live-2?mask=1")
        _, ap = get_json(app, "/api/d/live/approvals?mask=1")
    assert "verify@evil.example" in json.dumps(plain) and "/secrets/payroll.txt" in json.dumps(plain)
    text = json.dumps([masked, ap])
    assert (
        "verify@evil.example" not in text
        and "evil.example" not in text
        and "payroll" not in text
        and "docs.example" not in text
    )
    c5 = next(c for c in masked["calls"] if c["call"] == "c5")
    to = next(a for a in c5["args"] if a["name"] == "to")
    assert to["masked"] and to["text"] == "v•••@•••.example"
    body = next(a for a in c5["args"] if a["name"] == "body")
    assert body["kind"] == "digest" and "masked" not in body


def test_mask_text_shapes():
    from weir_dashboard.redact import mask_text

    assert mask_text("alice@corp.example") == "a•••@•••.example"
    assert mask_text("https://evil.example/a/b?x=1") == "https://e•••.example/•••"
    assert mask_text("/secrets/db.txt") == "/secrets/•••"
    assert mask_text("hello world") == "h••• (11 chars)"
    assert mask_text("a@x.example, b@y.example") == "a•••@•••.example, b•••@•••.example"


# ------------------------------------------------------------------ confidentiality
def test_no_api_response_carries_the_integrity_key_tracker_state_or_content(db):
    p, _ = db
    key = sqlite3.connect(p).execute("SELECT value FROM meta WHERE key='hmac_key'").fetchone()[0]
    tracker = [bytes(r[0]) for r in sqlite3.connect(p).execute("SELECT tracker FROM sessions") if r[0]]
    blobs = [bytes(r[0]) for r in sqlite3.connect(p).execute("SELECT blob FROM tracker_deltas")]
    macs = [r[0] for r in sqlite3.connect(p).execute("SELECT mac, tracker_sha FROM sessions")]
    assert key and blobs
    with running(p, policy=str(POLICY_FILE)) as app:
        seen = []
        for path in (
            "overview",
            "rules",
            "policy",
            "d/live/sessions",
            "d/live/approvals",
            "d/live/audit?limit=1000",
            "d/live/sessions/live-1",
            "d/live/sessions/live-2",
            "d/live/sessions/live-3",
            "config",
            "pulse",
        ):
            status, _, body = request(app, f"/api/{path}")
            assert status == 200
            seen.append(body)
        status, _, page = request(app, "/")
        seen.append(page)
    blob = b"\n".join(seen)
    assert key.encode() not in blob
    for b in tracker + blobs:
        assert b.hex().encode() not in blob and b[:24] not in blob
    for m in macs:
        assert m.encode() not in blob
    for needle in (SECRET, "sk_live_9fA3xQ72LmZ8", "PAYROLL_API_KEY"):
        assert needle.encode() not in blob, needle
    assert SENDMAIL["body"].encode() not in blob


def test_policy_view_does_not_show_command_lines_or_environment_values(tmp_path):
    text = POLICY_FILE.read_text()
    assert "[upstreams.mail]" in text
    pol = tmp_path / "p.toml"
    pol.write_text(text.replace("[upstreams.mail]", '[upstreams.mail]\nenv = { API_TOKEN = "hunter2-do-not-show" }', 1))
    load_policy(pol)  # the edited file is a valid policy
    db = tmp_path / "w.db"
    Store(str(db)).close()
    with running(db, policy=str(pol)) as app:
        _, body = get_json(app, "/api/policy")
    t = json.dumps(body)
    assert "hunter2" not in t and "weir_testbed" not in t
    mail = next(u for u in body["policy"]["upstreams"] if u["name"] == "mail")
    assert mail["env_names"] == ["API_TOKEN"]
    assert all(set(u) == {"name", "program", "args", "env_names"} for u in body["policy"]["upstreams"])


def test_policy_and_lock_views_are_derived_from_the_files(db, tmp_path):
    p, _ = db
    lock = tmp_path / "tools.lock.json"
    lock.write_text(json.dumps({"version": 1, "tools": {"mail__send_message": "ab" * 32}}))
    with running(p, policy=str(POLICY_FILE), lock=str(lock)) as app:
        _, body = get_json(app, "/api/policy")
    pol = load_policy(POLICY_FILE)
    assert body["policy"]["digest_full"] == pol.digest and len(body["policy"]["tools"]) == len(pol.tools)
    assert body["matches_recorded"] and all(body["matches_recorded"])
    assert (
        body["lock"]["ok"]
        and "mail__send_message" not in body["lock"]["declared_not_pinned"]
        and body["lock"]["declared_not_pinned"]
    )
    with running(p) as app:
        _, none = get_json(app, "/api/policy")
    assert none["loaded"] is False and none["lock"] == {"supplied": False}
    with running(p, policy=str(tmp_path / "missing.toml")) as app:
        _, bad = get_json(app, "/api/policy")
    assert bad["loaded"] is False and bad["error"]
