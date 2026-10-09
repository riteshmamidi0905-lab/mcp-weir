"""Server-side defences, source labelling and the demo loader."""

from __future__ import annotations

import inspect
import json
import re
import socket
from pathlib import Path

import pytest
from dashboard_helpers import get_json, post_json, request, running, seed

from mcp_weir.store import Store
from weir_dashboard import cli, demo, server, sources
from weir_dashboard.readonly import ReadOnlyStore

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "src" / "weir_dashboard" / "static"


@pytest.fixture
def db(tmp_path):
    p = tmp_path / "weir.db"
    ids = seed(p)
    return p, ids


# ------------------------------------------------------------------ localhost only
def test_the_server_listens_on_loopback_only_and_has_no_way_to_change_that(db):
    p, _ = db
    with running(p) as app:
        assert app.port > 0
    srv = server.create_server(server.App(str(p), None, None, False, Path("/nonexistent")), 0)
    try:
        assert srv.server_address[0] == "127.0.0.1" and srv.socket.getsockname()[0] == "127.0.0.1"
    finally:
        srv.server_close()
    assert "host" not in inspect.signature(server.create_server).parameters
    assert server.HOST == "127.0.0.1"
    for flag in ("--host", "--bind", "--listen"):
        with pytest.raises(SystemExit) as e:
            cli.main([flag, "0.0.0.0", "--port", "0"])
        assert e.value.code == 2
    src = (ROOT / "src" / "weir_dashboard" / "server.py").read_text() + (
        ROOT / "src" / "weir_dashboard" / "cli.py"
    ).read_text()
    assert "0.0.0.0" not in src


def test_the_cli_refuses_a_port_in_use_and_a_bad_port(db, tmp_path, capsys):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    port = s.getsockname()[1]
    try:
        assert cli.main(["--db", str(db[0]), "--port", str(port), "--demo-dir", str(tmp_path)]) == 2
    finally:
        s.close()
    assert "cannot listen" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["--port", "70000"])


# ------------------------------------------------------------------ request validation
def test_other_host_names_are_refused(db):
    p, _ = db
    with running(p) as app:
        for host in (
            "evil.example",
            f"evil.example:{app.port}",
            f"127.0.0.1.evil.example:{app.port}",
            "127.0.0.1",
            f"0.0.0.0:{app.port}",
            "",
        ):
            status, _, _ = request(app, "/api/overview", headers={"Host": host})
            assert status == 403, host
            status, _, _ = request(app, "/", headers={"Host": host})
            assert status == 403, host
        assert request(app, "/api/overview", headers={"Host": f"localhost:{app.port}"})[0] == 200


def test_cross_site_browser_requests_are_refused(db):
    p, _ = db
    with running(p) as app:
        assert request(app, "/api/overview", headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
        assert request(app, "/api/overview", headers={"Sec-Fetch-Site": "same-site"})[0] == 403
        assert request(app, "/api/overview", headers={"Sec-Fetch-Site": "same-origin"})[0] == 200


def test_approving_needs_origin_token_content_type_and_a_small_json_body(db):
    p, ids = db
    with running(p) as app:
        a = next(x for x in get_json(app, "/api/d/live/approvals")[1]["approvals"] if x["id"] == ids["pending"])
        body = {"decision": "approve", "fingerprint": a["fingerprint"]}
        url = f"/api/approvals/{a['id']}"
        assert post_json(app, url, body, origin=None)[0] == 403
        assert post_json(app, url, body, origin="http://evil.example")[0] == 403
        assert post_json(app, url, body, origin=f"http://127.0.0.1:{app.port + 1}")[0] == 403
        assert post_json(app, url, body, origin="null")[0] == 403
        assert post_json(app, url, body, token=None)[0] == 403
        assert post_json(app, url, body, token="wrong")[0] == 403
        assert post_json(app, url, body, ctype="text/plain")[0] == 415
        assert post_json(app, url, body, ctype="application/x-www-form-urlencoded")[0] == 415
        status, _, _ = request(
            app,
            url,
            method="POST",
            raw=b"x" * 5000,
            headers={"Content-Type": "application/json", "Origin": app.base, "X-Weir-Token": app.token},
        )
        assert status == 400
        status, _, _ = request(
            app,
            url,
            method="POST",
            raw=b"[1]",
            headers={"Content-Type": "application/json", "Origin": app.base, "X-Weir-Token": app.token},
        )
        assert status == 400
        status, _, _ = request(
            app,
            url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Origin": app.base,
                "X-Weir-Token": app.token,
                "Sec-Fetch-Site": "cross-site",
            },
            raw=json.dumps(body).encode(),
        )
        assert status == 403
        # none of the refused attempts changed anything
        assert ReadOnlyStore(str(p)).get_approval(ids["pending"]).state == "pending"
        # a GET can never resolve anything
        assert request(app, url)[0] == 404
        assert post_json(app, url, body, origin=f"http://localhost:{app.port}")[0] == 200


def test_every_response_has_the_security_headers_and_none_has_cors(db):
    p, _ = db
    with running(p) as app:
        for path in ("/", "/api/overview", "/static/app.js", "/static/app.css", "/api/nope", "/nothing"):
            status, h, _ = request(app, path)
            low = {k.lower(): v for k, v in h.items()}
            assert (
                low["content-security-policy"].startswith("default-src 'none'")
                and "script-src 'self'" in low["content-security-policy"]
            )
            assert (
                "unsafe-inline" not in low["content-security-policy"]
                and "unsafe-eval" not in low["content-security-policy"]
            )
            assert (
                low["x-content-type-options"] == "nosniff"
                and low["referrer-policy"] == "no-referrer"
                and low["cache-control"] == "no-store"
            )
            assert not any(k.startswith("access-control-") for k in low), path
        for method in ("OPTIONS", "PUT", "DELETE", "PATCH"):
            status, h, _ = request(app, "/api/overview", method=method)
            assert status == 405 and not any(k.lower().startswith("access-control-") for k in h)


def test_each_run_has_its_own_token_and_the_page_carries_it(db):
    p, _ = db
    with running(p) as a1, running(p) as a2:
        t1 = re.search(r'name="weir-token" content="([^"]+)"', request(a1, "/")[2].decode()).group(1)
        t2 = re.search(r'name="weir-token" content="([^"]+)"', request(a2, "/")[2].decode()).group(1)
        assert t1 == a1.token and t2 == a2.token and t1 != t2 and len(t1) >= 40
        # a token from one run does not work on another
        assert post_json(a1, "/api/demo/load", {"kind": "synthetic"}, token=t2)[0] == 403
        assert t1 not in request(a1, "/static/app.js")[2].decode()


def test_static_files_are_a_closed_list_and_nothing_traverses(db):
    p, _ = db
    with running(p) as app:
        assert request(app, "/static/app.js")[0] == 200 and request(app, "/static/dom.js")[0] == 200
        for bad in (
            "/static/index.html",
            "/static/../server.py",
            "/static/%2e%2e/server.py",
            "/static/..%2fserver.py",
            "/static/",
            "/static/x.py",
            "/static/.env",
            "//etc/passwd",
            "/..",
            "/api/../static/app.js",
        ):
            status = request(app, bad)[0]
            assert status in (403, 404), bad
        assert request(app, "/static/app.js")[2].startswith(b"import ")


def test_the_served_files_make_no_external_requests_and_never_build_html_from_data():
    files = {f.name: f.read_text() for f in STATIC.iterdir() if f.suffix in (".js", ".css", ".html")}
    for name, text in files.items():
        stripped = text.replace("http://www.w3.org/2000/svg", "")
        assert not re.search(r"https?://", stripped), name
        assert not re.search(
            r"@import|url\(\s*['\"]?https?:|<script[^>]*src=\"http|\bXMLHttpRequest\b|\bWebSocket\b|\bsendBeacon\b|\bEventSource\b|\beval\(|new Function|document\.write",
            text,
        ), name
        assert "localStorage" not in text or name in ("api.js",), name
    inner = [n for n, t in files.items() if "innerHTML" in t or "outerHTML" in t or "insertAdjacentHTML" in t]
    assert inner == ["dom.js"], "the only HTML-from-a-string is the icon table, which is a constant"
    assert files["dom.js"].count("innerHTML") == 1
    fetches = re.findall(r"fetch\(([^,)]*)", files["api.js"])
    assert all(f.strip().startswith("`/api/") for f in fetches)
    html = files["index.html"]
    assert "unpkg" not in html and '<link rel="stylesheet" href="/static/app.css">' in html and "style=" not in html


def test_the_api_never_serves_anything_that_is_not_json_or_the_fixed_page(db):
    p, _ = db
    with running(p) as app:
        for path in (
            "/api/health",
            "/api/config",
            "/api/overview",
            "/api/pulse",
            "/api/d/live/sessions",
            "/api/d/bad/sessions",
            "/api/d/live/sessions/%00",
            "/api/d/live/sessions/" + "a" * 100,
            "/api/d/live/audit?limit=abc",
        ):
            status, h, body = request(app, path)
            assert h["Content-Type"].startswith("application/json"), path
            json.loads(body)
            assert status in (200, 404, 503), (path, status)
        assert get_json(app, "/api/d/live/sessions/nope")[0] == 404


# ------------------------------------------------------------------ source labelling
def test_a_database_with_no_source_file_is_labelled_as_a_local_session(db):
    p, _ = db
    with running(p) as app:
        _, body = get_json(app, "/api/d/live/sessions")
    assert {s["source"]["kind"] for s in body["sessions"]} == {"live-local"}
    assert {s["source"]["label"] for s in body["sessions"]} == {"LIVE LOCAL SESSION"}  # events just written


def test_an_old_local_session_is_idle_not_live():
    info = sources.classify(None, "s", last_activity=1000.0, now=1000.0 + sources.LIVE_WINDOW_S + 1)
    assert info.kind == "live-local" and not info.live and info.label == "LOCAL SESSION · IDLE"
    assert sources.classify(None, "s", last_activity=1000.0, now=1001.0).live


@pytest.mark.parametrize(
    "kind,label", [(sources.RECORDED, "RECORDED REAL-MODEL REPLAY"), (sources.SYNTHETIC, "SYNTHETIC DEMO")]
)
def test_a_recorded_or_synthetic_database_is_never_shown_as_live(db, kind, label):
    p, _ = db
    sources.write_manifest(p, kind, scenario="s")
    with running(p) as app:
        _, body = get_json(
            app, "/api/d/live/sessions"
        )  # events were written a moment ago: recency must not make them live
        _, o = get_json(app, "/api/overview")
    for s in body["sessions"]:
        assert s["source"]["kind"] == kind and s["source"]["label"] == label and s["source"]["live"] is False
        assert "LIVE" not in s["source"]["label"]
    assert o["sessions"]["by_source"] == {kind: 3}


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        "[]",
        '{"format": 2, "source": "synthetic-demo"}',
        '{"format": 1, "source": "live-local"}',
        '{"format": 1, "source": "anything"}',
        "",
    ],
)
def test_an_unreadable_source_file_is_never_read_as_live(db, content):
    p, _ = db
    sources.manifest_path(p).write_text(content)
    with running(p) as app:
        _, body = get_json(app, "/api/d/live/sessions")
    assert {s["source"]["kind"] for s in body["sessions"]} == {"unknown"} and all(
        not s["source"]["live"] for s in body["sessions"]
    )
    assert "LIVE" not in {s["source"]["label"] for s in body["sessions"]}.pop()


def test_live_is_not_a_source_anyone_can_write():
    with pytest.raises(ValueError):
        sources.write_manifest("x.db", sources.LIVE)


def test_the_demo_script_marks_its_databases_and_the_dashboard_reads_the_mark(tmp_path, capsys):
    from weir_eval import demo as eval_demo

    eval_demo.main(["--out", str(tmp_path / "s")])
    eval_demo.main(["--replay", str(ROOT / "demo" / "recorded" / "f1-web.json"), "--out", str(tmp_path / "r")])
    capsys.readouterr()
    for d, kind in (("s", sources.SYNTHETIC), ("r", sources.RECORDED)):
        for arm in ("strict", "careless"):
            m = sources.read_manifest(tmp_path / d / f"weir-{arm}.db")
            assert m and m["source"] == kind and f"demo-{arm}" in m["sessions"]
        with running(tmp_path / d / "weir-careless.db") as app:
            _, body = get_json(app, "/api/d/live/sessions")
        assert [s["source"]["kind"] for s in body["sessions"]] == [kind]
        assert body["sessions"][0]["approver_kinds"] == ["auto (a programmatic approver, not a person)"]


# ------------------------------------------------------------------ demo loader
def test_the_synthetic_demo_is_computed_by_the_gateway_and_kept_apart(db, tmp_path):
    p, _ = db
    with running(p, demo_dir=tmp_path / "demos") as app:
        status, run = post_json(app, "/api/demo/load", {"kind": "synthetic"})
        assert status == 200 and run["label"] == "SYNTHETIC DEMO"
        arms = {a["key"]: a for a in run["arms"]}
        assert [a["title"] for a in run["arms"]] == [
            "NO GATEWAY",
            "WEIR + CAREFUL SIMULATED APPROVER",
            "WEIR + APPROVE-EVERYTHING SIMULATED APPROVER",
        ]
        assert (
            arms["A0"]["gateway"] is False
            and arms["A0"]["dataset"] is None
            and arms["A0"]["attacker_got_secret"] is True
        )
        assert arms["strict"]["attacker_got_secret"] is False and arms["careless"]["attacker_got_secret"] is False
        assert "simulated" in arms["strict"]["approver"] and "simulated" in arms["careless"]["approver"]
        # decisions come out of the real gateway's audit log for each arm
        _, strict = get_json(app, f"/api/d/{arms['strict']['dataset']}/sessions/demo-strict")
        _, careless = get_json(app, f"/api/d/{arms['careless']['dataset']}/sessions/demo-careless")
        assert [c["verdict"] for c in strict["calls"]] == ["ALLOW", "DENY", "DENY"]
        assert strict["calls"][1]["path"] == "Held, approver declined, blocked" and "R-APPROVAL-DENIED" in [
            h["code"] for h in strict["calls"][1]["rules"]
        ]
        assert [c["verdict"] for c in careless["calls"]] == ["ALLOW", "HOLD", "DENY"]
        assert careless["calls"][1]["path"] == "Held, approver approved, ran"
        assert [h["code"] for h in careless["calls"][2]["rules"]] == ["R-DEST-UNTRUSTED", "R-FLOW-CONF", "R-TRIFECTA"]
        for d in (strict, careless):
            assert d["summary"]["source"]["kind"] == "synthetic-demo" and d["summary"]["source"]["live"] is False
        # never mixed with the live database
        _, live = get_json(app, "/api/d/live/sessions")
        assert {s["id"] for s in live["sessions"]} == {"live-1", "live-2", "live-3"}
        assert get_json(app, f"/api/d/{arms['strict']['dataset']}/approvals")[1]["writable"] is False
        # and nothing can be approved there
        assert post_json(app, "/api/approvals/ap_00000000", {"decision": "approve", "fingerprint": "x"})[0] == 404
        assert [r["id"] for r in get_json(app, "/api/demo")[1]["runs"]] == [run["id"]]


def test_the_recorded_replay_is_labelled_as_recorded_and_still_computed_by_the_gateway(db, tmp_path):
    p, _ = db
    with running(p, demo_dir=tmp_path / "demos") as app:
        status, run = post_json(app, "/api/demo/load", {"kind": "recorded"})
        assert (
            status == 200
            and run["label"] == "RECORDED REAL-MODEL REPLAY"
            and "recorded from a local run" in run["agent"]
        )
        arms = {a["key"]: a for a in run["arms"]}
        assert arms["A0"]["attacker_got_secret"] is True and not arms["strict"]["attacker_got_secret"]
        _, d = get_json(app, f"/api/d/{arms['careless']['dataset']}/sessions/demo-careless")
        assert d["summary"]["source"]["kind"] == "recorded-replay" and not d["summary"]["source"]["live"]
        assert post_json(app, "/api/demo/load", {"kind": "nonsense"})[0] == 400
        assert post_json(app, "/api/demo/load", {"kind": "synthetic"}, origin=None)[0] == 403


def test_a_demo_run_directory_that_was_not_made_by_the_loader_is_not_served(db, tmp_path):
    p, _ = db
    with running(p, demo_dir=tmp_path / "demos") as app:
        assert get_json(app, "/api/d/demo.synthetic-abcdef.strict/sessions")[0] == 404
        assert get_json(app, "/api/d/demo.../sessions")[0] == 404
        assert get_json(app, "/api/d/demo.synthetic-abcdef.other/sessions")[0] == 404


def test_loading_the_demo_does_not_touch_the_live_database(db, tmp_path):
    p, _ = db
    import sqlite3

    def dump() -> list[str]:
        c = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        try:
            return list(c.iterdump())
        finally:
            c.close()

    before = dump()
    with running(p, demo_dir=tmp_path / "demos") as app:
        post_json(app, "/api/demo/load", {"kind": "synthetic"})
    assert dump() == before


# ------------------------------------------------------------------ separation from the evaluated code
def test_nothing_the_evaluation_froze_imports_the_dashboard():
    from weir_eval import freeze

    for rel in freeze.compute()["files"]:
        f = ROOT / rel
        if f.suffix == ".py":
            assert "weir_dashboard" not in f.read_text(), rel
    assert not any("weir_dashboard" in line for line in (ROOT / "eval" / "FREEZE.json").read_text().splitlines())


def test_the_dashboard_adds_no_third_party_dependency():
    stdlib = set(__import__("sys").stdlib_module_names)
    allowed = {"mcp_weir", "weir_eval", "weir_testbed", "weir_dashboard"}
    for f in (ROOT / "src" / "weir_dashboard").glob("*.py"):
        for line in f.read_text().splitlines():
            m = re.match(r"^(?:from|import)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if m:
                assert m.group(1) in stdlib | allowed | {"__future__"}, (f.name, line)


def test_opening_a_database_through_the_dashboard_does_not_create_wal_files_for_a_missing_db(tmp_path):
    p = tmp_path / "absent.db"
    with running(p) as app:
        request(app, "/api/overview")
        request(app, "/api/pulse")
    assert list(tmp_path.iterdir()) == []


def test_a_gateway_and_the_dashboard_can_use_one_database_at_the_same_time(db):
    """The gateway keeps writing while pages poll; readers see a consistent chain."""
    import threading

    p, _ = db
    st = Store(str(p))
    stop = threading.Event()
    seen = []

    def write() -> None:
        i = 0
        while not stop.is_set() and i < 150:
            st.append_event("live-1", "policy.unmatched_tool", {"tool": f"t{i}"})
            i += 1

    t = threading.Thread(target=write)
    with running(p) as app:
        t.start()
        for _ in range(25):
            status, o = get_json(app, "/api/overview?verify=1")
            assert status == 200
            seen.append(o["audit"]["ok"])
        stop.set()
        t.join()
    st.close()
    assert all(seen)


def test_an_unexpected_error_is_answered_with_json_and_leaks_no_traceback(db, monkeypatch):
    p, _ = db

    def boom(*a, **k):
        raise RuntimeError("secret internal detail /Users/someone/path")

    monkeypatch.setattr(demo, "build", boom)
    monkeypatch.setattr("weir_dashboard.model.overview", boom)
    with running(p) as app:
        status, out = post_json(app, "/api/demo/load", {"kind": "synthetic"})
        assert status == 500 and out["error"]["state"] == "internal"
        status, _, body = request(app, "/api/overview")
        assert (
            status == 500
            and b"Traceback" not in body
            and b"secret internal detail" not in body
            and b"/Users/" not in body
        )
        assert request(app, "/api/pulse")[0] == 200, "the server keeps serving"
