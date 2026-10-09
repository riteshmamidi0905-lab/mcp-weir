"""The local HTTP server: standard library only, bound to 127.0.0.1, same-origin, no CORS.

Threat model (docs/dashboard.md has the long form): a page in the same browser could try to (1) read the API from another
origin, (2) post an approval from another origin, (3) reach the server under another hostname (DNS rebinding), or (4) the
operator could bind it somewhere reachable by mistake. Defences here: the listening socket is only ever created on
127.0.0.1 (there is no option to change it); every request's Host must be 127.0.0.1:<port> or localhost:<port>; a POST
needs a matching Origin, ``application/json``, ``Sec-Fetch-Site: same-origin`` when the browser sends it, and a per-process
random token that only the served page contains; no response carries CORS headers; a strict Content-Security-Policy.
"""

from __future__ import annotations

import hmac
import json
import re
import secrets
import sqlite3
import sys
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from mcp_weir.policy import Policy, PolicyError, load_policy

from . import ANSWER_CHANNEL_NOTE, actions, demo, model, rules
from .readonly import DashboardDBError, ReadOnlyStore

HOST = "127.0.0.1"
STATIC_NAME = re.compile(r"^[a-z0-9-]+\.(js|css)$")
STATIC_TYPES = {"js": "text/javascript; charset=utf-8", "css": "text/css; charset=utf-8"}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}
DATASET = re.compile(r"^(live|demo\.[a-z]+-[0-9a-f]{6}\.(?:strict|careless))$")
SESSION_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
APPROVAL_ID = re.compile(r"^ap_[0-9a-f]{8}$")
MAX_BODY = 4096


class App:
    def __init__(self, db: str, policy: str | None, lock: str | None, mask: bool, demo_dir: Path) -> None:
        self.live = model.Dataset("live", db, writable=True, title="Local database")
        self.policy_path, self.lock_path, self.mask_default, self.demo_dir = policy, lock, mask, demo_dir
        self.token = secrets.token_urlsafe(32)
        self.port = 0
        self._demo: dict[str, model.Dataset] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ datasets
    def dataset(self, ds_id: str) -> model.Dataset | None:
        if ds_id == "live":
            return self.live
        m = re.match(r"^demo\.([a-z]+-[0-9a-f]{6})\.(strict|careless)$", ds_id)
        if not m:
            return None
        d = demo.run_dir(self.demo_dir, m.group(1))
        if d is None:
            return None
        with self._lock:
            if ds_id not in self._demo:
                self._demo[ds_id] = model.Dataset(
                    ds_id, str(d / f"weir-{m.group(2)}.db"), writable=False, title=f"Demo {m.group(1)}"
                )
            return self._demo[ds_id]

    def load_policy(self) -> tuple[Policy | None, str | None]:
        if not self.policy_path:
            return None, None
        try:
            return load_policy(self.policy_path), None
        except (PolicyError, OSError, ValueError) as e:
            return None, f"{type(e).__name__}: {str(e)[:200]}"

    def allowed_hosts(self) -> set[str]:
        return {f"127.0.0.1:{self.port}", f"localhost:{self.port}"}

    def allowed_origins(self) -> set[str]:
        return {f"http://{h}" for h in self.allowed_hosts()}


def make_handler(app: App) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "WeirControlCenter"
        sys_version = ""

        # ---------------------------------------------------------------- plumbing
        def log_message(self, fmt: str, *args: Any) -> None:
            """Only decisions (POST) and refusals (status 400 and up) are logged: polling would otherwise fill the terminal."""
            status = str(args[1]) if len(args) > 1 else ""
            if self.command == "POST" or status[:1] in ("4", "5"):
                print(f"weir-dashboard: {self.command} {urlsplit(self.path).path} -> {status}", file=sys.stderr)

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, obj: Any) -> None:
            self._send(
                status,
                json.dumps(obj, separators=(",", ":"), allow_nan=False).encode(),
                "application/json; charset=utf-8",
            )

        def _error(self, status: int, code: str, message: str) -> None:
            self._json(status, {"error": {"state": code, "message": message}})

        def _guard(self, post: bool) -> bool:
            if self.headers.get("Host") not in app.allowed_hosts():
                self._error(403, "host", "Unexpected Host header.")
                return False
            sfs = self.headers.get("Sec-Fetch-Site")
            if sfs is not None and sfs not in ("same-origin", "none"):
                self._error(403, "origin", "Cross-site request refused.")
                return False
            if post:
                if self.headers.get("Origin") not in app.allowed_origins():
                    self._error(403, "origin", "Missing or unexpected Origin.")
                    return False
                if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                    self._error(415, "type", "Content-Type must be application/json.")
                    return False
                if not hmac.compare_digest(self.headers.get("X-Weir-Token", ""), app.token):
                    self._error(403, "token", "Missing or wrong token. Reload the page.")
                    return False
            return True

        def _body(self) -> dict[str, Any] | None:
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if not 0 < n <= MAX_BODY:
                    raise ValueError
                data = json.loads(self.rfile.read(n))
                if not isinstance(data, dict):
                    raise ValueError
                return data
            except (ValueError, TypeError):
                self._error(400, "bad_request", "Expected a small JSON object.")
                return None

        def do_OPTIONS(self) -> None:
            self._error(405, "method", "No cross-origin access.")

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS

        # ---------------------------------------------------------------- GET
        def do_HEAD(self) -> None:
            self.do_GET()

        def _internal(self, e: BaseException) -> None:
            print(f"weir-dashboard: internal error {type(e).__name__}", file=sys.stderr)
            self._error(500, "internal", "The dashboard hit an unexpected error. Nothing was changed.")

        def do_GET(self) -> None:
            if not self._guard(False):
                return
            u = urlsplit(self.path)
            q = parse_qs(u.query)
            path = u.path
            if path == "/":
                html = (resources.files("weir_dashboard") / "static" / "index.html").read_text(encoding="utf-8")
                html = html.replace("__TOKEN__", app.token).replace("__ANSWER_NOTE__", ANSWER_CHANNEL_NOTE)
                html = html.replace("__MASK_DEFAULT__", "1" if app.mask_default else "0")
                self._send(200, html.encode(), "text/html; charset=utf-8")
                return
            if path.startswith("/static/"):
                name = path[len("/static/") :]
                f = resources.files("weir_dashboard") / "static" / name
                if not STATIC_NAME.match(name) or not f.is_file():
                    self._error(404, "missing", "Not found.")
                    return
                self._send(200, f.read_bytes(), STATIC_TYPES[name.rsplit(".", 1)[1]])
                return
            if not path.startswith("/api/"):
                self._error(404, "missing", "Not found.")
                return
            try:
                self._api(path[5:], q)
            except DashboardDBError as e:
                self._error(503, e.state, e.message)
            except sqlite3.Error as e:
                self._error(503, "db", f"The database could not be read ({type(e).__name__}).")
            except Exception as e:  # last resort: answer with JSON, never a traceback
                self._internal(e)

        def _mask(self, q: dict[str, list[str]]) -> bool:
            v = q.get("mask", [None])[0]
            return app.mask_default if v is None else v == "1"

        def _api(self, route: str, q: dict[str, list[str]]) -> None:
            mask = self._mask(q)
            parts = route.split("/")
            if route == "health":
                self._json(200, {"ok": True, "bind": f"{HOST}:{app.port}"})
            elif route == "config":
                self._json(
                    200,
                    {
                        "mask_default": app.mask_default,
                        "answer_channel_note": ANSWER_CHANNEL_NOTE,
                        "policy_supplied": app.policy_path is not None,
                        "lock_supplied": app.lock_path is not None,
                        "db_name": Path(app.live.path).name,
                        "port": app.port,
                    },
                )
            elif route == "pulse":
                try:
                    st = app.live.open()
                    try:
                        live: dict[str, Any] = {"state": "ok", "stamp": st.stamp()}
                    finally:
                        st.close()
                except DashboardDBError as e:
                    live = {"state": e.state}
                self._json(200, {"live": live, "demo_runs": len(demo.list_runs(app.demo_dir))})
            elif route == "overview":
                self._with_store(app.live, lambda st: model.overview(app.live, st, mask, q.get("verify") == ["1"]))
            elif route == "rules":
                self._rules()
            elif route == "policy":
                policy, err = app.load_policy()
                snap = None
                try:
                    st = app.live.open()
                    try:
                        snap = app.live.snapshot(st)
                    finally:
                        st.close()
                except DashboardDBError:
                    pass
                self._json(200, model.policy_view(policy, err, app.lock_path, snap))
            elif route == "demo":
                self._json(
                    200,
                    {
                        "runs": demo.list_runs(app.demo_dir),
                        "synthetic_available": demo.synthetic_available(),
                        "recorded_available": demo.recording_available(),
                        "answer_channel_note": ANSWER_CHANNEL_NOTE,
                    },
                )
            elif parts[0] == "d" and len(parts) >= 3 and DATASET.match(parts[1]):
                ds = app.dataset(parts[1])
                if ds is None:
                    self._error(404, "missing", "No such dataset.")
                elif parts[2] == "sessions" and len(parts) == 3:
                    self._with_store(ds, lambda st: model.sessions_list(ds, st, mask))
                elif parts[2] == "sessions" and len(parts) == 4 and SESSION_ID.match(parts[3]):

                    def one(st: ReadOnlyStore) -> Any:
                        d = model.session_detail(ds, st, parts[3], mask)
                        return (
                            d
                            if d is not None
                            else ({"error": {"state": "missing", "message": "No such session."}}, 404)
                        )

                    self._with_store(ds, one)
                elif parts[2] == "approvals" and len(parts) == 3:
                    self._with_store(ds, lambda st: model.approvals_list(ds, st, mask))
                elif parts[2] == "audit" and len(parts) == 3:
                    sid = q.get("session", [None])[0]
                    lim = (
                        min(1000, max(1, int(q.get("limit", ["200"])[0] or 200)))
                        if q.get("limit", ["200"])[0].isdigit()
                        else 200
                    )
                    self._with_store(
                        ds,
                        lambda st: model.audit_view(
                            ds, st, sid if sid and SESSION_ID.match(sid) else None, lim, q.get("verify") == ["1"]
                        ),
                    )
                else:
                    self._error(404, "missing", "Not found.")
            else:
                self._error(404, "missing", "Not found.")

        def _with_store(self, ds: model.Dataset, fn: Any) -> None:
            st = ds.open()
            try:
                out = fn(st)
            finally:
                st.close()
            if isinstance(out, tuple):
                self._json(out[1], out[0])
            else:
                self._json(200, out)

        def _rules(self) -> None:
            policy, err = app.load_policy()
            fired: dict[str, Counter[str]] = {}
            try:
                st = app.live.open()
                try:
                    snap = app.live.snapshot(st)
                finally:
                    st.close()
                for ev in snap.events:
                    if ev["kind"] == "call.decision" and not ev["malformed"]:
                        for h in ev["payload"].get("rules", []):
                            if isinstance(h, dict):
                                fired.setdefault(str(h.get("code")), Counter())[
                                    rules.verdict_ui(str(h.get("verdict")))
                                ] += 1
            except DashboardDBError:
                pass
            items = []
            for code in list(rules.CATALOGUE) + sorted(set(fired) - set(rules.CATALOGUE)):
                items.append(
                    {
                        **rules.describe(code, policy),
                        "fired": dict(fired.get(code, {})),
                        "fired_total": sum(fired.get(code, {}).values()),
                    }
                )
            self._json(
                200,
                {
                    "rules": items,
                    "policy_error": err,
                    "configured_from": "policy file" if policy else "gateway defaults",
                },
            )

        # ---------------------------------------------------------------- POST
        def do_POST(self) -> None:
            if not self._guard(True):
                return
            try:
                self._post()
            except Exception as e:  # last resort: answer with JSON, never a traceback
                self._internal(e)

        def _post(self) -> None:
            path = urlsplit(self.path).path
            body = self._body()
            if body is None:
                return
            if path.startswith("/api/approvals/"):
                aid = path[len("/api/approvals/") :]
                if not APPROVAL_ID.match(aid):
                    self._error(404, "missing", "No such approval.")
                    return
                status, out = actions.resolve(
                    app.live, aid, str(body.get("decision", "")), str(body.get("fingerprint", ""))
                )
                self._json(status, out)
            elif path == "/api/demo/load":
                kind = str(body.get("kind", ""))
                try:
                    self._json(200, demo.build(kind, app.demo_dir))
                except FileNotFoundError as e:
                    self._error(404, "recording", str(e))
                except ValueError as e:
                    self._error(400, "bad_request", str(e))
                except Exception as e:
                    self._internal(e)
            else:
                self._error(404, "missing", "Not found.")

    return Handler


def create_server(app: App, port: int) -> ThreadingHTTPServer:
    """Only ever loopback; there is deliberately no host parameter."""
    srv = ThreadingHTTPServer((HOST, port), make_handler(app))
    srv.daemon_threads = True
    if srv.server_address[0] != HOST:  # pragma: no cover - defensive
        srv.server_close()
        raise RuntimeError("refusing to listen on anything but 127.0.0.1")
    app.port = srv.server_address[1]
    return srv
