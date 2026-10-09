"""Command line: run the gateway, pin tool definitions, manage approvals, verify and explain the audit trail."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
import time
from typing import Any

from .gateway import Gateway
from .pinning import definition_hash, load_lock, write_lock
from .policy import PolicyError, load_policy
from .report import build_records, fmt_arg, render_html, render_text
from .server import serve, stdio_io
from .store import Store
from .upstream import StdioUpstream, UpstreamError


def _db(a: argparse.Namespace) -> str:
    return str(a.db or os.environ.get("WEIR_DB") or "weir.db")


def _build(a: argparse.Namespace) -> tuple[Gateway, Store]:
    policy = load_policy(a.policy)
    store = Store(_db(a))
    holder: dict[str, Gateway] = {}
    ups = {u.name: StdioUpstream(u, on_tools_changed=lambda s: holder["gw"].mark_stale(s)) for u in policy.upstreams}
    lock = load_lock(a.lock) if getattr(a, "lock", None) else None
    gw = Gateway(policy, store, ups, lock=lock, allow_policy_change=getattr(a, "allow_policy_change", False))
    holder["gw"] = gw
    return gw, store


def cmd_run(a: argparse.Namespace) -> int:
    gw, store = _build(a)

    async def main() -> None:
        await gw.start()
        session = gw.open_session(a.session)
        print(
            f"weir: session {session.id} policy {gw.policy.name} {gw.policy.digest[:12]} db {_db(a)}", file=sys.stderr
        )
        read_line, write_line = await stdio_io()
        await serve(gw, session, read_line, write_line)
        await gw.close()

    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    try:
        asyncio.run(main())
    except (UpstreamError, RuntimeError) as e:
        print(f"weir: {e}", file=sys.stderr)
        return 3
    finally:
        store.close()
    return 0


def cmd_lock(a: argparse.Namespace) -> int:
    gw, _ = _build(a)

    async def main() -> dict[str, str]:
        for up in gw.upstreams.values():
            await up.start()
        try:
            hashes = {}
            declared = {t.name for t in gw.policy.tools}
            for srv, up in gw.upstreams.items():
                for d in await up.list_tools():
                    if f"{srv}__{d['name']}" in declared:
                        hashes[f"{srv}__{d['name']}"] = definition_hash(d)
            return hashes
        finally:
            await gw.close()

    try:
        hashes = asyncio.run(main())
    except UpstreamError as e:
        print(f"weir: {e}", file=sys.stderr)
        return 3
    write_lock(a.out, hashes)
    print(f"wrote {a.out}: {len(hashes)} tool definitions pinned")
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    p = load_policy(a.policy)
    print(
        f"policy {p.name!r} OK  digest {p.digest[:16]}  {len(p.tools)} tools, {len(p.upstreams)} upstreams, "
        f"internal domains {list(p.internal_domains)}"
    )
    return 0


def cmd_approvals(a: argparse.Namespace) -> int:
    store = Store(_db(a))
    if a.action == "list":
        rows = store.list_approvals(a.state)
        for r in rows:
            print(
                f"{r.id}  {r.state:<9} {r.tool}  rules={','.join(r.rules)}  session={r.session_id}  "
                f"expires in {max(0, int(r.expires - time.time()))}s"
            )
        if not rows:
            print("(none)")
        return 0
    ap = store.get_approval(a.id)
    if ap is None:
        print(f"no such approval {a.id}", file=sys.stderr)
        return 1
    if a.action == "show":
        print(f"id {ap.id}\nstate {ap.state}\ntool {ap.tool}\nsession {ap.session_id}\nrules {', '.join(ap.rules)}")
        for k, v in ap.summary.get("args", {}).items():
            print(f"arg {k} = {fmt_arg(v)}")
        for m in ap.summary.get("rules", []):
            print(f"because {m}")
        for f in ap.summary.get("flows", []):
            print(f"  value from {f['call']} ({f['tool']}, {f['label']}) matched by {f['kind']}/{f['via']}")
        return 0
    outcome = store.resolve_approval(a.id, a.action == "approve", by=os.environ.get("USER", "cli"))
    print(f"{a.id}: {outcome}")
    return 0 if outcome in ("approved", "denied") else 1


def cmd_audit(a: argparse.Namespace) -> int:
    store = Store(_db(a))
    if a.action == "verify":
        ok, bad, n = store.verify_chain()
        print(f"audit chain OK ({n} events)" if ok else f"audit chain BROKEN at event #{bad} (after {n} good events)")
        return 0 if ok else 1
    events = list(store.events(a.session))
    if a.action == "tail":
        for ev in events[-a.n :]:
            p: dict[str, Any] = ev["payload"]
            print(
                f"#{ev['seq']:<5} {ev['session'] or '-':<14} {ev['kind']:<18} {p.get('tool', '')} {p.get('verdict', '')} "
                f"{','.join(h['code'] if isinstance(h, dict) else str(h) for h in p.get('rules', []))}"
            )
        return 0
    print(render_text(build_records(events)))
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    store = Store(_db(a))
    events = list(store.events(a.session))
    if not events:
        print(f"no events for session {a.session}", file=sys.stderr)
        return 1
    start = next((e for e in events if e["kind"] in ("session.start", "session.resume")), None)
    digest = start["payload"].get("policy", "") if start else ""
    name = start["payload"].get("policy_name", "") if start else ""
    page = render_html(a.session, name, digest, build_records(events), store.verify_chain())
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"wrote {a.out}")
    return 0


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(
        prog="weir", description="Information-flow gateway for MCP tool calls (research prototype)."
    )
    ap.add_argument("--db", help="SQLite database (default: $WEIR_DB or ./weir.db)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="serve MCP over stdio, proxying the upstreams in the policy")
    r.add_argument("--policy", required=True)
    r.add_argument("--session", help="resume this session id")
    r.add_argument("--lock", help="tool-definition lock file (see `weir lock`)")
    r.add_argument(
        "--allow-policy-change", action="store_true", help="allow resuming a session under a different policy"
    )
    r.set_defaults(fn=cmd_run)
    lk = sub.add_parser("lock", help="pin the current tool definitions of the declared tools")
    lk.add_argument("--policy", required=True)
    lk.add_argument("--out", default="tools.lock.json")
    lk.set_defaults(fn=cmd_lock)
    ck = sub.add_parser("check", help="validate a policy file")
    ck.add_argument("policy")
    ck.set_defaults(fn=cmd_check)
    ar = sub.add_parser("approvals", help="list, show, approve or deny pending approvals")
    ar.add_argument("action", choices=["list", "show", "approve", "deny"])
    ar.add_argument("id", nargs="?")
    ar.add_argument("--state", choices=["pending", "approved", "denied", "consumed", "expired"])
    ar.set_defaults(fn=cmd_approvals)
    au = sub.add_parser("audit", help="verify the hash chain, tail events, or explain a session")
    au.add_argument("action", choices=["verify", "tail", "explain"])
    au.add_argument("--session")
    au.add_argument("-n", type=int, default=30)
    au.set_defaults(fn=cmd_audit)
    rp = sub.add_parser("report", help="write a self-contained HTML flow trace for a session")
    rp.add_argument("--session", required=True)
    rp.add_argument("--out", default="weir-trace.html")
    rp.set_defaults(fn=cmd_report)
    a = ap.parse_args(argv)
    logging.basicConfig(
        level=os.environ.get("WEIR_LOG", "WARNING"),
        stream=sys.stderr,
        format="weir %(levelname)s %(name)s: %(message)s",
    )
    if a.cmd == "approvals" and a.action in ("show", "approve", "deny") and not a.id:
        ap.error("approvals show/approve/deny need an approval id")
    try:
        sys.exit(a.fn(a))
    except PolicyError as e:
        print(f"weir: invalid policy: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
