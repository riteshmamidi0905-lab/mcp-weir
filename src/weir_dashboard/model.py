"""View models: plain dictionaries built from what the database holds, for the JSON API.

Rules for this module: nothing is invented, nothing is inferred, no gateway decision is recomputed. Every field is either
copied from an audit event or an approval row, derived by counting them, or marked as a display convenience. Call records
come from ``mcp_weir.report.build_records`` (the gateway package's own reader of the audit chain).
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from mcp_weir import report
from mcp_weir.labels import BOTTOM, Conf, Integ, Label
from mcp_weir.pinning import load_lock
from mcp_weir.policy import Policy
from mcp_weir.store import canonical

from . import redact, rules, sources
from .readonly import ReadOnlyStore

ACTIVE_WINDOW_S = 300  # "active" = an event in the last five minutes; the log has no end-of-session marker
RECHECK_S = 10  # how old a chain verification may be before an overview recomputes it
STATUS_UI = {
    "ALLOWED": "ALLOWED",
    "BLOCKED": "BLOCKED",
    "HELD FOR APPROVAL": "HELD",
    "EXECUTED AFTER APPROVAL": "EXECUTED_AFTER_APPROVAL",
}
LATTICE = {"conf": [c.name.lower() for c in Conf], "integ": [i.name.lower() for i in Integ], "bottom": str(BOTTOM)}


def norm_args(args: Any, mask: bool) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not isinstance(args, dict):
        return out
    for k, v in args.items():
        if isinstance(v, str):
            entry: dict[str, Any] = {"name": str(k), "kind": "clear", "text": v}
        elif isinstance(v, dict) and "len" in v:
            entry = {
                "name": str(k),
                "kind": "digest",
                "len": v.get("len"),
                "sha256": str(v.get("sha256", "")),
                "note": v.get("note"),
            }
        else:
            entry = {"name": str(k), "kind": "other", "text": str(v)[:120]}
        out.append(redact.mask_arg(entry) if mask else entry)
    return out


def label_json(text: str) -> dict[str, Any] | None:
    """``"secret/untrusted"`` -> parsed through the gateway's own Label; None if it is not a label."""
    try:
        conf, integ = text.split("/")
        lab = Label.parse(conf, integ)
    except (ValueError, AttributeError):
        return None
    return {
        "text": str(lab),
        "conf": lab.conf.name.lower(),
        "integ": lab.integ.name.lower(),
        "rank": [int(lab.conf), int(lab.integ)],
    }


def eff_state(state: str, expires: float, now: float) -> str:
    """Same rule as ``Store.latest_approval_state``: a pending or approved row past its expiry is expired."""
    return "expired" if state in ("pending", "approved") and expires < now else state


def who(by: str | None) -> str | None:
    if by is None:
        return None
    if by == "auto":
        return "auto (a programmatic approver, not a person)"
    if by == "dashboard":
        return "person, via this dashboard"
    return f"{by} (command line)"


@dataclass
class Snapshot:
    stamp: str
    events: list[dict[str, Any]]
    by_session: dict[str, list[dict[str, Any]]]
    approvals: dict[str, dict[str, Any]]
    session_rows: dict[str, dict[str, Any]]
    malformed: int


@dataclass
class Dataset:
    """One database plus how to read it. ``kind`` is how it was produced (see ``sources``)."""

    id: str
    path: str
    writable: bool  # approvals may be resolved here (only the primary, local dataset)
    title: str = ""
    _snap: Snapshot | None = None
    _chain: tuple[float, str, tuple[bool, int | None, int]] | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def open(self) -> ReadOnlyStore:
        return ReadOnlyStore(self.path)

    def manifest(self) -> dict[str, Any] | None:
        return sources.read_manifest(self.path)

    def snapshot(self, store: ReadOnlyStore) -> Snapshot:
        st = store.stamp()
        key = canonical(st)
        with self._lock:
            if self._snap is not None and self._snap.stamp == key:
                return self._snap
        events = list(store.events_tolerant())
        by: dict[str, list[dict[str, Any]]] = {}
        for ev in events:
            if ev["session"]:
                by.setdefault(ev["session"], []).append(ev)
        times = store.approval_times()
        aps = {}
        for a in store.list_approvals():
            aps[a.id] = {"a": a, **times.get(a.id, {})}
        snap = Snapshot(
            key, events, by, aps, {r["id"]: r for r in store.session_rows()}, sum(1 for e in events if e["malformed"])
        )
        with self._lock:
            self._snap = snap
        return snap

    def chain(self, store: ReadOnlyStore, snap: Snapshot, force: bool = False) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            c = self._chain
            fresh = c is not None and c[1] == snap.stamp and now - c[0] < RECHECK_S
            if not force and fresh and c is not None:
                at, _, res = c
            else:
                res = store.verify_chain()
                at = now
                self._chain = (at, snap.stamp, res)
        ok, bad, n = res
        owner = next((e["session"] for e in snap.events if e["seq"] == bad), None) if bad is not None else None
        return {
            "ok": ok,
            "events": n,
            "first_bad_seq": bad,
            "first_bad_session": owner,
            "checked_at": at,
            "message": "Hash chain verified." if ok else "Hash-chain verification failed.",
            "scope": "Checks that each stored event still matches its hash link. It cannot show that events were not removed "
            "from the end, and the hashes are not keyed, so it is not proof against someone who can write the database.",
        }


# ---------------------------------------------------------------------------------------------- sessions
def _approval_json(ap: dict[str, Any], now: float) -> dict[str, Any]:
    a = ap["a"]
    return {
        "id": a.id,
        "state": eff_state(a.state, a.expires, now),
        "stored_state": a.state,
        "created": a.created,
        "expires": a.expires,
        "resolved_by": who(a.resolved_by),
        "resolved_by_raw": a.resolved_by,
        "resolved_at": ap.get("resolved_at"),
        "consumed_at": ap.get("consumed_at"),
    }


def _calls(snap: Snapshot, sid: str, now: float, mask: bool) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    events = snap.by_session.get(sid, [])
    good = [e for e in events if not e["malformed"]]
    recs = report.build_records(good)
    dec: dict[str, dict[str, Any]] = {}
    res: dict[str, dict[str, Any]] = {}
    ap_req: dict[str, str] = {}
    ap_consumed: dict[str, str] = {}
    ap_resolved: dict[str, dict[str, Any]] = {}
    for e in good:
        p, cid = e["payload"], e["payload"].get("call")
        if e["kind"] == "call.decision" and cid:
            dec[cid] = e
        elif e["kind"] == "call.result" and cid:
            res[cid] = e
        elif e["kind"] == "approval.request" and p.get("approval"):
            ap_req.setdefault(p["approval"], cid)
        elif e["kind"] == "approval.consumed" and p.get("approval"):
            ap_consumed[p["approval"]] = cid
        elif e["kind"] == "approval.resolve" and p.get("approval"):
            ap_resolved[p["approval"]] = p
    req_by_call = {cid: aid for aid, cid in ap_req.items() if cid}
    out: list[dict[str, Any]] = []
    approvals_seen: dict[str, dict[str, Any]] = {}
    for r in recs:
        d, rr = dec[r.call], res.get(r.call)
        status = STATUS_UI[report.status(r)]
        hits = []
        for h in r.rules:
            hits.append(
                {
                    "code": h["code"],
                    "title": rules.CATALOGUE.get(h["code"], {}).get("title", "Unrecognised rule"),
                    "verdict": rules.verdict_ui(h["verdict"]),
                    "message": h["message"],
                    "sources": [
                        {
                            **{k: s.get(k) for k in ("call", "tool", "label", "kind", "via", "hits")},
                            "label_obj": label_json(str(s.get("label", ""))),
                        }
                        for s in h.get("sources", [])
                    ],
                }
            )
        ap: dict[str, Any] | None = None
        aid = r.approval or req_by_call.get(
            r.call
        )  # a call an approver declined has no approval id in its decision, only a request event
        if aid:
            row = snap.approvals.get(aid)
            ap = (
                _approval_json(row, now)
                if row
                else {"id": aid, "state": "unknown", "stored_state": "unknown", "resolved_by_raw": None}
            )
            ap["requested_by_call"] = ap_req.get(aid)
            ap["consumed_by_call"] = ap_consumed.get(aid)
            if aid in ap_resolved:
                ap["chain_resolve"] = {
                    "approved": ap_resolved[aid].get("approved"),
                    "by": who(ap_resolved[aid].get("by")),
                }
            approvals_seen[aid] = ap
        verdict_ui = rules.verdict_ui(r.verdict)
        call = {
            "call": r.call,
            "seq": d["seq"],
            "ts": d["ts"],
            "ts_result": rr["ts"] if rr else None,
            "tool": r.tool,
            "server": r.tool.split("__", 1)[0] if "__" in r.tool else "",
            "verdict": verdict_ui,
            "raw_verdict": r.verdict,
            "status": status,
            "args": norm_args(r.args, mask),
            "external": r.external,
            "destinations": d["payload"].get("destinations", []),
            "rules": hits,
            "ctx_before": label_json(r.ctx_before),
            "result_label": label_json(r.result_label),
            "ctx_after": label_json(r.ctx_after) if r.forwarded else label_json(r.ctx_before),
            "forwarded": r.forwarded,
            "is_error": r.is_error,
            "uncertain": r.uncertain,
            "result_bytes": rr["payload"].get("bytes") if rr else None,
            "call_hash": d["payload"].get("call_hash"),
            "approval": ap,
        }
        call["explain"] = explain(call)
        call["path"] = decision_path(call)
        out.append(call)
    return out, approvals_seen


def _auto(c: dict[str, Any]) -> bool:
    ap = c.get("approval") or {}
    return ap.get("resolved_by_raw") == "auto"


def explain(c: dict[str, Any]) -> str:
    codes = ", ".join(h["code"] for h in c["rules"]) or "none"
    if c["status"] == "ALLOWED":
        return "No rule fired; the call was forwarded." if not c["rules"] else f"Allowed; rules recorded: {codes}."
    if c["status"] == "BLOCKED":
        if any(h["code"] == "R-APPROVAL-DENIED" for h in c["rules"]):
            who_ = (
                "A programmatic approver (not a person) declined the hold"
                if _auto(c)
                else "An approver denied this exact call"
            )
            return f"{who_}, so the call was blocked. Repeating the identical call stays blocked."
        first = next((h for h in c["rules"] if h["verdict"] == "DENY"), None)
        return (first["message"] + "." if first else "Blocked.") + " A deny cannot be approved."
    if c["status"] == "HELD":
        st = (c.get("approval") or {}).get("state")
        tail = {
            "pending": "Waiting for a person. After approval the agent must repeat the identical call; the gateway does not keep it open.",
            "approved": "Approved, not yet used. It runs only if the agent repeats the identical call before it expires.",
            "denied": "Denied; repeating the identical call is blocked.",
            "expired": "The approval expired unused.",
            "consumed": "Approved and used by a repeat of this call.",
        }.get(st or "", "Held for approval.")
        return f"Held: {codes}. {tail}"
    by = "a programmatic approver (not a person)" if _auto(c) else "an approver"
    return f"Held, then {by} approved it and it ran. That approval was single-use and is now used."


def decision_path(c: dict[str, Any]) -> str:
    if c["status"] == "ALLOWED":
        return "Allowed"
    if c["status"] == "BLOCKED":
        if any(h["code"] == "R-APPROVAL-DENIED" for h in c["rules"]):
            return (
                "Held, approver declined, blocked"
                if (c.get("approval") or {}).get("requested_by_call") == c["call"]
                else "Blocked by an earlier denial"
            )
        return "Blocked by a deny rule"
    if c["status"] == "HELD":
        return "Held, waiting for a person"
    return "Held, approver approved, ran"


def _counts(calls: list[dict[str, Any]]) -> dict[str, int]:
    v = Counter(c["verdict"] for c in calls)
    s = Counter(c["status"] for c in calls)
    return {
        "calls": len(calls),
        "allow": v["ALLOW"],
        "hold": v["HOLD"],
        "deny": v["DENY"],
        "held_now": sum(
            1 for c in calls if c["status"] == "HELD" and (c.get("approval") or {}).get("state") == "pending"
        ),
        "executed_after_approval": s["EXECUTED_AFTER_APPROVAL"],
    }


def current_ctx(calls: list[dict[str, Any]]) -> dict[str, Any]:
    for c in reversed(calls):
        if c["ctx_after"]:
            return c["ctx_after"]  # type: ignore[no-any-return]
    return label_json(str(BOTTOM)) or {}


def session_summary(
    ds: Dataset,
    snap: Snapshot,
    sid: str,
    manifest: dict[str, Any] | None,
    chain: dict[str, Any],
    now: float,
    mask: bool,
    built: tuple[list[dict[str, Any]], dict[str, dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    events = snap.by_session.get(sid, [])
    calls, aps = built or _calls(snap, sid, now, mask)
    start = next((e for e in events if e["kind"] in ("session.start", "session.resume") and not e["malformed"]), None)
    last = events[-1]["ts"] if events else None
    row = snap.session_rows.get(sid)
    ctx = current_ctx(calls)
    mismatch = None
    if row is not None and calls:
        stored = str(Label(Conf(row["ctx_conf"]), Integ(row["ctx_integ"])))
        mismatch = stored != ctx.get("text")
    src = sources.classify(manifest, sid, last, now)
    pending = [a for a in aps.values() if a["state"] == "pending"]
    return {
        "id": sid,
        "dataset": ds.id,
        "source": src.to_json(),
        "started": row["created"] if row else (events[0]["ts"] if events else None),
        "last_activity": last,
        "policy_name": start["payload"].get("policy_name") if start else None,
        "policy_sha": (start["payload"].get("policy") or "")[:12] if start else None,
        "ctx": ctx,
        "counts": _counts(calls),
        "pending_approvals": len(pending),
        "events": len(events),
        "malformed_events": sum(1 for e in events if e["malformed"]),
        "state_row_matches_audit": None if mismatch is None else not mismatch,
        "approver_kinds": sorted({a.get("resolved_by") or "" for a in aps.values() if a.get("resolved_by")}),
        "audit": {"chain_ok": chain["ok"], "first_bad_seq": chain["first_bad_seq"], "message": chain["message"]},
        "active": last is not None and now - last <= ACTIVE_WINDOW_S,
    }


def sessions_list(ds: Dataset, store: ReadOnlyStore, mask: bool = False) -> dict[str, Any]:
    snap, now, man = ds.snapshot(store), time.time(), ds.manifest()
    chain = ds.chain(store, snap)
    items = [session_summary(ds, snap, sid, man, chain, now, mask) for sid in snap.by_session]
    items.sort(key=lambda s: s["last_activity"] or 0, reverse=True)
    return {"sessions": items, "audit": chain}


def provenance(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Only relationships the gateway recorded: a rule hit that lists an earlier call as the source of a matched value."""
    edges = []
    for c in calls:
        for h in c["rules"]:
            for s in h["sources"]:
                edges.append(
                    {
                        "from": s["call"],
                        "to": c["call"],
                        "rule": h["code"],
                        "kind": s["kind"],
                        "via": s["via"],
                        "hits": s["hits"],
                        "source_tool": s["tool"],
                        "source_label": s["label"],
                        "to_tool": c["tool"],
                        "verdict": c["verdict"],
                    }
                )
    return edges


def ctx_steps(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps = []
    for c in calls:
        b, a = c["ctx_before"], c["ctx_after"]
        steps.append(
            {
                "call": c["call"],
                "tool": c["tool"],
                "before": b,
                "after": a,
                "grew": bool(a and b and a["rank"] != b["rank"]),
                "forwarded": c["forwarded"],
            }
        )
    return steps


def session_detail(ds: Dataset, store: ReadOnlyStore, sid: str, mask: bool = False) -> dict[str, Any] | None:
    snap, now, man = ds.snapshot(store), time.time(), ds.manifest()
    if sid not in snap.by_session:
        return None
    chain = ds.chain(store, snap)
    calls, aps = _calls(snap, sid, now, mask)
    summary = session_summary(ds, snap, sid, man, chain, now, mask)
    # an approval row: add the context the session had when it was held, and flag drift
    cur = summary["ctx"]
    for c in calls:
        ap = c["approval"]
        if ap and c["status"] == "HELD" and c["ctx_before"] and cur and c["ctx_before"]["text"] != cur["text"]:
            ap["context_changed"] = {"at_hold": c["ctx_before"]["text"], "now": cur["text"]}
    return {
        "summary": summary,
        "calls": calls,
        "ctx_steps": ctx_steps(calls),
        "provenance": provenance(calls),
        "approvals": sorted(aps.values(), key=lambda a: a.get("created") or 0),
        "lattice": LATTICE,
        "max_seq": snap.events[-1]["seq"] if snap.events else 0,
        "extra": summary["source"]["extra"],
    }


# ---------------------------------------------------------------------------------------------- overview
def overview(ds: Dataset, store: ReadOnlyStore, mask: bool = False, force_verify: bool = False) -> dict[str, Any]:
    snap, now, man = ds.snapshot(store), time.time(), ds.manifest()
    chain = ds.chain(store, snap, force_verify)
    sessions: list[dict[str, Any]] = []
    every: list[dict[str, Any]] = []
    for sid in snap.by_session:
        built = _calls(snap, sid, now, mask)
        sessions.append(session_summary(ds, snap, sid, man, chain, now, mask, built))
        every.extend({**c, "session": sid} for c in built[0])
    every.sort(key=lambda c: c["seq"], reverse=True)
    recent = [
        {
            "session": c["session"],
            "call": c["call"],
            "tool": c["tool"],
            "verdict": c["verdict"],
            "status": c["status"],
            "rules": [h["code"] for h in c["rules"]],
            "ts": c["ts"],
        }
        for c in every[:8]
    ]
    totals: Counter[str] = Counter()
    for s in sessions:
        totals.update({k: s["counts"][k] for k in ("calls", "allow", "hold", "deny")})
    pend = [a for a in snap.approvals.values() if eff_state(a["a"].state, a["a"].expires, now) == "pending"]
    last = snap.events[-1]["ts"] if snap.events else None
    kinds = Counter(s["source"]["kind"] for s in sessions)
    return {
        "dataset": ds.id,
        "database": {
            "name": ds.path.rsplit("/", 1)[-1],
            "state": "ok",
            "events": len(snap.events),
            "malformed_events": snap.malformed,
        },
        "activity": {
            "last_event": last,
            "age_s": None if last is None else max(0.0, now - last),
            "recent": last is not None and now - last <= sources.LIVE_WINDOW_S,
            "note": "The dashboard reads the database. It cannot see whether a gateway process is running; the audit log has no heartbeat.",
        },
        "audit": chain,
        "sessions": {
            "total": len(sessions),
            "active": sum(1 for s in sessions if s["active"]),
            "window_s": ACTIVE_WINDOW_S,
            "by_source": dict(kinds),
        },
        "approvals": {"pending": len(pend)},
        "decisions": {k: totals[k] for k in ("allow", "hold", "deny")} | {"calls": totals["calls"]},
        "recent": recent,
    }


# ---------------------------------------------------------------------------------------------- approvals
def fingerprint(a: Any) -> str:
    return hashlib.sha256(
        canonical([a.id, a.session_id, a.call_hash, a.tool, a.rules, a.summary]).encode()
    ).hexdigest()[:16]


def approvals_list(ds: Dataset, store: ReadOnlyStore, mask: bool = False) -> dict[str, Any]:
    snap, now = ds.snapshot(store), time.time()
    items = []
    for ap in snap.approvals.values():
        a = ap["a"]
        state = eff_state(a.state, a.expires, now)
        sid = a.session_id
        calls, _ = _calls(snap, sid, now, mask)
        held = next((c for c in calls if c["approval"] and c["approval"]["id"] == a.id and c["status"] == "HELD"), None)
        used = next(
            (
                c
                for c in calls
                if c["approval"] and c["approval"]["id"] == a.id and c["status"] == "EXECUTED_AFTER_APPROVAL"
            ),
            None,
        )
        cur = current_ctx(calls)
        item = {
            **_approval_json(ap, now),
            "session": sid,
            "tool": a.tool,
            "call_hash": a.call_hash[:12],
            "fingerprint": fingerprint(a),
            "rules": [
                {"code": r, "title": rules.CATALOGUE.get(r, {}).get("title", "Unrecognised rule")} for r in a.rules
            ],
            "reasons": list(a.summary.get("rules", [])),
            "args": norm_args(a.summary.get("args", {}), mask),
            "flows": [
                {
                    **{k: f.get(k) for k in ("call", "tool", "label", "kind", "via", "hits")},
                    "label_obj": label_json(str(f.get("label", ""))),
                }
                for f in a.summary.get("flows", [])
            ],
            "requested_call": held["call"] if held else None,
            "ctx_at_hold": held["ctx_before"]["text"] if held and held["ctx_before"] else None,
            "ctx_now": cur.get("text"),
            "context_changed": bool(
                held and held["ctx_before"] and cur and held["ctx_before"]["text"] != cur.get("text")
            ),
            "used_by_call": used["call"] if used else None,
            "can_resolve": ds.writable and state == "pending",
        }
        items.append(item)
    order = {"pending": 0, "approved": 1}
    items.sort(key=lambda i: (order.get(i["state"], 2), -(i["created"] or 0)))
    return {
        "approvals": items,
        "writable": ds.writable,
        "ttl_note": "Approvals expire; the policy's approval_ttl_seconds sets how long.",
    }


# ---------------------------------------------------------------------------------------------- audit
def event_summary(ev: dict[str, Any]) -> str:
    p, k = ev["payload"], ev["kind"]
    if ev["malformed"]:
        return "payload is not valid JSON"
    if k == "call.decision":
        codes = ",".join(h["code"] if isinstance(h, dict) else str(h) for h in p.get("rules", []))
        return f"{p.get('call')} {p.get('tool')} {rules.verdict_ui(p.get('verdict', ''))}" + (
            f" [{codes}]" if codes else ""
        )
    if k == "call.result":
        return f"{p.get('call')} result {p.get('label')}; context now {p.get('ctx_after')}"
    if k.startswith("approval."):
        return f"{p.get('approval', '')} {p.get('call', '')}".strip() + (f" by {p['by']}" if p.get("by") else "")
    if k in ("session.start", "session.resume"):
        return f"policy {p.get('policy_name') or ''!s} {str(p.get('policy') or '')[:12]}".strip()
    return ", ".join(f"{a}={str(b)[:60]}" for a, b in list(p.items())[:3])


def audit_view(
    ds: Dataset, store: ReadOnlyStore, session: str | None = None, limit: int = 200, force: bool = False
) -> dict[str, Any]:
    snap = ds.snapshot(store)
    chain = ds.chain(store, snap, force)
    evs = [e for e in snap.events if session is None or e["session"] == session]
    hashes = store.event_hashes(limit=1000)
    latest = evs[-limit:]
    kinds = Counter(e["kind"] for e in snap.events)
    return {
        "chain": chain,
        "total_events": len(snap.events),
        "kinds": dict(sorted(kinds.items())),
        "latest": [
            {
                "seq": e["seq"],
                "ts": e["ts"],
                "session": e["session"],
                "kind": e["kind"],
                "summary": event_summary(e),
                "hash": hashes.get(e["seq"], ("", ""))[1][:12],
                "prev": hashes.get(e["seq"], ("", ""))[0][:12],
                "malformed": e["malformed"],
                "broken": (not chain["ok"] and e["seq"] == chain["first_bad_seq"]),
            }
            for e in reversed(latest)
        ],
        "session": session,
        "latest_event": None
        if not snap.events
        else {"seq": snap.events[-1]["seq"], "ts": snap.events[-1]["ts"], "session": snap.events[-1]["session"]},
    }


# ---------------------------------------------------------------------------------------------- policy
def tool_json(t: Any) -> dict[str, Any]:
    return {
        "name": t.name,
        "server": t.server,
        "effect": t.effect.value,
        "result": str(t.result),
        "result_rules": [
            {"arg": r.arg, "glob": r.glob, "equals": r.equals, "label": str(r.label), "lowers": r.lower}
            for r in t.result_rules
        ],
        "targets": [{"arg": a, "kind": k} for a, k in t.targets],
        "content": list(t.content),
        "overrides": [{"rule": k, "action": rules.UI_ACTION[str(v)]} for k, v in t.rule_overrides],
    }


def policy_view(
    policy: Policy | None, policy_error: str | None, lock_path: str | None, snaps: Snapshot | None
) -> dict[str, Any]:
    recorded = sorted(
        {
            (e["payload"].get("policy_name"), (e["payload"].get("policy") or "")[:12])
            for e in (snaps.events if snaps else [])
            if e["kind"] in ("session.start", "session.resume") and not e["malformed"]
        },
        key=str,
    )
    pin_mismatch = sum(1 for e in (snaps.events if snaps else []) if e["kind"] == "pin.mismatch")
    out: dict[str, Any] = {
        "loaded": policy is not None,
        "error": policy_error,
        "recorded_policies": [{"name": n, "digest": d} for n, d in recorded],
        "pin_mismatch_events": pin_mismatch,
    }
    if policy is not None:
        out["policy"] = {
            "name": policy.name,
            "digest": policy.digest[:12],
            "digest_full": policy.digest,
            "internal_domains": list(policy.internal_domains),
            "rules": [
                {"key": k, "action": rules.UI_ACTION[str(v)] if k != "egress_budget_limit" else v}
                for k, v in asdict(policy.rules).items()
            ],
            "tracker": asdict(policy.tracker),
            "approval_ttl_seconds": policy.approval_ttl_seconds,
            "max_arg_bytes": policy.max_arg_bytes,
            "call_timeout_seconds": policy.call_timeout_seconds,
            # commands and environment are not shown beyond the program name and the variable names: they can carry credentials
            "upstreams": [
                {
                    "name": u.name,
                    "program": u.command[0].rsplit("/", 1)[-1] if u.command else "",
                    "args": max(0, len(u.command) - 1),
                    "env_names": [k for k, _ in u.env],
                }
                for u in policy.upstreams
            ],
            "tools": [tool_json(t) for t in policy.tools],
        }
        out["matches_recorded"] = [r["digest"] == policy.digest[:12] for r in out["recorded_policies"]]
    lock: dict[str, Any] = {"supplied": lock_path is not None}
    if lock_path:
        try:
            pins = load_lock(lock_path)
            lock.update(
                {
                    "ok": True,
                    "name": lock_path.rsplit("/", 1)[-1],
                    "pinned": [{"tool": k, "digest": v} for k, v in sorted(pins.items())],
                }
            )
            if policy is not None:
                declared = {t.name for t in policy.tools}
                lock["declared_not_pinned"] = sorted(declared - set(pins))
                lock["pinned_not_declared"] = sorted(set(pins) - declared)
        except ValueError as e:
            lock.update({"ok": False, "error": str(e)[:160]})
    out["lock"] = lock
    return out
