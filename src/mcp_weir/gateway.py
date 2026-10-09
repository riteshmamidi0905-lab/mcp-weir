"""The gateway core: transport-agnostic. One ``call_tool`` pipeline; the stdio server is a thin wrapper around it.

Order of work for a call (see docs/architecture.md section 2): resolve -> limits -> evaluate rules -> approval ->
forward with a timeout -> label the result, register it, join it into the session context, persist, audit ->
only then return it to the host. Any internal failure while deciding is a DENY, never an allow.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .destinations import parse_url
from .decision import Decision, RuleHit, Verdict, evaluate
from .labels import Conf, Integ, Label
from .pinning import definition_hash
from .policy import Policy, ToolSpec
from .session import Session
from .store import Approval, SessionRow, StateIntegrityError, Store, canonical
from .tracker import Match, Tracker
from .upstream import Upstream, UpstreamError

log = logging.getLogger("mcp_weir.gateway")
MAX_RESULT_BYTES = 8 * 1024 * 1024

Approver = Callable[[Approval], bool | None]


@dataclass
class ToolEntry:
    name: str  # namespaced
    server: str
    original: str
    definition: dict[str, Any]  # as the host sees it (namespaced name)
    digest: str
    pin_ok: bool = True


@dataclass
class CallOutcome:
    result: dict[str, Any]
    decision: Decision | None
    forwarded: bool
    call_id: str
    call_hash: str
    approval_id: str | None = None
    overhead_us: float = 0.0  # time spent in Weir, excluding the upstream call
    codes: list[str] = field(default_factory=list)


def error_result(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def result_text(result: dict[str, Any]) -> tuple[str, int]:
    """All text a result exposes to the model, plus a count of non-text blocks the tracker cannot see."""
    parts: list[str] = []
    binary = 0
    for block in result.get("content", []) if isinstance(result.get("content"), list) else []:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            parts.append(block["text"])
        elif block.get("type") == "resource" and isinstance(block.get("resource"), dict):
            t = block["resource"].get("text")
            if isinstance(t, str):
                parts.append(t)
            else:
                binary += 1
        else:
            binary += 1
    if result.get("structuredContent") is not None:
        parts.append(canonical(result["structuredContent"]))
    return "\n".join(parts), binary


def _match_dict(m: Match) -> dict[str, Any]:
    return {"call": m.call_id, "tool": m.tool, "label": str(m.label), "kind": m.kind, "via": m.via, "hits": m.hits}


def _hit_dict(h: RuleHit) -> dict[str, Any]:
    return {
        "code": h.code,
        "verdict": h.verdict.name,
        "message": h.message,
        "sources": [_match_dict(m) for m in h.matches],
    }


def _view_target(kind: str, value: Any, flat: str) -> Any:
    """A destination is always shown (that is what an approver is deciding), but a URL's query and fragment are not:
    they are exactly where exfiltrated data goes."""
    if kind == "url":
        u = parse_url(value)
        if u is None:
            return {
                "len": len(flat),
                "sha256": hashlib.sha256(flat.encode()).hexdigest()[:16],
                "note": "unparseable URL",
            }
        port = f":{u.port}" if u.port else ""
        return f"{u.scheme}://{u.host}{port}{u.path[:200]}" + (f"?...({len(u.query)} chars)" if u.query else "")
    return flat[:200]


def view_args(spec: ToolSpec | None, args: dict[str, Any]) -> dict[str, Any]:
    """What a human or a log may see. Target arguments (recipient, URL host and path, file path) are in clear; other
    arguments the policy does not declare as *content* are in clear (truncated); content arguments only as length and
    digest. Unknown tools get digests only."""
    content = set(spec.content) if spec else None
    kinds = dict(spec.targets) if spec else {}
    out: dict[str, Any] = {}
    for k, v in args.items():
        flat = v if isinstance(v, str) else canonical(v)
        if k in kinds:
            out[k] = _view_target(kinds[k], v, flat)
        elif content is not None and k not in content:
            out[k] = flat[:200]
        else:
            out[k] = {"len": len(flat), "sha256": hashlib.sha256(flat.encode()).hexdigest()[:16]}
    return out


class Gateway:
    def __init__(
        self,
        policy: Policy,
        store: Store,
        upstreams: Mapping[str, Upstream],
        *,
        lock: dict[str, str] | None = None,
        approver: Approver | None = None,
        clock: Callable[[], float] = time.time,
        allow_policy_change: bool = False,
    ) -> None:
        self.policy, self.store, self.upstreams = policy, store, upstreams
        self.lock, self.approver, self.clock = lock, approver, clock
        self.allow_policy_change = allow_policy_change
        self.tools: dict[str, ToolEntry] = {}
        self._baseline: dict[str, str] = {}
        self._stale: set[str] = set()
        self._key = store.hmac_key()

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        for up in self.upstreams.values():
            await up.start()
        await self.refresh_tools()
        declared = {t.name for t in self.policy.tools}
        for name in sorted(declared - set(self.tools)):
            self.store.append_event(None, "policy.unmatched_tool", {"tool": name})

    async def close(self) -> None:
        for up in self.upstreams.values():
            await up.close()

    def mark_stale(self, server: str) -> None:
        self._stale.add(server)

    async def refresh_tools(self, only: set[str] | None = None) -> None:
        for server, up in self.upstreams.items():
            if only is not None and server not in only:
                continue
            defs = await up.list_tools()
            seen = set()
            for d in defs:
                ns = f"{server}__{d['name']}"
                seen.add(ns)
                digest = definition_hash(d)
                expected = self.lock.get(ns) if self.lock is not None else self._baseline.setdefault(ns, digest)
                ok = expected == digest
                prior = self.tools.get(ns)
                if prior is not None and prior.digest != digest:
                    self.store.append_event(
                        None, "pin.mismatch", {"tool": ns, "was": prior.digest[:16], "now": digest[:16]}
                    )
                elif not ok:
                    self.store.append_event(
                        None, "pin.mismatch", {"tool": ns, "expected": (expected or "missing")[:16], "now": digest[:16]}
                    )
                self.tools[ns] = ToolEntry(ns, server, d["name"], {**d, "name": ns}, digest, ok)
            for gone in [n for n, e in self.tools.items() if e.server == server and n not in seen]:
                del self.tools[gone]
            self._stale.discard(server)

    # ------------------------------------------------------------------ sessions
    def open_session(self, sid: str | None = None) -> Session:
        cfg = self.policy.tracker
        if sid is not None:
            try:
                row = self.store.load_session(sid)
            except StateIntegrityError as e:
                self.store.append_event(sid, "session.refused", {"reason": "state integrity", "detail": str(e)[:200]})
                raise RuntimeError(f"refusing to resume session {sid}: {e}") from None
            if row is not None:
                ok, bad, _ = self.store.verify_chain()
                if not ok:
                    raise RuntimeError(f"refusing to resume session {sid}: the audit chain is broken at event #{bad}")
                if row.policy_sha != self.policy.digest and not self.allow_policy_change:
                    raise RuntimeError(
                        f"session {sid} was created under a different policy ({row.policy_sha[:12]} vs {self.policy.digest[:12]}); "
                        "refusing to resume (allow_policy_change=True overrides)"
                    )
                tracker = Tracker.load(self._key, row.tracker) if row.tracker else Tracker(self._key)
                s = Session(
                    sid,
                    tracker,
                    Label(Conf(row.ctx_conf), Integ(row.ctx_integ)),
                    row.external_count,
                    row.n_calls,
                    row.version,
                    tracker_dirty=False,
                    blind=row.blind,
                )
                self.store.append_event(
                    sid, "session.resume", {"policy": self.policy.digest, "ctx": str(s.ctx), "version": row.version}
                )
                return s
        sid = sid or "s_" + secrets.token_hex(6)
        s = Session(
            sid,
            Tracker(
                self._key,
                k_secret=cfg.k_secret,
                k_internal=cfg.k_internal,
                min_unit=cfg.min_unit,
                max_text=cfg.max_text,
            ),
        )
        self._persist(s, force_tracker=True)
        self.store.append_event(sid, "session.start", {"policy": self.policy.digest, "policy_name": self.policy.name})
        return s

    def _persist(self, s: Session, *, force_tracker: bool = False) -> None:
        s.version += 1
        row = SessionRow(
            s.id,
            self.policy.digest,
            int(s.ctx.conf),
            int(s.ctx.integ),
            s.external_count,
            s.n_calls,
            s.version,
            s.blind,
            b"",
        )
        if s.tracker_dirty or force_tracker:
            self.store.save_session(SessionRow(**{**row.__dict__, "tracker": s.tracker.dump()}))
            s.tracker_dirty = False
        else:
            self.store.update_session_state(row)

    # ------------------------------------------------------------------ host-facing
    async def list_tools(self) -> list[dict[str, Any]]:
        if self._stale:
            try:
                await self.refresh_tools(set(self._stale))
            except UpstreamError as e:
                self.store.append_event(None, "tools.refresh_failed", {"error": str(e)[:200]})
        declared = {t.name for t in self.policy.tools}
        return [e.definition for n, e in sorted(self.tools.items()) if n in declared and e.pin_ok]

    async def call_tool(self, session: Session, name: str, arguments: Any) -> dict[str, Any]:
        return (await self.call_tool_detailed(session, name, arguments)).result

    async def call_tool_detailed(self, session: Session, name: str, arguments: Any) -> CallOutcome:
        t_start = time.perf_counter()
        upstream_s = 0.0
        async with session.lock:
            session.n_calls += 1
            call_id = f"c{session.n_calls}"
            args = arguments if isinstance(arguments, dict) else None
            spec = self.policy.tool(name) if isinstance(name, str) else None
            entry = self.tools.get(name) if isinstance(name, str) else None
            call_hash = hashlib.sha256(canonical({"tool": name, "args": args}).encode()).hexdigest()
            if self._stale and entry is not None and entry.server in self._stale:
                try:
                    await self.refresh_tools({entry.server})
                    entry = self.tools.get(name)
                except UpstreamError as e:
                    self.store.append_event(session.id, "tools.refresh_failed", {"error": str(e)[:200]})
            try:
                if args is None:
                    return self._blocked(
                        session,
                        call_id,
                        call_hash,
                        name,
                        None,
                        Decision(Verdict.DENY, [RuleHit("R-LIMIT", Verdict.DENY, "arguments must be a JSON object")]),
                        t_start,
                    )
                if len(canonical(args)) > self.policy.max_arg_bytes:
                    return self._blocked(
                        session,
                        call_id,
                        call_hash,
                        name,
                        spec,
                        Decision(Verdict.DENY, [RuleHit("R-LIMIT", Verdict.DENY, "arguments exceed the size limit")]),
                        t_start,
                        args,
                    )
                decision = evaluate(
                    self.policy,
                    spec,
                    args,
                    ctx=session.ctx,
                    external_count=session.external_count,
                    tracker=session.tracker,
                    pin_ok=entry is not None and entry.pin_ok,
                    blind=session.blind,
                )
            except (sqlite3.Error, ValueError, KeyError, TypeError, RecursionError) as e:  # fail closed
                log.exception("decision failed")
                return self._blocked(
                    session,
                    call_id,
                    call_hash,
                    str(name),
                    spec,
                    Decision(
                        Verdict.DENY,
                        [RuleHit("R-INTERNAL", Verdict.DENY, f"could not evaluate the call ({type(e).__name__})")],
                    ),
                    t_start,
                    args if isinstance(args, dict) else None,
                )

            approval_id: str | None = None
            if decision.verdict is Verdict.DENY:
                return self._blocked(session, call_id, call_hash, name, spec, decision, t_start, args)
            if decision.verdict is Verdict.APPROVE:
                gate = self._gate(session, call_id, call_hash, name, spec, decision, args)
                if isinstance(gate, CallOutcome):
                    gate.overhead_us = (time.perf_counter() - t_start) * 1e6
                    return gate
                approval_id = gate
            assert entry is not None and spec is not None and args is not None
            if decision.external:
                session.external_count += 1
            self.store.append_event(
                session.id,
                "call.decision",
                self._decision_payload(call_id, call_hash, name, spec, args, decision, session.ctx, approval_id),
            )

        # ---- forward (outside the session lock so independent calls can run concurrently) -----------------
        t_up = time.perf_counter()
        try:
            raw = await self.upstreams[entry.server].call_tool(entry.original, args, self.policy.call_timeout_seconds)
            is_uncertain = False
        except UpstreamError as e:
            raw, is_uncertain = (
                error_result(
                    f"weir: upstream failure for {name}: {str(e)[:200]}. The call may or may not have taken effect; it was not retried."
                ),
                True,
            )
        except asyncio.CancelledError:
            self.store.append_event(session.id, "call.cancelled", {"call": call_id, "tool": name})
            raise
        upstream_s = time.perf_counter() - t_up

        # ---- label, register, join, persist, audit — then return ---------------------------------------------
        async with session.lock:
            text, binary = result_text(raw)
            if len(text.encode("utf-8", "ignore")) > MAX_RESULT_BYTES:
                raw, text, binary = error_result("weir: upstream result exceeded the size limit and was dropped"), "", 0
            label = decision.result_label
            idx = session.tracker.register(call_id, name, label, text)
            registered = idx is not None
            if not label.is_bottom and text and (idx is None or session.tracker.sources[idx].truncated):
                session.blind = True  # too large (or too many) to follow: from now on the value tier cannot vouch
            session.tracker_dirty |= registered
            session.ctx = session.ctx.join(label)  # in memory first: a persistence failure must only ever over-restrict
            try:
                self._persist(session)
                self.store.append_event(
                    session.id,
                    "call.result",
                    {
                        "call": call_id,
                        "tool": name,
                        "label": str(label),
                        "is_error": bool(raw.get("isError")),
                        "uncertain": is_uncertain,
                        "bytes": len(text),
                        "registered": registered,
                        "non_text_blocks": binary,
                        "ctx_after": str(session.ctx),
                        "external_count": session.external_count,
                    },
                )
            except sqlite3.Error:
                log.exception("could not record the call result")
                raw = error_result(
                    f"weir: could not record {name} in the audit trail; the result was withheld (fail closed)"
                )
        total = time.perf_counter() - t_start
        return CallOutcome(
            raw, decision, True, call_id, call_hash, approval_id, (total - upstream_s) * 1e6, decision.codes
        )

    # ------------------------------------------------------------------ helpers
    def _gate(
        self,
        session: Session,
        call_id: str,
        call_hash: str,
        name: str,
        spec: ToolSpec | None,
        decision: Decision,
        args: dict[str, Any],
    ) -> CallOutcome | str:
        """Handle a call that needs approval. Returns the consumed approval id to proceed, or an outcome to return."""
        consumed = self.store.consume_approval(session.id, call_hash)
        if consumed:
            self.store.append_event(
                session.id, "approval.consumed", {"approval": consumed, "call": call_id, "tool": name}
            )
            return consumed
        state = self.store.latest_approval_state(session.id, call_hash)
        if state == "denied":
            d = Decision(
                Verdict.DENY,
                [*decision.hits, RuleHit("R-APPROVAL-DENIED", Verdict.DENY, "a human denied this exact call")],
                decision.external,
                decision.result_label,
                decision.destinations,
            )
            return self._blocked(session, call_id, call_hash, name, spec, d, time.perf_counter(), args)
        aid = self.store.create_approval(
            session.id,
            call_hash,
            name,
            decision.codes,
            {
                "tool": name,
                "args": view_args(spec, args),
                "rules": [h.message for h in decision.hits],
                "flows": [_match_dict(m) for h in decision.hits for m in h.matches][:8],
            },
            self.policy.approval_ttl_seconds,
        )
        self.store.append_event(
            session.id, "approval.request", {"approval": aid, "call": call_id, "tool": name, "rules": decision.codes}
        )
        if self.approver is not None:
            verdict = self.approver(self.store.get_approval(aid))  # type: ignore[arg-type]
            if verdict is not None:
                self.store.resolve_approval(aid, bool(verdict), by="auto")
                self.store.append_event(
                    session.id, "approval.resolve", {"approval": aid, "approved": bool(verdict), "by": "auto"}
                )
                if verdict:
                    got = self.store.consume_approval(session.id, call_hash)
                    if got:
                        self.store.append_event(
                            session.id, "approval.consumed", {"approval": got, "call": call_id, "tool": name}
                        )
                        return got
                else:
                    d = Decision(
                        Verdict.DENY,
                        [*decision.hits, RuleHit("R-APPROVAL-DENIED", Verdict.DENY, "a human denied this exact call")],
                        decision.external,
                        decision.result_label,
                        decision.destinations,
                    )
                    return self._blocked(session, call_id, call_hash, name, spec, d, time.perf_counter(), args)
        self.store.append_event(
            session.id,
            "call.decision",
            self._decision_payload(call_id, call_hash, name, spec, args, decision, session.ctx, aid),
        )
        self._persist(session)
        msg = (
            f"weir: approval required for {name} (rules: {', '.join(decision.codes)}). Approval id: {aid}. "
            f"A human can run `weir approvals approve {aid}`; then repeat the identical call."
        )
        return CallOutcome(error_result(msg), decision, False, call_id, call_hash, aid, 0.0, decision.codes)

    def _blocked(
        self,
        session: Session,
        call_id: str,
        call_hash: str,
        name: str,
        spec: ToolSpec | None,
        decision: Decision,
        t_start: float,
        args: dict[str, Any] | None = None,
    ) -> CallOutcome:
        self.store.append_event(
            session.id,
            "call.decision",
            self._decision_payload(call_id, call_hash, name, spec, args or {}, decision, session.ctx, None),
        )
        self._persist(session)
        codes = decision.codes
        msg = f"weir: blocked {name}: {', '.join(codes)}. {decision.hits[0].message}."
        return CallOutcome(
            error_result(msg), decision, False, call_id, call_hash, None, (time.perf_counter() - t_start) * 1e6, codes
        )

    def _decision_payload(
        self,
        call_id: str,
        call_hash: str,
        name: str,
        spec: ToolSpec | None,
        args: dict[str, Any],
        d: Decision,
        ctx: Label,
        approval: str | None,
    ) -> dict[str, Any]:
        return {
            "call": call_id,
            "call_hash": call_hash[:16],
            "tool": name,
            "verdict": d.verdict.name,
            "rules": [_hit_dict(h) for h in d.hits],
            "external": d.external,
            "result_label": str(d.result_label),
            "ctx_before": str(ctx),
            "args": view_args(spec, args),
            "approval": approval,
            "destinations": [{"kind": x.kind, "reason": x.reason} for x in d.destinations],
        }
