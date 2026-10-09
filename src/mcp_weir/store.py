"""SQLite persistence: sessions (context label + tracker), tamper-evident event chain, single-use approvals.

Everything that must survive a crash is here. WAL mode; every multi-step change is one transaction. Callers treat
any ``sqlite3.Error`` as "the check could not run" and fail closed.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = "1"
GENESIS = "0" * 64

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  id TEXT PRIMARY KEY, created REAL NOT NULL, policy_sha TEXT NOT NULL,
  ctx_conf INTEGER NOT NULL, ctx_integ INTEGER NOT NULL, external_count INTEGER NOT NULL,
  tracker BLOB, version INTEGER NOT NULL, n_calls INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, session_id TEXT, kind TEXT NOT NULL,
  payload TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id, seq);
CREATE TABLE IF NOT EXISTS approvals(
  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, call_hash TEXT NOT NULL, tool TEXT NOT NULL,
  rules TEXT NOT NULL, summary TEXT NOT NULL, state TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
  resolved_at REAL, resolved_by TEXT, consumed_at REAL);
CREATE INDEX IF NOT EXISTS approvals_lookup ON approvals(session_id, call_hash, state);
"""


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def event_hash(prev: str, ts: float, session_id: str | None, kind: str, payload: str) -> str:
    return hashlib.sha256("\x1f".join((prev, repr(ts), session_id or "", kind, payload)).encode()).hexdigest()


@dataclass(frozen=True)
class Approval:
    id: str
    session_id: str
    call_hash: str
    tool: str
    rules: list[str]
    summary: dict[str, Any]
    state: str
    created: float
    expires: float
    resolved_by: str | None = None


class Store:
    def __init__(self, path: str, clock: Callable[[], float] = time.time) -> None:
        self.path, self.clock = path, clock
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=10.0)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(_SCHEMA)
        self._db.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)", (SCHEMA_VERSION,))
        row = self._db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row[0] != SCHEMA_VERSION:
            raise RuntimeError(f"database schema {row[0]} is not supported by this version ({SCHEMA_VERSION})")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------------ key
    def hmac_key(self) -> bytes:
        env = os.environ.get("WEIR_HMAC_KEY")
        if env:
            return bytes.fromhex(env)
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('hmac_key', ?)", (secrets.token_hex(32),))
            return bytes.fromhex(self._db.execute("SELECT value FROM meta WHERE key='hmac_key'").fetchone()[0])

    # ------------------------------------------------------------------ sessions
    def save_session(
        self,
        sid: str,
        policy_sha: str,
        ctx_conf: int,
        ctx_integ: int,
        external_count: int,
        tracker: bytes,
        version: int,
        n_calls: int = 0,
    ) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO sessions(id, created, policy_sha, ctx_conf, ctx_integ, external_count, tracker, version, n_calls) "
                "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET policy_sha=excluded.policy_sha, "
                "ctx_conf=excluded.ctx_conf, ctx_integ=excluded.ctx_integ, external_count=excluded.external_count, "
                "tracker=excluded.tracker, version=excluded.version, n_calls=excluded.n_calls",
                (sid, self.clock(), policy_sha, ctx_conf, ctx_integ, external_count, tracker, version, n_calls),
            )

    def update_session_state(
        self, sid: str, ctx_conf: int, ctx_integ: int, external_count: int, version: int, n_calls: int
    ) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE sessions SET ctx_conf=?, ctx_integ=?, external_count=?, version=?, n_calls=? WHERE id=?",
                (ctx_conf, ctx_integ, external_count, version, n_calls, sid),
            )

    def load_session(self, sid: str) -> tuple[Any, ...] | None:
        with self._lock:
            row: tuple[Any, ...] | None = self._db.execute(
                "SELECT policy_sha, ctx_conf, ctx_integ, external_count, tracker, version, n_calls FROM sessions WHERE id=?",
                (sid,),
            ).fetchone()
        return row

    # ------------------------------------------------------------------ audit chain
    def append_event(self, session_id: str | None, kind: str, payload: dict[str, Any]) -> int:
        body = canonical(payload)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
                prev = row[0] if row else GENESIS
                ts = self.clock()
                cur = self._db.execute(
                    "INSERT INTO events(ts, session_id, kind, payload, prev_hash, hash) VALUES(?,?,?,?,?,?)",
                    (ts, session_id, kind, body, prev, event_hash(prev, ts, session_id, kind, body)),
                )
                self._db.execute("COMMIT")
                return int(cur.lastrowid or 0)
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def events(self, session_id: str | None = None) -> Iterator[dict[str, Any]]:
        with self._lock:
            if session_id is None:
                rows = self._db.execute("SELECT seq, ts, session_id, kind, payload FROM events ORDER BY seq").fetchall()
            else:
                rows = self._db.execute(
                    "SELECT seq, ts, session_id, kind, payload FROM events WHERE session_id=? ORDER BY seq",
                    (session_id,),
                ).fetchall()
        for seq, ts, sid, kind, payload in rows:
            yield {"seq": seq, "ts": ts, "session": sid, "kind": kind, "payload": json.loads(payload)}

    def verify_chain(self) -> tuple[bool, int | None, int]:
        """(ok, first bad seq or None, number of events checked)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, ts, session_id, kind, payload, prev_hash, hash FROM events ORDER BY seq"
            ).fetchall()
        prev, n = GENESIS, 0
        for seq, ts, sid, kind, payload, prev_hash, h in rows:
            if prev_hash != prev or h != event_hash(prev, ts, sid, kind, payload):
                return False, seq, n
            prev, n = h, n + 1
        return True, None, n

    # ------------------------------------------------------------------ approvals
    def create_approval(
        self, session_id: str, call_hash: str, tool: str, rules: list[str], summary: dict[str, Any], ttl: float
    ) -> str:
        now = self.clock()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT id FROM approvals WHERE session_id=? AND call_hash=? AND state IN ('pending','approved') "
                    "AND expires>=? ORDER BY created DESC LIMIT 1",
                    (session_id, call_hash, now),
                ).fetchone()
                if row:
                    self._db.execute("COMMIT")
                    return str(row[0])
                aid = "ap_" + secrets.token_hex(4)
                self._db.execute(
                    "INSERT INTO approvals(id, session_id, call_hash, tool, rules, summary, state, created, expires) "
                    "VALUES(?,?,?,?,?,?,'pending',?,?)",
                    (aid, session_id, call_hash, tool, canonical(rules), canonical(summary), now, now + ttl),
                )
                self._db.execute("COMMIT")
                return aid
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def resolve_approval(self, aid: str, approve: bool, by: str = "cli") -> str:
        """Returns the new state, or the reason it could not change ('missing', 'expired', 'already <state>')."""
        now = self.clock()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT state, expires FROM approvals WHERE id=?", (aid,)).fetchone()
                if row is None:
                    out = "missing"
                elif row[0] != "pending":
                    out = f"already {row[0]}"
                elif row[1] < now:
                    self._db.execute("UPDATE approvals SET state='expired' WHERE id=?", (aid,))
                    out = "expired"
                else:
                    new = "approved" if approve else "denied"
                    self._db.execute(
                        "UPDATE approvals SET state=?, resolved_at=?, resolved_by=? WHERE id=?", (new, now, by, aid)
                    )
                    out = new
                self._db.execute("COMMIT")
                return out
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def consume_approval(self, session_id: str, call_hash: str) -> str | None:
        """Atomically turn one valid approval for exactly this call into 'consumed'. None if there is none."""
        now = self.clock()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT id FROM approvals WHERE session_id=? AND call_hash=? AND state='approved' AND expires>=? "
                    "ORDER BY created LIMIT 1",
                    (session_id, call_hash, now),
                ).fetchone()
                aid = None
                if row:
                    cur = self._db.execute(
                        "UPDATE approvals SET state='consumed', consumed_at=? WHERE id=? AND state='approved'",
                        (now, row[0]),
                    )
                    aid = str(row[0]) if cur.rowcount == 1 else None
                self._db.execute("COMMIT")
                return aid
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def latest_approval_state(self, session_id: str, call_hash: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT state, expires FROM approvals WHERE session_id=? AND call_hash=? ORDER BY created DESC LIMIT 1",
                (session_id, call_hash),
            ).fetchone()
        if row is None:
            return None
        return "expired" if row[0] in ("pending", "approved") and row[1] < self.clock() else str(row[0])

    def get_approval(self, aid: str) -> Approval | None:
        with self._lock:
            r = self._db.execute(
                "SELECT id, session_id, call_hash, tool, rules, summary, state, created, expires, resolved_by "
                "FROM approvals WHERE id=?",
                (aid,),
            ).fetchone()
        return self._approval(r) if r else None

    def list_approvals(self, state: str | None = None) -> list[Approval]:
        with self._lock:
            q = "SELECT id, session_id, call_hash, tool, rules, summary, state, created, expires, resolved_by FROM approvals"
            rows = self._db.execute(
                q + (" WHERE state=?" if state else "") + " ORDER BY created", (state,) if state else ()
            ).fetchall()
        return [self._approval(r) for r in rows]

    @staticmethod
    def _approval(r: tuple[Any, ...]) -> Approval:
        return Approval(r[0], r[1], r[2], r[3], json.loads(r[4]), json.loads(r[5]), r[6], r[7], r[8], r[9])
