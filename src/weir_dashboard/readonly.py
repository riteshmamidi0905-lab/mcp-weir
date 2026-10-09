"""Database access for the dashboard.

``ReadOnlyStore`` is a ``mcp_weir.store.Store`` whose connection is opened ``mode=ro`` with ``query_only`` on. It does not
run ``Store.__init__`` (which creates tables and switches the journal mode), so opening a database through it can never
create or alter anything, and the inherited readers (``events``, ``verify_chain``, ``list_approvals``,
``get_approval``, ``latest_approval_state``) are the gateway's own code, unchanged.

``ApprovalWriter`` is the only way this package writes: a read-write connection (never creating a file) that exposes
the gateway store's own ``resolve_approval`` and nothing else.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, NoReturn

from mcp_weir.store import SCHEMA_VERSION, Store


class DashboardDBError(RuntimeError):
    """The database cannot be read in a way the dashboard understands (missing, not SQLite, other schema)."""

    def __init__(self, state: str, message: str) -> None:
        super().__init__(message)
        self.state, self.message = state, message


class ReadOnlyError(PermissionError):
    """A write was attempted through a read-only store."""


def _connect(path: str, mode: str) -> sqlite3.Connection:
    uri = Path(path).resolve().as_uri() + f"?mode={mode}"
    try:
        db = sqlite3.connect(uri, uri=True, check_same_thread=False, isolation_level=None, timeout=5.0)
        row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.DatabaseError as e:
        if not Path(path).exists():
            raise DashboardDBError("missing", f"database not found: {Path(path).name}") from None
        text = str(e)
        if "not a database" in text or "malformed" in text:
            raise DashboardDBError("corrupt", "the file is not a readable SQLite database") from None
        if "no such table" in text:
            raise DashboardDBError("empty", "the database has no Weir tables yet") from None
        raise DashboardDBError("unreadable", f"could not open the database ({type(e).__name__})") from None
    if row is None or row[0] != SCHEMA_VERSION:
        db.close()
        found = "none" if row is None else str(row[0])
        raise DashboardDBError("schema", f"database schema {found} is not supported (expected {SCHEMA_VERSION})")
    return db


class ReadOnlyStore(Store):
    def __init__(self, path: str, clock: Callable[[], float] = time.time) -> None:
        self.path, self.clock = path, clock
        self._lock = threading.RLock()
        self._db = _connect(path, "ro")
        self._db.execute("PRAGMA query_only=ON")

    # Anything that would write, or read the integrity key, is refused outright.
    def _refuse(self, *_a: Any, **_k: Any) -> NoReturn:
        raise ReadOnlyError("the dashboard's read connection cannot write")

    hmac_key = save_session = update_session_state = load_session = append_event = _refuse
    create_approval = resolve_approval = consume_approval = _refuse

    # ------------------------------------------------------------------ extra SELECT-only readers
    def events_tolerant(self, session_id: str | None = None, after_seq: int = 0) -> Iterator[dict[str, Any]]:
        """Like ``Store.events`` but a row whose payload is not valid JSON is reported, not fatal."""
        q = "SELECT seq, ts, session_id, kind, payload FROM events WHERE seq>?"
        args: tuple[Any, ...] = (after_seq,)
        if session_id is not None:
            q, args = q + " AND session_id=?", (after_seq, session_id)
        with self._lock:
            rows = self._db.execute(q + " ORDER BY seq", args).fetchall()
        for seq, ts, sid, kind, payload in rows:
            try:
                body = json.loads(payload)
                if not isinstance(body, dict):
                    raise ValueError("payload is not an object")
                yield {"seq": seq, "ts": ts, "session": sid, "kind": kind, "payload": body, "malformed": False}
            except (ValueError, TypeError):
                yield {"seq": seq, "ts": ts, "session": sid, "kind": kind, "payload": {}, "malformed": True}

    def event_hashes(self, limit: int = 200) -> dict[int, tuple[str, str]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, prev_hash, hash FROM events ORDER BY seq DESC LIMIT ?", (limit,)
            ).fetchall()
        return {int(r[0]): (str(r[1]), str(r[2])) for r in rows}

    def session_rows(self) -> list[dict[str, Any]]:
        """Columns of ``sessions`` that are plain state. The tracker blobs, its digest and the MAC are never selected."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, created, policy_sha, ctx_conf, ctx_integ, external_count, n_calls, blind FROM sessions"
            ).fetchall()
        keys = ("id", "created", "policy_sha", "ctx_conf", "ctx_integ", "external_count", "n_calls", "blind")
        return [dict(zip(keys, r, strict=True)) for r in rows]

    def approval_times(self) -> dict[str, dict[str, Any]]:
        """Columns ``Store.get_approval`` does not return."""
        with self._lock:
            rows = self._db.execute("SELECT id, resolved_at, resolved_by, consumed_at FROM approvals").fetchall()
        return {r[0]: {"resolved_at": r[1], "resolved_by": r[2], "consumed_at": r[3]} for r in rows}

    def stamp(self) -> dict[str, Any]:
        """Cheap change detector for polling: newest event, event count, and a digest of approval states."""
        with self._lock:
            seq, n = self._db.execute("SELECT COALESCE(MAX(seq), 0), COUNT(*) FROM events").fetchone()
            ap = self._db.execute(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(state)), 0), COALESCE(MAX(created), 0) FROM approvals"
            ).fetchone()
            states = self._db.execute("SELECT state, COUNT(*) FROM approvals GROUP BY state ORDER BY state").fetchall()
            pending = self._db.execute(
                "SELECT COUNT(*) FROM approvals WHERE state='pending' AND expires>=?", (self.clock(),)
            ).fetchone()[0]
        return {
            "max_seq": seq,
            "events": n,
            "approvals": [ap[0], ap[1], ap[2], [list(s) for s in states]],
            "pending": pending,
        }


class ApprovalWriter(Store):
    """Read-write connection that only ever calls ``Store.resolve_approval``. Never creates a database."""

    def __init__(self, path: str, clock: Callable[[], float] = time.time) -> None:
        self.path, self.clock = path, clock
        self._lock = threading.RLock()
        self._db = _connect(path, "rw")

    def _refuse(self, *_a: Any, **_k: Any) -> NoReturn:
        raise ReadOnlyError("the dashboard may only resolve approvals")

    hmac_key = save_session = update_session_state = load_session = append_event = _refuse
    create_approval = consume_approval = _refuse
