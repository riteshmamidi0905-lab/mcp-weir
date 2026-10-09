"""The one write this package makes: resolving a held approval, through the gateway store's own ``resolve_approval``.

What the existing approval mechanism does (read from ``mcp_weir/store.py`` and ``gateway.py``, see docs/dashboard.md):

* an approval row is bound to (session, canonical hash of tool + arguments); the gateway consumes it only for a call with
  the same pair, once, before it expires (``consume_approval``);
* ``resolve_approval`` moves ``pending`` to ``approved`` or ``denied`` inside one ``BEGIN IMMEDIATE`` transaction and
  reports ``already <state>``, ``expired`` or ``missing`` otherwise, so two resolvers cannot both win;
* the gateway never waits: the agent has to repeat the identical call after an approval;
* a human decision made this way (or with ``weir approvals``) is stored in the ``approvals`` table; the gateway itself
  adds ``approval.resolve`` events only for its in-process approver, and ``approval.consumed`` when a repeat call uses it.

This module adds three checks before delegating: the dataset must be the primary, local one; the approval must exist
and still be pending; and the fingerprint the person was shown must equal the stored row's.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any

from . import model
from .readonly import ApprovalWriter, DashboardDBError

BY = "dashboard"


def resolve(
    ds: model.Dataset, approval_id: str, decision: str, fingerprint: str, clock: Any = time.time
) -> tuple[int, dict[str, Any]]:
    if decision not in ("approve", "deny"):
        return 400, _fail("bad_request", "decision must be 'approve' or 'deny'")
    if not ds.writable or ds.manifest() is not None:
        return 403, _fail(
            "not_live", "Approvals can only be resolved for a live local database, not a demonstration or recording."
        )
    try:
        store = ds.open()
    except DashboardDBError as e:
        return 503, _fail(e.state, e.message)
    try:
        a = store.get_approval(approval_id)
    except sqlite3.Error:
        return 503, _fail("db", "Could not read the approval. Nothing was changed.")
    finally:
        store.close()
    if a is None:
        return 404, _fail("missing", "No such approval.")
    if fingerprint != model.fingerprint(a):
        return 409, _fail(
            "changed", "This approval is not what the page showed. Reload and review it again. Nothing was changed."
        )
    state = model.eff_state(a.state, a.expires, clock())
    if state != "pending":
        return 409, _fail(state, f"This approval is already {state}. Nothing was changed.")
    try:
        writer = ApprovalWriter(ds.path)
    except DashboardDBError as e:
        return 503, _fail(e.state, e.message)
    try:
        outcome = writer.resolve_approval(approval_id, decision == "approve", by=BY)
    except sqlite3.Error:
        return 503, _fail("db", "The database refused the change. Nothing was changed.")
    finally:
        writer.close()
    if outcome in ("approved", "denied"):
        msg = (
            "Approved once. The agent must now repeat the identical call; the gateway does not run it by itself."
            if outcome == "approved"
            else "Denied. Repeating the identical call will be blocked (R-APPROVAL-DENIED)."
        )
        return 200, {"ok": True, "state": outcome, "message": msg}
    code = "expired" if outcome == "expired" else "conflict" if outcome.startswith("already") else outcome
    return 409, _fail(code, f"Not changed: {outcome}.")


def _fail(code: str, message: str) -> dict[str, Any]:
    return {"ok": False, "code": code, "message": message}
