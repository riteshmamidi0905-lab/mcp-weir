import sqlite3

import pytest

from mcp_weir.store import SessionRow, StateIntegrityError, Store


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_chain_verifies_and_detects_tampering(tmp_path):
    path = str(tmp_path / "a.db")
    s = Store(path)
    for i in range(5):
        s.append_event("s1", "call.decision", {"i": i})
    assert s.verify_chain() == (True, None, 5)
    s.close()
    db = sqlite3.connect(path)
    db.execute("UPDATE events SET payload='{\"i\":99}' WHERE seq=3")
    db.commit()
    db.close()
    ok, bad, n = Store(path).verify_chain()
    assert not ok and bad == 3 and n == 2


def test_chain_detects_deleted_and_reordered_events(tmp_path):
    for mutation in ("DELETE FROM events WHERE seq=2", "UPDATE events SET seq=seq+10 WHERE seq=2"):
        path = str(tmp_path / f"{abs(hash(mutation))}.db")
        s = Store(path)
        for i in range(4):
            s.append_event(None, "k", {"i": i})
        s.close()
        db = sqlite3.connect(path)
        db.execute(mutation)
        db.commit()
        db.close()
        assert not Store(path).verify_chain()[0]


def test_events_by_session(store):
    store.append_event("a", "k", {"x": 1})
    store.append_event("b", "k", {"x": 2})
    store.append_event("a", "k", {"x": 3})
    assert [e["payload"]["x"] for e in store.events("a")] == [1, 3]
    assert len(list(store.events())) == 3


def test_hmac_key_is_stable_per_database_and_env_overrides(tmp_path, monkeypatch):
    s = Store(str(tmp_path / "k.db"))
    k = s.hmac_key()
    assert len(k) == 32 and Store(str(tmp_path / "k.db")).hmac_key() == k
    monkeypatch.setenv("WEIR_HMAC_KEY", "ab" * 32)
    assert s.hmac_key() == bytes.fromhex("ab" * 32)


def test_session_roundtrip_and_integrity_tag(store, tmp_path):
    row = SessionRow("s1", "pol", 2, 1, 3, 11, 7, False, b"blob")
    store.save_session(row)
    assert store.load_session("s1") == row
    upd = SessionRow("s1", "pol", 1, 0, 4, 12, 8, True, b"")
    store.update_session_state(upd)
    got = store.load_session("s1")
    assert (got.ctx_conf, got.external_count, got.n_calls, got.version, got.blind, got.tracker) == (
        1,
        4,
        12,
        8,
        True,
        b"blob",
    )
    assert store.load_session("nope") is None
    with pytest.raises(KeyError):
        store.update_session_state(SessionRow("missing", "pol", 0, 0, 0, 0, 0))


@pytest.mark.parametrize(
    "tamper",
    [
        "UPDATE sessions SET ctx_conf=0",  # forget that a secret was seen
        "UPDATE sessions SET ctx_integ=0",
        "UPDATE sessions SET external_count=0",  # reset the egress budget
        "UPDATE sessions SET n_calls=0",
        "UPDATE sessions SET blind=0",
        "UPDATE sessions SET version=version+1",
        "UPDATE sessions SET policy_sha='x'",
        "UPDATE sessions SET tracker=X'00'",  # swap the tracker for an empty one
    ],
)
def test_tampering_with_a_persisted_session_is_detected(tmp_path, tamper):
    path = str(tmp_path / "t.db")
    s = Store(path)
    s.save_session(SessionRow("s1", "pol", 2, 1, 3, 11, 7, True, b"blob-bytes"))
    s.close()
    db = sqlite3.connect(path)
    db.execute(tamper)
    db.commit()
    db.close()
    with pytest.raises(StateIntegrityError):
        Store(path).load_session("s1")


def test_a_different_key_cannot_forge_a_session(tmp_path, monkeypatch):
    path = str(tmp_path / "k.db")
    monkeypatch.setenv("WEIR_HMAC_KEY", "aa" * 32)
    s = Store(path)
    s.save_session(SessionRow("s1", "pol", 2, 1, 3, 11, 7, False, b"x"))
    monkeypatch.setenv("WEIR_HMAC_KEY", "bb" * 32)
    with pytest.raises(StateIntegrityError):
        Store(path).load_session("s1")


def test_approval_lifecycle_single_use():
    clock = Clock()
    s = Store(":memory:", clock)
    aid = s.create_approval("s1", "h1", "mail__send_message", ["R-FLOW-CONF"], {"tool": "x"}, ttl=60)
    assert (
        s.create_approval("s1", "h1", "mail__send_message", ["R-FLOW-CONF"], {}, ttl=60) == aid
    )  # idempotent while open
    assert s.consume_approval("s1", "h1") is None  # still pending
    assert s.resolve_approval(aid, True) == "approved"
    assert s.consume_approval("s2", "h1") is None  # another session cannot use it
    assert s.consume_approval("s1", "other") is None  # nor can another call
    assert s.consume_approval("s1", "h1") == aid
    assert s.consume_approval("s1", "h1") is None  # single use
    assert s.resolve_approval(aid, True) == "already consumed"
    assert s.latest_approval_state("s1", "h1") == "consumed"


def test_approval_expiry_and_denial():
    clock = Clock()
    s = Store(":memory:", clock)
    a = s.create_approval("s1", "h1", "t", [], {}, ttl=60)
    clock.t += 61
    assert s.resolve_approval(a, True) == "expired"
    b = s.create_approval("s1", "h2", "t", [], {}, ttl=60)
    assert s.resolve_approval(b, True) == "approved"
    clock.t += 61
    assert s.consume_approval("s1", "h2") is None  # approved but too late
    assert s.latest_approval_state("s1", "h2") == "expired"
    c = s.create_approval("s1", "h3", "t", [], {}, ttl=60)
    assert s.resolve_approval(c, False) == "denied" and s.latest_approval_state("s1", "h3") == "denied"
    assert s.resolve_approval("ap_missing", True) == "missing"
    assert [x.id for x in s.list_approvals("denied")] == [c]
    assert s.get_approval(c).state == "denied"


def test_concurrent_consume_yields_one_winner(tmp_path):
    import threading

    s = Store(str(tmp_path / "c.db"))
    aid = s.create_approval("s1", "h", "t", [], {}, ttl=60)
    s.resolve_approval(aid, True)
    wins = []
    threads = [threading.Thread(target=lambda: wins.append(s.consume_approval("s1", "h"))) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(w is not None for w in wins) == 1
