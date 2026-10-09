"""Overhead microbenchmark: what does a gateway decision cost, in-process and over stdio?

In-process: time ``call_tool`` minus the (instant) in-process upstream, with a tracker holding N registered results.
Stdio: round-trip of a read-only call through the real gateway process versus straight to the same testbed server.
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mcp_weir.gateway import Gateway
from mcp_weir.labels import Conf, Integ, Label
from mcp_weir.policy import load_policy
from mcp_weir.store import Store
from weir_testbed.servers import in_process_upstreams
from weir_testbed.world import World

from .runner import POLICY_FILE
from .scenarios import ALNUM, base_world


def pct(vals: list[float], p: float) -> float:
    s = sorted(vals)
    return s[min(len(s) - 1, int(p * len(s)))]


async def in_process(n_fragments: int, calls: int = 2000) -> dict[str, float]:
    fx, _ = base_world(0)
    world = World.from_fixture(fx)
    gw = Gateway(load_policy(POLICY_FILE), Store(":memory:"), in_process_upstreams(world))
    await gw.start()
    s = gw.open_session()
    rng = random.Random(1)
    for i in range(n_fragments):  # 10,000 labelled results of ~200 characters
        s.tracker.register(
            f"c{i}",
            "files__read_file",
            Label(Conf.SECRET if i % 5 == 0 else Conf.INTERNAL, Integ.TRUSTED),
            "".join(rng.choices(ALNUM + "     ", k=200)),
        )
    s.ctx = Label(Conf.SECRET, Integ.UNTRUSTED)
    body = "".join(rng.choices(ALNUM + " ", k=1000))  # a 1 KB argument that matches nothing
    lat: list[float] = []
    for i in range(calls):
        out = await gw.call_tool_detailed(
            s,
            "mail__send_message" if i % 2 else "files__read_file",
            {"to": "lee@corp.example", "subject": "s", "body": body} if i % 2 else {"path": "/docs/q3.txt"},
        )
        lat.append(out.overhead_us)
    return {
        "fragments": n_fragments,
        "calls": calls,
        "p50_us": pct(lat, 0.5),
        "p95_us": pct(lat, 0.95),
        "p99_us": pct(lat, 0.99),
        "max_us": max(lat),
    }


def stdio(calls: int = 200) -> dict[str, float]:
    tmp = Path(tempfile.mkdtemp())
    fx = tmp / "world.json"
    fx.write_text(json.dumps(base_world(0)[0]))
    text = POLICY_FILE.read_text().replace("weir_testbed.servers", "weir_testbed.servers")
    import re

    env = f'env = {{ WEIR_WORLD = "{fx}" }}'
    pol = tmp / "policy.toml"
    pol.write_text(re.sub(r"(command = \[[^\]]*\])", lambda m: m.group(1) + "\n" + env, text))

    def talk(cmd: list[str], tool: str) -> list[float]:
        p = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env={**os.environ, "WEIR_WORLD": str(fx)},
        )
        assert p.stdin and p.stdout

        def rt(msg: dict[str, object]) -> dict[str, object]:
            assert p.stdin is not None and p.stdout is not None
            p.stdin.write(json.dumps(msg) + "\n")
            p.stdin.flush()
            out: dict[str, object] = json.loads(p.stdout.readline())
            return out

        rt(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "b", "version": "0"},
                },
            }
        )
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        out = []
        for i in range(calls):
            t = time.perf_counter()
            rt(
                {
                    "jsonrpc": "2.0",
                    "id": i + 2,
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": {"path": "/docs/q3.txt"}},
                }
            )
            out.append((time.perf_counter() - t) * 1000)
        p.stdin.close()
        p.wait(timeout=10)
        return out

    direct = talk([sys.executable, "-m", "weir_testbed.servers", "files"], "read_file")
    via = talk(
        [sys.executable, "-m", "mcp_weir", "--db", str(tmp / "b.db"), "run", "--policy", str(pol)], "files__read_file"
    )
    return {
        "calls": calls,
        "direct_p50_ms": statistics.median(direct),
        "direct_p99_ms": pct(direct, 0.99),
        "gateway_p50_ms": statistics.median(via),
        "gateway_p99_ms": pct(via, 0.99),
        "added_p50_ms": statistics.median(via) - statistics.median(direct),
    }


def main() -> int:
    res = {"in_process": [asyncio.run(in_process(n)) for n in (0, 1000, 10000)], "stdio": stdio()}
    print(json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
