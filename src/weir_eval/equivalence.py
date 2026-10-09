"""Does the fast in-process harness behave like the real gateway process?

For a sample of scenarios, run the scripted agent through the REAL stack: ``python -m mcp_weir run`` over stdio,
upstream testbed servers as separate processes, approvals answered through the database exactly as ``weir approvals``
would (the human oracle reads the approval record, resolves it, and the agent retries the identical call). Compare, call by
call, whether the call ran and which rules fired, and compare the world's effects, with the in-process run.

    python -m weir_eval.equivalence --suite dev --n 40 --arms A3,A1 --modes strict,careless
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp_weir.policy import load_policy
from mcp_weir.store import Store

from . import oracles
from .agents import CallRec, Trace, run_scripted
from .runner import ARM_RULES, POLICY_FILE, make_approver, run_one
from .scenarios import Scenario, suite


def policy_text(arm: str, world: Path, log: Path) -> str:
    text = POLICY_FILE.read_text()
    env = f'env = {{ WEIR_WORLD = "{world}", WEIR_WORLD_LOG = "{log}" }}'
    text = re.sub(r"(command = \[[^\]]*\])", lambda m: m.group(1) + "\n" + env, text)
    for key, val in (ARM_RULES[arm] or {}).items():
        text, n = re.subn(rf"^{key}\s*=.*$", f'{key} = "{val}"', text, flags=re.M)
        assert n == 1, key
    return text


class StdioGateway:
    def __init__(self, proc: asyncio.subprocess.Process) -> None:
        self.proc, self._id = proc, 0

    async def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method, **({"params": params} if params is not None else {})}
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self.proc.stdin.drain()
        while True:
            line = await asyncio.wait_for(self.proc.stdout.readline(), 60)
            if not line:
                raise RuntimeError("gateway exited")
            r = json.loads(line)
            if r.get("id") == self._id:
                return r  # type: ignore[no-any-return]


async def run_stdio(scn: Scenario, arm: str, mode: str) -> tuple[Trace, list[dict[str, Any]], list[list[str]]]:
    tmp = Path(tempfile.mkdtemp(prefix="weir-eq-"))
    world, log, pol, db = tmp / "world.json", tmp / "effects.jsonl", tmp / "policy.toml", tmp / "weir.db"
    world.write_text(json.dumps(scn.fixture))
    pol.write_text(policy_text(arm, world, log))
    policy = load_policy(pol)
    approver = make_approver(mode, scn, policy)
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "mcp_weir",
        "--db",
        str(db),
        "run",
        "--policy",
        str(pol),
        "--session",
        "eq",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=dict(os.environ),
    )
    gw = StdioGateway(proc)
    await gw.request(
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "eq", "version": "0"}},
    )
    assert proc.stdin is not None
    proc.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
    store = Store(str(db))

    class Ep:
        async def list_tools(self) -> list[dict[str, Any]]:
            return (await gw.request("tools/list"))["result"]["tools"]  # type: ignore[no-any-return]

        async def call(self, name: str, args: dict[str, Any]) -> CallRec:
            for _ in range(2):
                res = (await gw.request("tools/call", {"name": name, "arguments": args}))["result"]
                text = "\n".join(b.get("text", "") for b in res.get("content", []) if b.get("type") == "text")
                m = re.search(r"Approval id: (ap_[0-9a-f]+)", text)
                if m and approver is not None:
                    ap = store.get_approval(m.group(1))
                    if ap is not None and bool(approver(ap)):
                        store.resolve_approval(ap.id, True, by="oracle")
                        continue  # the human said yes: retry the identical call
                    if ap is not None:
                        store.resolve_approval(ap.id, False, by="oracle")
                break
            forwarded = not (res.get("isError") and text.startswith("weir:"))
            return CallRec(name, args, "", text, bool(res.get("isError")), forwarded, [], None, 0.0)

    trace = await run_scripted(scn, Ep(), compromised=scn.kind == "attack")
    assert proc.stdin is not None
    proc.stdin.close()
    await proc.wait()
    effects = [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
    # per-call rule codes, from the audit trail (decisions in order; one decision per call attempt)
    codes = [[h["code"] for h in e["payload"]["rules"]] for e in store.events("eq") if e["kind"] == "call.decision"]
    return trace, effects, codes


async def compare(scn: Scenario, arm: str, mode: str) -> dict[str, Any]:
    ref = await run_one(scn, arm, mode, keep_trace=True)
    trace, effects, codes = await run_stdio(scn, arm, mode)
    ref_calls = ref["trace"]["calls"]
    same_forward = [c["forwarded"] for c in ref_calls] == [c.forwarded for c in trace.calls]
    # rule codes per distinct call (in-process records the codes of the final attempt of each step)
    # a denial by the oracle human ends the step in-process; over stdio the agent simply does not retry, so that code never appears
    flat_ref = {code for c in ref_calls for code in c["codes"]} - {"R-APPROVAL-DENIED"}
    flat_stdio = {code for cs in codes for code in cs}
    ok_attack = oracles.attack_success(scn, effects, trace.final) if scn.attack else None
    ok_benign = None
    if not scn.attack:
        ok_benign = oracles.benign_ok(scn, [c.__dict__ for c in trace.calls], effects, trace.final)
    return {
        "id": scn.id,
        "arm": arm,
        "mode": mode,
        "same_forwarding": same_forward,
        "same_rules": flat_ref == flat_stdio,
        "ref_attack": ref.get("attack_success"),
        "stdio_attack": ok_attack,
        "ref_benign": ref.get("benign_ok"),
        "stdio_benign": ok_benign,
        "ref_rules": sorted(flat_ref),
        "stdio_rules": sorted(flat_stdio),
        "agree": same_forward
        and flat_ref == flat_stdio
        and ref.get("attack_success") == ok_attack
        and ref.get("benign_ok") == ok_benign,
    }


async def main_async(a: argparse.Namespace) -> int:
    scns = suite(a.suite)
    random.Random(a.seed).shuffle(scns)
    scns = scns[: a.n]
    rows = []
    for scn in scns:
        for arm in a.arms.split(","):
            for mode in a.modes.split(","):
                rows.append(await compare(scn, arm, mode))
    agree = sum(r["agree"] for r in rows)
    print(
        f"equivalence: {agree}/{len(rows)} runs agree (forwarding of every call, rules fired, attack outcome, task outcome)"
    )
    for r in rows:
        if not r["agree"]:
            print("  DISAGREE", json.dumps(r))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps({"agree": agree, "total": len(rows), "rows": rows}, indent=1))
    return 0 if agree == len(rows) else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", default="dev")
    ap.add_argument("--n", type=int, default=20, help="number of scenarios (sampled with --seed)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--arms", default="A3")
    ap.add_argument("--modes", default="strict,careless")
    ap.add_argument("--out", default="eval/results/equivalence.json")
    return asyncio.run(main_async(ap.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
