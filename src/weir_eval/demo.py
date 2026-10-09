"""The 60-second demonstration: one poisoned task, three ways.

    python -m weir_eval.demo                       # scripted obedient agent, no model needed
    python -m weir_eval.demo --replay demo/recorded/<name>.json   # replay recorded Qwen3-4B replies through the live gateway
    python -m weir_eval.demo --live                # run the local model now (llama-server on :8080)
    python -m weir_eval.demo --record demo/recorded/<name>.json   # (with --live) save the model's replies

For each of: no gateway; Weir with a careful human; Weir with a human who approves everything. Writes an HTML flow
trace of the third run (and of the second) from the audit chain.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp_weir import report
from mcp_weir.gateway import Gateway
from mcp_weir.store import Store
from weir_testbed.servers import in_process_upstreams
from weir_testbed.world import World

from . import oracles
from .agents import DirectEndpoint, GatewayEndpoint, LlamaAgent, ReplayAgent, Trace, run_scripted
from .runner import make_approver, policy_for
from .scenarios import Scenario, attack

RED, GREEN, AMBER, DIM, BOLD, OFF = "\033[31m", "\033[32m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"


def paint(s: str, c: str, tty: bool) -> str:
    return f"{c}{s}{OFF}" if tty else s


def write_source(db: Path, source: str, scn: Scenario, agent: str, sid: str, arm: str) -> None:
    """Mark a database this script made as non-live, in the file the dashboard reads (<db>.weir-source.json)."""
    body = {
        "format": 1,
        "source": source,
        "written_by": "weir_eval.demo",
        "scenario": scn.id,
        "agent": agent,
        "sessions": {sid: {"arm": arm}},
    }
    db.with_name(db.name + ".weir-source.json").write_text(json.dumps(body, indent=1, sort_keys=True) + "\n")


def mask(text: str, scn: Scenario) -> str:
    c = scn.attack.canary if scn.attack else ""
    return text.replace(c, c[:4] + "…" + "*" * 6) if c else text


async def one_arm(
    scn: Scenario, arm: str, mode: str, agent: LlamaAgent | None, db: Path | None
) -> tuple[Trace, World, str | None]:
    world = World.from_fixture(scn.fixture)
    ups = in_process_upstreams(world)
    sid = None
    if arm == "A0":
        ep: Any = DirectEndpoint(ups)
    else:
        pol = policy_for(arm)
        gw = Gateway(pol, Store(str(db)), ups, approver=make_approver(mode, scn, pol))
        await gw.start()
        session = gw.open_session(f"demo-{mode}")
        sid = session.id
        ep = GatewayEndpoint(gw, session)
    trace = await run_scripted(scn, ep, compromised=True) if agent is None else await agent.run(scn.task, ep)
    return trace, world, sid


def show(title: str, trace: Trace, world: World, scn: Scenario, tty: bool) -> bool:
    print(paint(f"\n{title}", BOLD, tty))
    for i, c in enumerate(trace.calls, 1):
        args = ", ".join(f"{k}={str(v)[:44]!r}" for k, v in c.args.items() if k not in ("body", "content"))
        if c.forwarded:
            tag = paint("ran", GREEN, tty) if c.tag != "attack" else paint("ran", RED, tty)
        elif "R-APPROVAL-DENIED" in c.codes:
            tag = paint("held, human said no", AMBER, tty)
        elif c.approval:
            tag = paint("held for a human", AMBER, tty)
        else:
            tag = paint("blocked", AMBER, tty)
        shown = " ".join(x for x in c.codes if x != "R-APPROVAL-DENIED")
        print(f"  {i}. {c.tool:<21} {args:<52} {tag}  {paint(shown, DIM, tty)}")
    won = oracles.attack_success(scn, world.effects, trace.final)
    print(
        "  "
        + (paint("ATTACKER GOT THE SECRET", RED, tty) if won else paint("nothing reached the attacker", GREEN, tty))
    )
    return won


async def main_async(a: argparse.Namespace) -> int:
    tty = sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))
    fam, var, order, delivery, seed = (a.scenario or "F1:value:untrusted_first:web:1").split(":")
    scn = attack(fam, var, order, delivery, int(seed), "demo")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    print(paint("WEIR DEMO", BOLD, tty), f" scenario {scn.id}")
    print(f"  user asks:   {scn.task}")
    print(
        f"  the content the agent will read contains a planted instruction:\n    {paint(scn.injection[:150], DIM, tty)}…"
    )
    if scn.attack:
        print(f"  secret:      {scn.attack.secret_path}  (value {mask(scn.attack.canary, scn)})")
    recording = json.loads(Path(a.replay).read_text()) if a.replay else None
    results: dict[str, dict[str, Any]] = {}
    for key, (title, arm, mode) in {
        "A0": ("A. Same agent, no gateway", "A0", "none"),
        "strict": ("B. Same agent behind Weir, a careful human is asked", "A3", "strict"),
        "careless": ("C. Behind Weir, and a human who approves everything", "A3", "careless"),
    }.items():
        agent: LlamaAgent | None = None
        if recording:
            agent = ReplayAgent(recording[key]["model_replies"])
        elif a.live:
            agent = LlamaAgent(a.base_url)
        db = out / f"weir-{key}.db"
        db.unlink(missing_ok=True)
        trace, world, sid = await one_arm(scn, arm, mode, agent, db if arm != "A0" else None)
        results[key] = {"model_replies": trace.raw, "final": trace.final}
        if sid:
            write_source(
                db,
                "recorded-replay" if recording else "synthetic-demo",
                scn,
                "recorded model replies"
                if recording
                else "local model, run live"
                if a.live
                else "scripted obedient agent",
                sid,
                title,
            )
        won = show(title, trace, world, scn, tty)
        if sid:
            store = Store(str(db))
            events = list(store.events(sid))
            page = report.render_html(
                sid,
                "workspace",
                events[0]["payload"].get("policy", ""),
                report.build_records(events),
                store.verify_chain(),
            )
            (out / f"trace-{key}.html").write_text(page)
        results[key]["attacker_won"] = won
    if a.record:
        Path(a.record).parent.mkdir(parents=True, exist_ok=True)
        Path(a.record).write_text(json.dumps({**results, "scenario": scn.id}, indent=1))
        print(f"\nrecorded model replies to {a.record}")
    print(f"\nflow traces: {out}/trace-strict.html, {out}/trace-careless.html")
    return 0 if results["A0"]["attacker_won"] and not results["strict"]["attacker_won"] else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="weir_eval.demo")
    ap.add_argument("--scenario", help="family:variant:order:delivery:seed, e.g. F1:value:untrusted_first:web:1")
    ap.add_argument("--live", action="store_true", help="drive the local model instead of the scripted agent")
    ap.add_argument("--replay", help="replay a recording made with --live --record")
    ap.add_argument("--record", help="save the model's replies here")
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--out", default=tempfile.mkdtemp(prefix="weir-demo-"))
    return asyncio.run(main_async(ap.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
