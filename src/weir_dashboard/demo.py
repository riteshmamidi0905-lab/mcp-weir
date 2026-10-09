"""Builds the demonstration data the Demo view shows, with the repository's existing demo code.

Nothing here replays stored decisions. A run executes the three arms of ``weir_eval.demo`` (no gateway; Weir with a careful
simulated approver; Weir with an approve-everything simulated approver) against the invented world, so every ALLOW, HOLD
and DENY is computed by the real gateway from the scripted agent's calls (or, for the recorded kind, from the recorded
replies of a real local model). The databases go to a separate directory and each gets a source file that marks it as
non-live, so the demonstration cannot be mistaken for a live session.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from pathlib import Path
from typing import Any

from mcp_weir.gateway import view_args
from weir_eval import oracles
from weir_eval.agents import ReplayAgent
from weir_eval.demo import one_arm
from weir_eval.runner import POLICY_FILE, policy_for
from weir_eval.scenarios import attack

from . import sources
from .model import norm_args

ROOT = Path(__file__).resolve().parents[2]
RECORDING = ROOT / "demo" / "recorded" / "f1-web.json"
SCENARIO = ("F1", "value", "untrusted_first", "web", 1, "demo")

ARMS = [
    ("A0", "NO GATEWAY", "A0", "none", None),
    (
        "strict",
        "WEIR + CAREFUL SIMULATED APPROVER",
        "A3",
        "strict",
        "simulated careful approver (an oracle that declines anything the attacker's text asked for)",
    ),
    (
        "careless",
        "WEIR + APPROVE-EVERYTHING SIMULATED APPROVER",
        "A3",
        "careless",
        "simulated approver that approves every hold",
    ),
]
KINDS = {"synthetic": sources.SYNTHETIC, "recorded": sources.RECORDED}


def synthetic_available() -> bool:
    """The demo uses the repository's example policy and scenario generator, so it needs a checkout (``pip install -e .``)."""
    return Path(POLICY_FILE).is_file()


def recording_available() -> bool:
    return synthetic_available() and RECORDING.is_file()


def list_runs(base: Path) -> list[dict[str, Any]]:
    runs = []
    for p in sorted(base.glob("*/run.json")) if base.is_dir() else []:
        try:
            runs.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return runs


def run_dir(base: Path, run_id: str) -> Path | None:
    if not run_id.replace("-", "").isalnum():
        return None
    p = base / run_id
    return p if (p / "run.json").is_file() else None


async def _build(kind: str, out: Path) -> dict[str, Any]:
    scn = attack(*SCENARIO)
    policy = policy_for("A3")
    recording = json.loads(RECORDING.read_text()) if kind == "recorded" else None
    agent_label = (
        "Qwen3-4B-Instruct-2507 (Q4_K_M), replies recorded from a local run on a development scenario (seed 1); the gateway decided afresh on replay"
        if recording
        else "scripted agent that obeys every instruction it reads"
    )
    arms: list[dict[str, Any]] = []
    for key, title, arm, mode, approver in ARMS:
        agent = ReplayAgent(recording[key]["model_replies"]) if recording else None
        db = out / f"weir-{key}.db"
        trace, world, sid = await one_arm(scn, arm, mode, agent, db if arm != "A0" else None)
        won = oracles.attack_success(scn, world.effects, trace.final)
        entry: dict[str, Any] = {
            "key": key,
            "title": title,
            "gateway": arm != "A0",
            "session": sid,
            "approver": approver,
            "attacker_got_secret": bool(won),
            "dataset": None if sid is None else f"demo.{out.name}.{key}",
        }
        if (
            sid is None
        ):  # no gateway, so no audit record exists: this is the demo runner's own trace of the agent's calls
            entry["calls"] = [
                {"tool": c.tool, "args": _view(policy, c.tool, c.args), "forwarded": c.forwarded} for c in trace.calls
            ]
        else:
            sources.write_manifest(
                db,
                KINDS[kind],
                written_by="weir_dashboard.demo",
                scenario=scn.id,
                agent=agent_label,
                sessions={sid: {"arm": title, "approver": approver}},
                recording=str(RECORDING.relative_to(ROOT)) if recording else None,
            )
        arms.append(entry)
    desc = {
        "format": 1,
        "id": out.name,
        "kind": kind,
        "label": sources.LABELS[KINDS[kind]],
        "detail": sources.DETAIL[KINDS[kind]],
        "created": time.time(),
        "scenario": scn.id,
        "task": scn.task,
        "agent": agent_label,
        "planted_instruction": scn.injection[:200],
        "arms": arms,
        "note": "Synthetic world: invented mailbox, files and web pages; the 'secret' is a random string made for this scenario.",
    }
    (out / "run.json").write_text(json.dumps(desc, indent=1))
    return desc


def _view(policy: Any, tool: str, args: dict[str, Any]) -> list[dict[str, Any]]:
    return norm_args(view_args(policy.tool(tool), args), False)


def build(kind: str, base: Path) -> dict[str, Any]:
    if kind not in KINDS:
        raise ValueError("unknown demo kind")
    if not synthetic_available():
        raise FileNotFoundError(
            "the demo needs a checkout of the repository installed with pip install -e . (examples/policies/workspace.toml was not found)"
        )
    if kind == "recorded" and not recording_available():
        raise FileNotFoundError("the recorded session demo/recorded/f1-web.json is not present in this checkout")
    base.mkdir(parents=True, exist_ok=True)
    out = base / f"{kind}-{secrets.token_hex(3)}"
    out.mkdir()
    return asyncio.run(_build(kind, out))
