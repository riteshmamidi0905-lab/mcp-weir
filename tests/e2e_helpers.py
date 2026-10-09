"""Drive the real `weir run` process over stdio with raw JSON-RPC, with testbed upstreams as real subprocesses."""

from __future__ import annotations

import contextlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

from helpers import FIXTURE, POLICY_FILE


def write_policy(
    tmp: Path,
    *,
    fixture: dict | None = None,
    fault: dict | None = None,
    rules: dict | None = None,
    call_timeout: float | None = None,
    log: Path | None = None,
    module: str = "weir_testbed.servers",
) -> tuple[Path, Path, Path]:
    """Copy examples/policies/workspace.toml and give every upstream the world fixture, an effect log and an optional fault."""
    world = tmp / "world.json"
    world.write_text(json.dumps(fixture or FIXTURE))
    log = log or tmp / "effects.jsonl"
    env = {"WEIR_WORLD": str(world), "WEIR_WORLD_LOG": str(log)}
    if fault:
        env["WEIR_FAULT"] = json.dumps(fault)
    env_line = "env = { " + ", ".join(f"{k} = {json.dumps(v)}" for k, v in env.items()) + " }"
    text = POLICY_FILE.read_text().replace("weir_testbed.servers", module)
    text = re.sub(r"(command = \[[^\]]*\])", lambda m: m.group(1) + "\n" + env_line, text)
    if call_timeout is not None:
        text = text.replace("call_timeout_seconds = 20", f"call_timeout_seconds = {call_timeout}")
    for k, v in (rules or {}).items():
        text = re.sub(rf"^{k}\s*=.*$", f"{k} = {json.dumps(v)}", text, flags=re.M)
    p = tmp / "policy.toml"
    p.write_text(text)
    return p, log, tmp / "weir.db"


def effects(log: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []


class Gateway:
    def __init__(self, policy: Path, db: Path, *, session: str = "e2e", extra: list[str] | None = None) -> None:
        self.db, self.policy = db, policy
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "mcp_weir",
                "--db",
                str(db),
                "run",
                "--policy",
                str(policy),
                "--session",
                session,
                *(extra or []),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env={**os.environ, "WEIR_LOG": "WARNING"},
        )
        self.lines: queue.Queue[str] = queue.Queue()
        self.err: list[str] = []
        threading.Thread(target=self._pump, args=(self.proc.stdout, self.lines), daemon=True).start()
        threading.Thread(target=lambda: self.err.extend(iter(self.proc.stderr.readline, "")), daemon=True).start()
        self._id = 0

    @staticmethod
    def _pump(stream, q) -> None:
        for line in iter(stream.readline, ""):
            q.put(line)
        q.put("")

    def send_raw(self, text: str) -> None:
        self.proc.stdin.write(text if text.endswith("\n") else text + "\n")
        self.proc.stdin.flush()

    def recv(self, timeout: float = 20.0) -> dict[str, Any] | None:
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("no output from the gateway; stderr: " + "".join(self.err)[-500:]) from None
        return json.loads(line) if line else None

    def request(self, method: str, params: dict | None = None, timeout: float = 20.0) -> dict[str, Any]:
        self._id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.send_raw(json.dumps(msg))
        while True:
            r = self.recv(timeout)
            if r is None or r.get("id") == self._id:
                return r or {}

    def notify(self, method: str, params: dict | None = None) -> None:
        self.send_raw(json.dumps({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})}))

    def initialize(self) -> dict[str, Any]:
        r = self.request(
            "initialize",
            {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}},
        )
        self.notify("notifications/initialized")
        return r

    def call(self, tool: str, args: dict | None = None, timeout: float = 20.0) -> dict[str, Any]:
        return self.request("tools/call", {"name": tool, "arguments": args or {}}, timeout)

    def text(self, resp: dict[str, Any]) -> str:
        return resp["result"]["content"][0]["text"]

    def close(self, kill: bool = False) -> int | None:
        if kill:
            self.proc.kill()
        else:
            with contextlib.suppress(OSError):
                self.proc.stdin.close()
        try:
            return self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return self.proc.wait()
