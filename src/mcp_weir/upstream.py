"""Upstream MCP servers: one asynchronous JSON-RPC client per server, over stdio.

The upstream process gets a minimal environment (never the gateway's own secrets), every request has a timeout,
and a crash fails the in-flight requests instead of hanging them. Non-idempotent calls are never retried.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from collections import deque
from collections.abc import Callable
from typing import Any, Protocol

from . import __version__
from .policy import UpstreamSpec

log = logging.getLogger("mcp_weir.upstream")

PROTOCOL_VERSION = "2025-06-18"
MAX_LINE = 16 * 1024 * 1024
_ENV_PASSTHROUGH = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "PYTHONPATH", "VIRTUAL_ENV", "SYSTEMROOT")


class UpstreamError(Exception):
    """The upstream failed in a way that is not a tool-level error result."""


class Upstream(Protocol):
    name: str

    async def start(self) -> None: ...
    async def list_tools(self) -> list[dict[str, Any]]: ...
    async def call_tool(self, name: str, arguments: dict[str, Any], timeout: float) -> dict[str, Any]: ...
    async def close(self) -> None: ...


class StdioUpstream:
    def __init__(
        self, spec: UpstreamSpec, *, start_timeout: float = 15.0, on_tools_changed: Callable[[str], None] | None = None
    ) -> None:
        self.name = spec.name
        self._spec = spec
        self._start_timeout = start_timeout
        self._on_tools_changed = on_tools_changed
        self._proc: asyncio.subprocess.Process | None = None
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._next_id = 1
        self._write_lock = asyncio.Lock()
        self._tasks: list[asyncio.Task[None]] = []
        self._closed = False
        self.stderr_tail: deque[str] = deque(maxlen=100)

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        env = {k: os.environ[k] for k in _ENV_PASSTHROUGH if k in os.environ}
        env.update(dict(self._spec.env))
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *self._spec.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=self._spec.cwd,
                limit=MAX_LINE,
            )
        except OSError as e:
            raise UpstreamError(f"cannot start upstream {self.name!r}: {e}") from None
        self._tasks = [asyncio.create_task(self._read_loop()), asyncio.create_task(self._stderr_loop())]
        try:
            await self._request(
                "initialize",
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-weir", "version": __version__},
                },
                self._start_timeout,
            )
            await self._notify("notifications/initialized")
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        self._closed = True
        proc = self._proc
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError, OSError):
                if proc.stdin:
                    proc.stdin.close()
            try:
                await asyncio.wait_for(proc.wait(), 2.0)
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), 2.0)
                except TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                    await proc.wait()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        self._fail_pending("upstream closed")

    # ------------------------------------------------------------------ API
    async def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(100):  # a paginator that never ends cannot hang the gateway
            res = await self._request("tools/list", {"cursor": cursor} if cursor else {}, self._start_timeout)
            tools.extend(t for t in res.get("tools", []) if isinstance(t, dict) and isinstance(t.get("name"), str))
            cursor = res.get("nextCursor")
            if not cursor:
                return tools
        raise UpstreamError("tools/list pagination did not terminate")

    async def call_tool(self, name: str, arguments: dict[str, Any], timeout: float) -> dict[str, Any]:
        return await self._request("tools/call", {"name": name, "arguments": arguments}, timeout)

    # ------------------------------------------------------------------ JSON-RPC plumbing
    async def _send(self, obj: dict[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or self._closed or proc.returncode is not None:
            raise UpstreamError(f"upstream {self.name!r} is not running")
        async with self._write_lock:
            try:
                proc.stdin.write((json.dumps(obj, separators=(",", ":")) + "\n").encode())
                await proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError, OSError):
                raise UpstreamError(f"upstream {self.name!r} closed its input") from None

    async def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        await self._send(msg)

    async def _request(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        rid = self._next_id
        self._next_id += 1
        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        try:
            await self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
            return await asyncio.wait_for(fut, timeout)
        except TimeoutError:
            with contextlib.suppress(UpstreamError):
                await self._notify("notifications/cancelled", {"requestId": rid, "reason": "gateway timeout"})
            raise UpstreamError(f"upstream {self.name!r} timed out after {timeout:g}s on {method}") from None
        finally:
            self._pending.pop(rid, None)

    def _fail_pending(self, why: str) -> None:
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(UpstreamError(f"upstream {self.name!r}: {why}"))

    async def _read_loop(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        try:
            while True:
                try:
                    line = await self._proc.stdout.readline()
                except (ValueError, asyncio.LimitOverrunError):
                    self._fail_pending("message exceeded the size limit")
                    continue
                if not line:
                    break
                try:
                    msg = json.loads(line)
                except (ValueError, RecursionError):
                    log.warning("upstream %s sent non-JSON output", self.name)
                    continue
                if isinstance(msg, dict):
                    await self._dispatch(msg)
        finally:
            self._fail_pending("process exited" if not self._closed else "closed")

    async def _dispatch(self, msg: dict[str, Any]) -> None:
        if "method" not in msg:  # a response
            rid = msg.get("id")
            fut = self._pending.get(rid) if isinstance(rid, int) else None
            if fut is None or fut.done():
                return
            if "error" in msg:
                err = msg["error"] if isinstance(msg["error"], dict) else {}
                fut.set_exception(
                    UpstreamError(f"upstream {self.name!r} error {err.get('code')}: {str(err.get('message'))[:300]}")
                )
            else:
                res = msg.get("result")
                fut.set_result(res if isinstance(res, dict) else {})
            return
        method = msg["method"]
        if "id" in msg:  # a server->client request: we advertise no capabilities, so refuse all but ping
            if method == "ping":
                with contextlib.suppress(UpstreamError):
                    await self._send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
            else:
                with contextlib.suppress(UpstreamError):
                    await self._send(
                        {
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "error": {"code": -32601, "message": "method not supported by the gateway"},
                        }
                    )
        elif method == "notifications/tools/list_changed" and self._on_tools_changed:
            self._on_tools_changed(self.name)

    async def _stderr_loop(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        while True:
            try:
                line = await self._proc.stderr.readline()
            except (ValueError, asyncio.LimitOverrunError):
                continue
            if not line:
                return
            self.stderr_tail.append(line.decode("utf-8", "replace").rstrip()[:500])
