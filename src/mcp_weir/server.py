"""Host-facing MCP server over stdio (newline-delimited JSON-RPC 2.0).

The protocol surface is deliberately small: ``initialize``, ``ping``, ``tools/list``, ``tools/call`` and the
``initialized`` / ``cancelled`` notifications. Resources, prompts, sampling and elicitation are not advertised and
answer "method not found". Oversized messages are rejected without killing the process.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sys
from collections.abc import Awaitable, Callable
from typing import Any

from . import __version__
from .gateway import Gateway
from .session import Session

log = logging.getLogger("mcp_weir.server")

SUPPORTED_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
MAX_MESSAGE = 4 * 1024 * 1024

ReadLine = Callable[[], Awaitable[tuple[bytes, bool]]]  # (line, oversize)
WriteLine = Callable[[bytes], Awaitable[None]]


def _error(rid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


async def serve(gateway: Gateway, session: Session, read_line: ReadLine, write_line: WriteLine) -> None:
    write_lock = asyncio.Lock()
    inflight: dict[Any, asyncio.Task[None]] = {}

    async def send(obj: dict[str, Any]) -> None:
        data = (json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        async with write_lock:
            await write_line(data)

    async def handle(msg: dict[str, Any]) -> None:
        rid = msg.get("id")
        method = msg.get("method")
        params = msg.get("params")
        if params is not None and not isinstance(params, dict):
            await send(_error(rid, -32602, "params must be an object"))
            return
        params = params or {}
        try:
            if method == "initialize":
                requested = params.get("protocolVersion")
                version = requested if requested in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
                await send(
                    {
                        "jsonrpc": "2.0",
                        "id": rid,
                        "result": {
                            "protocolVersion": version,
                            "capabilities": {"tools": {"listChanged": False}},
                            "serverInfo": {"name": "mcp-weir", "version": __version__},
                        },
                    }
                )
            elif method == "ping":
                await send({"jsonrpc": "2.0", "id": rid, "result": {}})
            elif method == "tools/list":
                await send({"jsonrpc": "2.0", "id": rid, "result": {"tools": await gateway.list_tools()}})
            elif method == "tools/call":
                name, arguments = params.get("name"), params.get("arguments", {})
                if not isinstance(name, str) or not (arguments is None or isinstance(arguments, dict)):
                    await send(_error(rid, -32602, "tools/call needs a string name and an object arguments"))
                    return
                result = await gateway.call_tool(session, name, arguments if arguments is not None else {})
                await send({"jsonrpc": "2.0", "id": rid, "result": result})
            else:
                await send(_error(rid, -32601, f"method not found: {str(method)[:80]}"))
        except asyncio.CancelledError:
            raise
        except Exception:  # boundary: never leak internals to the host
            log.exception("request failed")
            await send(_error(rid, -32603, "internal error in the gateway"))

    def finish(rid: Any) -> Callable[[asyncio.Task[None]], None]:
        def _done(_: asyncio.Task[None]) -> None:
            inflight.pop(rid, None)

        return _done

    while True:
        line, oversize = await read_line()
        if oversize:
            await send(_error(None, -32600, "message exceeds the size limit"))
            continue
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            await send(_error(None, -32700, "parse error"))
            continue
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            await send(_error(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request"))
            continue
        method = msg.get("method")
        if not isinstance(method, str):
            continue  # a response to something we never asked: ignore
        if "id" not in msg:  # notification
            if method == "notifications/cancelled":
                p = msg.get("params")
                task = inflight.get(p.get("requestId")) if isinstance(p, dict) else None
                if task is not None:
                    task.cancel()
            continue
        rid = msg["id"]
        if isinstance(rid, bool) or not isinstance(rid, int | str) or rid in inflight:
            await send(_error(None, -32600, "invalid or duplicate request id"))
            continue
        task = asyncio.create_task(handle(msg))
        inflight[rid] = task
        task.add_done_callback(finish(rid))

    for t in list(inflight.values()):
        t.cancel()
    for t in list(inflight.values()):
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await t


# ---------------------------------------------------------------------- real stdio
async def stdio_io() -> tuple[ReadLine, WriteLine]:
    """Blocking reads/writes on stdin/stdout moved to threads: works for pipes, files and terminals alike."""
    inp, out = sys.stdin.buffer, sys.stdout.buffer

    def _read() -> tuple[bytes, bool]:
        line = inp.readline(MAX_MESSAGE + 1)
        if len(line) > MAX_MESSAGE and not line.endswith(b"\n"):
            while True:  # discard the rest of the oversized message
                chunk = inp.readline(1 << 20)
                if not chunk or chunk.endswith(b"\n"):
                    break
            return b"", True
        return line, False

    def _write(data: bytes) -> None:
        out.write(data)
        out.flush()

    async def read_line() -> tuple[bytes, bool]:
        return await asyncio.to_thread(_read)

    async def write_line(data: bytes) -> None:
        await asyncio.to_thread(_write, data)

    return read_line, write_line
