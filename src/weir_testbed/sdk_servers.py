"""The same synthetic services as ``servers.py``, built with the official MCP Python SDK (``pip install mcp``).

Used to show that Weir interoperates with real SDK-built servers (schemas, structured output, protocol handshake)
rather than only with the hand-written testbed server. Run: ``python -m weir_testbed.sdk_servers <mail|files|web|notes>``.
"""

from __future__ import annotations

import json
import os
import sys

from mcp.server import MCPServer

from .world import World


def build(service: str, world: World, log_path: str | None = None) -> MCPServer:
    srv = MCPServer(f"testbed-{service}")
    flushed = 0

    def flush() -> None:
        nonlocal flushed
        if log_path and len(world.effects) > flushed:
            with open(log_path, "a", encoding="utf-8") as f:
                for e in world.effects[flushed:]:
                    f.write(json.dumps(e, sort_keys=True) + "\n")
            flushed = len(world.effects)

    if service == "mail":

        @srv.tool(description="List messages in the inbox.")
        def list_messages(unread_only: bool = False) -> str:
            return world.list_messages({"unread_only": unread_only})

        @srv.tool(description="Read one message by id.")
        def read_message(id: str) -> str:
            return world.read_message({"id": id})

        @srv.tool(description="Send an e-mail.")
        def send_message(to: str, subject: str, body: str) -> str:
            out = world.send_message({"to": to, "subject": subject, "body": body})
            flush()
            return out

    elif service == "files":

        @srv.tool(description="List files under a directory.")
        def list_files(path: str) -> str:
            return world.list_files({"path": path})

        @srv.tool(description="Read a file.")
        def read_file(path: str) -> str:
            return world.read_file({"path": path})

        @srv.tool(description="Write a file.")
        def write_file(path: str, content: str) -> str:
            out = world.write_file({"path": path, "content": content})
            flush()
            return out

        @srv.tool(description="Delete a file.")
        def delete_file(path: str) -> str:
            out = world.delete_file({"path": path})
            flush()
            return out

    elif service == "web":

        @srv.tool(description="Fetch a web page and return its text.")
        def fetch_url(url: str) -> str:
            out = world.fetch_url({"url": url})
            flush()
            return out

    elif service == "notes":

        @srv.tool(description="Publish a note to a shared page.")
        def publish_note(title: str, body: str) -> str:
            out = world.publish_note({"title": title, "body": body})
            flush()
            return out

        @srv.tool(description="Save a private note.")
        def save_note(title: str, body: str) -> str:
            out = world.save_note({"title": title, "body": body})
            flush()
            return out

    else:
        raise SystemExit(f"unknown service {service!r}")
    return srv


def main(argv: list[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        sys.exit("usage: python -m weir_testbed.sdk_servers <mail|files|web|notes>")
    path = os.environ.get("WEIR_WORLD")
    fx = json.loads(open(path, encoding="utf-8").read()) if path else {}  # noqa: SIM115
    build(argv[0], World.from_fixture(fx), os.environ.get("WEIR_WORLD_LOG")).run(transport="stdio")


if __name__ == "__main__":
    main()
