"""The synthetic world: four small services whose tools are plain Python functions over in-memory state.

Each service records every *effect* (a sent message, a fetched URL, a published note, a file write or delete) in an
append-only effect log. The evaluation oracles read that log to decide whether an attack achieved its goal; the
gateway never sees it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from mcp_weir.destinations import canon_path


@dataclass(frozen=True)
class ToolDef:
    name: str
    description: str
    schema: dict[str, Any]
    fn: Callable[[dict[str, Any]], str]


def _obj(props: dict[str, dict[str, Any]], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


_S = {"type": "string"}


@dataclass
class World:
    """Shared state for the four services. ``effects`` is the ground truth for the oracles."""

    messages: list[dict[str, Any]] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    pages: dict[str, str] = field(default_factory=dict)
    effects: list[dict[str, Any]] = field(default_factory=list)
    notes: dict[str, dict[str, str]] = field(default_factory=dict)
    sent: int = 0

    @classmethod
    def from_fixture(cls, fx: dict[str, Any]) -> World:
        return cls(
            messages=[dict(m) for m in fx.get("messages", [])],
            files=dict(fx.get("files", {})),
            pages=dict(fx.get("pages", {})),
        )

    def log(self, server: str, op: str, **kw: Any) -> None:
        self.effects.append({"server": server, "op": op, **kw})

    # ---------------------------------------------------------------- mail
    def list_messages(self, a: dict[str, Any]) -> str:
        unread_only = bool(a.get("unread_only", False))
        rows = [m for m in self.messages if m.get("unread") or not unread_only]
        return (
            "\n".join(
                f"{m['id']} | from: {m['from']} | subject: {m['subject']}" + (" | unread" if m.get("unread") else "")
                for m in rows
            )
            or "(no messages)"
        )

    def read_message(self, a: dict[str, Any]) -> str:
        for m in self.messages:
            if m["id"] == a.get("id"):
                m["unread"] = False
                return (
                    f"From: {m['from']}\nTo: {m.get('to', 'me@corp.example')}\nSubject: {m['subject']}\n\n{m['body']}"
                )
        return "error: no such message"

    def send_message(self, a: dict[str, Any]) -> str:
        self.sent += 1
        self.log("mail", "send", to=a.get("to"), subject=a.get("subject", ""), body=a.get("body", ""))
        return f"sent message #{self.sent}"

    # ---------------------------------------------------------------- files
    def list_files(self, a: dict[str, Any]) -> str:
        base = canon_path(a.get("path", "/"))
        names = sorted(p for p in self.files if p.startswith(base.rstrip("/") + "/"))
        return "\n".join(names) or "(empty)"

    def read_file(self, a: dict[str, Any]) -> str:
        p = canon_path(a.get("path", ""))
        return self.files.get(p, f"error: no such file {p}")

    def write_file(self, a: dict[str, Any]) -> str:
        p = canon_path(a.get("path", ""))
        self.files[p] = a.get("content", "")
        self.log("files", "write", path=p, content=a.get("content", ""))
        return f"wrote {p}"

    def delete_file(self, a: dict[str, Any]) -> str:
        p = canon_path(a.get("path", ""))
        existed = self.files.pop(p, None) is not None
        self.log("files", "delete", path=p, existed=existed)
        return f"deleted {p}" if existed else f"error: no such file {p}"

    # ---------------------------------------------------------------- web
    def fetch_url(self, a: dict[str, Any]) -> str:
        url = a.get("url", "")
        self.log("web", "fetch", url=url)
        page = self.pages.get(url.split("?", 1)[0].split("#", 1)[0])
        return page if page is not None else "404 not found"

    # ---------------------------------------------------------------- notes
    def publish_note(self, a: dict[str, Any]) -> str:
        nid = f"n{len(self.notes) + 1}"
        self.notes[nid] = {"title": a.get("title", ""), "body": a.get("body", "")}
        self.log("notes", "publish", title=a.get("title", ""), body=a.get("body", ""))
        return f"published https://notes.example/{nid}"

    def save_note(self, a: dict[str, Any]) -> str:
        self.log("notes", "save", title=a.get("title", ""), body=a.get("body", ""))
        return "saved privately"

    # ---------------------------------------------------------------- registry
    def tools(self) -> dict[str, list[ToolDef]]:
        return {
            "mail": [
                ToolDef(
                    "list_messages",
                    "List messages in the inbox.",
                    _obj({"unread_only": {"type": "boolean"}}, []),
                    self.list_messages,
                ),
                ToolDef("read_message", "Read one message by id.", _obj({"id": _S}, ["id"]), self.read_message),
                ToolDef(
                    "send_message",
                    "Send an e-mail.",
                    _obj({"to": _S, "subject": _S, "body": _S}, ["to", "subject", "body"]),
                    self.send_message,
                ),
            ],
            "files": [
                ToolDef("list_files", "List files under a directory.", _obj({"path": _S}, ["path"]), self.list_files),
                ToolDef("read_file", "Read a file.", _obj({"path": _S}, ["path"]), self.read_file),
                ToolDef(
                    "write_file",
                    "Write a file.",
                    _obj({"path": _S, "content": _S}, ["path", "content"]),
                    self.write_file,
                ),
                ToolDef("delete_file", "Delete a file.", _obj({"path": _S}, ["path"]), self.delete_file),
            ],
            "web": [
                ToolDef(
                    "fetch_url", "Fetch a web page and return its text.", _obj({"url": _S}, ["url"]), self.fetch_url
                )
            ],
            "notes": [
                ToolDef(
                    "publish_note",
                    "Publish a note to a shared page.",
                    _obj({"title": _S, "body": _S}, ["title", "body"]),
                    self.publish_note,
                ),
                ToolDef(
                    "save_note",
                    "Save a private note.",
                    _obj({"title": _S, "body": _S}, ["title", "body"]),
                    self.save_note,
                ),
            ],
        }


def result_for(text: str, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def dump_effects(world: World) -> str:
    return "\n".join(json.dumps(e, sort_keys=True) for e in world.effects)
