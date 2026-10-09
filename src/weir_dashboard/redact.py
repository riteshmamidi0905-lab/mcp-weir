"""Display-time masking. Nothing here changes what is stored; it changes what a screen shows.

The gateway already stores content arguments only as length and digest. What it does store in clear is what a person
approving a call needs: recipients, URL host and path, file paths, and arguments the policy did not declare as content
(see ``mcp_weir.gateway.view_args``). Masking mode hides those too, by shape, so a screen share does not show them.
"""

from __future__ import annotations

import re
from typing import Any

DOT = "•"
_EMAIL = re.compile(r"^([^@\s,;]+)@([^@\s,;]+)$")
_URL = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/\s?#:]+)(:\d+)?(/.*)?$")


def mask_text(s: str) -> str:
    """Keep only the shape: the first character, a count, and (for addresses) the top-level domain."""
    s = s.strip()
    if not s:
        return s
    if "," in s or ";" in s:
        return ", ".join(mask_text(p) for p in re.split(r"[,;]\s*", s) if p)
    m = _EMAIL.match(s)
    if m:
        tld = m.group(2).rsplit(".", 1)[-1] if "." in m.group(2) else ""
        return f"{m.group(1)[:1]}{DOT * 3}@{DOT * 3}" + (f".{tld}" if tld else "")
    m = _URL.match(s)
    if m:
        host = m.group(2)
        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        path = m.group(4) or ""
        return (
            f"{m.group(1)}://{host[:1]}{DOT * 3}"
            + (f".{tld}" if tld else "")
            + (f"/{DOT * 3}" if path.strip("/") else "")
        )
    if s.startswith("/"):
        first = s.split("/")[1] if len(s.split("/")) > 1 else ""
        return f"/{first}/{DOT * 3}" if s.count("/") > 1 else f"/{DOT * 3}"
    return f"{s[:1]}{DOT * 3} ({len(s)} chars)"


def mask_arg(arg: dict[str, Any]) -> dict[str, Any]:
    if arg.get("kind") == "clear":
        return {**arg, "text": mask_text(str(arg.get("text", ""))), "masked": True}
    return arg
