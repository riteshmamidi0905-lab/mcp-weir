"""Tool-definition pinning: detect a tool whose name, description or schema changed after review ("rug pull")."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .store import canonical


def definition_hash(tool: dict[str, Any]) -> str:
    """SHA-256 of the canonical tool definition, ignoring protocol metadata (``_meta``)."""
    return hashlib.sha256(canonical({k: v for k, v in tool.items() if k != "_meta"}).encode()).hexdigest()


def load_lock(path: str | Path) -> dict[str, str]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        tools = data["tools"]
        if (
            data.get("version") != 1
            or not isinstance(tools, dict)
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in tools.items())
        ):
            raise ValueError("unexpected lock structure")
        return dict(tools)
    except (OSError, ValueError, KeyError) as e:
        raise ValueError(f"cannot read lock file {path}: {e}") from None


def write_lock(path: str | Path, hashes: dict[str, str]) -> None:
    Path(path).write_text(
        json.dumps({"version": 1, "tools": dict(sorted(hashes.items()))}, indent=2) + "\n", encoding="utf-8"
    )
