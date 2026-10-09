"""Where a session came from: live local gateway, recorded replay, or synthetic demonstration.

The audit log does not say how a session was produced, so the label comes from a small JSON file next to the database
(``<db>.weir-source.json``) written by whatever produced it (``weir_eval.demo`` and this package's demo loader both
write one). A database without that file is read as the output of a local gateway. A manifest that exists but cannot be
understood is never read as live: the session is labelled ``SOURCE UNKNOWN``.

This is a label, not proof: the file is plain JSON that anyone with write access can edit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SUFFIX = ".weir-source.json"
FORMAT = 1
LIVE_WINDOW_S = 120  # a local session with an event this recent is shown as live

LIVE = "live-local"
RECORDED = "recorded-replay"
SYNTHETIC = "synthetic-demo"
UNKNOWN = "unknown"

LABELS = {
    LIVE: "LIVE LOCAL SESSION",
    RECORDED: "RECORDED REAL-MODEL REPLAY",
    SYNTHETIC: "SYNTHETIC DEMO",
    UNKNOWN: "SOURCE UNKNOWN",
}
DETAIL = {
    LIVE: "Recorded by a gateway on this machine.",
    RECORDED: "Model replies recorded earlier from a real local model and replayed through the gateway; decisions were "
    "recomputed, not recorded. Not a live session.",
    SYNTHETIC: "A scripted agent and a simulated approver in an invented world. Not a live session.",
    UNKNOWN: "A source file sits next to this database but could not be read, so nothing is claimed about its origin.",
}


@dataclass(frozen=True)
class SourceInfo:
    kind: str
    label: str
    detail: str
    live: bool  # LIVE kind and recent activity
    extra: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "label": self.label, "detail": self.detail, "live": self.live, "extra": self.extra}


def manifest_path(db: str | Path) -> Path:
    p = Path(db)
    return p.with_name(p.name + SUFFIX)


def write_manifest(db: str | Path, source: str, **fields: Any) -> None:
    if source not in (RECORDED, SYNTHETIC):
        raise ValueError("only non-live sources are written")
    body = {"format": FORMAT, "source": source, **fields}
    manifest_path(db).write_text(json.dumps(body, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def read_manifest(db: str | Path) -> dict[str, Any] | None:
    """None: no file. ``{"source": "unknown"}``: a file that cannot be used."""
    p = manifest_path(db)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if (
            not isinstance(data, dict)
            or data.get("format") != FORMAT
            or data.get("source") not in (RECORDED, SYNTHETIC)
        ):
            return {"source": UNKNOWN}
        return data
    except (OSError, ValueError):
        return {"source": UNKNOWN}


def classify(manifest: dict[str, Any] | None, session_id: str, last_activity: float | None, now: float) -> SourceInfo:
    if manifest is None:
        recent = last_activity is not None and now - last_activity <= LIVE_WINDOW_S
        label = LABELS[LIVE] if recent else "LOCAL SESSION · IDLE"
        return SourceInfo(LIVE, label, DETAIL[LIVE], recent, {})
    kind = str(manifest.get("source", UNKNOWN))
    if kind not in (RECORDED, SYNTHETIC):
        kind = UNKNOWN
    per = manifest.get("sessions", {})
    extra = dict(per.get(session_id, {})) if isinstance(per, dict) and isinstance(per.get(session_id), dict) else {}
    for k in ("scenario", "agent", "recording", "model"):
        if k in manifest and k not in extra:
            extra[k] = manifest[k]
    return SourceInfo(kind, LABELS[kind], DETAIL[kind], False, extra)
