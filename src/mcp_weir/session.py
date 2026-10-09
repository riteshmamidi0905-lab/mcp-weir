"""Per-session state: the context label (join of everything returned to the host), the egress counter and the tracker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from .labels import BOTTOM, Label
from .tracker import Tracker


@dataclass
class Session:
    id: str
    tracker: Tracker
    ctx: Label = BOTTOM
    external_count: int = 0
    n_calls: int = 0
    version: int = 0
    tracker_dirty: bool = True
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
