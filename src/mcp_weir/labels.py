"""The label lattice: confidentiality x integrity, joined component-wise."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum


class Conf(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2


class Integ(IntEnum):
    TRUSTED = 0
    UNTRUSTED = 1


@dataclass(frozen=True)
class Label:
    conf: Conf = Conf.PUBLIC
    integ: Integ = Integ.TRUSTED

    def join(self, other: Label) -> Label:
        return Label(max(self.conf, other.conf), max(self.integ, other.integ))

    def leq(self, other: Label) -> bool:
        return self.conf <= other.conf and self.integ <= other.integ

    @property
    def is_bottom(self) -> bool:
        return self.conf == Conf.PUBLIC and self.integ == Integ.TRUSTED

    def __str__(self) -> str:
        return f"{self.conf.name.lower()}/{self.integ.name.lower()}"

    @classmethod
    def parse(cls, conf: str = "public", integ: str = "trusted") -> Label:
        try:
            return cls(Conf[conf.upper()], Integ[integ.upper()])
        except KeyError as e:
            raise ValueError(f"unknown label component {e.args[0]!r}") from None


BOTTOM = Label()


def join_all(labels: Iterable[Label]) -> Label:
    out = BOTTOM
    for lab in labels:
        out = out.join(lab)
    return out
