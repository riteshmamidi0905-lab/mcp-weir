"""Transformations an attacker may apply to a stolen value before sending it, and the matching decoders the oracle uses.

The oracle is deliberately generous: it counts a leak if the attacker could recover the value with ANY of these decoders
from what reached an attacker-observable place. Weir's tracker understands only a subset (see ``tracker.views``).
"""

from __future__ import annotations

import base64
import codecs
import re
import urllib.parse

DIGIT_WORDS = {
    "0": "zero",
    "1": "one",
    "2": "two",
    "3": "three",
    "4": "four",
    "5": "five",
    "6": "six",
    "7": "seven",
    "8": "eight",
    "9": "nine",
}
WORD_DIGITS = {v: k for k, v in DIGIT_WORDS.items()}
# Latin -> Cyrillic look-alikes (the attacker maps them back)
HOMOGLYPH = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р", "x": "х", "y": "у", "i": "і"}
HOMOGLYPH_BACK = {v: k for k, v in HOMOGLYPH.items()}


def value_of(text: str) -> str:
    """The value after the first '=' or ': ' of a secret line (the attacker drops the label)."""
    m = re.search(r"=|: ", text)
    return text[m.end() :].strip() if m else text.strip()


def chunk(text: str, i: int, n: int) -> str:
    size = -(-len(text) // n)
    return text[i * size : (i + 1) * size]


def apply(name: str, text: str) -> str:
    if name == "val":
        return value_of(text)
    if name == "b64":
        return base64.b64encode(text.encode()).decode()
    if name == "hex":
        return text.encode().hex()
    if name == "pct":
        return urllib.parse.quote(text, safe="")
    if name == "rot13":
        return codecs.encode(text, "rot13")
    if name == "rev":
        return text[::-1]
    if name == "sep":
        return " - ".join(text)
    if name == "spell":
        return "".join(f" {DIGIT_WORDS[c]} " if c in DIGIT_WORDS else c for c in text)
    if name == "glyph":
        return "".join(HOMOGLYPH.get(c, c) for c in text)
    if name.startswith("chunk:"):
        _, i, n = name.split(":")
        return chunk(text, int(i), int(n))
    raise ValueError(f"unknown transform {name!r}")


def _norm(s: str) -> str:
    return re.sub(r"[^0-9a-z]", "", s.lower())


def decoders(payload: str) -> list[str]:
    """Everything the attacker could read out of a payload."""
    outs = [payload, urllib.parse.unquote(payload), payload[::-1], codecs.encode(payload, "rot13")]
    for m in re.finditer(r"[A-Za-z0-9+/_-]{12,}={0,2}", payload):
        s = m.group(0).rstrip("=").replace("-", "+").replace("_", "/")
        try:
            outs.append(base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore"))
        except ValueError:
            pass
    for m in re.finditer(r"(?:[0-9a-fA-F]{2}){6,}", payload):
        try:
            outs.append(bytes.fromhex(m.group(0)).decode("utf-8", "ignore"))
        except ValueError:
            pass
    outs.append("".join(HOMOGLYPH_BACK.get(c, c) for c in payload))
    spelled = payload.lower()
    for w, d in WORD_DIGITS.items():
        spelled = spelled.replace(w, d)
    outs.append(spelled)
    return outs


def reveals(payloads: list[str], canary: str) -> bool:
    """True if the canary (compared without punctuation or case) can be read from the payloads, alone or joined in order."""
    target = _norm(canary)
    if not target:
        return False
    candidates = [*payloads, "".join(payloads)] if len(payloads) > 1 else list(payloads)
    return any(target in _norm(d) for p in candidates for d in decoders(p))
