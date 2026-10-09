"""Value tracker: remembers *that* labelled data was returned and recognises it again in later arguments.

What is stored is keyed hashes only (BLAKE2b in keyed mode): of overlapping k-grams of the normalised text
(``secret`` k=8, ``internal`` k=24), of short whole values (``secret`` only, because k-grams cannot represent
them), and of entities (addresses, URLs, paths) found in *untrusted* text. No plaintext of a labelled value
is kept. The key normally lives in the same database, so this is hygiene against casual disclosure, not
encryption.

This is a **heuristic**. It recognises a value after normalisation (case, punctuation, spacing, Unicode
compatibility forms) and after one or two layers of base64, hex or percent-encoding. It does not recognise
paraphrase, translation, spelling-out, homoglyphs, rot13/reversal, or pieces shorter than k. See
``docs/design/03-v1-spec.md`` section 6; the evaluation measures how often each of these gets through.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
import sys
import unicodedata
import zlib
from array import array
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from .labels import Conf, Integ, Label


def normalize(text: str) -> str:
    """NFKC, case-fold, keep letters and digits only."""
    return "".join(c for c in unicodedata.normalize("NFKC", text).casefold() if c.isalnum())


def flatten(value: Any) -> str:
    """Turn an argument value into text for matching."""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", "replace")
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


_B64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX = re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{2}){6,}(?![0-9A-Za-z])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"https?://[^\s<>\"')\]]+")
_PATH = re.compile(r"(?<![\w.])(?:/[A-Za-z0-9._\-]+){2,}")


def _printable_ratio(s: str) -> float:
    return sum(c.isprintable() or c in "\n\t" for c in s) / len(s) if s else 0.0


def views(text: str, *, max_views: int = 32, max_chars: int = 1 << 20) -> list[tuple[str, str]]:
    """The text itself plus decodings of percent-, base64- and hex-encoded spans (two layers deep)."""
    out: list[tuple[str, str]] = [("direct", text[:max_chars])]
    seen = {out[0][1]}
    frontier = [("direct", out[0][1], 0)]
    while frontier and len(out) < max_views:
        via, t, depth = frontier.pop(0)
        if depth >= 2:
            continue
        cands: list[tuple[str, str]] = []
        if "%" in t:
            cands.append(("percent", unquote(t)))
        for m in _B64.finditer(t):
            s = m.group(0).rstrip("=").replace("-", "+").replace("_", "/")
            try:
                dec = base64.b64decode(s + "=" * (-len(s) % 4), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if len(dec) >= 4 and _printable_ratio(dec) >= 0.85:
                cands.append(("base64", dec))
        for m in _HEX.finditer(t):
            try:
                dec = bytes.fromhex(m.group(0)).decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                continue
            if len(dec) >= 4 and _printable_ratio(dec) >= 0.85:
                cands.append(("hex", dec))
        for how, dec in cands:
            if dec and dec not in seen and len(out) < max_views:
                seen.add(dec)
                label = how if via == "direct" else f"{via}>{how}"
                out.append((label, dec[:max_chars]))
                frontier.append((label, dec, depth + 1))
    return out


@dataclass(frozen=True)
class Source:
    call_id: str
    tool: str
    label: Label
    n_grams: int
    truncated: bool


@dataclass(frozen=True)
class Match:
    source: int
    call_id: str
    tool: str
    label: Label
    kind: str  # "gram" | "unit" | "entity"
    via: str  # "direct" | "percent" | "base64" | "hex" | combinations
    hits: int


def _encode_entry(
    src: Source, k: int, unit_lengths: list[int], grams: list[int], units: list[int], ents: list[int]
) -> bytes:
    """One registered source as a compact, compressed record: metadata plus the keyed hashes it added."""
    head = json.dumps(
        {
            "c": src.call_id,
            "t": src.tool,
            "l": [int(src.label.conf), int(src.label.integ)],
            "n": src.n_grams,
            "tr": src.truncated,
            "k": k,
            "u": unit_lengths,
        }
    ).encode()
    parts = [struct.pack("<I", len(head)), head]
    for hs in (grams, units, ents):
        arr = array("Q", hs)
        if sys.byteorder != "little":
            arr.byteswap()
        parts += [struct.pack("<I", len(arr)), arr.tobytes()]
    return zlib.compress(b"".join(parts), 3)


def _decode_entry(blob: bytes) -> tuple[dict[str, Any], list[array[int]]]:
    raw = zlib.decompress(blob)
    (hlen,) = struct.unpack_from("<I", raw, 0)
    head = json.loads(raw[4 : 4 + hlen])
    pos, arrays = 4 + hlen, []
    for _ in range(3):
        (n,) = struct.unpack_from("<I", raw, pos)
        pos += 4
        arr: array[int] = array("Q")
        arr.frombytes(raw[pos : pos + 8 * n])
        pos += 8 * n
        if sys.byteorder != "little":
            arr.byteswap()
        arrays.append(arr)
    return head, arrays


class Tracker:
    def __init__(
        self,
        key: bytes,
        *,
        k_secret: int = 8,
        k_internal: int = 24,
        min_unit: int = 5,
        max_text: int = 65536,
        max_sources: int = 50000,
    ) -> None:
        if not 4 <= k_secret <= k_internal:
            raise ValueError("require 4 <= k_secret <= k_internal")
        self._key = key
        self.k_secret, self.k_internal, self.min_unit = k_secret, k_internal, min_unit
        self.max_text, self.max_sources = max_text, max_sources
        self.sources: list[Source] = []
        self._grams: dict[int, list[int]] = {}
        self._units: dict[int, list[int]] = {}
        self._entities: dict[int, list[int]] = {}
        self._unit_lengths: set[int] = set()
        self._k_used: set[int] = set()
        self._journal: list[bytes] = []  # one compact entry per registered source, awaiting persistence
        self._templates = {
            tag: hashlib.blake2b(key=key, digest_size=8, person=tag) for tag in (b"gram", b"unit", b"ent")
        }

    # ------------------------------------------------------------------ hashing
    def _h(self, tag: bytes, s: str) -> int:
        h = self._templates[tag].copy()
        h.update(s.encode("utf-8"))
        return int.from_bytes(h.digest(), "big")

    # ------------------------------------------------------------------ registration
    def register(self, call_id: str, tool: str, label: Label, text: str) -> int | None:
        """Register a result. Returns the source index, or None if nothing needs tracking."""
        if label.is_bottom or not text or len(self.sources) >= self.max_sources:
            return None
        truncated = len(text) > self.max_text
        text = text[: self.max_text]
        idx = len(self.sources)
        n_grams = 0
        norm = normalize(text)
        k = self.k_secret if label.conf == Conf.SECRET else self.k_internal if label.conf == Conf.INTERNAL else 0
        gram_h: list[int] = []
        unit_h: list[int] = []
        ent_h: list[int] = []
        lengths: set[int] = set()
        if k and len(norm) >= k:
            n_grams = self._add_grams(norm, k, idx, gram_h)
            self._k_used.add(k)
        if label.conf == Conf.SECRET:
            lengths = self._add_units(text, idx, unit_h)
        if label.integ == Integ.UNTRUSTED:
            self._add_entities(text, idx, ent_h)
        src = Source(call_id, tool, label, n_grams, truncated)
        self.sources.append(src)
        self._journal.append(_encode_entry(src, k if n_grams else 0, sorted(lengths), gram_h, unit_h, ent_h))
        return idx

    def _add_grams(self, norm: str, k: int, idx: int, added: list[int]) -> int:
        n = 0
        for i in range(len(norm) - k + 1):
            h = self._h(b"gram", norm[i : i + k])
            lst = self._grams.setdefault(h, [])
            if not lst or lst[-1] != idx:
                lst.append(idx)
                added.append(h)
            n += 1
        return n

    def _add_units(self, text: str, idx: int, added: list[int]) -> set[int]:
        cands: set[str] = {text}
        for line in text.splitlines():
            cands.add(line)
            cands.update(re.split(r"[=:]", line))
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError):
            doc = None
        stack = [doc]
        while stack:
            cur = stack.pop()
            if isinstance(cur, str):
                cands.add(cur)
            elif isinstance(cur, dict):
                stack.extend(cur.values())
            elif isinstance(cur, list):
                stack.extend(cur)
        lengths: set[int] = set()
        for c in cands:
            n = normalize(c)
            if self.min_unit <= len(n) < self.k_secret:
                h = self._h(b"unit", n)
                lst = self._units.setdefault(h, [])
                if not lst or lst[-1] != idx:
                    lst.append(idx)
                    added.append(h)
                self._unit_lengths.add(len(n))
                lengths.add(len(n))
        return lengths

    def _add_entities(self, text: str, idx: int, added: list[int]) -> None:
        for e in self._entities_of(text):
            h = self._h(b"ent", e)
            lst = self._entities.setdefault(h, [])
            if not lst or lst[-1] != idx:
                lst.append(idx)
                added.append(h)

    @staticmethod
    def _entities_of(text: str) -> set[str]:
        ents: set[str] = set()
        for m in _EMAIL.finditer(text):
            addr = m.group(0)
            ents.add(normalize(addr))
            ents.add(normalize(addr.split("@", 1)[1]))
        for m in _URL.finditer(text):
            u = m.group(0).rstrip(".,;:")
            body = re.sub(r"^https?://", "", u)
            host = re.split(r"[/?#:]", body, maxsplit=1)[0]
            ents.add(normalize(host))
            ents.add(normalize(re.split(r"[?#]", body, maxsplit=1)[0]))
        for m in _PATH.finditer(text):
            p = m.group(0)
            ents.add(normalize(p))
            base = p.rsplit("/", 1)[1]
            if len(base) >= 5:
                ents.add(normalize(base))
        ents.discard("")
        return ents

    # ------------------------------------------------------------------ matching
    def match_content(self, value: Any) -> list[Match]:
        """Find registered values (by k-gram or short whole-value) inside an argument and its decodings."""
        if not self._grams and not self._units:
            return []
        text = flatten(value)
        found: dict[tuple[int, str, str], int] = {}
        ks = sorted(self._k_used)
        for via, view in views(text):
            norm = normalize(view)
            if not norm:
                continue
            if self._grams:
                for k in ks:
                    for i in range(len(norm) - k + 1):
                        for s in self._grams.get(self._h(b"gram", norm[i : i + k]), ()):
                            key = (s, "gram", via)
                            found[key] = found.get(key, 0) + 1
            if self._units:
                for ln in self._unit_lengths:
                    for i in range(len(norm) - ln + 1):
                        for s in self._units.get(self._h(b"unit", norm[i : i + ln]), ()):
                            key = (s, "unit", via)
                            found[key] = found.get(key, 0) + 1
        return self._to_matches(found)

    def match_entities(self, entities: Iterable[str]) -> list[Match]:
        """Find destination entities among those seen in untrusted results."""
        found: dict[tuple[int, str, str], int] = {}
        for e in entities:
            n = normalize(e)
            if len(n) < 4:
                continue
            for s in self._entities.get(self._h(b"ent", n), ()):
                key = (s, "entity", "direct")
                found[key] = found.get(key, 0) + 1
        return self._to_matches(found)

    def _to_matches(self, found: dict[tuple[int, str, str], int]) -> list[Match]:
        out = []
        for (s, kind, via), hits in sorted(found.items()):
            src = self.sources[s]
            out.append(Match(s, src.call_id, src.tool, src.label, kind, via, hits))
        return out

    # ------------------------------------------------------------------ incremental persistence (what the gateway uses)
    def params(self) -> bytes:
        return json.dumps(
            {
                "k_secret": self.k_secret,
                "k_internal": self.k_internal,
                "min_unit": self.min_unit,
                "max_text": self.max_text,
                "max_sources": self.max_sources,
            },
            sort_keys=True,
        ).encode()

    def pending(self) -> list[bytes]:
        """Journal entries not yet confirmed as persisted (a copy)."""
        return list(self._journal)

    def confirm(self, n: int) -> None:
        """The first ``n`` pending entries are safely stored."""
        del self._journal[:n]

    @classmethod
    def from_journal(cls, key: bytes, params: bytes, entries: Iterable[bytes]) -> Tracker:
        t = cls(key, **json.loads(params))
        for blob in entries:
            head, (grams, units, ents) = _decode_entry(blob)
            idx = len(t.sources)
            conf, integ = head["l"]
            t.sources.append(Source(head["c"], head["t"], Label(Conf(conf), Integ(integ)), head["n"], bool(head["tr"])))
            if head["k"]:
                t._k_used.add(head["k"])
            t._unit_lengths.update(head["u"])
            for table, hashes in ((t._grams, grams), (t._units, units), (t._entities, ents)):
                for h in hashes:
                    table.setdefault(h, []).append(idx)
        return t

    # ------------------------------------------------------------------ snapshot persistence (tests, tools)
    def stats(self) -> dict[str, int]:
        return {
            "sources": len(self.sources),
            "grams": len(self._grams),
            "units": len(self._units),
            "entities": len(self._entities),
        }

    def dump(self) -> bytes:
        header = json.dumps(
            {
                "v": 1,
                "k": [self.k_secret, self.k_internal, self.min_unit, self.max_text, self.max_sources],
                "unit_lengths": sorted(self._unit_lengths),
                "k_used": sorted(self._k_used),
                "sources": [
                    [s.call_id, s.tool, int(s.label.conf), int(s.label.integ), s.n_grams, s.truncated]
                    for s in self.sources
                ],
            }
        ).encode()
        parts = [b"WT1", struct.pack("<I", len(header)), header]
        for table in (self._grams, self._units, self._entities):
            hs, ss = array("Q"), array("I")
            for h, lst in table.items():
                for s in lst:
                    hs.append(h)
                    ss.append(s)
            if sys.byteorder != "little":
                hs.byteswap()
                ss.byteswap()
            parts += [struct.pack("<I", len(hs)), hs.tobytes(), ss.tobytes()]
        return zlib.compress(b"".join(parts), 6)

    @classmethod
    def load(cls, key: bytes, blob: bytes) -> Tracker:
        raw = zlib.decompress(blob)
        if raw[:3] != b"WT1":
            raise ValueError("not a tracker blob")
        (hlen,) = struct.unpack_from("<I", raw, 3)
        header = json.loads(raw[7 : 7 + hlen])
        ks, ki, mu, mt, ms = header["k"]
        t = cls(key, k_secret=ks, k_internal=ki, min_unit=mu, max_text=mt, max_sources=ms)
        t._unit_lengths = set(header["unit_lengths"])
        t._k_used = set(header.get("k_used", []))
        t.sources = [
            Source(cid, tool, Label(Conf(c), Integ(i)), n, bool(tr)) for cid, tool, c, i, n, tr in header["sources"]
        ]
        pos = 7 + hlen
        for table in (t._grams, t._units, t._entities):
            (n,) = struct.unpack_from("<I", raw, pos)
            pos += 4
            hs, ss = array("Q"), array("I")
            hs.frombytes(raw[pos : pos + 8 * n])
            pos += 8 * n
            ss.frombytes(raw[pos : pos + 4 * n])
            pos += 4 * n
            if sys.byteorder != "little":
                hs.byteswap()
                ss.byteswap()
            for h, s in zip(hs, ss, strict=True):
                table.setdefault(h, []).append(s)
        return t
