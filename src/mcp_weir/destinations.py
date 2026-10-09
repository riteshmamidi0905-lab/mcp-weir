"""Parse e-mail addresses, URLs and paths into destinations and classify them as internal or external.

Everything here fails closed: anything that cannot be parsed unambiguously is treated as *external*. Parser
differentials (backslashes, ``%`` source routes, extra ``@``, whitespace, control characters) are rejected
rather than interpreted, because a destination that two parsers read differently is a way to smuggle
an attacker's host past an allow-list.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

_DNS_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_LOCAL = re.compile(r"^[A-Za-z0-9._+\-]{1,64}$")
_BAD_URL_CHARS = re.compile(r"[\x00-\x20\x7f\\]")

Kind = Literal["internal", "external", "object"]


@dataclass(frozen=True)
class Url:
    scheme: str
    host: str
    port: int | None
    path: str
    query: str


@dataclass(frozen=True)
class Destination:
    """Where a call sends or applies something.

    ``kind`` is ``internal`` / ``external`` for network destinations (e-mail, URL) and ``object`` for things
    inside the trust domain (a file path). ``entities`` are the strings a tracker should look for when asking
    "did the attacker's text choose this destination?".
    """

    kind: Kind
    entities: tuple[str, ...] = ()
    reason: str = ""

    @property
    def external(self) -> bool:
        return self.kind == "external"


def valid_host(host: str) -> str | None:
    """Return the lower-case ASCII (IDNA) host if it is a well-formed multi-label DNS name or IP, else None."""
    host = host.strip().rstrip(".").lower()
    if not host or len(host) > 253:
        return None
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = ascii_host.split(".")
    if len(labels) < 2 or not all(_DNS_LABEL.match(part) for part in labels):
        return None
    return ascii_host


def is_internal_host(host: str, internal_domains: Iterable[str]) -> bool:
    """Exact match or true subdomain. ``corp.example.evil.net`` and ``corp-example.com`` are NOT internal."""
    for d in internal_domains:
        d = d.lower().rstrip(".")
        if host == d or host.endswith("." + d):
            return True
    return False


def parse_addresses(value: Any) -> tuple[list[tuple[str, str]], bool]:
    """Parse one address or a list/comma-separated list. Returns ((local, domain) pairs, all_ok)."""
    pieces: list[str] = []
    if isinstance(value, str):
        pieces = re.split(r"[;,]", value)
    elif isinstance(value, list | tuple):
        for item in value:
            if not isinstance(item, str):
                return [], False
            pieces.extend(re.split(r"[;,]", item))
    else:
        return [], False
    out: list[tuple[str, str]] = []
    ok = True
    for raw in pieces:
        s = raw.strip()
        if not s:
            continue
        if "<" in s or ">" in s:
            m = re.fullmatch(r"[^<>]*<([^<>]+)>\s*", s)
            if not m:
                ok = False
                continue
            s = m.group(1).strip()
        if s.count("@") != 1:
            ok = False
            continue
        local, domain = s.split("@")
        host = valid_host(domain)
        if not _LOCAL.match(local) or host is None:
            ok = False
            continue
        out.append((local.lower(), host))
    if not out:
        ok = False
    return out, ok


def parse_url(value: Any) -> Url | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or _BAD_URL_CHARS.search(s):
        return None
    try:
        parts = urlsplit(s)
        port = parts.port
        hostname = parts.hostname
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or hostname is None or parts.netloc.count("@") > 1:
        return None
    host = valid_host(hostname)
    if host is None:
        return None
    return Url(parts.scheme, host, port, parts.path, parts.query)


def canon_path(value: str) -> str:
    """Normalise ``..``, ``.`` and repeated slashes. POSIX keeps exactly two leading slashes as implementation-defined,
    so ``//secrets/x`` would otherwise escape a ``/secrets/*`` rule; collapse them."""
    n = posixpath.normpath(value)
    return "/" + n.lstrip("/") if n.startswith("/") else n


def normalize_path(value: Any) -> str | None:
    if not isinstance(value, str) or "\x00" in value or not value.startswith("/"):
        return None
    return canon_path(value)


def classify_target(kind: str, value: Any, internal_domains: Iterable[str]) -> Destination:
    """Classify one target argument. ``kind`` is the policy's declaration: email, url, path or other."""
    domains = tuple(internal_domains)
    if kind == "email":
        addrs, ok = parse_addresses(value)
        ents = tuple(dict.fromkeys(e for local, dom in addrs for e in (f"{local}@{dom}", dom)))
        if not ok:
            return Destination("external", ents, "unparseable or ambiguous address list")
        if all(is_internal_host(dom, domains) for _, dom in addrs):
            return Destination("internal", ents, "all recipients in internal domains")
        return Destination("external", ents, "recipient outside internal domains")
    if kind == "url":
        url = parse_url(value)
        if url is None:
            return Destination("external", (), "unparseable or ambiguous URL")
        ents = (url.host, f"{url.host}{url.path}")
        if is_internal_host(url.host, domains):
            return Destination("internal", ents, "host in internal domains")
        return Destination("external", ents, "host outside internal domains")
    # path / other: an object inside the trust domain
    path = normalize_path(value) if kind == "path" else None
    if path is not None:
        base = posixpath.basename(path)
        ents = (path,) + ((base,) if len(base) >= 5 else ())
        return Destination("object", ents, "file path")
    text = value if isinstance(value, str) else repr(value)
    return Destination("object", (text,) if len(text) >= 5 else (), "object identifier")
