"""Strict policy loading. An invalid policy refuses to start: unknown keys, bad enums and dangling references are errors."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import sys
import tomllib
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .destinations import canon_path
from .labels import BOTTOM, Label


class PolicyError(ValueError):
    """The policy file is invalid. Weir refuses to start."""


class Effect(StrEnum):
    READ = "read"
    WRITE = "write"
    EGRESS = "egress"


class Action(StrEnum):
    OFF = "off"
    APPROVE = "approve"
    DENY = "deny"


RULE_NAMES = (
    "dest_untrusted",
    "flow_conf_secret",
    "flow_conf_internal",
    "trifecta",
    "untrusted_read",
    "egress_budget",
    "gate_egress",
    "gate_write",
)
TARGET_KINDS = ("email", "url", "path", "other")
_NAME = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")


@dataclass(frozen=True)
class ResultRule:
    """Raises the label of a result when an argument matches (for example paths under /secrets/)."""

    arg: str
    label: Label
    glob: str | None = None
    equals: str | None = None

    def matches(self, args: dict[str, Any]) -> bool:
        if self.arg not in args:
            return True  # fail closed: the tool's default may be anything
        value = args[self.arg]
        if not isinstance(value, str):
            return True
        if self.equals is not None and value == self.equals:
            return True
        if self.glob is None:
            return False
        candidates = {value, unquote(value)}
        for c in list(candidates):
            candidates.add(canon_path(c))
            if not c.startswith("/"):
                candidates.add(canon_path("/" + c))
        return any(fnmatch.fnmatchcase(c, self.glob) for c in candidates)


@dataclass(frozen=True)
class ToolSpec:
    name: str  # namespaced: <server>__<tool>
    server: str
    tool: str
    effect: Effect
    result: Label = BOTTOM
    result_rules: tuple[ResultRule, ...] = ()
    targets: tuple[tuple[str, str], ...] = ()  # (argument, kind)
    content: tuple[str, ...] = ()
    rule_overrides: tuple[tuple[str, Action], ...] = ()

    def result_label_for(self, args: dict[str, Any]) -> Label:
        label = self.result
        for r in self.result_rules:
            if r.matches(args):
                label = label.join(r.label)
        return label

    def action(self, rule: str, default: Action) -> Action:
        return dict(self.rule_overrides).get(rule, default)


@dataclass(frozen=True)
class RuleConfig:
    dest_untrusted: Action = Action.APPROVE
    flow_conf_secret: Action = Action.DENY
    flow_conf_internal: Action = Action.APPROVE
    trifecta: Action = Action.APPROVE
    untrusted_read: Action = Action.APPROVE
    egress_budget: Action = Action.APPROVE
    gate_egress: Action = Action.OFF  # static, argument-blind approval gate on every egress call (the baseline arm)
    gate_write: Action = Action.OFF  # same, for write calls
    egress_budget_limit: int = 3


@dataclass(frozen=True)
class TrackerConfig:
    k_secret: int = 8
    k_internal: int = 24
    min_unit: int = 5
    max_text: int = 65536


@dataclass(frozen=True)
class UpstreamSpec:
    name: str
    command: tuple[str, ...]
    env: tuple[tuple[str, str], ...] = ()
    cwd: str | None = None


@dataclass(frozen=True)
class Policy:
    name: str
    internal_domains: tuple[str, ...]
    rules: RuleConfig = field(default_factory=RuleConfig)
    tracker: TrackerConfig = field(default_factory=TrackerConfig)
    upstreams: tuple[UpstreamSpec, ...] = ()
    tools: tuple[ToolSpec, ...] = ()
    max_arg_bytes: int = 65536
    approval_ttl_seconds: int = 900
    call_timeout_seconds: float = 20.0

    def tool(self, name: str) -> ToolSpec | None:
        return next((t for t in self.tools if t.name == name), None)

    def with_rules(self, **overrides: Any) -> Policy:
        """A copy with some global rules replaced (used to build the evaluation arms)."""
        cur = asdict(self.rules)
        for k, v in overrides.items():
            if k not in cur:
                raise PolicyError(f"unknown rule {k!r}")
            cur[k] = v if k == "egress_budget_limit" else Action(v)
        return replace(self, rules=RuleConfig(**cur))

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = json.loads(json.dumps(asdict(self), default=str, sort_keys=True))
        return out

    @property
    def digest(self) -> str:
        blob = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------- parsing helpers
def _only(d: Any, allowed: set[str], where: str) -> dict[str, Any]:
    if not isinstance(d, dict):
        raise PolicyError(f"{where}: expected a table")
    unknown = set(d) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {sorted(unknown)}")
    return d


def _action(v: Any, where: str) -> Action:
    try:
        return Action(v)
    except ValueError:
        raise PolicyError(f"{where}: must be one of off/approve/deny, got {v!r}") from None


def _label(d: Any, where: str) -> Label:
    d = _only(d, {"conf", "integ"}, where)
    try:
        return Label.parse(str(d.get("conf", "public")), str(d.get("integ", "trusted")))
    except ValueError as e:
        raise PolicyError(f"{where}: {e}") from None


def _int(v: Any, where: str, lo: int, hi: int) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise PolicyError(f"{where}: must be an integer in [{lo}, {hi}]")
    return v


def parse_policy(data: dict[str, Any]) -> Policy:
    top = _only(data, {"policy", "tracker", "rules", "upstreams", "tools"}, "policy file")
    meta = _only(
        top.get("policy", {}),
        {"name", "internal_domains", "max_arg_bytes", "approval_ttl_seconds", "call_timeout_seconds"},
        "[policy]",
    )
    name = meta.get("name")
    if not isinstance(name, str) or not name:
        raise PolicyError("[policy].name is required")
    domains = meta.get("internal_domains", [])
    if not isinstance(domains, list) or not all(isinstance(x, str) and x for x in domains):
        raise PolicyError("[policy].internal_domains must be a list of domain strings")

    t = _only(top.get("tracker", {}), {"k_secret", "k_internal", "min_unit", "max_text"}, "[tracker]")
    tracker = TrackerConfig(
        _int(t.get("k_secret", 8), "[tracker].k_secret", 4, 64),
        _int(t.get("k_internal", 24), "[tracker].k_internal", 4, 128),
        _int(t.get("min_unit", 5), "[tracker].min_unit", 3, 32),
        _int(t.get("max_text", 65536), "[tracker].max_text", 1024, 8 << 20),
    )
    if tracker.k_secret > tracker.k_internal:
        raise PolicyError("[tracker]: k_secret must not exceed k_internal")

    r = _only(top.get("rules", {}), {*RULE_NAMES, "egress_budget_limit"}, "[rules]")
    base = RuleConfig()
    kw: dict[str, Any] = {k: _action(r[k], f"[rules].{k}") for k in RULE_NAMES if k in r}
    if "egress_budget_limit" in r:
        kw["egress_budget_limit"] = _int(r["egress_budget_limit"], "[rules].egress_budget_limit", 0, 10_000)
    rules = replace(base, **kw)

    ups: list[UpstreamSpec] = []
    for uname, u in _only(top.get("upstreams", {}), set(top.get("upstreams", {})), "[upstreams]").items():
        if not _NAME.match(uname):
            raise PolicyError(f"[upstreams.{uname}]: server names are lower-case words joined by single underscores")
        u = _only(u, {"command", "env", "cwd"}, f"[upstreams.{uname}]")
        cmd = u.get("command")
        if not isinstance(cmd, list) or not cmd or not all(isinstance(c, str) for c in cmd):
            raise PolicyError(f"[upstreams.{uname}].command must be a non-empty list of strings")
        cmd = [sys.executable if c == "$PYTHON" else c for c in cmd]
        env = u.get("env", {})
        if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
            raise PolicyError(f"[upstreams.{uname}].env must map strings to strings")
        ups.append(UpstreamSpec(uname, tuple(cmd), tuple(sorted(env.items())), u.get("cwd")))
    server_names = {u.name for u in ups}

    tools: list[ToolSpec] = []
    for tname, spec in _only(top.get("tools", {}), set(top.get("tools", {})), "[tools]").items():
        where = f"[tools.{tname}]"
        if "__" not in tname:
            raise PolicyError(f"{where}: tool names are <server>__<tool>")
        server, tool = tname.split("__", 1)
        if server_names and server not in server_names:
            raise PolicyError(f"{where}: server {server!r} is not declared under [upstreams]")
        s = _only(spec, {"effect", "result", "result_rules", "target", "content", "rules"}, where)
        try:
            effect = Effect(str(s.get("effect")))
        except ValueError:
            raise PolicyError(f"{where}.effect must be read, write or egress") from None
        result = _label(s.get("result", {}), f"{where}.result")
        rrules: list[ResultRule] = []
        for i, rr in enumerate(s.get("result_rules", [])):
            rr = _only(rr, {"arg", "glob", "equals", "conf", "integ"}, f"{where}.result_rules[{i}]")
            if not isinstance(rr.get("arg"), str) or ("glob" not in rr and "equals" not in rr):
                raise PolicyError(f"{where}.result_rules[{i}]: needs arg and glob or equals")
            rrules.append(
                ResultRule(
                    rr["arg"],
                    _label({k: rr[k] for k in ("conf", "integ") if k in rr}, where),
                    rr.get("glob"),
                    rr.get("equals"),
                )
            )
        target = _only(s.get("target", {}), set(s.get("target", {})), f"{where}.target")
        for a, k in target.items():
            if k not in TARGET_KINDS:
                raise PolicyError(f"{where}.target.{a}: kind must be one of {TARGET_KINDS}")
        content = s.get("content", [])
        if not isinstance(content, list) or not all(isinstance(c, str) for c in content):
            raise PolicyError(f"{where}.content must be a list of argument names")
        ov = _only(s.get("rules", {}), set(RULE_NAMES), f"{where}.rules")
        if effect is Effect.EGRESS and not target and not content:
            raise PolicyError(f"{where}: an egress tool needs target and/or content arguments")
        tools.append(
            ToolSpec(
                tname,
                server,
                tool,
                effect,
                result,
                tuple(rrules),
                tuple(sorted(target.items())),
                tuple(content),
                tuple(sorted((k, _action(v, f"{where}.rules.{k}")) for k, v in ov.items())),
            )
        )
    return Policy(
        name=name,
        internal_domains=tuple(d.lower().rstrip(".") for d in domains),
        rules=rules,
        tracker=tracker,
        upstreams=tuple(ups),
        tools=tuple(tools),
        max_arg_bytes=_int(meta.get("max_arg_bytes", 65536), "[policy].max_arg_bytes", 256, 16 << 20),
        approval_ttl_seconds=_int(meta.get("approval_ttl_seconds", 900), "[policy].approval_ttl_seconds", 1, 86400 * 7),
        call_timeout_seconds=float(meta.get("call_timeout_seconds", 20.0)),
    )


def load_policy(path: str | Path) -> Policy:
    try:
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise PolicyError(f"cannot read policy {path}: {e}") from None
    return parse_policy(data)
