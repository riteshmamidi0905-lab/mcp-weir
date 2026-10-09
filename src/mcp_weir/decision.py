"""The rule engine: pure function of (policy, tool, arguments, session state, tracker) -> Decision.

Every rule that fires is recorded; the verdict is the most restrictive of them (DENY > APPROVE > ALLOW).
No clock, no I/O, no randomness: the same inputs always give the same decision, so decisions can be replayed
from the audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from .destinations import Destination, classify_target
from .labels import Conf, Integ, Label
from .policy import Action, Effect, Policy, ToolSpec
from .tracker import Match, Tracker


class Verdict(IntEnum):
    ALLOW = 0
    APPROVE = 1
    DENY = 2


@dataclass(frozen=True)
class RuleHit:
    code: str
    verdict: Verdict
    message: str
    matches: tuple[Match, ...] = ()


@dataclass
class Decision:
    verdict: Verdict
    hits: list[RuleHit] = field(default_factory=list)
    external: bool = False
    result_label: Label = field(default_factory=Label)
    destinations: list[Destination] = field(default_factory=list)

    @property
    def codes(self) -> list[str]:
        return [h.code for h in self.hits]


def _v(action: Action) -> Verdict:
    return Verdict.DENY if action is Action.DENY else Verdict.APPROVE


def evaluate(
    policy: Policy,
    spec: ToolSpec | None,
    args: dict[str, Any],
    *,
    ctx: Label,
    external_count: int,
    tracker: Tracker,
    pin_ok: bool = True,
    blind: bool = False,
) -> Decision:
    if spec is None:
        return Decision(Verdict.DENY, [RuleHit("R-UNKNOWN", Verdict.DENY, "tool is not declared in the policy")])
    if not pin_ok:
        return Decision(
            Verdict.DENY,
            [RuleHit("R-PIN", Verdict.DENY, "tool definition differs from the reviewed lock file (or is not in it)")],
        )

    rules = policy.rules
    hits: list[RuleHit] = []

    # ---- destinations and external-ness (fail closed) -------------------------------------------------
    dests = [classify_target(kind, args[arg], policy.internal_domains) for arg, kind in spec.targets if arg in args]
    if spec.effect is Effect.EGRESS:
        external = not dests or any(d.external for d in dests) or len(dests) < len(spec.targets)
    else:
        external = False
    result_label = spec.result_label_for(args)

    # ---- static gate (off by default; the permissions-only baseline) ------------------------------------
    gate_rule, gate_default = (
        ("gate_egress", rules.gate_egress)
        if spec.effect is Effect.EGRESS
        else ("gate_write", rules.gate_write)
        if spec.effect is Effect.WRITE
        else ("", Action.OFF)
    )
    if gate_rule and spec.action(gate_rule, gate_default) is not Action.OFF:
        hits.append(
            RuleHit(
                "R-GATE",
                _v(spec.action(gate_rule, gate_default)),
                f"every {spec.effect.value} call needs approval (static gate)",
            )
        )

    # ---- value tier -----------------------------------------------------------------------------------
    act = spec.action("dest_untrusted", rules.dest_untrusted)
    if act is not Action.OFF and dests and (spec.effect is Effect.WRITE or external):
        ents = tuple(dict.fromkeys(e for d in dests for e in d.entities))
        ms = tuple(m for m in tracker.match_entities(ents) if m.label.integ is Integ.UNTRUSTED)
        if ms:
            hits.append(
                RuleHit("R-DEST-UNTRUSTED", _v(act), "the destination or target appears in untrusted content", ms)
            )

    if external and spec.content:
        content = {a: args[a] for a in spec.content if a in args}
        ms_all = tracker.match_content(content) if content else []
        secret = tuple(m for m in ms_all if m.label.conf is Conf.SECRET)
        internal = tuple(m for m in ms_all if m.label.conf is Conf.INTERNAL)
        act_s = spec.action("flow_conf_secret", rules.flow_conf_secret)
        act_i = spec.action("flow_conf_internal", rules.flow_conf_internal)
        if secret and act_s is not Action.OFF:
            hits.append(RuleHit("R-FLOW-CONF", _v(act_s), "secret data would leave the trust boundary", secret))
        elif internal and act_i is not Action.OFF:
            hits.append(RuleHit("R-FLOW-CONF", _v(act_i), "internal data would leave the trust boundary", internal))

    act = spec.action("tracker_limit", rules.tracker_limit)
    if act is not Action.OFF and external and blind and ctx.conf >= Conf.INTERNAL:
        hits.append(
            RuleHit(
                "R-TRACKER-LIMIT",
                _v(act),
                "a labelled result was too large to track fully, so the value tier cannot vouch for this call",
            )
        )

    # ---- session tier ---------------------------------------------------------------------------------
    act = spec.action("trifecta", rules.trifecta)
    if act is not Action.OFF and external and ctx.conf is Conf.SECRET and ctx.integ is Integ.UNTRUSTED:
        hits.append(
            RuleHit("R-TRIFECTA", _v(act), "external egress after the session saw both secret and untrusted data")
        )

    act = spec.action("untrusted_read", rules.untrusted_read)
    if act is not Action.OFF and result_label.conf is Conf.SECRET and ctx.integ is Integ.UNTRUSTED:
        hits.append(RuleHit("R-UNTRUSTED-READ", _v(act), "a secret would be read after the session saw untrusted data"))

    act = spec.action("egress_budget", rules.egress_budget)
    if act is not Action.OFF and external and external_count >= rules.egress_budget_limit:
        hits.append(
            RuleHit(
                "R-EGRESS-BUDGET",
                _v(act),
                f"more than {rules.egress_budget_limit} external egress calls in this session",
            )
        )

    verdict = max((h.verdict for h in hits), default=Verdict.ALLOW)
    return Decision(verdict, hits, external, result_label, dests)
