"""The rule catalogue shown by the rule inspector.

Descriptions restate ``docs/policy.md`` section 3 and the messages in ``mcp_weir/decision.py``; nothing here decides
anything. Configured actions are read from ``mcp_weir.policy`` (the defaults, or the policy file you pass), and
``tests/test_dashboard_backend.py`` fails if a rule code appears in the gateway source but not in this table.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from mcp_weir.policy import Policy, RuleConfig

# code -> (title, tier, plain-English, evidence, config keys, can an approval clear it when it is a hold)
CATALOGUE: dict[str, dict[str, Any]] = {
    "R-UNKNOWN": {
        "title": "Unknown tool",
        "tier": "always on",
        "text": "The tool is not declared in the policy, so Weir does not know what it does or what its results are worth.",
        "evidence": "The tool name in the request.",
        "keys": [],
    },
    "R-PIN": {
        "title": "Tool definition changed",
        "tier": "always on",
        "text": "The tool's name, description or schema differs from the reviewed lock file, or the tool is not in it.",
        "evidence": "Pinned digest versus the digest the upstream server reported (see the Policy view).",
        "keys": [],
    },
    "R-LIMIT": {
        "title": "Arguments rejected",
        "tier": "always on",
        "text": "The arguments are not a JSON object, or they exceed the policy's size limit.",
        "evidence": "The request itself.",
        "keys": [],
    },
    "R-INTERNAL": {
        "title": "Could not evaluate",
        "tier": "always on",
        "text": "The rule engine failed on this call (storage error, malformed input), so the call was refused rather than guessed at.",
        "evidence": "The error class recorded in the rule message.",
        "keys": [],
    },
    "R-APPROVAL-DENIED": {
        "title": "A person denied this exact call",
        "tier": "approval",
        "text": "A human denied an earlier hold on the same tool and arguments in this session. Repeating the identical call is "
        "blocked; a different call is evaluated afresh.",
        "evidence": "The approval record for this call (state: denied).",
        "keys": [],
    },
    "R-GATE": {
        "title": "Static approval gate",
        "tier": "static",
        "text": "Every call of this effect (egress or write) needs approval whatever it contains. Off by default; it is the "
        "permissions-only baseline used in the evaluation.",
        "evidence": "The tool's declared effect.",
        "keys": ["gate_egress", "gate_write"],
    },
    "R-DEST-UNTRUSTED": {
        "title": "Destination came from untrusted content",
        "tier": "value",
        "text": "A target argument (recipient, URL host and path, file path) appears in content the session received from an "
        "untrusted source, and the call goes outside the boundary or changes state.",
        "evidence": "Earlier results that contained the destination (the call, its tool and label, match kind and hit count).",
        "keys": ["dest_untrusted"],
    },
    "R-FLOW-CONF": {
        "title": "Labelled data would leave",
        "tier": "value",
        "text": "A content argument of an external call contains data the tracker recognises from an earlier result labelled "
        "secret or internal. Secret and internal can be configured differently.",
        "evidence": "Earlier results whose keyed hashes matched the outgoing content (call, tool, label, match kind, hits).",
        "keys": ["flow_conf_secret", "flow_conf_internal"],
    },
    "R-TRACKER-LIMIT": {
        "title": "Tracker could not follow everything",
        "tier": "value",
        "text": "External egress after a labelled result that was too large or too numerous for the tracker to follow, so the "
        "value rules cannot vouch for this call.",
        "evidence": "The session's 'blind' flag and context label.",
        "keys": ["tracker_limit"],
    },
    "R-TRIFECTA": {
        "title": "Secret and untrusted data in one session",
        "tier": "session",
        "text": "External egress after the session has seen both secret data and untrusted content. It does not look at what "
        "the model did with the data.",
        "evidence": "The session context label before the call (secret/untrusted).",
        "keys": ["trifecta"],
    },
    "R-UNTRUSTED-READ": {
        "title": "Secret read after untrusted content",
        "tier": "session",
        "text": "A call whose result would be labelled secret, in a session that has already received untrusted content.",
        "evidence": "The session context label before the call, and the label the result would carry.",
        "keys": ["untrusted_read"],
    },
    "R-EGRESS-BUDGET": {
        "title": "Too many external calls",
        "tier": "session",
        "text": "More external egress calls in one session than the policy's limit.",
        "evidence": "The session's external-call counter against the configured limit.",
        "keys": ["egress_budget"],
    },
}

ALWAYS_DENY = {"R-UNKNOWN", "R-PIN", "R-LIMIT", "R-INTERNAL", "R-APPROVAL-DENIED"}
UI_ACTION = {"approve": "HOLD", "deny": "DENY", "off": "OFF"}
UI_VERDICT = {"ALLOW": "ALLOW", "APPROVE": "HOLD", "DENY": "DENY"}


def configured(code: str, rules: RuleConfig) -> list[dict[str, str]]:
    if code in ALWAYS_DENY:
        return [{"key": "(fixed)", "action": "DENY", "raw": "deny"}]
    cur = asdict(rules)
    return [{"key": k, "action": UI_ACTION[str(cur[k])], "raw": str(cur[k])} for k in CATALOGUE[code]["keys"]]


def describe(code: str, policy: Policy | None) -> dict[str, Any]:
    info = CATALOGUE.get(code)
    rules = policy.rules if policy else RuleConfig()
    out: dict[str, Any] = {
        "code": code,
        "known": info is not None,
        **(
            info
            or {
                "title": "Unrecognised rule",
                "tier": "unknown",
                "text": "This code is not in the dashboard's table.",
                "evidence": "",
                "keys": [],
            }
        ),
        "configured": configured(code, rules) if info else [],
        "configured_from": "policy file" if policy else "gateway defaults (no policy file loaded)",
    }
    if code == "R-EGRESS-BUDGET":
        out["limit"] = rules.egress_budget_limit
    if policy and info:
        over = []
        for t in policy.tools:
            for key, act in t.rule_overrides:
                if key in info["keys"]:
                    over.append({"tool": t.name, "key": key, "action": UI_ACTION[str(act)]})
        out["overrides"] = over
    return out


def verdict_ui(v: str) -> str:
    return UI_VERDICT.get(v, v)
