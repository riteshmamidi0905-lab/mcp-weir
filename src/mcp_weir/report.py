"""Flow trace: a readable account of one session built only from the audit chain.

The HTML page is self-contained (inline CSS and SVG, no scripts, no network). It shows, per tool call, what was asked,
what Weir decided, which rule fired, and which earlier result the offending value came from.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Any

VERDICT_CLASS = {"ALLOW": "allow", "APPROVE": "approve", "DENY": "deny"}


@dataclass
class CallRecord:
    call: str
    tool: str = ""
    verdict: str = "ALLOW"
    rules: list[dict[str, Any]] = field(default_factory=list)
    args: dict[str, Any] = field(default_factory=dict)
    result_label: str = ""
    ctx_before: str = ""
    ctx_after: str = ""
    external: bool = False
    forwarded: bool = False
    approval: str | None = None
    approval_events: list[str] = field(default_factory=list)
    is_error: bool = False
    uncertain: bool = False


def build_records(events: list[dict[str, Any]]) -> list[CallRecord]:
    recs: dict[str, CallRecord] = {}
    order: list[str] = []
    approvals: dict[str, list[str]] = {}
    for ev in events:
        if ev["kind"].startswith("approval.") and ev["payload"].get("call"):
            p = ev["payload"]
            approvals.setdefault(p["call"], []).append(f"{ev['kind'].split('.', 1)[1]} {p.get('approval', '')}".strip())
    for ev in events:
        p, kind = ev["payload"], ev["kind"]
        cid = p.get("call")
        if kind == "call.decision" and cid:
            r = recs.get(cid)
            if r is None:
                r = recs[cid] = CallRecord(cid)
                order.append(cid)
            r.tool, r.verdict, r.rules = p["tool"], p["verdict"], p.get("rules", [])
            r.args, r.result_label, r.ctx_before = p.get("args", {}), p.get("result_label", ""), p.get("ctx_before", "")
            r.external, r.approval = bool(p.get("external")), p.get("approval")
        elif kind == "call.result" and cid in recs:
            r = recs[cid]
            r.forwarded, r.ctx_after, r.is_error, r.uncertain = (
                True,
                p.get("ctx_after", ""),
                bool(p.get("is_error")),
                bool(p.get("uncertain")),
            )
    for cid, evs in approvals.items():
        if cid in recs:
            recs[cid].approval_events = evs
    return [recs[c] for c in order]


def status(r: CallRecord) -> str:
    if r.verdict == "DENY":
        return "BLOCKED"
    if r.verdict == "APPROVE":
        return "EXECUTED AFTER APPROVAL" if r.forwarded else "HELD FOR APPROVAL"
    return "ALLOWED"


def _fmt_arg(v: Any) -> str:
    if isinstance(v, str):
        return v
    return f"<{v.get('len')} chars, sha256 {v.get('sha256')}>"


def render_text(records: list[CallRecord]) -> str:
    lines = []
    for r in records:
        lines.append(
            f"{r.call:>4}  {status(r):<24} {r.tool}  [{r.ctx_before or '-'} -> {r.ctx_after or r.ctx_before or '-'}]"
        )
        for h in r.rules:
            lines.append(f"        {h['code']}: {h['message']}")
            for s in h.get("sources", [])[:3]:
                lines.append(
                    f"          from {s['call']} ({s['tool']}, {s['label']}) matched by {s['kind']}/{s['via']} x{s['hits']}"
                )
        for a, v in r.args.items():
            lines.append(f"        {a} = {_fmt_arg(v)}")
    return "\n".join(lines)


_CSS = """
:root{--bg:#fbfbfa;--fg:#17181a;--mut:#5b6068;--card:#fff;--line:#d9dbdf;--allow:#0d6b3a;--allowbg:#e3f4e8;--appr:#8a5a00;--apprbg:#fff2d6;--deny:#a11d1d;--denybg:#fde4e4;--chip:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#121316;--fg:#e8e9eb;--mut:#a0a5ad;--card:#1b1d21;--line:#33363c;--allow:#6fd39a;--allowbg:#12301f;--appr:#f0c36a;--apprbg:#3a2c0b;--deny:#ff8a8a;--denybg:#3a1414;--chip:#272a30}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px 56px}h1{font-size:22px;margin:0 0 4px}.sub{color:var(--mut);margin:0 0 20px}
.sum{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 20px}.sum span{background:var(--chip);border-radius:999px;padding:4px 12px;font-size:13px}
.call{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--line);border-radius:8px;padding:12px 14px;margin:0 0 12px}
.call.allow{border-left-color:var(--allow)}.call.approve{border-left-color:var(--appr)}.call.deny{border-left-color:var(--deny)}
.hd{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}.n{color:var(--mut);font-variant-numeric:tabular-nums}.tool{font-family:ui-monospace,Menlo,monospace;font-weight:600}
.badge{font-size:12px;font-weight:700;padding:2px 8px;border-radius:4px;letter-spacing:.02em}.allow .badge{background:var(--allowbg);color:var(--allow)}.approve .badge{background:var(--apprbg);color:var(--appr)}.deny .badge{background:var(--denybg);color:var(--deny)}
.chip{background:var(--chip);border-radius:4px;padding:1px 7px;font-size:12px;font-family:ui-monospace,Menlo,monospace}
.rule{margin:8px 0 0;padding:8px 10px;border-radius:6px;background:var(--chip)}.rule b{font-family:ui-monospace,Menlo,monospace}
.src{color:var(--mut);font-size:13px;margin:2px 0 0 12px}.args{font-family:ui-monospace,Menlo,monospace;font-size:13px;color:var(--mut);margin:8px 0 0;word-break:break-all}
svg{width:100%;height:auto;margin:0 0 20px;border:1px solid var(--line);border-radius:8px;background:var(--card)}
.foot{color:var(--mut);font-size:13px;margin-top:28px;border-top:1px solid var(--line);padding-top:12px}
@media (max-width:480px){main{padding:16px 16px 40px}}
"""


def _graph(records: list[CallRecord]) -> str:
    if not records:
        return ""
    row, w = 34, 880
    h = 20 + row * len(records)
    pos = {r.call: 20 + row * i for i, r in enumerate(records)}
    parts = [f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="Data-flow graph between tool calls">']
    colors = {"allow": "var(--allow)", "approve": "var(--appr)", "deny": "var(--deny)"}
    for i, r in enumerate(records):
        y = pos[r.call]
        c = colors[VERDICT_CLASS[r.verdict]]
        parts.append(
            f'<circle cx="24" cy="{y}" r="7" fill="{c}"/><text x="40" y="{y + 5}" font-size="13" fill="currentColor" '
            f'font-family="ui-monospace,Menlo,monospace">{html.escape(r.call)}  {html.escape(r.tool)}</text>'
        )
        parts.append(
            f'<text x="{w - 12}" y="{y + 5}" font-size="12" text-anchor="end" fill="{c}">{html.escape(status(r))}</text>'
        )
        for hit in r.rules:
            for s in hit.get("sources", []):
                if s["call"] in pos:
                    y0 = pos[s["call"]]
                    bend = 330 + 60 * ((i * 7 + y0) % 4)
                    parts.append(
                        f'<path d="M 31 {y0} C {bend} {y0}, {bend} {y}, 31 {y}" fill="none" stroke="{c}" stroke-width="1.6" '
                        f'stroke-dasharray="{"" if r.verdict == "DENY" else "4 3"}" opacity=".8"/>'
                    )
    parts.append("</svg>")
    return "".join(parts)


def render_html(
    session_id: str,
    policy_name: str,
    policy_digest: str,
    records: list[CallRecord],
    chain: tuple[bool, int | None, int],
) -> str:
    counts = {
        k: sum(1 for r in records if status(r) == k)
        for k in ("ALLOWED", "EXECUTED AFTER APPROVAL", "HELD FOR APPROVAL", "BLOCKED")
    }
    esc = html.escape
    out = [
        f"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>Weir flow trace {esc(session_id)}</title><style>{_CSS}</style><main>",
        f"<h1>Flow trace</h1><p class=sub>session <code>{esc(session_id)}</code> · policy <code>{esc(policy_name)}</code> "
        f"<code>{esc(policy_digest[:12])}</code></p>",
        "<div class=sum>"
        + "".join(f"<span>{n} {esc(k.lower())}</span>" for k, n in counts.items())
        + f"<span>audit chain {'verified' if chain[0] else 'BROKEN at #' + str(chain[1])} ({chain[2]} events)</span></div>",
        _graph(records),
    ]
    for r in records:
        cls = VERDICT_CLASS[r.verdict]
        out.append(
            f"<section class='call {cls}'><div class=hd><span class=n>{esc(r.call)}</span><span class=tool>{esc(r.tool)}</span>"
            f"<span class=badge>{esc(status(r))}</span>"
            f"<span class=chip>context {esc(r.ctx_before or '-')} → {esc(r.ctx_after or r.ctx_before or '-')}</span>"
            + (f"<span class=chip>result {esc(r.result_label)}</span>" if r.result_label else "")
            + "</div>"
        )
        if r.args:
            shown = ", ".join(
                f"{esc(k)}={esc(v) if isinstance(v, str) else '(' + str(v.get('len')) + ' chars, sha256 ' + esc(str(v.get('sha256'))) + ')'}"
                for k, v in r.args.items()
            )
            out.append(f"<p class=args>{shown}</p>")
        for h in r.rules:
            out.append(f"<div class=rule><b>{esc(h['code'])}</b> · {esc(h['message'])}")
            for s in h.get("sources", [])[:4]:
                out.append(
                    f"<div class=src>↳ value came from <b>{esc(s['call'])}</b> ({esc(s['tool'])}, {esc(s['label'])}); "
                    f"matched by {esc(s['kind'])} / {esc(s['via'])}, {s['hits']} hit(s)</div>"
                )
            out.append("</div>")
        if r.approval_events:
            out.append(f"<p class=args>approval: {esc('; '.join(r.approval_events))}</p>")
        if r.uncertain:
            out.append("<p class=args>upstream failure: the call may or may not have taken effect</p>")
        out.append("</section>")
    out.append(
        "<p class=foot>Built only from the audit chain: tool calls and tool results. Weir does not see the user's prompt, the model's "
        "reasoning or the final answer, and argument <em>contents</em> are shown as length and digest (destinations are shown in full). "
        "Value matching is a heuristic: a value that was paraphrased or re-encoded in an unsupported way is invisible to it.</p></main></html>"
    )
    return "".join(out)
