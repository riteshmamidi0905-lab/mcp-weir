"""Charts for the docs and the launch material, drawn from eval/results/headline.json (so every bar is a recorded count).

python eval/make_charts.py            # writes docs/assets/*.svg
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
H = json.loads((ROOT / "eval" / "results" / "headline.json").read_text())
C = H["scripted"]["cells"]
ARMS = [
    ("A0", "no gateway"),
    ("A1", "static approval gates"),
    ("A2", "value tier"),
    ("A3s", "session tier only"),
    ("A3", "value + session"),
    ("A3d", "value + session, session rules deny"),
]
INK, MUT, LINE, BG = "#17181a", "#5b6068", "#d9dbdf", "#ffffff"
GOOD, WARN, BAD = "#0d6b3a", "#b7791f", "#a11d1d"


def pct(arm: str, mode: str) -> float:
    c = C[f"{arm}/{mode}"]
    return 100 * c["attacks_reached_goal"] / c["attacks"]


def attacks_chart() -> str:
    w, rowh, left, bar = 980, 64, 290, 520
    h = 120 + rowh * len(ARMS)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" role="img" aria-labelledby="t d" font-family="Inter,Helvetica,Arial,sans-serif">',
        '<title id="t">Attacks that reached their goal, by gateway arm and by how careful the simulated approver is</title>',
        f'<desc id="d">Held-out scripted run, {C["A0/none"]["attacks"]} attacks per cell, with simulated (oracle) approvers. Bars show the share of attacks that reached their goal.</desc>',
        f'<rect width="{w}" height="{h}" fill="{BG}"/>',
        f'<text x="24" y="38" font-size="22" font-weight="700" fill="{INK}">Attacks that reached their goal</text>',
        f'<text x="24" y="62" font-size="14" fill="{MUT}">held-out run, scripted attacker that follows every planted instruction, simulated approvers, {C["A0/none"]["attacks"]:,} attacks per cell</text>',
    ]
    y0 = 96
    out.append(
        f'<rect x="{left}" y="{y0 - 14}" width="12" height="12" fill="{GOOD}"/><text x="{left + 18}" y="{y0 - 4}" font-size="13" fill="{INK}">a careful simulated approver</text>'
        f'<rect x="{left + 230}" y="{y0 - 14}" width="12" height="12" fill="{BAD}"/><text x="{left + 248}" y="{y0 - 4}" font-size="13" fill="{INK}">a simulated approver who approves everything</text>'
    )
    for i, (arm, name) in enumerate(ARMS):
        y = y0 + 12 + i * rowh
        out.append(
            f'<text x="24" y="{y + 20}" font-size="15" font-weight="600" fill="{INK}">{arm}</text><text x="24" y="{y + 38}" font-size="12" fill="{MUT}">{name}</text>'
        )
        modes = [("none", MUT)] if arm == "A0" else [("strict", GOOD), ("careless", BAD)]
        for j, (mode, col) in enumerate(modes):
            v = pct(arm, mode)
            yy = y + j * 26
            out.append(
                f'<rect x="{left}" y="{yy}" width="{bar}" height="20" fill="#eef0f3"/><rect x="{left}" y="{yy}" width="{max(1.5, bar * v / 100):.1f}" height="20" fill="{col}"/>'
                f'<text x="{left + bar + 10}" y="{yy + 15}" font-size="14" fill="{INK}">{v:.1f}%</text>'
            )
    out.append(f'<line x1="{left}" y1="{y0 + 4}" x2="{left}" y2="{h - 18}" stroke="{LINE}"/></svg>')
    return "\n".join(out)


def burden_chart() -> str:
    arms = [a for a in ARMS if a[0] != "A0"]
    w, rowh, left, bar = 980, 46, 290, 520
    h = 110 + rowh * len(arms)
    mx = max(C[f"{a}/strict"]["approvals_per_benign_task"] for a, _ in arms)
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" role="img" aria-labelledby="t d" font-family="Inter,Helvetica,Arial,sans-serif">',
        '<title id="t">Approvals a careful simulated approver is asked for, per legitimate task</title>',
        f'<desc id="d">{C["A1/strict"]["benign"]} benign tasks per arm, mean approvals requested per task.</desc>',
        f'<rect width="{w}" height="{h}" fill="{BG}"/>',
        f'<text x="24" y="38" font-size="22" font-weight="700" fill="{INK}">What it costs a user who only does legitimate work</text>',
        f'<text x="24" y="62" font-size="14" fill="{MUT}">mean approvals requested per benign task (careful simulated approver), {C["A1/strict"]["benign"]} tasks per arm (the user did ask for each one)</text>',
    ]
    for i, (arm, name) in enumerate(arms):
        y = 90 + i * rowh
        v = C[f"{arm}/strict"]["approvals_per_benign_task"]
        col = BAD if arm == "A1" else GOOD
        out.append(
            f'<text x="24" y="{y + 15}" font-size="15" font-weight="600" fill="{INK}">{arm}</text><text x="70" y="{y + 15}" font-size="12" fill="{MUT}">{name}</text>'
            f'<rect x="{left}" y="{y}" width="{bar}" height="20" fill="#eef0f3"/><rect x="{left}" y="{y}" width="{max(1.5, bar * v / (mx * 1.1)):.1f}" height="20" fill="{col}"/>'
            f'<text x="{left + bar + 10}" y="{y + 15}" font-size="14" fill="{INK}">{v:.2f}</text>'
        )
    out.append("</svg>")
    return "\n".join(out)


def main() -> None:
    d = ROOT / "docs" / "assets"
    d.mkdir(parents=True, exist_ok=True)
    (d / "results-attacks.svg").write_text(attacks_chart())
    (d / "results-burden.svg").write_text(burden_chart())
    print("wrote docs/assets/results-attacks.svg, results-burden.svg")


if __name__ == "__main__":
    main()
