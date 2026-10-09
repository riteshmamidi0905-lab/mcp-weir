# 02 · Five-plus candidate projects (M3)

Eight substantially different concepts were scored on the eleven criteria from the brief. **Every score is the author's judgement, not a measurement**; the script [`score_candidates.py`](score_candidates.py) only does the arithmetic and shows how the ranking moves under different weights. Higher is better in every column (so "overlap" and "gimmick risk" are scored as *low overlap* and *low gimmick risk*).

## Filter applied first

Rejected before scoring if the idea is, at its core, another chatbot, another RAG demo, a generic agent wrapper, a dashboard around an LLM, a toy multi-agent conversation, a thin API wrapper, or a flashy UI without engineering depth. Where a candidate came close to one of these, the risk is reflected in its *gimmick risk* score instead of silently dropping it.

## The candidates

| # | Concept | One-line case | Main weakness |
|---|---|---|---|
| C1 | **Weir**: an information-flow gateway at the MCP tool boundary (labels, taint tracking, session rules, approvals), with a utility–security evaluation against scripted attackers and a real local model | Closes the information-flow hole the author's own benchmark found (MT-02); first real MCP implementation in the portfolio; evaluation-heavy | The idea is established (CaMeL, FIDES, Rule of Two, vendor gateways); the value-matching tier is heuristic and will lose to paraphrase (to be measured, not hidden) |
| C2 | Browser / computer-use agent whose every action is checked against pre/post-conditions on synthetic web apps | Highest demo impact (people watch a browser move) | Only ~1% of postings; a 4B text model cannot reliably drive a browser, so results would measure the model; thin layer over Playwright |
| C3 | Durable, event-sourced agent workflow engine with deterministic replay, crash-tested with chaos | Real distributed-systems substance | The Copilot already has leases, idempotency and recovery; Temporal and LangGraph occupy the space; "toy Temporal" risk; weak demo |
| C4 | Governed data-analyst agent: natural language to read-only SQL, with every number in the answer traced to a result cell | Plays to the author's analytics background; very useful; high FDE/Applied-AI fit | ~2% of postings name it; "chat with your data" is the most crowded demo category; the verification idea is good but narrow |
| C5 | Schema-constrained decoding study: do grammar-constrained outputs fix the Copilot's interface failures (22/22, 13/13)? | Sharpest single experiment; tiny scope, finishable | An extension of one existing repo, not a new capability; weak standalone demo |
| C6 | Agent trace record / replay / diff for regression testing | Observability is ~35% of postings | Langfuse/LangSmith/OTel exist; replay already exists in the Copilot; dashboard-around-traces risk |
| C7 | Real-time voice agent with barge-in and a latency budget | Memorable demo | Not feasible on this machine without hosted speech APIs (no credentials, no spend); ~5% of postings |
| C8 | Agent long-term memory with temporal updates and contradiction handling, evaluated on a synthetic benchmark | Memory is a hot topic | ~5% of postings; a 4B model makes the evaluation noisy; slides into "RAG demo" |

## Scores (1–5)

Columns: TD technical depth · NV novelty (to this portfolio **and** the field) · US real usefulness · DM demo impact · AA Applied-AI relevance · FD FDE relevance · AE AI-Engineer relevance · EV evaluation potential · FN credible V1 finishable in one session · OV low overlap with the existing portfolio · GR low gimmick risk.

| Candidate | TD | NV | US | DM | AA | FD | AE | EV | FN | OV | GR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| C1 Weir | 5 | 3 | 4 | 4 | 4 | 4 | 5 | 5 | 4 | 4 | 3 |
| C2 Browser agent, verified actions | 4 | 3 | 3 | 5 | 3 | 3 | 4 | 3 | 2 | 5 | 2 |
| C3 Durable workflow engine | 4 | 2 | 4 | 2 | 3 | 3 | 4 | 4 | 3 | 2 | 3 |
| C4 Governed data-analyst agent | 3 | 2 | 5 | 4 | 5 | 5 | 3 | 4 | 4 | 3 | 3 |
| C5 Constrained-decoding study | 3 | 2 | 4 | 2 | 3 | 2 | 4 | 5 | 5 | 3 | 3 |
| C6 Trace record / replay / diff | 3 | 2 | 4 | 3 | 3 | 2 | 4 | 3 | 4 | 3 | 2 |
| C7 Voice agent | 4 | 3 | 3 | 5 | 3 | 3 | 4 | 3 | 1 | 5 | 3 |
| C8 Agent memory | 3 | 3 | 4 | 3 | 4 | 3 | 4 | 4 | 3 | 3 | 3 |

## Totals under four weightings (0–100)

| Candidate | balanced (used) | equal | career-fit heavy (AA, FD, AE ×2) | finishability heavy (FN ×3) |
|---|---|---|---|---|
| **C1 Weir** | **84** | **82** | **84** | **82** |
| C4 Governed data-analyst agent | 74 | 75 | 79 | 77 |
| C5 Constrained-decoding study | 69 | 65 | 65 | 72 |
| C8 Agent memory | 68 | 67 | 69 | 66 |
| C2 Browser agent | 67 | 67 | 67 | 63 |
| C7 Voice agent | 66 | 67 | 67 | 60 |
| C3 Durable workflow engine | 64 | 62 | 64 | 62 |
| C6 Trace record / replay / diff | 62 | 60 | 61 | 64 |

C1 ranks first under all four weightings, by 5–10 points over C4. That is not a tie, and it is also not a large margin on judgement-based scores; the choice does not rest on the arithmetic.

## What actually decided it

1. **It answers the question the audit asked.** The gap with the best evidence is the one the author's own benchmark exposed and left open (MT-02). No other candidate is a consequence of an existing finding.
2. **It is the only candidate that adds a real protocol integration.** MCP is mentioned by 16% of recent AI-engineering postings and the portfolio has no working MCP code tested against a real peer.
3. **Its evaluation is the most informative.** Three controllable arms (permissions only, value-flow tracking, session rules) against scripted attackers *and* a real tool-calling model give a utility–security curve rather than a single score, and the interesting results are the failures (what the heuristic tier misses; what the sound tier over-blocks).
4. **It is finishable.** Core logic is deterministic and testable without a model; the real-model run is an evaluation layer, not a dependency of the build.

## What would have changed the decision

- If the official MCP SDK could not interoperate with a hand-written stdio proxy (checked in M4; it can: the SDK server speaks newline-delimited JSON-RPC with the standard `initialize` handshake).
- If the local model never followed an injected instruction, the real-model arm would show nothing. ARB task MT-02 already recorded such a case with this model, and the scripted worst-case attacker does not depend on the model at all.
- C4 is the fallback. It is the better *career-fit* story for analytics-heavy roles; it lost on depth, novelty, and because text-to-SQL agents appear in ~2% of postings.

## Self-check on bias

The author of this document also proposed C1 first and will build it; the scores above favour it by construction wherever judgement was involved. Two scores were lowered during writing for that reason (novelty 4→3 because the idea is established in the literature; gimmick risk 4→3 because small open-source projects with the same aim already exist). The reader should treat the ranking as a transparent rationale, not as proof.
