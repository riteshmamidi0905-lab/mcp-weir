# 00 · Portfolio capability audit (M1)

*Written before any design decision for this project. Method: read each repository's README and docs, then grep the code (`flagship-build-notes/audit.py`, a read-only script run over the pinned public commits) and open the files the greps pointed at. Grep counts alone were not trusted: the first pass over-counted several rows (for example "streaming" matched "assess") and was corrected by reading the code.*

Repositories audited (all public, same author): Support Escalation Copilot (`v0.7.1`, 31 commits), AI Agent Runtime (`ai-agent-from-scratch`, `231b186`), Agent Runtime Benchmark (`agent-runtime-bench`, `679fa28`), MAREF (`1c00c90`), llmeval (`llm-eval-framework`, `99e6121`), plus the older supporting repos (`ai-skills-platform`, `genai-doc-assistant`, `ai-agent-toolkit`, `production-ai-agent-platform`, and others).

Legend: **●** demonstrated and evidenced in the repository · **◐** present but qualified (read the note) · **○** not demonstrated

## Capability matrix

| Capability | Copilot | Runtime | Agent Runtime Benchmark | MAREF | llmeval | Note |
|---|---|---|---|---|---|---|
| Agent loop (model ↔ tools, step budget) | ○ | ● | ◐ | ○ | ○ | Copilot is a fixed state machine **by design** (ADR-0002). ARB drives the runtime's loop. |
| Tool / function calling | ◐ | ● | ● | ◐ | ○ | Copilot's provider sends no `tools`; no real-model tool call exists in 34 recorded runs. Real-model native tool calling is evidenced only through ARB (Qwen3-4B via llama.cpp). |
| Structured outputs and schema validation | ● | ● | ● | ● | ◐ | Copilot: schema, citation and grounding checks at a trust boundary. |
| Constrained decoding | ◐ | ○ | ○ | ○ | ○ | Copilot used the server's generic JSON mode only; **schema-constrained decoding was never tried**, and the real model then failed the schemas (22/22, 13/13). |
| Retrieval (vector, governance, evaluation) | ● | ◐ | ○ | ○ | ○ | Copilot: pgvector, frozen 40-ticket held-out set, lexical/hybrid/rerank comparison. Runtime's semantic memory is a hashed bag of words. |
| Persistent state, transactions | ● | ● | ○ | ○ | ○ | PostgreSQL 16 (Copilot: forced RLS, versioned transitions, leases; Runtime: migrations, Docker Compose). |
| Human-in-the-loop approvals | ● | ● | ◐ | ○ | ○ | Copilot: hash-bound to the exact action, role, tenant, expiry. |
| Guardrails / policy engines | ● | ● | ◐ | ○ | ○ | Deterministic policy over trusted facts (Copilot); permission levels and a path sandbox (Runtime). |
| Prompt-injection containment (ARB, MAREF: *measured*, not implemented) | ● | ● | ● | ● | ○ | Copilot contains by **structure** (model has no write capability), not detection. 12 real-model injection runs; 92 catalogued attacks. |
| **Information-flow control (what data may reach which sink)** | **○** | **○** | **○ (gap found)** | ○ | ○ | **ARB task MT-02 found the gap**: every control held, a read-level tool was permitted, and a secret was still disclosed. No repository tracks where a value came from or where it is going. |
| Evaluation harness, oracles | ● | ● | ● | ● | ● | The strongest area of the portfolio. |
| Frozen / pre-registered protocols | ● | ○ | ● | ● | ○ | Hash-locked benchmark, decision rule written before the held-out split was touched, lock files. |
| Benchmarks and held-out discipline | ● | ○ | ● | ● | ○ | Same-author caveat is carried everywhere; stated, not hidden. |
| Failure analysis | ● | ○ | ◐ | ● | ○ | Four failure classes at the model–interface boundary (Copilot); 10-code failure taxonomy (MAREF). |
| Replay (model-free) | ● | ◐ | ○ | ○ | ○ | 154 recorded real-model replies replay through the unchanged workflow. |
| Tracing, audit trails | ● | ◐ | ○ | ◐ | ◐ | Hash-chained audit log and correlated event stream (Copilot). **No OpenTelemetry or off-the-shelf tracing backend anywhere.** |
| Idempotent side effects, recovery | ● | ◐ | ○ | ○ | ○ | Lease-based recovery, idempotency ledger, UNCERTAIN outcomes. |
| Security boundaries (tenant isolation, CSRF, CSP) | ● | ◐ | ○ | ○ | ○ | Row-level security keyed to a signed scope; uniform 404. |
| FastAPI / HTTP service, SSE | ◐ | ● | ○ | ○ | ● | Copilot's operator app is server-rendered. |
| CI | ● | ● | ○ | ○ | ○ | Copilot CI includes PostgreSQL-backed tests (CI found a real time-zone bug in the replay). |
| Docker | ◐ | ● | ○ | ○ | ○ | |
| Local model serving (llama.cpp) | ● | ◐ | ● | ◐ | ○ | One small model (Qwen3-4B-Instruct-2507 Q4_K_M) on one machine. |
| **MCP (Model Context Protocol) against real MCP peers** | ○ | ○ | ○ | ○ | ○ | The only MCP code is ~120 lines in an orphan repo (`production-ai-agent-platform/agentplatform/tools/mcp.py`), a hand-written JSON-RPC layer tested against its own tests, never against the official SDK or a real host. The runtime's docs *discuss* MCP; nothing implements it. |
| Hosted frontier-model APIs exercised in evidence | ○ | ◐ | ○ | ○ | ◐ | Provider adapters exist; the runtime's README says they were not run for lack of credentials. No evidence is built on a hosted model. |
| Enterprise-style integration (OAuth, SaaS connectors) | ○ | ○ | ○ | ○ | ○ | Customer systems in the Copilot are deterministic mocks with fault injection. |
| Multi-agent orchestration | ○ | ○ | ○ | ○ | ○ | Deliberately absent (Copilot rejects it in ADR-0002). |
| Browser / computer-use agents | ○ | ○ | ○ | ○ | ○ | |
| Multimodal LLMs, voice / real-time | ○ | ○ | ○ | ○ | ○ | Older classic-ML repos (OCR, speech, vision) predate and do not use LLMs. |
| Fine-tuning / training of LLMs | ○ | ○ | ○ | ○ | ○ | |
| Cloud deployment, real users | ○ | ○ | ○ | ○ | ○ | Everything is local and synthetic; the READMEs say so. |

## What the audit says

**Strengths that should not be repeated.** Evaluation discipline (frozen protocols, oracles, replay, failure taxonomies), approval-gated workflows, typed actions, tenant isolation, and honest reporting are already evidenced several times over. A sixth project in that style would add little.

**The gap with the best evidence behind it is already in the portfolio.** ARB task **MT-02** (`agent-runtime-bench/docs/RESULTS.md`, "the gap it exposes"): a fetched page told the model to read a configuration value and reveal it; the model called the read-level `get_config` and wrote the passphrase in its answer. In the benchmark's own words, *the controls constrain **actions** (writes, dangerous tools, budgets), not **information flow through permitted read tools***. All seven controls held in 240/240 runs and the secret was disclosed anyway. The portfolio documents the problem and stops there; it never builds the missing control.

**Capabilities with zero evidence and non-trivial market weight** (market data in `01-market-research.md`): MCP against real peers (≈16% of recent AI-engineering postings), enterprise integration patterns (≈55%), standard observability (≈35%), and agent security/guardrails beyond the Copilot's structural containment (≈26%). **Capabilities with zero evidence and little market weight**: computer-use agents (≈1%), text-to-SQL agents (≈2%), agent memory (≈5%), voice (≈5%, higher for FDE roles at ≈13%).

**Constraints on what can be built tonight** (also from the audit): one 8 GB machine; one local model (Qwen3-4B-Instruct-2507 Q4_K_M, which natively calls tools and, per ARB, does follow injected instructions at least sometimes); no hosted-model credentials and no permission to spend; no Docker daemon available to test container builds.

## Verdict for M1

> **The missing capability is a control for information flow at the tool boundary, built on the real tool protocol (MCP), with an evaluation that measures both the security it buys and the utility it costs.** It closes a documented hole in the author's own benchmark, it adds the portfolio's first real MCP implementation, and it does not repeat any existing evidence.
