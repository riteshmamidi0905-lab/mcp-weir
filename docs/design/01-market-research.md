# 01 · Market and capability research (M2)

Two kinds of evidence, kept apart: **(a)** what current AI-engineering job postings ask for, measured on postings the author had already collected for another purpose; **(b)** what the security and tooling literature says is unsolved or in demand right now. Neither is a study; both are a basis for choosing, and the limits are stated.

## (a) What postings ask for

**Method.** About 34,600 postings were fetched on 2026-10-02..08 from the public job-board APIs of 342 employers on Greenhouse, Lever and Ashby and 77 Workday tenants (full descriptions, de-duplicated by URL). Cohort: posted on or after 2026-06-01, title contains an AI/ML/LLM/agent/forward-deployed term **and** an engineering/solutions term, excluding sales, legal, recruiting, trainer and intern titles, and the posting body mentions LLMs, generative AI, agents or RAG. That leaves **1,282 postings from 231 employers**: 594 with applied-AI / AI-engineer titles and 213 forward-deployed / solutions titles. Each capability is a regular expression over title plus description ([`market_mine.py`](market_mine.py); the postings themselves are third-party content and are not republished).

**Limits.** Keyword presence, not requirement strength. Regexes both over- and under-match ("monitoring"-style words were removed in a second pass; "integration" still inflates the enterprise-integration row). One three-week snapshot, skewed towards employers on those boards, no labelling by hand. Treat differences of a few points as noise; the ordering of large gaps is the signal.

| Capability (share of postings mentioning it) | All (n=1,282) | Applied-AI / AI-engineer (n=594) | FDE / solutions (n=213) |
|---|---|---|---|
| Orchestration, multi-agent, workflows | 50% | 57% | 45% |
| Enterprise integration (APIs, OAuth/SSO, SaaS connectors) | 55% | 54% | 60% |
| Evaluation (evals, LLM-as-judge, eval suites, golden sets) | 35% | 42% | 22% |
| Observability / tracing | 35% | 41% | 16% |
| RAG / vector search | 34% | 38% | 31% |
| Agent security (guardrails, prompt injection, red-team, exfiltration, least privilege) | 26% | 33% | 19% |
| Tool / function calling | 20% | 25% | 11% |
| **MCP (Model Context Protocol)** | **16%** | **16%** | **15%** |
| Fine-tuning / post-training | 16% | 21% | 14% |
| Human-in-the-loop, approval, oversight | 11% | 14% | 8% |
| Sandboxing / isolated code execution | 7% | 5% | 1% |
| Voice / speech agents | 5% | 4% | 13% |
| Agent memory / long-running state | 5% | 7% | 0% |
| Text-to-SQL / data agents | 2% | 2% | 0% |
| **Computer-use / browser agents** | **1%** | **1%** | **0%** |
| Customer-facing / deployment into customer environments | 35% | 31% | 84% |

150 of the 1,282 postings (12%) mention MCP or tool calling **and** an agent-security term in the same description.

**Reading it.**
- Evaluation is the most valuable *specific* skill and the author's strongest area. It is a reason to make the new project evaluation-heavy, not a reason to build another evaluator.
- The capabilities this portfolio has never evidenced and employers do ask for, in order: enterprise integration (55%), orchestration (50%), observability (35%), **MCP (16%)**, **agent security beyond structural containment (26%)**. The first three are ingredients rather than products; MCP and agent security are the ones that can be the *subject* of a project, and they co-occur.
- Two capabilities that dominate conference demos are nearly absent from postings: computer-use agents (1%) and text-to-SQL agents (2%). Both were therefore ranked down in `02-candidates.md`.
- For forward-deployed roles the strongest signals are customer-environment deployment (84%) and integration (60%). The security review is the usual gate between "the demo worked" and "it may touch our mail", so a security control that is demonstrably usable is FDE-relevant even though only 19% of FDE postings name it.

## (b) What the literature says is open

Summaries below are of the cited sources; the CaMeL numbers were checked on the arXiv abstract page, the rest from search-result summaries of the linked pages.

- **The "lethal trifecta".** An agent that has (1) access to private data, (2) exposure to untrusted content and (3) a way to communicate externally can be steered into exfiltration by text in content it reads; removing any one leg breaks the chain ([overview](https://arcjet.com/learn/lethal-trifecta)). Meta's **Agents Rule of Two** states the same rule as a design constraint and adds "change state" to the third leg: an agent should satisfy at most two of the three without a human or other reliable validation ([coverage](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)).
- **CaMeL** (Debenedetti et al., [arXiv 2503.18813](https://arxiv.org/abs/2503.18813)): a protective layer that extracts control and data flow from the *trusted* query, tracks capabilities on every value, and blocks unauthorised flows; reported 77% of AgentDojo tasks solved with security guarantees versus 84% for an undefended system. The cost side (utility lost) is the honest part of the headline.
- **FIDES** (Costa & Köpf, [arXiv 2505.23643](https://arxiv.org/abs/2505.23643); shipped as an experimental feature of Microsoft Agent Framework, [docs](https://learn.microsoft.com/en-us/agent-framework/agents/security)): confidentiality and integrity labels propagated through tool calls, deterministic policy enforcement, a quarantined model for inspecting untrusted data.
- **MCP-specific risk.** Tool-description poisoning, "rug pulls" (a tool definition changed after approval) and tool shadowing are documented attack classes with reported CVEs, and gateways that inspect and enforce policy on MCP traffic are an emerging product category ([CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/), [Microsoft warning as reported](https://thehackernews.com/2026/06/microsoft-warns-poisoned-mcp-tool.html), [Invariant Labs "toxic flow" analysis](https://invariantlabs.ai/blog/toxic-flow-analysis)).

**Consequence for novelty.** None of this is new as an idea. Research systems (CaMeL, FIDES), a vendor gateway and several small open-source projects with overlapping aims already exist. This project must not be presented as a discovery. What it can honestly be is an **independent, fully tested, small-scale implementation at the MCP boundary with a measured utility–security trade-off, run against a real tool-calling model, with its failures published**, derived from a gap the author's own benchmark found.

## Conclusion for M2

The capability with the best combination of (i) market weight, (ii) zero existing evidence, (iii) direct lineage from a documented finding, and (iv) feasibility on one 8 GB machine with a local 4B model is **agent security at the MCP tool boundary: information-flow control, with measured utility cost**. It also touches tool calling, MCP, human-in-the-loop, observability and evaluation at once, which no single "missing skill" alternative does.
