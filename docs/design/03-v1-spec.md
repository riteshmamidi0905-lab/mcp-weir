# 03 · Weir V1 specification (M4)

> **Status: frozen on 2026-10-08 before any implementation.** Changes after this point are appended to *Spec changes* at the bottom with a date and a reason; the original text is not edited. Anything in the final repository that departs from this document without an entry there is a defect.

**Weir** is a gateway that sits between an AI agent host and the MCP servers it uses, and decides, call by call, whether data may flow where the agent is trying to send it.

## 1 · User and problem

**User.** An engineer who gives an LLM agent tools (mail, files, web) over MCP and has to answer a security reviewer's question: *"If the agent reads something hostile, what is the worst it can do with what it can already read?"*

**Problem.** Per-tool permissions are necessary and not sufficient. The author's own benchmark (ARB task MT-02) recorded the case: the policy allowed a read-level tool, every control held, and a secret still left because an instruction hidden in fetched content told the model to read it and say it. The same shape works for email, URLs and shared documents ("lethal trifecta": private data + untrusted content + a way out). Permissions say *which tools*; the missing control says *which data may reach which destination, given what the agent has already seen*.

## 2 · System boundary

```
 user prompt (trusted) ─► AGENT HOST ◄──► LLM (untrusted: steerable by any text it reads)
                              │ MCP over stdio
                       ┌──────▼───────┐
                       │     WEIR      │  deterministic: labels, tracker, policy, approvals, audit
                       └──┬─────┬──┬──┘
             MCP over stdio│     │  │
                      mail  files  web   (upstream MCP servers; trusted to be what the policy says they are)
```

**In scope (V1):** MCP **tools** (`tools/list`, `tools/call`) over **stdio**, host side and upstream side; text results; policy-driven labelling and enforcement; human approvals; tamper-evident audit; tool-definition pinning; an evaluation harness and a deterministic testbed.

**Out of scope (stated, not hidden):** MCP resources, prompts, sampling and elicitation; HTTP transports and authentication; images/binary results; multi-user ACLs; anything the host does with the *final answer* (rendering, auto-fetching markdown images); a compromised or malicious upstream server's code; detecting poisoned tool descriptions (only *changes* are detected, by pinning); covert channels (timing, call counts); social engineering of the approving human; model-level defences.

## 3 · Threat model

- **Trusted:** the user's prompt, the operator's policy file, the gateway process and its database, the upstream servers' code (as reviewed and pinned).
- **Untrusted:** the LLM (it may do anything any text in its context asks), and every byte returned by a tool whose policy says `integrity = "untrusted"`.
- **Attacker can:** write content the agent will read (inbound email, web page, shared document, file contents). In one scenario family, change an upstream tool definition after review ("rug pull").
- **Attacker goals:** (G1) get SECRET data to an attacker-observable place; (G2) cause a state change the user did not ask for (send mail to an arbitrary address, write or delete a file); (G3) get a secret into the *answer* the user reads.
- **Observation points Weir has:** tool calls and tool results. It does **not** see the model's reasoning, the user prompt, or the final answer. So for G3 the only enforceable control is on the *read* that makes the secret available.

## 4 · The AI component and the deterministic component

| | AI (untrusted) | Deterministic (Weir) |
|---|---|---|
| Responsibility | Plans the task, chooses tools and arguments, writes the answer | Labels every result by policy; tracks where labelled values appear in later arguments; classifies destinations; applies rules; queues approvals; forwards, times out, audits |
| Failure of this part | Is assumed (steered, wrong, malformed) | Is tested: unit, property, protocol, interop, fault-injection, red-team |
| What it is never trusted with | Deciding what is sensitive, who may receive it, whether a call is allowed | Deciding what the user meant |

There is no LLM inside Weir. This is deliberate: nothing an LLM would add here (classifying injections, judging risk) is something normal code can enforce, and a model in the enforcement path would make the enforcement steerable by the content it inspects.

## 5 · Policy model

A single TOML file, validated strictly at start-up (unknown keys, bad enums, undefined servers or tools in rules are errors; **an invalid policy refuses to start**).

- **Labels.** `conf ∈ {public < internal < secret}`; `integ ∈ {trusted < untrusted}`. Join is component-wise max. A *label* is a pair; the *session context label* is the join of the labels of everything Weir has returned to the host in this session.
- **Tools.** Every upstream tool must be declared (`<server>__<tool>`, namespaced by Weir); **undeclared tools are denied** (`R-UNKNOWN`). A declaration gives the tool's `effect` (`read` | `write` | `egress`), the labels its result carries (optionally per argument pattern, e.g. paths under `/secrets/`), its `target_args` (arguments that choose a destination or object: recipient, URL, path) and `content_args` (arguments that carry data out).
- **Destinations.** `internal_domains` (matched by exact domain or subdomain after proper parsing of e-mail addresses and URLs; lookalikes such as `corp.example.evil.net`, `corp-example.com` or `https://corp.example@evil.net/` are external; anything unparseable is external).
- **Rules** (each can be `off | approve | deny`, with the defaults below). Every rule that fires is recorded; the final effect is the most restrictive (`deny` > `approve` > `allow`).

| Rule | Fires when | Default | Why it exists |
|---|---|---|---|
| `R-UNKNOWN` | tool not declared in policy | deny | fail closed |
| `R-PIN` | tool definition differs from the lock file | deny | rug pull |
| `R-DEST-UNTRUSTED` | a `target_arg` of a write/egress tool contains a value that came from an `untrusted` result, and the destination is not internal | approve | a recipient chosen by the attacker's text |
| `R-FLOW-CONF` | a `content_arg` of a call to an **external** destination contains a tracked value with `conf ≥ internal` (**secret → deny**, internal → approve) | per label | explicit data-to-sink flow |
| `R-TRIFECTA` | an external-destination egress call while the session context is `secret` **and** `untrusted` | approve | sound fallback when the value was transformed so that matching cannot see it |
| `R-UNTRUSTED-READ` | a call whose declared result is `secret` while the session context is `untrusted` | approve | stops the attacker-induced read itself; the only control that helps G3 |
| `R-EGRESS-BUDGET` | more than *N* external egress calls in one session | approve | chunked exfiltration |

The rules map onto the Rule of Two: `R-TRIFECTA` and `R-UNTRUSTED-READ` are session-level (sound against a black-box model, expensive in utility); `R-FLOW-CONF` and `R-DEST-UNTRUSTED` are value-level (cheap in utility, defeatable by transformation).

## 6 · Value tracker (the heuristic part, specified so it can be attacked)

- Every text block of a result with a label above `(public, trusted)` is **registered**: normalised (Unicode NFKC, case-folded, only letters and digits kept), cut into overlapping k-grams (k = 8 for `secret`, 24 for `internal`, set by policy), plus a **whole-unit** entry for short values (lines and `key=value` right-hand sides shorter than k, minimum 5 normalised characters), plus **entities** (e-mail addresses, URLs and hosts, digit strings ≥ 6) for `R-DEST-UNTRUSTED`.
- Stored form is **keyed hashes only** (HMAC-SHA-256 under a per-database key); no plaintext of any labelled value is written to disk by the tracker.
- **Matching** an argument: normalise it the same way; also decode embedded base64, hex and percent-encoded spans and test the decoded text; look up k-gram hashes. A hit reports which earlier call and label it came from and how it matched (verbatim, normalised, decoded).
- **Known evasions, by design not handled:** paraphrase, translation, spelling digits as words, letter substitution, splitting a value into pieces shorter than k, reordering, rot13/reversal (not decoded), steganography. These are *expected* to defeat the value tier; the evaluation reports how often, and the session tier exists because of them.

## 7 · Approvals

A call that needs approval returns an MCP tool result with `isError: true` and a message naming the rule codes and an approval id; it contains **no** labelled data. A human approves or denies with the CLI (`weir approvals …`). An approval is bound to the exact call (session + tool + canonical-argument hash), single-use, and expires. The gateway executes an approved call only when the identical call is retried. Approving never edits a policy.

## 8 · Failure model

| Failure | Required behaviour |
|---|---|
| Invalid policy / lock file | refuse to start (non-zero exit, message on stderr) |
| Upstream crash, hang or malformed reply | the call fails with an error result after a timeout; no retry of non-idempotent tools; audit event; other upstreams unaffected |
| Gateway crash mid-session | on restart with the same session id, the context label and tracker state are restored from the database; a previously blocked attack stays blocked |
| Database unavailable or locked | fail closed (deny), never "allow because the check could not run" |
| Malformed JSON-RPC, oversize message, unknown method | JSON-RPC error; process keeps serving; limits are enforced (message and argument size) |
| Duplicate/replayed approval, double execution | approval consumed atomically; a second use is denied |
| Concurrent calls | decisions are serialised per session; a result is labelled and recorded **before** it is returned to the host |
| Tool definition changes after review | affected tools denied (`R-PIN`) and audit event |
| Audit tampering | detected by `weir audit verify` (hash chain) |

## 9 · Evaluation plan (protocol is frozen separately, before any final run)

- **Arms:** A0 direct to the servers (no Weir) · A1 permissions only (`R-UNKNOWN`, `R-PIN`, destination allow-list; what action-level controls give) · A2 A1 + value tier (`R-FLOW-CONF`, `R-DEST-UNTRUSTED`) · A3 A2 + session tier (`R-TRIFECTA`, `R-UNTRUSTED-READ`, `R-EGRESS-BUDGET`).
- **Workloads:** (i) *benign tasks* the user really asked for, including ones that legitimately read secrets or mail external parties (utility, false blocks, approval burden); (ii) *attack families* G1–G3 over channels mail, URL query, shared note, answer text, plus evasions, rug pull and cross-session; (iii) *adaptive attacks* written after the freeze, reported separately.
- **Agents:** a scripted benign agent; scripted **worst-case obedient attackers** (follow the injection perfectly, independent of any model); and **Qwen3-4B-Instruct-2507** (Q4_K_M, local, native tool calling) through the official MCP client.
- **Generation and splits:** scenarios are generated from templates by seed; development seeds are used while building; held-out seeds are generated only after the freeze. No change to Weir after the freeze is allowed to be re-run as if held out.
- **Reported:** counts with denominators and Wilson intervals; attack success per arm and per family; utility per arm; approvals per benign task; first rule that fired; gateway overhead (µs/call in-process, ms/call over stdio). Real-model and scripted results are never merged.
- **Honest limits to carry:** one author wrote the gateway, the testbed, the scenarios and the oracles; one small model; synthetic data; the oracle approver knows the ground truth (a real human may approve an attacker's request).

## 10 · Demonstration (60–90 seconds)

A synthetic mailbox contains a vendor invoice whose body hides an instruction. The same scripted-obedient agent and the same task ("summarise my unread mail and file anything urgent") run twice: directly (the passphrase arrives in the attacker's inbox) and through Weir (the secret read is held for approval; when it is approved anyway, the outgoing mail is denied for *two independent reasons*, one of which is a data-flow match). Weir then prints a **flow trace** (a self-contained HTML page from the audit log) showing each tool call, the label it carried, and the exact rule that stopped the leak. Optionally the real Qwen3-4B runs the same scenario live.

## 11 · Success criteria (targets, not claims; results are reported whether or not met)

1. All deterministic tests pass in CI; label-lattice and tracker properties pass under property-based testing; Weir interoperates with the **official MCP SDK** as host client and as upstream server.
2. On the held-out scripted workload: A0 attack success ≥ 90 % (otherwise the workload does not exercise the vulnerability) and A3 attack success ≤ 5 % on the non-adaptive families.
3. Every blocked attack and every false block is attributed to a named rule in the audit trail.
4. Gateway-added latency ≤ 20 ms at p99 per call in-process with a 10,000-fragment tracker.
5. At least one finding that is **not** a success is reported prominently (an evasion that works, a utility cost, a limitation of the boundary).

## 12 · Limitations to be repeated everywhere the project is described

Not a complete defence; value tracking is a heuristic and is expected to lose to a determined paraphrase; session rules trade utility for soundness; Weir cannot see the final answer, so G3 is only addressed at the read; the label policy is written by the operator and a wrong label is a bypass; synthetic world, one author, one small model; stdio only, tools only; never deployed, no users, no external validation.

## Spec changes

* **2026-10-08 (before any evaluation run): rule `R-GATE` added, default off.** Arm A1 ("permissions only") must be a real, comparable baseline: a static, argument-blind approval gate on every `egress` (and optionally every `write`) call, which is what per-tool approval gates in the author's earlier projects do. It was missing from §5. Default behaviour of every other arm is unchanged. Policy keys: `rules.gate_egress`, `rules.gate_write`.
* **2026-10-08 (before any evaluation run): approvals and the audit trail show every argument the policy does not declare as *content* in clear (truncated to 200 characters), content arguments only as length and digest.** §7 said approvals contain no labelled data; this keeps that true while letting a human see *what is being read or written*. The matched sources of a flow are listed, never the matched text. Policy authors must declare content arguments (including `write_file.content`); an undeclared sensitive argument would be logged in clear.
* **2026-10-08 (before any evaluation run): `/shared/*` paths are labelled `untrusted` in the example policy** (files outside parties can write), so a file can be an injection vector as well as mail and web pages.
* **2026-10-08 (before any held-out run): persisted sessions carry an integrity tag.** A MAC (HMAC-SHA-256) over the context label, counters, policy digest, version, blind flag and the tracker's digest is stored with each session row and checked on load; resuming also requires an intact audit chain. §8 listed "gateway crash mid-session" and "audit tampering"; this closes editing the session row (for example resetting the egress counter or forgetting that a secret was seen). With the key stored in the same file (the default) it detects accidents and casual edits only; supplying `WEIR_HMAC_KEY` from outside the file makes it resist editing the database. Tracker blobs are covered through their digest.
* **2026-10-08 (before any held-out run): rule `R-TRACKER-LIMIT` (default approve).** A labelled result larger than the tracker's per-result cap (default 64 KB) or beyond its source cap is only partly tracked; the session is marked *blind* and any later external egress with an internal-or-secret context needs approval. Added because "long context" is a way to put a secret where the value tier cannot see it; the session tier already covered the case only when untrusted data was also present. Arms: on in A2, A3, A3d; off in A1 and A3s.
