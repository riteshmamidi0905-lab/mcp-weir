# Limitations

Stated together, repeated wherever the project is described, and ordered by how much they matter. "Measured" means a number in [`docs/evaluation.md`](evaluation.md) or [`docs/red-team.md`](red-team.md); the rest are properties of the design.

## What Weir does not and cannot do

1. **It is not a complete defence.** It narrows what a steered agent can do with data it can already read. A determined attacker who controls both the injected text and the way the model transforms data finds a way through (measured: the adaptive attacks AD2–AD12 against the value tier).
2. **Weir does not see the model's final answer.** Weir mediates MCP tool calls and results. Once a secret is already in the model's context (it was legitimately shown earlier, then the model reads an injected instruction), Weir cannot inspect or stop the model repeating it in its reply. In the evaluation that attack (family F4, `secret_first`) reached its goal in **100%** of its runs under every arm **by construction**: the scripted agent is defined to repeat the secret and Weir has no answer interception, so it is not an empirical rate for language models. A gateway at this boundary can still reduce the risk by holding or blocking the *read* that puts the secret in context, but that does not apply when the user asked for that read. A host that renders model-chosen markdown images or links can leak data that Weir never sees.
3. **It does not see the user's prompt or the model's reasoning.** A recipient the user typed and a recipient an attacker typed look the same unless the attacker's text contains it.
4. **Covert channels are out of scope**: which tool is called, how many calls, timing, error behaviour.
4a. **It is not a formal information-flow-control system.** The labels are coarse (three confidentiality levels, two integrity levels), declared by an operator and only as good as that declaration; the content tracker is a heuristic; nothing is proved and there is no non-interference guarantee. "Information-flow" names the design vocabulary, not a verified property.
4b. **"First to stop" is an accounting convention, not a causal attribution or a ranking of importance.** It credits the first rule code listed on the first stopped attack call, and value-tier rules are listed before session-tier rules; counting every rule that fired, `R-FLOW-CONF` appears on 28.1% of those calls (13.9% first-listed) and `R-TRIFECTA` on 40.0% (2.4% first-listed). In A3 with a careful simulated approver, the first stopped call was a held call the oracle declined in 65.8% of attack runs (1,086 of 1,650) and a hard denial in 26.9% (444). The read happens before the send, so a rule that fires on the read is credited before one that would have fired on the send. The session rules ask by default, so with an approver who approves everything they stop nothing on their own (A3s, 100% of attacks) while the value tier's deny rules still stop a share (A2, 44.7%). The totals depend on the designed attack mix and differ by family. See `docs/evaluation.md` section 3.

## The value tier is a heuristic (measured)

5. It recognises a value after normalisation and after one or two layers of base64, hex or percent encoding. It does **not** recognise paraphrase, translation, spelling-out, homoglyphs, `rot13` or reversal, pieces shorter than the match length (8 normalised characters for `secret`, 24 for `internal`), a fingerprint (prefix, length, hash), base64 wrapped in short lines, or base64 of values shorter than 9 bytes. Each decoder added invites the next transformation.
6. **Data can ride in arguments it does not scan**: `R-FLOW-CONF` reads only the arguments the policy declares as *content*. The secret as the local part of a recipient address or a DNS label of a recipient domain passes (AD4, AD5). The straightforward fix is to scan target arguments as well; it was not applied because the evaluation was frozen.
7. **State changes that do not name their target are not flagged** (AD9, AD10): `R-DEST-UNTRUSTED` needs the target to appear in untrusted text.
8. Very long results are only partly tracked (per-result cap 64 KB, 50,000 results per session); the session is then marked *blind* and external egress needs approval (`R-TRACKER-LIMIT`).
9. Image and other non-text results are not tracked.

## The session tier costs usability (measured)

10. A session that mixed untrusted input with secrets is restricted whether or not anything was misused. With the shipped defaults, 19% of benign tasks (3 of 16 kinds) needed an approval; with the session rules set to *deny* (A3d), 6% of benign tasks cannot be completed at all.
11. The rules are only as good as the **policy**: an operator labels results, declares targets and content arguments, and lists internal domains. A wrong label, a missing content argument, or a tool that is not declared as egress is a bypass. Undeclared sensitive arguments appear in clear in approvals and the audit log.

## Humans

12. **Approvals show content only as a length and a digest** (to keep labelled data out of the database). A person approving "send to jordan@partner.example" cannot tell the user's e-mail from the attacker's (AD11). A static gate has the same weakness.
13. The evaluation's humans are **oracles** (a careful one that knows the user's intended steps, and one that approves everything). Real people fall in between; approval fatigue is not modelled. 0.19 approvals per benign task is a count, not a usability study.

## Protocol and engineering scope

14. **MCP tools over stdio only.** No resources, prompts, sampling, elicitation, HTTP transports or authentication. The gateway advertises the tools capability only.
15. **Tool descriptions are not inspected.** Pinning detects a definition that *changes*; it does not detect one that was malicious when you reviewed it, and tool annotations from servers are ignored (they are untrusted hints).
16. Denial messages name the rules that fired, which helps an adaptive attacker.
17. A timeout or crash after a non-idempotent call leaves the outcome **uncertain**; Weir reports it, never retries blindly, and does not reconcile it. There is no upstream restart.
18. The database key lives in the same file unless `WEIR_HMAC_KEY` is set, so the tracker's hashing is hygiene, not encryption, and the session integrity tag detects accidents and casual edits only.
19. One gateway process serves one session at a time per stdio connection; there is no multi-tenant isolation, authentication or rate limiting.

## The evidence

20. **Synthetic world, toy tools, English only, deterministic oracles that know the ground truth.** The scripted attacker is a worst case for *following* instructions and a weak case for *adapting*.
21. **One small model** (Qwen3-4B-Instruct-2507, Q4_K_M, greedy decoding, one pass per cell, one machine). The real-model result is about that model and these prompts; it is not a statement about frontier models, and no hosted model was evaluated.
22. **Same author** wrote the gateway, the testbed, the scenarios, the oracles and the red-team; an AI assistant did most of the writing; no independent review or external validation exists. The held-out seeds are held-out *instances*, not held-out *attack classes*.
23. The in-process harness is a stand-in for the real gateway process; equivalence was checked on a sample (160 held-out runs) and only on forwarding, rules fired and outcomes, not on all runs and not as a proof of total behavioural equivalence.
24. **Never deployed; no users; no external adoption; no performance claim beyond a microbenchmark** (in-process overhead and a stdio round-trip on one laptop).
25. **Prior art.** CaMeL, FIDES, Meta's Rule of Two, vendor MCP gateways and several small open-source projects address the same problem. This is not a claim of novelty or of being better than any of them; none was run for comparison.
