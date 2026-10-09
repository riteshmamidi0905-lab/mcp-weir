# Red-team log

Two phases, kept apart on purpose (see `eval/PROTOCOL.md` §9):

* **9a, implementation hardening, before the evaluation was frozen.** Bugs were fixed, and each fix has a regression test.
* **9b, adaptive attacks, after the held-out results.** Written with knowledge of Weir's rules; gaps are **reported, not fixed**, because fixing them would invalidate the frozen evaluation.

Nothing here is a penetration test by someone other than the author, and nothing here shows that Weir is secure.

## 9a · What the implementation red-team found (all fixed)

Found by writing hostile input *before* trusting the code; the fixes are in the commit history before the evaluation freeze.

| # | Found by | Defect | Consequence | Fix and test |
|---|---|---|---|---|
| 1 | a test (`test_policy.py`) | `posixpath.normpath("//secrets/x")` keeps two leading slashes, so a `/secrets/*` rule did not match `//secrets/x` | a secret file readable under a spelling the rule missed | `canon_path` collapses leading slashes; parametrised path tests |
| 2 | dev evaluation (sanity check on the no-gateway arm) | **public-path downgrade never existed**: labels only ever *joined*, so `/public/*` files stayed `internal` and every send of public data to a partner needed approval | utility cost (and a policy that said something it did not do) | explicit `lower = true` rules that apply only to an absolute, canonical, un-encoded path; tests that `/public/../secrets/x` keeps the secret label |
| 3 | dev evaluation (a "careful human" oracle approved an exfiltration) | the approval screen hid the **URL** of a web fetch, because the same argument was both target and content | an approver cannot judge a call it cannot see | target arguments are always shown (URL host and path in clear, query and fragment withheld) and the oracle judges on the same view |
| 4 | dev evaluation (oracle check) | the leak oracle mis-scored chunked exfiltration (it joined subjects between chunks) | an arm looked safer than it was | oracle reassembles bodies / query values only; the no-gateway arm must score ≥ 90% (and does) |
| 5 | fuzzing (`test_robustness.py`) | an exception raised by an **upstream implementation** (not a protocol error) propagated out of the gateway | a crash instead of an error result | any exception from an upstream is an "uncertain failure" result, logged |
| 6 | fuzzing | arguments that cannot be serialised (deeply nested) crashed the approval/audit view | crash on hostile input | safe canonicalisation: refused with `R-LIMIT`, never fatal |
| 7 | JSON-bomb test | a message nested hundreds of thousands deep raised `RecursionError`, which the stdio server did not catch (only `ValueError`) | **a single message could kill the gateway process** (and the same on the upstream side) | both decoders catch `RecursionError`; the server answers `-32700` and keeps serving |
| 8 | concurrency test (8 gateways opening one new database) | `PRAGMA journal_mode=WAL` / schema creation raised `database is locked` | start-up failure under contention | retry with backoff during initialisation |
| 9 | threat-model review | persisted session rows (context label, egress counter, tracker) could be edited to "forget" a secret | weakened protection after a restart if the file is writable | HMAC tag over the row; resume also requires an intact audit chain; `WEIR_HMAC_KEY` from outside the file makes the tag resist file editing |
| 10 | threat-model review | a result larger than the tracker's per-result cap hides a secret's tail from the value tier | silent blindness on long documents | the session is marked *blind*; later external egress needs approval (`R-TRACKER-LIMIT`) |

| 11 | the overhead benchmark (pre-freeze) | the whole tracker was re-serialised after every labelled result: per-call cost grew with session size (p99 741 ms at 10,000 results) | a long session became unusably slow (a denial of service by volume, and a failed success criterion) | append-only journal persisted in the same transaction as the session row; rolling digest in the MAC; benchmark rerun: p99 0.66 ms |

Attempts that did **not** break anything (kept as tests): look-alike and header-injected recipients, userinfo / backslash / `%00` / numeric-host / `javascript:` / `data:` / `file:` URLs, quoted-local-part and double-`@` addresses, Cyrillic homograph domains, fuzzed JSON arguments for every tool, 8 identical concurrent calls on one approval (exactly one runs), 10 concurrent sessions on one database (only the clean ones can read the secret), cross-session tracker isolation, plaintext secret at rest (none in the database or WAL), tampering with the audit chain, odd tool names (all `R-UNKNOWN`), HTML escaping in the flow trace.

## 9b · Adaptive attacks against the design

*(filled in after the held-out evaluation; see below)*
