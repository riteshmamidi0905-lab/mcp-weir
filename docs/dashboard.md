# The Weir Control Center

A local browser view of a Weir database. It shows sessions, tool calls, the decision Weir made on each (ALLOW, HOLD, DENY), the rules that fired, the data-flow relationships Weir recorded, pending approvals, the audit chain and the policy. It is a viewer for what the gateway recorded; it adds no rules, changes no decision, and is **not part of the gateway and not part of the frozen evaluation**.

```
agent host ──▶ weir run (the gateway) ──▶ MCP servers          weir-dashboard ──▶ http://127.0.0.1:8731
                    │                                                  ▲
                    └──── SQLite: sessions, events, approvals ─────────┘  (opened read-only)
```

> **Answer channel.** Weir mediates MCP tool calls and results. It does not inspect the model's final answer. A quiet dashboard therefore does not mean nothing leaked: it means no mediated call was held or blocked. The same sentence is on every page of the interface.

This is a research prototype's observability tool, written for one developer's machine. It is not a security review of anything, it makes no claim about how much it helps against any attack, and none of the benchmark numbers in this repository come from it or depend on it. It does not change any benchmark result, any frozen file or any claim made elsewhere in this repository.

![session flow: ALLOW, two HOLDs (one approved in the browser and then repeated by the agent) and a DENY](assets/dashboard-flow.png)

*A real `weir run` gateway driven over stdio by a small test client, in the invented world. The agent fetched a page (ALLOW), asked for a secret file (HOLD; a person approved it in the browser; the agent repeated the identical call and it ran) and then tried to mail the content out (DENY, which no approval can override). The three rules on that last call are the ones that fired.*

## Run it

```bash
pip install -e .                       # installs the weir-dashboard command next to weir
weir --db weir.db run --policy examples/policies/workspace.toml     # your agent host starts this, as before
weir-dashboard --db weir.db --policy examples/policies/workspace.toml --lock tools.lock.json
# Weir Control Center  http://127.0.0.1:8731/
```

`python -m weir_dashboard …` is the same command. Options: `--db` (default `$WEIR_DB` or `./weir.db`; it need not exist yet), `--policy` (enables the Policy view and the configured rule actions), `--lock` (shows what a lock file pins), `--port` (default 8731; `0` picks a free one), `--mask` (start with destinations and clear arguments masked), `--demo-dir`, `--open`. There is no option to listen anywhere except `127.0.0.1`.

**Why a separate command and not `weir dashboard`?** `weir` is `src/mcp_weir/cli.py`, one of the 32 files the evaluation froze and hashed. Adding a subcommand would change that file and the frozen root. The dashboard therefore lives in its own package, `src/weir_dashboard/`, which imports from `mcp_weir` and is imported by nothing in the frozen set (a test checks this, and `python -m weir_eval.freeze verify` still says "freeze intact").

To look at the databases the existing demo writes: `python -m weir_eval.demo --out /tmp/d`, then `weir-dashboard --db /tmp/d/weir-careless.db`. The demo script now also writes a small source file next to each database so the sessions show up labelled (see below).

## The views

| View | What it shows | Where it comes from |
|---|---|---|
| **Overview** | time since the last audit event, chain status, session counts, pending approvals, decision counts, the eight most recent decisions | counts of events and approval rows; nothing is estimated |
| **Sessions** | one row per session: source label, start, last activity, current context label, call counts by decision, pending approvals, chain status | `sessions` (plain columns), `events` |
| **Session → Flow** | each call as AGENT → WEIR → TOOL: arguments as recorded, the decision, rules fired with Weir's own messages, the result label, the context before and after; refreshed by polling once a second | `call.decision` and `call.result` events, read with `mcp_weir.report.build_records` |
| **Session → Provenance** | an edge from an earlier call to a later one wherever a rule hit names it as the source of a matched value | the `sources` lists inside `call.decision` events, nothing else |
| **Session → Context** | the label lattice (confidentiality public < internal < secret × integrity trusted < untrusted), the states the session reached and the call that first raised it to each | `ctx_before` / `ctx_after` in events; the lattice names come from `mcp_weir.labels` |
| **Approvals** | holds waiting for a person, with APPROVE and DENY | `approvals` table |
| **Audit** | VERIFY CHAIN, event count, latest event, events by kind, hash links | `Store.verify_chain` |
| **Policy** | read-only: tools, effects, label rules, targets, content arguments, rule actions, tracker settings, upstream names; the rule inspector; tool pinning | the policy file you pass, loaded with the gateway's own strict loader |
| **Demo** | the three-way demonstration, kept apart from your database | see below |

![approval card for a held call](assets/dashboard-approval.png)

![recorded data-flow relationships](assets/dashboard-provenance.png)

![the rule inspector explaining why a rule fired on one call](assets/dashboard-rule.png)

![the audit view after Verify chain](assets/dashboard-audit.png)

**Rule inspector.** Click any rule chip. The table behind it (`src/weir_dashboard/rules.py`) restates `docs/policy.md` section 3 and the messages in `decision.py`; the configured action is read from the policy (or the gateway defaults if no file was passed); "seen here" counts come from your events. A test fails if a rule code appears in the gateway source but not in the table.

**Words.** Weir's verdict names are ALLOW, APPROVE and DENY. The interface says HOLD for APPROVE (a person can decide) and DENY for DENY (blocked; an approval cannot override it). A call that was held and later ran after approval is shown as HOLD with "RAN AFTER APPROVAL". The gateway's own verdict name is in each call's details.

## Which sessions are live, recorded or synthetic

The audit log does not record how a session was produced, so the interface cannot read it from the log. Every session shows one of:

* **LIVE LOCAL SESSION**: the database has no source file, so the session is read as the output of a gateway on this machine, and it had an event in the last two minutes. An older one reads **LOCAL SESSION · IDLE**. This is an assumption with a stated basis, not proof: a database copied from elsewhere without its source file would be labelled the same way.
* **SYNTHETIC DEMO**: a source file next to the database says so. A scripted agent and a *simulated* approver in an invented world.
* **RECORDED REAL-MODEL REPLAY**: a source file says the model's replies were recorded earlier from a real local model (`demo/recorded/f1-web.json`) and replayed through the gateway. The decisions are recomputed on replay, not recorded; the approver is still simulated.
* **SOURCE UNKNOWN**: a source file exists but cannot be read. It is never treated as live.

The source file is `<database>.weir-source.json`, written by `weir_eval.demo` and by the dashboard's own demo loader. It is plain JSON and can be edited by anyone who can write the directory. Independently of the label, a session whose approvals were resolved by the name `auto` (the gateway's in-process approver) is flagged as resolved by a programmatic approver, not a person.

**Demo view.** *Load synthetic demo* runs the repository's existing three arms (`weir_eval.demo`) when you press it: no gateway; Weir with a careful simulated approver; Weir with an approve-everything simulated approver. Every ALLOW, HOLD and DENY is computed by the real gateway at that moment; the page replays nothing it stored. The databases go to a separate directory (`--demo-dir`, default a temporary one), are labelled as above, and never appear in your Sessions list or Overview counts. The "no gateway" column has no audit record (there was no gateway); it is the demo runner's own list of the calls the agent made, and the line "the planted secret reached the attacker" is the existing synthetic oracle's verdict on that invented world. *Load recorded real-model replay* does the same from the committed recording. Neither is a measurement, and neither says anything about how often an attack succeeds; the evaluation reports that, under its own protocol, and is untouched by this interface.

![the Demo view: three arms side by side](assets/dashboard-demo.png)

![the flow at a phone width: one column](assets/dashboard-mobile-flow.png)

## What it reads, and what it can change

**Reads.** The database is opened `mode=ro` with `query_only` on, through a subclass of the gateway's own `Store` that skips its schema setup (so opening a database cannot create or alter anything) and refuses every write method. From `meta` only the schema version is read: **the integrity key is never read or sent**. From `sessions` only plain columns are read (no tracker blob, digest or MAC); `tracker_deltas` is never read. Events and approvals are read as stored. The policy and lock files are read if you pass them; commands and environment values of upstream servers are not shown (names of environment variables are), because they can hold credentials. Tests scan every API response and the page for the key, the tracker bytes, the MACs and the synthetic secret. One side effect on disk: opening a cleanly closed WAL-mode database read-only makes SQLite create its `-wal` and `-shm` files beside it; the database's contents are unchanged (a test compares full dumps before and after).

**What it can change** (the heading for the rest of this section). Exactly one thing: pressing APPROVE or DENY on a held call calls `Store.resolve_approval(id, approve, by="dashboard")`, the same function `weir approvals approve` and `deny` call, on a separate read-write connection that cannot create a database and exposes no other write. It adds no events, edits no policy, has no policy editor, and cannot touch a DENY (there is nothing to approve: a deny never creates an approval row). Loading the demo writes to the demo directory only.

## Approval: what the existing mechanism does

Read from `store.py` and `gateway.py` before the write path was built, and then tested (`tests/test_dashboard_backend.py`). These are findings about Weir as it stands, and some are limits.

* **Bound to the exact call and session.** An approval row stores the session id and the SHA-256 of the canonical `{tool, arguments}`. The gateway consumes an approval only for a call with the same pair, in state `approved`, not expired. A call with different arguments (a trailing space is enough) or from another session does not use it (tested).
* **Single use, atomic.** `consume_approval` turns `approved` into `consumed` in one `BEGIN IMMEDIATE` transaction; the repeat of a consumed call needs a new approval (tested). `resolve_approval` is also one transaction and refuses anything but `pending`, so of any number of simultaneous decisions on one approval exactly one wins (tested with ten simultaneous requests, each on its own connection). A decision on an approval that is already approved, denied, consumed, expired or missing changes nothing and the page says why.
* **The gateway does not wait.** It returns "approval required" to the agent, which has to repeat the identical call after a person decides. Approving here does not run anything. The approval lives until it is used or expires (the policy's `approval_ttl_seconds`, 900 by default).
* **A denial is sticky.** After a deny, the identical call in that session is blocked with `R-APPROVAL-DENIED`, including after the approval's expiry time.
* **A deny cannot be approved.** A call with any DENY rule never reaches the approval step (`gateway.py`: a DENY verdict is returned before `_gate`), so no approval row exists for it. The page offers no button there and the server refuses unknown ids.
* **Not bound to the rule set or the session state (a limit).** An approval granted when only `R-DEST-UNTRUSTED` fired is consumed on a repeat even if `R-TRIFECTA` now fires too, because both are HOLD rules and the call is unchanged (a test characterises this). If a DENY rule applies on the repeat, the call is blocked and the approval stays unused until it expires. The page warns when the session's context label has changed since a call was held.
* **A human decision is not a chain event (a limit).** `weir approvals approve` and this dashboard write the decision to the `approvals` table (`resolved_by`, `resolved_at`). The gateway adds an `approval.resolve` event only for its in-process approver, and `approval.consumed` when a repeat call uses an approval. So an approval that is never used leaves nothing in the hash chain, and the `approvals` table is not hash-chained. The dashboard does not add events of its own: that would be a second process writing into the chain. The interface shows the table's record and labels it as such.
* **What the person approves is partly hidden.** Content arguments are stored as length and digest, so a person approving a send cannot read what is sent; this is how Weir keeps labelled data out of its database.
* **Before it writes**, the server checks that the dataset is the primary local one, the approval exists and is still pending, and that the fingerprint the page showed (a hash of the approval's id, session, call hash, tool, rules and summary) equals the stored row's, so a stale or different page cannot decide. The button asks twice ("Confirm: approve this exact call"). Database errors answer "Nothing was changed."

Not tested: a race against a live gateway in another OS process and against `weir approvals` at the same instant. SQLite's locking is what protects those; the dashboard adds no locking of its own.

## Localhost boundary and what it does not defend

Binding: the socket is created on `127.0.0.1` and there is no parameter to change that. A test fails if a host option appears or the wildcard address is named in the server source. If you ever need another address, that is a deliberate change to the code, not a flag.

| Concern | What the server does |
|---|---|
| A web page in your browser reading the API | no CORS headers on any response; `Sec-Fetch-Site` other than same-origin is refused; a cross-origin `fetch` cannot read the answers |
| A web page posting an approval | POST needs an `Origin` equal to this server, `Content-Type: application/json` (not a simple form type), `Sec-Fetch-Site: same-origin` when sent, and a random per-run token that only the served page contains |
| DNS rebinding (another name pointing at 127.0.0.1) | every request's `Host` must be `127.0.0.1:<port>` or `localhost:<port>` |
| Script injection from data | the page builds the DOM with text nodes; the only HTML parsed from a string is a constant icon table; `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'`, no inline script or style |
| Reaching other files | the static files are a closed list; no path is built from a request |
| Leaving traces | `Cache-Control: no-store`, `Referrer-Policy: no-referrer`; no analytics, fonts or requests to any other host |

**Not defended: other software on the same machine.** There is no login. Anyone who can open a TCP connection to `127.0.0.1` on this computer, another user or a local process, can read the pages, fetch the token from the page and approve a held call. The token stops other websites, not other local programs. Run it on a machine you trust, and stop it when you are not using it.

## Redaction

The gateway stores recipients, URL host and path, file paths and any argument the policy did not declare as content in clear, and content arguments only as length and digest. The dashboard shows exactly that and no more. **Mask** (top bar, or `--mask`) hides every clear value on screen by shape (`a•••@•••.example`, `https://e•••.example/•••`, `/secrets/•••`) before it leaves the server, so it is not a visual blur. It changes display only: the database is untouched. Masking does not hide tool names, rule codes, counts, labels or timestamps. Use it for screen sharing. The synthetic demo shows `verify@evil.example` because it is an invented address in an invented world.

## Accessibility

Keyboard operation of every control; a visible focus ring; skip link; landmarks and an aria-live region that announces new decisions; ALLOW, HOLD and DENY are distinguished by a word, an icon shape and a border style as well as colour; text pairs meet WCAG AA contrast in light and dark (a test computes it); `prefers-reduced-motion` turns off animation; touch targets are at least 44 px under 768 px wide; the layout has no page-level horizontal scroll from 1440 to 390 px, and the flow reflows to one column. These were checked with the headless browser tests below, not with a screen reader or on real devices.

## Tests

`tests/test_dashboard_backend.py`, `tests/test_dashboard_server.py` and `tests/test_dashboard_claims.py` run with the rest of `pytest`: read-only access, the data model against the gateway's own reader, the rule table against the gateway source, audit failure wording, the approval cases above, redaction, the server defences, source labelling, the demo loader, contrast, and claim guards (HOLD and DENY stay different; "simulated" and the synthetic label stay; a recorded or synthetic session cannot become live; the answer-channel sentence stays; banned phrases stay out). `tests/test_dashboard_ui.py` drives the page in headless Chromium: 26 browser tests covering navigation, decision cards, approval controls, rule inspector, audit failure, policy, labels, five widths, keyboard, reduced motion and live updates.

**Test counts.** The repository collects 418 tests. 342 of them are the suite whose count was recorded at release time in `eval/results/tests.json` (the number the README quotes); the other 76 are files named `tests/test_dashboard_*.py`, added with the Control Center. `tests/test_dashboard_counts.py` fails if these numbers stop agreeing with what `pytest` collects. The 26 browser tests are one `pytest` item (the wrapper in `test_dashboard_ui.py`, which also fails unless exactly 26 pass), so 418 counts the wrapper once.

**What runs where.** The standard CI matrix (three Python versions, two operating systems) runs 417 of them and skips the browser wrapper, because that job installs no Node. A separate `control-center` job installs Node and Chromium from a pinned lockfile (`tests/ui/package-lock.json`, Playwright 1.62.1), sets `WEIR_REQUIRE_BROWSER=1` so a missing prerequisite fails instead of skipping, and runs the Control Center test files, including the browser wrapper. Locally, `npm ci --prefix tests/ui && node tests/ui/node_modules/playwright/cli.js install chromium` is enough; `WEIR_NODE` and `WEIR_PLAYWRIGHT_DIR` override the defaults.

## Known limitations

* **No gateway status.** The database has no heartbeat, so the page cannot say whether a gateway process is running, how long it has been up or what its load is. It shows the time since the last event and whether that is recent. "Active session" means an event in the last five minutes; the log has no end-of-session record.
* **It cannot tell which lock file the gateway ran with.** Tool pinning is shown from the `--lock` file you give the dashboard; the log records only `pin.mismatch` events.
* **Chain verification is a consistency check**, not proof. It compares each stored event with its hash link using the gateway store's own code. It does not detect events removed from the end, and the hashes are not keyed, so someone who can write the database can rebuild them. A failure is reported as "Hash-chain verification failed." with the first failing event; the cause is not known from the page.
* **Labels come from a file.** The session source is a label from a plain file, as described above.
* **Provenance is what Weir recorded.** A source edge means the tracker matched text or a destination from an earlier result; paraphrased or re-encoded data is invisible to it, and nothing is inferred beyond the recorded matches.
* **Single machine, no login, one database at a time**, polling once a second, no push. Each refresh re-reads every event into memory. Measured once on a development laptop with a synthetic database of about 20,000 events: the overview answered in about 0.15 s. Larger databases were not tried.
* **No policy editing**, and no authentication or multi-user features by design for this version.
* The interface adds no protection of its own; it can show a problem only after the gateway has recorded it.

## Authorship

Claude wrote most of the design, code and tests of this interface in an autonomous AI-assisted session; Ritesh set the goal, boundaries and acceptance criteria and owns the public claims. It has had no independent review.
