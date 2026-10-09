# Writing a policy

Weir decides nothing on its own about what is sensitive: **you** declare it in a TOML file. A wrong label is a bypass, so the file is strict (unknown keys, bad values and dangling references refuse to start) and the example below is annotated with *why* each line is there. The complete example used by the tests, the demo and the evaluation is [`examples/policies/workspace.toml`](../examples/policies/workspace.toml).

```bash
weir check policy.toml                        # validate; prints the digest that sessions are bound to
weir lock --policy policy.toml --out tools.lock.json   # pin the tool definitions you reviewed
weir run  --policy policy.toml --lock tools.lock.json  # serve MCP over stdio
```

## 1 · Labels

* **Confidentiality** `public < internal < secret`; **integrity** `trusted < untrusted`. A label is the pair; join is the component-wise maximum.
* A tool's `result` says what its output is. `integrity = "untrusted"` means *an outsider can write it* (inbound mail, a fetched page, a file in a shared folder). `secret` means *must not leave the trust boundary even by accident* (keys, passphrases).
* The **session context label** is the join of everything Weir has returned to the host in this session. It only ever grows.

```toml
[tools.mail__read_message]
effect = "read"
result = { conf = "internal", integ = "untrusted" }     # mail bodies are attacker-controlled

[tools.files__read_file]
effect = "read"
result = { conf = "internal", integ = "trusted" }       # base label for every path ...
result_rules = [
  { arg = "path", glob = "/secrets/*", conf = "secret" },                  # ... raised for secrets (raising rules match ANY spelling of the path)
  { arg = "path", glob = "/public/*",  conf = "public", lower = true },    # ... lowered, but only for a canonical absolute path
  { arg = "path", glob = "/shared/*",  integ = "untrusted" },              # ... files outsiders can write
]
```

Path rules fail closed: `..`, `.`, repeated slashes (including the POSIX `//` special case), percent-encoding and relative spellings are tried, an argument that is missing or not a string counts as a match for a *raising* rule, and a *lowering* rule (`lower = true`) applies only to an absolute, canonical, un-encoded path. A path such as `/public/../secrets/key` therefore keeps the secret label.

## 2 · Effects, targets and content

| `effect` | Meaning |
|---|---|
| `read` | no side effect (but its result is labelled) |
| `write` | changes state inside the trust boundary (a file, a private note) |
| `egress` | information may leave the boundary: sending mail, fetching a URL (the request itself and its query string leave), publishing a shared page |

* `target = { arg = "email" \| "url" \| "path" \| "other" }` declares the arguments that **choose where**. E-mail and URL targets are parsed strictly and classified internal or external against `[policy].internal_domains` (exact domain or true subdomain; `corp.example.evil.net`, `corp-example.com`, `https://corp.example@evil.net/`, backslash and `%`-route tricks, extra `@`, whitespace and anything unparseable are **external**). An egress tool without a recipient/destination argument is external by definition (a shared page).
* `content = ["arg", …]` declares the arguments that **carry data**. Content arguments are matched against everything labelled that the session has seen. **Declare every argument that can carry data, including the `content` of a write tool**: arguments not declared as content are shown in clear in approvals and the audit log.

## 3 · Rules

Every rule is `off | approve | deny`; the verdict of a call is the most restrictive rule that fires. All hits are recorded.

| Rule | Fires when | Default |
|---|---|---|
| `R-UNKNOWN` | the tool is not declared | deny (always) |
| `R-PIN` | the tool definition differs from the lock file, or is not in it | deny (always) |
| `R-LIMIT` | arguments are not an object or exceed `max_arg_bytes` | deny (always) |
| `R-GATE` | `gate_egress` / `gate_write`: every egress / write call needs approval, whatever it contains | off |
| `R-DEST-UNTRUSTED` | a target argument (recipient, URL host and path, file path) appears in untrusted content, and the call goes outside or changes state | approve |
| `R-FLOW-CONF` | a content argument of an **external** call contains labelled data: secret → `flow_conf_secret`, internal → `flow_conf_internal` | deny / approve |
| `R-TRACKER-LIMIT` | external egress after a labelled result too large to track | approve |
| `R-TRIFECTA` | external egress while the session has seen secret **and** untrusted data | approve |
| `R-UNTRUSTED-READ` | a call whose result would be secret while the session has seen untrusted data | approve |
| `R-EGRESS-BUDGET` | more than `egress_budget_limit` external egress calls in one session | approve |

Any rule can be overridden for one tool: `rules = { dest_untrusted = "off" }`. The example turns `R-DEST-UNTRUSTED` off for `web__fetch_url`, because following a link in a page is what a web tool is for; the flow rules still apply to its URL.

The two tiers behave differently: **value** rules (`R-DEST-UNTRUSTED`, `R-FLOW-CONF`) cost little but can be beaten by transforming the data; **session** rules (`R-TRIFECTA`, `R-UNTRUSTED-READ`, `R-EGRESS-BUDGET`) do not care what the model did with the data, but restrict every session that mixed untrusted input with secrets. Set a session rule to `deny` if no human should be able to waive it.

## 4 · Tracker settings

```toml
[tracker]
k_secret = 8        # secret data is recognised from 8 consecutive letters/digits (after normalisation)
k_internal = 24     # internal data from 24; lower finds more, and matches ordinary words
min_unit = 5        # short secret values (PINs, passcodes) of at least 5 characters are matched whole
max_text = 65536    # per-result cap; larger labelled results make the session "blind" (R-TRACKER-LIMIT)
```

What the tracker recognises and what it does not is in [`docs/design/03-v1-spec.md`](design/03-v1-spec.md) §6 and measured in [`docs/evaluation.md`](evaluation.md).

## 5 · Approvals

A call that needs approval returns an error result naming the rules and an approval id (no labelled data). A human runs `weir approvals show <id>` (tool, clear arguments, content arguments only as length and digest, why, and which earlier results the flagged value came from), then `weir approvals approve <id>` or `deny`. The approval is bound to the exact call (session, tool, canonical argument hash), expires (`approval_ttl_seconds`), and is consumed by the first matching call. Because content is shown as a digest, **a human approving a send cannot read what is being sent**; that is a deliberate limit of keeping labelled data out of the database (see limitations).

## 6 · Pinning

`weir lock` records a SHA-256 of each declared tool's definition (name, description, input schema). With `--lock`, a tool whose definition differs, or that is not in the file, is withheld from the host and denied. Without a lock the first definitions seen in the process are the baseline, so a definition that *changes during a session* is also caught. This detects changes; it does not detect a tool description that was malicious when you reviewed it.
