# Getting started

Python ≥ 3.11. The library has no third-party runtime dependencies; the official MCP SDK is needed only for the interoperability tests and the SDK-built testbed servers.

```bash
git clone https://github.com/riteshmamidi0905-lab/mcp-weir.git && cd mcp-weir
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test,interop,dev]'
pytest -q                       # unit, property, gateway, stdio end-to-end, SDK-interop and evaluation-harness tests
```

## See it work (60 seconds, no model needed)

```bash
python -m weir_eval.demo        # a poisoned web page tells the agent to leak a secret; same agent, three ways
```

It runs one scripted attack (a fetched page contains an instruction to read a secret file and e-mail it) through (A) no gateway, (B) Weir with a careful human, (C) Weir with a human who approves everything, prints what happened to each call, and writes `trace-strict.html` and `trace-careless.html` (self-contained flow traces) to a temporary directory. With the local model running (`llama-server`, see `docs/evaluation.md`), `--live` drives it instead of the scripted agent, and `--replay demo/recorded/<name>.json` replays a recorded model session through the live gateway.

## Put it in front of an MCP server

1. Write a policy (see [`docs/policy.md`](policy.md); start from [`examples/policies/workspace.toml`](../examples/policies/workspace.toml)): declare the upstream servers, every tool you intend to allow, what each result is worth, and which arguments choose a destination or carry data.
2. `weir check policy.toml`: validate. An invalid policy refuses to start.
3. `weir lock --policy policy.toml --out tools.lock.json`: pin the tool definitions you reviewed.
4. Point the host at the gateway instead of at the servers. For a stdio host this is a normal MCP server entry:

```json
{ "mcpServers": { "workspace": { "command": "weir", "args": ["--db", "/var/lib/weir/weir.db", "run", "--policy", "/etc/weir/policy.toml", "--lock", "/etc/weir/tools.lock.json"] } } }
```

Tools are exposed as `<server>__<tool>`. Calls that need a human come back as an error result naming the rules and an approval id; approve with `weir --db … approvals show|approve|deny <id>` and the host retries the identical call. Everything is audited: `weir --db … audit verify`, `weir --db … report --session <id> --out trace.html`.

Tested against: the official MCP Python SDK client (2.3.0, both handshakes) and SDK-built servers. **Not** tested against any commercial MCP host.

## Reproduce the evaluation

```bash
python -m weir_eval.freeze verify                                     # the frozen files are intact
python -m weir_eval.run --suite smoke --out /tmp/smoke                # seconds; scripted agents only
python -m weir_eval.run --suite dev --out /tmp/dev --rugpull          # ~3 min, ~16,000 runs
python -m weir_eval.equivalence --suite dev --n 24 --arms A3,A1       # in-process harness vs the real stdio gateway
python -m weir_eval.bench                                             # overhead
python eval/make_tables.py eval/results/test-scripted/runs.jsonl.gz   # the tables in docs/evaluation.md
```

The **held-out** suite (seeds 100-109) was run once under the freeze recorded in `eval/FREEZE.json`; `weir_eval.run --suite test` refuses to run again without `--rerun` (which labels the result "not held out"). The real-model run needs `llama-server` with the exact model named in `eval/PROTOCOL.md`.
