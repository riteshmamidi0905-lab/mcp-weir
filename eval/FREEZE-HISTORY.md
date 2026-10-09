# Freeze history

Each freeze records the SHA-256 of every file that determines the held-out results (`eval/FREEZE.json` holds the current one; git tags keep the earlier ones).

| | root | tag | what ran under it |
|---|---|---|---|
| v1 | `0aeef30b283745c1e5042cee4acad3d51b152c706d1186d4e87b3e287e573ec3` | `eval-freeze-v1` | the **scripted** held-out suite (seeds 100-109, all arms and modes), the overhead benchmark, the held-out equivalence check |
| v1.1 | `20bf6d2083f977ac48f6d83b6f307c67c0f29bb811ef009bef0980608a2390a3` | `eval-freeze-v1.1` | the **real-model** held-out run (amendment A1 in `PROTOCOL.md`) |

Suite digests (generated scenario sets) are identical in both: dev `262422884221b225…`, test `5ff673c6ea1306d6…`.

## v1 → v1.1, file by file

| file | v1 | v1.1 | |
|---|---|---|---|
| `eval/PROTOCOL.md` | `e523d6d72042` | `f741f057d4bc` | CHANGED |
| `eval/run_realmodel.py` | `-` | `be7e5d85b099` | new |
| `examples/policies/workspace.toml` | `255639340487` | `255639340487` | identical |
| `src/mcp_weir/__init__.py` | `394fe7c4603a` | `394fe7c4603a` | identical |
| `src/mcp_weir/__main__.py` | `6d8b7d7846a8` | `6d8b7d7846a8` | identical |
| `src/mcp_weir/cli.py` | `bbb9dddcda2c` | `bbb9dddcda2c` | identical |
| `src/mcp_weir/decision.py` | `92ca8168007e` | `92ca8168007e` | identical |
| `src/mcp_weir/destinations.py` | `7837ff336254` | `7837ff336254` | identical |
| `src/mcp_weir/gateway.py` | `bd58a0430253` | `bd58a0430253` | identical |
| `src/mcp_weir/labels.py` | `dfd3793e6208` | `dfd3793e6208` | identical |
| `src/mcp_weir/pinning.py` | `6ad5aecd24cc` | `6ad5aecd24cc` | identical |
| `src/mcp_weir/policy.py` | `bf9220dd2e96` | `bf9220dd2e96` | identical |
| `src/mcp_weir/report.py` | `27675dda4e18` | `27675dda4e18` | identical |
| `src/mcp_weir/server.py` | `caf2878481be` | `caf2878481be` | identical |
| `src/mcp_weir/session.py` | `3b716aaebeb3` | `3b716aaebeb3` | identical |
| `src/mcp_weir/store.py` | `a1f56fc5ac9b` | `a1f56fc5ac9b` | identical |
| `src/mcp_weir/tracker.py` | `2d4e4e6f1b1b` | `2d4e4e6f1b1b` | identical |
| `src/mcp_weir/upstream.py` | `c2ac1a9491d7` | `c2ac1a9491d7` | identical |
| `src/weir_eval/agents.py` | `f0c4c63b9ae8` | `f0c4c63b9ae8` | identical |
| `src/weir_eval/analysis.py` | `5cd6aea53d9d` | `5cd6aea53d9d` | identical |
| `src/weir_eval/bench.py` | `10141a1805e7` | `10141a1805e7` | identical |
| `src/weir_eval/equivalence.py` | `42ec91ead7e0` | `42ec91ead7e0` | identical |
| `src/weir_eval/freeze.py` | `ad01172cec01` | `51e910655770` | CHANGED |
| `src/weir_eval/oracles.py` | `ba0fad0035b7` | `ba0fad0035b7` | identical |
| `src/weir_eval/run.py` | `11189f9c90c6` | `11189f9c90c6` | identical |
| `src/weir_eval/runner.py` | `4459703dffc1` | `4459703dffc1` | identical |
| `src/weir_eval/scenarios.py` | `4080482d80c6` | `4080482d80c6` | identical |
| `src/weir_eval/transforms.py` | `8ce7c4f06a14` | `8ce7c4f06a14` | identical |
| `src/weir_testbed/__init__.py` | `00ea312c2351` | `00ea312c2351` | identical |
| `src/weir_testbed/sdk_servers.py` | `2db7fbc405ec` | `2db7fbc405ec` | identical |
| `src/weir_testbed/servers.py` | `44b41e215537` | `44b41e215537` | identical |
| `src/weir_testbed/world.py` | `ac24b6e9a2f8` | `ac24b6e9a2f8` | identical |

Only the protocol text (the amendment), the new orchestrator `eval/run_realmodel.py` and the pattern list in `freeze.py` differ. The gateway, the policy, the scenario generator, the oracles, the runner, the agents and the analysis are byte-identical.
