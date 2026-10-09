# Security policy

Weir is a **research prototype**. It has never been deployed, has not been independently reviewed, and must not be relied on to protect real data. Its limits are listed in [`docs/limitations.md`](docs/limitations.md) and what got past it in [`docs/red-team.md`](docs/red-team.md).

* **Found a way to bypass a rule, crash the gateway, or recover plaintext from its database?** Please open a GitHub issue (nothing in this repository is a real credential; the "secrets" in the evaluation are random strings generated per scenario). If you would rather not disclose publicly, say so in a minimal issue and a private channel will be arranged.
* **Found a defect in the evaluation** (an oracle that mis-scores, a leak the harness cannot see)? Same: an issue, with the scenario id from `eval/results/`. The held-out results are frozen on purpose; defects found after the freeze are recorded as amendments in `eval/PROTOCOL.md`, not silently corrected.
* There is no bug bounty and no support commitment.
