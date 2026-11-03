# Open items after the mobile verification work: plan and status (2026-11-03)

Everything left open or "for the user to decide" at the end of 2026-11-02 (`docs/MOBILEVERIFY_V3_PARITY.md`,
`docs/HEADER_FIELD_PARITY.md` 7.1, `docs/QMDB_COMPACTION_DESIGN.md`, the audit leftovers) is listed here with
the decision taken on 2026-11-03 (user: implement all of it), the work it needs, how it is verified, and its
status. Agents working an item update its row and the per-item notes; nothing is "done" without the
verification named in its row.

Conventions for every workstream: one git worktree under `/data/n42-build/wt-*` with its own
`CARGO_TARGET_DIR`; every cargo/go command through `/data/n42-build/audit-notes/scripts/quiet-run.sh`; devnet
and fleet runs claim the box through `/data/blockchain/gov5-work/box-gate.sh` (`BOX_ME=rust`) and never kill
another lane's processes; Conventional Commits in English, one logical step per commit, pushed after each; no
assistant names or trailers in commits or PR bodies; evidence under `/data/n42-build/audit-notes/devnet/<tag>`
or `audit-notes/ci/`; research notes in English under `docs/`.

## 1. Workstreams

| # | Item | Decision | Owner stream | Verification | Status |
| --- | --- | --- | --- | --- | --- |
| A1 | Mixed gated devnet round (3 Rust + gov5 member, `n42_devnet_mobileanchor.json`, transfer load) — the `mv4h` round the session loss killed | run it; before B lands it documents the divergence, after B lands it must reach the same hashes | A | 360 s round: Rust and gov5 heads equal, gov5 errors 0, device 20/20 | open |
| A2 | Chain-94 genesis run (`crates/chainspec/res/genesis/gov5/`, needs the `--fork-time` step; gate off until 2027-01-01) | run it | A | mixed fleet on chain 94 genesis: same hashes, `/mobileverify` device certifies through the sidecar | open |
| B1 | Glamsterdam execution parity: gov5 runs `transitionAmsterdam` on any `IsGlamsterdam` chain, N42-native included; the Rust node treats `glamsterdamTime` as header-only | implement: Amsterdam EVM rules from gov5's `glamsterdamTime` on native chains, header/payload rules unchanged (no EIP-7928 on native chains, as gov5) | B | rule-set audit doc; unit tests; gated devnet with transfers: packetd receipts root equals the header's (the mv4f oracle); mixed round A1 same hashes | open |
| B2 | Rule-set audit: gov5 `transitionAmsterdam` / `IntrinsicGas` / `eips_amsterdam.go` against revm 43 `SpecId::AMSTERDAM` (both: 8037, 8038, 7708, 7843, 7981, 7954, 2780; revm also 7976, 8246, 7825, 7928, 7778, 7873, 7907; gov5 also 8024) | write `docs/GLAMSTERDAM_EXECUTION_PARITY.md`; parity with gov5 is the rule, every difference named with its effect on N42 transaction shapes | B | the doc, reviewed | open |
| C1 | QMDB compaction stage 1 read view: 2-4% read cost (+1 DRAM miss per read) | implement the fix named in the design review: the index keeps locations (512 GiB per file) | C | crate tests; X22 bench pair level with main (two pairs, same box state) | open |
| C2 | QMDB compaction stages 3 and 4 (`docs/QMDB_COMPACTION_DESIGN.md`) | implement | C | crate tests; `fleet7.sh roll --kill` in file mode; X22 pair level; portable-snapshot export/import still verifies | open |
| D1 | GitHub repository renamed to `n42blockchain/N42-rs` | set the remote URL in the shared checkout and the worktrees (config only) | D | `git remote -v`, a fetch | done 2026-11-02 |
| D2 | Five gov5 pull requests (`design/header-field-parity`, `fix/unchanged-account-no-op`, `test/mobileverify-cross-client-fixtures`, `test/mobileverify-device-genesis`, `feat/mobileverify-packetd`); the drafted bodies were lost with the session scratchpad | re-draft the bodies into `/data/n42-build/audit-notes/pr/` (persistent); opening them needs `gh auth login`, which only the user can do | D | bodies reviewed; PRs opened once gh is logged in | open |
| D3 | `n42-init-snapshot` cannot start at a root-carrying head; the SSZ payload form carries no root (`HEADER_FIELD_PARITY.md` 7.1) | implement both | D | unit tests; init at a gated devnet head and follow | open |
| D4 | packetd polls every 250 ms | add an opt-in `newHeads` subscription over WebSocket, keep the poll as fallback | D | gov5 test; live run shows sub-50 ms packet latency | open |
| D5 | Pure-Rust packet producer (gov5's read log is positional in Go `IntraBlockState` order) | feasibility spike only: can revm's access order be made identical for the devnet's transaction shapes? verdict in `MOBILEVERIFY_V3_PARITY.md`; no implementation unless the order is provably identical | D | the written verdict with a byte comparison against a sidecar packet | open |
| D6 | Registry index may differ across nodes near epoch boundaries (gov5 has the same 45 s wall-clock timer) | design note: epoch commits keyed on block timestamp, proposed to gov5; no code until gov5 agrees | D | the note in `MOBILEVERIFY_V3_PARITY.md` | open |
| E1 | Commit b1a96f563's body names the `CLAUDE.md` file | not done: it is pushed `main` history and a rewrite was declined; the body contains no attribution | — | — | closed |
| E2 | gov5 v2 tombstone portable snapshot (a compacting node is a pruned node to today's verifier) | gov5 cross-client item; C writes the format proposal into the compaction design doc | C | the proposal section | open |

## 2. Order and box use

A1 runs first (one 360 s round, evidence of the divergence), B works in parallel and reruns A1's shape when its
change builds; A2 after A1. C's bench pairs are the only full-load runs in this plan (seven-node fleet, ~25 min
per pair); they claim the box through box-gate like every other lane and post a line at the top of
`/data/blockchain/wr-logs/HANDOFF-gov5-performance-5m-2026-10-15.md` before each pair. D has no box use beyond
builds.

## 3. Notes per item

(Agents append dated notes here: what was found, what changed, where the evidence is.)

- D1 (2026-11-02): `origin` in the shared checkout `/home/n42/src/n42/n42-rs` now points at
  `git@github.com:n42blockchain/N42-rs.git` (worktrees share that config; `git remote -v` and `git fetch origin`
  from `wt-small` succeed without the "repository moved" notice). `Cargo.toml` and `README.md` already named the
  new URL; no doc named the old one.
