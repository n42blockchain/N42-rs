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
| A1 | Mixed gated devnet round (3 Rust + gov5 member, `n42_devnet_mobileanchor.json`, transfer load) — the `mv4h` round the session loss killed | run it; before B lands it documents the divergence, after B lands it must reach the same hashes | A | 360 s round: Rust and gov5 heads equal, gov5 errors 0, device 20/20 | blocked: `mv4h2` (2026-11-03) fails at genesis, before execution: gov5 adds the BAL hash to a Glamsterdam-at-genesis header, reth does not (new item A3); rerun after A3 and B |
| A2 | Chain-94 genesis run (`crates/chainspec/res/genesis/gov5/`, needs the `--fork-time` step; gate off until 2027-01-01) | run it | A | mixed fleet on chain 94 genesis: same hashes, `/mobileverify` device certifies through the sidecar | done: `c94-a` (2026-11-03) 160/160 hashes, gov5 errors 0, device 20/20 |
| B1 | Glamsterdam execution parity: gov5 runs `transitionAmsterdam` on any `IsGlamsterdam` chain, N42-native included; the Rust node treats `glamsterdamTime` as header-only | implement: Amsterdam EVM rules from gov5's `glamsterdamTime` on native chains, header/payload rules unchanged (no EIP-7928 on native chains, as gov5) | B | rule-set audit doc; unit tests; gated devnet with transfers: packetd receipts root equals the header's (the mv4f oracle); mixed round A1 same hashes | implemented, unit + gov5-fixture tests pass; G1 (EIP-8282) decided 2026-11-03: gov5 skips 8282 on native chains (gov5 `fix/native-no-eip8282`); field oracle `mv4b2` (2026-11-03) pass: packetd built packets for 120/120 blocks (110 with transactions), device 20/20 skipped 0, 1,322 transfers 0 rejected; A1 rerun `mv4h3` pending |
| B2 | Rule-set audit: gov5 `transitionAmsterdam` / `IntrinsicGas` / `eips_amsterdam.go` against revm 43 `SpecId::AMSTERDAM` (both: 8037, 8038, 7708, 7843, 7981, 7954, 2780; revm also 7976, 8246, 7825, 7928, 7778, 7873, 7907; gov5 also 8024) | write `docs/GLAMSTERDAM_EXECUTION_PARITY.md`; parity with gov5 is the rule, every difference named with its effect on N42 transaction shapes | B | the doc, reviewed | done: `docs/GLAMSTERDAM_EXECUTION_PARITY.md`, reviewed and accepted 2026-11-03 |
| C1 | QMDB compaction stage 1 read view: 2-4% read cost (+1 DRAM miss per read) | implement the fix named in the design review: the index keeps locations (512 GiB per file) | C | crate tests; X22 bench pair level with main (two pairs, same box state) | open |
| C2 | QMDB compaction stages 3 and 4 (`docs/QMDB_COMPACTION_DESIGN.md`) | implement | C | crate tests; `fleet7.sh roll --kill` in file mode; X22 pair level; portable-snapshot export/import still verifies | open |
| D1 | GitHub repository renamed to `n42blockchain/N42-rs` | set the remote URL in the shared checkout and the worktrees (config only) | D | `git remote -v`, a fetch | done 2026-11-02 |
| D2 | Five gov5 pull requests (`design/header-field-parity`, `fix/unchanged-account-no-op`, `test/mobileverify-cross-client-fixtures`, `test/mobileverify-device-genesis`, `feat/mobileverify-packetd`); the drafted bodies were lost with the session scratchpad | re-draft the bodies into `/data/n42-build/audit-notes/pr/` (persistent); opening them needs `gh auth login`, which only the user can do | D | bodies reviewed; PRs opened once gh is logged in | bodies drafted 2026-11-03 (seven, `audit-notes/pr/`, `OPEN.sh`); waiting for review and `gh auth login` |
| D3 | `n42-init-snapshot` cannot start at a root-carrying head; the SSZ payload form carries no root (`HEADER_FIELD_PARITY.md` 7.1) | implement both | D | unit tests; init at a gated devnet head and follow | code + unit tests done (5370fc53a, 9b6b65d13); devnet init-and-follow pending |
| D4 | packetd polls every 250 ms | add an opt-in `newHeads` subscription over WebSocket, keep the poll as fallback | D | gov5 test; live run shows sub-50 ms packet latency | code + tests done (gov5 8fe815dc); live latency run pending |
| D5 | Pure-Rust packet producer (gov5's read log is positional in Go `IntraBlockState` order) | feasibility spike only: can revm's access order be made identical for the devnet's transaction shapes? verdict in `MOBILEVERIFY_V3_PARITY.md`; no implementation unless the order is provably identical | D | the written verdict with a byte comparison against a sidecar packet | done 2026-11-03: identical on 139/139 `mv3b` blocks after one prelude reorder; creating transfers, contracts and Amsterdam untested, so no implementation |
| D6 | Registry index may differ across nodes near epoch boundaries (gov5 has the same 45 s wall-clock timer) | design note: epoch commits keyed on block timestamp, proposed to gov5; no code until gov5 agrees | D | the note in `MOBILEVERIFY_V3_PARITY.md` | done 2026-11-02 (note written; gov5 agreement pending) |
| A3 | Genesis parity on a chain with `glamsterdamTime` at genesis: gov5's genesis header carries `blockAccessListHash` = keccak(rlp([])) (element 22, no slot), reth's ends at `requestsHash`; gov5 puts no BAL hash in native blocks above genesis | decide which side changes (Rust genesis builder adds the empty BAL hash, or gov5 drops it on native chains), then implement | A/B | both clients init `n42_devnet_mobileanchor.json` to one hash; A1 rerun | fixed in Rust (67ff48630, 2026-11-03): the genesis builder adds the empty BAL hash under gov5's `glamsterdamTime`; test pins `0x9e8628a6`; devnet and chain-94 hashes unchanged. Live check is the A1 rerun `mv4h3` |
| G2 | Chain 94's Rust genesis still carried `glamsterdamTime` 1798761600 after gov5 7529e2e9 removed it | regenerate from gov5 main | A | hash unchanged; `cargo test -p reth-chainspec` | done (36111540d): both gov5 files regenerated from gov5 main 39cff9ce, chain 94 loses the key, chain 95 byte-identical, hashes unchanged; test run by the merge gate |
| E1 | Commit b1a96f563's body names the `CLAUDE.md` file | not done: it is pushed `main` history and a rewrite was declined; the body contains no attribution | — | — | closed |
| E2 | gov5 v2 tombstone portable snapshot (a compacting node is a pruned node to today's verifier) | gov5 cross-client item; C writes the format proposal into the compaction design doc | C | the proposal section | open |
| F1 | Dependency refresh on reth v2.8.1 (user, 2026-11-03: upgrade the dependencies, reth included) | `cargo update` plus the majors that compile and test; reth's own pins stay (alloy 2.5, revm 43, alloy-evm 0.39, reth-core 0.8.2) | F | check, n42-testing, ported crates, clique/primitives tests, fixture SHAs unchanged | done (merged 37787830d): 41 moves, majors ethereum_hashing/serde_utils 0.8, hashbrown 0.17, lru 0.19, zerocopy 0.8, hex-literal 1; alloy-trie held at 0.9.8 in the lockfile (0.9.9 breaks reth-trie-common); `docs/DEPENDENCY_REFRESH_2026_11.md` |
| F2 | reth v2.9.0: upstream replaced revm with evm2 (`refactor!: replace revm with evm2 #25002`), so the bump is an EVM-layer port, not a re-sync | spike inventory first; the port only on the user's decision | F | `docs/RETH_2_9_0_UPGRADE.md`: inventory, mapping table, estimate | spike done: 303 lines in 38 N42 files name revm/alloy_evm, fast_transfer, parallel_transfer (`State`/`graft_bundles`) and the 0x50 TxEnv all move to evm2's handler model; estimate 27-41 person-days plus a fleet re-baseline; recommendation: stay on v2.8.1 — **user decision** |

## 2. Order and box use

A1 runs first (one 360 s round, evidence of the divergence), B works in parallel and reruns A1's shape when its
change builds; A2 after A1. C's bench pairs are the only full-load runs in this plan (seven-node fleet, ~25 min
per pair); they claim the box through box-gate like every other lane and post a line at the top of
`/data/blockchain/wr-logs/HANDOFF-gov5-performance-5m-2026-10-15.md` before each pair. D has no box use beyond
builds.

## 3. Notes per item

(Agents append dated notes here: what was found, what changed, where the evidence is.)

- 2026-11-03 (A): `scripts/devnet-mobileanchor.sh` (round driver), `scripts/devnet-header-roots.py`
  (slot/root check) and `scripts/gov5-local-genesis.py` (local genesis from a gov5 chain) are
  committed. A1 `mv4h2`: gov5 member never peers -- genesis `0x9e8628a6` (gov5) vs `0x112489f0`
  (reth), "wrong fork digest version"; the Rust three commit alone (89 commits, 58 timeouts),
  leader roots 111/111, packetd drops all 83 transaction blocks (Amsterdam execution, as mv4f),
  device 20/20 on empty blocks only (skipped 72). A2 `c94-a`: pass. Details and evidence paths:
  `docs/MOBILEVERIFY_V3_PARITY.md` "Gate verification"; evidence `audit-notes/devnet/{mv4h2,c94-a,c94-genesis}`.
- 2026-11-03 (A): A3 fixed on the Rust side (67ff48630): gov5's genesis for a Glamsterdam-at-genesis
  chain is reth's 21 elements plus the empty BAL hash, no slot (recomputed from gov5's hash; gov5's
  `genesis_block.go` writes a slot too but its header carries none -- matched by observation). G2 done
  (36111540d): chain 94's Rust genesis regenerated from gov5 main without `glamsterdamTime`, so neither
  client puts the slot/root tail on chain 94 until a date is scheduled; chain 95 unchanged. A1 rerun
  `mv4h3` waits for B's gov5 tree (EIP-8282 off on native chains) and B's binaries.
- D1 (2026-11-02): `origin` in the shared checkout `/home/n42/src/n42/n42-rs` now points at
  `git@github.com:n42blockchain/N42-rs.git` (worktrees share that config; `git remote -v` and `git fetch origin`
  from `wt-small` succeed without the "repository moved" notice). `Cargo.toml` and `README.md` already named the
  new URL; no doc named the old one.
- D6 (2026-11-02): proposal section "Proposal: registry epochs keyed on block timestamps" at the end of
  `docs/MOBILEVERIFY_V3_PARITY.md`: step 1 commits on the first committed block of each timestamp epoch
  (`mobileRegistryEpochSeconds`), step 2 carries the batch with that block so followers can check the root's
  value; gated by a chain-config time with a one-time re-base from the leader's registry snapshot. No code.
- D4 (2026-11-02): gov5 `feat/mobileverify-packetd` 8fe815dc (pushed): `-ws <url>` and
  `packetd.HeadSubscriber`; `Follower.Wake` ends an idle or back-off wait. `go test
  ./internal/streamverify/packetd/ -run 'HeadSubscriber|Follower'` passes (`audit-notes/ci/d4-go.out`; block
  built 0.6 ms after its notification with a one-minute poll). The live devnet measurement needs a box claim
  and is left for stream A's next devnet round (add `-ws ws://127.0.0.1:18546` to packetd, EL `--ws`).
### B1/B2 (2026-11-03, branch `feat/glamsterdam-execution`)

- Audit: `docs/GLAMSTERDAM_EXECUTION_PARITY.md`. Every Amsterdam rule gov5 applies on a native chain
  matches revm 43 for N42's shapes except: **G1** gov5 runs the EIP-8282 builder-request calls at every
  Amsterdam block on native chains and refuses the block when the contracts have no code -- no bundled
  native genesis (gated devnet, devnet, chain-94 copy) deploys them, so a gov5 member refuses every gated
  devnet block (decided 2026-11-03: gov5 gates 8282 off on native chains, `UsesEIP8282BuilderRequests`, branch
  `fix/native-no-eip8282`); **G2** gov5 `7529e2e9` removed `glamsterdamTime` from
  chain 94, the Rust copy `crates/chainspec/res/genesis/gov5/mainnet_qmdb_staggered.json` still has
  1798761600 (handed to stream A); G3 builder SLOTNUM (fixed); G4 total gas cap 2^32-1 (latent);
  G5 parallel paths (fixed); G6/G7 pre-existing or admission-only.
- Implementation: `reth_chainspec::qmdb::glamsterdam_execution_active_at` (native + glamsterdamTime);
  `N42EvmConfig` selects `SpecId::AMSTERDAM` in `evm_env`/`next_evm_env`/`evm_env_for_payload`; reth's
  `EthereumHardfork::Amsterdam` stays off (no BAL, header/payload unchanged); parallel build and follower
  parallel paths fall back to serial; deferred includability prices Amsterdam intrinsic.
- Tests: `cargo test -p n42-engine-types --lib glamsterdam_execution_tests` (4 pass) incl. gov5's fixture
  block (gov5 branch `test/glamsterdam-native-fixtures` 9907ea97, 11 transaction shapes: receipts, logs,
  gas 749,700 vs receipts 994,536, receipts root, post-state all equal); ungated devnet environment equal to
  `EvmEnv::for_eth_block` field for field.
- **DEVNET_BIN for A:** `/data/n42-build/glam-target/debug/n42` and
  `/data/n42-build/glam-target/debug/examples/h2_validator` (debug), commit noted in the report line below.

- D2 (2026-11-03): bodies in `/data/n42-build/audit-notes/pr/<branch with / as ->.md` (first line = title):
  the five of the plan plus stream B's `test/glamsterdam-native-fixtures` and `fix/native-no-eip8282`
  `OPEN.sh` opens them with `gh pr create --repo n42blockchain/N42-gov5 --base main`
  in dependency order (both mobileverify test branches before `feat/mobileverify-packetd`, which contains their
  commits; the fixtures before `fix/native-no-eip8282`). Every branch merges cleanly onto gov5 `main`
  (`git merge-tree`). No PR opened (gh not logged in).
- D3 (2026-11-03): `5370fc53a` the SSZ `ExecutionPayloadV4` carries `mobileRegistryRoot` as a trailing fixed
  field present only when set (the first offset tells the forms apart; root-less encoding unchanged), test
  `ssz_execution_payload_v4_carries_the_mobile_registry_root` plus the crate's 30 SSZ tests
  (`audit-notes/ci/d3-ssz.out`); `9b6b65d13` `n42-init-snapshot` decodes the head as `N42Header`, test
  `init_starts_at_a_head_that_carries_a_registry_root` runs init end to end over a root-carrying head
  (14/14, `audit-notes/ci/d3-init.out`). The devnet init-and-follow (a `LATE_SNAPSHOT` run on
  `n42_devnet_mobileanchor.json`) needs a box claim and is not run.
- D5 (2026-11-03): verdict in `docs/MOBILEVERIFY_V3_PARITY.md` "Pure-Rust producer: feasibility". On 139 `mv3b`
  sidecar packets (transfers, coinbase credit, Prague block-start calls), revm read exactly Go's set. The only
  order difference is reth's 2935-before-4788 prelude; once that is swapped, the revm-recorded log is
  byte-identical to the packet on 139/139 blocks. Creating-recipient transfers, contract calls, reverts and
  gated Amsterdam execution are untested, so the sidecar stays. Tools and output are in
  `/data/n42-build/audit-notes/d5-spike/`.
