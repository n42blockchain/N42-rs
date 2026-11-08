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
| A1 | Mixed gated devnet round (3 Rust + gov5 member, `n42_devnet_mobileanchor.json`, transfer load) — the `mv4h` round the session loss killed | run it; before B lands it documents the divergence, after B lands it must reach the same hashes | A | 360 s round: Rust and gov5 heads equal, gov5 errors 0, device 20/20 | done (`mv4h4b2`, 2026-11-05, clean full-length rerun: 159 blocks, 160/160 hashes equal, gov5 sealed 40 / errors 0, device 20/20, packetd 159 packets, Rust read-back 119/119 ok and the 40 gov5-led blocks carry zero-then-committed registry roots; earlier `mv4h4`, 2026-11-04: Rust 3984881bf, gov5 `integ/mvdev-slot` d4a00b01 = header-field-parity b2f7f04f + 8282 fix): no `slot number` errors; gov5 sealed 20 blocks and all committed with no TC; hashes equal (72/72 read back); gov5-leader registry roots 9 zero (before the first epoch) and 9 equal to the Rust members' committed root; Rust leaders 54/54; device 20/20. Round cut at 80 blocks by another lane's fleet7 runner killing every `n42 node`/`h2_validator` (`run-loop351.sh:199`). Earlier: `mv4h3-fix` fixed the block-1 root (system-caller leaf); full-length rerun `mv4h4b` VOID (stream F's devnet held the ports with no claim; driver now refuses occupied ports and bounds the device, a35a6bfb6) |
| A2 | Chain-94 genesis run (`crates/chainspec/res/genesis/gov5/`, needs the `--fork-time` step; gate off until 2027-01-01) | run it | A | mixed fleet on chain 94 genesis: same hashes, `/mobileverify` device certifies through the sidecar | done: `c94-a` (2026-11-03) 160/160 hashes, gov5 errors 0, device 20/20 |
| B1 | Glamsterdam execution parity: gov5 runs `transitionAmsterdam` on any `IsGlamsterdam` chain, N42-native included; the Rust node treats `glamsterdamTime` as header-only | implement: Amsterdam EVM rules from gov5's `glamsterdamTime` on native chains, header/payload rules unchanged (no EIP-7928 on native chains, as gov5) | B | rule-set audit doc; unit tests; gated devnet with transfers: packetd receipts root equals the header's (the mv4f oracle); mixed round A1 same hashes | implemented, unit + gov5-fixture tests pass; G1 (EIP-8282) decided 2026-11-03: gov5 skips 8282 on native chains (gov5 `fix/native-no-eip8282`); field oracle `mv4b2` (2026-11-03) pass: packetd built packets for 120/120 blocks (110 with transactions), device 20/20 skipped 0, 1,322 transfers 0 rejected; done: the A1 rerun is `mv4h4b2` (2026-11-05, main 0f3cb36e7): 159 blocks, 160/160 hashes equal Rust/gov5, gov5 errors 0, device 20/20 |
| B2 | Rule-set audit: gov5 `transitionAmsterdam` / `IntrinsicGas` / `eips_amsterdam.go` against revm 43 `SpecId::AMSTERDAM` (both: 8037, 8038, 7708, 7843, 7981, 7954, 2780; revm also 7976, 8246, 7825, 7928, 7778, 7873, 7907; gov5 also 8024) | write `docs/GLAMSTERDAM_EXECUTION_PARITY.md`; parity with gov5 is the rule, every difference named with its effect on N42 transaction shapes | B | the doc, reviewed | done: `docs/GLAMSTERDAM_EXECUTION_PARITY.md`, reviewed and accepted 2026-11-03 |
| C1 | QMDB compaction stage 1 read view: 2-4% read cost (+1 DRAM miss per read) | implement the fix named in the design review: the index keeps locations (512 GiB per file) | C | crate tests; X22 bench pair level with main (two pairs, same box state) | done on feat/qmdb-compact-stage34 (0bb2428ea): crate tests (ci/c34-full2.log); micro-bench at main's level, relocated keys too (ci/c34-bench.log); X22 pair C34 (stage fx) branch 4.827/5.000 vs main 4.980/4.893 M/s, mean -0.5% = level |
| C2 | QMDB compaction stages 3 and 4 (`docs/QMDB_COMPACTION_DESIGN.md`) | implement | C | crate tests; `fleet7.sh roll --kill` in file mode; X22 pair level; portable-snapshot export/import still verifies | done on feat/qmdb-compact-stage34 (2231965e0, 7e1b4a3d1): crate tests 125+96+32 pass (ci/c34-full2.log); roll --kill file mode with compaction on: 90 s, 20 s and a 1,260 s leg whose kills restarted on punched files, 0 fault lines (ci/rollkill.log); portable export/import verifies, a compacted node refuses v1 as designed; X22 compaction-off pair level (C1); one leg with N42_QMDB_COMPACT=1 (stage fy) 4.825 vs main 4.953 M/s (-2.6%) while rewriting 20,732 twigs (1.7 GB relocated, 1.6 GB punched) of a fresh chain's whole history |
| D1 | GitHub repository renamed to `n42blockchain/N42-rs` | set the remote URL in the shared checkout and the worktrees (config only) | D | `git remote -v`, a fetch | done 2026-11-02 |
| D2 | Five gov5 pull requests (`design/header-field-parity`, `fix/unchanged-account-no-op`, `test/mobileverify-cross-client-fixtures`, `test/mobileverify-device-genesis`, `feat/mobileverify-packetd`); the drafted bodies were lost with the session scratchpad | re-draft the bodies into `/data/n42-build/audit-notes/pr/` (persistent); opening them needs `gh auth login`, which only the user can do | D | bodies reviewed; PRs opened once gh is logged in | bodies drafted 2026-11-03 (seven, `audit-notes/pr/`, `OPEN.sh`); waiting for review and `gh auth login` |
| D3 | `n42-init-snapshot` cannot start at a root-carrying head; the SSZ payload form carries no root (`HEADER_FIELD_PARITY.md` 7.1) | implement both | D | unit tests; init at a gated devnet head and follow | done (5370fc53a, 9b6b65d13; devnet `d3-init` 2026-11-08: MobileAnchor head 53 (24-element header, raw and hex) exported by the Rust node, late member initialised there followed to 149, 97/97 hashes equal on main/late/gov5, late EL 0 errors; `HEADER_FIELD_PARITY.md` 7.1) |
| D4 | packetd polls every 250 ms | add an opt-in `newHeads` subscription over WebSocket, keep the poll as fallback | D | gov5 test; live run shows sub-50 ms packet latency | code + tests done (gov5 8fe815dc); live latency run pending |
| D5 | Pure-Rust packet producer (gov5's read log is positional in Go `IntraBlockState` order) | feasibility spike only: can revm's access order be made identical for the devnet's transaction shapes? verdict in `MOBILEVERIFY_V3_PARITY.md`; no implementation unless the order is provably identical | D | the written verdict with a byte comparison against a sidecar packet | done 2026-11-03: identical on 139/139 `mv3b` blocks after one prelude reorder; creating transfers, contracts and Amsterdam untested, so no implementation |
| D6 | Registry index may differ across nodes near epoch boundaries (gov5 has the same 45 s wall-clock timer) | design note: epoch commits keyed on block timestamp, proposed to gov5; no code until gov5 agrees | D | the note in `MOBILEVERIFY_V3_PARITY.md` | done 2026-11-02 (note written; gov5 agreement pending) |
| A3 | Genesis parity on a chain with `glamsterdamTime` at genesis: gov5's genesis header carries `blockAccessListHash` = keccak(rlp([])) (element 22, no slot), reth's ends at `requestsHash`; gov5 puts no BAL hash in native blocks above genesis | decide which side changes (Rust genesis builder adds the empty BAL hash, or gov5 drops it on native chains), then implement | A/B | both clients init `n42_devnet_mobileanchor.json` to one hash; A1 rerun | done: 67ff48630; verified live in `mv4h3` (both clients 0x9e8628a6, gov5 peers) |
| G2 | Chain 94's Rust genesis still carried `glamsterdamTime` 1798761600 after gov5 7529e2e9 removed it | regenerate from gov5 main | A | hash unchanged; `cargo test -p reth-chainspec` | done (36111540d): both gov5 files regenerated from gov5 main 39cff9ce, chain 94 loses the key, chain 95 byte-identical, hashes unchanged; test run by the merge gate |
| E1 | Commit b1a96f563's body names the `CLAUDE.md` file | not done: it is pushed `main` history and a rewrite was declined; the body contains no attribution | — | — | closed |
| E2 | gov5 v2 tombstone portable snapshot (a compacting node is a pruned node to today's verifier) | gov5 cross-client item; C writes the format proposal into the compaction design doc | C | the proposal section | proposal written (`docs/QMDB_COMPACTION_DESIGN.md` section 6); gov5 adoption open |
| F1 | Dependency refresh on reth v2.8.1 (user, 2026-11-03: upgrade the dependencies, reth included) | `cargo update` plus the majors that compile and test; reth's own pins stay (alloy 2.5, revm 43, alloy-evm 0.39, reth-core 0.8.2) | F | check, n42-testing, ported crates, clique/primitives tests, fixture SHAs unchanged | done (merged 37787830d): 41 moves, majors ethereum_hashing/serde_utils 0.8, hashbrown 0.17, lru 0.19, zerocopy 0.8, hex-literal 1; alloy-trie held at 0.9.8 in the lockfile (0.9.9 breaks reth-trie-common); `docs/DEPENDENCY_REFRESH_2026_11.md` |
| F2 | reth v2.9.0: upstream replaced revm with evm2 (`refactor!: replace revm with evm2 #25002`), so the bump is an EVM-layer port, not a re-sync | spike inventory first; the port only on the user's decision | F | `docs/RETH_2_9_0_UPGRADE.md`: inventory, mapping table, estimate | spike done: 303 lines in 38 N42 files name revm/alloy_evm, fast_transfer, parallel_transfer (`State`/`graft_bundles`) and the 0x50 TxEnv all move to evm2's handler model; estimate 27-41 person-days plus a fleet re-baseline; recommendation was to stay on v2.8.1; **user decided 2026-11-03: do the port, keep pushing** (F3-F6) |
| F3 | evm2 port stage 1: the shallow layer | vendored crates (chain-state, provider, storage-overlay, rpc-types-compat, ethereum-node), `n42-sharded-output` / `n42-deferred-reverts` / `n42-qmdb-reth` on `reth_trie_common::bundle_state`, `n42-header` drops `EthExecutorSpec`, `n42-clique`'s `CachedReads` serde; fast/parallel paths behind an off-by-default cargo feature so the tree builds | F (wt-reth29, `upgrade/reth-v2.9.0`) | `cargo check --workspace` reports the real error count, then reaches zero | done 2026-11-05: code gate on the stock evm2 build: `cargo check --workspace --keep-going --tests` clean, workspace tests 1207 passed (+ the gov5 Amsterdam parity fix 287f8d32c) and 554 passed after the main merge, clippy on the N42 crates clean, native release build (`audit-notes/ci/f3-check7.log`, `f4-tests1/2.log`, `f4-merge1.log`, `f4-clippy2.log`) |
| F4 | evm2 port stage 2: a correct node on the stock evm2 handler | `N42EvmConfig` + Amsterdam spec/gas params on `Version`, 0x50 `TxEnv` mapping + sender cache, payload/direct_build/output_shards/frame_scan, `bin/n42` follower import, `reth-rpc` fork on evm2-inspectors, ef-tests runner; fast transfer / parallel build / graft off | F | workspace tests, ported-crate fixture SHAs, devnet, gov5 mixed devnet (mv4h3 shape), `roll --kill` on QMDB incl. a kill before the first persistence (TreeConfig/EngineArgs defaults identical 2.8.1→2.9.0, re-diff anyway) | done 2026-11-05 on 43b07fbf8 (branch + main 1ccfcae30): field gate `audit-notes/ci/f4-gate.log`. All-Rust devnet 100/100 commits, 0 timeouts, EL err=0; gov5-member devnet 133 views, gov5 sealed 33, committed 166, hashes equal; mixed MobileAnchor `f4-mv` 160 blocks, 161/161 hashes, roots 120/120 + 40 gov5-led, device 20/20, 160 packets; `roll --kill` f4k90 / f4k20 all members recommit, 0 fault lines, seven nodes agree; engine defaults re-diffed, identical. `docs/RETH_2_9_0_UPGRADE.md` "F4 result" |
| F5 | evm2 port stage 3: the performance paths as evm2 handlers | `fast_transfer` as a tx handler with its revm-equivalence tests rebuilt; `parallel_transfer` / `graft_bundles` / `batch_state` / `warm_ahead` on reth's bundle state; each switched on only after an X22 A/B pair against v2.8.1 (box through box-gate, user told before every full-load run) | F | A/B pairs, `fleet7-repeat` spread, no stall | **done 2026-11-06**: A/B E16 at parity with v2.8.1 + X22 (branch 4.66 / 4.82M against control 4.91 / 4.68M TPS, sealed_at 37 / 37, par_exec 29 / 27); E9 had failed 7.3x; g1-g10 in the port log |
| F5a | design note | revm `State` paths mapped onto evm2 + reth bundle state; graft as cache half + bundle half | F | read by the coordinator | done 2026-11-05 (a0e9a252f) |
| F5b | shared layer | `parallel_common` (already EVM-free), `batch_state` on evm2 (change-stream accumulator), `graft_fold` (bundle half, defensive) | F | unit tests vs reth `BlockState`; fold = sequential execution; revert to parent | done 2026-11-05 (b7af797c8, b387237b7; `ci/f5-b-gate.log` 464 passed) |
| F5c | leader parallel builder | batches on evm2 + cache half + `fold_into`; `N42_PARALLEL_BUILD*`, `BUILD_BATCHES`, `BUILD_COLLECT_IN_PLACE`, `FREEZE_POOL`, `PLAN_AHEAD_BODY*` | F | parallel bundle == sequential evm2 bundle, same state root, mixed block; devnet on/off hashes; A/B after F5f | done 2026-11-05 (c11d2386e, e54021e55, dabac1694; `ci/f5-c-gate.log` 471 passed; devnet f5c-par/par2/ser 100/100 hashes on two ELs, every block with txs parallel, 0 fold refusals); A/B after F5f |
| F5d | follower parallel import + graft | `N42_FOLLOWER_PARALLEL`, `FOLLOWER_GRAFT*`, `FOLLOWER_PARTITION_*`, `FOLLOWER_BUILD_PATH`, `FOLLOWER_FREE_ASYNC`; keep_cache=false as today | F | import == stock import (bundle, receipts root, state root); devnet on/off; A/B after F5f | done 2026-11-05 (189953eb0, 56babfcc4, 2cdfc7a1b, 9a4200b10; `ci/f5-d-gate.log` 476 passed; devnet f5d-par/ser/gov5b equal hashes on two ELs (and gov5), every import with txs parallel, 0 refused, 0 fold refusals); keep_cache=false a measurement item; A/B after F5f |
| F5e | read layers | `warm_ahead`, `N42_READ_SET`, `BUILD_PREFETCH`, `BUILD_MLP` on evm2 `Database` | F | layer reads == plain reads | re-scoped by the coordinator 2026-11-05 to the X22 knobs: done 2026-11-05 (656e985b0, e91c15be9; `ci/f5-e-gate.log` 500 passed; PARTITION_AHEAD / FREE_ASYNC ported, BUILD_PATH / COLLECT_IN_PLACE subsumed, PARTITION_HASH / PHASE_TIMERS retired, read layers legacy until the A/B; devnet f5e-x22 28/28 hashes, 0 refused, no "not available" line; its 58 timeouts reproduce on v2.8.1 X22 binaries, f5e-x22-main2) |
| F5f | fast transfer | evm2 registry handler wrapping the stock one, gated `N42_FAST_TRANSFER`, used by the batches | F | per-tx equivalence with the stock handler | done 2026-11-05 (`fast_handler.rs`; batches use it unless `N42_BATCH_FAST_TRANSFER=0`; Prague/Osaka, Amsterdam an F6 leftover; `ci/f5-f-gate.log` 427 passed + 1 known qmdb-reth timing flake; devnet f5f-fast / f5f-stock 100/100 hashes on two ELs, 0 refused, fast hits 3,006 / 0); A/B next, needs the user's clearance |
| F5g1 | X22 leader gap: early seal on evm2 | the evm2 step sets `par_txs`/`par_groups`; with `N42_SEAL_AT_EXEC` the block seals after the batches, commit/fold/finish behind the proposal, cache `Only` the withdrawal recipients, `failed_after_seal` on any later refusal | F | gate + `evm2_step_bound` numbers; fx pair E10 (coordinator) | code bc280fba2, bench 2d687b583; `ci/f5g1-gate.log` 503 passed; natives in /data/n42-build/reth29-native (target-cpu=native); E10 read 1.06-1.08M TPS at 0.185 s (4.6x) |
| F5g2 | X22 leader gap: execution 83 -> ~30 ms | profile the evm2 batch per transaction (state opening, fast_handler journal, `convert`, dispatch, batch State, receipts) and fix the top items | F | before/after per item | measured: "exec" held the 190k-account batch merge; on the shard path (F5g3) bench exec 97.7 -> 29.4 ms (X22 index) / 15.5 ms (plain); one transfer ~1.16 us thread time, ~60% inside evm2 `transact` (fast handler saves ~30 ns; inherent API no gain) -- further cuts need a journal bypass (design call); bench chain moved to Prague (`ci/f5g2-split3.log`); E11 fleet par_exec 26 vs control 27: parity, no bypass (coordinator) |
| F5g3 | X22 leader gap: fold behind the seal / merge elided | the evm2 step files its batch bundles into the output shards (beneficiary + withdrawal recipients split off), freezes behind the seal, hands them to the ShardedParent / merge-elide path | F | numbers; E11 | code bcb193399: bench finish fold 94.1 -> 0.2 ms, freeze 4.2 ms behind the seal, shards == fold bundle checked; gate `ci/f5g3-gate.log` (+gate2) check/clippy 0, engine-types 278 passed; devnet f5g3-x22 hashes 40/40, sharded_total 16 + 7; natives rebuilt for E11 (bcb193399); E11: 2.10-2.14M TPS, merge 0, state_wait 13 vs 2, sharded_total 989 (every full block) |
| F5g4 | X22 leader gap: the seal (tx root, body, give-back) | items 3-5 after E11 (2.10-2.14M TPS, sealed_at 92 vs 37; tx_root 30 + sealed 30 + give_back 21): body made ahead with the plan (fallback on the build pool), plan root carried to the seal, puller stopped at the pull with its join kept before the seal | F | bench + E12 | code d66e939ea (body), 698091538 (root), 20df09470 (give-back); bench seal body 48.4 -> 3.1 ms (fallback), move on the plan path; gate `ci/f5g4-gate.log` all rc 0, engine-types 278 passed; natives for E12 |
| F5g5 | Tenure stall after a timed-out view (height 19 on the deferred devnet) | stale-build guard measured against the canonical head, which a build ahead had moved onto an uncertified block; committed floor (forkchoice safe + deferred depth) for the guard | F | unit tests + devnet round | code 020cb0de5; main 0f3cb36e7 has it too (f5g5-main: height 19, same refusal; F6 leftover); fix round f5g5-fix height 57, 57/57 hashes equal, 33 canonical replacements, 0 failed proposals |
| F5g6 | Plan body never taken on the fleet | `plan_ahead_body_wanted` gate was revm-only; opened on evm2; puller field made tri-state (no puller on the bulk path) | F | unit test + E13 fields | code cf58b16fc; bench `plan_body_prep_bound` hook 11.4 ms off the build vs inline keys 8.4 + partition 0.8 + body 4.7; fields for E13 |
| F5g7 | Child waits 11-14 ms on the parent's output | output published at seal+15-19 ms behind the serial receipt commit; receipts moved off the path | F | bench + E13 | code f7fa91058 (`N42_EVM2_RECEIPTS_LATE`, default on); bench commit + finish 12.1 -> 0.0 ms, receipts 5.3 ms off path; equivalence unit test + evm2_step_bound late leg; E13 to show state_wait |
| F5g8 | evm2 step: ~25 ms before the execution, 5-12 ms after it (E13 sealed_at 64 vs 35-37) | the prepared build missed on every block (the selection moves `made.cands` into the bulk vector, the step compared its length); take fixed; the pre-exec and post-exec spans get their own fields; fees on the build pool | F | unit test + bench + E14 | bench: keys 8.0 + partition 0.8 + body 4.5 ms now from the plan, fees 2.9 -> 0.3 ms |
| F5g9 | evm2 batches: par_exec 39 vs control 28 (E14, -12..-15% TPS) | per-batch fields (spans, reads/transact/commit/shard add, before/gather/merge, pool log); hypotheses a-d checked (same pool, same open, shard add 20 us a batch, same dispatch); gather + sort of 200k results on one thread replaced by in-batch slots | F | unit test + bench + E15 | bench gather 5.5 -> 0.08 ms, shard-path exec 20.1 -> 15.3 ms |
| F5g10 | evm2 per-transaction machinery: batch CPU +30% (E15, -6% TPS; transact proper ~224 ms, 1.1 us a transfer) | direct transfer path: qualifying transfers applied to the batch's accounts, the rest of a batch on evm2 over the same accounts (`N42_BATCH_DIRECT_TRANSFER`, default on) | F | equivalence tests (Prague, Osaka) + bench + devnet g10 (direct vs evm2) + E16 | bench batch CPU 388k -> 140k us, transact proper + commit 1.6 -> 0.37 us a transfer, shard-path exec 14.8 -> 6.3 ms |
| F6 | evm2 port stage 4: merge + leftovers | `upgrade/reth-v2.9.0` into main; witness recorder (`docs/patches/0001-*`) redone on evm2's `State` or parked with a note; `docs/RETH_2_9_0_UPGRADE.md` port log | F → Fable merge gate | full gate, docs | **done 2026-11-06**: F6a removed the `legacy-revm-paths` feature and 16k lines (567f49093), 15 knobs retired with a one-time warning, witness recorder parked (`docs/WITNESS_REPLAY_RUST_PLAN.md`); F6 field gate rc 0 on every step (devnet rust 100 blocks, gov5 mixed 133 blocks hash equal, MobileAnchor mixed 161/161 hashes, roll --kill 90 s / 20 s); merged into main 6703c576f. Leftovers with a status in the port log "F6 leftovers": Amsterdam parallel step (open, before 2027-01-01), f5g1-seal2 race (probably closed by g5, not re-run). Stream G (reth v2.10.0 + all dependencies, branch `upgrade/reth-v2.10.0` from 567f49093) continues from here |
| G1 | reth v2.10.0, stream G (branch `upgrade/reth-v2.10.0` from `upgrade/reth-v2.9.0` 567f49093; the row ids G1-G8 are this stream's, not the chain-94 genesis row G2 above): vendored sync | `scripts/reth-sync.py v2.9.0 v2.10.0`, N42 deltas kept, dependency repairs by hand | G | conflicts resolved, repairs rechecked | done 2026-11-06 (51546a6ad): 30 merged, 1 conflict (`chainspec/src/spec.rs`, ours); nippy-jar / transaction-pool unchanged upstream, renamed 2.10.0; evm2-inspectors repair rebased onto 592bf18c |
| G2 | v2.10.0: tag + evm2 bump, whole lockfile, majors | every `tag = "v2.9.0"`, evm2 rev `592bf18c`, `cargo update`, majors that compile mechanically | G | `cargo update --verbose` table in the port log | done (b3f3a0fd4, 4589db923): upstream's `DaniPopes/evm2` patch adopted (reth-core pins the old evm2); alloy-trie held at 0.9.8; criterion 0.5 -> 0.8 bumped; the rest held with reasons (`docs/RETH_2_10_0_UPGRADE.md` "Dependency refresh") |
| G3 | v2.10.0: cascade + code gates | fix until check / clippy / tests pass; fast handler and direct transfer unchanged | G | check --workspace --tests, clippy-n42, n42-testing / engine-types / qmdb-state / qmdb-reth / env / n42, ported fixtures | done (40f99113b: one callback signature, #28207); all rc=0 (`ci/g-*.log`) |
| G4 | v2.10.0: engine defaults | diff TreeConfig / EngineArgs / persistence defaults | G | table in the port log | done: unchanged 2.9.0 -> 2.10.0; QMDB overrides stand |
| G5 | v2.10.0: native binaries | `-C target-cpu=native` n42, h2_validator, tx_flood, h2_keygen, send_tx | G | build rc | done: `/data/n42-build/reth210-native/release` (`ci/g-natives.log`) |
| G6 | v2.10.0: field gate | `audit-notes/scripts/g-gate.sh`: rounds rust + gov5, mv, k90, k20 | G | as the F6 gate | done 2026-11-06 10:38:55Z, all rc=0 (`ci/g-gate.log`): gb-rust 100/100 commits, 0 timeouts, EL err=0; gb-gov5 133 views, gov5 sealed 33 / committed 166 / errors 0, block 133 hash equal; g-mv 160 blocks, 161/161 hashes, roots 120/120 + 40 gov5-led, device 20/20, 160 packets, gov5 errors 0; gk90 / gk20 every roll recommits, 0 EL error lines, seven nodes agree (119 / 118) |
| G7 | v2.10.0: A/B fleet7 pair against the v2.9.0 code | X22 pair | Fable | pair level | **done 2026-11-07, parity**: GA1 (11-06) GA1a 4.82M / control 4.84M / GA1b 4.77M, round stopped by the D2 gate (G8); with the G8 fix on both sides, GA2 4.92 / 4.89 / 4.95 / 4.88M and GA3 4.91 / 4.95 / 4.87 / 4.78M (v2.10.0 / main control, a and b legs; win1 tx/s), eight legs, no EL exit, every gate line clean (`ci/pairs-queue.log`, `loop351fx-GA{2,3}.launch.out`) |
| G8 | same-parent rebuild root mismatch (found by GA1b, not a reth change) | `QmdbForest::insert` adopted the pending application's undo by parent alone; a second build on the same parent between a build's root computation and its insert left the tip mislabelled, a child filed a root over the sibling's state, and the next move through the grandparent replayed it (`re-applying block X gave root <true>, expected <filed>`, EL exit under `N42_QMDB_CANONICAL_FATAL`); on main since 49ac08391 (2026-08-26) | Opus + Fable review | failing test before the fix, qmdb-state / qmdb-reth / engine-types / n42 tests, clippy | **done 2026-11-07**: `pending_root` recorded at compute, adoption only when parent and root match (44cdc0873 on the 2.10 branch, cherry-picked to main be647d52a with the test 84c9ba04a); `docs/RETH_2_10_0_UPGRADE.md` "The same-parent rebuild root mismatch" |

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
- 2026-11-03 (A): `mv4h3` (`audit-notes/devnet/mv4h3`, NOTES.md). Rust binaries from feat/mobileverify-v3
  6474989e0, gov5 member from `/data/n42-build/gov5-wt-mvdev8282` (8282 off on native chains). Genesis
  `0x9e8628a6` on both (A3 holds live). gov5 then refuses block 1, an empty Rust-led block: "state root
  mismatch at block 1: proposer fdde74e1, locally computed 19dfd6ad", stays at height 0 (113 error lines);
  the three Rust validators commit alone (89 commits). B1 holds against the sidecar oracle: packetd built
  all 90 packets, 68 of them transaction blocks, no receipts-root drop; device 20/20 with 0 skipped; header
  roots 89/89. Trace rounds `mv4h3-trace`/`mv4h3-trace2` (gov5 `N42_FINALIZE_TRACE=1`, Rust
  `n42.qmdb.changes=debug`, Rust state read back at block 1): both sides write the same four accounts and
  two slots with the same values (faucet +1 ETH; coinbase 0x7099 to 0x11111112…0de0b6b3a763ffff; 2935 slot 0
  = genesis hash; 4788 slot 0xb68 = 1738984984); nothing at the 8282 addresses, the system address or
  7002/7251. The state agrees; the QMDB root over it does not, which points at the commitment step
  (leaf encoding or order on an Amsterdam block), not at execution. Fix decision is the coordinator's.
- 2026-11-04 (A): the offline recompute named it. With the system caller `0xff…fe` added, the block-1 root over the
  mobileanchor genesis is `fdde74e1` (7 operations, the Rust proposer's root); without it, `19dfd6ad` (6, gov5's root).
  gov5 drops that leaf under `IsGlamsterdam` (`internal/blockhelp.go:94`: no value transfer from the system address).
  Fix 3984881bf gates the leaf on Prague and not Glamsterdam (`system_caller_leaf_at`; test
  `glamsterdam_blocks_write_no_system_caller_leaf`). Rerun `mv4h3-fix` (`audit-notes/devnet/mv4h3-fix`, NOTES.md,
  DEVNET_BIN mobile-target/debug from 3984881bf): heights 89/89, all hashes equal, gov5 votes on all 89 commits,
  device 20/20, packetd 90/90. New finding: gov5's 30 own-sealed blocks carry slot 0 and the Rust ELs refuse them
  (header profile wants slot = number), so those views end in a TC.
- 2026-11-04 (A): `mv4h4` with gov5 `integ/mvdev-slot` (d4a00b01, b2f7f04f cherry-picked onto 6a16934a, pushed to
  the gov5 remote): zero slot errors, all 20 gov5-sealed blocks committed with no TC, 72/72 hashes equal,
  gov5-leader roots 9 zero + 9 equal to the Rust registry root, Rust leaders 54/54, device 20/20
  (`audit-notes/devnet/mv4h4`). The round was cut at 80 blocks because the wt-compact fleet7 runner's leg
  cleanup (`kill -9` of every `n42 node` / `h2_validator`) ran while this lane held the box claim.
- 2026-11-04 (A): `mv4h4b` VOID. Stream F's f4-rust/f4-gov5 devnet (reth29-native, n42_devnet.json, no box
  claim) held 18545/30313/19000-19003 from 08:14:31Z, and our claim came at 08:16:35Z. Our EL failed to bind,
  and packetd, send_tx and the device followed F's node. packetd's drops of 85-89 are its Glamsterdam-scheduled
  re-execution of F's non-Glamsterdam blocks (plain 21k transfers, Rust-sealed), not a divergence. The device
  step had no timeout and held the claim about 18 h. Fix a35a6bfb6 adds a post-claim port check and `timeout` on
  the device.
