# reth v2.9.0 → v2.10.0

Dated 2026-11-06, branch `upgrade/reth-v2.10.0`, made from `upgrade/reth-v2.9.0` at 567f49093
(the whole revm → evm2 port, F3-F6a, `docs/RETH_2_9_0_UPGRADE.md`). Stream G of
`docs/PLAN_OPEN_ITEMS_2026_11.md`. Upstream v2.10.0 (`f5192ac7`, 2026-11-05) is 34 commits after
v2.9.0. Unlike 2.8.1 → 2.9.0 this is a re-sync, not a port: no EVM layer change beyond one
callback signature.

## Versions moved

| Crate | v2.9.0 | v2.10.0 |
|---|---|---|
| reth (git tag, 103 entries) | v2.9.0 (`c9a780f4`) | v2.10.0 (`f5192ac7`); rust-version stays 1.96 |
| evm2, evm2-inspectors, evm2-jit (git rev) | `f93318f1` | `592bf18c` (6 commits, see below) |
| reth-core crates (`[patch.crates-io]`) | rev `275ce4cf` | unchanged |
| alloy 2.5.0, alloy-primitives 1.7.3, inkwell | - | unchanged |
| new upstream workspace deps | - | `opentelemetry-proto` 0.32, `prost` 0.14 (reth-tracing-otlp's file exporter; not needed by N42 crates) |

Upstream also turned on a `[patch."https://github.com/alloy-rs/evm2"]` that points evm2 at its
pre-transfer URL (`DaniPopes/evm2`, same rev). That patch applies to reth's own workspace only;
this repo keeps its own evm2 patch table (the vendored evm2-inspectors repair) and resolves evm2
from `alloy-rs/evm2` at the same revision.

## Sync (`scripts/reth-sync.py v2.9.0 v2.10.0`)

30 files merged (17 fast-forward), nothing added or deleted, one conflicted file
(`ci/g-sync.log`):

| File | Resolution |
|---|---|
| `chainspec/src/spec.rs` (2 hunks) | ours: the import list keeps `n42_testnet_nodes`; `bootnodes()` keeps the N42 testnet branch and its local `NamedChain as C` (upstream moved the alias to module scope) |

Dependency repairs, checked by hand:

- `reth-nippy-jar`, `reth-transaction-pool`: upstream changed nothing under either crate between
  the tags (the upstream manifests hash the same), so the repairs were only renamed `-2.10.0`,
  their manifests moved to the new tag / evm2 rev, and `PROVENANCE.json` / `PATCHES.diff` updated.
- `evm2-inspectors-0.1.0` (the traceCall beneficiary-prestate repair): rebased onto `592bf18c`.
  Upstream changed only `src/tracing/mod.rs` (#752, below), which applied cleanly; the N42 patch
  in `src/tracing/debug.rs` is unchanged (`N42-PATCH.diff` regenerated, same body).

## The evm2 rev diff (`f93318f1` → `592bf18c`)

Six commits (`/data/n42-build/evm2-src/evm2`, a clone of `alloy-rs/evm2`):

| Commit | Change | Effect on N42 |
|---|---|---|
| 592bf18c (#840) | `TxStateChanges`: a borrowed view of one transaction's changes, from `ExecutedTx::changes()` and `PendingState::changes()`; `ExecutedTx` implements `StateChangeSource`. `PendingState::account_changes{,_for}` now delegate to it | additive; `account_changes()` on `ExecutedTx` / `PendingState`, which `batch_state`, `graft_fold`, `parallel_build` and `fast_handler`'s tests use, is unchanged in signature and order |
| 2d80db94, 3a814311, bf9900ab | JIT codegen (`block_analysis.rs`) | none: JIT is off in our build |
| da5e6ace (#752) | inspectors: out-of-gas step cost is the whole remaining gas (reentrancy sentry 0); `Interpreter::failed_charge` and its two fields removed | the vendored evm2-inspectors repair took the tracing change; no N42 code read `failed_charge` |
| 3ca5cafa (#835) | base precompile cache: lock-free append-only list instead of an `RwLock<HashMap>` | none in behaviour; one shared lock fewer on every EVM construction |

reth v2.10.0's one EVM-facing API change follows from #840: `c1d254e06` (#28207, breaking)
passes the transaction's `evm2::TxStateChanges<'_>` to the
`execute_transaction_with_commit_condition` callback as a second argument (`BlockExecutor` and
`BlockBuilder`). `N42BlockExecutor` (`engine-types/src/n42_evm.rs`) forwards the callback to
reth's executor and only its signature changed (40f99113b). No N42 caller passes a
commit-condition closure of its own.

The fast handler (`fast_handler.rs`), the direct transfer path (`direct_transfer.rs`), the evm2
step in `payload.rs`, `parallel_common`, the follower import, `batch_state` and the output shards
needed no change. Their equivalence tests pass unchanged: `fast_handler::tests::*` (Prague /
Osaka coverage, qualifying transfers equal the stock handler, everything else handed on) and
`parallel_build::tests::the_direct_path_*` (direct path equals evm2 on qualifying transfers and on
sender runs, hands everything else to evm2) in `ci/g-t-main.log`.

**The second evm2 copy.** The first `cargo check` after the bump failed in reth-trie-common:
`reth_primitives_traits::Account: From<&evm2::AccountInfo>` was not satisfied. reth-core at
`275ce4cf` (which v2.9.0 and v2.10.0 both patch in) depends on evm2 at `f93318f1`, so the lock held
evm2 twice and reth-primitives-traits implemented the conversion for the old copy. Upstream v2.10.0
added `[patch."https://github.com/alloy-rs/evm2"]` with `evm2` / `evm2-inspectors` / `evm2-jit`
from `https://github.com/DaniPopes/evm2` at `592bf18c` for exactly this (the pre-transfer URL
redirects to alloy-rs/evm2; Cargo refuses a patch from the same source). This repo now carries the
same patch for `evm2` and `evm2-jit`; `evm2-inspectors` stays on the vendored repair. The lock holds
one evm2 (10 packages, all `DaniPopes/evm2?rev=592bf18c`).

## Dependency refresh

`cargo update` (whole lockfile, `ci/g-update.log`) after the tag and rev bump moved, besides reth
and evm2: alloy-trie 0.9.8 → 0.9.9 (pinned back, below), bincode_reloaded 3.1.26 → 3.1.29,
generator 0.8.11 → 0.8.12, mime 0.3.17 → 0.3.18, pest_stack_guard 1.0.0 → 1.0.1, psm 0.1.24 →
0.1.32, toml_edit 0.25.17 → 0.25.18, toml_writer 1.1.3 → 1.2.0, winnow 1.0.4 → 1.0.5; added
ar_archive_writer 0.5.3 and the windows-* 0.100 set (build tooling of psm; not built on Linux).

`cargo update --verbose` then lists 41 crates behind their latest major (`ci/g-check1.log`).
Most are transitive. The direct dependencies among them, by the rules of
`docs/DEPENDENCY_REFRESH_2026_11.md` (a major only for an N42-only dependency that reth does not
pin, and only if it compiles and tests pass; nothing whose wire or fixture behaviour could change
without a fixture run):

| Dependency | Used by | From | To / available | Status |
|---|---|---|---|---|
| `criterion` | `n42-clique`, `n42-primitives` (benches) | 0.5 | 0.8 | **bumped** (4589db923): `criterion::black_box` → `std::hint::black_box` |
| `alloy-trie` (lock) | reth-trie-common | 0.9.8 | 0.9.9 | left at 0.9.8: 0.9.9 adds a public `HashBuilder` field that reth's struct literal does not set; upstream v2.10.0's lock keeps 0.9.8 |
| `jni` | `mobile-sdk` | 0.21 | 0.22 | left at 0.21: every JNI entry point is rewritten for `EnvUnowned`, and the Android path cannot be exercised here |
| `rand_core` | `n42-tx-types` | 0.6 | 0.10 | left at 0.6: must match `merlin` 3's transcript RNG (0x50 batch verification) |
| `k256`, `sha2`, `secp256k1` | several (incl. `merkle_db_rs` sha2 0.10.9) | 0.13 / 0.10 / 0.30 | 0.14 / 0.11 / 0.33 | left: alloy's and reth's RustCrypto / secp generation; a bump splits the key types |
| `jsonwebtoken`, `base64` | `alloy-rpc-types-engine` fork, `reth-rpc` | 10 / 0.22 | 11 / 0.23 | left: the fork tracks alloy 2.5.0, which pins them |
| `enr` | vendored net crates | 0.13 | 0.14 | left: reth v2.10.0's workspace pins 0.13; discovery wire types |
| `itertools`, `strum`, `rand` 0.9 / 0.8, `parking_lot`, `sysinfo`, `tikv-jemallocator`, `codspeed-criterion-compat`, `similar-asserts`, `toml`, `roaring`, `rocksdb`, `lz4_flex`, `proptest`, `generic-array` | workspace (reth-pinned) | reth v2.10.0's versions | newer majors | left: pinned by reth v2.10.0's `[workspace.dependencies]` at the same versions; they move with reth |
| `zstd` 0.13.4 (lock) | transitive | 0.13 | 0.14.3 | left: the workspace is on 0.14.3; 0.13 comes in through a dependency |
| libp2p / gossipsub, ssz, blst, snappy, rlp | h2-net, h2-wire, primitives | - | - | nothing newer than the semver range was reported; not touched |

`[workspace.dependencies]` against upstream v2.10.0: every shared entry matches except where this
repo is ahead or N42-specific (`roaring` 0.11.4 vs 0.11.3, `hickory-resolver` 0.26.3 vs 0.26.1,
`test-fuzz` 8.1.1 vs 7, `bincode` → `n42-legacy-codec`). Upstream's new `opentelemetry-proto` /
`prost` entries serve reth-tracing-otlp's new file exporter; no N42 crate needs them.

## Engine defaults (the reth-bump rule)

| File (upstream) | v2.9.0 → v2.10.0 |
|---|---|
| `crates/engine/primitives/src/config.rs` (`TreeConfig`) | unchanged |
| `crates/node/core/src/args/engine.rs` (`EngineArgs`) | unchanged |
| `crates/node/core/src/args/*` | only `trace.rs`: `--tracing-otlp` accepts a `file:///` endpoint (doc comment); no default moved |
| `crates/engine/tree/src/persistence.rs` | test-only import moves |
| `crates/engine/tree/src/tree/**` | span parents borrowed (`parent: &parent_span`), imports moved to module scope, an `Option` combinator; no default or threshold changed |

So the defaults stand as recorded for v2.9.0: `persistence_threshold` 50,
`memory_block_buffer_target` 5, `num_state_masking_blocks` 30, `backfill_run_threshold`
`EPOCH_SLOTS`, `multiproof_task_chunk_size` 5, `reserved_cpu_cores` 1, `sparse_trie_prune_depth`
4, `state_root_task_timeout` 1 s; the node's QMDB overrides (`qmdb_tree_config`: masking 0,
threshold 8, buffer 6) apply unchanged. No new default touches persistence or memory buffering;
the field gate's `roll --kill` k90 / k20 runs are the standing SIGKILL-recovery check.

## Code gate

All through `audit-notes/scripts/quiet-run.sh`, target dir `/data/n42-build/reth210-target`
(seeded from the v2.9.0 one), head 4589db923:

| Step | Log | rc | Result |
|---|---|---|---|
| `cargo check --workspace --tests` | `ci/g-check.log` | 0 | clean (vendored-repair warnings only) |
| `cargo check -p n42-clique -p n42-primitives --benches` | `ci/g-bench.log` | 0 | criterion 0.8 benches build |
| `scripts/clippy-n42.sh` (`-D warnings`) | `ci/g-clippy.log` | 0 | clean |
| `cargo test -p n42-testing` | `ci/g-t-testing.log` | 0 | 28 passed, 1 ignored |
| `cargo test -p n42-engine-types -p n42-qmdb-state -p n42-env -p n42` | `ci/g-t-main.log` | 0 | 525 passed, 16 ignored |
| `cargo test -p n42-qmdb-reth` | `ci/g-t-qmdb-reth.log` | 0 | 132 passed, 5 ignored (the load-flaky lease test passed in the full run) |
| ported crates (bmt-core, twig-core, h2-primitives, h2-wire, h2-consensus, mobile-verify, h2-net, h2-execution) | `ci/g-t-ported.log` | 0 | 766 passed, 3 ignored (byte-exact fixtures included) |
| `cargo test -p n42-clique -p n42-primitives` | `ci/g-t-clique.log` | 0 | 291 passed |
| native release binaries (`n42`, `h2_validator`, `tx_flood`, `h2_keygen`, `send_tx`), `-C target-cpu=native` | `ci/g-natives.log` | 0 | `/data/n42-build/reth210-native/release` |

## Gate results (G6, 2026-11-06)

`audit-notes/scripts/g-gate.sh` (a copy of `f4-gate.sh` with `TREE` / `BIN` parametrised and
`FLOCKER=$LOCK` on the mv step), log `audit-notes/ci/g-gate.log`, 09:53:06Z to 10:38:55Z. It
ran on the native binaries from 4589db923 in `/data/n42-build/reth210-native/release`. The tree
head the rounds logged is 23741e099, which adds only docs to 4589db923. All four steps exited 0.

- **All-Rust devnet** (`gb-rust`, four members, 300 s, `devnet/gb-rust.out`), rc=0.
  - Every validator: commits=100, views=100, timeouts=0.
  - The execution layer: newPayload=400, qmdb_roots=100, err=0, height 100.
- **Devnet with a gov5 member** (`gb-gov5`, three Rust members plus gov5, 300 s,
  `devnet/gb-gov5.out`), rc=0.
  - 133 views, and the Rust members show commits=133.
  - v0's timeouts=2 is the view-1 start-up TC, logged twice, as in F4 and F6.
  - gov5: sealed=33, committed=166, errors=0, height 133.
  - The block 133 hash is the same on both clients: `0x5970ba61…faa1480`. EL err=0.
- **Mixed gated MobileAnchor round** (`g-mv`, `devnet-mobileanchor.sh g-mv --gov5 --txload`,
  360 s, `devnet/g-mv.out`, `devnet/g-mv/`), rc=0.
  - 160 blocks, both heights 160. All 161 hashes are the same, with no first difference
    (block 160 `0x589ce79b…ffd76cf6`). The genesis hash is the same on both clients.
  - gov5: sealed=40, committed=200, errors=0, warns=0.
  - Leader-root check: the Rust leaders' roots are ok=120, mismatch=0. Of the 40 gov5-led
    blocks, 4 carry the zero root and 36 the committed root.
  - Device: 2 devices, 20/20 certified, 0 failures.
  - packetd: 160 packets. Its one error line is "block 0 has no parent state", about the genesis.
  - send_tx: 1322 sent, with 2 error lines, the same count as `f4-mv` and `f6-mv`.
  - This is the same shape as F4's and F6's mv rounds.
- **`roll --kill` on the seven-node fleet7 shape** (`rollkill-check.sh`, outputs
  `ci/gk{90,20}-rollkill-*.out`). The first kill came at 90 s, and in the second run at 20 s,
  before the first persistence. Both runs exited 0.
  - In both runs, every one of rolls 1, 2 and 3 with `--kill` committed again, with 0 error lines
    in el.log. Each restarted node logged "restored the QMDB forest".
  - k20's roll 1 shows "commits since restart 1" at height 7, so the 20 s run's first kill
    restarted onto a chain at height 7.
  - The 360 s watch read 118 blocks (0.328 per s) in k90 and 117 (0.325 per s) in k20, against
    the 0.333 target.
  - At the end all seven nodes agree: on height 119 in k90 (`0xf11ab7f0…`) and on 118 in k20
    (`0xef67711b…`).

The v2.10.0 port changes nothing visible in the field: blocks, QMDB roots, the MobileAnchor
registry roots and the hashes are identical to gov5's across all three shapes, and SIGKILL
recovery on QMDB holds, including a kill before the first persistence.

## G7 A/B pairs GA1–GA3 (2026-11-06/07)

**Status: done, parity** (GA2/GA3 below). GA1 first.

**GA1 (2026-11-06 10:41–11:03Z).** The coordinator ran an X22 pair on the fleet7 bench. The legs were GA1a
(v2.10.0), GA10 (control: main's code, `reth29-native`) and GA1b (v2.10.0). Win1 read 4.82M TPS
on GA1a, 4.84M on GA10 and 4.77M on GA1b, so v2.10.0 is at parity with the control.

The D2 gate stopped the round on GA1b:

- After two empty builds of height 8191 on the same parent within 35 ms, the shared execution
  layer exited at block 8191.
- It logged "QMDB head cannot follow the canonical chain … re-applying block 0xbc75fd36… gave
  root 0x39850779…, expected 0x3c3a1440…".
- Evidence: `/data/blockchain/rust-fleet7-bench/node0/el.log` lines 107418–107439 and
  `bench-loop351D2S12P30T64X11T16GA1bMEMF/verify.json`.

The root cause is the forest defect recorded in the next section; it is not a reth or evm2
change and main had it too.

**GA2 and GA3 (2026-11-07 02:40–03:33Z).** Both sides rebuilt with the fix (v2.10.0 from
`25b986f9f` into `reth210-native`; the control from main `3bfb5b002`, which carries the same
two forest commits, into `wt-docs/target/native`). Each round ran four legs, v2.10.0 and control
alternating, win1 tx/s:

| round | v2.10.0 a | control | v2.10.0 b | control b |
| --- | --- | --- | --- | --- |
| GA2 | 4,920,000 | 4,893,333 | 4,946,667 | 4,876,733 |
| GA3 | 4,906,667 | 4,953,333 | 4,870,417 | 4,779,933 |

Eight legs, every block full, no execution-layer exit, and every gate line clean
(`invalid_blocks=0`, `incomplete=0`, `gas_mismatch=0`, `direct_imports_failed=0`,
`proposals_given_up=0`; `ci/pairs-queue.log`, `wt-main/target/fleet-runs/loop351fx-GA{2,3}.launch.out`).
Every difference is inside the 10% that single rounds cannot resolve, and the v2.10.0 legs
average slightly above the controls, so v2.10.0 is at parity with main. Merge gate passed.

## The same-parent rebuild root mismatch (GA1b, 2026-11-06)

**Evidence.** Leg GA1b (seven validators on one execution layer, X22, the
flood just ended) exited at 11:02:58.325Z with `QMDB head cannot follow the
canonical chain ... re-applying block 0xbc75fd36... (8191) gave root
0x39850779..., expected 0x3c3a1440...` (`rust-fleet7-bench/node0/el.log`
lines 107410-107439). 8191 is a tenure handover: node0 had chained block A
of 8191 on 0xe11459... (8190) for view 8192 (`chained=true`, .271715), node1
led view 8192 and had block B built on the same parent (`chained=false`,
.305737, after its FCU payload job on that parent was given up). Every 1024th
block in that log is the same shape (1023, 2047, ..., 7167 built twice on one
parent, the last four empty) and passed; the forest logs nothing per root, so
the exact interleaving at 8190/8191 is not in the log.

**Mechanism.** The payload builder computes a block's QMDB root
(`QmdbNodeState::compute_operations`, which leaves the block applied on the
tree as the forest's *pending* work) and files it (`insert`) in two separate
holds of the forest's lock. `QmdbForest::insert` adopted the pending
application as the filed block's own whenever the pending block's parent was
the filed block's parent. A second build of the same height computed between
the first's compute and its insert is pending on that same parent, so the
first block's record took the *second* block's undo and the forest's tip was
set to the first block while the tree held the second's state. Nothing
fails at that moment: reverts by that undo still restore the parent. But a
root computed on the mislabelled block -- its child -- is computed on the
sibling's state and filed; when a later move goes through the parent's parent
(a branch switch, a build on a sibling), the child is replayed onto the true
state and lands on another root: exactly `re-applying block X gave root
<true>, expected <filed>`. In GA1b, X is 8191, so the mislabelled block was
its parent 8190 (each block is requested twice on its parent, by the chain
and by the FCU job), and the move was the handover's sibling builds of 8191.
Not refuted: that the mislabel was at 8191 itself with a sibling of 8190;
both are this same defect. The hypotheses of a builder reading A's state,
the F5g8 prepared-build take, and evm2/reth #28207 are not needed: the
forest test below reproduces the error with no builder at all.

**Fix** (`44cdc0873`, `crates/n42/qmdb-state/src/forest.rs`). The forest
keeps the root the pending application gave (`pending_root`, set wherever
`pending` is) and `insert` adopts the pending work only when that root is the
filed block's root (equal roots are equal states, so adopting is then exact).
Otherwise the pending block is reverted and the block filed unapplied, as was
already done for a pending block on another parent; the next move replays it.
A single build per parent is unchanged (its root always matches).

**Test.** `forest::tests::a_sibling_computed_between_a_build_and_its_insert_is_not_adopted`
(`6d770907c`): compute P and P' on block 1, insert P, then P'; compute P's
child; move to P' and back. Before the fix the child's root is P' based and
the move fails with `Replay { block: child, expected: <filed>, got: <true> }`;
after it, both are the reference roots. Suite and clippy:
`/data/n42-build/audit-notes/ci/fix8191-test.log` (rc 0), `fix8191-clippy2.log` (rc 0; `fix8191-clippy.log` rc 101 was a doc-markdown lint on the new comment, fixed).

**Main.** The adoption rule dates from `49ac08391` (2026-08-26, the forest's
undo records), so v2.8.1, v2.9.0 and v2.10.0 all carry it; it is not a reth
or evm2 regression. The test applied to main 1f173b278 (which contains the
v2.9.0 merge 6703c576f) fails the same way. The fix should go to main as is.

### Second occurrence (loop351, 2026-11-09): not explained yet, instrumented

**Evidence.** X22 leg `loop351D2S12P30T64X11T16KA10MEMF` (natives from main
0ed56c1da, which carries the G8 fix be647d52a) exited at 01:34:37.634876Z
with `QMDB head cannot follow the canonical chain ... re-applying block
0x236ad708... (7167) gave root 0x15bcc69b..., expected 0x79e7885f...`
(`rust-fleet7-bench/bench-loop351D2S12P30T64X11T16KA10MEMF/node0-el.log`
line 95131, `node0-v.log` around line 122600). As in GA1b it is an empty-block
(txs=0, after the flood) tenure handover: node6 led through 7166 (0x44bf...),
node0 leads view 7168. 7167 was executed three times on 0x44bf: **E1** at
.583 is node6's chain build (`chained=true`, node6's beneficiary), **E2** at
.584 is node0's FCU payload job (`build ahead requested` .553654, `given up
resolved its payload job` .587281; its root job still files), **E3** at .614
is node0's first build of the tenure (`chained=false`), which became
0x236a. Node0's chain started 7168 on 0x236a at .617340; the forkchoice to
7167 at .633066 had to move the tree back to 0x236a (so the tip was off its
path, most likely moved by E2's late root job) and the replay failed. Every
block in the leg is built twice on its parent (chain and FCU job), and 6143
had the same three-build shape and passed.

**Why be647d52a does not cover it.** That fix stops `insert` adopting a
pending sibling with another root. Every forest path in this window
(insert's early return and adoption, rename with its no-op and alternate
fallback, `return_tree`'s re-parenting, `move_to`, the in-place and
releasing canonical moves, trim bounds, deferred renames and aliases, the
leased compute in `QmdbNodeState::with_leased_root`, the payload builder's
`publish`) moves a record's parent, operations and root as one unit, and
adoption on equal roots is exact. A replay mismatch therefore needs either
the tree labelled 0x44bf not to hold 0x44bf's state, or an apply that is
not a pure function of state and operations; neither is what be647d52a
addressed.

**What was excluded.** Randomised forest runs against a reference forest
(debug builds, so the upper-tree cache's debug asserts are on), all passing:
2,000 seeds of same-parent sibling builds (locked and leased roots, late and
deferred inserts, renames to sealed hashes, canonical moves) and 150 seeds in
entry-file mode with retain depth 3 and twig trimming (`ci/m-fuzz2.log`); the
same under `N42_QMDB_PARALLEL_APPLY=1 N42_ROOT_UPPER_DIRTY=1`
(`ci/m-fuzz3.log`); six seeds of 2,500 heights of empty system-contract
blocks with deletions, seven beneficiaries, 1-3 builds per height and the
child built ahead before canonical (`ci/m-fuzz4.log`). Reading excluded the
QmdbOps identity guard of precomputed leaf hashes, the upper-tree stale
flag, `apply_undo`'s index and revival paths, the key index's backward-shift
delete, the entry file's cut, offsets truncation and the undo-list and twig
pools. Not excluded: concurrency between `QmdbNodeState` lock holds beyond
the sequence below, precomputed leaf hashes from `N42_ROOT_OPS_BEFORE_GATE`
and ops-ahead merges, and real execution output.

**Test.** `node_state::more_tests::a_handover_with_a_late_given_up_payload_job_replays_to_the_sealed_root`
(d2eccf30e) replays the log's interleaving on one node state with empty
system-contract blocks built through `sorted_operations_from_execution`:
E1 filed, E2's root computed (before E3 or after C) and filed late, E3 filed
and renamed to S, the chain-ahead child C on S, E2's late insert, then the
forkchoice to S, which must stand at S's header root, and the next build on
S must land on C's root. 64 variants (E2 sharing E3's built hash or not, C
filed or not, leased or locked roots, heap or entry file, canonical head
deferred or not): **all pass** (`ci/m-handover-test.log`). The leading
hypothesis, that E2's late root job alone mislabels the tree, is refuted at
this level.

**Instrumentation** (32faaac44, `crates/n42/qmdb-state/src/forest.rs`), so
the next recurrence names its interleaving. On target `n42.qmdb`: every
`insert` with its outcome (early return with the held and offered roots and
the pending block, adopted, or filed unapplied with the reverted pending
block's parent and root), every `rename` (moved, already renamed, same-root
no-op with `from` kept, refused), every tree move (from, target, common
ancestor, pending block, reverted and replayed counts). These per-call lines
are logged for blocks of at most 64 leaf operations -- an empty block's
shape, where both occurrences were, and never a loaded block -- or for every
block under `N42_QMDB_FOREST_TRACE=1`: a size gate rather than an env-only
gate because the failure has only been seen on bench legs whose launch line
we do not want to change, and the forest cannot know cheaply that a
handover is in progress, whereas an empty block is visible in the record it
already holds. Under load each event pays one length compare. Always on:
after a move reverts anything (the pending block or records down to the
common ancestor), the tree's root is compared with the root filed for the
block the forest says it stands at, and a difference is an ERROR naming the
block and both roots (`QMDB tree root after ... is not the root filed for
the block it stands at (mislabelled tree)`): a mislabelled tree is reported
at the move that exposes it, not at the later replay. Its cost is one root
read per reverting move (a scan of the twig roots' leaf level, rehashing
only what changed); moves that revert nothing pay nothing.

Gates: `cargo check --workspace --tests` rc 0 (`ci/m-check.log`),
`scripts/clippy-n42.sh` rc 0 (`ci/m-clippy-n42.log`), qmdb-state / qmdb-reth /
engine-types / n42 tests 642 passed, 0 failed (`ci/m-tests.log`, the G8 test
included). Natives with the instrumentation: `/data/n42-build/g8b-native/release`
(`ci/m-natives.log`).
