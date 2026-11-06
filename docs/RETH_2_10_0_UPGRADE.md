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
