# reth v2.8.1 → v2.9.0 (spike: inventory, not ported)

Dated 2026-11-03, branch `upgrade/reth-v2.9.0`, stage 2 (stage 1, the dependency refresh on
v2.8.1, is `docs/DEPENDENCY_REFRESH_2026_11.md` and merges on its own). **The branch does not
compile past this point.** It holds the mechanical sync so the port can start from it; the port
itself waits for a decision.

## Versions moved

| Crate | v2.8.1 | v2.9.0 |
|---|---|---|
| reth (git tag) | v2.8.1 | v2.9.0 (`c9a780f4`), rust-version 1.95 → 1.96 |
| EVM | revm 43.0.3 + alloy-evm 0.39.0 + revm-inspectors 0.44.3 + revmc | **evm2 0.1.0** (+ evm2-inspectors, evm2-jit), git `alloy-rs/evm2` rev `f93318f1` |
| `reth-revm` | crate (vendored here as `crates/revm`, a patch target) | **deleted**; `cached` / `database` / `either` / `witness` live in `reth-evm` |
| reth-primitives-traits, reth-codecs(-derive), reth-rpc-traits, reth-zstd-compressors | crates.io 0.8.2 | reth-core git rev `275ce4cf` through `[patch.crates-io]` (as upstream does) |
| `BundleState` and friends | `revm::database` | `reth_trie_common::bundle_state` (a copy of revm's, on evm2's `AccountInfo` / `Bytecode`) |
| thiserror / zstd / rocksdb | 2.0.0 / 0.13 / 0.24 | 2.0.20 / 0.14.3 / 0.24 with `lz4,zstd,bindgen-runtime` |
| new workspace deps | - | `derive-where` 1.6, `smolgen` 0.1.1 |
| inkwell | - | git rev `c9d9734a` (LLVM 23, for evm2-jit) |
| alloy, alloy-trie, jsonrpsee, tokio | unchanged | unchanged (alloy-trie stays 0.9.8: 0.9.9 breaks reth-trie-common) |

## Sync (`scripts/reth-sync.py v2.8.1 v2.9.0`)

1 file added, 8 conflicted files (12 hunks), 6 kept-for-review, all resolved:

| File | Resolution |
|---|---|
| `bin/reth/Cargo.toml` (2) | `reth-revm` dropped; defaults stay ours (`jemalloc`, `portable`), not upstream's otlp/js-tracer/jit set |
| `ethereum/node/Cargo.toml` (2) | both sides' deps (`reth-payload-builder` + `evm2`); upstream's reth-evm features, our "no jit" note and `reth-consensus` |
| `storage/provider/Cargo.toml` (2) | ours kept: `revm` / `revm-database` for the N42 hooks (marked "to be ported"), `n42-tx-types` + upstream's `evm2` dev-dep |
| `storage/storage-overlay/Cargo.toml` | ours (`n42-sharded-output`); `revm` kept for the same reason |
| `storage/storage-overlay/src/builder.rs` | upstream's evm2 / reth-trie-common imports |
| `storage/provider/src/lib.rs` | union: upstream's `PipelineUnwind` + our `WriteStateInput` |
| `storage/db/src/lockfile.rs` | upstream's let-chain |
| `chainspec/src/spec.rs` (2) | upstream: `impl EthExecutorSpec for ChainSpec` and the block-reward tests are gone (the trait went with alloy-evm) |
| `crates/revm/*` (kept, "deleted upstream, changed here") | deleted; see below |

`crates/revm` had four N42 deltas: licence headers, `either.rs` (now upstream's
`reth_evm::either`), and `Serialize`/`Deserialize` on `CachedReads` / `CachedAccount`. The last
one is load-bearing: `n42-clique`'s `UnverifiedBlock` carries a `CachedReads` over the APoS
pub/sub, and `reth_evm::cached::CachedReads` has no serde. The port needs a serde wrapper in
`n42-clique` (or a vendored `reth-evm`, which this spike avoids). Every `reth-revm` dependency in
the workspace became `reth-evm` (same features: `std`, `witness`, `portable`) and every
`reth_revm::` path `reth_evm::` (64 lines, 24 files) -- correct for `cached` / `database` /
`either`, wrong for the `reth_revm::revm::*` re-exports, which have no counterpart.

`vendor/dependency-repairs/reth-{nippy-jar,transaction-pool}-2.8.1` were three-way merged by
hand (nippy-jar: no upstream change; transaction-pool: four files, one manifest conflict --
`revm` out, `evm2` dev-dep in, `reth-evm-ethereum` with `std`) and renamed `-2.9.0`, with
`PROVENANCE.json` and `PATCHES.diff` regenerated. The `revm-inspectors-0.44.3` and
`revmc-builtins` repairs are now unused patches (cargo warns): reth uses evm2-inspectors and
evm2-jit. The fee-disabled `traceCall` beneficiary-prestate fix the inspectors repair carries
has to be re-checked against evm2-inspectors before that repair is deleted.

**Engine defaults.** `crates/engine/primitives/src/config.rs` (TreeConfig) and
`crates/node/core/src/args/engine.rs` (EngineArgs) are byte-identical between v2.8.1 and
v2.9.0: persistence threshold 50, memory block buffer 5, `num_state_masking_blocks` 30, prewarm
settings all unchanged, so `effective_tree_config`'s QMDB overrides (8 / 6) still apply as they
are. The engine tree itself changed a lot (prewarm 527 lines, payload-processor reuse 1,061,
BAL execute 1,653), all on evm2.

## The evm2 cascade

### What the compiler shows

`cargo check --workspace --keep-going` (log `f-gate2.log`, last step) stops at **4 errors in 2
crates**, both at the root of the graph:

- `reth-chain-state` (vendored), 3 × E0308 "expected `BundleState`, found a different
  `BundleState`": the N42 canonical-notification fill (`n42_completed_outcome`) hands
  `n42-sharded-output` / `n42-deferred-reverts`, which are built on revm's `BundleState`, the new
  reth-trie-common one.
- `n42-header`, E0277: `N42ChainSpec` implements alloy-evm's `EthExecutorSpec` by delegating to
  `ChainSpec`, which no longer implements it.

That number is a floor, not an estimate: `reth-chain-state` sits under the provider, the engine,
the node builder and every N42 crate past `n42-header`, so nothing above it was type-checked.
Getting the next layer costs one shared-box queue slot per layer (two to five hours each today),
which the bounded spike did not spend; the static inventory below is what the port is sized on.

### Static inventory

303 lines in 38 files of `crates/n42` and `bin/n42` name `revm`, `revm_*` or `alloy_evm`
directly, another 37 files reach revm through `reth_evm::` re-exports, and the vendored crates
have 33 more lines (provider 26, storage-overlay 4, chain-state, rpc-types-compat, ethereum-node).

| Crate | revm / alloy-evm lines | Depth |
|---|---|---|
| `n42-engine-types` | 215 (+ `reth_evm::` re-exports) | **deep**: `fast_transfer.rs` (a custom `EvmFactory` / `Evm` wrapping `EthEvm` with a transfer path ahead of the interpreter), `parallel_transfer.rs` (8,690 lines: `State`, `CacheDB`, `BundleAccount`, `EvmState`, `graft_bundles`), `n42_evm.rs` (`N42EvmConfig`, block executor factory, `EthExecutorSpec`, `revm_spec_by_timestamp_and_block_number`, Amsterdam gas params), `payload.rs`, `direct_build.rs`, `output_shards.rs`, `batch_state.rs`, `warm_ahead.rs`, `frame_scan.rs` (`calculate_initial_tx_gas`, `Eip2780TxInfo`, `SpecId::AMSTERDAM`), `assembler.rs` |
| `bin/n42` | 12 + 25 in `follower_import.rs` | **deep**: the follower import executes through revm `State` and carries `CachedReads`; 4 `SpecId::AMSTERDAM` uses (B's Glamsterdam parity) |
| `n42-qmdb-reth` | 33 (`changes.rs` 28) | medium: QMDB changes are read off `BundleState` / `BundleAccount`; a type swap if reth-trie-common's copy keeps the API (it does, per its module list) |
| `n42-reth-rpc` (fork) | 14 + 2 alloy-evm | medium: `CacheDB`, inspectors → evm2-inspectors, `traceCall` repair |
| `n42-ef-tests` | 13 | medium: builds `CfgEnv` / `BlockEnv` / `TxEnv` / `CacheDB` itself |
| `n42-tx-types` | 2 + 1 alloy-evm | **design**: the 0x50 envelope implements `FromRecoveredTx` / `FromTxWithEncoded` into revm's `TxEnv` (as type byte 2); evm2 dispatches by a per-spec `TxRegistry`, so 0x50 needs a registry entry or the same mapping onto evm2's `TxEnv` |
| `n42-sharded-output`, `n42-deferred-reverts` | 3 + 3 | shallow: `BundleState` type swap -- but it is what blocks `reth-chain-state` |
| `n42-header` | 2 alloy-evm | shallow: drop or re-home `EthExecutorSpec` |
| `n42-clique` | via `CachedReads` | shallow: serde for `UnverifiedBlock`'s `CachedReads` |
| `n42-tx-ingest`, `mobile-sdk`, `mobile-verify`, `fusaka` | 9 / 4 / 1 / 1 | shallow |
| vendored provider / storage-overlay / chain-state | 33 | shallow-medium: the QMDB reader hooks and persistence timers take revm `BundleState` / `AccountInfo`; type swaps |
| witness recorder (`docs/patches/0001-*`, reth branch `witness-record`) | n/a | **redo**: its `StateReadObserver` hooks revm's `State`, which no longer exists in reth |

### revm → evm2 / reth v2.9.0 mapping

| revm 43 / alloy-evm 0.39 (N42 uses) | v2.9.0 counterpart | One-to-one? |
|---|---|---|
| `revm::primitives::hardfork::SpecId` (128 uses, 9 files), `SpecId::AMSTERDAM` (21 in N42 code) | `evm2::SpecId` (has `AMSTERDAM`); per-factory `EvmFactory::SpecId` | yes for the enum; the factory carries its own spec type |
| `CfgEnv` (12), `set_spec_and_mainnet_gas_params` | `evm2::Version` (`Version::new(spec)`, `chain_id`, EIP-8037 toggles) + `ExecutionConfig::for_spec_and_version` | no: configuration is split differently |
| `BlockEnv` (42) | `evm2::env::BlockEnv<T>` (`BlockEnvExt`) | mostly, generic over the type family |
| `TxEnv` (99, 9 files) | `evm2::env::TxEnv<T>` (`TxEnvExt`) built through `reth_evm::FromRecoveredTx` / `IntoTxEnv` | mostly; custom types go through the tx registry |
| `calculate_initial_tx_gas`, `Eip2780TxInfo` (frame_scan) | `evm2::ethereum::intrinsic_and_floor_gas(version, caller, to, input, al_accounts, al_keys, value)` + reth's `EvmTransactionValidationGasRules` | close; different inputs (needs the `Version`) |
| `alloy_evm::EvmFactory` / `EthEvmFactory` / `EthEvm` / `EthEvmBuilder` | `reth_evm_ethereum::EvmFactory` (`Types`, `spec_id`, `version`, `tx_registry`, `precompiles`, `configure_evm`), `RethEvmFactory` | **no**: an evm is not wrapped any more, a factory supplies a type family and a tx registry |
| revm `Handler` / `MainnetHandler` / frames (fast transfer's model) | `evm2::registry::TxHandler<T, Tx, Output>`, `evm2::evm::handler::TxHandlerHooks` | **no**: the transfer path has to become a tx handler (or hooks), and its equivalence proof ("revm's arithmetic, in revm's order") redone against evm2's handler |
| `alloy_evm::block::{BlockExecutor, BlockExecutorFactory}`, `ConfigureEvm` | `reth_evm::execute::{BlockExecutor, BlockExecutorFactory, Evm}`, `reth_evm::ConfigureEvm` (now `EvmEnv` trait, `jit_backend`, `prewarm_tx_result`, `speculative_next_evm_env`) | reshaped: same roles, different signatures |
| `alloy_evm::eth::spec::EthExecutorSpec` | gone (deposit contract read from the chain spec directly) | removal |
| `revm::database::{CacheDB, EmptyDB}` (85 / 70) | `evm2::evm::db::{CacheDB, EmptyDB}` | yes |
| `revm::database::State` (+ `StateBuilder`, transitions) | evm2 `State<'a>` is the in-EVM journal; block-level caching and bundles are reth's (`reth_evm::database`, `reth_trie_common::bundle_state`) | **no** for `parallel_transfer` / `graft_bundles`, which drive revm `State`'s bundle building directly |
| `BundleState` / `BundleAccount` / `TransitionState` (382 / 163 / 5) | `reth_trie_common::bundle_state::*` | yes (a copy of revm's API) |
| `AccountInfo` (284), `Bytecode` (157), `EvmState` / `ResultAndState` (61), `ExecutionResult` (63) | `evm2::evm::AccountInfo`, `evm2::bytecode::Bytecode`, evm2 results (`TxResult<T>`) | names map; field shapes need checking per site |
| `revm::Inspector`, `revm-inspectors` (traceCall, debug, otterscan) | `evm2::Inspector<T>`, `evm2-inspectors` | close; the N42 `traceCall` repair has to be re-made |
| `PrecompilesMap` | `evm2::Precompiles<T>` + `reth_evm::precompile_cache` | reshaped |
| `reth_revm::cached::CachedReads` (serde) | `reth_evm::cached::CachedReads` (no serde) | yes, minus serde |

**Verdict: not mechanical.** The decision rule ("under ~150 errors and only renames, no handler
or `EvmFactory` redesign for `fast_transfer` or the 0x50 `TxEnv`") fails on its second half
regardless of the error count: both need the evm2 tx-registry/handler model, and
`parallel_transfer`'s bundle grafting is written against revm's `State`, which reth no longer has.

## Estimate

Person-days for one engineer who knows the N42 EVM layer, compile-clean plus unit tests; box
queue time not included.

| Subsystem | Days |
|---|---|
| Vendored crates + `sharded-output` / `deferred-reverts` / `qmdb-reth` / `header` / `clique` (BundleState / AccountInfo swaps, `EthExecutorSpec`, `CachedReads` serde) | 3-4 |
| `n42_evm.rs` + `assembler.rs`: `N42EvmConfig`, executor factory, Amsterdam spec / gas params on `Version` | 2-3 |
| 0x50 transaction (`tx-types`, ingest, pool): `TxEnv` mapping + tx-registry entry, altsig sender cache wiring | 2-3 |
| `fast_transfer.rs` as an evm2 tx handler, with its revm-equivalence tests rebuilt | 4-6 |
| `parallel_transfer.rs` / `graft_bundles` / `batch_state.rs` / `warm_ahead.rs` on reth's bundle state | 5-8 |
| `payload.rs`, `direct_build.rs`, `output_shards.rs`, `frame_scan.rs` | 2-3 |
| `bin/n42` follower import, by-description bench, queue reorg | 2-3 |
| `reth-rpc` fork (evm2-inspectors, `traceCall` repair, sim/bundle) | 2-3 |
| `ef-tests` runner | 1-2 |
| witness recorder (outside the node path; can wait) | 2-3 |
| Gate: workspace tests, devnet, gov5 mixed devnet, `roll --kill` on QMDB | 2-3 |
| **Total** | **27-41** |

Paths tuned on revm 43 that need re-measuring on the seven-node fleet before the port can be
adopted -- every one of them is rewritten, not just recompiled:

- the fast transfer path (`N42_FAST_TRANSFER`; ~1.4 us/transfer saved vs revm's journal+frame);
- the parallel builder and follower graft (`N42_PARALLEL_BUILD`, `N42_FOLLOWER_GRAFT`;
  build 1,054 → 537 ms when introduced);
- deferred execution (the follower's check/vote/import split and `MERGE_ELIDE`);
- the X22 configuration's 5.1-5.2M TPS legs (`docs/NATIVE_FLEET7.md` 10.227-10.230), as A/B
  pairs against v2.8.1 + X22, plus the Amsterdam (EIP-8037) gas path B just merged.

evm2 also brings things worth measuring rather than only matching: reth's precompile cache moved
into `reth-evm`, the payload-processor prewarm/reuse rewrite, and evm2-jit (off in our build).

## Recommendation

Merge stage 1 now; keep the reth pin at v2.8.1. Do not start the evm2 port as a side task: it is a
27-41 day rewrite of the EVM layer under every N42 performance path, followed by a fleet
re-baseline. If the user wants it, schedule it as its own stream, in this order: (1) the shallow
layer (vendored crates, BundleState swaps, header/clique), which makes `cargo check` report the
real error count; (2) `N42EvmConfig` + 0x50 on the stock evm2 handler, fast/parallel paths off,
to get a correct node on the devnet and the gov5 mixed devnet; (3) the fast transfer and parallel
builder as evm2 handlers, each A/B-measured against v2.8.1 + X22 before it is switched on.
Meanwhile v2.8.x patch releases (if upstream cuts any) can be taken on the current layer.
