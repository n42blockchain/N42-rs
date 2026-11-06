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

## Port log

The port runs as workstream F of `docs/PLAN_OPEN_ITEMS_2026_11.md` (user decision 2026-11-03:
do it), in the spike's order: F3 shallow layer, F4 a correct node on the stock evm2 handler, F5
the performance paths, F6 merge prep.

### F3, shallow layer (2026-11-03)

Decisions, as briefed:

- **Bundle types.** `BundleState` / `BundleAccount` / `AccountRevert` / `Reverts` / ... come from
  `reth_trie_common::bundle_state` (`reth_trie::bundle_state` in crates that have `reth-trie`),
  `AccountInfo` from `evm2::evm`, `Bytecode` from `evm2::bytecode`. A rename everywhere: the copy
  keeps revm's API. Done in the vendored provider and storage-overlay, `n42-sharded-output`,
  `n42-deferred-reverts`, `n42-qmdb-reth` (c88338b04), and in `n42-engine-types` / `bin/n42`.
- **`n42-header`.** `EthExecutorSpec` dropped (4f4317558); nothing else implemented or required it
  but `n42_evm.rs` and three `payload.rs` bounds, which now ask for `EthChainSpec` only.
- **`CachedReads` serde.** `n42-clique::cached_reads_serde` mirrors the old derived shape and is
  used through `serde(with)`; the field keeps reth's type (07d41f51d).
- **0x50 on evm2.** No tx-registry entry: reth converts a recovered transaction through
  `FromRecoveredTx`, which has a blanket impl for every `T` with `evm2::ethereum::TxEnvelope:
  From<T>`. `From<N42TxEnvelope>` / `From<AltSigTx>` make a 0x50 transaction
  `TxEnvelope::Eip1559` with its fields, the type-byte-2 semantics it had on revm's `TxEnv`
  (c01415cb8). The caller stays the recovered sender.
- **`N42EvmConfig`** (639493f23). reth's `EthBlockExecutorFactory` bounds its chain spec by
  `EthChainSpec<Header = alloy Header>`, which `N42ChainSpec` (header `N42Header`) cannot meet,
  and its EVM constructor is crate-private; `N42BlockExecutorFactory` is the same ~60 lines
  without that bound, creating reth's `EthBlockExecutor` over `N42ReceiptBuilder`. The EVM
  factory is reth's `RethEvmFactory` (precompile cache policy `All`; JIT off in our build). The
  environment is `EthEvmEnv` (spec, `evm2::Version`, block env) built the way `EthEvmConfig`
  builds it, plus the N42 rules: the APoS signer as beneficiary, and on a native chain past
  `glamsterdamTime` `SpecId::AMSTERDAM` without reth's Amsterdam hardfork. evm2's Amsterdam
  version turns on EIP-8037, EIP-2780, EIP-7708 and EIP-8246 by default, which is the set gov5
  runs (`docs/GLAMSTERDAM_EXECUTION_PARITY.md` rows 57-70); the gov5 fixture test
  (`the_gated_devnet_block_matches_gov5`) is the arbiter in F4.
- **`legacy-revm-paths`** (de21cda35). `fast_transfer`'s factory and transfer
  (`fast_transfer_legacy.rs`, included under the feature), `parallel_transfer`, `batch_state` and
  `warm_ahead` build only with the feature, off by default and forwarded by `bin/n42`. The parts
  of `parallel_transfer` that never touch the EVM (knobs, worker pools, the sender partition,
  phase timers, the revert helpers over reth's bundle state, the build-path keys) moved to
  `parallel_common.rs`, which both builds see under the old `crate::parallel_transfer::` path.
  `legacy_paths::KNOBS` lists every knob of the gated paths; `N42EvmConfig::new` logs once
  "not available on evm2 yet" with the ones set. `follower_parallel()` and
  `plan_ahead_body_wanted()` read false without the feature; the payload builder's parallel step,
  the plan-ahead body and warm-ahead hooks and the follower's parallel / build-path execution are
  gated at their call sites, so the stock evm2 executor runs everything.
- **Payload builder on evm2** (9f77dd0cb). The block executor's `finish` returns
  `BlockExecutionOutput { result, state }` with the bundle already merged, so the early-seal path
  drops its own `merge_transitions`. Refused nonces are classified by downcasting
  `InvalidTxError::as_any()` to evm2's `HandlerError::InvalidNonce { expected, got }`
  (reth's `EthInvalidTxError` exposes it that way): `got < expected` is "too low" (skipped, the
  queue told), `got > expected` "too high". `execute_transaction` returns a `GasOutput`; the
  builder counts `tx_gas_used()`. Account reads in the stale check and the includability check go
  through `Evm::account_info` and the parent's `AccountReader`. The builder's `CachedReads`
  prefetch (`N42_BUILDER_PREFETCH`) wrote revm's cache directly and is legacy-only for now.
- **Output shards** (3cfd00ae7). The frozen output, its merges and its view are bundle-state code
  and build everywhere; the two `take_cached` commits and `into_staged` write revm's `State`
  cache and build only with `legacy-revm-paths`.
- **Intrinsic gas** (3cfd00ae7). `frame_scan` prices a transaction with evm2's
  `intrinsic_and_floor_gas` plus EIP-7702's per-authorization charge, the rule reth's
  `EvmTransactionValidationGasRules` and evm2's handlers apply. evm2 charges no state gas at the
  intrinsic phase (EIP-2780 moved it to runtime), so the shortfall is
  `max(intrinsic, floor) - gas_limit`. Without a known sender a call is priced as one to another
  account, as before.
- **Dependency repairs** (d12c2e574, 076c682e9). revmc-builtins (evm2-jit replaced revmc) and the
  stale revm-inspectors 0.44.1 lockfile are gone. The traceCall beneficiary-prestate repair moved
  to a vendored `evm2-inspectors` at the pinned evm2 revision (patched in through
  `[patch."https://github.com/alloy-rs/evm2"]`): evm2's default prestate lists only the accounts
  in the pending state, the same omission. Unlike the revm-era repair, an empty beneficiary is
  left out, the rule evm2 (and current Geth) applies to every account.
- **`reth-rpc-types-compat` dropped** (b5f643721). It carried no N42 delta and re-exported
  alloy-evm's revm-era RPC env types; node-core, `bin/n42` and `bin/reth` re-export
  `reth-rpc-convert` as upstream does. `crates/n42/reth-rpc` (not a member, disabled since
  v1.9.3) is left as it is.

### ef-tests runner

`crates/n42/ef-tests` no longer hand-rolls block execution on revm's `State`. Upstream v2.9.0's
`testing/ef-tests` runs every block through reth's executor, so ours does too, over an evm2
`InMemoryDB` instead of upstream's MDBX provider: blockchain tests decode each block's RLP (or
build it from an Engine API payload) and call `EthEvmConfig::executor(&mut db).execute`, then commit
the bundle into the db and record the block hash for `BLOCKHASH`; the hand-written EIP-4788 /
EIP-2935 storage writes, withdrawal crediting and 2 ETH PoW reward are gone (the executor applies
the real system calls, withdrawals and fork-correct rewards), and a block that fails to execute now
fails the test instead of being logged and skipped. State tests decode the variant's signed
`txbytes`, build the EVM from `evm_env` of a header made from the test environment, `transact_commit`
and merge the EVM's state cache back. The revm-era heuristics (precompile accounts guessed from the
test name, a forced empty coinbase before Spurious Dragon, the hand-written 6-blob cap and blob-fee
helpers) were dropped and left to evm2. The ported crate (code in c117217eb, lock in 7774ff867)
checks and its 48 non-ignored tests pass; the `#[ignore]`d fixture runs were not re-run (no
fixtures on this host).

### F3 result (2026-11-04)

`cargo check --workspace --keep-going --tests` is clean on the stock evm2 build
(`audit-notes/ci/f3-check7.log`, head 231e38825); `origin/main` had nothing new to merge. Seven
check rounds took the count from the first full pass (f3-check2: 10 errors, all in
`n42-engine-types`) through borrow-check fixes (the block executor now borrows `CachedReads`
through its database, so a builder must be consumed before the reads are handed back; a
partially moved builder stays drop-live to the borrow checker) to zero. The
`legacy-revm-paths` build is not expected to compile: its code still names revm 43's `State`
(`reth_evm::db::State` is gone), and F5 ports or removes it path by path.

### F4 result (2026-11-05)

F4 ran on 43b07fbf8, the branch with `origin/main` 1ccfcae30 merged in. That merge brought in the
system-caller leaf fix (3984881bf). Its one conflict was the QMDB changes call in the payload
builder's root path: the branch's `outcome.execution_state` is kept and the flag is main's
`system_caller_leaf_at`. Every run below used the stock evm2 handler (`legacy-revm-paths` off),
on native release binaries from `/data/n42-build/reth29-native/release`. The field gate was driven
by `audit-notes/scripts/f4-gate.sh`, log `audit-notes/ci/f4-gate.log`, done 07:33:52Z.

Code gate:

- Workspace tests: 1207 passed on the first run (`ci/f4-tests1.log`). The one failure was the
  gov5 Amsterdam parity test, which read code from the account info; it was fixed in 287f8d32c
  and passes on rerun (`ci/f4-tests2.log`). After the merge, n42-qmdb-reth, n42-engine-types and
  n42 ran 554 passed, 0 failed (`ci/f4-merge1.log`), and `cargo check --workspace
  --keep-going --tests` was clean.
- The ported-crate fixture tests (bmt-core, twig-core, h2-*, mobile-verify, h2-net,
  h2-execution) passed in the workspace run.
- Clippy on the N42 crates is clean (`ci/f4-clippy2.log`).

Field gate (evidence under `audit-notes/devnet/` and `audit-notes/ci/`):

- **All-Rust devnet** (`f4b-rust`, four members, 300 s, `devnet/f4b-rust.out`): 100 views.
  Every validator shows commits=100, views=100, timeouts=0. The execution layer shows
  newPayload=400, qmdb_roots=100, err=0. Height 100.
- **Devnet with a gov5 member** (`f4b-gov5`, three Rust members plus gov5 `integ/mvdev-slot`
  d4a00b01, 300 s, `devnet/f4b-gov5.out`): 133 views. The three Rust members show
  commits=133 and timeouts=0. v0's "timeouts=2" is the single view-1 start-up TC, logged twice.
  gov5 shows sealed=33, committed=166, errors=0, height 133. The block 133 hash (0x024e983f…)
  is the same on both clients. EL err=0.
- **Mixed gated MobileAnchor round** (`f4-mv`, `scripts/devnet-mobileanchor.sh f4-mv --gov5
  --txload`, 360 s, `devnet/f4-mv/`): 160 blocks, both heights 160, 161 hashes the same, no
  first difference.
  - gov5: sealed=40, committed=200, errors=0, warns=0.
  - Leader-root check: the Rust leaders' roots are ok=120, mismatch=0. Of the 40 gov5-led
    blocks, 4 carry the zero root (before the first registry epoch) and 36 the committed root.
  - Device: 2 devices, 20/20 certified, 0 failures.
  - packetd: 160 packets; its only warning is about the genesis.
  - send_tx: 1322 sent, 0 rejected. v0's timeouts=2 is again the view-1 start-up TC.
  - This is the same shape as `mv4h4b2` on main.
- **`roll --kill` on the seven-node fleet7 shape** (`rollkill-check.sh`, lean profile,
  `ci/rollkill.log` tags `rollkill-f4k90` / `rollkill-f4k20`, raw outputs
  `ci/f4k{90,20}-rollkill-*.out`). The first kill came at 90 s, and in the second run at 20 s,
  before the first persistence.
  - In both runs, every one of rolls 1, 2 and 3 with `--kill` committed again (commits since
    restart 2), with 0 fault lines in el.log.
  - The 360 s watch read 118 and 117 blocks (0.328 and 0.325 per s against the 0.333 target).
  - At the end all seven nodes agree on a common height with equal head hashes.
  - Each node's el.log carries one error line, `N42_TX_INGEST is not an address`, with an empty
    address. It comes from fleet7.sh passing an empty `N42_TX_INGEST` when `F7_INGEST` is unset.
    October logs have the same line, so it predates the port and is not part of F4.

What evm2 changed in behaviour: nothing visible in the field gate. Blocks, QMDB roots, the
MobileAnchor registry roots and the hashes are identical to gov5's across all three shapes, and
SIGKILL recovery on QMDB holds, including a kill before the first persistence. The engine
defaults are unchanged from 2.8.1 (see the notes below).

### F5 design (2026-11-05)

**What v2.9.0 offers in place of revm's `State`.** The bundle types kept revm's API in
`reth_trie_common::bundle_state`: `BundleState` and its pub `state`, `contracts`, `reverts` and
`state_size`, plus `BundleAccount`, `AccountRevert`, `TransitionState`, `TransitionAccount`,
`AccountStatus` with `on_changed` and the rest, and `apply_transitions_and_create_reverts`.

The block executor is two things.

- **The evm2 `Evm`.** Its `State` holds a transaction layer and journal over a `CacheDB` accepted
  overlay. `overlay_db_mut().cache.accounts` is a pub `AddressMap<Option<AccountInfo>>`, and
  contracts and storage sit beside it.
- **reth's `BlockState`.** It has a private `transitions` map, takes changes only through
  `commit(&TransactionChanges)` / `commit_account_changes(AccountChanges)`, and finalises to a
  bundle in `into_bundle()` at the end of `finish`, after the post-execution changes.

The consequences:

- No bundle is mutable mid-block.
- `merge_transitions` / `take_bundle` are gone.
- A transaction's changes arrive as evm2's change stream (`StateChangeSink`: account, storage,
  storage wipe, bytecode), not as `EvmState`.
- Account code is never in a reth `AccountInfo` (`without_code`). Touched code lives in the bundle's
  `contracts`.
- Transactions can be executed detached: `execute_transaction_without_commit`, then
  `commit_detached_transaction`.

**Finding that sets the order.** Every parallel batch, leader and follower alike
(`parallel_transfer.rs` 2751, 3194, 3312), builds its EVM with
`N42EvmFactory::with_fast_transfers(true)`. X22 therefore runs the transfer fast path inside the
batches even though it does not set `N42_FAST_TRANSFER`. F5c and F5d first run their batches on the
stock evm2 handler, which is correct but slower. Their A/B against v2.8.1 is like for like only once
F5f gives the batches the handler, or once a measurement shows evm2's own plain-call path is close
enough. evm2 has no interpreter-free transfer path of its own.

**Per path.**

| path | rename | rewrite |
| --- | --- | --- |
| `parallel_common.rs` | all of it: knobs, pools, partitions, phase timers, revert helpers already work on reth's bundle state | none; un-gate |
| `batch_state.rs` | `take_bundle`, `loaded`/`loaded_status`/`change` (bundle-account rules) | the read side becomes an evm2 `Database` (`get_account` / `get_code_by_hash` / `get_storage` / `get_block_hash`); `commit(EvmState)` becomes a `StateChangeSink` that folds each transaction's stream into the batch's `BundleAccount`s with the same status moves and the same `Unsupported` refusals (storage, create, destroy) |
| batch execution (`execute_for_build_*`, `follower_batch`, `execute_transfers_*`) | partition, dispatch, slots, `BuildRun`, body/fees | the batch loop drives a bare evm2 `Evm` over the batch's database (no pre- or post-execution) and feeds each committed transaction to `BatchState`. Step one is reth's `EthBlockExecutor` per batch, taking `block_state.into_bundle()`: the correctness baseline, measured, then replaced by the sink |
| graft family (`graft_bundles*`, `fold_bundles`, indexed/ranges/sharded/staged/streamed folds, base swap, prefault target, `install_staged`, output shards' `take_cached` / `into_staged`) | everything that folds bundles into a bundle | the target: they write into `&mut State<DB>` (`bundle_state` + `cache`), which v2.9.0 does not have mid-block, so they cannot be ported 1:1; see below |
| `warm_ahead.rs`, `ReadSet`/`ReadSetDb`, `WarmDb`/`FrozenWarm`, `BUILD_MLP` | the layers and their filling | revm `Database` → evm2 `Database` (four methods, `Word` keys); `AccountHint` for evm2's `CacheDB` and reth's `StateProviderDatabase` |
| `N42_BUILD_PREFETCH` | — | it wrote revm's `CachedReads`; becomes a fill of the batch database's warm layer, or is retired if `READ_SET` covers it (decided in F5e). reth 2.9.0's prewarm (`prewarm_tx_result`, `payload_processor/prewarm.rs`) serves the engine tree's newPayload path, which neither the leader's build nor the N42 follower import goes through, so it retires no knob of ours |
| `fast_transfer` | the qualification rules, counters, timers | `N42EvmFactory` (a revm EVM wrapper) becomes an evm2 registry entry for types 0, 1 and 2 (0x50 executes as 2) that wraps the stock Ethereum handler: `prepare` proves the shape on evm2's host, otherwise it delegates. It applies three balance changes and a nonce through `State::account` handles so that evm2's change stream and journal see them. The fork set stays Prague/Osaka (fleet7 is Osaka). Amsterdam needs its own tests first: EIP-8037 state gas on a creating recipient, EIP-2780 intrinsic, and the EIP-7708 transfer log, which changes the receipt |

**The graft, nearest shape: two halves.**

1. **Cache half** (builder; follower only for withdrawal recipients and the beneficiary). After the
   batches, write each grafted account's current info into the executor's accepted overlay
   (`evm.db_mut().overlay_db_mut().cache.accounts`). The serial tail, the withdrawals and the
   beneficiary credit then read the post-batch values, as they read `State.cache` today. The
   beneficiary's fee total is still applied as one credit before `finish`.
2. **Bundle half.** After `finish`, fold the batch bundles into the finished `BundleState` with one
   rule:
   - An account only the batches touched goes in as the batch left it, exactly as
     `graft_bundles_direct` does today.
   - An account also in the serial bundle keeps the serial `info`/`status`, which already include
     the batch's effect because it was read from the cache half. It takes `original_info` and the
     revert from the batch, which hold the parent's values. The serial revert to the post-batch value
     is dropped.
   - Batch accounts carry no storage or code (`Unsupported`), so nothing else merges.

   Every fold variant keeps its body and changes only its target, from `&mut State<DB>` to
   `&mut BundleState` plus the overlay. `finish` returns the bundle, so the N42 executor needs no
   fork.

**Equivalence tests.** These are rebuilt against the stock `N42EvmConfig` executor
(`executor(db).execute(block)` over an evm2 `InMemoryDB`) on the same block, replacing revm's
`State` as the reference:

- `parallel_matches_serial*`, `build_run_matches_serial` and
  `the_build_path_matches_the_follower_path_and_the_serial_executor`: the bundle compared by state,
  contracts and sorted reverts (`assert_same_bundle`), the receipts root, and the QMDB root through
  `changes_from_execution`.
- The fold-equality tests: indexed = direct = sharded = staged, unchanged since they compare bundles.
- New blocks to test:
  - transfers plus contract calls in the serial tail that touch batch senders;
  - a withdrawal to a batch-touched account;
  - a creating recipient at Amsterdam gas;
  - a 0x50 sender;
  - the beneficiary as a recipient, which must refuse the parallel path.
- F5f: the stock handler against the fast handler, transaction by transaction: gas, refund, balances,
  nonce, the touched set and the change stream, plus the receipt with and without EIP-7708.

**Open questions for the coordinator.**

- Should F5c/F5d's A/B wait for F5f? My recommendation: yes; measure the stock-handler batches only
  as a data point.
- Is the follower's `keep_cache = false` still worth keeping, given that the cache half is cheap?
  To be measured.

### F5b, the shared layer (2026-11-05)

- **`parallel_common.rs`** was already EVM-free and built on the stock build since F3: nothing to
  port. Its knobs stay in `legacy_paths::KNOBS` until the paths that read them work (F5c/F5d).
- **`batch_state.rs`: rewritten (b7af797c8).** On evm2, an `Evm` owns and caches its database,
  so the batch state is no longer the batch's database. It is only the accumulator.
  - `BatchState::commit(&PendingState)` folds each finalised transaction's `account_changes()`
    into `TransitionAccount`s by the rule of `BlockState::commit_account_changes`, and
    `take_bundle` is `apply_transitions_and_create_reverts(Reverts)`. So its bundle is the stock
    accumulator's by construction.
  - It refuses (`Unsupported`): storage, a storage wipe, new code, creation, selfdestruct, and an
    account left absent or empty.
  - The revm-era file is kept as `batch_state_legacy.rs` under `legacy-revm-paths` for the legacy
    parallel paths until F5c/F5d port them.
  - Dropped and not yet replaced:
    - `commit_transfer(PlainTransfer)`: the evm2 fast handler (F5f) applies its changes through
      the state, so they arrive in the same stream.
    - The in-place `take_bundle` optimisation (loop283): a baseline first.
    - `hint_account` / `prefetch_account` (`N42_BUILD_MLP`): F5e, with the read layers.
  - Tests (4): its bundle equals reth's `BlockState::into_bundle()` field for field on transfers
    with repeated senders, a recipient that later sends, a recipient that did not exist, the
    beneficiary, and a legacy transfer. A storage write and a creation are refused.
- **`graft_fold.rs`: new (b387237b7), the graft's bundle half from the F5 design.**
  - `merge_batches` merges the batch bundles. Credits from different batches are added together;
    at most one batch may debit an account (the `TwoDebits` refusal). It refuses storage, code
    (in the info or in contracts), destroyed or absent accounts, and different originals.
  - `MergedBatches::accounts()` is what the cache half writes into the executor's overlay.
  - `fold_into` checks first and changes nothing on a refusal. The refusals are serial storage on
    a batch account, and `Stale`: the serial original differs from the batches' final info. That
    is the real check that the cache half held the account; it covers the beneficiary and every
    withdrawal recipient.
  - Then the fold: the final info is the serial one when the serial part touched the account,
    otherwise the batches'. The original is the batches'. The status and the revert are recomputed
    from (batch original, final) through a `TransitionAccount`. Batch reverts go into the block's
    revert set (`append_reverts`, sorted by address, the serial revert to the post-batch value
    dropped), as `graft_bundles_direct` placed them.
  - A refusal logs one warn line (target `n42::graft`), counts (`refused_count()`) and returns
    `FoldRefused`.
  - Tests (5):
    - two batches sharing a recipient and the beneficiary, plus a serial tail spending from that
      recipient, a batch sender and a batch-created account, run over the cache half: the fold
      equals the sequential execution, and `revert_latest` on the folded bundle gives back the
      parent;
    - a serial `Changed` over a batch-created account folds to `InMemoryChange` with a `DeleteIt`
      revert;
    - a serial change back to the parent value: see below;
    - a stale account (a withdrawal recipient the cache half missed) is refused, the bundle is
      unchanged and the counter goes up;
    - the merge's refusals (storage, two debits, different originals) and the merging of a debit
      with a credit.
- **One point differs from the brief: a change back to the parent's value.** reth's accumulator
  treats an account that a block changed and changed back as unchanged:
  `update_and_create_revert` returns no revert for it (`AccountRevert::is_empty`), and
  `apply_transitions_and_create_reverts` then leaves it out of the bundle. The stock sequential
  execution does the same, so the fold drops such an account and the serial part's revert along
  with it, rather than keep it as `Changed`. The test pins this. Changing only the balance back
  while the nonce moved is still a change.

Gate: `ci/f5-b-gate.log`. `cargo check --workspace --keep-going --tests` is clean. n42-engine-types
(263 including the 9 new tests), n42-qmdb-reth, n42-qmdb-state and n42-testing: 464 passed,
0 failed.

### F5c, the leader's parallel builder (2026-11-05)

- **Rewritten, not renamed.** The revm-era step (`parallel_transfer::execute_for_build*`, slots,
  output shards, the staged/streamed/indexed grafts) stays under `legacy-revm-paths` until F6. The
  evm2 step is new code: `parallel_build.rs`, a wrapper in `n42_evm.rs`, and a block in
  `default_n42_payload` under `cfg(not(legacy-revm-paths))`.
- **`parallel_build::execute_batches`.** It partitions the candidates by sender (or takes the
  partition the plan made), packs the groups into batches (`Dispatch::from_env`:
  `N42_BUILD_BATCHES` / `N42_BUILD_ONE_WAVE`) and runs each batch on the build pool
  (`N42_PARALLEL_BUILD_THREADS`). A batch has its own evm2 `Evm` over its own view of the parent,
  and every transfer goes through the stock handler (`evm.transact`, `BatchState::commit`,
  `evm.commit_state`).
  - A transfer the EVM refuses is skipped with its sender's later ones and given back at the end,
    as the revm-era step did.
  - Under deferred execution, each sender's summed worst case is kept within its parent balance
    (`includability::RunLedger`, audit R3-E1). The balance comes from the first transfer's
    `AccountChanges::original`, and the check runs before the commit.
  - The batches' bundles are merged with `merge_batches` (F5b).
- **The cache half: `install_cache`.** It writes the merged accounts into the block executor's
  overlay (`CacheDB::insert_account_info`) at their post-batch values. It first refuses, writing
  nothing (`Refused::Cache`), if the overlay already holds one of them at a value other than the
  batches' original, for example an account a pre-execution system call touched.
- **The receipts: `commit_run`.** It commits each executed transfer in candidate order through the
  stock `commit_transaction`, with an empty write set (`TxResultWithState { result, pending_state:
  empty }`). The executor counts the gas and builds the receipt as for any transaction, so
  cumulative gas, receipts and the EIP-8037 split come out as in a serial build. The state is in
  the merge.
- **The bundle half: `N42BlockExecutor`.** reth's `EthBlockExecutor` plus a pending merge
  (`set_pending_fold`). `finish_with_block_access_list` and
  `finish_with_prepared_block_access_list` fold the merge into the bundle with `fold_into`
  before anything reads it (hashed post-state, QMDB root, assembler). Every other method delegates,
  including `execute_transaction_with_commit_condition`, so the serial loop keeps the stock path.
  The factory's `Executor` is this type on every chain; with no merge pending it is the inner
  executor.
- **When the payload builder takes the step.** With `N42_PARALLEL_BUILD=1`, on a chain without
  reth's Amsterdam or gov5's Glamsterdam execution: the BAL index and the separate block gas
  counters are private to the executor, and the existing gate already sends Glamsterdam blocks to
  the serial path.
  - The candidates come from the puller, the frames' bulk vector, or the pool's iterator. The
    iterator source is new: the devnet has no puller or queue.
  - The step runs only when every candidate is a plain transfer and nothing executed before it.
    Otherwise the candidates go to the serial loop in candidate order.
  - A fix outside the step: the serial loop now takes the step's hand-back (`lookahead`) before the
    pool's iterator when `N42_BUILDER_PREFETCH` is 0. Before, those candidates were lost. The
    revm-era step had the same hole for a bulk vector without a puller.
- **The refusal rule, end to end.**
  - A refusal before the cache half (partition, unsupported change, merge, cache conflict) gives
    the block to the serial loop in the same build.
  - A refusal at `finish` surfaces as `BlockExecutionError::Internal(Other(FoldRefused))`. The
    payload builder (`finish_or_rebuild!`) then executes the same transactions again, in order,
    on a fresh executor over the parent, and finishes that block.
  - The transactions are copied for this only on a build with a merge pending: a cost the A/B
    should watch, and one to remove once refusals at `finish` are shown to be unreachable.
  - Counters: `graft_fold::refused_count()`, `parallel_build::serial_rebuilds()`,
    `parallel_build::committed_runs()`.
- **One line per build** (target `n42::parallel_build`, info): `parallel`, `txs`, `skipped`,
  `batches`, `refused` (`no-candidates`, `transactions-before`, `not-all-transfers`,
  `not-parallel`, `unsupported-change`, `merge-refused`, `cache-conflict`), the two refusal
  counters, and pull/exec/commit milliseconds.
- **Knobs.**
  - Dropped from `legacy_paths::KNOBS`: `N42_PARALLEL_BUILD`, `N42_PARALLEL_BUILD_THREADS`,
    `N42_BUILD_BATCHES`, `N42_BUILD_ONE_WAVE`, `N42_FREEZE_POOL(_THREADS)` and
    `N42_PLAN_AHEAD_BODY(_THREADS)`.
  - `FREEZE_POOL=own` now only frees the candidates behind the build: the receipts it moved off
    the seal are committed on the builder's thread.
  - `PLAN_AHEAD_BODY` installs an evm2 plan hook that makes the candidates, keys, hashes and
    partition. The revm-era body parts are not made.
  - `N42_BUILD_COLLECT_IN_PLACE` stays listed: the evm2 step collects per batch and has no slots,
    so it has no effect yet.
  - The output shards' `take_cached` / `into_staged` stay legacy, and so does `N42_OUTPUT_SHARDS`
    (not in `KNOBS`; inert on evm2). They are the sharded alternative to the merge, worth porting
    only if the A/B says the merge is the cost.
- **Tests (11 new).** `parallel_build` (5):
  - a mixed block (batched transfers with shared recipients and a created recipient, then a serial
    tail that spends batch credits, a batch sender's next nonce, the created account's first spend,
    a transfer to the beneficiary and a storage-writing contract call, then two withdrawals) gives
    the receipts, gas, bundle state, reverts and contracts of the sequential stock execution;
  - batched transfers alone, the same;
  - a refused transfer and its sender's later ones are skipped;
  - the worst-case ledger;
  - the cache half's refusal writes nothing.

  `payload` (2):
  - the parallel build's header equals the serial build's (state, transactions and receipts roots
    included), and a fold made to refuse at `finish` (a test-only hook) is rebuilt serially in the
    same build to the same header;
  - a deferred parallel build keeps each sender's worst case within its balance and passes the
    follower's verdict.

  The test addresses sit clear of the precompiles: a 21,000-gas value transfer to 0x02 runs out of
  gas and moves nothing, which first looked like a lost credit.
  Amsterdam gas is covered only by refusal: the step does not run there.

Gate: `ci/f5-c-gate.log`. `cargo check --workspace --keep-going --tests` is clean.
n42-engine-types (270 including the new tests), n42-qmdb-reth, n42-qmdb-state and n42-testing:
471 passed, 0 failed. `clippy -p n42-engine-types --lib` is clean. `--features legacy-revm-paths`
still does not compile on v2.9.0, as before F5.

**Devnet (`ci/f5c-gate.log`, `scripts/f5c-gate.sh` in audit-notes).** Three all-Rust 300 s rounds
of `devnet-fleet.sh` on a native release build of dabac1694, under the round lock and the box gate.
Member 3 ran on its own execution layer (`LATE_VALIDATOR=3`), so a second EL re-executed every block
the first one built, and the other way round. Two `send_tx` senders ran at 2 tx/s each (1,002
transactions, 0 rejected).

| round | knobs | blocks main = late | blocks with txs | parallel / no-candidates (main + late EL) | batches | fold refused / rebuilds | EL ERROR / WARN |
| --- | --- | --- | --- | --- | --- | --- | --- |
| f5c-par | `PARALLEL_BUILD=1 THREADS=8 FREEZE_POOL=own PLAN_AHEAD_BODY=1` | 100 / 100 same hash | 82 | 64 + 18 / 13 + 5 | 1 each | 0 / 0 | 0 / 6, 0 / 5 |
| f5c-par2 | the same + `BUILD_BATCHES=2` | 100 / 100 same hash | 84 | 64 + 20 / 13 + 3 | 2 each | 0 / 0 | 0 / 6, 0 / 5 |
| f5c-ser | none | 100 / 100 same hash | 85 | (no step) | - | - | 0 / 6, 0 / 5 |

- Every block with transactions went parallel. The others had no candidates.
- The WARN lines are the same in all three rounds and all start-up notes (global thread pool,
  `N42_BUILT_KEEP`, the orchestrator's idle branch). Nothing came from `n42::graft` or
  `n42::parallel_build`.
- Consensus looked the same with and without the step: 98 commits and 4 view timeouts on members
  0-2, 93 commits on the late member.
- At devnet load, two senders make two groups. The default dispatch packs them into one batch;
  f5c-par2 forces two.
- Open: the A/B against v2.8.1 waits for F5f. The equivalence on a fleet7-sized block is still
  unmeasured.

### F5d, the follower's parallel import (2026-11-05)

- **Rewritten, not renamed.** The revm-era follower paths (`execute_transfers_planned`, the build
  path, graft index/ranges/stream, partition ahead, merge behind, async frees) stay under
  `legacy-revm-paths` until F6. The evm2 import is `parallel_build::import_block` and one block in
  `bin/n42/src/follower_import.rs` under `cfg(not(legacy-revm-paths))`. It reuses the F5c pieces
  unchanged: `execute_batches`, `commit_run`, `N42BlockExecutor`'s fold at `finish`.
- **What it takes.** The block's leading plain transfers: every transaction up to the first that has
  input, an access list, blobs or authorizations, or whose sender or recipient is the beneficiary.
  0x50 (Ed25519) transfers count as plain transfers.
  - Those run in sender batches over the parent (`Dispatch::from_env`). Each batch has its own
    view of the parent (`open_parent_state`), as the revm path's groups did.
  - The block's executor then runs its pre-execution changes, the transfers' receipts (`commit_run`)
    and the rest of the block transaction by transaction (the serial tail), then `finish`, which
    folds the merge.
  - The batches now refuse a transfer that used more than 21,000 gas (`TRANSFER_GAS`). Such a
    transfer ran code at its recipient, and that code could read what another batch changed. The
    builder skips it like any refused transfer.
- **keep_cache=false, ported as `CacheScope::Only`.** On a block of transfers only, the executor's
  overlay receives just the withdrawal recipients among the batch accounts. Those are the only
  accounts the block's end reads. On a block with a serial tail every batch account is installed
  (`CacheScope::All`), because the tail may read any of them. The stale check in `fold_into` keeps
  a miss correct: it refuses, and the block is imported serially. **Measurement item for the A/B:**
  whether caching everything (as the builder does) costs or saves on the follower.
- **The refusal rule.**
  - Every `Err` (no leading transfer, a skipped transfer, partition, unsupported change, merge,
    cache conflict, a tail transaction's error, a fold refused at `finish`) leaves nothing behind.
    The same call then imports the block through the stock executor, so a step's refusal never
    rejects a payload. A block that is really invalid is refused by that serial import, with the
    stock error.
  - Blocks without transactions do not enter the step.
  - Counters: `parallel_build::imports_parallel()`, `imports_refused()`,
    `graft_fold::refused_count()`.
- **One line per import** (target `n42::parallel_import`, info). An import that went parallel logs
  `parallel=true`, `txs`, `tail`, `batches`, `accounts`, `cached`, `batches_us` and `finish_us`. A
  refused one logs `parallel=false` and `refused=<reason>`. Both carry the three counters.
- **Knobs.**
  - `N42_FOLLOWER_PARALLEL` is ported.
  - `N42_FOLLOWER_GRAFT`, `N42_FOLLOWER_BATCH_STATE` and `N42_FOLLOWER_SENDER_GROUPS` are subsumed:
    the evm2 import always groups by sender, runs batch states and folds. All four are dropped from
    `KNOBS`.
  - `N42_FOLLOWER_BUILD_PATH` and `N42_FOLLOWER_PARTITION_AHEAD` now read off on evm2 (their
    getters check `LEGACY_REVM_PATHS`), so `by_ref_road`, `keys_ahead` and the build path never
    start there. They stay in `KNOBS`, as do `FOLLOWER_GRAFT_{INDEX,RANGES,STREAM}`,
    `FOLLOWER_PARTITION_HASH`, `FOLLOWER_FREE_ASYNC` and `FOLLOWER_MERGE_BEHIND`. Each is a
    revm-era refinement with nothing to act on in the evm2 import; port one only if the A/B points
    at its phase.
- **Tests (5 new).** `parallel_build` (4):
  - a mixed block equals the stock import (`executor().execute`) in receipts, gas, bundle state,
    reverts, contracts, receipts root and the QMDB root of the bundle. The block has batched
    transfers with shared recipients, a created recipient and a 0x50 sender, then a serial tail
    that opens with a storage-writing contract call: after it a batch recipient spends, a batch
    sender sends again, the created account spends, and a transfer pays the beneficiary. Two
    withdrawals follow, one to a batch recipient;
  - leading transfers that spend in-block credits. A recipient with a parent balance of its own
    spends on the batches' view, and the merge adds the credit to the debit, equal to the stock
    import. An account the block creates has nothing on that view, so its spend is skipped and
    the block is refused (imported serially);
  - a block of transfers only caches just the withdrawal recipients and gives the same result;
  - the fallback: a fold made to refuse at `finish` refuses the import and is counted, and the
    serial import is the stock one; a block that opens with a contract call, and a transfer to a
    contract (skipped by the gas check), are refused.

  `payload` (1): a block built by the F5c parallel builder and imported by the F5d parallel
  follower equals its serial import: receipts, gas (and the header's gas), bundle, reverts,
  contracts and QMDB root. This is "build path = follower path = serial", the legacy tree's test.

Gate: `ci/f5-d-gate.log`. `cargo check --workspace --keep-going --tests` is clean in the touched
files; the one warning left is the existing unused `Header` import in `engine_ext_tests.rs`.
Clippy is clean on `-p n42-engine-types -p n42 --lib --bins`. n42-engine-types (275), n42-qmdb-reth,
n42-qmdb-state and n42-testing: 476 passed, 0 failed.

**Devnet (`ci/f5d-gate.log`, `scripts/f5d-gate.sh` in audit-notes).** 300 s rounds of
`devnet-fleet.sh` on a native release build of 9a4200b10, under the round lock and the box gate,
with the F5c load: two `send_tx` senders at 2 tx/s, 1,002 transactions. One member ran on its own
execution layer (`LATE_VALIDATOR`), so a second EL imported every block.
- The follower import runs only behind the raw payload channel (`N42_PAYLOAD_SERVE`, with
  `N42_FOLLOWER_DIRECT_IMPORT=1`). The devnet had no channel, so `DEVNET_PAYLOAD_SERVE=1` was added
  to `devnet-fleet.sh` (main EL on 18571, the late EL on 18581).
- Every round, the control included, ran with the channel and direct import, so in the control the
  same path imports serially.
- A first f5d-par without the channel never reached the step and was stopped.

| round | knobs | blocks main = late | parallel imports (main + late EL) | refused / fold refused | builder steps (main + late) | EL ERROR |
| --- | --- | --- | --- | --- | --- | --- |
| f5d-par | `FOLLOWER_PARALLEL=1` + F5c builder knobs | 100 / 100 same hash | 155 + 64 | 0 / 0 | 64 + 9 parallel, 0 rebuilds | 0, 0 |
| f5d-ser | none (direct import, serial) | 100 / 100 same hash | (no step; 77 direct imports on the late EL) | - | - | 0, 0 |
| f5d-gov5b | `FOLLOWER_PARALLEL=1`, `--gov5`, `LATE_VALIDATOR=2` | 131 / 131 same hash, gov5 head hash equal | 115 + 58 | 0 / 0 | - | 0, 0 |

- Every block with transactions went parallel: 1 batch each, `tail=0`, since every devnet
  transaction is a plain transfer.
- The main EL counts above its 73-85 distinct blocks because several validators share it and each
  hands it the same block (no `N42_IMPORT_ONCE`).
- The WARN lines are the engine loop's idle-branch notes, in every round.
- gov5 (`gov5-wt-mvdev8282`) sealed 33 blocks, committed 162, logged 0 errors, and its block 129
  hash equals reth's.
- The first f5d-gov5 sent all load to the Rust EL, so all 33 gov5 blocks were empty. f5d-gov5b put
  the second sender on gov5's RPC (28545). Only 3 gov5-sealed blocks then carried transactions (13
  of them): gov5 gossips its pool to the Rust members, whose leaders included most of the load
  first. All 3 went through the parallel import on both ELs with equal hashes.
- Open: the A/B against v2.8.1 waits for F5f. No devnet block had a serial tail or more than one
  batch; those shapes are covered only by the unit tests.

### F5e, the X22 knobs on evm2 (2026-11-05)

The rule (coordinator, 2026-11-05): the A/B runs the X22 profile (`crates/n42/env/src/profile.rs`),
so before F5f only the knobs X22 sets have to work on evm2. Everything else in
`legacy_paths::KNOBS` stays under `legacy-revm-paths`, and the A/B decides whether to port it.

- **X22 knobs that were still legacy-listed:**
  - `N42_FOLLOWER_BUILD_PATH`, `N42_FOLLOWER_PARTITION_AHEAD`, `N42_FOLLOWER_PARTITION_HASH`,
    `N42_FOLLOWER_FREE_ASYNC` and `N42_BUILD_COLLECT_IN_PLACE` are decided below.
  - `N42_PLAN_AHEAD` and `N42_PLAN_AHEAD_WAIT_MS` are not legacy: they live in the transaction
    queue's frame selection (`n42_tx_queue::plan_ahead`), which has no EVM in it, so they run on
    evm2 unchanged.
- **The partition ahead, ported.** `parallel_build::plan_import` makes the block's `ImportPlan`:
  the leading transfers' (sender, recipient) and their partition by sender.
  - With `N42_FOLLOWER_PARTITION_AHEAD=1`, `follower_import` spawns it on the worker pool once the
    block is known, and the execution takes it just before the gate.
  - `import_block` takes `Option<ImportPlan>`. A missing plan, or one made for another fee
    recipient, is made inside.
  - The per-import line gains `planned` and `plan_wait_us`.
- **The frees off the import thread, ported.** With `N42_FOLLOWER_FREE_ASYNC=1`, the import's keys
  and partition (now handed back in `ParallelRun::groups`) are dropped on the worker pool.
  - The batches' merge is consumed by the fold at `finish`, so it is not part of this.
  - The revm-era transaction environments do not exist on evm2.

| knob | state on evm2 | why |
| --- | --- | --- |
| `N42_FOLLOWER_PARALLEL` | ported (F5d) | `parallel_build::import_block` |
| `N42_FOLLOWER_GRAFT`, `N42_FOLLOWER_BATCH_STATE`, `N42_FOLLOWER_SENDER_GROUPS` | subsumed (F5d) | the evm2 import always groups by sender, runs batch states and folds |
| `N42_FOLLOWER_BUILD_PATH` | subsumed | the follower's parallel import is `import_block`, the builder's batches and fold; the getter reads off on evm2 |
| `N42_BUILD_COLLECT_IN_PLACE` | subsumed | the evm2 builder step collects per batch and has no slots |
| `N42_FOLLOWER_PARTITION_AHEAD` | ported | `plan_import` on the worker pool before the gate |
| `N42_FOLLOWER_FREE_ASYNC` | ported | keys and partition freed on the worker pool |
| `N42_FOLLOWER_PARTITION_HASH` | retired | it sped up the component partition (`partition_shared`); the evm2 import partitions by sender, one map probe per sender run |
| `N42_PHASE_TIMERS` | retired | per-door read counts for the revm fast transfer; the per-build and per-import lines carry the timings the A/B reads |
| `N42_FAST_TRANSFER` | F5f | the evm2 registry handler |
| `N42_READ_SET`, `N42_BUILD_PREFETCH`, `N42_BUILD_MLP`, `N42_PLAN_AHEAD_WARM` (`warm_ahead.rs` as a whole) | legacy until the A/B | read layers over revm `State`; worth porting only if the A/B shows reads as the cost |
| `N42_GRAFT_{INDEX,RANGES,STREAM,SHARDED,BASE_SWAP,PREFAULT}`, `N42_BUILD_GRAFT_NO_CACHE` | legacy until the A/B | revm-era graft variants; the evm2 step has one merge and fold |
| `N42_FOLLOWER_GRAFT_{INDEX,RANGES,STREAM}`, `N42_FOLLOWER_MERGE_BEHIND` | legacy until the A/B | the same, on the follower |

Each row has the matching note in `docs/KNOBS.md`. The ported, subsumed and retired knobs leave
`KNOBS`, so a node started with X22 on evm2 logs no "not available on evm2" line for them.
The legacy-until-A/B ones X22 does not set.

Devnet round f5e-x22 (`ci/f5d-gate.log`, `devnet/f5e-x22`, binaries of e91c15be9): every launch
with `N42_PROFILE=x22` on the F5c/F5d load, second EL, payload channel.

- Both ELs and all four validators logged "N42_PROFILE=x22 set 100 knob(s)"; the 13 frameBlocks
  knobs (`N42_PLAN_AHEAD`, `N42_PLAN_AHEAD_WAIT_MS`, `N42_FRAME_*` ...) were withdrawn, because the
  devnet genesis has no frameBlocks, so PLAN_AHEAD is not exercised on the devnet.
- Hashes equal 28/28 on both ELs; parallel imports 39 (main EL, all 2 batches) and 12 (late EL,
  all `planned=true`); builder parallel steps 36; refused 0, fold refusals 0, serial rebuilds 0,
  EL ERROR 0; no "not available on evm2" line in any log.
- **Only 28 blocks in 300 s, 58 view timeouts per validator** (blocks of two leaders out of four time
  out: the proposal goes out with its body elided and `peers=0`, the others wait in "import-gated
  vote: waiting for execution validation" until the view ends). The control is the same round on
  main's v2.8.1 binaries that carry the profile (`wt-docs` native build of 2026-11-04, copied to
  `/data/n42-build/f5e-control`), round f5e-x22-main2: **28 blocks, 58 timeouts per validator,
  28/28 hashes**, the same picture. So it is the X22 profile on the devnet's shape (three validators
  on one EL, a genesis without frameBlocks or deferred execution), not evm2. The without-profile
  rounds read 98 blocks and 4 timeouts. (A first control, f5e-x22-main, used the 2026-10-24
  binaries, which predate `N42_PROFILE` and ran the stock configuration: void.)

### F5f, the fast transfer as an evm2 registry handler (2026-11-05)

`crates/n42/engine-types/src/fast_handler.rs`, as designed in F5a.

- **What it is.** `fast_handler::registry` re-registers transaction types 0, 1 and 2 on the
  stock registry (0x50 executes as type 2). Each prepare closure records the transaction's shape,
  then calls the stock prepare, so validation (nonce, intrinsic gas, fee, balance for the fee) is
  the stock handler's. Each execute closure tries `transfer` and falls back to the stock
  `execute_prepared`.
- **What it takes.** A call with empty input and an empty access list, on Prague or Osaka, no
  inspector, recipient not the caller, not the beneficiary (nor the caller the beneficiary), not
  a precompile, codeless, not an empty account receiving zero value, and a caller balance that
  covers the value after the fee. It moves the value with `State::transfer`, builds the Stop result
  with the stock gas tracker, and settles through `settle_initial_frame_gas` and the stock
  `settle_transaction` hooks, so refunds, the EIP-7623 floor and the fee split are the stock ones.
- **Amsterdam is refused.** `covers(spec)` is Prague and Osaka only; on Amsterdam the handler hands
  every transaction to the stock one (F6 leftover below).
- **Equivalence tests**, transaction by transaction against the stock handler (result `Debug` and
  the sorted account changes), on Prague and Osaka:
  - taken: 1559 to an existing account, 1559 creating the recipient, gas limit over the intrinsic,
    legacy, 2930 with an empty access list, 0x50, zero value to an existing account;
  - handed over (equal and not counted as hits): zero value to an empty account, a contract, a
    precompile, self, the beneficiary, with input, 2930 with an access list, value lacking after
    the fee, nonce ahead, gas limit under the intrinsic.
- **Where it runs.** The parallel build and import batches' EVMs carry it unconditionally, as the
  revm-era batches did (`fast_handler::as_batch` in `parallel_build::run_batch`);
  `N42_BATCH_FAST_TRANSFER=0` turns it off for the stock-handler data point. `N42_FAST_TRANSFER=1`
  puts it on every EVM the node makes (`TxRegistrySource::n42_tx_registry` on `RethEvmFactory`),
  and leaves `legacy_paths::KNOBS`. The per-build and per-import lines carry
  `fast_hits_total` / `fast_delegated_total`.

Gate (`ci/f5-f-gate.log`): workspace check rc 0, clippy (engine-types, n42) rc 0, tests 427 passed
and 1 failed: the qmdb-reth timing test
`a_rename_while_the_tree_is_leased_is_followed_and_tree_readers_wait_for_it` (`tree_waits >= 1`
under the gate's load; untouched code, 3/3 passing alone, `ci/f5-f-flaky.log`). The
`legacy-revm-paths` feature does not build on evm2 (reth_evm `eth`, `db`, `EvmFactory` are gone);
that is the state since F4, not new.

Devnet pair (`ci/f5d-gate.log`, `devnet/f5f-*`, binaries of 5e582b610, follower and builder knobs,
second EL, payload channel):

| round | hashes equal | imports parallel (main / late EL) | refused | builder steps | fast hits (main / late) | delegated | timeouts per validator |
| --- | --- | --- | --- | --- | --- | --- | --- |
| f5f-fast | 100/100 | 158 / 64 | 0 | 64 | 3,006 / 1,002 | 0 | 4, 4, 4, 0 |
| f5f-stock (`N42_BATCH_FAST_TRANSFER=0`) | 100/100 | 158 / 64 | 0 | 64 | 0 / 0 | 0 | 4, 4, 4, 0 |

Both rounds carried 1,002 transfers in 74 blocks, EL ERROR 0 on both ELs, fold refusals 0, serial
rebuilds 0. The main EL ran the handler 3,006 times for the 1,002 transfers (its builds plus the imports
it runs), the late EL 1,002 times; none was handed over, since the load is transfers to
existing accounts, so the hand-over path is covered by the unit tests only. Speed is the A/B's
question; the devnet carries 3-4 transfers a block.

### F5g, the X22 leader gap on evm2 (2026-11-05)

**The A/B failed.** Stage fx, tag E9, 2026-11-05 16:12-16:39Z (`wt-main/target/fleet-runs/loop351fx-E9.launch.out`;
one shared EL, import once, seven validators, the 600M replay set, 30 ms pacing):

| leg | binaries | win1 TPS | win2 | win3 | cycle |
| --- | --- | --- | --- | --- | --- |
| E9a | branch 5e582b610 | 673,333 | 640k | 673k | 0.297 s |
| E9b | branch 5e582b610 | 664k | 673k | 667k | 0.297 s |
| E90 | main 0f3cb36e7 | 4,910,033 | | | 0.040-0.041 s |
| E90b | main 0f3cb36e7 | 4,940,000 | | | 0.040-0.041 s |

A 7.3x gap, not noise: invalid_blocks=0, tc=7 and the hashes are fine on the branch, but the binding
wait is the seal on every block (299 ms). On a full block (980) the branch logs
`parallel step … txs=200000 batches=128 pull_ms=0 exec_ms=83 commit_ms=52`, then `a build did not
seal early … why="the parallel step built nothing" par_txs=0` (81 of 81 full blocks), then
`payload build phases … par_exec_ms=83 par_fold_ms=52 par_ms=151 loop_ms=154 finish_ms=116
assemble_ms=10 total_ms=297 open_layers=6 open_kept_accounts=1162067`. No `seal-first build phases`
line exists on the branch. The control's full block (1178): `seal-first build phases … par_ms=37
par_exec_ms=27 par_fold_ms=3 direct_receipts=true tx_root_ms=1 sealed_at_ms=34 state_ready_ms=56
roots_ms=29 merge_ms=0`.

**Root cause, plainly.** F5e checked that every knob X22 sets is recognised on evm2. It did not port
the code those knobs select. The X22 leader pipeline is the revm-era step in `payload.rs` (the
`#[cfg(feature = "legacy-revm-paths")]` block: seal at the execution's end, the body ahead, direct
receipts, the output shards' freeze, shard mix and live-index defer, the fields at the seal, root
ops ahead, fused receipts), plus the legacy parts of `output_shards.rs` and `direct_build.rs`. The
evm2 step (F5c) executes and folds and pushes the block's transactions into the builder, but it never
set `par_txs`. The early-seal gate (`no_seal_why`) therefore read every block as "the parallel step
built nothing", and every block sealed only after the whole ordinary finish: 83 ms of execution,
52 ms of fold, 116 ms of finish. F5e's devnet round could not show this, because the devnet genesis
has no deferred execution and so no early seal at all.

#### g1, the early seal on evm2 (bc280fba2)

- **The gate's inputs.** The evm2 step sets `par_txs` and `par_groups` when its commit succeeds, so
  `no_seal_why`, the `a build did not seal early` line and the phases lines see what it built.
  Without `N42_SEAL_AT_EXEC` a full block now seals at the gate, after the fold but before the
  finish.
- **Seal before the fold** (`N42_SEAL_AT_EXEC=1`, which X22 sets). The seal happens right after the
  batches when all of these hold: the conditions behind `seal_early_possible`, no blobs, at least one
  transfer executed, and the block full on the batches' own gas (`gas_left < 21,000`, the queue
  drained, or within `seal_shortfall`). The gate below uses the same test. In that order:
  - the transactions go into the builder and the fees are credited;
  - the lookahead goes back to the queue and the puller is dropped, as on the revm-era step;
  - `seal_block!` computes the transactions root (the frame tree on a frameBlocks chain), takes the
    parent's carried fields and hands the payload to the `EarlySeal` hook;
  - the frames' bulk vector, when it was executed whole, is noted as the build's whole take.
- **Behind the proposal.** `commit_run` (the cache half and the receipts), the fold at `finish`, and
  the finish itself all run after the proposal goes out.
  - A block sealed this way installs only the withdrawal recipients in the executor's cache
    (`CacheScope::Only`, the follower's rule for a block without a serial tail). After the batches
    only the block's end runs, and it reads no batch account.
  - Any refusal from `commit_run` after the seal returns `failed_after_seal`, which tells the store's
    waiters and logs at error level. A refusal at the finish already failed loudly on this path. A
    block sealed early is never rebuilt serially into a different block.

Per-step cost of a 200,000-transfer block on evm2 (`parallel_build::tests::evm2_step_bound`,
release, 4 rounds, medians, `ci/f5g1-bench.log`). The shape is the replay set's: 400 senders of 500,
recipients drawn from 2,000,000, ~190,800 accounts touched. The parent is an in-memory map, so the
reads are a lower bound on the node's.

| threads | exec | tx root (MPT) | commit, cache All | commit, cache Only | finish (fold, block end) |
| --- | --- | --- | --- | --- | --- |
| 32 | 92.1 ms | 45.7 ms | 42.9 ms | 12.6 ms | 94.3 ms |
| 16 | 100.7 ms | 43.8 ms | 42.2 ms | 14.0 ms | 94.2 ms |

- **Execution is not a read cost.** The batches take 92 ms with every read from memory, against
  83 ms on the fleet. That is g2's target: the evm2 per-transaction work, not the state stack.
- **The tx root on the fleet is not this MPT.** fleet7's genesis has frameBlocks, so the seal takes
  the frame tree over the known frame layout; the control logs `tx_root_ms=1`. The MPT figure applies
  only to a chain without frames.
- **What moves.** The seal now waits only for exec plus the root. The commit (12.6 ms with the narrow
  cache instead of 42.9) and the finish (94 ms) run behind the proposal and become the next build's
  state wait: g3 and g4.
- **Expected leader cycle.** About pull + exec + seal: 83 ms of execution on the fleet plus a few ms
  of frame root and the carried fields, against 297 ms in E9. The fleet number is the fx pair's
  (E10).

Gate (`ci/f5g1-gate.log`): workspace check rc 0, clippy (engine-types, n42) rc 0, tests rc 0 with
503 passed. The natives for E10 are in `/data/n42-build/reth29-native/release`, built from 2d687b583
with `RUSTFLAGS="-C target-cpu=native"` as `branch-natives.sh` builds. The cargo build itself took
1 min 36 s; with the box queue it took 6 min 10 s.
**E9's branch binaries were built without `target-cpu=native`**, while main's natives had it. That is
a confound, although it cannot explain a 7.3x gap.

Devnet check of the seal path (`ci/f5d-gate.log`, `devnet/f5g1-*`):
- **The devnet genesis cannot reach the seal path as it ships.** It has no deferred execution
  (`audit-notes/devnet/n42_devnet_deferred.json` adds `deferredExecutionTime: 0`), round-robin
  leaders give no build on an own block (`hotstuff.leaderTenure: 8` added), and the own-block
  build needs the fleet's `N42_HASHED_TABLES=off`.
- **f5g1-x22b** (that genesis, X22 plus the fleet's state knobs): hashes equal 18/18 on both ELs,
  imports parallel 18 and 8, fold refusals 0, serial rebuilds 0.
  - One early-sealed block's finish failed loudly: block 19 was built ahead on the leader's own block
    18 after a foreign empty block 19 had already been committed. The QMDB stale-parent refusal is the
    right outcome there; the error line and `failed_after_seal` fired, and the chain was not affected.
  - The run had X22's devnet timeouts (40 per validator, as in f5e-x22).
  - The seal-first phases line prints only for blocks of 1,000 transactions or more, so the devnet
    shows no count of early seals.
- **f5g1-seal2** (deferred, tenure 8, seal-at-exec, no X22) stalled at block 1. It was a start-up race:
  validator 0 proposed block 1 before the others were up, its own block became the EL's canonical
  head, and every later build on genesis was refused as stale. All builds in it were empty
  (`no-candidates`), so the evm2 seal path never ran. This is not a g1 effect; it is noted for the
  devnet's deferred start-up.

#### E10, and the order after it

The fx pair E10 (18:06-18:29Z, natives of 2d687b583, `wt-main/target/fleet-runs/loop351fx-E10.launch.out`)
read 1.06-1.08M TPS at a 0.185 s cycle on the branch, against the control's 4.9M at 0.041 s: a 4.6x
gap, down from 7.3x. Medians per full block, branch against control (ms): state_wait 71 / 2, par_exec
67 / 27, par_fold 14 / 2, tx_root 26 / 2, give_back 16 / 0, sealed 26 / 3, sealed_at 182 / 37,
merge 61 / 0. The coordinator's order: the merge (and with it state_wait), then exec, then the
transactions root, the seal's body, the give-back.

#### g3, the output shards on the evm2 step (merge elided, state_wait)

**Why `merge_elide()` did nothing on evm2.** Merge elision acts on the output shards: the next
build reads a block that is still in its shards, under the executor's residual
(`built_executions::shards_ready` with a `ShardedParent`), the roots read `shards.view(residual)`,
and the block's one bundle is merged behind them or not at all. The evm2 step never made shards.
Every batch bundle was merged into one map (`merge_batches`), and that map was folded into the
executor's bundle in `finish` (`graft_fold::fold_into`, 190,000 accounts). That fold is E10's
`merge` 61 ms, and the next build's `state_wait` 71 ms waited for it.

**The change.**
- `execute_batches_into` hands each batch's bundle to a sink on the batch's own thread, which is
  `OutputShards::add`. It first splits off the accounts the executor still needs: the beneficiary,
  whose credits from every batch the finish sums, and the withdrawal recipients, which the block's
  end reads. Those few stay in the run's `merged` and take the old fold, so nothing reads the shards
  before they are frozen.
- On a block that seals at the execution's end, the evm2 step now:
  - freezes the shards behind the seal, on their own thread under X22's `N42_FREEZE_AFTER_SEAL`
    (joined where the seal branch files the residual, the revm-era join);
  - writes only the split-off accounts into the executor's cache (`CacheScope::Only`);
  - hands the frozen shards to the existing `output_shards` path. That path (`shards_ready`, the
    roots on the view, `N42_MERGE_ELIDE`) is the control's code, which was already compiled on
    evm2.
- A block that took the shard path but did not seal merges the shards back into one bundle, with
  the split-off bundles, and runs the old path.
- `sharded_total` on the `parallel step` line counts the sealed runs whose output stayed in shards.

**Bench** (`evm2_step_bound`, 200,000 transfers, 400 senders, recipients from 2,000,000 so ~190,700
accounts, in-memory parent, 32 threads, release, medians of 4). Both legs are on a Prague chain
(below). The shard leg checks that the shards merged under the finish's residual give the fold
path's bundle, account by account and revert by revert. That check passes in plain and index mode.

| path | exec | freeze | commit | finish (fold) |
| --- | --- | --- | --- | --- |
| before: merge, fold at finish | 97.7 ms | | 41.8 (All) / 11.4 (Only) | 94.1 ms |
| shards, plain (16) | 15.5 ms | 42.8 ms | 11.6 ms | 0.0 ms |
| shards, X22 (16, index, live index, own pool) | 29.4 ms | 4.2 ms | 10.8 ms | 0.2 ms |

(`ci/f5g3-bench1.log`, `ci/f5g3-bench2.log`, `ci/f5g2-split2.log`.) The 94 ms fold is gone from the
finish. What the next build waits for is the freeze, 4.2 ms behind the seal under X22. The fleet's
`merge` 61 and `state_wait` 71 should fall to the control's few ms. That is to be read in E11.

Gate for bcb193399 (`ci/f5g3-gate.log`, `ci/f5g3-gate2.log`):
- workspace check rc 0 and clippy (engine-types, n42, with tests) rc 0;
- engine-types: 278 passed, 8 ignored;
- `n42-qmdb-reth`: one failure under a box load of 113,
  `a_rename_while_the_tree_is_leased_is_followed_and_tree_readers_wait_for_it`. It is a 100 ms
  sleep race on the waiter, in a crate this change does not touch, and it passes alone;
- qmdb-state, n42-testing and n42-env pass.

Devnet round **f5g3-x22** (`ci/f5d-gate.log`, `devnet/f5g3-x22`) ran on the E11 natives, with the
deferred genesis (tenure 8), X22 and the fleet's state knobs:
- hashes equal 40/40 on both execution layers;
- imports parallel 38 and 18, fold refusals 0, serial rebuilds 0;
- `sharded_total` 16 on the main EL and 7 on the late one: early-sealed blocks whose output stayed
  in the shards and that the next build read through the sharded parent;
- one `failed_after_seal`, the stale-parent refusal g1 also showed (a build ahead on block 40 after
  41 was canonical). The chain was not affected.

Natives for E11: `/data/n42-build/reth29-native/release`, built from bcb193399 with
`RUSTFLAGS="-C target-cpu=native"` (`ci/f5g3-natives.log`).

#### g2, the execution: where a transfer goes

**"exec" held the merge.** The step's exec time included `merge_batches`, the 190,000-account
merge of the batch bundles. On the shard path that merge is gone: exec is 97.7 -> 29.4 ms with
X22's live index, or 15.5 ms without it. E10's fleet number for the same span is 67 ms (with
QMDB reads); the bench, from memory, gives 97.7 before and 29.4 after.

**The bench chain was Shanghai.** The fast transfer handler is registered only from Prague
(`fast_handler::covers`), so the earlier bench numbers were without it. The timing tests now run
on Prague (`F5G_SPEC=shanghai` for the old chain); the fleet chain is Osaka from genesis.

**One transfer** (`evm2_batch_split`, one batch of 20,000 transfers on one thread, Prague, release,
ns per transfer, `ci/f5g2-split3.log`):

| part | fast handler | stock handler | fast, inherent API |
| --- | --- | --- | --- |
| `convert` (pooled tx clone, envelope) | 55-62 | 54 | 55 |
| evm2 `transact` (reth trait: detach) | 632-655 | 667-678 | 606-610 (inherent) |
| `BatchState::commit` | 270-319 | 282-288 | 277-285 |
| `commit_state` / `commit()` | 108-165 | 108-156 | 145-146 |
| result push | 28-49 | 28 | 29 |
| whole loop | 1,155-1,305 | 1,198-1,248 | 1,156-1,160 |

Per batch, on top: `take_bundle` 5.2-6.2 ms and the old `merge` 8.7-9.2 ms per 20,000
transfers (~0.27 and ~0.44 us a transfer). The merge is the part the shards removed.

- The fast handler saves ~30 ns of the ~650 ns in `transact`. The handler skips the
  interpreter, but the rest of the transaction is still evm2's: the stock `prepare`, the
  transaction overlay over the batch's accepted overlay and `CacheDB`, the gas settlement and the
  scratch clear.
- The inherent `transact` + `account_changes()` + `commit()` (no owned `PendingState`) is no
  faster in total. It moves cost from the detach into the commit.
- So the remaining per-transfer cost (~1.15 us of thread time, about 60% of it `transact`) is
  inside evm2's transaction and overlay layers. Only bypassing evm2's transaction state for the
  batch would cut it further, and that is a design decision. With the merge gone, the step is
  within the ~30 ms target in the bench, so no change was made there for now.

#### E11, after g3

The fx pair E11 (19:35-20:00Z, natives of bcb193399 against main, `wt-main/target/fleet-runs/loop351fx-E11.launch.out`,
legs `strip-loop351D2S12P30T64X11T16E11{a,0,b,0b}MEMF`):
- **Throughput.** The branch read 2,100,000 / 2,140,000 TPS (E11a / E11b) at a 0.093-0.095 s cycle,
  against the control's 4,873,333 / 4,993,333. The gap is 2.3x, down from 4.6x.
- **Health.** `sharded_total` 989: every full block took the shard path. Fold refusals 0, serial
  rebuilds 0, invalid 0, tc 7.

Medians (E11a), branch against control, ms:

| state_wait | par_exec | par_fold | tx_root | give_back | sealed | sealed_at | merge | state_ready | roots | finish |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 13 / 2 | 26 / 27 | 16 (behind the seal) | 30 / 2 | 21 / 0 | 30 / 3 | 92 / 37 | 0 / 0 | 25 / 81 | 21 / 29 | 25 / 100 |

- **Exec is at parity.** par_exec is 26 against 27, so the evm2 per-transfer cost does not bind on
  the fleet. No journal bypass.
- **The rest of the gap is the seal.** The transactions root (30), the seal (30) and the give-back
  (21) make up 81 of the 92 ms to the seal. The target after items 3-5 is a sealed_at of about
  35-40.

#### g4, the seal: transactions root, body, give-back (items 3-5)

**Items 3-4, the root and the body ahead.**
- On evm2 the plan-ahead hook (`make_prepared_build`, `N42_PLAN_AHEAD_BODY`) made only the keys,
  the hashes and the partition. The evm2 seal then:
  - cloned each executed transaction into the builder one by one (`to_consensus`);
  - split them into transactions and senders serially at the seal;
  - collected the 200,000 hashes again;
  - found the frame layout and root there.
  That is E10's tx_root 26 and sealed 26.
- The hook now makes what the control's makes, on the plan body's own pool: the transactions,
  their senders and, under `N42_PLAN_AHEAD_PARTS=1` with frame blocks, the frame layout and root of
  the hashes on that plan (`frame_blocks::root_ahead`).
- At the seal the evm2 step takes that body when the block is every candidate in pull order and the
  plan's hashes are the pulled set's (`body_matches_pull`: length plus first, middle and last
  hash). The seal then carries the root (`seal_root_carried`), so `seal_hashes_ahead`,
  `seal_root_ahead` and `commit_body_ahead_used` read true on the phases line.
- Otherwise (no plan, a different set, a skipped transfer) the body, senders and hashes are made
  from the executed candidates on the build pool in one pass. The seal then finds the frame root
  over those hashes, as before.
- A chain without frame blocks keeps the MPT root at the seal. The bench's 45 ms MPT root is that
  case; the fleet seals frame roots.

Code: d66e939ea (item 4, the body ahead) and 698091538 (item 3, the root carried).

Bench (`evm2_step_bound`, `ci/f5g4-bench1.log`, 200,000 transfers, 32 threads, medians of 4): the
seal-side body (transactions, senders, hashes) takes 48.4 ms as the evm2 seal made it (a clone into
the builder per transaction, the serial split and the hash collect), against 3.1 ms on the build
pool (the fallback). On the plan path it is a move at the seal.

The frame root carried from the hook is the control's mechanism (its tx_root is 2 ms on the fleet).
The bench has no frame plan, so the fleet number for it comes from E12. The rest of the bench is
unchanged: shard exec 29.6 ms, freeze 3.2 ms, finish 0.2 ms.

**Item 5, the give-back.**
- What runs before the seal:
  - the lookahead's return: each transaction beyond the budget is sent back to the puller as a
    refusal;
  - the puller's drop: stop, drop the receiver, join the thread. The thread applies the refusals
    and, as it ends, the pool walk gives back what it took.
- Both have to be complete before the seal. The chained build pulls at the seal, and loop232/233
  found its lanes holed both when the lookahead was still checked out and when the puller's walk
  was still ending. So neither part moves behind the seal.
- The phases line now times them apart (`seal_lookahead_us`, `seal_puller_join_us`).
- What did change is when they start. With `N42_PULLER_STOP_AT_PULL` (default on; `0` restores the
  old order), a full pull on a block that can seal at the execution's end returns the lookahead and
  stops the puller right after the pull (`Puller::stop`: done flag and receiver, no join). The
  walk's wind-down then runs beside the batches, and the seal keeps only the join, which by then
  should be ~0.
  - A block that afterwards does not seal (a skipped transfer) builds on without the lookahead and
    the walk. It is a slightly emptier block, never a lost transaction: the given-back
    transactions are back in the queue.
  - `puller_stopped_at_pull` on the phases line says which order ran.

Code: 20df09470. There is no bench for this one: the 21 ms is the pool walk's wind-down under the
fleet's ingest. E12's `seal_lookahead_us` / `seal_puller_join_us` say which part it was and
whether the stop at the pull took it off the seal's path. On the devnet, blocks are never full at
the pull, so the stop does not engage there.

Gate for d66e939ea, 698091538 and 20df09470 (`ci/f5g4-gate.log`): workspace check rc 0, clippy
(engine-types, n42, with tests) rc 0, and tests rc 0 with `--no-fail-fast` (engine-types 278,
qmdb-reth 126 and the rest).

Natives for E12: `/data/n42-build/reth29-native/release`, built from 20df09470 with
`RUSTFLAGS="-C target-cpu=native"` (`ci/f5g4-natives.log`).

Devnet round **f5g4-x22** (`ci/f5d-gate.log`, `devnet/f5g4-x22`) ran on those natives, with the
g3 shape:
- hashes equal 18/18 on both execution layers;
- imports parallel 18 and 8, fold refusals 0, serial rebuilds 0;
- `sharded_total` 8 + 3.

It went only to height 19 in 300 s, as g1's f5g1-x22b did (height 19, commits 18). The cause is
older than items 3-5:
- Validator 0, leading an 8-view tenure, proposed a block 19 built ahead on its own block 18.
- Its execution layer's finish behind the seal refused that block as a stale parent, because
  another block 19 was already head there.
- The EL then no longer held own block 19, and every remaining view of the tenure logged
  `could not build a block to propose err=missing payload`, timing out at 24-30 s each. The run
  ended inside that tenure.

This is a recovery gap in the validator after a `failed_after_seal`: it keeps asking for a build on
the sealed own block instead of falling back to the committed head. It shows on the devnet's
start-up fork, not on the fleet (E11: tc 7, no stall). It is noted for the coordinator and not
fixed here.

#### E12, after g4

The fx pair E12 (20:35-20:49Z, natives of 648c03ba4 against main,
`/data/blockchain/rust-fleet7-bench/bench-loop351D2S12P30T64X11T16E12{a,0}MEMF`, runner log
`ci/pairs-queue.log`) ran one pair only: the runner's body gate stopped on the control leg
(`proposals_given_up=3`, a teardown artifact).
- **Throughput.** The branch read 2,846,133 TPS at a 0.070 s cycle, against the control's 4,833,333
  (0.041 s). The gap is 1.7x, down from 2.3x.
- **Items 3-5 did their job.** tx_root 30 -> 3, sealed 30 -> 3, give_back 21 -> 2 (E11 -> E12).
- **What is left.** sealed_at 63-67 against 37, and the next build's `state_wait` 11-14 ms on the
  parent's `output` (control ~2): the branch filed its shards at seal + 15-22 ms
  (`seal_to_shards_ready_us`), the control at seal + 2.4-3.8 ms. The plan body was never taken
  (`commit_body_ahead_used=false` on every build).

#### g5, the tenure stall after a timed-out view (F5g5)

**What happened** (f5g4-x22, validator 0's log and its execution layer's, 20:29:52-20:33Z):
1. At view 31 (leader 3) validator 0 checked and voted for block 19 `0x38da…`. As the next leader
   it at once asked its execution layer for a build ahead on that block. That build's forkchoice
   made `0x38da…` canonical, although it had no QC.
2. View 31 timed out, and the TC sent view 32 to validator 0 on its high-QC block 18 `0xeae…`.
3. The block it built ahead on 18 was refused at the finish as a stale parent, "below the
   canonical head 19". Every later build of the tenure on 18 was refused the same way. The
   validator logged `could not build a block to propose err=missing payload` and each view timed
   out at 24-30 s.

So the parent was right: the driver builds on the high-QC block, as it must. The refusal came from
the QMDB stale-build guard (`QmdbForest::check_build_parent`, 5d9fa0349, loop351 X9j). That guard
measures "stale" against the canonical head, and the canonical head had run ahead of consensus onto
an uncertified block. reth itself builds on a canonical ancestor at or above the finalized block;
the guard was the only obstacle.

**The fix.**
- The guard gets the committed block's number (`QmdbNodeState::set_committed_source`,
  `QmdbForest::check_build_parent_above`). A parent at or above the committed block is not
  refused, even when the canonical head is past it. A parent below it is still refused, which is
  the X9j case: a build ahead on 1020 after 1021 was committed.
- bin/n42 gives the committed number as the forkchoice's `safe` plus the deferred-execution depth.
  Under the default `split` settlement tags, `safe` is the block whose execution a committed child
  carries.
- Under `legacy` tags `safe` is the committed block itself, so the floor is one block stricter.
  The guard then refuses exactly what it refused before, never more.
- With no source, or a source that does not know the safe block, the guard behaves as before.

**Main has it too** (f5g5-main, 20:58-21:03Z, main 0f3cb36e7's natives from
`/data/n42-build/wt-docs/target/native/release`, the same deferred genesis and X22 profile,
`/data/n42-build/audit-notes/devnet/f5g5-main`). The chain stopped at height 19 (the late member at 18,
blocks 1-18 identical). The execution layer logged the same refusal at 20:59:50Z: "the finish behind
the seal FAILED number=19 err=refused a build on block 18 (0x7ee6…): it is below the canonical head
19 (persisted 12), a stale parent". Validator 0 then logged `could not build a block to propose
err=missing payload` seven times, for views 33 onward. 40 timeouts in 300 s. So the stall predates
the port: it comes with the stale guard (5d9fa0349), which main carries. The fix is made on this
branch, and main gets it with the F6 merge. It is listed under the F6 leftovers below until then.

**The fix round** (f5g5-fix, 21:40-21:45Z, branch natives of f7fa91058, the same genesis, profile and
knobs, `devnet/f5g5-fix`):
- Height 57, against main's 19. The late member is also at 57, blocks 1-57 are identical, and 1002
  transactions landed in 33 blocks.
- Execution-layer errors 0, `after_seal_failed` 0, and no `could not build a block to propose` on any
  validator.
- The start-up fork still happens, and so do the forks after it. 33 times a canonical block was
  replaced at its height, by a build ahead on an uncertified block followed by the certified one:
  block 1 at 21:40:55Z after the view-1 TC, block 11 twice (21:41:37Z, 21:41:49Z), and others. The
  build on the high-QC parent below the head was never refused.
- 68 timeouts in 300 s, against main's 40 in a run that stopped at 19. This is the devnet's usual
  leader rotation with idle validators.

#### g6, the plan body on evm2 (F5g6)

**Why it never ran.** `frame_blocks::plan_ahead_body_wanted` opened only when the revm-era paths
were built (`LEGACY_REVM_PATHS`) and the block sealed on its counters. On the stock evm2 build that
gate was always closed, so the queue's plan-ahead hook was never installed, `take_prepared_body`
found nothing, and every E12 build fell back to the body made at the seal (F5g4's 3-5 ms on the
build pool) plus the keys made serially before the batches. The gate is now
`plan_body_gate(legacy, seal_on_counters, body, plan_ahead, by_frames)`: on evm2 it needs only the
knobs (`N42_PLAN_AHEAD_BODY`, plan-ahead, pull by frames), all set by X22. Unit test
`the_plan_body_gate_opens_on_evm2_without_the_counted_seal`.

**Why the puller stop did not show.** On the fleet the build takes the frames' bulk vector, and a
bulk take has no puller (`best_txs` stays on the build thread when `bulk.is_some()`), so there was
nothing to stop. The phases field is now `puller_at_pull` = `stopped` (stopped at the pull),
`kept` (a puller, stopped at the seal) or `none` (the bulk take or the direct iterator); E13
should read `none` on full blocks.

**Cost** (`plan_body_prep_bound`, release, 200,000 0x50 transfers from 400 senders, medians of 5):
- the hook on the plan body's pool, off the build: 11.4 ms;
- what the build did inline without it: keys 8.4 ms (serial, before the batches), partition 0.8 ms,
  body 4.7 ms (at the seal, on the build pool), about 13.9 ms on the build's path.
With the gate open, a block that is its plan's whole take reads all of these from the plan
(`commit_body_ahead_used=true`, `par_prep_ms` 0). The devnet never fills, so the fields flipping are
for E13.

#### g7, the shards filed at the finish's end, the receipts behind it (F5g7)

**What the child waited on.** On the evm2 shard path the seal is followed by the freeze (on its
own thread, `freeze_late=true`), then `commit_run`, then the executor's finish, and only then are
the shards filed (`shards_ready`). `commit_run` committed the 200,000 receipts one by one through
the executor (`commit_transaction` with an empty write set), 11.9 ms on the bench
(`evm2_step_bound`, shard path `commit_ms`) and the whole of the E12 `par_fold_ms` 14-21 and
`seal_to_shards_ready` 15-22. The finish itself, the block's end alone, is 0.2 ms.

**What the child reads before the parent's finish.** Its open reads the frozen shards and the
residual. The residual is the executor's bundle after the finish: the beneficiary's summed credit
and the withdrawal recipients (both split off the batches' bundles into the run's small `merged`
and folded at the finish), plus the post-block system calls' and the withdrawals' own writes. Those
last two exist only after the finish, so a residual filed before the finish would be incomplete.
The fix keeps the filing after the finish and takes the receipts off the path in front of it.

**The fix** (`N42_EVM2_RECEIPTS_LATE`, default on, `0` restores the commit):
- On a block sealed at the execution's end with its output in shards, and with nothing committed
  before the step, `commit_run` gets no results (the cache half and the pending fold only).
- The receipts are built on a thread (`parallel_build::late_receipts`, 5.3 ms off the path on the
  bench) and joined where they are first read: the receipts root beside the QMDB root, as
  `N42_SHARDS_BEFORE_RECEIPTS` does on the revm-era step. `receipts_late=true` in the phases line.
- The finish reads no receipt it would miss: transfers have no logs, so the deposit requests are
  empty either way, and `gas_used` is replaced by the late receipts' total at the join.
- Bench: commit + finish before the filing 12.1 -> 0.0 ms. Expected on the fleet:
  `seal_to_shards_ready` about 2-3 ms and `state_wait` near the control's 2.

**Equivalence.** `the_late_receipts_equal_the_committed_ones` (unit test): receipts, gas, requests,
bundle and reverts equal the sequential execution's. `evm2_step_bound` keeps its shard-path check
(the shards under the residual equal the fold path's bundle) and adds a late leg: the late receipts
equal the committed ones, gas and requests equal, and the shards under the late residual equal the
committed residual's.

#### E13, after g6-g7

The fx pairs E13 (21:48-22:14Z, natives f7fa91058 against main, two pairs,
`wt-main/target/fleet-runs/strip-loop351D2S12P30T64X11T16E13{a,0,b,0b}MEMF/el.log`):
- **Throughput.** The branch read 2,926,667 / 2,953,333 TPS (cycle 0.068 s) against the control's
  5,025,283 / 4,838,183 (0.040-0.041 s). sharded 1378/1378, refusals 0, invalid 0.
- **g7 worked.** state_wait median 0 (1274 of 1378 blocks "none"), seal_to_shards_ready_us 1433,
  receipts_late=true, par_fold 0.
- **g6 half worked.** The hook ran on every block (plan_body=1, plan_body_us 12-13.5k), but the step
  never took the prepared build (prep_from_plan, commit_body_ahead_used, exec_prepared_groups all
  false).
- **What is left.** sealed_at median 64 against 35-37. par_to_seal 60.9 = par_exec 29 +
  exec_end_to_seal 5 + about 25 ms before the execution that no field named.

#### g8, the evm2 step's span around the execution (F5g8)

**Why the prepared build missed.** The selection moves the plan's candidates into the bulk vector
(`frame_blocks::select`: `std::mem::take(&mut prepared.cands)`), so the step's check
`made.cands.len() == cands.len()` compared 0 with 200,000 and failed on every block. The step then
made the keys serially (8.0 ms on the bench, more on the fleet's cold memory), the partition inside
`execute_batches_into` (0.8 ms), and the body at the seal (4.5 ms on the build pool). The take is now
the plan's when the keys and transactions have the candidates' length and the candidates are the
selection's bulk vector, uncut (`made_cands_cut`, unit test
`the_prepared_build_is_the_plans_only_on_its_uncut_bulk_take`). `prep_from_plan` and
`exec_prepared_groups` are now set on the evm2 path.

**New phases-line fields** (us):
- `evm2_pre_exec_us`: from the step's start to `execute_batches_into`.
- Its parts: `evm2_open_us` (the deferred state's open, including state_wait), `evm2_prepared_us`
  (the take), `evm2_keys_us` (keys made inline on a miss), `evm2_shards_new_us`, `evm2_setup_us`
  (the rest of the set-up).
- `evm2_prepared_miss`: none / no_plan / `keys_len a!=b` / `cands_len a!=b` / `bulk_cut a!=b` /
  `transactions_len a!=b`.
- `evm2_fees_us`: after the execution, the run's indices plus the fees and gas.
- The rest of the post-execution span keeps its existing fields: `commit_body_ms`,
  `seal_lookahead_us`, `seal_puller_join_us`, `exec_end_to_seal_us`, `sealed_ms`.

**Post-execution.** The fees loop over the executed set (each candidate's tip read cold) now runs on
the build pool: 2.9 -> 0.3 ms on the bench.

**Bench** (`plan_body_prep_bound`, release, 200,000 transfers, medians of 5):

| | ms |
| --- | --- |
| hook, on the plan-body pool, off the build | 11.7 |
| keys, inline, taken from the plan now | 8.0 |
| partition, inline, taken from the plan now | 0.8 |
| body at the seal, taken from the plan now | 4.5 |
| output shards' set-up | 0.0 |
| fees, serial -> pool | 2.9 -> 0.3 |

With the plan taken, the pre-execution span is the open, which state_wait 0 makes ~0.1 ms with the
pre-execution changes, plus the set-up. The post-execution span is the indices, the fees (0.3), the
body's move and match, and the seal. E14 is to show `evm2_pre_exec_us` at 2-3 ms or less and
`exec_end_to_seal_us` at about 3 ms.

#### E14, after g8

The fx pairs E14 (22:42-23:08Z, natives eb1859ed6 against main, two pairs,
`wt-main/target/fleet-runs/strip-loop351D2S12P30T64X11T16E14{a,0,b,0b}MEMF/el.log`):
- **Throughput.** The branch read 4,158,133 / 4,333,333 TPS (cycle 0.046-0.048 s) against the
  control's 4,900,000 / 4,906,667 (0.041 s), -12..-15%.
- **g8 worked.** evm2_prepared_miss=none and commit_body_ahead_used=true on 1957 of 1969 blocks.
  evm2_pre_exec_us 879 (open 763), exec_end_to_seal_us 1580, sealed_ms 1, tx_root 1.
- **What is left is the execution.** par_exec p10/p50/p90 was 33/39/49 on the branch against
  24/28/38 on the control, and sealed_at 37/43/54 against 35-37. The evm2 path had no per-batch
  fields.

#### g9, the evm2 batches (F5g9)

**Instrumentation** (`execute_batches_into`, on the phases line):
- The revm-era step's batch fields, same names and meaning: `batch_median/max/min_ms`,
  `batch_start_skew_ms`, `batch_last_start_us`, `batch_last_end_us`, `batch_open_sum_us`,
  `batch_txs_max/min`, `batch_threads`, `batch_wall_sum_us`, `batch_cpu_sum_us`, faults, switches.
- Inside the batches, summed: `evm2_batch_reads_us` (the parent state's `Database` calls),
  `evm2_batch_transact_us` (reads included), `evm2_batch_commit_us`, `evm2_batch_shard_add_us`.
  The per-transaction parts are sampled, one transaction in 16, and scaled.
- Outside the batches: `evm2_exec_before_us` (partition and batching), `evm2_exec_gather_us` (the
  executed sets into candidate order), `evm2_exec_merge_us`.
- The batches' pool is logged once ("evm2 batches' pool": threads, thread name, CPUs, layout).

**The hypotheses**, in the order given:
- **(a) The pool.** No. `execute_batches_into` runs on `parallel_common::build_pool()`, the same
  pool the revm-era step uses (`parallel_transfer` re-exports it). Both E14 legs' per-thread CPU
  (`tidcpu-*.tsv`) shows 32 `n42-build` threads. The E9a "Failed to build global thread pool" is
  rayon's global pool, already initialised, and the batches do not use it. Per block, the build
  pool's CPU is about 11% higher on the branch (38,671 at 0.849x the control's blocks, against
  40,959), not the 1.4x the wall time shows.
- **(b) The per-batch open.** The open is the same as the control's: `StateProviderDatabase` over
  `open_parent_state()`, once per batch, in both. reth's evm2 `Database` impl reads exactly as the
  revm one does. The fleet's cost per batch comes with E15 (`batch_open_sum_us`,
  `evm2_batch_reads_us`). On the bench the reads are 8-10% of transact.
- **(c) The shard add.** Small: 2.6 ms summed over 128 batches on the bench, about 20 us a batch.
- **(d) The dispatch.** The same as the control's (`N42_BUILD_BATCHES=128`, largest first). On the
  bench, 128 batches of 1,500-2,000 transfers on 32 threads give a start skew of 11 ms, 3 ms per
  batch: four waves, as on the control.

**The top finding: the gather.** After the batches, one thread put the 200,000 results (120 bytes
each) into one vector and sorted them by candidate index. On the bench that was 5.5 ms of the
20 ms execution (`evm2_exec_gather_us`), on top of the 14 ms the batches took. Each batch now writes
each result into its candidate's slot, on its own thread, as the revm-era step's slots did
(`ScatterSlots`). With nothing skipped, the slots become the vector in place with no copy; with
holes, the written ones are taken in order. Unit test
`the_scatter_slots_give_the_executed_set_in_candidate_order` covers in-place, holes, and dropping
each value exactly once.

**Bench** (`evm2_step_bound`, release, 32 threads, `N42_BUILD_BATCHES=128`, three rounds):
- gather 5.5 -> 0.08 ms;
- shard-path execution 20.1 -> 15.3 ms;
- outside the batches, besides the gather: partition and batching 1.0 ms (made from the plan on the
  fleet), merge 0.14 ms.

E15 is to read par_exec against the control's 28, with the batch fields to name any rest.

#### E15, after g9

The fx pairs E15 (natives 45dc7d5c7 against main, two pairs,
`wt-main/target/fleet-runs/strip-loop351D2S12P30T64X11T16E15{a,0,b,0b}MEMF/el.log`):
- **Throughput.** The branch read 4,584,300 / 4,633,333 TPS against the control's 4,986,667 /
  4,646,667: about -6%, systematic.
- **Where it is.** On E15a against its control: par_exec 35 vs 27, sealed_at 41 vs 37, and
  batch_cpu_sum 961k vs 738k with wall about equal to CPU. The batches cost 30% more CPU per
  block.
- **Inside the batches** (`evm2_batch_*`): reads 441k, transact 665k with the reads in it, so
  about 224 ms of transact proper (1.1 us a transfer), commit 92k, shard add 42k. The pool had
  32 threads on CPUs 0-63.
- **What is left is evm2's per-transaction machinery.** The registry dispatch, the stock prepare,
  the journal, the pending state and its change stream, and the batch's commit of that stream
  cost more than the revm-era fast transfer the control runs.

#### g10, the direct transfer path (F5g10)

**What it does** (`crates/n42/engine-types/src/direct_transfer.rs`):
- A batch applies each plain transfer straight to its own accounts:
  - the sender is debited the value plus 21,000 x the settled price, and its nonce is bumped;
  - the recipient is credited the value;
  - the beneficiary is credited 21,000 x the tip.
- The three accounts go into the batch state through `BatchState::commit_info`, the same rule
  `commit_account` applies (now shared). The result is evm2's for a transfer: success, 21,000
  spent, no refund, the floor, a stop.
- Reads go through `Layered`: the accounts the batch has read or written, over the parent.

**What qualifies.** The fast handler's predicate plus every check the stock `prepare` makes:
- a call with no input and no access list;
- sender, recipient and beneficiary are three different accounts;
- the recipient is above 0x1ff (every Prague and Osaka precompile is at or below it) and has no
  code (an EIP-7702 delegation counts as code);
- the chain id matches (a legacy transaction without one is handed on);
- the priority fee is no more than the fee cap, and the settled price is at least the base fee;
- the gas limit is between 21,000 and the block's limit and the transaction cap;
- the sender exists, has no code, has the transaction's nonce (below u64::MAX), and holds the
  gas limit x the fee cap plus the value;
- a zero value goes only to an existing account that is not empty, and a zero tip only to such a
  beneficiary (anything else is an EIP-161 touch).

**Where it applies.** `DirectTransfers::new` returns `None` (with a debug reason, `refusal`)
unless:
- the spec is one `fast_handler::covers`: Prague or Osaka, never Amsterdam;
- the environment has every stock check on;
- EIP-2780 and EIP-8037 are off;
- a transfer's intrinsic gas is 21,000.

**When a transaction does not qualify**, nothing has been written. The batch makes its EVM at that
point, over the same `Layered` accounts, so the EVM sees every transfer applied before it. That
transaction and the rest of the batch run on evm2 (with the fast handler, as before). The
deferred-execution ledger admits a direct transfer with the sender's balance before it, as it does
on the evm2 path.

**Wiring.**
- `execute_batches` and `execute_batches_into` take `Option<&DirectTransfers>`. The builder
  (`payload.rs`) and the follower import pass `DirectTransfers::for_env(env, shape_of)`.
- `N42_BATCH_DIRECT_TRANSFER=0` turns the path off; the batches then run as in g9.
- Counters:
  - `direct_hits_total` and `direct_delegated_total` on the "parallel step" and "parallel import"
    lines;
  - the block's `evm2_direct_hits` and `evm2_direct_delegated` on the phases line.

**Equivalence tests** (`parallel_build.rs`; the batches with the path against the batches on evm2
alone, on Prague and on Osaka):
- **What is compared:** the same refusal or the same skipped set; the same results (Debug of the
  whole result); and, after `commit_run` and the block's end, the same receipts, gas, post-state,
  reverts and contracts.
- **The fast handler's 7 taken cases**, all applied directly:
  - 1559 to an existing account, and creating its recipient;
  - 1559 over the intrinsic gas;
  - legacy;
  - 2930 with an empty access list;
  - 0x50 as 1559;
  - zero value to an existing account.

  Plus a zero tip to an existing beneficiary.
- **The handler's 10 handed-on cases**, all handed on with equal outcomes. Plus an unprotected
  legacy transaction, a fee cap under the base fee, a priority fee over the cap, and a sender with
  a delegation.
- **Sender runs:**
  - a run of six;
  - a nonce gap (2 applied, the rest skipped on both paths);
  - the balance running out mid-run (2 applied);
  - recipients that send later;
  - a self-transfer mid-run (the EVM made over the written accounts, the rest of the batch on it);
  - an unprotected legacy transaction mid-run, then zero to an empty account;
  - to a delegated account;
  - to a precompile after a transfer;
  - a created account spending.

**Bench** (`evm2_step_bound`, release, 32 threads, `N42_BUILD_BATCHES=128`, five rounds;
`f5g10-bench-d1.log` and `f5g10-bench-d0.log`). The shard path, 200,000 transfers, summed over
the batches:

| | evm2 + handler (g9) | direct path |
| --- | --- | --- |
| batch CPU | 384-394k us | 138-144k us (-64%) |
| transact | 299-312k us | 104-114k us |
| reads (part of transact) | 30-45k us | 31-38k us |
| commit | 42-58k us | 0 (inside transact) |
| transact proper + commit | ~320k us (1.6 us a transfer) | ~75k us (0.37 us a transfer) |
| shard-path execution | 14.4-14.8 ms | 6.3 ms |
| step execution (`exec_ms`) | 89.5 ms | 80.9 ms |

All 200,000 executed on both paths, and the shard path's bundle under the residual equals the
fold path's, as before. On the bench, what the path leaves is mostly the parent reads (about a
third) and the three account-map writes.

**Devnet** (`f5d-gate.sh` `ONLY=g10`, natives c8b70f45d, 300 s each, the F5c builder knobs and the
follower import, member 3 on its own execution layer, two `send_tx` senders):
- **f5g10-direct (path on).**
  - Blocks 1..100 hash-equal on both execution layers, with 1,002 transactions in 78 blocks.
  - 170/170 parallel imports on main and 64/64 on the late execution layer; 0 refused, 0 fold
    refusals, ERROR=0.
  - Every batch transaction went through the path and nothing was handed on: main
    `direct_hits_total=3006 direct_delegated_total=0`, late 1002/0, `fast_hits_total=0`.
- **f5g10-evm2 (`N42_BATCH_DIRECT_TRANSFER=0`).**
  - Blocks 1..100 hash-equal, with 1,002 transactions in 75 blocks.
  - 161/161 and 64/64 parallel imports, ERROR=0.
  - `fast_hits_total=3006` / 1002 and `direct_hits_total=0`.
- **Warnings.** In both rounds the WARNs are only the engine loop's idle notes (`idle_before_ms`
  3000-6000).

E16 is to read par_exec and batch_cpu_sum against the control's 27 and 738k, with
`evm2_batch_transact_us` and `evm2_direct_hits` on the phases line.

#### E16, after g10, and the F5 verdict

The fx pairs E16 (2026-11-06 01:36-02:02Z, natives c8b70f45d against main, two pairs):
- **Throughput.** The branch read 4,664,833 / 4,820,000 TPS against the control's 4,913,333 /
  4,680,000 (-5% / +3%). Windows 2-3: branch 4.93 / 4.93 and 4.92 / 4.91M, control 4.97 / 4.95
  and 4.88 / 4.93M.
- **Per block, the two are now the same machine** (branch against control):
  - sealed_at 37 / 37, par_exec 29 / 27;
  - batch_median 5 / 5, batch_start_skew 21 / 21;
  - batch_cpu_sum 764k / 744k.
- **The direct path.** `evm2_direct_hits` was 200,000 on every full block, and
  direct_delegated_total 8,918 over the leg. Refusals 0, invalid 0.

**F5 gate PASSED: parity with v2.8.1 + X22.**

The A/B legs from E9 to E16: win1 of each leg, and the per-block medians, branch against control.

| leg | branch natives | branch win1 TPS | control win1 TPS | sealed_at (ms) | par_exec (ms) |
| --- | --- | --- | --- | --- | --- |
| E9 | 5e582b610 | 673,333 / 664k | 4,910,033 / 4,940,000 | ~299 / 34 | 83 / 27 |
| E10 | 2d687b583 | 1.06-1.08M | 4.9M | 182 / 37 | 67 / 27 |
| E11 | bcb193399 | 2,100,000 / 2,140,000 | 4,873,333 / 4,993,333 | 92 / 37 | 26 / 27 |
| E12 | 648c03ba4 | 2,846,133 (one pair) | 4,833,333 | 63-67 / 37 | not recorded |
| E13 | f7fa91058 | 2,926,667 / 2,953,333 | 5,025,283 / 4,838,183 | 64 / 35-37 | 29 / not recorded |
| E14 | eb1859ed6 | 4,158,133 / 4,333,333 | 4,900,000 / 4,906,667 | 43 / 35-37 | 39 / 28 |
| E15 | 45dc7d5c7 | 4,584,300 / 4,633,333 | 4,986,667 / 4,646,667 | 41 / 37 | 35 / 27 |
| E16 | c8b70f45d | 4,664,833 / 4,820,000 | 4,913,333 / 4,680,000 | 37 / 37 | 29 / 27 |

What each F5g item moved:
- **g1, the early seal on evm2.** The step had never set `par_txs`, so every block sealed after the
  whole finish. With the seal at the execution's end, sealed_at went from ~299 to 182 ms (E9 -> E10).
- **g2, the execution.** No change to the code path. It found that "exec" included the batches'
  190k-account merge, and that the bench ran on Shanghai, without the handler. It re-based the
  bench on Prague.
- **g3, the output shards.** Merge elided, state_wait 71 -> 13, sealed_at 182 -> 92 (E10 -> E11).
  par_exec was at parity (26 / 27).
- **g4, the seal's body.** tx_root 30 -> 3, sealed 30 -> 3, give_back 21 -> 2; sealed_at
  92 -> 63-67 (E11 -> E12).
- **g5, the tenure stall after a timed-out view.** A correctness fix: the stale-build guard's
  committed floor is now forkchoice safe + the deferred depth. The fix round reached 57/57 equal
  blocks with 0 failed proposals.
- **g6, the plan body on evm2.** The hook ran on every block, but the prepared build was not taken
  until g8.
- **g7, the shards at the finish's end, the receipts behind it.** state_wait 11-14 -> 0,
  seal_to_shards_ready 15-22 ms -> 1.4 ms (E12 -> E13).
- **g8, the step's span around the execution.** The prepared take was fixed and the fees moved to
  the pool. pre_exec ~25 -> 0.9 ms; sealed_at 64 -> 43; 2.93 -> 4.16-4.33M TPS (E13 -> E14).
- **g9, the batches.** Per-batch fields; the gather moved into in-batch slots (5.5 -> 0.08 ms on the
  bench). sealed_at 43 -> 41, par_exec 39 -> 35, 4.58-4.63M TPS (E14 -> E15).
- **g10, the direct transfer path.** Batch CPU -64% on the bench. On the fleet, par_exec 35 -> 29
  and sealed_at 41 -> 37, at parity (E15 -> E16).

### F6a, the revm-era paths removed (2026-11-06)

F5 passed at E16, so the `legacy-revm-paths` feature and everything behind it are gone:

- **Deleted files.** `batch_state_legacy.rs`, `warm_ahead.rs`, the revm-era `parallel_transfer.rs`,
  `fast_transfer.rs` / `fast_transfer_legacy.rs`, `legacy_paths.rs`, the three engine-types
  integration tests that drove them (`e1_bound_bench`, `output_shards`, `output_shards_bench`) and
  the follower's `by_description_bench`. `crate::parallel_transfer` stays as a re-export of the
  EVM-free `parallel_common`, which keeps its name.
- **Removed code.** The cfg'd items in `payload.rs`, `output_shards.rs`, `direct_build.rs`,
  `parallel_common.rs`, `frame_blocks.rs`, `follower_import.rs` and `lib.rs`, with their tests, and
  the crate-level `cfg_attr(not(feature = "legacy-revm-paths"), allow(dead_code, ...))` lines.
  rustc's dead-code warnings then removed what only the revm paths used, among them the graft
  folds, the read set, the prefetchers, the follower's sender groups and build path, the
  `ExecSplit::of` / `RootSlot` / `prespawn_early_root` machinery, the `FrozenShards` beneficiary
  and about 200 phase variables in the build loop that were never assigned on evm2.
- **Cargo.** The feature lines in `engine-types/Cargo.toml` and `bin/n42/Cargo.toml` and the
  optional `revm` / `alloy-evm` dependencies are gone, as is the `tikv-jemallocator` dev-dependency
  that only the deleted bench used.
- **The plan body gate.** It is `body && plan_ahead && by_frames` (`frame_blocks::plan_body_gate`).
  `payload::seal_on_counters` had no other reader and is removed. `N42_SEAL_ON_COUNTERS` stays in
  X22 (the measured set) and `docs/KNOBS.md` says that nothing reads it on evm2.
- **Retired knobs.** `N42_READ_SET`, `N42_BUILD_PREFETCH`, `N42_BUILD_MLP`, `N42_PLAN_AHEAD_WARM`,
  `N42_BUILD_GRAFT_NO_CACHE`, `N42_GRAFT_{INDEX,RANGES,STREAM,SHARDED,BASE_SWAP,PREFAULT}`,
  `N42_FOLLOWER_GRAFT_{INDEX,RANGES,STREAM}` and `N42_FOLLOWER_MERGE_BEHIND` select nothing.
  `docs/KNOBS.md` gives each a `retired` row with its reason. `n42_env::warn_retired_once`
  (`crates/n42/env/src/retired.rs`, called from `N42EvmConfig::new`) logs one line naming any that
  is set to a non-empty value, and the knob is otherwise ignored.
- **Commits.** ac4b1699e (n42-env), b7ed74021 (the removal) and 37dcdc270 (the witness note).
  ac4b1699e also swept in the file deletions that were already staged, so it does not build on its own;
  b7ed74021 completes it. Both were pushed before this was noticed, so they were not rewritten.
- **Gates.** `scripts/clippy-n42.sh` (`-D warnings`) and `cargo check --workspace --tests` are clean.
  The engine-types, n42, n42-env, qmdb-state and n42-testing tests pass. In qmdb-reth, 126 of 127 pass under the
  full-suite load. The failure is `a_rename_while_the_tree_is_leased_is_followed_and_tree_readers_wait_for_it`, the
  sleep-timed lease test already known to be load-flaky in F5. It passes 3 of 3 in isolation. qmdb-reth has no code
  change in F6a.

**Left behind, runtime-dead but not flagged by rustc.** These are `pub` or reached only through
values that are now constant, so rustc does not flag them. They are a follow-up clean-up with no
behaviour change:

- the follower's shard-merge path (`sharded` is always `None`) and `StartedShards`;
- the `LateBlock` waiting machinery that served the by-reference road;
- the `ExecSplit` fields on the import line, which are always zero;
- the copy-aside road's by-reference half (`N42_FOLLOWER_COPY_ASIDE` now only moves the copy).

**The witness recorder** (`docs/patches/0001-feat-witness-record-*.patch`) is parked. Its
`StateReadObserver` hooks revm's `State`, which does not exist in reth v2.9.0. On evm2 it would hang
off the state's read path, either the overlay `Database` implementation the executor reads through
or a `StateChangeSink` beside it. Recorder and replayer must share one EVM version, because the
witness is positional. `docs/WITNESS_REPLAY_RUST_PLAN.md` "2026-11-06" has the note. No code.

### F6 leftovers

Items the F5 paths leave for F6 or later, each with a status (2026-11-06) and the condition that
brings it back:

- **The Amsterdam parallel step.** **Open, needed before 2027-01-01.** The builder's (F5c) and the
  follower's (F5d) parallel step stays serial on an Amsterdam / Glamsterdam chain today, because
  a batch does not write block access list entries for the accounts it touches. Two things
  need it, and neither runs Amsterdam today. One is chain 94, which flips to Glamsterdam execution
  on 2027-01-01; from then on its blocks execute serially on this node. The other is any fleet7
  genesis given an Amsterdam time. The fast handler's Amsterdam port (below) goes with it. Both
  need the BAL entries per batch, folded in transaction order at finish, and an equivalence test
  against the serial Amsterdam execution. The `mobileverify-v3-parity` decision (gov5 runs
  Amsterdam on any IsGlamsterdam chain) is the user's and decides whether this lands before or
  after chain 94's flip.
- **The deferred-genesis devnet start-up race** (f5g1-seal2). **Probably closed by g5; not
  re-run.** Validator 0 proposed block 1 before the others were up, its block became the EL's
  canonical head, and every later build on genesis was refused as stale. g5's committed floor
  (020cb0de5: forkchoice safe + the deferred depth) lets a build on the committed block, genesis
  here, pass the stale-build guard, which is the refusal that stalled it. To confirm, rerun
  f5g1-seal2's shape (deferred, tenure 8, seal-at-exec, validators started apart). The F6 field
  gate does not include that shape.
- **The empty `N42_TX_INGEST`.** **Fixed in F6a.** `scripts/fleet7.sh` passes `N42_TX_INGEST=` to a
  node that serves no ingest, and `bin/n42` logged "N42_TX_INGEST is not an address" at ERROR once
  per node. An empty or blank value now reads as unset.
- **The reth v2.9.0 engine defaults.** **No change.**
  - `TreeConfig` (`crates/engine/primitives/src/config.rs`) and `EngineArgs`
    (`crates/node/core/src/args/engine.rs`) are byte-identical between upstream v2.8.1 and v2.9.0.
    The other files under `crates/node/core/src/args/` did not change either.
  - The defaults therefore stand as in v2.8.1:
    - `persistence_threshold` 50;
    - `memory_block_buffer_target` 5;
    - `num_state_masking_blocks` 30;
    - `backfill_run_threshold` `EPOCH_SLOTS`;
    - `multiproof_task_chunk_size` 5;
    - `reserved_cpu_cores` 1;
    - `sparse_trie_prune_depth` 4;
    - `state_root_task_timeout` 1 s.
  - What the node pins: on a QMDB chain `qmdb_tree_config` (`crates/node/builder/src/builder/mod.rs`)
    forces `num_state_masking_blocks` to 0. It lowers the persistence threshold to 8 and the
    buffer target to 6 when they are still reth's defaults.
  - `scripts/fleet7-env.sh` passes `--engine.persistence-threshold 8` and
    `--engine.memory-block-buffer-target 6` explicitly.
  - The vendored `EngineArgs` differs from upstream only by `--engine.state-trie-overlay`.
  - The F6 field gate's `roll --kill` k90 and k20 runs cover the SIGKILL recovery the reth-bump
    rule asks for.
- **Runtime-dead code after F6a.** **Open, clean-up only.** See "F6a" above (the follower's
  shard-merge path, `LateBlock` waiting, `ExecSplit` zeros, the by-reference half of copy-aside).
- **The tenure stall after a timed-out view, on main** (F5g5). **Open until the F6 merge.** Main
  0f3cb36e7 stalls at height 19 on the deferred devnet (f5g5-main): the stale-build guard refuses
  the build on the high-QC block once a build ahead has made an uncertified block canonical. The fix (020cb0de5, a committed
  floor for the guard) is on this branch and reaches main with the F6 merge. A main release
  before that merge needs it cherry-picked.
- **The serial-rebuild copy of the transaction list** (F5c). **Open.** Measure it in the A/B. Remove it only
  if fold refusals at `finish` prove unreachable in the field.
- **The fast transfer on an Amsterdam chain** (F5f). **Open, with the Amsterdam parallel step.** `fast_handler::covers` is Prague and Osaka
  only: on Amsterdam (EIP-8037 state gas, the block access list) the handler hands every
  transaction to the stock one. Port it, with its own equivalence tests against the stock Amsterdam
  handler, before fleet7 or chain 94 runs Amsterdam blocks through the parallel step.
- **The output shards' revm-era take** (`take_cached` / `into_staged`). **Closed in F6a**: removed
  with the feature. E16 showed the evm2 step at parity without them (merge elided since g3).

### Notes for the history

- Commit c117217eb (`fix(storage-overlay): ...`) also carries the ef-tests runner port: the two
  were made in parallel in one worktree and that commit swept the staged ef-tests files in. The
  branch was already pushed, so it was not rewritten; the ef-tests subsection above describes
  that part of it.
- Engine defaults (the reth-bump rule): `TreeConfig` (`crates/engine/primitives/src/config.rs`)
  and `EngineArgs` (`crates/node/core/src/args/engine.rs`) have no default that differs between
  upstream v2.8.1 and v2.9.0; the vendored `EngineArgs` differs from upstream only by N42's
  `--engine.state-trie-overlay`. `roll --kill` (including a kill before the first persistence)
  still runs in F4.
