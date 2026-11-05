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
