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

### F6 leftovers

Items the F5 paths leave for F6 or later, each with the condition that brings it back:

- **The parallel step on an Amsterdam chain.** The step (builder F5c, follower F5d) does not run on
  a chain with reth's Amsterdam or gov5's Glamsterdam execution: the block access list would lack
  the batch accounts' entries. fleet7 is Osaka. Chain 94 flips on 2027-01-01, so this is needed
  before a parallel build runs there (coordinator 2026-11-05).
- **The serial-rebuild copy of the transaction list** (F5c). Measure it in the A/B. Remove it only
  if fold refusals at `finish` prove unreachable in the field.
- **The fast transfer on an Amsterdam chain** (F5f). `fast_handler::covers` is Prague and Osaka
  only: on Amsterdam (EIP-8037 state gas, the block access list) the handler hands every
  transaction to the stock one. Port it, with its own equivalence tests against the stock Amsterdam
  handler, before fleet7 or chain 94 runs Amsterdam blocks through the parallel step.
- **The output shards** (`take_cached` / `into_staged`, `N42_OUTPUT_SHARDS`). Stay legacy; port
  only if the A/B shows the merge is the cost.

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
