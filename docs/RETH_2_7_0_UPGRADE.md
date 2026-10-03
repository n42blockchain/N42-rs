# reth v2.5.1 → v2.7.0

Dated 2026-10-02, branch `upgrade/reth-v2.7.0` (from `feat/native-fleet7` at `6a6b81cf3`).

## Versions moved

| Crate | v2.5.1 | v2.7.0 |
|---|---|---|
| reth (102 git entries) | tag v2.5.1 | tag v2.7.0 |
| revm / sub-crates | 42.0.1 / 42.0.0 | 43.0.3 / 43.0.0 |
| revm-inspectors | 0.42.0 | 0.44.0 |
| alloy-* (consensus, eips, genesis, rpc-types, provider, ...) | 2.3.0 | 2.5.0 |
| alloy-evm | 0.38.0 | 0.39.0 |
| alloy-hardforks | 0.4.7 | 0.4.9 |
| alloy-eip7928 | 0.4.5 | 0.4.10 |
| reth-primitives-traits, reth-codecs(-derive), reth-rpc-traits (crates.io, reth-core) | 0.6.0 | 0.8.1 |
| tokio-util | 0.7.4 | 0.7.11 |

N42-only dependencies (libp2p, tikv-jemallocator, ed25519-dalek, ...) were not bumped. `roaring`
stays on 0.11.4 (upstream pins 0.11.3). jsonrpsee, tokio and alloy-primitives did not change.

The forked `crates/n42/alloy-rpc-types-{engine,beacon}` were three-way merged from their real base
(crates.io 2.3.0, though their manifests said 2.4.1) to 2.5.0 and now say 2.5.0; without that the
`[patch.crates-io]` entries stop applying and two copies of each crate end up in the graph. The
merge was clean (engine: `jwt.rs`, `payload.rs`; beacon: `block.rs`, `payload.rs`). The new
upstream module `ssz_engine_types` builds `ExecutionPayloadV1` in a test; that literal now sets the
N42 `difficulty`/`nonce` fields, which SSZ skips.

## Sync (`scripts/reth-sync.py v2.5.1 v2.7.0`)

95 files merged, 12 added, 1 deleted, 13 conflicts. The script's `patched_dirs()` also picks up the
*commented-out* patch entries, so it copied upstream's `crates/evm/` back in and listed ~40 files
under reverted forks (`crates/chain-state`, `crates/rpc/rpc-eth-api`, ...) as "kept"; those were
discarded. (The script also resolves `../reth` relative to the repository root, which is wrong from
a worktree under `.claude/worktrees/`; it was run with `RETH` pointed at the real checkout.)

Conflicts and resolutions:

| File | Resolution |
|---|---|
| `revm/src/database.rs` | upstream (`EvmStateProvider` moved to storage-api) + N42 licence header |
| `chainspec/src/api.rs` | upstream dropped `calc_next_block_base_fee`; kept our concrete `impl EthChainSpec for ChainSpec` imports |
| `chainspec/src/spec.rs` | upstream's rewritten fork-id tests (ours was only a formatting change) |
| `node/builder/src/launch/engine.rs` | upstream's `Some(payload) = built_payloads.next()` + our branch timing lines |
| `storage/provider/src/lib.rs` | upstream's export list (`HistoricalStateProvider*`, `BalNotification*` gone) + our `WriteStateInput` |
| `storage/provider/.../blockchain_provider.rs`, `rocksdb/provider.rs` | upstream (ours had only un-let-chained the same code) |
| `storage/provider/.../database/provider.rs` | upstream's `ExecutedBlock::hashed_state_refs` inside our `N42_HASHED_TABLES=off` guard |
| `storage/provider/.../state/historical.rs` | upstream (see below) |
| `storage/storage-api/src/lib.rs` | both: our beacon/snapshot/legacy/ommers/validator/withdrawals modules + upstream's `evm` |
| `net/network/src/network.rs` | both imports (`NewBlock` and `ForkFilter`) |
| `net/network/tests/it/{transaction_hash_fetching,txgossip}.rs` | upstream (+ header); not a workspace member, not compiled here |

Deleted upstream and changed here only by a licence header or a two-field initializer:
`revm/src/cancelled.rs`, `ethereum/node/src/engine_ssz_containers.rs` (its SSZ containers moved to
alloy's `ssz_engine_types`) -- deleted.

### New vendored crate: `crates/storage/storage-overlay`

Upstream removed `HistoricalStateProvider(Ref)` from reth-provider. Historical state, and state
under in-memory tree blocks, is now read by `reth-storage-overlay`'s `OverlayStateProvider`. Our
`historical.rs` carried the QMDB reader hooks (`n42_state::reader()` in `on`/`verify` mode, and the
`N42_HASHED_TABLES=off` refusal) on its plain-state reads, plus the chunked parallel hashed
post-state. Taking upstream's `historical.rs` alone would have silently dropped them: with
`N42_HASHED_TABLES=off` the overlay would read the empty hashed tables. So reth-storage-overlay is
vendored as a 17th patch target and carries the same hooks in `basic_account_from_db` /
`storage_from_db` and `hashed_post_state` (`n42_hashed_state_version` and the chunked hashing are
copied there, since the crate cannot depend on reth-provider). The latest-state provider keeps its
own hooks unchanged.

## API changes ported

- `StateProviderDatabase<DB>` needs `DB: EvmStateProvider` (new trait in storage-api, with
  `StateProvider::into_evm_state_provider`): `engine-types/src/payload.rs`,
  `bin/n42/src/{follower_import,main}.rs`, `mobile-sdk/src/lib.rs`.
- `StateProofProvider::multiproof_v2` (required): delegated in `engine-types/src/direct_build.rs`
  (`CountingStateProvider`) and `output_shards.rs` (`ShardLayer`).
- `ExecutedBlock` gained `bal: Option<Arc<DecodedRevmBal>>`: `None` in `direct_build.rs`
  (`executed_under_seal`, `executed_from_output`), as upstream does outside engine validation.
- `reth-chain-state` removed `MemoryOverlayStateProvider(Ref)`. The builder and the follower import
  lay executed parents that are not yet in the tree over a historical provider, which upstream's
  `OverlayStateProvider` does not do; v2.5.1's implementation is kept in
  `engine-types/src/memory_overlay.rs` (plus `multiproof_v2`).
- `EngineValidator::validate_block` takes `SealedBlockWithAccessList`: the stub
  `EthereumEngineValidator` in `crates/ethereum/node/src/engine.rs`.

Everything else (revm 43, alloy-evm 0.39 at the EVM seam, `batch_state.rs`, `fast_transfer.rs`,
`N42TxEnvelope` on reth-primitives-traits 0.8, `N42PooledTransaction` -- the new `PoolTransaction`
methods all have defaults --, consensus, payload builder) compiled without change.

## Behaviour changes upstream made under us

- **Sender-recovery cache.** v2.7.0 enables the engine's sender-recovery cache by default
  (`--engine.sender-recovery-cache`, `SenderRecoveryCache`), and the pool's
  `try_recover_with_cache[_opt]` / RPC's `recover_raw_transaction_with_cache` use it. The default
  recovers through `SignedTransaction::recover_signer`, so 0x50 transactions recover through
  `N42TxEnvelope`'s AltSig path; the fleet already passes the flag.
- **State reads under the tree** go through `OverlayStateProvider` instead of
  `MemoryOverlayStateProvider` + `HistoricalStateProvider`. Our hooks are on the new path, but its
  read order (an overlay built from the tree's blocks, history lookups with a fallback block) is
  upstream's and has not been measured on the fleet.
- **Bogota.** alloy-hardforks 0.4.9 adds `EthereumHardfork::Bogota`, parsed from
  `genesis.config.bogotaTime`. None of our genesis files set it, so no N42 chain activates it;
  `N42_HARDFORKS` is unchanged. Sepolia now schedules Amsterdam upstream.

Two test-only breaks: the `StateProviderFactory` test double in `direct_build.rs` needs the new
`Primitives` type and `state_with_block_appended`; and `cargo test -p n42-tx-queue` builds
reth-storage-api without `std`, where our `beacon.rs`/`validator.rs` used `std::` paths (now
`alloc`/`core`).

## Verification (2026-10-02)

| Command | Result |
|---|---|
| `cargo check --workspace` | clean |
| `cargo clippy --workspace --lib --bins --examples` | 0 errors (1,238 warnings, none in the new code) |
| `cargo test -p n42-testing` | 26 passed, 1 ignored |
| ported crates (bmt-core ... h2-execution) | 572 passed, 1 ignored |
| `-p n42-engine-types --lib --tests` | 217 passed, 13 ignored |
| `-p n42-tx-types` / `-p n42-tx-ingest` / `-p n42-tx-queue` | 20 (4 ignored) / 61 / 40 (4 ignored) |
| `-p n42-qmdb-reth` / `-p n42-primitives` | 49 (5 ignored) / 200 |
| `-p n42-clique -p n42-bmt-core -p n42-consensus-traits -p n42-consensus-core` | 125 passed, 1 ignored |
| `-p n42 --lib --bins` | 114 passed, 5 ignored |
| release `n42`, `h2_validator`, `tx_flood` | build |

No `testdata/` fixture changed.

## The follower slowdown on the fleet (loop308) and the fix

Measured on three nodes with 163k-transaction blocks, the v2.7.0 binaries read win1 0.56-0.57M
against 1.13-1.16M. The leader's parallel execution and the roots did not move; the followers'
build-path execution did. In `bench-loop308UPb` node1 the build-path lines read (mean over
blocks with batches): `batch_median_ms` 92-117 against 13-15 on `bench-loop308BASE`, and
`exec_pre_ms` -- the block's own executor's pre-execution system calls, a handful of reads beside
the batches -- 85-109 against 0. A few reads taking as long as a whole batch means every opener
waited on one shared piece of work, not on its reads.

That work is the execution overlay. The follower's batches each open
`state_by_block_hash(anchor)` (the anchor is the block under its kept layers, still in the
tree's memory). v2.5.1 answered that with `MemoryOverlayStateProvider`: the in-memory blocks'
bundles walked per read over the database at the persisted anchor, nothing done at open.
v2.7.0's `BlockchainProvider::state_provider_for_state` answers it with
`reth-storage-overlay`'s `OverlayStateProvider`, whose first read flattens every in-memory block
from the persisted anchor to the tip into one `ExecutionOverlay` (`AddressMap` of accounts plus
an empty storage map per account), cached per (anchor, tip): extended from the previous tip's
overlay when that is cached and not shared (`Arc::make_mut` clones it whole when it is), merged
from every block when the anchor moved (each persistence). Every batch and the executor wait on
that one computation (`OverlayWaiter`). `n42_overlay_open_cost_at_fleet_shape` (reth-provider,
`--ignored`, release, eight in-memory blocks of 147k accounts, idle box): opening a tip and its
first read takes 24-118 ms flattened against 10-40 us walked; 160k reads then take 9-12 ms
flattened against 12-27 ms walked on one thread (the follower spreads them over 32).

Fix: `state_provider_for_state` (so `latest`, `pending` and `state_by_block_hash` on an
in-memory block) opens `MemoryOverlayStateProvider` over the persisted anchor again
(`n42_layered_state_provider`). The type moved from `engine-types` into the vendored
`reth-provider` (`providers/state/memory_overlay.rs`, re-exported by
`n42_engine_types::memory_overlay`). The database side under it is `OverlayStateProvider` at the
anchor with an empty execution overlay, so the QMDB hooks (`N42_QMDB_READS=on|verify`,
`N42_HASHED_TABLES=off` refusing) are on the read path exactly as before. When the anchor is not
readable that way -- not the canonical block at its number, or above the persisted state/trie
frontier -- the upstream path is taken. `N42_OVERLAY_READS=upstream` restores the upstream path
for an A/B leg. `n42_layered_reads_match_upstream_overlay` checks both paths answer the same
accounts and block hashes at every tip of a five-block chain.

Engine settings for the bench: v2.7.0 requires `num-state-masking-blocks +
memory-block-buffer-target < persistence-threshold`; with the bench's threshold 8 and buffer
target 6 that leaves masking at 0 or 1, and the runs use `RETH_ENGINE_NUM_STATE_MASKING_BLOCKS=0`.
Masking 0 is v2.5.1's behaviour (state persisted with its blocks). With masking on, masked blocks'
state stays only in memory, the anchor of the in-memory chain sits above the state/trie frontier,
and `n42_layered_state_provider` declines (upstream's path) -- so keep masking at 0.

## The `state-ovly` pool and `--engine.state-trie-overlay`

loop309/310's per-thread CPU accounting put the remaining upgrade cost on one place: the
`state-ovly` worker pool (`reth_tasks::Runtime::state_trie_overlay_worker_pool`,
`DEFAULT_STATE_TRIE_OVERLAY_WORKER_THREADS = 4`) burnt ~21-22k CPU units per leg on every v2.7.0
leg and 0 on v2.5.1. The pool belongs to `reth-storage-overlay`'s `OverlayManager`, shared by the
provider factory and the engine tree. What it runs:

- **Execution overlays.** Any `OverlayStateProvider` over an in-memory tip flattens every block
  from the persisted anchor to that tip into one `ExecutionOverlay` (accounts, storage, code) on
  its first read, cached per (anchor, tip); the computation runs on the pool and the opener waits.
  The engine tree's payload validator opens one per `newPayload` (its own
  `OverlayStateProviderFactory`, not the `BlockchainProvider` path fixed above), and so does any
  `BlockchainProvider` read that falls back to upstream's path.
- **Precompute on insert.** `OverlayManager::insert_block` (every block the tree inserts,
  `InsertExecutedBlock` included) spawns a pool task extending the parent tip's cached execution
  overlay by the new block -- once one overlay is cached, every following block keeps one built,
  147k accounts a block on the fleet, and the whole chain is re-merged from scratch after each
  persistence moves the anchor.
- **State trie overlays** (merged trie updates + hashed post-state for the Merkle-Patricia
  root, proofs and the sparse trie). Consumed by the engine's default state-root task and by
  `eth_getProof`-style readers; `QmdbStateRootStrategy` never asks for them, and the payload-builder
  state-root handle stays at the trait default (`None`).

On a QMDB chain nothing consumes the flattened overlays beyond the reads themselves, which
v2.5.1 answered by walking the in-memory blocks per read.

The switch: `--engine.state-trie-overlay <bool>` (env `RETH_ENGINE_STATE_TRIE_OVERLAY`, a new
`Option<bool>` field on the vendored `EngineArgs`). Unset, `EngineArgs::state_trie_overlay_enabled`
resolves it from the genesis: **false** when the chain declares the QMDB state commitment or
`N42_HASHED_TABLES=off`, **true** otherwise (upstream's behaviour). `launch/engine.rs` then builds
either `OverlayManager::new(pool)` (true) or `OverlayManager::without_state_trie_overlay()`
(false); the startup log line `Overlay manager created state_trie_overlay=...` says which. With
false:

- the manager holds no worker pool, so `insert_block` schedules nothing and no task ever reaches
  `state-ovly`; `crates/ethereum/cli/src/app.rs` also sizes that pool at one idle thread instead
  of four (the runtime always builds it);
- execution overlays are **layered** (`ExecutionOverlay::layered`): opening one only resolves the
  block path from the anchor to the tip; each account / storage / bytecode read then looks the
  blocks' `BundleState`s up newest first (a written slot answers; a destroyed account's unwritten
  slot answers zero; otherwise the next older block, then the database) -- v2.5.1's
  `MemoryOverlayStateProvider` order. Nothing is cached in the manager. This is the fallback for
  the engine validator's reads, which would otherwise have waited on the flattening inline;
- state trie overlays still work, computed on demand on the caller's thread and cached as before,
  so Merkle-Patricia roots and proofs over in-memory blocks keep answering on a chain that asks.

`n42_layered_execution_overlay_matches_flattened` (storage-overlay, `manager.rs`) checks the
layered and flattened overlays answer the same accounts (account ids stripped), storage (including
a later block shadowing an earlier one and a destroyed account) and bytecode at two anchors, and
that the layered manager caches nothing. storage-overlay is not a workspace member: its 54 lib
tests were run by adding it to `members` temporarily.

## Not verified

Nothing was run on a node or the fleet; no throughput round was taken on v2.7.0. The QMDB hooks on
the new overlay path (`N42_QMDB_READS=verify|on`, `N42_HASHED_TABLES=off`) are compiled but not
exercised by any test. Tests of the vendored non-member crates (network, storage-overlay, revm,
bin/reth) were not run.
