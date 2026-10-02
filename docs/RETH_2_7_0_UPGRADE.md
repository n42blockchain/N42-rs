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

## Not verified

See the verification table in the hand-back / commit log of this branch. Nothing was run on a node
or the fleet; no throughput round was taken on v2.7.0.
