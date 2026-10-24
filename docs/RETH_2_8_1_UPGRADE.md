# reth v2.7.0 → v2.8.1

Dated 2026-10-23, branch `upgrade/reth-v2.8.1` (from `main` at `5a943f4d7`).

## Versions moved

| Crate | v2.7.0 | v2.8.1 |
|---|---|---|
| reth (103 git entries) | tag v2.7.0 | tag v2.8.1 (+ new `reth-snap-sync` entry) |
| reth-primitives-traits, reth-codecs(-derive) (crates.io, reth-core) | 0.8.1 | 0.8.2 |
| revm-inspectors | 0.44.0 (patched 0.44.1) | 0.44.3 (patched 0.44.3) |
| alloy-trie | 0.9.4 | 0.9.8 |
| alloy-hardforks | 0.4.9 | 0.4.11 |
| boa (via revm-inspectors) | 0.21.1 (patched) | 0.22.0 (unpatched) |

revm (43.0.3), alloy (2.5.0), alloy-evm (0.39.0) and jsonrpsee did not move upstream. Every
other crate took `cargo update`'s semver-compatible latest (tokio 1.54.1, rustls 0.23.46,
serde_json 1.0.154, zstd 0.14.3, ...). N42-only dependencies were not given major bumps.

## Sync (`scripts/reth-sync.py v2.7.0 v2.8.1`)

17 files added, 0 deleted, 14 conflicts. The script now reads the patch table with `tomllib`,
so the commented-out entries no longer come back.

| File | Resolution |
|---|---|
| `chainspec/src/spec.rs` (9) | our relocated `blob_params_to_schedule`, plain `DisplayHardforks::new` and test imports; upstream's `U256::ZERO`, `is_london_active_at_block` and `address!` tests |
| `node/builder/src/builder/mod.rs` | upstream's `launch_with_debug_capabilities_and_backfill` (its `engine_api_launcher` already calls our `effective_tree_config`) |
| `storage/provider/.../database/provider.rs` | the QMDB `on_state_unwound` hook first, then upstream's changeset precompute in `unwind_trie_state_from` |
| `storage/provider/.../consistent.rs` | upstream (ours had only un-let-chained the same code) + our `N42PlainReverts` import |
| `storage/provider/.../rocksdb/provider.rs`, `static_file/manager.rs` | upstream's slot conversion, iterating our borrowed `plain_reverts` |
| `storage/storage-overlay/src/provider.rs` (4) | upstream's `from_parts` constructor, with `n42_state_version` added to it |
| `ethereum/cli/Cargo.toml`, `src/app.rs` | our default features and `state-ovly` sizing + upstream's `account-ext` feature and `--engine.cpu-cores` |
| `net/peers/src/{lib,node_record}.rs`, `net/network/tests/it/*` | upstream (+ licence headers) |

The merge also left two duplicate keys in `ethereum/node/Cargo.toml` (`reth-errors`,
`reth-engine-tree`, added by both sides).

### Dependency repairs

- `vendor/dependency-repairs/reth-{nippy-jar,transaction-pool}-2.7.0` are patch targets the
  sync script does not see (their paths do not exist upstream). They were three-way merged by
  hand from `crates/storage/nippy-jar` and `crates/transaction-pool` (one conflict, nippy-jar
  tests, both kept) and renamed `-2.8.1`. Upstream's manifests did not change.
- `revm-inspectors`: reth now requires `^0.44.3`, so the 0.44.1 replacement stopped applying.
  0.44.3 still lacks the fee-disabled `traceCall` beneficiary prestate; the same patch is
  re-applied to `revm-inspectors-0.44.3` (provenance and `N42-PATCH.diff` regenerated).
- 0.44.3 moves to boa 0.22, which does not depend on `paste`, so the boa 0.21.1 repairs were
  unused and are removed.

## API changes ported

- `StateProofProvider::multiproof_v2(targets, requires_masks)` -- no `TrieInput` any more:
  the delegates in `engine-types/src/{direct_build,output_shards}.rs`, and
  `MemoryOverlayStateProvider` (below).
- `ComputedTrieData` is `SortedTrieData` (no `.sorted` wrapper): `direct_build.rs`, the memory
  overlay, `n42_persist_tests.rs`.
- `OverlayStateProvider::provider()` now carries a `Deref` bound; the N42 prefetch helper
  impl block takes it too.
- `upsert` on a dup cursor no longer needs `DbDupCursorRW` in scope (`init_snapshot.rs`).

### Proofs over in-memory blocks

`eth_getProof` calls `multiproof_v2` on the provider `state_provider_for_state` returns. In
v2.7.0 that path passed an empty `TrieInput` and `MemoryOverlayStateProvider` prepended the
in-memory blocks' trie updates and hashed state to it. v2.8.1 proves against the provider's
own state only, which the walked overlay cannot express. `n42_layered_state_provider` now
gives the overlay a proof fallback: when a proof is asked for and in-memory blocks are on top,
it opens upstream's `OverlayStateProvider` for the same tip (which holds the tip's trie
overlay) and asks it. Plain reads never open it, so the follower's read path is unchanged.
`n42_layered_reads_match_upstream_overlay` now also checks both paths return the same
multiproof at every tip. A `MemoryOverlayStateProvider` built without the fallback (tests,
`engine-types`) reports `UnsupportedProvider` for such proofs.

## Behaviour changes upstream made under us

- **Engine defaults.** `TreeConfig` / `EngineArgs` defaults are unchanged apart from the new
  `prewarm_reuse` (off). `num_state_masking_blocks` stays 30, persistence threshold 50.
  `--engine.cpu-cores` is new.
- **Snap sync.** `--snap.v2` (snap/2 sync, a pluggable engine backfill) is new and off by
  default; `reth-node-ethereum` gains a `snap` module. The new "refuse databases the selected
  sync cannot use" check only concerns snap-synced databases.
- **Trie.** `MultiProofCalculator` (storage-overlay) reuses known storage roots across proofs;
  `--rpc` responses are compressed only when large; mapped bytecode pages are prefetched
  (`mdbx/value_prefetch.rs`).

## Verification (2026-10-23)

| Command | Result |
|---|---|
| `cargo check --workspace` / `--workspace --tests` | clean |
| `cargo clippy --workspace --lib --bins --examples` | 0 errors (1,333 warnings, none in the new code) |
| `cargo test -p n42-testing` | 28 passed, 1 ignored |
| ported crates (bmt-core ... h2-execution) | all passed, 1 ignored |
| `-p n42-engine-types --lib --tests` | 299 passed, 17 ignored |
| `-p n42-tx-types` / `-p n42-tx-ingest` / `-p n42-tx-queue` | 21 (6 ignored) / 65 / 123 (11 ignored) |
| `-p n42-qmdb-reth` / `-p n42-primitives` | 86 (5 ignored) / 200 |
| `-p n42-clique -p n42-consensus-traits -p n42-consensus-core` | 118 passed, 1 ignored |
| `-p n42 --lib --bins` | 160 passed, 5 ignored |
| `-p reth-provider --lib n42` | 25 passed, 4 ignored (incl. the multiproof check) |
| `-p reth-chainspec --lib` | 53 passed |
| `-p n42-dependency-compat-tests` | 3 passed |
| release `n42`, `h2_validator`, `tx_flood` | build |
| `n42 init` + `n42 node` on `n42_devnet.json`, 20 s | genesis written, HotStuff path (APoS mining off), engine loop up, clean SIGTERM; no ERROR |

Two test-only breaks were fixed: upstream's hoodi fork-id test needs `hoodi` in scope, and
`BeaconEngineMessage::NewPayload` gained a `cause` field (two test patterns). No `testdata/`
fixture changed.

Not done here: a fleet leg (`scripts/fleet7.sh`, `roll <i> --kill` recovery on QMDB) and a
throughput bookend against v2.7.0. After the v2.7.0 bump the engine defaults and the overlay
read path both changed under the fleet (loop308); v2.8.1 leaves the defaults alone, but the
overlay's multiproof calculator and the new prewarm/value-prefetch paths are unmeasured on it.
