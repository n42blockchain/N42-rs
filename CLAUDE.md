# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

N42 is a **partial fork of [reth](https://github.com/paradigmxyz/reth)**. Most of reth is consumed as a
git dependency pinned to a tag (`reth = { git = "...", tag = "v1.11.0" }` — grep `Cargo.toml` for the tag
to confirm the current version); a subset of reth crates is vendored under `crates/` and substituted into
the whole dependency graph via `[patch.'https://github.com/paradigmxyz/reth.git']` in the root `Cargo.toml`.
N42-specific code lives under `crates/n42/` and `bin/n42/`.

Consensus is **APoS** (an extended Clique/PoA) plus a beacon/validator layer, not Ethereum's beacon chain.

## Build / test / lint

```bash
cargo build --release                  # builds default-members = bin/n42 only
cargo build --profile maxperf          # fat LTO, codegen-units=1
cargo check --workspace                # what CI gates on (.github/workflows/test.yml)
cargo test -p n42-testing              # the main test suite CI runs
cargo clippy --workspace --lib --bins --examples   # CI lint (.github/workflows/lint.yml)
```

Running one test:

```bash
cargo test -p n42-testing test_single_signer__no_votes_cast -- --nocapture
cargo test -p n42-clique --lib integration_tests::                # APoS unit/integration tests
```

Ethereum Foundation spec tests (`crates/n42/ef-tests`) are `#[ignore]`d by default and need fixtures:

```bash
EF_TESTS_PATH=/path/to/execution-spec-tests/fixtures \
  cargo test -p n42-ef-tests --test blockchain_tests -- --ignored
```

End-to-end (needs release binaries + node/npm + `jq`):

```bash
cargo build --release && cargo build --release -p mobile-sdk --example mobile-sdk-test
./tests/e2e.sh
```

Running a node:

```bash
cargo run --release --bin n42 -- node --chain crates/chainspec/res/genesis/n42_devnet.json \
  --dev.consensus-signer-private-key 0x... --dev.block-time 4s --http --ws
```

Caveat: `tests/e2e.sh` passes `--chain n42-devnet`, but the vendored
`crates/ethereum/cli/src/chainspec.rs` currently maps only `mainnet|sepolia|holesky|hoodi|dev` and falls
through to `parse_genesis()` for anything else — the `n42`/`n42-devnet` names were dropped during a reth
re-sync even though `N42` and `N42_DEVNET` still exist in `crates/chainspec`. Pass a genesis JSON path:
`--chain crates/chainspec/res/genesis/n42_devnet.json`.

`n42_devnet.json` is the native chain's devnet: `"stateScheme": "qmdb"`, `"consensus": "hotstuff"`
with four dev validators (secrets in `n42_devnet_validators.json`, derived from a public seed — dev
only), every Ethereum fork through Osaka active at genesis, and the Prague system contracts in the
alloc. Both `--chain <path>` and the `N42_DEVNET` constant build its genesis header the same way, with
the QMDB root of the alloc; a genesis file that declares its own fork schedule is trusted over the
legacy `N42_HARDFORKS` list. The same file is what a gov5 node is initialised from (`n42 init`).
On a chain whose genesis names a `hotstuff` validator set `bin/n42` runs `HotStuffConsensus`
(gov5's header profile and roots) instead of APoS and spawns no miner: the fleet
(`cargo run -p n42-h2-node --example h2_validator -- --chain <genesis> --propose …`) drives it over
the Engine API. `scripts/devnet-fleet.sh <tag> <secs> [--gov5]` runs the whole devnet — one QMDB
node, four Rust validators, or three plus a gov5 member from `../N42-gov5` (which needs
`docs/gov5-cancun-parent-beacon-root.patch` applied). `docs/N42_26_PORT.md` "Joining a Go fleet"
lists every cross-client rule that had to be matched.

`cargo build`/`cargo test` with no `-p` only touches `default-members` (`bin/n42`). Use `--workspace`
deliberately — it is a very large build.

## Workspace layout and the fork boundary

Three distinct kinds of crate directory exist, and they behave differently:

1. **`crates/n42/*` — original N42 code.** Workspace members, freely editable.
2. **Vendored reth forks that ARE workspace members** (`crates/chainspec`, `crates/consensus/consensus`,
   `crates/primitives-traits`, `crates/storage/{db,db-api,provider,storage-api}`, `crates/node/{core,builder}`,
   `crates/ethereum/{cli,hardforks,node}`, `crates/net/peers`, `crates/rpc/rpc-types-compat`).
3. **Vendored reth forks that are NOT workspace members but ARE patch targets**
   (`crates/revm`, `crates/ethereum/evm`, `crates/net/network`, `crates/net/network-api`,
   `crates/storage/libmdbx-rs`, `bin/reth`). They compile only as dependencies. `cargo test --workspace`
   will not run their tests.

Editing anything in (2) or (3) rewrites reth for *every* crate in the graph, including the upstream git
crates that depend on it — a signature change there can cascade into hundreds of upstream compile errors.
Prefer adding code in `crates/n42/*` and wiring it in at the node-builder level. When you must touch a
forked crate, keep the change additive (new trait method with a default impl, new table, new field with
serde defaults) so upstream call sites still compile.

The commented-out entries in `[workspace] members` and in the `[patch]` table are deliberate: they mark
crates that were previously forked and have since been reverted to upstream. Don't uncomment them casually.

### N42 customizations inside forked reth crates

- `crates/primitives-traits/src/header/clique_utils.rs` — `recover_address()` / `seal_hash()` for APoS
  signature recovery from block headers (N42-only file).
- `crates/consensus/consensus/src/lib.rs` — the `Consensus` trait is extended with APoS operations
  (`prepare`, `seal`, `snapshot`, `propose`, `discard`, `proposals`, `total_difficulty`, `wiggle`,
  signer get/set) plus N42 error variants.
- `crates/storage/{db-api,storage-api,provider}` — beacon tables (`BeaconStateRecord`, `BeaconBlockRecord`,
  `BeaconNum2Hash`, `PlainValidatorState`, `ValidatorsHistory`, `ValidatorChangeSets`) and the
  `BeaconProvider` / `BeaconProviderWriter` traits (`crates/storage/storage-api/src/beacon.rs`).
- `crates/chainspec/src/spec.rs` — `N42` (testnet, chain id 1142) and `N42_DEVNET` (1143) specs with
  genesis JSON in `crates/chainspec/res/genesis/`.
- `crates/node/core/src/args/dev.rs` — N42 CLI flags: `--dev.consensus-signer-private-key`,
  `--dev.migrate-old-chain-data-from-db`, `--dev.migrate-old-chain-data-from-rpc`.
- `crates/ethereum/evm` — uses `recover_address()` for the block beneficiary instead of `header.beneficiary`.

`N42_CUSTOMIZATIONS.md` is the maintained (Chinese) inventory of these; update it when the set changes.

Two alloy crates are also forked and patched over crates.io: `crates/n42/alloy-rpc-types-{engine,beacon}`.

## Architecture

`bin/n42/src/main.rs` is the whole wiring story and is worth reading first. It:

- builds the node from `N42Node` (`crates/n42/engine-types/src/node.rs`), a reth `ComponentsBuilder`
  that keeps reth's Ethereum pool/executor but swaps in `N42ConsensusBuilder`, `N42PayloadServiceBuilder`,
  and `N42NetworkBuilder`;
- merges two custom RPC namespaces from `bin/n42/src/consensus_ext.rs`: `consensusExt` (auth transport —
  `propose`, `discard`, `get_snapshot`, `proposals`) and `consensusBeaconExt` (public transport —
  `submitVerification`, beacon block/state/validator queries);
- spawns either `N42Miner` (normal block production) or `N42Migrate` (when a `--dev.migrate-old-chain-data-*`
  flag is set) — they are mutually exclusive;
- runs an in-process pub/sub router (`pubsub-mem`) that bridges a tokio broadcast channel of
  `(UnverifiedBlock, Vec<BLSPubkey>)` onto per-validator topics keyed by hex pubkey.

Block production/verification loop: `N42Miner` (`crates/n42/consensus-client/src/miner.rs`, the largest
and most intricate file in the repo) builds a payload, seals it via APoS, broadcasts the `UnverifiedBlock`
to the validator set over pubsub, and collects BLS verification signatures returned through the
`consensusBeaconExt.submitVerification` RPC and the `verification_rx` channel before finalizing.

Key N42 crates:

| Crate | Role |
| --- | --- |
| `crates/n42/clique` | `APos` — the consensus engine: snapshots, signer voting, seal/verify_seal, wiggle timing. Implements reth's extended `Consensus`/`FullConsensus`. |
| `crates/n42/primitives` | Beacon-chain primitives: validators, committees, shuffling, snapshots, `safe_arith`. |
| `crates/n42/consensus-client` | Miner, beacon state machine, chain-data migration, validator networking, storage. |
| `crates/n42/engine-types` | `N42Node` and the consensus/network/payload component builders. |
| `crates/n42/engine-primitives` | Payload attribute builders (`N42PayloadAttributesBuilder`). |
| `crates/n42/consensus-traits`, `consensus-core`, `storage` | Extraction layer pulling N42 logic back out of the forked reth crates (see `docs/ARCHITECTURE.md`). |
| `crates/n42/mobile-sdk` | Validator key/deposit/exit tooling; `examples/mobile-sdk-test.rs` drives the e2e script; `build-aar.sh` + `ios/` for mobile builds. |
| `crates/n42/fusaka` | Fusaka (Prague EL + Osaka CL) hardfork constants, BLS12-381 and PeerDAS checks. |
| `crates/n42/{bmt-core,twig-core}` | QMDB state commitment: sparse binary Merkle tree and twig engine (Blake3). Ported from `../N42-26`; zero reth/mdbx coupling. `twig_core::qmdb_compat` carries gov5's key derivation, account encoding, proof codec, and portable-snapshot verifier. |
| `crates/n42/{h2-primitives,h2-wire,h2-consensus}` | HotStuff-2 interop: BLS + message types, the Go↔Rust v4 wire codec, and validator-set + finality verification. Ported from `../N42-26`; tested against gov5's byte-exact fixtures. |
| `crates/n42/mobile-verify` | Mobile verification formats: receipts, BLS attestations, twig/SBMT state proofs. Distinct from `mobile-sdk`, which is validator key/deposit tooling. |
| `crates/n42/h2-execution` | Execution-layer seam (`ExecutionLayer`: Engine API in alloy types, no reth types) plus the driver connecting HotStuff-2 to it. A concrete reth adapter is not yet written — see `docs/N42_26_PORT.md`. |
| `crates/n42/h2-net` | gov5-compatible GossipSub transport, the `/rpc/status/1/ssz_snappy` handshake (without which gov5 drops the peer), gov5's block-body topic (`block_gossip`: `/n42/<fork digest>/block/ssz_snappy`, RLP `[header, txs, verifiers, rewards]` — a proposal names only a hash, so without this followers cannot vote), and a read-only finality observer. `cargo run -p n42-h2-net --example h2_observer -- --help`. The libp2p `secp256k1` feature is load-bearing — gov5 nodes use secp256k1 identities and the Noise handshake fails without it. |
| `crates/n42/n42-testing` | Integration tests for APoS signer voting — the suite CI runs. Tests live in `src/dev.rs` behind `#[cfg(test)]`, not in `tests/`. |
| `crates/n42/ef-tests` | Ethereum Foundation state/blockchain/transaction spec-test runner. |

## Sibling repos and ported code

Three N42 clients live side by side on this host, and code moves between them:

- `../N42-gov5` — the Go client (go-ethereum/Erigon-derived). Runs the
  production `mainnet_qmdb_staggered` 7-node HotStuff fleet and owns the
  byte-exact interop fixtures. Also has an `eth-el` mode (`--chain eth-mainnet`)
  and writes reth-format MDBX tables for cross-client work.
- `../N42-26` — the newer Rust client, on reth **2.4.1** (edition 2024, rustc
  1.97) with HotStuff-2 and QMDB. Depends on reth by local path (`../reth`).
- `../reth` — a reth checkout at 2.4.1, 1,484 commits ahead of this repo's
  pinned v1.11.0.

The `n42-{bmt-core,twig-core,h2-primitives,h2-wire,h2-consensus,mobile-verify,h2-net,h2-execution}`
crates came from `../N42-26` (`h2-net` is new, modelled on its `n42-network`;
`h2-execution` ports its EL seam and adds a driver). They are additive and wired into nothing —
the APoS node path is untouched. Read `docs/N42_26_PORT.md` before extending
them: it records what was renamed and why, the edition-2021 adaptations, what
was deliberately left behind, and the fixture SHAs that must match gov5.

Ported crates carry gov5 cross-client fixtures under `testdata/`. Those are
byte-exact contracts — compare by SHA-256 of raw bytes, never text-mode content.

```bash
cargo test -p n42-bmt-core -p n42-twig-core -p n42-h2-primitives -p n42-h2-wire \
           -p n42-h2-consensus -p n42-mobile-verify -p n42-h2-net \
           -p n42-h2-execution                                      # 412 tests
```

## Upgrading reth

`docs/RETH_2_4_1_UPGRADE.md` is the current, measured assessment (the guide below
is older and its "current version" section is stale). The short version: reth
2.4.1 deleted or relocated 22 of the 121 reth crates this repo depends on, and
two of them — `reth-primitives-traits` (which holds the APoS `clique_utils`) and
`reth-rpc-types-compat` — are crates this repo maintains vendored forks of. They
must be re-homed against a different upstream before anything else resolves.


`docs/RETH_UPGRADE_GUIDE.md` and `patches/` describe the process (note: the guide's "current version"
section lags the actual pinned tag). The workflow is: bump every `tag = "vX.Y.Z"` in `[workspace.dependencies]`,
re-sync each vendored crate against the new upstream while re-applying the N42 deltas above, then fix the
cascade. `update.sh` generates/applies diffs between a sibling `../reth` checkout and the vendored crates.
`patches/v1.4.3-base/` holds the historical baseline diffs. `.upgrade-backup/n42-custom-files/` keeps copies
of the N42-only files so they can be restored after an upstream overwrite.

Commit convention in this repo is Conventional Commits (`fix:`, `chore:`, `test:`), and upgrade work happens
on `upgrade/reth-vX.Y.Z` branches merged into `main`.

## Conventions

- `[workspace.lints]` denies `unused_must_use` and `rust_2018_idioms` and warns on `missing_docs`,
  `missing_debug_implementations`, `unreachable_pub`, plus a large clippy nursery set. New crates should
  carry `[lints] workspace = true`.
- N42-authored files start with the `// Copyright (c) 2017-2025 N42 Contributors` / SPDX header.
- Recent commits have deliberately removed `unwrap`/`panic` from consensus and SDK paths; keep new code in
  `crates/n42/clique`, `consensus-client`, and `mobile-sdk` on `Result`-based error handling.
- Several top-level `*.md`/`*.txt` reports (`EF_TESTS_*`, `UPGRADE_STATUS.md`, `TEST_SUMMARY.txt`,
  `SECURITY_*`) are point-in-time snapshots from past upgrades — treat them as history, not current state.
- Much of `docs/` and `N42_CUSTOMIZATIONS.md` is written in Chinese.
