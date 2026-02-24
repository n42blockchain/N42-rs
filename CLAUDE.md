# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

N42 is a high-performance blockchain platform built as a fork of [Reth](https://github.com/paradigmxyz/reth) (currently v1.11.0), with a custom APoS (Authority Proof of Stake) consensus mechanism and Beacon chain integration. Rust 1.86+, edition 2021. Workspace version: 2.1.5.

## Build & Development Commands

```bash
# Build (default-member is bin/n42)
cargo build                        # debug build
cargo build --release              # release build (LTO enabled)

# Run node
cargo run --release -- --dev       # local dev node (no mining — no signer set)

# Run node with consensus signer (enables mining at 8s block interval)
cargo run --release -- node \
  --chain n42 \
  --dev.consensus-signer-private-key <PRIVATE_KEY> \
  --dev.block-time 8s

# Tests
cargo test -p n42-testing          # primary test suite (CI uses this)
cargo test -p n42-ef-tests         # Ethereum Foundation spec tests
cargo test -p <crate-name>        # single crate tests
cargo test -p <crate-name> -- <test_name>  # single test

# Lint (matches CI exactly)
cargo clippy --workspace --lib --bins --examples

# Check compilation
cargo check --workspace

# Generate RPC/local docs
cargo doc --no-deps --all-features --document-private-items

# Chain data migration from old node via RPC
RUST_LOG=info ./n42 node \
  --chain n42 \
  --dev.block-time 4s \
  --disable-discovery --with-unused-ports \
  --dev.consensus-signer-private-key $NODE_PRIVATE_KEY \
  --datadir $NODE_DATA_DIR \
  --dev.migrate-old-chain-data-from-rpc $OLD_CHAIN_RPC

# Enable HTTP JSON-RPC
n42 node --http --http.api "eth,net,web3,txpool,debug,trace,admin,rpc,reth,ots"
```

## Architecture

### Reth Fork Model

N42 forks ~14 Reth crates via Cargo `[patch]` in the workspace Cargo.toml. The fork crates live under `crates/` and shadow upstream Reth dependencies. The `[patch.'https://github.com/paradigmxyz/reth.git']` section maps each forked crate to a local path. Two alloy crates (`alloy-rpc-types-engine`, `alloy-rpc-types-beacon`) are patched via `[patch.crates-io]`.

Key forked crates with significant N42 modifications:
- `crates/primitives-traits/` — `clique_utils.rs` for seal hash and signer recovery
- `crates/consensus/consensus/` — Extended `Consensus` trait with APoS methods (`prepare`, `seal`, `snapshot`, `propose`, `wiggle`, etc.)
- `crates/storage/provider/` — Largest patch (~9K lines), Beacon table integration
- `crates/storage/db/`, `crates/storage/db-api/` — Beacon table definitions + models (`beacon.rs`, `snapshot.rs`, `validator.rs`)
- `crates/storage/storage-api/` — Beacon/Snapshot/Validator API traits
- `crates/chainspec/` — N42 chain spec, genesis configs (`res/genesis/n42.json`, `n42_devnet.json`)
- `crates/ethereum/hardforks/` — N42-specific hardforks (BeijingFork, `n42.rs`)
- `crates/ethereum/evm/` — Uses `recover_address()` for beneficiary in `evm_env()`
- `crates/net/peers/` — N42 testnet bootnodes
- `crates/node/core/` — N42 node config, version, dev flags
- `crates/rpc/rpc-types-compat/` — RPC type compatibility shims

When upgrading Reth upstream, use `update.sh` to generate diffs against a checked-out `../reth` directory (requires `reth_dir` pointing to upstream), apply patches, resolve conflicts. See `docs/RETH_UPGRADE_GUIDE.md`.

### N42-Native Crates (`crates/n42/`)

These are wholly N42-owned (not forked from Reth):

| Crate | Purpose |
|-------|---------|
| `clique` | APoS consensus engine — snapshot caching, voting, difficulty calculation, signer recovery |
| `primitives` | Beacon chain types — BeaconState, BeaconBlock, Validator, SSZ encoding, tree hash |
| `consensus-traits` | Trait definitions — `SignerManager`, `VotingManager`, `AposConsensus` |
| `consensus-core` | Consensus logic — state transitions, block validation, slot/epoch utilities |
| `consensus-client` | Orchestration — Miner, Validator, N42Migrate, P2P messaging, RPC endpoints |
| `engine-types` | `N42Node` type implementation |
| `engine-primitives` | `N42PayloadAttributesBuilder` and payload types |
| `storage` | N42 Beacon table definitions, codecs, table IDs (starting at 100) |
| `pubsub-mem` | In-memory pub/sub router for block broadcasting to validators |
| `gateway` | Aggregator, local router, miner client, health/server endpoints |
| `reth-rpc` | N42-specific RPC extensions |
| `merkle_db_rs` | Merkle DB implementation |
| `fusaka` | Prague/Osaka hardfork support (EIP-7702) |
| `mobile-sdk` | JNI bindings for mobile integration |
| `alloy-rpc-types-engine` | Patched alloy engine types (adds `difficulty`/`nonce` fields to `ExecutionPayloadV1`) |
| `alloy-rpc-types-beacon` | Patched alloy beacon types (adds `difficulty`/`nonce` to `BeaconExecutionPayloadV1`) |
| `ef-tests` | Ethereum Foundation execution spec test runner |
| `n42-testing` | Test framework and utilities |

### Execution Flow

Entry point: `bin/n42/src/main.rs`

1. CLI parses args → builds `N42Node` via `reth-node-builder`
2. Creates channels: `verification_tx/rx` (mpsc, cap 10,000), `broadcast_tx` (broadcast, cap 1,000), `router_tx/rx` (mpsc, cap 10,000)
3. Registers RPC extensions (`ConsensusExt` on auth module, `ConsensusBeaconExt` on public modules)
4. Spawns `pubsub` router loop and a bridge task that fans broadcast channel messages out to individual validator topics (keyed by BLS pubkey hex)
5. Spawns either `N42Miner` (when `--dev.consensus-signer-private-key` is set) or `N42Migrate` (when migration flags are set); falls back to `MiningMode::NoMining`
6. Miner uses configurable `MiningMode` (interval-based with default 8s block time)

### Consensus Architecture

APoS consensus (`n42-clique`) uses:
- Snapshot-based validator set management (512 in-memory snapshots, 4096 cached TDs, 128 cached reads)
- Voting mechanism for authorizing/deauthorizing validators
- Wiggle time calculation for block timing
- ECDSA signature recovery from block headers (`seal_hash` + `recover_address`)
- BLS pubkeys for Beacon chain integration
- `UnverifiedBlock` type passed to validators for verification; validators return BLS signature over `AttestationData`

### Storage Layer

Three-tier design: Application (reth-provider) → Storage API → DB API (MDBX).
N42 extends with Beacon-specific tables: `BeaconStateRecord`, `BeaconBlockRecord`, `BeaconNum2Hash`, `PlainValidatorState`, `ValidatorsHistory`, `ValidatorChangeSets`.
N42-table IDs start at 100 (defined in `crates/n42/storage/src/tables.rs`, `N42TableId` enum).

### N42-Specific RPC

`consensusBeaconExt` namespace (exposed on public WebSocket, sensitive — don't expose publicly):
- `subscribeToVerificationRequest(pubkey)` — WS subscription; emits `UnverifiedBlock` to validators
- `submitVerification(pubkey, sig, attestation_data, block_hash)` — validator submits BLS attestation
- `get_beacon_block_by_hash/number`, `get_beacon_state_by_*`, `get_beacon_validator_by_pubkey`, `get_total_effective_balance`

`consensus` namespace (on auth module):
- APoS signer management and proposal/discard methods

## Workspace Conventions

- **Lints**: Workspace-level clippy lints are enforced (62 nursery rules enabled). `unused_must_use` is deny. `result_large_err` is explicitly allowed.
- **Allocator**: Default is jemalloc. Use `--no-default-features` when switching to snmalloc.
- **Features**: `dev` feature enables dev-mode CLI options (consensus signer key, block time config, migration flags).
- **Serialization**: Beacon types use SSZ (`ethereum_ssz`) + Tree Hash. Standard Ethereum types use RLP/serde.
- **Where to add N42 features**: consensus traits → `n42-consensus-traits`; state logic → `n42-consensus-core`; storage types → `n42-storage`; APoS impl → `n42-clique`. Keep `reth-consensus` as a thin pass-through layer.
