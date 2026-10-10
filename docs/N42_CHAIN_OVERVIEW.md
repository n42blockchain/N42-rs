# N42 native chain: overview for new engineers

Status: written 2026-10-09 from the repository's own docs and crate-level comments. Numbers are quoted from
`docs/BREAKTHROUGH_DESIGN.md` (BD); where a source was unclear the text says "(to be confirmed)".

## 1. Positioning and overall architecture

N42 is a **partial fork of reth**. Most of reth is a git dependency pinned to an upstream tag (`v2.7.0` since
2026-10-02; grep `Cargo.toml` for the tag). A subset of reth crates is vendored under `crates/` and substituted into
the whole dependency graph through `[patch.'https://github.com/paradigmxyz/reth.git']`. N42 code lives in
`crates/n42/*` and `bin/n42/`.

| Kind | Where | Rule |
| --- | --- | --- |
| Original N42 code | `crates/n42/*` | Freely editable workspace members |
| Vendored reth, workspace member | `crates/chainspec`, `crates/consensus/consensus`, `crates/storage/{db,db-api,provider,storage-api}`, `crates/node/{core,builder}`, `crates/ethereum/{cli,hardforks,node}`, `crates/net/peers`, `crates/chain-state` | Changes rewrite reth for the whole graph; keep them additive |
| Vendored reth, patch target only | `crates/revm`, `crates/net/network`, `crates/net/network-api`, `crates/storage/storage-overlay`, `bin/reth` | Compile only as dependencies; `cargo test --workspace` does not run their tests |

`N42_CUSTOMIZATIONS.md` (Chinese) is the maintained inventory of the changes inside forked crates.

Two consensus paths exist. **HotStuff-2** is the native chain (genesis `"consensus": "hotstuff"`); **APoS**
(extended Clique) is the older path. The native chain also uses a QMDB state commitment (`"stateScheme": "qmdb"`).

Layering of the n42-native crates:

| Layer | Crates |
| --- | --- |
| Consensus | `h2-primitives` (BLS, message types), `h2-consensus` (state machine, validator set, finality verification), `h2-wire` (Go/Rust wire codec) |
| Network | `h2-net` (libp2p GossipSub transport and RPCs) |
| Execution seam | `h2-execution` (`ExecutionLayer` trait, `ExecutionDriver`), `h2-el-rpc` (Engine API client), `h2-node` (`H2Service` loop, validator binaries) |
| State | `bmt-core`, `twig-core`, `qmdb-state`, `qmdb-reth` |
| Transactions | `tx-types`, `tx-ingest`, `tx-queue` |
| Mobile | `mobile-verify`, `mobile-service`, `mobile-sdk` |
| Legacy APoS | `clique`, `clique-utils`, `consensus-client`, `primitives`, `engine-types`, `pubsub-mem` |

`bin/n42/src/main.rs` is the wiring. It builds the node from `N42Node` (`crates/n42/engine-types/src/node.rs`, a reth
`ComponentsBuilder` with `N42ConsensusBuilder`, `N42PayloadServiceBuilder`, `N42NetworkBuilder`), merges the
`consensusExt` (auth) and `consensusBeaconExt` (public) RPC namespaces from `bin/n42/src/consensus_ext.rs`, and
spawns `N42Miner` or `N42Migrate` (mutually exclusive) on the APoS path. On a chain whose genesis names a `hotstuff`
validator set, `bin/n42` runs `HotStuffConsensus` (gov5's header profile and roots) and spawns **no** miner; an
external fleet of `h2_validator` processes (`cargo run -p n42-h2-node --example h2_validator`) drives it over the
Engine API.

## 2. Consensus

### HotStuff-2

- `h2-consensus` holds the protocol state machine (`protocol`: proposal, voting, quorum assembly, pacemaker, view
  changes, timeout certificates), the validator set with epochs and leader selection (`validator`), and read-only
  finality verification of a committed gov5 H2-v4 `Decide` (`h2_finality`, usable by observers and mobile verifiers).
- Two voting rounds (R1 static vote, R2 commit vote). The genesis flag `hotstuff.twoPhaseVoteGate` (R1 static vote,
  R2 commit vote held until import) exists; it is `false` in `n42_fleet7_bench.json`.
- A quorum certificate (QC) comes from aggregated BLS votes; a timeout certificate (TC) drives view change. Timing
  keys in genesis: `period`, `baseTimeout`, `maxTimeout`, `fastPropose`, `minProposeDelayMs`.
- Leader rotation: leaders hold a tenure (the docs speak of "tenure handovers"); the exact rotation rule is in
  `h2-consensus/src/validator` (to be confirmed).
- Committee pool: genesis `hotstuff.committeePool` (`poolSize` 200000, `committeeSize` 512 in the fleet7 bench genesis).
  Every header links to the parent's committee evidence through `parentBeaconRoot`; `epochLength` is 200 in fleet7
  genesis files, 20 in `n42_devnet.json`.
- Block reward is paid as withdrawals (`devBlockReward`, `devFaucetAddress`).

### Interop with gov5 (Go client)

`h2-wire` is the Go/Rust contract and nothing else: the legacy H2 codec (`h2_wire.rs`) and the chain-bound v4
envelope with its signing domains (`h2_v4.rs`). It has no networking stack. Fixtures under `testdata/` are
byte-exact contracts shared with gov5 (`internal/consensus/hotstuff/testdata/`); compare by SHA-256 of raw bytes,
never text mode. Genesis key `interopV4: true` selects the v4 envelope. `docs/N42_26_PORT.md` ("Joining a Go
fleet") lists every cross-client rule that had to be matched. gov5 does not support the direct vote protocol (below),
so mixed fleets must use `gossip` or `both`.

### Deferred execution

Rule (`docs/PHASE_D_DEFERRED_EXECUTION.md` section 2): the header of block N carries the execution result of an
earlier block (`stateRoot`, `receiptsRoot`, `logsBloom`, `gasUsed`) instead of its own, so a follower can vote
before it has imported the block. Execution of a block cannot fail it (section 4).

- **Depth 1**: header N carries N-1's result. **Depth 2** (`docs/DEFERRED_DEPTH_2_DESIGN.md`): header N carries the
  result of N-2; blocks 1 and 2 carry the genesis result; block 3 is the first with an executed result.
- Genesis keys: `deferredExecutionTime` (0 = active from genesis) and `deferredExecutionDepth` (default 1; depth 2 is
  accepted only with `deferredExecutionTime` 0).
- Voting paths: **import-gated** (the follower imports, then votes) and **check-before-slot**
  (`N42_CHECK_BEFORE_SLOT=1`; a deferred block queued behind busy import slots sends its sealed header as a
  check-only request and the layer answers one CHECKED frame when the header is one of its kept builds;
  `docs/SHARED_EXECUTION_SCOPE.md` section 19).
- Settlement: see section 4 (settlement tags).

### APoS (legacy)

`crates/n42/clique` (`APos`) implements snapshots, signer voting, seal/verify_seal and wiggle timing, plugged into
the extended `Consensus` trait in `crates/consensus/consensus`. `N42Miner` (`consensus-client/src/miner.rs`) builds,
seals, broadcasts an `UnverifiedBlock` over `pubsub-mem` and collects BLS verification signatures through
`consensusBeaconExt.submitVerification`. Chain ids: N42 testnet 1142, `N42_DEVNET` 1143.

## 3. Networking

`h2-net` is the gov5-compatible GossipSub transport (libp2p). It carries gov5's router parameters, topic strings and
message-ID function, so a Rust member behaves like a Go one at the pubsub layer. The GossipSub parameters are a gov5
wire contract asserted in tests, not a tuning surface.

| Piece | Detail |
| --- | --- |
| Consensus topic | `/n42/h2/4/ssz_snappy` (v4 envelopes), via `H2V4Transport` (member) or `H2V4Observer` (read-only) |
| Block body topic | `block_gossip`: `/n42/<fork digest>/block/ssz_snappy`, fork digest = first 4 genesis-hash bytes; payload is RLP `[header, txs, verifiers, rewards]` (a proposal names only a hash, so followers need it to vote) |
| Transactions | gov5's `transaction_v2` topic; validators with `--el-rpc` gossip their pool and hand received ones to `eth_sendRawTransaction` |
| Handshake | `/rpc/status/1/ssz_snappy`; gov5 drops peers that skip it |
| Sync RPCs | `block_by_hash` (fetch-on-miss, served and used), `bodies_by_range` (served) |
| Identify | libp2p identify; go-libp2p-pubsub meshes only with identified peers |
| Identity | secp256k1 libp2p identities with Noise; the libp2p `secp256k1` feature is load-bearing |

Vote transport: `N42_VOTE_TRANSPORT=gossip|direct|both` (default `gossip`). `direct` sends a vote by request-response
(`/n42/vote/1`, `h2-net/src/rpc.rs`) straight to the view's leader, whose peer id is learned from a signed hello
(`h2-consensus` `protocol/vote_hello.rs`, `h2-node` `direct_votes.rs`); an unknown leader falls back to gossip.
`both` sends on both paths. Related switches: `N42_GOSSIP_OFF_LOOP=1` (swarm polled on its own task, bounded
channels) and `N42_VOTE_AGGREGATE_VERIFY=1`. The fleet is a static full mesh with no discovery and no devp2p.

## 4. Execution layer

- **Seam**: `h2-execution` defines `ExecutionLayer` (Engine API in alloy types, no reth types) and
  `ExecutionDriver`, which services consensus requests. `h2-el-rpc` is the adapter that speaks authenticated
  JSON-RPC Engine API, so one adapter drives reth, this repo's node, or gov5's `eth-el` mode. `h2-node` `H2Service`
  connects network, consensus and execution; it does not own discovery, key management or persistence.
- **Seal-first build**: with deferred execution the leader seals before its own execution finishes
  (`PHASE_D_DEFERRED_EXECUTION.md` section 13). The leader lays the unlanded ancestors' state over the engine's
  state: `N42_LEADER_LAYERS` (kept builds `KEEP = 3`; see `DEFERRED_DEPTH_2_DESIGN.md`).
- **Own-block hand-off**: the leader's own block reaches its layer as a header-only `request::OWN_BLOCK`; the build is
  kept in `built_executions` and the QMDB tree is renamed to the sealed hash (`chain_alias::rename`). Followers
  import through `payload_serve.rs` / `follower_import.rs`. At E=1 (seven keys on one layer) there is no per-hash
  gate, so every key would execute the block again (`SHARED_EXECUTION_SCOPE.md` section 2) (details of the current
  import-once handling: to be confirmed).
- **Settlement tags** (`N42_SETTLEMENT_TAGS=split|legacy`, default `split`, `h2-execution/src/settlement.rs`):
  latest = committed block; safe = newest certified block (one behind under deferred execution); finalized =
  certified and at or below this node's persisted block (read via `n42Engine_persistedBlock`). `legacy` sends
  head = safe = finalized = committed.
- **Parallel execution**: `N42_PARALLEL_BUILD=1` (the leader's transfers in per-sender batches, grafted onto the
  block's state), `N42_FOLLOWER_GRAFT=1`, `N42_FOLLOWER_PARALLEL=1`, `N42_PARALLEL_BUILD_THREADS=64` (build pool),
  `N42_PARALLEL_STATE_COMMIT` (on by default). Details: `docs/BREAKTHROUGH_DESIGN.md` 10.x and
  `NATIVE_FLEET7.md`.
- `N42_CANON_NOTIFY_LEAN=1` (vendored `crates/chain-state`, bench only): the canonical-chain notification carries
  blocks and trie handles but an empty `ExecutionOutcome`, which saves ~23 ms per block on the engine tree thread;
  pool maintenance, RPC caches and log subscriptions are degraded (see `N42_CUSTOMIZATIONS.md`).

## 5. Storage and state

- **QMDB** is the state commitment: the header's state root is the root of a QMDB twig forest, not an MPT root.
  `bmt-core` is a pure-blake3 sparse binary Merkle tree (SBMT) with proof verification; `twig-core` is the
  all-DRAM twig engine (2048-leaf twig subtrees plus an upper Merkle over twig roots, append-only slot model,
  `qmdb_compat` = gov5's key derivation, account encoding, proof codec and portable-snapshot verifier). Both have
  no reth/mdbx dependencies so mobile/FFI can verify proofs.
- `qmdb-state` turns a block's changes into a root and proofs (no reth types). `qmdb-reth` wires it into reth:
  `chainspec` (reads `stateScheme`, rebuilds the genesis header with a QMDB root), `changes` (revm bundle to leaves,
  gov5's dirty-set rule), `node_state` (the one forest per node, persisted so a restart continues the append history).
- Persistence design: `docs/QMDB_ENTRY_LOG.md` (entry file mapped from disk, checkpoint bounded by `next_slot`,
  restart rebuilds twig node arrays from leaves; the P1 core in `twig-core` is all-DRAM, the entry log was a design
  when written, current status to be confirmed). Checkpoint compaction details: to be confirmed.
- **Leader layers**: `N42_LEADER_LAYERS` lets a build stack unlanded parent layers. **Tree lease**
  (`N42_QMDB_COMPUTE_OFFLOCK=1`): the tree is lifted out of the forest under a short lock, hashed unlocked and
  returned. `N42_QMDB_RENAME_DEFER=1` queues the rename while the forest lock is held. `N42_QMDB_PERSIST_BATCH=1`
  batches persistence (BD 10.101).
- **Relation to reth storage**: MDBX and static files remain the backend. QMDB read hooks
  (`reth_storage_api::n42_state`, modes `on` / `verify`) serve latest state in `crates/storage/provider` and
  historical/overlay state in `crates/storage/storage-overlay`. `N42_HASHED_TABLES=off` stops writing hashed tables.
  `N42_ACCOUNT_HISTORY=off` skips the `AccountsHistory` index (changesets kept, gap marker `N42AccountHistoryGap`);
  `N42_PERSIST_QMDB_IN_SCOPE=1` advances the QMDB view beside backend writes
  (`docs/PERSISTENCE_COST_STUDY.md`, `crates/storage/provider/src/providers/n42_persist.rs`).
- `MemoryOverlayStateProvider` (removed upstream in v2.7.0) is kept in the vendored provider crate.
- Beacon tables (`BeaconStateRecord`, `BeaconBlockRecord`, ...) serve the APoS path.

## 6. Transaction layer

| Component | Role |
| --- | --- |
| `tx-types` | `N42TxEnvelope` = reth's envelope (0x00-0x04) plus type **0x50** `AltSigTx`: Ed25519, `alg_type` 0x01, 32-byte pubkey, 64-byte signature, no contract creation, sender = `keccak256(alg_type \|\| pubkey)[12..]`, EIP-7932 aligned. Spec: `docs/spec/N42_TX_0x50.md` |
| Gate | Genesis `config.altSigTx: true` (both fleet7 genesis files; not the devnet). Otherwise the pool refuses the type, ingest drops it, block validation rejects it |
| `tx-ingest` | Binary TCP path (length-prefixed raw EIP-2718 frames, in-order acks, no JSON/hex round trip). Verifies 0x50 in batches (`N42_ED25519_BATCH`, default 64) and records senders in a shared cache (`N42_ALTSIG_SENDER_CACHE`, default 2^20) read by follower import and payload conversion |
| `tx-queue` | A builder-side source beside reth's pool (the pool cost ~0.5 s per 163k-tx block). Per-sender nonce-ordered lanes; hands out one tx per sender per pass in first-arrival order; gapped lanes are held out; `frames` (`FramePlan`, `NewFrame`, `MAX_FRAMES`) plan blocks; switches `N42_QUEUE_OFFLOCK`, `N42_QUEUE_PLAN_SNAPSHOT`, `N42_TX_QUEUE_DRAINER=1`, `N42_TX_QUEUE_RUN`. Genesis `frameBlocks: true` (meaning: to be confirmed) |

Batch verification of Ed25519 costs 13 us per signature at batch 64 against 29-63 us for one `ecrecover`
(`docs/sigbench/`, `docs/SIGNATURE_AND_BATCH_TX_SURVEY.md`). Test vectors: `crates/n42/tx-types/testdata/altsig_vectors.json`.

## 7. Mobile verification

| Crate | What it is |
| --- | --- |
| `mobile-verify` | Formats and the phone's half: BLS-signed verification receipts, aggregation into attestations, state proofs (twig / SBMT) checked against a block's state root, a code cache. Execution-stack free: runs on `bmt-core` and `twig-core`, so no EVM, MDBX or networking is needed. The re-execution verifier is deliberately not ported |
| `mobile-service` | The node's half: what it publishes for phones and what it does with what they send back. Finality is served as the committed gov5 v4 `Decide`, verifiable against the validator set, so a phone need not trust the service |
| `mobile-sdk` | Validator key, deposit and exit tooling (`deposit_exit.rs`, `blst_utils.rs`, `jni.rs`, `c_ffi.rs`), `build-aar.sh` for Android and `ios/`; `examples/mobile-sdk-test.rs` drives `tests/e2e.sh` |

A light client can verify: a committed `Decide` (needs the validator set and `h2_finality`), a state proof for an
account against the block's state root (needs the proof and the root from a verified header), and attestations by
validators. Exact end-to-end data flow is in `docs/` mobile notes (to be confirmed).

## 8. Deployment shapes and performance today

| Shape | Description |
| --- | --- |
| Devnet | `scripts/devnet-fleet.sh <tag> <secs> [--gov5]`: one QMDB node, four Rust validators or three plus a gov5 member; genesis `n42_devnet.json` |
| fleet7 | `scripts/fleet7.sh` (`up --fresh`, `status`, `watch`, `roll`, `down`), seven members with their own layer and validator, static full mesh; launch arguments live only in `scripts/fleet7-env.sh`; genesis `n42_fleet7.json`; bench genesis `n42_fleet7_bench.json` (epoch 200, 200k-key pool, 512 signers, `altSigTx`, `frameBlocks`) |
| E=1 bench | Seven validator keys share one execution layer (`SHARED_EXECUTION_SCOPE.md`); rounds via `scripts/fleet7-bench.sh` |

Current results (BD 10.102, 200k transfers per block, E=1): the plain S1 set holds 3.9M tx/s across all three
windows at 40 and 35 ms pacing (3.93 / 3.93 / 3.52M); the X7 leg `D2S12P40T64X6` read window 1 at 3.947M, a round
total of 342.6M transactions and a cycle of 51 ms (sealed_at median 38 ms). The goal is 5M tx/s, a 40 ms cycle at
200k per block.

The X7 switch set: `N42_QMDB_RENAME_DEFER=1`, `N42_HANDOFF_HEAD_MOVE=number`, `N42_HANDOFF_NO_CLONE=1`,
`N42_HANDOFF_MOVE_BODY`, `N42_CANON_NOTIFY_LEAN=1`, `N42_QUEUE_OFFLOCK=1`, `N42_QMDB_COMPUTE_OFFLOCK=1`,
`N42_QMDB_PERSIST_BATCH=1`, plus `N42_CHECK_BEFORE_SLOT=1`, `N42_LEADER_LAYERS=6`, `N42_PARALLEL_BUILD_THREADS=64`,
on a depth-2 genesis. (Exact composition of each leg label such as X6 / X7 / X8: BD 10.100-10.102.) The snapshot
planner (X8, `N42_QUEUE_PLAN_SNAPSHOT`) regressed and was excluded. Never conclude from a single round: window 1 and
the round total are the stable metrics (`scripts/fleet7-repeat.sh`).

## 9. Further reading

| Topic | Document |
| --- | --- |
| Fork boundary, customizations | `CLAUDE.md`, `N42_CUSTOMIZATIONS.md` (Chinese), `docs/ARCHITECTURE.md`, `docs/RETH_2_7_0_UPGRADE.md`, `docs/RETH_UPGRADE_GUIDE.md` |
| Ported crates, gov5 interop | `docs/N42_26_PORT.md` |
| Deferred execution, settlement | `docs/PHASE_D_DEFERRED_EXECUTION.md` (sections 1-3, 17), `docs/DEFERRED_DEPTH_2_DESIGN.md` |
| Shared execution layer, seal chain | `docs/SHARED_EXECUTION_SCOPE.md` (sections 19-20), `docs/E1_MANY_KEYS.md` |
| Fleet and benches | `docs/NATIVE_FLEET7.md`, `scripts/fleet7-env.sh` |
| Performance record | `docs/BREAKTHROUGH_DESIGN.md` (10.98-10.102) |
| 0x50 transactions | `docs/spec/N42_TX_0x50.md`, `docs/ROADMAP_ED25519_TX.md`, `docs/SIGNATURE_AND_BATCH_TX_SURVEY.md` |
| QMDB, persistence | `docs/QMDB_ENTRY_LOG.md`, `docs/QMDB_LAYERZERO_COMPARISON.md`, `docs/QMDB_UPGRADE_PLAN.md`, `docs/PERSISTENCE_COST_STUDY.md` |
