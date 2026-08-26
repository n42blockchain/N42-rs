# N42-26 → n42-rs port, and gov5 interop status

Status as of 2026-08-24. Companion to `docs/RETH_UPGRADE_GUIDE.md`.

## Why this document exists

Three N42 clients are in play on this host:

| Repo | Language | Base | Consensus | State commitment |
|---|---|---|---|---|
| `n42-rs` (this repo) | Rust | reth **v1.11.0** (edition 2021, rustc 1.86) | APoS / Clique | Ethereum MPT |
| `../N42-26` | Rust | reth **2.4.1** (edition 2024, rustc 1.97, local `../reth` path dep) | HotStuff-2 | QMDB twig-forest + JMT |
| `../N42-gov5` | Go | go-ethereum 1.17.4 / Erigon-derived | HotStuff-2 (+ APoS, APoA) | pluggable: MPT / JMT / **QMDB** / Verkle / LtHash |

gov5 runs the production `mainnet_qmdb_staggered` 7-node fleet (chainId 94,
`stateScheme: qmdb`). N42-26 is the Rust client already built against that
fleet's contracts. This repo is the older Rust client; this document tracks what
of N42-26's interop surface now exists here, and what does not.

## What was ported

Eight new crates under `crates/n42/`, all additive — nothing in the existing
APoS node wiring was touched. **199 tests pass**, including every pinned gov5
cross-client vector. The lockfile gained 68 packages (libp2p's tree) and lost
none: no existing package version was replaced, so the reth v1.11.0 build graph
resolves exactly as before.

Test count by crate: bmt-core 7, twig-core 38, h2-primitives 48, h2-wire 9,
h2-consensus 209, mobile-verify 61, h2-net 35, h2-execution 9 — **423 total**.

| Crate | From N42-26 | Lines | Tests | What it gives this repo |
|---|---|---|---|---|
| `n42-bmt-core` | `n42-bmt-core` | 898 | 7 | Sparse binary Merkle tree (Blake3). Zero deps beyond blake3/serde/thiserror. |
| `n42-twig-core` | `n42-twig-core` | 4,092 | 38 | QMDB twig engine + `qmdb_compat`: gov5 key derivation, account-value encoding, proof codec, and the **portable-snapshot verifier**. |
| `n42-h2-primitives` | `n42-primitives` | 1,846 | 48 | BLS12-381 keys/aggregation/batch-verify and the HotStuff-2 message types, including the chain-bound v4 signing domains. |
| `n42-h2-wire` | `n42-network/src/h2_{wire,v4}.rs` | 1,200 | 9 | The Go↔Rust wire contract: legacy H2 codec + v4 envelope, all five documented rejection paths. Carries no networking stack. |
| `n42-h2-consensus` | `n42-consensus` (all but `adapter.rs`) + `n42-consensus-service/h2_finality.rs` | 12,599 | 209 | The HotStuff-2 protocol core — state machine, proposal, voting, quorum assembly, pacemaker, view change, timeout certificates — plus validator set, epoch management, leader selection, rotor, vote log, and `VerifyH2V4Decide`. Enough to *participate*, not only observe. |
| `n42-mobile-verify` | `n42-mobile` (format half) | 2,363 | 61 | Verification receipts, BLS attestation aggregation, twig/SBMT state proofs, hot-contract code cache. |
| `n42-h2-net` | new, modelled on `n42-network` | 2,266 | 35 | gov5-compatible GossipSub transport: topic strings, router parameters, gov5's message-ID function, the `/rpc/status/1/ssz_snappy` handshake. `H2V4Transport` is the bidirectional mesh member (subscribe, decode, **publish**); `H2V4Observer` is the read-only use of it, turning wire bytes into verified finality. Ships a runnable `h2_observer` example. |
| `n42-h2-execution` | seam from `n42-consensus-service/src/el.rs`; driver is new | 920 | 9 | The execution-layer seam (`ExecutionLayer`, Engine API in alloy types only) and the driver that services consensus's requests against it, plus an in-memory EL for testing the loop. |

### Renames

`n42-primitives` in N42-26 collides with this repo's existing `n42-primitives`
(beacon-chain primitives, `crates/n42/primitives`). The port is therefore
`n42-h2-primitives`, and imports were rewritten `n42_primitives::` →
`n42_h2_primitives::`. Likewise `n42-mobile` → `n42-mobile-verify` to sit
alongside the existing `mobile-sdk` crate, which does something different
(validator key/deposit/exit tooling).

`n42-h2-consensus` defines its own minimal `ValidatorInfo` (address, BLS pubkey,
optional peer id) rather than pulling N42-26's `n42-chainspec`, which would drag
in reth-chainspec **and** libp2p for three fields. The serde field names match
gov5 genesis `validators` entries, so chainspec JSON deserializes unchanged.

### Edition-2021 adaptations

N42-26 is edition 2024; this repo is edition 2021. Two mechanical fixes were
needed, both marked in-place:

- `n42-mobile-verify/src/verification.rs` — one let-chain (`&& let Some(..)`)
  rewritten as a nested `if let`. Same semantics.
- `n42-twig-core` tests — `rand` 0.9 here vs 0.10 there: `rand::RngExt` →
  `rand::Rng`, plus an explicit `RngCore` import for `fill_bytes`.
- The protocol core carried **11 more let-chains**, each rewritten in place and
  marked `// edition-2021: N42-26 writes this as a let-chain`. Nine had no
  `else` and became nested `if let`. Two could not: the `changes_hash` binding
  in `proposal.rs` has an `else`, so the guard moved into `Option::filter`
  inside the same expression; and the import-gated vote in `proposal.rs`
  resolves the pending view up front, which also ends the borrow of `self`
  before `send_vote`.

Everything else compiled unchanged, which is the useful signal: these modules
were written free of both the reth version and the edition.

## What was deliberately NOT ported

| Not ported | Why |
|---|---|
| `n42-consensus/adapter.rs` | The only meaningfully reth-coupled file in that crate (14 refs: `FullConsensus`, `EthBeaconConsensus`, `RecoveredBlock`, `BlockExecutionResult`). Those APIs differ between reth 1.11 and 2.4.1. Porting it means either the reth upgrade or a rewrite against 1.11. |
| `n42-consensus/{receipt,extra_data}.rs` | 175 lines. `receipt.rs` needs `alloy_consensus::EthereumReceipt` (an alloy 2.x name; this repo is on alloy 1.6), and `extra_data.rs` returns `reth_consensus::ConsensusError`. Both are execution-side glue, not protocol. |
| `n42-consensus-service` (orchestrator, ingest, persistence, EL port) | Binds consensus to the reth 2.4.1 node/engine. This is where the version wall actually is. |
| `n42-mobile/verifier.rs`, `packet.rs`, `quic_client.rs` | Re-execution verifier (reth-revm), and the QUIC transport. Format was the goal, not transport. |
| `n42-jmt` | Depends on `n42-execution` (reth-coupled) and `reth-libmdbx`. The twig/BMT engines underneath it are ported; the storage-backed tree is not. |

## Interop contract — fixture integrity

The four gov5 fixtures are byte-exact contracts. Verified on 2026-08-24 that the
copies vendored here match gov5 `main` **and** the SHAs pinned in
`../N42-gov5/docs/H2_V4_RUST_SYNC_BRIEF.md`:

```
0c5877432b8d7adb3fc60c5226564ad1d0e099b6c73f39b823703926e82d2aee  cross_client_h2_v1.json
f3f20d4641455eaf7ea6c96641fc4674134080aefcb300c219ab34a53d4d9510  h2_v4_domains_v1.json
09a98f549fcfa1b4185b78b975fa680608c73e169758cb0c052c72efbff4ff83  h2_v4_envelope_v1.json
feacd6d0d2dc3babcbe3440384021ee9291b68103baaf7d47cd0ff1c6b703488  h2_v4_finality_v1.json
```

Locations here: `crates/n42/h2-wire/testdata/` (first three),
`crates/n42/h2-consensus/testdata/` (finality), plus
`crates/n42/twig-core/testdata/cross_client_v1.json` for the QMDB vectors.

**Compare by SHA-256 of raw bytes, never text-mode content.** gov5 learned this
the hard way: a Windows checkout with `core.autocrlf=true` rewrote these files
to CRLF and produced phantom drift. gov5 pins `testdata/*.json -text` in
`.gitattributes`; do the same here if this repo is ever checked out on Windows.

Against the brief's action list for the Rust side:

- [x] 1. Verify fixture SHAs
- [x] 2. v4 domains, all eight message phases — `h2_v4::tests::matches_gov5_domains_and_binds_chain_identity`
- [x] 3. v4 envelope codec + five rejection paths — `h2_v4::tests::envelope_decoding_rejects_all_five_documented_paths`
- [x] 4. Consume finality proofs — `h2_finality::tests::verifies_gov5_finality_fixture_and_binds_domain`
- [x] 5. Transport for the observer path — `n42-h2-net`. A two-node gossip
  loopback test (`tests/gossip_loopback.rs`) publishes a fixture Decide over a
  real socket through a gov5-parameterised mesh and verifies it on the other
  side. **Partially attached to a real Go node — see below.**
- [x] 7. Publish path — `H2V4Transport::publish`. `tests/transport_publish.rs`
  sends a fixture Decide from one transport and verifies it as finality at a
  peer that did not send it, which is the direction an observer never exercises:
  without it a Rust validator can vote into the void and look healthy doing it.
  Chain-identity mismatch is refused before the wire, and an empty mesh is
  reported as transient so a node that starts before its fleet retries instead
  of giving up.
- [ ] 6. (Standing constraint) do not configure epoch validator changes on a v4 chain.

## Live cross-client attach: how far it got

There is no gov5 fleet on this Linux host — the deployment docs point at a
Windows operator box (`E:\qs-node0..6`). So a real Go node was built and run
here instead: gov5 `v5.7.960` from source, on the purpose-built
`h2_interop_test` chainspec (chainId 96, four validators, `interopV4: true`).

What worked: **the Rust observer peered with the genuine Go node.** Noise
handshake, yamux muxing, libp2p identity negotiation, and gossipsub version
negotiation all succeeded — the Rust log reports
`peer_type=Gossipsub v1.2` for the Go peer, and the observer subscribed to
`/n42/h2/4/ssz_snappy`.

**One real bug was found and fixed only because of this run.** gov5 nodes carry
**secp256k1** libp2p identities. The first attach failed with:

```
Handshake failed: Invalid public key: cargo feature `secp256k1` is not enabled
```

`n42-h2-net` had a minimal libp2p feature set that omitted it (N42-26's dep list
includes it; it was dropped when the feature list was trimmed). Fixed, with a
comment saying why it is not optional. The observer also used to swallow dial
errors — a silent dial failure looks exactly like an idle fleet — so it now
reports `ObserverEvent::DialFailed`, which is what surfaced this at all.

**The status handshake is now implemented, and the connection is sustained.**
gov5 drops peers that cannot answer `/rpc/status/1/ssz_snappy`
(`internal/sync/service.go` wires `AddConnectionHandler(s.reValidatePeer, s.sendGoodbye)`).
`crates/n42/h2-net/src/{status,rpc}.rs` implements both directions of it, and a
run against the live Go node held for the full 75-second test with no
disconnect — the eventual drop in gov5's log is this side's timeout exiting.

Three things about that wire format are easy to get wrong, and all three are
pinned against vectors generated by gov5's own Go code
(`testdata/gov5_status_v1.json`):

- **RPC payloads are snappy-*framed*, gossip payloads are snappy-*raw*.** Mixing
  them produces bytes that look plausible and decode to nothing.
- **`sync_pb.Status` has eight protobuf fields but its SSZ codegen serialises
  two** — genesis hash and current height, both variable-length `H256`.
- **`H256` byte order.** Each 8-byte group is read big-endian into a `u64`
  (`ConvertHashToH256`) then written little-endian by SSZ, so every group appears
  reversed on the wire.

Reading is done by walking snappy frame headers to find the exact message
boundary rather than reading to EOF, because the varint declares the
*uncompressed* length and gov5 does not promise to half-close.

**A finding from the live run**: this gov5 node advertises a **zero genesis hash**
in its status (`ourGenesis: 0x0000…`), which is also why its gossip topics read
`/n42/00000000/...` rather than the real `3bec3e86` digest. Since gov5's
fork-digest check is just the first four bytes of that hash, an observer must
advertise the same value or be disconnected as a fork mismatch — confirmed from
both sides. gov5 has `--p2p.genesis-override` for exactly this class of
mismatch. Check what the fleet actually advertises before configuring
`--genesis`; it is not necessarily the chain's real genesis hash.

Also note the test node never joined the v4 topic: with no validator key
configured its HotStuff service stays idle, so `s.h2V4Identity` is nil and the
topic is never published to. A finality-carrying attach needs a chain with at
least one keyed validator producing blocks; the pinned `h2_interop_test`
validator private keys are not in the repo (they live on the operator host).

## Fleet database compatibility

The 7-node fleet is `stateScheme: qmdb`, not MPT. The supported cross-client
path is **not** opening gov5's MDBX directly — it is the portable snapshot:

```bash
# on the gov5 side
go run ./cmd/n42-qmdb-export --db <replay-target>/chaindata \
  --out <checkpoint>.n42qmdb --map.gb 512
```

The consumer checks chain/checkpoint identity and the Blake3 content digest,
then recomputes frozen leaf roots, active-bit commitments, twig roots, and the
upper root. That consumer now exists here:
`n42_twig_core::qmdb_compat::verify_portable_stream`, covered by
`verify_portable_stream_matches_in_memory_root`,
`portable_snapshot_roundtrip_checks_identity_root_and_digest`, and
`verify_portable_stream_non_power_of_two_twig_count`.

Caveat from the gov5 spec: the exporter fails if historical dead-slot rows are
missing, so production exports require replay data created with
`--qmdb-history`. A live-key-only snapshot cannot reproduce the split
commitment.

Also available here, byte-compatible with Go and cross-checked by the ported
tests (`cross_check_root_vs_gov5_go`, `cross_check_sorted_batch_vs_gov5_go`,
`cross_check_sharded16_root_vs_gov5_go`): `gov5_account_key`,
`gov5_storage_key`, `encode_gov5_account_value`, `GOV5_EMPTY_CODE_HASH`.

## Execution-layer glue

`n42-h2-consensus` decides about block *hashes*; it never touches a block body.
`n42-h2-execution` is what connects it to something that executes.

The seam (`el.rs`, ported from N42-26's `n42-consensus-service/src/el.rs`) is an
`ExecutionLayer` trait over the Engine API expressed **entirely in alloy types** —
`ExecutionData`, `ForkchoiceState`, `ForkchoiceUpdated`, `PayloadAttributes`,
`PayloadId`, `PayloadStatus`. No reth type crosses it. That is the property that
lets the consensus half of this repo stay independent of the reth version
underneath, and it is why the HotStuff-2 port landed without the 2.4.1 upgrade.

`driver.rs` services the three flows consensus actually needs:

| Consensus says | Driver does | Consensus hears |
|---|---|---|
| (leader for this view) | FCU-with-attrs, then resolve the build | `ConsensusEvent::BlockReady` |
| `EngineOutput::ExecuteBlock(hash)` | `new_payload` for that block | `ConsensusEvent::BlockImported` |
| `EngineOutput::BlockCommitted` | FCU with head = safe = finalized | — |

The middle row carries the safety property. N42 votes are **import-gated**: a
follower votes only after its own execution layer accepted the block. The tests
pin the three ways that must not be short-circuited — an `INVALID` verdict, an
EL error, and a `SYNCING`/`ACCEPTED` status (which is *not* a verdict: the EL has
not executed the block, so voting then would be voting blind). In all three the
driver withholds the import event and leaves the head where it was.

What is **not** ported is N42-26's 14.7k-line orchestrator — compact blocks,
eager import, payload caching, bad-block caches. Those are reth-2.4.1-coupled
throughput work, not protocol, and inheriting them would have re-imported the
version wall this seam exists to avoid.

What remains for a node that actually produces blocks: a concrete
`ExecutionLayer` implementation over reth v1.11.0's `ConsensusEngineHandle` and
`PayloadBuilderHandle`. That is a node-side adapter — it belongs next to
`bin/n42`, needs the reth stack to compile, and is the one piece of this path
that a reth upgrade would disturb. The trait is small (four methods) precisely so
that adapter is the only thing that has to move.

Note for that adapter: this repo's vendored `alloy-rpc-types-engine` adds
**`difficulty` and `nonce` to `ExecutionPayloadV1`** (APoS carries its
Clique-style seal there). Upstream alloy has neither, so payloads built here do
not round-trip through an unmodified alloy without those fields.

## Storage-format findings (reth side)

Checked against `../reth` (2.4.1) and this repo's vendored crates:

- **The MDBX table set has not changed between reth v1.11.0 and 2.4.1.** `git
  diff c1015022f HEAD -- crates/storage/db-api/src/tables/mod.rs` shows no table
  added or removed. This repo's 29 core tables are identical to 2.4.1's; the
  divergence is only N42's 15 extra beacon/snapshot/validator tables.
- `StorageSettings` / the `Metadata` table (reth #19384, Nov 2025) is already
  present here and is near-identical to 2.4.1's. The one local delta: `base()`
  is gated on an `edge` feature and returns `v1()` by default, where upstream
  returns `v2()`. `PartialStateTrieUnwindMarker` is absent here.
- Therefore `storage_v2` / hashed-canonical — the layout gov5's
  `modules/state/hashed_readonly.go` targets, and which its
  `internal/mptbuild` + `internal/mptproof/reth_hashed.go` read and write — is
  reachable on this reth version at the schema level. What differs is the
  provider/trie implementation: 140 files and ~23.8k inserted lines between
  v1.11.0 and 2.4.1 under `crates/storage` + `crates/trie`.

Conclusion: MPT-side storage compatibility with gov5's eth-el path is a
provider/trie question, not a schema-migration question. That is a materially
smaller problem than it first appears.

## EVM / EIP alignment

This repo's `N42_HARDFORKS` (`crates/ethereum/hardforks/src/hardforks/n42.rs`)
schedules Frontier→ArrowGlacier at block 0, Paris at TTD 0, Shanghai and Cancun
at 1746576000, Prague at 1748930400, and Osaka at **4070908800 (2099-01-01)** —
deliberately parked, per the in-file comment, to avoid Osaka's
`MAX_TX_GAS_LIMIT_OSAKA` of 2^24 on devnets. `BEIJING_FORK` is `ForkCondition::Never`.

gov5's fleet chainspec mirrors ETH mainnet forks (shanghai@305000,
cancun@3935000, pectra/osaka/fusaka by time), and gov5 reports green EEST
consume-engine shards through Osaka. So the EIP gap is Osaka/Fusaka being
scheduled-but-parked here, on a revm that predates several Osaka refinements.

Between reth v1.11.0 and 2.4.1: **1,484 commits**, revm 34 → 42 (this repo pins
revm 34.0.0, alloy 1.6.3, alloy-primitives 1.5.6; 2.4.1 pins revm 42.0.1, alloy
2.3.0, alloy-primitives 1.6.1). EL-visible items in that range include the
revm v37 bump for EIP-8037 state gas and Amsterdam header-field validation.

## Transport: matching gov5's router

`n42-h2-net` reproduces gov5's pubsub configuration from
`internal/p2p/pubsub.go`, because a mesh built with different overlay degrees or
heartbeat timing still interoperates but behaves inconsistently under load:

| Parameter | gov5 | Source |
|---|---|---|
| topic | `/n42/h2/4/ssz_snappy` | `H2V4Topic` + the encoding suffix. Note it is *not* fork-digest scoped, unlike gov5's block topic — the v4 envelope carries chain identity itself, which is what makes it cross-client. |
| D / Dlo / Dhi | 8 / 6 / 12 | `gossipSubD`, `gossipSubDlo`; Dhi is go-libp2p's default, not overridden |
| heartbeat | 700 ms | `gossipSubHeartbeatInterval` |
| history length / gossip | 6 / 3 | `gossipSubMcacheLen`, `gossipSubMcacheGossip` |
| seen-message TTL | 30 s | `seenMessagesTTL` — deliberately not libp2p's 2 min default; at fleet throughput the default measured 391 MB of live heap |
| max transmit size | 1,223,370 B | `GossipMaxSize()` = `snappy.MaxEncodedLen(1 MiB)` = `32 + n + n/6`. Must be the *encoded* bound: gov5 hit a bug where a cap pinned at the raw 1 MiB silently held the network at the default. |
| signature policy | `StrictNoSign` + `NoAuthor` | mapped to rust-libp2p `ValidationMode::Anonymous` + `MessageAuthenticity::Anonymous` |
| transport | TCP + QUIC-v1, Noise, yamux | `internal/p2p/options.go`. This crate dials TCP only; QUIC is left off because a QUIC dial to a TCP-only listener fails in a way that reads like a consensus fault. |

### Two findings worth sending back to the other repos

**gov5's `MsgID` is Keccak256, not SHA-256.** The doc comment on
`internal/p2p/message_id.go` says `SHA256(genesisHash || topic || data)[:20]`,
but `common/hash.Hash` pulls a `crypto.KeccakState`. The comment is wrong, not
the code. `crates/n42/h2-net/testdata/gov5_message_id_v1.json` pins five vectors
generated by calling gov5's own hash function through that exact byte layout, so
a future "fix" to match the comment fails a test that names the reason.

**N42-26's message-ID function does not match gov5's.**
`n42-network/src/gossipsub/handlers.rs` computes `keccak256(data || topic)` —
no genesis hash, and the topic after the data. gov5 folds the genesis hash in
and puts the topic first. The message ID is a purely local dedup key so the two
still interoperate, but they dedup differently, and gov5's genesis scoping is
load-bearing: go-libp2p-pubsub marks an ID seen globally across topics and
before validation, so without topic scoping an attacker can replay a block's
bytes on another subscribed topic to pre-seed the seen-cache and have the
genuine block dropped as a duplicate. This crate implements gov5's.

### libp2p version

N42-26 pins libp2p 0.57.0 at a git rev. Using that rev here forces a cascade of
workspace-wide bumps — `bytes` ^1.12, `regex` ^1.13, `tokio` ^1.53, `either`
^1.16, then `cc` and `rustls` — each of which would move versions under the
reth v1.11.0 build. This crate therefore uses libp2p **0.56 from crates.io**,
which resolves with no version replaced anywhere in the lockfile. The gossipsub
wire protocol is unchanged between the two, so interop is unaffected. Revisit
when the repo moves to reth 2.4.1, at which point matching N42-26's pin costs
nothing.

## Roadmap

Ordered by dependency, not by value.

1. **Run the observer against the live fleet.** Everything below the socket is
   tested; what remains is operational — point `h2_observer` at real fleet
   peers with the fleet's genesis hash and validator list, and confirm it
   follows finality. Needs the fleet's peer multiaddrs and an operator willing
   to let an extra peer connect.
2. **HotStuff-2 protocol core.** ~9k near-reth-free lines. Gives this repo a
   voting/proposing node rather than an observer. Independent of the reth
   version; can land before any upgrade.
3. **reth v1.11.0 → 2.4.1.** The wall. 1,484 upstream commits across 12+
   vendored fork crates, plus edition 2021 → 2024 and rustc 1.86 → 1.97. This
   repo's own history (1.9.3 → 1.10.2 → 1.11.0) shows what each step costs.
   Prerequisite for `adapter.rs`, `n42-consensus-service`, `n42-jmt`, and for
   EL parity with N42-26.
4. **QMDB as a live state backend.** `verify_portable_stream` bootstraps from a
   snapshot; running the fleet's commitment scheme as this node's state root
   engine is a different and much larger job — it means an alternative to reth's
   MPT `StateRootProvider`.

An honest alternative to 3 and 4: N42-26 already *is* the reth-2.4.1 Rust client
with HotStuff-2 and QMDB. If the goal is a Rust node on the gov5 fleet rather
than this specific codebase, converging on N42-26 is cheaper than back-porting
into a reth-1.11 fork. This repo's distinct asset is APoS/Clique plus the beacon
storage layer, which N42-26 does not have.
