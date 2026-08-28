# Erigon borrow audit, 2026-08-28: gov5 interop and the QMDB commitment path

Erigon's May–August 2026 work keeps returning to a few patterns: a compression
codec built per message (its snappy writer pool, then a zstd one), a block
range served from two independent DB views (hash from one snapshot, body from
another — #22533), received ranges buffered without a total byte budget, and
I/O done under a lock in the state-root path. This audit takes those patterns
to the Rust node's gov5 interop (`crates/n42/h2-net`, `h2-node`, `h2-el-rpc`,
`h2-wire`) and its QMDB commitment path (`qmdb-reth`, `qmdb-state`,
`twig-core`, `bmt-core`), with the file:line evidence for each verdict, what
was changed with the tests and numbers behind it, and what was deliberately
not done.

Branch `perf/erigon-borrow-20260828`, four code commits then this document.

## Findings

| Pattern | Where | Verdict | Change |
| --- | --- | --- | --- |
| (a) codec per message — framed snappy | `h2-net/src/status.rs:200-212` `frame_payload`: `snap::write::FrameEncoder::new(Vec::new())` per call; `status.rs:228` `FrameDecoder::new` per call. Used by every status, `block_by_hash` and `bodies_by_range` chunk (`rpc.rs`), so a 1024-block range reply built 1024 encoders. | **Found.** A fresh framed codec zeroes 76 KiB (`dst`) and reserves 64 KiB (`src`); the decoder zeroes 130 KiB. | Pooled: commit `1a344cbc2`. |
| (a) codec per message — raw snappy | `h2-wire/src/h2_v4.rs:104` and `h2_wire.rs:256` `snap::raw::Encoder::new()` per gossip publish; `h2-net/src/block_gossip.rs:137` per block body. `raw::Decoder::new()` at `h2_v4.rs:115`, `h2_wire.rs:247`, `block_gossip.rs:150`. | **Found, minor.** The raw encoder is a 2 KiB stack table plus a 32 KiB heap table grown on the first input past a few KiB and re-grown per instance. `raw::Decoder` is a zero-sized type: constructing it costs nothing, so those sites were not a finding. | Encoder pooled through the same thread-local: commit `1a344cbc2`. |
| (a) zstd | none in `crates/n42` | Not applicable — gov5's wire is snappy only. | — |
| (b) range served from separate views | `h2-node/src/service.rs:1439-1454` `serve_range`: one `el.block_by_number(n)` per block, each an independent `eth_getBlockByNumber` over `h2-el-rpc/src/engine.rs:329-338`; no linkage between neighbours. A reorg between two calls served blocks of two chains; the importer's per-block hash check (`decode_block_rlp`) cannot see across blocks, so the seam surfaced only as a `newPayload` failure at the peer. | **Found.** Over a JSON-RPC seam there is no `database_provider_ro()` to hold; the equivalent is to anchor once and walk by hash. | Anchored walk-back: commit `00e63fd6c`. Existing hash re-verification on receipt (`service.rs` `decode_block_rlp`, `block.block_hash == hash` for by-hash replies) kept. |
| (b) `block_by_hash` fetch-on-miss | `service.rs:903-916`: one `block_by_hash` call per request | Not a finding — a single read is one view. | — |
| (c) range receive — per-block and count limits | `h2-net/src/rpc.rs:518-540` `BodiesByRangeCodec::read_response`: per block 64 MiB (`MAX_BLOCK_CHUNK`, gov5's `MaxBlockChunkSize`), count `MAX_RANGE_BLOCKS` 1024 checked *after* the 1025th block was read and decoded. | Present but the count check ran late. | Checked before the body is read: commit `53b4a2294`. |
| (c) range receive — total byte budget | none; 64 MiB × 1024 = 64 GiB reachable in theory | **Found.** | `MAX_RANGE_BYTES` = 256 MiB of declared bytes: commit `53b4a2294`. gov5 has no equivalent constant to match (`internal/p2p/encoder/ssz.go` caps chunks only). |
| (c) range receive — buffering everything before import | libp2p `request_response::Codec` returns one `Vec<BlockChunk>` at stream close; `service.rs` `pending_imports` then imports in order. | Structural; bounded by the budget. | Not changed — see "Not done". |
| (c) range receive — backpressure | `service.rs:228-235`: `pending_imports` uncapped, `pending_ranges` capped at 8 (`MAX_PENDING_RANGES`), `pending_block_requests` at 256. | `pending_imports` is bounded by construction: replies come only for requests this node made, one catch-up runs at a time with one request in flight (`request_next_range` is called only after a reply is processed). | Documented on the field: commit `53b4a2294`. |
| (d) lock held across file I/O — QMDB | `qmdb-reth/src/node_state.rs:179-227` `initialize`: `self.lock()` then `read_snapshot(&path)` (`std::fs::read` + bincode decode) and, at genesis, the alloc replay, all under the forest mutex. | **Found.** Startup-only, but every other handle (`state_root`, `is_initialized`, `Debug`, proofs) blocked behind the read instead of answering `Uninitialised`. | Read, decode and replay moved off the lock; install under it once: commit `fd43712ae`. |
| (d) lock held across file I/O — `on_canonical` | `node_state.rs:363-372`: `forest.snapshot()` (a tree clone) under the lock, `write_snapshot` outside it | Already correct; the clone under the lock is memory, not I/O. | — |
| (d) lock held across file I/O — `initialize_from_portable` | `node_state.rs:232-270`: decode, verify, `write_snapshot` all before the lock | Already correct. | — |
| (d) twig-core, bmt-core, qmdb-state | no `Mutex`/`RwLock` in `twig-core/src`, `bmt-core/src`; the only lock in `qmdb-state` is the `StateProofProvider` impl for `Mutex<QmdbForest>` (`forest.rs:438`), no I/O in any of them (`grep std::fs` is empty outside `node_state.rs`) | Not applicable. | — |
| (d′) two views of the tip tree | `mobile-service/src/service.rs:312-322` `prove`: `prove_account` then `state_root`, two lock acquisitions; `on_canonical` runs between them on every commit | **Found** — the same "two snapshots" shape as (b), on the proof path. A report could name a root its proof does not verify against. | `prove_*_anchored` on `StateProofProvider`, one lock for both: commit `fd43712ae`. |
| (e) tip-state query on a historical path | QMDB roots and proofs are read from the forest's canonical head (`QmdbForest::prove_account` moves to `head` first, `forest.rs:325`); `eth_getBlockByNumber` / `state_by_block_id` in `crates/n42/reth-rpc` are vendored upstream reth, where `latest` resolves to the in-memory tip; the payload builder's `state_by_block_hash(parent)` (`engine-types/src/payload.rs:335`) is upstream reth's own tip path. | Not found. | — |

## What changed

### 1. `perf(h2-wire): pool the snappy codecs instead of building one per message` — `1a344cbc2`

`n42_h2_wire::snappy`: one thread-local scratch (raw encoder + block buffer)
borrowed by `compress_raw`, `frame`/`frame_into`, `unframe`. The framing
format is reimplemented over the raw codec because `snap::write::FrameEncoder`
writes its stream identifier once per instance and offers no reset, so it
cannot be reused for a second message. Every call site in `h2_v4.rs`,
`h2_wire.rs`, `block_gossip.rs` and `status.rs` now goes through it; the
`framed_len` boundary walk in `status.rs` is unchanged.

Tests (`cargo test -p n42-h2-wire snappy`, 10 tests): framed output
byte-identical to `snap`'s across 10 sizes straddling the 64 KiB block
boundary and both chunk kinds (compressed and, for incompressible data,
uncompressed); decoding cross-checked against `FrameDecoder` in both
directions; the declared-length cut and trailing-byte behaviour of
`read_exact` reproduced; CRC32C check value pinned (`0xE3069283`) and the
SSE4.2 and table paths compared on odd lengths; corrupt body, flipped CRC,
missing stream identifier, truncation, reserved and skippable chunks each
refused or skipped as `snap` does. The gov5 status and block fixture tests in
`h2-net` pass unchanged.

Timing (`cargo test --release -p n42-h2-wire snappy::tests::timing -- --ignored --nocapture`,
this host, per op, fresh codec per call → pooled):

| payload | frame | unframe | raw compress |
| --- | --- | --- | --- |
| 72 B (a status) | 0.5 → 0.03 µs (16×) | 0.7 → 0.04 µs (17×) | 0.03 → 0.02 µs |
| 1 MiB | 1368 → 1366 µs | 707 → 686 µs (+3 %) | 1293 → 1288 µs |
| 12 MiB | 16.5 → 16.4 ms | 8.75 → 8.49 ms (+3 %) | 15.6 → 15.4 ms |

The construction cost is a fixed ~0.5–0.7 µs per codec, so the gain is on
the small, frequent messages (a status handshake, a 1024-block range reply's
framing) and disappears into compression time on large payloads; the 3 % on
decode comes from decompressing straight into the output instead of through
the decoder's intermediate block. This is a smaller win than the allocation
sizes suggest: glibc hands back zeroed pages for the 76 KiB buffers lazily,
so the memset the pool avoids was mostly never paid.

### 2. `fix(h2-node): serve a range from one view of the chain` — `00e63fd6c`

`serve_range` resolves the highest block of the range by number once, then
fetches every earlier block by its child's `parent_hash`, so the reply is one
chain by construction whatever the head does meanwhile. Each block fetched by
hash is checked to hash to what its child named and to carry the expected
number; the range is bounded by the execution layer's reported head. An
execution layer without a head or by-hash lookup (the trait defaults), or
missing a block of the range, is walked forward by number with the parent
link checked between neighbours, so a seam ends the reply rather than being
served across. `MockExecutionLayer`'s built blocks now name their parent, so
the mock chain links the way a real one does.

Tests (`cargo test -p n42-h2-node --lib range_tests`, 5 tests): a reorg
injected after the fourth lookup still yields the twelve blocks of the chain
that was canonical at the anchor (fails on the old code, which served eight
of one chain and four of another); the forward walk stops at the seam when
no head is reported; ranges bounded by the head and by `MAX_RANGE_BLOCKS`; a
block missing by hash falls back to the forward walk; a wrong block answered
by hash is not served. The four-node fleet suite (a late member pulling the
chain by range) and `h2-execution` pass.

### 3. `fix(h2-net): budget the bytes of a range reply, and refuse past the caps before reading` — `53b4a2294`

`MAX_RANGE_BYTES` (256 MiB of declared, uncompressed bytes across a reply)
and the two existing caps are all checked on the varint that opens a chunk,
before anything is allocated for it. `read_framed_limit` is split into
`read_varint` + `read_framed_body` for that.

Tests (`cargo test -p n42-h2-net bodies_by_range`, 4 new): refused at the
block where the running total crosses the budget, on declared rather than
wire bytes (100 zero bytes frame to far fewer and still count as 100); the
1025th block refused with the cursor standing at its digest, body unread; a
block declared past the chunk cap refused after its varint; the codec applies
the production bounds.

### 4. `fix(qmdb): read the snapshot off the forest lock, and anchor proofs to one view` — `fd43712ae`

`QmdbNodeState::initialize` reads, decodes and (at genesis) replays with the
lock released and takes it once to install; a racing second initialiser finds
it done. `StateProofProvider::prove_account_anchored` /
`prove_storage_anchored` return root and proof from one view, overridden by
the forest, the linear state and the node handle to take their lock once; the
mobile `prove` report uses them.

Tests (`cargo test -p n42-qmdb-reth node_state`, 2 new): four threads
initialising concurrently install one forest with the snapshot on disk and
the root intact; an anchored proof verifies against the root it came with
(`QmdbProof::verify_for_key`), storage without a leaf and an uninitialised
handle answer `None`. `qmdb-state` and the mobile state-proof suite pass.

## Verification

- `cargo test -p n42-h2-wire -p n42-h2-net -p n42-h2-node -p n42-h2-execution
  -p n42-qmdb-state -p n42-qmdb-reth -p n42-mobile-service`: all green
  (h2-net 42 lib + 13 integration, h2-node 5 lib + 6 fleet + 8 persistence,
  qmdb-reth 19 + 1, qmdb-state 10 + 10, mobile-service 5 + 5 + 9 + 7).
- `cargo clippy --lib --tests` on each touched crate: no new warnings in the
  touched files (`crates/n42/alloy-rpc-types-engine` and `n42-primitives`
  carry pre-existing ones).
- `cargo build` (default members, `bin/n42`): builds.
- `cargo fmt`: the new file `h2-wire/src/snappy.rs` is rustfmt-clean. The
  edited files were left in their existing style: `cargo fmt --check` on the
  four touched crates reports 179 diffs *before* this branch, so a blanket
  format would have buried the change under unrelated churn.
- Not run: the devnet fleet (`scripts/devnet-fleet.sh`), the full workspace
  build, `cargo test --workspace`.

## Not done, and why

- **Incremental import of a range reply.** The blocks of a reply are handed
  up together at stream close because libp2p's `request_response::Codec`
  contract is one response value; importing as blocks arrive would need a
  hand-rolled stream protocol (libp2p-stream) beside the request-response
  behaviour, a new protocol id the gov5 side would not know, or a smaller
  `count` per request from the catch-up (which is one line in
  `request_next_range` but trades round trips for memory without a
  measurement to justify where). The byte budget bounds what the whole-reply
  contract can cost; that is the fix here.
- **A single database view for range serving.** The execution layer is
  reached over the Engine API's `eth_` methods (`h2-el-rpc`), so there is no
  `database_provider_ro()` to hold across a range. Anchoring by hash gives the
  same guarantee (one chain, the one canonical at the anchor) at the cost of
  one extra call (`eth_blockNumber`) per range. An in-process adapter that
  could hold a provider does not exist yet (`docs/N42_26_PORT.md`).
- **Pooling `raw::Decoder`.** It is a zero-sized type; there is nothing to
  pool. `decompress_raw` exists only so callers have one place to go.
- **Zstd.** Not used anywhere on the gov5 wire.
- **`QmdbForest::snapshot()` under the lock in `on_canonical`.** It clones the
  whole tree under the lock before the write happens outside it. That is
  memory, not I/O, and making it cheaper (a copy-on-write tree, or a snapshot
  taken from the immutable head record) is a data-structure change in
  `qmdb-state`, not a lock-placement one; left for a measurement on a
  production-sized forest.
- **`cargo fmt` on the edited files.** See "Verification".
- **A criterion bench for the codecs.** The touched crates have no bench
  targets; an `#[ignore]`d timing test in `snappy.rs` prints the numbers
  above and is the reproducible artefact for them.
