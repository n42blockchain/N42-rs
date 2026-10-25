# Maturity audit and hardening, October 2026

After the seven-node fleet passed 5M TPS (round 10.230, main `47b8180ab`, tag
`fleet7-x22-5.2M-20261024`) the code added over the previous three months was audited for
production maturity rather than throughput. This document records what the audit found, what
was fixed, what was deliberately left alone, and the design items that remain.

## 1. Scope and method

- Tree: main `91a360b57` (reth v2.8.1). N42-authored code only: `bin/n42`, `crates/n42/*`, the
  N42 additions in `crates/chain-state`, `crates/storage/{provider,storage-overlay}`. About
  227k lines; 1,868 commits on main since 2026-07-24.
- Four independent read-only reviews, one per area, plus a static catalog of every runtime
  knob (`docs/KNOBS.md`). Priorities: P0 = a panic or wrong state reachable in production
  (node, consensus, fleet); P1 = correctness or resource defect; P2 = robustness and
  maintainability.
- Result: 82 findings (4 P0, 37 P1, 41 P2). The raw finding lists are not checked in; this
  document keeps the ones that changed code or that remain open.

## 2. What the audit did not find

- No panic reachable from a bad peer block in the execution layer: every peer-supplied index
  and length is checked, sender errors become `Err`, the `unsafe` in `bin/n42`, `tx-ingest`
  and `engine-types` is syscall glue and CPU intrinsics with no shared memory.
- In the HotStuff stack the 500+ `unwrap`/`expect` are almost all in tests; production code
  has about 25, each after a length check. Peer-byte decoders cap sizes.
- Decoding of untrusted bytes in QMDB (portable snapshot, proof codec, delta-log framing) is
  sound; the mmap/madvise/SIMD `unsafe` in `twig-core` is justified.
- Every knob but one is read once (`OnceLock`); none sits in a hot loop.

## 3. Systemic issues

1. **Fail-silent recovery.** The dominant pattern is "recover and continue": poisoned locks
   taken with `into_inner`, a failed QMDB apply whose tree is handed back as the parent state,
   a dead pruner thread whose feed is dropped, engine errors (including a vote-log fsync
   failure) logged at `debug`. Each hides the one event that should stop the node.
2. **Work accepted before it is authenticated or bounded.** Range serving on the consensus
   loop, future-view messages buffered before any signature check, request protocols without
   per-peer limits, the body channel allocating the declared length.
3. **The measured configuration is not the shipped one.** The X22 record runs ~70 off-by-default
   knobs set on a script line; `cargo test`, CI and a plain `n42 node` run the defaults.
   Thirteen knobs enable on *any* value (`=0` still turns them on), 41 were undocumented.
4. **Bench probes in the production binary.** `N42_INGEST_VERIFY=shard` takes a 0x50 sender
   from the wire claim; `N42_TX_INGEST`/`N42_PAYLOAD_SERVE` bind wherever they are told.

## 4. Fixes landed

Three branches, each from main, each change additive with a unit test for the behaviour:

- `audit/ingest-hardening` — tx-types, tx-ingest, tx-queue, engine-types, bin/n42.
- `audit/qmdb-hardening` — qmdb-reth, qmdb-state, twig-core, bmt-core, chain-state.
- `audit/h2-hardening` — h2-consensus, h2-node, h2-execution, h2-el-rpc, h2-net.

(Per-commit list filled in at merge time; see section 7.)

Decisions behind the fixes:

- **Frame root malleability.** `binary_merkle_root` pairs an odd last leaf with itself, so
  `[a,b,c]` and `[a,b,c,c]` share a root, and on a `frameBlocks` chain that root is the
  header's `transactionsRoot`. `frameBlocks` exists only in the Rust chain (gov5 has no such
  mode), but changing the root would change block hashes, so the fix rejects any body or
  frame that holds a duplicate transaction hash. A domain-separated root is a genesis-flagged
  change for later.
- **0x50 sender.** For an Ed25519 transaction the sender is `keccak(alg‖pubkey)`, one hash;
  it is now always derived, in every ingest mode, and a wire claim that disagrees drops the
  transaction. Cache readers re-check the hit against the derived sender.
- **Loopback by default.** The raw payload channel and the ingest refuse a non-loopback
  bind unless `*_ALLOW_REMOTE=1`; with `N42_TX_INGEST_DIRECT`, `N42_INGEST_VERIFY=shard|leader`
  or attested frames they refuse it outright. The fleet (seven nodes on one box, all
  127.0.0.1) is unaffected.
- **QMDB fail-stop.** The forest carries a `poisoned` reason. A block apply that errors after
  it may have mutated the tree, a panic caught around the apply, or a poisoned forest mutex
  sets it; afterwards every root, insert, `move_to` and persistence call returns
  `Poisoned(reason)`. A node that cannot prove its tree is at `tip` stops instead of sealing or
  attesting to a wrong root. `move_to` applies or restores the undo on every error path.
- **Key index shards.** The shard is chosen from seeded bits (the index is never persisted and
  the seed is per process), and the 2^24-bucket limit returns an error instead of asserting.
- **Consensus loop.** Range, block-by-hash and txns serving run on spawned tasks with per-peer
  and total caps; replies are capped by blocks and bytes. Future-view timeouts are
  deduplicated before verification and relayed once. The future-message buffer deduplicates,
  caps per sender and per view, and evicts the highest view. View-jump QCs are checked for
  usefulness before any pairing. Engine output is non-lossy. Local faults log at `error`.
- **Panics on the block path.** The four per-block `thread::Builder::spawn(..).expect` and the
  three `join().expect` in the builder return `Err` like the follower already did.

## 5. Deliberately not changed

- `into_inner` on the ~100 poisoned-lock sites outside the forest: made visible (error log
  naming the store) but kept, because the right policy per store (clear vs fail-stop) needs a
  per-store decision and a fleet run; the forest got fail-stop because its invariant is global.
- The pruner feed stays an unbounded channel. Bounding it changes the hand-off that the 5M
  configuration depends on (round 10.227: frees moved off the pruner thread); it now warns
  when the depth passes 64. A bound needs a bench pair, not a code review.
- `VoteLogFsync` is logged at `error` and counted but is not fatal yet (section 6.5).

## 6. Open design items

### 6.1 Knob truthiness and an adopted-configuration preset

Thirteen knobs are presence-only, the rest parse `1/true` or a number, and two parse
`!= "0"`. Unify on one helper (`n42_env::flag(name, default)`: on = `1|true|on|yes`, off =
`0|false|off|no|""`, anything else = warn and default) and migrate the thirteen; this is a
behaviour change only for someone passing `=0` to enable, which nothing in `scripts/` does.
Then add `N42_PROFILE=x22` (or `--n42.profile`), applied at process start before any
`OnceLock` read, that sets the adopted knob set when the knobs are unset. The binary then
carries the measured configuration, and one integration test per adopted mode can compare
its block and state root against the default path. Owner: a single branch after the three
hardening branches merge (it touches the same files).

### 6.2 QMDB entry-file compaction

The entry file, the 8-byte-per-slot offset heap and the active bits grow with total appends,
never with live state (~200 MB/s on disk, ~6 MB/s of heap at fleet load), and `trim_dead_twigs`
only frees twig leaf nodes. Design: QMDB-style compaction — re-append the live entries of the
oldest twigs, retarget their index slots, then release the file prefix with
`fallocate(PUNCH_HOLE)` and drop the matching offset segments and bits; an alarm metric for
file bytes per live key. The read view's 40-bit byte offsets (1 TiB) become slot numbers
resolved through `Offsets` in the same change (today the view invalidates itself at 1 TiB).

### 6.3 QMDB durability ordered against MDBX

QMDB's delta log follows canonical notifications asynchronously while MDBX persistence is a
separate path, so a crash can leave MDBX ahead of the log and the node refuses to start
(`SnapshotMismatch`). Design: `on_state_persisted` (which runs before the DB commit) waits for
or forces `settle_canonical` up to `blocks.last()` and fails the batch if it cannot; an
`on_canonical` error becomes fatal rather than logged. Verify with `roll --kill` under load.

### 6.4 Bounds on the road and the pruner feed

The road's taken map keeps up to 131k frames alive and `retire` scans it every block; a frame
whose gas exceeds the block limit blocks the FIFO behind it. Design: bound the taken map by
the own-block hold window, index it by first-member sender so `retire` touches only the
senders in the pruned block, and refuse oversize frames at `road_admit`. Each is a bench pair
(X22 control vs change) before adoption.

### 6.5 Local faults that should stop a validator

`VoteLogFsync` means the node cannot record what it voted for; continuing risks equivocation
after a restart. Proposal: fatal after N consecutive failures, with the counter exported.
Likewise an `Invalid` answer to a commit forkchoice is a divergence between consensus and the
execution layer; proposal: stop voting and raise an error event. Both need an operator story
(restart, resync) before they are switched on.

### 6.6 Certificates on range-pulled blocks

Blocks pulled by `bodies_by_range` become head (and `safe` in legacy settlement) after
decodability and sequence checks only; the embedded QC and leader seal are not verified.
Design: verify the parent QC in each header against the validator set before `new_payload`,
never move `safe` on a pulled block, and compare behaviour with gov5's range import before
changing the cross-client expectation.

### 6.7 Lint baseline

CI runs `cargo clippy --workspace --lib --bins --examples` without `-D warnings`. A warning
baseline per crate, then `-D warnings` on `crates/n42/*`, is the cheap next step once the
hardening branches are in.

## 7. Merge record

Filled in when the branches land on main.
