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
  transaction. The earlier read-side re-checks in the follower and the engine validator were
  removed as dead code: the guard is the derivation at insert plus the loopback-only bind of
  the trusting modes, and the 0x50 *signature* is still unchecked in `shard`/`leader` mode,
  which is why those modes now need `N42_BENCH_UNSAFE=1` at start-up.
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
- `VoteLogFsync` is logged at `error` and counted; consecutive failures are fatal since section 6.5.

## 6. Open design items

### 6.1 Knob truthiness and an adopted-configuration preset

Thirteen knobs are presence-only, the rest parse `1/true` or a number, and two parse
`!= "0"`. Unify on one helper (`n42_env::flag(name, default)`: on = `1|true|on|yes`, off =
`0|false|off|no|""`, anything else = warn and default) and migrate the thirteen; this is a
behaviour change only for someone passing `=0` to enable, which nothing in `scripts/` does.
Then add `N42_PROFILE=x22` (or `--n42.profile`), applied at process start before any
`OnceLock` read, that sets the adopted knob set when the knobs are unset. The binary then
carries the measured configuration, and one integration test per adopted mode can compare
its block and state root against the default path.

Done in `3bd981d69`, `c6d049e53`, `d8cb61101`, `47e38c629` (branch `design/knob-profile`): crate
`crates/n42/env` (`n42_env::flag` / `parse` / `var`, unit-tested branch by branch); 45 switch
reads migrated to `flag` (16 presence-only, 4 "anything but 0", 25 default-on `!= "0"`) and 26
one-line numeric reads to `parse`; `N42_PROFILE=x22` (env only, no CLI flag) applied as the first
statement of `bin/n42` and `h2_validator`, 41 knobs = the `adopted` rows of `docs/KNOBS.md`,
held equal to them by a test. Not done: the per-mode root-equality integration tests, and the
`== "1"` switches (still exact-match). Completed 2026-10-27 (branch `design/knob-profile-x22`): the
X22 base set (the loop351 `ALLA` line and its per-leg additions, 46 rows that were `experimental`) and
13 tuned values whose compiled default differs (`N42_ED25519_BATCH` 256, `N42_ALTSIG_SENDER_CACHE`
2^22, `N42_OUTPUT_SHARDS` 16, the build throttle 48/80, ...) are `adopted` and in the profile, which
is now 99 knobs (101 with the 6.4 road knobs adopted below) and reproduces the node-side environment of an X22 leg. What a leg passes beyond it
is classed `bench-only` (bench gateway key and attestation minimum, `N42_IMPORT_ONCE`, the storage
mode `N42_HASHED_TABLES=off` / `N42_QMDB_READS=on`, `N42_ACCOUNT_HISTORY=off`,
`N42_SETTLEMENT_TAGS=legacy`, `N42_PERSIST_QMDB_IN_SCOPE`, `N42_STORAGE_OP_METRICS=0`, and
`N42_LOCK_SITES`, moved out of the profile) or is a launcher variable (`MALLOC_CONF`,
`TOKIO_WORKER_THREADS`, `RAYON_NUM_THREADS`).

### 6.2 QMDB entry-file compaction

The entry file, the 8-byte-per-slot offset heap and the active bits grow with total appends,
never with live state (~200 MB/s on disk, ~6 MB/s of heap at fleet load), and `trim_dead_twigs`
only frees twig leaf nodes. Design: QMDB-style compaction — re-append the live entries of the
oldest twigs, retarget their index slots, then release the file prefix with
`fallocate(PUNCH_HOLE)` and drop the matching offset segments and bits; an alarm metric for
file bytes per live key. The read view's 40-bit byte offsets (1 TiB) become slot numbers
resolved through `Offsets` in the same change (today the view invalidates itself at 1 TiB).

Design written 2026-10-27: `docs/QMDB_COMPACTION_DESIGN.md`. Re-appending live entries at new
slots would change the positional root (a consensus rule shared with gov5), so the design moves
bytes and keeps slots: a second relocated file of slot-numbered records, atomic `Offsets`
retargeting, a slot-resolving read view, epoch-deferred `PUNCH_HOLE`. Stage 0 (growth metrics)
is the first landing; stages 1-4 each need a bench pair.

### 6.3 QMDB durability ordered against MDBX

QMDB's delta log follows canonical notifications asynchronously while MDBX persistence is a
separate path, so a crash can leave MDBX ahead of the log and the node refuses to start
(`SnapshotMismatch`). Design: `on_state_persisted` (which runs before the DB commit) waits for
or forces `settle_canonical` up to `blocks.last()` and fails the batch if it cannot; an
`on_canonical` error becomes fatal rather than logged. Verify with `roll --kill` under load.

Done in `42cd67f4a`, `a4a33f0fc`, `97e23d124` (branch `design/qmdb-durability`); field check pending.
The hook is the additive, error-returning `on_state_persisted_checked`: past
`N42_QMDB_SETTLE_WAIT_MS` (default 30000) the batch fails before its commit (`PersistUnsettled`), so
no `n42_qmdb_persist_unsettled` gauge was needed. A fatal `on_canonical` error (Poisoned,
Uninitialised, State refusals; not log I/O, which the next head retries) exits the node unless
`N42_QMDB_CANONICAL_FATAL=0`. `docs/PERSISTENCE_COST_STUDY.md` section 9 states the ordering.

### 6.4 Bounds on the road and the pruner feed

The road's taken map keeps up to 131k frames alive and `retire` scans it every block; a frame
whose gas exceeds the block limit blocks the FIFO behind it. Design: bound the taken map by
the own-block hold window, index it by first-member sender so `retire` touches only the
senders in the pruned block, and refuse oversize frames at `road_admit`. Each is a bench pair
(X22 control vs change) before adoption.

Implemented behind knobs in `ad111b05a` and `54362f7d1` (tests). Bench pairs run 2026-10-27 (loop351
stage fm, section 8.2): no measurable cost, so both knobs are on by default since the adoption commit on
`design/integration-2026-10-next` (`N42_ROAD_TAKEN_BOUND=0` / `N42_ROAD_RETIRE_INDEX=0` turn them off;
`adopted` rows in `docs/KNOBS.md`, in the X22 profile).
`N42_ROAD_TAKEN_BOUND=1` forgets a taken frame neither retired nor handed back once more than
`N42_OWN_HOLD_BLOCKS` + 8 own blocks were held since its take (its block has left the hold
window; a later give-back goes the lanes' path with a flush, as after `N42_ROAD_TAKEN_MAX`);
`N42_ROAD_RETIRE_INDEX=1` retires through an index by first-member sender. The oversize refusal
is unconditional, against the gas limit of the latest frame build (nothing is refused before the
first build). Metrics: `n42_road_taken_frames`, `n42_road_oversize_frames_total`.

### 6.5 Local faults that should stop a validator

`VoteLogFsync` means the node cannot record what it voted for; continuing risks equivocation
after a restart. Proposal: fatal after N consecutive failures, with the counter exported.
Likewise an `Invalid` answer to a commit forkchoice is a divergence between consensus and the
execution layer; proposal: stop voting and raise an error event. Both need an operator story
(restart, resync) before they are switched on.

Done in `14818bf86`, `2d147152a`, `26b095081` and the docs commit adding `docs/OPERATOR_FAULTS.md`:
`N42_VOTE_LOG_FATAL_AFTER` consecutive vote-log failures (default 3, `0` off) halt the engine's
voting and stop the validator (`ConsensusError::Fatal` -> `ServiceError::Fatal`, exit code 3,
`n42_h2_fatal{reason="vote_log"}`, `n42_h2_vote_log_failures_total`); a commit forkchoice answered
`Invalid` halts voting and proposing while the node keeps following
(`n42_h2_voting_halted{reason="commit_invalid"}`, `N42_HALT_ON_COMMIT_INVALID=0` off). Operator
story in `docs/OPERATOR_FAULTS.md`.

### 6.6 Certificates on range-pulled blocks

Blocks pulled by `bodies_by_range` become head (and `safe` in legacy settlement) after
decodability and sequence checks only; the embedded QC and leader seal are not verified.
Design: verify the parent QC in each header against the validator set before `new_payload`,
never move `safe` on a pulled block, and compare behaviour with gov5's range import before
changing the cross-client expectation.

Done in `6c737e8e2`, `4dae5c17a`, `e833bd966`: each pulled block must extend the one before it, and the committed QC in
its header is verified through the proposal-path check (`ConsensusEngine::verify_header_qc`)
before `newPayload`; the first failure ends the batch and the peer is not asked again for the
gap (`H2Service::check_pulled_block`). A pulled block is head only in both settlement modes.
No knob. gov5 comparison in `docs/N42_26_PORT.md` "Certificates on pulled blocks".

### 6.7 Lint baseline

CI runs `cargo clippy --workspace --lib --bins --examples` without `-D warnings`. A warning
baseline per crate, then `-D warnings` on `crates/n42/*`, is the cheap next step once the
hardening branches are in.

Baseline on the merged tree (`c07716826`, 2026-10-26 23:29 UTC, the CI command): exit 0,
0 errors, 1,497 warnings. The bulk is the pre-existing APoS/beacon code: `crates/n42/primitives`
341, `ef-tests` 143, `consensus-client` 125, `bin/n42` 96, `fusaka` 50, `mobile-sdk` 39; by
lint, `doc_markdown` 216, `missing_docs` 286 (fields, methods, structs, functions, variants),
`missing_const_for_fn` 108, `collapsible_if` 91, `or_fun_call` 41. The crates this audit touched
carry 126 of them (`engine-types` 44, `h2-node` 25, `qmdb-reth` 18, `tx-queue` 16,
`h2-consensus` 9, `tx-ingest` 8, `h2-el-rpc` 4, `tx-types` 1, `qmdb-state` 1): mostly
`collapsible_if` 28, `doc_markdown` 10, `type_complexity` 9, `missing_const_for_fn` 9, plus three
uses of revm's deprecated `ExecutionResult::gas_used` (now `tx_gas_used`) that the v2.8.1 bump
surfaced. No warning is an error class (no `unused_must_use`, no `rust_2018_idioms`). The log is
`ci/clippy-c07716826.log` under the audit notes; the per-crate `-D warnings` step stays deferred.

### 6.8 QMDB health gauges

Done in `22ac2990b`: `bin/n42` exports `n42_qmdb_forest_poisoned` and
`n42_qmdb_unchecked_restart` (1/0, sampled every 10 s, latched for the run, each logged once
at error level with its reason) on a QMDB chain.

## 7. Merge record

Three fix branches, each reviewed against `docs/MATURITY_AUDIT_RECONCILIATION_2026_10.md`, were
merged with `--no-ff` into `audit/maturity-2026-10` on 2026-10-25, after three documentation
commits on that branch (`ab6d6771d` KNOBS.md with the four new knobs, `6d32e66df` the section 4
0x50 correction, `c36a6c6b9` the reconciliation report):

- `0fa0eb9e3` merge: audit/ingest-hardening into the maturity branch
- `1f5dc72e6` merge: audit/qmdb-hardening into the maturity branch
- `f3e0e4e23` merge: audit/h2-hardening into the maturity branch (one automatic merge in
  `crates/n42/h2-el-rpc/src/engine.rs`, where the ingest branch's `MAX_FRAME` replacements meet
  the h2 branch's raw-channel deadlines)

Against `main` (47b8180ab) the merged tree changes 60 files, +6671/-1011 lines. Branch heads:
ingest `6c24a6299`, qmdb `68677f00a`, h2 `971671bf8`.

### 7.1 Verification

- `cargo check --workspace --tests` on the merged tree: clean (0 errors; the 818 warnings are the
  pre-existing `missing_docs` / `unreachable_pub` / `unnecessary_qualification` lints the
  workspace already carried, see section 6.7).
- `cargo test` of the thirteen touched crates (n42-tx-types, n42-tx-ingest, n42-tx-queue, n42,
  n42-qmdb-state, n42-twig-core, n42-bmt-core, n42-qmdb-reth, n42-h2-consensus, n42-h2-node,
  n42-h2-execution, n42-h2-el-rpc, n42-h2-net): all green on `0c76beddd` (2026-10-26 13:26 UTC,
  `--no-fail-fast`, 55 test binaries). The merge surfaced three tests on main that asserted the
  behaviour the fixes changed, rewritten to the new contracts: the h2-consensus output
  back-pressure pair (`d83fd32fa` holds outputs in order past a full channel, test `dd73929c7`)
  and the tx-ingest claiming-frame test (`7b1bac92b` derives the 0x50 sender, test `0c76beddd`,
  which also covers the wrong-claim drop and its counter).
- Hot-path changes that still need a fleet7 control pair before the branch lands on main (the
  reconciliation's open cost questions): `61689b62b` seeded shard choice in the QMDB key index,
  `dfd8ebcbc` + `0ca8cd375` the duplicate-hash check on described bodies. Pair run 2026-10-26
  15:03-15:28 UTC (loop351 stage fl: X22 configuration, 600M replay set, two alternating pairs,
  main `47b8180ab` native binaries against the merged tree's at `0c76beddd`, after a warm leg):

  | leg | tree | win1 M tx/s | win2 | win3 | round total | notes |
  | --- | --- | --- | --- | --- | --- | --- |
  | AUa | audit | 4.967 | 5.073 | 4.960 | 145.9M | tc=7, one engine idle >5 s |
  | AU1 | main | 5.087 | 5.233 | 5.167 | 151.1M | clean |
  | AUb | audit | 5.073 | 5.087 | 4.973 | 147.5M | tc=7, one engine idle >5 s |
  | AU1b | main | 5.080 | 5.133 | 5.173 | 149.8M | tc=7, one engine idle >5 s |

  Audit against main: window 1 mean 5.020 vs 5.083 (-1.2%), round total 146.7M vs 150.5M
  (-2.5%). Both inside the single-round spread (CLAUDE.md: a difference under about 10% between
  single rounds is invisible), so no regression is measurable from the audit fixes and the
  dependency refresh; both arms read ~2% under round 10.230's main (5.189 / 5.208), which is the
  box's state after the day's QS rounds, not the tree. The seven timeout certificates per leg
  appear on a main leg too, so they are not the audit's. Peak during the stage: Tctl 59 C,
  CPU_VRM0 49 C, socket 364 W (temp-guard.sh, no trip).
- The HotStuff-2 changes (`115e1d486` exact-view validator sets, `98aef5e28` staged changes,
  `c74099d10` bounded body bookkeeping) needed one `scripts/devnet-fleet.sh --gov5` run with
  `GOV5_DELAY`, `LATE_VALIDATOR` and `ABSENT_VALIDATOR` each, since a view jump across an epoch
  boundary without the staged set is now refused. Run 2026-10-26 20:09-20:31 UTC on the merged
  tree's release binaries (`c07716826`, same code as `0c76beddd`) with the gov5 member from
  `../N42-gov5`; `epochLength` 20, so every run crosses several epoch boundaries:

  | run | shape | reth height | gov5 errors | rejoin | head hash reth = gov5 |
  | --- | --- | --- | --- | --- | --- |
  | gov5late | `GOV5_DELAY=120`, 360 s | 160 | 0 | gov5 sealed 40 of the last 200 views | `0x8ad7790c…5fa14` equal |
  | late | `LATE_VALIDATOR=2 LATE_DELAY=120`, 360 s | 121 | 0 | member 2 pulled 0 -> 8 by range, synced at height 19, 102 commits, same head as main | `0x82dd99cd…ebf2` equal |
  | absent | `ABSENT_VALIDATOR=2 ABSENT_AT=120 ABSENT_FOR=120`, 480 s | 180 | 0 | absent at 52, back at 82: range pull 52 -> 60 then catch-up to 82 in 74 ms, first commit 23 s after return, 98 commits / 26 proposals after, same head as main | `0xfbeca38b…2741` equal |

  Every execution layer reports `err=0`; the view timeouts on the two present validators are the
  slots of the member that is away (the devnet's four-validator rotation keeps proposing them),
  and they stop once it is back. The late and absent members' validators each rejoined across
  epoch boundaries with the staged validator set, so the exact-view sets hold on the real path.

### 7.2 Commits by branch

### audit/ingest-hardening (29 commits)

- `7b1bac92b` fix(tx-ingest): derive the 0x50 sender instead of taking the wire claim
- `dfd8ebcbc` fix(frame-blocks): refuse bodies and frames that hold a duplicate tx hash
- `c5ac3731d` fix(engine): turn per-block thread spawn and join panics into errors
- `91d5d73bc` fix(tx-ingest): enforce loopback binds, cap connections, bound frame reads
- `16bddc39b` fix(queue-prune): fall back to inline pruning when the pruning thread dies
- `5fdb4a8e3` fix(node): run the QMDB head follower off the tokio workers
- `03b87dd2d` fix(engine): log poisoned locks on consensus-data stores once, at error level
- `a994af754` fix(follower): keep the vote closure usable when its thread cannot be spawned
- `ef085b0d5` fix(engine-types): deref the recovered guard at the two output_shards try_lock sites
- `0ca8cd375` perf(frame-blocks): check a described body for repeats in O(frames), once
- `5042bdabc` fix(tx-ingest): drop the dead 0x50 cache-hit filters and state what the probes trust
- `f5653ee88` fix(node): run the QMDB head follower on a named thread of its own
- `d2c083871` fix(queue-prune): reset the feed depth when the pruning thread is found dead
- `b795cd54d` fix(payload): fail the build in the store when a root job panics after state_ready
- `d6d4f3dc0` test(tx-ingest): cover a wrong Eth claim in shard mode
- `8dd56f60d` fix(node): refuse trusting ingest modes without N42_BENCH_UNSAFE=1
- `0cba8093b` fix(payload-serve): forget a held execution when its import ends, bound the wait
- `ceefe9722` fix(payload-serve): check frame lengths, cap connections, bound request bodies
- `cf8e1d060` fix(tx-ingest): free a gated connection's slot when its peer closes
- `f93025ce6` fix(node): set RUST_BACKTRACE first in main and turn start-up unwraps into errors
- `72adebf6d` fix(rpc): refuse a verification the miner cannot take, end a subscription on a bad block
- `b2941a80a` fix(follower): stop the import when the verified shards merge differs
- `ef6af61de` fix(evm): warn when an APoS seal does not recover instead of crediting silently
- `5344c71ca` fix(engine-types): name stores capped below the leader's layer depth, warn on finishing evictions
- `421db69bd` test(tx-types): read the batch timing's size as production reads it
- `cd52ead77` docs(engine-types): say why the build pool has no inline fallback
- `6723a073a` test(payload): cover a late revert set that gets no thread
- `0fd790e0a` test(queue-prune): cover the pruning thread's minimum fold and capped carry
- `6c24a6299` test(output-shards): check the elided bundle's root input against the whole map

### audit/qmdb-hardening (23 commits)

- `3380503e8` fix(qmdb-state): poison the forest after a failed or panicked mutation
- `99e5f929d` fix(qmdb-state): keep the tree and tip in step on move_to error paths
- `61689b62b` fix(twig-core): seed the key index's shard choice and refuse a full shard
- `a78957b60` fix(bmt-core): refuse a proof deeper than a key's 256 bits
- `999de1de3` fix(qmdb-reth): fsync the directory after the log rotation and a fresh log
- `8a5f9b67e` fix(qmdb-reth): invalidate the read view past the 1 TiB entry-file mapping
- `239f4ee40` fix(qmdb-reth): check the restored QMDB root against the persisted head's
- `507c3b675` fix(chain-state): name the block when a canonical notification lacks its revert set
- `2153fe362` fix(twig-core): map the key-index snapshot error in the portable loader
- `3e6fc8365` fix(qmdb-reth): reset the log cursor before the rotation's directory fsync
- `3bdd18cdb` fix(twig-core): do not class a pre-undo hydrate failure as a store failure
- `bc4b72adc` fix(qmdb-reth): never record an absent root and treat an unreadable roots file as advisory
- `3cb888036` docs(qmdb-reth): state that a poisoned forest stalls, and report it for a health check
- `9683f70df` docs(twig-core): note the seeded shards' open perf question; gate block_changes on poison
- `b027032de` fix(twig-core): return the entry-file and key-index errors from QmdbCompatTree::set
- `035ceb10f` fix(qmdb-reth): flag a restart whose restored root could not be checked
- `32b64eb39` fix(qmdb-reth): count failed deferred renames and keep them as aliases
- `33a8e2f48` fix(qmdb-reth): log failed removals of superseded files and never leave the trie sort unrun
- `307609125` fix(twig-core): make the entry-file view's offset reads unsafe and add a checked read
- `077c87c95` fix(twig-core): assert hash_parents' bounds in debug builds and state the SIMD safety
- `08e08b18e` fix(twig-core): make a clone of a file-backed tree read-only
- `65062a3f1` test(twig-core): name the io error kind by its full path in the duplicate test
- `68677f00a` test(qmdb): cover a failed undo in the revert loop, a short entry file and a short delta log

### audit/h2-hardening (27 commits)

- `f38f51aa5` fix(h2-consensus): deduplicate future-view timeouts before verifying or relaying
- `7c74e891e` fix(h2-consensus): bound and deduplicate the future-view message buffer
- `fcf416d27` fix(h2-consensus): refuse a view-jump QC that cannot move the view before verifying it
- `b9012b7b9` fix(h2-node): log local consensus engine faults at error level and count them
- `4766e9ee6` fix(h2-el-rpc): put every raw-channel Engine exchange under a deadline
- `d63b6d98b` fix(h2-node): bound the body channel's allocation, read time and connections
- `b45db792d` fix(h2-node): forget a disconnected peer's height and cap the first catch-up window
- `d83fd32fa` fix(h2-consensus): hold engine outputs past a full channel instead of sleeping and dropping
- `2c200fbda` fix(h2-node): serve range, block and fill requests off the consensus loop, capped
- `c44b17da1` fix(h2-execution): finalise a commit only on a Valid forkchoice and retry a failed one
- `622460d40` fix(h2-consensus): let a view jump on the node's own lock or commit go ahead without the pairing
- `67914b6a0` fix(h2-consensus): treat a future timeout as handled only while the buffer holds it
- `a83198d40` fix(h2-node): return a serve slot when the work is done and give fills their own share
- `0c0928f17` fix(h2-node): cap range replies by bytes first and end a probe at the height it began at
- `3aa6525c7` fix(h2-execution): keep a failed commit's retry past an older landing and send it off the loop
- `ff48da983` fix(h2-consensus): deduplicate future-buffer entries on the whole message, not its key
- `25d51b385` fix(h2-consensus): do not pre-check future CommitVote signatures before buffering
- `c872f126f` refactor(h2-consensus): drop the view-jump QC memo, which could never hit
- `2e05e9948` fix(h2-node): bound the served-reply channel and hold the serve slot until the answer is handed on
- `cb12204cb` test(h2-node): a range request past one peer's share is refused with the server-error code
- `46bd8e903` fix(h2-consensus): keep unchecked future messages out of the named sender's share
- `98aef5e28` fix(h2-consensus): stage validator changes only when they are the certified set
- `115e1d486` fix(h2-consensus): verify view-jump QCs and NewView TCs against their exact view's set
- `647f6709d` perf(h2-el-rpc): read N42_OWN_BLOCK_BY_HEADER once instead of on every own-block import
- `3f241ae6f` fix(h2-node): disconnect a peer whose status names another chain
- `c74099d10` fix(h2-node): bound and age out awaited and held body bookkeeping
- `971671bf8` test(h2-node): tolerate the real status a paired peer queued before the mismatch

## 8. Design-item integration record (2026-10-27)

Branch `design/integration-2026-10` = main `7b730e65d` + the five item branches (6.1 `design/knob-profile`,
6.5 `design/fatal-local-faults`, 6.6 `design/range-pull-qc`, 6.3 `design/qmdb-durability`,
6.4 `perf/road-bounds`; the only merge conflict was `Cargo.lock`) + `4e43be3ac`, which reads the items'
new knobs through `n42_env`. `design/integration-2026-10-next` adds the 6.1 completion
(`design/knob-profile-x22`) and 6.2 stage 0 (`design/qmdb-entry-metrics`, section 6.2 and
`docs/QMDB_COMPACTION_DESIGN.md` 3.7 / 5).

### 8.1 Verification of `4e43be3ac`

- `cargo check --workspace --tests`: clean. `cargo test --no-fail-fast` of the thirteen crates of
  section 7.1 plus `n42-env` and `n42-testing` (58 test binaries) and
  `cargo test -p reth-provider --lib n42_persist` (the 6.3 refusal test in both orders): all green
  (2026-10-27 09:37-12:56 UTC).
- Fleet7 control pair (loop351 stage fl, X22 configuration, 600M replay set, the integration tree's
  native binaries against the X22 record binaries of main `47b8180ab`, alternating, after a warm leg):

  | leg | binaries | window 1 | round (3 windows) |
  |---|---|---|---|
  | AUa | integration | 4,966,667 tx/s | 461.0M |
  | AU1 | main | 5,086,667 tx/s | 463.0M |
  | AUb | integration | 5,073,333 tx/s | 460.0M |
  | AU1b | main | 5,080,000 tx/s | 459.8M |

  Round totals within 0.3%, window 1 within the single-round spread (section 7.1's 10% rule): no
  regression from the five items with their knobs at defaults (`N42_ROAD_TAKEN_BOUND` and
  `N42_ROAD_RETIRE_INDEX` off; 6.3's settle wait and fatal canonical errors on; 6.5 and 6.6 on).
  Gates on every leg: `invalid_blocks=0 gas_mismatch=0 fields_mismatches=0 own_not_committed=0`.
- Devnet, the three shapes of section 7.1 on the integration binaries (14:02-14:24 UTC): gov5late
  head 160 identical on reth and gov5; late member synced 0 -> 8 -> 16 -> 19 and holds the main head
  at 121; absent member away at 52, range pull to 60, catch-up to 82, first commit at view 98, same
  head as main at 185 (`main=back=reth=gov5`). Every execution layer `errors=0`.
- `cargo clippy --workspace --lib --bins --examples`: 0 errors, 1,504 warnings against the 1,497 of
  section 6.7. The seven new ones are style lints in the items' code (`collapsible_if` in
  `h2-node/src/service.rs`, `qmdb-reth/src/node_state.rs` and `state_reader.rs`; one
  `match_same_arms` and one `use_self` in `node_state.rs`; one `use_self` in `tx-queue/src/road.rs`;
  one `doc_markdown` in `service.rs`), to be cleared with the per-crate `-D warnings` step.
- Pending at the time of writing, run automatically after the above: the 6.3 field check (`fleet7.sh
  up --fresh` on the integration binaries at 200 tx/s, `roll 1/2/3 --kill`, the forest's recovery
  and fault lines) and the 6.4 bench pairs (loop351 stage fm: `N42_ROAD_TAKEN_BOUND=1
  N42_ROAD_RETIRE_INDEX=1` against the X22 control, two alternating pairs). Results in 8.2.

### 8.2 Field check and bench pairs (2026-10-27, after 8.1)

- **6.3 field check, `roll --kill` on the integration binaries** (fleet7 lean profile, heap forest, 200 tx/s;
  14:35-14:43 UTC): rolls 2 and 3 came back (forest restored at block 92, kills at heights 112 and 126, no
  fault line). **Roll 1 failed**: node1 was killed at block 28 with MDBX still at genesis (every stage
  checkpoint 0); the forest's checkpoint stood at block 1 with deltas through 28, and the restart refused
  it: `QMDB snapshot is at block 1 (…) but the database head is block 0 (…); the forest cannot be rebuilt
  from execution state`. Two defects: (a) the genesis-seeded forest writes no checkpoint, the first head
  move checkpoints at block 1, so a replay can never stop at genesis (both storage modes); (b) MDBX
  persisted nothing in 28 blocks / 85 s although reth's threshold persistence (2 blocks in the lean
  profile) should have run, and the other kills show a persisted head 20-34 blocks behind (node4, stopped
  gracefully, persisted its head 141). Fix for (a) and instrumentation for (b) on
  `design/integration-2026-10-next` (see the commits there); (b)'s cause is open and is reproduced on the
  devnet next. The check must also be run in the X22 configuration (`N42_QMDB_ENTRY_FILE=1`), which is
  what production runs; the lean profile keeps the forest on the heap.
- **6.4 bench pairs** (loop351 stage fm, X22 configuration, 600M replay set, integration binaries, warm leg
  then two alternating pairs; 14:51-15:17 UTC):

  | leg | `N42_ROAD_TAKEN_BOUND` + `N42_ROAD_RETIRE_INDEX` | window 1 | round (3 windows) |
  |---|---|---|---|
  | RBa | on | 5,033,333 tx/s | 459.6M |
  | RB0 | off | 5,071,067 tx/s | 454.1M |
  | RBb | on | 5,085,083 tx/s | 457.4M |
  | RB0b | off | 5,040,000 tx/s | 452.9M |

  On: 5.03/5.09, 459.6/457.4M; off: 5.07/5.04, 454.1/452.9M. Within the single-round spread either way,
  so the bound and the index cost nothing measurable, and they are adopted (on by default). Gates clean on
  every leg. RBb reported `rename_fallbacks_total=2276` (the early rename of the fields-at-seal path fell
  back to the parent's `Complete` on nearly every build); the counter is reported, not gated, and the same
  per-leg mode appears in 11 of 417 loop351 legs since stage dy, independent of these knobs.
