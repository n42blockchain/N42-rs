# Audit reconciliation: findings against the fix branches (2026-10-25)

Companion to `docs/MATURITY_HARDENING_2026_10.md`: every finding of the October 2026 maturity audit
with its status on the three hardening branches, read from the diffs. The B list was lost with the
session scratch space (a host reboot); its known items are listed. Items marked "recommend fixing now"
were taken up on the branches after this table was written; the merge record in the main document
says which landed.

Audit tree: main `91a360b57`. Branches (all from origin/main): `audit/ingest-hardening` (15 commits), `audit/qmdb-hardening` (14, `wt-audit-qmdb`), `audit/h2-hardening`
(20, `wt-audit-h2`). Every FIXED/PARTIAL entry below was checked against `git diff origin/main..HEAD`,
not the commit title. "Doc" = `docs/MATURITY_HARDENING_2026_10.md`; its section 5 is an
unnumbered list, so it is cited as §5 (topic). Nothing was built or run.

Hot path (needs a bench pair, X22 control vs change, window 1 + total): leader build, follower import,
tx ingest/queue/pruner, QMDB apply/commit.

## A. bin/n42 + engine-types (21)

| # | Prio | Finding | Status | Evidence |
|---|---|---|---|---|
| A1 | P1 | `N42_INGEST_VERIFY=shard` ships in prod (sender_cache.rs:113, follower_import.rs:2069, claimed_build.rs:124) | PARTIAL | 7b1bac92b derives the 0x50 sender (claim that disagrees is dropped); 91d5d73bc refuses any non-loopback ingest bind while leader/shard/direct/attest is on; 5042bdabc documents that the 0x50 *signature* is still unchecked. Missing: no feature/genesis gate; Eth claims in shard mode are still taken as-is |
| A2 | P1 | `N42_PAYLOAD_SERVE` binds anywhere (main.rs:480, payload_serve.rs:2925) | FIXED | 91d5d73bc: `remote_bind_refusal` returns PermissionDenied off loopback unless `N42_PAYLOAD_SERVE_ALLOW_REMOTE=1`, warns when allowed |
| A3 | P1 | Adopted config = ~70 env knobs in run scripts (run-loop345d.sh:241, output_shards.rs:192) | DEFERRED | Doc §6.1 (`N42_PROFILE=x22` preset, one integration test per adopted mode) |
| A4 | P1 | Pruner feed unbounded mpsc (queue_prune.rs:503, 130) | DEFERRED | Doc §5 (pruner feed) + §6.4. Branch added a depth gauge and a warn past 64 (16bddc39b) |
| A5 | P1 | Per-block `spawn(..).expect` (follower_import.rs:713, 3359; assembler.rs:333; parallel_transfer.rs:869) | FIXED | c5ac3731d: vote road runs inline on spawn failure (a994af754 keeps the closure in a slot), QMDB-root spawn error -> `Err`, assembler writes the error into `job.out`, build pool retries at half the threads down to 1 (still panics at 0 threads, documented) |
| A6 | P1 | `join().expect` on root jobs (payload.rs:3261, 3967) | FIXED | c5ac3731d maps the joins to `Err` via `failed_after_seal`; b795cd54d calls `built_executions::fail(block_hash)` after `state_ready` so children do not wait the 3 s WAIT |
| A7 | P1 | ~100 `into_inner` poison recoveries (built_executions.rs:562 ...) | DEFERRED | Doc §5 (into_inner). 03b87dd2d/ef085b0d5 route the consensus-data stores through `recover_poisoned` (one error log per store), behaviour unchanged |
| A8 | P2 | HELD_EXECUTIONS leak on early return; `wait_for_release` no timeout (payload_serve.rs:2117, follower_import.rs:256) | NOT ADDRESSED | payload_serve diff only adds the bind check |
| A9 | P2 | SIGUSR2 handler not async-signal-safe (stacks.rs:24) | NOT ADDRESSED | - |
| A10 | P2 | `set_var` after threads exist (main.rs:43, 60) | NOT ADDRESSED | - |
| A11 | P2 | `N42_SHARDS_MERGE_OFF_PATH=verify` mismatch only warns (follower_import.rs:244) | NOT ADDRESSED | - |
| A12 | P2 | `submitVerification` drops on full channel (consensus_ext.rs:210) | NOT ADDRESSED | - |
| A13 | P2 | Subscription `.unwrap()` in RPC task (consensus_ext.rs:179) | NOT ADDRESSED | - |
| A14 | P2 | Start-up unwraps on operator input (main.rs:475, 311, 394) | NOT ADDRESSED | - |
| A15 | P2 | APoS beneficiary fallback on failed recovery (n42_evm.rs:104) | NOT ADDRESSED | - |
| A16 | P2 | Near-duplicate / rejected knobs, no unknown-name check (payload.rs:718) | DEFERRED | Doc §6.1 covers truthiness + preset only; the unknown-`N42_*` registry and deleting rejected knobs are not written down anywhere |
| A17 | P2 | Per-block OS thread spawns instead of a pool (payload.rs:1180, 4040; follower_import.rs:3486) | NOT ADDRESSED | - |
| A18 | P2 | Process-global hash-keyed stores, implicit cap>=depth (built_executions.rs:147 ...) | NOT ADDRESSED | - |
| A19 | P2 | Test gaps on hot-path files | PARTIAL | 16bddc39b adds `a_dead_pruning_thread_is_followed_by_inline_pruning` (PruneSender after death). Missing: spawn_late_reverts spawn failure, min/max fold, merge_elide vs whole-map root, `wait_for_release` with sender dropped |
| A20 | P2 | Unchecked `as u32` frame lengths vs reader's 256 MiB (payload_serve.rs:1652 ...) | NOT ADDRESSED | - |
| A21 | P2 | Busy-poll miss wait in compact-body assembly (engine_validator.rs:450) | NOT ADDRESSED | - |

## B. tx-types / tx-ingest / tx-queue (19 in the lost list; 11 known)

Priorities were lost with the list (0 P0, 8 P1, 11 P2); the column gives an estimate (`~`).

| # | Prio | Finding | Status | Evidence |
|---|---|---|---|---|
| B1 | ~P1 | Pruner thread death leaves the queue never pruned (queue_prune.rs, main.rs:740) | FIXED | 16bddc39b: body under `catch_unwind`, `forward()` forgets the dead sender and prunes this and every later item inline; d2c083871 resets FEED_DEPTH + gauge. Items left in the dead inbox are lost (documented) |
| B2 | ~P1 | Pruner feed is an unbounded channel | DEFERRED | Doc §5 (pruner feed), §6.4 (= A4) |
| B3 | ~P1 | Road's taken map keeps ~131k frames; `retire` scans it per block | DEFERRED | Doc §6.4 |
| B4 | ~P1 | Oversize frame (gas > block limit) blocks the FIFO | DEFERRED | Doc §6.4 (refuse at `road_admit`) |
| B5 | ~P1 | `spawn(..).expect` / `join().expect` on the block path | FIXED | = A5/A6 (c5ac3731d, a994af754, b795cd54d) |
| B6 | ~P2 | ~100 `into_inner` poisoned-lock recoveries | DEFERRED | Doc §5 (into_inner) (= A7) |
| B7 | ~P1 | Frame root malleability (`[a,b,c]` = `[a,b,c,c]`) | FIXED | dfd8ebcbc: ingest refuses a frame with a duplicate hash, `root_for_body_counted` refuses the frame-tree match for a body with a duplicate (falls to MPT); 0ca8cd375 makes the vote-road check O(frames + hashed-frame txs) (`frame_body_ambiguous`) and caches checked bodies (`DISTINCT_BODIES`, 64) |
| B8 | ~P1 | Shard mode takes the 0x50 sender from the wire claim | FIXED | 7b1bac92b derives `alt_tx.sender()`, drops a disagreeing claim (counted `dropped_altsig_claim`); d6d4f3dc0 tests a wrong Eth claim. Signature forgery residual tracked under A1 |
| B9 | ~P1 | Ingest / payload-serve bind anywhere, no connection cap or read timeout | PARTIAL | 91d5d73bc: ingest loopback-only (+ hard refusal in trusting modes), 256-connection semaphore, 30 s frame-body timeout, accept-error backoff; payload_serve loopback-only. Missing: payload_serve connection cap / idle handling |
| B10 | ~P2 | `N42_ED25519_BATCH` 64 in prod vs 128 in the ignored test (sender_cache.rs:197, alt_sig.rs:847) | NOT ADDRESSED | still 64 / 128 |
| B11 | ~P2 | Presence-only env knobs | DEFERRED | Doc §6.1 |
| B12-B19 | - | (lost) | unknown | Re-derive from a fresh read of tx-types/tx-ingest/tx-queue if needed |

## C. HotStuff stack (21)

| # | Prio | Finding | Status | Evidence |
|---|---|---|---|---|
| C1 | P0 | `bodies_by_range` served on the consensus loop (service.rs:2452, 4762) | FIXED | 2c200fbda: range/block/txns serving on spawned tasks holding `execution_layer_arc()`, per-peer 4 / total 32 slots (fills 16/64, a83198d40); 0c0928f17 caps replies at 128 MiB (`range_reply_takes`); 2e05e9948 bounds the reply channel (8). Reply is still collected, not streamed (bounded) |
| C2 | P1 | Future-view timeouts verified + relayed before dedup (timeout.rs:57) | FIXED | f38f51aa5 + 67914b6a0: a counted-and-buffered sender returns `Ok(true)` before any pairing; relay moved after `add_verified_timeout`; DuplicateVote -> `Ok(false)` so the buffer gets a copy |
| C3 | P1 | Future buffer: unauthenticated, no dedup, evicts lowest view (state_machine.rs:1139, 165) | FIXED | 7c74e891e/ff48da983: `buffer_future_message` dedups on key + blake3 of the whole message, caps 8/sender and 64/view, evicts the highest view; Vote/Proposal pre-verified when the set is known. 25d51b385 deliberately skips the CommitVote pre-check (see "looks incomplete" 3) |
| C4 | P1 | View-jump QC verified before usefulness check (state_machine.rs:1275) | FIXED | fcf416d27: early return when `qc.view+1 <= current`, Vote/CommitVote out before verify; 622460d40 skips the pairing for a QC equal to the own locked/committed QC; c872f126f drops the dead memo |
| C5 | P1 | `emit()` sleeps then drops outputs on a full channel (state_machine.rs:1594) | FIXED | d83fd32fa: ordered `output_overflow` VecDeque, no sleep; `release_outputs()` drained by `next_output()` in service; Closed still errors |
| C6 | P1 | All engine errors logged at debug (service.rs:2343 ...) | FIXED | b9012b7b9: `ConsensusError::is_local()`; `report_engine_error` logs local faults at error + `LOCAL_ENGINE_ERRORS` counter. Fatal VoteLogFsync: Doc §5/§6.5 |
| C7 | P1 | Range-pulled blocks become head/safe with no QC/seal check (service.rs:3781, driver.rs:2698) | DEFERRED | Doc §6.6 |
| C8 | P1 | Peer heights unauthenticated, never decay (service.rs:4147, 2287) | FIXED | b45db792d: entry removed on disconnect, first catch-up window capped at `latest + far_ahead*8`; 0c0928f17 ends a probe at its start height and lowers the stored height. Heights themselves still unauthenticated (bounded) |
| C9 | P1 | Request protocols without per-peer/global limits (rpc.rs:172 ..., service.rs:2007) | FIXED | 2c200fbda/a83198d40 serve slots; `served_txns` bounded (2e05e9948); client range read capped at `MAX_RANGE_READ_BYTES` 128 MiB (rpc.rs); refusals send the server-error code (cb12204cb test). No inbound connection gating (optional item) |
| C10 | P1 | Body channel allocates declared length, no timeout/cap (body_channel.rs:211, 283) | FIXED | d63b6d98b: `read_body` grows from a 4 MiB reserve as bytes arrive, 30 s frame deadline, 64-connection semaphore, warn off loopback. No peer allow-list; `from` still self-declared |
| C11 | P1 | Raw-channel Engine calls without deadline (engine.rs:788, 1727 ...) | FIXED | 4766e9ee6: every raw exchange in `within_raw_deadline` (8 s, `N42_RAW_CHANNEL_TIMEOUT_MS`), own-body request too; silent-server test |
| C12 | P1 | Failed commit FCU forgotten; legacy finalized advanced first (driver.rs:2843, 3036) | PARTIAL | c44b17da1/3aa6525c7: `finalized` set only on Valid; Err -> `CommitRetry` with 200 ms..5 s backoff, survives an older landing, sent off the loop; Invalid -> error log + `commits_refused`. Missing: Invalid does not stop voting (Doc §6.5) |
| C13 | P2 | Validator-change commit uses local pending set (decision.rs:118, voting.rs:385) | NOT ADDRESSED | - |
| C14 | P2 | `validator_set_for_view` guessing fallback (timeout.rs:401, state_machine.rs:1296) | NOT ADDRESSED | view-jump path still calls `validator_set_for_view` |
| C15 | P2 | Default signing profile `Native` unsafe (quorum.rs:23) | NOT ADDRESSED | - |
| C16 | P2 | Production validator is an example binary (examples/h2_validator.rs) | NOT ADDRESSED | - |
| C17 | P2 | Lineage churn; `awaiting_bodies` / `held_bodies` unbounded (settlement.rs:96, service.rs:312) | NOT ADDRESSED | - |
| C18 | P2 | Pump backpressure stalls the swarm (pump.rs:216) | NOT ADDRESSED | pump diff adds only `RespondRangeError` |
| C19 | P2 | `N42_OWN_BLOCK_BY_HEADER` read per call; safety-off knobs unrefused (engine.rs:1439, persistence.rs:484) | NOT ADDRESSED | still `std::env::var` at engine.rs:1482/1495 |
| C20 | P2 | Status fork mismatch never disconnects (service.rs:2287) | NOT ADDRESSED | - |
| C21 | P2 | Test gaps on new code | PARTIAL | Added: dup future timeout, buffer full of far views, dedup/bad sig, emit past capacity, closed channel, serve off the loop, 5th range refused, body timeout/growth, silent raw server, commit retry/refusal. Missing: `import_ranges` uncertified (§6.6), `process_decide` hash mismatch (C13) |

## D. QMDB layer (21)

| # | Prio | Finding | Status | Evidence |
|---|---|---|---|---|
| D1 | P0 | Failed/panicked apply leaves half-applied tree as parent (qmdb_compat.rs:2165, forest.rs:736, node_state.rs:1666) | FIXED | 3380503e8: `QmdbForest.poisoned`; `poison_if_mutated` on Store/Index errors from apply / leased apply, poison on caught panic; every root/insert/move_to/checkpoint returns `Poisoned`; failpoint tests. 3bdd18cdb keeps a pre-undo hydrate failure out of the Store class |
| D2 | P0 | Forest mutex poisoning recovered with `into_inner` (node_state.rs:1456, 1547) | FIXED | 3380503e8: `poisoned_forest_guard` poisons the forest on every taker; 3cb888036 adds `NodeState::poisoned()` for a health check |
| D3 | P0 | Key-index shard grindable, `assert!` at 2^24 (index.rs:10, 130) | FIXED | 61689b62b: shard = mixed `key[..8] ^ per-process seed`; `IndexError::{ShardFull, SlotTooLarge, BatchTooLarge}` returned, maps to `QmdbOperationError::Index` -> forest poisoned. Perf open (9683f70df note) |
| D4 | P1 | Entry file / offsets / bits never compacted (entry_store.rs:106) | DEFERRED | Doc §6.2 |
| D5 | P1 | 40-bit byte offsets, panic past 1 TiB (entry_view.rs:21, index.rs:29) | FIXED | 8a5f9b67e: `record_end` returns None past the map, `raise_floor` flags `past_view`, view invalidates instead of slicing; key-index refusal also invalidates. Widening to slot numbers: Doc §6.2 |
| D6 | P1 | Restart never checks restored root (node_state.rs:2093, 1975) | FIXED | 239f4ee40: `forest.roots` ring (1024 slots, keccak-tagged) written at each persisted head; checkpoint/snapshot/heap restarts compare -> `RestoredRootMismatch`; bc4b72adc skips zero/absent roots, unreadable file = warn. Missing record (first start after upgrade) = unchecked with warn |
| D7 | P1 | `move_to` error paths desync tree and tip (forest.rs:1509) | FIXED | 99e5f929d: replay mismatch applies the undo back (poisons if that fails); revert/pending undo restored on failure, tip set to the block still applied |
| D8 | P1 | Delta log durability not ordered before MDBX commit (n42_persist.rs:200) | DEFERRED | Doc §6.3 |
| D9 | P1 | No directory fsync after rotation / fresh log (node_state.rs:3211, 2764) | FIXED | 999de1de3: `sync_parent_dir` after the rename to `.sealed` and when `append_delta` creates the log (`from == 0`); 3e6fc8365 resets the cursor before that fsync |
| D10 | P1 | `expect` on deferred revert set in canonical notification (in_memory.rs:994) | FIXED | 507c3b675: explicit fail-stop panic naming block number + hash (the finding's stated alternative); test asserts the message |
| D11 | P1 | Possible deadlock: `advance` par_iter under `advancing` (read_view.rs:562, 701) | NOT ADDRESSED | `advance` still runs `changes.par_iter()` under `advancing` |
| D12 | P1 | `on_canonical` blocks a tokio worker (main.rs:283) | FIXED | ingest branch 5fdb4a8e3 + f5653ee88: named std thread `n42-qmdb-follow` with `blocking_recv`, spawn error -> eyre |
| D13 | P1 | Failed deferred rename only logged (node_state.rs:1514) | NOT ADDRESSED | `drain_renames` unchanged (node_state.rs:1704) |
| D14 | P1 | `BmtProof::verify` panics on >256-deep proof (bmt-core lib.rs:546) | FIXED | a78957b60: `base_depth + siblings > 256` (checked_add) -> false; 257-sibling test |
| D15 | P2 | `EntryFileView::{key,record}` safe but can SIGBUS (entry_view.rs:40) | PARTIAL | 8a5f9b67e adds bounded `record_end`; `key`/`record` stay safe `pub fn`, no EOF/len bound, no SAFETY notes |
| D16 | P2 | SIMD lane pointer math unchecked (simd.rs:171, 306, 587) | NOT ADDRESSED | - |
| D17 | P2 | Clone of a file-backed tree shares file + truncation guard (entry_store.rs:747, qmdb_compat.rs:1600) | NOT ADDRESSED | - |
| D18 | P2 | Contradictory `N42_QMDB_READS` parsing (node_state.rs:309 vs n42_state.rs:95) | DEFERRED | Doc §6.1 (knob parsing owned by the knob task; brief forbade parsing changes) |
| D19 | P2 | Checkpoint / snapshot files have no checksum (node_state.rs:3061, 3120) | PARTIAL | A corrupt checkpoint that changes the tree is now caught by the D6 root check; the files themselves still carry no CRC |
| D20 | P2 | Swallowed `remove_file` / exec_cache spawn results (node_state.rs:2832 ...; exec_cache.rs:146) | NOT ADDRESSED | - |
| D21 | P2 | Fault-injection test gaps | PARTIAL | Added: failpoint feature, apply/lease poisoning, refused computation not poisoning, replay mismatch, corrupt entry file restart, heap restart root, absent roots, 1 TiB, bmt depth, dir fsync. Missing: `apply_undo` failure in the revert loop, entry file shorter than checkpoint, log ending before the DB head |

## Proposed fixes for PARTIAL and NOT ADDRESSED items

- **A1 (S, no bench)** bin/n42 `main.rs` start-up (next to the `N42_INGEST_SHARD` check): refuse
  `N42_INGEST_VERIFY=shard|leader` unless the genesis has a `benchUnsafe` flag or `N42_BENCH_UNSAFE=1`
  is also set; log every trusting knob at warn. Unit test on `parse_ingest_verify`. Script change: add the
  ack knob to `fleet7-env.sh`. Start-up only.
- **A8 (S, no bench)** `bin/n42/src/payload_serve.rs`: RAII guard calling `forget_hold(held_hash)` on drop;
  `follower_import.rs` `wait_for_release`: `recv_timeout` (view timeout) returning `HELD_DROPPED`.
  Off the per-tx path; one leg to confirm nothing changes is enough.
- **A9 (S)** `stacks.rs`/help text: document the deadlock risk; optionally skip threads whose `wchan` is a
  futex. Opt-in diagnostic.
- **A10 (S)** `main.rs`: move `set_var("RUST_BACKTRACE")` before `n42_core_layout::init()` with a SAFETY
  comment, or drop it and set it in the scripts.
- **A11 (S)** `follower_import.rs:244`: on a mismatch use the on-path merge and return `Err` (verify mode only).
- **A12 (S)** `consensus_ext.rs:210`: return an RPC error on `TrySendError::{Full,Closed}` and warn. APoS path only.
- **A13 (S)** `consensus_ext.rs:179`: `match` the serialisation result, warn and break.
- **A14 (S)** `main.rs:475, 311, 394`: `map_err(|e| eyre!(..))?` / `ok_or_else`.
- **A15 (S)** `engine-types/src/n42_evm.rs:104`: return an execution error, or warn + `debug_assert!`
  (APoS only; not on the fleet's HotStuff path).
- **A17 (L, bench pair)** engine-types: per-role long-lived worker threads fed by channels for the early merge,
  late reverts, QMDB root and vote road. Leader build + follower import, so a bench pair.
- **A18 (L, bench pair)** engine-types: an `ExecutionHub` owned by `N42Node`. Short-term (S, no bench):
  assert at start-up that every store cap >= `N42_LEADER_LAYERS + 2`, warn on evicting a held entry.
- **A19 (S-M, tests only)** add the four missing tests; they need `#[doc(hidden)] set_*` overrides on the
  OnceLock knobs involved (no behaviour change).
- **A20 (S, no bench)** `payload_serve.rs`: shared `MAX_FRAME` constant; `u32::try_from(len)` and
  `len <= MAX_FRAME` before each write, protocol error otherwise. One compare per frame.
- **A21 (M, bench pair)** `engine_validator.rs:450`: wait on a queue notify fired by the drainer rather than
  `drain_now()` + 1 ms sleep. Touches the lanes lock (the ~5M ceiling), so a bench pair.
- **B9 (S, no bench)** `payload_serve.rs` accept loop: a connection semaphore (e.g. 64) like the ingest's.
  No read timeout: these connections are long-lived and idle between blocks; a per-frame body deadline
  (after the header byte) is fine.
- **B10 (S)** align the ignored test default to 64 (or state why 128 is measured); test-only change.
- **C13 (S-M)** `h2-consensus decision.rs` / `voting.rs`: commit pending changes only when
  `hash_changes(pending) == decide.validator_changes_hash`; leader uses `cached_changes_hash(block_hash)`.
  Two tests. Latent (no caller, gov5 profiles reject changes).
- **C14 (S)** `timeout.rs:401`, `state_machine.rs` view jump: use `resolve_qc_validator_set` /
  `known_validator_set_for_view` and refuse when unknown.
- **C15 (M)** `quorum.rs`: make the signing profile a constructor argument; `Native` behind `cfg(test)`.
  Touches every engine construction site and test helper.
- **C16 (M)** move `examples/h2_validator.rs` to `crates/n42/h2-node/src/bin/`, add SIGTERM handling that
  flushes the checkpoint, and a start-up test that `hotstuff` genesis gives a gov5 profile. Scripts change path.
- **C17 (M)** `service.rs` / `settlement.rs`: feed lineage only from imported or expected-leader blocks;
  age out `awaiting_bodies` / `held_bodies` (cap + TTL, drop on `body_store` eviction).
- **C18 (M-L)** `h2-net pump.rs`: keep polling the swarm while the inbound queue is full; a bounded local
  queue that sheds tx/body events before consensus messages. Consensus timing, so a fleet run (not the TPS pair).
- **C19 (S)** `h2-el-rpc engine.rs:1482/1495`: cache `N42_OWN_BLOCK_BY_HEADER` in a OnceLock (same parse).
  The safety-knob refusal (`N42_VOTE_LOG_NOSYNC`, `N42_VOTE_BEFORE_IMPORT`) belongs with §6.1.
- **C20 (S)** `service.rs:2539`: call a transport `disconnect(peer)` on a fork-digest mismatch; check gov5
  interop (gov5 already says goodbye, so a disconnect is harmless).
- **C21 (S)** add the `process_decide` hash-mismatch test with C13; the `import_ranges` one waits for §6.6.
- **D11 (M, one bench leg)** `qmdb-reth read_view.rs:562`: compute the journal (`index.get` per key) before
  taking `advancing`, or serially as `step_back` does. Persistence path, per block; a leg to confirm the
  persist timers do not move.
- **D13 (S, no bench)** `node_state.rs:1704`: count failures in a metric and keep a failed rename as a
  `from -> to` alias so the sealed hash still resolves; test with a trimmed `from`.
- **D15 (S)** `twig-core entry_view.rs`: make `key`/`record` `pub(crate)` or `unsafe fn` with a checked
  wrapper bounding `len` by `MAX_VALUE`; SAFETY notes at the read_view call sites.
- **D16 (S)** `simd.rs`: `debug_assert!` the parent indices once per call + SAFETY comment (a release
  `assert!` would be on the QMDB commit path and need a bench pair).
- **D17 (S-M)** `entry_store.rs`/`qmdb_compat.rs`: a clone of a file-backed tree becomes read-only
  (`push`/`truncate` -> `Err`), no shared truncation guard; `try_clone` returns `Result`. No production clone today.
- **D19 (M)** checksum prefix on checkpoint/snapshot: an on-disk format change (brief forbids it now); needs
  a version bump and a reader for the old format. Defer to §6.3 work.
- **D20 (S)** `node_state.rs:2832...`: log `remove_file` errors; `exec_cache.rs:146`: compute inline when
  `spawn_blocking` fails, log a publish error.
- **D21 (S-M, tests only)** with the failpoint feature already there: undo failure in the revert loop,
  short entry file, log ending before the DB head.

## Fixes in the branches with no corresponding finding (record them)

- 3cb888036 `NodeState::poisoned()` health accessor; 9683f70df gates `block_changes` on poison.
- bc4b72adc "never record an absent root, unreadable roots file advisory" and the `forest.roots` file itself
  (a new on-disk file, additive; outside the brief's "no on-disk format change" only in spirit).
- 2153fe362 maps the key-index error in the portable loader; 3bdd18cdb hydrate-vs-store classification.
- 0c0928f17 probe-height rule for catch-up (behaviour change in catch-up termination).
- New knobs: `N42_TX_INGEST_ALLOW_REMOTE`, `N42_PAYLOAD_SERVE_ALLOW_REMOTE` (strict `== "1"`),
  `N42_RAW_CHANNEL_TIMEOUT_MS` (8 s default) -- add to `docs/KNOBS.md`.
- New metrics/counters: `n42_queue_prune_feed_depth`, `dropped_altsig_claim`, `frames_duplicate`,
  `REFUSED_DUPLICATE`, `LOCAL_ENGINE_ERRORS`, `commits_refused`.
- R-ingest follow-ups landed: R1 (0ca8cd375), R2 (5042bdabc), R3 (f5653ee88), R5 (d2c083871), R6
  (b795cd54d), R7 (`root_us` taken before the check), R8 (d6d4f3dc0). R4 (gated connections hold ingest
  semaphore slots; 8 stall cycles fill 256 with `GATE_MAX_WAIT_MS=0`) is not addressed.

## Fixes that look wrong or incomplete

1. **Doc §4 is stale on 0x50**: "Cache readers re-check the hit against the derived sender" -- 5042bdabc removed
   both read-side filters (follower_import, engine_validator); the real guard is the derivation at insert plus
   the loopback-only refusal. Reword before merge.
2. **Hot-path costs not yet benched**: (a) 61689b62b replaces the sorted-run shard split in `insert_sorted`
   with a hash + scatter (`group_by_shard`) on every QMDB apply, and `get`/prefetch now hash the key -- the
   author flags this as open (9683f70df); (b) dfd8ebcbc adds a per-frame duplicate sort at ingest and
   `root_for_body_counted` sorts a whole body when it is not in `DISTINCT_BODIES` (64 entries); (c) 0ca8cd375
   still collects the hashes of every hashed frame. All need the X22 bench pair before main.
3. **Future buffer residual** (C3): CommitVote, PrepareQC and Decide are buffered without a signature check
   (25d51b385 by design). A forged CommitVote naming a victim sender counts against that sender's 8-slot cap,
   and eviction only removes higher views, so 8 forged view+1 entries keep the victim's real view+1 messages out.
   Cheap fix: do not count unauthenticated messages against a sender's cap (cap them as a separate "anonymous" class).
4. **New `expect` in twig-core**: `QmdbCompatTree::set` now has `.expect("the QMDB key index is full")`
   (qmdb_compat.rs:1910). Comment says genesis/tests/vectors only; acceptable, but it is a new panic in a prod
   crate, against the brief. Genesis with a huge alloc would hit it before the block path's error.
5. **D6 coverage gap**: the root check is skipped (warn) when `forest.roots` is absent, so the first restart
   after deploying the branch, and any node whose ring slot was overwritten (> 1024 heads), is unchecked.
6. **A5 residue**: `parallel_transfer::build_pool` still panics if not even one thread can be spawned
   (documented; `&'static` pool has no `Err` path).
7. **Pruner fallback** (B1): items still in the dead thread's inbox are lost (documented); their senders' mined
   txs stay queued until a later block for the same sender prunes them.

## Summary

| Group | FIXED | PARTIAL | DEFERRED | NOT ADDRESSED | Total |
|---|---|---|---|---|---|
| A | 3 | 2 | 4 | 12 | 21 |
| B (known 11 of 19) | 4 | 1 | 5 | 1 | 11 |
| C | 10 | 2 | 1 | 8 | 21 |
| D | 10 | 3 | 3 | 5 | 21 |

Recommend fixing now (safe, no perf question; mostly S): A1 (start-up ack for trusting ingest modes),
A8 (held-entry guard + timeout), A10 (set_var order), A11 (verify-mode Err), A12 (verification RPC error),
A13 (subscription unwrap), A14 (start-up unwraps), A15 (beneficiary error), A20 (frame length check),
B9 (payload_serve connection cap), B10 (batch default in test), C13 (certified change hash), C14 (strict set
resolution), C19 (OnceLock for one knob), C20 (disconnect on fork mismatch), D13 (rename metric + alias),
D15 (view API unsafe/crate-private), D16 (SIMD debug_assert), D17 (read-only clone), D20 (log swallowed
results), the test gaps A19/C21/D21, the doc fix (wrong 1), and the CommitVote cap fix (wrong 3).

Defer: A17, A18, A21 (hot path, bench pair); D11 (one bench leg, persistence path); C15, C16, C17, C18
(M-L, consensus behaviour, fleet runs); D19 (on-disk format); everything already DEFERRED to doc §5/§6.
Gate the merge of qmdb/ingest branches on the bench pair for wrong 2.
