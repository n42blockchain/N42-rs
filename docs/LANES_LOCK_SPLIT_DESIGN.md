# Lanes lock split design

Design note (no code, no runs) for candidate 4 of docs/DEGRADED_ONSET_ANALYSIS.md Q3: split the tx-queue's lanes lock
(`TxQueue::inner: Arc<Mutex<Inner<T>>>`, `crates/n42/tx-queue/src/lib.rs`). Data: the X14 legs of loop351 stage bu,
`bench-loop351D2S12P30T64X11T16Yf{b,c}` (`target/fleet-runs/loop351bu.launch.out`, "lanes lock, drain and pruner"
sub-reports; per-block fields from `strip-...Yf{b,c}/el.log`). Line numbers are the tree of bench/main-x11t16
(main 1f369746e lineage; the stage bv commits `N42_HANDOFF_DONE_FIRST` / `N42_PRUNE_LEAN` are not in it). X14 runs with
`N42_QUEUE_OFFLOCK=1`, `N42_TX_QUEUE_DRAINER=1`, `N42_TX_QUEUE_DRAIN_CHUNK=8192`, `N42_PLAN_AHEAD(_BODY)=1`, and
**without** `N42_QUEUE_PLAN_SNAPSHOT` (excluded in 10.102).

## 1. Who holds the lock, and for how long

What the sub-reports measure directly (window 1 / 2 / 3, per 5 s unless noted):

| leg | lock duty | holds / 5 s | longest hold (median of 5 s maxima / max) and holder | lock wait / 5 s (longest) | inbox drains / 5 s, tx each, mean hold |
| --- | --- | --- | --- | --- | --- |
| Yfb | 95.5 / 96.0 / 97.5% | 16.1k / 14.9k / 11.5k | 36-46 / 44-52 ms, `lib.rs:2558` (5-6 of 6 samples), `lib.rs:3389` (1) | 8.95 / 8.44 / 10.08 s (51-62 ms) | 2,160 / 2,158 / 1,928; 10.4-11.3k; 1.19 / 1.19 / 1.45 ms |
| Yfc | 95.5 / 96.5 / 93.5% | 18.2k / 13.7k / 15.1k | 35-40 / 42-54 ms, `lib.rs:2558` (5-6 of 6), `lib.rs:3389` (1) | 8.16 / 9.03 / 7.99 s (47-58 ms) | 2,175 / 2,119 / 2,060; 10.0-10.6k; 1.20 / 1.28 / 1.22 ms |

A lock wait of 8-10 s per 5 s means on average ~1.7 threads are queued on the lock at any moment. Per holder (Yfb window 1;
Yfc within a point; only the drain and the pruner are metered by name, the rest is the residual of the 95.5%):

| holder (file:line, fn) | thread | when | hold per call | share of wall time | on the seal path? |
| --- | --- | --- | --- | --- | --- |
| inbox drain: `lib.rs:3173 drain_chunked` (drainer slices of 8,192), plus the drains inside other holds (`drain_inbox` / `drain_inbox_block`) | drainer, any holder | ~430 / s, 4.5M tx/s | 1.19 ms mean (~113 ns/tx), max 40-54 ms (the pruner's full drain) | **~51%** (2,160 x 1.19 ms / 5 s) | housekeeping; on the path only as wait |
| pruner `prune_block`: `lib.rs:2558 remove_mined_offlock` first hold (full `drain_inbox` + prepared check), then holds of 256 senders (`OFFLOCK_PRUNE_SENDERS`), the forget-taken hold, 32-frame sweep holds | pruner (canonical subscriber) | 22.6 blocks / s; ~180 holds a block (inferred from the hold count) | remove 14.2 p50 / 17.5 mean / 36.6 p90 ms a block, lock wait 7.8 / 10.6 / 24.4 ms a block | **16-20%** without its drain ("lock held by it"), 31-35% with drain and settle | housekeeping |
| `lib.rs:2722 settle_own_block` (from `prune_block`) | pruner | per canonical block | 1.5 p50 / 3.2 mean / 8.7 p90 ms | ~4% (inside the 31-35%) | housekeeping |
| `lib.rs:2681 hold_own_block` (hand-off; after the onset 200,000 `dropped(HeldEvicted)` per call) | hand-off task | per own block | not timed; ~5-9 ms after the onset (queue_ms minus the forget's wait) | **~10-18%** (residual estimate) | **yes** without `N42_HANDOFF_DONE_FIRST`: the next build's `handed.recv()` waits for it |
| `lib.rs:4057 forget_whole_take` (O(1): `last_build` taken whole, `handed` set) | hand-off task | per own block | microseconds; **wait 1.5 p50 / 4.6 mean / 15.2 p90 ms** (`queue_lock_us`) | <1% | **yes**, also with `DONE_FIRST` (it runs before `done`) |
| `lib.rs:3389 frames_for_build_ahead` (prepared-plan verdict, `open_build`, bounded `drain_inbox_block` 2,048, top-up / fresh plan on a discard) | builder | per build (plan_ahead used on 677 of 678) | ~0.3-1 ms; 36-44 ms on a discarded plan (fresh `plan_frames` in-hold) | ~2-5% | **yes**: `start_select_ms` 1 p50 / 5 p90 / 2.3-2.5 mean |
| plan-ahead `prepare_next_locked` / `offlock_plan` / `offlock_commit` (`lib.rs:3833 / 3883 / 3960`), `wait_for_plan` (3776) | builder side thread | per build, beside the parent's execution | `plan_prep_us` 8.7-9.3 ms p50 incl. waits | ~5-10% | no (only when the build waits: `plan_wait_us` 0.6-0.9 ms mean) |
| `settle_offlock_in` (3592), `finish_frame_build` (3514/3522), `QueueBest::next` / `mark_invalid` (5616-5728), depth / `usable` / `len` readings | builder, gate | per build, rare | short | few % | partly (finish at seal) |

So the top three are **the inbox drain (~51%)**, **the pruner (16-20%, 31-35% with its drain and settle)** and **the
hand-off's own-block hold (~10-18% after the onset)**. The build's own plan/take is a few percent; what it pays is
*waiting*: on the seal path the lanes lock costs `start_select` (2.3-2.5 ms mean) plus the hand-off's two acquisitions
(`forget_whole_take` wait 4.3-4.6 ms mean, 13-15 ms p90, then `hold_own_block`), against `start_handoff_ms` 11 p50 /
12.2-12.7 mean and `sealed_at_ms` 40.9-41.5 mean.

## 2. What the lock protects, and what couples it

`Inner<T>` (lib.rs:753): `lanes` (per-sender `Lane { by_nonce: BTreeMap, queued, mined, chain_mined, parked }`),
`arrivals` (round-robin order of senders with queued work), `len` / `parked_len` / `parked_order` / `park_*`, `current` /
`run`, `gaps`, `pending_drain` / `pending_frames` / `pending_in` / `pending_out` (a chunked drain's remainder), `frames`
(the `FrameIndex`: frame id -> hashes, sender runs, own `Arc`s; live and retired), `pending` / `settling` (a frame
build's noted takes), `last_build` (parent, taken list), `prepared` (the plan-ahead), `handed`, `builds`, `held` (own
blocks not yet settled, bounded by `N42_OWN_HOLD_BLOCKS`), `pruned_through`, `pruning`, `lanes_gen`, `usable_cache`,
`drops`, `swept_reported`. **Not** under it already: the inbox and frame inbox (own mutexes), the by-hash index
(`HashIndex`, `HASH_INDEX_SHARDS` RwLocks, pruned in `prune_block` after the lanes), the depth mirror and staged/in-hand
counters (atomics, stored at every release in `TimedInner::drop`).

Invariants that couple the fields (the reason a split is not free):

1. **Watermark**: a lane never holds a nonce at or below its sender's mined watermark, whichever door it came in by
   (drain, give-back, own-block settle) -- prune, drain and give-back must agree on `Lane::mined` per sender.
2. **Inbox order**: the lanes are a prefix of the arrivals in inbox order; a frame is indexed only after its last
   transaction is in its lane (`pending_frames` marks against `pending_out`, `drain_pending` lib.rs:4667).
3. **Frames over lanes**: a frame's runs name (sender, nonce) in many lanes; `check_runs` / `check_by_ref` read
   `lanes` while walking `frames`; `sweep_ids_into` / `sweep_retired_into` drop a frame when any member is mined;
   `settle` (lib.rs:4265) pops noted takes from lanes into `last_build`'s list and retires the frame -- one atomic step.
4. **Plan validity**: a prepared plan is used only if `builds`, `handed == {build, Some(parent)}`, `last_build` and
   `pruning` say nothing moved (`prepared_verdict`, lib.rs:4510); an off-lock plan commits only if `lanes_gen` is unmoved.
5. **Own-block ledger**: `last_build` -> `handed` (forget) -> `held` (hold) -> settle by the pruner at the block's
   height; a different hash at the height gives the uncarried transactions back into the lanes (invariant 1 applies).
6. **Depth**: `len + pending_drain.len()` and `parked_len` are exact at every release (the gate reads the mirror).

## 3. Three split options

**(a) Shard the lanes by sender** (N shards, each `{lanes, arrivals, len, parked}` behind its own lock; drains and
prunes partition their batch by shard and take one shard at a time). Gains: drain and prune parallelise and a builder
waits for at most one shard's slice; per-shard duty ~95%/N. Hazards: invariant 3 -- a 500-tx frame has runs in several
shards, so `plan_frames` / `check_runs`, `settle`, the sweep and `prepared_verdict` need all the shards a frame names,
in a fixed order (deadlock discipline), or all N for a plan (the build start then serialises on every shard and waits
for every shard's current drain slice); the frame index needs its own lock, ordered after the shard locks, and frame
insertion after the last member's shard insert (invariant 2 across shards); `arrivals` fairness and `run` become
per-shard (walk order changes, which the frame path does not use but `best_for_walk` does); `lanes_gen` becomes a
vector. **The frame index is what makes (a) hard**: `frame_blocks::select` -> `frames_for_build_timed` ->
`plan_frames` validates every frame against the lanes it names, `best_for_build` / `best_for_walk` iterate `arrivals`
across all senders, and `drain_inbox_block` inside the build-start hold must index frames whose members just landed in
other shards. Expected: duty per shard 25-50% at N=4; seal path -2..-4 ms *if* the plan locks only the shards it touches,
~0 if it locks all. Largest change of the three (most of lib.rs's 7,700 lines touch `lanes`).

**(b) Separate the housekeeping from the build lock.** Two moves under one idea -- the build's lock holds only what a
build must see atomically; housekeeping prepares its mutation off the lock and publishes it in a short step:
(b1) an **own-block ledger lock** for `last_build`'s *completed* take, `handed`, `held`, `drops` (lock order: lanes ->
ledger, never the reverse), so `forget_whole_take`, `hold_own_block` (with its eviction accounting) and the common case
of `settle_own_block` never take the lanes lock; (b2) **drains as prepared runs**: the drainer groups its slice by
sender off the lock (stable, so per-sender arrival order and the frame marks are kept), probes nothing, and splices
per-sender runs under the lock (one map look-up and one ordered append per run instead of per transaction; the flood's
frames hold a few runs each); (b3) **the prune as a published watermark**: the pruner folds `highest`, swaps it into a
cumulative `Arc<AddressHashMap<u64>>` (one hold, the generalisation of today's `pruning` field) and the physical removal
of dead heads is lazy (the drain's splice, the plan's head read, a background sweep in small holds). Hazards: (b1) the
taken list is filled by `settle` of `pending` under the lanes lock, so the ledger may only hand over a take marked
complete (set under the lanes lock when `pending`/`settling` are empty for that build; the plan-ahead path, 677 of 678
builds, is complete at `open_build`), else fall back; `prepared_verdict` reads `handed` -> nested ledger read.
(b3) every reader of a lane head must honour the published watermark (invariant 1 becomes "no *live* entry at or below"),
`len`/`usable` must not count dead entries (invariant 6), the frame sweep still needs lanes (stays in small holds).
Expected: (b1) removes the forget wait (4.3-4.6 ms mean, 13-15 p90) and the hold from the seal path and ~10-20% of duty;
(b2) drain ~113 -> ~50-60 ns/tx under the lock, duty -20..-25 points; (b3) pruner hold 17.5 -> <5 ms a block.

**(c) Read-mostly snapshot for the planner** (RCU lane heads; mutators behind one lock). This exists as
`N42_QUEUE_PLAN_SNAPSHOT` (snapshot.rs: frames copied in-hold, lanes read in 8,192-sender holds, plan off-lock, commit
with a per-lane check) and **regressed and was excluded** (10.102: lock duty 92.5%, longest hold 46.5 ms, the drains moved
into the block path). It also aims at the wrong holder: the plan is prepared ahead on 677 of 678 builds and the build
start's own hold is a few percent of duty; the 95% is drain + prune + hold. A true RCU over ~350k-1M lanes needs a
persistent map (every drain publishes a new version: 4.5M inserts/s of path copying) -- more memory traffic on a build
that is already memory-latency bound (10.114). Frames make it hard as well: the snapshot of a frame's runs must be
consistent with the lanes it names (invariant 3), which is exactly what snapshot.rs's commit-time re-check pays for.

## 4. Recommendation: (b), in stages

(b) attacks the measured holders in order of their weight, keeps the frame index and the planner untouched (invariants
2-4 stay inside one lock) and each stage is a separate env gate with a counter that proves it. (a) stays the fallback if
the lock is still > 80% busy at 5M after (b); (c) is closed.

| stage | gate (default off) | change | proof counter (bench sub-report / el.log) | expected |
| --- | --- | --- | --- | --- |
| 0 | -- | timers only: `hold_own_block` lock wait / hold / evicted (`hold_lock_us`, `hold_us`), `settle_own_block` split; a per-holder duty table in `LockStats` (hold ns by `Location`, top 8 on the ingest line) | per-holder shares replace this note's residual estimates | none (measurement) |
| 1 | `N42_QUEUE_LEDGER_LOCK=1` | (b1): ledger lock for completed takes, `handed`, `held`, `drops`; `forget_whole_take` / `hold_own_block` / `settle_own_block` (no give-back) off the lanes lock; fallback to the lanes path when the take is not complete | `queue_lock_us` on "built ahead on the sealed own block" 1.5 / 15 ms (p50 / p90) -> ~0; `start_handoff_ms` mean; lanes lock duty -10..-18 points after the onset | seal path -3..-5 ms mean; gap -1..-2 ms on top of stage bv |
| 2 | `N42_TX_QUEUE_DRAIN_RUNS=1` | (b2): drainer slices grouped by sender off the lock, spliced by run | `drain_ns / drain_txs` 113 -> <= 60 ns/tx; drain mean hold 1.19 -> ~0.6 ms; lock wait / 5 s 8-10 s -> < 4 s | duty -20..-25 points; `start_select_ms` mean -1 |
| 3 | `N42_PRUNE_WATERMARK=1` | (b3): published cumulative watermark, lazy dead-head removal, sweep in small holds | pruner remove hold 17.5 -> < 5 ms a block; pruner lag 0 at +90 s (lag.py); no `queue pruning fell behind` | removes the onset's trigger; duty < 70% |
| 4 | (only if needed) | (a) with shards for lanes, the frame index under its own lock | per-shard duty | headroom past 5M |

Each stage ships with unit tests beside the existing `prune_tests.rs` / `drain_tests.rs` / `offlock_tests.rs` (ordering,
give-back, depth mirror exactness), then three interleaved legs against X14 + stage bv; adopt on two of three pairs at
+1.5% as in 10.144.

Risks:

1. **Ordering**: a second lock invites a lanes <-> ledger inversion; enforce lanes -> ledger only (a debug assertion on
   the ledger guard that the thread does not later take the lanes lock), and keep `hold_own_block`'s free after both.
2. **Incomplete takes** (stage 1): a frame build whose `pending` takes are not yet settled must not be handed over from
   the ledger; a wrong flag loses or double-forgets a block's transactions (round-43-class nonce refusals). Test: a
   top-up build plus a racing prune.
3. **Give-back under the ledger** (stage 1): a different hash at the height must re-enter the lanes under the lanes lock,
   with invariant 1; keep that branch on the lanes path.
4. **Drain order** (stage 2): grouping must be stable per sender and keep the frame marks counting transactions, not runs,
   or a frame is indexed before its last member (invariant 2) -- the 10.141-10.143 collapse class.
5. **Dead entries** (stage 3): any reader that skips the watermark sees mined transactions as usable (empty or refused
   blocks); `len`, `usable`, `gate_len_locked` and the parked accounting must all subtract them; the most invasive stage,
   which is why it comes last and only if stage bv's lean pruner leaves the onset in place.
6. **Measurement**: lock duty is per 5 s and per node; a stage that only moves waits between the lanes and the ledger
   lock shows as duty down and nothing else -- judge by `start_handoff_ms`, `sealed_at_ms` and the window totals.
