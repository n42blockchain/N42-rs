# Frame road: frames that bypass the lanes

Design note (2026-10-20, after loop351 stages dl-do, BREAKTHROUGH_DESIGN 10.186). Goal: take the per-transaction work
off the tx-queue's lanes lock, the ceiling every leader-side cut of 10.176-10.186 ran into.

## 1. Why

`N42_LOCK_SITES=1` (988a22b1f) on stage do, per 5 s on node0 (the shared EL), middle of the flood:

| site | function | X18 (LSa, 4.631M/s, duty 85%) | cuts + drainer + no vote-log sync (LSs, 4.546M/s, duty 98%) |
| --- | --- | --- | --- |
| lib.rs:4067 | `drain_grouped` (inbox -> lanes, frames indexed when their last member lands) | 50.4%, 3,271 holds, 770 us | 46.1%, 2,402 holds, 959 us |
| lib.rs:4785 | `offlock_plan` (bounded drain + `plan_frames` checking every frame against its lanes) | 26.3%, 122 holds, 10.7 ms | 13.6%, 114 holds, 5.9 ms |
| lib.rs:4609 | `top_up_prepared` | -- | 17.1%, 269 holds, 3.2 ms |
| lib.rs:4565 | `prepare_continuously` | 3.4% | 7.4% |
| lib.rs:3457 / 3225 / 4291 / 3106 / 2684 | settle_own_block / remove_mined_offlock / frames_for_build_ahead / finish_remainder / usable | 5.2% together | 13.4% together |

Drain ~95 ns a transaction (the flood's 500-transaction frames hold runs of length ~1, so `DRAIN_RUNS` cannot batch them),
the plan's check ~50 ns, the commit's `split_off` per sender: ~0.2 us of lanes-lock work per transaction, which reaches
100% duty at ~5M tx/s (ARCHITECTURE_TOWARD_5M section 2 extrapolated 5.0-5.6M). Above ~90% duty the drain falls behind,
frames wait in `pending_frames` (4,300 against 450), the index runs dry (400 frames against 4,300 at the take) and the
build waits 6-10 ms for its plan: the bistable supply of 10.169 / 10.185 / 10.186. When the supply holds, the build
seals at 28.5 ms (DNcb) and the gap moves to the vote side. Every cut that speeds the pipeline raises the lock's demand.

## 2. The road

On E=1 every block is built by this queue's own builder, and the flood's frames are attested and nonce-aligned
(`frames_unaligned=0` on every leg). A frame can then be **admitted whole into a FIFO without touching the lanes**:

* **Admission (ingest thread, off the lanes lock).** A per-sender *road* map, sharded (64 shards of
  `Mutex<AddressHashMap<RoadSender>>`, `RoadSender { next: u64, lane_owned: bool }`). A frame is road-admitted when, for
  every member, the sender is known to the road (`next` set), not `lane_owned`, and the member's nonce is `next`; then all
  members' `next` advance and the frame is pushed to the road FIFO (its own short lock: an O(1) push of an `Arc`).
  Members of one frame are distinct senders in the flood; a frame that names a sender twice needs consecutive nonces in
  frame order (checked the same way). The shards are locked in ascending order for one frame (no deadlock), or one shard
  at a time with a two-phase check-then-advance under all touched shards.
* **Seeding.** The flood's senders always have lane entries (~120 each), so a sender cannot wait for an empty lane. A
  sender joins the road at the first aligned, attested frame that names it while the road is on: under the lanes lock,
  once per sender (18,750 senders in the 600M set), `next` = its lane's highest nonce + 1 (or the mined watermark + 1
  with an empty lane, or the frame's nonce when the sender is unknown to the lanes and to the chain's watermark only if
  the frame is the first it ever sent -- else the lanes path), and the sender's lane entries are counted into
  `lane_debt` (an atomic: transactions of road senders still in the lanes). A frame whose member nonce is not `next`,
  an unattested or unaligned frame, goes the lanes path and marks its senders `lane_owned` (their later frames too, until
  the sender's lane is empty and nothing of it is in flight -- then it may re-join). **Corrected in section 5:** a
  `lane_owned` sender with frames still queued on the road deadlocks the road; stage 1 invalidates the road instead.
* **The gate (invariant R1).** Road frames are eligible only while `lane_debt == 0`: no transaction of a road sender is
  in the lanes, so a road frame's predecessors were all taken by this build's ancestors. The lanes path decrements
  `lane_debt` when it takes (settles) or prunes a road sender's entry and increments it when it gives one back. On the
  flood the debt drains in ~0.5 s after the switch (2.3M queued at 5M/s) and then stays 0; a lanes give-back of a road
  sender (an abandoned build) closes the gate until that entry is taken again. Its abandoned children give their road
  frames back to the FIFO front, so the order holds.
* **Build.** The plan takes road frames first, FIFO, whole, up to the gas limit, without a per-transaction check; then the
  existing frame/lanes planner fills the rest. The road frames of a build are its *road take*.
* **Hand-back.** A build that is not committed returns its road take to the FIFO front in order (the senders' `next`
  already counts them, so the order is the only thing to keep). A build committed on the canonical chain retires its road
  take (dropped off the lock, `QUEUE_FREE_THREADS`).
* **Accounting.** `len`, the depth mirror the ingest gate reads, and `usable` add the road's transaction count (an atomic).
  The pruner has nothing to remove for road transactions: they left the FIFO at the take.
* **Failure / reorg / restart.** A canonical block not built here (never on E=1, possible on a multi-EL fleet) or a
  refusal invalidates the road: drain the FIFO into the lanes path in order, clear the road map, and let seeding start
  again. Restart starts with an empty road.

## 3. Expected

Lanes-lock duty from 85-98% to ~20% (the drain and plan of road frames leave it; the sweep, settle and prune of lane
transactions stay), the frame supply no longer bistable (plan wait 0, `par_start` ~3-4 ms), sealed_at ~29-33. The gap
then sits on the tick (30 + 1.6), the serial root (`roots_ms` 35-37) and the vote side (the vote-log sync, 8-12 ms on
/data's NVMe shared with seven ELs; a separate device for the consensus datadir is the production-safe answer,
`N42_VOTE_LOG_NOSYNC` the bench-only bound). 5M needs the mean gap at 40.0; the root cycle allows ~37.

## 4. Stages (each behind `N42_FRAME_ROAD=1`, default off)

| stage | change | proof |
| --- | --- | --- |
| 0 | road map + FIFO + admission and seeding, counters (`road_frames`, `road_txs`, `road_refused{reason}`, `road_len`) logged on the ingest line; no build uses it (admitted frames are immediately also given to the lanes path, so nothing changes) | admission rate ~= ingest rate after the first block per sender; refusal reasons |
| 1 | the build takes road frames first; hand-back and retire; accounting | unit tests: take / give-back / commit / interleaved lanes sender (R1), depth mirror exact; fleet: lock duty < 40%, plan wait 0, `fields_mismatches=0`, verify pass |
| 2 | invalidation path (refusal, foreign canonical block), restart | unit tests + `roll --kill` |
| 3 | bench: X18 + road vs X18, two pairs; then + the cuts + NOSYNC | two-pair rule |

## 5. Stage 1 as built (2026-10-20, branch perf/frame-road)

`crates/n42/tx-queue/src/road.rs`, hooks in `lib.rs`; `N42_FRAME_ROAD=1` is the road, `=count` stage 0 (admission and
seeding counted, every frame still on the lanes path). Where it differs from section 2, and why:

* **No `lane_owned`; a refusal invalidates the road.** The frame planner takes a lane's head as the account's next nonce.
  A frame of a road sender S that goes the lanes path while S still has frames queued on the road (`k..k+3` on the road,
  `k+4` in the lanes) is planned ahead of them -- the block refuses it -- and the gate, shut by that very lane entry, never
  takes `k..k+3`: the road stops for good. So whenever a transaction of a sender *on the road* (one with an admitted frame
  this epoch) would reach the lanes beside its road frames -- a refused frame naming it, a frameless push (pool listener,
  reorg), a road frame given back in part (a refusal mid-frame, an untake), a lanes give-back of it -- the road is
  **invalidated** (`Inner::road_flush`): the map is cleared and the epoch raised (every sender seeds again), the FIFO's
  frames are inserted into the lanes in admission order and indexed there. A refused frame whose senders were seeded but
  not yet on the road only moves their `next` past it (no flush). Taken frames of an older epoch handed back go to the
  lanes and are indexed. This is stage 2's "refusal" item, pulled in because stage 1 is not live without it.
* **Seeding** holds the drain gate and drains everything pushed so far in the seeding hold (the lane tail must include
  frames still in the inbox, or `next` is too low and the next frame refused). A sender whose lane is empty but known is
  *not* seeded from the mined watermark: what it has in flight (a build's take, an own block) is not in the lanes, so the
  watermark cannot say where it is; the frame is refused `unknown` and the sender joins at its next frame. A sender the
  lanes never saw joins at its nonce in the frame and gets an empty lane (for the chain's watermark and a give-back).
* **`lane_debt` is recounted at the gate**, not kept by increments: a lane carries the epoch its sender joined in, every
  insert into such a lane (drain, run slice, give-back) adds the sender to a debt set, and the gate prunes the set of empty
  lanes and counts what is left (the `lane_debt` gauge). Exact where it is read, and no hook on the take or prune paths.
* **Prepared plans** (plan-ahead): a plan holding road frames records the epoch; its verdict refuses it (`Below`) when the
  epoch moved or a road sender has debt again (a give-back between the plan and the build). Road frames at a top-up's tail
  are correct: their predecessors are earlier in the same body.
* **Gate stuck.** Debt the frame planner can never take (a road sender's frameless lane entry, a frame's tail) would shut
  the gate for good, and with frames on the road `frames_arriving` refuses the walk. The gate shut for 8 builds with the
  debt not shrinking invalidates the road.
* **Retire**: a canonical prune (`prune_block`, `remove_folded`) drops the taken frames whose first member the block
  mined; a give-back recognises a whole frame by the pointer of its first transaction followed by the rest in order.
  The taken list gets the road's transactions in plan order, on the planner's pool past 16,384 (a reference count each,
  a cache miss each).
* Other: with `N42_QUEUE_PLAN_SNAPSHOT` the road only counts (the snapshot planner never takes from it); a walking build
  invalidates a non-empty road first; `take_frames` finds a taken road frame by id.

**Left for stage 2:** a canonical block not built here (stale road frames on the FIFO and in prepared plans: their
`lowest` does not list road senders); the window between a refused frame's admission decision and its staging into the
inbox, in which the sender's next frame can be admitted and planned before the refused one reaches the lanes (the
block refuses it and the road is invalidated, so it is a stall, not a fault); a flush loop when untakeable debt keeps
coming back (each cycle builds from the lanes); restart; the 16 KB hash copy per admitted frame (`RoadFrame::of`).

