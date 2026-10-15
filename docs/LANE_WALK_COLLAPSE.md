# Lane-walk collapse: onset analysis of stage bq leg Fb (2026-10-15)

Leg `loop351D2S12P30T64X11T16Fb` (main's tree c00da0335 plus runner scripts, E=1: one execution layer, seven
keys) read 4.21M / 2.80M / 2.31M; its twins Fa and Fc on the same tree read 382.6M with zero frames skipped.
Logs: `/data/blockchain/rust-fleet7-bench/bench-loop351D2S12P30T64X11T16Fb/node0-el.log` (the only EL, so the
leader of every view). All block numbers below are that log's `seal-first build phases` lines.

## 1. Onset: the leg's first full block was a lane walk

| time (UTC) | block | what the leader's EL logs |
| --- | --- | --- |
| 17:15:08.7-10.94 | 796-863 | pre-flood: small or empty blocks by hashes (the same in Fc); no prune, no WARN |
| 17:15:10.97-11.09 | **864** | first full build: `plan_wait_timeout=true` (30 ms), `start_frames_index=0`, `by_ref=0 slow=0`, `queued=779000`; sealed 200,000 txs as a **hash-list body** (`bytes=6400828`, no `frame build sealed` line) = the `FRAME_BUILDS_WALKED` branch of `frame_blocks::select` |
| 17:15:11.17 | 865 | `plan_discard="not_on_its_parent"`, `frame build sealed frames=400 skipped=208`, index 1,195 |
| 11.22-11.56 | 866-870 | skipped 517 per build |
| 12.48 | 888 | skipped 4 (prune removed the frames the walk mined), then +~8 a block |
| 35.46 | 1384 | first build >6,000: the count is now quantised at ~4,200 multiples (4,162 / 8,387 / 12,784 / 17,831 / 22,543): each planning pass (plan, top-up) re-skips a stuck set the size of the whole live index (`frames_indexed` 4,200-4,900 in the prune lines) |
| 37.37 / 37.64 | 1417 | first `canonical subscriber lag: queue pruner`, first `own block was still held when the bound was reached` (bound=16, 200,000 `held_evicted`): consequences, 33 s after onset; they then amplify (evicted, unmined nonces are new holes) |
| 39.3-40.7 | 1463-1489 | 23k -> 48k skipped, `plan_wait_timeout` back, blocks of 104-175k txs; w2 median 20,172, w3 32,165 |

Fc's first full block (1034, 17:20:22.36) was `frame build sealed frames=100 skipped=0`, `start_frames_index=83`.
In Fb the refusal never fired: `frame plan empty while frames are arriving` 0 times (also 0 in Fc), no hold WARN
or prune lag before 37 s, no tenure change (one EL), 90 `not_on_its_parent` discards against 1 in Fc (all after
864; a consequence of slow plans, not the cause). So 10.140's "mid-run" collapse is the flood-start walk again:
it was seeded at block 864 and only *became visible* late, because the stuck set grows slowly until it fills the index.

## 2. Why e4893e175 missed it: frames in the drainer's hands are invisible

`TxQueue::frames_arriving()` (tx-queue/src/lib.rs ~2044) checks `frames_staged != 0` and `pending_frames`
non-empty. `drain_chunked` (~3105) first takes the frame inbox **off the lanes' lock** and subtracts it from
`frames_staged`, then takes the transaction inbox into `in_hand` (which the depth counts: `queued=779000`), and
only then waits for the lanes' lock to `push_pending`. While the build holds that lock to plan (index 0, nothing
to plan), the drainer waits with every frame in a local variable; when the build lets go and asks
`frames_arriving()`, `frames_staged` is 0 and `pending_frames` is still empty if it wins the lock first -> `false`
-> `best_for_build` walks; the walk's own drain then moves the batch into the lanes and takes 200,000 lane heads.

## 3. Why the skipping never resets

`plan_serial`/`plan_parallel` count a frame `ByRef::Unusable` when any of its runs does not start at its
sender's lane head, and leave it **in the live index** (only a take `retire`s a frame; the prune drops a frame
only when the chain mined its first run). A walked block leaves, for every sender cut mid-frame, a lane head that
belongs to a frame the walk half-took; nothing in frame mode takes that head again (the walk is the only
frameless puller and it runs only on an empty plan), so that sender's later frames are all Unusable, and a mixed
frame strands its other senders' runs too. The stuck set grows with the flood (~8 frames a block) until it is
the whole index; from then each top-up pass re-scans it, plans run short, the plan-ahead misses its 30 ms, the
pruner lags and the own-block hold bound evicts -- the w2/w3 shape. `give_back`'s `revive_by_first` does not help:
it revives only frames a discarded plan took whole.

## 4. The one-probe branch's commits

`d0c39d343`, `e68af1d3d`, `9a110b8f8`, `2463720f7` touch only `engine-types` (`one_probe.rs`, `output_shards.rs`,
`batch_state.rs`, `payload.rs`, `parallel_transfer.rs`) and `qmdb-reth`; none touches `tx-queue` or
`frame_blocks::select`. The one-probe tree's tx-queue differs from main's only by an off-by-default body wait
(`N42_ONE_PROBE_BODY_WAIT_MS`). None removes the race; at most they change its timing (shorter plan hooks). 2 of 16
against 0 of 14 is not significant (Fisher one-sided p ~0.28). **Do not cherry-pick any of them for this.**

## 5. Smallest fix for main

1. `tx-queue/src/lib.rs`: a `frames_in_hand: AtomicUsize`, raised in `drain_chunked` (and any other off-lock
   taker of `frame_inbox`) *before* `frames_staged.fetch_sub`, lowered after `push_pending` under the lock;
   `frames_arriving()` returns true while it is nonzero. (Checking `in_hand != 0` alone leaves the gap between
   taking the frames and taking the batch.)
2. Defence in depth in `engine-types/src/frame_blocks.rs` `select`: refuse the walk also when
   `queue.frames_indexed() > 0` or the queue holds more than a block's worth, i.e. walk only a thin pool
   (funding, RPC) -- a flood's pool is never frameless.
3. Log `FRAME_BUILDS_WALKED` beside `frame_walk_refused` in the phases line (today a walk is visible only as a
   hash-list body without a `frame build sealed` line).

## 6. Measurement that proves it

Six or more X11+T16 legs at 30 ms on the fixed tree (Fb's collapse rate is 2 in 16): `start_frames_skipped` must be
0 on every build of every leg, `FRAME_BUILDS_WALKED` must not move after the flood's first full block, and that
block must log `frame build sealed`. A nonzero `frame plan empty while frames are arriving` count is the guard
working, not a failure. A unit test: frames taken by `drain_chunked` but not yet pushed -> `frames_arriving()`.
