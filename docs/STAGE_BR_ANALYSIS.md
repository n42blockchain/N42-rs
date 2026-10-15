# Stage br analysis: the control's collapse onset and the answer-before-reverts shortfall

Read-only analysis of loop351 stage br (BREAKTHROUGH_DESIGN 10.141; tree 34664e4cf = main c00da0335 + the lane-walk in-hand fix, `N42_FRAME_WALK_REFUSE_INDEXED` off). Logs: `bench-loop351D2S12P30T64X11T16{t,ABRa,ABRb,ABRc}`; controls `...G4b` (stage bp) and `...Fa/Fc` (stage bq). Method and scripts as docs/CYCLE_TAIL_ANALYSIS.md.

## Q1. Control leg t: a streaming walk that ended at the gas cap

### Timeline (leader EL, node0-el.log)

| time (UTC) | block | what the log shows |
| --- | --- | --- |
| 19:47:03.756-04.979 | 793-830 | funding: small hash-list bodies (86-500 txs) |
| 04.98-05.955 | 831-861 | 31 empty builds (`txs=0`), no refusal, no WARN |
| **05.987** | **862** | build 1730 starts on an empty pool: `start_frames_index=0`, `plan_wait_timeout=true`; plan empty, `frames_arriving()` false -> `FRAME_BUILDS_WALKED` branch. `par_pull_ms=280`, `sealed_at_ms=410`: the walk pulls the flood's first burst *as it arrives* |
| 06.373 | 862 | `built ahead ... number=862 txs=200000 bytes=6400828` (hash-list body, no `frame build sealed`); phases: `queued=2374000` at seal |
| 06.432 | 863 | first `frame build sealed frames=400 skipped=75`, index 5,494 |
| 06.477-06.780 | 864-869 | `skipped=1608` each (walked frames: lane head past their first nonce until 862 is mined) |
| 06.821-... | 870-883 | `skipped=0`: the sweep dropped the frames 862 mined |
| 07.5 on | 884 | `skipped` 1, 7, 13, 19, 42 ... growing; 12-20k per build in the windows, max 57,868 |

`frame_builds_walked=865` is cumulative and counts every empty pre-flood build too, so it cannot show the walk of 862.

### The three legs side by side

| leg | walked block | txs | how the walk ended | `par_pull_ms` | skipped afterwards |
| --- | --- | --- | --- | --- | --- |
| t | 862 | 200,000 | **gas cap**, inbox still streaming (queued 2.37M) | 280 | 75, 1608, then 0 for 14 blocks, then growing to 12-58k: collapse |
| ABRa | 858 | 3,000 | dry (lanes empty; aligned body, 1,044 bytes) | 0 | 0 throughout |
| ABRb | none (1 refusal, `reason="arriving"`, 19:57:22.568) | -- | -- | -- | 0 throughout |
| ABRc | 1049 | 88,000 | dry (below the cap) | 21 | 2933, 880, 704, 352, then 0 for good |

### Mechanism (code path)

1. `frame_blocks::select` decides once, at plan time: plan empty, `frames_arriving()` false (inbox empty, nothing in hand, `pending_frames` empty), index 0 -> `queue.best_for_build(parent)`.
2. That `QueueBest` (walk mode) calls `drain_inbox_block` on **every refill** (tx-queue `impl Iterator for QueueBest`, `next`, ~l.5592): the walk is a streaming puller. The flood starts during it; it drains frame transactions into the lanes and takes them in lane order until the builder hits the gas limit.
3. Stopping at the cap cuts senders mid-run. `FrameIndex::sweep_into` drops a frame once **any** run's first nonce is mined, so a half-taken frame is dropped and its untaken tail stays in the lane as frameless lane heads.
4. `check_by_ref` (frames.rs ~l.760) returns `ByRef::Unusable` when `head + run.before != run.first_nonce`; every later frame of a cut sender, and every frame that shares a run with one, is skipped by `plan_serial`/`plan_parallel` (`plan.skipped += 1`, lib.rs ~l.4341) and stays in the index. Nothing in frame mode takes the orphan heads (only a walk does, and a walk runs only on an empty plan), so the stuck set spreads frame by frame (the +6/block from 884).
5. ABRa/ABRc recovered because their walks ended **dry**: no sender was left with a tail, the walked frames were swept once the walked block was mined (ABRc: four builds in the four-block pipeline), and nothing was orphaned.

### Smallest fix

A walk in frame mode must not stream: take only what the lanes hold when `select` decides. In tx-queue add a `drain: bool` to `QueueBest` (true for `best_for_build`, false for a new `best_for_walk`), skip `drain_inbox_block` in `next` when false, and call `best_for_walk` from the `FRAME_BUILDS_WALKED` branch. The pool is thin there by construction (the refusal passed), so the walk ends dry, as ABRa/ABRc did. Arrivals during the build stay in the inbox for the next plan. About 8 lines; unit test: walk an empty queue, `push_frame` three frames, pull -> `None`, and the next plan takes all three whole.

**Would `N42_FRAME_WALK_REFUSE_INDEXED=1` have prevented this instance? No.** At select time the index was 0 (`start_frames_index=0`) and `frames_indexed()` = index + in hand + staged was 0 too, since `frames_arriving()` was false. The frames arrived during the 280 ms pull, after the only check. The gate only covers a walk that *starts* with frames indexed (the case it was added for); stage bs can still collapse this way.

## Q2. Answer before reverts: L fell 25-29 ms, the cycle 1-2 ms

### L = seal -> answer (window blocks, means; p50 in brackets)

| step | G4b | ABRa | ABRb |
| --- | --- | --- | --- |
| seal -> merge start | 56.9 (55.2) | 58.2 (54.1) | 62.9 (59.5) |
| merge: state + reverts | 49.2 + 47.9 | 51.8 + 0 | 52.9 + 0 |
| merge end -> state ready (new) | 0.0 | 10.9 (p90 33.8) | 11.1 (p90 34.1) |
| seal -> state ready | 160.8 | 121.1 | 127.0 |
| state ready -> handed | 12.6 | 19.0 | 17.8 |
| handed -> canonical | 3.6 | 3.5 | 3.6 |
| canonical -> answer | 21.9 | 26.7 | 25.9 |
| **L** | **198.9** (198.0) | **170.2** (166.9) | **174.2** (170.1) |

The reverts did leave the path (47.9 ms), but 19-23 ms came back: a new wait between merge end and state ready (41-42% of blocks, 10-44 ms, median 25), +5..6 ms in the hand-off and +4..5 ms in newPayload, and +2..4 ms of state merge (the late-revert thread runs beside it). The merge-end -> state-ready step only builds the `Arc`, calls `n42_deferred_reverts::register` and `built_executions::state_ready`. `register` runs `entries.retain(|e| Arc::strong_count(&e.keep) > 1)` under the registry lock: when the engine has already let go of an older block's output, the registry holds the last `Arc` and the merger thread frees a ~185k-account bundle there, on the answer path. That fits the bimodal shape but is not proven: put a timer around it.

### Where the remaining L cut went (cycle decomposition, 4 gaps = proposal(N-3) -> proposal(N+1), means)

| segment | G4b | ABRa | ABRb |
| --- | --- | --- | --- |
| proposal(N-3) -> answer(N-3) | 162.5 | 143.0 | 149.5 |
| answer(N-3) -> 4th follower vote(N) | 5.3 (p50 0.9) | 20.9 (p50 6.2) | 10.3 (p50 3.9) |
| 4th vote(N) -> proposal(N+1) | 18.8 | 24.9 | 22.8 |
| **4 gaps** | **186.6** | **188.8** | **182.6** |
| mean gap, all windows / w1 | 46.7 / 46.1 | 47.2 / 45.7 | 45.7 / 45.1 |

(ABRa's views run one ahead of its blocks; mapped here, CYCLE_TAIL's scripts assume view = number.) Followers still hold the vote on N-3's answer (ABRb: 778 of 1,002 released holds by N-3, corr(gap(N), L(N-4)) 0.55). But of the 25 ms L cut only 13 ms shows from the proposal, because the **seal got later**:

| leader build (full blocks, unskipped) | G4b | Fa | Fc | ABRa | ABRb | ABRc |
| --- | --- | --- | --- | --- | --- | --- |
| `start_best_ms` p50 / mean | 3 / 5.4 | 3 / 5.4 | 3 / 4.9 | 10 / 11.8 | 11 / 12.8 | 13 / 14.5 |
| `sealed_at_ms` p50 / mean | 31 / 30.8 | 31 / 31.5 | 31 / 31.5 | 34 / 36.6 | 34 / 37.1 | 35 / 38.9 |
| seal-to-seal p50 | 36.2 | | | 38.4 | 38.7 | |
| own-block held at bound / pruner lag WARNs | 0 / 0 | 0 / 0 | 0 / 0 | 1518 / 1335 | 1655 / 1485 | 1856 / 1585 |

All three ABR legs went into G4a's degraded state (`canonical subscriber lag: queue pruner`, `own block was still held when the bound was reached`, `the queue let go of transactions`) 15-20 s into the flood: ABRb from block 1383 (19:57:37.5), ABRa from 1287. Before the onset `start_best_ms` was p50 4 (mean 6.4); after it, 12 (14.0). Controls were in this state in 1 of 5 legs (G4a), ABR in 3 of 3 (Fisher one-sided p = 0.07). Plausibly the plan waits for the lanes' lock while the lagging pruner holds it (prune `lock_us` p90 24 ms); not proven. Gaps waiting on the seal rose from 725/1930 (G4b) to 1023/1971 (ABRb). The vote side gave back another 9 (ABRb) to 22 (ABRa) ms per four gaps.

**Shortfall, ABRb, per four gaps:** expected -47 (reverts) -> L actually -25 (-22 returned on the answer path) -> -13 after the seal moved -> -4 after the vote side's +9 = **-1.0 ms a gap** (ABRa +0.5; window 1 -0.4..-1.0 by this windowing, -2.4 by the bench's).

### Next levers

| rank | lever | expected |
| --- | --- | --- |
| 1 | Find why ABR legs enter the pruner-lag / hold-bound state (3 of 3), e.g. whether the late reverts delay the queue pruner's canonical notification or its lock. Back to `start_best` 3-4 ms and `sealed_at` 31 | -6 ms on the seal; gap -3..-4 ms (window-bound share back to G4b's) |
| 2 | Take the old-output free out of `register` (collect the dead entries, drop them after the unlock on a background thread), after a timer confirms it | L -11 (mean), gap -2..-3 |
| 3 | `N42_ANSWER_AT_INSERT=1` on top (canonical -> answer is now 26 ms) | L -20..-25, gap capped near the seal pace (~38.5 p50) |

Levers 1 and 2 together take the four-gap sum from 182.6 to about 160-165, a 40-41 ms mean gap. Below that the seal floor (seal-to-seal 38.5 p50) sets the pace, and lever 3 pays only after the seal is faster.
