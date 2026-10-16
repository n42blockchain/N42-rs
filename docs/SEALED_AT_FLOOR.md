# Where 4 ms of the leader's sealed_at can come from

Read-only analysis of the two X14 controls of loop351 stage bx (`bench-loop351D2S12P30T64X11T16M{a,b}`, 30 ms pacing,
200k-transfer blocks, E=1, drain 4.455 / 4.449M/s) and, for the hand-off question, `...Mh{a,b}` (`N42_HANDOFF_DONE_FIRST=1`).
Source: every `seal-first build phases` line of `node0-el.log` sealed in T0 .. T0+88 s with >= 190k transfers (Ma 1,957, Mb 1,956
builds), the queue pruner's lines on the same log, and `loop351bx.launch.out`. docs/VOTE_BOUND_GAPS.md set the target: mean
proposal gap = mean `sealed_at` (39.9 / 40.8) + start delay; 40 ms needs `sealed_at` -4 ms plus the five-block window.
Scripts are kept outside the repo (the analysis job's `tmp/saf/`: `parse.py`, `ana.py` .. `ana5.py`).

Three corrections to the starting picture:

* X14 builds on **64** threads (`N42_PARALLEL_BUILD_THREADS=64`, `N42_CORE_LAYOUT_BUILD_CORES=64`, layout `b64/c16/bg128`),
  so 128 batches are two waves, not four.
* **The roots are not in `sealed_at`.** The seal is taken at the execution's end on counters; the block's QMDB root runs behind
  it (seal + 24.8 -> seal + 62 ms) on the 16 critical cores. A root reaches `sealed_at` only through the carried fields: at
  carried depth 2 block N's seal waits for N-2's state root and receipts (`parent_fields_us`, inside `sealed_ms`).
* **The start floor is the parent's `seal_to_shards_ready`, not the hand-off.** The child's execution starts 1.1 / 2.0 ms (p50)
  after the parent's shards are filed on the controls and 0.2 ms after on Mha. The hand-off wait (11-12 ms) just happens to
  end there. That is why `N42_HANDOFF_DONE_FIRST` is elastic (10.116, 10.147): on Mh{a,b} `par_start` falls 14.7 -> 4.7-5.4,
  but `state_wait` (on the parent's output) rises 2.4 -> 6.8-7.5 and `gap_before_exec` 2 -> 7, so `sealed_at` drops only
  3.1 / 2.1 ms (36.8 / 38.7).

## 1. sealed_at, decomposed (ms, p50 / mean; the identity holds to a 0.5 ms residual)

| part | Ma | Mb | what it is |
| --- | --- | --- | --- |
| **sealed_at** | 37 / **39.9** | 37 / **40.8** | build start -> seal |
| par_start | 12 / 14.7 | 14 / 16.3 | start -> parallel step |
| . start_handoff | 10 / 11.3 | 10 / 12.2 | wait for the parent's queue hand-off; of it the hold 7.7 / 8.1 (8.4 / 8.9), the rest most likely the lanes lock |
| . start_select | 0 / 2.0 | 0 / 2.6 | frame take |
| . plan_wait | 0 / 0.6 | 0 / 0.8 | plan ahead never late (no timeouts, plan_body 0 on 2 / 1 builds) |
| . other | 0 / 0.8 | 0 / 0.7 | |
| par_to_seal | 17.5 / 20.1 | 17.1 / 19.5 | step -> seal |
| . state_wait | 0.3 / 2.4 | 0.2 / 1.9 | parent's output not yet filed (`output` on 39% / 34% of builds) |
| . par_exec | 15 / 16.6 | 15 / 16.5 | the batches |
| .. CPU floor (batch wall sum / 64) | 10.9 / 12.1 | 10.8 / 12.1 | |
| .. imbalance (last end - floor) | 4.1 / 4.9 | 4.2 / 4.8 | the second wave's tail |
| . rest (hook, collect, exec end -> seal 0.1) | 0.6 / 0.9 | 0.7 / 1.0 | |
| sealed | 2 / 4.6 | 2 / 4.5 | seal path |
| . parent_fields wait | 0 / 2.2 | 0 / 2.3 | N-2's fields late on 19% / 18% of builds (`both`) |
| . tx root / frame layout | 1 / 1.5-1.8 | 1 / 1.7 | |

Batch start skew (9.2 / 9.1 mean, last start 9.8 / 9.6 ms) is neither the lanes lock (`batch_live_lock_waits` 0 on every build;
hold time uncorrelated with anything, r <= 0.11) nor the dispatch (`batch_dispatch_us` 0.4 ms, first start 0.1 ms). With
128 batches on 64 workers the last batch starts when the slowest first-wave batch ends. Batches are equal by transfer count
(1,000-2,000, largest first), but they take 2-12 ms (min 2.4, median 5.0, max 12.0 mean): cost per transfer varies by batch,
so count balancing leaves ~5 ms of tail.

## 2. The tail: mean minus median is three separate causes, unclustered

Top decile of `sealed_at` (>= 57 / 59 ms): mean 67.7 / 68.3 against 36.7 / 37.4 for the rest. That is 3.1 ms of the mean
(0.1 x the difference). Only 14 of 200 / 217 such builds are followed by another one.

| part | tail tax on the mean, Ma / Mb | top-decile builds by kind, Ma / Mb |
| --- | --- | --- |
| par_exec (CPU doubles, not waits) | 1.41 / 1.17 | exec only (par_exec >= 22): 72 / 72 |
| sealed (parent_fields 0.83 / 0.89) | 0.89 / 0.89 | fields only (sealed >= 8): 50 / 43 |
| par_start (hand-off 0.43 / 0.46, select 0.30 / 0.44) | 0.74 / 1.03 | start only (par_start >= 25): 43 / 63 |
| | | mixed 31 / 38, none 4 / 1 |

What the slow builds correlate with (r = Pearson over all builds):

| suspect | evidence | verdict |
| --- | --- | --- |
| slow execution (155 builds, 8%) | batch CPU sum 1.22 s vs 0.69 s at the same 200k transfers; `view_journal_searches` 145k vs 75k; `batch_view_index_wait_us` 12.0 vs 4.5 ms (summed over batches); 39 of 155 in the first 10 s | CPU-bound reads below the batch map. The suspect is the QMDB view's journal walk while the parent's index is deferred (`N42_LIVE_INDEX_DEFER=1`). Not isolated yet |
| pruner's long holds | prune hold vs `start_handoff` r = 0.30-0.33, vs par_exec 0.00; lock duty 92-97% (`lib.rs:4693` holds of 7-9 ms) | feeds the hand-off's lock wait (~3 ms mean), not the execution |
| lanes lock in the batches | `batch_live_lock_hold_us` r 0.04 / 0.00 with `sealed_at`, waits 0 | no |
| other work on the box | E=1 import-once: no separate follower import. The single-thread merges of N-1..N-3 (55 ms each) overlap slow and fast builds alike (1.19 vs 1.19 of `sealed_at`). Previous block's `roots_ms` r = -0.08 / -0.10 | no |
| grandparent's root | N-2's fields ready 29.7 vs 12.5 ms after N's start; r 0.44 / 0.56 with `sealed_ms` | the fields tail |

## 3. Inside the roots (behind the seal; they matter through the fields only)

| step (ms p50 / mean, Ma; Mb within 0.5) | value |
| --- | --- |
| seal -> shards ready (fold `par_behind_seal` 7.1 / 7.8, then an untimed 6.6 / 6.7, finish 0.2) | 14.3 / 15.0 |
| ops ahead (one `n42-ops-ahead` thread: encode 6.3 / 7.4, sort 5.0 / 5.9) -> seal + | 22.0 / 22.9 |
| seal -> root start / end | 24.8 / 28.0 -> 59.6 / 62.0 |
| root compute | 28.0 / 29.5 |
| . apply 20.5 / 21.9 = leaves (QMDB leaf hashing) 4.0 / 5.0, writes 3.9 / 5.6, index 4.3 / 5.2, rehash (twig + SBMT upper levels) 5.7 / 6.4, retire 1.9 / 2.5, delta 1.4 / 2.1, sort 0.7 / 0.8, undo 0.5 / 0.6 | |
| . residual ops 2.9 / 4.4, ops finish 2.4 / 2.7, wait for ops ahead 0 / 1.7 | |
| seal -> fields published (state root + receipts) | 61.5 / 64.4 (p90 86.6) |
| transactions root (on the seal path, frames' layout) | 1-2 |

The fields wait is a race between N-2's seal + 64 ms and N's seal, which comes about 2 x 40 ms later. A replay of the measured
slack gives a mean wait of 2.5 / 2.7 ms now, 3.4 / 3.6 ms if every seal came 4 ms sooner, and 4.6 / 4.7 ms at 8 ms sooner. **Every
seal-side cut gives about a quarter of itself back here unless the fields also come sooner.**

## 4. Candidates for -4 ms of mean sealed_at

| rank | candidate | mechanism | expected | kind |
| --- | --- | --- | --- | --- |
| 1 | **the untimed 6.6 ms before shards ready, with `N42_HANDOFF_DONE_FIRST=1`** | Between the parallel step's end and the finish (`payload.rs` ~3447-3483) the build gives back the lookahead and deferred transactions (`refuse!`, which takes the queue's lanes lock at 92-97% duty) and drops the pulled set (200k pooled `Arc`s), all before `shards_ready`. The child's execution is pinned to that moment (+0.2 ms on Mha). Move the give-backs and the drop behind the shards' filing or onto a background thread, and time them | shards ready 15 -> ~9; `sealed_at` -3..-5 on the done-first path. On the control path the hand-off still binds, so it only pays together with done-first | small code change + existing knob |
| 2 | **execution imbalance** (4.9 ms mean) | Two waves at equal counts but unequal cost. Knob: `N42_BUILD_BATCHES=192/256` (smaller tail, +0.37 ms per extra view open). Design: workers pull small chunks of sender groups from an atomic cursor (work stealing), leaving ~1 ms of tail | knob -1..-2; stealing -3..-3.5 | knob, then design |
| 3 | **N-2's fields sooner** (2.2 mean now, 3.4 after a 4 ms cut) | The root starts 10 ms after shards ready because ops ahead encodes and sorts 13 ms on one thread. Spread encode/sort over the 16 critical cores (the leaves already are). Candidate 1 also starts the root 6 ms sooner | -1.5..-2, and it keeps 1 and 2 from giving ~1 ms back | small code change |
| 4 | slow-execution builds (8%, CPU x1.8) | journal walk / deferred index (section 2) | -0.5..-1.2 (their whole tax is 1.2-1.4) | measurement first: an `N42_LIVE_INDEX_DEFER=0` leg and per-batch journal time |
| 5 | hand-off lock wait + select (3.2 + 2.0 mean) | the pruner's 7-9 ms lanes-lock holds before the hand-off | ~0 by itself: done-first already removes it and the shards then bind (Mh). Counts only after 1 | -- |

Not candidates: the plan (wait 0.6-0.8, never late), the dispatch (0.4 ms), the lanes lock inside the batches (no waits), the
roots themselves (their tail does not reach `sealed_at`), and the one-block build-ahead gate (it delays the build's start,
which is outside `sealed_at`; it is the vote-side lever of VOTE_BOUND_GAPS, the two-ahead build).
Realistic stack: 1 + 3 gives -4..-6 and 2 (knob) gives another -1..-2. **4 ms needs 1 and 3 together**: 1 alone would lose ~1 ms to
the fields race.

## 5. Run first, and the counters that prove it

First, a small code change with no behaviour change: time the 6.6 ms (`give_back_us`, `drop_pulled_us`) and move both behind
`shards_ready` under a switch. Run it with `N42_HANDOFF_DONE_FIRST=1` on X14: two legs against two done-first legs and two
controls, on the 600M set, scored by drain rate. Beside it run the knob-only `N42_BUILD_BATCHES=256` pair, which needs no
build. The counters:

* `seal_to_shards_ready_us` mean 15.0 -> <= 9.5. The new timers should account for the old 6.6 ms gap
  (`seal_to_finish - par_behind_seal`).
* child exec start - parent shards ready stays <= 1 ms p50. Then `state_wait_us` mean 6.8 -> <= 3 and `gap_before_exec` 7 -> <= 2
  (done-first legs as the reference).
* `sealed_at` mean 36.8-38.7 (done-first) -> <= 34.5, and 39.9-40.8 (control) -> <= 36. Seal-to-seal mean -3 or better.
* `parent_fields_us` mean stays <= 2.5 and the `both` share <= 20%. If it rises toward 3.4, candidate 3 is next.
* BATCHES=256: imbalance (`batch_last_end_us` - `batch_wall_sum_us`/threads) 4.9 -> <= 3, `batch_open_sum_us` +<= 25 ms,
  `par_exec` mean -1.5.
* guards: verify clean, no `Sidechain block not found`, pruner lag as on the controls, plan_body 2 share as on Mh (7-10%).
