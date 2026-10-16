# The X15 build's remaining cuts toward a 26 ms seal

Read-only analysis of loop351 stage ca (BREAKTHROUGH_DESIGN 10.150): X15 legs `bench-loop351D2S12P30T64X11T16Qs{a,b}`
(X14 + `N42_HANDOFF_DONE_FIRST=1 N42_SHARDS_READY_FIRST=1`, drain 4.581 / 4.563M/s) against the X14 controls `...Q{a,b}`
(4.250 / 4.410M/s), 600M set. Source: every `seal-first build phases` line of `node0-el.log` sealed in T0 .. T0+90 s with
>= 190k transfers (Qsa 2,059, Qsb 2,048, Qa 1,916, Qb 1,980 builds), node1..6-v.log and `loop351ca.launch.out`. Method and
field names as in docs/SEALED_AT_FLOOR.md; scripts kept outside the repo (`parse.py`, `ana.py` .. `ana5.py`).

Over the whole 90 s (not window 1 only) X15's `sealed_at` is **33 / 34 p50, 34.6 / 35.4 mean** (p90 49 / 50); window 1 reads
30-31 p50 and it drifts up 3-5 ms by window 3 (section 3). Mean proposal gap 43.7 / 43.9 = mean `sealed_at` + start delay 9.0 / 8.5.

## 1. sealed_at, decomposed (ms, p50 / mean; identity holds to a 0.5 ms residual)

| part | Qsa | Qsb | Qa (ctl) | Qb (ctl) | X15 - ctl (means) |
| --- | --- | --- | --- | --- | --- |
| **sealed_at** | 33 / **34.6** | 34 / **35.4** | 37 / 42.0 | 36 / 39.7 | **-5.9** |
| par_start | 3 / 4.3 | 3 / 4.1 | 12 / 13.0 | 12 / 13.0 | **-8.8** |
| . start_handoff (of it the hold) | 1 / 2.5 (0.8) | 1 / 2.4 (0.7) | 9 / 10.2 (8.4) | 9 / 10.2 (8.5) | -7.8 |
| . start_select | 0 / 0.7 | 0 / 0.7 | 1 / 1.7 | 1 / 1.6 | -0.9 |
| . plan_wait / other | 0 / 0.3, 1 / 0.7 | 0 / 0.2, 1 / 0.7 | 0 / 0.4, 1 / 0.8 | 0 / 0.5, 1 / 0.7 | -0.2 |
| par_to_seal | 19.5 / 21.8 | 19.5 / 22.0 | 17.8 / 21.3 | 17.7 / 20.7 | +0.9 |
| . state_wait (`output` on 48-49%) | 0.9 / 2.4 | 1.1 / 2.5 | 0.5 / 2.3 | 0.3 / 2.5 | **0.0** |
| . gap_before_exec (overlaps state_wait) | 2 / 2.7 | 2 / 2.7 | 1 / 2.2 | 0 / 2.4 | +0.4 |
| . par_exec (last batch end) | 16.2 / 17.8 | 16.3 / 18.1 | 15.2 / 18.2 | 15.3 / 17.5 | +0.1 |
| .. CPU floor (wall sum / 64) | 11.8 / 12.9 | 12.0 / 13.1 | 11.0 / 12.9 | 11.0 / 12.5 | +0.3 |
| .. imbalance | 4.2 / 4.9 | 4.2 / 5.0 | 4.0 / 5.3 | 4.1 / 5.0 | -0.2 |
| . rest (own body prep on late-body builds) | 0.5 / 1.6 | 0.5 / 1.5 | 0.5 / 0.8 | 0.4 / 0.6 | **+0.9** |
| sealed | 5 / 8.1 | 5 / 8.8 | 3 / 7.2 | 2 / 5.5 | **+2.1** |
| . parent_fields wait (`both` 49% / 52%; ctl 32% / 21%) | 0 / 5.5 | 1.3 / 6.2 | 0 / 5.0 | 0 / 2.9 | +1.9 |
| . tx root | 2 / 2.2 | 2 / 2.1 | 2 / 1.9 | 2 / 1.9 | +0.2 |
| seal -> shards ready (par_to_shards; pulled_drop) | 7.8 (0.2; 0.0) | 7.6 (0.2; 0.0) | 14.3 (6.7; 6.4) | 14.0 (6.2; 5.9) | -6.3 |
| child exec start - parent shards ready | 0.3 p50 | 0.3 | 0.7 | 0.9 | |
| start delay (gap - sealed_at) | 1.8 / 9.0 | 1.7 / 8.5 | 1.7 / 5.0 | 1.7 / 5.8 | **+3.4** |

What SHARDS_READY_FIRST changed: the start fell as expected and more (-8.8 = the hand-off -7.8, the select -0.9), and this
time **state_wait gave nothing back** (2.4 -> 2.4; with done-first alone it rose 2.4 -> 6.8-7.5): the parent's shards are filed
0.2 ms after the parallel step, so the child, starting 1.8 ms after the parent's seal, reaches its execution 0.3 ms after
them. Of the -8.8, **3.0 came back** inside `sealed_at`: the parent-fields wait +1.9 (the seal now comes sooner than N-2's
fields) and the late plan bodies +0.9 (section 2). Outside it the start delay rose +3.4 (vote-bound builds with > 10 ms
delay: 14.2-14.6% of builds x 50-52 ms = 7.1-7.6 ms of the mean, against 7.3-8.7% / 3.4-4.2 on the controls), so the
gap fell only 46.3 -> 43.8 (VOTE_BOUND_GAPS' elasticity).

Tail (top decile >= 49 / 50 ms: 60.8 / 62.2 against 31.6 / 32.1 for the rest; 3.0 / 3.3 ms of the mean): fields 1.37 / 1.53
(of it the parent-fields wait 1.32 / 1.43), par_exec 1.26 / 1.37, par_start 0.17 / 0.21, state_wait 0.10 / 0.06. By kind:
fields-only 98 / 92, exec-only 71 / 64, both 12 / 29, start 6 / 8 of ~205. The start no longer has a tail.

## 2. The plan_body 2 builds: a late body, not a short plan

`plan_body` is the plan's *body* (0 none, 1 used, 2 not ready = `PreparedBodyTake::Late`, 3 not this build's), not the
top-up (that is `plan_ahead` 2). On every leg every plan was prepared ahead and full: `plan_ahead` 1 on 2,058 / 2,046 builds,
`plan_topup_txs` 0, no `plan_wait_timeout`, plan_wait 0.3 ms mean, queue at the builds 2.34M. The index was not short and the
planner was not late; **the body hook was** (`N42_PLAN_AHEAD_BODY_THREADS=16`, made 12.5 ms after the plan is stored).

| leg | body | builds | sealed_at p50 / mean | par_to_seal mean | own prep (par_prep + partition + slots) | gap_before_exec | plan_age p50 | parent sealed_at p50 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Qsa | 1 used | 1,865 | 32 / 33.9 | 20.8 | 0 | 2.4 | 27.5 | 34 |
| Qsa | **2 late** | 193 (9.4%) | 39 / **41.9** | 31.6 | 6.4 + 2.5 + 1.2 | 5.4 | **9.8** | **23** |
| Qsb | 1 used | 1,873 | 33 / 34.7 | 21.2 | 0 | 2.5 | 28.0 | 35 |
| Qsb | **2 late** | 173 (8.4%) | 41 / **42.4** | 31.1 | 6.2 + 2.3 + 1.1 | 5.7 | **8.5** | **24** |
| Qa / Qb | 2 late | 33 / 14 | 49 / 53.9, 45 / 45.3 | 33.5 / 29.3 | ~10 | 5.3 / 6.0 | 11 | 30 |

* A late body costs **+8 ms** of `sealed_at` (10.5 ms of own preparation on the critical path, partly overlapped). Tax on
  the mean: 0.75 / 0.65 ms now. Late happens only when the plan is younger than ~15 ms (46% of builds with plan_age < 15 ms,
  ~1% above), i.e. when the **parent sealed fast** (p50 23-24 ms): the plan is stored at the parent's take + 10 ms, its body
  at + 22.5 ms, and the child starts at the parent's seal + 1.8. Estimated body-ready minus child start on late builds:
  **+2.3 ms p50** (+1.9 / +2.8 mean): the build gives up 2-3 ms short of the body and spends 10.5 ms making its own.
* It grows as the seal shrinks: 24-26% of builds whose parent sealed under 26 ms are late; at a 26 ms mean that is
  half the builds, i.e. ~2-2.5 ms of mean.
* Smallest change: **on `Late`, wait on the body slot (condvar on `BodySlot`, bound `N42_PLAN_BODY_WAIT_MS=5`)** before
  falling back. Expected -0.6..-0.7 now, and it keeps ~2 ms from coming back at a 26 ms seal. The alternatives are larger and
  buy less: a larger plan-ahead or two plans ahead do not help (the plan is never short); `N42_PLAN_AHEAD_WAIT_MS` waits for
  the plan, not the body; more body threads (16 -> 32) shorten 12.5 ms but take cores from the build's neighbour.

## 3. The fields wait is the serial root, near saturation

`parent_fields` (N's seal waits for N-2's state root and receipts) is the largest part that grew, and it drifts over the
round with the chain's state:

| leg, window | sealed_at mean | parent_fields mean | seal -> fields | root compute (rehash) | root duration / gap = utilisation | root start - prev root end p50 | ops ahead done -> root start |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Qsa w1 / w3 | 32.3 / 36.7 | 3.5 / 7.5 | 65.7 / 77.2 | 29.3 (4.9) / 34.9 (8.4) | 34.7 / 42.4 = 0.82; 39.1 / 45.2 = 0.87 | 1.9 / 1.7 | 3.7 / 9.7 |
| Qsb w1 / w3 | 33.2 / 38.9 | 2.8 / 10.5 | 64.0 / 83.4 | 29.0 (5.2) / 37.8 (8.6) | 0.81 / 0.91 | 2.3 / 1.6 | 3.1 / 11.5 |
| Qb w1 / w3 (ctl) | 38.6 / 38.2 | 0.5 / 2.2 | 55.1 / 65.9 | 25.5 (5.0) / 31.3 (8.4) | 0.65 / 0.80 | 10.4 / 2.8 | 3.8 / 6.5 |

The roots run one after another: a root starts ~2 ms after the previous one ends (p50) and 4-12 ms after its own ops ahead
are ready, at 82-91% utilisation of the block interval. Root compute grows 29 -> 35-38 ms over the round (twig/SBMT rehash
4.9 -> 8.5, leaves 5.5 -> 6.6-7.9, apply 22 -> 27-30); the controls drift the same way but have 2-4 ms more gap to absorb
it. At a 40 ms gap a 38 ms root is utilisation 0.95: the fields wait would dominate. **Spreading ops-ahead's encode/sort is
no longer a lever** (SEALED_AT_FLOOR candidate 3): the root waits for the previous root, not for the ops.

## 4. Remaining build-side cuts toward a mean sealed_at of ~26 (from 34.6-35.4)

| rank | cut | mechanism | expected (mean) | proof counters |
| --- | --- | --- | --- | --- |
| 1 | **root duration / the fields race** | the serial QMDB root at 0.82-0.91 utilisation; parallelise the rehash upper levels and the leaves further on the 16 critical cores, or carry depth 3 (N's seal waits for N-3's fields) | -4 (5.5-6.2 -> ~1.5) and the w1->w3 drift (+4.4 / +5.7) gone | `parent_fields_us` mean <= 2 in every window, `both` share <= 25% (now 49-52%), root duration / gap <= 0.75, root start - prev root end p50 >= 5 ms, `root_rehash_us` w3 <= 6 ms |
| 2 | **execution imbalance (work stealing)** | 4.9-5.0 ms between the CPU floor and the last batch end; 256 batches did not move it (10.150); workers pull small sender-group chunks from an atomic cursor | -3..-3.5 | imbalance (`batch_last_end_us` - `batch_wall_sum_us`/64) <= 1.5, par_exec mean 17.9 -> <= 14.5, `batch_open_sum_us` +<= 25 ms |
| 3 | **wait for a late plan body** | section 2: bounded wait on the body slot instead of 10.5 ms of own prep; small code change | -0.7 now; protects ~2 at a 26 ms seal | `plan_body` 2 -> a new `plan_body_wait_us` (p50 <= 3 ms), late fallbacks <= 1%, par_to_seal of those builds 31 -> <= 24, `par_prep_ms` mean 0.6 -> ~0 |
| 4 | slow-execution builds | top decile par_exec 28.7-29.2 against 16.5 (tax 1.3-1.4); partly the imbalance of 2, partly CPU per transfer (the journal walk of SEALED_AT_FLOOR section 2) | -1 | top-decile par_exec <= 22; `view_journal_searches` / `batch_view_index_wait_us` on the slow builds |

Sum -8.7..-9.2 -> 25.4-26.7 ms. Not candidates now: the hand-off (2.5 mean, hold 0.8: at most ~1.5 left), the select (0.7),
the plan's fullness (always full), the ops-ahead spread (section 3), the parent's fold behind the seal (7.0-7.7 ms; the
child already reaches it only 0.3 ms early, so its whole remaining cost is the 2.4 ms state_wait, ranked after 4).

Order to run: **3 first** (small, sure, a prerequisite: every later cut makes more bodies late), then 1 (the largest, and the
one that grows with the state), then 2. The target arithmetic: at the current start delay (8.5-9.0 mean) 26 ms is a 35 ms
gap on paper, but the start delay is elastic (it rose +3.4 while the seal fell 5.9): a mean gap of 40 needs the build at
~26 **and** the vote side (VOTE_BOUND_GAPS: L 129-130 ms seal -> state ready, unchanged).

## 5. The followers

E=1 with import-once: the six followers import nothing themselves; the shared execution layer answers every key. Their part
is unchanged by X15 and far inside the window:

| leg | follower check_us p50 / p99 (nodes 1, 3, 5) | quorum -> last vote p50 / p99 (R1) | proposal -> commit p50 / p90 | slow vote-log syncs per follower log |
| --- | --- | --- | --- | --- |
| Qsa | 166-170 / 484-626 us | 1.6 / 8.4 ms | 32 / 45 | 597-615 (29-31% of blocks) |
| Qa (ctl) | 158-164 / 477-543 us | 1.5 / 9.5 ms | 32 / 48 | 498-550 (25-28%) |

No follower is the next bound. What the faster seal meets is the vote-bound wait on the shared layer's answer (start delay
> 10 ms on 14.2-14.6% of builds, against 7.3-8.7% on the controls): the five-block window or a shorter L, not the followers.
