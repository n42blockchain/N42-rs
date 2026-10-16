# Degraded onset analysis on the X14 legs

Read-only analysis of loop351 stage bu (BREAKTHROUGH_DESIGN 10.144): X14 legs `bench-loop351D2S12P30T64X11T16Yf{b,c}`
(X13 + `N42_REGISTER_FREE_OFFLOCK=1`), the X13 control `...Yc` (399.0M) and the X11+T16 control `...G4b` (stage bp, no ABR).
Method and scripts as docs/CYCLE_TAIL_ANALYSIS.md (`parse.py`, `ana.py`, `ana2.py`) plus `onset.py`, `prepost.py`, `comp.py`,
`lag.py` (kept outside the repo, beside the earlier ones). Yfb and Yfc start with a view-1 TC, so their views run
one ahead of the block numbers (view = number + 1); the scripts were rerun with that offset (without it the seal-bound share reads 97%).
"Onset" = the first `an own block was still held when the bound was reached` WARN.

## Q1. L and the gap's composition with the registry free gone

L = seal -> EL answer (window blocks, means; p50 in brackets):

| step | G4b (no ABR) | Yc (X13) | Yfb (X14) | Yfc (X14) |
| --- | --- | --- | --- | --- |
| seal -> merge start | 56.9 | 60.1 | 63.1 | 61.0 |
| merge (state; reverts deferred under ABR) | 49.2 + 47.9 | 53.2 + 0 | 54.8 + 0 | 54.4 + 0 |
| register free (p90) | -- | 33-36 ms on 1/3 of builds | 4 us | 4 us |
| seal -> state ready | 160.8 | 124.6 | 118.0 | 115.6 |
| state ready -> handed | 12.6 | 17.9 | 19.0 | 18.8 |
| handed -> canonical | 3.6 | 4.5 | 5.0 | 5.9 |
| canonical -> answer (header newPayload) | 21.9 | 27.3 | 26.3 | 26.9 |
| **L** | **198.9** (198.0) | **174.2** (171.3) | **168.3** (165.7) | **166.4** (164.0) |

The off-lock free took 7-9 ms off seal -> state ready (Yc 124.6 -> 115.6-118.0) and 6-8 ms off L. Followers still release
the vote on N-3's answer (Yfb 1098 of 1161 matched holds; 4th follower vote 1.2 ms p50 after answer(N-3)); four gaps = 182-184 ms
against L 166-168. But the gap does not follow L any more: corr(gap(N), L(N-4)) is 0.29-0.38 (0.50-0.55 on G4b/Yc) because
**most gaps are now seal-bound** (the proposal waits for its own seal, not for the QC of N-1):

| leg, phase | blocks | mean gap | p50 | seal-bound share | seal-bound mean | vote-bound mean | sealed_at mean | seal-to-seal mean | start_handoff p50 / mean |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G4b, no onset | 1930 | 46.7 | 36.1 | 38% | 34.3 | 54.1 | 30.9 | 46.7 | 1 / 3.5 |
| Yc, pre (T0+0..21.7 s) | 492 | 44.7 | 35.0 | 52% | 36.2 | 54.1 | 34.4 | 44.5 | 2 / 4.5 |
| Yc, post | 1503 | 45.3 | 37.5 | 50% | 38.4 | 52.4 | 38.1 | 45.4 | 10 / 11.6 |
| Yfb, pre (T0+0..8.2 s) | 184 | 45.6 | 41.0 | 45% | 42.7 | 48.0 | 38.4 | 45.4 | 2 / 3.4 |
| Yfb, post | 1790 | 45.6 | 40.3 | 59% | 42.5 | 50.1 | 41.9 | 45.6 | 12 / 13.7 |
| Yfc, pre (T0+0..11.1 s) | 257 | 44.3 | 39.4 | 50% | 40.6 | 48.0 | 36.9 | 44.1 | 3 / 4.9 |
| Yfc, post | 1704 | 46.2 | 40.4 | 64% | 42.7 | 52.5 | 41.5 | 46.2 | 11 / 13.3 |

(Yfb/Yfc pre-onset is the flood's first 8-11 s, where `par_ms` is still 37-40 against 28-31 later; it is not a clean baseline.
Yc's 21 s pre-onset is.) The builds chain at once (prev_seal_to_start p50 1.2 ms), so the seal-to-seal cycle is
`sealed_at` + ~3 ms, and after the onset that is 45-46 ms: the mean gap *is* the build cycle. The freed L shows up only in the
vote-bound gaps (vote side (L - 12)/4 = 38.6-39.1 ms, below the seal pace). The 11 ms of `sealed_at` the onset adds is almost all
`start_handoff_ms` (+9-10 ms p50; `start_select_ms` +1, plan wait, par_ms unchanged).

## Q2. The onset

**First event, every leg:** `canonical subscriber lag: queue pruner behind=10` (Yfb T0+8.07 s, Yfc +11.0, Yc +21.54), then within
0.1-0.15 s the first hold eviction (`number=1029 holding=1045 bound=16`) and `the queue let go of transactions` (`held_evicted`).
No tenure or view event, no THP/fault change (batch_minflt flat), no `Sidechain` line before it (Yfb's comes 13 s later).

**What falls behind is the pruner's throughput, not a wait on ABR's reverts.** Pruned blocks against canonical blocks (lag.py):

| leg | prune ms per block before onset | after | pruner lag (blocks) at +10 / +30 / +60 / +90 s | notifications skipped (broadcast 256 full) |
| --- | --- | --- | --- | --- |
| G4b | 35-39 | -- | 2 / 3 / 2 / 2 | 0 |
| Yc | 40-44 | 38-60 | 5 / 50 / 267 / 444 | 135 in 102 events |
| Yfb | 43-46 | 50-78 | 29 / 213 / 410 / 689 | 388 in 261 events |

At 22.3-22.9 blocks/s (gap 44-45 ms) a 40-46 ms prune per block is a utilisation of 0.9-1.0; G4b's 35-39 ms at 21.4 blocks/s is
0.8. Once a burst pushes the backlog past ~8 notifications it never drains: the per-block cost then rises (lock wait 7 -> 12-18 ms,
remove hold 10-12 -> 20-26 ms), the lag grows ~8 blocks/s until the 256-deep canonical channel overflows, and from then on
notifications are dropped (`queue pruning fell behind ... skipped`). A held own block is settled only by the pruner reaching its
height (`settle_own_block` from `prune_block`), so with the pruner 16+ blocks behind every hold evicts the oldest one; with
`N42_OWN_HOLD_BLOCKS=128` (Xh1/Xh2) the evictions merely start later (`number=1663 holding=1791`) and `start_handoff_ms` is worse
(mean 21-23 ms against 11-12); with `N42_QUEUE_PRUNE_THREAD=1` (Xpt) the lag moves into the unbounded mpsc channel (no lag WARNs)
and the evictions (1692) and the hand-off wait (11.1 ms mean) are unchanged. That is why neither knob moved it (10.143).

**Why the pruner is slower on ABR legs.** It shares the lanes lock with the inbox drainer, the selector and the hand-off; the
lock's duty is 85-89% per 5 s (window 1) on the non-ABR controls (Fa, Fc, G4a-c) and 92-95% from the flood's first full 5 s on Yc/Yfb/Yfc
(98-99% peaks after the onset). The pruner's first hold drains the inbox (`remove_mined_offlock`, lib.rs:2558, the longest holder
on every leg: 33-45 ms per 5 s, i.e. the pruner pays the ingest's backlog), and its lock wait is serial with its own work. ABR's
legs run faster (ingest delivered 4.47-4.65M/s against 4.25-4.49M/s, 22.4 against 21.4 blocks/s): more drain duty per second and
a shorter per-block budget push utilisation from 0.8 to ~1, after which the onset is a matter of the first burst. ABR's deferred
reverts are not on this path: with `N42_CANON_NOTIFY_LEAN=1` (on in X13/X14) `blocks_to_chain_with` skips `n42_completed_outcome`,
so the notification never waits for the late revert set; the reverts are consumed by `n42_deferred_reverts::register` and
persistence only. G4a (no ABR) entered the same state at 15 s; all six stage-bu legs (X13 and X14) entered it (Ya-Yfc 1498-1940
evictions), and Yc still read 399.0M, so the onset costs ~1 ms of mean gap, not the windows.

**How the onset reaches the seal:** the next build's selector waits for the parent's hand-off task (`handed.recv()`, payload.rs
~l.486 -> `start_handoff_ms`), and that task ends with `queue.hold_own_block(..)` before `done.send(())` (payload_serve.rs
~l.1267). After the onset every hold evicts: 200,000 `inner.dropped(HeldEvicted, ..)` calls under the lanes lock, then a
200,000-`Arc` free (lib.rs ~l.2685-2711) -- on the path the build is blocked on. Not timed yet; the +9-10 ms p50 matches it.

## Q3. Candidates to a 40 ms mean gap (from 45.6-46.2)

The gap is now the build cycle on ~60% of blocks (sealed_at 41.5-41.9 + 3 ms); the vote side is at ~39 ms. A 40 ms mean needs the
seal cycle at ~36-37 ms mean and L <= ~165 ms.

| rank | change | kind | mechanism | evidence | expected |
| --- | --- | --- | --- | --- | --- |
| 1 | Send the hand-off's `done` before `hold_own_block`, or move the eviction's per-tx `dropped` accounting to one counter add and its free to the queue's freeing thread | small code (~10 lines; add `hold_evict_us` to the hand-off line first) | the selector stops waiting on a 200k-entry eviction | start_handoff p50 1-2 (G4b, pre-onset) -> 10-12 post-onset on every ABR leg; Xh1/Xh2 worse with a deeper hold | sealed_at -8..-10 -> seal cycle ~37; mean gap **-3..-4** (seal-bound share falls back toward 40-50%) |
| 2 | Keep the pruner at utilisation < 0.8: no inbox drain inside its first hold, and fold all waiting notifications into one `highest` map and one removal per wake (Xpt's thread already batches the wake but prunes each block) | small code | removes the absorbing state and its knock-ons: lock duty 95 -> ~88%, forget (`queue_prune_ms` in the hand-off 1/2.9 -> 4/6.5) and select waits | prune per block 35-39 (no onset) vs 40-46 (onset) vs 50-78 (after); 135-388 notifications dropped (by-hash entries of those blocks are never pruned) | no onset: hand-off -3, select -1; mean gap **-1..-2** on top of 1 (alone -3..-4, it also removes 1's trigger) |
| 3 | `N42_ANSWER_AT_INSERT=1` on X14 | knob (exists) | answer at the hand-off insert; canonical -> answer (26-27 ms, +4-5 over G4b) leaves L | vote-bound gaps 50-52 ms mean on 36-41% of blocks; corr(gap, L(N-4)) still 0.3-0.4 | L -20 -> vote side ~34 ms; mean gap **-1..-2** once 1 has lowered the seal pace (alone ~0: the seal binds) |
| 4 | Split the lanes lock (inbox hand-over without the lanes lock, or per-shard lanes) | design | the lock is 92-99% busy; every queue step on the seal path (select, forget, hold, prune) queues on it | duty 92-99% vs 85-89%; lock wait 7.5-10.4 s per 5 s; holder 2558/3389 33-54 ms | select/forget/hand-off -2..-4 ms; gap **-1..-2**; also the headroom for 5M |

1 + 2 restore the G4b-like seal (sealed_at ~31-34, seal cycle ~35-37) at X14's L (166-168), which puts the mean at ~41-42 ms;
3 on top takes the vote side below the seal and the mean to ~39-40 (4.9-5.0M TPS at 200k-tx blocks). Run 1 first: it is the
smallest, it is measurable on its own (`start_handoff_ms` back to 1-2 ms p50 after the onset), and it does not depend on the onset
being prevented.
