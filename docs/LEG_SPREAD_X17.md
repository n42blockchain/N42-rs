# Why identical X17 legs spread 4.41-4.70M/s

Read-only analysis of loop351 stage cg's two X17 controls `bench-loop351D2S12P30T64X11T16Wa` (4.410M/s) and `...Wb`
(4.696M/s), same tree, one hour apart (BREAKTHROUGH_DESIGN 10.156), against the earlier controls Ta/Tb (cd), Ua/Ub (ce),
Va/Vb (cf), and Ura/Urb (ce, the first X17 legs). Note: per 10.153/10.154 Ta, Tb, Ua, Ub are **X16** controls (X17 minus
the build-ahead and root cuts); Va, Vb, Wa, Wb, Ura, Urb are X17. Inputs: node0-el.log `seal-first build phases` and
`Block added to canonical chain` lines, validator WARNs, round.txt memory headers, the launch.out summaries. T0 = first full
canonical block; windows = T0 + [0,30), [30,60), [60,90). Scripts kept outside the repo (`/tmp/lsx17`: `p.py` parse,
`a.py` per-window/5 s decomposition, `f.py`/`s.py` fault series and leg table).

## 1. The answer in one line

**Wa lost to a page-cache refault storm, not to the chain.** From T0+60 s the execution layer took 9k, 86k, 130k, 159k,
92k, 42k major faults per 5 s (root_majflt + batch_majflt: the root and the execution batches faulting state pages back
from disk); every critical phase inflated together and window 3 fell to 4.14M/s. Wb had 7 major faults in its worst build.
The same storm is in every slow X17-or-X16 control (Ua, Va, Wa, Ura) and in none of the fast ones.
No hold-bound state (`still held` / held_warns = 0 on every leg), no pruner lag, no in-window view timeout, no slow
follower, no flood hiccup (queue at the builds 2.3-2.4M and 100% full blocks throughout), no foreign claim (gov5's
35zzzcl ended 20:26, the claim was taken 20:30; swap-in 0.1-0.3 pages/s all day).

## 2. Wa against Wb, per window (means over canonical blocks; ms)

| window | leg | blocks | M/s | gap mean | gap p90 | gaps >80 ms (n / s) | sealed_at mean / p90 | start delay | par | roots | parent_fields | seal_to_fields | majflt (k) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| w1 | Wa | 686 | 4.573 | 43.8 | 73 | 49 / 5.07 | 34.5 / 53 | 8.9 | 38.7 | 36.0 | 2.8 | 64.6 | 0.0 |
| w1 | Wb | 710 | 4.733 | 42.3 | 72 | 51 / 4.73 | 33.5 / 48 | 8.4 | 38.9 | 36.9 | 3.1 | 66.2 | 0.0 |
| w2 | Wa | 684 | 4.560 | 43.8 | 74 | 47 / 4.74 | 34.9 / 51 | 8.5 | 38.9 | 36.8 | 3.3 | 65.7 | 0.0 |
| w2 | Wb | 695 | 4.633 | 43.2 | 76 | 61 / 5.97 | 33.5 / 48 | 9.2 | 38.6 | 36.5 | 3.4 | 65.7 | 0.0 |
| w3 | Wa | 621 | **4.140** | **48.3** | **93** | **98 / 10.43** | **41.4 / 73** | 6.5 | **46.2** | **42.8** | **9.9** | **79.2** | **510** |
| w3 | Wb | 701 | 4.673 | 42.8 | 73 | 42 / 4.13 | 34.6 / 50 | 7.7 | 37.8 | 36.5 | 3.0 | 65.1 | 0.0 |

(start delay = prev_seal_to_start; "majflt" is root + batch over the window.) The 23.2M-transaction round gap (398.0 vs
421.2M) is 115 blocks: **80 in window 3** (the storm) and 35 spread over windows 1-2 (Wa 4.567M/s before the storm against
Wb's 4.683, -2.5%, inside the 4% window-1 noise of one configuration). In window 3 the loss is sealed_at (+6.8 ms mean,
+23 p90: par +8.4 with par_exec p90 39 vs 22, the gated root +6.3, the parent's fields +6.9) and twice the long gaps
(10.4 s against 4.1 s of gaps over 80 ms); the start delay did not grow (6.5 vs 7.7). It is a CPU-side slowdown of
everything that touches state pages: the merge (memory-only, 57-60 ms) is the one phase that did not slow.

## 3. The gap per 5 s (Wa / Wb blocks; Wa's sealed_at mean, parent_fields, majflt)

| T0+ s | 0 | 5 | 10 | 15 | 20 | 25 | 30 | 35 | 40 | 45 | 50 | 55 | **60** | 65 | 70 | 75 | 80 | 85 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Wa blocks | 110 | 112 | 117 | 110 | 117 | 120 | 112 | 118 | 115 | 113 | 113 | 113 | 110 | 107 | 96 | 96 | 100 | 112 |
| Wb blocks | 117 | 120 | 120 | 119 | 117 | 117 | 117 | 118 | 115 | 110 | 113 | 122 | 117 | 116 | 114 | 120 | 120 | 114 |
| Wa sealed_at | 37.7 | 33.6 | 33.2 | 36.8 | 34.7 | 31.4 | 35.8 | 33.9 | 35.7 | 34.9 | 34.2 | 34.6 | 35.9 | 41.1 | 44.2 | 47.2 | 43.7 | 37.8 |
| Wa parent_fields | 0.7 | 2.4 | 1.1 | 7.2 | 3.3 | 2.4 | 4.9 | 4.1 | 2.1 | 2.6 | 4.8 | 1.2 | 2.8 | 7.8 | 12.6 | 15.5 | 14.9 | 7.5 |
| Wa majflt (k) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 9 | 86 | 130 | 159 | 92 | 42 |

**Wa diverges at T0+60-65 s**, the bucket the faults start; it recovers partly by T0+85 as the fault rate falls. Before
that the two legs differ only at T0+0-5 and T0+15-20 (Wa's 10 `Sidechain block not found in TreeState` WARNs, the stage
table's "10 warnings", are at T0+1 and T0+8, one forkchoice episode; Wb has none). Wa's view-1 TC (tc=7, "engine service
loop: a slow branch or a long idle") is at T0-28 s, in the decay, and only shifts views to number + 1.

## 4. The eight controls (plus the two first X17 legs)

| leg | set | drain | w1 | w2 | w3 | majflt (k) | storm onset | M/s before / after onset | hugeprep pool before (GB) | order9 at start | load at start | first leg after WARM |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Ta | X16 | 4.463 | 4.507 | 4.440 | 4.433 | 0 | -- | 4.460 / -- | 27 | 11238 | 7.07 | yes |
| Tb | X16 | 4.537 | 4.620 | 4.567 | 4.393 | 0 | -- | 4.527 / -- | 33 | 10151 | 6.74 | |
| Ua | X16 | **4.335** | 4.420 | 4.380 | 4.247 | **311** | T0+80 | 4.400 / 3.94 | 36 | 10258 | 7.19 | yes |
| Ub | X16 | 4.502 | 4.567 | 4.440 | 4.467 | 0 | -- | 4.491 / -- | 44 | 10471 | 7.42 | |
| Va | X17 | **4.341** | 4.440 | 4.500 | 4.153 | **462** | T0+75 | 4.469 / 3.84 | 28 | 10262 | 5.28 | yes |
| Vb | X17 | 4.598 | 4.720 | 4.440 | 4.593 | 0 | -- | 4.584 / -- | 35 | 9899 | 5.69 | |
| Wa | X17 | **4.410** | 4.573 | 4.560 | 4.140 | **806** | T0+60 | 4.567 / 4.14 | 34 | 9366 | 5.87 | yes |
| Wb | X17 | 4.696 | 4.733 | 4.633 | 4.673 | 0 | -- | 4.680 / -- | 44 | 11553 | 3.82 | |
| Ura | X17 | 4.486 | 4.600 | 4.533 | 4.280 | 445 | T0+65 | 4.557 / 4.25 | 37 | 9780 | 5.18 | |
| Urb | X17 | 4.697 | 4.713 | 4.713 | 4.607 | 191 | T0+80 | 4.718 / 4.36 | 49 | 10789 | 6.62 | |

Correlation with the drain rate over the eight controls: major faults **-0.65** (the three storm legs are the three lowest:
mean 4.362 against 4.559 for the five clean ones), first window +0.94 (it is a third of the score), w3/w1 +0.57 (the
storm's footprint), hugeprep pool before +0.55 and order9 at start +0.45 (no storm above order9 10,300, but Tb and Vb ran
clean below it), start load -0.49 (carried by Wb's 3.82; Ub at 7.42 was clean), EL warnings -0.12, tc -0.24, MemFree -0.22.
Over the stages' 24 legs (variants included) a storm of more than 30k faults hit **3 of the 4 first legs after the WARM
leg** (Ua, Va, Wa; WARM replays the 400M set, the scored legs the 91 GB 600M set) and 6 of the 20 later legs (Tha, Ura, Urb,
Uab, Vmb, Wpa); a storm costs 0.02-0.16M/s of drain against the leg's own pre-onset rate (Wa 0.16, Va 0.13, Ura 0.07, Ua 0.07, Urb 0.02), more the earlier and larger.

Mechanism (consistent with the THP heap-reclaim storms of round 43): the box has 136 GB; at the flood's 60-80 s mark the
EL heap (peak RSS 50-54 GB), Shmem (28 -> 35 GB over the day: the /tmp tmpfs) and the page cache of the replay files the
flood streams (~0.65 GB/s, use-once, 61 GB per leg) exhaust the free pages, kswapd reclaims, and it takes the EL's hot
state-file pages with the cold replay pages; the root and the execution batches then fault them back. A leg that starts
with the 600M set's head already cached (a later leg) streams less new cache and usually escapes.

## 5. Causes of the spread, ranked, and the smallest action for each

| rank | cause | share of the 4.41-4.70 spread | smallest action |
| --- | --- | --- | --- |
| 1 | refault storm in windows 2-3 (Ua, Va, Wa, Ura) | 0.07-0.16M/s on a storm leg; 3 of 8 controls | bench: score a leg only if windows' root_majflt + batch_majflt < 10k (print it on the leg line; rerun otherwise); stream the replay files with `posix_fadvise(DONTNEED)` behind the reader in tx_flood (use-once pages leave the cache, ~61 GB less pressure); clear stale tmpfs (Shmem 35 GB) before the stage |
| 2 | the first leg after WARM is cold for the 600M set | 3 of 4 first legs stormed | bench: WARM on the 600M set, or put a variant (not a control) first |
| 3 | residual noise of a clean leg (4.47-4.72 pre-storm/clean X17) | ~0.10M/s, window-1 noise 4% | none cheap; pair legs adjacently and keep the 2-pair rule |
| 4 | start-up episodes (view-1 TC, Sidechain-not-found at T0+8 s) | <0.02M/s | none needed (outside the windows or one bucket) |
| -- | hold bound, pruner, followers, flood, foreign load | 0 on these legs | -- |

The degraded/hold-bound state of DEGRADED_ONSET_ANALYSIS did not occur on any of these legs; the pruner ran 80-92% busy on
clean and storm legs alike (Wb w3 92%, Wa w3 62% because blocks slowed).

## 6. What a Wb-every-time X17 reads, and what 5.0 needs

Clean X17 legs read 4.598 (Vb), 4.696 (Wb), 4.697 (Urb, storm only at T0+80); the storm legs' pre-onset rates are
4.469 / 4.557 / 4.567. **A storm-free X17 reads ~4.60-4.70, mean ~4.65M/s**: removing the storm alone moves the stage mean
from ~4.55 to ~4.65 and halves the spread, but does not by itself give "every leg 4.70".
5.0M/s is 25 blocks/s, a 40.0 ms mean gap against Wb's 42.3-43.2: **-2.5..-3 ms of mean gap on a storm-free leg**. Two
places hold it: the long-gap tail (Wb: 42-61 gaps over 80 ms per window, 4.1-6.0 s of every 30 s; at the 39 ms median
they would cost ~2 s, worth +7-10%) and the AFTER_MERGE_CUT levers (merge off the critical cores, child on N-1's output,
the fields path: -2..-3 ms each, ~-5 together). Either one at about half its estimate on storm-free legs reaches 5.0.
