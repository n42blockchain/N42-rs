# The long-gap tail on storm-free X17 legs

Read-only analysis of loop351 stage ch (BREAKTHROUGH_DESIGN 10.157): the control `bench-loop351D2S12P30T64X11T16Xb`
(4.660M/s), the control `...Xa` (4.640) and `...Xea` (`N42_CHILD_ON_OUTPUT=1 N42_ROOT_LOOKUPS_EARLY=1`, 4.693, interval p90
39.6). Zero major faults in every batch. Window = proposals T0 .. T0+88 s (2,000-2,057 a leg). T0 is the **last**
`first full block at epoch` line of round.txt (each round.txt of this stage carries two; the first one is stale, so a
script that takes the first match reads the wrong window). Per proposal N: the bound (seal N, commit N-1, prop N-1 + 30 ms),
the EL's `seal-first build phases`, handed / canonical / answer times, all seven validators' votes, QC, commit, imports,
`vote log sync was slow`, and the EL's `forest lock waited|held`, pruner (`prune_ms`) and checkpoint lines.
Scripts are kept outside the repo (`/tmp/ltail`: `tail.py` classify, `dec.py` decompose, `ready.py`, `fx.py`, `ex.py`,
`sim4.py`, a replay built on the vbg/bar `sim3.py` model with the AT_SEAL start gate).

## 1. The answer in brief

* **The tail is smaller than the 4-6 s quoted from Wb**: gaps over 80 ms take **2.2-3.8 s of each 30 s window** here.
  Xb has 94 (8.6 s of 88 s), Xa 107 (9.9 s) and Xea 92 (8.4 s). Their gross excess over 40 ms is 2.4-2.8 ms of mean gap.
  Each one is followed by a 31-33 ms catch-up gap (81-92% of them tick-bound), so cutting one is worth less than its excess.
* **96-98% of them are vote-bound** (Xb 90 of 94). The proposal waits for commit(N-1), whose 4th follower vote waits for
  the EL's answer for N-4. The long gap *is* the answer gap of N-4 (mean 94-96 ms, against 43 overall). That answer gap
  is **the seal gap of N-4 (55 ms mean) plus a jump in L of N-4 (+40 ms)**: two ordinary deviations of about one sigma
  each, stacked. No single discrete event causes it.
* **No discrete event shows up as a cause.** There is no TC in the window (all 31 timeouts are at view 1) and no held-block
  or hold-bound warning. One or two tenure handovers come at 1024 views, ~110 ms each. Faults stay low (majflt > 0 in 1-9
  long gaps, a handful of pages). Checkpoint compactions are not enriched (1.2-1.5/s in long gaps, 1.5/s overall). Pruner
  `prune_ms` >= 50 is 1.15x enriched and forest-lock waits 1.1-1.5x, both weak.
* **The vote-log sync is a passenger.** It releases the 4th vote in 34-39 long gaps, but it adds only ~6 ms (sync 5-6 ms)
  to a gap that is already ~85 ms. Removing it is worth -0.1 ms in the replay.
* **The two largest tail causes are the L tail (root, merge and the answer path) and the build's exec straggler**: -1.4..-1.65
  and -1.1..-1.3 ms of mean gap in the replay. The amplifier is the 6-block loop (one-ahead gate + 4-block vote window).
  Relaxing it (two-ahead or the five-block window) is worth -3.3..-3.7, more than removing every tail.

## 2. Per leg, inside the window (ms)

| leg | proposals | gap mean / p50 / p90 | bound seal / vote / tick | gaps >80: w1 / w2 / w3 (s) | total | gap after a long one |
| --- | --- | --- | --- | --- | --- | --- |
| Xb | 2,057 | 42.77 / 35.8 / 68.0 | 67 / 930 / 1,060 | 37 / 32 / 25 (3.38 / 3.02 / 2.21) | 94, 8.60 s | 33.4 (84% tick-bound) |
| Xa | 2,017 | 43.08 / 36.2 / 69.1 | 71 / 933 / 1,013 | 31 / 35 / 41 (2.91 / 3.21 / 3.80) | 107, 9.92 s | 32.7 (81%) |
| Xea | 2,000 | 42.72 / 35.2 / 68.0 | 77 / 875 / 1,048 | 31 / 34 / 27 (2.90 / 3.10 / 2.43) | 92, 8.43 s | 32.5 (92%) |

On the vote-bound long gaps (Xb, n = 90), the follower import comes 0.1 ms after the EL answer and the vote 0.9 ms after
the import (p50; 1.2 mean, against 4.0 mean on all blocks). Commit -> proposal is 4.0 ms p50. Gaps of the answer of N-4:
94-96 mean against 43 overall. Seal gap of N-4: 54-55 p50. L jump of N-4: +36..+42 p50. L itself is 187-190 p50, 214-219 p90.

## 3. Cause classes (primary cause = the largest of seal-gap excess, L jump and release jump of the gap's N-4)

| class | Xb n / total ms / mean excess >40 | Xa | Xea | ms of mean gap if gap -> 40 (Xb / Xa / Xea) |
| --- | --- | --- | --- | --- |
| L jump: seal -> state ready (root, fields after root, merge) | 39 / 3,547 / 50.9 | 42 / 3,921 / 53.3 | 35 / 3,259 / 53.1 | 0.97 / 1.11 / 0.93 |
| L jump: canonical -> answer (newPayload answer) | 11 / 1,005 / 51.4 | 20 / 1,881 / 54.0 | 13 / 1,155 / 48.8 | 0.27 / 0.54 / 0.32 |
| L jump: state ready -> handed | 5 / 513 / 62.5 | 7 / 635 / 50.7 | 10 / 915 / 51.5 | 0.15 / 0.18 / 0.26 |
| L jump: handed -> canonical | 4 / 368 / 52.0 | 8 / 757 / 54.6 | 3 / 268 / 49.2 | 0.10 / 0.22 / 0.07 |
| seal gap of N-4: one-ahead start gate | 13 / 1,136 / 47.4 | 13 / 1,146 / 48.1 | 10 / 902 / 50.2 | 0.30 / 0.31 / 0.25 |
| seal gap of N-4: par_exec tail | 12 / 1,107 / 52.2 | 9 / 810 / 50.0 | 10 / 904 / 50.4 | 0.30 / 0.22 / 0.25 |
| seal gap of N-4: fields wait | 1 / 82 / 42.1 | 0 | 1 / 87 / 46.8 | 0.02 / 0 / 0.02 |
| release chain (vote-log sync, QC, commit, slack) | 5 / 446 / 49.2 | 6 / 567 / 54.5 | 8 / 739 / 52.3 | 0.12 / 0.16 / 0.21 |
| seal-bound: own build slow (par_exec, fields) | 2 / 186 / 53.2 | 1 / 83 / 42.6 | 1 / 97 / 57.3 | 0.05 / 0.02 / 0.03 |
| tenure handover (1024 views) | 2 / 215 / 67.6 | 1 / 119 / 78.7 | 1 / 105 / 65.4 | 0.07 / 0.04 / 0.03 |
| view change (TC), pruner / held-block eviction, host faults | 0 | 0 | 0 | 0 |

The excess summed over all long gaps, by component (ms of mean gap, Xb / Xa / Xea), runs from largest to smallest.
L seal -> ready is +1.07 / 1.24 / 1.06. The seal start gate is +0.64 / 0.74 / 0.61. L canonical -> answer is +0.53 / 0.77 / 0.53.
The seal exec tail is +0.46 / 0.54 / 0.54. L ready -> handed is +0.21 / 0.13 / 0.14. The rest is small or negative (the
release chain runs -0.13..-0.22: QC and commit are faster on these gaps). Inside the state-ready jumps of 20 ms or more
(Xb 51), the largest piece is the root 24 times, fields-after-root 12 times, the merge 11 times and the root wait 4 times.
On Xea it is the merge 24 times and the root 16 times.
Blocks sealed above the `sealed_at` p90 (50 ms, Xb 188) against all: par_exec 34 / 18, batch_max 30 / 12.5, batch start skew
19.6 / 10.3, involuntary switches 13.8 / 5.5, majflt 0: a straggler batch started late and preempted (CPU contention, not memory).

## 4. Clustered or scattered?

They are **scattered in time, but echo at 6-7 blocks.** Long gaps per 5 s run 1-13 with no trend. The block number mod 200
(epoch), mod 4, and handovers (1-2 per leg) show nothing. Two long gaps never come back to back, because the catch-up
follows. Distances between successive long gaps:

| distance (blocks) | 1 | 2 | 3 | 4 | 5 | **6** | **7** | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Xb | 0 | 2 | 1 | 2 | 1 | **11** | **9** | 2 | 1 | 2 | 2 | 3 | 3 | 0 | 5 |
| Xa | 0 | 2 | 1 | 1 | 2 | **12** | **10** | 3 | 6 | 6 | 3 | 2 | 5 | 8 | 1 |
| Xea | 0 | 0 | 1 | 1 | 1 | **12** | **6** | 5 | 5 | 3 | 3 | 3 | 7 | 2 | 1 |

18-22 of 91-106 pairs sit at distance 6-7, against ~8 expected for scattered gaps at a 5% rate. This is the closed loop
`start(N) >= prop(N-2)`, `prop(N) >= answer(N-4)`. A late answer delays a proposal, the proposal gates a start two blocks
later, and that block's seal feeds the answer four blocks later. One tail event costs twice.

## 5. What removing each cause would buy (replay, AT_SEAL gate; the base reads 1.4 / 1.5 / 2.6 ms under the real gap, so deltas only)

| removed (values above p90 replaced by p50; "cap p50" in brackets) | Xb | Xa | Xea |
| --- | --- | --- | --- |
| build: `sealed_at` tail (exec straggler, fields, hand-off) | **-1.32** (-1.84) | **-1.12** (-1.63) | **-1.28** (-1.93) |
| L: root end -> answer (merge, hand-off, canonical, answer) | -0.82 (-1.65) | -0.64 (-1.77) | -0.76 (-1.81) |
| L: root duration | -0.47 (-1.01) | -0.63 (-1.25) | -0.35 (-0.68) |
| **L: all parts (root ready, root, fields, root end -> answer)** | **-1.65** (-3.34) | **-1.57** (-3.64) | **-1.41** (-2.98) |
| proposal slack / vote -> commit / vote-log sync / fields after root | -0.37 / -0.11 / -0.09 / -0.06 | -0.38 / -0.14 / -0.07 / -0.07 | -0.36 / -0.26 / -0.12 / -0.02 |
| every tail together | -3.87 | -3.56 | -3.54 |
| structural: two-ahead start / five-block window / no start gate / tick 25 | -3.27 / -3.48 / -4.93 / -0.26 | -3.41 / -3.55 / -5.19 / -0.25 | -3.41 / -3.65 / -6.28 / -0.37 |

The replay assumes the tail would not reappear elsewhere. `sealed_at` is elastic (10.116) and three floors sit within 3 ms
(AFTER_MERGE_CUT), so read these as upper bounds. 40.0 from 42.7 needs -2.7 ms. The top two tails together reach
-2.5..-3.0 only if they are removed completely. The structural levers reach it alone.

**Top two, mechanism and smallest change:**
1. **The L tail (-1.4..-1.65).** Seal -> state ready jumps by 20-80 ms when the leased root computes long, or when the merge
   runs long beside it (the root and merge share the critical cores, as 10.155 found). The answer path adds forest-lock waits:
   `on_canonical` / `on_canonical#2` wait behind `tree_lease` 431 times in Xb's window (12.5 s summed), and a block with
   a wait of 20 ms or more answers 5-6 ms later (canonical -> answer 35.8 against 30.5).
   Existing knob first: **`N42_QMDB_CANONICAL_DEFER=1`** (the head advances without waiting for the lease). It was neutral
   at stage ad, where it "engaged rarely", but X17's waits are a different regime: re-measure it on X17 with the
   `on_canonical` wait count as the mechanism check. Stack it with `N42_ROOT_LOOKUPS_EARLY=1`, which already cut these waits
   (section 6).
2. **The build's exec straggler (-1.1..-1.3).** One batch of 20 starts ~10 ms late and runs 30 ms (preempted 2.5x more
   often), so par_exec doubles. `N42_BUILD_WORK_STEALING=1` was neutral on X16 (stage cc), and no tested knob moves it.
   The smallest change is to keep the merge and the next root off the build's cores while a build runs, or to shrink the
   last batch (`N42_BUILD_BATCHES`). Both are untested.
3. **Above both, cut the echo**: `N42_BUILD_AHEAD_GATE=seal` (two-ahead; the orphan path was fixed in 4ce0981bc) or the
   five-block window (`N42_FAR_AHEAD_BLOCKS=2 N42_PARENT_OUTPUTS_KEPT=6 N42_OWN_HOLD_BLOCKS=64`; 3 of 4 legs collapsed on
   the hold bound and a fix is in progress) each take -3.3..-3.7. `N42_PLAN_AHEAD_WAIT_MS`, `N42_BUILD_THROTTLE_*` and
   `F7_LEADER_TENURE` act on nothing in this tail: there are no plan waits, no throttle holds, and handovers are 0.03-0.07 ms.

## 6. Why Xea's p90 (39.6) beat Xb's (45.2)

**It did not, inside the window.** The 39.6 / 45.2 figures are the validators' proposal interval over all proposals of the
leg: 8,431 on Xea against 6,936 on Xb. Xea logged ~1,300 more tick-paced 31.8 ms intervals after the window, and they
pull the leg-wide p90 down. Inside the window they match: proposal p90 68.0 / 68.0, canonical-interval p90 69.5 / 68.4,
mean gap 42.77 / 42.72, gaps over 80 ms 94 / 92 (Xb / Xea). The stage table's interval p90 is not a tail metric; score the
tail with in-window gaps over 80 ms. What the early lookups did remove is real but small: `on_canonical*` waits behind the
lease 431 -> 274 (12.5 -> 7.4 s summed), gaps holding a forest wait >= 20 ms 38% -> 26%, the root 25.0 -> 21.0 ms p50 but its
wait 25.4 -> 31.9, and the state-ready jumps moved to the merge (24 of 52 against 11 of 51).

That is the hint: a cut inside L moves the jitter to the next stage of the same chain, and the tail stays. The tail falls
only when the chain's jitter is cut as a whole (section 5, "all L parts") or when the 6-block loop stops doubling it.
