# Why building ahead gained little on X16

Read-only analysis of loop351 stage cd (BREAKTHROUGH_DESIGN 10.152), 600M set, 30 ms pacing, drain-rate scored:
controls `bench-loop351D2S12P30T64X11T16T{a,b}` (4.463 / 4.537M/s), `N42_BUILD_AHEAD_AT_SEAL=1` `...Th{a,b}` (4.537 /
4.576), two ahead (`N42_BUILD_AHEAD_GATE=seal` + AT_SEAL + `N42_BUILT_KEEP=5 N42_OWN_HOLD_BLOCKS=32`) `...Tt{a,b}` (Tta
4.559, tc=7; Ttb stopped by BODYGATE, see section 6). Window T0 .. T0+88 s, joins as in docs/BUILD_AHEAD_AND_VOTE_PACE.md
(`parse.py`, `ana.py`, `sd.py`, `cls.py`, `L.py`) plus `ph.py` / `ser.py` / `cl2.py` (phase means, the serial root and the
fields gate, start classes); scripts kept outside the repo. Means unless marked p50.

## 1. The answer in brief

* **The mechanisms worked; the gap did not move.** AT_SEAL kept every held start (gated-after-prop(N-1) 16% -> 1 build) and
  two-ahead started 45% of builds before prop(N-2). The start delay fell 10.3 -> 6.4 -> 2.3 ms, `sealed_at` rose
  34.5 -> 37.7 -> 41.6, and the mean gap stayed 44.8 / 44.1 / 43.9.
* **The answer is anchored to the proposal, not to the seal.** prop -> answer A = 153.4 / 156.8 / 155.7 ms on Ta / Tha / Tta,
  while the seal's lead over the proposal grew 28.0 -> 35.2 -> 42.3. L = seal -> answer grew by the same amount
  (181.5 -> 192.0 -> 197.9): the earlier seal waits in the serial QMDB root's queue. The old model held L constant, and that
  is where the predicted -3..-5 ms (+8-12%) went.
* **The binding resource is the serial root.** It waits on the previous root for 81% -> 89% of blocks (idle p50 2 ms), and
  its busy share of the gap went 0.81 -> 0.89. Building ahead removed the root's starvation idle (8.4 -> 4.7 ms) and
  slowed the root by CPU contention (36.5 -> 39.2 ms): net -0.9 ms, which is the +1..+2.5% the legs read.
* **The tick does not bind the mean**: 44-45% of proposals are tick-bound but they are 31.5 ms catch-up gaps after
  vote-bound ones, and the vote is anchored on the answer of N-4. A 25 ms pacer is worth ~0 ms now.
* **Next lever: the root cuts on AT_SEAL** (`N42_ROOT_UPPER_DIRTY=1 N42_ROOT_OPS_BEFORE_GATE=1`, -10.6 ms of root on Sra),
  expected -2..-3.5 ms of gap (+5..8%), then shortening the 120 ms after the root (merge, answer).

## 2. Mean gap = sealed_at + start delay, and the start delay's classes

| leg | gap | sealed_at | start delay | at parent seal (< 4 ms): share, mean-share | gated at prop(N-1): share, p50/mean, mean-share | kept at prop(N-2): share, p50/mean, mean-share | other | before prop(N-2) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Ta | 44.8 | 34.5 | 10.3 | 83%, 1.51 | 16%, 50.0/52.6, **8.22** | -- | 1%, 0.58 | 0% |
| Tb | 44.2 | 35.1 | 9.1 | 85%, 1.49 | 14%, 47.5/50.1, **6.94** | -- | 1%, 0.69 | 0% |
| Tha | 44.1 | 37.7 | 6.4 | 69%, 1.19 | 1 build | 27%, 12.9/14.9, **4.09** | 4%, 1.12 | 0% |
| Thb | 43.7 | 37.4 | 6.3 | 68%, 1.17 | 0 | 27%, 11.9/13.9, **3.78** | 4%, 1.32 | 0% |
| Tta | 43.9 | 41.6 | 2.3 | 98%, 1.81 | 0 | 0 | 2%, 0.48 | **45%** |

Question 1: the held starts were kept (548 / 547 builds start ~1 ms after prop(N-2), `build_start_trigger` send 661 / 688).
The kept start waits for almost nothing: state_wait 1.0, plan_wait 0, parent_fields p50 0 (mean 6.5); it seals in 33.3 ms
(the Ta gated build, which started 50 ms late with everything ready, sealed in 23.5). The predicted 7 ms became 3.0-3.9 ms
of start delay (the one-ahead rule still waits for prop(N-2), 12.9 ms), and the seal took back 2.3-3.2 of it:
builds started at the parent's seal now take 39.7 instead of 36.6, mostly the parent-fields wait.

## 3. What the seal spent (question 2; means, ms)

| phase | Ta | Tha | Tta | Tta started before prop(N-2) / the rest |
| --- | --- | --- | --- | --- |
| sealed_at | 34.5 | 37.7 | **41.6** | 43.4 / 40.2 |
| par_start (start_best + hand-off) | 3.2 | 3.0 | 4.1 | 4.8 / 3.5 |
| state_wait | 3.7 | 3.5 | 4.9 | 5.5 / 4.5 |
| gap_before_exec | 3.9 | 3.5 | 4.9 | 5.6 / 4.5 |
| par_run (par_exec) | 21.9 (17.8) | 22.3 (18.5) | 24.3 (19.0) | 25.1 / 23.6 |
| sealed_ms (exec end -> sealed) | 7.7 | 11.0 | 11.8 | 12.0 / 11.7 |
| of it parent_fields wait (N-2's fields) | 4.8 (45% wait > 1 ms) | 7.9 (61%) | **8.5 (66%)** | 7.9 / 9.2 |
| plan_wait / plan_body_wait | 0.13 / 0 | 0.07 / 0 | 0.05 / 0 | |
| root_compute (the root, same cores) | 31.7 | 34.4 | 35.2 | |
| batch open thread-time sum | 51.1 | 54.0 | 57.5 | |
| lanes lock duty w1/w2/w3 | 84/78/82% | 86/81/79% | 86/85/81% | |

The +7.1 ms on Tta is +3.7 the fields gate (seal(N) >= fields(N-2): seal(N) - seal(N-2) is 87.8-89.6 on every leg, the
root chain seen from the seal) and +3.4 contention (start, state wait, gap before exec, par_run +1..+1.6 each, worst on the
builds running beside a second one). Not the plan (0), not the lanes lock (duty unchanged within noise).

## 4. The vote pace and L (question 3; p50 / mean, ms)

| quantity | Ta | Tha | Tta |
| --- | --- | --- | --- |
| proposals bound by seal / vote / tick (count) | 10 / 40 / 49% | 5 / 51 / 44% | 4 / 51 / 45% |
| same, time share | 11 / 54 / 35% | 6 / 63 / 31% | 5 / 62 / 33% |
| tick-bound gap mean | 31.7 | 31.4 | 32.0 |
| prop(N) -> prepare QC(N) | 20.9 / 28.1 | 28.1 / 30.8 | 27.1 / 30.6 |
| prop(N) -> commit(N) | 24.7 / 32.0 | 31.5 / 34.2 | 31.0 / 34.6 |
| lead = prop(N) - seal(N) | 21.6 / 28.0 | 33.4 / 35.2 | 41.3 / 42.3 |
| **A = prop(N) -> answer(N)** | 154.8 / 153.4 | 156.8 / 156.8 | 155.0 / 155.7 |
| c = prop(N) - answer(N-4), vote-bound | 12.6 / 14.4 | 10.9 / 13.1 | 13.8 / 14.4 |
| (A + c) / 4 | 42.0 | 42.5 | 42.5 |
| prop(N) - prop(N-4) (four gaps) | 179.3 | 176.4 | 175.7 |
| L: seal -> bundle / bundle -> root start (queue) / root | 9.2 / 23.2 / 36.5 | 9.0 / 27.5 / 38.8 | 9.2 / 28.8 / 39.2 |
| L: root end -> state ready (merge 61) / -> handed / -> canonical / -> answer | 63.1 / 15.5 / 5.0 / 29.0 | 63.1 / 17.7 / 5.8 / 30.1 | 64.6 / 20.0 / 6.0 / 30.1 |
| **L = seal -> answer** | 181.5 | 192.0 | 197.9 |
| root idle (start - previous end) p50 / mean; waits on the previous root | 1.9 / 8.4; 81% | 2.0 / 5.3; 87% | 2.0 / 4.7; 89% |
| root busy / gap | 0.81 | 0.88 | 0.89 |

The vote still releases on the followers' import of N-3 (= the shared EL's answer of N-4) and c is unchanged. L absorbed
the lead: +10.5 / +16.4 ms, of which the root queue +4.3 / +5.6, the root +2.3 / +2.7, state ready -> handed +2.2 / +4.5.
Is the pacer binding? No: tick-bound proposals are 44-45% by count but they follow vote-bound gaps (54 ms mean) and the
next vote-bound proposal waits for answer(N-4) whatever the tick did. With `F7_BLOCK_INTERVAL_MS=25` the expected gain is
~0 while (A + c)/4 = 42.5 > 30; lower the pacer only once the gap reads under ~33.

## 5. The corrected model and the next lever (question 4)

    gap >= max( root cycle,  (A + c) / 4,  seal_to_fields / 2 )
    root cycle = root busy + hand-over (~2)                 Ta 38.5, Tta 41.2
    A = (root_end - prop) + T_tail,  T_tail = root end -> answer ~120 (merge 61, hand-off 20, canonical 6, answer 30)

Under building ahead the root runs back to back, so root_end(N) ~ root_end(N-1) + root cycle: an earlier seal only lengthens
the root queue and A stays ~155. The old `(L + c + sealed_at + 1.7) / (5 + k)` assumed L fixed; with the measured L it gives
40.8 (k = 1) and 36.5 (k = 2), still under the measured 44, because the k proposals ahead do not move the answer.
Check at k = 0 with the root cut (stage cc Sra against Sa): root 35.9 -> 25.3, root busy 0.58, A 151.6 -> 144.9, gap
43.6 -> 43.3 -- there the start delay bound, here the root does: the two must be stacked.

| next | expected mean gap | why |
| --- | --- | --- |
| 1. AT_SEAL + root cuts (`N42_ROOT_UPPER_DIRTY=1 N42_ROOT_OPS_BEFORE_GATE=1`), two legs against AT_SEAL | **43.9 -> ~40.5-41.5 (-2..-3.5, +5-8%)** | root cycle 41 -> ~28 stops binding; A -7 (Sra) .. -10 (queue drains) -> (A + c)/4 40.0-40.8 |
| 2. then cut T_tail: answer at insert (canonical -> answer 30 -> ~8) | -5 more (0.25 ms per ms of A) | the 30 ms is the followers' newPayload waiting in the import slot (`slot_wait_ms` 41 on block 1933) |
| 3. the state merge (61 ms, `merge_threads=1`) in two | -7 more if halved | the largest single piece of T_tail |
| floors after 1-3 | ~35 | fields gate seal_to_fields / 2 (~70 / 2 with the root cut); the tick (30 + 1.5 slack) next |
| two-ahead over AT_SEAL | -0.2 measured, +3.2 seal on its builds | not worth its risk until the root and T_tail are cut |

Proof counters for 1: root (start -> end) <= 29, root busy / gap <= 0.7, A <= 148, `sealed_at` <= 36 (the fields gate
eases with the root), lead unchanged, `own_not_committed` 0.

## 6. Correctness on the two-ahead legs

Tta: own_not_committed 0, "still held when the bound" 0, tc 7 (view offset 1, one view timeout), EL refusal 1. Ttb:
**BODYGATE stop**, own_not_committed 1: "an own block at a pruned height was not the one committed ... back=401" at block
1024, the tenure handover in the warm-up (401-transaction builds). The release (`release_own_blocks_from`) fired at 2048
and 3072 ("own blocks held at or above this build's height were replaced", 200,000 each) but not at 1024, so the handover
orphan of BUILD_AHEAD_TWO_AUDIT section 2 is still reachable; Ttb read 4.613 / 4.553 / 4.480 before the stop. Another
reason to put the root cuts on AT_SEAL (k = 1: 0 such lines on Tha / Thb) rather than on two-ahead.
