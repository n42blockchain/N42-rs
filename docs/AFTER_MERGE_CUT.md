# What binds the gap after the merge cut

Read-only analysis of loop351 stage cf on X17 (X16 + `N42_BUILD_AHEAD_AT_SEAL=1 N42_ROOT_UPPER_DIRTY=1
N42_ROOT_OPS_BEFORE_GATE=1`), 600M set, 30 ms pacing: controls `bench-loop351D2S12P30T64X11T16V{a,b}`, `N42_MERGE_PARALLEL=8`
`...Vm{a,b}`, `N42_ANSWER_AT_INSERT=1` `...Vab` (Vaa not parsed). Window T0 .. T0+88 s (~2,000 blocks a leg), node0-el.log
build lines joined with the seven validator logs as in docs/BUILD_AHEAD_RESULTS.md (scripts kept outside the repo). Means
unless marked p50. Inside the window the proposal interval reads p50 36.6-38, mean 43.4-45.6 (whole-leg median 31.8).

## 1. The answer in brief

* **No single resource binds.** The gap is the seal chain (mean gap = start delay + `sealed_at`, an identity: builds start at
  the parent's seal 65-91% of the time) and on every X17 leg it reads 43.4-44.0 ms. Three floors sit at 36-39 ms each --
  the builder through its parent's output, the fields two-cycle, and the one-ahead start-gate loop -- and their jitter
  (p90 of `par_run` 36, of seal -> fields 92) puts the mean ~5-6 ms above the largest. The root cycle (29-32) and the tick
  (30) are below them.
* **The merge cut reached L but not A**: merge 62.5 -> 40.3 ms, L = seal -> answer 188.9 -> 177.8 (-11.1). The eight merge
  threads run on the critical set beside the next root and head: gated root 25.8 -> 29.8, head 18.9 -> 22.2, seal -> bundle
  +1.0, so seal -> fields +8.5 (65.6 -> 74.1). The seal paid it: `sealed_at` +3.7 (fields wait +1.9, parent-output wait +1.2,
  `par_run` +1.1), while the relaxed gate loop cut the start delay 8.0 -> 4.1. Net gap 43.6 -> 43.4; A = L - lead stays 152.
* **The serial root is no longer the floor**: busy 0.59-0.69 of the gap, its gated start waits on its own head 64-74% of
  the time (head end - fields(N-1) p50 4.4-8.6 ms), root cycle 29-32 ms against a 43 ms gap.
* **(A + c)/4 is not a closed cycle**: answers follow the seal (L); proposals reach the seal chain only through the one-ahead
  start (start(N) >= prop(N-2)): 6 gaps >= `sealed_at` + L + c = 38.3 on Vma, 39.6 on Vb.
* **Next**: take the merge off the critical set (keep the -11 of L, return the +8.5 of seal -> fields), then the parent-output
  wait, then the fields path; each alone ~-2..-3 ms, all three together ~-5 to a ~35-36 mean (+10-12%), then the tick, root cycle and `par_run` (23). The tick pays <= 0.5-0.9 ms.

## 2. Per leg: what released each proposal and each seal (window means)

| leg | drain M/s | gap | prop bound by seal / vote / tick (count; time) | start delay | `sealed_at` | seal released last by fields(N-2) / output(N-1) / start gate / own work |
| --- | --- | --- | --- | --- | --- | --- |
| Va control | 4.341 | 45.6 | 10/46/45%; 12/57/31% | 8.5 | 37.2 | 28 / 29 / 23 / 20% |
| Vb control | 4.598 | 43.6 | 6/43/51%; 7/56/38% | 8.0 | 35.6 | 26 / 32 / 26 / 17% |
| Vma merge 8 | 4.619 | 43.4 | 12/41/47%; 14/52/34% | 4.1 | 39.3 | 42 / 34 / 9 / 15% |
| Vmb merge 8 | pending | 44.0 | 12/43/46%; 14/53/33% | 4.6 | 39.4 | 40 / 32 / 11 / 17% |
| Vab answer at insert | 4.618 | 43.5 | 22/36/42%; 27/42/31% | 3.1 | 40.4 | 39 / 30 / 6 / 26% |

Tick-bound proposals are 31.6-32.0 ms catch-up gaps after vote-bound ones (51-57 ms); vote-bound ones wait for commit(N-1),
whose fourth follower vote is released by the follower import of N-4 (= the shared EL's answer, vote4 - ans(N-4) p50 1.0):
c = prop(N) - ans(N-4) = 12.0-14.5. Start-delay classes: at the parent seal (1.7 ms) 65 / 67% on the controls, 82-91% on the
cut legs; gated at prop(N-2) (p50 11-14, mean 15-18) 25-28% -> 8-13%, three quarters of them after a tick-bound proposal.

## 3. The gap decomposed (means, ms)

| piece | Va | Vb | Vma | Vmb | Vab |
| --- | --- | --- | --- | --- | --- |
| start delay (seal(N-1) -> start) | 8.5 | 8.0 | 4.1 | 4.6 | 3.1 |
| pre-exec (start, hand-off, plan) | 3.9 | 3.1 | 2.8 | 3.0 | 4.7 |
| state wait on the parent's output (N-1's bundle; 45% of builds on Vb, 59% on Vma, mean 6.2-6.8 when it waits) | 2.8 | 2.8 | 4.0 | 3.7 | 3.5 |
| `par_run` (execution) | 22.5 | 22.8 | 23.8 | 23.8 | 23.2 |
| exec end -> sealed, excluding the fields wait | 4.1 | 3.6 | 3.4 | 3.6 | 3.1 |
| fields wait (N-2's fields; share > 1 ms) | 3.9 (28%) | 3.4 (26%) | 5.3 (42%) | 5.4 (40%) | 5.8 (39%) |
| **gap** | **45.6** | **43.6** | **43.4** | **44.0** | **43.5** |

Each cut since stage cd moved time from the first row into the waits: an earlier start waits longer for N-1's output and
N-2's fields. The builder's own work (pre-exec + `par_run` + tail) is 29-31 ms.

## 4. L and A: where the 20 ms went (means, ms)

| piece | Vb | Vma | Vab |
| --- | --- | --- | --- |
| seal -> bundle / bundle -> gated root start / gated root | 9.3 / 27.5 / 25.8 | 10.3 / 31.5 / 29.8 | 10.0 / 30.1 / 28.6 |
| root end -> merge start / merge (gather + combine) | 3.1 / 62.6 | 2.7 / 40.7 (16.7 + 23.4) | 3.9 / 68.3 |
| seal -> state ready | 128.8 | 115.4 | 141.3 |
| state ready -> handed / -> canonical / -> answer | 21.0 / 7.0 / 32.1 | 21.5 / 7.5 / 33.5 | 16.6 / 8.1 / 0.8 |
| **L = seal -> answer** | **188.9** | **177.8** | **166.7** |
| lead = prop(N) - seal(N) | 36.8 | 26.1 | 21.4 |
| **A = prop -> answer** (p50) | **152.1** (153.2) | **151.7** (151.6) | **145.3** (144.9) |
| seal -> fields (excluding the gate wait) | 65.6 (62.4) | 74.1 (70.8) | 72.5 (68.2) |
| fields -> answer | 123.3 | 103.7 | 94.2 |

The 20 ms reached the answer side of fields (fields -> answer -19.6); the seal -> fields path grew 8.5 under the merge
threads, and the seal came 10.7 ms closer to its proposal (fields gate, start delay). Answer at insert removes the 30 ms
canonical -> answer (and 4 of hand-off) but the merge grows +5.8 and the seal +4.8 the same way. The EL itself is not the
floor: ans(N) - max(state ready(N), ans(N-1)) = 39 (22 on Vab) with canonical(N) after ans(N-1) on 37-42% of blocks.

## 5. The serial root (means; p50 by window)

| quantity | Va | Vb | Vma | Vmb | Vab |
| --- | --- | --- | --- | --- | --- |
| root busy / gap | 0.60 | 0.59 | 0.69 | 0.68 | 0.66 |
| gated start bound by N-1's fields / its own head | 26 / 74% | 26 / 74% | 36 / 64% | 36 / 64% | 33 / 67% |
| head: pre-gate (ops-ahead wait; encode; sort) | 19.5 (11.4; 9.7; 5.8) | 18.9 (11.2; 9.2; 5.5) | 22.2 (13.2; 11.1; 6.0) | 22.1 (13.1; 10.8; 6.1) | 20.3 (12.1; 10.1; 5.9) |
| idle between gated roots p50 / mean | 10.5 / 18.5 | 10.6 / 17.8 | 7.3 / 13.6 | 7.7 / 14.1 | 9.1 / 14.9 |
| root cycle (compute + end -> fields) | 29.5 | 28.8 | 32.3 | 32.6 | 32.4 |
| `root_compute` p50 w1 / w2 / w3 | 24.1 / 22.5 / 28.0 | 23.3 / 24.6 / 24.4 | 28.9 / 28.9 / 30.6 | 26.3 / 28.5 / 30.6 | 24.5 / 26.8 / 30.3 |
| of it lookups / writes / index / rehash | 5.2 / 7.0 / 6.2 / 5.2 | 4.8 / 6.2 / 6.1 / 5.5 | 5.8 / 7.9 / 6.7 / 5.3 | 5.7 / 8.0 / 6.8 / 5.0 | 5.1 / 7.5 / 6.6 / 5.6 |

The root idles 13.6-18.5 ms a block, waiting on its own head; it couples to the gap through the fields two-cycle
(seal(N) >= fields(N-2)): (seal -> fields without the gate wait + tail) / 2 = 33.0 (Vb), 37.1 (Vma), 35.7 (Vab).

## 6. The corrected model and the ranked levers

    gap = start delay + sealed_at  >=  max( builder,  fields 2-cycle,  gate loop,  root cycle,  tick ) + jitter (~5-6)
    builder        = seal -> bundle(N-1) + par_run + tail                Vb 35.7   Vma 37.5   Vab 36.3
    fields 2-cycle = (seal -> fields without gate wait + tail) / 2       Vb 33.0   Vma 37.1   Vab 35.7
    gate loop      = (sealed_at + L + c) / 6, c ~13                      Vb 39.6   Vma 38.3   Vab 36.7

Root cycle 28.8 / 32.3 / 32.4, tick 30 + 1.6. The three upper floors lie within 3 ms of each other on every leg: each single
cut since stage cd (two-ahead, AT_SEAL, root cuts, merge, answer at insert) moved the mean 0-1 ms into the next wait.

| next | expected mean gap | why |
| --- | --- | --- |
| 1. merge off the critical set (its 8 threads on the behind/background cores, 4 threads, or more critical cores: the root's +4.0 and head's +3.3 are contention) | -2..-3 (43.4 -> ~41) | keeps L -11 (gate loop 38.3 -> ~37.6) and returns seal -> fields +8.5 (fields floor 37.1 -> ~33) and `sealed_at` +3.7 |
| 2. the parent-output wait: start the child on N-1's output before the frozen bundle (seal -> bundle 9-10 ms, waited by 57-59% of builds) | -2..-3 with 1 (alone ~-1: the fields floor takes it) | builder floor 37.5 -> ~32 |
| 3. fields path: lookups early (c48f3c05e, -4.6 gated) then the head's ops-ahead wait (13 ms) | -2.3 per -4.6 of seal -> fields | fields floor = half the seal -> fields latency; depth 3 removes it but is a consensus change and leaves the builder and gate floors at ~37 |
| 4. L for the gate loop: answer at insert kept (Vab gate floor 36.7, L -22) | -0..-1 alone (Vab 43.5) | binds only once 1-3 are in |
| 5. `F7_BLOCK_INTERVAL_MS=25` | <= 0.5 (Vma) / 0.9 (Vb), likely ~0 | only the 8-13% of builds gated at prop(N-2) after a tick-bound proposal gain up to 5 ms, and an earlier start waits on output and fields |

Proof counters for 1: seal -> fields <= 66 with merge <= 42, gated root <= 26, `sealed_at` <= 36, fields wait <= 3.5 and start
delay <= 5, mean in-window gap <= 41.5; fields_mismatches 0.
