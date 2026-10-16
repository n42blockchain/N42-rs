# Why an earlier build start "thins blocks" on X14 (it does not)

Read-only analysis of loop351 stage bx (BREAKTHROUGH_DESIGN 10.147): controls `bench-loop351D2S12P30T64X11T16M{a,b}`,
`N42_HANDOFF_DONE_FIRST=1` legs `...Mh{a,b}`, hand-off + `N42_QUEUE_LEDGER_LOCK=1` legs `...Mhl{a,b}`; sources are
`node0-el.log` (the one execution layer: every build's `seal-first build phases` line and every `Block added to canonical
chain` line), `flood.log`, `round.txt` and `target/fleet-runs/loop351bx.launch.out`. Windows are T0 + 0/30/60/90 s,
T0 = "first full block" in round.txt. Scripts: `parse.py`, `canon.py`, `gaps.py`, `gap2.py` (kept outside the repo).

## 1. The answer in one line

10.147's hypothesis is wrong. **No build seals a thin block**: every one of the 2,000 builds on every leg carries 200,000
transactions. Mha's window 3 is "thin" because **the bench's fixed 400M-transaction supply ran out at T0+88.18 s** and the
chain produced 52 empty blocks in the last 1.8 s of the window. The round metric is capped at the supply: 400.0M means only
"the average rate over the round was at least 400M / 90 s = 4.444M/s".

## 2. Window 3 of Mha against Ma (canonical blocks)

| leg | w3 blocks | empty | non-empty mean | w3 txs | last block with txs |
| --- | --- | --- | --- | --- | --- |
| Ma, control | 675 | 6 | 199.7k | 133.61M | T0+89.79 s |
| Mb, control | 675 | 3 | 200.0k | 134.40M | T0+89.90 s |
| **Mha**, hand-off | 695 | **52** | 199.8k | 128.50M | **T0+88.18 s** |
| Mhb, hand-off | 641 | 0 | 200.0k | 128.20M | T0+91.17 s |
| Mhla, hand-off + ledger | 645 | 0 | 200.0k | 129.00M | T0+91.75 s |
| Mhlb, hand-off + ledger | 640 | 0 | 200.0k | 128.00M | T0+91.25 s |

The "15k missing transactions per block" of Mha's window 3: 52 empty blocks x 200k / 695 blocks = **15.0k**, all of it.
(The feed check's `FEED-BOUND: w3 full 93%` on Mha is the same artefact: the queue at builds hits 0 only in the last seconds.)

## 3. Per window, build side (leader builds, `seal-first build phases`)

| leg | window | builds | txs p10 / p50 | seal-to-seal p50 / mean ms | gaps > 80 ms (count, sum s) | plan_wait mean ms, timeouts | plan_body 0 / 1 / 2 | queued at build p50 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Ma | w1 | 670 | 200k / 200k | 39.3 / 44.7 | 44, 4.11 | 0.36, 0 | 2 / 652 / 16 | 2.37M |
| Ma | w2 | 662 | 200k / 200k | 40.9 / 45.3 | 33, 3.06 | 0.78, 0 | 0 / 649 / 13 | 2.40M |
| Ma | w3 | 667 | 200k / 200k | 40.9 / 44.6 | 25, 2.34 | 0.70, 1 | 0 / 656 / 11 | 2.38M |
| Mha | w1 | 690 | 200k / 200k | 38.6 / 43.5 | 30, 2.83 | 0.28, 0 | 2 / 621 / 67 | 2.36M |
| Mha | w2 | 671 | 200k / 200k | 38.8 / 44.7 | 42, 3.98 | 0.27, 0 | 0 / 605 / 66 | 2.36M |
| Mha | w3 | 639 (to +88 s) | 200k / 200k | 38.4 / 43.9 | 41, 3.94 | 0.30, 1 | 0 / 589 / 50 | 2.36M |
| Mhb | w2 | 642 | 200k / 200k | 38.9 / 46.7 | 50, 4.99 | 0.16, 0 | 0 / 602 / 40 | 2.37M |
| Mhla | w2 | 634 | 200k / 200k | 39.5 / 47.3 | 57, 5.66 | 0.35, 0 | 1 / 590 / 43 | 2.36M |

The plan ahead is never late: no `plan_body 0` builds after window 1's first seconds, plan_wait under 1 ms, one timeout
(the last, empty-supply build). `plan_body 2` (a topped-up plan) is 7-10% of builds with the early hand-off against 2% on
the controls, but those builds are full too: a top-up costs nothing visible. The queue sits at 2.36-2.40M (the pool cap is
~2.5M) through every window on every leg and drains only when the flood's set is exhausted.

## 4. Where windows 2-3 go on the hand-off legs: the long gaps, which are not the build's

The seal-to-seal median is 1-2 ms *shorter* with the early hand-off (sealed_at p50 34-36 ms against 35-38; start_handoff
p50 1-2 ms against 8-11). What differs is the tail: gaps over 80 ms, T0..+88 s:

| leg | gaps > 80 ms | sum | mean gap | build start delay in them | sealed_at in them | plan_wait in them |
| --- | --- | --- | --- | --- | --- | --- |
| Ma | 101 | 9.5 s | 93 ms | 43.8 ms | 49.3 ms | 0.12 ms |
| Mb | 95 | 9.0 s | 92 ms | 36.5 ms | 56.0 ms | 1.21 ms |
| Mha | 115 | 10.8 s | 95 ms | 52.5 ms | 42.7 ms | 0.09 ms |
| Mhb | 131 | 12.9 s | 98 ms | 42.9 ms | 55.2 ms | 0.07 ms |
| Mhla | 123 | 11.9 s | 97 ms | 34.4 ms | 62.5 ms | 0.49 ms |
| Mhlb | 139 | 13.3 s | 96 ms | 51.9 ms | 43.9 ms | 0.65 ms |

In a long gap the next build *starts* 35-52 ms late (start delay = gap - sealed_at), with its plan ready: the leader is waiting
for the chain (the vote-bound gaps of DEGRADED_ONSET_ANALYSIS Q1: vote side (L - 12)/4 = 38-39 ms, plus deferred depth 2), not
for the queue. The early hand-off seals faster, so more gaps cross over to vote-bound, and the extra 1.3-4.8 s of long gaps
per round (hand-off 115-139 long gaps, 10.8-13.3 s; controls 95-101, 9.0-9.5 s) eats what the shorter build saved. That is the w1-up / w2-3-down shape; 10.146's ledger lock and 10.132's five-block
window show the same signature and should be re-read the same way (gap tail, not block size).

## 5. Supply and flood

| leg | flood submit time | flood mean rate | delivered (ingest) median w1 / w2 / w3 | slots_busy | flood wait share | drain rate (400M / time to last tx block) |
| --- | --- | --- | --- | --- | --- | --- |
| Ma | 89.5 s | 4.47M/s | 4.51 / 4.47 / 4.45M/s | 19% | 96% | **4.455M/s** |
| Mb | 89.6 s | 4.46M/s | 4.51 / 4.41 / 4.47M/s | 20% | 96% | **4.449M/s** |
| Mha | 87.8 s | 4.56M/s | 4.61 / 4.50 / 4.53M/s | 20-21% | 96% | **4.535M/s** (+1.8%) |
| Mhb | 90.9 s | 4.40M/s | 4.57 / 4.49 / 4.23M/s | 18-20% | 96% | 4.386M/s (-1.5%) |
| Mhla | 91.4 s | 4.37M/s | 4.57 / 4.42 / 4.12M/s | 18-20% | 96% | 4.357M/s (-2.1%) |
| Mhlb | 90.9 s | 4.40M/s | 4.50 / 4.37 / 4.40M/s | 20-21% | 96% | 4.383M/s (-1.5%) |

(Stage bw for comparison: Lha's set ran out at T0+89.80 s, so its 400.0M "record" is the same cap.)

* **Not rate-bound on supply.** The flood is the pre-generated replay `/data/n42-pregen/g900000-400m` (12,500 senders x
  32,000 tx, 64 workers, conc 64, batch 500, `rate=6000000/s`, cores 112-127,240-255, `sign 0s`). Its 64 workers spend 96% of
  their time waiting for pool room (`wait 5235 s` of 64 x 85 s), the ingest slots are 80% idle, and the pool stays full: the
  delivered rate *is* the chain's take. The flood is not CPU-bound; its own ceiling was not reached in these legs.
* **Volume-bound.** The set is 400M transactions (61 GB). Any leg faster than 4.444M/s exhausts it before T0+90 s and pads
  window 3 with empty blocks; a leg slower than that leaves the tail outside the windows. Both controls sit 0.1-0.2% above the
  cap, so "400.0M on both controls" says only that they cleared it.

## 6. Ceiling and the answer to each question

1. Mha's thin window 3 is supply exhaustion (52 empty blocks after T0+88.18 s), not thinner builds; per-window the plan is
   ready, the queue is full (2.36M) and every build is 200k.
2. Supply rate: delivered 4.45-4.61M/s median = the chain's rate under pool back-pressure; the queue never drains until the
   set ends (layer-0 queue t+0..t+60: 2.36-2.44M on Mha, t+80: 0; Ma 2.33-2.39M throughout).
3. Plan ahead: not late on any leg (no fix needed there). The hand-off's w2-3 loss is the vote-bound gap tail (section 4).
4. **X14's ceiling under this bench is ~4.45M/s averaged over the round (controls 4.449-4.455M/s; best leg Mha 4.535M/s),
   and the round metric cannot read above 400M by construction.** 5M TPS for 90 s needs 450M transactions plus the 2.5M pool:
   generate a >= 500M set (~76 GB at 152 B/tx; /data has 792 GB free), e.g. `tx_flood --pregen-out /data/n42-pregen/g900000-500m
   --pregen-txs 500000000 --senders 15625 --pertx 32000 ...` as in derive333.py, before any 5M claim can be measured.

Next step: score legs by drain rate (400M / time to the last non-empty block) or move the bench to a >= 500M set, so that a
faster leg reads higher instead of filling window 3 with empty blocks; then attack the vote-bound long gaps (95-139 per round,
9-13 s) rather than the build's start.
