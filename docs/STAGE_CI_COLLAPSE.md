# Why stage ci's X17 legs read 3.0M/s

Stage ci (loop351, 2026-10-16 23:47 - 00:13 local) ran four legs named X17 (`X11T16Ya`-`Yd`) at
3.01-3.13M/s, against 4.61-4.69M/s for the same names in stage ch two hours earlier. BREAKTHROUGH_DESIGN
10.158 left it open and suspected the WARM leg on the 600M set or the host. **Neither: the four legs
were not X17.** They ran the base configuration at deferred-execution depth 1 -- the WARM leg's
configuration, which reads 3.1-3.2M/s in every stage.

## The cause: stage ci never defined the X17 variables

In `scripts/fleet7-runs/run-loop351.sh` every stage block defines its own shell variables
(`D2`, `PA`, `BA`, `X3`..`X10`, `SM`, `C16`, `X11`) before its `b7` lines; stages ch and cj do. The
`ci)` block (added in 02bbc7d0a) copies ch's `b7` lines but not the definitions, so `$D2` and `$X11`
expanded to nothing (`$S1 $S2 $T64` are global, line 321, and survived). The legs ran:

| what | stage ch Xa (X17) | stage ci Ya | source |
| --- | --- | --- | --- |
| genesis | `n42_fleet7_bench_d2.json` | default `n42_fleet7_bench.json` | `$D2` empty |
| deferred depth (node0-el.log, validator start-up; Ya-Yd and ci WARM all `depth=1`) | `depth=2` | `depth=1` | the only config difference of the d2 genesis |
| EL knobs missing in ci | -- | `N42_QMDB_RENAME_DEFER`, `HANDOFF_HEAD_MOVE=number`, `HANDOFF_NO_CLONE`, `HANDOFF_MOVE_BODY`, `CANON_NOTIFY_LEAN`, `QUEUE_OFFLOCK`, `QMDB_COMPUTE_OFFLOCK`, `QMDB_PERSIST_BATCH`, `SHARD_MIX`, `PLAN_AHEAD_WAIT_MS=30`, all five `CORE_LAYOUT*` | `$X11` empty |
| validator knobs missing | -- | `N42_PLAN_AHEAD_WAIT_MS=30` | `$X11` empty |
| EL env entries (`el binary ... env:` line) | 60 | 45 | launch.out line 1061 / 1068 |

The env lines were printed in both launch logs; a sorted diff of them shows exactly the list above and
nothing else. The binary and the tree were the same (02bbc7d0a, no rebuild), as 10.158 says.

## (1) Timeline of the first 70 s (node0's execution layer, 5 s buckets from the first non-empty block)

| s | Xa blocks/s | Xa txs/block | Xa sidechain | Xa queued p50 | Ya blocks/s | Ya txs/block | Ya sidechain | Ya queued p50 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | 25.6 | 64k | 1 | 1.36M | 24.8 | 41k | 1 | 2.53M |
| 5 | 21.6 | 200k | 0 | 2.38M | 16.0 | 200k | 9 | 2.48M |
| 10 | 21.8 | 200k | 1 | 2.39M | 15.6 | 200k | 32 | 2.46M |
| 15 | 22.6 | 200k | 0 | 2.36M | 15.6 | 200k | 38 | 2.48M |
| 20 | 23.6 | 200k | 0 | 2.35M | 16.8 | 200k | 15 | 2.47M |
| 30 | 24.0 | 200k | 0 | 2.34M | 15.6 | 200k | 24 | 2.47M |
| 40 | 24.4 | 200k | 1 | 2.30M | 15.6 | 200k | 29 | 2.48M |
| 50 | 23.8 | 200k | 0 | 2.33M | 15.8 | 200k | 25 | 2.48M |
| 60 | 22.6 | 200k | 0 | 2.35M | 16.0 | 200k | 22 | 2.42M |
| leg total sidechain | | | 4 | | | | 510 | |

Ya does not *fall* behind: it is at 15.6-16 blocks/s from the first full bucket and stays there for
the whole leg, exactly the WARM legs' rate (3.15M/s = 15.8 blocks x 200k). The queue is full in both
(2.3-2.5M queued at every build), so supply is not the limit; the flood was identical (18,750 senders
at offset 900000 funded in 1.8 s / 2.1 s, same replay header). The "Sidechain block not found" lines
are spread over the whole leg, not concentrated at the flood start: they are the depth-1 / no-X11
build path, as on WARM.

## (2) What the validators waited for

Vote collection is not the difference: first vote -> quorum p50 0.2-0.3 / p90 0.5-0.7 ms and quorum ->
last vote p50 1.5-3.2 ms in both legs. The longer proposal -> quorum p90 (63 vs 39 ms) and the
proposal interval p90 (67 vs 45 ms) are the depth-1 rule: a header carries the result of its parent
(not of the grandparent), so a follower checks block N only after it has executed N-1, and the leader's
next proposal waits on its own execution instead of overlapping one more block. node1's "waiting for
execution validation" lines are fewer (345 vs 1,024) because there is less to run ahead of. Ya also
had 33 view-timeout lines and 7 TCs, all at view 1 (03:51:59 UTC, start-up), the 6.0 s maximum
interval and `engine_idles_over_5s=1` -- the WARM legs show the same start-up signature; Xa showed
none. No slow follower import, no vote-log-sync stall (271 lines vs 525 in Xa).

## (3) The WARM-on-600M hypothesis and the host

- No residue: each leg resets its datadirs; the runner's `cleanup`/per-leg teardown is unchanged
  between ch and ci; WARM itself read 3.19M (normal). Nothing is needed to explain ci beyond the
  configuration.
- Host: load at leg start 7.17 (ch 7.93), zero major faults in both, no gate failures; the kernel log is
  not readable without root (`dmesg`: not permitted). The gov5 run began at 00:39, after the stage.
  The per-leg CPU sampler's "no execution-layer process" line in ci is not evidence of a host event.
- 10.158's question (does a 600M WARM spoil the X17 legs?) was **not tested** by stage ci and stays
  open; there is no reason to expect it does.

## (4) Re-running safely

- Stage cj defines `D2`..`X11` itself, so its Za/Zb controls are real X17 legs. Watch per leg:
  the `el binary ... env:` line has 60 entries and contains `N42_CORE_LAYOUT=isolate` and
  `N42_SHARD_MIX=1`; node0-el.log's start-up line reads `deferred execution ... depth=2`; the WARM
  leg reads `depth=1`. Expected: 4.6M/s, single-digit "Sidechain block not found" counts, tc=0.
- Do not reuse ci's block as is. If the 600M WARM question matters, run it as `mk WARM 7 16 $R6`
  in a stage block that carries the definitions (copy ch's lines 1214-1220 first).
- Cheapest guard (not done here, a code change): `b7` refusing to start when `$X11` or `$D2` is
  empty, or the leg check failing when the logged depth differs from the tag's `D2`.
- 10.158's table is a depth-1 base-config measurement; read it as a WARM-class result, not X17.
