# Vote-bound gaps on X14 and the levers to a 40 ms mean

Read-only analysis of the two loop351 stage bx controls `bench-loop351D2S12P30T64X11T16M{a,b}` (X14, 30 ms pacing, 200k-tx
blocks, E=1; both 400.0M, drain 4.455 / 4.449M/s; docs/EARLY_START_THIN_BLOCKS.md). Window = T0 .. T0+88 s (before the
400M set runs out). Per block N: the EL's `seal-first build phases` (seal, `sealed_at_ms`, `prev_seal_to_start_us`, L parts),
`own block imported by header` (the answer), canonical and hand-off lines; on every validator `proposal sent`, `send kind`
(proposal, prepare_qc), `block committed!`, `recv kind="proposal"`, `compact block body received`, `imported a block`,
`import starting`, the import-gated vote lines and `vote log sync was slow`. Blocks are joined by hash (Ma's views run one
ahead of the numbers, Mb's do not). Scripts (outside the repo): `/home/n42/.claude/jobs/03ef7830/tmp/vbg/`
(`parse.py`, `ana.py`, `anat.py`, `cls.py`, `L.py`, `sim.py`, `prop.py`).

## 1. The answer in brief

* A proposal waits for one of three things: its own seal, the commit of N-1 (votes), or the 30 ms tick after the previous
  proposal. Vote-bound proposals are 34-37% of blocks but 42-46% of the time; every vote-bound proposal is released by the
  **followers' import of N-4's answer** (97%), 9-13 ms after it. No follower straggles: the four follower votes land within 0.3 ms.
* The long *seal* gaps of EARLY_START (Ma 81, Mb 66 over 80 ms) are two kinds: 2/3 are the build's **one-ahead rule**
  (N+1 may not start while N-1 is unproposed; it then starts 0.8 ms after N's proposal), 1/3 are slow builds.
* Mean gap = mean `sealed_at` (39.9 / 40.8) + mean start delay (5.1 / 4.2). **The seal alone is a 41 ms floor**: no vote-side
  lever reaches 40 ms by itself (simulation, section 5); 40 needs `sealed_at` -4 ms **and** one vote-side lever.

## 2. What binds each proposal (prop(N) = max(seal N, commit N-1, prop N-1 + 30) + slack)

| leg | bound | share of blocks | gap p50 / p90 / mean | slack after the bound p50 | share of time |
| --- | --- | --- | --- | --- | --- |
| Ma | seal | 25% | 43.8 / 66.3 / 48.1 | 3.7 | 27% |
| Ma | vote (commit N-1) | 37% | 53.1 / 82.0 / 56.8 | 2.6 | 46% |
| Ma | tick | 38% | 31.4 / 36.5 / 31.6 | 1.4 | 27% |
| Mb | seal / vote / tick | 28% / 34% / 38% | means 49.8 / 56.0 / 31.6 | 4.3 / 2.6 / 1.4 | 31% / 42% / 26% |

Proposal gaps over 80 ms: Ma 95 (84 vote, 11 seal), Mb 74 (57 vote, 16 seal, 1 tick). The tick binds the catch-up after a
vote-bound gap, so it is not a lever (tick 25 ms in the simulation: -0.2 ms; 10.133 measured the same).

The vote-bound chain, p50 (mean) ms: answer(N-4) at the EL -> follower `imported a block` 0.1 -> 4th follower vote on N-1
0.9 (1.8) -> prepare QC 1.9 (2.7) -> commit 2.9 (3.5) -> proposal N 2.6 (4.5): prop(N) - answer(N-4) = 9.3 (12.5), Mb 10.1 (13.9).
Release of the 4th follower vote on vote-bound blocks: within 3 ms of the follower's import of answer(N-4) 501 / 718 (Mb 436 / 664);
6.5-6.9 ms after it 198 (209), of which ~70% carry a slow vote-log sync (5.5 ms mean; 7% of the prompt ones); by the body or
proposal arrival under 1%. The follower's own check is 0.16-0.3 ms (`check_us`); the body arrives 13-19 ms (p50) before the vote.

## 3. Anatomy of the long seal gaps (Ma, times from seal(N); M = N-1, the block whose QC gates prop(N))

| kind (count Ma / Mb) | prop(N-1) | 4th voter has N-1 | answer(N-4) | 4th vote(N-1) | QC(N-1) | prop(N) | build N+1 starts | seal N+1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| one-ahead delayed (54 / 38), p50 | 19.2 | 18.7 | 36.1 | 39.5 | 41.9 | 55.5 | 59.3 | 89.5 |
| same, mean | 19.8 | 19.9 | 33.2 | 38.7 | 41.9 | 57.1 | 59.1 | 93.4 |
| Mb one-ahead delayed, p50 | 16.3 | 16.6 | 30.4 | 32.3 | 36.4 | 53.0 | 53.8 | 88.8 |
| build-bound (27 / 28), p50 | -24.4 | -24.4 | 6.4 | 7.2 | 8.9 | 21.0 | 1.2 | 86.9 |

* In a delayed gap the leader sealed N before proposing N-1 (N-1 itself vote-bound), so the one-ahead rule
  (`h2-el-rpc/src/engine.rs` `chain_start_decision`, gate `Send`) holds N+1 until N is taken; 87% start 0.7-3.9 ms after prop(N).
  prop(N) waits for the QC of N-1 (+16 ms p50 after it: commit 3, then the tick, which bound 35 of 54 such proposals).
* Dominant wait of the 4th vote in these gaps: answer of N-4 (30 of 54 within 3 ms, 14 more 6-7 ms after it: the vote-log
  sync), 3 by arrival, 7 by another import. Last voter: spread over all six followers (Ma all blocks: nodes 3 and 4 20% each,
  the others 9-17%, the leader's node excluded); first-to-last follower vote p50 0.3 ms. One shared EL answers all keys at once.
* Build-bound gaps: the build started 1.2 ms after the parent's seal and ran 80-90 ms (`par_exec` p90 57, `sealed_at` p90 90).

## 4. L on the leader and the follower's answer -> vote

| step (window blocks) | Ma p50 | Ma p90 | Ma mean | Mb mean |
| --- | --- | --- | --- | --- |
| seal -> bundle (shards ready) | 14.2 | 18.8 | 14.8 | 14.7 |
| bundle -> root start | 8.6 | 28.6 | 13.2 | 13.1 |
| root (start -> end) | 32.4 | 46.9 | 34.0 | 33.9 |
| root end -> merge start | 0.4 | 3.7 | 2.5 | 2.3 |
| merge, state only (reverts 0 under ABR) | 53.6 | 68.1 | 54.8 | 55.0 |
| **seal -> state ready** | 117.3 | 144.6 | 119.5 | 119.1 |
| state ready -> handed to the engine | 15.8 | 33.5 | 18.6 | 17.8 |
| handed -> canonical | 1.5 | 16.8 | 5.8 | 5.3 |
| canonical -> answer (header newPayload) | 26.3 | 42.6 | 28.1 | 26.7 |
| **L = seal -> answer** | 169.9 | 200.5 | 171.9 | 168.9 |
| follower: answer(N-4) -> 4th vote on N-1 | 0.9 | 7.3 | 1.8 | 1.9 |

The merge is serial behind the root and the fields (fields at seal + 61.5 p50): 54 ms of single-thread merge after the
root's end is the largest single part of L. With reverts off the path, seal -> state ready is bundle 15 + root wait and root
47 + merge 55.

## 5. What each cut buys (replay of the measured per-block parts)

`sim.py` replays each block with its measured `sealed_at`, L, vote release, QC+commit and proposal slack under the three
rules above (one-ahead build, vote on N-1 after answer(N-4), 30 ms tick). It reproduces the mean gap (45.0 / 45.1 against
45.0 / 45.0). Cuts, mean gap in ms, Ma / Mb:

| cut | alone | + `sealed_at` -4 | + `sealed_at` -8 |
| --- | --- | --- | --- |
| none | 45.0 / 45.1 | 44.6 / 44.7 | 43.8 / 43.8 |
| L -20 (answer at insert) | 43.5 / 43.5 | 41.1 / 41.3 | 40.9 / 41.0 |
| L -35 | 42.2 / 42.7 | 39.9 / 40.3 | 38.8 / 39.0 |
| L -50 (merge at shards ready) | 41.6 / 42.2 | | |
| five-block window | 42.1 / 42.6 | **40.0 / 40.1** | 38.6 / 38.7 |
| five-block window + L -20 | 41.4 / 42.1 | **38.8 / 39.2** | 37.2 / 37.5 |
| two-ahead build | 42.9 / 43.4 | 41.9 / 41.8 | 41.4 / 41.2 |
| five-block window + two-ahead | 41.3 / 42.0 | 38.5 / 38.8 | 37.3 / 37.3 |
| L -20 + two-ahead | 41.8 / 42.3 | 40.0 / 39.9 | 38.6 / 38.4 |
| QC+commit -3, slack -3, vote-log sync gone, tick 25 | 44.7, 44.7, 44.9, 44.8 / 45.0 | | |

Caveat: `sealed_at` is elastic (10.116): the early hand-off cut `start_handoff` 11-12 -> 1.4-3.5 ms, yet `sealed_at` fell only
1-3 ms (36.8-39.1) and the start delay rose to 6.9-7.6 ms (gaps 44.1-46.0 on Mh{a,b}, Mhl{a,b}), in line with the replay's
-0.3 for -3. A lever that adds threads beside the build (AAI's side task, the early merge) can give the seal back.

Single L part that moves the mean most: the merge (L -50 if it runs at shards ready: -3 ms of mean); the answer pass is -1.5.
Over all levers: the five-block window, -2.5..-2.9 alone.

## 6. Levers to 40 ms, ranked

| rank | lever | mechanism | expected (replay) | status / risk |
| --- | --- | --- | --- | --- |
| 1 | five-block window `N42_FAR_AHEAD_BLOCKS=2 N42_PARENT_OUTPUTS_KEPT=6` (+ `N42_OWN_HOLD_BLOCKS=64` as in 10.132) | vote on N-1 waits for answer(N-5): the 46% vote-bound time shrinks; also removes most one-ahead delays | -2.5..-2.9; with `sealed_at` -4: 40.0 | knobs exist; 10.131's collapses were the lane walk (fixed); 10.132's -3% rounds (369-374M) were X11+T16 legs scored by round, before ABR and the pruner fixes, with the pruner 9-255 notifications behind. Never run on X14; score by drain rate |
| 2 | `sealed_at` -4 (seal side) | `start_handoff` 11-12 ms mean (hold 8); `par_start` 15-16; the lean pruner (be8643a79) and done-first | needed: every vote lever floors at 41-42 without it | early hand-off measured: elastic, only -1..-3 |
| 3 | `N42_ANSWER_AT_INSERT=1` | canonical -> answer (26-28 ms) off L | -1.5 alone; -1.2 on top of 1 + 2 (38.8-39.2) | correctness: no state, FIFO insert-before-newPayload, failure latched at ERROR; its 341.6M leg was MS+AAI on X10 (10.116), where the seal rose 33 -> 40 with MS's thread beside the build; the lane walk is not on its path. Safe to measure alone on X14 |
| 4 | merge at shards ready (S3, `N42_MERGE_AT_SHARDS_READY=1`) | the 55 ms merge starts at seal + 14 on its pool instead of after the root/fields | L -50: -3 alone | measured only in the disturbed 10.115; a pool beside the build (10.116 risk) |
| 5 | two-ahead build (`N42_BUILD_AHEAD_GATE=seal`, `N42_BUILD_AHEAD_AT_SEAL=1`) | N+1 starts at N's seal even with N-1 unproposed | -1.6..-2.1 | broke on X7 (own_not_committed=3, child on a replaced parent; stage w); design work |
| -- | followers' check, vote-log fsync, QC/commit, tick | 0.2 ms check; 6 ms sync on ~25% of 4th votes; 1.9 + 2.9 ms | -0.1..-0.3 each | not levers |

## 7. Run first, and the counters that prove it

Run the five-block window alone on X14 (three legs against two X14 controls, quiet box, drain rate as the score). It is
knob-only, the largest single lever, and it tests the model directly. Counters (`cls.py`, `anat.py` on the legs):

* vote-bound share of proposals 34-37% -> under 20%, its share of time 42-46% -> under 25%; proposal gaps > 80 ms 74-95 -> under 30;
* the 4th follower vote on N-1 released by the import of answer(N-5), not N-4 (expected > 90% of vote-bound blocks);
* start delay (seal gap - `sealed_at`) mean 4.2-5.1 -> under 2 ms, one-ahead-delayed seal gaps 38-54 -> under 15;
* mean proposal gap 45.0 -> 42-43 ms, drain rate 4.45 -> >= 4.6M/s, `sealed_at` mean unchanged (39.9-40.8; elasticity check);
* guards: no `an own block was still held when the bound was reached`, no `Sidechain block not found`, pruner lag line
  as on the controls, verify clean. Then stack AAI, then the seal-side cut; the 40 ms mean needs both sides.
