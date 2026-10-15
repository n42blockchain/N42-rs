# Cycle tail analysis toward a 40 ms mean cycle

Read-only analysis of the three loop351 stage bp legs (X11+T16, 30 ms pacing, 200k-tx blocks, E=1;
`bench-loop351D2S12P30T64X11T16G4{a,b,c}`, tree 879e751e7 + ced5314db, BREAKTHROUGH_DESIGN 10.139).
Windows are the bench's (first full canonical block + 3 x 30 s). Per block N: the leader's
`seal-first build phases` line, the EL's `own block imported by header number=N` (the answer),
`Block added to canonical chain`, and on the validators `send kind="proposal|prepare_qc|decide"`,
the import-gated vote lines (`waiting for execution validation` / `execution validated, sending vote`),
`imported a block`. The view number equals the block number. Gap = proposal(N) - proposal(N-1) at the leader.
L = seal(N) -> answer(N) (`sealed_unix_us` to the EL answer line).

## 1. The distribution: bimodal, and the excess is a one-in-four stall, not slow blocks

| leg | gap p50 | p75 | p90 | p99 | mean | mean - p50 | from top decile | from the rest | time in gaps > 60 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| G4b (386.0M) | 36.1 | 55.8 | 83.7 | 120.1 | 46.7 | 10.5 | 6.6 | 3.9 | 40% |
| G4c (383.6M) | 37.0 | 55.4 | 82.3 | 119.5 | 47.0 | 10.0 | 6.6 | 3.4 | 41% |
| G4a (369.2M) | 38.2 | 59.4 | 87.3 | 121.2 | 48.8 | 10.6 | 6.7 | 3.9 | 43% |

Canonical-to-canonical gaps give the same mean (G4b 46.7: p50 36.5, p90 99.3, p99 152.4); windows 1-3
of G4b/G4c differ by under 1 ms of mean. G4b histogram (10 ms bins from 20 ms): 168, 1023, 166, 152,
105, 93, 66, 60, 51, 26, 14, 6. Two thirds of the excess sits in the top decile, but the top decile is
not a set of slow blocks: no slow gap is followed by another slow gap (0 of 193, G4b; 0 of 192, G4c),
and the four-gap sum tracks L of the block four back (mean 186.6 ms against L 198.9).

## 2. What the slow gaps wait for

Slow = top decile of gap (>= 83.7 ms, G4b); G4c in brackets where it differs.

| field (median) | gap < p50 | p50-p90 | slow (>= p90) | slow p90 |
| --- | --- | --- | --- | --- |
| gap | 31.3 | 34.0 | 100.0 | 120.1 |
| seal-to-seal | 36.2 | 36.5 | 34.6 (35.1) | 48.7 |
| sealed_at_ms | 30 | 31 | 33 | 45 |
| par_exec_ms | 15 | 15 | 15 | 18 |
| roots_ms | 31 | 30 | 29 (28.5) | 39 (43) |
| plan_wait_us / plan_wait_timeout / start_frames_skipped | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 | 1275 / 0 / 0 |
| batch_live_lock_hold_us | 27.8k | 28.2k | 28.2k | 33.3k |
| seal(N) -> proposal(N) | 15.0 | 20.8 | **79.5** | 99.0 |
| proposal(N-1) -> prepare QC(N-1) | 10.9 | 15.5 | **92.1** | 110.8 |
| L of block N | 198.9 | 198.1 | 197.6 | 223.4 |

- **No leader phase is long on the slow blocks.** The block is sealed on time (seal-to-seal 34.6 ms) and
  then waits 79.5 ms for the QC of N-1; only 2 of 193 slow gaps (1 of 192, G4c) are seal-bound, against
  725 of 1930 gaps overall (the fast ones, which run at the seal's pace). Roots p90 44 ms is not the tail.
- **The vote is held for N-3's answer, not the follower's own check.** 1497 of 1930 views have held
  votes; of the holds whose release can be matched to an import, 1173 of 1245 (94%; G4c 1169 of 1264)
  are released by block N-3's import, 37 by N-2, 35 by N-4. The quorum's 4th follower vote on N comes
  0.9 ms (p50; p90 16) after the EL's answer for N-3. corr(gap(N), L(N-4)) = 0.50 (G4c 0.47), with
  N-2, N-3, N-5 at -0.2 .. 0.1. So mean gap = (L - c)/4 with c = 12 (measured), 19 in 10.114.
- **Correlates.** Tenure handover (block 2048) gaps 96, 45, 91, 31, 93: the ordinary pattern. Slow vote-log
  syncs: 31% of slow gaps vs 39% of the rest (not enriched). `forest lock waited on_canonical held_by=tree_lease`:
  29% of slow gaps vs 9% (G4c 31% vs 7%), 3-4x against the 2.5x their length explains -- a small effect
  on L, inside the hand-off tail below. Build minor faults are higher in slow blocks (1768 vs 657, p90 11k)
  without moving their phases. Prune lag: QMDB reader_lag 6-10, prune_ms p50 37, no hold or lag WARNs in G4b/G4c.

L, the quantity that sets the mean (window blocks):

| step | G4b p50 | p90 | mean | G4c p50 | G4a p50 |
| --- | --- | --- | --- | --- | --- |
| seal -> root start | 21.6 | 37.1 | 24.1 | 20.5 | 20.2 |
| root (start -> end) | 32.4 | | 31.1 | 30.5 | 27.4 |
| root end -> merge start | 1.2 | | 1.7 | 1.3 | 1.5 |
| merge, one thread: state + reverts | 48.5 + 47.3 | 62.6 + 60.3 | 103.9 | 48.4 + 47.0 | 49.1 + 46.9 |
| seal -> state ready | 160.2 | 183.7 | 160.8 | 157.2 | 155.9 |
| state ready -> handed to the engine | 10.6 | 23.2 | 12.6 | 11.3 | 11.7 |
| handed -> canonical | 1.1 | 10.7 | 3.6 | 1.1 | 1.0 |
| canonical -> answer (header newPayload) | 20.5 | 32.5 | 21.9 | 22.6 | 22.2 |
| **L = seal -> answer** | **198.0** | **224.5** | **198.9** | **198.3** | **197.2** |

The follower import completes at the same instant as the answer (198.1 ms after the seal; single
execution layer, import-once), so the follower's own `slot_wait_ms` (p50 32) is inside L, not added to it.

**G4a's window 2-3 dip.** From t = 15 s (six `Sidechain block not found in TreeState`), G4a logs
`an own block was still held when the bound was reached` on every block (1430 in the windows),
`canonical subscriber lag: queue pruner behind=10` (1212) and `the queue let go of transactions` (839);
G4b and G4c log none of the three. Its rate stays normal until t = 50 s; in 50-80 s the leg makes 92-97
blocks per 5 s (others 105-110), mean gap 52-54 ms, mean L 204-218 ms (others 191-198), roots p90 54-83 ms
(others 37-46), build minor faults 3.7-4.4k (others 2.7-3.3k). +20 ms of L gives +5 ms of gap, exactly the
model. Why the root's tail grows in that interval is not shown by these logs (fault counts correlate).

## 3. Candidates to bring the mean gap to <= 40 ms

Target: with a four-block window, mean gap 40 needs L <= 4 x 40 + 12 = 172 ms (27 ms off today's 199).
Below about 37 ms the gap becomes seal-paced (seal-to-seal p50 36, the fast gaps 31-34), so every
candidate below is capped there.

| rank | change | mechanism | evidence | expected mean gap | cost / risk |
| --- | --- | --- | --- | --- | --- |
| 1 | `N42_ANSWER_BEFORE_REVERTS=1` (exists: f0df037b1, 35884dafd, 8b3f1146f) | answer after the state half of the merge; the 47 ms revert half follows, read through `n42_deferred_reverts` | `merge_reverts_us` p50 47.2 / p90 60 on the answer path; its only legs (stage ah, X9ABR, 3.77 / 2.78 / 2.57M) ran on the frame-index-defect tree whose windows 2-3 collapsed (10.111), so it was never measured on a clean tree; their state ready already read 142 vs 160 here | L -35..-47 -> 37-39 ms (-8..-10) | no code; persistence and readers wait on the late revert set; **measurement-only first: three X11+T16+ABR legs** |
| 2 | five-block vote window (`N42_FAR_AHEAD_BLOCKS=2`) made stable | the vote on N waits for N-4's answer: mean = (L - c)/5 = 37 ms, i.e. seal-paced | corr(gap(N), L(N-4)) 0.50; holds released by N-3 in 94%; the one non-collapsing leg holds the window-1 record (4.377M) | 37-38 ms (-9) | 3 of 4 legs collapse today (own-block hold bound sized for four; build-parent `Sidechain block not found`); fix in flight |
| 3 | start the merge at the bundle, beside the root (`S3` early merge) | the merge waits for the root's end (merge start 55.2 = root end 54.0 + 1.2) while the bundle is ready ~15 ms after the seal | the table above: 40 ms of serial wait on L | L -20..-40 -> 37-42 ms (-5..-10) | adds a thread beside the next build: 10.116 showed that pays in the seal (+6 ms p50 with MS); S3 was only measured in the disturbed 10.115; **measurement-only first** |
| 4 | `N42_ANSWER_AT_INSERT=1` alone | answer VALID at the hand-off insert, newPayload on a side task | canonical -> answer 20.5-22.6 ms p50 (p90 32-37) | L -18..-22 -> 41-42 ms (-5) | 10.109 measured it only on the degraded host, 10.116 only stacked on MS (the side task cost the seal); **measurement-only first: X11+T16+AAI legs** |
| 5 | shorten seal -> root start and the hand-off tail | the root waits 21.6 ms (p90 37) after the seal; state ready -> hand-off 10.6 (p90 23-28); `on_canonical` forest-lock waits held by the tree lease | rows 1, 6, 7 of the L table; WARN enrichment in slow gaps | L -8..-15 -> 43-45 ms (-2..-4) | **measurement first**: split the 21.6 ms into ops-ahead encode (`seal_to_ops_ahead_us` ~18 ms) vs lease wait before choosing a cut |

Combination: 1 + 4 together take about 65 ms off L (199 -> ~134), which puts the four-block window at
(134 - 12)/4 = 31 ms, i.e. below the seal's pace: the gap would then be seal-bound at about 36-37 ms
(~5.4M at 200k tx), with no change to the vote window. The order to run is therefore 1, then 4 on top of
it, then 2 if the seal tail (seal-to-seal p90 48-50) still leaves the mean above 40.
Separately, G4a's held-bound / pruner-lag state (1 leg in 3 in bm, bn, bp) costs 3 ms of mean gap on
that leg's windows 2-3; it is a defect to find, not a lever.

Analysis scripts: `parse.py`, `ana.py`, `ana2.py` in the analysis job's scratch directory (outside the repo).
