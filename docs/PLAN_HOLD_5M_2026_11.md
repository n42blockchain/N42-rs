# Holding the overall goal after the open-items plan (2026-11-10)

`docs/PLAN_OPEN_ITEMS_2026_11.md` is finished: every row is done and both clients' `main` carry the work.
This plan goes back to the overall goal and lists what still stands between today's `main` and it.

**Overall goal** (user, 2026-10-07; met on `main` 2026-10-24, tag `fleet7-x22-5.2M-20261024`): the all-Rust
seven-node fleet sustains **5M TPS** on window 1 of the X22 round, with every block valid on every node, and
the node stays byte-compatible with gov5.

## 1. Where `main` stands against it

| Measure | 2026-10-24 (tag) | 2026-10-30 controls | 2026-11-07..10 controls |
| --- | --- | --- | --- |
| win1, main natives | 5.19 / 5.21M | 4.92-5.15M (ten legs, mean 5.01M) | 4.78-4.98M (fourteen legs, mean 4.89M) |

Single legs differ by up to 10%, but fourteen consecutive control legs under 5M is not one leg: `main` reads
2-6% under the tagged build. Nothing merged since the tag was meant to cost throughput, and every merge passed
a pair "at parity" against the `main` of its day, so a slow drift of sub-noise steps, a box change (the PSU
swap of 2026-10-29, kernel, memory layout) or the runner are all candidates.

Second gap: the same-parent rebuild root mismatch (G8/M1) stopped two rounds (blocks 8191 and 7167) and its
mechanism is unknown. A fleet that can exit on an empty-block handover does not "sustain" anything.

## 2. Workstreams

| # | Item | Method | Verification | Status |
| --- | --- | --- | --- | --- |
| P1 | Is the drop code or box? | pairs with the tagged natives (`wt-port`, 47b8180ab) as the candidate against today's `main` natives, same runner, same day | two pairs; tag legs >= 3% over main legs in both = code | **done 11-10: code** (tag +4.5% / +5.3% over main in PA1 / PA2) |
| P2 | If code: find the step | natives at the merge points between 47b8180ab and `main` (maturity audit 8ff447481, compaction c992a5ee4, N42Header b87fa2884, reth v2.9.0 6703c576f, v2.10.0, Amsterdam step 235076649, today), halving by pairs | the step that separates >= 3% twice | done 11-10: no single step; phase diff named three costs |
| P3 | Fix or gate the step | per finding; a knob in the X22 profile if the cost buys something `main` needs | pair back in the 5.0-5.2M band, twice | done 11-11: main 5.06-5.12M on four legs |
| P4 | If box: re-baseline | record the band of the tagged build today as the reference; the goal is judged against it | docs | waits for P1 |
| S1 | G8 mechanism | every pair leg runs with the forest trace; a deterministic reproducer of the empty-block tenure handover (three executions of one block on one parent, child built ahead) in the crate tests | the reproducer fails on `main` and passes with the fix | no mechanism found in the 7167 log (second reading, `docs/RETH_2_10_0_UPGRADE.md`); replay diagnosis merged 2026-11-10 (38bf5f76f): the next recurrence logs a verdict among three causes; open until then |
| Q1 | `cargo clippy -- -D warnings` is red again on N42 crates (`twig-core` `entry_store.rs`, `index.rs`; `qmdb-reth` `executed_fields.rs`, `node_state_tests.rs`) | fix the warnings, no behaviour change | clippy clean on the crates d07ec6584 covered | **done 2026-11-10**: the d07ec6584 gate (`scripts/clippy-n42.sh`) was green all along; the named sites were test targets, fixed in 74b6bdba2; `--all-targets` across all N42 crates has a backlog in tests and benches, not in scope |

Not reopened: QMDB compaction stage 1 read view (C1 closed in the open-items plan), chain 94 Amsterdam date
(scheduling), per-crate `-D warnings` beyond the set d07ec6584 covered.

## 3. Log

- 2026-11-10: P1 pairs PA1/PA2 queued 06:06Z behind foreign box claims (n26, qs). S1/Q1 branch merged.
- 2026-11-10 14:13Z: PA1/PA2 never ran. `launch-loop351.sh` waits in its pre-gate for up to 4 h and files
  no box request there, while the foreign E1N26 chain re-requests the box within 3-6 minutes of each
  ~2.5 h round, so the launcher had no FIFO position and gave up twice (06:06-10:07Z, 10:08-14:09Z).
  Requeued with `audit-notes/scripts/pairs-request-keeper.sh`, which keeps `.box-request-rust` live
  while the queue has lines and no runner is up.
- 2026-11-10 16:24Z: **P1 = code.** Pairs PA1/PA2 (legs a/b = tag natives 47b8180ab, 0/0b = main natives
  ba379f5ad), window 1: PA1 tag 5.173 / 5.073M vs main 4.967 / 4.840M (+4.5%); PA2 tag 5.179 / 5.053M vs
  main 4.873 / 4.840M (+5.3%). The tagged build still reads 5.05-5.18M on today's box, so the box is not
  the cause; eight legs, no fatal, no replay miss, no mislabelled tree. P2 starts: natives at d07ec6584
  (10-30, before N42Header), 6d373bbbe (11-04, before reth v2.9.0), 6703c576f (v2.9.0) and 0ed56c1da
  (v2.10.0), each paired against the tag natives.
- 2026-11-10 18:44Z: P2 round 1, each point against the tag natives (window 1, M TPS; legs a/b point, 0/0b tag):
  d07ec6584 5.000 / 4.858 vs 5.107 / 5.200 (-4.3%); 6d373bbbe 4.993 / 4.933 vs 5.073 / 4.911 (-0.6%);
  6703c576f (reth v2.9.0) 4.873 / 4.960 vs 5.193 / 5.173 (-5.1%); 0ed56c1da (v2.10.0) 4.972 / 4.937 vs
  4.951 / 5.127 (-1.7%). Pooled: the four points read 4.86-5.00 (eight legs, mean 4.94), the tag 4.91-5.20
  (twelve legs with PA, mean 5.10), `main` 4.88. Most of the step is therefore already in at d07ec6584:
  it lies in 47b8180ab..d07ec6584 (10-24..10-30), and the reth bumps are not it. All 16 legs clean.
  Round 2: 6eb585176 (maturity audit), 8ff447481 (design items), 62bc01b59 (QC embed + leftovers),
  134b9c215 (before compaction stages 1-2).
- 2026-11-10 21:04Z: P2 round 2, against the tag natives: 6eb585176 5.044 / 4.807 vs 5.093 / 5.011 (-2.5%);
  8ff447481 5.047 / 4.904 vs 5.007 / 5.113 (-1.7%); 62bc01b59 5.073 / 5.013 vs 5.147 / 5.093 (-1.5%);
  134b9c215 5.007 / 5.013 vs 5.120 (-2.1%; tag leg CD0 stalled, exit 1, tc=7, an engine idle over 5 s).
  Over both rounds: tag 5.10 (19 legs), the eight points 4.97 (16 legs, no trend between them), `main`
  4.88 (4 legs today, 4.89 over the 14 before). No single step: about -2.5% is already in at 6eb585176,
  the first point after the tag (the maturity-audit merges), and about -1.5% more lies between
  0ed56c1da and `main`. Two-leg pairs cannot resolve steps this small, so the next reading is by phase:
  the per-leg phase and timer files of all 39 legs, grouped by binary (in progress). Round 3 on the box:
  `main` natives rebuilt from current `main`, then 0ed56c1da vs `main` twice and 6eb585176 vs tag twice.
- 2026-11-10 21:30Z: P2 by phase (39 legs; `audit-notes/ci/phase-diff/REPORT.md`). The whole loss is the
  leader's build-start-to-seal time: mean gap 39.13 ms (tag) / 40.14 (points) / 41.10 (`main`), tracking
  `sealed_at_ms` (r = 0.98); consensus timings unchanged. (1) Maturity merge, about +1.0 ms: the root job
  is ~3 ms slower (roots 35.1 -> 38.3 ms, root_index 5.68 -> 7.0-7.6, root_leaves 6.0 -> 7.1-10), so the
  seal waits for the grandparent's fields; first candidate 1f5dc72e6, the seeded shard choice of the key
  index (`twig-core/src/index.rs` `shard_of`, `group_by_shard`). (2) reth v2.9.0 port, about +0.5 ms:
  a 3.4-3.8 ms fee/gas reduce between execution end and the seal (`payload.rs`, `evm2_fees_us`) and
  par_exec +1.8 ms. (3) 0ed56c1da -> `main` +0.4 ms, within noise. CD0 was not a stall: one of the
  18,750 funding transfers was refused ("insufficient funds ... have 0"), funding never mined.
  P3 started on two branches: `perf/index-shard-cost` (attribution knob `N42_INDEX_SHARD_KEY0`, then the
  seeded path made as fast) and `perf/evm2-fees-in-exec` (fees summed inside the execution workers).
- 2026-11-10 23:17Z: round 3. 0ed56c1da vs `main` (natives rebuilt from b99f46d17, with the replay
  diagnosis): DA 4.933 / 4.904 vs 4.867 / 4.893, DB 4.927 / 4.899 vs 4.847 (+1.0% over seven legs).
  6eb585176 vs tag: EA 5.100 / 4.987 vs 5.113 / 5.167, EB 5.020 / 5.080 vs 5.004 / 5.160 (-1.3%).
  Consistent in sign with the phase reading, each step near the leg noise. `perf/evm2-fees-in-exec`
  handed back (fees and gas summed on the batches, batch transactions converted from a reference; tests
  and the clippy gate green); natives building, pairs FA/FB against `main` queued.
- 2026-11-11 01:30Z: P3 first readings (window-1 means of the leader's build line; `ci/phase-diff/quick.py`).
  `perf/evm2-fees-in-exec` vs `main` (FA/FB): exec_end_to_seal 3.3-3.5 ms -> 0.0006 ms, but sealed_at
  38.9-39.4 vs 38.8-40.2 and window 1 4.81-4.91M vs 4.75-4.94M (+0.9%): the seal is bound by the root job
  (roots 37-39 ms against 32-34 on the tag legs), so the saved time is waited away. `integ/hold-5m`
  (fees + `perf/index-shard-cost`) vs `main` (HA/HB): 4.87-4.93M vs 4.79-4.92M (+0.7%), root_index 7.9-8.1
  ms against 7.1-7.8 on `main` and 5.5 on the tag: the microbench gain of the partitioned seeded batch
  (insert 3.7 -> 2.5 ms, apply 5.6 -> 3.8 ms on a 33M-key index) does not show on the 480M-account fleet.
  Next: the attribution knob itself, KA/KB = integ natives with `N42_INDEX_SHARD_KEY0=1` against the same
  natives without it (runner hook `LOOP351_QC_ENV`, bench tree 54c749f99).
- 2026-11-11 02:26Z: attribution confirmed. KA/KB, integ natives with `N42_INDEX_SHARD_KEY0=1` against the
  same natives without it (four legs each, window-1 means): root_index 5.8-6.2 vs 7.8-8.2 ms, root_leaves
  5.7-6.7 vs 6.9-9.0, roots 35.8-36.6 vs 36.7-39.1, sealed_at 37.6-38.0 vs 38.4-39.0; window 1
  5.020 / 5.073 / 4.824 / 5.011M vs 4.887 / 4.973 / 4.973 / 4.865M (+1.2%). The seeded shard choice is
  the cost and the first fix missed it: at fleet scale the loss is in the lookup paths the 33M-key
  microbench called level. The branch goes back for a fix measured at the real entry count. The knob
  still leaves roots ~3 ms over the tag (32-34 ms); par_exec is +1.5 ms since the evm2 port and the root
  job starts from its output, so a third branch, `perf/evm2-par-exec`, profiles the batch execution.
- 2026-11-11 03:10Z: the second index fix holds on the fleet. The branch now probes a seeded batch by
  shard on the pool and confirms in key order, measured at the fleet's shape (2.03M live keys, 33.5 MB
  of index tables, 440M entry slots; the earlier "many-GB tables" guess was wrong, the cost was
  out-of-order entry-file reads across 256 tables). Legs LA0 / LA0b / LB0: root_index 4.2 ms (tag 5.5,
  `main` 7.1-7.5, key0 knob 6.0-6.9), window 1 4.917 / 4.953 / 5.017M against the knob's 4.984 / 4.880M.
  The seeded shard choice stays; the knob stays bench-only and off.
- 2026-11-11 03:40Z: `perf/evm2-par-exec` handed back. The direct path kept two maps per batch (the
  bundle and a second layered read map); `BatchState` now holds the bundle accounts and is the read
  layer. Microbench `par_exec_profile`: 6.5-6.7 -> 5.6 ms a batch set, ~700 -> ~600 ns a transfer.
  `perf` is not usable on this box (`kernel.perf_event_paranoid` is 4).
- 2026-11-11 05:13Z: `integ/hold-5m` (fees on the batches + index locality + the read layer) passed the
  gate (17 results ok, 0 failures, clippy clean) and pairs H5A/H5B against `main` natives:

  | window-1 mean | integ (4 legs) | `main` (2 legs) | tag (earlier legs) |
  |---|---|---|---|
  | TPS | 4.987 / 5.060 / 4.973 / 4.784M | 4.847 / 4.920M | 5.05-5.18M |
  | sealed_at ms | 37.7 / 37.7 / 38.1 / 39.9 | 39.5 / 38.9 | 36.6-36.7 |
  | roots ms | 37.2 / 36.8 / 34.8 / 35.5 | 38.6 / 38.2 | 32-34 |
  | root_index ms | 4.4 / 4.4 / 4.0 / 4.0 | 7.8 / 7.6 | 5.5 |
  | par_exec ms | 27.3 / 28.8 / 27.7 / 27.3 | 29.9 / 30.3 | - |
  | engine import ms | 69.4 / 69.9 / 65.0 / 64.5 | 73.2 / 71.5 | 55-60 |
  | QMDB persist s/leg | 56.5 / 57.9 / 52.4 / 53.2 | 64.1 / 63.9 | 37-41 |

  Every leg fatal=0, no replay miss. Mean +1.4% over `main`, about half of the gap to the tag. Merged
  into `main`. Still open for P3: the import side (import +10 ms, persist +30% over the tag; branch
  `perf/import-persist-cost` in work), root_leaves 7.2-8.9 ms, and H5Bb's seal at 39.9 with roots at 35.5.
- 2026-11-11 06:25Z: `main` reads back in the band. `perf/import-persist-cost` handed back one import
  cost: `with_header_tail` (N42Header merge, 2bad5b091) cloned the whole 200,000-transaction payload on
  every hand-off (`payload_ms` 3 -> 9.8 ms); the payload now moves, and comes back unchanged on a
  refusal. The QMDB persist growth is `settle_through` waiting for the tree lease on the parallel
  persist thread (delta log settled before the database commits); the save scope grew 1.3 s a leg,
  inside the spread, so the guarantee stays as it is. Pairs H5C/H5D, the fix against the new `main`
  natives (c13ecf9bf), gate green (17 results ok, clippy clean), every leg fatal=0, no replay miss:

  | window-1 mean | fix (4 legs) | `main` c13ecf9bf (4 legs) |
  |---|---|---|
  | TPS | 5.093 / 5.147 / 5.025 / 4.940M | 5.120 / 5.071 / 5.085 / 5.060M |
  | sealed_at ms | 37.1 / 36.9 / 37.3 / 38.4 | 37.1 / 37.5 / 37.4 / 37.8 |
  | engine import ms | 64.7 / 64.9 / 61.8 / 56.5 | 69.4 / 67.2 / 69.9 / 66.7 |
  | own-block import ms | 66.8 / 66.9 / 62.7 / 56.3 | 76.2 / 71.6 / 76.8 / 71.4 |

  The import cut is exact (5-10 ms) and does not move the round: the import is beside the cycle. Merged.
  P3's bar (in the 5.0-5.2M band, twice) is met by the `main` legs of both pairs: four of four at
  5.06-5.12M, mean 5.084M, against 4.84-4.97M before the three fixes. Seven of eight legs of the round
  are past 5M. Open, none blocking: sealed_at is 37.1-37.8 ms against the tag's 36.6-36.7
  (root_leaves 7.3-9.0 ms, par_exec 28.5-30.0); forkchoice `syncing` answers are still twice the tag's
  count, cause unknown; S1 (hold it) continues with A/A legs on later merges.
