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
| P2 | If code: find the step | natives at the merge points between 47b8180ab and `main` (maturity audit 8ff447481, compaction c992a5ee4, N42Header b87fa2884, reth v2.9.0 6703c576f, v2.10.0, Amsterdam step 235076649, today), halving by pairs | the step that separates >= 3% twice | waits for P1 |
| P3 | Fix or gate the step | per finding; a knob in the X22 profile if the cost buys something `main` needs | pair back in the 5.0-5.2M band, twice | waits for P2 |
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
