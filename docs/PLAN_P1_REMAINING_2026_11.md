# Profile 1: everything not yet closed, and the order to close it (2026-11-26)

Owner direction (2026-11-26): run the `commit_qc/1` server round as early as possible, record every item
that cannot be closed yet, and work through them step by step. Status of the standard itself:
`docs/MIXED_PRODUCTION_STATUS.md` (top summary). This file is the work list; each item names who acts,
what "done" means, and its state. Update the state column as items move; keep the order unless an item
blocks.

Releases at the time of writing: gov5 main 5464ee6e, n42-rs main e9f15edc4, n42-26 main 80ecf52.
Releases at the 2026-11-27 review: gov5 main 08ecf671 (AM33, AM34, AM35, txpool leak fix), n42-rs main
d8a5e54d2 (code; docs 1f6ad73bb), n42-26 main b64f650 (AM33, late equivocation; PR #51/#53/#55 open).

## A. v1.1 coverage (the standard)

| # | Item | Who | Done when | State |
| --- | --- | --- | --- | --- |
| A1 | n42-rs as a `commit_qc/1` server to another client in a mixed round | n42-rs + gov5 + n42-26 | round Q1 (T0 2026-11-26 20:45 EST): gov5 serving off, n42-26 v3 down, gov5 node4 rejoins from genesis; its tail anchored by n42-rs v2's `commit_qc/1`; headers equal | DONE: round Q1 (0..203 equal); n42-26 v3 anchored on n42-rs v2 `commit_qc/1` #56 |
| A2 | Declare v1.1 closed in the status doc and the standard's V1_RC table | n42-rs (standard owner by delegation) | A1 passed; summary + release commits recorded | DONE 2026-11-26 21:20 (status doc top) |

## B. Performance targets (AM31, not gate criteria; idle-time work)

| # | Item | Who | Done when | State |
| --- | --- | --- | --- | --- |
| B1 | n42-rs catch-up bound by the network, not execution | n42-rs | empty-chain pull at or above link rate on a 100 Mbit/s budget (today ~47 Mbit/s); the floor is one QMDB root per block (~0.12 ms) | small apply implemented on design/p1-run-root (root 85-103 -> 11-12 us per empty block; per-run root rejected, docs/P1_RUN_ROOT_DESIGN.md); next: paired empty-chain leg, then a mixed round, then merge |
| B2 | Batch import for blocks over 16 KiB of transactions | n42-rs | range import re-measured against the engine path on heavy blocks since the step-3 root worker; cap raised if it wins (at most ~14 % on 4b-R's pull) | in progress (catch-up agent, perf/p1-catchup) |
| B3 | Estimate and, if feasible, measure a chain-94-sized catch-up | n42-rs | blocks/s, MB/s, peak RSS and disk on a long heavy history (S1-like or the `gov5-work/p1scale` state) with current main | in progress (catch-up agent, after B2) |
| B4 | gov5 catch-up speed (S1: 25.7 blk/s) and catch-up peak (4 GB) | gov5 | gov5's own measurement against S1 | gov5 main adfa43fc includes perf/p1-catchup-v2: 44 vs 35 blk/s, anon peak 0.6 vs 1.5 GB (re-measure after AM35 per F2) |
| B5 | n42-26 steady-load memory (1.1 GB at 40 min, rising slowly) and catch-up | n42-26 | plateau shown over >= 90 min at 150 tx/s | M90b: n42-26 337 -> 1,804 MiB in 96 min, caps not reached; next a >= 6.5 h round. The caps are PR #51, which M3d and M90b ran but main does not carry: merge #51 before the 6.5 h round so the round measures a release |
| B6 | n42-rs EL peak during heavy catch-up: RocksDB memtables (~480 MB) | n42-rs | either a smaller budget that does not stall (upstream write stall + pinned memtables; `N42_ROCKSDB_WRITE_BUFFER_STALL`) or a documented decision to keep 4 GiB | cause found: OptimisticTransactionDB keeps 2x128 MiB of flushed memtables per CF as conflict history (never used); knob N42_ROCKSDB_MEMTABLE_MB on perf/p1-memory-2; heavy-catch-up legs queued after 00:32 EST, then profile-1 default |
| B7 | n42-rs steady-state RSS re-measured with the RPC cache cap and QMDB entry file (memory step 2) | n42-rs | one >= 60 min 150 tx/s leg | M90b: EL 181 -> 682 MiB in 92 min (2.5 MiB/min at the end, slowing), validator flat 54 MiB; not flat yet: >= 6.5 h round with the B6 knob |

## C. Explorer (testnet, remote machine)

| # | Item | Who | Done when | State |
| --- | --- | --- | --- | --- |
| C1 | Apply the explorer node settings on the remote machine (`docs/EXPLORER_RPC_PERF.md` section 7: `N42_RPC_BATCH_CONCURRENCY=16`, `--rpc.max-response-size 1024`, `--db.rocksdb-block-cache-size 1GB`, debug/trace APIs, ws) and the Blockscout side (internal-tx concurrency/batch or `ETHEREUM_JSONRPC_GETH_TRACE_BY_BLOCK=true`) | owner / operator of that machine | Blockscout's indexer lag measured before and after | waiting on access |
| C2 | Re-run `scripts/explorer-load.py` against a node on current main with real RTT | n42-rs | numbers for the remote hop recorded | after C1 |

## D. Moved to v1.2 by AM31

| # | Item | Who | State |
| --- | --- | --- | --- |
| D1 | Peer-to-peer state sync (`qmdb_*`, `code_by_hash`) | all three | feasibility notes exist (`docs/P1_STATESYNC_FEASIBILITY_n42rs.md`, gov5's, n42-26's HANDOFF post) |
| D2 | Mixed equivocation round | all three | DONE: mixed round M3d (2026-11-26 22:00-22:40 EST) passed, see status doc |

## E. Open since v1 (status doc, §7 and risks)

| # | Item | Who | State |
| --- | --- | --- | --- |
| E1 | gov5 proposal-equivocation detection (M3d) | gov5 | DONE (gov5 b5cf49a7, ef2f6bb0); proven in M3d |
| E2 | §7: validator-set changes (E2), B11 follower rule, kept-tail bounds, vectors V2/V5/V7/V9, tenure > 1, epoch-boundary TCs, a negative leader | all three | vectors published 11-26; n42-rs passes V2, V7, V9 (2 GossipSub fixes), AM33 (main d8a5e54d2); gov5 generated them and implements AM34 (main 08ecf671); n42-26 has AM33 (b64f650) and AM34 item 6 (e5932de) but no V2/V7/V9 tests in its tree and no AM34 items 3-5 yet (see F1) |
| E3 | Liveness risk: k consecutive absent leaders stall ~24 + 48 + 96·(k−2) s | standard | DONE: gate 5e (2026-11-27) six consecutive absent leaders cost 224 s (216 + slot) vs 464 s in 5d, headers equal on 8 dumps; implemented in all three |
| E4 | Whole-set restart from the committed head: gov5 found (2d2c9690) that a set restarted together never voted again, because recovery did not count the committed head as imported. Check n42-rs (profile 1, import-gated votes): all-Rust devnet, stop every member, restart, chain must continue | n42-rs | graceful whole-set restart PASSES; whole-set SIGKILL HALTS for good (committed blocks only in EL memory, threshold 8); with persistence threshold 0 it recovers. Fix = AM35, tracked as E5-E9 |
| E5 | AM35 adopted: status PROPOSED -> ADOPTED in the standard | owner | DONE 2026-11-27: AM35 ADOPTED by the owner (standard heading updated) |
| E6 | AM35 in gov5 | gov5 | DONE: gov5 main adfa43fc = 08ecf671 + fix/p1-am35-pitfalls (durable-only persisted lock, hash-checked recovery and leader parent gate, N42_PROPOSE_BEFORE_WRITE refused); binary n42-p1.main-adfa43fc for E9 and the long memory round |
| E7 | AM35 in n42-rs | n42-rs | owner pre-approved (2026-11-27, widened): integ/p1-am35-am36 at 7e9e3c165 (AM35 fix/p1-durable-commit-vote 297b634bd + AM36 feat/p1-am36-validate-forward 398bf9a8f) merges into main once E9 passes with exactly this commit, no substantial change after; all-Rust gate 15/15 recovered, old main halts; 150 tx/s: commit-vote p50 5.0 / p99 13.1 ms |
| E8 | AM35 in n42-26 (option A, consensus-dir block journal) | n42-26 | PR #57 (72facd3): local whole-set kill -9 15/15 recovered (5 after commit, 5 on the leader release line, 5 on a follower release line with every member locked on B: B replayed from the journal, ~30 s); control on main halts for good. PR #58 (AM36, F1) refuses altSigTx/frameBlocks on profile 1. E9 lesson: trigger window kills on a follower release, match message text only |
| E9 | AM35 gate: whole-set SIGKILL of a mixed set under load, 5 kills right after a commit and 5 between a PrepareQC and its commit QC | n42-rs (tool) + all three | trigger-file contract agreed (watcher writes am35-trigger/<round>-<n>; each client kills its own); trigger lines in from gov5 (T1 "hotstuff: block committed", T2 "two-phase vote: casting held commit vote") and n42-26 (T1 N42_COMMIT_STATE Committed, T2 n42::am35 "commit vote released after durable lock"); n42-rs watcher + killer being written by the AM35 agent |

## F. Follow-ups from the 2026-11-27 review

| # | Item | Who | State |
| --- | --- | --- | --- |
| F4 | AM36 validate-then-forward in all three | all three | AM36 ADOPTED by the owner 2026-11-27. n42-26 PR #58 (10952c3); gov5 fix/p1-validate-then-forward (78c76e2e); n42-rs in integ/p1-am35-am36 7e9e3c165. Mixed smk (02:50, n42-rs not on AM36): headers 0..168 equal on 7 dumps, 0 Reject anywhere; smk2 (03:25, all three on AM36) running |
| F1 | n42-26 catches up on v1.2: V2 (EIP-7708 transfer log in receipts), V7 (leader schedule, no 2^64-1 row), V9 (GossipSub), AM34 items 3-5 (refuse QC/TC for view 2^64-1, G2 topics only, no cohort topics) | n42-26 | open |
| F2 | Re-baseline B1-B7 after AM35 merges on all three: AM35 adds a durable write on the commit-vote path, so catch-up and memory numbers taken before it do not carry over. Merge the catch-up branches (rs perf/p1-catchup, design/p1-run-root, perf/p1-memory-2; gov5 perf/p1-catchup; n42-26 PR #53, #55) onto post-AM35 main | each client | open |
| F3 | Host: /data at 98% (147 GB free, scripts refuse under 50 GB). Free build caches and merged worktrees before the 6.5 h round and B3 | owner + each session | 11-27 01:20: n42-rs freed wt-docs/target, target-g5, target-g6, target-g6t (~174 GB); /data 740 GB free |

## Closed while writing this list

- gov5 R3-E2 (`fix/unchanged-account-no-op`): merged into gov5 main via b5d24722 (2026-11-08); the
  branch name was a local ref only. Profile 1 forbids its gate (`unchangedAccountNoOpTime`).
- gov5 steady-load memory fix and explorer RPC work: gov5 main 5464ee6e.
- n42-26 PR #50 (pre-import check speed): n42-26 main 80ecf52.
- n42-rs clippy gate after the catch-up merges: e9f15edc4.

## Order

A1 -> A2 first (in flight). Then, on an idle box: B7 (one long leg, cheap), B2 (re-measure, may be a
one-line change), B3, B1 (design first). B6 only if B1-B3 leave memory as the limit. C waits on access.
D and E are v1.2 planning: D2's injector and E2's vectors are the first concrete steps.

Revised order (2026-11-27): E5 and E8's commit first (no work lost), then E7 (with its latency leg) and
E8 merged, the E9 tool, the E9 gate. Then F3 and the >= 6.5 h memory round on three mains that all carry
AM35 (B5-B7, n42-26 PR #51 merged), then F2. F1 runs in parallel on n42-26.
