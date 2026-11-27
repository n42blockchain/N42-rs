# Profile 1: everything not yet closed, and the order to close it (2026-11-26)

Owner direction (2026-11-26): run the `commit_qc/1` server round as early as possible, record every item
that cannot be closed yet, and work through them step by step. Status of the standard itself:
`docs/MIXED_PRODUCTION_STATUS.md` (top summary). This file is the work list; each item names who acts,
what "done" means, and its state. Update the state column as items move; keep the order unless an item
blocks.

Releases at the time of writing: gov5 main 5464ee6e, n42-rs main e9f15edc4, n42-26 main 80ecf52.

## A. v1.1 coverage (the standard)

| # | Item | Who | Done when | State |
| --- | --- | --- | --- | --- |
| A1 | n42-rs as a `commit_qc/1` server to another client in a mixed round | n42-rs + gov5 + n42-26 | round Q1 (T0 2026-11-26 20:45 EST): gov5 serving off, n42-26 v3 down, gov5 node4 rejoins from genesis; its tail anchored by n42-rs v2's `commit_qc/1`; headers equal | running |
| A2 | Declare v1.1 closed in the status doc and the standard's V1_RC table | n42-rs (standard owner by delegation) | A1 passed; summary + release commits recorded | after A1 |

## B. Performance targets (AM31, not gate criteria; idle-time work)

| # | Item | Who | Done when | State |
| --- | --- | --- | --- | --- |
| B1 | n42-rs catch-up bound by the network, not execution | n42-rs | empty-chain pull at or above link rate on a 100 Mbit/s budget (today ~47 Mbit/s); the floor is one QMDB root per block (~0.12 ms) | in progress: design agent (branch design/p1-run-root, doc docs/P1_RUN_ROOT_DESIGN.md) |
| B2 | Batch import for blocks over 16 KiB of transactions | n42-rs | range import re-measured against the engine path on heavy blocks since the step-3 root worker; cap raised if it wins (at most ~14 % on 4b-R's pull) | in progress (catch-up agent, perf/p1-catchup) |
| B3 | Estimate and, if feasible, measure a chain-94-sized catch-up | n42-rs | blocks/s, MB/s, peak RSS and disk on a long heavy history (S1-like or the `gov5-work/p1scale` state) with current main | in progress (catch-up agent, after B2) |
| B4 | gov5 catch-up speed (S1: 25.7 blk/s) and catch-up peak (4 GB) | gov5 | gov5's own measurement against S1 | gov5 agent on perf/p1-catchup; first numbers 2026-11-27 |
| B5 | n42-26 steady-load memory (1.1 GB at 40 min, rising slowly) and catch-up | n42-26 | plateau shown over >= 90 min at 150 tx/s | n42-26 to schedule |
| B6 | n42-rs EL peak during heavy catch-up: RocksDB memtables (~480 MB) | n42-rs | either a smaller budget that does not stall (upstream write stall + pinned memtables; `N42_ROCKSDB_WRITE_BUFFER_STALL`) or a documented decision to keep 4 GiB | in progress (memory agent, perf/p1-memory-2, after B7) |
| B7 | n42-rs steady-state RSS re-measured with the RPC cache cap and QMDB entry file (memory step 2) | n42-rs | one >= 60 min 150 tx/s leg | in progress (memory agent, perf/p1-memory-2); 4b-R2 read ~520 MiB at 28 min |

## C. Explorer (testnet, remote machine)

| # | Item | Who | Done when | State |
| --- | --- | --- | --- | --- |
| C1 | Apply the explorer node settings on the remote machine (`docs/EXPLORER_RPC_PERF.md` section 7: `N42_RPC_BATCH_CONCURRENCY=16`, `--rpc.max-response-size 1024`, `--db.rocksdb-block-cache-size 1GB`, debug/trace APIs, ws) and the Blockscout side (internal-tx concurrency/batch or `ETHEREUM_JSONRPC_GETH_TRACE_BY_BLOCK=true`) | owner / operator of that machine | Blockscout's indexer lag measured before and after | waiting on access |
| C2 | Re-run `scripts/explorer-load.py` against a node on current main with real RTT | n42-rs | numbers for the remote hop recorded | after C1 |

## D. Moved to v1.2 by AM31

| # | Item | Who | State |
| --- | --- | --- | --- |
| D1 | Peer-to-peer state sync (`qmdb_*`, `code_by_hash`) | all three | feasibility notes exist (`docs/P1_STATESYNC_FEASIBILITY_n42rs.md`, gov5's, n42-26's HANDOFF post) |
| D2 | Mixed equivocation round | all three | in progress: n42-rs test-only injector (branch feat/p1-equivocation-injector); gov5 agrees one injector is enough |

## E. Open since v1 (status doc, §7 and risks)

| # | Item | Who | State |
| --- | --- | --- | --- |
| E1 | gov5 proposal-equivocation detection (M3d) | gov5 | DONE in gov5 main since 2026-11-25 (b5cf49a7, 5eb5aba9); only the mixed M3d round remains, after D2 |
| E2 | §7: validator-set changes (E2), B11 follower rule, kept-tail bounds, vectors V2/V5/V7/V9, tenure > 1, epoch-boundary TCs, a negative leader | all three | vectors V2, V7, V9 and the V5 additions (B4 equal timestamps, B13 state gas, AM25 requests) from gov5 by 2026-11-27 18:00 EST; then all three run them |
| E3 | Liveness risk: k consecutive absent leaders stall ~24 + 48 + 96·(k−2) s | standard | AM33 draft circulated (docs/AM33_DRAFT_CONSECUTIVE_ABSENT_LEADERS.md: double once per f+1 TCs); awaiting gov5 / n42-26 review |

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
