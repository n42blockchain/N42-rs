# Catch-up performance (P1): measured, and what bounds it

Branch `perf/p1-catchup`. Goal (owner): a node that is behind, or fresh from
genesis, pulls committed blocks by range and executes them fast enough that
the network is the only bottleneck -- verification, execution and
persistence well above 125 MB/s of block data (1 Gbit/s), on realistic
blocks. The real target is chain 94 (the N42 old main chain).

## 1. Targets

Chain 94 (numbers from gov5, 2026-11-26): 14.1M blocks, ~10 GB of block data.
gov5's replay v2 (full execution from genesis, no network) runs 6,910
blocks/s over the mostly-empty first 13.2M blocks (25.2M txs) and 224
blocks/s, ~40k tx/s, over the tx-heavy 13.2M-13.9M (128.7M txs): ~1.5-2 h
genesis to head, peak RSS ~29 GB.

| link | whole chain 94 (10 GB) moves in | per-block budget to stay network-bound |
| --- | --- | --- |
| 100 Mbit/s (12.5 MB/s) | ~14 min | 14.1M blocks in 14 min: ~60 us a block |
| 1 Gbit/s (125 MB/s) | ~80 s | ~6 us a block |
| 10 Gbit/s (1.25 GB/s) | ~8 s | <1 us a block |

So "network-bound" means a per-block fixed cost far below 1 ms on empty
blocks (well above 7k blocks/s) and execution well above 40k tx/s on heavy
ranges (1 Gbit/s of 118-byte transfers is ~1.06M tx/s).

## 2. The benchmark

`scripts/catchup-bench.sh` (with `catchup-sampler.py`, `catchup-report.py`):

- **Chain** (`genesis`, `produce`): the profile-1 V1 genesis
  (`testdata/profile1/gov5/V1/genesis_8s.json`) with `blockIntervalMs` 500,
  20,000 pre-funded flood senders and 100,000 pre-created recipients (1 wei,
  so a transfer is 21,000 gas under Amsterdam's EIP-8037 and touches a
  scattered account), four `profile1-round.sh` members (own EL each), and
  `tx_flood` phases: idle, 2k, 10k, 40k, idle, 20k, 40k tx/s, idle.
- **Leg** (`leg <name>`): member 3's EL and consensus store are wiped and
  re-initialised; members 0 and 1 restart and serve (two of four: no quorum,
  the chain stands still); member 3 starts and pulls the whole chain over the
  real path -- `h2_validator` range pull (`bodies_by_range/1`, pipeline,
  anchored import) -> Engine API `newPayload` + one forkchoice per batch ->
  reth engine tree -> EVM -> QMDB root -> persistence. The sampler records
  member 3's EL height every 0.5 s and the CPU of every member process; the
  report gives blocks/s, tx/s, MB/s overall and per block-size class (5 s
  windows classed by mean txs/block), the EL's per-block cycle and state-root
  time per class (its log), the engine metrics (`--metrics`), and the
  validator's `catch-up timing` line (fetch, verify, newPayload, forkchoice).
- Everything runs on one host (localhost links): the link is never the
  bound, so a leg measures the node's own ceiling.

The chain (`/data/n42-build/p1-catchup`, produced 2026-11-26 08:26-08:50 UTC):

| class (txs/block) | blocks | txs | MB | mean block |
| --- | ---: | ---: | ---: | ---: |
| near-empty (<50) | 518 | 0 | 0.5 | 1.0 KB |
| small (50-2k) | 478 | 479,632 | 57.1 | 119 KB |
| medium (2k-8k) | 512 | 2,632,545 | 314.7 | 615 KB |
| large (8k-16k) | 451 | 4,586,518 | 549.3 | 1.22 MB |
| full (>=16k; 287 at 22,857 = 480M gas) | 318 | 7,176,458 | 858.3 | 2.70 MB |
| **all** | **2,277** | **14,875,153** | **1,780** | 118 bytes/tx |

`perf` is not available to this user (`kernel.perf_event_paranoid` = 4), so
the breakdown comes from the node's own timers: the validator's
`catch-up timing` line, the EL's per-block log and its Prometheus metrics.

## 3. Baseline

Leg `base1` (2026-11-26 09:22 UTC, pre-merge tree 124f7f0b8; load average
0.2 at the start, so the box was otherwise quiet; member 3 unpinned on 254
CPUs):

| | |
| --- | --- |
| whole chain | 2,276 blocks in 254.6 s: **8.9 blocks/s, 58,426 tx/s, 7.0 MB/s** |
| CPU | EL 70.6 cores, validator 0.1 core |
| per class (5 s windows) | small 36 blocks/s, medium 13.6, large 9.6, full 3.9 blocks/s (87,666 tx/s) |
| EL cycle (p50) | near-empty 4.7 ms (root 2.2), small 23, medium 55, large 90, full 173 ms (root 13) |
| engine metrics (mean) | newPayload 54 ms, post-execution validation 9.1 ms, receipt-root task 35.6 ms, payload-convert 12.1 ms, persistence 194 ms per cycle (414 cycles, 80 s) |
| validator | fetch 429 s summed over 40 replies (max 21 s), verify 6.1 s (2.7 ms/block), newPayload 138 s, forkchoice 7.6 s |

The same leg on origin/main after the sync v1.1 merge (main1, 004ac1167)
reads the same: 8.7 blocks/s, 56,993 tx/s (section 4). The merge moved
Rust-to-Rust pulls onto `/2` without changing where the time goes.

Where the time went:

1. **Fetch, not execution.** The importer waited for blocks about half the
   pull: newPayload is 138 s of 254 s. Two causes:
   - the server read every block with `eth_getBlockByNumber(full=true)` over
     JSON, ~1 s per 128-block reply even for small blocks;
   - the pipeline sized a range's deadline by the blocks/s its peer last
     served at. Learnt on empty blocks (11,000 blocks/s) the deadline was the
     2 s floor for 128 full blocks; every such range missed it, was
     reassigned, its reply was dropped on arrival and asked again, and the
     peer backed off exponentially (log: one "missed its deadline" per range
     from block 513 on, back-offs up to 20 s).
2. **The EL's per-block fixed cost.** An empty block costs ~5.6 ms end to
   end at the tail of the pull: ~1.8 ms validation and execution, ~1.9 ms
   QMDB root (a root over the one account a reward withdrawal touches), ~1.6
   ms the validator's round trip (newPayload response, forkchoice, next
   newPayload). That is ~180 empty blocks/s, against the 7,000/s target.
3. **Verification** costs 2.7 ms a block (a header-QC BLS check and the
   profile-1 seal BLS check, both on the validator's loop): a ceiling of ~370
   blocks/s on its own, well below the target.
4. **CPU.** The EL used 70 cores to execute at most ~100k tx/s: reth's
   prewarm and the parallel root spin over the box's 254 CPUs.

## 4. Steps

Each step is measured as a whole leg on the same chain; box load is the
load average at leg start (the box was shared with a coordinator round at
times, see each row).

| step | leg | blocks/s | tx/s | MB/s | load at start | note |
| --- | --- | ---: | ---: | ---: | --- | --- |
| baseline (pre-merge) | base1 | 8.9 | 58,426 | 7.0 | 0.2 | fetch-bound half the time |
| 1. bulk range read (`n42Engine_blocksByRange`) | bulk1 | 10.8 | 72,956 | 8.7 | 121 (base1's tail) | fetch 429 s -> 13.5 s; one 30 s stall (below) |
| raw channel + direct import (fleet7 path) | direct1 | 0.5 | - | - | 122 | not usable for catch-up as is: every raw newPayload fails (status 3) and waits 6 s before JSON |

After the sync v1.1 merge (`68ef53ea5`: Rust peers now pull over
`bodies_by_range/2`), every leg below was rerun on the merged tree. From 11:28
UTC the coordinator's S1 round (5 devnet members, ~150 tx/s, light CPU) ran
beside them, with the coordinator's leave. "Load" is the 1-min load average at
leg start, which includes the tail of the previous leg. `pin64` started beside
a foreign `rustc` build.

| step | leg | blocks/s | tx/s | MB/s | EL cores | load at start | note |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| **baseline: origin/main 004ac1167** | main1 | **8.7** | 56,993 | 6.8 | 68 | 0.3 (+S1) | fetch 367 s summed, max reply 11 s |
| 1+2. bulk read (/1 and /2) + byte deadlines | br1 | 16.7 | 110,527 | 13.2 | 129 | 37 (+S1) | import-bound: newPayload 134.6 s of 134.6 s |
| 3. + lazy screening | brlazy1 | 16.5 | 109,280 | 13.1 | 129 | 172 (+S1) | verified 92 of 2,277 blocks; no gain while import bounds |
| 4. + full-buffer gap fix (`cd9fd328f`) | br2 | 16.7 | 108,988 | 13.0 | 128 | 10 (+S1) | no stall (brpin1, before it, stalled at block 1,271) |
| 5. EL on 32 CPUs (16 cores + siblings) | pin2e | **22.8** | 148,856 | 17.8 | 13 | 102 (+S1) | lazy off |
| 5. same, lazy on | pin2 | 22.7 | 148,305 | 17.8 | 13 | 26 (+S1) | |
| 5. EL on 16 CPUs | pin8 | 18.2 | 118,931 | 14.2 | 9 | 20 (+S1) | too few for full blocks |
| 5. EL on 64 CPUs | pin64 | 23.1 | 151,089 | 18.1 | 21 | 22 (+S1, rustc) | |

Per block class (5 s windows, blocks/s / tx/s):

| leg | small | medium | large | full (22,857 txs) |
| --- | --- | --- | --- | --- |
| main1 | 36 / 36,869 | 12.2 / 60,244 | 6.0 / 60,443 | 3.0 / 67,119 |
| br1 | 57 / 40,698 | 23.7 / 99,138 | 11.1 / 116,078 | 5.9 / 133,558 |
| pin2e | 130 / 100,642 | 34.2 / 142,152 | 14.4 / 153,417 | 6.9 / 156,473 |
| pin64 | 125 / 92,400 | 37.0 / 140,328 | 14.9 / 150,839 | 7.8 / 166,406 |

EL cycle per block, p50 (state root mean in brackets):

| leg | near-empty | small | medium | large | full |
| --- | --- | --- | --- | --- | --- |
| main1 | 4.76 ms (2.23) | 22.5 (7.1) | 54.8 (8.3) | 89.6 (10.3) | 170 (13.4) |
| br2 (254 CPUs) | 4.83 (2.25) | 22.2 (6.8) | 55.3 (8.4) | 89.1 (10.3) | 169 (13.4) |
| pin2e (32 CPUs) | **2.23 (0.35)** | 8.5 (1.0) | 34.7 (2.2) | 66.8 (3.2) | 143 (4.6) |
| pin64 (64 CPUs) | 2.47 (0.53) | 9.3 (1.6) | 34.7 (3.2) | 65.1 (4.8) | 135 (6.1) |

**Step 1: one bulk read per range** (`89cb428df`, `/2` in this branch after
the v1.1 merge). The EL gains `n42Engine_blocksByRange(start, count,
max_bytes)`: canonical blocks as raw RLP, read in one provider pass, capped
at 1,024 blocks and the byte bound. The validator's range server
(`bodies_by_range/1` and `/2`) takes a range from it when the EL offers the
method and falls back to the block-by-block read otherwise (an older EL
answers method-not-found once and is not asked again). Replies are byte for
byte what the old road serves (test
`a_bulk_range_read_serves_what_the_block_by_block_read_does`, /1 and /2,
bodies and headers only). The pipelined pull's fetch time fell from 429 s to
13.5 s (max reply 21 s -> 0.56 s).

bulk1 also stalled once: at block 1,269 the importer stood for 30 s and the
stall watchdog finished the pull serially (12 blocks/s). Step 4 found the
cause.

**Step 2: deadlines by bytes, late replies kept** (`970f464e0`). A range's
deadline is now its expected bytes (an EWMA of block size, times the count,
capped at a reply's bound) over the peer's byte rate, times the factor; a
reply that arrives after its deadline is taken when nothing holds its range
yet (what of it was still a gap is taken back, the peer's back-off cleared),
and a copy that arrives after it is skipped. Tests:
`a_slow_peers_range_is_reassigned_and_its_late_reply_taken_once`,
`a_late_reply_before_the_range_is_asked_again_is_taken_and_ends_the_gap`,
`the_deadline_follows_the_bytes_a_range_is_expected_to_carry`.

**Step 3: lazy screening** (`fe117b3e3`, `N42_SYNC_LAZY_VERIFY=1`, off by
default). An anchored pull verifies the header QC and the profile-1 seal of
a reply's last block (and of a block whenever the unanchored tail reaches
half of `MAX_TAIL_BLOCKS`), instead of every block's. The others are still
decoded, parent-linked to the block before them, checked against every
header rule except the seal, and held in the anchor buffer. Safety is the
same as under `enforce`:

- *What executes.* A pulled block reaches `newPayload` only when a verified
  commit-QC anchor at or above it, parent-linked down to it through blocks
  this pull holds, authenticates it -- the rule every pulled block already
  follows (`sync_anchor.rs`). Lazy screening skips checks on blocks that
  would be authenticated by that descendant chain anyway; it adds no road to
  execution.
- *Why the skipped checks are redundant.* A commit QC on block N is 2f+1
  signatures over N's hash; N's hash commits to its parent hash, and so on
  down. Under at most f faults, the chain a verified commit QC fixes is the
  committed chain, so every ancestor's own QC and seal are implied by it.
  The seal and QC of a block below a verified anchor carry no information
  the anchor does not.
- *A forger.* A forged run never anchors: its blocks wait in the buffer for
  a QC no forger can produce, the buffer is bounded (`MAX_TAIL_BLOCKS`,
  bytes), and the reply's last block -- always verified -- fails, which
  excludes the peer exactly as before. A forged block cannot be executed
  ahead of its anchor (tests
  `lazy_screening_executes_nothing_a_forger_served`, forged from block 150
  and from block 2, beside an honest peer; and
  `lazy_screening_executes_the_same_chain_verifying_a_fraction`, serial and
  pipelined, verifying an eighth of the blocks or fewer).
- *Blame.* A block that fails a later check still blames the peer whose
  reply carried it; the pull goes on with the others.

What it gives up: a forger is detected at the end of its reply rather than at
its first forged block -- up to one reply of wasted bandwidth, never wasted
execution.

Measured: verification falls from 6.2-6.5 s to 1.2-1.5 s a pull (92 of 2,277
blocks checked), but the leg does not get faster (brlazy1 16.5 vs br1 16.7,
pin2 22.7 vs pin2e 22.8): verification runs beside the importer, not in
front of it, and at 17-23 blocks/s the importer is the bound. It matters once
the EL passes ~350 empty blocks/s (eager screening costs 2.7 ms a block on the
validator's loop). **It stays off by default** until the safety argument above
has been reviewed.

**Step 4: a full buffer still asks for the gap below it** (`cd9fd328f`). Two
legs (bulk1, and brpin1 on the step-2 tree) stopped at block ~1,270 with
"pulled blocks no verified anchor covers are left unexecuted held=1". The
pipeline stopped assigning any range, gaps included, once its ready buffer held
`MAX_READY_BYTES` (256 MiB, ~95 full blocks). A range below the buffer came
back short. Its rest became a gap that delivery waited on, and the buffer,
full of ranges above the gap, could not drain: a deadlock, which the 30 s
watchdog broke by falling back to the serial pull. A gap below everything the
buffer holds is now asked for whatever the buffer's size (test
`a_full_buffer_still_asks_for_the_gap_delivery_waits_on`). Steps 1-2 hit it
more often because ranges of full blocks now arrive faster than the importer
drains them.

**Step 5: the EL on fewer CPUs** (bench knob `CB_CPUS`, no code change). On
this box's 254 CPUs the EL burned 128 cores to execute ~110k tx/s, and an
empty block's QMDB root took 2.2 ms. Pinned to 32 CPUs it uses 13 cores, the
root of an empty block takes 0.35 ms, the empty-block cycle halves (4.8 ->
2.2 ms), small blocks run 2.6x faster, and full blocks 18% faster. reth's and
QMDB's pools size themselves to the machine and then spend their time handing
tiny tasks across 254 threads. 64 CPUs is no better than 32 on empty blocks
and slightly better on full ones; 16 CPUs is too few for full blocks.

**Step 6: batch import of a committed range** (`n42Engine_importRange`,
`bin/n42/src/catchup_import.rs`; validator side `N42_SYNC_BATCH_IMPORT=1`,
off by default). The validator's pulled-block importer hands every queued
block of one pull generation (up to 256) to the EL in one call instead of one
`newPayload` each. The EL converts the payloads as `newPayload` does, then for
each block, in order:

1. checks it against the parent: the same header, pre-execution and body
   rules the engine uses (`validate_header`, `validate_header_against_parent`,
   `validate_block_pre_execution_with_tx_root`), with one difference given
   below;
2. executes it on one EVM cache carried across the run (no per-block
   prewarm, no state-cache rebuild, no per-block engine task fan-out);
3. checks its receipts, gas and requests (`validate_block_post_execution`);
4. computes its QMDB root and compares it with the header's state root
   (`validate_block_operations`, the follower import's check);
5. once every block of the run has passed, hands the executed blocks to the
   engine's tree in order (`executed_inserts`, the fleet7 follower's road),
   so persistence and history are what they are for any block.

One forkchoice at the end moves the head to the last block. The call is all
or nothing: the head moves only when every block of the run passed, the last
one with the full rules. The run stops at the first block that fails any check
and reports it as `refused`, with nothing imported and nothing handed to the
tree. The validator then imports the whole run by `newPayload`, so the
verdict on a bad block is always the per-block path's. A run whose first
parent is not the EL's head, a chain under deferred execution, or an engine
that is not running answers `unavailable`, and the validator goes block by
block.

Two deviations from the first sketch (section 7, item 1):

- *The root is still per block, not one per batch.* The QMDB forest records a
  version per block, and history, persistence and the engine tree are keyed
  by it. Pinned, an empty block's root costs 0.35 ms. A mismatch is localised
  to its block when it happens, with no re-execution pass.
- *Persistence is the engine's.* The executed blocks enter the tree like any
  other block and are persisted at the engine's threshold, not once per call.

**The condition for ever turning it on by default.** A batch is imported
only after the BLS check of a commit QC at or above its last block has
passed, and only when the batch is parent-linked to that QC's block and to the
EL's head. Execution may start speculatively, but nothing becomes canonical,
is persisted or is served, and no forkchoice moves, before that. A failed
check or a root mismatch leaves no trace in the EL. Where the code holds it:

- *QC first.* The validator spawns the batched importer only under
  `N42_SYNC_ANCHOR=enforce` (`sync_batch_import && sync_anchor_mode ==
  Enforce` in `service.rs`; under `observe` or `off` it imports block by
  block). Under enforce, a pulled block is queued for the importer only when
  a commit-domain QC, verified under the set of its exact view, names a block
  at or above it. The anchor buffer is parent-linked from that block down to
  the executed head (`buffer_pulled`, `sync_anchor.rs`). Every block of a batch
  is therefore covered by a verified commit QC before the EL sees it.
- *Linked to our head.* The EL refuses a run whose first parent is not its
  canonical head (`unavailable`), and checks each block's parent link.
- *No trace on failure.* The EL executes the whole run on a private cache.
  It hands the executed blocks to the engine's tree only after every block
  has passed, the last one also with its QC and seal. Only then does one
  forkchoice move the head. A refused run hands over nothing, moves no head
  and persists nothing. A block whose QMDB root does not match is not filed
  in the forest. Blocks of a failed run whose roots did match stay as
  in-memory, non-canonical forest entries, as a fork block's do under
  `newPayload`, and are never persisted.
- *Test.* `a_batch_whose_top_qc_is_forged_leaves_the_el_head_and_state_unchanged`
  (a chain whose QCs are forged from block 2, no honest peer, batch import
  and lazy screening on): no run, no block and no forkchoice reaches the EL.
  `batch_import_runs_the_honest_chain_and_nothing_a_forger_served` (a forger
  beside an honest peer, eager and lazy): the honest chain goes in runs, in
  order, and no forged block is ever in one.

**Safety.** The live path does not change: `newPayload`, forkchoice, the
builder and the follower import are not touched. The method is on the
JWT-authenticated Engine API, and only the validator's catch-up importer calls
it. That importer only ever holds blocks under a verified commit-QC anchor
(step 3), and it stops calling it once the pull is done and the loop is at the
head. The one check the EL drops is on every block *but the last of a run*:
the profile-1 header's two BLS checks, the embedded QC and the proposer's
seal. The last block gets the full rule set (`HotStuffConsensus::
without_header_signatures` is the same rules with the proposer schedule taken
out). The EL's own guarantee is therefore at least what `newPayload` gives
block by block, without trusting the caller:

- The last block's embedded QC is 2f+1 signatures over its parent's hash. That
  hash commits to the grandparent's, and so on down to the run's first block.
  So every block below the last is quorum-certified through the hash chain,
  the same way a block's own embedded QC certifies only its parent under
  `newPayload`.
- The last block's seal is checked as `newPayload` checks it.
- A forged block inside the run therefore cannot match the hash chain the
  last block's verified QC fixes. A run with a forged tail fails at its last
  block, and nothing of it reaches the engine's tree.
- Everything else -- execution, receipts, gas, requests, the state root
  against the QMDB root, the parent link, timestamps, the committee link --
  is checked for every block, as before.

`N42_CATCHUP_IMPORT=0` withdraws the method on the EL (it answers `null`, and
the validator stops asking). Tests: `batched_importer_*` (one call for a
queued run; block by block without the method; a refused block gets the
per-block verdict), `import_range_is_null_when_not_offered_*`,
`an_import_range_answer_is_read`; end to end, the catch-up legs below, which
check the joiner's head hash against the servers'.

## 5. Throughput against link speed

Best configuration measured (pin2e: branch, EL on 32 CPUs) against what each
link would deliver. Empty blocks are ~1 KB here and ~710 bytes on average on
chain 94 (10 GB / 14.1M blocks).

| shape | node today (pin2e) | 100 Mbit/s | 1 Gbit/s | 10 Gbit/s |
| --- | --- | --- | --- | --- |
| full blocks (2.7 MB, 22,857 transfers) | 6.9 blocks/s, 18.7 MB/s, 156k tx/s | 4.6 blocks/s: **network-bound** (1.5x headroom) | 46 blocks/s: node 15% of the link | 463 blocks/s: 1.5% |
| near-empty blocks (~1 KB) | ~450 blocks/s (2.23 ms) | ~12,000 blocks/s: node 3.7% of the link | ~120,000/s: 0.4% | 0.04% |
| whole bench chain (1.78 GB) | 100 s, 17.8 MB/s | 142 s: **network-bound** | 14 s | 1.4 s |
| baseline main1, same chain | 261 s, 6.8 MB/s | 142 s: node-bound | | |

So on transaction-heavy blocks the node now outruns a 100 Mbit/s link (it did
not: main1 reads 6.8 MB/s, half the link). On empty blocks it is 27x short of
even 100 Mbit/s. That is the chain-94 problem, because 13.2M of its blocks are
near-empty.

## 6. Chain 94 estimate

A model from the measured per-block cost (C, the empty-block cycle) plus the
per-transaction cost (t, the full-block cycle over its 22,857 transfers).
Chain 94's heavy range is not all transfers, so t is a floor there.

| | C | t | 13.2M near-empty blocks | 0.7M heavy blocks, 128.7M txs | rest (~0.2M blocks, ~empty) | **total** |
| --- | --- | --- | --- | --- | --- | --- |
| main1 (origin/main) | 4.76 ms | 7.4 us | 17.5 h | 0.9 h + 0.3 h | 0.3 h | **~19 h** |
| pin2e (this branch, 32 CPUs) | 2.23 ms | 6.3 us | 8.2 h | 0.4 h + 0.2 h | 0.1 h | **~9 h** |
| gov5 replay v2 (no network) | 0.145 ms | 25 us/tx at 224 blocks/s | 0.5 h | ~0.9 h | | **1.5-2 h** |
| 100 Mbit/s link, 10 GB | | | | | | 14 min |
| 1 Gbit/s link | | | | | | 80 s |

On chain 94 the heavy range is not the problem: we run ~150k tx/s on transfers
against gov5's ~40k tx/s there. The empty range is: 2.23 ms a block against
gov5's 0.145 ms, 15x. Being network-bound at 1 Gbit/s on chain 94 needs an
empty block below ~6 us, 370x the per-block cost we have now. That cannot come
from one newPayload per block; it needs the batch import below.

## 7. What remains the bottleneck, and next steps

The importer is the bound in every leg after step 2: newPayload time equals
the pull's wall time (pin2e: 99.8 s of 99.9 s). Fetch (one bulk read per
range, deadlines by bytes, replies of 128 full blocks in at most 4.4 s on
loopback) and verification (off the import path; lazy screening when it
matters) are no longer on the critical path.

What one block costs in the EL (unpinned tail of a pull, empty blocks, from
the EL log): ~1.8 ms validation and execution, ~1.9 ms QMDB root (0.35 ms on 32
CPUs), ~1.6 ms the validator's round trip (newPayload reply, forkchoice every
batch, next newPayload). On full blocks the engine's per-block tasks dominate
(engine metrics, means over a pull): prewarm 52 ms, receipt-root task 35 ms,
payload-convert 12 ms, post-execution validation 9 ms, persistence 194 ms
per cycle of ~5.5 blocks.

Next steps, largest first:

1. **Batch import for committed ranges** (an Engine extension such as
   `n42Engine_importRange(blocks)`). It would execute a run of
   anchor-authenticated blocks in one call and one state transition, check
   the QMDB root at the batch boundary (and the per-block header roots
   lazily), and persist once per batch. A root mismatch at the boundary is
   localised by re-executing the batch block by block from its parent state.
   This is gov5 replay v2's shape, and the only road to <1 ms per empty
   block. It reuses the fleet7 follower import (`follower_import.rs`,
   grafted state, parallel root) but not its raw channel: the direct-import
   path as it stands (`N42_FOLLOWER_DIRECT_IMPORT=1`, leg direct1) fails
   every raw newPayload with status 3 during catch-up and falls back to JSON
   after a 6 s wait, 0.5 blocks/s.
2. **Size the EL's pools for the work, not the machine** (step 5): 2x on
   small blocks and a 6x cheaper empty-block root, from a pin. Make it a
   setting for sync nodes (rayon / QMDB worker caps), or pin the catch-up EL
   as the bench does.
3. **Engine work that catch-up does not need**: prewarming (the
   transactions of a committed block are known and run in order),
   per-block receipt-root tasks, and the persistence threshold (larger
   batches while far behind).
4. **Lazy screening on by default** once the safety argument in step 3 is
   reviewed and the EL passes ~350 blocks/s.
5. **More peers, larger ranges**: with two serving peers on loopback, fetch
   was never the bound after step 1. On real links with batch import it will
   be, and the scheduler already spreads ranges across up to `MAX_SLOTS` (4)
   peers and asks over `/2` when the peer speaks it.

Reproduce: `scripts/catchup-bench.sh produce` (once, ~25 min), then
`CB_BIN=<dir with n42 and examples/h2_validator> scripts/catchup-bench.sh leg <name>`
(`CB_CPUS=0-15,128-143 CB_SERVER_CPUS=64-95,192-223` for step 5,
`CB_ENV=N42_SYNC_LAZY_VERIFY=1` for lazy screening). Legs and reports:
`/data/n42-build/p1-catchup/legs/<name>/report.txt`.
