# Architecture toward 5M tx/s

Design survey, 2026-10-17. Nothing built or run; figures are quotations of the docs cited (BD = BREAKTHROUGH_DESIGN.md
section numbers). Starting point: X17, seven validators on one shared execution layer (E=1), one 128-core EPYC 9B45
(256 threads, one NUMA node, 136 GB), 200k-transfer blocks at 30 ms pacing, storm-free drain 4.60-4.75M/s (records:
round 424.0M, windows 4.747 / 4.800 / 4.753M, BD 10.159). 5.0M/s at 200k is a **40.0 ms mean proposal gap**; X17 reads
42.3-43.5. Every knob and small-code lever is spent (BD 10.152-10.159): single cuts are worth <= 1.5 ms, and the two
structural levers tried (two blocks ahead, the five-block vote window) lose on this box. This note asks what architecture
changes are left, what they would buy, what they cost in protocol terms, and in which order to do them.

## 1. What sets the gap today

`gap = start delay + sealed_at >= max(builder, fields two-cycle, gate loop, root cycle, tick) + jitter` (AFTER_MERGE_CUT 6).

| floor | definition | value (X17, ms) | source |
| --- | --- | --- | --- |
| builder | seal -> N-1's bundle + `par_run` + tail | 35.7-37.5 | AFTER_MERGE_CUT 6 |
| fields two-cycle | seal(N) >= fields(N-2) (carried depth 2): (seal -> fields + tail) / 2 | 33.0-37.1 | AFTER_MERGE_CUT 5 |
| gate loop | start(N) >= prop(N-2), prop(N) >= answer(N-4): (sealed_at + L + c) / 6, c ~13 | 36.7-39.6 | AFTER_MERGE_CUT 2, 6 |
| vote window | (A + c) / 4, A = proposal -> answer 145-155 | 40.0-42.5 | BUILD_AHEAD_RESULTS 4-5 |
| root cycle | gated root + hand-over (root busy 0.59-0.69 of the gap) | 28.8-32.6 | AFTER_MERGE_CUT 5 |
| tick | pacing + slack | 30 + 1.6 | BUILD_AHEAD_RESULTS 4 |
| jitter above the highest | p90 of `par_run` 36, of seal -> fields 92 | ~5-6 | AFTER_MERGE_CUT 1 |

Three floors sit within 3 ms of each other, so removing one moves the gap into the next (10.155-10.157: the parallel merge
cut L by 11 and the gap by 0.2; the child on the parent output removed its 8 ms wait and read as the controls). The long
gaps (2.2-3.8 s of every 30 s over 80 ms) are 96-98% vote-bound and echo at 6-7 blocks: one late answer costs twice through
the 6-block loop (LONG_GAP_TAIL 1, 4). Two structural facts follow: (a) **L = seal -> answer (166-190 ms) is the pacing
term**, through the vote rule; (b) what kills deeper pipelines on this box is the cost of each block in flight (a second
build costs 3-4 ms of seal; the five-block window costs 5 ms of seal, BD 10.149, 10.153, 10.159), not the rule itself.

## 2. Per-component ceilings on this box (each alone binding, 200k blocks)

| component | per-block cost now (ms) | ceiling alone (M tx/s) | growth / note | source |
| --- | --- | --- | --- | --- |
| ingest (flood offer) | set rate 6M/s; queue 2.3-2.4M at every build | >= 6.0 | Ed25519 batch verify; above 4.8M unmeasured | BD 10.157, LEG_SPREAD 1 |
| tx-queue lanes lock | duty 79-97% at 4.4-4.7M/s | **~5.0-5.6** (duty -> 100%) | drain ~51% of duty; drain runs + lean pruner adopted | LANES_LOCK 1, BD 10.149-10.153 |
| build, CPU only | `par_exec` floor 12-13 + imbalance 4-5 | 11-12 | memory-latency bound: dependent probes | X15_BUILD_NEXT 1, BD 10.124 |
| build, own work | pre-exec + `par_run` + tail 29-31 | 6.5-6.9 | linear, 0.10 ms / 1k transfers | AFTER_MERGE_CUT 3, BD 10.91 |
| builder floor (with its waits) | 35.7-37.5 | 5.3-5.6 | waits on N-1's output / N-2's fields | AFTER_MERGE_CUT 6 |
| QMDB root (serial) | gated 25-30, cycle 29-33 | 6.1-6.9 | +3..+6 ms over a round as the tree grows; ~15 ms of serial sections | ROOT_PIPELINE 1, SES 13.3 |
| fields two-cycle | 33-37 | 5.4-6.1 | half of seal -> fields | AFTER_MERGE_CUT 5 |
| state merge (latency, one thread) | 42-62 (70 MB map, ~190k accounts from ~270 maps) | enters L only | parallel version competes for the critical cores | BD 10.155-10.156 |
| answer path / gate loop | L 167-189 -> 36.7-39.6 | 5.0-5.4 | answer at insert -22 ms of L | AFTER_MERGE_CUT 4 |
| consensus vote window (4 blocks) | (A + c) / 4 = 42-42.5 | **4.7 (binds now)** | /5 gives 5.9 on paper; lost in practice | BUILD_AHEAD_RESULTS 5 |
| persistence | 0.17 ms / 1k transfers (~34 at 200k) | ~5.9 | measured at 3.2M (BD 10.91); recheck at 4.7M | BD 10.91 |
| tick | 30 | 6.7 | free parameter | |
| memory | EL peak RSS 50-54 GB + Shmem 28-35 + replay cache | storms on 3 of 8 legs | -0.07..-0.16M/s a storm leg | LEG_SPREAD_X17 4 |

**Who caps next.** Remove the vote window and the next three are the gate loop (5.0-5.4), the builder (5.3-5.6) and the
lanes lock (~5.0-5.6, extrapolated from duty): 5.0M is reachable by pipelining only if the lanes lock is relieved at the
same time, and ~5.5M is the box's ceiling for 200k blocks without a cheaper build or root.

## 3. The directions

| # | direction | mechanism | expected effect | contract change (gov5) | risk | size |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | carried depth 3 + index overlay | header N carries result(N-3); N's lookups beside N-1's apply (ROOT_PIPELINE C1 stage 2 + stage 4) | fields floor gone; alone -0..-1.5 ms (builder and gate floors stay ~37); replay 37.1 -> 32.2 at k=2 with C1 | **yes**: `deferredExecutionDepth: 3`, `ParentLink` lineage, settlement lags one more, mobile proofs pair N with N+3; gov5 must implement D=3 or the chain is Rust-only | medium-high: one more block in flight (the five-block window's failure mode), recovery at D=3 untested | 3-4 wk + gov5 |
| 2 | vote at check, with an in-flight budget | the shared EL answers CHECKED for N from N-1's build output and N-2's fields record (both exist at N's seal on E=1) instead of after N-3 lands; the far-ahead hold becomes a byte / block budget | vote loop gone: floor -> max(builder, fields, consensus ~32) + jitter, -2..-3.5 ms (5.0-5.15M) if the seal does not grow | **no**: what a vote attests is unchanged (PHASE_D 11); the hold is node-local (`h2-node` `runs_far_ahead`) | high on this box: same in-flight depth as the five-block window, which lost 5 ms of seal | 2-3 wk |
| 3 | E=2, or a build / commit process split | second EL builds while the first roots, leaders alternate | **negative**: each EL must execute every block (state is per EL); by tenure the leading EL is today's E=1 and the other duplicates ~35 cores and ~50 GB; per-block alternation builds on a parent known only after its import (seal -> state ready 115-130 ms). A process split adds no L3 or memory channels, which is what the contention is (merge on cores 80-87 slower than on the critical set, BD 10.156) | none | -- | rejected |
| 4a | root batching (one root per two blocks) or a sharded tree | amortise upper levels / shard the commitment | root is not the floor (busy 0.59-0.69); ~0 now | **yes**: new `stateRoot` semantics / layout, fixtures, snapshot verifier (ROOT_PIPELINE C3 rejected) | high | rejected |
| 4b | **per-block delta log instead of the 70 MB post-state map** | the build's output shards become a sorted per-block delta (key, account) owned by the block; persistence, the in-memory overlay and RPC read it lazily; the QMDB root already computes from the ops, not from the map | merge 42-62 -> ~5; L 178 -> ~125; gate loop (36 + 125 + 13)/6 = 29 stops binding; blocks in flight L/gap 4.2 -> ~3; alone -0.5..-1.5 ms, but it is what makes 2 and 1 affordable | none: state, roots, headers byte-identical | medium: reth's `ExecutedBlock` / persistence / reorg paths consume the map | 3-4 wk |
| 5 | per-shard tx queue feeding per-shard builders | lanes by sender shard; frames made shard-local at ingest (the flood's 500-tx frames are per gateway) | lock duty /N; no gap gain now, removes the ~5.0-5.6M lock ceiling | none | high: frame index invariants 2-4 (LANES_LOCK 3a) | 4-6 wk |
| 6 | **larger blocks: 300-400k at 45-60 ms** | fewer consensus rounds per transfer; the fixed part of the gap is amortised | see section 4: +0.2..+0.9M/s if the linear phases stay linear | none (gas limit and body size are header / transport parameters) | medium: memory, persistence, feed | 1 wk |
| 7 | the host: second box / NUMA-CCD placement | validators + flood off the box; NPS4 or CCD-aligned critical set | spread, not ceiling: removes storms (+0.05-0.1M/s mean); placement +-1-2% | none | low; validators remote would ship 19 MB bodies x7 per block unless hash-only frames | 1-2 wk |
| 8 | consensus pipelining (chained HotStuff-2 with k in flight; Monad / Sei asynchronous execution; DAG ordering) | see section 5 | k in flight = direction 2 with a protocol name; async execution generalises PHASE_D's deferral to "vote needs only state at N-d" | Monad style: **yes** (vote rule + includability on a reserve balance); DAG: a new consensus | high | 6-12 wk |
| 9 | execution model (Block-STM / declared-lock scheduler) | account-level conflict scheduling for mixed workloads | 0 on the transfer flood (already conflict-free by construction); needed for contracts | none (execution is deterministic) | medium | 6-10 wk |
| 10 | (the ceiling table, section 2) | | | | | |
| 11 | arena / epoch block memory | every per-block allocation in a per-block slab, released whole when the block's epoch retires | ends the 7-95 ms free class (BD 10.144, 10.145, 10.150); jitter -0.5..-1.5 ms; less heap fragmentation under thp:always | none | medium: ownership rewrite across output shards, registry, queue frees | 3-5 wk |

## 4. Block shape (6): do the floors scale with the block?

The last sweeps (BD 10.82, 10.91-10.93, at 49-61 ms seals) found every phase linear: seal 0.30-0.31 ms / 1k, root
0.15 ms / 1k, persistence 0.17 ms / 1k, and the rate only +2-10% from 200k to 400k (400k holding 3.31-3.39M against
3.05-3.17M at 200k), because the fixed part was ~10 of 61 ms. X17 has moved the linear phases off the chain and left fixed
ones on it: start delay 3-8, pre-exec ~3, exec tail ~3.5, c / 6 ~2, jitter ~5, the tick. Estimate F = 12-18 ms fixed of
the 42.5, so `gap(s) = F + (42.5 - F) * s / 200k`:

| block | pacing | gap (F = 12 / 18) | M tx/s | what breaks first |
| --- | --- | --- | --- | --- |
| 200k | 30 ms | 42.5 | 4.70 | (today) |
| 300k | 45 ms | 57.8 / 54.8 | 5.19 / 5.48 | queue pool 3M slots = 10 blocks; replay set 600M lasts ~115 s at 5.2M |
| 400k | 60 ms | 73.0 / 67.0 | 5.48 / 5.97 | persistence ~68-75 ms a block (BD 10.91) ~= the gap; EL in-flight state doubles (RSS 50-54 -> est. 75-90 GB on a 136 GB box with storms already at 60-80 s) |

Gas ceiling 6.3e9 / 8.4e9 at 300k / 400k, raw-channel cap 256 MiB (a 400k body ~140 MB), compact-body cap 1,048,576
entries all hold (BD 10.91); gov5's gossip path cannot carry bodies over ~100 MB (gossip legs collapse, BD 10.91), which
already excludes a mixed fleet at 200k. The estimate is an upper bound in the same sense as LONG_GAP_TAIL's replay: jitter
may scale with the block. It is still the cheapest test of the whole roadmap, because it needs no code.

## 5. Consensus pipelining and asynchronous execution (8)

* **Chained HotStuff-2 with k blocks in flight.** Ordering is not slow here: followers check in 0.2 ms, four votes land
  inside 1 ms, prepare QC 2-3 ms after the last vote (BUILD_AHEAD_AND_VOTE_PACE 2). The proposal waits for commit(N-1)
  only because the 4th vote on N-1 waits for answer(N-4). Allowing k uncommitted proposals is the five-block window
  generalised; it inherits its cost per block in flight. Same lever as direction 2, with the same prerequisite (4b, 11).
* **Monad / Sei-style asynchronous execution.** PHASE_D already moved the header's execution fields back by D (2 today):
  the vote checks N-2's result and N's includability on N-1's post-state. The includability check is what still ties the
  vote to N-1's execution output. Monad decouples it with a reserve-balance rule (consensus checks spend against state at
  N-d minus the worst-case spend of the blocks in flight), so a vote needs no execution newer than N-d. On E=1 that buys
  nothing extra over direction 2 (N-1's output exists at N's seal); it matters only on a fleet whose followers execute
  separately (gov5 interop, E>1), and it is a protocol change on both clients (vote rule, includability, header depth d).
* **DAG / mempool ordering (Narwhal / Bullshark, Mysticeti).** They scale dissemination and ordering across validators.
  Here one executor (the shared EL) does build, root, merge and answer for all seven; ordering throughput is far from
  binding, and a DAG adds ordering work on the same box. They remove the vote-on-answer dependency only because their votes
  do not attest execution, which is again direction 2's change, not the DAG. Not a route to 5M on one box.

## 6. Execution model and the post-state map (9, 4b)

* **Conflict schedulers.** The transfer fast path partitions by sender groups and sums recipient credits (commutative), so
  the flood has no conflicts to schedule; Block-STM's optimistic re-execution or a Solana-style declared-lock scheduler
  (needs access lists, i.e. a transaction-type change) buys 0 on this benchmark and is the requirement for contract load.
  Neither changes consensus. Keep it off the 5M path; size it when a mixed workload is benchmarked.
* **Delta log instead of the map.** The 61 ms merge clones ~190k accounts from ~270 batch maps into one 70 MB table on
  one thread (BD 10.154); parallel versions cut it to 42 or 57 ms and lost the gain to the critical cores (10.155-10.156).
  The map exists for reth's engine tree and persistence (`ExecutedBlock`), not for the commitment: the root is computed
  from the ops-ahead encode of the shards. A per-block delta (the shards' sorted runs, concatenated by key range, owned by
  the block's arena) applied lazily by persistence and read through the overlay removes the merge from L, the 70 MB copy
  from memory bandwidth, and one more 200k-entry free per block. Reorg / revert paths read the same delta.

## 7. Memory and allocation (11)

Three adopted fixes moved large frees off a critical thread: the registry's eviction free (32-36 ms p90, 95 ms max, BD
10.144), the hand-off's evicted outputs (10.145), the pulled-set drop on the build path (6.9-7.6 ms, 10.150). Each one was
found by a stall and fixed by a dedicated free thread; the class remains (200k-entry maps, `Arc` refcount churn across
~270 maps, jemalloc purges under thp:always feeding the reclaim storms of LEG_SPREAD_X17 4). Design: a per-block arena
(slabs from a pool of 2 MB pages, index-based structures instead of `Arc` graphs), an epoch per block retired when the
block is persisted and no reader holds it (an epoch counter as in crossbeam-epoch), release = return the slabs to the
pool. It ends the class instead of adding a thread per case and caps the heap at (blocks in flight + 2) arenas.

## 8. Cross-client contract (12)

| direction | stateRoot layout | header fields | `deferredExecutionTime` / depth | vote rule | gov5 byte-exact |
| --- | --- | --- | --- | --- | --- |
| 1 depth 3 | same | same fields, carries N-3 | depth 3 (new genesis files) | follower waits N-3's fields | **needs gov5 D=3** |
| 2 vote at check | same | same | same | same attestation, node-local timing | yes |
| 3 E=2 / split | same | same | same | same | yes (rejected anyway) |
| 4a root batching / shards | **changed** | every other header | -- | -- | **no** |
| 4b delta log | same | same | same | same | yes |
| 5 per-shard queue | same | same | same | same | yes |
| 6 larger blocks | same | gas limit only | same | same | yes (gov5 gossip cannot carry the body) |
| 7 host | same | same | same | same | yes |
| 8 Monad-style | same | carries N-d | depth d | **vote on reserve balance** | **needs both clients** |
| 8 DAG | same | new certificate | -- | **new consensus** | **no** |
| 9 scheduler | same | same | same | same | yes |
| 11 arena | same | same | same | same | yes |

## 9. Ranking by expected M/s per week

| rank | direction | expected (M/s) | weeks | M/s per week | condition |
| --- | --- | --- | --- | --- | --- |
| 1 | 6 larger blocks | +0.2..+0.9 | 1 | 0.2-0.9 | the fixed share of the gap is 12-18 ms; memory holds |
| 2 | 4b delta log | +0.05..+0.15 alone; enables 2 | 3-4 | 0.02-0.05 alone, ~0.1 with 2 | L falls >= 40 ms |
| 3 | 2 vote at check | +0.3..+0.45 after 4b; <= 0 before (five-block result) | 2-3 | 0.1-0.15 after 4b | `sealed_at` does not grow |
| 4 | 7 host | +0.05..+0.1 (spread) | 1-2 | 0.05 | mostly makes 6 safe on memory |
| 5 | 11 arena | +0.05..+0.15 (jitter) | 3-5 | 0.03 | |
| 6 | 1 depth 3 + overlay | +0..+0.2 alone, +0.3..+0.5 after 2 | 3-4 + gov5 | 0.05-0.1 | gov5 implements D=3 |
| 7 | 5 per-shard queue | 0 to 5M, headroom past ~5.3 | 4-6 | 0 now | needed once the lock duty reaches ~100% |
| 8 | 9 scheduler | 0 on transfers | 6-10 | 0 | mixed workload |
| -- | 3, 4a, 8 (DAG / Monad) | <= 0 here / protocol | | | rejected for this box |

## 10. The two to start, and the first week of each

**A. The block-shape sweep at X17's floors (direction 6).** Week 1, no code: a 300k / 45 ms and a 400k / 60 ms arm on the
X17 set (pool slots raised to 4M, a 300k / 400k-frame replay set of >= 600M transfers, gas ceiling = transfers x 21,000),
each twice between two 200k controls, with the memory guard (score only legs under 10k majflt per window, LEG_SPREAD 5)
and `F7_BLOCK_INTERVAL_MS` stepped down to the seal + 5 as in BD 10.91. Counters: drain M/s; in-window mean gap per 1k
transfers (ms / k) and its intercept across 200 / 300 / 400k (the fixed part F); `sealed_at`, L, persistence ms / block,
EL peak RSS. Proof: F >= 12 ms and a 300k pair over 5.0M/s with persistence < 0.9 of the gap.

**B. The delta log, measured before it is wired (direction 4b, then 2).** Week 1: behind a switch, hand persistence and
the in-memory overlay the output shards' per-key-range sorted runs instead of the merged map (the map still built in the
background and compared on a verify leg), plus the timers that place the merge on L. Counters: `merge` on the answer path
61 -> <= 5 ms; L 178 -> <= 135; seal -> fields and `sealed_at` unchanged (+<= 1 ms: the cut must not take the critical
cores, the failure of 10.155); blocks in flight L / gap <= 3.3; persistence ms / block unchanged; `fleet7-verify` clean,
fields_mismatches 0. When it holds, the five-block window (`N42_FAR_AHEAD_BLOCKS=2`) is the cheap proxy for vote at check:
it must read `sealed_at` within 1 ms of the control, which is the condition it failed in 10.149 and 10.159.

The 5M arithmetic: A alone may reach it (5.2-5.5M at 300k on the estimate); B + 2 at 200k reaches 5.0-5.15M on the floors
of section 1 and needs the lanes lock to stay under 100% duty. Neither touches the gov5 contract.
