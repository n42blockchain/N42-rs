# Fleet7 plan v4 -- the vote path binds, not the build (2026-09-20)

Supersedes the ordering in `FLEET7_PLAN_V3.md` section 5; its three conditions for 1M stand. Evidence is in
`FLEET7_PATH_AUDIT.md` section 9 (loop170-181) unless a leg is named here.

## 1. What the measurements say binds the cycle

One leader tenure of loop179 R1b (64 views, 163,000-transfer blocks, pacing 350 ms), read from the leader's own log:

| quantity | p10 | p50 | p90 |
| --- | --- | --- | --- |
| a finished build waiting for its proposal | 11 | **188** | 463 ms |
| proposal, after the view opens | 80 | 129 | 422 ms |
| R1 vote collection | 228 | **287** | 366 ms |
| R2 vote collection | 5 | 6 | 18 ms |

63 of 64 builds were built ahead and ready. So:

- **The leader's build is not the constraint.** It finishes ~190 ms before it is wanted. Every leader-side cut since
  loop170 (direct receipts, the body split, the encodings) shortened something that was not on the critical path,
  which is why each read "neutral" on the round.
- **The supply is not the constraint** (loop180: the flood peaks at 429k/s and sends 41M a round against 25M mined;
  doubling its concurrency halves what it delivers).
- **The vote path is.** R1 is the followers' road to a vote: body in, decode, senders, then a check that waits for
  the follower's own import of the parent (execution 140 ms, QMDB root 27, engine insert 38). The leader proposes
  N+1 while the followers are still importing N, so in steady state R1 is the followers' per-block serial chain.
- **Pacing binds on top of it.** The natural cycle is R1 + R2 + the proposal's own path, ~330-350 ms; the bench paces
  at 350, set at loop141 when the chain was slower, and the measured cycle is 393-399. A lever that shortens the
  natural cycle cannot show while the pacing is above it -- `N42_CHECK_ON_PARENT_OUTPUT` (loop169) and the
  follower's streamed graft (loop176-177) were both judged under that ceiling.

Also established, and not to be re-litigated:

- Both parallel phases saturate at ~8 pinned threads (leader execution 78 / 88 / 94 / 101 ms at 8 / 16 / 32 / 64;
  a follower's import 95 ms from 8 threads up). The box is one socket, one NUMA node; the limit is memory traffic
  and the L3, not cores. Seven machines are seven memory systems -- that is what "1M is a seven-machine number"
  means. The earlier unpinned scaling table is void.
- The graft's one map cannot be parallelised: a sharded fold loses to the single mutex (108 ms against 172 under
  seven-way load) because the shards still have to become reth's one `HashMap`. On the leader the single-mutex fold
  costs more than it saves on a loaded node (loop176); on a follower it pays and is the default.

## 2. The plan, in the order the constraint moves

Each step names what would falsify it. A step that fails its criterion is dropped, not tuned.

**Step 0 -- lower the pacing (config only).** Legs at 350 / 300 / 275 / 250 ms on the adopted configuration.
Expect the cycle to follow the pacing down to the natural ~330-350 and stop there. Falsified if 300 collapses the
way it did at loop141 (tenure handovers stalling, TCs past the start-up one). Every leg from here on records
`R1_collect`, `proposal@` and the ready-build wait beside the phase medians: their absence is how the binding
constraint went unseen for ten loops.

**Step 1 -- the check reads the parent's output the moment its execution ends.** `N42_CHECK_ON_PARENT_OUTPUT`
publishes the parent's execution output when the parent's QMDB root is filed; publish it when the execution
finishes instead (the check needs ~6,000 senders' nonces and balances, all in the bundle) and turn it on. This takes
the engine insert (38 ms) out of R1 and lets the sender check overlap the root (27 ms) rather than follow it. The
root itself stays on the vote path: the child's header carries the parent's state root and a follower must compare
it with its own before it votes. Expect R1 ~287 -> ~220. The flag as it stands was only ever judged under the 350 ms
pacing (loop169), so its first leg is a rerun at the pacing step 0 settles on, with no code. Falsified if R1 does not
move with the pacing out of the way, or any invalid block or gas-used mismatch appears.

**Step 2 -- a follower executes N+1 on N's output, not on the engine's tree.** The follower-side twin of
build-on-seal: lay N's execution output over the state at N-1 (`opener_on_built_parent` already does this for the
leader) so N+1's execution starts when N's ends, and N's root and engine insert run beside it. The follower's
block-to-block chain becomes its execution alone (~140 ms on the fleet). Expect R1 -> ~130-150 and the natural cycle
-> ~200, at which point the leader's build-to-build chain (~253 ms) is what binds. Falsified by any divergence in
roots across nodes (`scripts/fleet7-verify.py`), or if R1 does not fall below the leader's chain.

*As implemented (branch `plan-v4/step1-2`, flag `N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT=1`), three things the step did not
say.* The overlay is sound with the hashed tables off because reth's `MemoryOverlayStateProvider` answers accounts,
storage and code from the executed block's bundle (`memory_overlay.rs` 114-124, 237-262) and reaches the hashed
state only for its trie methods -- which is also why the leader's build-on-seal is valid on the fleet; the path is
refused unless `N42_HASHED_TABLES=off`, since a destroyed account's storage zeroing does go through the hashed state.
The flag implies the check-on-output path: both read the same publication. And the import is one serial function --
check, the parent's fields, the vote, then the execution -- so the execution still starts after the parent's root
and only the engine insert leaves its wait; the step's full claim needs the vote road and the execution road side by
side once the sender check has passed (branch `plan-v4/step2b`, in progress).

**Step 3 -- the leader's chain, once it binds.** Three cuts, each independent:
- *No map on the chain.* The next build does not need reth's one map, it needs an answer per address. Keep the
  batches' bundles as they are and build only an index `address -> batch` (24 bytes an entry and cache-resident,
  against 300-byte moves into a 45 MB table: ~7 ms expected against 45-67), with the few accounts two batches both
  touched merged into a small side map; serve the next build through an overlay provider of our own; build the QMDB
  operations from the batches in parallel; and make reth's `BundleState` for the engine insert on a thread behind the
  seal. Bench it under seven-way load first: falsified if index-plus-reads is not under 20 ms there.
- *The transactions root beside the execution*, over the candidate list, redone only when something was skipped
  (rare). It hides today behind the graft; when the graft leaves, it would otherwise surface as ~24 ms.
- *The pool walk for N+1 started during N's seal.* 17-21 ms. The supply is not binding (loop180), so this is walk
  latency; the queue's hold on an own block's transactions is what keeps a walk from re-taking them, and the test
  for this step is exactly that no mined transaction is taken twice.

**Step 4 -- eight threads a pool, a node: FALSIFIED (loop181), dropped.** Two legs each: with both pools at 8 the
leader's parallel step is 110-115 ms against 79-82 at 16, a follower's import 371-373 against 302-320, window 1
308-340k against 331-337k; cutting the ingest to 8 as well changes nothing (111-114, 362-373). The pinned bench
measures a parallel speed-up, and that does saturate at eight threads; on a node the pools share 32 CPUs with the
ingest, tokio and the engine, and what a wider pool buys there is its share of the scheduler. Conclusions about
thread counts come from fleet legs only.

**Then measure the floor.** The protocol's fixed cost has never been read: loop180's leg for it ran at 100 ms pacing
and measured the pacing. Redo it at 10 ms with 10,000-transaction blocks. With steps 1-3 done the cycle on this box
should sit near 200 ms (~800k TPS of block capacity); what the seven nodes' shared memory system lets them keep of
that is the number this box can give, and the rest of the way is a machine per node.

## 2b. The round's decay is the vote path under a memory squeeze (loop182, 2026-09-20)

Step 0's legs held at every pacing (350 / 300 / 275 / 250 ms: no TC past the start-up one, no invalid block; 300
collapsed at loop141 and does not now), and the view's total followed the pacing down, 367 -> 313-334 ms. But the
round did not move: 25.43M, 25.41M, 25.43M, 25.10M transactions -- 156 full blocks in 90 s, a 577 ms average cycle
against 400 in window 1. **The round is set by windows 2 and 3, not by window 1, and no pacing reaches them.**

What grows across the windows of one leg (loop182 P350a, medians of all nodes; `target/fleet-runs/decay.py`):

| | window 1 | window 2 | window 3 |
| --- | --- | --- | --- |
| cycle | 404 | 490 | 520 ms |
| R1 vote collection | 280 | 322 | 386 ms |
| proposal path | 109 | 136 | 139 ms |
| a follower's import, total | 325 | 324 | 305 ms |
| the leader's build, total | 307 | 309 | 311 ms |
| free memory, lowest | 30.5 | 18.1 | 15.8 GB |
| direct-compaction stalls per 30 s | 657 | 635 | 974 |
| QMDB compaction, median (max) | 10 (118) | 29 (134) | 50 (289) ms |

The compute does not slow down at all; the two phases that move 24.7 MB bodies between processes do, together with
the ingest's reply times, while the box runs out of memory: seven execution layers at 10-12.6 GB resident are 82-88 GB
of anonymous memory on a 136 GB box, the page cache is what gives, and the kernel's compaction stalls climb. Of that
136 GB, **22 GB is held by stale files on the `/tmp` tmpfs**: 19,908 `erigon-lfp-buf-*` and 151
`erigon-sortable-buf-*` ETL buffers left by the Go client's runs between 2026-09-09 and 2026-09-19, open in no
process. They are RAM for as long as they exist. Removing them is the cheapest cut on this list, and the leg after it
reads the floor of free memory and windows 2-3 before anything else is judged; what is left of the decay after that
is the execution layer's own resident set, which a heap profile (`scripts/fleet7-profile.sh --alloc`) has to split.

## 2c. Steps 1 and 2 on the fleet (loop183, pacing 275 ms, the tmpfs cleared of 21.8 GB)

| leg | window 1 | round (M tx) | view total ms | R1 ms | invalid blocks | free memory floor |
| --- | --- | --- | --- | --- | --- | --- |
| V0a today | 339,784 | 26.02 | 313 | 153 | 0 | 51.7 GB |
| V0b | 391,021 | 24.29 | 279 | 7 | 0 | 8.8 GB |
| V1a check on the parent's output | 388,814 | 26.36 | 288 | 106 | 0 | 15.4 GB |
| V1b | **401,741** | 27.51 | 285 | 13 | 0 | 24.5 GB |
| V2a execute on the parent's output | 390,935 | 23.94 | 430 | 219 | **29, 3 TCs** | **2.7 GB** |
| V2b | 390,539 | **28.13** | 284 | 8 | 0 | 11.0 GB |

Window 1 passes 400k and the round 28M for the first time at this block shape (25.4M before the pacing and the tmpfs).

**Step 1: passes.** Both legs lead their pair on window 1 and the round, R1 153 -> 106 where the pair is comparable,
no invalid block in these two legs or in loop169's three.

**Step 2: no gain to show, and one leg to explain.** The two roads overlap by 0-1 ms at the median over 164 and 232
blocks: at this pacing the parent's fields are already filed when the child's sender check passes, so the vote road
has nothing to wait for and the execution was not waiting on the root either. The step's premise does not hold at a
275 ms pacing; it would at a cycle short enough for the child to arrive while its parent is still importing. V2a's
29 invalid blocks are one event on one node: node0's read view was invalidated at block 289 ("a persisted block's
changes are not on the tree's path"), which with the tables off turns the next read the view cannot answer into a
refused block (359) and refuses its 28 descendants by their link. Whether executing on the parent's output made that
invalidation or the tables-off mode carries it anyway is being read from the logs; the flag stays off either way
until it is known.

**The memory floor is not fixed by the tmpfs.** Three of six legs still bottom under 12 GB with 22 GB more to start
from, and the floor does not follow the configuration (V0a 51.7, V0b 8.8). The next runner samples resident memory
by process class through the leg; until then the floor is a hazard in its own right (a node under 3 GB free is one
allocation from the OOM killer).

## 2d. The memory is the execution layers' (loop184), and the read view's lag is survivable now

The 29 refused blocks of loop183 V2a were not the new flag's: free memory reached its 2.7 GB floor, 11 s later node0's
persistence stalled for 33 s, the chain ran 68 blocks past the read view, the forest pruned the view's next record
at its 64-block cap, and with the tables off the first read the dead view could not answer refused a block and its
descendants by their link. loop156 V1 logged the same reason on seven nodes with no such flag. It is a hazard of the
tables-off mode, which every leg runs. Merged since (536c1de84, c26764bfc): the cap is a setting, 1024 with the
tables off (a pruned record is a dead node, a kept one is memory); a WARN at half and three quarters of the cap, and
the lag logged every 64 blocks -- that leg said nothing before it was fatal. Step 1 is the default (bd827ed73).

loop184, three legs of that build, resident memory sampled by process class every 5 s:

| leg | execution layers, peak of their sum | largest one | validators | free floor | reader lag, max | window 1 | round (M tx) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M0a | 98.6 GB | 16.3 GB | 6.0 GB | 32.7 GB | 24 | 352,967 | 26.73 |
| M0b | 95.0 GB | 15.3 GB | 6.1 GB | 33.3 GB | 32 | 400,896 | 27.68 |
| M0c | 117.2 GB | 20.1 GB | 6.1 GB | 11.6 GB | 30 | 392,068 | 26.06 |

Seven execution layers go from ~1 GB to 15-20 GB each inside a 90 s round, 150-200 MB a second a node, and are
95-117 GB of a 136 GB box at their peak; nothing else on the box matters. That growth is what takes the page cache,
stalls persistence and slows the phases that move bodies (section 2b), so it is the round's ceiling on this box and
the next thing to split: a jemalloc heap profile of a leg (`--features jemalloc-prof`, `scripts/fleet7-profile.sh
--alloc`). The candidates, by arithmetic: the blocks held in memory until persisted (the reader lag says 24-32 of
them, each a 24.7 MB body, a ~45 MB bundle, its reverts and receipts, and the forest's record -- ~4 GB), the QMDB
index and forest growing by ~147,000 keys a block, the pool and queue at 489,000 slots, the 4M-entry sender cache,
and what the allocator keeps for two seconds at this churn.

## 2e. Window 3 was the flood's fee cap; the sustained ceiling is persistence (loop185-186)

**Every round's third window was the harness.** The flood's fee cap is 1e14 wei; full blocks raise the base fee
12.5% each, and ~156 of them from a round's starting fee reach the cap. From there the flood is priced out and the
blocks run 53-62% full around the cap -- in every leg since the chain passed ~2.5 blocks a second. "The round does not
move with the pacing" (section 2b) was this: 156 full blocks is 25.4M transactions. Window 3's cycle was the
SHORTEST of the three (0.36-0.45 s), with half-empty blocks. Round totals from loop179 to loop185 are not comparable
with anything; windows 1 and 2 are. `fleet7-bench.sh` compares the cap as a big integer now and a round that means
to stay full passes `--gasprice 1e24` (~412 full blocks).

loop186, the old cap (G0) against 1e24 (G1), tps / occupancy:

| leg | window 1 | window 2 | window 3 | round (M tx) |
| --- | --- | --- | --- | --- |
| G0a | 390,533 / 98.6% | 274,635 / 99.2% | 211,446 / 52.7% | 26.33 |
| G0b | 382,753 / 98.0% | 302,923 / 99.6% | 232,704 / 61.8% | 27.58 |
| G1b | 399,298 / 98.0% | 307,560 / 99.3% | **309,277 / 100%** | **30.51** |
| G1a | 390,969 / 98.7% | 72,852 / 32.0% | 54,331 / 36.0% | 15.55 (stalled) |

G1b is the first round full from end to end: ~400k in window 1, then a steady 0.527 s cycle and ~308k in windows 2
AND 3 -- the chain settles, it does not keep decaying. G1a is what the settling costs on this box: at +65 s the seven
execution layers were 109 GB, the page cache 1.8 GB of a 136 GB machine, the fleet stalled as one (ingest replies
0.5 s -> 5 s on all seven nodes), and the backlog drained to 28 GB once blocks stopped.

**The heap (loop185, `target/fleet-runs/heap-read.py`).** The 15-20 GB a node reaches is live data, not the
allocator's, and it is backlog, not a leak: node0 falls 14.9 -> 6 GB inside the load the moment blocks stop being
full. Of the 9.5 GB it grows by: the bundles of executed blocks 42%, the blocks themselves (bodies, recovered
transactions) 32%, QMDB 15% (its per-block records bounded; the twig tree's young twigs grow with the state),
RocksDB memtables 9%. 1.5 GB is sender caches, flat from start-up, 1 GB of it `F7_SENDER_CACHE_MULT=4`, which the
code's own comment puts inside the noise: 7 GB of the box for nothing measured.

**Persistence does not keep up with full blocks.** The lag between the canonical head and the persisted block on
node0 through G1b: 7, 9, 22, 13, 11, 33, 44 at the end of the load, 9 and 7 after it. Over the last 128 blocks it
grows by ~17 blocks per 64 -- persistence runs at 70-80% of the chain's rate -- and every block it is behind is
130-200 MB of heap. So on this box the sustained rate is persistence's, and window 1 is a sprint the memory pays
for. Being read now: where a save's time goes, whether the save is one busy thread or one that waits, and what the
threshold 8 / buffer 6 settings do to it.

## 2f. Persistence, made cheaper by configuration (loop187)

Every leg full to the end (fee cap 1e24), each node's metrics scraped before the fleet goes down. K1 = the adopted
configuration with `F7_SENDER_CACHE_MULT=1`; K2 = K1 + `--prune.transaction-lookup.full`; K3 = K2 +
`N42_ROCKSDB_NOSYNC=1` (bench only).

| leg | reader lag, max | execution layers, peak sum | free floor | window 2 | window 3 | round (M tx) | saves: seconds / count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| K1b | 22 | 88.9 GB | 49.0 GB | 304,066 | 298,824 | 28.85 | 165.2 / 84 |
| K2b | 9 | 72.8 GB | 65.2 GB | 336,781 | 336,833 | 31.72 | 93.9 / 162 |
| K3a | 9 | 72.2 GB | 65.3 GB | 369,451 | 352,406 | **33.36** | 93.9 / 170 |
| K3b | 9 | 72.7 GB | 63.4 GB | 369,453 | 336,776 | 32.90 | 94.3 / 161 |
| K1a, K2a | 12, 9 | 66.1, 74.0 GB | 59.9, 63.5 GB | a regime of 1.7-2.7 s cycles with full blocks; see below |

**Dropping the transaction-hash index is the cut.** 163,000 `TransactionHashNumbers` puts a block were the largest
single write of a save; without them persistence keeps up -- the lag sits at 9, the minimum the threshold 8 / buffer
6 settings allow, where it ran to 22-44 -- the seven execution layers peak at 72-74 GB instead of 89-117, the box
keeps 63-65 GB free instead of 11-49, and windows 2 and 3 read 337-369k where they read ~300k. The sustained rate
moved from ~308k to ~340-360k and the round to 33.36M. The WAL sync adds a little on top (K3 against K2: window 2
369k against 337k, one pair each) and is bench-only. The sender-cache multiplier at 1 costs nothing measurable.
By-hash RPC lookups (`eth_getTransactionByHash`, receipts by hash) do not work on a node run this way: for a
validator that is a fair trade, for an RPC node it is not, so it is a role's setting rather than a default.

**Two legs of six fell into a slow regime: defect 10, the queue gives a mined block's transactions back.** Full
blocks, memory free, no serial fallback, no invalid block, no TC -- and a cycle of 1.7-2.7 s. It is not the fee cap
(the first suspect: healthy legs cycle at 0.46 s with the base fee at 1.8e19, K1a fell at 1e8, and every fee, balance
and arithmetic refusal is 0 in all five legs). At a tenure handover a node had two builds in flight on one parent;
the block from the first had been committed and its 163,000 transactions pruned as mined, and the second
`best_for_build` on the same parent took the arm "previous build on the same parent was not committed; its
transactions are offered again" -- `count=169293` (K1a node3), `166216` (K2a node6), where healthy legs log 0
(`crates/n42/tx-queue/src/lib.rs` ~386). Nothing removes them again. From then on every build of that leader meets
them: each is refused for a stale nonce (814,431 and 743,464 refusals against <= 17,300 anywhere else), a refusal
skips the rest of its sender's group, any skip in the parallel step disables the early seal, and the serial tail
waits ~2.8 s in the puller getting past them: a 250 ms build becomes 3.4-4.1 s. Followers' imports and the votes stay
flat throughout. loop186 G1a and loop177's two "stalled" legs read the same way and were probably this. A weak form
(7-17k stale transactions that clear) shows on healthy legs from the superseded-parent give-back a few lines below.
Fix in progress (branch `plan-v4/queue-giveback`): nothing at or below a sender's mined nonce re-enters the lanes,
and a stale-nonce refusal removes the transaction for good.

## 2g. Defect 10 fixed, and the configuration confirmed (loop188)

The queue's fix (aefd9384d): every lane keeps the highest nonce the chain has mined for its sender, and every way
into the lanes -- arrivals, both give-back arms, an own block's settlement, `mark_invalid` -- refuses at or below it;
a stale-nonce refusal from the builder, which used to be dropped on the floor while the transaction was offered
again forever, is final; a reverted block lowers the watermark. Six legs, full to the end, because the defect had
fired in two of six: Q2 = `--prune.transaction-lookup.full`, Q3 = Q2 + `N42_ROCKSDB_NOSYNC=1`.

| | window 1 | window 2 | window 3 | round (M tx) |
| --- | --- | --- | --- | --- |
| six legs, range | 406,575 - 434,437 | 325,519 - 385,745 | 307,088 - 331,420 | 31.26 - 33.63 |
| mean | 426,055 | 355,452 | 318,886* | 32.82 |

(*one window 3 was cut short by the end of its flood.) No window's cycle left 0.375-0.526 s; 361-366 early-sealed
builds a leg (none in the tenures defect 10 took); reader lag 9-10; the execution layers 74-80 GB at their peak and
the box 61-70 GB free; no invalid block. The give-back never offered a transaction in these six legs, so the fix was
not exercised on the fleet -- at the rate the defect fired that is a one-in-eleven chance, and what holds it is the
unit tests (the three that reproduce it fail with the filter stubbed out). Q3 is not distinguishable from Q2 over
three legs each, so **the confirmed configuration is Q2**: pacing 275 ms, check on the parent's output, the follower's
streamed graft, the tables off, the allocator settings, 12 ingest recovery threads, the sender-cache multiplier at 1,
no transaction-hash index, and a flood whose fee cap outlasts the round.

Where a cycle goes in it (Q2c, medians per window): the leader's build seals at 211-229 ms and is not what binds; a
follower's import is convert 52-55, senders 29-31, **execution 141 -> 167**, root 32-33, engine insert 50-54, ~400 ms in
all -- not shorter than window 1's cycle -- and R1 reads 259 -> 297 ms, which is that import's state-dependent chain
(execution + root + insert, 226-252) plus the check. The child now arrives while its parent is still importing: the
premise step 2 lacked at loop183's cycle. loop189 judges it again.

## 2h. Step 2 judged again: dropped (loop189)

Three pairs on the confirmed configuration, X1 = `N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT=1`:

| | R1 ms | view total ms | import total ms | window 1 | round (M tx) |
| --- | --- | --- | --- | --- | --- |
| X0, mean of three | 202 | 296 | 393 | 430,584 | 32.10 |
| X1, mean of three | 208 | 312 | 370 | 429,489 | 32.92 |

The import is 22 ms shorter and nothing that binds moved; over 1,264 two-road blocks the roads still overlap by 0 ms
at the median, so the parent's fields are filed before the child's sender check passes even at a 0.375-0.40 s cycle.
No invalid block, no gas-used mismatch, the fleet's commitments agree. **The step is dropped**: the code stays, off.
What section 2g read into R1 -- the follower's execution + root + insert -- was wrong: those are not what the vote
waits for. What a cycle consists of in this configuration is being read event by event from a leg's logs, because
the medians do not add up (the leader proposes ~250 ms into a view at a 275 ms pacing, which a pacing counted from
the parent's proposal should not produce).

## 2i. A cycle, event by event (loop189 X0a, window 1) -- and what follows from it

58 consecutive full blocks under one leader; the per-block sums have a median of 369.8 ms, which is the measured
cycle. t = 0 is the leader's `block body prepared` for N.

| segment | median ms | what it is |
| --- | --- | --- |
| A body out -> proposal sent | 1.7 | work |
| **B proposal -> R1 quorum** | **261.0** | the followers' road to a vote, below |
| C R1 -> the next view opens | 8.7 | the R2 round trip |
| D view open -> `proposal preamble` | 51.1 | 37 of it the leader's own commit forkchoice, awaited inside the service loop; 11 retry granularity |
| E preamble -> sealed | 14.6 (mean 36.5) | the leader's own build-ahead: done at +334 against a preamble at +328, a coin flip |
| F -> the next body | 6.5 | RLP encode |

B, per follower: gossip transfer + the validator's decode 36.6 (19 decode) -> hand-off to the execution layer **51.5**
-> `convert_payload_to_block` **55.0** -> `check_includable` **91.5** -> vote 0.8. The quorum (5 of 7: the leader and
four followers) is gated by the fourth-fastest follower at +258.9; the straggler grace was the gate on 1 block of 57.

What this settles:
- **`check_ms` ~200 is work, not a wait.** The parent's execution output is filed ~80 ms before the child's payload
  reaches the execution layer. That is why steps 1 and 2 moved nothing: there was no wait on the road for them to
  remove. Section 2g's reading of R1 is withdrawn.
- **The pacing is worth 3%.** Its rule has a hard floor at 275.6 ms from the leader's previous build and binds on
  23 of 57 blocks, at a median wait of 0; at a pacing of 0 the cycle would be 367 ms.
- **The block is serialised twice on the vote road.** The validator decodes the gossip body, re-encodes 163,000
  transactions into a `NEW_PAYLOAD` frame, pushes 26 MB over the socket, and the execution layer parses them again:
  107 ms, 29% of the cycle. The leader's own block avoids exactly this with `OWN_BLOCK`; a follower's has no such
  request.
- **The leader's build-ahead is the next thing in line.** It finishes at +334 ms; once B is ~100 ms shorter it is
  what the cycle waits for, and step 3 (the leader's chain) stops being premature.

In progress, in the order of what they are worth: the gossip body handed to the execution layer as received and
decoded once (`plan-v4/body-once`, with a `vote road:` log line so this table never has to be rebuilt from seven
logs); `check_includable` measured on its own and cut (`plan-v4/check-parallel`). After them: the commit forkchoice
off the service loop's await (37 ms of D), then the leader's chain.

## 2j. The vote road cut, the commit forkchoice off the loop -- and the cycle pinned by the leader's build chain (loop190-191)

Three changes, each judged on the confirmed configuration with the cycle dissected the way section 2i did it
(window 1, full blocks, the segments summing to the cycle exactly; `scratchpad/dissect190.py`):

| ms, medians | loop189 X0 | Z0 a / b | Z1 (+`N42_COMMIT_FCU_ASYNC`) a / b | Z2 (+`N42_BODY_ONCE`) a / b |
| --- | --- | --- | --- | --- |
| cycle | 369.8 | 375.5 / 356.0 | 372.8 / 362.5 | 359.9 / 360.7 |
| B proposal -> R1 quorum | 261.0 | 259.5 / 247.0 | 252.0 / 242.0 | **226.0 / 224.0** |
| D view open -> preamble | 51.1 | 63.3 / 57.0 | **41.9 / 43.2** | 49.5 / 59.4 |
| E preamble -> sealed | 14.6 | 35.5 / 25.5 | **59.0 / 58.0** | **59.5 / 61.0** |
| C, F | 8.7, 6.5 | 8, 6 | 9, 6 | 8, 6 |
| win1 TPS | 407-434k | 402k / 427k | 407k / 431k | 434k / 432k |

(loop190's three Y0/Y1 pairs read the same: B 248-255 -> 224-226, D+E ~90 -> ~120, cycle 358-364 -> 355-358.)

- **`check_includable` in one pass (1173a69b4 on the branch, unconditional): kept.** 5 ms on the fleet. Section 2i's
  "`check_includable` 91.5" was the whole stretch from the conversion's end to the vote -- header, 163,000 sender
  look-ups (30 ms), the check, and ~50 ms that no field names -- not the check. On an idle pinned box the old check
  was 9 ms (11 ms of CPU at one thread); the new one is 5 ms either way. 531 single-flaw blocks match the old
  implementation's error string for string; a block wrong in several ways now names the earliest transaction in block
  order, where the old one named whichever sender group the hash map reached first.
- **`N42_BODY_ONCE=1` (the gossip body handed to the execution layer as received, decoded once): works, kept opt-in.**
  B falls by ~26 ms (the validator no longer decodes and re-encodes 163,000 transactions); on the execution layer's
  side the road is no shorter (one decode of 63-73 ms against receive 13 + decode 13 + convert 54). 0 bodies refused
  in 11,557 foreign-body blocks, no invalid block, verify clean. Before it becomes the default: a body whose header is
  right and whose transactions are not stays in the validator's body store under that hash, and the real body is then
  dropped as one "already held" -- evict on the execution layer's refusal.
- **`N42_COMMIT_FCU_ASYNC=1` (one commit forkchoice in flight, in commit order, the answer applied as a report): works,
  kept opt-in.** D falls by ~17 ms (the forkchoice is 23-34 ms in flight, never queued behind another: queued_ms 0 in
  1,183 samples), no refused forkchoice, no body held.
- **Neither moves the cycle, and the dissection says why: every millisecond taken from B or D came back as E**, the
  leader waiting at its preamble for its own build-ahead (25-35 -> 58-61 ms). The falsification criterion I set for the
  forkchoice step (`proposal=@` down by 20 ms) was the wrong one -- `proposal=@` is D+E+F, and E absorbs D.
- **The cycle is the leader's build chain.** On the window-1 leaders' execution layers the period from one build's start
  to the next is 351-360 ms -- the cycle -- and only 267-294 ms of it is the build (`sealed_at` 204-222, state ready
  ~19 later, encode 30). The rest: 68-84 ms between a block's state being ready and the validator's `BUILD_ON_OWN`
  request for the next one arriving (the builder idle, waiting for the block to be shipped, sealed and asked for), and
  33-42 ms between that request and the build starting. The consensus chain (B+C+D+F) is ~290-330 ms, right behind.
- The vote road's line sums to ~130 of its ~180 ms on both roads; the unnamed 50 ms is not a wait for the parent (its
  root and engine insert are done before the child's check ends). `plan-v4/vote-road-sum` names and measures it.
- loop190 Y1a lost window 3, and not to the harness alone (`plan-v4/ingest-gate`, merged 331b7c11c..59f8f7cfb).
  **node5's execution layer stopped at block 382**, at the handover after its own tenure: its validator went on
  receiving every body and every Decide, and never started another import. **Defect 12, fixed (644b60fea), latent on
  both roads:** an own block's import reports on its own channel and never re-entered the driver, so a commit answered
  SYNCING because it beat that import (5-8 a leg, with or without the flag) was parked in `pending_commits` and never
  run again; the driver's head stayed one block back; harmless while the tenure goes on, since the next own commit
  moves the head, and fatal on the LAST block of a tenure: the next leader's first block is then two above the tip,
  `far_ahead` holds it (at debug level), and every block after it. The own import now replays a parked commit and
  moves the tip itself, `far_ahead` lets through a block whose parent this node imported, and a held body says so
  (info, and a WARN after 2 s). Its queue froze at 411,428 against an ingest
  gate of 407,500; nothing but a canonical block on that node lowers the queue, so the gate stayed shut; the flood sends
  every frame to all seven nodes and read the replies with no timeout, so all 64 workers blocked; the six healthy nodes
  drained into two last blocks and then built empty ones, which prune nothing. The gate had no liveness of its own:
  it now lets a frame through after 15 s (`N42_TX_INGEST_GATE_MAX_WAIT_MS`, `gate_forced` in the stats line, a WARN
  after 2 s -- a leg with `gate_forced > 0` is not comparable), and the flood's ingest read times out after 10 s,
  names the node and reconnects. A counter race in the queue's inbox (`staged` wrapping for a few nanoseconds) was
  found and fixed on the way; it was not the stall.
- `/home` filled during loop190 Y0a (the runner's memory sampler lost lines; the node logs are on `/data`). Build
  output now goes to `/data/n42-build`.

**Order of work from here.** (1) `plan-v4/build-chain`: the execution layer starts block n+1 the moment block n's state
is ready, on the validator's hint that the next height is its own, and the `BUILD_ON_OWN` request takes the build in
flight -- a build period of ~245 ms instead of ~355. (2) With the build chain under the consensus chain, B and D count
again: legs with build-chain + body-once + async forkchoice, and the pacing below 275 ms (its floor binds once the
cycle is under ~300). (3) The vote road's unnamed 50 ms and the 30 ms of sender look-ups. At 163,000 transactions a
290 ms cycle is 560k TPS.

## 2k. The build chain, half working, already moves the cycle (loop193)

`N42_BUILD_CHAIN=1` (`plan-v4/build-chain`, merged e2192590d..59a5e0c60). The brief's premise was wrong and the
implementer said so instead of guessing: the execution layer cannot start block n+1 by itself, because n+1's parent is
the hash consensus seals -- the built header plus the view's extra data and the leader's BLS signature -- and that hash
goes into the EIP-2935 and EIP-4788 writes before execution. So the execution layer says *when* and the validator says
*what*: a hinted `BUILD_ON_OWN` is answered with the built header the moment it seals, before the encode and the 26 MB
push; the validator's client seals it for the view it will be proposed under and sends the next `BUILD_ON_OWN` on a
connection of its own; the proposal's request compares parent hash and attributes and takes the build in flight. The one
guess is the view, checked, never repaired. No change to the queue.

Window 1, full blocks, medians (ms); W0 = confirmed configuration, W1 = +chain, W2 = +async forkchoice +body-once,
W3 = W2 at a pacing of 225:

| | W0 a / b | W1 a / b | W2 a / b | W3 a / b |
| --- | --- | --- | --- | --- |
| cycle | 391.6 / 375.9 | 351.2 / 341.1 | 339.7 / 326.3 | 351.3 / 325.6 |
| B | 243 / 226 | 210 / 225 | 229 / 185 | 202 / 173.5 |
| D | 67 / 70 | 79 / 64 | 75 / 89 | 55 / 68 |
| E | 59 / 62 | **9 / 15** | 15 / 15 | 64 / 31 |
| full blocks of window 1 | 67/68, 75/77 | 61/83, 64/80 | 56/80, 58/86 | 53/80, 56/85 |
| win1 TPS | 369k / 415k | 427k / 409k | 402k / 428k | 394k / 425k |

- **It passes its criterion** (the cycle down 35-50 ms, E from ~60 to 9-15) **with half the chain refused.** Per leg
  620-733 chains started, 239-322 taken, and all but 3-6 of the rest discarded because the execution layer refused the
  chained request: "the parent's execution result is not known here" (289 of 347 in W1b), "no state found" (56). A
  chained request names the predicted sealed parent; what the builder filed, it filed under the built hash. A refusal
  is only noticed when the proposal's request arrives, ~275 ms later. When it works the build is slower than an
  unchained one (344 ms against 307): it now overlaps its parent's roots and encode on the same pool.
- **The blocks come out short** (full blocks 75/77 -> ~58/82), so TPS does not follow the cycle: three own blocks are
  outstanding under the chain and the bench sizes the pool at three blocks with the gate at 5/6 of it. To be settled
  with the fix: whether the gate counts held transactions (then the pool is sized at ~5 blocks for chain legs) or the
  pull simply comes earlier than the refill.
- No invalid block, verify agrees, no alias warning, no body held, `gate_forced` 0 in seven legs (7 in W2a, whose
  window 2 is therefore void). Defects 11 and 12 did not show.
- **The vote road's copy off the road was worth more than predicted**: the fourth-fastest follower's road is 142-155 ms
  against 180-187 in loop191 (the microbench said 17 ms; the fleet says ~32), the line sums (`other_ms` 0), and B fell
  to 226-243 in the baseline legs -- where E promptly absorbed it (35 -> 60), as section 2j says it must.
- Pacing at 225 ms (W3) reads no better than 275 (W2); not the binding term yet.

## 2l. The chain whole, the pool sized for it -- and the constraint back on the vote road (loop194)

`plan-v4/build-chain-2` (merged 9f481bf04..f618e663d) corrected section 2k's reading: the refusals were not half of
everything, they were **every empty block and no full one** (ten-second buckets: 16/0 refused/taken before the flood,
0/13 in it). An empty block takes the builder's ordinary finish (the early seal needs transactions), and that finish
never looked for the parent's execution under its build hash; 56 more wanted the grandparent's state a median of 18 ms
before its import landed. Both fixed; a refusal is acted on when it arrives. The short blocks were not the gate
counting held transactions (`TxQueue::len()` counts neither what a build took nor what is held; pinned by a test): the
chained pull comes ~275 ms earlier in the queue's refill, the queue's median is unchanged and its trough halves.

Window 1; X0 = confirmed configuration, X1 = chain + async forkchoice + body-once at the bench's pool of 3 blocks,
X2 = the same at 4 blocks (`F7_BENCH_POOL_SLOTS=652000`), X3 = at 5:

| | X0 a / b | X1 a / b | X2 a / b | X3 a / b |
| --- | --- | --- | --- | --- |
| chains taken / started | -- | 455/466, 455/464 | 441/453, 459/467 | 407/415, 429/437 |
| queue trough (p5) | 198k / 191k | 67k / 86k | 166k / 102k | 224k / 243k |
| full blocks of window 1 | 70/72, 72/73 | 55/80, 52/83 | **73/75, 76/78** | 73/75, (31/33) |
| cycle, full blocks (dissected) | 409 / 398 | 332 / 341 | **367 / 373** | 391 / -- |
| B | 242 / 228 | 198 / 216 | 249 / 240 | 286 / -- |
| D | 68 / 69 | 72 / 79 | 68 / 101 | 66 / -- |
| E | 41 / 65 | 20 / 14 | **11 / 10** | 10 / -- |
| win1 TPS | 390k / 397k | 397k / 408k | **403k / 423k** | 403k / (175k) |

- **The chain does what it was built for: E is gone (10 ms), the refusals are gone (2-9 a leg, 5-8 discards).** The
  build chain no longer pins the cycle.
- **It fails the criterion I set (full blocks above 90% at a cycle under 345 ms): at full blocks the cycle is 367-373,
  -30..-35 ms on the baseline, and window 1 reads +3..6%.** X1's 332-341 ms were blocks 10% short.
- **The constraint is B again, and B grows with the pool:** the vote road's decode reads 72 -> 82 -> 85 ms and its
  sender look-ups 27 -> 38 -> 43 ms at 3 -> 4 -> 5 blocks of pool (B 198-216 -> 240-249 -> 286). Every node ingests every
  transaction (`F7_INGEST_ALL`), so a deeper gate is more signature verification in flight on the 16 cores the import
  runs on. Supply and the vote road compete for one pool of threads; the pool's size is a trade, and 4 blocks is where
  it stands.
- Where B goes now (X2b, fourth-fastest follower, from the leader's body leaving): body at the follower's execution
  layer +43 ms (26 MB to six peers), decode 82, sender look-ups 38, check 6, vote released at +237.
- The baseline itself drifted over the night (window 1: 429k loop190, 402-427k loop191, 369-415k loop193, 390-397k
  here; memory headers alike). Pairs within a run are the comparison; across runs a baseline is +-7%.
- X3 (5 blocks): two legs with a stretch of 1-4 s cycles, in X3b at blocks 127-140 -- the second tenure handover.
  Not seen at 3 or 4 blocks. Open; not the configuration.
- Pacing 225 (loop193 W3) no better than 275.

**What follows.** Of B's ~240 ms, ~160 are spent moving and re-deriving what the follower already holds: with
`F7_INGEST_ALL` every follower has verified every transaction of the block and recorded its sender before the block
exists. A proposal body that names the transactions (hashes in block order, 5 MB instead of 26 MB -- or short ids, 1.3
MB) lets the follower assemble the block from its own queue: no 26 MB transfer, no decode of 163,000 transactions, no
sender look-ups -- and the hash of the assembled block against the proposal's is the whole check. Missing transactions
fall back to the full body. This is `DIRECT_PUSH`'s channel, Rust-only and opt-in already; gov5's block topic is
untouched. After it the build (period ~260-310 under the chain) binds again, and plan step 3 is next.

## 2m. The compact body: the road is 50-75 ms shorter, and the way it was built costs more than that (loop195)

`N42_COMPACT_BODY=1` (`plan-v4/compact-body`, merged 0063b60db..4a31eadd7): the execution layer returns a built block's
transaction hashes with it, the leader pushes header + hashes (5.2 MB against 26 MB) to peers whose body channel greeted
for it, the follower's execution layer assembles the block from its own queue without removing anything, recomputes
the transactions root against the header's, takes the senders as given, and on a miss waits 20 ms and then asks for the
whole body. gov5's topic and RPCs are untouched. On an idle pinned box the two roads cost the same (37 against 38 ms);
the implementer said so, and said what the bench could not show.

Window 1, full blocks; P0 = confirmed configuration, P1 = chain configuration (loop194 X2), P2 = P1 + compact body:

| | P0 a / b | P1 a / b | P2 a / b |
| --- | --- | --- | --- |
| cycle | 411 / 364 | 371 / 375 | 456 / 477 |
| B | 246 / 227 | 278 / 254 | **206 / 202** |
| E | 59 / 53 | 12 / 12 | **115 / 181** |
| win1 TPS | 379k / 433k | 391k / 402k | 201k / 321k |

- **The mechanism holds: B is 50-75 ms shorter with only 72% of the blocks assembled.** No invalid block, verify agrees.
- **As built it fails.** The by-hash index sits in the queue: the builder's pull went 22 -> 103 ms (`par_pull_ms`; build
  313 -> 414 ms), which is E; the follower's assembly reads 102-105 ms against the bench's 22 (it contends with the
  ingest inserting into the same structure); and 28% of the compact bodies were refused for about 8 missing
  transactions each, every refusal costing the whole body. `plan-v4/compact-body-2`: the index out of the queue's lock
  with the builder's pull back at 22 ms as the acceptance number, what the missing eight are, and a request for the
  missing transactions alone.
- **The "drifting baseline" of tonight is the huge-page pool at the leg's start, again** (CLAUDE.md, round 43). Eleven
  baseline legs, order-9+ blocks free at the start against window 1: 16,800-18,900 -> 427-433k (five legs); 16,200 ->
  402k; 15,500-15,900 -> 397-415k; 14,700 -> 390k; 13,200-13,500 -> 369-379k. The weak starts are every round's first
  leg -- the one after the runner's build -- and I made them weaker tonight: build output moved to `/data/n42-build`,
  the agents' directory there was not in `dropcache`'s list, ~10 GB stayed cached, and `hugeprep` stopped at 37-38 GB
  of its 40. Fixed in `fleet7-bench.sh` (341e636a6). A round's first leg was the baseline in every runner since
  loop190, so **loop193-194's "+3..6% for the chain configuration" is the pool, not the chain**: at matched pools the
  chain configuration reads 397-428k against 390-415k, inside the spread. What the chain does beyond doubt is E:
  53-62 -> 10-12 ms in every leg; the cycle then waits on B instead.
- A merged branch broke an integration test of the branch before it (`build_chain.rs`, a tuple grew); the runner's
  test stage caught it before the claim. Agents now run the touched crates' full test targets.

## 2n. The compact body, second build -- and three configurations with one window 1 (loop196)

`plan-v4/compact-body-2` (merged d6926ad75..a1a553c20). The 81 ms was the by-hash index written inside the queue's
critical section (the builder's puller drains the inbox under the lanes' lock; the drain took a shard write lock per
transaction while an assembly held 163,000 read locks); the ingest's thread writes it now, outside every queue lock.
The missing transactions were not 8 a block (that was the mean over the blocks that assembled): a refused block missed a
median of ~570, whole senders -- **the frames this node's ingest gate is holding**, which the leader, its queue just
drained by its own build, admitted and built from. No wait could bring them; a miss is now answered by asking a peer
for those transactions by index.

A warm-up leg first, then alternating (window 1, full blocks, medians); Q1 = chain configuration, Q2 = Q1 + compact:

| | Q1 a / b | Q2 a / b / c | Q0 |
| --- | --- | --- | --- |
| `par_pull_ms` | 20 / 21 | **20 / 20 / 22** | 19 |
| compact share of foreign blocks | -- | 92% / 92% / 95% | -- |
| B | 281 / 259 | **213 / 197 / 187** | 217 |
| D | 47 / 61 | 88 / 86 / 116 | 73 |
| E | 11 / 9 | 11 / 11 / 10 | 43 |
| cycle | 361 / 350 | 350 / 360 / 349 | 357 |
| win1 TPS | 429k / 436k | 417k / (338k) / 435k | 438k |

- The index fix holds (`par_pull_ms` 20-22) and the compact road carries 92-95% of the blocks; **B is 60-80 ms shorter**.
- **Three things still wrong with it.** The fill asks the first connected peer, which under a compact body does not
  hold the whole body either: 229-331 "could not supply" a leg against 13-46 fills, each ending in the whole body. The
  assembly reads 112-116 ms on the fleet against 22 on the idle bench, so the road's execution-layer part is no shorter
  than the decode it replaces (197-202 ms total against ~178); B's gain is the transfer and the validator's side. And D
  grows by what B loses (47-61 -> 86-116 ms): nothing is logged on the leader between `block committed` and the next
  `proposal preamble`, the build is ready before the commit, so those are 70-110 ms of the validator's own loop --
  suspected, not shown: serving the fill and whole-body requests on it.
- **Every configuration reads the same window 1: 429-439k at a 349-361 ms cycle** -- confirmed, chain, chain + compact
  -- whichever of B, D, E is cut. Windows 2-3 read 325-365k in all of them, all night. In these legs the ingest's gate
  stands open for stretches of 25 s (`gate_us_per_frame` 250-500 us against 40-55 ms when it gates) with every node
  ingesting 345-390k/s: in those stretches **the harness is the limit**, and window 1 is its stock (the pool filled
  during the decay) plus its rate. The flood spends 8% of its workers' time signing and 63% waiting for seven replies
  to a frame; the ingest's recover slots are ~40% busy. loop197 asks it directly: the same configuration at 64, 128
  and 192 flood workers.
- With `dropcache` covering the agents' build directory every leg starts with 3.8-5.7 GB cached, and the pool's size at
  the start no longer predicts window 1 (Q0 at 13,268 order-9 blocks read 438k). What predicted the slow legs of
  section 2m was the cached residue (10-12 GB) behind the small pool, not the pool's count: reclaim needs something to
  reclaim.

## 2o. More supply is a slower chain: the limit is a node's sixteen cores (loop197)

Section 2n asked whether the harness was the limit. It is not, and the answer is more useful than that. The chain
configuration at 64, 128 and 192 flood workers, a warm-up leg first, alternating:

| flood workers | window 1 | cycle | window 2 | the gate open (5 s samples) | queue trough (p5) |
| --- | --- | --- | --- | --- | --- |
| 64 (three legs) | 435-443k | 0.366 s | 369-380k | 5 | 101-104k |
| 128 (two legs) | 397-401k | 0.40-0.41 s | 320-331k | 4-5 | 266-292k |
| 192 (one leg) | 380k | 0.429 s | 326k | 0 | 408k |

- **The deeper the queue is kept, the slower the fleet.** Supply and the chain are not two resources: every node
  verifies every transaction (`F7_INGEST_ALL`) on the cores its import and its build run on, and a fuller gate is more
  of that in flight. The fleet is fastest at 64 workers *because* the flood then falls short in stretches and leaves
  the nodes their cores. loop194 had already shown the other face of it (the vote road's decode 72 -> 85 ms and its
  sender look-ups 27 -> 43 ms as the pool went from 3 to 5 blocks).
- So every configuration reads 429-443k for one reason, and it is not B, D or E: at ~11 us of ingest per transaction
  435k/s is about five of a node's sixteen cores before a block is touched; at 1M/s it would be eleven. **What is left
  of the vote road and of the build are slices of one budget**, and cutting one hands its time to another (E absorbed
  B and D in 2j, D absorbed B in 2n) until the budget itself is addressed.
- The legs at 64 workers ran out of transactions in window 3 (6,000 senders x 10,000); later runners use 12,000.
- loop198 (queued behind gov5's claim when this was written): the chain and the confirmed configurations with
  `threadcpu.py` beside them -- per-thread-name CPU of every execution layer, validator and the flood, the table that
  says where the sixteen cores go.

## 2p. Checkpoint, 2026-09-21: where the seven-node campaign stands

Tagged `fleet7-plan-v4-7node-20260921`. One night's work in the commander/agent mode of section 4: eleven agent branches
judged and merged, nine rounds of legs (loop190-198), every round's runner and printout under `scripts/fleet7-runs/`.

| | state | flag (all opt-in; no default changed) |
| --- | --- | --- |
| `check_includable` in one pass | kept, unconditional: 5 ms on the fleet | -- |
| vote road line that sums; sealed copy off the road | kept: the road 185 -> 150 ms | -- |
| body handed to the execution layer as received | works, B -26 ms | `N42_BODY_ONCE=1` |
| commit forkchoice off the service loop | works, D -17 ms | `N42_COMMIT_FCU_ASYNC=1` |
| the leader's builds chained | works, E 60 -> 10 ms; needs a pool of 4 blocks | `N42_BUILD_CHAIN=1`, `F7_BENCH_POOL_SLOTS=652000` |
| compact body (hashes; follower assembles from its queue) | B -60..80 ms; three defects open | `N42_COMPACT_BODY=1` |
| defect 10 (stale give-back), 11 (gate without liveness, flood without a timeout), 12 (own block's parked commit) | fixed | -- |
| harness: fee cap, `dropcache` list, warm-up leg, pool-matched comparison | fixed / adopted | -- |

Window 1 on the confirmed configuration went 350k -> 426k before this plan's section 2j (loop188); since then every
structural step has worked in its own segment and none has moved window 1 beyond 429-443k, for the reason section 2o
gives. Open on the compact body: the fill asks a peer that holds no whole body (ask the proposer, or serve from the
imported block); the assembly is 112-116 ms on the fleet against 22 idle; the leader's loop spends 70-110 ms between a
commit and the next preamble once B is short (suspected: serving fills and bodies on the loop). Open elsewhere: pool 5
blocks stalls at a handover; 2 x "no QMDB tree for parent" a leg under the chain.

**Next: four nodes.** Seven nodes at 16 cores each leave ~11 cores for a block at today's rate and ~5 at 1M. Four nodes
at 28 cores each (quorum 3 of 4) change the budget, not the code: the same binaries, a four-validator genesis, the
launch arguments in one env file as `fleet7-env.sh` has them. What to read first there: loop198's per-thread table
at 16 cores against the same table at 28, then the dissection -- the segments that were slices of one budget should
separate again.

## 2q. Four nodes: 538-543k at the pacing floor, ~600k below it, and the follower's import is the bound (loop199-200)

`plan-v4/fleet4` (merged 2aba0c93c): the same binaries, `n42_fleet4_bench.json` (fleet7's with validators 0-3, the
same keys), 4 x 56 CPUs (28 physical cores each; the flood on the same sixteen cores as before), quorum 3 of 4, a root
of its own. The smoke leg passed every check (4/4 agree, no invalid block, no committee-evidence error, the CPU sets as
printed). Where the sixteen cores of a seven-node member went 13.7 (tokio 5.8, rayon 3.8, jemalloc 1.9, storage 1.7),
a four-node member's twenty-eight go 17.9 (tokio 9.0, rayon 5.1, storage 3.0): the same work spread wider, ten cores
to spare.

| four nodes, chain configuration | pacing 275 (loop199 x5, loop200 x2) | 225 | 175 | 125 |
| --- | --- | --- | --- | --- |
| window 1 | 532-543k at 0.300-0.303 s | 578k / 603k | 579k / 600k | 599k / 436k |
| window 2 | 527-543k | 429k / 549k | 345k / 579k | 562k / 572k |
| cycle, full blocks (dissected) | 288 | -- | 261 | 263 |
| B / D / E | 150 / 120 / 7 | | 216 / 25 / 8 | 216 / 19 / 8 |
| follower import (total / exec / root) | 195 / 96 / 26 | 390 | 372 / 135 / 34 | 379 |
| queue trough (p5) | 138-208k | 90-97k | 88-91k | 90k |

- **At 275 ms every configuration reads the same 0.300 s** -- chain or not, rayon 16 or 28 -- because the pacing
  binds: D is 120 ms of waiting. Window 1 and 2 are the same 538-543k, the first time window 2 has matched window 1.
- **Below 275 the cycle reaches 261-263 ms (600k) and window 2 becomes erratic**: the follower's import goes 195 ->
  370-390 ms (execution 96 -> 135, root 26 -> 34, and the rest waiting), longer than the cycle, so the backlog grows
  and a window collapses (345k, 429k, 436k) or does not. The vote (deferred) is released at +180 ms; what cannot keep
  up is the execution behind it. R1 rises 145 -> 166-203 as the import's threads take the cores the vote road runs on.
  This is the seven-node limit at a higher rate: at 28 cores a node still spends 17-18 of them, and the pacing at 275
  was hiding the import behind the wait.
- **The flood keeps up**: 538-548k/s delivered with the queue's median at 486k; at 20,000 tx a sender, window 3 is no
  longer the flood running dry.
- Peak memory 57-60 GB for four execution layers (75-90 for seven).

**What follows.** The floor at four nodes is the follower's import, 195 ms with slack and 370 ms without: its
execution (96-135 ms for 163,000 transfers on the 16-28-thread pool) and root. Two directions, both in this plan:
the compact body (the road's decode and sender look-ups gone; `plan-v4/compact-body-3`, whose two commits are in but
unverified) frees cores the import can use; and the import's own execution -- the grafted parallel transfer at 96 ms
against ~50 ms of pure execution in the builder -- is plan step 3's other half. Pacing stays at 275 until the import
is under the cycle at 225.

## 2r. The compact body at four nodes: a shorter road and a slower import (loop201)

`plan-v4/compact-body-3` (merged a4306d8ba..58a0e3487): the assembly in one parallel pass (look-up and copy on the
worker that found the transaction), the fill asked of the member that built the block (the body channel names its
sender), a fill served from the imported block when no whole body is held, serving off the consensus loop, and a
`leader loop between commit and preamble` line naming where D goes. Under a load that reproduces the fleet's (twelve
ingest threads pushing, a busy pool) the assembly is 51-63 ms, not the 40 the brief asked; what remains is the random
read of 163,000 queue objects other threads allocated, and closing it is an arena, not a tweak -- the implementer
stopped there.

Four nodes, chain configuration; C = body road, K = + `N42_COMPACT_BODY=1`; windows 1 / 2 / 3:

| | C275 a / b | K275 a / b | C225 a / b | K225 a / b |
| --- | --- | --- | --- | --- |
| window 1 | 537k / 538k | 543k / 532k | 578k / 579k | **597k / 619k** |
| window 2 | 543k / 538k | **467k / 494k** | 577k / 563k | **445k / 440k** |
| window 3 | 456k / 516k | 396k / 413k | 523k / 498k | 407k / 396k |
| R1 | 145 / 145 | 122 / 126 | 207 / 203 | 143 / 136 |
| follower import total / exec | 190 / 98 | 227-240 / 132-134 | 361-369 / 132-135 | 301-306 / 147 |
| assemble | -- | 65 / 67 | -- | 75 / 71 |
| fills: proposer asked / failed | -- | 186 / 0 | -- | 130 / 0 |

- **The road is shorter** (R1 -20..65 ms; the fill works: every one asked of the proposer, none failed, 1-2 whole-body
  fallbacks a leg; assembly 65-75 ms against 112-116) **and the block executes slower**: the import's execution 96-98
  -> 132-134 ms at 275 (the parallel phases themselves +6 ms; the rest outside them) -- and windows 2-3 read 15-20% under
  the body road in all four legs. Memory peaks are the same (57-60 GB). Suspected, not shown: the assembled block's
  163,000 transactions are copies made by sixteen workers, scattered where a decoded body's are contiguous.
- **Set aside at four nodes**: opt-in as it is, with the three fixes in; not the constraint here and a loss on windows
  2-3. Its instrument stays: `unnamed_ms` is most of every `leader loop` line (121-216 ms), so serving peers was not
  where D went -- at pacing 275 D is the pacing wait itself.
- **Pacing 225 without it: 578k / 577k and 579k / 563k** on windows 1 / 2 (loop200's two legs: 603k / 429k, 578k / 549k)
  -- three of four hold at a follower import of 361-369 ms against a 278 ms cycle. loop202 confirms it over more legs
  and tries 200.

## 2s. Four nodes at pacing 225: the configuration (loop202)

Chain configuration, no compact body, `--pertx 20000`; a warm-up leg then C225 x3, C200 x2, C275 x1 interleaved:

| | C275 | C225 a / b / c | C200 a / b |
| --- | --- | --- | --- |
| window 1 | 542k | 589k / 575k / 583k | 602k / 594k |
| window 2 | 538k | **571k / 562k / 556k** | 557k / 464k |
| window 3 | 500k | 508k / 475k / 482k | 497k / 462k |
| cycle, full blocks (dissected) | 288 | 262 (B 217, D 32, E 8) | -- |
| R1 | 144 | 190-201 | 166-196 |
| follower import total / exec / root | 189 / 96 / 26 | 361-370 / 131-133 / 33 | 370-374 / 133-136 |
| queue trough (p5) | 158k | 88-91k | 90-91k |

- **225 is the four-node configuration: 575-589k on window 1 and 556-571k on window 2, three of three** (five of six
  with loop201's; loop200's one collapse to 429k stays the one exception in seven legs). 200 buys nothing beyond 225
  (the cycle is the same 262-270 ms) and lost a window 2 (464k). `F7_BLOCK_INTERVAL_MS=225` from here.
- The cycle at 225 is B: 217 of 262 ms is the followers' road to the second-fastest vote, and behind the vote the
  import runs 361-370 ms (execution 131-133, root 33, sender look-ups 34, engine 49; the remaining ~115 waiting for
  its parent) -- a block behind the chain and steady there, which is what deferred execution allows.
- A member's twenty-eight cores at 225: 17.4 in use (tokio 9.2, rayon 4.9, storage 2.4), the same as at 275: the rate
  went up 7% on the same CPU; the rest is waiting.

**Checkpoint, 2026-09-22, tag `fleet4-plan-v4-20260922`.** Seven nodes: 429-443k (16 cores each, the CPU budget). Four
nodes: 556-589k at 28 cores each, pacing 225, quorum 3 of 4. Every step of this plan is merged, opt-in; the chain,
body-once and async-forkchoice flags are the configuration; the compact body is in the tree and off.

**Next.** The follower's import is a block behind and its execution is 131-136 ms for 163,000 transfers where the
builder's parallel step is 72 ms of execution in a 213 ms `par` phase: plan step 3's other half, the follower's
grafted execution (partition 31, groups 54-59, merge 9 of the 133 -- and ~40 ms outside the phases). Then the sender
look-ups (34 ms a block, on every follower, for transactions the ingest already recovered -- the compact body's one
part worth keeping on its own). Then jemalloc's background thread (1.9 cores a member at seven nodes).

## 2t. The follower's execution, named and cut: window 2 at 590-614k (loop203)

`plan-v4/follower-exec` (merged 9ebcbeb95): `parallel import phases` sums to `exec_ms` (env, batch, gas, receipts,
drop, other added); the partition memoises the sender's party across the queue's runs and grows its map with the
block (unconditional); `N42_FOLLOWER_PARTITION_HASH=1` finds the addresses that can join two senders on the pool and
probes a small table serially; `N42_FOLLOWER_FREE_ASYNC=1` frees the 32 MB of transaction environments on the pool.
The bench was built to the leg's shape first (380 senders, 154,000 accounts, the state served from one shared map)
and read every phase within 2x of the fleet; it also showed the groups phase memory-bound (32x the threads, 2.4x the
speed), so 28 rayon threads buy nothing there.

Four nodes, pacing 225; E0 = no new flag, E1 = + partition hash, E2 = + both:

| | E0 a / b | E1 a / b | E2 a / b |
| --- | --- | --- | --- |
| window 1 | 596k / 595k | 615k / 608k | 624k / **636k** |
| window 2 | 492k / 569k | 396k / 453k | **590k / 614k** |
| cycle | 0.273 / 0.270 | 0.263 / 0.266 | 0.259 / 0.256 |
| import total | 350 / 321 | 303 / 302 | 262 / **209** |
| exec_ms (phases' total) | 123 (96) / 115 (91) | 102 (82) / 106 (81) | 96 (80) / 83 (75) |
| partition / groups / drop | 21 / 50 / 2 | 12 / 50 / 2 | 11 / 50 / 0 |

- **Both flags: the import 350 -> 209-262 ms, under the cycle, and window 2 at 590-614k, the best two legs of the
  campaign.** Window 1 624-636k. Adopted into the chain configuration pending loop204's three more legs.
- The ~37 ms outside the old phases: env 5, receipts 2, drop 2, other 1 named inside the executor; the rest --
  `exec_ms` minus the executor's total, 24-27 ms with the drop in place, 8-16 with `FREE_ASYNC` -- is the freeing
  that ran after the executor's own timers stopped. The bench's 6-8 was the same thing on an allocator with nothing
  else to do.
- E1 alone lost both window 2s (396k, 453k); with the free off the pool as well it held twice. Two legs each; the
  alternation was E0 E1 E2, so the E2 legs were never first after a warm-up. loop204 confirms.

## 2u. E2 confirmed: 586-636k / 590-619k; pacing 200 and the allocator's thread off do not help (loop204)

| four nodes, 225, both follower flags | E2 (five legs, loop203-204) | E2 at pacing 200 | E2, `background_thread:false` |
| --- | --- | --- | --- |
| window 1 | 586-636k | 636k / 637k | 607k / 618k |
| window 2 | **590k, 614k, 619k, 606k, 607k** | 574k / 385k | 573k / 451k |
| import total / exec | 209-297 / 83-99 | 304-323 / 102-110 | 304-342 / 104-116 |

- **Five of five E2 legs hold window 2 at 590k or better: this is the four-node configuration** (`run-loop204.sh`'s
  `CH`). Pacing 200 gains 0-1% on window 1 and lost a window 2 again; the allocator's background thread costs nothing
  measurable at four nodes (it is under 0.15 of a core in the thread table) and turning it off lengthened the import
  and lost a window 2. Both stay as they are.
- Where a member's twenty-eight cores go at E2: 18.4-19.2 in use (tokio 9.7-9.9, rayon ~5, storage ~2.5).

## 2v. The collapse has a mechanism: the import waits for the engine, then the imports collide (loop205-206)

`plan-v4/senders-from-queue` (merged 81d8202fe, `N42_SENDERS_FROM_QUEUE=1`): the follower takes a foreign block's
senders from the tx-queue's by-hash index the ingest already fills (3.3 ms for 162,000 on the bench under load; every
one of 163,000 found on the fleet). It does what it says -- `senders_ms` 34 -> 5, R1 150 -> 116-126, window 1 640-652k
at 0.250 s -- and every S leg lost window 2 (369-451k at 225; 505k / 423k at 250; 522k at 275 with a 1.2 s stall in
window 3), while E2 in the same runs held 2 of 4 (620k, 589k against 451k, 467k).

A read-only analysis of eleven legs (seven collapsed, four held; scripts under the session's scratchpad) found:
- **The bench's "window 2" is t = 90-120 s of the leg and "window 3" t = 190-220**, not the second and third 30 s:
  window 2 reads the chain after 90 s, and the chain oscillates between two regimes with a 65-80 s period.
- **The import has one untimed region, and it is the mechanism.** `wait_for_parent` (follower_import.rs:1259): block
  n+1's execution waits for block n to be canonical in the engine with its fields recorded -- n's root, hashed state,
  mined bookkeeping and engine hand-off (~115-190 ms) -- because `state_by_block_hash(parent)` needs the parent
  canonical. Clean, the wait is 10-14 ms; once the import exceeds the cycle the waits stack, several imports run at
  once, their rayon work collides and **exec inflates 1.5-2.5x** (0 overlapping imports: exec 79-83, groups 52-55,
  total 140-156; two or more: exec 116-149, groups 74-108, total 340-403; with S, exec 155-203). Root (25-35) and the
  engine insert (49-55) are flat through it. The loop breaks only when a tenure handover stalls the chain long enough
  to drain it, and re-enters within ~30 s. After a drain exec is back at 82 on a state that only grew: a congestion
  term, not a state term.
- The vote road is already off the engine (`check_on_parent_output`, `parent_wait_ms=0`); only the execution waits.
  `N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT` -- plan step 2, dropped at seven nodes in section 2h because there was no wait
  then -- is the path that does not: n+1 executes on n's published bundle over the state at the grandparent. Today it
  declines when the grandparent is not canonical either, which under a backlog is exactly when it is needed.
- **Tenure handovers cost 0.6-1.8 s each in every leg** (the new leader's parent still importing, `forkchoiceUpdated`
  Syncing, retried 64-170 times a leg) -- a constant tax; a leader entering its tenure with a backlog costs 7.5-11.4 s
  in its 64 blocks, and that is what separates the held legs from the collapsed ones (node3's tenure at views
  448-511). Memory, the huge-page pool and the starting baseline are not the separator.
- **S trades 28 ms of clean road for 40-80 ms of congested exec**; off until the import is pipelined. And loop206
  showed the entry into the slow regime is a step (import 0.12 -> 0.31 between two 15 s buckets), at pacing 275 as at
  225, with 0.18 s of slack and 67-80 GB free: what triggers it is being chased (the analysis' follow-up).

**The entry is a root tail, and the root tracks a cost that grows through the leg.** Twenty steps (five legs x four
nodes) share no event -- not a handover, the gate, a prune, a lag -- but every leg's `compacted the QMDB log into a new
checkpoint` grows monotonically (bytes 0.6 -> 12.2 MB, `total_ms` p50 5 -> 150-169 over ~900 blocks) and the
follower's `root_ms` tracks it (p50 24 -> 38-50, tails of 150-319). The first slow import of a leg is one outsized
root (S250a nodes 1 and 3: `root_ms` 319 / 284 at block 385, exec normal) into which the next block's vote road runs;
the wait and the exec inflation follow one block later and then sustain themselves. So two fixes, not one: the
pipeline stops the regime sustaining itself (a step becomes a ramp), and the checkpoint's growth has to be bounded or
taken off the root's path, or window 3 goes anyway -- `plan-v4/qmdb-checkpoint`. Also measured: the S flag's index
removal doubles the canonical prune (`prune_ms` 39 -> 94), which is why its queue sits 80k deeper.

In progress: `plan-v4/import-pipeline` -- the wait timed (`parent_engine_wait_ms`), execution on the parent's published
output as the default with the outputs stacked to the nearest canonical ancestor, at most one execution in flight per
node. A fix must move, at t = 90-120 s: the wait 125-190 -> under 30, exec 120-190 -> 90, import total 330-450 -> under
250, slow-proposal seconds in a tenure 7.5-11.4 -> under 1, window 2 >= 600k in every leg.

## 2w. The import pipelined: the engine wait gone, window 2 at 614-630k in two legs of three (loop207)

`plan-v4/import-pipeline` (merged 269b83377, 2d21ea238): block n+1 executes on n's published output by default, the
outputs stacked as reth overlay providers (newest first; no bundle merge -- merging two blocks' bundles is 94 ms,
composing them 6-180 ns a read) down to the nearest ancestor the engine holds, at most four deep; one execution in
flight per node; the includability check reads the same stack; the engine wait, the gate and the wait for the parent's
root are named on the `direct import` line. The vote and the root are where they were.

Four nodes, E2 at 225; P = the default, O = `N42_FOLLOWER_EXEC_ON_PARENT_OUTPUT=0`:

| | P a / b / c | O a / b |
| --- | --- | --- |
| window 1 | 636k / 630k / 630k | 628k / 624k |
| window 2 | **630k / 466k / 614k** | 564k / 284k |
| import total / exec | 190-211 / 88-96 | 280-305 / 97-106 |
| `parent_engine_wait_ms` p50 / p90 | 0 / 0 | 60-61 / 123 |
| `two roads` blocks | 692-791 (nearly all) | 0 |
| root p50 / p90 | 32 / 65-113 | 32-34 / 57-63 |
| checkpoint ms, first / last quarter | 13-17 / 13-14 | 13-14 / 12-14 |

- **The mechanism of section 2v is removed**: the import no longer waits for the engine (0 against 60-123), the
  execution runs beside the vote on nearly every block, the import is 190-211 ms with 50-60 ms of slack under the
  cycle, and the gate never queued (`gate_ms` 0). Two of three P legs held window 2 at 614-630k, the best yet; the
  warm-up read 630k as well.
- The checkpoint's cost grows less on the uncongested box (first-quarter median 4-5 ms, last-quarter 35-91 in all 24
  logs, against 169 under loop206's congestion -- the runner's own first/last-quarter counter misread it as flat). The
  root's p90 tails (57-113) remain and are the entry the analysis named; `plan-v4/qmdb-checkpoint` went to what
  accumulates in the bytes (section 2y).
- **Pb and Ob lost their windows to a third defect, on the leader (defect 13).** In each, the node leading one
  64-view tenure lost the seal-first build path for the whole tenure (1 and 0 `seal-first build phases` of 62 builds,
  against 61-62 in every other tenure of the five legs): with a full pool it proposed late (Pb node3, views 448-511:
  proposal@ p50 185 against 80-87 for the same node in Pa/Pc, `fcu_ms` 113, the chain's `wait_ms` 401, cycle 0.366),
  and with the chained builds having taken and held several blocks' worth it proposed EMPTY blocks (Ob node1, views
  362-382: `txs=3912` then `txs=0` while its queue held 334-360k -- later nonces of the same senders, unusable until
  the held blocks commit). Nothing on today's lines says why; `plan-v4/leader-early-seal`. The root tail's new coupling
  through the vote road's `fields_ms` (root 635 on view 442 -> fields 440-512 on 443) is real, two-block, and recovers.
  loop208 runs P four more times with `root_wait_ms` on the line.

## 2x. The follower is fixed; the leader is the bar (loop208)

Four more P legs (E2 at 225, the import pipelined, `root_wait_ms` on the line):

| | Pa | Pb | Pc | Pd |
| --- | --- | --- | --- | --- |
| window 1 | 630k | 641k | 625k | 642k |
| window 2 | **630k** | 489k | **619k** | 391k |
| import total / engine wait / root wait | 177 / 0 / 0 | 188 / 0 / 0 | 188 / 0 / 0 | 185 / 0 / 0 |
| root p50 / p90 | 29 / 60 | 30 / 65 | 30 / 65 | 30 / 65 |
| `seal-first build phases` of ~850 blocks | 520 | 499 | 641 | 532 |

- **The follower's import is done as a bound**: 177-188 ms with no engine wait and no root wait, on every leg, and the
  cycle/import trace shows the import flat at 0.16-0.25 s through every collapse. Over seven P legs (loop207-208)
  window 1 reads 625-642k, and window 2 holds at 614-630k in four and collapses in three.
- **Every collapse is now the leader's**: the cycle steps to 0.40-0.77 s with the import at 0.14-0.15 (Pd t+90, Pa
  t+135, Pb t+105), and only 60-75% of a leg's builds early-seal (499-641 of ~850) -- section 2w's defect 13 is not
  rare, it is most tenures at some point. `plan-v4/leader-early-seal` is the work; window 2 >= 600k in every leg is the
  bar it has to meet.

## 2y. The checkpoint is the active-bit set; its replay was keccak; the root tail is not the checkpoint

`plan-v4/qmdb-checkpoint` (merged): the QMDB checkpoint is exactly one bit per slot the tree has ever appended
(`ForestCheckpoint.active`, `next_slot/8 + 52` bytes: 18,750 B a block for 150,000 touched accounts, 61,940 B at block
101 -> 9.2 MB at block 584 on the fleet and 18,750 B a block exactly on the bench). QMDB appends only, so it grows with
the chain by construction, cannot be bounded without recycling slots -- which changes every root -- and compresses 9%
(78% of the words of a 29M-slot checkpoint are non-zero). Its cost was not the write (0 ms) but the replay of the
sealed delta-log segment behind it, as long as the checkpoint itself, with a keccak256 over every record: the
per-record tear digest is a CRC-32 now (either digest accepted on read, so an older datadir still replays; a downgrade
would see the new log as torn). Bench (`checkpoint_growth.rs`, reproducing the fleet to the megabyte and millisecond):
compaction at 13.3 MB 45-48 -> 28-30 ms (replay 36 -> 9), 3.2 s -> 1.8 s a leg; root unchanged at ~52. The
`compacted the QMDB log` line carries `replay_ms encode_ms write_ms sync_ms`.

**The root tail is not the checkpoint.** The compaction takes no forest lock and runs on its own thread; 0 of 124 root
tails in loop206 and 13 of 643 (2%) in loop207 overlapped a compaction, fewer than ordinary imports do; root p50
tracking the checkpoint's ms over a leg was common cause (both grow with the leg). Two leads left for the import, both
unverified: `FileEntries::seal_tail` maps 256 MB with `MAP_POPULATE` under the forest lock inside the root job once per
~43 blocks (39.6 B an entry); and root tails land on the same block numbers on different nodes (loop206 E2 nodes 2 and
3 at 532, 557, 577, 608, 622) -- a property of the block, not of a node's background work. With the follower no longer
the bound (2x), neither is chased before defect 13.

## 2z. Defect 13: one refused candidate cost a tenure its early seal

`plan-v4/leader-early-seal` (merged 31fa789e4). The mechanism, from nine legs' build lines: the parallel step drops a
candidate its transfer path refuses and every later candidate of that sender's run (`parallel_transfer.rs:1220-1231`);
the early-seal gate required `block_full`, computed before the serial loop as "under 21,000 gas left or the pull
drained", so one skipped candidate left the block 21,000 gas short and the gate fell through -- silently. The skipped
head went back to the queue as `ExceedsGasLimit`, which tells the queue nothing, and a lane's lowest nonce is what
every build is offered first: the same unusable head, refused again, its run skipped again, until a handover raised
the lane's watermark. Pb node3 (views 448-511): `refused[6]` (the fast path's `sender.nonce != tx.nonce`) +1 per
build, `par_skipped` 256-512 every build, 1 seal of 62, the same node/blocks in Pa 62 of 62. Ob node1: `par_skipped`
2,880 -> 163,000 over twenty builds while `par_groups` fell 384 -> 59, then `gas=0` blocks with 334-360k queued.
Across nine legs a tenure seals 61-64 of 64 or 0-1 of 64; every collapsed tenure has `par_skipped > 0` on every build;
not node-specific; later tenures (t5-t12).

The fix: the gate allows a shortfall of `block_gas_limit / 64` (`N42_SEAL_SHORTFALL_DIV`; the remainder goes to the
next block); a skipped head is diagnosed with one account read and returned as `NonceNotConsistent`, so a stale head
is dropped with everything below it and a head above the account's nonce parks the lane (`Parked`, up to 8 builds, or
until the hole fills or the chain passes it); `usable=` beside `queued=`; `a build did not seal early why=`; a WARN for
a near-empty build over a deep queue. Open: where an individual hole below a lane's lowest nonce comes from -- with
`N42_TX_INGEST_DIRECT=1` the transaction is in neither the queue nor the pool, so the gap-repair feed cannot fill it;
the fix makes the build survive a hole rather than prevent one, and `usable=` now shows whether holes accumulate.

## 2aa. Defect 13 mostly gone: 94-97% of builds early-seal, window 2 570-647k (loop209)

Five P legs on the merged tree (import pipelined, checkpoint replay CRC, early seal fixed):

| | Pa | Pb | Pc | Pd | Pe |
| --- | --- | --- | --- | --- | --- |
| window 1 | (421k) | **647k** | 630k | 636k | 636k |
| window 2 | **647k** | **641k** | 570k | 581k | 619k |
| window 3 | 565k | 532k | 432k | 478k | (428k) |
| builds that early-sealed | 94% | 97% | 95% | 96% | 95% |
| `gas=0` builds with a deep queue / near-empty WARNs | 13 / 8 | 3 / 0 | 0 / 2 | 1 / 2 | 0 / 4 |
| import total / root p90 | 189 / 67 | 194 / 69 | 206 / 85 | 197 / 73 | 183 / 64 |
| checkpoint replay, last quarter | 2 ms | 2 | 2 | 2 | 2 |

- **The early seal holds**: 94-97% of a leg's builds against 60-75% before, and no tenure at 0-1 of 64. The
  cycle/import trace is flat at 0.24-0.28 s through most of every leg. Window 2 reads 570-647k -- the two best legs of
  the campaign (647k / 641k and 647k / 646k on windows 1-2) -- against the bar of 600k in every leg: three of five.
- **The empty-build residue remains**: Pa's window 1 (occupancy 64%, 13 builds at `gas=0` over a deep queue, `why=the
  parallel step built nothing` x6), Pe's window 3 (71%). The queue's usable depth (p5 137-178k) says the lanes were
  there; what the parallel step found nothing in is the next question -- the hole below a lane's lowest nonce that
  section 2z left open.
- The checkpoint's replay is 2 ms at the end of a leg (was 36 at 13 MB); root p90 64-85 as before.

## 2ab. The holes: my own park, the gate it shut, and a give-back through the wrong door

`plan-v4/lane-holes` (merged 184de30f7). loop209's thirteen empty builds were one node, one 15-second window, and the
park of section 2z turned against itself: the skipped head was diagnosed against the PARENT's state, but the parallel
step drops a sender's run wherever a batch's view lacks what other groups credit it in the same block, so the head sits
k above the parent's nonce -- the block's own progress, not a hole -- and two builds with `par_skipped` 144-146k parked
the node's whole lane set (`usable=0`, `queued=569,520`). The ingest's gate counted the parked transactions, shut,
nothing arrived, the empty blocks pruned nothing, and the depth froze until the chain moved past the tenure. Fixed at
both ends: the diagnosis reads the block's own state (the graft's bundle, then the db), and the gate's depth
(`gate_len`) leaves parked lanes out.

The hole's origin, reproduced by a test: an own block B sealed at height h and held; a later build on B is re-offered
a nonce B carries and refuses it as behind the chain, and the lane's watermark rises on that verdict (it must -- round
44); consensus commits another block at h; `settle_own_block` gives B's transactions back through `give_back`, which
filters them against that watermark, and the nonce is in neither the queue nor a block, with every later nonce of the
sender queued behind it. B was never committed, so the give-back now goes through the unmined door, lowering the
watermark first, and the prune for the block that was committed re-raises it from what was mined. Three more doors in
the ingest (an undecodable transaction, a signature that did not recover, a 0x50 that did not verify) were `debug!`
and permanent -- a frame is acknowledged by count -- and the async path answered with the raw count before decoding;
it answers with what it decoded now, and every drop the queue or the ingest makes is counted by reason and named.
The generator is ruled out (accepted = min across the four streams; a timeout re-sends).

## 2ac. Four of five at 625-634k; the doors are counted and not yet closed (loop210)

| | Pa | Pb | Pc | Pd | Pe |
| --- | --- | --- | --- | --- | --- |
| window 1 | 641k | 641k | 641k | 646k | 638k |
| window 2 | **634k** | **625k** | **625k** | 407k | **625k** |
| early seal | 96% | 96% | 96% | 94% | 96% |
| `gas=0` over a deep queue | 3 | 2 | 2 | 2 | 0 |
| ingest drops | 0 | 0 | 0 | 0 | 0 |
| `let go` events (stale_give_back per event) | 13 (776-828) | 20 (584-776) | 8 (8-680) | 52 (448-648) | 11 (776-840) |
| parked, max | 50,600 | 631,212 | 130,816 | 375,456 | 159,672 |

- **Four of five legs at 625-634k on window 2, all five at 638-646k on window 1**: the best run of the campaign, and
  the cycle/import trace flat at 0.24-0.26 s for 90 s in every leg. Pd lost its window 2 at t+90 with the import at
  0.18 s -- the leader again, in the leg with the most let-go events.
- The ingest's doors are shut (0 drops in five legs). The queue's are not: `stale_give_back` still lets go of 450-840
  transactions an event, 8-52 events a leg -- a give-back path the fix of 2ab did not route -- and whole lane sets are
  still parked at some moment of every leg (up to 631k). `plan-v4/lane-holes-2`: which give-back, what parks, Pd's
  stall. The bar stands: window 2 >= 600k in every leg.

## 2ad. The counter was the chain working; the mass parks were a build for a decided height

`plan-v4/lane-holes-2` (merged). `stale_give_back` was not a hole: its samples are contiguous descending runs of one
sender -- the builder's own end-of-build give-back -- and nothing is ever dropped twice (a hole is re-offered and
re-dropped every build, as defect 13 showed). Under the build chain the puller applies a build's refusals late, by
which time the next build has taken those transactions, built them and the prune has raised the watermark. The lane
now keeps the chain's watermark apart from what a build's verdict raised; a transaction the chain's part filters is
`mined`, unsampled; `stale_*` now means "no block ever confirmed this", the shape a hole takes.

The nine mass parks in five legs were one shape: a second build for a height the chain had already decided, at a
handover, on the superseded parent -- behind the queue's pruning by two committed blocks, so every lane's lowest nonce
looked gapped and all 384 senders were parked (`parked` 537k -> 631k, `usable` 2,000, blocks at 8-118k for 1.4 s:
~half a million transactions an event). Guards: the diagnosis runs only when the build executed something, never for
a decided height (`canonical_head`, one atomic fed by the canonical subscriber), never when most senders look gapped;
parks capped at 64 lanes (`N42_TX_QUEUE_PARK_LANES`); `superseded=` on the build line. Pd's window 2 was two such
parks inside it.

## 2ae. The park costs more than the defect; five of five at 619-636k when it stays small (loop211-212)

loop211 (lane-holes-2 in): Pa / Pb 625-630k on both windows with `parked` 0 / 137k -- the cleanest legs yet -- and Pd
lost both windows (407k, then 75k at 24% occupancy: 55 empty builds, `parked` 559k despite the 64-lane cap,
`park_capped` 283k, one `stale_give_back` event of 6,464), Pe its window 3 (129k, `parked` 561k). loop212, an A/B on
`N42_TX_QUEUE_PARK_LANES=0` (which turned out to mean "no cap", not "off"): window 2 held in five of five (636k / 619k /
625k / 619k / 619k, window 1 630-636k), and the run's one bad window 3 (NPb, 75%) again carried a mass park (677k).

- Over loop210-212, fourteen of fifteen legs hold window 2 at 619-636k; the one that did not, and every lost window 3,
  carried a mass park of the sender set. The park was built to survive a hole; what it does at scale is manufacture a
  starvation. It goes off by default (`plan-v4/lane-holes-3`), keeping what the same work put right: the seal gate's
  shortfall, the stale-head diagnosis on the block's own state, the unmined give-back door, the ingest's ack by decoded
  count, the drop counters, `superseded=`.
- The four-node state, then: **window 1 630-646k, window 2 619-636k, cycle 0.252-0.263 s** on the P configuration
  (`run-loop212.sh`'s `CH`), the follower's import 178-202 ms with no waits, early seal 94-97%.

## 2af. Parking off: a parked lane is a sink

`plan-v4/lane-holes-3` (merged). `N42_TX_QUEUE_PARK_LANES=0` removed the cap, not the park; it now means off, and off is
the default. The mass parks did not come from the diagnosis the guards protect: the serial loop turns every
`NonceTooHigh` it meets into `NonceNotConsistent`, and `mark_invalid`'s gap branch parked once per transaction -- 329
lanes from one decided-height build in loop212 NPb, correctly labelled `superseded=true` and correctly ignored by the
diagnosis. And the cap could not have saved it: loop211 Pd held exactly 64 parked lanes while what they held grew
1,434 -> 5,505 transactions each (92k -> 560k), because a parked lane is a sink -- nothing drains it, the generator
keeps feeding its sender, and `gate_len` hides it from the ingest -- until ten consecutive empty blocks were committed
over a 370k queue. The legs that never parked were the cleanest of the campaign. Also fixed: a prune that ended a park
left the pruned part counted for ever. loop211 Pd's `stale_give_back` samples are not holes (133 distinct of 133;
ascending runs a prune confirmed a moment later, or lanes behind the chain).

## 2ag. Parking off is worse: a gapped lane refused every build (loop213)

| parking off | Pa | Pb | Pc | Pd | Pe |
| --- | --- | --- | --- | --- | --- |
| window 1 | 630k | 641k | 641k | 631k | 641k |
| window 2 | 488k | 369k | 608k | 614k | 353k |
| early seal | 96% | 82% | 94% | 97% | 81% |
| gapped heads reported (parks declined) | 28k | 221k | 93k | 8k | 270k |
| `gas=0` builds, not superseded | 0 | 0 | 0 | 0 | 26 |

Two of five against five of five with parks on (loop212) and four of five (loop210-211). Pb and Pe stalled at t+90-120
(cycle 0.61-0.86 s, the import at 0.12-0.14: the leader): with nothing parked, a lane whose head looks gapped is
refused by every build, and at 220-270k refusals a leg the serial loop churns and the builds go late or empty.
Neither mechanism is right, because both treat the symptom: a build sees most heads gapped when its PARENT is behind
the queue -- the queue pruned by blocks the parent does not have (a chained build on a block the chain replaced, a
handover build on a parent this node has not imported). The move is then to refuse the build and rebuild on the head,
not to refuse 163,000 candidates or park the senders: `plan-v4/stale-parent`.

## 2ah. The stale-parent hypothesis falsified: the collapse is node-local, gradual, and in the lanes

`plan-v4/stale-parent` (merged: instrumentation; the refusal built and off). loop213 Pe's 26 empty builds were chained
builds on the node's own previous block, canonical and committed before each build ran -- not a replaced block, not
a handover parent, not a stale parent (no reorg, no replaced own block, no pruner lag, no ingest drop, no generator
timeout in the leg). What the leg shows instead: on the stalling node `par_groups` -- the distinct senders a build was
offered -- falls 387 -> 326 -> 301 -> 251 -> 36 over twenty blocks while the queue holds 380-535k, so 383,412
transactions sit in ~36 lanes of ~10,600 each with every head refused (`NonceTooHigh`, 270k a leg); the committed
blocks go 165k -> 26k -> 9k -> 0 for twenty-four views, and the moment the tenure ends the next leader mines 163k a
block from the same flood. The two nodes that stalled carry `stale_refusal` 14-15k and `stale_give_back` 8-20k; the
two that did not, 6-18 and 0. What no line could say is which nonce is missing and on which side of the account nonce
a head sits: `the heads a build could not use` (sender, lane head, account nonce, head - nonce) and `holes a build ran
into that the pool cannot fill` (with `N42_TX_INGEST_DIRECT` the pool never has them, so the gap feed has dropped
every such hole silently since it was written) say it now. loop214 reads them.

## 2ai. The heads and the holes, on the fleet (loop214)

Four P legs with the two lines: window 2 625k / 636k / 538k / 598k, window 1 630-641k; Pd stalled in window 3
(287k: early seal 82%, 18 empty builds on canonical parents, `par_groups` p5 29, 281k `NonceTooHigh` reported). The
lines appear only on the nodes that stall (Pd node2: 22 `heads`, 32 `holes`; node0 11 / 9; healthy nodes 0 / 0), so
the instrument is on the defect. The stale-parent refusal, on, would have fired twice in four legs: not that. Being
read: the sign of head - nonce per sender, whether the missing nonce ever reached the node or any other node's block.

## 2aj. The door: a build's "behind the chain" verdict acted on for a block consensus did not keep

`plan-v4/lane-holes-4` (merged 0a107ef68). The heads a stalling node could not use had **account nonce 0** and lane
heads at 64, 192, 320 -- whole runs of `N42_TX_QUEUE_RUN` -- fixed from the moment they appeared, the same 29 senders
for forty builds; no other node ever reported those senders, and no canonical block ever carried their nonce 0: the
generator delivered them everywhere and one node's queue lost them. The door: three builds ran at once for heights
the chain had already committed, each on an own block consensus replaced; re-offered the sender's first run, each
refused it as "behind the chain" (its parent's state had the sender past that run), and `mark_invalid`'s stale branch
dropped the transaction and everything below it and raised the watermark so no give-back could return it -- 64
refusals removed the run for good. Fixed: a "behind the chain" verdict is acted on only as far as a canonical block
confirms it (`chain_mined`); past that the transaction goes back and the sender is skipped for the rest of that build
(one refusal a sender a build, which also removes the `stale_refusal` walk-ups); and a build for a height the chain
has already committed is cancelled before it selects anything (`N42_BUILD_SKIP_DECIDED=0` disables). Why three
builds ran for committed heights is not addressed; the cancel counts them. Confirmed on the fleet: pending (loop215
carries it).

**Checkpoint, tag `fleet4-plan-v4-p-20260922`, merged to `main`.** Four nodes, the P configuration
(`scripts/fleet7-runs/run-loop214.sh`'s `CH`, parking off): window 1 630-646k, window 2 619-636k when nothing stalls
(fourteen of fifteen legs over loop210-212), cycle 0.252-0.263 s. Known: `n42-testing`'s
`test_altsig_transfer__is_mined_and_typed_0x50` fails when the suite runs in parallel and passes alone or with
`--test-threads=1`, at this tag and at the previous one -- a process-wide flag another test sets first, not a
regression of this work; to be made order-independent.

## 3. What not to do

- Do not judge a cycle-shortening change at a pacing above the natural cycle; do not judge any change without R1.
- Do not shard the graft's map, stream the graft on the leader, widen the pools, or add flood concurrency: measured,
  each loses (section 1, loop176, loop178, loop180).
- Do not move work "behind the seal" and call it a gain: the leader has 190 ms of slack already. Only the vote path
  and, after step 2, the build-to-build chain count.
- Do not kill a runner without its fleet, or edit a crate between a runner's build and its claim: the runner's
  cleanup takes the fleet down now and its guard refuses a stale binary, but both cost a box window when tripped.

## 4. How this plan is run

One session holds the plan and the box: it decides the order, launches every runner, reads each leg against its
step's criterion, merges, and amends this document. Implementation goes to agents that start from nothing but a
brief: each works in its own git worktree, builds into `target/agents`, runs no cargo while a measurement holds the
box, never touches a runner, the claim files or a process, and hands back a branch (`plan-v4/<step>`) and a report
of what changed, what was tested and what could not be verified. Nothing reaches `feat/native-fleet7` unmerged by
the commander, and no crate is edited in the main checkout between a runner's build and its claim. Results are
appended to `FLEET7_PATH_AUDIT.md` section 9 as each step is judged; a step that fails its criterion is recorded
there with its numbers and dropped.

## 5. Plan v5: the ceilings between 640k and 1M, and the attempts (2026-09-22)

Where the four-node fleet stands after plan v4: window 1 630-646k, window 2 619-636k when nothing stalls, at a
0.252-0.263 s cycle with 163,000-transfer blocks (`docs/FLEET7_PLAN_V4.md` 2q-2ai). 1M TPS is either the same block at
a 0.163 s cycle, or a 260,000-transfer block at today's cycle, or anything between. Every number below is a
measurement from loop207-214 unless marked; the ceilings are given as the rate each would allow on its own, so the
lowest is the one that binds and the order of work is the order of the table.

| # | ceiling | measured today | rate it allows alone | what would move it |
| --- | --- | --- | --- | --- |
| 1 | **B, the followers' road to the 2nd vote** (proposal -> quorum) | 217 ms of the 252 ms cycle: transfer to the follower's EL 43, decode 63-73, sender look-ups 34 (5 with the queue index), check 5, hand-off/verify ~50 | ~750k at B = 217; B must be ~150 for 1M at 163k | the block described by hashes and assembled from the queue (B -60..80 measured, but the assembly copies; a sender-only look-up is 3 ms); the decode in the transport thread while the frame streams; the vote released before the body is fully materialised |
| 2 | **the leader's build period** (start of build n -> start of n+1) | 250-300 ms (par 213: pull 21, prep 11, exec 72, collect 18, commit 18, fold 76; seal at 225; encode 30) -- hidden by the chain today, but it is the block rate's floor | ~600-650k at 163k; must be ~160 ms, or the block must be 260k | the fold (76) and the collect/commit (36) are the graft's representation (plan v4 step 3: address -> batch index, tx root beside exec); the pull (21) is the queue's lock; the encode (30) is off the path with the chain |
| 3 | **the follower's import** (execute + root + insert) | 178-202 ms, no waits: exec 83-96 (groups 50 memory-bound: 32x threads = 2.4x), root 30-33 (tails 60-113), engine insert 49 | ~850k at 163k if it must stay under the cycle; a block behind is allowed (deferred execution), so it bounds throughput, not latency | the groups phase is memory-bound: fewer, larger accounts per group or a state layout that keeps a sender's runs local; the engine insert (49) is reth's tree -- keep the executed block out of it (`N42_FOLLOWER_DIRECT_IMPORT` already hands it in executed; what remains is the notification/canonical update) |
| 4 | **the supply**: every node verifies every transaction | ingest ~11 us CPU a transaction, 4 nodes x 550k/s = 6 cores a node at today's rate, 11 at 1M; the flood delivers 550k/s at 64 workers and more workers slowed the chain (loop197) | ~900k/s before the ingest's cores collide with the import's (28-core node: 18-19 used now) | the leader alone verifies at ingest; followers take senders from the block's evidence (the 0x50 batch verification is 3-4x cheaper than secp256k1 already); or a signature scheme with aggregation; or the flood's frames carrying pre-recovered senders that a follower checks in batch |
| 5 | **the leader's own commit / handover tax** | tenure handover 0.6-1.8 s each (64 blocks), 2-3% of the leg; `the parent is still importing` retried 22-82 times a leg | ~3% | the new leader building on the parent's published output (the leader twin, section 2v/2w: not cheap -- three pieces) or a longer tenure (`F7_LEADER_TENURE` 64 -> 256: 4x fewer handovers; a wire contract? no -- a fleet setting) |
| 6 | **consensus fixed costs** C (R2) + F (encode) + D (view open -> preamble) | 5 + 5 + 25-60 ms | ~1.2M at C+F alone; D is the pacing wait today | D is the pacing (225): at 1M the pacing is 150 and D is real -- the commit forkchoice is already off the loop |
| 7 | **memory and persistence** | 4 ELs 57-63 GB of 136; persistence keeps up with tx-lookup pruned | not binding at 4 nodes | -- |
| 8 | **the block's size itself** | 163,000 transfers at 3.423G gas; the cycle is linear in accounts touched (0.40 s + 2.8 us/account at 7 nodes, `docs/BLOCK_SHAPE_SURVEY.md`) | a 260k block at the same cycle IS 1M -- if 1-4 scale linearly with the block (they are per-transaction passes) the cycle grows ~1.6x and nothing is gained; if the fixed parts (C, D, F, handover, the pull's lock, the encode) are a third of the cycle, 1.3x | measure it: one leg at 5.4G gas (260k) with the current configuration says how much of the cycle is per-transaction |

**Reading it.** 1 and 2 are the two chains that alternate as the binding one (2j-2x); 3 is under the cycle now and
becomes the bound once 1 and 2 are cut by a third; 4 is the wall behind all three, because 1-3 run on the cores 4
spends. Nothing in 5-7 is worth a round before 1-4. **1M at 163k blocks needs B, the build and the import each cut by
~35-40% at once; 1M at 260k blocks needs the fixed parts to be a third of today's cycle** -- and that is a single leg
to find out (8), before any code.

**The attempts, in order, each with its falsification:**

- **A. The 260k block (8), one round, no code.** `--gasceil 5460000000` (260k transfers), pool 4 blocks scaled
  (`F7_BENCH_POOL_SLOTS` 1,040,000), `--pertx` raised, index bound raised. Read the cycle and its dissection. If the
  cycle is under 0.34 s the per-transaction share is under two thirds and the rest of this plan is about the block size
  as much as the cycle; if it is 0.40+ the per-transaction passes are everything and the plan is 1-4 only.
- **B. Supply off the followers' cores (4).** Followers stop verifying signatures at ingest for transactions they will
  only see again in a block: the ingest keeps the raw transaction and its hash, recovery happens on the road from the
  block's sender list (0x50: the batch verification the follower runs today for misses, 128 a batch; secp256k1:
  `recover_signer` on the pool). This turns 6-11 cores of ingest into ~1 on three of four nodes and moves the work to
  the vote road, where it is batched. Falsified if B grows by more than the ingest's cores buy (the leg's per-thread
  table decides: tokio-rt 9.7 -> ?).
- **C. B by the block's description (1).** The compact body's assembly copied transactions and lost (2r); a body that
  carries hashes and the follower's road that looks up sender + the transaction's *bytes offset in its own ingest log*
  (no copy, no decode: the ingest keeps the frame) and computes the root from the kept bytes. The vote needs the
  root, the senders and the includability check -- none needs the transactions decoded if the ingest kept the decoded
  form. Target B 217 -> 150. Falsified if the road's execution-layer part is not under 60 ms on the fleet (2r's was 197).
- **D. The graft's representation (2), plan v4 step 3.** fold 76 + collect/commit 36 of the leader's 213 ms `par`:
  address -> batch index instead of per-address maps, the tx root beside the execution, the pull pre-walked. Target
  the build period 250-300 -> 180. Falsified if `par_fold_ms` does not halve on the fleet.
- **E. The import's groups (3).** Memory-bound at 50 ms; the state layout (QMDB slots by first touch) makes a sender's
  accounts scattered; a per-block prefetch of the ~150k touched accounts before the groups run (the block names them)
  converts random reads into a streaming pass. Falsified if `groups_ms` does not fall under 35 with prefetch on.
- **F. Handovers (5).** `F7_LEADER_TENURE=256` -- one leg, no code; then the leader twin if the 3% matters at the end.

### 5.1 Attempts A and F (loop215): the block size is not a lever; the tenure is

| | P (reference) | G260 a / b (260,000-tx blocks) | T256 a / b (tenure 256) |
| --- | --- | --- | --- |
| window 1 | 635k | 532k / 591k | **663k / 663k** |
| window 2 | 625k | 481k / 430k | 625k / 647k |
| cycle | 0.257 | **0.476 / 0.435** | 0.246 |
| R1 / import / build | 150 / 185 / 274 | 265-276 / 312-366 / 358-410 | 145-148 / 189 / 274-275 |
| handovers (`still importing`) | 35 | 131 / 163 | 13 / 54 |
| early seal | 96% | 94-96% | 98-99% |

- **A, falsified.** A block 1.6x larger costs a cycle 1.7-1.9x longer: R1 x1.8, the import x1.7-2.0, the build x1.3-1.5.
  The per-transaction passes are the whole cycle and then some (the queue's deeper pool and the 26 -> 42 MB body cost
  more than proportionally). The block size stays at 163,000; 1M is the cycle, and 1-4 of the table are the plan.
- **F, adopted.** `F7_LEADER_TENURE=256`: 663k on window 1 in both legs (the best yet), window 2 625k / 647k, the
  handover tax a quarter of before, early seal 98-99%. The configuration carries it from here.
- lane-holes-4 on the fleet: `the heads a build could not use` with account nonce 0 -- **0 in every leg** (the fix's
  signature); `stale_unconfirmed` 310-6,061 says how often a build stood on a state consensus did not keep, a reading.

### 5.2 The block size's sweet spot (loop216): 163k, and the cycle is per-transaction

Four sizes at four nodes (tenure 256; each size paced near 0.9x its cycle; window 1 / window 2, medians of the legs):

| transfers a block | 120,000 | 163,000 | 200,000 | 260,000 |
| --- | --- | --- | --- | --- |
| cycle (window 1) | 0.195-0.197 s | 0.252 s | 0.319 s | 0.435-0.476 s |
| TPS, window 1 / 2 | 607-616k / 588-596k | 646-663k / 619-647k | 619-620k / 479-598k | 532-591k / 430-481k |
| R1 / import / build (ms) | 105-110 / 138-140 / 212-216 | 145-153 / 189-198 / 274-283 | 188-197 / 255-305 / 343-379 | 265-276 / 312-366 / 358-410 |

- **163,000 is the sweet spot, and it is flat**: 616k below it, 620k above it, 560k at 260k. Not a lever.
- **The cycle is per-transaction with a ~35 ms fixed part**: 120k -> 163k adds 1.33 us a transaction, 163k -> 200k
  1.8, 200k -> 260k 2.3 (the pool deeper, the body larger, the passes less cache-friendly); the intercept of the first
  segment is 35 ms -- 14% of the cycle. R1 scales at 0.9 us a transaction, the import at 1.4, the build at 1.6. So
  1M at any block size means the three per-transaction chains (1-3 of the table) cut by ~40% together; nothing in the
  fixed part is worth more than 5% of the way.

### 5.3 Attempt B, falsified on the bench: verification is a relocation, not a saving

`plan-v5/supply-off-followers` (merged, `N42_INGEST_VERIFY=leader` off by default): followers queue a transaction under
the sender its frame claims, the builder verifies what it includes in batches, the vote road verifies every claimed
sender itself and compares. The bench (`n42-tx-types/tests/road_senders`, 163,000 transactions, 16 threads): 0x50
batch verification **132-135 ms** (13.0 us of CPU a transaction; one at a time 379), secp256k1 recovery 308-310; the
ingest's own cost with verification off 0.72 us (0x50) / 0.16 (secp256k1). The bar was 25 ms (2.45 us a
transaction); the cheapest signature is 5.3x that. And the arithmetic: the ingest gives back 550k/s x 13 us = 7.2
cores a node, and the road takes +132 ms on a B of 217 in a 252 ms cycle -- a third off the rate before the cores do
anything. Every node verifies each transaction once either way; B moves that work from a background pool onto the
binding path. Not run on the fleet: the bench and the arithmetic agree and are not close. What does clear the bar is a
cheaper signature -- aggregation -- and, as configuration, the ingest's pool made smaller and lower-priority so it
contends less with the import (`N42_TX_INGEST_RECOVER_PARALLEL`, `N42_TX_INGEST_RECOVER_NICE`): loop217.

### 5.4 The ingest's pool as configuration (loop217): not a lever either

| | P (12 threads, nice 10) a / b | R6 (6 threads) a / b | R8 | R12N19 (nice 19) |
| --- | --- | --- | --- | --- |
| window 1 / 2 | 652k / 630k, 657k / 560k | 534k / 526k, 531k / 523k | 627k / 605k | 657k / 635k |
| occupancy | 99% | **77%** | 92-94% | 99% |
| ingest slots busy | 62-63% | 92-93% | 87% | 64% |
| R1 / import / build | 150-153 / 206-212 / 260-271 | 82-94 / 133-137 / 177-180 | 133 / 180 / 243 | 146 / 205 / 263 |

- Six recover threads starve the queue (occupancy 77%, the pool 92% busy: the ingest cannot keep up with 650k/s at
  13 us a transaction on six threads) and every chain phase is faster because the blocks are three-quarters full --
  the same shape as loop197's "more supply is a slower chain", from the other side. Eight threads: 92% full, no gain.
  Nice 19 against nice 10: identical. **Ceiling 4 is what the bench said: the signature's cost, not its scheduling**,
  and only a cheaper signature moves it.
- Pb's window 3: six blocks in 30 s (a 5 s cycle, 5 timeouts) -- a stall shape not seen before; one leg, read later.

Attempt D (`plan-v5/graft-representation`) was interrupted mid-implementation by the account's spend limit; its
uncommitted state is saved as a WIP commit on the branch (unbuilt, untested) to be resumed. C and E wait for the same.

### 5.5 Pacing 200 with tenure 256 (loop218): the cycle is B's now, not the pacing's -- and a stall that stops the chain

| | P225 | P200 a / b / c |
| --- | --- | --- |
| window 1 | 663k at 0.246 s | 663k / 657k / 663k at 0.244-0.248 s |
| window 2 | 614k | 636k / 440k / 375k |
| window 3 | 630k | 619k / 597k / **0 (the chain stopped; 6 TCs)** |

- **Pacing stays at 225.** At 200 the cycle does not move (0.244-0.248 against 0.246): B (~217) plus the fixed parts
  is the cycle, and the pacing no longer binds; what 200 does is lose windows (two of three).
- **A stall that stops the chain, twice now**: loop217 Pb's window 3 (six blocks in 30 s, five TCs) and loop218
  P200c's (no block at all in window 3, six TCs, the chain 510 blocks against ~970). Not seen before tenure 256 was
  adopted (loop215-218 = the tenure-256 legs; 4 of 22 legs). Being read: what a view timeout at tenure 256 looks like
  -- the leader's build, the parent's import, the queue -- and whether it is the tenure or the pacing.

### 5.6 The stall that stopped the chain: a `Cancelled` that panicked the execution layer (defect 14, fixed)

The analysis of loop217 Pb and loop218 P200c: in both, node2's execution layer crashed -- reth's payload-builder
service hit `unreachable!("the cancel signal never fired")` (basic/src/lib.rs:493) because the build for a height the
chain had already decided (0a107ef68, `N42_BUILD_SKIP_DECIDED`, on by default) answered `BuildOutcome::Cancelled`, an
outcome reth reserves for its own cancel signal. The process exited; the leader rule is `(view / tenure) % n` and a TC
moves the chain on by one view, so the dead node stayed leader for the rest of its tenure with timeouts backing off
6 -> 12 -> 24 -> 30 s: at tenure 256 that is ~2 h, at 64 ~30 min -- the tenure sets how long the stall lasts, not
whether it happens. The same panic is in six legs since loop215 (215warm, 215P, 216S120b, 217R6a, 217Pb, 218P200c) and
none of the thirty before; the counter "2 of 22" undercounted it. Every timeout reads `proposed=true` though no
proposal was sent (a label to fix). Followers were idle and clean; the queue held 436-564k usable; the flood ran until
the crash. Fixed (a41862b95): both early returns answer `Aborted` (a build that chose not to produce), which the job
logs at debug and retries; the rate limiter's first call prints now. A liveness backstop (skip a leader after a TC)
would change `verify_leader`, a rule shared with gov5 -- not taken. loop219 confirms.

Confirmed (loop219, four P legs): 0 panics, tc = 1 in every leg, every window over 90 blocks (min 92-114); the decided-
height line now prints (1); window 1 646-668k, window 2 522-646k. The leg-to-leg spread of window 2 (2 of 4 under
600k, the import and R1 unchanged) is the residue plan v5's C/D/E address, not a stall.

### 5.7 Attempt C on the fleet (loop220): B halved, and the pacing is the cycle again

`N42_BLOCK_BY_DESCRIPTION=1` (merged ce965a896): the follower's execution layer resolves the block's hashes to the
queue's own `Arc`'d transactions, encodes them into chunk buffers and roots over those; the owned clone reth's types
force is ~3 ms.

| | P a / b | C a / b / c |
| --- | --- | --- |
| vote road total | 120 / 121 ms | **69 / 69 / 65** |
| R1 | 148 / 148 | **77 / 76 / 73** |
| B (dissected, window 1) | 139.5 | **71-73** |
| D (view open -> preamble) | 81 | **147** |
| cycle | 0.246-0.248 | 0.242-0.244 |
| window 1 / 2 | 657k / 636k, 663k / 636k | 668k / 641k, 674k / 641k, 668k / 641k |
| window 3 | 603k / 613k | 483k / 494k / 565k |

- **The road is halved** (B 140 -> 72; the fill asks the proposer 370-390 times a leg, none fails, 2-3 whole-body
  fallbacks) **and the cycle does not move**, because every millisecond B lost went to D: at pacing 225 the leader
  waits at the preamble for the pacing, and the cycle is 225 + ~15. Window 1 +1.5%, window 2 +1%.
- So the pacing binds again -- and below it the build period (250-300, hidden by the chain until now) is the next
  wall, which is what attempt D is cutting. loop221 lowers the pacing with C on (175 / 150) to measure how much of the
  build the chain can hide and where E reappears.
- Window 3 is lower with C (483-565k against 603-613k): to read when the pacing legs are in.

### 5.8 Below the pacing, the build period is the wall at ~232 ms (loop221)

C on (B 71-96), the pacing swept:

| pacing | 225 | 175 a / b | 150 | 125 |
| --- | --- | --- | --- | --- |
| cycle | 241.6 | 229.8 / 233.6 | 235.0 | 232.6 |
| D (pacing wait) / E (waiting for the build) | 146 / 9 | 92 / 46, 90 / 50 | 44 / 74 | 45 / 81 |
| window 1 / 2 | 668k / 641k | 679k / 630k, 679k / 636k | 674k / 641k | **685k / 652k** |
| build total / the chain's lead / wait | 270 / 109 / 190 | 269-277 / 80 / 212-217 | 275 / 82 / 216 | 271 / 86 / 208 |

- **The cycle stops at 230-235 ms whatever the pacing below 225**: the pacing wait (D) turns into the wait for the
  leader's own build (E, 9 -> 80). The build period the chain hides is ~232 ms -- the wall. B (72), the import
  (160-186) and everything else are under it now. Window 1 679-685k, window 2 630-652k, no window lost in five legs.
- **Pacing 175 and C join the configuration** (125 read the best leg but one; it is tried again once the build moves).
- **Attempt D is the whole plan from here**: the build period 232 -> 160 is 1M at this block (163k / 0.16 = 1.02M),
  with B and the import already under 160. Its parts on the leader's line: par 213-241 (pull 21, prep 11, exec 72-81,
  collect 18, commit 18-22, fold 76-86), seal, state_ready 18-20, roots 44-48, finish 65-73. The chain starts the
  next build at the seal (lead ~85 ms), so the period is `sealed_at` + (the next build's wait for the state) -- the
  fold, collect and commit are on it; the roots and finish are hidden if the next build's state read waits for them
  (`find_ms` on the chained request says). E (the import's prefetch) is not on the path any more.

### 5.9 Attempt D on the bench: the graft was page faults, not probes (`plan-v5/graft-representation-2`)

`bench_build_run` (162,000 transfers, 6,000 senders in runs of 27, recipients from two million, `RAYON_NUM_THREADS=16
taskset -c 0-31`, idle box, three rounds) now prints the leader's phases apart. Against the four-node legs it
reproduces the graft (42-54 ms against 56-64), the commit at half (9.5-10.5 against 18-22) and the collect at a
quarter (4-5 against 18): the last two are moves of pool-allocated transactions on a node whose memory three others
share, which an idle bench does not have. The transactions root beside the graft is 13.5-16 ms, under the graft.

`bench_map_insert` took the graft apart: 161,760 accounts inserted into a map just reserved cost 27-30 ms in random
order and 29-30 in the map's bucket order; into the same map once its pages are mapped, 18 and 7.5. The fleet's
allocator hands a table this size fresh pages every block (`oversize_threshold:0`, `thp:never`), so the leader paid a
page fault for every fifteen accounts inside its build chain. Hence the three switches (all off by default):

| bench, ms (three rounds) | collect | commit | graft | exec |
| --- | --- | --- | --- | --- |
| today (fold in place) | 4-5 | 9.5-10.5 | 42-45 | 94-96 |
| `N42_GRAFT_INDEX=1` (the WIP: sorted (bucket, address, batch) touches, one pass) | 5 | 9.5 | 60-62 | 95 |
| `N42_GRAFT_RANGES=1` (the same, the merge pass on the pool in address ranges) | 5 | 9.5-10 | 53-55 | 94-96 |
| `N42_BUILD_COLLECT_IN_PLACE=1` | **0** | **5** | 44.5-46 | 95-96 |
| + `N42_GRAFT_PREFAULT=1` (map and revert list mapped beside the execution, 31-37 ms on its own thread) | 0 | 5 | **26.5-27** | 97-98 |
| + prefault + `N42_GRAFT_RANGES=1` | 0 | 5 | 35.5-36 | 97-98 |

- **Direction 1 (address -> batch index) and 2 (ranges on the pool) are falsified on the bench.** Writing the block's
  map in bucket order saves less than listing, sorting and moving every account a second time costs, with or without
  mapped memory. Kept behind their switches for one leg on a loaded node, where locality may be worth more.
- **What pays is not the representation but the memory**: the prefault takes the graft 42-45 -> 26.5-27 for 2-3 ms
  of execution, and leaving the transfers in their slots takes collect + commit 14-15 -> 5 (the body is copied out of
  the slots once, on the pool; the order is a vector of pointers). One probe per account in the graft (`entry` in
  place of a look-up and an insert, behaviour-neutral, in the default path) is another 2 ms.
- **Direction 3 is not there to take**: the QMDB operations are sorted by gov5's key, a hash of the address, so no
  order the fold can leave helps `roots_ms`; `state_ready`'s merge is 5-7 ms on the bench. Direction 4 is not needed
  while the root (14 ms) stays under the graft (27).
- The bench's leader chain, collect + commit + graft: 58-60 -> 31.5-32 ms. On the fleet that is 112 -> ~45-55 if the
  leg's collect and commit shrink as the bench's do; the prefault's cost to `par_exec_ms` is the thing a leg must read.

What a four-node leg must read, `N42_BUILD_COLLECT_IN_PLACE=1 N42_GRAFT_PREFAULT=1` against the reference:
`seal-first build phases` `par_collect_ms` 18 -> ~0, `par_commit_ms` 18-22 -> ~10, `par_graft_ms` (new) and
`par_fold_ms` 76-86 -> ~40, `par_exec_ms` not up by more than ~5, `par_prefault_ms` (new, beside) under `par_exec_ms`,
`sealed_at_ms` and the build period down by ~50; window 2 >= 600k; verify 4/4.

### 5.10 Attempt D on the fleet (loop222): the prefault buys nothing there

| `seal-first build phases`, medians | R a / b | G (collect in place + prefault) a / b | GR (+ ranges) |
| --- | --- | --- | --- |
| collect / commit / fold (graft) | 9 / 12 / 63 (49), 8 / 14 / 65 (48) | 0 / 16 / 67 (48), 0 / 17 / 68 (48) | 0 / 17 / 87 (66) |
| exec / prefault (own thread) | 63 / --, 69 / -- | 69 / 36, 71 / 37 | 82 / 38 |
| sealed_at / total | 185 / 235, 195 / 255 | 188 / 249, 191 / 253 | 224 / 292 |
| cycle (dissected) / E | (stalled) / --, -- | 239 / 55, 233 / 51 | 257 / 70 |
| window 1 / 2 | 650k / 509k (b) | 684k / 655k, 685k / 575k | 619k / 418k |

- **The collect in place is real (9 -> 0) and the prefault is not**: the graft reads 48 ms with the pages touched
  ahead exactly as without, `sealed_at` does not move, and the build's total is 10-15 ms longer for the thread. The
  bench's page-fault reading (fresh pages every block) does not hold on the fleet -- its heaps run `thp:always` with a
  2 s dirty decay, so the map's pages are resident already; what the fleet's 48 ms graft is remains unmeasured on the
  fleet (the bench's 42-45 reproduced the number but not the cause). Ranges are worse under load (87), as idle.
- Kept: `N42_BUILD_COLLECT_IN_PLACE=1` (collect 0; commit +3 for it, net ~-6). `N42_GRAFT_PREFAULT` and the folds stay
  off. The build period is still ~232; par is exec 63-71 + graft 48 + commit 16 + pull 21 + prep 11 with the seal at
  185-195. Next, as configuration first: the leader's streamed graft (`N42_GRAFT_STREAM=1`, falsified as a default at
  seven nodes with 16 cores, untested at 28) and the builder's pool at 28 threads now that the build is the wall.

### 5.11 The build as configuration (loop223): the streamed graft moves the cost, the wider pool adds to it

| `seal-first build phases`, medians | R | S (graft stream) a / b | T (rayon 28) | ST |
| --- | --- | --- | --- | --- |
| exec / fold (graft) / commit | 65 / 73 (55) / 16 | 106 / 41 (0) / 15, 104 / 42 / 16 | 67 / 73 (56) / 15 | 103 / 38 / 15 |
| sealed_at / total | **186** / 243 | 197 / 253, 194 / 251 | 202 / 258 | 193 / 250 |
| cycle / E | 229 / 40 | 232 / 47, 236 / 53 | 243 / 57 | 240 / 55 |
| window 1 / 2 | **690k** / 636k | 685k / 614k, 674k / 636k | 652k / 598k | 657k / 619k |

- The streamed graft takes the fold from 73 to 41 and puts 40 ms into exec (65 -> 104-106): the graft's work moved
  onto the execution's threads, the seal is 8-11 ms later. Falsified again, at 28 cores as at 16. The pool at 28
  threads is slower everywhere (seal 202). Both stay off. The reference read 690k on window 1, the best leg yet.
- **The parallel step is the wall**: `sealed_at` 186 = pull 21 + prep 11 + exec 65 + commit 16 + fold 73, and the build
  period is that plus ~45. The chain hides the roots and the finish already. To 160 ms the graft (55 ms, the same on
  the fleet whether the map's pages are touched ahead or not, whether the fold is indexed or ranged) must be
  understood on the fleet, not the bench: a profiled leg (`cargo build --profile profiling`, `perf` on the leader's
  execution layer during window 1, `--no-inline`) is the next step, and no agent until it has been read.

Each attempt is one agent brief and one runner; the bar for adopting any is the same as plan v4's: window 2 in every leg,
verify 4/4, and the number it targets moving on the fleet, not on a bench.

## 6. Plan v6: the ceilings between 690k and 1M, redrawn after plan v5 (2026-09-24)

Where it stands: four nodes, the configuration of 5.8 plus `N42_BUILD_COLLECT_IN_PLACE=1`, window 1 674-690k, window 2
614-655k, cycle 229-236 ms, 163,000-transfer blocks. 1M is this block at a 163 ms cycle (5.2: the block size is not a
lever; the cycle is per-transaction). What plan v5 settled: B is halved (C), the supply's cost is the signature and
not its scheduling (B, 5.3-5.4), the tenure is 256 (F), the follower's import is pipelined and under the cycle. What
binds now is one thing.

| # | ceiling | measured (loop221-223) | rate it allows alone | to 163 ms |
| --- | --- | --- | --- | --- |
| 1 | **the leader's parallel step + the chain's restart** = the build period | `sealed_at` 186 = pull 21 + prep 11 + exec 65 + commit 16 + fold/graft 73; the next build starts ~45 after the seal (waits for the parent's state, `find_ms` 15-20, `queue_ms` 16); period ~230 | **~710k** | the step to ~120 and the restart to ~15: graft 73 -> ~15, exec 65 -> ~35, pull+prep 32 -> ~20 |
| 2 | B, the road to the 2nd vote | 72-83 (transfer 43 is most of it now) | ~1.5M | nothing until 1 is done |
| 3 | the follower's import | 160-186 (exec 84-96, root 30, insert 49), pipelined | ~900k; must stay under the cycle | at 163 ms it is level: exec's groups (50, memory-bound) need the prefetch |
| 4 | the supply's signatures | 13 us CPU a transaction (0x50 batch), 550k/s = 7 cores a node of 28 | ~1M before the ingest collides with 1 and 3 (13 cores at 1M) | a cheaper signature only; not this plan |
| 5 | fixed parts: C + F + the pacing floor | ~12 ms + pacing 175 (the cycle is 230 anyway) | -- | pacing to 125 once 1 moves |

**The attempts, in order of what they are worth, each with its falsification:**

- **G. The graft's 55 ms, named on the fleet first** (loop224, a perf leg of the leader's execution layer; no agent
  until it is read). Then the representation: for transfers every recipient update is an ADD -- commutative -- so the
  batches need not carry bundle states to merge: a batch keeps (sender: final nonce, balance) and (recipient: delta);
  the block's bundle is one parallel sort of ~300k (address, delta) keys and a linear sum, not 163,000 probes into a
  43 MB map. The fast-transfer path (`N42_FAST_TRANSFER`) already knows a transaction is a plain transfer.
  Falsified if `par_fold_ms` does not fall under 25 on the fleet with roots identical on four nodes.
- **H. The leader's execution at 65 ms** = 6.4 us of CPU a transfer on 16 threads: a plain transfer is ~1 us of
  work, the rest is the state read (QMDB read view, cache misses on 150k scattered accounts). The pull knows every
  sender and recipient before the execution: prefetch the block's accounts into the cache on the pool while the pull
  and prep run (`N42_BUILD_PREFETCH=1`), so the execution reads warm memory. Falsified if `par_exec_ms` does not fall
  under 45 with the prefetch hidden behind pull+prep.
- **J. The chain's restart at ~45 ms**: the next build waits for the parent's state to be installed (`StateReady`,
  15-20) and the queue's hand-off (16); a build on the parent's *published output* (as the follower executes, 2w) would
  start at the seal. Falsified if `find_ms` + `queue_ms` on chained builds do not fall under 10.
- **I. pull + prep at 32 ms**: the puller's batches and the transaction environments could be made during the previous
  block's fold (the queue's next run is known). Last, smallest.
- **E (import prefetch)** is needed at 163 ms, not before: the import is level with the cycle then.

If G + H + J land as sized, the parallel step is ~120 and the restart ~15: a 135 ms period, and the cycle is then B
(72) + D/E small + fixed ~12 = ~100-135 ms -- 1.2M at this block. The pacing then goes to 125 or off.

### 6.1 Attempt H on the bench: the leader's reads contend on the read view (plan v6, ceiling 1)

`plan-v6/build-prefetch` (merged d644bdbe5, `N42_BUILD_PREFETCH=1` off): the parallel build uses no `CachedReads`; each
batch opens its own `State` over a `MemoryOverlayStateProvider` on the QMDB read view, so every account's first read
in a batch goes to the view. Warming the builder's own layer halves the execution on the bench (32-35 -> 16-17 ms;
the bench's exec is 0.5x the fleet's 65) -- but the prefetch itself costs 35-37 ms of wall and 545-585 ms of pool
time for 159,230 accounts: **3.5 us a read with sixteen threads reading at once against 0.7 us alone**. That is the
finding, and it is bigger than H: the leader's execution (65) and the follower's groups (50, "memory-bound": 32x the
threads gave 2.4x, 2t) are concurrent reads of the view contending -- the suspect is `read_at`'s global `versions`
RwLock, taken and held for every read (read_view.rs:218). `plan-v6/read-view-concurrency` (K): a snapshot per batch of
reads, the record read outside any lock, truncation kept safe; the bar is 16 threads at ~1 us a read, then exec and
groups on the fleet.

### 6.2 Attempt J on the fleet (loop225): the restart at the seal, 723k

| | R a / b | J (`N42_BUILD_ON_OUTPUT=1`) a / b |
| --- | --- | --- |
| window 1 / 2 | 690k / 636k, 685k / 636k | **723k / 650k, 678k / 665k** |
| cycle (dissected) / E | 230 / 44, 229 / 45 | **220 / 36, 219 / 33** |
| chained `find_ms` / `queue_ms` / total | 15 / 16 / 272, 15 / 17 / 270 | **0** / 18 / 258, 0 / 18 / 256 |
| `sealed_at` / total | 190 / 247, 186 / 243 | 223 / 288, 223 / 285 |

- The chained build starts at the parent's seal (`find_ms` 0), the build period 230 -> 220, window 1 723k -- the
  best leg of the campaign -- and window 2 650-665k. `sealed_at` reads 33 ms later because the build now begins
  earlier and its `setup` includes the wait for the parent's bundle; the period is what counts. Adopted.
- `queue_ms` 18 is the fold of 163k nonces (`queue_fold_us` 6-7 ms) plus the walk, lock 0: now beside the build.
- With the period at 220 the pacing (175) is binding again: D 92-95. loop226 lowers it with J on.

### 6.3 Pacing below 175 with J (loop226): the wall is at 218-222 ms, and the low pacings lose windows

| pacing | 175 | 150 a / b | 125 a / b |
| --- | --- | --- | --- |
| cycle (dissected) / D / E | 221 / 89 / 35 | 222 / 71 / 46, 219 / 71 / 52 | 218 / 49 / 61, 222 / 50 / 58 |
| window 1 / 2 | 619k / 424k | 673k / (87k, a 1.9 s stall), **727k** / 652k | 718k / 672k, **735k** / (255k, a 0.64 s stall) |

- The cycle floors at 218-222 ms whatever the pacing: the pacing wait (D) becomes the wait for the build (E). The
  build period with J is ~220 -- the wall. Window 1 reads 727-735k at 125-150 (the best legs yet) and two of four low
  pacing legs lost their window 2 to a stall (1.9 s and 0.64 s cycles, no panic, 1-2 TCs); 175 lost one too this
  round. **The pacing stays at 175** until the wall moves; the stall shape at 150/125 is read once it recurs at 175.
- What the wall is made of, with J: the leader's parallel step (pull 21 + prep 11 + exec 65 + commit 16 + graft 73 =
  186) plus the seal and the next build's setup. K (the read view under concurrency: exec 65) and G (the graft 73)
  are the two cuts; each is worth ~30-40 ms of the 220.

### 6.4 Attempt K on the fleet (loop227): neutral -- the reads were never the bound there

| | J175 legs without the change (loop225-226) | K a / b / c / d |
| --- | --- | --- |
| leader `par_exec_ms` | 62-65 | 60-64 |
| follower `groups_ms` / import exec | 60-71 / 103-111 | 65-70 / 102-110 |
| window 1 / 2 | 678-723k / 650-665k | 723-728k / 632-654k |

- The striped lock is noise on the fleet in both directions (my first reading of a follower regression compared
  against loop203-209's numbers, before C and J; the J legs already read 103-111 / 60-71). Reverted as neutral; the
  bench commit stays. The bench's 6x at 16 threads is the idle box's, where every read reaches the view.
- The lead it leaves: on the fleet the view's head sits ~20 blocks behind the chain (`reader_lag` 21-26 with the
  hashed tables off), so most of a block's account reads are answered by the in-memory overlay of unpersisted blocks
  -- a walk of up to ~20 bundle maps per account -- before any read reaches the view. Unmeasured; a counter of reads
  answered per overlay depth settles it (L). If so the 65 ms of the leader's execution and the follower's 65-70 of
  groups are the overlay's depth, and the lever is a flatter overlay (one merged map kept incrementally) or a view
  that runs closer to the head.

### 6.5 The overlay's depth as configuration (loop228): not it, and the counter says the reads go elsewhere

| | R | PT2 a / b (persist at 2, buffer 2) | PT4 | Dc (counts on) |
| --- | --- | --- | --- | --- |
| leader exec / `sealed_at` | 61 / 213 | 69 / 227, 71 / 227 | 68 / 222 | 66 / 225 |
| follower groups / import exec | -- | 68 / 108, 69 / 110 | 58 / 102 | 69 / 109 |
| `reader_lag` max | 14 | 19 / 18 | 12 | 30 |
| cycle / E | 220 / 38 | 227 / 40, 224 / 40 | 225 / 43 | -- |
| window 1 / 2 | -- | 690k / 670k (b) | 630k / 500k | 616k (2) |

- Persisting within two blocks moves nothing (exec 69-71, groups 68-69) and the view's lag barely (18-19): the
  in-memory overlay's depth is not the cost. Falsified as configuration.
- The counter: the leader's build makes ~3,966 counted account reads a block, the follower's import ~3,128, all at
  depth 0 and none historical -- against ~150,000 distinct accounts a block. **The execution's reads do not go through
  the overlay provider the counter wraps**: the fast-transfer path reads through another door (K's report: the hot
  callers reach the view through `N42StateReader`, a vendored trait). So neither the view's lock (K) nor the overlay's
  depth (L) is what 65 ms of execution and 60-70 of groups are made of, and the two benches that "reproduced" the
  numbers reproduced them by other causes. The instrument that says where those milliseconds go is a profile of the
  running leader; failing that, timers inside the fast path (reads / EVM / write-back) and inside the graft.

### 6.6 Timers inside the fast path and the graft (loop229): the reads are the execution, the insert is the graft, and the seal waits for neither

`plan-v6/fast-path-timers` (merged 81288dda4, `N42_PHASE_TIMERS=1` off): every 64th `transfer` call on a worker is
timed in full (reads / qualification+arithmetic / touched-account build / rest) and the sum scaled by the call count;
the read doors are counted exactly (cache, state provider, QMDB view). The graft's in-place fold is split into base
swap / reserve / insert / reverts. loop229, four nodes at the CH configuration, pacing 175:

| leg | win1 | win2 | note |
| --- | --- | --- | --- |
| warm | 717,169 | 645,717 | |
| T (`N42_PHASE_TIMERS=1`) | 722,546 | 634,320 | the timers cost nothing visible |
| R | 657,255 | 700,826 | win1 a bad window; win2 the leg's number |

The leader's `seal-first build phases` on a full block (medians of the T leg; pool time is the sum over the 16
build threads):

| | wall ms | pool ms | of which |
| --- | --- | --- | --- |
| `par_exec` (the transfers) | 66 | 436 | reads 379, EVM 15, write 32, other 10 |
| `par_graft` (the fold) | 58 | -- | base 1, reserve 9, **insert 40**, reverts 6 |

Reads a block: 488,612 attempted -- 325,585 answered by the batch's own cache, 59,089 by the state provider,
103,938 by the QMDB view. So the doors are hit once per account the block touches (~163k) and the other two reads a
transaction are cache hits; 379 ms of pool time over ~163k door reads is **~2.3 us a read**, the same number 6.1
measured on the bench for sixteen threads reading at once (3.5 us, against 0.7 alone). The follower's
`parallel import phases` say the same (groups 69: reads 261, EVM 15, write 31, other 10; 72,682 provider, 70,647
view). Two facts follow. (1) **87% of the execution's pool time is the account reads**, not the EVM and not the
write-back; K's striped lock did not change them, so the contention is below the lock -- the view's lookup itself
under sixteen readers, or the provider door (the overlay stack over MDBX) which the fleet uses for a third of the
door reads and the bench does not. (2) 436 ms of pool time over a 66 ms wall is 6.6 threads of 16 busy inside
`transfer`: the remaining 60% of the wall is outside the timed region (per-batch `State` and environment setup,
receipts, scheduling, or waiting) and the timers cannot see it. A profile still owes that split (perf is blocked:
`kernel.perf_event_paranoid` = 4).

The graft is one thing: **the single-threaded insert of the block's ~147k touched accounts into the block's bundle
state, 40 of 58 ms, 270 ns an account** -- two or three cache-missing probes into a map of that size, memory latency,
not computation. A parallel representation (attempt G as sized) would shard that map and save perhaps 25-30 ms.

But the bigger thing is where the seal sits. The seal-first path (payload.rs ~1285-1700) needs, of the block's own
execution, only the transaction set and the transactions root, which is computed *beside* the graft precisely because
the graft's 60-100 ms hide it (loop139); the state root, receipts root, logs bloom and gas used it writes are the
parent's. The commit (14-18), the graft (40-59), the beneficiary credit and the withdrawal put-back all run before
`hook(payload)` -- the proposal -- by code order alone, and the same machinery that already runs the roots behind the
seal (`behind_the_seal`, `parent_executed_fields_or_built` with its wait, `StateReady` for the chained build) would
carry them. Sealed at 185-197 today; pull 26 + prep 11 + part 3 + exec 55-63 + the seal's own 4-7 puts it at
**~115-125 if the transactions root is started at the prep's end** (the body is the executed set in slot order; with
no skipped sender it is the pulled set, so the root can be computed ahead and re-done only when `run.skipped` is not
empty) and ~140 if it stays beside the exec's end. The chained build then waits for the parent's output instead of its
pull+prep: state ready at seal + ~80 against pull+prep+part 40, so the period is ~145 rather than 220. The follower's
road B starts 70 ms earlier too. After that the follower's import (180-209: exec 102-110, groups 58-70) is the wall,
and attempt E (import prefetch) becomes the next term.

**Decision**: attempt G is redrawn as **G2, the seal at the execution's end** (`plan-v6/seal-at-exec`, flag
`N42_SEAL_AT_EXEC=1`), before any graft representation work; the graft's own 40 ms matters only once it is on the
follower's or the chained build's path. Falsified if `sealed_at_ms` does not fall under 140 on full blocks, or if it
does and win1 does not rise above 760k because the chained build's exec waits for the parent's fold (a relocation:
read `par_exec_ms` and the chained build's wait on the parent).

### 6.7 G2 on the fleet (loop230, loop231): the seal moves 70 ms earlier and the chained build's setup absorbs all of it

`plan-v6/seal-at-exec` (merged f2d104590, `N42_SEAL_AT_EXEC=1` off): the transactions root is computed on its own
thread from the pulled set while the batches execute and taken at the seal when nothing was skipped
(`tx_root_ahead`, `tx_root_wait_ms`); the seal follows the body's collection; the commit, the graft, the fee credit,
the withdrawal put-back and the give-backs run behind the proposal under `failed_after_seal`.

**loop230 was void**: every ahead seal was refused by the later gate as "no early seal asked for this build" -- the
seal had taken `early_seal` with it, and the gate's first test was `early_seal.is_none()`. Each such build was
proposed and then failed behind the seal, the chain fell back to the ordinary import at a 0.41 s cycle, 397k. Fixed
in the gate (a block sealed at the step's end counts as asked) and re-run as loop231:

| leg | win1 | win2 | sealed_at | setup | pull+prep+part | exec | fold | tx_root_wait |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 619,373 | 418,316 (stall) | 224 | 14 | 25+11+3 | 64 | 79 | -- |
| G2a | 722,368 | 564,925 | **217** | **74** | 24+11+3 | 70 | 75 | 0 |
| R | 727,729 | 666,859 | 225 | 14 | 24+11+3 | 65 | 77 | -- |
| G2b | 732,843 | 211,707 (stall) | **217** | **76** | 26+11+3 | 65 | 77 | 0 |

No errors on either G2 leg; 810 / 419 builds sealed ahead with the root ahead every time (its wait 0). The seal did
move: on a G2 build it comes right after the execution, ~70 ms earlier in the build than before -- and the build's
`setup_ms` grew from 14 to 74-76, so `sealed_at_ms` is 217 against 224 and win1 is the same 722-733k. The
relocation the plan named, exactly: the chained build (J) starts at the parent's seal and its first act is
`open_parent_state()` (payload.rs ~723, `opener_on_sealed_parent` waiting for the parent's `StateReady`), which
now comes ~70 ms *after* the seal instead of ~15 ms before it. The pull, the prep and the partition (38 ms), which
need the queue and the parent header but not the parent's state, sit behind that wait. **The period is the chain
exec -> fold -> state ready -> (next) exec, ~65 + 77 + 16 + the setup's residue, and where the seal sits inside it
does not change its length.**

What G2 bought is the *place* to overlap: with the seal at the exec's end, the next build's pull+prep+part can run
during the parent's fold if the state is opened only when the exec needs it. Attempt **G3** (`plan-v6/state-after-pull`,
flag `N42_STATE_AFTER_PULL=1`): move `open_parent_state()` and everything that needs it (the executor over the
state provider, the cached reads) to just before the parallel step's execution, after the pull, the prep and the
partition. Expected: setup ~15, the state wait ~30 (70 minus the 38 the pull covers), sealed_at ~180, period ~180
-> ~880k at this block if the follower's import (179-213) does not become the wall first -- which it will at ~200;
attempt E (import prefetch) is then the next term. Falsified if `setup_ms` + the new `state_wait_ms` on a G2+G3
build are not under 45, or if they are and win1 stays under 760k.

The stall on G2b's window 2 (39 blocks at 0.77 s, tc=1) and on the warm leg's (77 blocks at 0.39 s, tc=1, flag off)
are the pacing-175 stall that recurs at random since loop226; still unread.

### 6.8 G3 on the fleet (loop232): the state opens after the pull, and the pull finds the parent's lookahead still out

`plan-v6/state-after-pull` (merged 4b9ef6ca2, `N42_STATE_AFTER_PULL=1` off): the builder's `State` sits over a
`LazyParentDb`; the parent's state (and the pre-execution system calls, the only thing in setup that read it) is
opened in a hook after the pull, the prep and the partition, just before the batches run; `state_wait_ms` and
`state_after_pull` on the phases lines.

| leg | win1 | win2 | sealed_at | setup | state_wait | ahead seals / full builds |
| --- | --- | --- | --- | --- | --- | --- |
| warm | 721,791 | 630,238 | 226 | 14 | -- | -- |
| G23a (G2+G3) | **407,153** | 564,650 | **166** | 0 | 0 | 107 / 180 |
| R | 725,111 | 655,278 | 225 | 15 | -- | -- |
| G23b | **558,424** | 542,706 | **171** | 0 | 0 | 167 / 284 |

The mechanism worked as designed -- setup 0, the state wait 0, a block sealed at 166-171 ms instead of 225 -- and
the leg was slower: 117 of the G23a builds did not seal ahead because "the parallel step left the block short of the
gas limit", each preceded by `holes a build ran into that the pool cannot fill` (a sender's account nonce 692, the
queue's lowest 820: 128 transactions of one sender checked out). The chained build now pulls *at* the parent's seal,
and the parent's lookahead -- what its puller took beyond the block -- is given back only behind the graft, ~60 ms
later (`refuse!` of `lookahead`, `drop(pulled)`, payload.rs ~2006). Under G2 alone the child's 70 ms wait for the
state hid that; under G3 the child pulled from holed lanes, built short, fell to the serial loop and the cycle went
to 0.29-0.39 s. A short block also refuses the ahead seal, which is why the seal count is below the build count.
**Fix**: the lookahead and the puller are given back right after the ahead seal, before the graft (a few ms; the
skipped senders' heads, rare on a full block, keep their late give-back with the diagnosis). Re-run as loop233.

### 6.9 G2+G3 with the lookahead given back at the seal (loop233): the build's wait is gone and the pacing is what is left

| leg | win1 | win2 | sealed_at | state_wait | cycle (full, dissected) | B | D | E | short builds / holes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 726,647 | 660,976 | 223 | -- | 215 | 73 | 97 | 25 | -- |
| G23a | 731,733 | 668,194 | **179** | 23 | **197** | 79 | 85 | **10** | 30 / 39 |
| R | 706,118 | 655,985 | 221 | -- | 220 | 71.5 | 95.5 | 30.5 | -- |
| G23b | 659,464 | 258,008 (stall) | **178** | 20 | 204 | 83 | 89 | 11 | 57 / 74 |

Sealed at 178-179 instead of 221-223, as 6.7 sized it, and the dissected full-block cycle is 197 against 220: the
segment that fell is E, the leader waiting for its own build (30 -> 10). B did not move (the follower's road does
not depend on the leader's fold). What is left of the cycle is **D, the wait between the view opening and the
proposal's preamble, 85-95 ms in every leg -- the 175 ms pacing**: with the build ready at ~180 the leader sits on
the interval. The throughput did not follow the cycle (731k against 706-727k) because the G23 legs' blocks were not
all full (occupancy 96-98%, 30-57 builds short of the gas limit, 39-74 hole warnings, TCs 3-4 against 1): the
lookahead give-back now runs behind the hook and the puller's own walk gives back when its thread ends, which is
after `done` is set and asynchronous -- one batch of one sender (the holes are 256 nonces wide) is still out when
the chained build's hand-off runs. Fixed: the give-back before the proposal, and the puller's drop joins its thread.

Next: the pacing. Every earlier trial below 175 (6.3) stalled with the build at the wall; the build now ends at
~180 and the pacing at 175 is what the leader waits on. loop234 runs G23 at 175, 150 and 125. Falsified if 150 does
not lift win1 above 780k, or if it stalls as 6.3's did.

### 6.10 G2+G3 at pacing 175 / 150 / 125 (loop234): the holes are gone, the cycle is 200, and the flood cannot fill it

With the puller joined on drop and the give-back before the proposal (`give_back_ms` 1), the holes are gone (2-10
warnings a leg against 39-74) and no G23 build was short for that reason.

| leg | win1 | win2 | sealed_at | cycle (full, dissected) | B | D | E | txs/block p10 | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm (no G2/G3) | 684,567 | 670,157 | 222 | 219 | 73 | 96 | 35 | 163,000 | 2 |
| P175 | 716,575 | 658,402 | 173 | **200** | 81 | 91 | 10 | **151,000** | 1 |
| P150 | 508,230 (5 s stall) | 661,865 | 182 | 201 | 87 | 61.5 | 11 | 156,000 | 1 |
| P125 | 267,473 | 705,896 | 181 | 195 | 77 | 58 | 27 | -- | 4 |

The pacing is not it: at 150 and 125 the wait D falls by the 25-35 ms taken off the interval and the dissected
cycle does not move (200 -> 201 -> 195), while the legs stall (P150's window 1 holds a 5 s cycle; P125 four TCs)
as 6.3's did. What holds the cycle at ~200 with the build ending at 173-182 is two things the dissection shows and
one it does not:

- **the follower's import is 207 ms a block** (`direct import` on a full block: the execution 122 = partition 19 +
  env 8 + groups 75 + merge 18 + receipts 6; the QMDB root 75; the engine's insert 46; mined 9, checks 7). One import
  a cycle, so the cycle cannot go under it for long: at pacing 150 the follower falls behind, B grows (81 -> 87)
  and the view times out;
- **the supply**: at a 200 ms cycle the chain wants 163k x 5 = 815k tx/s. The leader's ingest reads 680k/s (busy
  12 us a transaction; 12 recovery slots, so not its bound), and the flood's log says why: `sign 1143s` at 75 s is
  **15 signing thread-seconds a second, on the 16 physical cores (112-127) that four 56-core nodes leave it**, and
  its window-1 rate is 736-750k/s. So 10% of P175's blocks are 151k instead of 163k (occupancy 97% against 99%),
  which is where the cycle's gain went: 716k is 163k x 0.97 / 0.222. R legs at the 220 ms cycle want 740k/s and
  get it.

**Decision**: the flood's core budget first (loop235: `F7_CORES_PER_NODE=48`, 32 physical cores for the flood, with
and without G2+G3 -- a configuration change, no code; falsified if the flood's window-1 rate does not pass 800k/s
or win1 stays under 780k), then the follower's import: the QMDB root (75) and the engine insert (46) run serially
after the execution on the import thread, and neither is needed by the *next* block's execution, only by the vote on
the block after (the root) and by persistence (the insert). Attempt **E2**: the root and the insert of block n behind
the execution of n+1 (`bin/n42/src/follower_import.rs`, `root_wait_ms` / `parent_engine_wait_ms` already gate the
cases where the next block needs them), so the import's serial term is the execution, ~122. That is the follower's
term of the 1M plan: 163k at a 160 ms cycle needs the import under 160.

### 6.11 The flood's core budget (loop235) and the follower's real chain: neither the cores nor the root and insert

| leg | win1 | win2 | sealed_at | cycle (full) | E | txs/block p10 | flood win1 (k/s) | sign thread-s/s | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm (56 cores, G2+G3) | 722,585 | 504,360 | 224 | 220 | 35 | 163,000 | 704-739 | 15 | 2 |
| F48a (48, G2+G3) | 719,410 | 647,441 | 187 | 209 | 11 | 152,500 | 667-733 | 12 | 3 |
| R48 (48, no G2/G3) | 689,987 | 179,293 (stall) | 226 | 229 | 43 | 163,000 | 660-719 | 12 | 7, 1 invalid block |
| F48b (48, G2+G3) | 549,315 | 280,757 | 185 | 203 | 11 | 144,000 | 0-96 (!) | 5 | 4 |

(The warm leg ran without the G2/G3 flags by the runner's construction; it is the R at 56.) Falsified twice over:
the flood signed *less* with 32 cores than with 16 (12 and 5 thread-seconds a second against 15), so it was never
core-bound, and the 48-core nodes were slower (R48's cycle 229 against 220, E 43 against 35, seven TCs and one
invalid block: "the QMDB reader did not answer slot", a read-view timeout under the tighter budget, seen once and
noted). F48b's flood hardly sent at all in window 1 (its log shows 0-96k/s and an empty reply vector: the flood
itself stalled, 79 builds short) -- a void leg.

What the flood *is* bound by is its replies: 64 requests of 500 transactions in flight (`--conc 64 --rpcbatch 500`)
at ~45 ms a reply is ~710k/s, and every leg reads 660-740k/s in window 1 whatever the cores. On the node the
ingest's line says where the 45 ms go: `acq_us_per_frame` 25,000 (a frame waits 25 ms for one of the 12 recovery
slots, `slots_busy_pct` 70), `gate_us_per_frame` 10,500, `recover_ms_per_frame` 6 (12 us a transaction). So the
supply's knobs are the flood's concurrency and the ingest's slot count, not cores: loop236 runs G2+G3 at 56 cores
with `--conc 128`, with 20 slots, and with both. Falsified if the flood's window-1 rate does not pass 800k/s, or if
it does and the blocks are still short (p10 under 163,000) or win1 stays under 780k.

**The follower's chain, read from P175's logs** (a Sonnet pass over node2, window 1, n=143 full blocks): the vote
on n+1 needs only n's execution *fields* (the state root the QMDB root job files, checked by
`wait_for_parent_fields`), not n's engine insert; n+1's execution is gated on n's by `EXEC_GATE` while n's root and
insert run beside it (`root_wait_ms` and `parent_engine_wait_ms` medians 0). So the root (47, spikes to 103) and the
insert (46) are already off the chain, and 6.10's E2 is moot. The chain per cycle is **the road (65-75: assemble
18, the transactions root over the assembled body 24, copy 10, check 7) + the execution (104-122: partition 19,
env 8, groups 68, merge 18, receipts 6) = 170-197**, which is the cycle. The root is hidden under the next block's
road only just: when it spikes (block 415, 103 ms) the next vote waits on it (`two roads` vote_ms 76). The
follower's terms of the 1M plan are therefore the execution's partition and merge (37 of 122, both derivable from
the queue and the groups the way the leader's are) and the road's transactions root beside its assembly.

### 6.12 The supply's knobs (loop236): more concurrency slows the followers' road, and the ceiling at four nodes is the node's CPU

G2+G3 at 56 cores, pacing 175; the flood at `--conc 64` / 12 recovery slots is the warm leg.

| leg | win1 | win2 | flood win1 (k/s) | reply ms | acq us/frame | slots busy | txs p10 | cycle (full) | B | D |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 705,820 | 351,184 (stall) | 740 | 224-242 | 28,261 | 68% | 157,000 | 198 | 77 | 90 |
| C128 (`--conc 128`) | 569,393 | 619,371 | 628 | 538-603 | 51,279 | 62% | 163,000 | 252 | **167** | 64 |
| C128S20 (+20 slots) | 613,878 | 592,125 | 615 | 537-587 | 32,654 | 38% | 163,000 | 260 | **167** | 70 |
| S20 (20 slots) | 559,796 (flood stall) | 717,626 | -- | -- | 18,177 | 42% | 163,000 | 200 | 87 | 87 |

Falsified, and instructively. Doubling the flood's concurrency filled every block (p10 163,000) and *lowered* the
flood's rate (740 -> 628k/s, replies 240 -> 570 ms) while the follower's road B went from 77 to 167 ms and the
cycle from 198 to 252-260: the ingest's work (12 us a transaction, verified on every node) is on the same cores as
the road's assembly and the execution, and more of it in flight is less chain. Twenty slots alone did not change
the rate (the flood is reply-bound at 64 in flight, 45 ms a reply, ~710-740k/s) and its window 1 fell to a
fleet-wide 7 s stall at 25-40 s (replies of 6.9-7.5 s on every node, `engine_idles_over_5s` 3; the same stall took
F48b in 6.11 and the warm leg's window 2 here) -- the memory-reclaim stall of round 43, still with us.

(The huge-page pool was 47-66 GB at every leg's start today by the bench's own `hugeprep:` line; the `order9+`
count in the `memory :` line undercounts it because order-10 blocks are 4 MB. Today's legs are comparable.)

**Where this leaves the four-node ceiling.** At a 200 ms cycle each node ingests and verifies 815k tx/s
(~10 cores of the node's 28 physical), the follower imports a block in 207-225 ms (execution 122 gated one at a
time, the QMDB root 47-75 and the engine insert 46 beside the next execution) on the same cores, and the leader
builds in ~180 (16 threads for ~70 ms, the fold behind). The cycle is stable at 175 pacing and not at 150, because
the follower's import (207+) is longer than the cycle it must keep up with, and the supply at ~740k/s cannot fill
163k blocks faster than every 220 ms. Three things follow, in order:

1. **the follower's import must go under the cycle**: partition (19) and merge (18) out of the gated execution
   (both derivable from the queue's lanes and the groups, the way the leader's are), and the engine insert (46) --
   what it copies for a 147k-account block, and whether the executed block can carry the bundle by `Arc` --
   attempt **F1**;
2. **the leader's period** has the 39 ms gap before the ahead seal (6.11's last paragraph; `plan-v6/seal-gap`
   in flight) -- with it the build ends at ~140 and pacing 150 is a leader-side possibility;
3. **the supply** is CPU: verification on every node is the largest per-transaction term the fleet pays four
   times over (12 us x 4 nodes x 1M/s = 48 cores of the box's 128). `N42_INGEST_VERIFY=leader` is not a probe
   of it: it moves the followers' verification onto the vote road (13 us x 163k a block, 5.x's relocation), so
   the leg would measure the road, not the contention. The design question for 1M on this box is where
   signatures are verified -- once, or by a quorum's worth of nodes rather than all -- not how fast.

### 6.13 The gap before the ahead seal, named (loop237): the parent's state wait and the build's first 19 ms, not the seal

`plan-v6/seal-gap` (merged 32f111136; timers on by default, the pooled slot passes and the deferred cumulative gas
on the flag-on path): the leader's build now accounts for itself. On a full G2+G3 block (medians over the leg):

| par_start | pull | prep | pre_exec | par_run = part + state_wait + exec | scope_join | commit | seal | residue | sealed_at |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 18-20 | 21-22 | 11-12 | 0 | 91-98 = 3 + 19-26 + 68-69 | 0 | 9 (was 15) | 7 | ~8 | **171-177** |

So the "39 ms" of 6.11 was three things already on the line or just off it: the commit (15, now 9), the wait for
the parent's state (`state_wait_ms` 19-26 -- the parent's fold of 76 and its `state_ready` of 20 end ~25 ms after
the child has pulled, prepped and partitioned), and **`par_start_ms` 18-20: the build's first 19 ms, before the
pull** (the puller's start, `cons.prepare`, the block environment; it was under `setup_ms` 0 because that timer
ended earlier). The seal itself is 7. The period did not move (sealed_at 171-177 against 173-183).

| leg | win1 | win2 | cycle (full) | B | D | txs p10 | note |
| --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 555,146 | 733,628 | 199 | 77 | 90 | 148,000 | window-1 stall, flood 0/s at 45 s |
| G175 | 548,127 | 660,826 | 195 | 78 | 90 | 146,500 | window-1 stall |
| G150 | **746,060** | 645,772 | 202 | 87 | 64 | 149,000 | the best window 1 to date, 95% occupancy |
| G175b | 551,396 | 694,508 | 195 | 72 | 99 | 146,500 | window-1 stall |

Three of four legs lost window 1 to the stall (cycle 0.288 over the window, `engine_idles_over_5s` 2-3): it is
now the largest source of variance in the campaign and is read next (a log pass: what the nodes and the flood do
in the 7 s). G150's 746k came at 95% occupancy -- every block short of 163k because the supply is 730-750k/s.

What the leader's period is made of now, and what each term needs: par_start 19 (name it; likely the pool's
`best_transactions` snapshot and the puller's thread), pull+prep 33 (attempt I: the queue's next run prepared
during the parent's fold), state_wait 22 (the parent's graft insert, 40 of the fold's 76, single-threaded: attempt
G proper, a sharded insert on the pool -- it also shortens the follower's merge 18), exec 69 (the reads, 6.6), the
rest 30. The follower's import (207-229) is F1, in flight.

### 6.14 The window-1 stall, read (loop237): a stale build at the tenure handover grinds 163,000 transfers serially (defect 15)

A Sonnet pass over the three stalled legs and the one that did not: every stall is the same transition, the new
leader's second block after the handover (256 -> 257, node1), 8.7-9.0 s long, with the leader silent and the
followers timing the view out at +5.9 s; memory is not it (MemFree 55-69 GB throughout, `compact_stall` flat, the
execution layers' RSS *falls* 11 GB as the stalled build's allocations are freed). The leader's own log then says
what it did for 9 s: block 256 was built by the ordinary path (`leader build path view=256 ahead=false build_ms=299`)
and sealed; a build-ahead request on the *old* parent 255 arrived 3 ms after the chained one on 256 and was
declared stale -- but a build on parent 255 for height 256 ran anyway: its parallel step skipped all 163,000
candidates (their lanes "looked gapped" because block 256 had just mined them), and the build fell into the
serial loop, which pulled afresh and executed 163,000 transfers one at a time (`fast=163000`, 55 us each: 9.2 s,
`build_ms=9216`), holding the payload service while view 257's forkchoice waited 9 s (`fcu_ms=9051`) and the
ingest gate closed on a pool over its limit. In G150 the same transition took 0.8 s. The window-1 numbers of
three legs in 6.13 (548-555k) are this defect, not the configuration; **defect 15**, fixed on
`plan-v6/stale-build-serial` (a build whose parallel step skipped everything it was offered declines with
`Aborted`, and the consensus client builds the ordinary way; the serial loop is never entered with a full parallel
step's worth of skipped work on a chained build; merged 1944a01f2).

**Correction from the fix's author (the views and the heights differ by one)**: the 9 s build was not the stale
request but the *legitimate* chained build on the new leader's first block (the one its ordinary `try_build` had
just sealed): its parallel step saw every sender's account nonce one block behind the queue's lane (10828 against
10892, exactly the block's 64 a sender), skipped all 163,000 as "gapped", and the serial loop then pulled afresh
and built a valid block at 55 us a transfer. In every one of the twelve loop237 builds over 1 s, `fast` equals
`par_skipped`. So the gapped verdict was spurious, and the open question is why the chained build on a parent
built by the ordinary path reads a state one block behind (`opener_on_sealed_parent` on a `try_build` parent, the
parent build's `cached_reads`, or the warm layer; `forget_mined` also reported `forgotten=0` for that block) --
**defect 15b**, to read next; the decline makes the handover cost ~0.3 s instead of 9.

Also seen on the way: `canonical blocks pruned from the queue ... prune_ms=82-114` on every node at every block --
~100 ms of queue pruning a block, whose thread and lock are worth knowing before the follower's road is tuned.

### 6.15 F1 on the fleet (loop238): the follower's gate 105 -> 95 and the engine 46 -> 25, and the cycle does not move

`plan-v6/follower-import` (merged fe8fe0c14): the partition and the environments planned on the road
(`N42_FOLLOWER_PARTITION_AHEAD=1`), the reverts sorted on their own thread beside the finish
(`N42_FOLLOWER_MERGE_BEHIND=1`), the remembered block moved into the engine instead of copied
(`N42_ENGINE_TAKE_SEALED=1`; the transaction-list copy removed for everyone).

| leg | win1 | win2 | gated exec (part+env+groups+merge) | reverts wait | engine | root | import total | cycle | B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm (G2+G3) | **752,708** | 659,515 | 105 = 13+6+70+12 | -- | 46 (remember 16, new_payload 22) | 49 | 224 | 198 | 77 |
| F175 | 721,036 | 680,871 | 95 = 0+0+69+18 | 15 | 27 (11, 6) | 49 | 214 | 196 | 81 |
| F150 | 466,908 (defect 15) | 716,584 | 93 = 0+0+68+18 | 15 | 22 | 55 | 229 | 186 | 80 |
| B128 (`N42_ED25519_BATCH=128`) | 731,256 | 653,018 | 101 | -- | 47 | 46 | 214 | 195 | 74 | 

Parts 1 and 3 did what they were sized to do: the partition and the environments are gone from the gate
(19 -> 0, `ahead_wait_ms` 3-4, the plan is ready when the gate opens) and the engine's 46 is 22-27 (the list copy
and the block copy). Part 2 is negative: the reverts sorted on a separate thread are *waited for* (`reverts_wait_ms`
15) and `merge_ms` reads 18 against 12 inline -- the sort does not overlap the finish, it contends with it; the
flag stays off. Net, the gated execution is 105 -> 95 and the import 224 -> 214, and the fleet's cycle is 196
against 198 and win1 721k against 752k (noise; warm's 752,708 is the campaign's best window). The follower's
import was not what the cycle was made of at pacing 175, as 6.11 said: it is the leader's period (172-176 + the
hand-off) and the supply (736-744k/s; p10 blocks 142-161k).

`N42_ED25519_BATCH=128` is void: `busy_us_per_tx` stayed 12 and the leg had **11 invalid blocks** and 45 short
builds: the followers rejected the leader's blocks with `deferred execution: header carries ExecutedFields {..} for
parent .., this node ..` (123 such lines) -- a **state-root disagreement**, so the batch size changes which
transactions a node accepts or how it executes them. That is a correctness defect in the verification path
(**defect 16**, not on the 1M path, to be read before any batch-size change; the default stays 64).

The road at `--conc 128` (6.12) is not the queue's lock after all: the follower's `vote road` grew only 66 -> 80
(assemble 16 -> 18, root 21-22) while B grew 77 -> 167, so the other ~75 ms sit between the execution layer's
road and the validator -- the Engine API calls and the ingest's HTTP frames share the execution layer's eight
tokio workers (`TOKIO_WORKER_THREADS=8`), and 128 frames of 500 in flight starve the engine's calls. **Q1 is
therefore first a configuration probe**: `TOKIO_WORKER_THREADS=16` with and without `--conc 128`.

Where the campaign stands after plan v6's attempts G2, G3, seal-gap, F1: the four-node fleet reads 720-753k on
window 1 at a ~196 ms cycle with 96-97% occupancy, up from 690-735k at 220 ms when plan v6 began. Every term is
now known to the millisecond, and the two that bind are the supply (the flood's reply-bound 740k/s against the
ingest and the road sharing the queue's lock, 6.12) and the leader's period (par_start 19, pull+prep 33, state
wait 22, exec 69, 6.13). The next attempts, in order: **Q1** -- the queue's lock (ingest inserts, the road's
assembly and the ~100 ms per-block prune all under it): shard it by sender so `--conc 128` fills the blocks without
B growing; **G proper** -- the graft insert sharded on the pool (state wait 22 -> 0 and the follower's merge);
**I** -- the next run pulled and prepped during the parent's fold; and par_start's 19 ms, named.

### 6.16 Defect 15 closed, sixteen tokio workers fill the blocks (loop239): 769,447

Configuration: G2+G3 + F1 parts 1 and 3 (`N42_FOLLOWER_PARTITION_AHEAD=1 N42_ENGINE_TAKE_SEALED=1`), pacing 175.

| leg | win1 | win2 | occupancy | txs p10 | sealed_at | import total | cycle | B | D | declined | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 748,062 | 677,263 | 96.3% | 158,000 | 166 | 192 | 195 | 78 | 88 | 3 | 1 |
| T16 (`TOKIO_WORKER_THREADS=16`) | **769,447** | 638,553 | **98.3%** | **163,000** | 161 | 178 | 195 | 77 | 90 | 3 | 1 |
| T16C128 (+ `--conc 128`) | 559,612 | 635,604 | 99.0% | 163,000 | 148 | 151 | 244 | **161** | 60 | 4 | 7 |
| P150 | 726,328 | 653,593 | 95.5% | 151,500 | 163 | 194 | 194 | 81 | 70 | 7 | 2 |

Defect 15's decline holds: no window was lost to the handover (3-7 declines a leg, each ~0.3 s; `stuck` 0), and
the four windows read within 3% of each other for the first time today. Sixteen tokio workers fill the blocks
(p10 163,000, occupancy 98.3%) at the same cycle: **769,447 on window 1, the campaign's best**, and the
configuration from here on. `--conc 128` is falsified a third time and the tokio workers were not its cause
either: B 161 with sixteen as with eight, while the flood itself starved (window-1 rate 99k/s, seven TCs). What
couples the frames in flight to the proposal's road is still unnamed; it is not the execution layer's road
(+14 ms, 6.15) and not the runtime's workers. Pacing 150 is now stable (no stall, cycle 194) and no faster: the
cycle is the leader's period plus the hand-off, 161-166 + ~30.

Supply is the binding term for throughput: at full blocks the fleet reads what the flood delivers (750k/s at
`--conc 64 --rpcbatch 500`, reply-bound at ~45 ms). The next probe is the frame, not the concurrency:
`--rpcbatch 1000` at 64 in flight (twice the transactions a reply), and at 32 (the same in-flight transactions
as today, half the requests) -- loop240. On the leader's side the period's terms are G proper (the parent's
graft insert sharded so the chained build's `state_wait` 20 goes to 0), `par_start` 19 named and cut, and
attempt I (pull + prep during the parent's fold, 33) -- together ~70 of the 161, in flight as one agent.

### 6.17 The flood's frame size (loop240): it is the transactions in flight, not the requests

| leg | in flight | win1 | win2 | flood win1 (k/s) | reply ms | cycle | B | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm (64 x 500) | 32k | 736,067 | 622,842 | 751 | 240-254 | 196 | 77 | 1 |
| RB1000 (64 x 1000) | 64k | 525,262 | 228,226 | 644 | 521-577 | 236 | **160** | 8 |
| RB1000C32 (32 x 1000) | 32k | **761,971** | 662,336 | 740 | 228-242 | 196 | 82 | 1 |
| RB1000b (64 x 1000) | 64k | 84,039 | 336,845 | 619 | 517-599 | -- | 122 | 23 |

Sixty-four thousand transactions in flight at the ingest -- whether as 128 requests of 500 (6.12, 6.16) or 64 of
1000 -- cost the followers' road B ~80 ms and the flood its rate (the replies go from 240 to 550 ms, the same
transactions a second arrive later); thirty-two thousand as 32 requests of 1000 behave exactly like 64 of 500
(762k, B 82). So the supply is not bound by the request count, the frame size, the recovery slots or the runtime's
workers: **something on the follower's proposal-to-vote path is slowed by the transactions waiting at its ingest**,
by ~80 ms for 32k more of them, and the execution layer's own `vote road` line shows only +14 of it (6.15). What
that is -- the queue's lock held by the admission, the validator's request for the body waiting behind ingest
frames on the same HTTP server, the pool's memory -- is read next from RB1000 against RB1000C32 (same frames, twice
the in-flight). Until it is named the supply stays at ~750k/s, and the throughput at ~770k.

### 6.18 The coupling, named: the road's request queues behind the ingest on the execution layer's runtime

A Sonnet pass over RB1000 (64k in flight) against RB1000C32 (32k), follower node2, window 1: from the validator's
"body received" to "checked" is 138.9 ms against 69.5 (n=37 / 107), the vote follows within 0.6 ms in both, and the
execution layer's own road timers read 76 against 72. **The request waits ~65-70 ms before the road's first timer
starts.** On the ingest side at 64k in flight, `reply_us_per_frame` 44-90k against 32-38k, `gate_us_per_frame`
11-40k against 6-10k, `acq_us_per_frame` 35-49k against 26-29k, eight `held at the ingest gate` warnings against
one. The ingest's frames (`tx-ingest`, recovery on `spawn_blocking`) and the road's serving (`payload_serve.rs`,
its `spawn_blocking` calls and the loopback Engine-API channel) share the execution-layer process's one tokio
runtime and blocking pool; with 64k frames in flight the road's dispatch sits in that queue. Sixteen workers did not
change it (6.16), so it is the blocking pool, the channel or the scheduler rather than the async workers alone.
Attempt **Q2** (`plan-v6/road-runtime`, `N42_ROAD_RUNTIME=1`): the road's path on its own runtime and blocking
pool, with `dispatch_wait_ms` on the `vote road` line to prove the decoupling: falsified if, at 64k in flight,
`dispatch_wait_ms` does not fall under 10 and B under 100 while the ingest's own frame times stay elevated.
If it holds, `--conc 128` (or 64 x 1000) fills the blocks at ~1M tx/s of supply, and the cycle is the term again.

### 6.19 The sharded graft and the hand-off off the lock (loop241, on a box that was not quiet)

Run at 01:37-01:56 on 2026-09-25 with a foreign `rbtcd` soak on the box (a Bitcoin node at ~3.5 cores, MemAvailable
97 GB at the claim): every leg, the warm one included, is ~15% slower than the same configuration the day before
(exec 86 against 64-69, the follower's import 272 against 190, B 102 against 77, window 2 under 500k), so only the
differences within the run are read.

| leg | win1 | par_start | hand-off `queue_ms` | state_wait | graft_insert (split / build / merge) | par_graft | sealed_at |
| --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 756,451 | 13 | 12 | 29 | 40 (--) | 62 | 200 |
| GS (`N42_GRAFT_SHARDED=1`) | 640,678 | 16 | 15 | **83** | **106** (7 / 61 / 37) | 121 | 240 |
| SA (`N42_BUILD_START_ASYNC=1`) | 659,774 | **5** | **4** | 37 | 40 | 62 | 197 |
| GSSA | 622,221 | 6 | 5 | 92 | 105 (7 / 62 / 36) | 121 | 257 |

**G proper is falsified as built**: the sharded insert is 2.6x slower than the single-threaded one -- 61 ms to build
32 shard maps on the pool and 37 to merge them into the block's map, against 40 for the plain insert -- and the
chained build's `state_wait` triples. The parallel build does not win because the per-account cost is not
computation but the cache-missing probe into a large map, and thirty-two smaller maps built on sixteen threads
plus a serial merge of 147k entries do more of those probes, not fewer. The flag stays off; a graft that avoids
the merge (per-shard maps read by the consumers) is the only parallel form left, and it is invasive.

**SA works as sized and moves nothing**: the hand-off's fold and partition off the queue's lock cut `par_start`
13 -> 5 and `queue_ms` 12 -> 4, and `state_wait` grew by the same 8 (29 -> 37): the chained build merely reaches
the wait for the parent's state earlier, as the author predicted without a shorter fold. Adopted anyway (the lock
is held 8 ms less per block on the leader, which the ingest and the road share).

So the leader's period is the parent's fold (62 + `state_ready` 15) reaching the child's execution, and the fold
is the graft insert's 40 ms of memory latency. What is left for it: the insert into a pre-sized map is already
`reserve`d (9 ms); the probe cost itself would need a different map (an open-addressing table keyed by a prefix,
or the shards kept unmerged) -- deferred behind Q2, because the supply binds first.

### 6.20 Q2 on the fleet (loop242): the road's runtime and the nice level are not it either

`plan-v6/road-runtime` (merged 314756c9a): the validator's channel served on a dedicated 4-worker runtime
(`N42_ROAD_RUNTIME=1`), `dispatch_wait_ms` from the kernel's receive stamp to the road's first timer
(`N42_ROAD_DISPATCH_WAIT=1` for the baseline). The author's suspicion was the ingest's nice-10 recovery threads
being reused by tokio as workers; `N42_TX_INGEST_RECOVER_NICE=0` is the probe. Same unquiet box as 6.19.

| leg | in flight | win1 | win2 | cycle | B | dispatch_wait | road total | flood 45 s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 32k | 671,029 | 466,936 | 212 | 102 | 0 | 117 | 432k/s, replies 390-427 ms |
| RR | 32k | 650,855 | 476,970 | 218 | 92 | 0 | 107 | 387k/s |
| RRC128 | 64k | 564,663 | 505,283 | 261 | **166** | 0 | 85 | 32k/s (replies 8-9 s: a flood stall) |
| N0C128 (nice 0) | 64k | 558,113 | 565,045 | 259 | **166** | 0 | 83 | 642k/s |

Falsified twice: with the road on its own runtime B is 166 at 64k in flight as before, and at nice 0 the same
166; `dispatch_wait_ms` reads 0 everywhere -- either the request truly does not wait in the socket, or the counter
cannot see it (the validator opens a new connection whenever the previous reply is still out, and the first segment
on a fresh socket predates the timestamp option; the author flagged this). Either way the ~70 ms between the
validator's "body received" and the road's first timer (6.18) are not the execution layer's runtime, its
blocking pool, its thread priorities or its socket queue. What is left is the plainest reading: **CPU contention on
the node's 28 physical cores** -- twice the frames being decoded and recovered at once slows every other thread on
the node, the validator's included, by the same ~70 ms, and no runtime split changes that. The supply is therefore
bound by per-node CPU as 6.12 said: verification on every node at 12 us a transaction, plus decode, against the
consensus path on the same cores.

Where this leaves the 1M question after plan v6 (2026-09-25): four nodes read 750-770k on a quiet box at a
~195 ms cycle with full blocks; the cycle's terms are all named (6.13-6.19) and the two that bind -- the parent's
graft insert (40 ms of memory latency) and the supply (750k/s of CPU-bound ingest) -- do not yield to the
parallel forms tried. Two configuration probes remain before any further code: (a) **the block's size at this
cycle** -- 200k transactions a block at 195 ms is 1.0M if the supply follows, and the per-block fixed terms (B
~77, the hand-off, the seal) now weigh more than the per-transaction ones (5.x found 163k flat against 200k at the
old cycle; the balance has moved); (b) **three nodes** (quorum 2 of 3, 37 physical cores each), which gives the
ingest and the consensus path room without changing a line. Both need a quiet box (the day's second run was 15%
under the first for a foreign soak), and the box is shared by turns.

### 6.21 The block's size at the 195 ms cycle (loop243, quiet box): 200k is not a step

| leg | block | win1 | win2 | occupancy | cycle | B | exec | graft | road | import |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 163k | 740,323 | 623,007 | 97.3% | 195 | 76 | 65 | 62 | 76 | 199 |
| B200 | 200k | 784,064 | 571,193 | **91.5%** | 221 | 96 | 81 | 70 | 112 | 264 |
| B200b | 200k | 741,544 | 601,743 | 93.9% | 226 | 98 | 76 | 70 | 97 | 256 |
| W163 | 163k | 763,730 | 620,965 | 97.6% | 196 | 75 | 68 | 60 | 81 | 206 |

A 200k block costs the cycle its per-transaction terms back (exec +12, graft +8, the road +25, B +20: 195 -> 221-226)
and the supply cannot fill it (91-94% occupancy at 745-770k/s), so it reads 742-784k against 740-764k: inside the
spread. 163k stays.

## 7. Where plan v6 ends (2026-09-25)

Four nodes, the native chain, 163k-transfer blocks, pacing 175, the configuration of loop239 T16 plus SA
(`N42_SEAL_AT_EXEC=1 N42_STATE_AFTER_PULL=1 N42_FOLLOWER_PARTITION_AHEAD=1 N42_ENGINE_TAKE_SEALED=1
N42_BUILD_START_ASYNC=1 TOKIO_WORKER_THREADS=16` on the CH configuration): **740-770k on window 1 on a quiet box**
(769,447 the best), a 195 ms cycle with 97-98% occupancy, and no window lost to a stall since defect 15. Plan v6
began at 690-735k and 220 ms.

Every millisecond of the cycle is named. The leader's period (161-172 to the seal, ~195 with the hand-off): the
queue hand-off 5, pull 22, prep 12, partition 3, the wait for the parent's state 20-29, execution 64-69 (87% of it
the account reads at ~2.3 us under sixteen threads), commit 9, seal 7. Behind the seal the parent's fold (graft
insert 40 of memory latency, 62 in all) and `state_ready` 15 set the child's wait. The follower's road B 75-77
(assemble 16, the transactions root 22, copy 8, check 7, transport), its gated execution 95, its import 190-206.

What was tried and falsified in plan v6, in one line each: verifying on the road (relocation); the read view's
lock (K, neutral); the overlay's depth (L); the graft's index/ranges/prefault/stream; pacing under 175 (stalls,
then no gain); the flood's cores (reply-bound); `--conc 128` / 64 x 1000 (B +80 from per-node CPU); twenty recovery
slots; ed25519 batch 128 (defect 16); the sharded graft (2.6x slower); the reverts sorted beside the finish
(waited for); the road on its own runtime and at nice 0; 200k blocks. What was adopted: G2, G3, F1 parts 1 and 3,
SA, sixteen tokio workers; defects 10-15 fixed.

The two walls, and what 1M needs from each:
1. **Supply.** Every node decodes and verifies every transaction (12 us each) on the same 28 physical cores as its
   consensus path; at ~750k/s the flood is reply-bound and any more in flight slows the road by the CPU it takes.
   1M needs verification paid once per transaction fleet-wide (a claim the leader's inclusion certifies and a
   follower checks in batch off the vote path, or a sharded verification with a quorum's coverage) -- a protocol
   design, not a knob -- or more cores per node (three nodes).
2. **The cycle.** At 163k a block, 1M is 163 ms. The leader's period is bounded below by the parent's fold reaching
   the child (graft 40 + state_ready 15 + the child's pull/prep 34 in parallel) plus execution 65 plus ~25 of
   seal, hand-off and transport: ~150 if the graft's memory latency yields (a different map, or the shards kept
   unmerged and read by the consumers), and the follower's B (75) must fall with it (the transactions root beside
   the assembly, the copy removed).

The next probe is three nodes (quorum 2 of 3, 37 physical cores each; no code), which loosens the first wall and
says whether the second then binds where 6.13-6.19 predict. After it, the work is design: where signatures are
verified, and what the block's state map is.

### 7.1 Three nodes (loop244): 836,695 on window 1, and a fleet that does not hold

Quorum 3 of 3 on `n42_fleet3_bench.json`, 37 physical cores a node (74 logical), the flood on the 17 left;
the loop239-T16 + SA configuration at 163k, pacing 175. Quiet box (load 2.3, 120 GB).

| leg | win1 | win2 | occupancy | cycle | B | D | E | sealed_at | exec | graft | import | road | flood win1 | TCs | short |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm | **836,695** | 494,132 | 100% | 190 | 66 | 103 | 8 | 128 | 52 | 45 | 134 | 58 | 837-878k/s | 12 | 63 |
| R | **831,207** | 29,817 | 100% | 190 | 66.5 | 101 | 8 | 127 | 52 | 43 | 136 | 58 | 690k/s | 9 | 7 |
| C128 | 18,133 | 347 | -- | -- | -- | -- | -- | 88 | 43 | 41 | 102 | 55 | 0 (replies 15 s) | 32 | 25 |
| R2 | 374,886 | 5,505 | -- | 190 | 66 | 104 | 8 | 119 | 51 | 41 | 122 | 55 | 0 | 20 | 85 |

Window 1 is the campaign's best by 9% and every term moved the way section 7 predicted when the node has cores:
the leader seals at 127-128 (execution 52 against 65-68, the graft 43-45 against 60-62), the follower's road is
58 and its import 134-136, B is 66, the flood delivers 837-878k/s and every block is full. **The cycle is 190
because the leader waits: D is 101-104 ms -- the 175 ms pacing.** At pacing 150 this shape is ~165 ms and 990k;
at 125, if the followers keep up (import 136 < 150), ~1.08M.

And the fleet does not hold: after window 1 every leg collapses (R's window 2 is 8 blocks; C128 died with the
flood's replies at 15 s; R2 never reached full speed), with 9-32 TCs a leg against 1-2 on four nodes and 63-85
builds short. Quorum 3 of 3 has no straggler to spare: whatever one node does for longer than the view timeout is
a TC, where on four nodes the fourth vote covered it. Read next from the logs (the first TC after window 1: which
node, what it was doing, memory at that moment) before any pacing leg -- a three-node fleet that holds for a
round, at pacing 150, is the 1M measurement.

### 7.2 Why three nodes do not hold: the ingest gate, a peer fetch, and no spare vote

A Sonnet pass over loop244's first TCs: in every failing leg the sequence is the same. The flood delivers
840-880k/s to three pools instead of four; a node's pool crosses its limit (543,333 transactions), the ingest gate
holds new frames for 2 s at a time (`a frame has been held at the ingest gate ... depth=581792 limit=543333`);
the next block's description names transactions that node has not ingested yet (`asking a peer for the
transactions this node does not hold ... wanted=896`), the fetch-and-reassemble takes up to 5.8 s, and the view
times out before that node votes -- with quorum 3 of 3 that is a TC every time (R: view 375, node0; warm: view
423, nodes 0 and 2). Memory is not it (MemFree 44-50 GB at the moment). The four-node leg with the same
configuration (loop243 W163) shows the same gate holds at the same depths and one TC in three windows: the
3-of-4 quorum absorbed the straggler. Gate holds then recur every 6-20 s for the rest of the leg (a chronic
backlog, not a one-off), so the collapse is structural at this supply and pool size.

Two levers, one taken now: the pool's limit (loop245 runs three nodes with `F7_BENCH_POOL_SLOTS=1000000`, so the
gate does not close under an 880k/s supply that the chain consumes at ~860k/s), and the peer fetch, which should
not take seconds for 900 transactions (a code path to read if the gate holds persist). A taller view timeout would
mask the same thing at the cost of every real fault. `F7_STRAGGLER_GRACE_MS` is not involved (a pre-vote stall).

### 7.3 Three nodes with a 1,000,000-slot pool at pacing 175 / 150 / 125 (loop245): 904,491 on a window, and still no round

| leg | pacing | win1 | win2 | occupancy | cycle (dissected) | B | D | import | sealed_at | flood win1 | gate holds | peer fetch | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 175 | 787,804 | **820,385** | 100% | 190 | 69 | 101 | 138 | 131 | 650k/s | 18 | 0 | 14 |
| P150 | 150 | 336,854 (10 s stall) | 478,064 | 95% | 167 | 73 | 71 | 152 | 135 | 326k/s | 32 | 0 | 26 |
| P125 | 125 | **904,491** | 367,972 | 99% | **164** | **123** | 12 | **172** | 136 | 888k/s | 22 | 0 | 12 |
| P150b | 150 | 380,919 | 409,855 | 99% | 167 | 63.5 | 81 | 154 | 134 | 246k/s | 21 | 0 | 11 |

The bigger pool removed the peer fetches (0 in every leg, from up to 5.8 s) and the warm leg held two full
windows for the first time on three nodes (788k / 820k). At pacing 125 window 1 reads **904,491 at a 164 ms cycle
with 99% occupancy -- the campaign's best window by 8%** -- and the shape says where it stops: B is 123 (against
66-73) because the follower's import grew to 172 ms, longer than the cycle it must keep up with, so the followers
fall behind and their votes arrive late; at pacing 150 the legs stalled for 10 s inside window 1 (the same
early stall as 6.3's, on three nodes now with no spare vote). TCs are 11-26 a leg with gate holds 18-32, and the
two no longer correlate one to one (no fetch follows a hold). The logs of the first TCs are being read.

What 1M needs from three nodes, in numbers: a cycle of 163 ms at 163k with the follower's import under it. At
pacing 125 the leader seals at 136 and the road is 67, so the cycle would be ~150 if the followers kept up; the
follower's import at that pace is 172 (136 at 190 ms), so it is the follower's pipeline -- the gated execution
(6.15: 95 of it) and what contends with it when blocks come every 164 ms -- that has to lose ~20-30 ms, or the
straggler must not cost a view (a fourth node with a 3-of-4 quorum has the vote to spare but not the cores).

### 7.4 The three-node TCs, read (loop245): the ingest gate deadlocks against the block it is waiting for (defect 17), and the follower's root grows at 164 ms

Every TC inspected (5 of 5, warm and P125; P150's 10 s stall is the same) is one mechanism: the pool's depth
crosses the gate's limit (833,333 of the 1,000,000 slots -- a fixed fraction), the ingest holds new frames, the
follower's road assembling the proposed block by description wants transactions that sit in the held frames
(`asking for the transactions this node does not hold wanted=124`, retried every 40-80 ms, no peer fetch), and
the gate reopens only on a canonical block's prune -- which needs this block. The stall lasts the view timeout
(5.9-6.0 s, `idle_before_ms` 5995-6227) and with no spare vote is a TC every time. Not an import backlog (the
follower's imports were steady before it), not the leader (its build 7-8 ms), not memory. **Defect 17**, on
`plan-v6/gate-deadlock`: the gate opens for a pending block's missing transactions.

The second, independent bound at pacing 125: the follower's import averages 208 ms against the 164 ms cycle, and
the term that grew is the QMDB root -- 68 ms against 39 at pacing 175 (execution 78 against 73, the engine insert
18 against 34, `parent_engine_wait` 11 against 1) -- the root runs beside the next block's execution and at this
pace they contend. B 123 is that lag (the leader's collect samples 71-197 against 67-108). So a three-node round at
pacing 125 needs both: the gate fixed, and the follower's root ~30 ms cheaper or off the contended cores (the
parallel state commit's pool against the execution's), which is the follower-side term of the 1M plan.

### 7.5 The gate opened for a pending block (loop246): the pool then grows without bound, and the fleet dies faster

`plan-v6/gate-deadlock` (4c703eb06): the ingest gate opens for 500 ms from the road's last miss, renewed by each
retry. Three nodes, pool 1,000,000, pacing 175 / 150 / 125 / 125:

| leg | win1 | win2 | cycle | B | TCs | `engine_idles_over_5s` | gate opened (episodes / frames) | flood at 45 s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 603,079 | 124,962 | 189 | 71 | 25 | 23 | 48 / 19,004 | 0/s |
| P150 | **880,163** | 103,230 | 168 | 75 | 13 | 13 | 40 / 17,159 | 411k/s |
| P125 | 378,570 | 54,398 | 178 | 142 | 13 | 13 | 43 / 15,953 | 0/s |
| P125b | 394,984 | 130,395 | 172 | 135 | 14 | 14 | 56 / 25,988 | 38k/s |

Worse, not better: the deadlock is gone (no 6 s waits on a held frame), but with the road missing something on
most blocks the window never closes -- 16-26 thousand frames (8-13 million transactions) admitted past the limit
a leg -- the pool grows without bound, the flood's replies stop (0/s at 45 s in three legs), and the fleet collapses
in window 2 to 54-130k with 13-25 TCs. P150's window 1 (880,163 at a 168 ms cycle, every block full) is the second
best window on record and says again what the shape can do for thirty seconds. The fix as built is turned off by
default (`N42_TX_INGEST_GATE_FOR_BLOCK=1` opts in); a bounded form (admit only the frames the road wants, or a
cap per episode) is possible but it treats the symptom.

The cause is the supply itself: the flood sends as fast as the nodes reply, and on three nodes that is 880k/s
against a chain that consumes 860k/s at 190 ms (and less whenever anything hiccups), so the pool must fill, the
gate must close, and the block being assembled is then behind the gate. On four nodes the same excess was
absorbed by the spare vote and a 6 s stall a leg. What a fleet needs is a supply at or just under its consumption:
`tx_flood --rate` (a fleet-wide token bucket, like the txgen's `--rate`), run at ~850k/s on three nodes -- then no
gate, no deadlock, and the pacing legs measure the chain rather than the backpressure. That is the next leg.

### 7.6 Three nodes with the supply rated at 850k/s (loop247): 863k / 841k on two windows, and a cascade that still starts

`tx_flood --rate` (56f1ca7ee, a process-wide token bucket; `F7_FLOOD_RATE` in the bench), the gate strict,
pool 1,000,000, three nodes, pacing 175 / 150 / 125 / 150. The flood held its rate exactly (849,978-849,980/s in
every leg, replies 188 ms).

| leg | pacing | win1 | win2 | occupancy | txs p10 | cycle | B | D | import | root | TCs | idles >5 s | gate holds |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| warm | 175 | 608,515 | 65,498 | 99% | 163,000 | 190 | 67 | 103 | 133 | 28 | 12 | 10 | 21 |
| P150 | 150 | 842,664 | 500,291 | 96% | 113,000 | 166 | 67 | 76 | 156 | 37 | 9 | 14 | 19 |
| P125 | 125 | **863,245** | **841,305** | 93-96% | 99,000 | **158** | 87 | 32 | 169 | 51 | 12 | 13 | 21 |
| P150b | 150 | 876,275 | 676,581 | 95-99% | 119,500 | 167 | 66 | 78 | 154 | 37 | 8 | 10 | 23 |

Two things at once. **At pacing 125 the chain runs a 158 ms cycle and holds two windows at 863k / 841k** -- the
first time a three-node leg keeps its second window -- and the blocks are short (p10 99,000, occupancy 93%)
because 850k/s is now the supply cap: the chain would consume ~1.03M/s at that cycle. So the rate, not the chain,
is what these windows measure, and the next leg raises it (950k and 1.0M at pacing 125: the pool then drains
rather than fills, so the gate should stay open). **And the cascade still starts**: 8-12 TCs and 10-14 idles over
5 s a leg, 19-23 gate holds, the warm leg's window 2 at 65k -- with the supply under consumption the gate cannot
be the first cause; something else stalls a view (a handover decline, a follower's root spike, an import over the
view timeout), the chain pauses, the pool fills in the pause, the gate closes on the next block's transactions,
and 7.4's deadlock does the rest. The first TC of P125 and P150b is being read for that first cause.

### 7.7 The cascade's first cause (loop247, read): the fill of a block's missing transactions waits at the gate (defect 17b)

Every TC inspected (3 of 3, P125 / P150b / warm) begins the same way, without a prior stall: the leader proposes
in 6-11 ms; one follower's road misses a residue of the block (510 / 1796 / 553 of 163,000) and asks a peer at
+80 ms; the peer answers; the follower logs `the peer supplied the missing transactions ... filled=510` **5.9 s
later, 4-8 ms after the view timed out** and the NewView's prune reopened its gate (the follower's own gate hold
began 80 ms after the ask, at depth 871,500 against 833,333). The other follower votes normally; the stuck one
rotates (node1, node1, node2). So the peer's supply enters the follower through the gated path, and a proposed
block's own transactions are held by the backpressure meant for the flood. The pool, under a flood rated at
850k/s, sits pinned at the gate line (833,176 for the whole window) rather than draining: the chain's usable set is
a fraction of the pool's depth (p10 blocks 99,000 with 833k queued -- the queue's lanes hold far-future nonces),
so "supply under consumption" never became "pool under the limit". **Defect 17b**, on `plan-v6/fill-past-gate`:
the fill of a proposed block's missing transactions is admitted regardless of depth. Raising the flood's rate
(loop248) will not help until it lands -- it tightens the same margin.

### 7.8 Three nodes at pacing 125, the supply at 900k-1.0M (loop248): 926,931 and 919,764 on windows, and the same cascade

| leg | rate | win1 | win2 | occupancy | txs p10 | cycle | B | D | import | root | TCs | idles >5 s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R900 | 900k | **919,764** | 315,372 | 91.6% | 118,500 | **153.5** | 75 | 41.5 | 171 | 45 | 9 | 11 |
| R950 | 950k | 874,368 | 20,189 | 99.3% | 163,000 | 169 | **133** | 9 | 171 | 45 | 12 | 12 |
| R1000 | 1.0M | 849,203 | 22,348 | 99.5% | 162,552 | 157.5 | 83 | 33 | 154 | 33 | 16 | 15 |
| R950b | 950k | **926,931** | 375,304 | 99.6% | 163,000 | 162.8 | 120 | 17.6 | 173 | 43 | 22 | 21 |

Two windows over 900k for the first time -- 926,931 at 950k/s with every block full at a 163 ms cycle, 919,764 at
900k/s where the chain ran a **153.5 ms cycle** (163k in 153 ms is 1.06M/s) and the supply left the blocks 92%
full. The shape between the two: at 900k the road B is 75 and the leader waits 41 ms on the pacing; at 950k and
above B is 83-133 -- the followers' road stretches as the ingest carries more (the per-node CPU coupling of 6.20,
now at 950k rather than 64k in flight), and D falls to nothing. So the chain's own cycle is ~153 ms at this shape
and the supply that fills it without slowing the road is somewhere between 900k and 950k/s: **the 1M window is
within ~7% of what this fleet shows, and the round is not held** (window 2 at 20-375k, 9-22 TCs, 11-21 idles over
5 s -- defect 17b in every case, the fill of a block's missing transactions behind the gate, in flight on
`plan-v6/fill-past-gate`). The next leg is this table again with the fill admitted past the gate; if a round then
holds at 900-950k, the remaining terms are B at 950k (the ingest's CPU beside the road) and the pool's usable
fraction (p10 118,500 at 900k with 833k queued).

**Correction (the fix's author, from the code)**: the fill never goes through the ingest gate. The follower's
execution layer reports the miss, its validator asks the proposer (`request_block_txns`), the proposer's validator
prepares the answer from its body store on a blocking task and puts it on a `served_txns` channel -- **which the
event loop drained only when something else woke its `select!`**. A leader waiting for votes has nothing else to
wake it, so the prepared reply sat until the view timeout (node2 logged nothing from 45.80 to 51.72; `filled=510`
8 ms after the TC). Defect 17b is that missing wake: the loop now selects on the channel and the reply goes out at
once (`plan-v6/fill-past-gate`, merged c2e59d151; `N42_FILL_REPLY_ON_DRAIN=1` restores the old behaviour); the
serving side logs `served a peer the transactions it was missing` with `waited_ms`, the asking side's
`the peer supplied the missing transactions` line gains `wanted` and `waited_ms`. The pool pinned at the gate line
is real but was not the cause; 7.4's gate deadlock (17) remains a second, slower path when the gate does close on a
block's own transactions.

### 7.9 Three nodes with the fill reply woken at once (loop249): the round holds, 922k on a window, and the supply-bound shape

`plan-v6/fill-past-gate` (c2e59d151): the proposer's prepared fill goes out on the step it is ready. Three nodes,
pacing 125, pool 1,000,000, rates 900k / 950k / 900k / 950k. Tagged `fleet3-900k-window-20260925`.

| leg | rate | win1 | win2 | occupancy | cycle | B | D | fills served | gate holds | TCs | idles >5 s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R900 | 900k | 281,370 (stall) | 668,107 | 94-99% | 153 | 80 | 34 | 245 | 26 | 5 | 5 |
| R950 | 950k | 892,651 | 657,410 | 99% | 164 | 122.5 | 12 | 852 | 10 | 5 | 4 |
| R900b | 900k | **922,277** | 641,261 | **90%** | **154.8** | 79 | 44 | 983 | 17 | 6 | 6 |
| R950b | 950k | 898,390 | 608,484 | 99.5% | 164.6 | 118 | 13 | 612 | 6 | 4 | 4 |

The fill works (245-983 served a leg, no 6 s waits on it), TCs are 4-6 a leg instead of 9-22, and **window 2 holds
at 608-668k in every leg** -- the first three-node rounds with both windows substantive; each remaining TC still
costs ~6 s of a 30 s window, which is the whole difference between the two windows. The cycle at 900k is 153-155
(163k in 155 ms is 1.05M/s of capacity) and the blocks are 90% full because 900k/s arrive: `usable` is 389-406k
at the median, holes 5-9 a leg -- **the chain is supply-bound at 900k**. At 950k the blocks fill and B goes to
118-122 (from 79), the cycle to 164: the coupling of 6.20 and 7.8, at the followers' ingest. So the window tops out
at ~925k from either side, 4% under 1M, with the leader at 136 ms and the followers' road at 70 when not coupled.
What is left: the remaining 4-6 TCs a leg (being read), and the coupling at 950k -- the followers' ingest at that
rate (recovery slots, the queue's lock) beside the road.

### 7.10 The remaining TCs (loop249, read): the fill churns without converging (defect 18), plus two smaller shapes

Of 13 TCs across R950b, R900b and R900, **8 are one new shape**: with the proposer now answering every fill in
2-7 ms, the asking follower re-asks every 35-40 ms for the same two `wanted=` counts alternately (2828 / 137,
2159 / 626, 2990 / 25 ...), 340-360 rounds over the 6.9 s to the view timeout, and afterwards `foreign body
refused ... of 163000 not held here` shows the block still nearly whole missing; the whole-body fallback then
completes it in 1.0-1.2 s -- after the TC. No gate hold is involved (0 in those legs). Each fill is applied to
something the next miss check does not read: **defect 18**, on `plan-v6/fill-converge` (the fill written into the
one frame the next assembly reads; a bound of 3 rounds before the whole-body fetch). The other two shapes: R900's
window-1 stall was 7.4's gate deadlock from the start-up transient (the supply outran consumption for ~30 s, the
pool crossed the line to 1,031,644, replies 6-13 s until +55 s); and one TC where the leader proposed 4.6 s late
because "the parent is still importing; proposing once it lands" (view 768) -- a leader-side wait on its own
import, noted as 18b.

### 7.11 The ingest's slots at 950k (loop250): more slots is worse, and the best round so far

| leg | rate | slots | win1 | win2 | cycle | B | ingest rate / node | slots busy | fills | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S16 | 950k | 16 | 461,601 | 603,954 | 164 | 123 | 751k | 57% | 1,202 | 8 |
| S20 | 950k | 20 | 397,092 | 565,355 | 167 | 122 | 429k | 27% | 4,768 | 13 |
| R925 | 925k | 12 | 279,955 (stall) | **907,303** | 163 | 98 | 811k | 76% | 951 | 6 |
| R950 | 950k | 12 | **926,383** | **768,641** | 168 | 118.5 | 802k | 75% | 1,507 | 9 |

Falsified: with 16 or 20 recovery slots the nodes admit *less* (751k and 429k/s against 802-811k with 12), B is
122-123 either way and the fills multiply (up to 4,768: more churn, defect 18) -- the ingest's threads take the
cores the road and the execution need, exactly 6.20's coupling. Twelve stays. The control leg is the campaign's
best round: **926,383 on window 1 and 768,641 on window 2** at 950k/s, and R925's second window 907,303. The
per-node ingest at 12 slots admits ~800-810k/s of a 925-950k/s offer, and that, with the road at 98-123 while it
does, is the supply wall on this box: verification and decode at 11-12 us a transaction on every node.

**Defect 18, read from the code and fixed** (`plan-v6/fill-converge`, merged d48670bbc): when a peer's answer came
back, the validator took the compact body *as it first arrived* from its cache, appended the fill and passed the
result to the driver -- and never stored it back. Round two's fill therefore replaced round one's on the original
holed frame (the filled frame's size alternating 5,686,269 / 5,239,563 bytes in the log), and the execution layer,
counting misses correctly on what it was given, asked for the other set again. Now `merge_fill` combines every fill
into the frame of record in index order, a duplicate body no longer overwrites it, and a miss report after
`N42_FILL_ROUNDS_MAX` rounds (3) or naming a position already supplied goes straight to the whole-body fetch
(`fill converged rounds=..` / `fill did not converge; asking for the whole body`). Why the queue lost the second set
(137 transactions there at the first assembly, gone at the second -- the parent's commit 40 ms earlier?) is not
confirmed; the bound covers it. 18b untouched.

### 7.12 The fill converging (loop251): 931,787 on a window, TCs 1-3 a leg, the round at 730-850k

| leg | rate | win1 | win2 | cycle | B | D | fills (rounds 1 / 2) | fallbacks | gate holds | TCs | idles >5 s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A950 | 950k | 830,719 | 727,828 | 159 | 114.5 | 14 | 61 (54 / 7) | 0 | 10 | 2 | 2 |
| A925 | 925k | 655,791 | **853,006** | 164 | 116 | 11.5 | 87 (83 / 7) | 0 | 3 | 2 | 2 |
| B950 | 950k | **931,787** | 651,771 | 161 | 110 | 25 | 62 (52 / 10) | 0 | 5 | 1 | 1 |
| B925 | 925k | 464,138 (stall) | 782,363 | 163 | 89.5 | 31 | 81 (65 / 16) | 0 | 20 | 3 | 3 |

Every fill converges in one or two rounds (no fallback), the TCs are 1-3 a leg (from 4-6, from 9-22 before
17b), and the window record is **931,787** at a 161 ms cycle with 99% occupancy. A round still loses ~6 s to each
remaining TC (a window 2 of 652-853k against a window 1 of 831-932k), and B sits at 110-116 at 925-950k: the
per-node ingest admits 690-800k/s of the offer with the road stretched by the same contention (6.20, 7.11).
Tagged `fleet3-930k-window-20260925`; main fast-forwarded.

Where the 1M stands after the three-node campaign (loop244-251): the leader seals at 136-142; the chain's cycle
is 153-163 (1.0-1.06M/s of capacity at 163k); the window tops at ~930k because the followers' ingest at
925-950k/s takes the cores the road needs (B 79 -> 110-123 between 900k and 950k); and a round is a window minus
6 s per remaining TC. The three levers, in order of cost: the remaining TCs (1-3 a leg; the leader waiting on its
own parent's import, 18b, and the start-up transient); the ingest's priority against the road (a probe: the
recovery threads at nice 19, loop252); and, for the window past 1M, verification paid once per transaction
fleet-wide rather than on every node -- the design question, unchanged since 6.12.

### 7.13 The last TCs (loop251, read): every one is the new leader waiting on its own execution layer at the handover (18b)

Eight TCs in four legs. Four are view 1 in every leg (peers dialled before the mesh formed: harmless, before the
windows). **The other four are all one shape, at views 256 and 1024 -- the tenure boundaries**: the new leader's
first proposal waits on its own execution layer (`the parent is still importing; proposing once it lands`,
`forkchoiceUpdated returned no payload id (status Syncing)`, `no payload build for id ...`,
`crates/n42/h2-node/src/service.rs` ~2634-2644) for 5.3-9.1 s, and proposes as the view times out. One leg shows
the reason directly: `imported a block ... import_ms=7091` on the new leader -- its import of the parent took
7 s where a follower's import is 180-200 ms. **The follower's import is longer than the cycle (171-197 against
159-164, 7.12), so a follower falls behind by 20-40 ms a block across a tenure; at the handover the new leader must
have the parent in its engine's tree before `forkchoiceUpdated` can start its first build, and it drains the
tenure's backlog first** -- 256 blocks x 20-40 ms is the 5-9 s observed. B925's window-1 stall is that TC (one
7.4 s cycle) with gate holds following it, not preceding. Defect 18 is confirmed gone; 18b is the whole remainder.

Two ways out, one taken now: a longer tenure (loop253: `F7_LEADER_TENURE=1024`, one handover per 164 s instead
of four per leg; the backlog then drains once a leg rather than four times -- the same loss per handover, fewer
handovers) and the proper fix, the tenure's first build on the parent's *published output* (the chained path
already builds that way; only the first build of a tenure goes through `forkchoiceUpdated` on the engine's tree) so
the new leader proposes at once and its engine catches up beside it -- in flight. The follower's import itself
(the root at 45-51 beside the next execution) is the term that makes the backlog, and shortening it is what
1M needs anyway.

### 7.14 The ingest at nice 19 (loop252): no effect on B; the window record 936,737

| leg | rate | nice | win1 | win2 | cycle | B | ingest rate / node | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| N19a | 950k | 19 | 575,963 (stall) | 793,232 | 156 | 107 | 750k | 2 |
| N19b | 925k | 19 | **936,737** | 755,202 | 162 | 113 | 771k | 2 |
| C950 | 950k | 10 | 923,211 | 760,638 | 163 | 109 | 802k | 2 |
| N19c | 950k | 19 | 910,927 | 755,209 | 168 | 112.5 | 803k | 1 |

Falsified: the recovery threads' priority does not move B (107-113 at nice 19 against 109 at 10), so the road is
not losing the cores to *those* threads by scheduling -- the contention is the ingest's whole footprint (decode,
recovery, admission, the HTTP replies) on the node, or the memory bandwidth it takes, not a priority. The window
record moved to **936,737** (N19b, 925k/s, 99.4% occupancy, 162 ms cycle), the rounds read 755-793k on window 2
with 1-2 TCs a leg (18b, the handover). So: the leader at 134-140, the chain at 156-168, the road at 107-113 under
a 925-950k/s ingest, the windows at 911-937k, and the round a handover short. loop253 (the tenure at 1024) and
18b's fix are what turn a window into a round; the window itself is the ingest's footprint against the road,
which is the design question (verification paid once).

### 7.15 The tenure at 1024 (loop253): 953,423 on a window, one TC a leg, and the windows that decay without any

| leg | rate | tenure | win1 | win2 | win3 | cycle (win1) | B | TCs | `still importing` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T950a | 950k | 1024 | 935,253 | 771,508 | 597,272 | 168 | 130 | 1 (start-up) | 0 |
| T925 | 925k | 1024 | 919,922 | 717,167 | 706,273 | 167 | 122 | 1 | 0 |
| T950b | 950k | 1024 | **953,423** | 776,926 | 542,866 | **164** | 118 | 1 | 26 |
| C950 | 950k | 256 | 918,583 | 722,442 | 592,210 | 161.5 | 107 | 1 | 18 |

With one handover a leg the in-window TCs are gone (the one TC each is view 1, before the flood) and the window
record is **953,423** at a 169 ms cycle with every block full -- 4.7% under 1M. And the round still decays: every
leg, the control included and with no TC in it, reads ~770k on window 2 and 540-700k on window 3 at 100%
occupancy, the cycle stretching 0.17 -> 0.21 -> 0.27-0.30 s. That decay is not consensus; it is the chain getting
slower as the leg runs -- the state grows by ~147k fresh accounts a block (the flood's recipients), so the QMDB
root, the reads and the follower's import all lengthen, and the heaps grow with them -- the same slope every
campaign has seen (window 1 is the metric for that reason; CLAUDE.md). Tagged `fleet3-950k-window-20260925`.

What 1M on a window needs now is 5%: the ingest admits ~750-800k/s a node of a 950k offer with B at 118-130
while it does. Either the ingest's cost per transaction falls (the ed25519 batch verifier's backend and batch
size -- `docs/SIGNATURE_AND_BATCH_TX_SURVEY.md` has this host's numbers -- or verification paid once fleet-wide),
or the road's B is decoupled from it (nothing tried has: runtime, nice, slots). 18b's proper fix (in flight) is
for the round, not the window.

### 7.16 The verifier's cost, surveyed: the node is built for generic x86-64

A Sonnet pass over the verifier and `docs/SIGNATURE_AND_BATCH_TX_SURVEY.md`: `busy_us_per_tx` 11-12 is the
signature alone -- the decode, the hash and the sender cache run before the recovery slot is taken and cost under
1 us (5.3's `road_senders` bench: 13.0 us with verification, 0.72 without); it matches sigbench's batch-64 figure
(12.99 us a signature) on this host, an AMD EPYC 9B45. The merged batch equation and the decompressed-key cache are
already in (`alt_sig.rs`, `sender_cache.rs`). **Neither the node nor sigbench is built with `-C target-cpu=native`**
(no `.cargo/config.toml`, no `RUSTFLAGS` in the bench scripts): `curve25519-dalek` runs its generic backend and never
its AVX2 / AVX-512 one. That is the 5% lever at the least risk, and loop254 runs it (a `target/native` build for
the node, the validator and the flood; generic control). Batch 256 is 10.2 us against 13.0 in sigbench (21%) but
defect 16 (batch 128 -> state-root disagreements) must be read first. `ed25519-zebra` is unevaluated. Anything
past ~25% is verification paid once fleet-wide -- a protocol change, not a knob.

**18b, corrected from the code and the logs** (`plan-v6/tenure-first-build`, d632e0bf1, not yet merged): the parent
lands in the new leader's engine ~60 ms after the first `Syncing`; what takes 5-9 s is the payload job the next
`forkchoiceUpdated` starts -- its first build finishes in 0.7 s and then `getPayload` hangs until it returns
"no payload build for id" 5.1-9.0 s later (`engine service loop ... idle_before_ms` 5516-9057), the payload-job /
persistence stall of loop161. So it is a stuck payload job at the handover, not the import backlog; the follower's
import over the cycle is real but is not what the TC is made of. The fix avoids the job altogether: with
`N42_TENURE_FIRST_ON_OUTPUT=1` (validator and execution layer both) the tenure's first build goes through the
chained path on the parent's *published* output -- the follower's outputs are filed in `PARENT_OUTPUTS` /
`executed_fields` under the sealed hash, not in `built_executions`, so a new opener (`opener_on_published_parent`)
reads them, the parent's transactions leave the queue from its bundle, and the forkchoice build stays as the
fallback. To be run after loop254; the stuck job itself (why `getPayload` hangs at a handover) still owes a
reading.

### 7.17 The node built for this CPU (loop254): 970,277 on a window

`target/native` (`RUSTFLAGS="-C target-cpu=native"`, 913 crates in 3.5 min), three nodes, tenure 1024, pacing 125.

| leg | build | rate | win1 | win2 | occupancy | cycle | B | ingest rate / node | busy us/tx |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| NATa | native | 950k | **970,277** | 787,802 | 99.2% | 159 | **87** | 726k | 11 |
| C950 | generic | 950k | 948,067 | 793,230 | 99.4% | 165.5 | 120 | 772k | 11 |
| NATb | native | 950k | 960,064 | 743,854 | 99.3% | 167 | 103 | 813k | 11 |
| NAT925 | native | 925k | 952,213 | 603,067 | 94.0% | 158 | 86 | 803k | 11 |

The verifier's cost did not move (`busy_us_per_tx` 11 either way: `curve25519-dalek` 4's AVX backend is not
selected by target features alone -- it needs its `simd` backend cfg, to be checked), but the rest of the node
did: B 86-103 against 120, the cycle 158-167, and the windows **970,277 / 960,064 / 952,213 against 948,067** --
3% under 1M with every block full, one TC a leg (view 1). Adopted: the native build is the fleet's binary from
here. Tagged `fleet3-970k-window-20260925`. Next: 18b's first build on the published output (the round), and the
dalek `simd` backend for the verifier (the window's last 3%).

### 7.18 The tenure's first build on the published output (loop255): the handover costs nothing, 969,028

`plan-v6/tenure-first-build` (merged 5a3e4af7f, `N42_TENURE_FIRST_ON_OUTPUT=1` on validator and execution layer),
native build, three nodes, tenure 1024, pacing 125.

| leg | flag | rate | win1 | win2 | cycle | B | first build on output / fallback | `still importing` | invalid |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TFa | on | 950k | 959,205 | 771,494 | 165 | 112.5 | 1 / 0 | 1 | 0 |
| C950 | off | 950k | 965,495 | 679,132 | 162 | 103.5 | -- | 29 | 0 |
| TFb | on | 950k | **969,028** | 700,866 | 161 | 102 | 1 / 0 | 0 | 0 |
| TF925 | on | 925k | 944,350 | 766,043 | 166 | 97 | 1 / 0 | 0 | 0 |

The path works: at the one handover a leg (view 1024) the new leader built on the parent's published output
with no fallback, no `still importing` retries (0-1 against 29) and no invalid block; the flag is adopted in the
runners (the code default stays off until a shorter-tenure leg confirms it at every handover). With tenure 1024
the handover falls in window 3, so windows 1-2 do not change by it: 944-969k and 679-771k as before -- the
decay across windows is the state's growth, not consensus. The window stands at 969-970k; the last 3% is the
verifier: `curve25519-dalek` 4 selects its AVX2 backend only with `--cfg curve25519_dalek_backend="simd"` (not by
`target-cpu` alone), which loop256 builds.

### 7.19 The verifier's simd backend (loop256): no change to the cost, the ingest at ~820k/s a node whatever is offered

| leg | build | rate | win1 | win2 | cycle | B | ingest rate / node | busy us/tx | slots busy |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SIMDa | native + simd cfg | 950k | 958,416 | 760,449 | 162 | 124 | 786k | 11 | 72% |
| NATc | native | 950k | 933,807 | 760,632 | 163 | 104 | 806k | 11 | 76% |
| SIMDb | native + simd cfg | 950k | 948,974 | 766,053 | 167 | 129 | 810k | 11 | 76% |
| SIMD1000 | native + simd cfg | 1.0M | 957,634 | 749,766 | 165 | 107 | **822k** | 11 | 77% |

`--cfg curve25519_dalek_backend="simd"` on top of `target-cpu=native` leaves `busy_us_per_tx` at 11 (the batch
equation's multiscalar multiplication is not where that backend helps, or the cfg did not take -- the build log
shows no such warning either way), and the windows are the same 949-958k; at a 1.0M/s offer each node admits
822k/s, so **the per-node ingest ceiling is ~800-820k/s at 11 us a signature, whatever the flood offers**, and the
window is ~950-970k. The last levers inside the protocol are the batch size (sigbench: 256 is 21% cheaper a
signature, blocked by defect 16 -- read next) and the verifier crate itself; past those, verification once fleet-wide.

## 8. Where the campaign stands (2026-09-25, after loop256)

Three nodes on this box, the node built for its CPU, batch 256, tenure 1024 (or 256 under 18b), the supply rated at
925-950k/s, the fills and the handover fixed: **977,627 on a window (loop257), 950-970k on every window 1 since, 750-790k on window 2 as the
state grows, one TC a leg (view 1)**. Four nodes stood at 769k when the day began. Tags:
`fleet3-977k-window-20260925`, main at the same commit. The 2.3% to 1M on a window is the ingest's 11 us a signature
on every node against the road that shares its cores; the round past 1M is a different matter (the state's growth
over a leg, a protocol's verification design). `docs/FLEET7_PLAN_V4.md` sections 6-7 carry every measurement.

### 7.20 Defect 16 re-read: not the batch size -- every leg since loop238 has run at batch 128

The runner's shared `C` string has carried `N42_ED25519_BATCH=128` since loop238, so the "B128" leg differed from its
siblings in nothing (the ingest lines agree: ~125 transactions a batch in every leg), and the 11-12 us a signature
measured all day is batch 128. What that leg showed instead: the tenure's first build stuck 8 s (18b), two sibling
blocks at 768, a reorg, two concurrent builds of 769 on the surviving sibling, and 770 built on the *output* of
the 769 that was not the one committed -- the followers refused 771 on its state root alone (receipts and gas
agree). **Defect 16 is therefore a build-on-output sibling defect at a handover (18c)**: a lookup that can take the
wrong sibling's build out of the registry (`reuse_own_build`, `take(.., None)` in `payload_serve.rs`) is the
suspect; 18b's fix removes the stuck first build that produced the siblings and may remove the trigger. The
verifier maps verdicts by index correctly at every batch size (a new test, `the_batch_size_changes_no_verdict_and_no_sender`,
200 transactions, 7 senders across chunk boundaries, three bad signatures, chunks of 1 / 64 / 128 / 200 / 256).
The batch-size claims in 6.15, 7.16 and 7.19 are withdrawn; batch 256 (sigbench: 10.2 us against 11.x at 128) is a
plain configuration leg, loop257, together with a short-tenure leg (256) under 18b's path to see whether the
sibling shape recurs.

### 7.21 Batch 256 and the short tenure under 18b (loop257): 977,627 on a window, four handovers clean

| leg | batch | tenure | win1 | win2 | cycle | B | ingest rate / node | busy us/tx | handovers on output / fallback | invalid | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B256a | 256 | 1024 | 953,036 | 727,338 | 161.5 | 122 | 679k | **10** | 1 / 0 | 0 | 1 |
| C128 | 128 | 1024 | 955,156 | 766,069 | 163 | 95.5 | 756k | 11 | 1 / 0 | 0 | 1 |
| B256b | 256 | 1024 | **977,627** | 776,936 | 162 | 119.5 | 835k | **10** | 1 / 0 | 0 | 2 |
| T256 | 256 | 256 | 942,811 | **831,105** | 159 | 124 | 826k | 10 | **6 / 0** | 0 | 3 |

Batch 256 takes the signature to 10 us (from 11) and the window to **977,627** -- 2.3% under 1M -- and is adopted.
The short tenure under 18b's path is clean: six handovers a leg on the published output, no fallback, no invalid
block, and the best window 2 on record (831,105), so `N42_TENURE_FIRST_ON_OUTPUT=1` meets its own bar and 18c's
sibling shape did not recur. Tagged `fleet3-977k-window-20260925`. The next and last configuration leg is the
offer above 950k with batch 256 (the ingest admitted 835k/s here and 822k at a 1.0M offer in 7.19): loop258.

### 7.22 The offer at 1.0M and 1.05M (loop258): the generator itself tops out at ~925k/s

| leg | offer | win1 | win2 | flood win1 (k/s) | ingest rate / node | gate holds | cycle | B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| R1000a | 1.0M | 967,097 | 776,922 | 926 | 821k | 8 | 157 | 109.5 |
| C950 | 950k | 966,900 | 744,333 | 925 | 824k | 0 | 164 | 125.5 |
| R1000b | 1.0M | 957,398 | 760,637 | 913 | 784k | 2 | 161.5 | 115 |
| R1050 | 1.05M | 959,364 | 700,876 | 921 | 723k | 0 | 169 | 128.5 |

Whatever is asked of it, the flood delivers 913-926k/s in window 1 (`sign` ~900 thread-seconds over a leg on its
17 physical cores: it signs at the pace it sends), and the windows sit at 957-977k with every block full. **The
window is now bound by the generator, not the chain**: the chain's cycle is 157-169 with the blocks full, and B
109-128. The one configuration left is the cores: three nodes at 70 logical (35 physical) instead of 74 leave the
flood 23 physical cores (+35% of signing), at 68 it has 26 -- loop259, at a 1.05M offer, with the 74-core control.
Falsified if the nodes lose more than the flood gains (the cycle over 175, B over 130) or the window stays under 990k.

### 7.23 Cores from the nodes to the flood (loop259): the flood does not sign faster with them

| leg | node cores | flood cores (physical) | offer | win1 | win2 | flood win1 (k/s) | sign thread-s | cycle | B | TCs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| N70a | 70 | 23 | 1.05M | 955,799 | 787,790 | 903 | 824 | 164 | 125.5 | 5 |
| C74 | 74 | 17 | 950k | 945,979 | 744,332 | 896 | 918 | 161 | 115 | 1 |
| N70b | 70 | 23 | 1.05M | 958,509 | 776,932 | 877 | 823 | 161 | 123 | 2 |
| N68 | 68 | 26 | 1.05M | 944,552 | 771,195 | 905 | 793 | 162 | 126 | 1 |

Falsified: with 23-26 physical cores the flood delivers the same 877-905k/s and signs *less* (793-824
thread-seconds against 918) -- it is not signing-bound but bound by its send-and-reply loop (64 requests of 500 in
flight per node at ~180 ms a reply). The nodes at 70/68 cores are not hurt (cycle 161-164, B 123-126). So the
generator's structure -- the requests in flight and the frame -- is the last supply term, and a rated flood
with more in flight no longer risks 6.17's coupling (the token bucket bounds what is in flight): loop260 runs
`--rpcbatch 1000` and `--conc 96` at a 1.0M offer.

### 7.24 Bigger frames and more requests in flight (loop260): the coupling returns under the token bucket too

| leg | frame x in flight | offer | win1 | win2 | flood win1 (k/s) | reply ms | cycle | B |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RB1000 | 1000 x 64 | 1.0M | 907,326 | 782,366 | 866 | 398-456 | 176 | 143 |
| C96 | 500 x 96 | 1.0M | 928,311 | 755,157 | 869 | 275-319 | 171.5 | 137 |
| C950 | 500 x 64 | 950k | **975,788** | 679,340 | 950 | 170-171 | **155.5** | **97.5** |
| RB1000C96 | 1000 x 96 | 1.0M | 844,589 | 760,623 | 807 | 614-716 | 186 | 150 |

Falsified: with 48k or 64k transactions in flight the followers' road stretches (B 137-150), the replies 300-700 ms,
and the flood delivers *less* (807-869k) -- 6.17's coupling is about what sits in the ingest at once, and the token
bucket does not lower that. The control at 500 x 64 is the shape: 975,788 at a 155.5 ms cycle, B 97.5 -- the
generator delivering 950k/s and the fleet consuming all of it.

## 8 (continued). The four-node-to-three-node campaign, closed (2026-09-25 19:00)

Twenty-one rounds on three nodes (loop244-260). Window 1 stands at **977,627** (loop257) with 966-976k on every
control since; the fleet consumes what the generator delivers at 950k/s with every block full, at a 155-165 ms
cycle (163k in 155 ms is 1.05M/s of capacity). The 2.2% to 1M on a window is the supply: the ingest of every node
admits ~800-840k/s at 10 us a signature with 12 slots, and any attempt to push more through it (more in flight,
bigger frames, more slots, more cores, a lower priority) stretches the followers' road by the CPU it takes. Rounds
read 780-830k on window 2 as the state grows (7.15). Adopted along the way: three nodes, pool 1,000,000, the
supply rated, the fills converging (17b, 18), the tenure's first build on the published output (18b), tenure
1024, the node built for its CPU, ed25519 batch 256. Falsified: the gate opened for a block, slots 16/20, nice 0/19,
cores to the flood, frames of 1000, 96 requests, offers above 950k.

What would cross 1M on a window is not a knob: verification paid once per transaction fleet-wide (the leader's
inclusion as the claim, checked by followers in batch off the vote path, or verification sharded with a quorum's
coverage) -- a protocol design with a safety argument to write first -- or a generator on another box, so the
flood's 17 cores stop competing with the nodes' ingest for the same memory bandwidth. Both are decisions, not
measurements; the measurements are in this document.

## 9. The generator off the signing path (2026-09-26)

The user's direction after section 8: pre-generate the transactions -- signed and encoded exactly as the flood
sends them -- into files on disk once (tens of GB on /data), and have the flood read and send them, so the 17 cores
beside the nodes sign nothing and the generator's rate is the send loop alone. `tx_flood --pregen-out <dir>
--pregen-txs <n>` writes one file per worker in the live send order (frames of `--rpcbatch`, length-prefixed, a
header the replay checks against its arguments); `tx_flood --replay <dir>` sends them through the unchanged send
loop (`--conc`, `--rate`, the same summary lines); the bench passes `F7_FLOOD_REPLAY=<dir>`. A replay set is valid
against a fresh chain only (the derived senders at nonce 0 after funding), which every leg is. The first leg
repeats 7.24's control with the replayed set at 950k and then raises the offer, to see whether the send loop
alone delivers 1M/s and whether the followers' road stays at ~100 when the generator no longer competes for the
box's memory bandwidth. In flight on `plan-v6/flood-pregen`.

### 9.1 The replayed flood (loop261): the generator was never the bound

`plan-v6/flood-pregen` (merged b67478347): 192M ed25519 transfers in the live send order, 64 files, 29 GB, made in
about a minute; the flood's own tests pass (6, byte-identical frames); replay checked every header and every
worker's first sender at nonce 0 and signed nothing (`sign 0s`).

| leg | flood | offer | win1 | win2 | flood win1 (k/s) | ingest rate / node | cycle | B | reply ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| REP950 | replay | 950k | 950,035 | 684,892 | 897 | 824k | 170 | 134 | 184-220 |
| C950 | live | 950k | **975,487** | **869,281** | 950 | 853k | 157 | 113 | 168 |
| REP1000 | replay | 1.0M | 956,023 | 782,374 | 910 | 770k | 164 | 127.5 | 176-211 |
| REP1050 | replay | 1.05M | 967,100 | 717,354 | 935 | 671k | 163.5 | 126.5 | 171-206 |

Falsified: with signing removed the flood delivers 897-935k/s -- no more than the live one at 950k -- and the
windows sit at 950-967k with B 127-134, while the live control reads 975,487 / 869,281 (the best window 2 on
record). The generator's rate was never its CPU: it is the send-and-reply loop against the nodes' ingest (64
requests of 500 per node, a reply every 170-220 ms), and the nodes admit ~820-850k/s each however the frames are
made. The replay is kept (deterministic supply, no signing cores, a leg's flood reproducible byte for byte) but
it does not move the window. **The supply term is the node's ingest, full stop** -- the 10 us a signature on
every node and the CPU the followers' road shares with it -- and past it lies the design question of section 8.

### 9.2 The sharded-verification probe, first try (loop262): the shard path needs a claiming flood

`plan-v6/ingest-shard` (merged 7319c655d + the cache fix): `N42_INGEST_VERIFY=shard`, each execution layer told
its `N42_INGEST_SHARD=i/n` by `fleet7.sh`. The legs read `shard_verified=0 shard_claimed=0`: the shard rule
applies to a *claiming* frame, and the bench's flood sends none unless asked (`tx_flood --claim-sender`), so every
transaction went through the full verification as under `all` -- the four legs are four more controls (967-976k
on window 1, C950's window 2 825,835). `F7_FLOOD_CLAIM=1` now passes the flag; loop263 repeats the legs with it.

### 9.3 The sharded-verification probe (loop263): a third of the verification, and the fleet is slower

| leg | mode | offer | win1 | win2 | cycle | B | busy us/tx | slots busy | ingest rate / node | flood win1 | reply ms | road total | import |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SH950 | shard (1/3 verified) | 950k | 863,871 | 760,642 | 179 | **137.5** | **4** | 28% | 784k | 819k | 195-216 | 67 | 148 |
| C950 | all | 950k | **975,932** | 863,852 | 153.5 | **77.5** | 10 | 73% | 817k | 950k | 169 | 67 | 164 |
| SH1000 | shard | 1.0M | 836,687 | 760,633 | 191 | 143.5 | 4 | 27% | 751k | 819k | 195-216 | 66 | 140 |
| SH1050 | shard | 1.05M | 847,567 | 771,504 | 187 | 143 | 4 | 27% | 755k | 813k | 196-216 | 66 | 141 |

The probe engaged (64M verified, 128M admitted on the claim; the ingest's busy time 4 us against 10, the slots
27% against 73%, `verified_on_road` 0) and **the fleet lost 11%**: B 137-144 against 77.5 while the execution
layer's own road stayed at 66-67 and the leader's seal at 135-138; the flood delivered 813-843k/s with replies
195-216 ms against 169. So the verification's CPU was not what couples the ingest with the road: the claim path
costs the road ~60 ms somewhere before its own timers, and slows the ingest's replies with a third of the work.
That falsifies the design note's premise as stated (section 2.B's saving is real in CPU and does not reach the
window on this fleet) until the coupling is named -- being read from the two legs.

### 9.4 Why a third of the verification made the fleet slower (loop263, read): the ingest gate, again

Over window 1 on the follower (node1): the road's own timers hardly moved (`vote road` 63 -> 71, `checked` 65 ->
73), the leader's collect grew 85 -> 148 -- and the follower's ingest line says why: `gate_us_per_frame` ~280 ->
~26,000, `reply_us_per_frame` ~1,600 -> ~36,700, `acq_us_per_frame` 1,300-4,100 -> 9,500-10,800, with
`busy_us_per_tx` 10 -> 4 and the slots 82-85% -> 29-31%. The follower's queue sits at 867,000 against 552,000
under `all` (from the first block: 646k against 482k; the pool's cap 1,000,000, the gate line 833,333); the gate
reopens only on a canonical block's prune, so near the cap every frame is held, the replies the flood measures
stretch (169 -> 195-216 ms), the follower's vote slips, the leader's collect grows, the next prune comes later
and the queue creeps further -- a feedback loop. The leader's own ingest shows none of it (gate 350-590 us both
legs). **The coupling between the ingest and the road is the follower's backpressure gate, not the CPU**: under
`all` the verification itself throttles admission (slots 73-85% busy) and the queue stays at 550k, under the
gate line; make admission cheaper and the queue rises to the gate, which then costs every frame and every vote.
Which is also 6.17-6.20 in another form (more in flight = a deeper queue = the gate). Next: the same probe with
the gate line out of reach (pool 2,000,000) and the offer at or under consumption -- loop264 -- to see whether the
cheaper ingest then reaches the window, and, independently, whether the gate should hold frames at all on a
follower whose queue the next block will prune (a bounded, non-blocking backpressure instead of a hold).

### 9.5 The shard probe with a 2M pool (loop264): the queue's depth is the cost

| leg | mode / pool | offer | win1 | win2 | cycle | B | queue depth (median) | gate us/frame | reply us/frame | road total | busy us/tx |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SH950 | shard / 2M | 950k | 603,078 | 559,613 | 269 | 246 | **1,700,000** | 43,323 | 54,607 | **152** | 4 |
| C950 | all / 1M | 950k | **965,669** | 700,852 | 162 | 118.5 | 678,500 | 7,367 | 34,188 | 77 | 10 |
| SH1000 | shard / 2M | 1.0M | 461,820 | 554,179 | 400 | 382 | 1,699,500 | 42,986 | 54,434 | 147 | 4 |
| SH1050 | shard / 2M | 1.05M | 456,381 | 554,179 | 290 | 255 | 1,698,500 | 44,058 | 55,456 | 149 | 4 |

Worse again, and it names the term: with the cap at 2,000,000 the follower's queue sits at 1,700,000 -- the new
gate line -- and now the **road itself is 147-152 ms against 77**: the vote road assembles the block from the queue,
and the queue's work grows with its depth (the assembly, the copy, the prune over 1.7M entries), so a deeper queue
is a slower road, a later vote, a slower chain, a deeper queue. The cheaper ingest buys nothing because it only lets
the queue fill to whatever line the gate draws, and every line above ~550k costs the road more than the
verification saved. Under `all` the verification throttles admission before the queue deepens; that accident is
why `all` is faster. The lever is therefore the *depth*, not the CPU: backpressure at a shallow queue (a few
blocks' worth, ~400-500k), held cheaply, with the flood's token bucket pacing the offer to consumption.
loop265: shard and all at a 500,000-slot pool (gate 417k) and at 650,000, 950k/s.
