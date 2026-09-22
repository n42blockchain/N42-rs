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
