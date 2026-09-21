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
